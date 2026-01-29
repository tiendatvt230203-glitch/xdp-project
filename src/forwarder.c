#include "../inc/forwarder.h"
#include "../inc/packet_crypto.h"
#include "../inc/flow_table.h"
#include <signal.h>
#include <poll.h>
#include <pthread.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/ethernet.h>

static volatile int running = 1;

static struct packet_crypto_ctx crypto_ctx;
static int crypto_enabled = 0;

static struct flow_table g_flow_table;

struct local_thread_args {
    struct forwarder *fwd;
    int local_idx;
};

struct wan_thread_args {
    struct forwarder *fwd;
    int wan_idx;
};

static int encrypt_packet(void *pkt_data, uint32_t pkt_len) {
    if (!crypto_enabled) return 0;

    // New implementation: packet size unchanged (zero overhead)
    return packet_encrypt(&crypto_ctx, (uint8_t *)pkt_data, pkt_len);
}

static int decrypt_packet(void *pkt_data, uint32_t pkt_len) {
    if (!crypto_enabled) return 0;

    // New implementation: packet size unchanged (zero overhead)
    return packet_decrypt(&crypto_ctx, (uint8_t *)pkt_data, pkt_len);
}

static void sigint_handler(int sig) {
    (void)sig;
    running = 0;
}

static uint32_t get_dest_ip(void *pkt_data, uint32_t pkt_len) {
    if (pkt_len < sizeof(struct ether_header) + sizeof(struct iphdr))
        return 0;
    struct ether_header *eth = (struct ether_header *)pkt_data;
    if (ntohs(eth->ether_type) != ETHERTYPE_IP)
        return 0;
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    return ip->daddr;
}

static int parse_flow(void *pkt_data, uint32_t pkt_len,
                      uint32_t *src_ip, uint32_t *dst_ip,
                      uint16_t *src_port, uint16_t *dst_port,
                      uint8_t *protocol) {
    if (pkt_len < sizeof(struct ether_header) + sizeof(struct iphdr))
        return -1;

    struct ether_header *eth = (struct ether_header *)pkt_data;
    if (ntohs(eth->ether_type) != ETHERTYPE_IP)
        return -1;

    struct iphdr *ip = (struct iphdr *)(eth + 1);
    *src_ip = ip->saddr;
    *dst_ip = ip->daddr;
    *protocol = ip->protocol;

    int ip_hdr_len = ip->ihl * 4;
    uint8_t *transport = (uint8_t *)ip + ip_hdr_len;

    if (ip->protocol == IPPROTO_TCP) {
        if (pkt_len < sizeof(struct ether_header) + ip_hdr_len + sizeof(struct tcphdr))
            return -1;
        struct tcphdr *tcp = (struct tcphdr *)transport;
        *src_port = ntohs(tcp->source);
        *dst_port = ntohs(tcp->dest);
    } else if (ip->protocol == IPPROTO_UDP) {
        if (pkt_len < sizeof(struct ether_header) + ip_hdr_len + sizeof(struct udphdr))
            return -1;
        struct udphdr *udp = (struct udphdr *)transport;
        *src_port = ntohs(udp->source);
        *dst_port = ntohs(udp->dest);
    } else {
        *src_port = 0;
        *dst_port = 0;
    }

    return 0;
}

static void *gc_thread(void *arg) {
    (void)arg;
    while (running) {
        sleep(10);
        flow_table_gc(&g_flow_table);
    }
    return NULL;
}

static void *local_rx_thread(void *arg) {
    struct local_thread_args *args = (struct local_thread_args *)arg;
    struct forwarder *fwd = args->fwd;
    int local_idx = args->local_idx;
    struct xsk_interface *local = &fwd->locals[local_idx];
    int batch_size = local->batch_size;

    void *pkt_ptrs[MAX_BATCH_SIZE];
    uint32_t pkt_lens[MAX_BATCH_SIZE];
    uint64_t addrs[MAX_BATCH_SIZE];

    while (running) {
        int rcvd = interface_recv(local, pkt_ptrs, pkt_lens, addrs, batch_size);
        if (rcvd > 0) {
            int wan_used[MAX_INTERFACES] = {0};

            for (int i = 0; i < rcvd; i++) {
                uint32_t src_ip, dst_ip;
                uint16_t src_port, dst_port;
                uint8_t protocol;

                int wan_idx;
                if (parse_flow(pkt_ptrs[i], pkt_lens[i],
                               &src_ip, &dst_ip, &src_port, &dst_port, &protocol) == 0) {
                    wan_idx = flow_table_get_wan(&g_flow_table,
                                                  src_ip, dst_ip, src_port, dst_port,
                                                  protocol, pkt_lens[i]);
                } else {
                    wan_idx = 0;
                }

                if (encrypt_packet(pkt_ptrs[i], pkt_lens[i]) != 0) {
                    __sync_fetch_and_add(&fwd->total_dropped, 1);
                    continue;
                }

                struct xsk_interface *wan = &fwd->wans[wan_idx];

                if (interface_send_batch(wan, pkt_ptrs[i], pkt_lens[i]) == 0) {
                    __sync_fetch_and_add(&fwd->local_to_wan, 1);
                    wan_used[wan_idx] = 1;
                } else {
                    __sync_fetch_and_add(&fwd->total_dropped, 1);
                }
            }

            for (int w = 0; w < fwd->wan_count; w++) {
                if (wan_used[w])
                    interface_send_flush(&fwd->wans[w]);
            }

            interface_recv_release(local, addrs, rcvd);
        }
    }

    return NULL;
}

static void *wan_rx_thread(void *arg) {
    struct wan_thread_args *args = (struct wan_thread_args *)arg;
    struct forwarder *fwd = args->fwd;
    int wan_idx = args->wan_idx;
    struct xsk_interface *wan = &fwd->wans[wan_idx];
    int batch_size = wan->batch_size;

    void *pkt_ptrs[MAX_BATCH_SIZE];
    uint32_t pkt_lens[MAX_BATCH_SIZE];
    uint64_t addrs[MAX_BATCH_SIZE];

    while (running) {
        int rcvd = interface_recv(wan, pkt_ptrs, pkt_lens, addrs, batch_size);
        if (rcvd > 0) {
            int local_used[MAX_INTERFACES] = {0};

            for (int i = 0; i < rcvd; i++) {
                if (decrypt_packet(pkt_ptrs[i], pkt_lens[i]) != 0) {
                    __sync_fetch_and_add(&fwd->total_dropped, 1);
                    continue;
                }

                uint32_t dest_ip = get_dest_ip(pkt_ptrs[i], pkt_lens[i]);
                if (dest_ip == 0) {
                    __sync_fetch_and_add(&fwd->total_dropped, 1);
                    continue;
                }

                int local_idx = config_find_local_for_ip(fwd->cfg, dest_ip);
                if (local_idx < 0) {
                    __sync_fetch_and_add(&fwd->total_dropped, 1);
                    continue;
                }

                struct xsk_interface *local = &fwd->locals[local_idx];
                struct local_config *local_cfg = &fwd->cfg->locals[local_idx];

                if (interface_send_to_local_batch(local, local_cfg, pkt_ptrs[i], pkt_lens[i], wan_idx) == 0) {
                    __sync_fetch_and_add(&fwd->wan_to_local, 1);
                    local_used[local_idx] = 1;
                } else {
                    __sync_fetch_and_add(&fwd->total_dropped, 1);
                }
            }

            for (int l = 0; l < fwd->local_count; l++) {
                if (local_used[l])
                    interface_send_to_local_flush(&fwd->locals[l], wan_idx);
            }

            interface_recv_release(wan, addrs, rcvd);
        }
    }

    return NULL;
}

int forwarder_init(struct forwarder *fwd, struct app_config *cfg) {
    memset(fwd, 0, sizeof(*fwd));
    fwd->cfg = cfg;

    crypto_enabled = cfg->crypto_enabled;
    if (crypto_enabled) {
        if (packet_crypto_init(&crypto_ctx, cfg->crypto_key, cfg->crypto_iv) != 0) {
            fprintf(stderr, "Failed to initialize AES-128 encryption\n");
            return -1;
        }

        if (cfg->fake_ethertype != 0) {
            packet_crypto_set_fake_ethertype(&crypto_ctx, cfg->fake_ethertype);
            printf("Crypto: ENABLED (zero overhead, fake_ethertype=0x%04X)\n", cfg->fake_ethertype);
        } else {
            printf("Crypto: ENABLED (zero overhead)\n");
        }
    }

    uint32_t window_size = cfg->wans[0].window_size;
    flow_table_init(&g_flow_table, window_size, cfg->wan_count);
    printf("Flow table initialized: window_size=%u bytes, wan_count=%d\n",
           window_size, cfg->wan_count);

    for (int i = 0; i < cfg->local_count; i++) {
        if (interface_init_local(&fwd->locals[i], &cfg->locals[i], cfg->bpf_file) != 0) {
            fprintf(stderr, "Failed to init LOCAL %s\n", cfg->locals[i].ifname);
            goto err_locals;
        }
        fwd->local_count++;
    }

    for (int i = 0; i < cfg->wan_count; i++) {
        if (interface_init_wan_rx(&fwd->wans[i], &cfg->wans[i], "bpf/xdp_wan_redirect.o") != 0) {
            fprintf(stderr, "Failed to init WAN %s\n", cfg->wans[i].ifname);
            goto err_wans;
        }
        fwd->wan_count++;
    }

    return 0;

err_wans:
    for (int j = 0; j < fwd->wan_count; j++)
        interface_cleanup(&fwd->wans[j]);
err_locals:
    for (int j = 0; j < fwd->local_count; j++)
        interface_cleanup(&fwd->locals[j]);
    flow_table_cleanup(&g_flow_table);
    return -1;
}

void forwarder_cleanup(struct forwarder *fwd) {
    if (crypto_enabled) {
        packet_crypto_cleanup(&crypto_ctx);
    }

    flow_table_cleanup(&g_flow_table);

    for (int i = 0; i < fwd->local_count; i++)
        interface_cleanup(&fwd->locals[i]);
    for (int i = 0; i < fwd->wan_count; i++)
        interface_cleanup(&fwd->wans[i]);
}

void forwarder_run(struct forwarder *fwd) {
    pthread_t local_threads[MAX_INTERFACES];
    pthread_t wan_threads[MAX_INTERFACES];
    pthread_t gc_tid;
    struct local_thread_args local_args[MAX_INTERFACES];
    struct wan_thread_args wan_args[MAX_INTERFACES];

    signal(SIGINT, sigint_handler);
    signal(SIGTERM, sigint_handler);

    pthread_create(&gc_tid, NULL, gc_thread, NULL);

    for (int i = 0; i < fwd->local_count; i++) {
        local_args[i].fwd = fwd;
        local_args[i].local_idx = i;
        pthread_create(&local_threads[i], NULL, local_rx_thread, &local_args[i]);
    }

    for (int i = 0; i < fwd->wan_count; i++) {
        wan_args[i].fwd = fwd;
        wan_args[i].wan_idx = i;
        pthread_create(&wan_threads[i], NULL, wan_rx_thread, &wan_args[i]);
    }

    while (running) {
        sleep(1);
    }

    for (int i = 0; i < fwd->local_count; i++)
        pthread_join(local_threads[i], NULL);
    for (int i = 0; i < fwd->wan_count; i++)
        pthread_join(wan_threads[i], NULL);
    pthread_join(gc_tid, NULL);
}

void forwarder_print_stats(struct forwarder *fwd) {
    (void)fwd;
}
