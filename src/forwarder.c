/* XDP forwarder: local <-> WAN, optional L2/L3/L4 crypto, flow-based WAN selection */
#include "../inc/forwarder.h"
#include "../inc/packet_crypto.h"
#include "../inc/flow_table.h"
#include "../inc/fragment.h"
#include "../inc/config.h"
#include <string.h>
#include <signal.h>
#include <pthread.h>
#include <sched.h>
#include <time.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/ethernet.h>

static volatile int running = 1;
static struct packet_crypto_ctx crypto_ctx;
static int crypto_enabled = 0;
static int crypto_layer = 0;
static struct flow_table g_flow_table;

struct queue_thread_args {
    struct forwarder *fwd;
    int iface_idx;
    int queue_idx;
    int tx_queue_base;
    int core_id;
    int wan_worker_index;
};

static void pin_thread_to_core(int core_id) {
    if (core_id < 0) return;
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(core_id, &cpuset);
    (void)pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
}

static inline void drop(struct forwarder *fwd, uint64_t *detail) {
    __sync_fetch_and_add(&fwd->total_dropped, 1);
    if (detail) __sync_fetch_and_add(detail, 1);
}

static uint32_t get_dest_ip(void *pkt_data, uint32_t pkt_len) {
    if (pkt_len < sizeof(struct ether_header) + sizeof(struct iphdr)) return 0;
    struct ether_header *eth = (struct ether_header *)pkt_data;
    if (ntohs(eth->ether_type) != ETHERTYPE_IP) return 0;
    return ((struct iphdr *)(eth + 1))->daddr;
}

static int parse_flow(void *pkt_data, uint32_t pkt_len,
                     uint32_t *src_ip, uint32_t *dst_ip, uint16_t *src_port, uint16_t *dst_port, uint8_t *protocol) {
    if (pkt_len < sizeof(struct ether_header) + sizeof(struct iphdr)) return -1;
    struct ether_header *eth = (struct ether_header *)pkt_data;
    if (ntohs(eth->ether_type) != ETHERTYPE_IP) return -1;
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    *src_ip = ip->saddr;
    *dst_ip = ip->daddr;
    *protocol = ip->protocol;
    int ip_hdr_len = ip->ihl * 4;
    uint8_t *transport = (uint8_t *)ip + ip_hdr_len;
    if (ip->protocol == IPPROTO_TCP) {
        if (pkt_len < (uint32_t)(sizeof(struct ether_header) + ip_hdr_len + sizeof(struct tcphdr))) return -1;
        *src_port = ntohs(((struct tcphdr *)transport)->source);
        *dst_port = ntohs(((struct tcphdr *)transport)->dest);
    } else if (ip->protocol == IPPROTO_UDP) {
        if (pkt_len < (uint32_t)(sizeof(struct ether_header) + ip_hdr_len + sizeof(struct udphdr))) return -1;
        *src_port = ntohs(((struct udphdr *)transport)->source);
        *dst_port = ntohs(((struct udphdr *)transport)->dest);
    } else {
        *src_port = *dst_port = 0;
    }
    return 0;
}

static inline uint32_t flow_hash_tq(uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port, uint8_t protocol) {
    uint32_t h = src_ip ^ dst_ip;
    h ^= ((uint32_t)src_port << 16) | dst_port;
    h ^= protocol;
    h ^= (h >> 16); h *= 0x85ebca6b; h ^= (h >> 13); h *= 0xc2b2ae35; h ^= (h >> 16);
    return h;
}

static void apply_wan_mac(struct xsk_interface *wan, uint8_t *pkt) {
    memcpy(pkt, wan->dst_mac, 6);
    memcpy(pkt + 6, wan->src_mac, 6);
}

/* Send two fragments to WAN; update stats and flow_table bytes if wire_total > orig_len. */
static void send_two_frags(struct forwarder *fwd, struct xsk_interface *wan, int tq, int wan_idx, int *wan_used,
                           uint8_t *f1, uint32_t f1_len, uint8_t *f2, uint32_t f2_len, uint32_t orig_len,
                           uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port, uint8_t protocol) {
    apply_wan_mac(wan, f1);
    apply_wan_mac(wan, f2);
    uint32_t wire_total = f1_len + f2_len;
    if (wire_total > orig_len)
        flow_table_add_bytes(&g_flow_table, src_ip, dst_ip, src_port, dst_port, protocol, wire_total - orig_len);
    if (interface_send_batch_queue(wan, tq, f1, f1_len) == 0) {
        __sync_fetch_and_add(&fwd->local_to_wan, 1);
        wan_used[wan_idx] = 1;
    } else drop(fwd, NULL);
    if (interface_send_batch_queue(wan, tq, f2, f2_len) == 0)
        __sync_fetch_and_add(&fwd->local_to_wan, 1);
    else drop(fwd, NULL);
}

static void *gc_thread(void *arg) {
    (void)arg;
    while (running) {
        sleep(60);
        flow_table_gc(&g_flow_table);
    }
    return NULL;
}

static void *local_queue_thread(void *arg) {
    struct queue_thread_args *args = (struct queue_thread_args *)arg;
    struct forwarder *fwd = args->fwd;
    pin_thread_to_core(args->core_id);
    int local_idx = args->iface_idx, queue_idx = args->queue_idx, tx_base = args->tx_queue_base;
    struct xsk_interface *local = &fwd->locals[local_idx];
    void *pkt_ptrs[MAX_BATCH_SIZE];
    uint32_t pkt_lens[MAX_BATCH_SIZE];
    uint64_t addrs[MAX_BATCH_SIZE];
    uint8_t frag1_buf[2048], frag2_buf[2048];
    int wan_used[MAX_INTERFACES] = {0};
    int wan_tx_q[MAX_INTERFACES];

    for (int w = 0; w < fwd->wan_count; w++)
        wan_tx_q[w] = tx_base % fwd->wans[w].queue_count;

    while (running) {
        int rcvd = interface_recv_single_queue(local, queue_idx, pkt_ptrs, pkt_lens, addrs, local->batch_size);
        if (rcvd <= 0) continue;

        for (int i = 0; i < rcvd; i++) {
            uint32_t src_ip, dst_ip;
            uint16_t src_port, dst_port;
            uint8_t protocol;
            int wan_idx = (parse_flow(pkt_ptrs[i], pkt_lens[i], &src_ip, &dst_ip, &src_port, &dst_port, &protocol) == 0)
                ? flow_table_get_wan(&g_flow_table, src_ip, dst_ip, src_port, dst_port, protocol, pkt_lens[i]) : 0;
            struct xsk_interface *wan = &fwd->wans[wan_idx];
            int tq = wan_tx_q[wan_idx];
            uint8_t *pkt = (uint8_t *)pkt_ptrs[i];

            int sent = 0;
            if (crypto_enabled && crypto_layer == 3 && frag_need_split(pkt_lens[i])) {
                apply_wan_mac(wan, pkt);
                uint32_t f1_len = 0, f2_len = 0;
                if (frag_split_and_encrypt(&crypto_ctx, pkt, pkt_lens[i], frag1_buf, &f1_len, frag2_buf, &f2_len) == 0) {
                    send_two_frags(fwd, wan, tq, wan_idx, wan_used, frag1_buf, f1_len, frag2_buf, f2_len, pkt_lens[i],
                                  src_ip, dst_ip, src_port, dst_port, protocol);
                    sent = 1;
                } else drop(fwd, NULL);
            } else if (crypto_enabled && crypto_layer == 2 && frag_need_split_l2(pkt_lens[i])) {
                apply_wan_mac(wan, pkt);
                uint32_t f1_len = 0, f2_len = 0;
                if (frag_split_and_encrypt_l2(&crypto_ctx, pkt, pkt_lens[i], frag1_buf, &f1_len, frag2_buf, &f2_len) == 0) {
                    send_two_frags(fwd, wan, tq, wan_idx, wan_used, frag1_buf, f1_len, frag2_buf, f2_len, pkt_lens[i],
                                  src_ip, dst_ip, src_port, dst_port, protocol);
                    sent = 1;
                } else drop(fwd, NULL);
            }

            if (!sent) {
                if (crypto_enabled && crypto_layer == 2) apply_wan_mac(wan, pkt);
                uint32_t len = pkt_lens[i];
                if (crypto_enabled) {
                    int nl = packet_encrypt(&crypto_ctx, pkt, len);
                    if (nl < 0) { drop(fwd, NULL); continue; }
                    len = (uint32_t)nl;
                }
                if (interface_send_batch_queue(wan, tq, pkt, len) == 0) {
                    __sync_fetch_and_add(&fwd->local_to_wan, 1);
                    wan_used[wan_idx] = 1;
                } else drop(fwd, NULL);
            }
        }

        for (int w = 0; w < fwd->wan_count; w++)
            if (wan_used[w]) interface_send_flush_queue(&fwd->wans[w], wan_tx_q[w]);
        interface_recv_release_single_queue(local, queue_idx, addrs, rcvd);
    }
    free(args);
    return NULL;
}

static void sigint_handler(int sig) { (void)sig; running = 0; }

static int decrypt_packet(void *pkt_data, uint32_t *pkt_len) {
    if (!crypto_enabled) return 0;
    int new_len = packet_decrypt(&crypto_ctx, (uint8_t *)pkt_data, *pkt_len);
    if (new_len < 0) return -1;
    *pkt_len = (uint32_t)new_len;
    return 0;
}

static int do_decrypt(struct forwarder *fwd, struct frag_table *frag_tbl, uint8_t *pkt, uint32_t *pkt_len,
                      uint8_t *reassemble_buf, uint8_t **out_pkt, uint32_t *out_len) {
    uint16_t frag_pkt_id; uint8_t frag_index;
    if (crypto_enabled && crypto_layer == 3 && frag_tbl && frag_is_fragment(pkt, *pkt_len, &frag_pkt_id, &frag_index)) {
        int dec_len = frag_decrypt_fragment(&crypto_ctx, pkt, *pkt_len, &frag_pkt_id, &frag_index);
        if (dec_len < 0) { drop(fwd, NULL); return -1; }
        *pkt_len = (uint32_t)dec_len;
        uint32_t reasm_len = 0;
        int ret = frag_try_reassemble(frag_tbl, pkt, *pkt_len, frag_pkt_id, frag_index, reassemble_buf, &reasm_len);
        if (ret == 0) return 0;
        if (ret == 1) { *out_pkt = reassemble_buf; *out_len = reasm_len; return 1; }
        drop(fwd, NULL); return -1;
    }
    if (decrypt_packet(pkt, pkt_len) != 0) { drop(fwd, NULL); return -1; }
    *out_pkt = pkt; *out_len = *pkt_len;
    if (crypto_enabled && crypto_layer == 2 && frag_tbl) {
        uint16_t l2_pkt_id; uint8_t l2_frag_index;
        if (frag_is_fragment_l2(pkt, *pkt_len, &l2_pkt_id, &l2_frag_index)) {
            uint32_t reasm_len = 0;
            int ret = frag_try_reassemble_l2(frag_tbl, pkt, *pkt_len, l2_pkt_id, l2_frag_index, reassemble_buf, &reasm_len);
            if (ret == 0) return 0;
            if (ret == 1) { *out_pkt = reassemble_buf; *out_len = reasm_len; return 1; }
            drop(fwd, NULL); return -1;
        }
    }
    return 1;
}

static void *wan_queue_thread(void *arg) {
    struct queue_thread_args *args = (struct queue_thread_args *)arg;
    struct forwarder *fwd = args->fwd;
    pin_thread_to_core(args->core_id);
    int wan_idx = args->iface_idx, queue_idx = args->queue_idx, tx_base = args->tx_queue_base;
    struct xsk_interface *wan = &fwd->wans[wan_idx];
    void *pkt_ptrs[MAX_BATCH_SIZE];
    uint32_t pkt_lens[MAX_BATCH_SIZE];
    uint64_t addrs[MAX_BATCH_SIZE];
    uint8_t reassemble_buf[4096];
    uint32_t local_used_queues[MAX_INTERFACES] = {0};
    struct frag_table *frag_tbl = NULL;
    int gc_counter = 0;
    if (crypto_enabled && (crypto_layer == 3 || crypto_layer == 2)) {
        frag_tbl = calloc(1, sizeof(struct frag_table));
        if (frag_tbl) frag_table_init(frag_tbl);
    }
    uint64_t rate_bytes = 0;
    double rate_next = 0;
    uint64_t my_rate_bps = (fwd->cfg->local_rate_limit_mbps > 0 && fwd->wan_count > 0)
        ? (fwd->cfg->local_rate_limit_mbps * 1000000ULL / 8) / (uint64_t)fwd->wan_count : 0;

    while (running) {
        int rcvd = interface_recv_single_queue(wan, queue_idx, pkt_ptrs, pkt_lens, addrs, wan->batch_size);
        if (rcvd <= 0) continue;

        for (int i = 0; i < rcvd; i++) {
            uint8_t *pkt = (uint8_t *)pkt_ptrs[i];
            uint32_t pkt_len = pkt_lens[i];
            uint8_t *final_pkt = pkt;
            uint32_t final_len = pkt_len;
            int dr = do_decrypt(fwd, frag_tbl, pkt, &pkt_len, reassemble_buf, &final_pkt, &final_len);
            if (dr <= 0) continue;
            if (dr == 0) continue;

            uint32_t dest_ip = get_dest_ip(final_pkt, final_len);
            if (dest_ip == 0) { drop(fwd, &fwd->dropped_bad_ip); continue; }
            int local_idx = config_find_local_for_ip(fwd->cfg, dest_ip);
            if (local_idx < 0) { drop(fwd, &fwd->dropped_no_local_match); continue; }

            struct xsk_interface *local_iface = &fwd->locals[local_idx];
            struct local_config *local_cfg = &fwd->cfg->locals[local_idx];
            int nq = local_iface->queue_count > 0 ? local_iface->queue_count : 1;
            uint32_t src_ip, dst_ip; uint16_t src_port, dst_port; uint8_t protocol;
            int tq = (parse_flow(final_pkt, final_len, &src_ip, &dst_ip, &src_port, &dst_port, &protocol) == 0)
                ? (int)(flow_hash_tq(src_ip, dst_ip, src_port, dst_port, protocol) % (uint32_t)nq)
                : (args->wan_worker_index >= 0 ? args->wan_worker_index % nq : tx_base % nq);

            int send_ok = 0;
            for (int r = 0; r < 32 && !send_ok; r++) {
                if (interface_send_to_local_batch_queue(local_iface, tq, local_cfg, final_pkt, final_len) == 0)
                    send_ok = 1;
                else for (volatile int s = 0; s < 200; s++) (void)s;
            }
            if (send_ok) {
                __sync_fetch_and_add(&fwd->wan_to_local, 1);
                if (tq < 32) local_used_queues[local_idx] |= (1u << tq);
                if (my_rate_bps > 0) {
                    struct timespec ts;
                    clock_gettime(CLOCK_MONOTONIC, &ts);
                    double now = ts.tv_sec + ts.tv_nsec / 1e9;
                    if (rate_next == 0) rate_next = now + 1.0;
                    if (now >= rate_next) { rate_bytes = 0; rate_next = now + 1.0; }
                    rate_bytes += final_len;
                    if (rate_bytes > my_rate_bps) {
                        double sl = rate_next - now;
                        if (sl > 0 && sl < 2.0) usleep((useconds_t)(sl * 1e6));
                        rate_bytes = final_len;
                        clock_gettime(CLOCK_MONOTONIC, &ts);
                        rate_next = ts.tv_sec + ts.tv_nsec / 1e9 + 1.0;
                    }
                }
            } else {
                drop(fwd, &fwd->dropped_local_tx_fail);
                if (tq < FORWARDER_MAX_LOCAL_QUEUES) __sync_fetch_and_add(&fwd->dropped_local_tx_fail_by_queue[tq], 1);
            }
        }
        for (int l = 0; l < fwd->local_count; l++)
            for (int q = 0; q < fwd->locals[l].queue_count && q < 32; q++)
                if (local_used_queues[l] & (1u << q)) interface_send_to_local_flush_queue(&fwd->locals[l], q);
        interface_recv_release_single_queue(wan, queue_idx, addrs, rcvd);
        if (frag_tbl && ++gc_counter >= 1000) { frag_table_gc(frag_tbl); gc_counter = 0; }
    }
    if (frag_tbl) free(frag_tbl);
    free(args);
    return NULL;
}

int forwarder_init(struct forwarder *fwd, struct app_config *cfg) {
    memset(fwd, 0, sizeof(*fwd));
    fwd->cfg = cfg;
    crypto_enabled = cfg->crypto_enabled;
    crypto_layer = cfg->encrypt_layer;
    if (crypto_enabled) {
        packet_crypto_set_aes_bits(cfg->aes_bits);
        if (packet_crypto_init(&crypto_ctx, cfg->crypto_key) != 0) {
            fprintf(stderr, "Failed to init AES-%d\n", cfg->aes_bits);
            return -1;
        }
        packet_crypto_set_encrypt_layer(cfg->encrypt_layer);
        packet_crypto_set_mode(cfg->crypto_mode);
        packet_crypto_set_nonce_size(cfg->nonce_size);
        if (crypto_layer == 2) packet_crypto_set_ethertype(cfg->fake_ethertype_ipv4, cfg->fake_ethertype_ipv6);
        if (crypto_layer == 2 || crypto_layer == 3)
            packet_crypto_set_fake_protocol(cfg->fake_protocol != 0 ? cfg->fake_protocol : 99);
    }
    if (!crypto_enabled) {
        for (int i = 0; i < cfg->local_count; i++) {
            if (cfg->locals[i].queue_count <= 1) {
                interface_set_queue_count(cfg->locals[i].ifname, 4);
                int hwq = interface_get_queue_count(cfg->locals[i].ifname);
                if (hwq > 1) cfg->locals[i].queue_count = hwq;
            }
        }
        for (int i = 0; i < cfg->wan_count; i++) {
            if (cfg->wans[i].queue_count <= 1) {
                int hwq = interface_get_queue_count(cfg->wans[i].ifname);
                if (hwq > 1) cfg->wans[i].queue_count = hwq;
            }
        }
    }
    flow_table_init(&g_flow_table, cfg->wans[0].window_size, cfg->wan_count);
    for (int i = 0; i < cfg->local_count; i++)
        interface_set_queue_count(cfg->locals[i].ifname, cfg->locals[i].queue_count);
    for (int i = 0; i < cfg->wan_count; i++)
        interface_set_queue_count(cfg->wans[i].ifname, cfg->wans[i].queue_count);
    for (int i = 0; i < cfg->local_count; i++) {
        if (interface_init_local(&fwd->locals[i], &cfg->locals[i], cfg->bpf_file) != 0) {
            fprintf(stderr, "Failed to init LOCAL %s\n", cfg->locals[i].ifname);
            goto err;
        }
        fwd->local_count++;
    }
    for (int i = 0; i < cfg->wan_count; i++) {
        uint16_t w4 = (crypto_enabled && crypto_layer == 2) ? cfg->fake_ethertype_ipv4 : 0;
        uint16_t w6 = (crypto_enabled && crypto_layer == 2) ? cfg->fake_ethertype_ipv6 : 0;
        if (interface_init_wan_rx(&fwd->wans[i], &cfg->wans[i], "bpf/xdp_wan_redirect.o", w4, w6) != 0) {
            fprintf(stderr, "Failed to init WAN %s\n", cfg->wans[i].ifname);
            goto err;
        }
        fwd->wan_count++;
    }
    return 0;
err:
    for (int j = 0; j < fwd->wan_count; j++) interface_cleanup(&fwd->wans[j]);
    for (int j = 0; j < fwd->local_count; j++) interface_cleanup(&fwd->locals[j]);
    flow_table_cleanup(&g_flow_table);
    return -1;
}

void forwarder_cleanup(struct forwarder *fwd) {
    if (crypto_enabled) packet_crypto_cleanup(&crypto_ctx);
    flow_table_cleanup(&g_flow_table);
    for (int i = 0; i < fwd->local_count; i++) interface_cleanup(&fwd->locals[i]);
    for (int i = 0; i < fwd->wan_count; i++) interface_cleanup(&fwd->wans[i]);
}

void forwarder_run(struct forwarder *fwd) {
    signal(SIGINT, sigint_handler);
    signal(SIGTERM, sigint_handler);
    int total_local_queues = 0, total_wan_queues = 0;
    for (int i = 0; i < fwd->local_count; i++) total_local_queues += fwd->locals[i].queue_count;
    for (int i = 0; i < fwd->wan_count; i++) total_wan_queues += fwd->wans[i].queue_count;
    int total_threads = total_local_queues + total_wan_queues;
    pthread_t *threads = calloc(total_threads, sizeof(pthread_t));
    struct queue_thread_args *args = calloc(total_threads, sizeof(struct queue_thread_args));
    if (!threads || !args) { fprintf(stderr, "Failed to alloc thread arrays\n"); free(threads); free(args); return; }
    pthread_t gc_tid;
    pthread_create(&gc_tid, NULL, gc_thread, NULL);
    int thread_idx = 0;
    for (int i = 0; i < fwd->local_count; i++)
        for (int q = 0; q < fwd->locals[i].queue_count; q++) {
            args[thread_idx] = (struct queue_thread_args){ .fwd = fwd, .iface_idx = i, .queue_idx = q, .tx_queue_base = q, .core_id = -1, .wan_worker_index = -1 };
            pthread_create(&threads[thread_idx], NULL, local_queue_thread, &args[thread_idx]);
            thread_idx++;
        }
    for (int i = 0; i < fwd->wan_count; i++)
        for (int q = 0; q < fwd->wans[i].queue_count; q++) {
            args[thread_idx] = (struct queue_thread_args){ .fwd = fwd, .iface_idx = i, .queue_idx = q, .tx_queue_base = q, .core_id = -1, .wan_worker_index = thread_idx - total_local_queues };
            pthread_create(&threads[thread_idx], NULL, wan_queue_thread, &args[thread_idx]);
            thread_idx++;
        }
    while (running) sleep(1);
    for (int i = 0; i < total_threads; i++) pthread_join(threads[i], NULL);
    pthread_join(gc_tid, NULL);
    free(threads);
    free(args);
}

void forwarder_print_stats(struct forwarder *fwd) {
    if (!fwd) return;
    int nq = (fwd->local_count > 0 && fwd->locals[0].queue_count <= FORWARDER_MAX_LOCAL_QUEUES) ? fwd->locals[0].queue_count : 1;
    if (nq <= 0) nq = 1;
    uint64_t tx_wait = 0;
    for (int i = 0; i < fwd->local_count; i++)
        for (int q = 0; q < fwd->locals[i].queue_count && q < MAX_QUEUES; q++)
            tx_wait += fwd->locals[i].queues[q].tx_wait_loops;
    fprintf(stdout, "[STATS] local_to_wan=%lu wan_to_local=%lu total_dropped=%lu dropped_bad_ip=%lu dropped_no_local_match=%lu dropped_local_tx_fail=%lu",
            fwd->local_to_wan, fwd->wan_to_local, fwd->total_dropped, fwd->dropped_bad_ip, fwd->dropped_no_local_match, fwd->dropped_local_tx_fail);
    for (int i = 0; i < nq && i < FORWARDER_MAX_LOCAL_QUEUES; i++)
        fprintf(stdout, " q%d=%lu", i, (unsigned long)fwd->dropped_local_tx_fail_by_queue[i]);
    fprintf(stdout, " tx_wait_loops=%lu\n", (unsigned long)tx_wait);
}
