#include "../inc/forwarder.h"
#include "../inc/packet_crypto.h"
#include "../inc/flow_table.h"
#include "../inc/config.h"
#include "../inc/crypto_layer2.h"
#include "../inc/crypto_layer3.h"
#include "../inc/crypto_layer4.h"
#include "../inc/wan_arp.h"
#include "../inc/crypto_policy_utils.h"
#include "../inc/crypto_dispatch.h"
#include <signal.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <time.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netpacket/packet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <net/if_arp.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>


#define NUM_WORKERS 1
#define WORKER_RING_SIZE 4096

static volatile int running = 1;

static struct packet_crypto_ctx crypto_ctx;
static int crypto_enabled = 0;
static int crypto_layer = 0;

static struct flow_table g_flow_table;


static struct packet_crypto_ctx g_policy_crypto_ctx[MAX_CRYPTO_POLICIES];
static int g_policy_crypto_ctx_ready[MAX_CRYPTO_POLICIES];


static struct app_config *g_cfg_ptr = NULL;

static inline uint32_t clamp_u32(uint32_t v, uint32_t lo, uint32_t hi) {
    if (v < lo) return lo;
    if (v > hi) return hi;
    return v;
}

static void compute_profile_weighted_wan_windows(const struct app_config *cfg,
                                                 uint32_t *out_wan_window_sizes,
                                                 int max_wans) {
    if (!cfg || !out_wan_window_sizes || max_wans <= 0)
        return;

    /* Base window (bytes) that will be scaled by BE % weight.
     * Keeping a large base reduces switching frequency (more stable, less reorder).
     */
    const uint32_t base_kb = WAN_REORDER_WINDOW_KB;
    const uint32_t base_bytes = base_kb * 1024U;

    /* Don't let low-weight WAN get too tiny (prevents rapid switching). */
    const uint32_t min_kb = 512; /* 512KB */
    const uint32_t min_bytes = min_kb * 1024U;

    for (int pi = 0; pi < cfg->profile_count; pi++) {
        const struct profile_config *p = &cfg->profiles[pi];
        if (!p->enabled || p->wan_count <= 0)
            continue;

        int sumw = 0;
        for (int i = 0; i < p->wan_count; i++) {
            int w = p->wan_bandwidth_weight[i];
            if (w > 0)
                sumw += w;
        }
        if (sumw <= 0)
            continue; /* no explicit weights -> keep default windows */

        for (int i = 0; i < p->wan_count; i++) {
            int wan_idx = p->wan_indices[i];
            int w = p->wan_bandwidth_weight[i];
            if (wan_idx < 0 || wan_idx >= max_wans)
                continue;
            if (w <= 0)
                continue; /* weight=0 means excluded when any_weight is enabled */

            uint64_t scaled = ((uint64_t)base_bytes * (uint64_t)w) / (uint64_t)sumw;
            uint32_t win = (scaled > (uint64_t)UINT32_MAX) ? UINT32_MAX : (uint32_t)scaled;
            win = clamp_u32(win, min_bytes, base_bytes);
            out_wan_window_sizes[wan_idx] = win;
        }
    }
}

static int select_wan_idx_for_packet(struct forwarder *fwd,
                                     uint32_t src_ip, uint32_t dst_ip,
                                     uint16_t src_port, uint16_t dst_port,
                                     uint8_t protocol, uint32_t pkt_len) {

    if (fwd && fwd->cfg && fwd->cfg->profile_count > 0) {
        int profile_idx = config_select_profile_for_flow(fwd->cfg, src_ip, dst_ip);
        if (profile_idx >= 0 && profile_idx < fwd->cfg->profile_count) {
            struct profile_config *p = &fwd->cfg->profiles[profile_idx];
            if (p->wan_count > 1) {
                int allowed[MAX_INTERFACES];
                int weights[MAX_INTERFACES];
                int n = 0;
                int any_weight = 0;
                for (int i = 0; i < p->wan_count; i++) {
                    if (p->wan_bandwidth_weight[i] > 0)
                        any_weight = 1;
                }
                for (int i = 0; i < p->wan_count && n < MAX_INTERFACES; i++) {
                    int wi = p->wan_indices[i];
                    if (wi < 0 || wi >= fwd->cfg->wan_count)
                        continue;
                    allowed[n] = wi;
                    if (any_weight && p->wan_bandwidth_weight[i] <= 0)
                        continue;
                    weights[n] = p->wan_bandwidth_weight[i];
                    n++;
                }
                if (n == 1)
                    return allowed[0];
                if (n > 1) {
                    const int *wp = any_weight ? weights : NULL;
                    return flow_table_get_wan_profile(&g_flow_table,
                                                      src_ip, dst_ip,
                                                      src_port, dst_port,
                                                      protocol, pkt_len,
                                                      allowed, n, wp);
                }
            } else if (p->wan_count == 1) {
                int wi = p->wan_indices[0];
                if (wi >= 0 && wi < fwd->cfg->wan_count)
                    return wi;
            }
        }
    }

    return flow_table_get_wan(&g_flow_table,
                               src_ip, dst_ip, src_port, dst_port,
                               protocol, pkt_len);
}

static const struct crypto_policy *select_crypto_policy_for_packet(struct forwarder *fwd,
                                                                     uint32_t src_ip, uint32_t dst_ip,
                                                                     uint16_t src_port, uint16_t dst_port,
                                                                     uint8_t protocol) {
    if (!fwd || !fwd->cfg)
        return NULL;
    return crypto_select_policy_for_flow(fwd->cfg,
                                          src_ip, dst_ip,
                                          src_port, dst_port,
                                          protocol);
}

static void apply_default_crypto_params(struct forwarder *fwd) {
    if (!fwd || !fwd->cfg)
        return;
    crypto_apply_default_from_cfg(fwd->cfg);
}

static void apply_crypto_params_from_policy(const struct crypto_policy *cp) {
    if (!cp)
        return;
    crypto_apply_from_policy(cp);
}

static int encrypt_packet_with_ctx(struct packet_crypto_ctx *ctx,
                                     void *pkt_data, uint32_t *pkt_len) {
    if (!crypto_enabled || !ctx) return 0;
    int new_len = packet_encrypt(ctx, (uint8_t *)pkt_data, *pkt_len);
    if (new_len < 0)
        return -1;
    *pkt_len = (uint32_t)new_len;
    return 0;
}

static struct arp_cache g_arp[MAX_INTERFACES];
static struct arp_cache g_wan_arp[MAX_INTERFACES];
static int g_arp_inited = 0;

static int set_wan_l2_addrs(struct forwarder *fwd, int wan_idx, uint8_t *pkt) {
    if (!fwd || wan_idx < 0 || wan_idx >= fwd->wan_count)
        return -1;
    return wan_rewrite_dest_mac(&g_wan_arp[wan_idx],
                                 &fwd->cfg->wans[wan_idx],
                                 &fwd->wans[wan_idx],
                                 pkt);
}

static void log_wan_peer_mac(struct forwarder *fwd, int wan_idx) {
    if (!fwd || wan_idx < 0 || wan_idx >= fwd->wan_count)
        return;
    wan_log_peer_mac(&g_wan_arp[wan_idx], fwd->wans[wan_idx].ifname, &fwd->cfg->wans[wan_idx]);
}

struct packet_job {
    struct forwarder *fwd;
    int local_idx;
    int queue_idx;
    int tx_queue_base;
    void *pkt_ptr;
    uint32_t pkt_len;
    uint64_t addr;
};

struct worker_ring {
    struct packet_job jobs[WORKER_RING_SIZE];
    uint32_t head;
    uint32_t tail;
    pthread_mutex_t lock;
} __attribute__((aligned(64)));

static struct worker_ring g_worker_rings[NUM_WORKERS];
static uint32_t g_dispatch_counter = 0;

struct queue_thread_args {
    struct forwarder *fwd;
    int iface_idx;
    int queue_idx;
    int tx_queue_base;
    int core_id;
    int wan_worker_index;
    int worker_id;
};

static void pin_thread_to_core(int core_id) {
    (void)core_id;

    core_id = 0;

    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(core_id, &cpuset);
    (void)pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
}

static int encrypt_packet(void *pkt_data, uint32_t *pkt_len) {
    if (!crypto_enabled) return 0;

    if (g_cfg_ptr) {
        packet_crypto_set_mode(g_cfg_ptr->crypto_mode);
        packet_crypto_set_aes_bits(g_cfg_ptr->aes_bits);
        packet_crypto_set_nonce_size(g_cfg_ptr->nonce_size);
        if (g_cfg_ptr->encrypt_layer == 3)
            packet_crypto_set_fake_protocol((uint8_t)(g_cfg_ptr->fake_protocol & 0xFF));
        packet_crypto_set_policy_id(0);
    }

    int new_len = packet_encrypt(&crypto_ctx, (uint8_t *)pkt_data, *pkt_len);
    if (new_len < 0) {
        return -1;
    }
    *pkt_len = (uint32_t)new_len;
    return 0;
}

static int decrypt_packet(void *pkt_data, uint32_t *pkt_len) {
    if (!crypto_enabled) return 0;

    if (g_cfg_ptr) {
        packet_crypto_set_mode(g_cfg_ptr->crypto_mode);
        packet_crypto_set_aes_bits(g_cfg_ptr->aes_bits);
        packet_crypto_set_nonce_size(g_cfg_ptr->nonce_size);
        if (g_cfg_ptr->encrypt_layer == 3)
            packet_crypto_set_fake_protocol((uint8_t)(g_cfg_ptr->fake_protocol & 0xFF));
        packet_crypto_set_policy_id(0);
    }

    int new_len = packet_decrypt(&crypto_ctx, (uint8_t *)pkt_data, *pkt_len);
    if (new_len < 0) {
        return -1;
    }
    *pkt_len = (uint32_t)new_len;
    return 0;
}

static int decrypt_packet_auto_l2(struct forwarder *fwd,
                                  uint8_t *pkt, uint32_t *pkt_len,
                                  uint8_t *scratch, size_t scratch_sz) {
    if (!crypto_enabled || !fwd || !fwd->cfg || !pkt || !pkt_len)
        return -1;


    uint8_t pkt_marker = pkt[12];
    uint16_t fake_ipv4 = packet_crypto_get_fake_ethertype_ipv4();
    uint16_t fake_ipv6 = packet_crypto_get_fake_ethertype_ipv6();
    if (!((fake_ipv4 && pkt_marker == (uint8_t)(fake_ipv4 >> 8)) ||
          (fake_ipv6 && pkt_marker == (uint8_t)(fake_ipv6 >> 8)))) {
        return 0;
    }

    if (fwd->cfg->policy_count <= 0) {
        apply_default_crypto_params(fwd);
        int new_len = packet_decrypt(&crypto_ctx, pkt, *pkt_len);
        if (new_len < 0) return -1;
        *pkt_len = (uint32_t)new_len;
        return 0;
    }


    uint8_t policy_id = (uint8_t)(pkt[13] & 0x7F);

    for (int pi = 0; pi < fwd->cfg->policy_count && pi < MAX_CRYPTO_POLICIES; pi++) {
        const struct crypto_policy *cp = &fwd->cfg->policies[pi];
        if (!cp || cp->action != POLICY_ACTION_ENCRYPT_L2)
            continue;
        if (!g_policy_crypto_ctx_ready[pi])
            continue;
        if ( (uint8_t)(cp->id & 0x7F) != policy_id)
            continue;

        apply_crypto_params_from_policy(cp);
        int new_len = packet_decrypt(&g_policy_crypto_ctx[pi], pkt, *pkt_len);
        if (new_len < 0)
            return -1;
        *pkt_len = (uint32_t)new_len;
        return 0;
    }


    return -1;
}


static int l4_extract_policy_id_ipv4(uint8_t *pkt, uint32_t pkt_len,
                                       uint8_t *policy_id_out, int *nonce_size_out) {
    if (!pkt || !policy_id_out || !nonce_size_out)
        return -1;


    return crypto_l4_extract_policy_id_ipv4(pkt, pkt_len, policy_id_out, nonce_size_out);
}

static int l3_extract_policy_id(uint8_t *pkt, uint32_t pkt_len,
                                uint8_t *policy_id_out) {
    if (!pkt || !policy_id_out || pkt_len < 14 + 20)
        return -1;


    return crypto_l3_extract_policy_id(pkt, pkt_len, policy_id_out);
}

static int decrypt_packet_auto_by_action(struct forwarder *fwd,
                                           uint8_t *pkt, uint32_t *pkt_len,
                                           int action_layer,
                                           uint8_t *scratch, size_t scratch_sz) {
    if (!crypto_enabled || !fwd || !fwd->cfg || !pkt || !pkt_len)
        return -1;

    struct crypto_dispatch_ctx dctx = {
        .base_ctx = &crypto_ctx,
        .per_policy_ctx = g_policy_crypto_ctx,
        .per_policy_ready = g_policy_crypto_ctx_ready
    };
    return crypto_decrypt_packet_auto_by_action(crypto_enabled, fwd->cfg, &dctx,
                                                action_layer, pkt, pkt_len,
                                                scratch, scratch_sz);
}


static void sigint_handler(int sig) {
    (void)sig;
    running = 0;
}

static uint32_t get_dest_ip(void *pkt_data, uint32_t pkt_len) {
    /* Must respect possible VLAN/extra L2 headers; don't assume Ethernet+IPv4 is fixed at offset 14. */
    uint8_t *pkt = (uint8_t *)pkt_data;
    int l3_off = crypto_eth_ipv4_offset(pkt, pkt_len);
    if (l3_off < 0)
        return 0;
    if (pkt_len < (uint32_t)(l3_off + sizeof(struct iphdr)))
        return 0;
    struct iphdr *ip = (struct iphdr *)(pkt + l3_off);
    return ip->daddr; /* already in network byte order */
}

static int parse_flow(void *pkt_data, uint32_t pkt_len,
                      uint32_t *src_ip, uint32_t *dst_ip,
                      uint16_t *src_port, uint16_t *dst_port,
                      uint8_t *protocol) {
    uint8_t *pkt = (uint8_t *)pkt_data;
    int l3_off = crypto_eth_ipv4_offset(pkt, pkt_len);
    if (l3_off < 0)
        return -1;
    if (pkt_len < (uint32_t)(l3_off + 20))
        return -1;

    struct iphdr *ip = (struct iphdr *)(pkt + l3_off);
    *src_ip = ip->saddr;
    *dst_ip = ip->daddr;
    *protocol = ip->protocol;

    int ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < 20)
        return -1;
    uint8_t *transport = pkt + l3_off + ip_hdr_len;

    if (ip->protocol == IPPROTO_TCP) {
        if (pkt_len < (uint32_t)(l3_off + ip_hdr_len + (int)sizeof(struct tcphdr)))
            return -1;
        struct tcphdr *tcp = (struct tcphdr *)transport;
        *src_port = ntohs(tcp->source);
        *dst_port = ntohs(tcp->dest);
    } else if (ip->protocol == IPPROTO_UDP) {
        if (pkt_len < (uint32_t)(l3_off + ip_hdr_len + (int)sizeof(struct udphdr)))
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

static inline uint32_t flow_hash_local_tq(uint32_t src_ip, uint32_t dst_ip,
                                          uint16_t src_port, uint16_t dst_port,
                                          uint8_t protocol) {
    uint32_t h = src_ip ^ dst_ip;
    h ^= ((uint32_t)src_port << 16) | dst_port;
    h ^= protocol;
    h ^= (h >> 16);
    h *= 0x85ebca6b;
    h ^= (h >> 13);
    h *= 0xc2b2ae35;
    h ^= (h >> 16);
    return h;
}

static void *gc_thread(void *arg) {
    (void)arg;
    pin_thread_to_core(0);
    while (running) {
        sleep(60); 
        flow_table_gc(&g_flow_table);
    }
    return NULL;
}



static void *local_queue_thread_no_crypto(void *arg) {
    struct queue_thread_args *args = (struct queue_thread_args *)arg;
    struct forwarder *fwd = args->fwd;

    pin_thread_to_core(args->core_id);
    int local_idx = args->iface_idx;
    int queue_idx = args->queue_idx;
    int tx_base = args->tx_queue_base;

    struct xsk_interface *local = &fwd->locals[local_idx];
    int batch_size = local->batch_size;

    void *pkt_ptrs[MAX_BATCH_SIZE];
    uint32_t pkt_lens[MAX_BATCH_SIZE];
    uint64_t addrs[MAX_BATCH_SIZE];

    while (running) {
        int rcvd = interface_recv_single_queue(local, queue_idx,
                                               pkt_ptrs, pkt_lens, addrs, batch_size);
        if (rcvd <= 0)
            continue;

        int wan_used[MAX_INTERFACES] = {0};
        int wan_tx_q[MAX_INTERFACES];
        for (int w = 0; w < fwd->wan_count; w++)
            wan_tx_q[w] = tx_base % fwd->wans[w].queue_count;

        for (int i = 0; i < rcvd; i++) {
            uint32_t src_ip, dst_ip;
            uint16_t src_port, dst_port;
            uint8_t protocol;

            int wan_idx;
            if (parse_flow(pkt_ptrs[i], pkt_lens[i],
                           &src_ip, &dst_ip, &src_port, &dst_port, &protocol) == 0) {
                wan_idx = select_wan_idx_for_packet(fwd,
                                                    src_ip, dst_ip, src_port, dst_port,
                                                    protocol, pkt_lens[i]);
            } else {
                wan_idx = 0;
            }

            if (wan_idx < 0 || wan_idx >= fwd->wan_count)
                wan_idx = 0;

            struct xsk_interface *wan = &fwd->wans[wan_idx];
            int tq = wan_tx_q[wan_idx];
            uint8_t *pkt = (uint8_t *)pkt_ptrs[i];

            if (set_wan_l2_addrs(fwd, wan_idx, pkt) != 0) {
                __sync_fetch_and_add(&fwd->total_dropped, 1);
                continue;
            }

            if (interface_send_batch_queue(wan, tq, pkt, pkt_lens[i]) == 0) {
                __sync_fetch_and_add(&fwd->local_to_wan, 1);
                wan_used[wan_idx] = 1;
            } else {
                __sync_fetch_and_add(&fwd->total_dropped, 1);
            }
        }

        for (int w = 0; w < fwd->wan_count; w++) {
            if (wan_used[w])
                interface_send_flush_queue(&fwd->wans[w], wan_tx_q[w]);
        }

        interface_recv_release_single_queue(local, queue_idx, addrs, rcvd);
    }

    return NULL;
}

static void *wan_queue_thread_no_crypto(void *arg) {
    struct queue_thread_args *args = (struct queue_thread_args *)arg;
    struct forwarder *fwd = args->fwd;
    pin_thread_to_core(args->core_id);
    int wan_idx = args->iface_idx;
    int queue_idx = args->queue_idx;
    int tx_base = args->tx_queue_base;

    struct xsk_interface *wan = &fwd->wans[wan_idx];
    int batch_size = wan->batch_size;

    void *pkt_ptrs[MAX_BATCH_SIZE];
    uint32_t pkt_lens[MAX_BATCH_SIZE];
    uint64_t addrs[MAX_BATCH_SIZE];

    while (running) {
        int rcvd = interface_recv_single_queue(wan, queue_idx,
                                                pkt_ptrs, pkt_lens, addrs, batch_size);
        if (rcvd <= 0)
            continue;

        uint32_t local_used_queues[MAX_INTERFACES] = {0};

        for (int i = 0; i < rcvd; i++) {
            uint8_t *pkt = (uint8_t *)pkt_ptrs[i];
            uint32_t pkt_len = pkt_lens[i];

            uint32_t dest_ip = get_dest_ip(pkt, pkt_len);
            if (dest_ip == 0) {
                __sync_fetch_and_add(&fwd->total_dropped, 1);
                __sync_fetch_and_add(&fwd->dropped_bad_ip, 1);
                continue;
            }

            int local_idx = config_find_local_for_ip(fwd->cfg, dest_ip);
            if (local_idx < 0) {
                static time_t last_no_local_debug = 0;
                time_t now = time(NULL);
                if (now - last_no_local_debug >= 1) {
                    last_no_local_debug = now;

                    char dest_str[INET_ADDRSTRLEN] = {0};
                    struct in_addr da = { .s_addr = dest_ip };
                    inet_ntop(AF_INET, &da, dest_str, sizeof(dest_str));

                    uint32_t src_ip_pf = 0, dst_ip_pf = 0;
                    uint16_t src_port_pf = 0, dst_port_pf = 0;
                    uint8_t protocol_pf = 0;
                    int parse_ok = (parse_flow(pkt, pkt_len,
                                                &src_ip_pf, &dst_ip_pf,
                                                &src_port_pf, &dst_port_pf,
                                                &protocol_pf) == 0);

                    int local_idx_parse = -1;
                    if (parse_ok) {
                        local_idx_parse = config_find_local_for_ip(fwd->cfg, dst_ip_pf);
                    }

                    char dst_parse_str[INET_ADDRSTRLEN] = {0};
                    char src_parse_str[INET_ADDRSTRLEN] = {0};
                    if (parse_ok) {
                        struct in_addr sa2 = { .s_addr = src_ip_pf };
                        struct in_addr da2 = { .s_addr = dst_ip_pf };
                        inet_ntop(AF_INET, &sa2, src_parse_str, sizeof(src_parse_str));
                        inet_ntop(AF_INET, &da2, dst_parse_str, sizeof(dst_parse_str));
                    } else {
                        snprintf(src_parse_str, sizeof(src_parse_str), "NA");
                        snprintf(dst_parse_str, sizeof(dst_parse_str), "NA");
                    }

                    const struct local_config *l0 = (fwd && fwd->cfg && fwd->cfg->local_count > 0)
                                                       ? &fwd->cfg->locals[0]
                                                       : NULL;
                    char l0_net[INET_ADDRSTRLEN] = {0};
                    char l0_mask[INET_ADDRSTRLEN] = {0};
                    int l0_used_ok = 0;
                    int l0_parse_ok = 0;
                    if (l0) {
                        struct in_addr na = { .s_addr = l0->network };
                        struct in_addr ma = { .s_addr = l0->netmask };
                        inet_ntop(AF_INET, &na, l0_net, sizeof(l0_net));
                        inet_ntop(AF_INET, &ma, l0_mask, sizeof(l0_mask));
                        l0_used_ok = ((dest_ip & l0->netmask) == l0->network);
                        if (parse_ok)
                            l0_parse_ok = ((dst_ip_pf & l0->netmask) == l0->network);
                    }

                    const char *cause = NULL;
                    if (parse_ok) {
                        cause = (local_idx_parse >= 0)
                                    ? "CAUSE=dest_extraction_mismatch:get_dest_ip!=parse_flow"
                                    : "CAUSE=cidr_mismatch:dst_ip not in local networks";
                    } else {
                        cause = "CAUSE=parse_flow_failed:cannot validate dst_ip";
                    }

                    fprintf(stdout,
                            "[NO_LOCAL_MATCH %s path=wan_no_crypto t=%ld] dest_used=%s(0x%08x) dst_parse=%s(0x%08x) local_idx_parse=%d local_count=%d l0=%s/%s used_ok=%d parse_ok=%d\n",
                            cause,
                            (long)now,
                            dest_str, dest_ip,
                            dst_parse_str, parse_ok ? dst_ip_pf : 0,
                            local_idx_parse,
                            fwd && fwd->cfg ? fwd->cfg->local_count : 0,
                            l0_net, l0_mask, l0_used_ok, l0_parse_ok);
                }
                __sync_fetch_and_add(&fwd->total_dropped, 1);
                __sync_fetch_and_add(&fwd->dropped_no_local_match, 1);
                continue;
            }

            struct xsk_interface *local_iface = &fwd->locals[local_idx];
            struct local_config  *local_cfg   = &fwd->cfg->locals[local_idx];
            int nq = local_iface->queue_count;
            if (nq <= 0) nq = 1;

            int tq;
            {
                uint32_t src_ip, dst_ip;
                uint16_t src_port, dst_port;
                uint8_t protocol;
                if (parse_flow(pkt, pkt_len, &src_ip, &dst_ip, &src_port, &dst_port, &protocol) == 0)
                    tq = (int)(flow_hash_local_tq(src_ip, dst_ip, src_port, dst_port, protocol) % (uint32_t)nq);
                else
                    tq = args->wan_worker_index >= 0 ? (args->wan_worker_index % nq) : (tx_base % nq);
            }

            
            uint8_t dst_mac[6];
            if (arp_cache_lookup(&g_arp[local_idx], dest_ip, dst_mac)) {
                memcpy(pkt, dst_mac, 6);
                memcpy(pkt + 6, g_arp[local_idx].if_mac, 6);
            } else {
                arp_send_request(&g_arp[local_idx], dest_ip);
                __sync_fetch_and_add(&fwd->total_dropped, 1);
                interface_recv_release_single_queue(wan, queue_idx, &addrs[i], 1);
                continue;
            }

            if (interface_send_to_local_batch_queue(local_iface, tq, local_cfg, pkt, pkt_len) == 0) {
                __sync_fetch_and_add(&fwd->wan_to_local, 1);
                local_used_queues[local_idx] |= (1u << tq);
            } else {
                __sync_fetch_and_add(&fwd->total_dropped, 1);
                __sync_fetch_and_add(&fwd->dropped_local_tx_fail, 1);
            }
        }

        for (int l = 0; l < fwd->local_count; l++) {
            if (local_used_queues[l]) {
                for (int q = 0; q < fwd->locals[l].queue_count && q < 32; q++) {
                    if (local_used_queues[l] & (1u << q))
                        interface_send_flush_queue(&fwd->locals[l], q);
                }
            }
        }

        interface_recv_release_single_queue(wan, queue_idx, addrs, rcvd);
    }

    return NULL;
}

static void *local_queue_thread_l2(void *arg) {
    struct queue_thread_args *args = (struct queue_thread_args *)arg;
    struct forwarder *fwd = args->fwd;

    pin_thread_to_core(args->core_id);
    int local_idx = args->iface_idx;
    int queue_idx = args->queue_idx;
    int tx_base = args->tx_queue_base;

    struct xsk_interface *local = &fwd->locals[local_idx];
    int batch_size = local->batch_size;

    void *pkt_ptrs[MAX_BATCH_SIZE];
    uint32_t pkt_lens[MAX_BATCH_SIZE];
    uint64_t addrs[MAX_BATCH_SIZE];

    while (running) {
        int rcvd = interface_recv_single_queue(local, queue_idx,
                                               pkt_ptrs, pkt_lens, addrs, batch_size);
        if (rcvd <= 0)
            continue;

        int wan_used[MAX_INTERFACES] = {0};
        int wan_tx_q[MAX_INTERFACES];
        for (int w = 0; w < fwd->wan_count; w++)
            wan_tx_q[w] = tx_base % fwd->wans[w].queue_count;

        for (int i = 0; i < rcvd; i++) {
            uint32_t src_ip, dst_ip;
            uint16_t src_port, dst_port;
            uint8_t protocol;

            int wan_idx;
            if (parse_flow(pkt_ptrs[i], pkt_lens[i],
                           &src_ip, &dst_ip, &src_port, &dst_port, &protocol) == 0) {
                wan_idx = select_wan_idx_for_packet(fwd,
                                                    src_ip, dst_ip, src_port, dst_port,
                                                    protocol, pkt_lens[i]);
            } else {
                wan_idx = 0;
            }

            if (wan_idx < 0 || wan_idx >= fwd->wan_count)
                wan_idx = 0;

            struct xsk_interface *wan = &fwd->wans[wan_idx];
            int tq = wan_tx_q[wan_idx];

            uint32_t pkt_len = pkt_lens[i];
            uint8_t *pkt = (uint8_t *)pkt_ptrs[i];

            if (set_wan_l2_addrs(fwd, wan_idx, pkt) != 0) {
                __sync_fetch_and_add(&fwd->total_dropped, 1);
                continue;
            }

            const struct crypto_policy *cp = select_crypto_policy_for_packet(fwd,
                                                                             src_ip, dst_ip,
                                                                             src_port, dst_port,
                                                                             protocol);
            struct packet_crypto_ctx *use_ctx = &crypto_ctx;
            int bypass_crypto = 0;

            if (cp) {
                if (cp->action == POLICY_ACTION_BYPASS) {
                    bypass_crypto = 1;
                } else if (cp->action != POLICY_ACTION_ENCRYPT_L2) {

                    bypass_crypto = 1;
                } else {
                    int pi = (int)(cp - fwd->cfg->policies);
                    if (pi >= 0 && pi < MAX_CRYPTO_POLICIES && g_policy_crypto_ctx_ready[pi]) {
                        use_ctx = &g_policy_crypto_ctx[pi];
                    } else {
                        bypass_crypto = 1;
                    }
                    if (!bypass_crypto)
                        apply_crypto_params_from_policy(cp);
                }
            } else {

                bypass_crypto = 1;
            }

            if (bypass_crypto) {
                if (interface_send_batch_queue(wan, tq, pkt_ptrs[i], pkt_len) == 0) {
                    __sync_fetch_and_add(&fwd->local_to_wan, 1);
                    wan_used[wan_idx] = 1;
                } else {
                    __sync_fetch_and_add(&fwd->total_dropped, 1);
                }
                continue;
            }
            if (encrypt_packet_with_ctx(use_ctx, pkt_ptrs[i], &pkt_len) != 0) {
                __sync_fetch_and_add(&fwd->total_dropped, 1);
                continue;
            }

            if (interface_send_batch_queue(wan, tq, pkt_ptrs[i], pkt_len) == 0) {
                __sync_fetch_and_add(&fwd->local_to_wan, 1);
                wan_used[wan_idx] = 1;
            } else {
                __sync_fetch_and_add(&fwd->total_dropped, 1);
            }
        }

        for (int w = 0; w < fwd->wan_count; w++) {
            if (wan_used[w])
                interface_send_flush_queue(&fwd->wans[w], wan_tx_q[w]);
        }

        interface_recv_release_single_queue(local, queue_idx, addrs, rcvd);
    }

    return NULL;
}

static void *local_queue_thread_l3l4(void *arg) {
    struct queue_thread_args *args = (struct queue_thread_args *)arg;
    struct forwarder *fwd = args->fwd;

    pin_thread_to_core(args->core_id);
    int local_idx = args->iface_idx;
    int queue_idx = args->queue_idx;
    int tx_base = args->tx_queue_base;

    struct xsk_interface *local = &fwd->locals[local_idx];
    int batch_size = local->batch_size;

    void *pkt_ptrs[MAX_BATCH_SIZE];
    uint32_t pkt_lens[MAX_BATCH_SIZE];
    uint64_t addrs[MAX_BATCH_SIZE];

    while (running) {
        int rcvd = interface_recv_single_queue(local, queue_idx,
                                               pkt_ptrs, pkt_lens, addrs, batch_size);
        if (rcvd <= 0)
            continue;


        for (int i = 0; i < rcvd; i++) {
            struct packet_job job;
            job.fwd = fwd;
            job.local_idx = local_idx;
            job.queue_idx = queue_idx;
            job.tx_queue_base = tx_base;
            job.pkt_ptr = pkt_ptrs[i];
            job.pkt_len = pkt_lens[i];
            job.addr = addrs[i];

            uint32_t src_ip, dst_ip;
            uint16_t src_port, dst_port;
            uint8_t protocol;
            uint32_t key_hash;
            if (parse_flow(job.pkt_ptr, job.pkt_len,
                           &src_ip, &dst_ip,
                           &src_port, &dst_port,
                           &protocol) == 0) {
                key_hash = flow_hash_local_tq(src_ip, dst_ip, src_port, dst_port, protocol);
            } else {
                key_hash = __sync_fetch_and_add(&g_dispatch_counter, 1);
            }

            uint32_t target = key_hash % NUM_WORKERS;
            struct worker_ring *ring = &g_worker_rings[target];

            int enqueued = 0;
            pthread_mutex_lock(&ring->lock);
            uint32_t next_tail = (ring->tail + 1) % WORKER_RING_SIZE;
            if (next_tail != ring->head) {
                ring->jobs[ring->tail] = job;
                ring->tail = next_tail;
                enqueued = 1;
            }
            pthread_mutex_unlock(&ring->lock);

            if (!enqueued) {
                __sync_fetch_and_add(&fwd->total_dropped, 1);
                interface_recv_release_single_queue(local, queue_idx, &addrs[i], 1);
            }
        }
    }

    return NULL;
}



static void *wan_queue_thread_l2(void *arg) {
    struct queue_thread_args *args = (struct queue_thread_args *)arg;
    struct forwarder *fwd = args->fwd;
    pin_thread_to_core(args->core_id);
    int wan_idx = args->iface_idx;
    int queue_idx = args->queue_idx;
    int tx_base = args->tx_queue_base;

    struct xsk_interface *wan = &fwd->wans[wan_idx];
    int batch_size = wan->batch_size;

    void *pkt_ptrs[MAX_BATCH_SIZE];
    uint32_t pkt_lens[MAX_BATCH_SIZE];
    uint64_t addrs[MAX_BATCH_SIZE];
    uint8_t decrypt_scratch[8192];

    while (running) {
        int rcvd = interface_recv_single_queue(wan, queue_idx,
                                                pkt_ptrs, pkt_lens, addrs, batch_size);
        if (rcvd <= 0)
            continue;

        uint32_t local_used_queues[MAX_INTERFACES] = {0};

        for (int i = 0; i < rcvd; i++) {
            uint8_t *pkt = (uint8_t *)pkt_ptrs[i];
            uint32_t pkt_len = pkt_lens[i];
            uint8_t *final_pkt = pkt;
            uint32_t final_len = pkt_len;


            if (decrypt_packet_auto_l2(fwd, pkt, &pkt_len,
                                        decrypt_scratch, sizeof(decrypt_scratch)) != 0) {
                __sync_fetch_and_add(&fwd->total_dropped, 1);
                continue;
            }
            final_pkt = pkt;
            final_len = pkt_len;


            uint32_t dest_ip = get_dest_ip(final_pkt, final_len);
            if (dest_ip == 0) {
                __sync_fetch_and_add(&fwd->total_dropped, 1);
                __sync_fetch_and_add(&fwd->dropped_bad_ip, 1);
                continue;
            }

            int local_idx = config_find_local_for_ip(fwd->cfg, dest_ip);
            if (local_idx < 0) {
                static time_t last_no_local_debug = 0;
                time_t now = time(NULL);
                if (now - last_no_local_debug >= 1) {
                    last_no_local_debug = now;

                    char dest_str[INET_ADDRSTRLEN] = {0};
                    struct in_addr da = { .s_addr = dest_ip };
                    inet_ntop(AF_INET, &da, dest_str, sizeof(dest_str));

                    uint32_t src_ip_pf = 0, dst_ip_pf = 0;
                    uint16_t src_port_pf = 0, dst_port_pf = 0;
                    uint8_t protocol_pf = 0;
                    int parse_ok = (parse_flow(final_pkt, final_len,
                                                &src_ip_pf, &dst_ip_pf,
                                                &src_port_pf, &dst_port_pf,
                                                &protocol_pf) == 0);

                    int local_idx_parse = -1;
                    if (parse_ok) {
                        local_idx_parse = config_find_local_for_ip(fwd->cfg, dst_ip_pf);
                    }

                    char dst_parse_str[INET_ADDRSTRLEN] = {0};
                    char src_parse_str[INET_ADDRSTRLEN] = {0};
                    if (parse_ok) {
                        struct in_addr sa2 = { .s_addr = src_ip_pf };
                        struct in_addr da2 = { .s_addr = dst_ip_pf };
                        inet_ntop(AF_INET, &sa2, src_parse_str, sizeof(src_parse_str));
                        inet_ntop(AF_INET, &da2, dst_parse_str, sizeof(dst_parse_str));
                    } else {
                        snprintf(src_parse_str, sizeof(src_parse_str), "NA");
                        snprintf(dst_parse_str, sizeof(dst_parse_str), "NA");
                    }

                    const struct local_config *l0 = (fwd && fwd->cfg && fwd->cfg->local_count > 0)
                                                       ? &fwd->cfg->locals[0]
                                                       : NULL;
                    char l0_net[INET_ADDRSTRLEN] = {0};
                    char l0_mask[INET_ADDRSTRLEN] = {0};
                    int l0_used_ok = 0;
                    int l0_parse_ok = 0;
                    if (l0) {
                        struct in_addr na = { .s_addr = l0->network };
                        struct in_addr ma = { .s_addr = l0->netmask };
                        inet_ntop(AF_INET, &na, l0_net, sizeof(l0_net));
                        inet_ntop(AF_INET, &ma, l0_mask, sizeof(l0_mask));
                        l0_used_ok = ((dest_ip & l0->netmask) == l0->network);
                        if (parse_ok)
                            l0_parse_ok = ((dst_ip_pf & l0->netmask) == l0->network);
                    }

                    const char *cause = NULL;
                    if (parse_ok) {
                        cause = (local_idx_parse >= 0)
                                    ? "CAUSE=dest_extraction_mismatch:get_dest_ip!=parse_flow"
                                    : "CAUSE=cidr_mismatch:dst_ip not in local networks";
                    } else {
                        cause = "CAUSE=parse_flow_failed:cannot validate dst_ip";
                    }

                    fprintf(stdout,
                            "[NO_LOCAL_MATCH %s path=wan_l2 t=%ld] dest_used=%s(0x%08x) dst_parse=%s(0x%08x) local_idx_parse=%d local_count=%d l0=%s/%s used_ok=%d parse_ok=%d\n",
                            cause,
                            (long)now,
                            dest_str, dest_ip,
                            dst_parse_str, parse_ok ? dst_ip_pf : 0,
                            local_idx_parse,
                            fwd && fwd->cfg ? fwd->cfg->local_count : 0,
                            l0_net, l0_mask, l0_used_ok, l0_parse_ok);
                }
                __sync_fetch_and_add(&fwd->total_dropped, 1);
                __sync_fetch_and_add(&fwd->dropped_no_local_match, 1);
                continue;
            }

            struct xsk_interface *local_iface = &fwd->locals[local_idx];
            struct local_config  *local_cfg   = &fwd->cfg->locals[local_idx];
            int nq = local_iface->queue_count;
            if (nq <= 0) nq = 1;

            int tq;
            {
                uint32_t src_ip, dst_ip;
                uint16_t src_port, dst_port;
                uint8_t protocol;
                if (parse_flow(final_pkt, final_len, &src_ip, &dst_ip, &src_port, &dst_port, &protocol) == 0) {
                    /* Hardcoded debug for 192.168.9.2 -> 192.168.182.2 after decrypt (Server01 -> Server02). */
                    static int dbg_init = 0;
                    static uint32_t dbg_src = 0;
                    static uint32_t dbg_dst = 0;
                    if (!dbg_init) {
                        struct in_addr a_src, a_dst;
                        inet_pton(AF_INET, "192.168.9.2", &a_src);
                        inet_pton(AF_INET, "192.168.182.2", &a_dst);
                        dbg_src = a_src.s_addr;
                        dbg_dst = a_dst.s_addr;
                        dbg_init = 1;
                    }
                    if (dbg_init && src_ip == dbg_src && dst_ip == dbg_dst) {
                        char sbuf[INET_ADDRSTRLEN] = {0};
                        char dbuf[INET_ADDRSTRLEN] = {0};
                        struct in_addr sa = { .s_addr = src_ip };
                        struct in_addr da = { .s_addr = dst_ip };
                        inet_ntop(AF_INET, &sa, sbuf, sizeof(sbuf));
                        inet_ntop(AF_INET, &da, dbuf, sizeof(dbuf));
                        fprintf(stdout,
                                "[L3_DEBUG_AFTER_DECRYPT path=wan_l3l4] src=%s dst=%s proto=%u len=%u\n",
                                sbuf, dbuf, (unsigned)protocol, (unsigned)final_len);
                    }
                    tq = (int)(flow_hash_local_tq(src_ip, dst_ip, src_port, dst_port, protocol) % (uint32_t)nq);
                } else {
                    tq = args->wan_worker_index >= 0 ? (args->wan_worker_index % nq) : (tx_base % nq);
                }
            }

            uint8_t dst_mac[6];
            if (arp_cache_lookup(&g_arp[local_idx], dest_ip, dst_mac)) {
                memcpy(final_pkt, dst_mac, 6);
                memcpy(final_pkt + 6, g_arp[local_idx].if_mac, 6);
            } else {
                arp_send_request(&g_arp[local_idx], dest_ip);
                __sync_fetch_and_add(&fwd->total_dropped, 1);
                continue;
            }

            if (interface_send_to_local_batch_queue(local_iface, tq, local_cfg, final_pkt, final_len) == 0) {
                __sync_fetch_and_add(&fwd->wan_to_local, 1);
                if (tq < 32)
                    local_used_queues[local_idx] |= (1u << tq);
            } else {
                __sync_fetch_and_add(&fwd->total_dropped, 1);
                __sync_fetch_and_add(&fwd->dropped_local_tx_fail, 1);
            }
        }

        for (int l = 0; l < fwd->local_count; l++) {
            for (int q = 0; q < fwd->locals[l].queue_count && q < 32; q++)
                if (local_used_queues[l] & (1u << q))
                    interface_send_to_local_flush_queue(&fwd->locals[l], q);
        }

        interface_recv_release_single_queue(wan, queue_idx, addrs, rcvd);

    }
    return NULL;
}



static void *wan_queue_thread_l3l4(void *arg) {
    struct queue_thread_args *args = (struct queue_thread_args *)arg;
    struct forwarder *fwd = args->fwd;
    pin_thread_to_core(args->core_id);
    int wan_idx = args->iface_idx;
    int queue_idx = args->queue_idx;
    int tx_base = args->tx_queue_base;

    struct xsk_interface *wan = &fwd->wans[wan_idx];
    int batch_size = wan->batch_size;

    void *pkt_ptrs[MAX_BATCH_SIZE];
    uint32_t pkt_lens[MAX_BATCH_SIZE];
    uint64_t addrs[MAX_BATCH_SIZE];
    uint8_t decrypt_scratch[8192];

    while (running) {
        int rcvd = interface_recv_single_queue(wan, queue_idx,
                                                pkt_ptrs, pkt_lens, addrs, batch_size);
        if (rcvd <= 0)
            continue;

        uint32_t local_used_queues[MAX_INTERFACES] = {0};

        for (int i = 0; i < rcvd; i++) {
            uint8_t *pkt = (uint8_t *)pkt_ptrs[i];
            uint32_t pkt_len = pkt_lens[i];
            uint8_t *final_pkt = pkt;
            uint32_t final_len = pkt_len;

            (void)0;

            if (crypto_enabled && crypto_layer == POLICY_ACTION_ENCRYPT_L3 &&
                fwd->cfg && fwd->cfg->policy_count > 0) {
                uint8_t policy_id = 0;
                int found = 0;
                if (l3_extract_policy_id(pkt, pkt_len, &policy_id) == 0) {
                    for (int pi = 0; pi < fwd->cfg->policy_count && pi < MAX_CRYPTO_POLICIES; pi++) {
                        const struct crypto_policy *cp = &fwd->cfg->policies[pi];
                        if (!cp || cp->action != POLICY_ACTION_ENCRYPT_L3)
                            continue;
                        if (!g_policy_crypto_ctx_ready[pi])
                            continue;
                        if ((uint8_t)(cp->id & 0x7F) != policy_id)
                            continue;
                        apply_crypto_params_from_policy(cp);
                        found = 1;
                        break;
                    }
                }
                if (!found)
                    apply_default_crypto_params(fwd);
            }


            {
                uint8_t pkt_marker = pkt[12];
                uint16_t fake_ipv4 = packet_crypto_get_fake_ethertype_ipv4();
                uint16_t fake_ipv6 = packet_crypto_get_fake_ethertype_ipv6();
                int has_l2_marker =
                    ((fake_ipv4 && pkt_marker == (uint8_t)(fake_ipv4 >> 8)) ||
                     (fake_ipv6 && pkt_marker == (uint8_t)(fake_ipv6 >> 8)));
                if (has_l2_marker) {
                    if (decrypt_packet_auto_l2(fwd, pkt, &pkt_len,
                                               decrypt_scratch,
                                               sizeof(decrypt_scratch)) != 0) {
                        __sync_fetch_and_add(&fwd->total_dropped, 1);
                        continue;
                    }
                }
            }

            if (decrypt_packet_auto_by_action(fwd, pkt, &pkt_len,
                                                POLICY_ACTION_ENCRYPT_L3,
                                                decrypt_scratch,
                                                sizeof(decrypt_scratch)) != 0) {
                __sync_fetch_and_add(&fwd->total_dropped, 1);
                continue;
            }

            if (decrypt_packet_auto_by_action(fwd, pkt, &pkt_len,
                                                POLICY_ACTION_ENCRYPT_L4,
                                                decrypt_scratch,
                                                sizeof(decrypt_scratch)) != 0) {
                __sync_fetch_and_add(&fwd->total_dropped, 1);
                continue;
            }
            final_pkt = pkt;
            final_len = pkt_len;


            uint32_t dest_ip = get_dest_ip(final_pkt, final_len);
            if (dest_ip == 0) {
                __sync_fetch_and_add(&fwd->total_dropped, 1);
                __sync_fetch_and_add(&fwd->dropped_bad_ip, 1);
                continue;
            }

            int local_idx = config_find_local_for_ip(fwd->cfg, dest_ip);
            if (local_idx < 0) {
                static time_t last_no_local_debug = 0;
                time_t now = time(NULL);
                if (now - last_no_local_debug >= 1) {
                    last_no_local_debug = now;

                    char dest_str[INET_ADDRSTRLEN] = {0};
                    struct in_addr da = { .s_addr = dest_ip };
                    inet_ntop(AF_INET, &da, dest_str, sizeof(dest_str));

                    uint32_t src_ip_pf = 0, dst_ip_pf = 0;
                    uint16_t src_port_pf = 0, dst_port_pf = 0;
                    uint8_t protocol_pf = 0;
                    int parse_ok = (parse_flow(final_pkt, final_len,
                                                &src_ip_pf, &dst_ip_pf,
                                                &src_port_pf, &dst_port_pf,
                                                &protocol_pf) == 0);

                    int local_idx_parse = -1;
                    if (parse_ok) {
                        local_idx_parse = config_find_local_for_ip(fwd->cfg, dst_ip_pf);
                    }

                    char dst_parse_str[INET_ADDRSTRLEN] = {0};
                    char src_parse_str[INET_ADDRSTRLEN] = {0};
                    if (parse_ok) {
                        struct in_addr sa2 = { .s_addr = src_ip_pf };
                        struct in_addr da2 = { .s_addr = dst_ip_pf };
                        inet_ntop(AF_INET, &sa2, src_parse_str, sizeof(src_parse_str));
                        inet_ntop(AF_INET, &da2, dst_parse_str, sizeof(dst_parse_str));
                    } else {
                        snprintf(src_parse_str, sizeof(src_parse_str), "NA");
                        snprintf(dst_parse_str, sizeof(dst_parse_str), "NA");
                    }

                    const struct local_config *l0 = (fwd && fwd->cfg && fwd->cfg->local_count > 0)
                                                       ? &fwd->cfg->locals[0]
                                                       : NULL;
                    char l0_net[INET_ADDRSTRLEN] = {0};
                    char l0_mask[INET_ADDRSTRLEN] = {0};
                    int l0_used_ok = 0;
                    int l0_parse_ok = 0;
                    if (l0) {
                        struct in_addr na = { .s_addr = l0->network };
                        struct in_addr ma = { .s_addr = l0->netmask };
                        inet_ntop(AF_INET, &na, l0_net, sizeof(l0_net));
                        inet_ntop(AF_INET, &ma, l0_mask, sizeof(l0_mask));
                        l0_used_ok = ((dest_ip & l0->netmask) == l0->network);
                        if (parse_ok)
                            l0_parse_ok = ((dst_ip_pf & l0->netmask) == l0->network);
                    }

                    const char *cause = NULL;
                    if (parse_ok) {
                        cause = (local_idx_parse >= 0)
                                    ? "CAUSE=dest_extraction_mismatch:get_dest_ip!=parse_flow"
                                    : "CAUSE=cidr_mismatch:dst_ip not in local networks";
                    } else {
                        cause = "CAUSE=parse_flow_failed:cannot validate dst_ip";
                    }

                    fprintf(stdout,
                            "[NO_LOCAL_MATCH %s path=wan_l3l4 t=%ld] src=%s:%u dst=%s:%u proto=%u len=%u | dest_used=%s(0x%08x) dst_parse=%s(0x%08x) local_idx_parse=%d local_count=%d l0=%s/%s used_ok=%d parse_ok=%d\n",
                            cause,
                            (long)now,
                            dest_str, dest_ip,
                            src_parse_str, (unsigned)src_port_pf,
                            dst_parse_str, (unsigned)dst_port_pf,
                            (unsigned)protocol_pf, (unsigned)final_len,
                            dst_parse_str, parse_ok ? dst_ip_pf : 0,
                            local_idx_parse,
                            fwd && fwd->cfg ? fwd->cfg->local_count : 0,
                            l0_net, l0_mask, l0_used_ok, l0_parse_ok);
                }
                __sync_fetch_and_add(&fwd->total_dropped, 1);
                __sync_fetch_and_add(&fwd->dropped_no_local_match, 1);
                continue;
            }

            struct xsk_interface *local_iface = &fwd->locals[local_idx];
            struct local_config  *local_cfg   = &fwd->cfg->locals[local_idx];
            int nq = local_iface->queue_count;
            if (nq <= 0) nq = 1;

            int tq;
            {
                uint32_t src_ip, dst_ip;
                uint16_t src_port, dst_port;
                uint8_t protocol;
                if (parse_flow(final_pkt, final_len, &src_ip, &dst_ip, &src_port, &dst_port, &protocol) == 0)
                    tq = (int)(flow_hash_local_tq(src_ip, dst_ip, src_port, dst_port, protocol) % (uint32_t)nq);
                else
                    tq = args->wan_worker_index >= 0 ? (args->wan_worker_index % nq) : (tx_base % nq);
            }

            uint8_t dst_mac[6];
            if (arp_cache_lookup(&g_arp[local_idx], dest_ip, dst_mac)) {
                memcpy(final_pkt, dst_mac, 6);
                memcpy(final_pkt + 6, g_arp[local_idx].if_mac, 6);
            } else {
                arp_send_request(&g_arp[local_idx], dest_ip);
                __sync_fetch_and_add(&fwd->total_dropped, 1);
                continue;
            }

            if (interface_send_to_local_batch_queue(local_iface, tq, local_cfg, final_pkt, final_len) == 0) {
                __sync_fetch_and_add(&fwd->wan_to_local, 1);
                if (tq < 32)
                    local_used_queues[local_idx] |= (1u << tq);
            } else {
                __sync_fetch_and_add(&fwd->total_dropped, 1);
                __sync_fetch_and_add(&fwd->dropped_local_tx_fail, 1);
            }
        }

        for (int l = 0; l < fwd->local_count; l++) {
            for (int q = 0; q < fwd->locals[l].queue_count && q < 32; q++)
                if (local_used_queues[l] & (1u << q))
                    interface_send_to_local_flush_queue(&fwd->locals[l], q);
        }

        interface_recv_release_single_queue(wan, queue_idx, addrs, rcvd);

    }
    return NULL;
}

static void *worker_thread(void *arg) {
    struct queue_thread_args *args = (struct queue_thread_args *)arg;
    int worker_id = args->worker_id;

    if (worker_id < 0 || worker_id >= NUM_WORKERS)
        return NULL;

    pin_thread_to_core(args->core_id);

    struct worker_ring *ring = &g_worker_rings[worker_id];
    uint8_t frag1_buf[2048];
    uint8_t frag2_buf[2048];

    while (running) {
        struct packet_job job;
        int has_job = 0;

        pthread_mutex_lock(&ring->lock);
        if (ring->head != ring->tail) {
            job = ring->jobs[ring->head];
            ring->head = (ring->head + 1) % WORKER_RING_SIZE;
            has_job = 1;
        }
        pthread_mutex_unlock(&ring->lock);

        if (!has_job) {
            sched_yield();
            continue;
        }

        struct forwarder *fwd = job.fwd;
        if (!fwd) {
            continue;
        }

        uint32_t wan_tx_q[MAX_INTERFACES];
        int wan_used[MAX_INTERFACES] = {0};
        for (int w = 0; w < fwd->wan_count; w++)
            wan_tx_q[w] = job.tx_queue_base % fwd->wans[w].queue_count;

        uint32_t src_ip = 0, dst_ip = 0;
        uint16_t src_port = 0, dst_port = 0;
        uint8_t protocol = 0;

        int flow_ok = (parse_flow(job.pkt_ptr, job.pkt_len,
                                  &src_ip, &dst_ip, &src_port, &dst_port, &protocol) == 0);

        int wan_idx;
        if (flow_ok) {
            wan_idx = select_wan_idx_for_packet(fwd,
                                                src_ip, dst_ip, src_port, dst_port,
                                                protocol, job.pkt_len);
        } else {
            wan_idx = 0;
        }

        if (wan_idx < 0 || wan_idx >= fwd->wan_count) {
            wan_idx = 0;
        }

        struct xsk_interface *wan = &fwd->wans[wan_idx];
        int tq = wan_tx_q[wan_idx];

        uint32_t pkt_len = job.pkt_len;


        const struct crypto_policy *cp = NULL;
        struct packet_crypto_ctx *use_ctx = &crypto_ctx;
        int bypass_crypto = 0;
        if (crypto_enabled) {
            if (!flow_ok) {
                bypass_crypto = 1;
            } else {
                cp = select_crypto_policy_for_packet(fwd,
                                                     src_ip, dst_ip,
                                                     src_port, dst_port,
                                                     protocol);
                if (cp) {
                    if (cp->action == POLICY_ACTION_BYPASS) {
                        bypass_crypto = 1;
                    } else {
                        int pi = (int)(cp - fwd->cfg->policies);
                        if (pi >= 0 && pi < MAX_CRYPTO_POLICIES && g_policy_crypto_ctx_ready[pi]) {
                            use_ctx = &g_policy_crypto_ctx[pi];
                        } else {
                            bypass_crypto = 1;
                        }
                        if (!bypass_crypto)
                            apply_crypto_params_from_policy(cp);
                    }
                } else {

                    bypass_crypto = 1;
                }
            }

            if (bypass_crypto) {
                uint8_t *pkt = (uint8_t *)job.pkt_ptr;
                if (set_wan_l2_addrs(fwd, wan_idx, pkt) != 0) {
                    __sync_fetch_and_add(&fwd->total_dropped, 1);
                    goto release_local;
                }

                if (interface_send_batch_queue(wan, tq, job.pkt_ptr, pkt_len) == 0) {
                    __sync_fetch_and_add(&fwd->local_to_wan, 1);
                    wan_used[wan_idx] = 1;
                } else {
                    __sync_fetch_and_add(&fwd->total_dropped, 1);
                }
                goto skip_encrypt_flush;
            }
        }

        if (!crypto_enabled) {
            uint8_t *pkt = (uint8_t *)job.pkt_ptr;
            if (set_wan_l2_addrs(fwd, wan_idx, pkt) != 0) {
                __sync_fetch_and_add(&fwd->total_dropped, 1);
                goto release_local;
            }

            if (interface_send_batch_queue(wan, tq, pkt, pkt_len) == 0) {
                __sync_fetch_and_add(&fwd->local_to_wan, 1);
                wan_used[wan_idx] = 1;
            } else {
                __sync_fetch_and_add(&fwd->total_dropped, 1);
            }
        } else {
            uint8_t *pkt = (uint8_t *)job.pkt_ptr;
            if (set_wan_l2_addrs(fwd, wan_idx, pkt) != 0) {
                __sync_fetch_and_add(&fwd->total_dropped, 1);
                goto release_local;
            }

            int new_len = -1;
            if (cp) {
                if (cp->action == POLICY_ACTION_ENCRYPT_L2) {
                    new_len = crypto_layer2_encrypt(use_ctx, job.pkt_ptr, pkt_len);
                } else if (cp->action == POLICY_ACTION_ENCRYPT_L3) {
                    new_len = crypto_layer3_encrypt(use_ctx, job.pkt_ptr, pkt_len);
                } else if (cp->action == POLICY_ACTION_ENCRYPT_L4) {
                    new_len = crypto_layer4_encrypt(use_ctx, job.pkt_ptr, pkt_len);
                }
            }

            if (new_len < 0) {
                __sync_fetch_and_add(&fwd->total_dropped, 1);
                goto release_local;
            }
            pkt_len = (uint32_t)new_len;

            if (interface_send_batch_queue(wan, tq, job.pkt_ptr, pkt_len) == 0) {
                __sync_fetch_and_add(&fwd->local_to_wan, 1);
                wan_used[wan_idx] = 1;
            } else {
                __sync_fetch_and_add(&fwd->total_dropped, 1);
            }
        }

skip_encrypt_flush:
        for (int w = 0; w < fwd->wan_count; w++) {
            if (wan_used[w])
                interface_send_flush_queue(&fwd->wans[w], wan_tx_q[w]);
        }

release_local:
        if (job.fwd && job.local_idx >= 0 &&
            job.local_idx < job.fwd->local_count) {
            struct xsk_interface *local = &job.fwd->locals[job.local_idx];
            interface_recv_release_single_queue(local, job.queue_idx, &job.addr, 1);
        }
    }

    return NULL;
}

int forwarder_init(struct forwarder *fwd, struct app_config *cfg) {
    memset(fwd, 0, sizeof(*fwd));
    fwd->cfg = cfg;
    g_cfg_ptr = cfg;
    interface_reset_redirect_maps();


    for (int i = 0; i < cfg->local_count; i++)
        cfg->locals[i].queue_count = 1;
    for (int i = 0; i < cfg->wan_count; i++)
        cfg->wans[i].queue_count = 1;

    crypto_enabled = cfg->crypto_enabled;
    crypto_layer = cfg->encrypt_layer;
    int has_encrypt_l2 = 0;
    if (crypto_enabled) {
        packet_crypto_set_aes_bits(cfg->aes_bits);
        if (packet_crypto_init(&crypto_ctx, cfg->crypto_key) != 0) {
            fprintf(stderr, "Failed to initialize AES-%d encryption\n", cfg->aes_bits);
            return -1;
        }


        memset(g_policy_crypto_ctx_ready, 0, sizeof(g_policy_crypto_ctx_ready));
        for (int pi = 0; pi < cfg->policy_count && pi < MAX_CRYPTO_POLICIES; pi++) {
            const struct crypto_policy *cp = &cfg->policies[pi];
            if (!cp)
                continue;
            if (cp->action == POLICY_ACTION_BYPASS)
                continue;

            int key_nonzero = 0;
            for (int k = 0; k < AES_KEY_LEN; k++) {
                if (cp->key[k] != 0) { key_nonzero = 1; break; }
            }
            if (!key_nonzero)
                continue;

            packet_crypto_set_aes_bits(cp->aes_bits);
            if (packet_crypto_init(&g_policy_crypto_ctx[pi], cp->key) != 0) {
                fprintf(stderr, "[DB CRYPTO] Failed to init policy ctx id=%d (AES=%d)\n",
                        cp->id, cp->aes_bits);
                continue;
            }
            g_policy_crypto_ctx_ready[pi] = 1;
        }


        for (int pi = 0; pi < cfg->policy_count && pi < MAX_CRYPTO_POLICIES; pi++) {
            if (cfg->policies[pi].action == POLICY_ACTION_ENCRYPT_L2 && g_policy_crypto_ctx_ready[pi]) {
                has_encrypt_l2 = 1;
                break;
            }
        }

        packet_crypto_set_encrypt_layer(cfg->encrypt_layer);
        packet_crypto_set_mode(cfg->crypto_mode);
        packet_crypto_set_nonce_size(cfg->nonce_size);
        if (has_encrypt_l2) {
            if (cfg->fake_ethertype_ipv4 == 0 && cfg->fake_ethertype_ipv6 == 0) {

                cfg->fake_ethertype_ipv4 = 0x88b5;
                cfg->fake_ethertype_ipv6 = 0x88b6;
            }
            packet_crypto_set_ethertype(cfg->fake_ethertype_ipv4, cfg->fake_ethertype_ipv6);
        }
        if (crypto_layer == 3) {
            if (cfg->fake_protocol != 0)
                packet_crypto_set_fake_protocol(cfg->fake_protocol);
            else
                packet_crypto_set_fake_protocol(99);
        }
    }



    uint32_t wan_window_sizes[MAX_INTERFACES] = {0};
    for (int i = 0; i < cfg->wan_count && i < MAX_INTERFACES; i++)
        wan_window_sizes[i] = cfg->wans[i].window_size;
    compute_profile_weighted_wan_windows(cfg, wan_window_sizes, cfg->wan_count);
    flow_table_init(&g_flow_table, wan_window_sizes, cfg->wan_count);

    int total_threads = 0;
    for (int i = 0; i < cfg->local_count; i++) {
        interface_set_queue_count(cfg->locals[i].ifname, cfg->locals[i].queue_count);
        total_threads += cfg->locals[i].queue_count;
    }
    for (int i = 0; i < cfg->wan_count; i++) {
        interface_set_queue_count(cfg->wans[i].ifname, cfg->wans[i].queue_count);
        total_threads += cfg->wans[i].queue_count;
    }
    total_threads += NUM_WORKERS;

    for (int i = 0; i < cfg->local_count; i++) {
        if (interface_init_local(&fwd->locals[i], &cfg->locals[i], cfg->bpf_file) != 0) {
            fprintf(stderr, "Failed to init LOCAL %s\n", cfg->locals[i].ifname);
            interface_cleanup(&fwd->locals[i]);
            goto err_locals;
        }
        fwd->local_count++;
    }


    if (cfg->redirect.src_count > 0 || cfg->redirect.dst_count > 0) {
        if (interface_push_redirect_cfg(&cfg->redirect) != 0) {
            fprintf(stderr, "[XDP] Failed to push redirect rules to config_map\n");

        }
    }

    
    for (int i = 0; i < fwd->local_count; i++) {
        if (arp_init_for_local(&g_arp[i], &fwd->locals[i], &running) == 0) {
            pthread_t tid;
            pthread_create(&tid, NULL, arp_listener_thread, &g_arp[i]);
            pthread_detach(tid);
            g_arp_inited = 1;
            fprintf(stderr, "[ARP] ready on %s (ip=%u)\n",
                    g_arp[i].ifname, (unsigned)ntohl(g_arp[i].if_ip));
        }
    }

    for (int i = 0; i < cfg->wan_count; i++) {
        uint16_t wan_fake4 = (crypto_enabled && has_encrypt_l2) ? cfg->fake_ethertype_ipv4 : 0;
        uint16_t wan_fake6 = (crypto_enabled && has_encrypt_l2) ? cfg->fake_ethertype_ipv6 : 0;
        if (interface_init_wan_rx(&fwd->wans[i], &cfg->wans[i], "bpf/xdp_wan_redirect.o", wan_fake4, wan_fake6) != 0) {
            fprintf(stderr, "Failed to init WAN %s\n", cfg->wans[i].ifname);
            goto err_wans;
        }
        fwd->wan_count++;
        if (cfg->wans[i].dst_ip != 0) {

            memset(fwd->wans[i].dst_mac, 0, MAC_LEN);
            memset(fwd->wans[i].src_mac, 0, MAC_LEN);
        }
    }


    for (int i = 0; i < fwd->wan_count; i++) {
        if (cfg->wans[i].dst_ip == 0) {
            fprintf(stderr,
                    "[WAN ARP] if=%s dst_ip=0 -> using static/fallback MAC path\n",
                    cfg->wans[i].ifname);
            continue;
        }
        if (arp_init_for_local(&g_wan_arp[i], &fwd->wans[i], &running) == 0) {
            pthread_t tid;
            pthread_create(&tid, NULL, arp_listener_thread, &g_wan_arp[i]);
            pthread_detach(tid);
            g_arp_inited = 1;
            log_wan_peer_mac(fwd, i);
        } else {
            fprintf(stderr, "[ARP] WARN: cannot init WAN ARP on %s\n", cfg->wans[i].ifname);
        }
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


static void forwarder_run_no_crypto(struct forwarder *fwd) {
    int total_local_queues = 0;
    for (int i = 0; i < fwd->local_count; i++)
        total_local_queues += fwd->locals[i].queue_count;

    int total_wan_queues = 0;
    for (int i = 0; i < fwd->wan_count; i++)
        total_wan_queues += fwd->wans[i].queue_count;

    int total_threads = total_local_queues + total_wan_queues;

    pthread_t *threads = calloc(total_threads, sizeof(pthread_t));
    struct queue_thread_args *args = calloc(total_threads, sizeof(struct queue_thread_args));
    if (!threads || !args) {
        fprintf(stderr, "[NO-CRYPTO] Failed to allocate thread arrays\n");
        free(threads); free(args);
        return;
    }

    pthread_t gc_tid;
    pthread_create(&gc_tid, NULL, gc_thread, NULL);

    int thread_idx = 0;


    int local_rx_idx = 0;
    for (int i = 0; i < fwd->local_count; i++) {
        struct xsk_interface *local = &fwd->locals[i];
        for (int q = 0; q < local->queue_count; q++) {
            args[thread_idx].fwd = fwd;
            args[thread_idx].iface_idx = i;
            args[thread_idx].queue_idx = q;
            args[thread_idx].tx_queue_base = q;
            args[thread_idx].core_id = 0;
            args[thread_idx].wan_worker_index = -1;
            args[thread_idx].worker_id = -1;
            pthread_create(&threads[thread_idx], NULL, local_queue_thread_no_crypto, &args[thread_idx]);
            thread_idx++;
            local_rx_idx++;
        }
    }


    int wan_worker_idx = 0;
    for (int i = 0; i < fwd->wan_count; i++) {
        struct xsk_interface *wan = &fwd->wans[i];
        for (int q = 0; q < wan->queue_count; q++) {
            args[thread_idx].fwd = fwd;
            args[thread_idx].iface_idx = i;
            args[thread_idx].queue_idx = q;
            args[thread_idx].tx_queue_base = q;
            args[thread_idx].core_id = 0;
            args[thread_idx].wan_worker_index = wan_worker_idx;
            args[thread_idx].worker_id = -1;
            pthread_create(&threads[thread_idx], NULL, wan_queue_thread_no_crypto, &args[thread_idx]);
            wan_worker_idx++;
            thread_idx++;
        }
    }

    while (running) {
        sleep(1);
        forwarder_print_stats(fwd);
    }

    for (int i = 0; i < total_threads; i++)
        pthread_join(threads[i], NULL);
    pthread_join(gc_tid, NULL);

    free(threads);
    free(args);
}


static void forwarder_run_l2(struct forwarder *fwd) {
    int total_local_queues = 0;
    for (int i = 0; i < fwd->local_count; i++)
        total_local_queues += fwd->locals[i].queue_count;

    int total_wan_queues = 0;
    for (int i = 0; i < fwd->wan_count; i++)
        total_wan_queues += fwd->wans[i].queue_count;


    fprintf(stderr, "[L2 DEBUG] total_local_queues=%d, total_wan_queues=%d\n",
            total_local_queues, total_wan_queues);
    for (int i = 0; i < fwd->local_count; i++) {
        fprintf(stderr, "[L2 DEBUG] local[%d] ifname=%s queue_count=%d\n",
                i, fwd->locals[i].ifname, fwd->locals[i].queue_count);
    }
    for (int i = 0; i < fwd->wan_count; i++) {
        fprintf(stderr, "[L2 DEBUG] wan[%d] ifname=%s queue_count=%d\n",
                i, fwd->wans[i].ifname, fwd->wans[i].queue_count);
    }


    int total_threads = total_local_queues + total_wan_queues;

    pthread_t *threads = calloc(total_threads, sizeof(pthread_t));
    struct queue_thread_args *args = calloc(total_threads, sizeof(struct queue_thread_args));
    if (!threads || !args) {
        fprintf(stderr, "[L2] Failed to allocate thread arrays\n");
        free(threads); free(args);
        return;
    }

    pthread_t gc_tid;
    pthread_create(&gc_tid, NULL, gc_thread, NULL);

    int thread_idx = 0;


    int local_rx_idx = 0;
    for (int i = 0; i < fwd->local_count; i++) {
        struct xsk_interface *local = &fwd->locals[i];
        for (int q = 0; q < local->queue_count; q++) {
            args[thread_idx].fwd = fwd;
            args[thread_idx].iface_idx = i;
            args[thread_idx].queue_idx = q;
            args[thread_idx].tx_queue_base = q;
            args[thread_idx].core_id = 0;
            args[thread_idx].wan_worker_index = -1;
            args[thread_idx].worker_id = -1;
            pthread_create(&threads[thread_idx], NULL, local_queue_thread_l2, &args[thread_idx]);
            thread_idx++;
            local_rx_idx++;
        }
    }


    int wan_worker_idx = 0;
    for (int i = 0; i < fwd->wan_count; i++) {
        struct xsk_interface *wan = &fwd->wans[i];
        for (int q = 0; q < wan->queue_count; q++) {
            args[thread_idx].fwd = fwd;
            args[thread_idx].iface_idx = i;
            args[thread_idx].queue_idx = q;
            args[thread_idx].tx_queue_base = q;
            args[thread_idx].core_id = 0;
            args[thread_idx].wan_worker_index = wan_worker_idx;
            args[thread_idx].worker_id = -1;
            pthread_create(&threads[thread_idx], NULL, wan_queue_thread_l2, &args[thread_idx]);
            wan_worker_idx++;
            thread_idx++;
        }
    }

    while (running) {
        sleep(1);
        forwarder_print_stats(fwd);
    }

    for (int i = 0; i < total_threads; i++)
        pthread_join(threads[i], NULL);
    pthread_join(gc_tid, NULL);

    free(threads);
    free(args);
}


static void forwarder_run_l3(struct forwarder *fwd) {
    int total_local_queues = 0;
    for (int i = 0; i < fwd->local_count; i++)
        total_local_queues += fwd->locals[i].queue_count;

    int total_wan_queues = 0;
    for (int i = 0; i < fwd->wan_count; i++)
        total_wan_queues += fwd->wans[i].queue_count;

    int total_threads = total_local_queues + total_wan_queues + NUM_WORKERS;

    pthread_t *threads = calloc(total_threads, sizeof(pthread_t));
    struct queue_thread_args *args = calloc(total_threads, sizeof(struct queue_thread_args));
    if (!threads || !args) {
        fprintf(stderr, "[L3] Failed to allocate thread arrays\n");
        free(threads); free(args);
        return;
    }

    for (int w = 0; w < NUM_WORKERS; w++) {
        g_worker_rings[w].head = 0;
        g_worker_rings[w].tail = 0;
        pthread_mutex_init(&g_worker_rings[w].lock, NULL);
    }

    pthread_t gc_tid;
    pthread_create(&gc_tid, NULL, gc_thread, NULL);

    int thread_idx = 0;


    int local_rx_idx = 0;
    for (int i = 0; i < fwd->local_count; i++) {
        struct xsk_interface *local = &fwd->locals[i];
        for (int q = 0; q < local->queue_count; q++) {
            args[thread_idx].fwd = fwd;
            args[thread_idx].iface_idx = i;
            args[thread_idx].queue_idx = q;
            args[thread_idx].tx_queue_base = q;
            args[thread_idx].core_id = 0;
            args[thread_idx].wan_worker_index = -1;
            args[thread_idx].worker_id = -1;
            pthread_create(&threads[thread_idx], NULL, local_queue_thread_l3l4, &args[thread_idx]);
            thread_idx++;
            local_rx_idx++;
        }
    }


    int wan_worker_idx = 0;
    for (int i = 0; i < fwd->wan_count; i++) {
        struct xsk_interface *wan = &fwd->wans[i];
        for (int q = 0; q < wan->queue_count; q++) {
            args[thread_idx].fwd = fwd;
            args[thread_idx].iface_idx = i;
            args[thread_idx].queue_idx = q;
            args[thread_idx].tx_queue_base = q;
            args[thread_idx].core_id = 0;
            args[thread_idx].wan_worker_index = wan_worker_idx;
            args[thread_idx].worker_id = -1;
            pthread_create(&threads[thread_idx], NULL, wan_queue_thread_l3l4, &args[thread_idx]);
            wan_worker_idx++;
            thread_idx++;
        }
    }


    for (int w = 0; w < NUM_WORKERS; w++) {
        args[thread_idx].fwd = fwd;
        args[thread_idx].iface_idx = -1;
        args[thread_idx].queue_idx = -1;
        args[thread_idx].tx_queue_base = 0;
        args[thread_idx].core_id = 0;
        args[thread_idx].wan_worker_index = -1;
        args[thread_idx].worker_id = w;
        pthread_create(&threads[thread_idx], NULL, worker_thread, &args[thread_idx]);
        thread_idx++;
    }

    while (running) {
        sleep(1);
        forwarder_print_stats(fwd);
    }

    for (int i = 0; i < total_threads; i++)
        pthread_join(threads[i], NULL);
    pthread_join(gc_tid, NULL);

    free(threads);
    free(args);
}


static void forwarder_run_l4(struct forwarder *fwd) {
    int total_local_queues = 0;
    for (int i = 0; i < fwd->local_count; i++)
        total_local_queues += fwd->locals[i].queue_count;

    int total_wan_queues = 0;
    for (int i = 0; i < fwd->wan_count; i++)
        total_wan_queues += fwd->wans[i].queue_count;

    int total_threads = total_local_queues + total_wan_queues + NUM_WORKERS;

    pthread_t *threads = calloc(total_threads, sizeof(pthread_t));
    struct queue_thread_args *args = calloc(total_threads, sizeof(struct queue_thread_args));
    if (!threads || !args) {
        fprintf(stderr, "[L4] Failed to allocate thread arrays\n");
        free(threads); free(args);
        return;
    }

    for (int w = 0; w < NUM_WORKERS; w++) {
        g_worker_rings[w].head = 0;
        g_worker_rings[w].tail = 0;
        pthread_mutex_init(&g_worker_rings[w].lock, NULL);
    }

    pthread_t gc_tid;
    pthread_create(&gc_tid, NULL, gc_thread, NULL);

    int thread_idx = 0;


    int local_rx_idx = 0;
    for (int i = 0; i < fwd->local_count; i++) {
        struct xsk_interface *local = &fwd->locals[i];
        for (int q = 0; q < local->queue_count; q++) {
            args[thread_idx].fwd = fwd;
            args[thread_idx].iface_idx = i;
            args[thread_idx].queue_idx = q;
            args[thread_idx].tx_queue_base = q;
            args[thread_idx].core_id = 0;
            args[thread_idx].wan_worker_index = -1;
            args[thread_idx].worker_id = -1;
            pthread_create(&threads[thread_idx], NULL, local_queue_thread_l3l4, &args[thread_idx]);
            thread_idx++;
            local_rx_idx++;
        }
    }


    int wan_worker_idx = 0;
    for (int i = 0; i < fwd->wan_count; i++) {
        struct xsk_interface *wan = &fwd->wans[i];
        for (int q = 0; q < wan->queue_count; q++) {
            args[thread_idx].fwd = fwd;
            args[thread_idx].iface_idx = i;
            args[thread_idx].queue_idx = q;
            args[thread_idx].tx_queue_base = q;
            args[thread_idx].core_id = 0;
            args[thread_idx].wan_worker_index = wan_worker_idx;
            args[thread_idx].worker_id = -1;
            pthread_create(&threads[thread_idx], NULL, wan_queue_thread_l3l4, &args[thread_idx]);
            wan_worker_idx++;
            thread_idx++;
        }
    }


    for (int w = 0; w < NUM_WORKERS; w++) {
        args[thread_idx].fwd = fwd;
        args[thread_idx].iface_idx = -1;
        args[thread_idx].queue_idx = -1;
        args[thread_idx].tx_queue_base = 0;
        args[thread_idx].core_id = 0;
        args[thread_idx].wan_worker_index = -1;
        args[thread_idx].worker_id = w;
        pthread_create(&threads[thread_idx], NULL, worker_thread, &args[thread_idx]);
        thread_idx++;
    }

    while (running) {
        sleep(1);
        forwarder_print_stats(fwd);
    }

    for (int i = 0; i < total_threads; i++)
        pthread_join(threads[i], NULL);
    pthread_join(gc_tid, NULL);

    free(threads);
    free(args);
}



void forwarder_run(struct forwarder *fwd) {
    signal(SIGINT, sigint_handler);
    signal(SIGTERM, sigint_handler);

    if (!crypto_enabled) {
        forwarder_run_no_crypto(fwd);
    } else if (crypto_layer == 2) {
        forwarder_run_l2(fwd);
    } else if (crypto_layer == 3) {
        forwarder_run_l3(fwd);
    } else if (crypto_layer == 4) {
        forwarder_run_l4(fwd);
    } else {
        forwarder_run_l3(fwd);
    }
}

void forwarder_print_stats(struct forwarder *fwd) {
    if (!fwd) return;

    time_t now = time(NULL);
    static uint64_t last_total_dropped = 0;
    static uint64_t last_dropped_bad_ip = 0;
    static uint64_t last_dropped_no_local_match = 0;
    static uint64_t last_dropped_local_tx_fail = 0;
    static uint64_t last_tx_wait_loops = 0;

    int nq = (fwd->local_count > 0 && fwd->locals[0].queue_count <= FORWARDER_MAX_LOCAL_QUEUES)
             ? fwd->locals[0].queue_count : 0;
    if (nq <= 0) nq = 1;

    uint64_t tx_wait_loops = 0;
    for (int i = 0; i < fwd->local_count; i++) {
        for (int q = 0; q < fwd->locals[i].queue_count && q < MAX_QUEUES; q++)
            tx_wait_loops += fwd->locals[i].queues[q].tx_wait_loops;
    }

    uint64_t delta_total_dropped = fwd->total_dropped - last_total_dropped;
    uint64_t delta_bad_ip = fwd->dropped_bad_ip - last_dropped_bad_ip;
    uint64_t delta_no_local = fwd->dropped_no_local_match - last_dropped_no_local_match;
    uint64_t delta_local_tx_fail = fwd->dropped_local_tx_fail - last_dropped_local_tx_fail;
    uint64_t delta_tx_wait_loops = tx_wait_loops - last_tx_wait_loops;

    fprintf(stdout,
            "[STATS] local_to_wan=%lu wan_to_local=%lu total_dropped=%lu "
            "dropped_bad_ip=%lu dropped_no_local_match=%lu dropped_local_tx_fail=%lu",
            fwd->local_to_wan,
            fwd->wan_to_local,
            fwd->total_dropped,
            fwd->dropped_bad_ip,
            fwd->dropped_no_local_match,
            fwd->dropped_local_tx_fail);
    if (delta_local_tx_fail > 0 || delta_total_dropped > 0) {
        for (int i = 0; i < nq && i < FORWARDER_MAX_LOCAL_QUEUES; i++)
            fprintf(stdout, " q%d=%lu", i, (unsigned long)fwd->dropped_local_tx_fail_by_queue[i]);
    }
    fprintf(stdout, " tx_wait_loops=%lu\n", (unsigned long)tx_wait_loops);

    if (delta_total_dropped > 0) {
        fprintf(stdout,
                "[DROP_EVENT t=%ld] +%lu total | +%lu bad_ip | +%lu no_local_match | +%lu local_tx_fail | tx_wait_loops_delta=%lu\n",
                (long)now,
                (unsigned long)delta_total_dropped,
                (unsigned long)delta_bad_ip,
                (unsigned long)delta_no_local,
                (unsigned long)delta_local_tx_fail,
                (unsigned long)delta_tx_wait_loops);
    }

    last_total_dropped = fwd->total_dropped;
    last_dropped_bad_ip = fwd->dropped_bad_ip;
    last_dropped_no_local_match = fwd->dropped_no_local_match;
    last_dropped_local_tx_fail = fwd->dropped_local_tx_fail;
    last_tx_wait_loops = tx_wait_loops;

    /* WAN ARP logging is noisy; print it periodically only. */
    {
        static time_t last_arp_print = 0;
        int do_arp = (now - last_arp_print) >= 10;
        if (do_arp)
            last_arp_print = now;

        if (do_arp) {
            for (int w = 0; w < fwd->wan_count; w++) {
                const struct wan_config *wc = &fwd->cfg->wans[w];
                if (wc->dst_ip == 0) {
                    fprintf(stdout, "[WAN ARP] if=%s peer ARP=disabled (static/fallback path)\n",
                            fwd->wans[w].ifname);
                    continue;
                }

                char ipbuf[INET_ADDRSTRLEN] = {0};
                struct in_addr a = { .s_addr = wc->dst_ip };
                inet_ntop(AF_INET, &a, ipbuf, sizeof(ipbuf));

                uint8_t mac[6];
                if (arp_cache_lookup(&g_wan_arp[w], wc->dst_ip, mac)) {
                    fprintf(stdout,
                            "[WAN ARP] if=%s peer=%s dest_mac=%02x:%02x:%02x:%02x:%02x:%02x\n",
                            fwd->wans[w].ifname, ipbuf,
                            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
                } else {
                    fprintf(stdout, "[WAN ARP] if=%s peer=%s dest_mac=UNRESOLVED\n",
                            fwd->wans[w].ifname, ipbuf);
                }
            }
        }
    }
}