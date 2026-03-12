#include "../inc/forwarder.h"
#include "../inc/packet_crypto.h"
#include "../inc/flow_table.h"
#include "../inc/fragment.h"
#include "../inc/config.h"
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

#define NUM_WORKERS 4
#define WORKER_RING_SIZE 4096

/* ========================================================================
 * RING MODE: Software ring buffer để không phụ thuộc số queue NIC
 * ======================================================================== */
#define NUM_RING_WORKERS 5
#define SW_RING_SIZE 8192

struct ring_packet {
    uint8_t data[2048];
    uint32_t len;
    int src_iface_idx;
    int src_queue_idx;
};

struct sw_ring {
    struct ring_packet packets[SW_RING_SIZE];
    volatile uint32_t head;  /* Consumer đọc từ đây */
    volatile uint32_t tail;  /* Producer ghi vào đây */
    pthread_mutex_t lock;    /* Lock cho multiple producers */
} __attribute__((aligned(64)));

/* Ring cho Local → WAN (5 rings, mỗi worker 1 ring) */
static struct sw_ring g_local_to_wan_rings[NUM_RING_WORKERS];

/* Ring cho WAN → Local (5 rings, mỗi worker 1 ring) */
static struct sw_ring g_wan_to_local_rings[NUM_RING_WORKERS];

/* ======================================================================== */

static volatile int running = 1;

static struct packet_crypto_ctx crypto_ctx;
static int crypto_enabled = 0;
static int crypto_layer = 0;

static struct flow_table g_flow_table;

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

/* Forward declarations for ring mode threads */
static void *local_rx_dispatcher_thread(void *arg);
static void *wan_rx_dispatcher_thread(void *arg);
static void *local_to_wan_ring_worker(void *arg);
static void *wan_to_local_ring_worker(void *arg);

static void pin_thread_to_core(int core_id) {
    if (core_id < 0)
        return;

    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(core_id, &cpuset);
    (void)pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
}

static int encrypt_packet(void *pkt_data, uint32_t *pkt_len) {
    if (!crypto_enabled) return 0;

    int new_len = packet_encrypt(&crypto_ctx, (uint8_t *)pkt_data, *pkt_len);
    if (new_len < 0) {
        return -1;
    }
    *pkt_len = (uint32_t)new_len;
    return 0;
}

static int decrypt_packet(void *pkt_data, uint32_t *pkt_len) {
    if (!crypto_enabled) return 0;

    int new_len = packet_decrypt(&crypto_ctx, (uint8_t *)pkt_data, *pkt_len);
    if (new_len < 0) {
        return -1;
    }
    *pkt_len = (uint32_t)new_len;
    return 0;
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
    } 
    
    else if (ip->protocol == IPPROTO_UDP) {
        if (pkt_len < sizeof(struct ether_header) + ip_hdr_len + sizeof(struct udphdr))
            return -1;
        struct udphdr *udp = (struct udphdr *)transport;
        *src_port = ntohs(udp->source);
        *dst_port = ntohs(udp->dest);
    } 
    
    else {
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
    while (running) {
        sleep(60);  /* was 10s: GC lock contention caused drop spike at ~10s */
        flow_table_gc(&g_flow_table);
    }
    return NULL;
}

/* ========================================================================
 * NO-CRYPTO: Hàm riêng cho option không mã hóa - chỉ forward, không check gì
 * ======================================================================== */

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
                wan_idx = flow_table_get_wan(&g_flow_table,
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

            memcpy(pkt, wan->dst_mac, 6);
            memcpy(pkt + 6, wan->src_mac, 6);

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
                __sync_fetch_and_add(&fwd->total_dropped, 1);
                __sync_fetch_and_add(&fwd->dropped_no_local_match, 1);
                continue;
            }

            struct xsk_interface *local_iface = &fwd->locals[local_idx];
            struct local_config *local_cfg = &fwd->cfg->locals[local_idx];
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

            memcpy(pkt, local_cfg->dst_mac, 6);
            memcpy(pkt + 6, local_iface->src_mac, 6);

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


/* ========================================================================
 * LAYER 3/4: Hàm dùng cho L3 và L4 (enqueue to worker)
 * ======================================================================== */

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

        /* L3/L4: enqueue to worker ring */
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


/* ========================================================================
 * LAYER 3/4: wan_queue_thread cho Layer 3 và 4
 * ======================================================================== */

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

    struct frag_table *frag_tbl = calloc(1, sizeof(struct frag_table));
    if (frag_tbl)
        frag_table_init(frag_tbl);

    uint8_t reassemble_buf[4096];
    int gc_counter = 0;

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

            uint16_t frag_pkt_id;
            uint8_t frag_index;
            int is_frag = frag_is_fragment(pkt, pkt_len, &frag_pkt_id, &frag_index);

            if (is_frag) {
                int dec_len = frag_decrypt_fragment(&crypto_ctx, pkt, pkt_len,
                                                    &frag_pkt_id, &frag_index);
                if (dec_len < 0) {
                    __sync_fetch_and_add(&fwd->total_dropped, 1);
                    continue;
                }
                pkt_len = (uint32_t)dec_len;

                uint32_t reasm_len = 0;
                int ret = frag_try_reassemble(frag_tbl, pkt, pkt_len,
                                             frag_pkt_id, frag_index,
                                             reassemble_buf, &reasm_len);
                if (ret == 0) {
                    continue;
                } else if (ret == 1) {
                    final_pkt = reassemble_buf;
                    final_len = reasm_len;
                } else {
                    __sync_fetch_and_add(&fwd->total_dropped, 1);
                    continue;
                }
            } else {
                if (decrypt_packet(pkt, &pkt_len) != 0) {
                    __sync_fetch_and_add(&fwd->total_dropped, 1);
                    continue;
                }
                final_pkt = pkt;
                final_len = pkt_len;
            }

            /* Forward to local */
            uint32_t dest_ip = get_dest_ip(final_pkt, final_len);
            if (dest_ip == 0) {
                __sync_fetch_and_add(&fwd->total_dropped, 1);
                __sync_fetch_and_add(&fwd->dropped_bad_ip, 1);
                continue;
            }

            int local_idx = config_find_local_for_ip(fwd->cfg, dest_ip);
            if (local_idx < 0) {
                __sync_fetch_and_add(&fwd->total_dropped, 1);
                __sync_fetch_and_add(&fwd->dropped_no_local_match, 1);
                continue;
            }

            struct xsk_interface *local_iface = &fwd->locals[local_idx];
            struct local_config *local_cfg = &fwd->cfg->locals[local_idx];
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

            memcpy(final_pkt, local_cfg->dst_mac, 6);
            memcpy(final_pkt + 6, local_iface->src_mac, 6);

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

        if (frag_tbl && ++gc_counter >= 1000) {
            frag_table_gc(frag_tbl);
            gc_counter = 0;
        }
    }

    if (frag_tbl) free(frag_tbl);
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

        uint32_t src_ip, dst_ip;
        uint16_t src_port, dst_port;
        uint8_t protocol;

        int wan_idx;
        if (parse_flow(job.pkt_ptr, job.pkt_len,
                       &src_ip, &dst_ip, &src_port, &dst_port, &protocol) == 0) {
            wan_idx = flow_table_get_wan(&g_flow_table,
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

        if (!crypto_enabled) {
            uint8_t *pkt = (uint8_t *)job.pkt_ptr;
            memcpy(pkt, wan->dst_mac, 6);
            memcpy(pkt + 6, wan->src_mac, 6);

            if (interface_send_batch_queue(wan, tq, pkt, pkt_len) == 0) {
                __sync_fetch_and_add(&fwd->local_to_wan, 1);
                wan_used[wan_idx] = 1;
            } else {
                __sync_fetch_and_add(&fwd->total_dropped, 1);
            }
        } else if (crypto_layer == 3 && frag_need_split(pkt_len)) {

            uint8_t *pkt = (uint8_t *)job.pkt_ptr;
            memcpy(pkt, wan->dst_mac, 6);
            memcpy(pkt + 6, wan->src_mac, 6);

            uint32_t f1_len = 0, f2_len = 0;
            if (frag_split_and_encrypt(&crypto_ctx,
                                       pkt, pkt_len,
                                       frag1_buf, &f1_len,
                                       frag2_buf, &f2_len) != 0) {
                __sync_fetch_and_add(&fwd->total_dropped, 1);
                goto release_local;
            }

            memcpy(frag1_buf, wan->dst_mac, 6);
            memcpy(frag1_buf + 6, wan->src_mac, 6);
            memcpy(frag2_buf, wan->dst_mac, 6);
            memcpy(frag2_buf + 6, wan->src_mac, 6);

            uint32_t wire_total = f1_len + f2_len;
            if (wire_total > pkt_len) {
                flow_table_add_bytes(&g_flow_table,
                                     src_ip, dst_ip, src_port, dst_port,
                                     protocol, wire_total - pkt_len);
            }

            if (interface_send_batch_queue(wan, tq, frag1_buf, f1_len) == 0) {
                __sync_fetch_and_add(&fwd->local_to_wan, 1);
                wan_used[wan_idx] = 1;
            } else {
                __sync_fetch_and_add(&fwd->total_dropped, 1);
            }

            if (interface_send_batch_queue(wan, tq, frag2_buf, f2_len) == 0) {
                __sync_fetch_and_add(&fwd->local_to_wan, 1);
            } else {
                __sync_fetch_and_add(&fwd->total_dropped, 1);
            }

        } else if (crypto_layer == 2 && frag_need_split_l2(pkt_len)) {

            uint8_t *pkt = (uint8_t *)job.pkt_ptr;
            memcpy(pkt, wan->dst_mac, 6);
            memcpy(pkt + 6, wan->src_mac, 6);

            uint32_t f1_len = 0, f2_len = 0;
            if (frag_split_and_encrypt_l2(&crypto_ctx,
                                          pkt, pkt_len,
                                          frag1_buf, &f1_len,
                                          frag2_buf, &f2_len) != 0) {
                __sync_fetch_and_add(&fwd->total_dropped, 1);
                goto release_local;
            }

            memcpy(frag1_buf, wan->dst_mac, 6);
            memcpy(frag1_buf + 6, wan->src_mac, 6);
            memcpy(frag2_buf, wan->dst_mac, 6);
            memcpy(frag2_buf + 6, wan->src_mac, 6);

            uint32_t wire_total = f1_len + f2_len;
            if (wire_total > pkt_len) {
                flow_table_add_bytes(&g_flow_table,
                                     src_ip, dst_ip, src_port, dst_port,
                                     protocol, wire_total - pkt_len);
            }

            if (interface_send_batch_queue(wan, tq, frag1_buf, f1_len) == 0) {
                __sync_fetch_and_add(&fwd->local_to_wan, 1);
                wan_used[wan_idx] = 1;
            } else {
                __sync_fetch_and_add(&fwd->total_dropped, 1);
            }

            if (interface_send_batch_queue(wan, tq, frag2_buf, f2_len) == 0) {
                __sync_fetch_and_add(&fwd->local_to_wan, 1);
            } else {
                __sync_fetch_and_add(&fwd->total_dropped, 1);
            }

        } else {
            if (crypto_layer == 2) {
                uint8_t *pkt = (uint8_t *)job.pkt_ptr;
                memcpy(pkt, wan->dst_mac, 6);
                memcpy(pkt + 6, wan->src_mac, 6);
            }

            if (encrypt_packet(job.pkt_ptr, &pkt_len) != 0) {
                __sync_fetch_and_add(&fwd->total_dropped, 1);
                goto release_local;
            }

            if (interface_send_batch_queue(wan, tq, job.pkt_ptr, pkt_len) == 0) {
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

    crypto_enabled = cfg->crypto_enabled;
    crypto_layer = cfg->encrypt_layer;
    if (crypto_enabled) {
        packet_crypto_set_aes_bits(cfg->aes_bits);
        if (packet_crypto_init(&crypto_ctx, cfg->crypto_key) != 0) {
            fprintf(stderr, "Failed to initialize AES-%d encryption\n", cfg->aes_bits);
            return -1;
        }
        packet_crypto_set_encrypt_layer(cfg->encrypt_layer);
        packet_crypto_set_mode(cfg->crypto_mode);
        packet_crypto_set_nonce_size(cfg->nonce_size);
        if (crypto_layer == 2) {
            packet_crypto_set_ethertype(cfg->fake_ethertype_ipv4, cfg->fake_ethertype_ipv6);
        }
        if (crypto_layer == 2 || crypto_layer == 3) {
            if (cfg->fake_protocol != 0)
                packet_crypto_set_fake_protocol(cfg->fake_protocol);
            else
                packet_crypto_set_fake_protocol(99);
        }
    }

    /* Tự động set queue count cho local nếu chưa được config */
    for (int i = 0; i < cfg->local_count; i++) {
        if (cfg->locals[i].queue_count <= 1) {
            int want = 4;
            interface_set_queue_count(cfg->locals[i].ifname, want);
            int hwq = interface_get_queue_count(cfg->locals[i].ifname);
            if (hwq > 1)
                cfg->locals[i].queue_count = hwq;
        }
    }

    /* Tự động set queue count cho WAN nếu chưa được config */
    if (!crypto_enabled) {
        for (int i = 0; i < cfg->wan_count; i++) {
            if (cfg->wans[i].queue_count <= 1) {
                int hwq = interface_get_queue_count(cfg->wans[i].ifname);
                if (hwq > 1)
                    cfg->wans[i].queue_count = hwq;
            }
        }
    }

    uint32_t window_size = cfg->wans[0].window_size;
    flow_table_init(&g_flow_table, window_size, cfg->wan_count);

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
            goto err_locals;
        }
        fwd->local_count++;
    }

    for (int i = 0; i < cfg->wan_count; i++) {
        uint16_t wan_fake4 = (crypto_enabled && crypto_layer == 2) ? cfg->fake_ethertype_ipv4 : 0;
        uint16_t wan_fake6 = (crypto_enabled && crypto_layer == 2) ? cfg->fake_ethertype_ipv6 : 0;
        if (interface_init_wan_rx(&fwd->wans[i], &cfg->wans[i], "bpf/xdp_wan_redirect.o", wan_fake4, wan_fake6) != 0) {
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

/* ========================================================================
 * PER-OPTION forwarder_run implementations
 * Mỗi option có hàm run riêng, core layout riêng, không đụng chạm nhau.
 * ======================================================================== */

/* NO-CRYPTO: Ring Mode với 5 core mỗi chiều
 * Local→WAN: core 0-4
 * WAN→Local: core 5-9 */
static void forwarder_run_no_crypto(struct forwarder *fwd) {
    fprintf(stderr, "[NO-CRYPTO RING] Starting with %d workers per direction\n", NUM_RING_WORKERS);
    
    /* Init rings */
    for (int i = 0; i < NUM_RING_WORKERS; i++) {
        g_local_to_wan_rings[i].head = 0;
        g_local_to_wan_rings[i].tail = 0;
        pthread_mutex_init(&g_local_to_wan_rings[i].lock, NULL);
        
        g_wan_to_local_rings[i].head = 0;
        g_wan_to_local_rings[i].tail = 0;
        pthread_mutex_init(&g_wan_to_local_rings[i].lock, NULL);
    }
    
    int total_local_queues = 0;
    for (int i = 0; i < fwd->local_count; i++)
        total_local_queues += fwd->locals[i].queue_count;
    
    int total_wan_queues = 0;
    for (int i = 0; i < fwd->wan_count; i++)
        total_wan_queues += fwd->wans[i].queue_count;
    
    int total_threads = total_local_queues + total_wan_queues + NUM_RING_WORKERS * 2;
    
    fprintf(stderr, "[NO-CRYPTO RING] local_queues=%d, wan_queues=%d, workers=%d, total_threads=%d\n",
            total_local_queues, total_wan_queues, NUM_RING_WORKERS * 2, total_threads);
    
    pthread_t *threads = calloc(total_threads, sizeof(pthread_t));
    struct queue_thread_args *args = calloc(total_threads, sizeof(struct queue_thread_args));
    if (!threads || !args) {
        fprintf(stderr, "[NO-CRYPTO RING] Failed to allocate\n");
        free(threads); free(args);
        return;
    }
    
    pthread_t gc_tid;
    pthread_create(&gc_tid, NULL, gc_thread, NULL);
    
    int thread_idx = 0;
    
    /* Local RX dispatchers - chia đều trên core 0-4 */
    int local_disp_idx = 0;
    for (int i = 0; i < fwd->local_count; i++) {
        struct xsk_interface *local = &fwd->locals[i];
        for (int q = 0; q < local->queue_count; q++) {
            args[thread_idx].fwd = fwd;
            args[thread_idx].iface_idx = i;
            args[thread_idx].queue_idx = q;
            args[thread_idx].core_id = local_disp_idx % NUM_RING_WORKERS;
            pthread_create(&threads[thread_idx], NULL, local_rx_dispatcher_thread, &args[thread_idx]);
            thread_idx++;
            local_disp_idx++;
        }
    }
    
    /* WAN RX dispatchers - chia đều trên core 5-9 */
    int wan_disp_idx = 0;
    for (int i = 0; i < fwd->wan_count; i++) {
        struct xsk_interface *wan = &fwd->wans[i];
        for (int q = 0; q < wan->queue_count; q++) {
            args[thread_idx].fwd = fwd;
            args[thread_idx].iface_idx = i;
            args[thread_idx].queue_idx = q;
            args[thread_idx].core_id = 5 + (wan_disp_idx % NUM_RING_WORKERS);
            pthread_create(&threads[thread_idx], NULL, wan_rx_dispatcher_thread, &args[thread_idx]);
            thread_idx++;
            wan_disp_idx++;
        }
    }
    
    /* Local→WAN workers: core 0-4 */
    for (int w = 0; w < NUM_RING_WORKERS; w++) {
        args[thread_idx].fwd = fwd;
        args[thread_idx].worker_id = w;
        args[thread_idx].core_id = w;
        pthread_create(&threads[thread_idx], NULL, local_to_wan_ring_worker, &args[thread_idx]);
        thread_idx++;
    }
    
    /* WAN→Local workers: core 5-9 */
    for (int w = 0; w < NUM_RING_WORKERS; w++) {
        args[thread_idx].fwd = fwd;
        args[thread_idx].worker_id = w;
        args[thread_idx].core_id = 5 + w;
        pthread_create(&threads[thread_idx], NULL, wan_to_local_ring_worker, &args[thread_idx]);
        thread_idx++;
    }
    
    fprintf(stderr, "[NO-CRYPTO RING] All %d threads started\n", thread_idx);
    
    while (running) sleep(1);
    
    for (int i = 0; i < thread_idx; i++)
        pthread_join(threads[i], NULL);
    pthread_join(gc_tid, NULL);
    
    free(threads);
    free(args);
}

/* LAYER2: Local->WAN trên core 0-3 (rã gói + mã hóa + fw),
 *         WAN->Local trên core 4-7 (giải mã + ráp gói + fw) */
/* LAYER3: Local->WAN trên core 0-3 (RX) + core 4-7 (worker crypto/fw),
 *         WAN->Local trên core 8-11 */
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

    /* Local RX: core 0-3, dùng hàm L3/L4 */
    int local_rx_idx = 0;
    for (int i = 0; i < fwd->local_count; i++) {
        struct xsk_interface *local = &fwd->locals[i];
        for (int q = 0; q < local->queue_count; q++) {
            args[thread_idx].fwd = fwd;
            args[thread_idx].iface_idx = i;
            args[thread_idx].queue_idx = q;
            args[thread_idx].tx_queue_base = q;
            args[thread_idx].core_id = local_rx_idx % 4;
            args[thread_idx].wan_worker_index = -1;
            args[thread_idx].worker_id = -1;
            pthread_create(&threads[thread_idx], NULL, local_queue_thread_l3l4, &args[thread_idx]);
            thread_idx++;
            local_rx_idx++;
        }
    }

    /* WAN->Local: core 8-11, dùng hàm L3/L4 */
    int wan_worker_idx = 0;
    for (int i = 0; i < fwd->wan_count; i++) {
        struct xsk_interface *wan = &fwd->wans[i];
        for (int q = 0; q < wan->queue_count; q++) {
            args[thread_idx].fwd = fwd;
            args[thread_idx].iface_idx = i;
            args[thread_idx].queue_idx = q;
            args[thread_idx].tx_queue_base = q;
            args[thread_idx].core_id = 8 + (wan_worker_idx % 4);
            args[thread_idx].wan_worker_index = wan_worker_idx;
            args[thread_idx].worker_id = -1;
            pthread_create(&threads[thread_idx], NULL, wan_queue_thread_l3l4, &args[thread_idx]);
            wan_worker_idx++;
            thread_idx++;
        }
    }

    /* Worker crypto/fw Local->WAN: core 4-7 */
    for (int w = 0; w < NUM_WORKERS; w++) {
        args[thread_idx].fwd = fwd;
        args[thread_idx].iface_idx = -1;
        args[thread_idx].queue_idx = -1;
        args[thread_idx].tx_queue_base = 0;
        args[thread_idx].core_id = 4 + w;
        args[thread_idx].wan_worker_index = -1;
        args[thread_idx].worker_id = w;
        pthread_create(&threads[thread_idx], NULL, worker_thread, &args[thread_idx]);
        thread_idx++;
    }

    while (running)
        sleep(1);

    for (int i = 0; i < total_threads; i++)
        pthread_join(threads[i], NULL);
    pthread_join(gc_tid, NULL);

    free(threads);
    free(args);
}

/* LAYER4: Tương tự L3, có thể tùy chỉnh core layout riêng sau */
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

    /* Local RX: core 0-3, dùng hàm L3/L4 */
    int local_rx_idx = 0;
    for (int i = 0; i < fwd->local_count; i++) {
        struct xsk_interface *local = &fwd->locals[i];
        for (int q = 0; q < local->queue_count; q++) {
            args[thread_idx].fwd = fwd;
            args[thread_idx].iface_idx = i;
            args[thread_idx].queue_idx = q;
            args[thread_idx].tx_queue_base = q;
            args[thread_idx].core_id = local_rx_idx % 4;
            args[thread_idx].wan_worker_index = -1;
            args[thread_idx].worker_id = -1;
            pthread_create(&threads[thread_idx], NULL, local_queue_thread_l3l4, &args[thread_idx]);
            thread_idx++;
            local_rx_idx++;
        }
    }

    /* WAN->Local: core 8-11, dùng hàm L3/L4 */
    int wan_worker_idx = 0;
    for (int i = 0; i < fwd->wan_count; i++) {
        struct xsk_interface *wan = &fwd->wans[i];
        for (int q = 0; q < wan->queue_count; q++) {
            args[thread_idx].fwd = fwd;
            args[thread_idx].iface_idx = i;
            args[thread_idx].queue_idx = q;
            args[thread_idx].tx_queue_base = q;
            args[thread_idx].core_id = 8 + (wan_worker_idx % 4);
            args[thread_idx].wan_worker_index = wan_worker_idx;
            args[thread_idx].worker_id = -1;
            pthread_create(&threads[thread_idx], NULL, wan_queue_thread_l3l4, &args[thread_idx]);
            wan_worker_idx++;
            thread_idx++;
        }
    }

    /* Worker crypto/fw Local->WAN: core 4-7 */
    for (int w = 0; w < NUM_WORKERS; w++) {
        args[thread_idx].fwd = fwd;
        args[thread_idx].iface_idx = -1;
        args[thread_idx].queue_idx = -1;
        args[thread_idx].tx_queue_base = 0;
        args[thread_idx].core_id = 4 + w;
        args[thread_idx].wan_worker_index = -1;
        args[thread_idx].worker_id = w;
        pthread_create(&threads[thread_idx], NULL, worker_thread, &args[thread_idx]);
        thread_idx++;
    }

    while (running)
        sleep(1);

    for (int i = 0; i < total_threads; i++)
        pthread_join(threads[i], NULL);
    pthread_join(gc_tid, NULL);

    free(threads);
    free(args);
}

/* ========================================================================
 * RING MODE: Software ring buffer - không phụ thuộc số queue NIC
 * Local → WAN: 5 core (0-4)
 * WAN → Local: 5 core (5-9)
 * ======================================================================== */

/* Helper: Flow hash để cùng flow vào cùng worker (tránh reorder) */
static inline uint32_t ring_flow_hash(const uint8_t *pkt, uint32_t len) {
    if (len < 34) return 0;
    uint16_t ethertype = ((uint16_t)pkt[12] << 8) | pkt[13];
    
    /* IPv4 */
    if (ethertype == 0x0800) {
        uint32_t src_ip = *(uint32_t *)(pkt + 26);
        uint32_t dst_ip = *(uint32_t *)(pkt + 30);
        uint8_t protocol = pkt[23];
        
        uint32_t h = src_ip ^ dst_ip;
        
        /* Thêm port nếu là TCP/UDP - phân bố đều hơn */
        if (len >= 38 && (protocol == 6 || protocol == 17)) {
            uint16_t src_port = ((uint16_t)pkt[34] << 8) | pkt[35];
            uint16_t dst_port = ((uint16_t)pkt[36] << 8) | pkt[37];
            h ^= ((uint32_t)src_port << 16) | dst_port;
        }
        
        h ^= (h >> 16);
        h *= 0x85ebca6b;
        h ^= (h >> 13);
        h *= 0xc2b2ae35;
        h ^= (h >> 16);
        return h;
    }
    
    /* IPv6 */
    if (ethertype == 0x86DD && len >= 54) {
        /* Hash dựa trên last 4 bytes của src + dst IPv6 */
        uint32_t src_suffix = *(uint32_t *)(pkt + 34);
        uint32_t dst_suffix = *(uint32_t *)(pkt + 50);
        uint32_t h = src_suffix ^ dst_suffix;
        h ^= (h >> 16);
        h *= 0x85ebca6b;
        return h;
    }
    
    return 0;
}

/* Helper: Enqueue packet vào ring (thread-safe) */
static inline int ring_enqueue(struct sw_ring *ring, const uint8_t *pkt, uint32_t len,
                               int iface_idx, int queue_idx) {
    pthread_mutex_lock(&ring->lock);
    
    uint32_t next_tail = (ring->tail + 1) % SW_RING_SIZE;
    if (next_tail == ring->head) {
        pthread_mutex_unlock(&ring->lock);
        return -1; /* Ring full */
    }
    
    struct ring_packet *slot = &ring->packets[ring->tail];
    if (len > sizeof(slot->data)) len = sizeof(slot->data);
    memcpy(slot->data, pkt, len);
    slot->len = len;
    slot->src_iface_idx = iface_idx;
    slot->src_queue_idx = queue_idx;
    
    ring->tail = next_tail;
    pthread_mutex_unlock(&ring->lock);
    return 0;
}

/* Helper: Dequeue packet từ ring (single consumer, không cần lock) */
static inline int ring_dequeue(struct sw_ring *ring, struct ring_packet *out) {
    if (ring->head == ring->tail) {
        return -1; /* Ring empty */
    }
    
    *out = ring->packets[ring->head];
    ring->head = (ring->head + 1) % SW_RING_SIZE;
    return 0;
}

/* -------- LOCAL RX DISPATCHER: Thu gói từ local, đẩy vào 5 ring -------- */
static volatile uint64_t g_local_disp_recv = 0;
static volatile uint64_t g_local_disp_enqueue = 0;

static void *local_rx_dispatcher_thread(void *arg) {
    struct queue_thread_args *args = (struct queue_thread_args *)arg;
    struct forwarder *fwd = args->fwd;
    pin_thread_to_core(args->core_id);
    
    int local_idx = args->iface_idx;
    int queue_idx = args->queue_idx;
    struct xsk_interface *local = &fwd->locals[local_idx];
    int batch_size = local->batch_size;
    
    fprintf(stderr, "[LOCAL_DISP] Started: local_idx=%d queue_idx=%d core=%d\n", 
            local_idx, queue_idx, args->core_id);
    
    void *pkt_ptrs[MAX_BATCH_SIZE];
    uint32_t pkt_lens[MAX_BATCH_SIZE];
    uint64_t addrs[MAX_BATCH_SIZE];
    
    while (running) {
        int rcvd = interface_recv_single_queue(local, queue_idx,
                                               pkt_ptrs, pkt_lens, addrs, batch_size);
        if (rcvd <= 0) continue;
        
        __sync_fetch_and_add(&g_local_disp_recv, rcvd);
        
        for (int i = 0; i < rcvd; i++) {
            uint8_t *pkt = (uint8_t *)pkt_ptrs[i];
            uint32_t len = pkt_lens[i];
            
            /* Flow hash để chọn worker */
            uint32_t hash = ring_flow_hash(pkt, len);
            int target = hash % NUM_RING_WORKERS;
            
            if (ring_enqueue(&g_local_to_wan_rings[target], pkt, len, local_idx, queue_idx) == 0) {
                __sync_fetch_and_add(&g_local_disp_enqueue, 1);
            } else {
                __sync_fetch_and_add(&fwd->total_dropped, 1);
            }
        }
        
        interface_recv_release_single_queue(local, queue_idx, addrs, rcvd);
    }
    
    return NULL;
}

/* -------- WAN RX DISPATCHER: Thu gói từ WAN, đẩy vào 5 ring -------- */
/* Hash dựa trên source MAC để 2 mảnh fragment cùng nguồn vào cùng ring */
static inline uint32_t wan_source_hash(const uint8_t *pkt, uint32_t len) {
    if (len < 14) return 0;
    
    /* Hash source MAC (bytes 6-11) - 2 mảnh cùng nguồn = cùng ring */
    uint32_t h = 0;
    h ^= *(uint32_t *)(pkt + 6);      /* 4 bytes đầu src MAC */
    h ^= (uint32_t)(*(uint16_t *)(pkt + 10)) << 16;  /* 2 bytes cuối src MAC */
    
    /* MurmurHash finalizer */
    h ^= (h >> 16);
    h *= 0x85ebca6b;
    h ^= (h >> 13);
    h *= 0xc2b2ae35;
    h ^= (h >> 16);
    
    return h;
}

static volatile uint64_t g_wan_disp_recv = 0;
static volatile uint64_t g_wan_disp_enqueue = 0;

static void *wan_rx_dispatcher_thread(void *arg) {
    struct queue_thread_args *args = (struct queue_thread_args *)arg;
    struct forwarder *fwd = args->fwd;
    pin_thread_to_core(args->core_id);
    
    int wan_idx = args->iface_idx;
    int queue_idx = args->queue_idx;
    struct xsk_interface *wan = &fwd->wans[wan_idx];
    int batch_size = wan->batch_size;
    
    fprintf(stderr, "[WAN_DISP] Started: wan_idx=%d queue_idx=%d core=%d\n", 
            wan_idx, queue_idx, args->core_id);
    
    void *pkt_ptrs[MAX_BATCH_SIZE];
    uint32_t pkt_lens[MAX_BATCH_SIZE];
    uint64_t addrs[MAX_BATCH_SIZE];
    
    int is_encrypted = crypto_enabled && crypto_layer == 2;
    
    while (running) {
        int rcvd = interface_recv_single_queue(wan, queue_idx,
                                               pkt_ptrs, pkt_lens, addrs, batch_size);
        if (rcvd <= 0) continue;
        
        __sync_fetch_and_add(&g_wan_disp_recv, rcvd);
        
        for (int i = 0; i < rcvd; i++) {
            uint8_t *pkt = (uint8_t *)pkt_ptrs[i];
            uint32_t len = pkt_lens[i];
            
            uint32_t hash;
            if (is_encrypted) {
                /* Hash source MAC - đảm bảo 2 mảnh fragment cùng nguồn vào cùng ring */
                hash = wan_source_hash(pkt, len);
            } else {
                /* Flow hash cho gói tin không mã hóa */
                hash = ring_flow_hash(pkt, len);
            }
            int target = hash % NUM_RING_WORKERS;
            
            if (ring_enqueue(&g_wan_to_local_rings[target], pkt, len, wan_idx, queue_idx) == 0) {
                __sync_fetch_and_add(&g_wan_disp_enqueue, 1);
            } else {
                __sync_fetch_and_add(&fwd->total_dropped, 1);
            }
        }
        
        interface_recv_release_single_queue(wan, queue_idx, addrs, rcvd);
    }
    
    return NULL;
}

/* -------- LOCAL→WAN WORKER: Lấy từ ring, mã hóa, forward -------- */
static volatile uint64_t g_l2w_worker_processed = 0;

static void *local_to_wan_ring_worker(void *arg) {
    struct queue_thread_args *args = (struct queue_thread_args *)arg;
    struct forwarder *fwd = args->fwd;
    int worker_id = args->worker_id;
    pin_thread_to_core(args->core_id);
    
    fprintf(stderr, "[L2W_WORKER] Started: worker_id=%d core=%d\n", worker_id, args->core_id);
    
    struct sw_ring *ring = &g_local_to_wan_rings[worker_id];
    struct ring_packet pkt;
    
    uint8_t frag1_buf[2048];
    uint8_t frag2_buf[2048];
    
    /* Layer 2 encryption */
    int is_l2_crypto = crypto_enabled && crypto_layer == 2;
    
    while (running) {
        if (ring_dequeue(ring, &pkt) != 0) {
            /* Ring empty, spin wait */
            for (volatile int i = 0; i < 100; i++);
            continue;
        }
        
        __sync_fetch_and_add(&g_l2w_worker_processed, 1);
        
        uint8_t *data = pkt.data;
        uint32_t len = pkt.len;
        
        /* Chọn WAN interface dựa trên flow */
        uint32_t src_ip = 0, dst_ip = 0;
        uint16_t src_port = 0, dst_port = 0;
        uint8_t protocol = 0;
        int wan_idx = 0;
        
        if (len >= 34) {
            src_ip = *(uint32_t *)(data + 26);
            dst_ip = *(uint32_t *)(data + 30);
            protocol = data[23];
            if (len >= 38) {
                src_port = ((uint16_t)data[34] << 8) | data[35];
                dst_port = ((uint16_t)data[36] << 8) | data[37];
            }
            wan_idx = flow_table_get_wan(&g_flow_table, src_ip, dst_ip, 
                                         src_port, dst_port, protocol, len);
        }
        
        if (wan_idx < 0 || wan_idx >= fwd->wan_count) wan_idx = 0;
        struct xsk_interface *wan = &fwd->wans[wan_idx];
        int tx_q = worker_id % wan->queue_count;
        
        /* Copy MAC */
        memcpy(data, wan->dst_mac, 6);
        memcpy(data + 6, wan->src_mac, 6);
        
        if (is_l2_crypto) {
            /* Layer 2: rã gói nếu cần + mã hóa */
            if (frag_need_split_l2(len)) {
                uint32_t f1_len = 0, f2_len = 0;
                if (frag_split_and_encrypt_l2(&crypto_ctx, data, len,
                                              frag1_buf, &f1_len,
                                              frag2_buf, &f2_len) != 0) {
                    __sync_fetch_and_add(&fwd->total_dropped, 1);
                    continue;
                }
                memcpy(frag1_buf, wan->dst_mac, 6);
                memcpy(frag1_buf + 6, wan->src_mac, 6);
                memcpy(frag2_buf, wan->dst_mac, 6);
                memcpy(frag2_buf + 6, wan->src_mac, 6);
                
                if (interface_send_batch_queue(wan, tx_q, frag1_buf, f1_len) == 0)
                    __sync_fetch_and_add(&fwd->local_to_wan, 1);
                if (interface_send_batch_queue(wan, tx_q, frag2_buf, f2_len) == 0)
                    __sync_fetch_and_add(&fwd->local_to_wan, 1);
                interface_send_flush_queue(wan, tx_q);
            } else {
                if (encrypt_packet(data, &len) != 0) {
                    __sync_fetch_and_add(&fwd->total_dropped, 1);
                    continue;
                }
                if (interface_send_batch_queue(wan, tx_q, data, len) == 0) {
                    __sync_fetch_and_add(&fwd->local_to_wan, 1);
                    interface_send_flush_queue(wan, tx_q);
                }
            }
        } else {
            /* NO CRYPTO: chỉ forward */
            if (interface_send_batch_queue(wan, tx_q, data, len) == 0) {
                __sync_fetch_and_add(&fwd->local_to_wan, 1);
                interface_send_flush_queue(wan, tx_q);
            }
        }
    }
    
    return NULL;
}

/* -------- WAN→LOCAL WORKER: Lấy từ ring, giải mã, forward -------- */
static volatile uint64_t g_w2l_worker_processed = 0;

static void *wan_to_local_ring_worker(void *arg) {
    struct queue_thread_args *args = (struct queue_thread_args *)arg;
    struct forwarder *fwd = args->fwd;
    int worker_id = args->worker_id;
    pin_thread_to_core(args->core_id);
    
    fprintf(stderr, "[W2L_WORKER] Started: worker_id=%d core=%d\n", worker_id, args->core_id);
    
    struct sw_ring *ring = &g_wan_to_local_rings[worker_id];
    struct ring_packet pkt;
    
    /* Layer 2 encryption */
    int is_l2_crypto = crypto_enabled && crypto_layer == 2;
    
    struct frag_table *frag_tbl = NULL;
    if (is_l2_crypto) {
        frag_tbl = calloc(1, sizeof(struct frag_table));
        if (frag_tbl) frag_table_init(frag_tbl);
    }
    
    uint8_t reassemble_buf[4096];
    int gc_counter = 0;
    
    while (running) {
        if (ring_dequeue(ring, &pkt) != 0) {
            for (volatile int i = 0; i < 100; i++);
            continue;
        }
        
        __sync_fetch_and_add(&g_w2l_worker_processed, 1);
        
        uint8_t *data = pkt.data;
        uint32_t len = pkt.len;
        uint8_t *final_pkt = data;
        uint32_t final_len = len;
        
        if (is_l2_crypto) {
            /* Giải mã L2 */
            if (decrypt_packet(data, &len) != 0) {
                __sync_fetch_and_add(&fwd->total_dropped, 1);
                continue;
            }
            final_pkt = data;
            final_len = len;
            
            /* Ráp gói nếu là fragment */
            if (frag_tbl) {
                uint16_t l2_pkt_id;
                uint8_t l2_frag_index;
                if (frag_is_fragment_l2(data, len, &l2_pkt_id, &l2_frag_index)) {
                    uint32_t reasm_len = 0;
                    int ret = frag_try_reassemble_l2(frag_tbl, data, len,
                                                     l2_pkt_id, l2_frag_index,
                                                     reassemble_buf, &reasm_len);
                    if (ret == 0) continue;
                    else if (ret == 1) {
                        final_pkt = reassemble_buf;
                        final_len = reasm_len;
                    } else {
                        __sync_fetch_and_add(&fwd->total_dropped, 1);
                        continue;
                    }
                }
            }
        }
        
        /* Tìm local interface */
        uint32_t dest_ip = get_dest_ip(final_pkt, final_len);
        if (dest_ip == 0) {
            __sync_fetch_and_add(&fwd->total_dropped, 1);
            continue;
        }
        
        int local_idx = config_find_local_for_ip(fwd->cfg, dest_ip);
        if (local_idx < 0) {
            __sync_fetch_and_add(&fwd->total_dropped, 1);
            continue;
        }
        
        struct xsk_interface *local_iface = &fwd->locals[local_idx];
        struct local_config *local_cfg = &fwd->cfg->locals[local_idx];
        int tx_q = worker_id % local_iface->queue_count;
        if (tx_q < 0) tx_q = 0;
        
        memcpy(final_pkt, local_cfg->dst_mac, 6);
        memcpy(final_pkt + 6, local_iface->src_mac, 6);
        
        if (interface_send_to_local_batch_queue(local_iface, tx_q, local_cfg, final_pkt, final_len) == 0) {
            __sync_fetch_and_add(&fwd->wan_to_local, 1);
            interface_send_to_local_flush_queue(local_iface, tx_q);
        } else {
            __sync_fetch_and_add(&fwd->total_dropped, 1);
        }
        
        if (frag_tbl && ++gc_counter >= 1000) {
            frag_table_gc(frag_tbl);
            gc_counter = 0;
        }
    }
    
    if (frag_tbl) free(frag_tbl);
    return NULL;
}

/* -------- MAIN: forwarder_run_ring_mode -------- */
static void forwarder_run_ring_mode(struct forwarder *fwd) {
    fprintf(stderr, "[RING MODE] Starting with %d workers per direction\n", NUM_RING_WORKERS);
    
    /* Init rings */
    for (int i = 0; i < NUM_RING_WORKERS; i++) {
        g_local_to_wan_rings[i].head = 0;
        g_local_to_wan_rings[i].tail = 0;
        pthread_mutex_init(&g_local_to_wan_rings[i].lock, NULL);
        
        g_wan_to_local_rings[i].head = 0;
        g_wan_to_local_rings[i].tail = 0;
        pthread_mutex_init(&g_wan_to_local_rings[i].lock, NULL);
    }
    
    /* Count total threads:
     * - Local RX dispatchers (1 per local queue)
     * - WAN RX dispatchers (1 per WAN queue)
     * - Local→WAN workers (5)
     * - WAN→Local workers (5)
     */
    int total_local_queues = 0;
    for (int i = 0; i < fwd->local_count; i++)
        total_local_queues += fwd->locals[i].queue_count;
    
    int total_wan_queues = 0;
    for (int i = 0; i < fwd->wan_count; i++)
        total_wan_queues += fwd->wans[i].queue_count;
    
    int total_threads = total_local_queues + total_wan_queues + NUM_RING_WORKERS * 2;
    
    fprintf(stderr, "[RING MODE] local_queues=%d, wan_queues=%d, workers=%d, total_threads=%d\n",
            total_local_queues, total_wan_queues, NUM_RING_WORKERS * 2, total_threads);
    
    pthread_t *threads = calloc(total_threads, sizeof(pthread_t));
    struct queue_thread_args *args = calloc(total_threads, sizeof(struct queue_thread_args));
    if (!threads || !args) {
        fprintf(stderr, "[RING MODE] Failed to allocate\n");
        free(threads); free(args);
        return;
    }
    
    pthread_t gc_tid;
    pthread_create(&gc_tid, NULL, gc_thread, NULL);
    
    int thread_idx = 0;
    
    /* Local RX dispatchers - chia đều trên core 0-4 (chia sẻ với Local→WAN workers) */
    int local_disp_idx = 0;
    for (int i = 0; i < fwd->local_count; i++) {
        struct xsk_interface *local = &fwd->locals[i];
        for (int q = 0; q < local->queue_count; q++) {
            args[thread_idx].fwd = fwd;
            args[thread_idx].iface_idx = i;
            args[thread_idx].queue_idx = q;
            args[thread_idx].core_id = local_disp_idx % NUM_RING_WORKERS; /* Core 0-4 */
            pthread_create(&threads[thread_idx], NULL, local_rx_dispatcher_thread, &args[thread_idx]);
            thread_idx++;
            local_disp_idx++;
        }
    }
    
    /* WAN RX dispatchers - chia đều trên core 5-9 (chia sẻ với WAN→Local workers) */
    int wan_disp_idx = 0;
    for (int i = 0; i < fwd->wan_count; i++) {
        struct xsk_interface *wan = &fwd->wans[i];
        for (int q = 0; q < wan->queue_count; q++) {
            args[thread_idx].fwd = fwd;
            args[thread_idx].iface_idx = i;
            args[thread_idx].queue_idx = q;
            args[thread_idx].core_id = 5 + (wan_disp_idx % NUM_RING_WORKERS); /* Core 5-9 */
            pthread_create(&threads[thread_idx], NULL, wan_rx_dispatcher_thread, &args[thread_idx]);
            thread_idx++;
            wan_disp_idx++;
        }
    }
    
    /* Local→WAN workers: core 0-4 */
    for (int w = 0; w < NUM_RING_WORKERS; w++) {
        args[thread_idx].fwd = fwd;
        args[thread_idx].worker_id = w;
        args[thread_idx].core_id = w; /* Core 0, 1, 2, 3, 4 */
        pthread_create(&threads[thread_idx], NULL, local_to_wan_ring_worker, &args[thread_idx]);
        thread_idx++;
    }
    
    /* WAN→Local workers: core 5-9 */
    for (int w = 0; w < NUM_RING_WORKERS; w++) {
        args[thread_idx].fwd = fwd;
        args[thread_idx].worker_id = w;
        args[thread_idx].core_id = 5 + w; /* Core 5, 6, 7, 8, 9 */
        pthread_create(&threads[thread_idx], NULL, wan_to_local_ring_worker, &args[thread_idx]);
        thread_idx++;
    }
    
    fprintf(stderr, "[RING MODE] All %d threads started\n", thread_idx);
    
    while (running) sleep(1);
    
    for (int i = 0; i < thread_idx; i++)
        pthread_join(threads[i], NULL);
    pthread_join(gc_tid, NULL);
    
    free(threads);
    free(args);
}

/* ======================================================================== */

void forwarder_run(struct forwarder *fwd) {
    signal(SIGINT, sigint_handler);
    signal(SIGTERM, sigint_handler);

    if (!crypto_enabled) {
        forwarder_run_no_crypto(fwd);
    } else if (crypto_layer == 2) {
        /* Layer 2: Software ring buffer, 5 core mỗi chiều */
        fprintf(stderr, "[FORWARDER] Layer 2 with Software Ring (5 cores per direction)\n");
        forwarder_run_ring_mode(fwd);
    } else if (crypto_layer == 3) {
        forwarder_run_l3(fwd);
    } else if (crypto_layer == 4) {
        forwarder_run_l4(fwd);
    } else {
        /* Fallback: dùng L3-style */
        forwarder_run_l3(fwd);
    }
}

void forwarder_print_stats(struct forwarder *fwd) {
    if (!fwd) return;

    int nq = (fwd->local_count > 0 && fwd->locals[0].queue_count <= FORWARDER_MAX_LOCAL_QUEUES)
             ? fwd->locals[0].queue_count : 0;
    if (nq <= 0) nq = 1;

    uint64_t tx_wait_loops = 0;
    for (int i = 0; i < fwd->local_count; i++) {
        for (int q = 0; q < fwd->locals[i].queue_count && q < MAX_QUEUES; q++)
            tx_wait_loops += fwd->locals[i].queues[q].tx_wait_loops;
    }

    fprintf(stdout,
            "[STATS] local_to_wan=%lu wan_to_local=%lu total_dropped=%lu "
            "dropped_bad_ip=%lu dropped_no_local_match=%lu dropped_local_tx_fail=%lu",
            fwd->local_to_wan,
            fwd->wan_to_local,
            fwd->total_dropped,
            fwd->dropped_bad_ip,
            fwd->dropped_no_local_match,
            fwd->dropped_local_tx_fail);
    for (int i = 0; i < nq && i < FORWARDER_MAX_LOCAL_QUEUES; i++)
        fprintf(stdout, " q%d=%lu", i, (unsigned long)fwd->dropped_local_tx_fail_by_queue[i]);
    fprintf(stdout, " tx_wait_loops=%lu", (unsigned long)tx_wait_loops);
    
    /* Ring mode debug stats */
    fprintf(stdout, " [RING] local_disp_recv=%lu local_disp_enq=%lu l2w_processed=%lu "
            "wan_disp_recv=%lu wan_disp_enq=%lu w2l_processed=%lu\n",
            (unsigned long)g_local_disp_recv, (unsigned long)g_local_disp_enqueue,
            (unsigned long)g_l2w_worker_processed,
            (unsigned long)g_wan_disp_recv, (unsigned long)g_wan_disp_enqueue,
            (unsigned long)g_w2l_worker_processed);
}

