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

static void *local_queue_thread(void *arg) {
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

    uint8_t frag1_buf[2048];
    uint8_t frag2_buf[2048];

    while (running) {
        int rcvd = interface_recv_single_queue(local, queue_idx,
                                               pkt_ptrs, pkt_lens, addrs, batch_size);
        if (rcvd <= 0)
            continue;

        /* Layer2 encrypt: xử lý trực tiếp trên 4 core gắn với 4 queue */
        if (crypto_enabled && crypto_layer == 2) {
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

                uint32_t pkt_len = pkt_lens[i];
                uint8_t *pkt = (uint8_t *)pkt_ptrs[i];

                memcpy(pkt, wan->dst_mac, 6);
                memcpy(pkt + 6, wan->src_mac, 6);

                if (frag_need_split_l2(pkt_len)) {
                    uint32_t f1_len = 0, f2_len = 0;
                    if (frag_split_and_encrypt_l2(&crypto_ctx,
                                                  pkt, pkt_len,
                                                  frag1_buf, &f1_len,
                                                  frag2_buf, &f2_len) != 0) {
                        __sync_fetch_and_add(&fwd->total_dropped, 1);
                        continue;
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
                    if (encrypt_packet(pkt_ptrs[i], &pkt_len) != 0) {
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
            }

            for (int w = 0; w < fwd->wan_count; w++) {
                if (wan_used[w])
                    interface_send_flush_queue(&fwd->wans[w], wan_tx_q[w]);
            }

            interface_recv_release_single_queue(local, queue_idx, addrs, rcvd);
            continue;
        }

        /* Các mode khác vẫn dùng mô hình receiver + worker */
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

static void *wan_queue_thread(void *arg) {
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

    struct frag_table *frag_tbl = NULL;
    if (crypto_enabled && (crypto_layer == 3 || crypto_layer == 2)) {
        frag_tbl = calloc(1, sizeof(struct frag_table));
        if (frag_tbl)
            frag_table_init(frag_tbl);
    }

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
            int is_frag = 0; 
            if (!crypto_enabled) {
                goto wan_rx_forward;
            }

            if (crypto_enabled && crypto_layer == 3 && frag_tbl) {
                is_frag = frag_is_fragment(pkt, pkt_len, &frag_pkt_id, &frag_index);
            }

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

                if (crypto_enabled && crypto_layer == 2 && frag_tbl) {
                    uint16_t l2_pkt_id;
                    uint8_t l2_frag_index;
                    if (frag_is_fragment_l2(pkt, pkt_len, &l2_pkt_id, &l2_frag_index)) {
                        uint32_t reasm_len = 0;
                        int ret = frag_try_reassemble_l2(frag_tbl, pkt, pkt_len,
                                                        l2_pkt_id, l2_frag_index,
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
                }
            }
        }

wan_rx_forward:
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

            int send_ok = 0;
            for (int retry = 0; retry < 32 && !send_ok; retry++) {
                if (interface_send_to_local_batch_queue(local_iface, tq, local_cfg,
                                                        final_pkt, final_len) == 0) {
                    send_ok = 1;
                    break;
                }
                for (volatile int spin = 0; spin < 200; spin++);
            }

            if (send_ok) {
                __sync_fetch_and_add(&fwd->wan_to_local, 1);
                if (tq < 32)
                    local_used_queues[local_idx] |= (1u << tq);
               
                
            } 
            else {
                __sync_fetch_and_add(&fwd->total_dropped, 1);
                __sync_fetch_and_add(&fwd->dropped_local_tx_fail, 1);
                if (tq < FORWARDER_MAX_LOCAL_QUEUES)
                    __sync_fetch_and_add(&fwd->dropped_local_tx_fail_by_queue[tq], 1);
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

    if (!crypto_enabled) {
        for (int i = 0; i < cfg->local_count; i++) {
            if (cfg->locals[i].queue_count <= 1) {
                int want = 4;
                interface_set_queue_count(cfg->locals[i].ifname, want);
                int hwq = interface_get_queue_count(cfg->locals[i].ifname);
                if (hwq > 1)
                    cfg->locals[i].queue_count = hwq;
            }
        }
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

void forwarder_run(struct forwarder *fwd) {
    signal(SIGINT, sigint_handler);
    signal(SIGTERM, sigint_handler);

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
        fprintf(stderr, "Failed to allocate thread arrays\n");
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
            /* Pin 4 thread nhận local vào các core 0-3 */
            args[thread_idx].core_id = local_rx_idx % 4;
            args[thread_idx].wan_worker_index = -1;
            args[thread_idx].worker_id = -1;

            pthread_create(&threads[thread_idx], NULL, local_queue_thread, &args[thread_idx]);
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
            /* Pin các thread WAN RX/forward vào core 8-11 (chiều WAN->Local) */
            args[thread_idx].core_id = 8 + (wan_worker_idx % 4); 
            args[thread_idx].wan_worker_index = wan_worker_idx;
            args[thread_idx].worker_id = -1;
            pthread_create(&threads[thread_idx], NULL, wan_queue_thread, &args[thread_idx]);
            
            wan_worker_idx++; 
            thread_idx++;
        }
    }

    for (int w = 0; w < NUM_WORKERS; w++) {
        args[thread_idx].fwd = fwd;
        args[thread_idx].iface_idx = -1;
        args[thread_idx].queue_idx = -1;
        args[thread_idx].tx_queue_base = 0;
        /* Pin 4 worker local->wan vào các core 4-7 */
        args[thread_idx].core_id = 4 + w; 
        args[thread_idx].wan_worker_index = -1;
        args[thread_idx].worker_id = w;
        pthread_create(&threads[thread_idx], NULL, worker_thread, &args[thread_idx]);
        thread_idx++;
    }

    while (running) {
        sleep(1);
    }

    for (int i = 0; i < total_threads; i++)
        pthread_join(threads[i], NULL);
    pthread_join(gc_tid, NULL);

    free(threads);
    free(args);
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
    fprintf(stdout, " tx_wait_loops=%lu\n", (unsigned long)tx_wait_loops);
}