/*
 * LOCAL TX Stress Test
 *
 * Test WAN → LOCAL path by generating traffic directly to LOCAL TX
 * This simulates what WAN threads do - sending packets to LOCAL interface
 *
 * Usage: sudo ./bin/local_tx_stress <interface> <rate_mbps> <duration_sec>
 * Example: sudo ./bin/local_tx_stress enp7s0 2500 10
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <pthread.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <sys/mman.h>
#include <linux/if_xdp.h>
#include <bpf/libbpf.h>
#include <bpf/xsk.h>
#include <bpf/bpf.h>

#define FRAME_SIZE      4096
#define FRAME_COUNT     (16 * 1024)
#define UMEM_SIZE       (FRAME_COUNT * FRAME_SIZE)
#define RING_SIZE       4096
#define BATCH_SIZE      64
#define PKT_SIZE        1400

static volatile int running = 1;

// Stats
static uint64_t total_sent = 0;
static uint64_t total_failed = 0;
static uint64_t total_bytes = 0;

struct tx_queue {
    struct xsk_socket *xsk;
    struct xsk_umem *umem;
    void *bufs;
    struct xsk_ring_prod tx;
    struct xsk_ring_cons comp;
    struct xsk_ring_prod fill;
    struct xsk_ring_cons rx;
    uint64_t tx_slot;
    int pending;
};

static void sigint_handler(int sig) {
    (void)sig;
    running = 0;
}

// Build a dummy UDP packet
static void build_packet(void *buf, int pkt_size, uint32_t seq) {
    struct ether_header *eth = buf;
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    struct udphdr *udp = (struct udphdr *)(ip + 1);

    // Ethernet
    memset(eth->ether_dhost, 0x11, 6);
    memset(eth->ether_shost, 0x22, 6);
    eth->ether_type = htons(ETHERTYPE_IP);

    // IP
    ip->version = 4;
    ip->ihl = 5;
    ip->tos = 0;
    ip->tot_len = htons(pkt_size - sizeof(*eth));
    ip->id = htons(seq & 0xFFFF);
    ip->frag_off = 0;
    ip->ttl = 64;
    ip->protocol = IPPROTO_UDP;
    ip->check = 0;
    ip->saddr = htonl(0xC0A80901);  // 192.168.9.1
    ip->daddr = htonl(0xC0A8B601);  // 192.168.182.1

    // UDP
    udp->source = htons(12345);
    udp->dest = htons(5201);
    udp->len = htons(pkt_size - sizeof(*eth) - sizeof(*ip));
    udp->check = 0;

    // Payload - fill with sequence number
    uint8_t *payload = (uint8_t *)(udp + 1);
    memset(payload, seq & 0xFF, pkt_size - sizeof(*eth) - sizeof(*ip) - sizeof(*udp));
}

static int init_tx_queue(struct tx_queue *q, const char *ifname, int queue_id) {
    int ret;
    uint32_t idx;

    memset(q, 0, sizeof(*q));

    // Allocate UMEM buffer
    ret = posix_memalign(&q->bufs, getpagesize(), UMEM_SIZE);
    if (ret || !q->bufs) {
        fprintf(stderr, "posix_memalign failed\n");
        return -1;
    }
    mlock(q->bufs, UMEM_SIZE);

    // Create UMEM
    struct xsk_umem_config umem_cfg = {
        .fill_size = RING_SIZE,
        .comp_size = RING_SIZE,
        .frame_size = FRAME_SIZE,
        .frame_headroom = 0,
        .flags = 0
    };

    ret = xsk_umem__create(&q->umem, q->bufs, UMEM_SIZE, &q->fill, &q->comp, &umem_cfg);
    if (ret) {
        fprintf(stderr, "xsk_umem__create failed: %d\n", ret);
        free(q->bufs);
        return -1;
    }

    // Create socket (TX only, no XDP program)
    struct xsk_socket_config sock_cfg = {
        .rx_size = RING_SIZE,
        .tx_size = RING_SIZE,
        .libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,
        .bind_flags = XDP_COPY
    };

    ret = xsk_socket__create(&q->xsk, ifname, queue_id, q->umem, &q->rx, &q->tx, &sock_cfg);
    if (ret) {
        fprintf(stderr, "xsk_socket__create failed: %d\n", ret);
        xsk_umem__delete(q->umem);
        free(q->bufs);
        return -1;
    }

    // Fill the fill ring
    ret = xsk_ring_prod__reserve(&q->fill, RING_SIZE, &idx);
    for (int i = 0; i < ret; i++)
        *xsk_ring_prod__fill_addr(&q->fill, idx++) = i * FRAME_SIZE;
    xsk_ring_prod__submit(&q->fill, ret);

    q->tx_slot = RING_SIZE;  // TX uses second half of UMEM
    q->pending = 0;

    printf("[QUEUE %d] Initialized: fd=%d, umem=%p\n", queue_id, xsk_socket__fd(q->xsk), q->bufs);
    return 0;
}

static void cleanup_tx_queue(struct tx_queue *q) {
    if (q->xsk) xsk_socket__delete(q->xsk);
    if (q->umem) xsk_umem__delete(q->umem);
    if (q->bufs) {
        munlock(q->bufs, UMEM_SIZE);
        free(q->bufs);
    }
}

static int send_packet(struct tx_queue *q, uint32_t seq, int pkt_size) {
    uint32_t idx;

    // Drain completion ring
    uint32_t comp_idx;
    int completed = xsk_ring_cons__peek(&q->comp, RING_SIZE, &comp_idx);
    if (completed > 0)
        xsk_ring_cons__release(&q->comp, completed);

    // Reserve TX slot
    int reserved = xsk_ring_prod__reserve(&q->tx, 1, &idx);
    if (reserved < 1) {
        // Flush and retry
        if (q->pending > 0) {
            sendto(xsk_socket__fd(q->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
            q->pending = 0;
        }

        completed = xsk_ring_cons__peek(&q->comp, RING_SIZE, &comp_idx);
        if (completed > 0)
            xsk_ring_cons__release(&q->comp, completed);

        reserved = xsk_ring_prod__reserve(&q->tx, 1, &idx);
        if (reserved < 1)
            return -1;
    }

    // Get TX buffer address (second half of UMEM)
    uint64_t addr = (q->tx_slot % (FRAME_COUNT / 2) + FRAME_COUNT / 2) * FRAME_SIZE;
    q->tx_slot++;

    // Build packet
    void *pkt = (uint8_t *)q->bufs + addr;
    build_packet(pkt, pkt_size, seq);

    // Submit to TX ring
    xsk_ring_prod__tx_desc(&q->tx, idx)->addr = addr;
    xsk_ring_prod__tx_desc(&q->tx, idx)->len = pkt_size;
    xsk_ring_prod__submit(&q->tx, 1);

    q->pending++;

    // Auto-flush every BATCH_SIZE packets
    if (q->pending >= BATCH_SIZE) {
        sendto(xsk_socket__fd(q->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
        q->pending = 0;
    }

    return 0;
}

static void flush_tx(struct tx_queue *q) {
    if (q->pending > 0) {
        sendto(xsk_socket__fd(q->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
        q->pending = 0;
    }
}

// Thread arguments
struct thread_args {
    struct tx_queue *queue;
    int queue_id;
    uint64_t target_pps;  // Packets per second
    uint64_t sent;
    uint64_t failed;
    uint64_t bytes;
};

static void *tx_thread(void *arg) {
    struct thread_args *args = arg;
    struct tx_queue *q = args->queue;
    uint32_t seq = args->queue_id * 1000000;

    printf("[THREAD %d] Started, target: %lu pps\n", args->queue_id, args->target_pps);

    // Calculate delay between packets for rate limiting
    // If target_pps is 0, send as fast as possible
    uint64_t delay_ns = args->target_pps > 0 ? 1000000000UL / args->target_pps : 0;

    struct timespec last_time, now;
    clock_gettime(CLOCK_MONOTONIC, &last_time);

    while (running) {
        if (send_packet(q, seq++, PKT_SIZE) == 0) {
            args->sent++;
            args->bytes += PKT_SIZE;
        } else {
            args->failed++;
        }

        // Rate limiting (if enabled)
        if (delay_ns > 0) {
            clock_gettime(CLOCK_MONOTONIC, &now);
            uint64_t elapsed = (now.tv_sec - last_time.tv_sec) * 1000000000UL +
                              (now.tv_nsec - last_time.tv_nsec);
            if (elapsed < delay_ns) {
                struct timespec sleep_time = {
                    .tv_sec = 0,
                    .tv_nsec = delay_ns - elapsed
                };
                nanosleep(&sleep_time, NULL);
            }
            last_time = now;
        }
    }

    flush_tx(q);
    printf("[THREAD %d] Stopped: sent=%lu, failed=%lu\n", args->queue_id, args->sent, args->failed);
    return NULL;
}

int main(int argc, char **argv) {
    if (argc < 4) {
        printf("Usage: %s <interface> <rate_mbps> <duration_sec> [num_threads]\n", argv[0]);
        printf("Example: %s enp7s0 2500 10 4\n", argv[0]);
        printf("  rate_mbps=0 means unlimited (as fast as possible)\n");
        return 1;
    }

    const char *ifname = argv[1];
    int rate_mbps = atoi(argv[2]);
    int duration = atoi(argv[3]);
    int num_threads = argc > 4 ? atoi(argv[4]) : 4;

    if (num_threads > 8) num_threads = 8;

    // Calculate target packets per second per thread
    uint64_t total_pps = 0;
    if (rate_mbps > 0) {
        // rate_mbps * 1000000 / 8 / PKT_SIZE = packets per second
        total_pps = (uint64_t)rate_mbps * 1000000 / 8 / PKT_SIZE;
    }
    uint64_t pps_per_thread = total_pps / num_threads;

    printf("===========================================\n");
    printf("   LOCAL TX Stress Test\n");
    printf("===========================================\n");
    printf("Interface:    %s\n", ifname);
    printf("Target rate:  %d Mbps (%lu pps total)\n", rate_mbps, total_pps);
    printf("Duration:     %d seconds\n", duration);
    printf("Threads:      %d (each %lu pps)\n", num_threads, pps_per_thread);
    printf("Packet size:  %d bytes\n", PKT_SIZE);
    printf("===========================================\n\n");

    signal(SIGINT, sigint_handler);

    // Initialize queues
    struct tx_queue queues[8];
    pthread_t threads[8];
    struct thread_args args[8];

    for (int i = 0; i < num_threads; i++) {
        if (init_tx_queue(&queues[i], ifname, i) != 0) {
            fprintf(stderr, "Failed to init queue %d\n", i);
            // Cleanup already initialized
            for (int j = 0; j < i; j++)
                cleanup_tx_queue(&queues[j]);
            return 1;
        }
    }

    printf("\n[MAIN] Starting %d TX threads...\n\n", num_threads);

    // Start threads
    for (int i = 0; i < num_threads; i++) {
        args[i].queue = &queues[i];
        args[i].queue_id = i;
        args[i].target_pps = pps_per_thread;
        args[i].sent = 0;
        args[i].failed = 0;
        args[i].bytes = 0;
        pthread_create(&threads[i], NULL, tx_thread, &args[i]);
    }

    // Monitor stats
    struct timespec start_time, now;
    clock_gettime(CLOCK_MONOTONIC, &start_time);

    uint64_t last_sent = 0, last_bytes = 0;

    while (running) {
        sleep(1);

        clock_gettime(CLOCK_MONOTONIC, &now);
        int elapsed = now.tv_sec - start_time.tv_sec;

        if (elapsed >= duration) {
            running = 0;
            break;
        }

        // Sum stats from all threads
        uint64_t sent = 0, failed = 0, bytes = 0;
        for (int i = 0; i < num_threads; i++) {
            sent += args[i].sent;
            failed += args[i].failed;
            bytes += args[i].bytes;
        }

        uint64_t pps = sent - last_sent;
        uint64_t mbps = (bytes - last_bytes) * 8 / 1000000;
        double drop_pct = (sent + failed) > 0 ? 100.0 * failed / (sent + failed) : 0;

        printf("[%3ds] Sent: %lu (+%lu pps, %lu Mbps) | Failed: %lu (%.2f%%)\n",
               elapsed, sent, pps, mbps, failed, drop_pct);

        last_sent = sent;
        last_bytes = bytes;
    }

    printf("\n[MAIN] Stopping threads...\n");

    // Wait for threads
    for (int i = 0; i < num_threads; i++)
        pthread_join(threads[i], NULL);

    // Final stats
    uint64_t total_s = 0, total_f = 0, total_b = 0;
    for (int i = 0; i < num_threads; i++) {
        total_s += args[i].sent;
        total_f += args[i].failed;
        total_b += args[i].bytes;
    }

    double avg_mbps = (double)total_b * 8 / duration / 1000000;
    double drop_pct = (total_s + total_f) > 0 ? 100.0 * total_f / (total_s + total_f) : 0;

    printf("\n===========================================\n");
    printf("   FINAL RESULTS\n");
    printf("===========================================\n");
    printf("Total Sent:   %lu packets\n", total_s);
    printf("Total Failed: %lu packets (%.2f%%)\n", total_f, drop_pct);
    printf("Total Bytes:  %lu\n", total_b);
    printf("Avg Rate:     %.2f Mbps\n", avg_mbps);
    printf("Avg PPS:      %lu\n", total_s / duration);
    printf("===========================================\n");

    // Cleanup
    for (int i = 0; i < num_threads; i++)
        cleanup_tx_queue(&queues[i]);

    return 0;
}
