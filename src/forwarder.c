#define _GNU_SOURCE
#include "../inc/forwarder.h"
#include "../inc/packet_crypto.h"
#include <signal.h>
#include <poll.h>
#include <pthread.h>
#include <netinet/ip.h>
#include <net/ethernet.h>
#include <sched.h>
#include <unistd.h>

#define MAX_TOTAL_QUEUES 256

static volatile int running = 1;
static pthread_mutex_t wan_lock = PTHREAD_MUTEX_INITIALIZER;

static struct packet_crypto_ctx crypto_ctx;
static int crypto_enabled = 0;

struct queue_info {
    struct xsk_interface *iface;
    struct xsk_queue *queue;
    int iface_idx;
    int queue_idx;
    int is_wan;
};

struct worker_thread_args {
    struct forwarder *fwd;
    int thread_id;
    struct queue_info *queues;
    int queue_count;
};

static int encrypt_packet(void *pkt_data, uint32_t *pkt_len)
{
    if (!crypto_enabled) return 0;

    int new_len = packet_encrypt(&crypto_ctx, (uint8_t *)pkt_data, *pkt_len);
    if (new_len < 0) {
        return -1;
    }
    *pkt_len = (uint32_t)new_len;
    return 0;
}

static int decrypt_packet(void *pkt_data, uint32_t *pkt_len)
{
    if (!crypto_enabled) return 0;

    int new_len = packet_decrypt(&crypto_ctx, (uint8_t *)pkt_data, *pkt_len);
    if (new_len < 0) {
        return -1;
    }
    *pkt_len = (uint32_t)new_len;
    return 0;
}

static void sigint_handler(int sig)
{
    (void)sig;
    running = 0;
}

static uint32_t get_dest_ip(void *pkt_data, uint32_t pkt_len)
{
    if (pkt_len < sizeof(struct ether_header) + sizeof(struct iphdr))
        return 0;
    struct ether_header *eth = (struct ether_header *)pkt_data;
    if (ntohs(eth->ether_type) != ETHERTYPE_IP)
        return 0;
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    return ip->daddr;
}

static struct xsk_interface *get_wan_locked(struct forwarder *fwd, uint32_t pkt_len, int *wan_idx)
{
    pthread_mutex_lock(&wan_lock);

    int curr = fwd->current_wan;
    uint32_t window_size = fwd->cfg->wans[curr].window_size;

    fwd->wan_bytes[curr] += pkt_len;
    if (fwd->wan_bytes[curr] >= window_size) {
        fwd->wan_bytes[curr] = 0;
        fwd->current_wan = (curr + 1) % fwd->wan_count;
    }

    *wan_idx = fwd->current_wan;
    struct xsk_interface *wan = &fwd->wans[fwd->current_wan];

    pthread_mutex_unlock(&wan_lock);
    return wan;
}

static int recv_from_queue(struct xsk_queue *queue, struct xsk_interface *iface,
                           void **pkt_ptrs, uint32_t *pkt_lens, uint64_t *addrs,
                           int max_pkts, int queue_idx)
{
    uint32_t idx_rx = 0;
    int rcvd = xsk_ring_cons__peek(&queue->rx, max_pkts, &idx_rx);
    if (rcvd == 0)
        return 0;

    for (int j = 0; j < rcvd; j++) {
        const struct xdp_desc *desc = xsk_ring_cons__rx_desc(&queue->rx, idx_rx + j);
        uint64_t encoded = ((uint64_t)queue_idx << 56) | (desc->addr & 0x00FFFFFFFFFFFFFF);
        addrs[j] = encoded;
        pkt_ptrs[j] = (uint8_t *)queue->bufs + desc->addr;
        pkt_lens[j] = desc->len;
    }

    xsk_ring_cons__release(&queue->rx, rcvd);
    return rcvd;
}

static void release_to_queue(struct xsk_queue *queue, uint64_t addr, uint32_t batch_size)
{
    uint64_t real_addr = addr & 0x00FFFFFFFFFFFFFF;
    uint32_t idx_fill;

    int ret = xsk_ring_prod__reserve(&queue->fill, 1, &idx_fill);
    if (ret != 1) {
        uint32_t comp_idx;
        int comp = xsk_ring_cons__peek(&queue->comp, batch_size, &comp_idx);
        if (comp > 0)
            xsk_ring_cons__release(&queue->comp, comp);

        ret = xsk_ring_prod__reserve(&queue->fill, 1, &idx_fill);
        if (ret != 1)
            return;
    }

    *xsk_ring_prod__fill_addr(&queue->fill, idx_fill) = real_addr;
    xsk_ring_prod__submit(&queue->fill, 1);
}

static void process_local_queue(struct forwarder *fwd, struct queue_info *qinfo)
{
    struct xsk_interface *local = qinfo->iface;
    struct xsk_queue *queue = qinfo->queue;
    int batch_size = local->batch_size;

    void *pkt_ptrs[MAX_BATCH_SIZE];
    uint32_t pkt_lens[MAX_BATCH_SIZE];
    uint64_t addrs[MAX_BATCH_SIZE];

    int rcvd = recv_from_queue(queue, local, pkt_ptrs, pkt_lens, addrs, batch_size, qinfo->queue_idx);
    if (rcvd <= 0)
        return;

    int wan_used[MAX_INTERFACES] = {0};

    for (int i = 0; i < rcvd; i++) {
        if (encrypt_packet(pkt_ptrs[i], &pkt_lens[i]) != 0) {
            __sync_fetch_and_add(&fwd->total_dropped, 1);
            release_to_queue(queue, addrs[i], batch_size);
            continue;
        }

        int wan_idx;
        struct xsk_interface *wan = get_wan_locked(fwd, pkt_lens[i], &wan_idx);

        if (interface_send_batch(wan, pkt_ptrs[i], pkt_lens[i]) == 0) {
            __sync_fetch_and_add(&fwd->local_to_wan, 1);
            wan_used[wan_idx] = 1;
        } else {
            __sync_fetch_and_add(&fwd->total_dropped, 1);
        }

        release_to_queue(queue, addrs[i], batch_size);
    }

    for (int w = 0; w < fwd->wan_count; w++) {
        if (wan_used[w])
            interface_send_flush(&fwd->wans[w]);
    }
}

static void process_wan_queue(struct forwarder *fwd, struct queue_info *qinfo)
{
    struct xsk_interface *wan = qinfo->iface;
    struct xsk_queue *queue = qinfo->queue;
    int batch_size = wan->batch_size;

    void *pkt_ptrs[MAX_BATCH_SIZE];
    uint32_t pkt_lens[MAX_BATCH_SIZE];
    uint64_t addrs[MAX_BATCH_SIZE];

    int rcvd = recv_from_queue(queue, wan, pkt_ptrs, pkt_lens, addrs, batch_size, qinfo->queue_idx);
    if (rcvd <= 0)
        return;

    int local_used[MAX_INTERFACES] = {0};

    for (int i = 0; i < rcvd; i++) {
        if (decrypt_packet(pkt_ptrs[i], &pkt_lens[i]) != 0) {
            __sync_fetch_and_add(&fwd->total_dropped, 1);
            release_to_queue(queue, addrs[i], batch_size);
            continue;
        }

        uint32_t dest_ip = get_dest_ip(pkt_ptrs[i], pkt_lens[i]);
        if (dest_ip == 0) {
            __sync_fetch_and_add(&fwd->total_dropped, 1);
            release_to_queue(queue, addrs[i], batch_size);
            continue;
        }

        int local_idx = config_find_local_for_ip(fwd->cfg, dest_ip);
        if (local_idx < 0) {
            __sync_fetch_and_add(&fwd->total_dropped, 1);
            release_to_queue(queue, addrs[i], batch_size);
            continue;
        }

        struct xsk_interface *local = &fwd->locals[local_idx];
        struct local_config *local_cfg = &fwd->cfg->locals[local_idx];

        if (interface_send_to_local_batch(local, local_cfg, pkt_ptrs[i], pkt_lens[i], qinfo->iface_idx) == 0) {
            __sync_fetch_and_add(&fwd->wan_to_local, 1);
            local_used[local_idx] = 1;
        } else {
            __sync_fetch_and_add(&fwd->total_dropped, 1);
        }

        release_to_queue(queue, addrs[i], batch_size);
    }

    for (int l = 0; l < fwd->local_count; l++) {
        if (local_used[l])
            interface_send_to_local_flush(&fwd->locals[l], qinfo->iface_idx);
    }
}

static void *worker_thread(void *arg)
{
    struct worker_thread_args *args = (struct worker_thread_args *)arg;
    struct forwarder *fwd = args->fwd;

    if (args->queue_count == 0) {
        fprintf(stderr, "Thread %d: no queues assigned\n", args->thread_id);
        return NULL;
    }

    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(args->thread_id % sysconf(_SC_NPROCESSORS_ONLN), &cpuset);
    pthread_setaffinity_np(pthread_self(), sizeof(cpuset), &cpuset);

    struct pollfd *fds = malloc(sizeof(struct pollfd) * args->queue_count);
    if (!fds) {
        fprintf(stderr, "Thread %d: malloc failed\n", args->thread_id);
        return NULL;
    }

    for (int i = 0; i < args->queue_count; i++) {
        if (!args->queues[i].queue || !args->queues[i].queue->xsk) {
            fprintf(stderr, "Thread %d: invalid queue %d\n", args->thread_id, i);
            free(fds);
            return NULL;
        }
        fds[i].fd = xsk_socket__fd(args->queues[i].queue->xsk);
        fds[i].events = POLLIN;
    }

    printf("Thread %d started with %d queues\n", args->thread_id, args->queue_count);

    while (running) {
        int has_data = 0;

        for (int i = 0; i < args->queue_count; i++) {
            struct queue_info *qinfo = &args->queues[i];

            if (!qinfo->queue || !qinfo->queue->xsk)
                continue;

            if (qinfo->is_wan) {
                process_wan_queue(fwd, qinfo);
            } else {
                process_local_queue(fwd, qinfo);
            }

            uint32_t idx;
            if (xsk_ring_cons__peek(&qinfo->queue->rx, 1, &idx) > 0)
                has_data = 1;
        }

        if (!has_data) {
            poll(fds, args->queue_count, 1);
        }
    }

    free(fds);
    return NULL;
}

int forwarder_init(struct forwarder *fwd, struct app_config *cfg)
{
    memset(fwd, 0, sizeof(*fwd));
    fwd->cfg = cfg;

    crypto_enabled = cfg->crypto_enabled;
    if (crypto_enabled) {
        if (packet_crypto_init(&crypto_ctx, cfg->crypto_key, cfg->crypto_iv) != 0) {
            fprintf(stderr, "Failed to initialize AES-128 encryption\n");
            return -1;
        }
        packet_crypto_set_fake_ethertype(cfg->fake_ethertype);
    }

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
    return -1;
}

void forwarder_cleanup(struct forwarder *fwd)
{
    if (crypto_enabled) {
        packet_crypto_cleanup(&crypto_ctx);
    }

    for (int i = 0; i < fwd->local_count; i++)
        interface_cleanup(&fwd->locals[i]);
    for (int i = 0; i < fwd->wan_count; i++)
        interface_cleanup(&fwd->wans[i]);
}

void forwarder_run(struct forwarder *fwd)
{
    int num_threads = fwd->cfg->num_threads;

    if (num_threads <= 0) {
        fprintf(stderr, "Invalid num_threads: %d\n", num_threads);
        return;
    }

    pthread_t *threads = malloc(sizeof(pthread_t) * num_threads);
    struct worker_thread_args *thread_args = malloc(sizeof(struct worker_thread_args) * num_threads);
    struct queue_info *all_queues = malloc(sizeof(struct queue_info) * MAX_TOTAL_QUEUES);

    if (!threads || !thread_args || !all_queues) {
        fprintf(stderr, "Memory allocation failed\n");
        free(threads);
        free(thread_args);
        free(all_queues);
        return;
    }

    signal(SIGINT, sigint_handler);
    signal(SIGTERM, sigint_handler);

    int total_queues = 0;

    for (int i = 0; i < fwd->local_count; i++) {
        struct xsk_interface *local = &fwd->locals[i];
        printf("LOCAL %s: %d queues\n", local->ifname, local->queue_count);
        for (int q = 0; q < local->queue_count && total_queues < MAX_TOTAL_QUEUES; q++) {
            if (!local->queues[q].xsk) {
                fprintf(stderr, "LOCAL %s queue %d: xsk is NULL\n", local->ifname, q);
                continue;
            }
            all_queues[total_queues].iface = local;
            all_queues[total_queues].queue = &local->queues[q];
            all_queues[total_queues].iface_idx = i;
            all_queues[total_queues].queue_idx = q;
            all_queues[total_queues].is_wan = 0;
            total_queues++;
        }
    }

    for (int i = 0; i < fwd->wan_count; i++) {
        struct xsk_interface *wan = &fwd->wans[i];
        printf("WAN %s: %d queues\n", wan->ifname, wan->queue_count);
        for (int q = 0; q < wan->queue_count && total_queues < MAX_TOTAL_QUEUES; q++) {
            if (!wan->queues[q].xsk) {
                fprintf(stderr, "WAN %s queue %d: xsk is NULL\n", wan->ifname, q);
                continue;
            }
            all_queues[total_queues].iface = wan;
            all_queues[total_queues].queue = &wan->queues[q];
            all_queues[total_queues].iface_idx = i;
            all_queues[total_queues].queue_idx = q;
            all_queues[total_queues].is_wan = 1;
            total_queues++;
        }
    }

    printf("Total valid queues: %d, Threads: %d\n", total_queues, num_threads);

    if (total_queues == 0) {
        fprintf(stderr, "No valid queues found\n");
        free(threads);
        free(thread_args);
        free(all_queues);
        return;
    }

    int actual_threads = num_threads;
    if (actual_threads > total_queues)
        actual_threads = total_queues;

    for (int t = 0; t < actual_threads; t++) {
        thread_args[t].fwd = fwd;
        thread_args[t].thread_id = t;
        thread_args[t].queues = malloc(sizeof(struct queue_info) * MAX_TOTAL_QUEUES);
        thread_args[t].queue_count = 0;
        if (!thread_args[t].queues) {
            fprintf(stderr, "Failed to allocate queues for thread %d\n", t);
            for (int j = 0; j < t; j++)
                free(thread_args[j].queues);
            free(threads);
            free(thread_args);
            free(all_queues);
            return;
        }
    }

    for (int q = 0; q < total_queues; q++) {
        int t = q % actual_threads;
        thread_args[t].queues[thread_args[t].queue_count++] = all_queues[q];
    }

    for (int t = 0; t < actual_threads; t++) {
        printf("Thread %d: %d queues\n", t, thread_args[t].queue_count);
        if (pthread_create(&threads[t], NULL, worker_thread, &thread_args[t]) != 0) {
            fprintf(stderr, "Failed to create thread %d\n", t);
        }
    }

    while (running) {
        sleep(1);
    }

    for (int t = 0; t < actual_threads; t++) {
        pthread_join(threads[t], NULL);
        free(thread_args[t].queues);
    }

    free(threads);
    free(thread_args);
    free(all_queues);
}

void forwarder_print_stats(struct forwarder *fwd)
{
    (void)fwd;
}
