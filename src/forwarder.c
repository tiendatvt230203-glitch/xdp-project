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

static volatile int running = 1;
static pthread_mutex_t wan_lock = PTHREAD_MUTEX_INITIALIZER;

static struct packet_crypto_ctx crypto_ctx;
static int crypto_enabled = 0;

static int next_cpu = 0;
static pthread_mutex_t cpu_lock = PTHREAD_MUTEX_INITIALIZER;

struct queue_thread_args {
    struct forwarder *fwd;
    int iface_idx;
    int queue_idx;
    int is_wan;
    int cpu_id;
};

static void pin_to_cpu(int cpu_id)
{
    int num_cpus = sysconf(_SC_NPROCESSORS_ONLN);
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(cpu_id % num_cpus, &cpuset);
    pthread_setaffinity_np(pthread_self(), sizeof(cpuset), &cpuset);
}

static int get_next_cpu(void)
{
    pthread_mutex_lock(&cpu_lock);
    int cpu = next_cpu++;
    pthread_mutex_unlock(&cpu_lock);
    return cpu;
}

static int encrypt_packet(void *pkt_data, uint32_t *pkt_len)
{
    if (!crypto_enabled) return 0;
    int new_len = packet_encrypt(&crypto_ctx, (uint8_t *)pkt_data, *pkt_len);
    if (new_len < 0) return -1;
    *pkt_len = (uint32_t)new_len;
    return 0;
}

static int decrypt_packet(void *pkt_data, uint32_t *pkt_len)
{
    if (!crypto_enabled) return 0;
    int new_len = packet_decrypt(&crypto_ctx, (uint8_t *)pkt_data, *pkt_len);
    if (new_len < 0) return -1;
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

static int queue_recv(struct xsk_queue *queue, void **pkt_ptrs, uint32_t *pkt_lens,
                      uint64_t *addrs, int max_pkts)
{
    uint32_t idx_rx = 0;
    int rcvd = xsk_ring_cons__peek(&queue->rx, max_pkts, &idx_rx);
    if (rcvd == 0) return 0;

    for (int i = 0; i < rcvd; i++) {
        const struct xdp_desc *desc = xsk_ring_cons__rx_desc(&queue->rx, idx_rx + i);
        addrs[i] = desc->addr;
        pkt_ptrs[i] = (uint8_t *)queue->bufs + desc->addr;
        pkt_lens[i] = desc->len;
    }
    xsk_ring_cons__release(&queue->rx, rcvd);
    return rcvd;
}

static void queue_recv_release(struct xsk_queue *queue, uint64_t *addrs, int count, int batch_size)
{
    for (int i = 0; i < count; i++) {
        uint32_t idx_fill;
        int ret = xsk_ring_prod__reserve(&queue->fill, 1, &idx_fill);
        if (ret != 1) {
            uint32_t comp_idx;
            int comp = xsk_ring_cons__peek(&queue->comp, batch_size, &comp_idx);
            if (comp > 0) xsk_ring_cons__release(&queue->comp, comp);
            ret = xsk_ring_prod__reserve(&queue->fill, 1, &idx_fill);
            if (ret != 1) continue;
        }
        *xsk_ring_prod__fill_addr(&queue->fill, idx_fill) = addrs[i];
        xsk_ring_prod__submit(&queue->fill, 1);
    }
}

static void *local_queue_thread(void *arg)
{
    struct queue_thread_args *args = (struct queue_thread_args *)arg;
    struct forwarder *fwd = args->fwd;
    struct xsk_interface *local = &fwd->locals[args->iface_idx];
    struct xsk_queue *queue = &local->queues[args->queue_idx];
    int batch_size = local->batch_size;

    pin_to_cpu(args->cpu_id);
    printf("LOCAL queue %d thread started on CPU %d\n", args->queue_idx, args->cpu_id);

    void *pkt_ptrs[MAX_BATCH_SIZE];
    uint32_t pkt_lens[MAX_BATCH_SIZE];
    uint64_t addrs[MAX_BATCH_SIZE];

    struct pollfd pfd = {
        .fd = xsk_socket__fd(queue->xsk),
        .events = POLLIN
    };

    while (running) {
        int rcvd = queue_recv(queue, pkt_ptrs, pkt_lens, addrs, batch_size);
        if (rcvd > 0) {
            int wan_used[MAX_INTERFACES] = {0};

            for (int i = 0; i < rcvd; i++) {
                if (encrypt_packet(pkt_ptrs[i], &pkt_lens[i]) != 0) {
                    __sync_fetch_and_add(&fwd->total_dropped, 1);
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
            }

            for (int w = 0; w < fwd->wan_count; w++) {
                if (wan_used[w])
                    interface_send_flush(&fwd->wans[w]);
            }

            queue_recv_release(queue, addrs, rcvd, batch_size);
        } else {
            poll(&pfd, 1, 1);
        }
    }

    return NULL;
}

static void *wan_queue_thread(void *arg)
{
    struct queue_thread_args *args = (struct queue_thread_args *)arg;
    struct forwarder *fwd = args->fwd;
    struct xsk_interface *wan = &fwd->wans[args->iface_idx];
    struct xsk_queue *queue = &wan->queues[args->queue_idx];
    int batch_size = wan->batch_size;

    pin_to_cpu(args->cpu_id);
    printf("WAN %d queue %d thread started on CPU %d\n", args->iface_idx, args->queue_idx, args->cpu_id);

    void *pkt_ptrs[MAX_BATCH_SIZE];
    uint32_t pkt_lens[MAX_BATCH_SIZE];
    uint64_t addrs[MAX_BATCH_SIZE];

    struct pollfd pfd = {
        .fd = xsk_socket__fd(queue->xsk),
        .events = POLLIN
    };

    while (running) {
        int rcvd = queue_recv(queue, pkt_ptrs, pkt_lens, addrs, batch_size);
        if (rcvd > 0) {
            int local_used[MAX_INTERFACES] = {0};

            for (int i = 0; i < rcvd; i++) {
                if (decrypt_packet(pkt_ptrs[i], &pkt_lens[i]) != 0) {
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

                if (interface_send_to_local_batch(local, local_cfg, pkt_ptrs[i], pkt_lens[i], args->iface_idx) == 0) {
                    __sync_fetch_and_add(&fwd->wan_to_local, 1);
                    local_used[local_idx] = 1;
                } else {
                    __sync_fetch_and_add(&fwd->total_dropped, 1);
                }
            }

            for (int l = 0; l < fwd->local_count; l++) {
                if (local_used[l])
                    interface_send_to_local_flush(&fwd->locals[l], args->iface_idx);
            }

            queue_recv_release(queue, addrs, rcvd, batch_size);
        } else {
            poll(&pfd, 1, 1);
        }
    }

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
    signal(SIGINT, sigint_handler);
    signal(SIGTERM, sigint_handler);

    int total_threads = 0;
    for (int i = 0; i < fwd->local_count; i++)
        total_threads += fwd->locals[i].queue_count;
    for (int i = 0; i < fwd->wan_count; i++)
        total_threads += fwd->wans[i].queue_count;

    printf("Starting %d threads (1 per queue)\n", total_threads);

    pthread_t *threads = malloc(sizeof(pthread_t) * total_threads);
    struct queue_thread_args *args = malloc(sizeof(struct queue_thread_args) * total_threads);

    int t = 0;

    for (int i = 0; i < fwd->local_count; i++) {
        struct xsk_interface *local = &fwd->locals[i];
        printf("LOCAL %s: %d queues\n", local->ifname, local->queue_count);
        for (int q = 0; q < local->queue_count; q++) {
            args[t].fwd = fwd;
            args[t].iface_idx = i;
            args[t].queue_idx = q;
            args[t].is_wan = 0;
            args[t].cpu_id = get_next_cpu();
            pthread_create(&threads[t], NULL, local_queue_thread, &args[t]);
            t++;
        }
    }

    for (int i = 0; i < fwd->wan_count; i++) {
        struct xsk_interface *wan = &fwd->wans[i];
        printf("WAN %s: %d queues\n", wan->ifname, wan->queue_count);
        for (int q = 0; q < wan->queue_count; q++) {
            args[t].fwd = fwd;
            args[t].iface_idx = i;
            args[t].queue_idx = q;
            args[t].is_wan = 1;
            args[t].cpu_id = get_next_cpu();
            pthread_create(&threads[t], NULL, wan_queue_thread, &args[t]);
            t++;
        }
    }

    while (running) {
        sleep(1);
    }

    for (int i = 0; i < total_threads; i++)
        pthread_join(threads[i], NULL);

    free(threads);
    free(args);
}

void forwarder_print_stats(struct forwarder *fwd)
{
    (void)fwd;
}
