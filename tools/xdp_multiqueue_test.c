// Multi-queue test - each queue has its own UMEM (separate from main code)
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <poll.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <linux/if_xdp.h>
#include <linux/if_link.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>
#include <linux/ip.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <xdp/xsk.h>

#define FRAME_SIZE 4096
#define FRAME_COUNT 4096
#define UMEM_SIZE (FRAME_SIZE * FRAME_COUNT)
#define RING_SIZE 4096
#define MAX_QUEUES 16

// Per-queue state - each queue has its own UMEM
struct queue_state {
    struct xsk_socket *xsk;
    struct xsk_umem *umem;
    void *bufs;
    struct xsk_ring_prod fill;
    struct xsk_ring_cons comp;
    struct xsk_ring_prod tx;
    struct xsk_ring_cons rx;
    uint64_t rx_count;
};

static volatile int running = 1;
static struct queue_state queues[MAX_QUEUES];
static int queue_count = 0;

static void sigint_handler(int sig) {
    (void)sig;
    running = 0;
}

static int get_queue_count(const char *ifname)
{
    struct ethtool_channels channels = {0};
    struct ifreq ifr = {0};
    int fd, ret;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return 1;

    strncpy(ifr.ifr_name, ifname, IF_NAMESIZE - 1);
    channels.cmd = ETHTOOL_GCHANNELS;
    ifr.ifr_data = (void *)&channels;

    ret = ioctl(fd, SIOCETHTOOL, &ifr);
    close(fd);

    if (ret < 0) return 1;

    int count = channels.combined_count;
    if (count == 0) count = channels.rx_count;
    if (count == 0) count = 1;

    return count > MAX_QUEUES ? MAX_QUEUES : count;
}

static int init_queue(struct queue_state *q, const char *ifname, int queue_id, int xsks_fd)
{
    int ret;
    uint32_t idx;

    memset(q, 0, sizeof(*q));

    // Allocate UMEM buffer for this queue
    ret = posix_memalign(&q->bufs, getpagesize(), UMEM_SIZE);
    if (ret) {
        fprintf(stderr, "Queue %d: posix_memalign failed\n", queue_id);
        return -1;
    }
    mlock(q->bufs, UMEM_SIZE);

    // Create UMEM for this queue
    ret = xsk_umem__create(&q->umem, q->bufs, UMEM_SIZE, &q->fill, &q->comp, NULL);
    if (ret) {
        fprintf(stderr, "Queue %d: xsk_umem__create failed: %d\n", queue_id, ret);
        free(q->bufs);
        return -1;
    }

    // Create socket for this queue
    struct xsk_socket_config cfg = {
        .rx_size = RING_SIZE,
        .tx_size = RING_SIZE,
        .libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,
        .bind_flags = XDP_COPY
    };

    ret = xsk_socket__create(&q->xsk, ifname, queue_id, q->umem, &q->rx, &q->tx, &cfg);
    if (ret) {
        fprintf(stderr, "Queue %d: xsk_socket__create failed: %d\n", queue_id, ret);
        xsk_umem__delete(q->umem);
        free(q->bufs);
        return -1;
    }

    // Register in xsks_map
    int fd = xsk_socket__fd(q->xsk);
    ret = bpf_map_update_elem(xsks_fd, &queue_id, &fd, 0);
    if (ret) {
        fprintf(stderr, "Queue %d: bpf_map_update_elem failed: %d\n", queue_id, ret);
        xsk_socket__delete(q->xsk);
        xsk_umem__delete(q->umem);
        free(q->bufs);
        return -1;
    }

    // Fill the fill queue
    ret = xsk_ring_prod__reserve(&q->fill, RING_SIZE, &idx);
    for (int i = 0; i < ret; i++)
        *xsk_ring_prod__fill_addr(&q->fill, idx++) = i * FRAME_SIZE;
    xsk_ring_prod__submit(&q->fill, ret);

    printf("[Queue %d] Initialized: socket fd=%d, umem=%p, fill=%d frames\n",
           queue_id, fd, q->bufs, ret);

    return 0;
}

static void cleanup_queue(struct queue_state *q)
{
    if (q->xsk) xsk_socket__delete(q->xsk);
    if (q->umem) xsk_umem__delete(q->umem);
    if (q->bufs) {
        munlock(q->bufs, UMEM_SIZE);
        free(q->bufs);
    }
    memset(q, 0, sizeof(*q));
}

int main(int argc, char **argv)
{
    const char *ifname = "enp7s0";
    const char *bpf_file = "bpf/xdp_redirect.o";
    uint32_t local_network = 0x0009A8C0;  // 192.168.9.0
    uint32_t local_netmask = 0x00FFFFFF;  // 255.255.255.0

    if (argc > 1) ifname = argv[1];

    printf("=== Multi-Queue XDP Test (Separate UMEM per queue) ===\n");
    printf("Interface: %s\n", ifname);

    int ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        perror("if_nametoindex");
        return 1;
    }

    // Get queue count
    queue_count = get_queue_count(ifname);
    printf("Detected %d RX queues\n\n", queue_count);

    // Detach existing XDP
    bpf_set_link_xdp_fd(ifindex, -1, XDP_FLAGS_SKB_MODE);

    // Load BPF
    printf("[1] Loading BPF...\n");
    struct bpf_object *obj = bpf_object__open_file(bpf_file, NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Failed to open BPF\n");
        return 1;
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "Failed to load BPF\n");
        return 1;
    }

    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "xdp_redirect_prog");
    struct bpf_map *xsks_map = bpf_object__find_map_by_name(obj, "xsks_map");
    struct bpf_map *config_map = bpf_object__find_map_by_name(obj, "config_map");
    struct bpf_map *stats_map = bpf_object__find_map_by_name(obj, "stats_map");

    if (!prog || !xsks_map || !config_map) {
        fprintf(stderr, "Missing program or maps\n");
        return 1;
    }

    int prog_fd = bpf_program__fd(prog);
    int xsks_fd = bpf_map__fd(xsks_map);
    int config_fd = bpf_map__fd(config_map);
    int stats_fd = stats_map ? bpf_map__fd(stats_map) : -1;

    // Update config
    int key0 = 0, key1 = 1;
    bpf_map_update_elem(config_fd, &key0, &local_network, 0);
    bpf_map_update_elem(config_fd, &key1, &local_netmask, 0);
    printf("[2] Config updated\n");

    // Initialize all queues (each with separate UMEM)
    printf("[3] Initializing %d queues...\n", queue_count);
    for (int q = 0; q < queue_count; q++) {
        if (init_queue(&queues[q], ifname, q, xsks_fd) != 0) {
            fprintf(stderr, "Failed to init queue %d\n", q);
            for (int j = 0; j < q; j++)
                cleanup_queue(&queues[j]);
            bpf_object__close(obj);
            return 1;
        }
    }

    // Attach XDP AFTER all sockets are created
    printf("[4] Attaching XDP...\n");
    if (bpf_set_link_xdp_fd(ifindex, prog_fd, XDP_FLAGS_SKB_MODE)) {
        fprintf(stderr, "Failed to attach XDP\n");
        for (int q = 0; q < queue_count; q++)
            cleanup_queue(&queues[q]);
        bpf_object__close(obj);
        return 1;
    }

    printf("\n=== Ready ===\n");
    printf("Send traffic from client to non-local dest\n");
    printf("Press Ctrl+C to stop\n\n");

    signal(SIGINT, sigint_handler);
    signal(SIGTERM, sigint_handler);

    uint64_t total_rx = 0;

    while (running) {
        // Poll all queues
        struct pollfd pfds[MAX_QUEUES];
        for (int q = 0; q < queue_count; q++) {
            pfds[q].fd = xsk_socket__fd(queues[q].xsk);
            pfds[q].events = POLLIN;
        }

        int poll_ret = poll(pfds, queue_count, 1000);

        // Receive from all queues
        for (int q = 0; q < queue_count; q++) {
            uint32_t rx_idx;
            int rcvd = xsk_ring_cons__peek(&queues[q].rx, 64, &rx_idx);

            if (rcvd > 0) {
                for (int i = 0; i < rcvd; i++) {
                    const struct xdp_desc *desc = xsk_ring_cons__rx_desc(&queues[q].rx, rx_idx + i);
                    total_rx++;
                    queues[q].rx_count++;

                    // Return buffer to fill queue
                    uint32_t fi;
                    if (xsk_ring_prod__reserve(&queues[q].fill, 1, &fi) == 1) {
                        *xsk_ring_prod__fill_addr(&queues[q].fill, fi) = desc->addr;
                        xsk_ring_prod__submit(&queues[q].fill, 1);
                    }
                }
                xsk_ring_cons__release(&queues[q].rx, rcvd);
            }
        }

        // Print stats
        if (stats_fd >= 0) {
            uint64_t stats[8] = {0};
            for (int i = 0; i < 8; i++)
                bpf_map_lookup_elem(stats_fd, &i, &stats[i]);

            printf("\r[XDP] total=%lu redir_try=%lu success=%lu no_sock=%lu | [RX] ",
                   stats[0], stats[3], stats[5], stats[6]);

            for (int q = 0; q < queue_count; q++)
                printf("Q%d:%lu ", q, queues[q].rx_count);

            printf("| total=%lu    ", total_rx);
            fflush(stdout);
        }
    }

    printf("\n\n=== Final Stats ===\n");
    printf("Total received: %lu\n", total_rx);
    for (int q = 0; q < queue_count; q++)
        printf("  Queue %d: %lu packets\n", q, queues[q].rx_count);

    // Cleanup
    bpf_set_link_xdp_fd(ifindex, -1, XDP_FLAGS_SKB_MODE);
    for (int q = 0; q < queue_count; q++)
        cleanup_queue(&queues[q]);
    bpf_object__close(obj);

    printf("Done\n");
    return 0;
}
