// Full test: Load XDP + Create socket + Show stats + Receive packets
#include <linux/if_xdp.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <xdp/xsk.h>
#include <poll.h>
#include <signal.h>
#include <sys/mman.h>
#include <net/ethernet.h>
#include <linux/ip.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#define FRAME_SIZE 4096
#define FRAME_COUNT 4096
#define UMEM_SIZE (FRAME_SIZE * FRAME_COUNT)
#define RING_SIZE 4096

static volatile int running = 1;

static void sigint_handler(int sig) {
    (void)sig;
    running = 0;
}

int main(int argc, char **argv)
{
    const char *ifname = "enp7s0";
    const char *bpf_file = "bpf/xdp_redirect.o";
    uint32_t local_network = 0x0009A8C0;  // 192.168.9.0 in little endian
    uint32_t local_netmask = 0x00FFFFFF;  // 255.255.255.0

    if (argc > 1) ifname = argv[1];

    printf("=== Full XDP Test (Stats + Receive) ===\n");
    printf("Interface: %s\n", ifname);
    printf("Press Ctrl+C to stop\n\n");

    int ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        perror("if_nametoindex");
        return 1;
    }
    printf("[1] Interface %s ifindex=%d\n", ifname, ifindex);

    // Detach any existing XDP
    bpf_set_link_xdp_fd(ifindex, -1, XDP_FLAGS_SKB_MODE);
    printf("[2] Detached existing XDP\n");

    // Allocate UMEM
    void *bufs;
    int ret = posix_memalign(&bufs, getpagesize(), UMEM_SIZE);
    if (ret) {
        perror("posix_memalign");
        return 1;
    }
    mlock(bufs, UMEM_SIZE);
    printf("[3] UMEM allocated: %d MB\n", UMEM_SIZE / (1024*1024));

    // Create UMEM
    struct xsk_umem *umem;
    struct xsk_ring_prod fill;
    struct xsk_ring_cons comp;

    ret = xsk_umem__create(&umem, bufs, UMEM_SIZE, &fill, &comp, NULL);
    if (ret) {
        fprintf(stderr, "[ERROR] xsk_umem__create: %d\n", ret);
        return 1;
    }
    printf("[4] UMEM created\n");

    // Load BPF
    struct bpf_object *obj = bpf_object__open_file(bpf_file, NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "[ERROR] bpf_object__open_file\n");
        return 1;
    }

    ret = bpf_object__load(obj);
    if (ret) {
        fprintf(stderr, "[ERROR] bpf_object__load: %d\n", ret);
        return 1;
    }
    printf("[5] BPF loaded\n");

    // Get program and maps
    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "xdp_redirect_prog");
    struct bpf_map *xsks_map = bpf_object__find_map_by_name(obj, "xsks_map");
    struct bpf_map *config_map = bpf_object__find_map_by_name(obj, "config_map");
    struct bpf_map *stats_map = bpf_object__find_map_by_name(obj, "stats_map");

    if (!prog || !xsks_map || !config_map) {
        fprintf(stderr, "[ERROR] Missing program or maps\n");
        return 1;
    }

    int prog_fd = bpf_program__fd(prog);
    int xsks_fd = bpf_map__fd(xsks_map);
    int config_fd = bpf_map__fd(config_map);
    int stats_fd = stats_map ? bpf_map__fd(stats_map) : -1;

    printf("[6] Program fd=%d, xsks_map fd=%d, config_map fd=%d, stats_map fd=%d\n",
           prog_fd, xsks_fd, config_fd, stats_fd);

    // Update config_map
    int key0 = 0, key1 = 1;
    bpf_map_update_elem(config_fd, &key0, &local_network, 0);
    bpf_map_update_elem(config_fd, &key1, &local_netmask, 0);
    printf("[7] config_map updated\n");

    // Create AF_XDP socket for queue 0
    struct xsk_socket *xsk;
    struct xsk_ring_prod tx;
    struct xsk_ring_cons rx;

    struct xsk_socket_config sock_cfg = {
        .rx_size = RING_SIZE,
        .tx_size = RING_SIZE,
        .libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,
        .bind_flags = XDP_COPY
    };

    ret = xsk_socket__create(&xsk, ifname, 0, umem, &rx, &tx, &sock_cfg);
    if (ret) {
        fprintf(stderr, "[ERROR] xsk_socket__create: %d (errno=%d: %s)\n", ret, errno, strerror(errno));
        return 1;
    }
    int xsk_fd = xsk_socket__fd(xsk);
    printf("[8] AF_XDP socket created fd=%d\n", xsk_fd);

    // Register in xsks_map
    int queue = 0;
    ret = bpf_map_update_elem(xsks_fd, &queue, &xsk_fd, 0);
    if (ret) {
        fprintf(stderr, "[ERROR] bpf_map_update_elem: %d\n", ret);
        return 1;
    }
    printf("[9] Socket registered in xsks_map[0]\n");

    // Attach XDP AFTER socket is registered
    ret = bpf_set_link_xdp_fd(ifindex, prog_fd, XDP_FLAGS_SKB_MODE);
    if (ret) {
        fprintf(stderr, "[ERROR] bpf_set_link_xdp_fd: %d\n", ret);
        return 1;
    }
    printf("[10] XDP attached\n");

    // Fill the fill queue
    uint32_t idx;
    ret = xsk_ring_prod__reserve(&fill, RING_SIZE, &idx);
    for (int i = 0; i < ret; i++)
        *xsk_ring_prod__fill_addr(&fill, idx++) = i * FRAME_SIZE;
    xsk_ring_prod__submit(&fill, ret);
    printf("[11] Fill queue populated with %d frames\n", ret);

    printf("\n=== Ready ===\n");
    printf("Send traffic to non-local dest (e.g., ping 192.168.182.2 from client)\n\n");

    signal(SIGINT, sigint_handler);
    signal(SIGTERM, sigint_handler);

    uint64_t total_rx = 0;
    uint64_t last_stats[8] = {0};

    while (running) {
        // Check RX
        uint32_t rx_idx;
        int rcvd = xsk_ring_cons__peek(&rx, 64, &rx_idx);

        if (rcvd > 0) {
            for (int i = 0; i < rcvd; i++) {
                const struct xdp_desc *desc = xsk_ring_cons__rx_desc(&rx, rx_idx + i);
                total_rx++;
                printf("[RX] pkt %lu len=%u\n", total_rx, desc->len);

                // Return to fill
                uint32_t fi;
                if (xsk_ring_prod__reserve(&fill, 1, &fi) == 1) {
                    *xsk_ring_prod__fill_addr(&fill, fi) = desc->addr;
                    xsk_ring_prod__submit(&fill, 1);
                }
            }
            xsk_ring_cons__release(&rx, rcvd);
        }

        // Show stats every second (non-blocking poll)
        struct pollfd pfd = { .fd = xsk_fd, .events = POLLIN };
        int poll_ret = poll(&pfd, 1, 1000);

        if (stats_fd >= 0) {
            uint64_t stats[8] = {0};
            for (int i = 0; i < 8; i++)
                bpf_map_lookup_elem(stats_fd, &i, &stats[i]);

            printf("[XDP] total=%lu non-IP=%lu local=%lu try=%lu success=%lu no_sock=%lu | [USERSPACE] rx=%lu\n",
                   stats[0], stats[1], stats[2], stats[3], stats[5], stats[6], total_rx);

            for (int i = 0; i < 8; i++)
                last_stats[i] = stats[i];
        }
    }

    printf("\n=== Done ===\n");
    printf("Total received in userspace: %lu\n", total_rx);

    // Cleanup
    bpf_set_link_xdp_fd(ifindex, -1, XDP_FLAGS_SKB_MODE);
    xsk_socket__delete(xsk);
    xsk_umem__delete(umem);
    munlock(bufs, UMEM_SIZE);
    free(bufs);
    bpf_object__close(obj);

    return 0;
}
