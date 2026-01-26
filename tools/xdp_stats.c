#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <net/if.h>
#include <linux/if_link.h>

static volatile int running = 1;

static void sigint_handler(int sig) {
    (void)sig;
    running = 0;
}

int main(int argc, char **argv)
{
    const char *ifname = "enp7s0";
    const char *bpf_file = "bpf/xdp_redirect.o";

    if (argc > 1) ifname = argv[1];

    printf("=== XDP Stats Monitor ===\n");
    printf("Interface: %s\n", ifname);
    printf("Press Ctrl+C to stop\n\n");

    int ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        perror("if_nametoindex");
        return 1;
    }

    // Load BPF
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
    if (!prog) {
        fprintf(stderr, "Program not found\n");
        return 1;
    }

    // Attach XDP
    int prog_fd = bpf_program__fd(prog);
    bpf_set_link_xdp_fd(ifindex, -1, XDP_FLAGS_SKB_MODE); // detach first
    if (bpf_set_link_xdp_fd(ifindex, prog_fd, XDP_FLAGS_SKB_MODE)) {
        fprintf(stderr, "Failed to attach XDP\n");
        return 1;
    }
    printf("XDP attached\n");

    // Get stats map
    struct bpf_map *stats_map = bpf_object__find_map_by_name(obj, "stats_map");
    struct bpf_map *config_map = bpf_object__find_map_by_name(obj, "config_map");

    if (!stats_map) {
        fprintf(stderr, "stats_map not found\n");
        bpf_set_link_xdp_fd(ifindex, -1, XDP_FLAGS_SKB_MODE);
        return 1;
    }

    int stats_fd = bpf_map__fd(stats_map);
    int config_fd = config_map ? bpf_map__fd(config_map) : -1;

    // Update config
    if (config_fd >= 0) {
        uint32_t network = 0x0009A8C0; // 192.168.9.0
        uint32_t netmask = 0x00FFFFFF; // 255.255.255.0
        int key0 = 0, key1 = 1;
        bpf_map_update_elem(config_fd, &key0, &network, 0);
        bpf_map_update_elem(config_fd, &key1, &netmask, 0);
        printf("config_map updated: network=192.168.9.0, netmask=255.255.255.0\n");
    }

    printf("\nMonitoring XDP stats...\n");
    printf("Send traffic from client (e.g., ping 192.168.182.2)\n\n");

    signal(SIGINT, sigint_handler);
    signal(SIGTERM, sigint_handler);

    uint64_t prev[8] = {0};

    while (running) {
        uint64_t stats[8] = {0};

        for (int i = 0; i < 8; i++) {
            bpf_map_lookup_elem(stats_fd, &i, &stats[i]);
        }

        printf("\r[Stats] total=%lu | non-IP=%lu | local=%lu | try_redir=%lu | success=%lu | no_sock=%lu",
               stats[0], stats[1], stats[2], stats[3], stats[5], stats[6]);
        fflush(stdout);

        for (int i = 0; i < 8; i++)
            prev[i] = stats[i];

        sleep(1);
    }

    printf("\n\n=== Final Stats ===\n");
    uint64_t stats[8] = {0};
    for (int i = 0; i < 8; i++)
        bpf_map_lookup_elem(stats_fd, &i, &stats[i]);

    printf("Total packets:      %lu\n", stats[0]);
    printf("Non-IP (passed):    %lu\n", stats[1]);
    printf("Local net (passed): %lu\n", stats[2]);
    printf("Redirect attempted: %lu\n", stats[3]);
    printf("Config missing:     %lu\n", stats[4]);
    printf("Redirect success:   %lu\n", stats[5]);
    printf("No socket (fail):   %lu\n", stats[6]);

    // Cleanup
    bpf_set_link_xdp_fd(ifindex, -1, XDP_FLAGS_SKB_MODE);
    bpf_object__close(obj);
    printf("\nXDP detached\n");

    return 0;
}
