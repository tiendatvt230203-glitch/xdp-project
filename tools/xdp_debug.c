#include "../inc/interface.h"
#include "../inc/config.h"
#include <linux/if_link.h>

int main(int argc, char **argv)
{
    struct app_config cfg;
    const char *config_file = "config.cfg";

    if (argc > 1)
        config_file = argv[1];

    printf("=== XDP Debug Tool ===\n\n");

    // Load config
    if (config_load(&cfg, config_file) != 0) {
        fprintf(stderr, "Failed to load config\n");
        return 1;
    }

    if (cfg.local_count == 0) {
        fprintf(stderr, "No LOCAL interface in config\n");
        return 1;
    }

    struct local_config *local_cfg = &cfg.locals[0];

    printf("1. CONFIG FILE:\n");
    printf("   Interface: %s\n", local_cfg->ifname);
    printf("   Network:   0x%08X (%u.%u.%u.%u)\n",
           local_cfg->network,
           (local_cfg->network >> 0) & 0xFF,
           (local_cfg->network >> 8) & 0xFF,
           (local_cfg->network >> 16) & 0xFF,
           (local_cfg->network >> 24) & 0xFF);
    printf("   Netmask:   0x%08X (%u.%u.%u.%u)\n",
           local_cfg->netmask,
           (local_cfg->netmask >> 0) & 0xFF,
           (local_cfg->netmask >> 8) & 0xFF,
           (local_cfg->netmask >> 16) & 0xFF,
           (local_cfg->netmask >> 24) & 0xFF);
    printf("   BPF file:  %s\n", cfg.bpf_file);

    // Check if BPF file exists
    printf("\n2. BPF FILE CHECK:\n");
    if (access(cfg.bpf_file, F_OK) == 0) {
        printf("   [OK] %s exists\n", cfg.bpf_file);
    } else {
        printf("   [ERROR] %s NOT FOUND!\n", cfg.bpf_file);
        return 1;
    }

    // Check interface
    printf("\n3. INTERFACE CHECK:\n");
    int ifindex = if_nametoindex(local_cfg->ifname);
    if (ifindex > 0) {
        printf("   [OK] %s ifindex=%d\n", local_cfg->ifname, ifindex);
    } else {
        printf("   [ERROR] %s not found!\n", local_cfg->ifname);
        return 1;
    }

    // Check current XDP status
    printf("\n4. CURRENT XDP STATUS:\n");
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "ip link show %s | grep -i xdp", local_cfg->ifname);
    printf("   Running: %s\n", cmd);
    int ret = system(cmd);
    if (ret != 0) {
        printf("   [INFO] No XDP program currently attached\n");
    }

    // Load BPF object and check maps
    printf("\n5. LOADING BPF OBJECT:\n");
    struct bpf_object *obj = bpf_object__open_file(cfg.bpf_file, NULL);
    if (libbpf_get_error(obj)) {
        printf("   [ERROR] Failed to open BPF file\n");
        return 1;
    }
    printf("   [OK] BPF object opened\n");

    ret = bpf_object__load(obj);
    if (ret) {
        printf("   [ERROR] Failed to load BPF object: %d\n", ret);
        bpf_object__close(obj);
        return 1;
    }
    printf("   [OK] BPF object loaded\n");

    // Find program
    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "xdp_redirect_prog");
    if (!prog) {
        printf("   [ERROR] xdp_redirect_prog not found!\n");
        bpf_object__close(obj);
        return 1;
    }
    printf("   [OK] xdp_redirect_prog found\n");

    // Find maps
    struct bpf_map *xsks_map = bpf_object__find_map_by_name(obj, "xsks_map");
    struct bpf_map *config_map = bpf_object__find_map_by_name(obj, "config_map");

    printf("\n6. BPF MAPS:\n");
    if (xsks_map) {
        printf("   [OK] xsks_map found (fd=%d, max_entries=%d)\n",
               bpf_map__fd(xsks_map), bpf_map__max_entries(xsks_map));
    } else {
        printf("   [ERROR] xsks_map NOT FOUND!\n");
    }

    if (config_map) {
        printf("   [OK] config_map found (fd=%d, max_entries=%d)\n",
               bpf_map__fd(config_map), bpf_map__max_entries(config_map));
    } else {
        printf("   [ERROR] config_map NOT FOUND!\n");
    }

    // Attach XDP
    printf("\n7. ATTACHING XDP:\n");
    int prog_fd = bpf_program__fd(prog);
    ret = bpf_set_link_xdp_fd(ifindex, prog_fd, XDP_FLAGS_SKB_MODE);
    if (ret) {
        printf("   [ERROR] Failed to attach XDP: %d (errno=%d: %s)\n",
               ret, errno, strerror(errno));

        // Try to detach first
        printf("   [INFO] Trying to detach existing XDP first...\n");
        bpf_set_link_xdp_fd(ifindex, -1, XDP_FLAGS_SKB_MODE);

        ret = bpf_set_link_xdp_fd(ifindex, prog_fd, XDP_FLAGS_SKB_MODE);
        if (ret) {
            printf("   [ERROR] Still failed: %d\n", ret);
            bpf_object__close(obj);
            return 1;
        }
    }
    printf("   [OK] XDP attached in SKB mode\n");

    // Update config_map
    printf("\n8. UPDATING CONFIG_MAP:\n");
    if (config_map) {
        int config_fd = bpf_map__fd(config_map);
        int key0 = 0, key1 = 1;

        ret = bpf_map_update_elem(config_fd, &key0, &local_cfg->network, 0);
        printf("   network update: %s (key=0, value=0x%08X)\n",
               ret == 0 ? "OK" : "FAILED", local_cfg->network);

        ret = bpf_map_update_elem(config_fd, &key1, &local_cfg->netmask, 0);
        printf("   netmask update: %s (key=1, value=0x%08X)\n",
               ret == 0 ? "OK" : "FAILED", local_cfg->netmask);

        // Read back to verify
        uint32_t read_net = 0, read_mask = 0;
        bpf_map_lookup_elem(config_fd, &key0, &read_net);
        bpf_map_lookup_elem(config_fd, &key1, &read_mask);
        printf("   Verify read: network=0x%08X, netmask=0x%08X\n", read_net, read_mask);
    }

    // Check XDP is attached
    printf("\n9. VERIFY XDP ATTACHED:\n");
    system(cmd);

    // Test packet matching
    printf("\n10. PACKET MATCHING TEST:\n");
    uint32_t test_dst = htonl(0xC0A8B602); // 192.168.182.2
    uint32_t local_net = local_cfg->network;
    uint32_t local_mask = local_cfg->netmask;

    printf("   Test dest IP: 192.168.182.2 (0x%08X)\n", test_dst);
    printf("   Local network: 0x%08X\n", local_net);
    printf("   Local netmask: 0x%08X\n", local_mask);
    printf("   (dest & mask): 0x%08X\n", test_dst & local_mask);
    printf("   Match local? %s\n",
           ((test_dst & local_mask) == local_net) ? "YES (XDP_PASS)" : "NO (redirect to userspace)");

    // Cleanup - detach XDP
    printf("\n11. CLEANUP:\n");
    bpf_set_link_xdp_fd(ifindex, -1, XDP_FLAGS_SKB_MODE);
    printf("   XDP detached\n");

    bpf_object__close(obj);
    printf("   BPF object closed\n");

    printf("\n=== Debug Complete ===\n");

    return 0;
}
