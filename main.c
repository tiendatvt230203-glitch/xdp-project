#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <bpf/libbpf.h>
#include "config.h"
#include "forwarder.h"

// Suppress all libbpf logs
static int libbpf_print_silent(enum libbpf_print_level level,
                               const char *format, va_list args)
{
    (void)level;
    (void)format;
    (void)args;
    return 0;
}

static void print_usage(const char *prog)
{
    printf("Usage: %s [config_file]\n", prog);
    printf("  config_file: Path to configuration file (default: config.cfg)\n");
    printf("\nConfig file format:\n");
    printf("  LOCAL <interface> <mac>\n");
    printf("  WAN <interface> <mac>\n");
    printf("  GATEWAY_MAC <mac>\n");
    printf("  BPF_FILE <path>\n");
    printf("\nExample:\n");
    printf("  LOCAL enp7s0 20:7c:14:f8:0c:d0\n");
    printf("  WAN enp5s0 20:7c:14:f8:0d:4e\n");
    printf("  GATEWAY_MAC 00:11:22:33:44:55\n");
}

int main(int argc, char **argv)
{
    struct app_config cfg;
    struct forwarder fwd;
    const char *config_file = "config.cfg";

    if (argc > 1) {
        if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        }
        config_file = argv[1];
    }

    // Suppress libbpf warnings
    libbpf_set_print(libbpf_print_silent);

    printf("=================================\n");
    printf("   XDP Packet Forwarder v2.0\n");
    printf("=================================\n\n");

    // Load configuration
    printf("[MAIN] Loading config from: %s\n", config_file);
    if (config_load(&cfg, config_file) != 0) {
        fprintf(stderr, "Failed to load config\n");
        return 1;
    }
    config_print(&cfg);

    // Initialize forwarder
    if (forwarder_init(&fwd, &cfg) != 0) {
        fprintf(stderr, "Failed to initialize forwarder\n");
        return 1;
    }

    // Run forwarding loop
    forwarder_run(&fwd);

    // Cleanup
    forwarder_cleanup(&fwd);

    printf("[MAIN] Exited cleanly.\n");
    return 0;
}
