#include "../inc/forwarder.h"
#include <signal.h>

static volatile int running = 1;

static void sigint_handler(int sig)
{
    (void)sig;
    running = 0;
    printf("\n[FWD] Received signal, stopping...\n");
}

int forwarder_init(struct forwarder *fwd, struct app_config *cfg)
{
    memset(fwd, 0, sizeof(*fwd));

    printf("[FWD] Initializing forwarder...\n");

    // Initialize WAN interfaces first
    for (int i = 0; i < cfg->wan_count; i++) {
        if (interface_init_wan(&fwd->wans[i], &cfg->wans[i], cfg->gateway_mac) != 0) {
            fprintf(stderr, "Failed to init WAN %s\n", cfg->wans[i].ifname);
            // Cleanup already initialized
            for (int j = 0; j < i; j++)
                interface_cleanup(&fwd->wans[j]);
            return -1;
        }
        fwd->wan_count++;
    }

    // Initialize LOCAL interfaces
    for (int i = 0; i < cfg->local_count; i++) {
        if (interface_init_local(&fwd->locals[i], &cfg->locals[i], cfg->bpf_file) != 0) {
            fprintf(stderr, "Failed to init LOCAL %s\n", cfg->locals[i].ifname);
            // Cleanup
            for (int j = 0; j < i; j++)
                interface_cleanup(&fwd->locals[j]);
            for (int j = 0; j < fwd->wan_count; j++)
                interface_cleanup(&fwd->wans[j]);
            return -1;
        }
        fwd->local_count++;
    }

    printf("[FWD] Initialized %d LOCAL and %d WAN interfaces\n",
           fwd->local_count, fwd->wan_count);

    return 0;
}

void forwarder_cleanup(struct forwarder *fwd)
{
    printf("[FWD] Cleaning up...\n");

    for (int i = 0; i < fwd->local_count; i++)
        interface_cleanup(&fwd->locals[i]);

    for (int i = 0; i < fwd->wan_count; i++)
        interface_cleanup(&fwd->wans[i]);

    printf("[FWD] Cleanup complete\n");
}

struct xsk_interface *forwarder_get_wan(struct forwarder *fwd)
{
    // Simple round-robin
    struct xsk_interface *wan = &fwd->wans[fwd->current_wan];
    fwd->current_wan = (fwd->current_wan + 1) % fwd->wan_count;
    return wan;
}

void forwarder_run(struct forwarder *fwd)
{
    void *pkt_ptrs[BATCH_SIZE];
    uint32_t pkt_lens[BATCH_SIZE];
    uint64_t addrs[BATCH_SIZE];

    signal(SIGINT, sigint_handler);
    signal(SIGTERM, sigint_handler);

    printf("[FWD] Forwarding loop started. Press Ctrl+C to stop.\n");

    uint64_t last_print = 0;

    while (running) {
        // Process each LOCAL interface
        for (int i = 0; i < fwd->local_count && running; i++) {
            struct xsk_interface *local = &fwd->locals[i];

            // Receive packets
            int rcvd = interface_recv(local, pkt_ptrs, pkt_lens, addrs, BATCH_SIZE);
            if (rcvd == 0)
                continue;

            // Forward each packet to WAN
            for (int j = 0; j < rcvd; j++) {
                // Get WAN for this packet (load balancing)
                struct xsk_interface *wan = forwarder_get_wan(fwd);

                if (interface_send(wan, pkt_ptrs[j], pkt_lens[j]) == 0) {
                    fwd->total_forwarded++;
                } else {
                    fwd->total_dropped++;
                }
            }

            // Release buffers
            interface_recv_release(local, addrs, rcvd);
        }

        // Print stats every 10000 packets
        if (fwd->total_forwarded - last_print >= 10000) {
            printf("[FWD] Forwarded: %lu, Dropped: %lu\n",
                   fwd->total_forwarded, fwd->total_dropped);
            last_print = fwd->total_forwarded;
        }
    }

    printf("[FWD] Loop stopped. Final stats:\n");
    forwarder_print_stats(fwd);
}

void forwarder_print_stats(struct forwarder *fwd)
{
    printf("\n=== Forwarder Statistics ===\n");
    printf("Total forwarded: %lu\n", fwd->total_forwarded);
    printf("Total dropped: %lu\n", fwd->total_dropped);

    printf("\nLOCAL interfaces:\n");
    for (int i = 0; i < fwd->local_count; i++)
        interface_print_stats(&fwd->locals[i]);

    printf("\nWAN interfaces:\n");
    for (int i = 0; i < fwd->wan_count; i++)
        interface_print_stats(&fwd->wans[i]);

    printf("============================\n");
}
