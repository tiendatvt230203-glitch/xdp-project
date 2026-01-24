#include "../inc/forwarder.h"
#include <signal.h>
#include <poll.h>

static volatile int running = 1;

static void sigint_handler(int sig)
{
    (void)sig;
    running = 0;
    printf("\n[FWD] Stopping...\n");
}

int forwarder_init(struct forwarder *fwd, struct app_config *cfg)
{
    memset(fwd, 0, sizeof(*fwd));

    printf("\n[FWD] Initializing forwarder...\n");

    // Initialize WAN interfaces first
    for (int i = 0; i < cfg->wan_count; i++) {
        if (interface_init_wan(&fwd->wans[i], &cfg->wans[i]) != 0) {
            fprintf(stderr, "Failed to init WAN %s\n", cfg->wans[i].ifname);
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
            // Cleanup WANs
            for (int j = 0; j < fwd->wan_count; j++)
                interface_cleanup(&fwd->wans[j]);
            // Cleanup already initialized LOCALs
            for (int j = 0; j < i; j++)
                interface_cleanup(&fwd->locals[j]);
            return -1;
        }
        fwd->local_count++;
    }

    printf("\n[FWD] Ready! %d LOCAL, %d WAN interfaces\n", fwd->local_count, fwd->wan_count);
    printf("[FWD] Load balancer: window size = %d bytes\n", LB_WINDOW_SIZE);
    for (int i = 0; i < fwd->wan_count; i++) {
        printf("[FWD] WAN[%d] = %s\n", i, fwd->wans[i].ifname);
    }

    return 0;
}

void forwarder_cleanup(struct forwarder *fwd)
{
    printf("\n[FWD] Cleaning up...\n");

    for (int i = 0; i < fwd->local_count; i++)
        interface_cleanup(&fwd->locals[i]);

    for (int i = 0; i < fwd->wan_count; i++)
        interface_cleanup(&fwd->wans[i]);

    printf("[FWD] Cleanup complete\n");
}

// Get WAN interface using window-based load balancing
// Each window goes to one WAN before switching
static struct xsk_interface *get_wan(struct forwarder *fwd, uint32_t pkt_len)
{
    // Add packet size to counter
    fwd->window_bytes += pkt_len;

    // If window is full, switch to next WAN and reset counter
    if (fwd->window_bytes >= LB_WINDOW_SIZE) {
        printf("[LB] Window full (%lu bytes)! Switching WAN[%d] -> WAN[%d]\n",
               fwd->window_bytes,
               fwd->current_wan,
               (fwd->current_wan + 1) % fwd->wan_count);
        fflush(stdout);

        fwd->current_wan = (fwd->current_wan + 1) % fwd->wan_count;
        fwd->window_bytes = 0;
    }

    return &fwd->wans[fwd->current_wan];
}

void forwarder_run(struct forwarder *fwd)
{
    void *pkt_ptrs[BATCH_SIZE];
    uint32_t pkt_lens[BATCH_SIZE];
    uint64_t addrs[BATCH_SIZE];

    signal(SIGINT, sigint_handler);
    signal(SIGTERM, sigint_handler);

    printf("\n╔════════════════════════════════════════════════╗\n");
    printf("║       FORWARDING STARTED - Ctrl+C to stop      ║\n");
    printf("╚════════════════════════════════════════════════╝\n\n");

    uint64_t last_print = 0;

    while (running) {
        // Poll from all LOCAL interfaces
        for (int local_idx = 0; local_idx < fwd->local_count; local_idx++) {
            struct xsk_interface *local = &fwd->locals[local_idx];

            int rcvd = interface_recv(local, pkt_ptrs, pkt_lens, addrs, BATCH_SIZE);
            if (rcvd == 0)
                continue;

            // Forward each packet to WAN (window-based load balancing)
            for (int i = 0; i < rcvd; i++) {
                struct xsk_interface *wan = get_wan(fwd, pkt_lens[i]);

                if (interface_send(wan, pkt_ptrs[i], pkt_lens[i]) == 0) {
                    fwd->total_forwarded++;
                } else {
                    fwd->total_dropped++;
                }
            }

            // Release buffers
            interface_recv_release(local, addrs, rcvd);
        }

        // Print stats every 1000 packets
        if (fwd->total_forwarded - last_print >= 1000) {
            printf("[FWD] Forwarded: %lu | Dropped: %lu\n",
                   fwd->total_forwarded, fwd->total_dropped);
            last_print = fwd->total_forwarded;
        }
    }

    printf("\n[FWD] Stopped.\n");
    forwarder_print_stats(fwd);
}

void forwarder_print_stats(struct forwarder *fwd)
{
    printf("\n╔════════════════════════════════════════════════╗\n");
    printf("║                 FINAL STATISTICS               ║\n");
    printf("╠════════════════════════════════════════════════╣\n");
    printf("║ Total Forwarded: %-29lu ║\n", fwd->total_forwarded);
    printf("║ Total Dropped:   %-29lu ║\n", fwd->total_dropped);
    printf("╟────────────────────────────────────────────────╢\n");

    for (int i = 0; i < fwd->local_count; i++)
        interface_print_stats(&fwd->locals[i]);

    for (int i = 0; i < fwd->wan_count; i++)
        interface_print_stats(&fwd->wans[i]);

    printf("╚════════════════════════════════════════════════╝\n");
}
