#include "../inc/forwarder.h"
#include <signal.h>

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

    // Initialize LOCAL interface
    if (interface_init_local(&fwd->local, cfg) != 0) {
        fprintf(stderr, "Failed to init LOCAL %s\n", cfg->local.ifname);
        for (int j = 0; j < fwd->wan_count; j++)
            interface_cleanup(&fwd->wans[j]);
        return -1;
    }

    printf("\n[FWD] Ready! 1 LOCAL, %d WAN interfaces\n", fwd->wan_count);

    return 0;
}

void forwarder_cleanup(struct forwarder *fwd)
{
    printf("\n[FWD] Cleaning up...\n");

    interface_cleanup(&fwd->local);

    for (int i = 0; i < fwd->wan_count; i++)
        interface_cleanup(&fwd->wans[i]);

    printf("[FWD] Cleanup complete\n");
}

static struct xsk_interface *get_wan(struct forwarder *fwd)
{
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

    printf("\n╔════════════════════════════════════════════════╗\n");
    printf("║       FORWARDING STARTED - Ctrl+C to stop      ║\n");
    printf("╚════════════════════════════════════════════════╝\n\n");

    uint64_t last_print = 0;

    while (running) {
        // Receive packets from LOCAL
        int rcvd = interface_recv(&fwd->local, pkt_ptrs, pkt_lens, addrs, BATCH_SIZE);
        if (rcvd == 0)
            continue;

        // Forward each packet to WAN
        printf("[DEBUG] Received %d packets from LOCAL\n", rcvd);
        for (int i = 0; i < rcvd; i++) {
            struct xsk_interface *wan = get_wan(fwd);

            printf("[DEBUG] Sending pkt %d (%u bytes) to %s\n", i, pkt_lens[i], wan->ifname);

            if (interface_send(wan, pkt_ptrs[i], pkt_lens[i]) == 0) {
                fwd->total_forwarded++;
                printf("[DEBUG] OK - forwarded\n");
            } else {
                fwd->total_dropped++;
                printf("[DEBUG] FAIL - dropped\n");
            }
        }

        // Release buffers
        interface_recv_release(&fwd->local, addrs, rcvd);

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

    interface_print_stats(&fwd->local);
    for (int i = 0; i < fwd->wan_count; i++)
        interface_print_stats(&fwd->wans[i]);

    printf("╚════════════════════════════════════════════════╝\n");
}
