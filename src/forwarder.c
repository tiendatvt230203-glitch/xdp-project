#include "../inc/forwarder.h"
#include <signal.h>
#include <poll.h>

static volatile int running = 1;

static void sigint_handler(int sig)
{
    (void)sig;
    running = 0;
}

int forwarder_init(struct forwarder *fwd, struct app_config *cfg)
{
    memset(fwd, 0, sizeof(*fwd));

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
            for (int j = 0; j < fwd->wan_count; j++)
                interface_cleanup(&fwd->wans[j]);
            for (int j = 0; j < i; j++)
                interface_cleanup(&fwd->locals[j]);
            return -1;
        }
        fwd->local_count++;
    }

    printf("[FWD] Ready: %d LOCAL, %d WAN, window=%dKB\n",
           fwd->local_count, fwd->wan_count, LB_WINDOW_SIZE / 1024);

    return 0;
}

void forwarder_cleanup(struct forwarder *fwd)
{
    for (int i = 0; i < fwd->local_count; i++)
        interface_cleanup(&fwd->locals[i]);

    for (int i = 0; i < fwd->wan_count; i++)
        interface_cleanup(&fwd->wans[i]);
}

// Get WAN interface using window-based load balancing
static struct xsk_interface *get_wan(struct forwarder *fwd, uint32_t pkt_len)
{
    fwd->window_bytes += pkt_len;

    if (fwd->window_bytes >= LB_WINDOW_SIZE) {
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

    printf("[FWD] Running... (Ctrl+C to stop)\n");

    while (running) {
        for (int local_idx = 0; local_idx < fwd->local_count; local_idx++) {
            struct xsk_interface *local = &fwd->locals[local_idx];

            int rcvd = interface_recv(local, pkt_ptrs, pkt_lens, addrs, BATCH_SIZE);
            if (rcvd == 0)
                continue;

            for (int i = 0; i < rcvd; i++) {
                struct xsk_interface *wan = get_wan(fwd, pkt_lens[i]);

                if (interface_send(wan, pkt_ptrs[i], pkt_lens[i]) == 0)
                    fwd->total_forwarded++;
                else
                    fwd->total_dropped++;
            }

            interface_recv_release(local, addrs, rcvd);
        }
    }

    printf("\n[FWD] Forwarded: %lu | Dropped: %lu\n",
           fwd->total_forwarded, fwd->total_dropped);
}

void forwarder_print_stats(struct forwarder *fwd)
{
    printf("Forwarded: %lu | Dropped: %lu\n",
           fwd->total_forwarded, fwd->total_dropped);
}
