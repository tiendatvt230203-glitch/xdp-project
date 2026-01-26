#ifndef FORWARDER_H
#define FORWARDER_H

#include "interface.h"

// Window size for load balancing (64KB per WAN before switching)
#define LB_WINDOW_SIZE (64 * 1024)

struct forwarder {
    // LOCAL interfaces (RX from clients, TX back to clients)
    struct xsk_interface locals[MAX_INTERFACES];
    int local_count;

    // WAN interfaces (RX + TX combined)
    struct xsk_interface wans[MAX_INTERFACES];
    int wan_count;

    // Reference to config (for IP → LOCAL lookup)
    struct app_config *cfg;

    // Load balancer state (LOCAL → WAN)
    int current_wan;           // Current WAN index
    uint64_t window_bytes;     // Bytes sent in current window

    // Stats
    uint64_t local_to_wan;     // Packets forwarded LOCAL → WAN
    uint64_t wan_to_local;     // Packets forwarded WAN → LOCAL
    uint64_t total_dropped;
};

int forwarder_init(struct forwarder *fwd, struct app_config *cfg);
void forwarder_cleanup(struct forwarder *fwd);
void forwarder_run(struct forwarder *fwd);
void forwarder_print_stats(struct forwarder *fwd);

#endif
