#ifndef FORWARDER_H
#define FORWARDER_H

#include "interface.h"
#include "config.h"

// Forwarder context - manages all interfaces
struct forwarder {
    struct xsk_interface locals[MAX_INTERFACES];
    int local_count;

    struct xsk_interface wans[MAX_INTERFACES];
    int wan_count;

    // Current WAN index for round-robin load balancing
    int current_wan;

    // Stats
    uint64_t total_forwarded;
    uint64_t total_dropped;
};

// Initialize forwarder from config
int forwarder_init(struct forwarder *fwd, struct app_config *cfg);

// Cleanup all interfaces
void forwarder_cleanup(struct forwarder *fwd);

// Run forwarding loop (blocking)
void forwarder_run(struct forwarder *fwd);

// Get next WAN for load balancing (round-robin)
struct xsk_interface *forwarder_get_wan(struct forwarder *fwd);

// Print all stats
void forwarder_print_stats(struct forwarder *fwd);

#endif
