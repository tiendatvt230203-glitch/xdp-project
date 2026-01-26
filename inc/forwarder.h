#ifndef FORWARDER_H
#define FORWARDER_H

#include "interface.h"

// Window size for load balancing (64KB per WAN before switching)
#define LB_WINDOW_SIZE (64 * 1024)

struct forwarder {
    // LOCAL interfaces (receive packets from clients)
    struct xsk_interface locals[MAX_INTERFACES];
    int local_count;

    // WAN interfaces (send packets to other servers)
    struct xsk_interface wans[MAX_INTERFACES];
    int wan_count;

    // Load balancer state
    int current_wan;           // Current WAN index
    uint64_t window_bytes;     // Bytes sent in current window

    // Stats
    uint64_t total_forwarded;
    uint64_t total_dropped;
};

int forwarder_init(struct forwarder *fwd, struct app_config *cfg);
void forwarder_cleanup(struct forwarder *fwd);
void forwarder_run(struct forwarder *fwd);
void forwarder_print_stats(struct forwarder *fwd);

#endif
