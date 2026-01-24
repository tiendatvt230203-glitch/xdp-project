#ifndef FORWARDER_H
#define FORWARDER_H

#include "interface.h"

struct forwarder {
    // LOCAL interface (receive packets from clients)
    struct xsk_interface local;

    // WAN interfaces (send packets to other servers)
    struct xsk_interface wans[MAX_INTERFACES];
    int wan_count;

    // Round-robin index
    int current_wan;

    // Stats
    uint64_t total_forwarded;
    uint64_t total_dropped;
};

int forwarder_init(struct forwarder *fwd, struct app_config *cfg);
void forwarder_cleanup(struct forwarder *fwd);
void forwarder_run(struct forwarder *fwd);
void forwarder_print_stats(struct forwarder *fwd);

#endif
