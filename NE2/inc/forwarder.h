#ifndef FORWARDER_H
#define FORWARDER_H

#include "interface.h"

/** Per-site drop reason: increments with total_dropped so [STATS] can show *which* branch dropped. */
enum fwd_drop_reason {
    FWD_DR_LOCAL_NC_SET_WAN_L2,
    FWD_DR_LOCAL_NC_WAN_TX,
    FWD_DR_WAN_NC_BAD_IP,
    FWD_DR_WAN_NC_NO_LOCAL,
    FWD_DR_WAN_NC_ARP_MISS,
    FWD_DR_WAN_NC_LOCAL_TX,
    FWD_DR_LOCAL_L2_SET_WAN_L2,
    FWD_DR_LOCAL_L2_BYPASS_TX,
    FWD_DR_LOCAL_L2_ENCRYPT_FAIL,
    FWD_DR_LOCAL_L2_WAN_TX,
    FWD_DR_L3L4_RING_FULL,
    FWD_DR_WAN_L2_DECRYPT,
    FWD_DR_WAN_L2_BAD_IP,
    FWD_DR_WAN_L2_NO_LOCAL,
    FWD_DR_WAN_L2_ARP_MISS,
    FWD_DR_WAN_L2_LOCAL_TX,
    FWD_DR_WAN_L3L4_L2_DECRYPT,
    FWD_DR_WAN_L3L4_L3_DECRYPT,
    FWD_DR_WAN_L3L4_L4_DECRYPT,
    FWD_DR_WAN_L3L4_BAD_IP,
    FWD_DR_WAN_L3L4_NO_LOCAL,
    FWD_DR_WAN_L3L4_ARP_MISS,
    FWD_DR_WAN_L3L4_LOCAL_TX,
    FWD_DR_WORKER_BYPASS_SET_WAN_L2,
    FWD_DR_WORKER_BYPASS_TX,
    FWD_DR_WORKER_NOC_SET_WAN_L2,
    FWD_DR_WORKER_NOC_TX,
    FWD_DR_WORKER_ENC_SET_WAN_L2,
    FWD_DR_WORKER_ENC_FAIL,
    FWD_DR_WORKER_ENC_TX,
    FWD_DROP_REASON_COUNT
};

#define FWD_DROP(fwd, dr)                                                                          \
    do {                                                                                           \
        __sync_fetch_and_add(&(fwd)->total_dropped, 1);                                           \
        __sync_fetch_and_add(&(fwd)->dropped_by_reason[(dr)], 1);                                 \
    } while (0)

#define FWD_DROP_BAD_IP(fwd, dr)                                                                   \
    do {                                                                                           \
        FWD_DROP((fwd), (dr));                                                                     \
        __sync_fetch_and_add(&(fwd)->dropped_bad_ip, 1);                                           \
    } while (0)

#define FWD_DROP_NO_LOCAL(fwd, dr)                                                                 \
    do {                                                                                           \
        FWD_DROP((fwd), (dr));                                                                     \
        __sync_fetch_and_add(&(fwd)->dropped_no_local_match, 1);                                   \
    } while (0)

#define FWD_DROP_LOCAL_TX(fwd, dr)                                                                 \
    do {                                                                                           \
        FWD_DROP((fwd), (dr));                                                                     \
        __sync_fetch_and_add(&(fwd)->dropped_local_tx_fail, 1);                                    \
    } while (0)

static inline const char *fwd_drop_reason_tag(enum fwd_drop_reason r) {
    static const char *const tags[FWD_DROP_REASON_COUNT] = {
        "local_nc_set_wan_l2",
        "local_nc_wan_tx",
        "wan_nc_bad_ip",
        "wan_nc_no_local",
        "wan_nc_arp_miss",
        "wan_nc_local_tx",
        "local_l2_set_wan_l2",
        "local_l2_bypass_tx",
        "local_l2_encrypt_fail",
        "local_l2_wan_tx",
        "l3l4_ring_full",
        "wan_l2_decrypt",
        "wan_l2_bad_ip",
        "wan_l2_no_local",
        "wan_l2_arp_miss",
        "wan_l2_local_tx",
        "wan_l3l4_l2_decrypt",
        "wan_l3l4_l3_decrypt",
        "wan_l3l4_l4_decrypt",
        "wan_l3l4_bad_ip",
        "wan_l3l4_no_local",
        "wan_l3l4_arp_miss",
        "wan_l3l4_local_tx",
        "worker_bypass_set_wan_l2",
        "worker_bypass_tx",
        "worker_noc_set_wan_l2",
        "worker_noc_tx",
        "worker_enc_set_wan_l2",
        "worker_enc_fail",
        "worker_enc_tx",
    };
    if ((unsigned)r >= FWD_DROP_REASON_COUNT)
        return "?";
    return tags[r];
}

struct forwarder {
    struct xsk_interface locals[MAX_INTERFACES];
    int local_count;

    struct xsk_interface wans[MAX_INTERFACES];
    int wan_count;

    struct app_config *cfg;

    int current_wan;
    uint64_t wan_bytes[MAX_INTERFACES];

    uint64_t local_to_wan;
    uint64_t wan_to_local;
    uint64_t total_dropped;


    uint64_t dropped_bad_ip;
    uint64_t dropped_no_local_match;
    uint64_t dropped_local_tx_fail;
#define FORWARDER_MAX_LOCAL_QUEUES 16
    uint64_t dropped_local_tx_fail_by_queue[FORWARDER_MAX_LOCAL_QUEUES];

    uint64_t dropped_by_reason[FWD_DROP_REASON_COUNT];
};

int forwarder_init(struct forwarder *fwd, struct app_config *cfg);
void forwarder_cleanup(struct forwarder *fwd);
void forwarder_run(struct forwarder *fwd);
void forwarder_print_stats(struct forwarder *fwd);

#endif
