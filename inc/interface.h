#ifndef INTERFACE_H
#define INTERFACE_H

#include "common.h"
#include "config.h"

// Interface state - each interface has its own complete ring set
struct xsk_interface {
    // Socket and UMEM
    struct xsk_socket *xsk;
    struct xsk_umem *umem;
    void *bufs;

    // All 4 rings - each interface has its own
    struct xsk_ring_prod fill;     // Fill ring (producer)
    struct xsk_ring_cons comp;     // Completion ring (consumer)
    struct xsk_ring_prod tx;       // TX ring (producer)
    struct xsk_ring_cons rx;       // RX ring (consumer)

    // Interface info
    int ifindex;
    char ifname[IF_NAMESIZE];
    int type;                      // IFACE_TYPE_LOCAL or IFACE_TYPE_WAN
    uint8_t mac[MAC_LEN];          // Interface MAC
    uint8_t dst_mac[MAC_LEN];      // Destination MAC (for WAN: gateway MAC)

    // Stats
    uint64_t rx_packets;
    uint64_t tx_packets;
    uint64_t rx_bytes;
    uint64_t tx_bytes;
};

// Initialize LOCAL interface (RX with XDP redirect)
int interface_init_local(struct xsk_interface *iface,
                         const struct iface_config *cfg,
                         const char *bpf_file);

// Initialize WAN interface (TX for forwarding)
int interface_init_wan(struct xsk_interface *iface,
                       const struct iface_config *cfg,
                       const uint8_t *gateway_mac);

// Cleanup interface
void interface_cleanup(struct xsk_interface *iface);

// Receive packets from interface (for LOCAL)
// Returns number of packets received
// Packet pointers and lengths are stored in pkt_ptrs and pkt_lens
int interface_recv(struct xsk_interface *iface,
                   void **pkt_ptrs, uint32_t *pkt_lens,
                   uint64_t *addrs, int max_pkts);

// Release RX buffers back to fill queue
void interface_recv_release(struct xsk_interface *iface,
                            uint64_t *addrs, int count);

// Send packet through interface (for WAN)
// Automatically rewrites MAC addresses
int interface_send(struct xsk_interface *iface,
                   void *pkt_data, uint32_t pkt_len);

// Batch send packets
int interface_send_batch(struct xsk_interface *iface,
                         void **pkt_data, uint32_t *pkt_lens, int count);

// Print interface stats
void interface_print_stats(struct xsk_interface *iface);

#endif
