#ifndef INTERFACE_H
#define INTERFACE_H

#include "common.h"
#include "config.h"
#include <pthread.h>

// Per-queue socket state - each queue has its own UMEM
struct xsk_queue {
    struct xsk_socket *xsk;
    struct xsk_umem *umem;       // Separate UMEM per queue
    void *bufs;                   // Separate buffer per queue
    struct xsk_ring_prod fill;
    struct xsk_ring_cons comp;
    struct xsk_ring_prod tx;
    struct xsk_ring_cons rx;

    // Per-queue TX state (for parallel TX without mutex)
    uint64_t tx_slot;
    int pending_tx_count;
};

// Interface state - supports multiple queues
struct xsk_interface {
    // Shared UMEM across all queues
    struct xsk_umem *umem;
    void *bufs;
    size_t umem_size;

    // Per-queue sockets (for multi-queue RX)
    struct xsk_queue queues[MAX_QUEUES];
    int queue_count;
    int current_queue;              // Round-robin for recv

    // Single socket pointer for WAN (TX only, queue 0)
    struct xsk_socket *xsk;
    struct xsk_ring_prod fill;
    struct xsk_ring_cons comp;
    struct xsk_ring_prod tx;
    struct xsk_ring_cons rx;

    // Interface info
    int ifindex;
    char ifname[IF_NAMESIZE];

    // MAC addresses for rewriting
    uint8_t src_mac[MAC_LEN];      // Source MAC (this interface)
    uint8_t dst_mac[MAC_LEN];      // Destination MAC (remote interface)

    // TX slot tracking (atomic for thread safety)
    uint64_t tx_slot;

    // TX mutex for thread-safe batch TX
    pthread_mutex_t tx_lock;
    int pending_tx_count;           // Pending packets in TX batch

    // Stats (use atomic operations)
    uint64_t rx_packets;
    uint64_t tx_packets;
    uint64_t rx_bytes;
    uint64_t tx_bytes;
};

// Initialize LOCAL interface (RX with XDP redirect)
int interface_init_local(struct xsk_interface *iface,
                         const struct local_config *local_cfg,
                         const char *bpf_file);

// Initialize WAN interface (TX only for forwarding)
int interface_init_wan(struct xsk_interface *iface,
                       const struct wan_config *wan_cfg);

// Initialize WAN interface with RX (for receiving return traffic)
int interface_init_wan_rx(struct xsk_interface *iface,
                          const struct wan_config *wan_cfg,
                          const char *bpf_file);

// Cleanup interface
void interface_cleanup(struct xsk_interface *iface);

// Receive packets from LOCAL interface
int interface_recv(struct xsk_interface *iface,
                   void **pkt_ptrs, uint32_t *pkt_lens,
                   uint64_t *addrs, int max_pkts);

// Release RX buffers back to fill queue
void interface_recv_release(struct xsk_interface *iface,
                            uint64_t *addrs, int count);

// Send packet through WAN interface (rewrites MAC) - single packet
int interface_send(struct xsk_interface *iface,
                   void *pkt_data, uint32_t pkt_len);

// Send packet to LOCAL interface (rewrites MAC from local_config) - single packet
int interface_send_to_local(struct xsk_interface *iface,
                            const struct local_config *local_cfg,
                            void *pkt_data, uint32_t pkt_len);

// ============== BATCH TX (High Performance) ==============
// Add packet to TX batch (no kick yet)
int interface_send_batch(struct xsk_interface *iface,
                         void *pkt_data, uint32_t pkt_len);

// Flush all pending TX packets (kick once)
void interface_send_flush(struct xsk_interface *iface);

// Add packet to LOCAL TX batch (uses specific queue for parallel TX)
int interface_send_to_local_batch(struct xsk_interface *iface,
                                  const struct local_config *local_cfg,
                                  void *pkt_data, uint32_t pkt_len,
                                  int tx_queue);

// Flush LOCAL TX (specific queue)
void interface_send_to_local_flush(struct xsk_interface *iface, int tx_queue);

// Print interface stats
void interface_print_stats(struct xsk_interface *iface);

#endif
