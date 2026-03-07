#ifndef INTERFACE_H
#define INTERFACE_H

#include "common.h"
#include "config.h"
#include <pthread.h>

struct xsk_queue {
    struct xsk_socket *xsk;
    struct xsk_umem *umem;
    void *bufs;
    struct xsk_ring_prod fill;
    struct xsk_ring_cons comp;
    struct xsk_ring_prod tx;
    struct xsk_ring_cons rx;

    uint64_t tx_slot;
    int pending_tx_count;           
    pthread_mutex_t tx_lock;
};

struct xsk_interface {
    struct xsk_umem *umem;
    void *bufs;
    size_t umem_size;
    uint32_t ring_size;
    uint32_t frame_size;
    uint32_t batch_size;

    struct xsk_queue queues[MAX_QUEUES];
    int queue_count;
    int current_queue;

    struct xsk_socket *xsk;
    struct xsk_ring_prod fill;
    struct xsk_ring_cons comp;
    struct xsk_ring_prod tx;
    struct xsk_ring_cons rx;

    int ifindex;
    char ifname[IF_NAMESIZE];

    uint8_t src_mac[MAC_LEN];
    uint8_t dst_mac[MAC_LEN];

    uint64_t tx_slot;

    pthread_mutex_t tx_lock;
    int pending_tx_count;

    uint64_t rx_packets;
    uint64_t tx_packets;
    uint64_t rx_bytes;
    uint64_t tx_bytes;
};

// --- NHÓM KHỞI TẠO VÀ GIẢI PHÓNG ---

// Khởi tạo LOCAL: Tạo UMEM, attach XDP program, tạo AF_XDP socket
int interface_init_local(struct xsk_interface *iface,
                         const struct local_config *local_cfg,
                         const char *bpf_file);

// Khởi tạo WAN (basic)
int interface_init_wan(struct xsk_interface *iface,
                       const struct wan_config *wan_cfg);

// Khởi tạo WAN + local BPF program với fake_ethertype filter
int interface_init_wan_rx(struct xsk_interface *iface,
                          const struct wan_config *wan_cfg,
                          const char *bpf_file,
                          uint16_t fake_ethertype_ipv4,
                          uint16_t fake_ethertype_ipv6);

// Giải phóng UMEM, đóng socket, detach XDP
void interface_cleanup(struct xsk_interface *iface);


// --- NHÓM NHẬN GÓI TIN (RECEIVE) ---

// Nhận batch packet
int interface_recv(struct xsk_interface *iface,
                   void **pkt_ptrs, uint32_t *pkt_lens,
                   uint64_t *addrs, int max_pkts);

// Trả frame về fill ring sau khi xử lý xong
void interface_recv_release(struct xsk_interface *iface,
                            uint64_t *addrs, int count);

// Nhận batch từ một queue cụ thể 
int interface_recv_single_queue(struct xsk_interface *iface, int queue_idx,
                                void **pkt_ptrs, uint32_t *pkt_lens,
                                uint64_t *addrs, int max_pkts);

// Trả frame cho queue cụ thể                               
void interface_recv_release_single_queue(struct xsk_interface *iface,
                                          int queue_idx,
                                          uint64_t *addrs, int count);


// --- NHÓM GỬI GÓI TIN (SEND) ---

// Gửi ngay 1 gói tin
int interface_send(struct xsk_interface *iface,
                   void *pkt_data, uint32_t pkt_len);

int interface_send_to_local(struct xsk_interface *iface,
                            const struct local_config *local_cfg,
                            void *pkt_data, uint32_t pkt_len);

// Gửi batch (Default Queue)
int interface_send_batch(struct xsk_interface *iface,
                         void *pkt_data, uint32_t pkt_len);

int interface_send_to_local_batch(struct xsk_interface *iface,
                                  const struct local_config *local_cfg,
                                  void *pkt_data, uint32_t pkt_len,
                                  int tx_queue);

// Gửi batch (Specific Queue)
int interface_send_batch_queue(struct xsk_interface *iface, int queue_idx,
                                void *pkt_data, uint32_t pkt_len);

int interface_send_to_local_batch_queue(struct xsk_interface *iface,
                                         int queue_idx,
                                         const struct local_config *local_cfg,
                                         void *pkt_data, uint32_t pkt_len);


// --- NHÓM ĐẨY DỮ LIỆU (FLUSH) ---

void interface_send_flush(struct xsk_interface *iface);

void interface_send_to_local_flush(struct xsk_interface *iface, int tx_queue);

void interface_send_flush_queue(struct xsk_interface *iface, int queue_idx);

void interface_send_to_local_flush_queue(struct xsk_interface *iface,
                                          int queue_idx);


// --- NHÓM QUẢN LÝ HỆ THỐNG VÀ THỐNG KÊ ---

void interface_print_stats(struct xsk_interface *iface);

// Set số hardware queue cho NIC (ethtool -L)
int interface_set_queue_count(const char *ifname, int desired_count);

// Đọc số queue hiện tại của NIC
int interface_get_queue_count(const char *ifname);

#endif
