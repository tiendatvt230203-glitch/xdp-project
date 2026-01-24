#include "../inc/interface.h"
#include <poll.h>
#include <net/ethernet.h>

static struct bpf_object *bpf_obj = NULL;
static int xsk_map_fd = -1;
static int config_map_fd = -1;

// Initialize LOCAL interface with XDP program
int interface_init_local(struct xsk_interface *iface,
                         const struct iface_config *cfg,
                         const char *bpf_file)
{
    int ret;
    struct bpf_program *prog;
    struct bpf_map *map;
    int prog_fd;
    uint32_t idx;

    memset(iface, 0, sizeof(*iface));
    iface->type = IFACE_TYPE_LOCAL;
    iface->ifindex = if_nametoindex(cfg->ifname);
    strncpy(iface->ifname, cfg->ifname, IF_NAMESIZE - 1);
    memcpy(iface->mac, cfg->mac, MAC_LEN);

    if (iface->ifindex == 0) {
        fprintf(stderr, "Interface %s not found\n", cfg->ifname);
        return -1;
    }

    // Allocate UMEM buffer
    ret = posix_memalign(&iface->bufs, getpagesize(), UMEM_SIZE);
    if (ret || !iface->bufs) {
        perror("posix_memalign");
        return -1;
    }

    // Create UMEM with all 4 rings
    ret = xsk_umem__create(&iface->umem, iface->bufs, UMEM_SIZE,
                           &iface->fill, &iface->comp, NULL);
    if (ret) {
        perror("xsk_umem__create");
        free(iface->bufs);
        return -1;
    }

    // Load BPF object (only once)
    if (!bpf_obj) {
        bpf_obj = bpf_object__open_file(bpf_file, NULL);
        if (libbpf_get_error(bpf_obj)) {
            fprintf(stderr, "Failed to open %s\n", bpf_file);
            bpf_obj = NULL;
            goto err;
        }

        ret = bpf_object__load(bpf_obj);
        if (ret) {
            fprintf(stderr, "Failed to load BPF object\n");
            goto err;
        }

        prog = bpf_object__find_program_by_name(bpf_obj, "xdp_redirect_prog");
        if (!prog) {
            fprintf(stderr, "Program not found\n");
            goto err;
        }
        prog_fd = bpf_program__fd(prog);

        map = bpf_object__find_map_by_name(bpf_obj, "xsks_map");
        if (!map) {
            fprintf(stderr, "xsks_map not found\n");
            goto err;
        }
        xsk_map_fd = bpf_map__fd(map);

        // Get config_map for subnet filtering
        map = bpf_object__find_map_by_name(bpf_obj, "config_map");
        if (!map) {
            fprintf(stderr, "config_map not found\n");
            goto err;
        }
        config_map_fd = bpf_map__fd(map);

        // Load LOCAL subnet config into BPF map
        // Key 0: network address, Key 1: netmask
        int key0 = 0, key1 = 1;
        ret = bpf_map_update_elem(config_map_fd, &key0, &cfg->network, 0);
        if (ret) {
            perror("bpf_map_update_elem config network");
            goto err;
        }
        ret = bpf_map_update_elem(config_map_fd, &key1, &cfg->netmask, 0);
        if (ret) {
            perror("bpf_map_update_elem config netmask");
            goto err;
        }

        printf("[IFACE] Loaded subnet filter: network=0x%08x, mask=0x%08x\n",
               cfg->network, cfg->netmask);

        // Attach XDP program
        ret = bpf_set_link_xdp_fd(iface->ifindex, prog_fd, XDP_FLAGS_SKB_MODE);
        if (ret) {
            fprintf(stderr, "bpf_set_link_xdp_fd failed on %s\n", iface->ifname);
            goto err;
        }
    }

    // Socket config - LOCAL needs RX and TX rings
    struct xsk_socket_config sock_cfg = {
        .rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
        .tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS,
        .libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,
        .bind_flags = XDP_COPY
    };

    ret = xsk_socket__create(&iface->xsk, iface->ifname, 0, iface->umem,
                             &iface->rx, &iface->tx, &sock_cfg);
    if (ret) {
        perror("xsk_socket__create");
        bpf_set_link_xdp_fd(iface->ifindex, -1, XDP_FLAGS_SKB_MODE);
        goto err;
    }

    // Update xsks_map
    int key = 0;
    int fd = xsk_socket__fd(iface->xsk);
    ret = bpf_map_update_elem(xsk_map_fd, &key, &fd, 0);
    if (ret) {
        perror("bpf_map_update_elem");
        xsk_socket__delete(iface->xsk);
        bpf_set_link_xdp_fd(iface->ifindex, -1, XDP_FLAGS_SKB_MODE);
        goto err;
    }

    // Fill the fill queue
    ret = xsk_ring_prod__reserve(&iface->fill, XSK_RING_PROD__DEFAULT_NUM_DESCS, &idx);
    for (int i = 0; i < XSK_RING_PROD__DEFAULT_NUM_DESCS; i++)
        *xsk_ring_prod__fill_addr(&iface->fill, idx++) = i * FRAME_SIZE;
    xsk_ring_prod__submit(&iface->fill, XSK_RING_PROD__DEFAULT_NUM_DESCS);

    printf("[IFACE] LOCAL %s initialized (MAC: %02x:%02x:%02x:%02x:%02x:%02x)\n",
           iface->ifname,
           iface->mac[0], iface->mac[1], iface->mac[2],
           iface->mac[3], iface->mac[4], iface->mac[5]);

    return 0;

err:
    if (bpf_obj) {
        bpf_object__close(bpf_obj);
        bpf_obj = NULL;
    }
    if (iface->umem) xsk_umem__delete(iface->umem);
    if (iface->bufs) free(iface->bufs);
    return -1;
}

// Initialize WAN interface for TX
int interface_init_wan(struct xsk_interface *iface,
                       const struct iface_config *cfg,
                       const uint8_t *gateway_mac)
{
    int ret;

    memset(iface, 0, sizeof(*iface));
    iface->type = IFACE_TYPE_WAN;
    iface->ifindex = if_nametoindex(cfg->ifname);
    strncpy(iface->ifname, cfg->ifname, IF_NAMESIZE - 1);
    memcpy(iface->mac, cfg->mac, MAC_LEN);
    memcpy(iface->dst_mac, gateway_mac, MAC_LEN);

    if (iface->ifindex == 0) {
        fprintf(stderr, "Interface %s not found\n", cfg->ifname);
        return -1;
    }

    // Allocate UMEM buffer
    ret = posix_memalign(&iface->bufs, getpagesize(), UMEM_SIZE);
    if (ret || !iface->bufs) {
        perror("posix_memalign");
        return -1;
    }

    // Create UMEM with all 4 rings
    ret = xsk_umem__create(&iface->umem, iface->bufs, UMEM_SIZE,
                           &iface->fill, &iface->comp, NULL);
    if (ret) {
        perror("xsk_umem__create");
        free(iface->bufs);
        return -1;
    }

    // Socket config - WAN needs both RX and TX
    struct xsk_socket_config sock_cfg = {
        .rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
        .tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS,
        .libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,
        .bind_flags = XDP_COPY
    };

    ret = xsk_socket__create(&iface->xsk, iface->ifname, 0, iface->umem,
                             &iface->rx, &iface->tx, &sock_cfg);
    if (ret) {
        perror("xsk_socket__create");
        xsk_umem__delete(iface->umem);
        free(iface->bufs);
        return -1;
    }

    // Fill the fill queue for RX
    uint32_t idx;
    ret = xsk_ring_prod__reserve(&iface->fill, XSK_RING_PROD__DEFAULT_NUM_DESCS, &idx);
    for (int i = 0; i < XSK_RING_PROD__DEFAULT_NUM_DESCS; i++)
        *xsk_ring_prod__fill_addr(&iface->fill, idx++) = i * FRAME_SIZE;
    xsk_ring_prod__submit(&iface->fill, XSK_RING_PROD__DEFAULT_NUM_DESCS);

    printf("[IFACE] WAN %s initialized (SRC MAC: %02x:%02x:%02x:%02x:%02x:%02x, DST MAC: %02x:%02x:%02x:%02x:%02x:%02x)\n",
           iface->ifname,
           iface->mac[0], iface->mac[1], iface->mac[2],
           iface->mac[3], iface->mac[4], iface->mac[5],
           iface->dst_mac[0], iface->dst_mac[1], iface->dst_mac[2],
           iface->dst_mac[3], iface->dst_mac[4], iface->dst_mac[5]);

    return 0;
}

void interface_cleanup(struct xsk_interface *iface)
{
    if (iface->xsk) xsk_socket__delete(iface->xsk);

    // Detach XDP if LOCAL
    if (iface->type == IFACE_TYPE_LOCAL && iface->ifindex) {
        bpf_set_link_xdp_fd(iface->ifindex, -1, XDP_FLAGS_SKB_MODE);
    }

    if (iface->umem) xsk_umem__delete(iface->umem);
    if (iface->bufs) free(iface->bufs);

    printf("[IFACE] %s cleaned up\n", iface->ifname);
    memset(iface, 0, sizeof(*iface));
}

// Cleanup BPF objects (call once at end)
void interface_cleanup_bpf(void)
{
    if (bpf_obj) {
        bpf_object__close(bpf_obj);
        bpf_obj = NULL;
    }
}

// Receive packets from LOCAL interface
int interface_recv(struct xsk_interface *iface,
                   void **pkt_ptrs, uint32_t *pkt_lens,
                   uint64_t *addrs, int max_pkts)
{
    uint32_t idx_rx = 0;
    int rcvd;

    // Poll socket
    struct pollfd fds = {
        .fd = xsk_socket__fd(iface->xsk),
        .events = POLLIN
    };

    int ret = poll(&fds, 1, 100);
    if (ret <= 0)
        return 0;

    // Peek received packets
    rcvd = xsk_ring_cons__peek(&iface->rx, max_pkts, &idx_rx);
    if (rcvd == 0)
        return 0;

    // Get packet pointers and lengths
    for (int i = 0; i < rcvd; i++) {
        const struct xdp_desc *desc = xsk_ring_cons__rx_desc(&iface->rx, idx_rx + i);
        addrs[i] = desc->addr;
        pkt_ptrs[i] = (uint8_t *)iface->bufs + desc->addr;
        pkt_lens[i] = desc->len;
    }

    // Release RX ring entries
    xsk_ring_cons__release(&iface->rx, rcvd);

    iface->rx_packets += rcvd;

    return rcvd;
}

// Release RX buffers back to fill queue
void interface_recv_release(struct xsk_interface *iface,
                            uint64_t *addrs, int count)
{
    uint32_t idx_fill = 0;

    int ret = xsk_ring_prod__reserve(&iface->fill, count, &idx_fill);
    if (ret != count) {
        return;
    }

    for (int i = 0; i < count; i++) {
        *xsk_ring_prod__fill_addr(&iface->fill, idx_fill + i) = addrs[i];
    }

    xsk_ring_prod__submit(&iface->fill, count);
}

// Send packet through WAN interface with MAC rewrite
int interface_send(struct xsk_interface *iface,
                   void *pkt_data, uint32_t pkt_len)
{
    uint32_t idx;
    struct ether_header *eth;

    // Reserve TX slot
    if (xsk_ring_prod__reserve(&iface->tx, 1, &idx) < 1)
        return -1;

    // Copy packet to TX buffer
    memcpy(iface->bufs, pkt_data, pkt_len);

    // Rewrite MAC addresses
    eth = (struct ether_header *)iface->bufs;
    memcpy(eth->ether_dhost, iface->dst_mac, MAC_LEN);  // Gateway MAC
    memcpy(eth->ether_shost, iface->mac, MAC_LEN);      // WAN interface MAC

    // Set TX descriptor
    xsk_ring_prod__tx_desc(&iface->tx, idx)->addr = 0;
    xsk_ring_prod__tx_desc(&iface->tx, idx)->len = pkt_len;
    xsk_ring_prod__submit(&iface->tx, 1);

    // Trigger send
    sendto(xsk_socket__fd(iface->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);

    // Wait for completion
    uint32_t comp_idx;
    int retries = 1000;
    while (xsk_ring_cons__peek(&iface->comp, 1, &comp_idx) < 1) {
        if (--retries == 0)
            return -1;
        usleep(10);
    }
    xsk_ring_cons__release(&iface->comp, 1);

    iface->tx_packets++;
    iface->tx_bytes += pkt_len;

    return 0;
}

// Batch send packets
int interface_send_batch(struct xsk_interface *iface,
                         void **pkt_data, uint32_t *pkt_lens, int count)
{
    uint32_t idx;
    int sent = 0;

    int reserved = xsk_ring_prod__reserve(&iface->tx, count, &idx);
    if (reserved == 0)
        return 0;

    // Copy packets and set descriptors
    for (int i = 0; i < reserved; i++) {
        uint64_t addr = i * FRAME_SIZE;
        struct ether_header *eth;

        memcpy((uint8_t *)iface->bufs + addr, pkt_data[i], pkt_lens[i]);

        // Rewrite MAC
        eth = (struct ether_header *)((uint8_t *)iface->bufs + addr);
        memcpy(eth->ether_dhost, iface->dst_mac, MAC_LEN);
        memcpy(eth->ether_shost, iface->mac, MAC_LEN);

        xsk_ring_prod__tx_desc(&iface->tx, idx + i)->addr = addr;
        xsk_ring_prod__tx_desc(&iface->tx, idx + i)->len = pkt_lens[i];
    }
    xsk_ring_prod__submit(&iface->tx, reserved);

    sendto(xsk_socket__fd(iface->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);

    // Wait for completions
    uint32_t comp_idx;
    int completed = 0;
    int retries = 1000;
    while (completed < reserved && retries > 0) {
        int n = xsk_ring_cons__peek(&iface->comp, reserved - completed, &comp_idx);
        if (n > 0) {
            xsk_ring_cons__release(&iface->comp, n);
            completed += n;
        } else {
            usleep(10);
            retries--;
        }
    }

    iface->tx_packets += completed;

    return completed;
}

void interface_print_stats(struct xsk_interface *iface)
{
    printf("[STATS] %s (%s): RX=%lu TX=%lu\n",
           iface->ifname,
           iface->type == IFACE_TYPE_LOCAL ? "LOCAL" : "WAN",
           iface->rx_packets, iface->tx_packets);
}
