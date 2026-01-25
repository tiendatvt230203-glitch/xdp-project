#include "../inc/interface.h"
#include <poll.h>
#include <net/ethernet.h>
#include <unistd.h>
#include <errno.h>

static struct bpf_object *bpf_obj = NULL;
static int xsk_map_fd = -1;
static int config_map_fd = -1;

int interface_init_local(struct xsk_interface *iface,
                         const struct local_config *local_cfg,
                         const char *bpf_file)
{
    int ret;
    struct bpf_program *prog;
    struct bpf_map *map;
    int prog_fd;
    uint32_t idx;

    memset(iface, 0, sizeof(*iface));
    iface->ifindex = if_nametoindex(local_cfg->ifname);
    strncpy(iface->ifname, local_cfg->ifname, IF_NAMESIZE - 1);
    memcpy(iface->src_mac, local_cfg->src_mac, MAC_LEN);
    memcpy(iface->dst_mac, local_cfg->dst_mac, MAC_LEN);

    if (iface->ifindex == 0) {
        fprintf(stderr, "Interface %s not found\n", local_cfg->ifname);
        return -1;
    }

    ret = posix_memalign(&iface->bufs, getpagesize(), UMEM_SIZE);
    if (ret || !iface->bufs) {
        perror("posix_memalign");
        return -1;
    }

    // Lock memory to prevent swapping
    mlock(iface->bufs, UMEM_SIZE);

    ret = xsk_umem__create(&iface->umem, iface->bufs, UMEM_SIZE,
                           &iface->fill, &iface->comp, NULL);
    if (ret) {
        perror("xsk_umem__create");
        free(iface->bufs);
        return -1;
    }

    if (!bpf_obj) {
        if (access(bpf_file, F_OK) != 0) {
            fprintf(stderr, "XDP object not found: %s\n", bpf_file);
            goto err;
        }

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
            fprintf(stderr, "XDP program not found\n");
            goto err;
        }
        prog_fd = bpf_program__fd(prog);

        map = bpf_object__find_map_by_name(bpf_obj, "xsks_map");
        if (!map) {
            fprintf(stderr, "xsks_map not found\n");
            goto err;
        }
        xsk_map_fd = bpf_map__fd(map);

        map = bpf_object__find_map_by_name(bpf_obj, "config_map");
        if (map) {
            config_map_fd = bpf_map__fd(map);
            int key0 = 0, key1 = 1;
            bpf_map_update_elem(config_map_fd, &key0, &local_cfg->network, 0);
            bpf_map_update_elem(config_map_fd, &key1, &local_cfg->netmask, 0);
        }

        ret = bpf_set_link_xdp_fd(iface->ifindex, prog_fd, XDP_FLAGS_SKB_MODE);
        if (ret) {
            fprintf(stderr, "bpf_set_link_xdp_fd failed: %d\n", ret);
            goto err;
        }
    }

    struct xsk_socket_config sock_cfg = {
        .rx_size = RING_SIZE,
        .tx_size = RING_SIZE,
        .libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,
        .bind_flags = XDP_COPY
    };

    ret = xsk_socket__create(&iface->xsk, iface->ifname, 0, iface->umem,
                             &iface->rx, &iface->tx, &sock_cfg);
    if (ret) {
        perror("xsk_socket__create LOCAL");
        bpf_set_link_xdp_fd(iface->ifindex, -1, XDP_FLAGS_SKB_MODE);
        goto err;
    }

    int key = 0;
    int fd = xsk_socket__fd(iface->xsk);
    ret = bpf_map_update_elem(xsk_map_fd, &key, &fd, 0);
    if (ret) {
        perror("bpf_map_update_elem xsks_map");
        xsk_socket__delete(iface->xsk);
        bpf_set_link_xdp_fd(iface->ifindex, -1, XDP_FLAGS_SKB_MODE);
        goto err;
    }

    // Fill the entire fill queue
    ret = xsk_ring_prod__reserve(&iface->fill, RING_SIZE, &idx);
    for (uint32_t i = 0; i < RING_SIZE; i++)
        *xsk_ring_prod__fill_addr(&iface->fill, idx++) = i * FRAME_SIZE;
    xsk_ring_prod__submit(&iface->fill, RING_SIZE);

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

int interface_init_wan(struct xsk_interface *iface,
                       const struct wan_config *wan_cfg)
{
    int ret;
    uint32_t idx;

    memset(iface, 0, sizeof(*iface));
    iface->ifindex = if_nametoindex(wan_cfg->ifname);
    strncpy(iface->ifname, wan_cfg->ifname, IF_NAMESIZE - 1);
    memcpy(iface->src_mac, wan_cfg->src_mac, MAC_LEN);
    memcpy(iface->dst_mac, wan_cfg->dst_mac, MAC_LEN);

    if (iface->ifindex == 0) {
        fprintf(stderr, "Interface %s not found\n", wan_cfg->ifname);
        return -1;
    }

    ret = posix_memalign(&iface->bufs, getpagesize(), UMEM_SIZE);
    if (ret || !iface->bufs) {
        perror("posix_memalign");
        return -1;
    }

    mlock(iface->bufs, UMEM_SIZE);

    ret = xsk_umem__create(&iface->umem, iface->bufs, UMEM_SIZE,
                           &iface->fill, &iface->comp, NULL);
    if (ret) {
        perror("xsk_umem__create");
        free(iface->bufs);
        return -1;
    }

    struct xsk_socket_config sock_cfg = {
        .rx_size = RING_SIZE,
        .tx_size = RING_SIZE,
        .libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,
        .bind_flags = XDP_COPY
    };

    ret = xsk_socket__create(&iface->xsk, iface->ifname, 0, iface->umem,
                             &iface->rx, &iface->tx, &sock_cfg);
    if (ret) {
        perror("xsk_socket__create WAN");
        xsk_umem__delete(iface->umem);
        free(iface->bufs);
        return -1;
    }

    // Fill queue for TX completion recycling
    ret = xsk_ring_prod__reserve(&iface->fill, RING_SIZE, &idx);
    for (uint32_t i = 0; i < RING_SIZE; i++)
        *xsk_ring_prod__fill_addr(&iface->fill, idx++) = i * FRAME_SIZE;
    xsk_ring_prod__submit(&iface->fill, RING_SIZE);

    // Track next TX slot
    iface->tx_slot = 0;

    return 0;
}

void interface_cleanup(struct xsk_interface *iface)
{
    if (iface->xsk) xsk_socket__delete(iface->xsk);
    if (iface->umem) xsk_umem__delete(iface->umem);
    if (iface->bufs) {
        munlock(iface->bufs, UMEM_SIZE);
        free(iface->bufs);
    }

    if (iface->ifindex && bpf_obj)
        bpf_set_link_xdp_fd(iface->ifindex, -1, XDP_FLAGS_SKB_MODE);

    memset(iface, 0, sizeof(*iface));
}

int interface_recv(struct xsk_interface *iface,
                   void **pkt_ptrs, uint32_t *pkt_lens,
                   uint64_t *addrs, int max_pkts)
{
    uint32_t idx_rx = 0;

    // Non-blocking check first
    int rcvd = xsk_ring_cons__peek(&iface->rx, max_pkts, &idx_rx);
    if (rcvd == 0) {
        // Brief poll if nothing available
        struct pollfd fds = {
            .fd = xsk_socket__fd(iface->xsk),
            .events = POLLIN
        };
        if (poll(&fds, 1, 1) <= 0)
            return 0;
        rcvd = xsk_ring_cons__peek(&iface->rx, max_pkts, &idx_rx);
        if (rcvd == 0)
            return 0;
    }

    for (int i = 0; i < rcvd; i++) {
        const struct xdp_desc *desc = xsk_ring_cons__rx_desc(&iface->rx, idx_rx + i);
        addrs[i] = desc->addr;
        pkt_ptrs[i] = (uint8_t *)iface->bufs + desc->addr;
        pkt_lens[i] = desc->len;
    }

    xsk_ring_cons__release(&iface->rx, rcvd);
    iface->rx_packets += rcvd;

    return rcvd;
}

void interface_recv_release(struct xsk_interface *iface,
                            uint64_t *addrs, int count)
{
    uint32_t idx_fill = 0;

    int ret = xsk_ring_prod__reserve(&iface->fill, count, &idx_fill);
    if (ret != count) {
        // Try releasing some completions first
        uint32_t comp_idx;
        xsk_ring_cons__peek(&iface->comp, BATCH_SIZE, &comp_idx);
        xsk_ring_cons__release(&iface->comp, BATCH_SIZE);

        ret = xsk_ring_prod__reserve(&iface->fill, count, &idx_fill);
        if (ret != count)
            return;
    }

    for (int i = 0; i < count; i++)
        *xsk_ring_prod__fill_addr(&iface->fill, idx_fill + i) = addrs[i];

    xsk_ring_prod__submit(&iface->fill, count);
}

int interface_send(struct xsk_interface *iface,
                   void *pkt_data, uint32_t pkt_len)
{
    uint32_t idx;
    struct ether_header *eth;

    // Release completed TX buffers
    uint32_t comp_idx;
    int completed = xsk_ring_cons__peek(&iface->comp, BATCH_SIZE, &comp_idx);
    if (completed > 0)
        xsk_ring_cons__release(&iface->comp, completed);

    int reserved = xsk_ring_prod__reserve(&iface->tx, 1, &idx);
    if (reserved < 1) {
        // Force kick and retry
        sendto(xsk_socket__fd(iface->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
        completed = xsk_ring_cons__peek(&iface->comp, BATCH_SIZE, &comp_idx);
        if (completed > 0)
            xsk_ring_cons__release(&iface->comp, completed);
        reserved = xsk_ring_prod__reserve(&iface->tx, 1, &idx);
        if (reserved < 1)
            return -1;
    }

    // Use rotating TX buffer slots
    uint64_t addr = (iface->tx_slot % (FRAME_COUNT / 2)) * FRAME_SIZE;
    iface->tx_slot++;

    void *tx_buf = (uint8_t *)iface->bufs + addr;
    memcpy(tx_buf, pkt_data, pkt_len);

    // Rewrite MAC
    eth = (struct ether_header *)tx_buf;
    memcpy(eth->ether_dhost, iface->dst_mac, MAC_LEN);
    memcpy(eth->ether_shost, iface->src_mac, MAC_LEN);

    xsk_ring_prod__tx_desc(&iface->tx, idx)->addr = addr;
    xsk_ring_prod__tx_desc(&iface->tx, idx)->len = pkt_len;
    xsk_ring_prod__submit(&iface->tx, 1);

    sendto(xsk_socket__fd(iface->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);

    iface->tx_packets++;
    iface->tx_bytes += pkt_len;

    return 0;
}

void interface_print_stats(struct xsk_interface *iface)
{
    printf("%s: RX=%lu TX=%lu\n", iface->ifname, iface->rx_packets, iface->tx_packets);
}
