#include "../inc/interface.h"
#include <poll.h>
#include <net/ethernet.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>
#include <linux/if.h>

static struct bpf_object *bpf_obj = NULL;
static int xsk_map_fd = -1;
static int config_map_fd = -1;

// Get number of RX queues from NIC
static int get_rx_queue_count(const char *ifname)
{
    struct ethtool_channels channels = {0};
    struct ifreq ifr = {0};
    int fd, ret;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return 1;

    strncpy(ifr.ifr_name, ifname, IF_NAMESIZE - 1);
    channels.cmd = ETHTOOL_GCHANNELS;
    ifr.ifr_data = (void *)&channels;

    ret = ioctl(fd, SIOCETHTOOL, &ifr);
    close(fd);

    if (ret < 0)
        return 1;

    int count = channels.combined_count;
    if (count == 0)
        count = channels.rx_count;
    if (count == 0)
        count = 1;

    return count > MAX_QUEUES ? MAX_QUEUES : count;
}

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

    // Get number of RX queues
    int queue_count = get_rx_queue_count(local_cfg->ifname);
    printf("[LOCAL] %s has %d RX queues\n", local_cfg->ifname, queue_count);

    ret = posix_memalign(&iface->bufs, getpagesize(), UMEM_SIZE);
    if (ret || !iface->bufs) {
        perror("posix_memalign");
        return -1;
    }

    mlock(iface->bufs, UMEM_SIZE);

    // Create shared UMEM - use first queue's fill/comp rings
    ret = xsk_umem__create(&iface->umem, iface->bufs, UMEM_SIZE,
                           &iface->queues[0].fill, &iface->queues[0].comp, NULL);
    if (ret) {
        perror("xsk_umem__create");
        free(iface->bufs);
        return -1;
    }

    // Load XDP program (only once)
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

    // Create socket for each queue
    for (int q = 0; q < queue_count; q++) {
        struct xsk_queue *queue = &iface->queues[q];

        if (q == 0) {
            // First queue uses UMEM directly
            ret = xsk_socket__create(&queue->xsk, iface->ifname, q, iface->umem,
                                     &queue->rx, &queue->tx, &sock_cfg);
        } else {
            // Other queues share UMEM
            ret = xsk_socket__create_shared(&queue->xsk, iface->ifname, q, iface->umem,
                                            &queue->rx, &queue->tx,
                                            &queue->fill, &queue->comp, &sock_cfg);
        }

        if (ret) {
            fprintf(stderr, "xsk_socket__create queue %d failed: %d\n", q, ret);
            for (int j = 0; j < q; j++)
                xsk_socket__delete(iface->queues[j].xsk);
            bpf_set_link_xdp_fd(iface->ifindex, -1, XDP_FLAGS_SKB_MODE);
            goto err;
        }

        // Register socket in xsks_map
        int fd = xsk_socket__fd(queue->xsk);
        ret = bpf_map_update_elem(xsk_map_fd, &q, &fd, 0);
        if (ret) {
            fprintf(stderr, "bpf_map_update_elem queue %d failed\n", q);
            for (int j = 0; j <= q; j++)
                xsk_socket__delete(iface->queues[j].xsk);
            bpf_set_link_xdp_fd(iface->ifindex, -1, XDP_FLAGS_SKB_MODE);
            goto err;
        }

        printf("[LOCAL] Queue %d registered in xsks_map\n", q);
        iface->queue_count++;
    }

    // Fill the fill queue (queue 0 owns it)
    uint32_t frames_per_queue = RING_SIZE;
    ret = xsk_ring_prod__reserve(&iface->queues[0].fill, frames_per_queue, &idx);
    for (uint32_t i = 0; i < frames_per_queue; i++)
        *xsk_ring_prod__fill_addr(&iface->queues[0].fill, idx++) = i * FRAME_SIZE;
    xsk_ring_prod__submit(&iface->queues[0].fill, frames_per_queue);

    printf("[LOCAL] %s ready with %d queues\n", iface->ifname, iface->queue_count);
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
    // Clean up multi-queue sockets (LOCAL)
    for (int q = 0; q < iface->queue_count; q++) {
        if (iface->queues[q].xsk)
            xsk_socket__delete(iface->queues[q].xsk);
    }

    // Clean up single socket (WAN)
    if (iface->xsk)
        xsk_socket__delete(iface->xsk);

    if (iface->umem)
        xsk_umem__delete(iface->umem);

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
    int total_rcvd = 0;

    // Guard against WAN interface (no queues)
    if (iface->queue_count == 0)
        return 0;

    // Multi-queue: check all queues round-robin
    for (int i = 0; i < iface->queue_count && total_rcvd < max_pkts; i++) {
        int q = (iface->current_queue + i) % iface->queue_count;
        struct xsk_queue *queue = &iface->queues[q];

        int rcvd = xsk_ring_cons__peek(&queue->rx, max_pkts - total_rcvd, &idx_rx);
        if (rcvd == 0)
            continue;

        for (int j = 0; j < rcvd; j++) {
            const struct xdp_desc *desc = xsk_ring_cons__rx_desc(&queue->rx, idx_rx + j);
            addrs[total_rcvd + j] = desc->addr;
            pkt_ptrs[total_rcvd + j] = (uint8_t *)iface->bufs + desc->addr;
            pkt_lens[total_rcvd + j] = desc->len;
        }

        xsk_ring_cons__release(&queue->rx, rcvd);
        total_rcvd += rcvd;
    }

    // Update round-robin index
    iface->current_queue = (iface->current_queue + 1) % iface->queue_count;

    if (total_rcvd == 0) {
        // Poll all queues briefly
        struct pollfd fds[MAX_QUEUES];
        for (int q = 0; q < iface->queue_count; q++) {
            fds[q].fd = xsk_socket__fd(iface->queues[q].xsk);
            fds[q].events = POLLIN;
        }
        if (poll(fds, iface->queue_count, 1) <= 0)
            return 0;

        // Retry receive after poll
        for (int q = 0; q < iface->queue_count && total_rcvd < max_pkts; q++) {
            if (!(fds[q].revents & POLLIN))
                continue;

            struct xsk_queue *queue = &iface->queues[q];
            int rcvd = xsk_ring_cons__peek(&queue->rx, max_pkts - total_rcvd, &idx_rx);
            if (rcvd == 0)
                continue;

            for (int j = 0; j < rcvd; j++) {
                const struct xdp_desc *desc = xsk_ring_cons__rx_desc(&queue->rx, idx_rx + j);
                addrs[total_rcvd + j] = desc->addr;
                pkt_ptrs[total_rcvd + j] = (uint8_t *)iface->bufs + desc->addr;
                pkt_lens[total_rcvd + j] = desc->len;
            }

            xsk_ring_cons__release(&queue->rx, rcvd);
            total_rcvd += rcvd;
        }
    }

    iface->rx_packets += total_rcvd;
    return total_rcvd;
}

void interface_recv_release(struct xsk_interface *iface,
                            uint64_t *addrs, int count)
{
    uint32_t idx_fill = 0;

    // Guard against WAN interface (no queues)
    if (iface->queue_count == 0)
        return;

    // Use queue 0's fill ring (shared UMEM owner)
    struct xsk_ring_prod *fill = &iface->queues[0].fill;
    struct xsk_ring_cons *comp = &iface->queues[0].comp;

    int ret = xsk_ring_prod__reserve(fill, count, &idx_fill);
    if (ret != count) {
        // Try releasing some completions first
        uint32_t comp_idx;
        xsk_ring_cons__peek(comp, BATCH_SIZE, &comp_idx);
        xsk_ring_cons__release(comp, BATCH_SIZE);

        ret = xsk_ring_prod__reserve(fill, count, &idx_fill);
        if (ret != count)
            return;
    }

    for (int i = 0; i < count; i++)
        *xsk_ring_prod__fill_addr(fill, idx_fill + i) = addrs[i];

    xsk_ring_prod__submit(fill, count);
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
