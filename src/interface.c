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

    // Load XDP program FIRST (before creating sockets)
    if (!bpf_obj) {
        // Detach any existing XDP
        bpf_set_link_xdp_fd(iface->ifindex, -1, XDP_FLAGS_SKB_MODE);

        if (access(bpf_file, F_OK) != 0) {
            fprintf(stderr, "XDP object not found: %s\n", bpf_file);
            return -1;
        }

        bpf_obj = bpf_object__open_file(bpf_file, NULL);
        if (libbpf_get_error(bpf_obj)) {
            fprintf(stderr, "Failed to open %s\n", bpf_file);
            bpf_obj = NULL;
            return -1;
        }

        ret = bpf_object__load(bpf_obj);
        if (ret) {
            fprintf(stderr, "Failed to load BPF object\n");
            bpf_object__close(bpf_obj);
            bpf_obj = NULL;
            return -1;
        }

        prog = bpf_object__find_program_by_name(bpf_obj, "xdp_redirect_prog");
        if (!prog) {
            fprintf(stderr, "XDP program not found\n");
            bpf_object__close(bpf_obj);
            bpf_obj = NULL;
            return -1;
        }
        prog_fd = bpf_program__fd(prog);

        map = bpf_object__find_map_by_name(bpf_obj, "xsks_map");
        if (!map) {
            fprintf(stderr, "xsks_map not found\n");
            bpf_object__close(bpf_obj);
            bpf_obj = NULL;
            return -1;
        }
        xsk_map_fd = bpf_map__fd(map);

        map = bpf_object__find_map_by_name(bpf_obj, "config_map");
        if (map) {
            config_map_fd = bpf_map__fd(map);
            int key0 = 0, key1 = 1;
            bpf_map_update_elem(config_map_fd, &key0, &local_cfg->network, 0);
            bpf_map_update_elem(config_map_fd, &key1, &local_cfg->netmask, 0);
        }
    }

    // UMEM config with explicit ring sizes (critical for multi-queue!)
    struct xsk_umem_config umem_cfg = {
        .fill_size = RING_SIZE,
        .comp_size = RING_SIZE,
        .frame_size = FRAME_SIZE,
        .frame_headroom = 0,
        .flags = 0
    };

    struct xsk_socket_config sock_cfg = {
        .rx_size = RING_SIZE,
        .tx_size = RING_SIZE,
        .libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,
        .bind_flags = XDP_COPY
    };

    // Create separate UMEM and socket for each queue
    for (int q = 0; q < queue_count; q++) {
        struct xsk_queue *queue = &iface->queues[q];
        uint32_t idx;

        // Allocate separate buffer for this queue
        ret = posix_memalign(&queue->bufs, getpagesize(), UMEM_SIZE);
        if (ret || !queue->bufs) {
            fprintf(stderr, "Queue %d: posix_memalign failed\n", q);
            goto err_queues;
        }
        mlock(queue->bufs, UMEM_SIZE);

        // Create separate UMEM for this queue
        ret = xsk_umem__create(&queue->umem, queue->bufs, UMEM_SIZE,
                               &queue->fill, &queue->comp, &umem_cfg);
        if (ret) {
            fprintf(stderr, "Queue %d: xsk_umem__create failed: %d\n", q, ret);
            munlock(queue->bufs, UMEM_SIZE);
            free(queue->bufs);
            queue->bufs = NULL;
            goto err_queues;
        }

        // Create socket for this queue
        ret = xsk_socket__create(&queue->xsk, iface->ifname, q, queue->umem,
                                 &queue->rx, &queue->tx, &sock_cfg);
        if (ret) {
            fprintf(stderr, "Queue %d: xsk_socket__create failed: %d\n", q, ret);
            xsk_umem__delete(queue->umem);
            munlock(queue->bufs, UMEM_SIZE);
            free(queue->bufs);
            queue->bufs = NULL;
            goto err_queues;
        }

        // Register socket in xsks_map
        int fd = xsk_socket__fd(queue->xsk);
        ret = bpf_map_update_elem(xsk_map_fd, &q, &fd, 0);
        if (ret) {
            fprintf(stderr, "Queue %d: bpf_map_update_elem failed\n", q);
            xsk_socket__delete(queue->xsk);
            xsk_umem__delete(queue->umem);
            munlock(queue->bufs, UMEM_SIZE);
            free(queue->bufs);
            queue->bufs = NULL;
            goto err_queues;
        }

        // Fill the fill queue for this queue
        ret = xsk_ring_prod__reserve(&queue->fill, RING_SIZE, &idx);
        if (ret != RING_SIZE) {
            fprintf(stderr, "Queue %d: fill reserve got %d, expected %d\n", q, ret, RING_SIZE);
        }
        for (int i = 0; i < ret; i++)
            *xsk_ring_prod__fill_addr(&queue->fill, idx++) = i * FRAME_SIZE;
        xsk_ring_prod__submit(&queue->fill, ret);

        // Initialize per-queue TX state
        queue->tx_slot = 0;
        queue->pending_tx_count = 0;

        iface->queue_count++;
    }

    // Attach XDP AFTER all sockets are created and registered
    prog = bpf_object__find_program_by_name(bpf_obj, "xdp_redirect_prog");
    prog_fd = bpf_program__fd(prog);
    ret = bpf_set_link_xdp_fd(iface->ifindex, prog_fd, XDP_FLAGS_SKB_MODE);
    if (ret) {
        fprintf(stderr, "bpf_set_link_xdp_fd failed: %d\n", ret);
        goto err_queues;
    }

    // Initialize TX mutex for thread-safe batch TX
    iface->pending_tx_count = 0;
    pthread_mutex_init(&iface->tx_lock, NULL);

    return 0;

err_queues:
    // Cleanup already created queues
    for (int j = 0; j < iface->queue_count; j++) {
        struct xsk_queue *queue = &iface->queues[j];
        if (queue->xsk) xsk_socket__delete(queue->xsk);
        if (queue->umem) xsk_umem__delete(queue->umem);
        if (queue->bufs) {
            munlock(queue->bufs, UMEM_SIZE);
            free(queue->bufs);
        }
    }
    bpf_set_link_xdp_fd(iface->ifindex, -1, XDP_FLAGS_SKB_MODE);
    if (bpf_obj) {
        bpf_object__close(bpf_obj);
        bpf_obj = NULL;
    }
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

// WAN RX - separate BPF object per WAN interface
int interface_init_wan_rx(struct xsk_interface *iface,
                          const struct wan_config *wan_cfg,
                          const char *bpf_file)
{
    int ret;
    struct bpf_object *wan_bpf_obj = NULL;
    struct bpf_program *prog;
    struct bpf_map *map;
    int prog_fd, wan_xsk_map_fd;

    memset(iface, 0, sizeof(*iface));
    iface->ifindex = if_nametoindex(wan_cfg->ifname);
    strncpy(iface->ifname, wan_cfg->ifname, IF_NAMESIZE - 1);
    memcpy(iface->src_mac, wan_cfg->src_mac, MAC_LEN);
    memcpy(iface->dst_mac, wan_cfg->dst_mac, MAC_LEN);

    if (iface->ifindex == 0) {
        fprintf(stderr, "WAN Interface %s not found\n", wan_cfg->ifname);
        return -1;
    }

    // Get number of RX queues
    int queue_count = get_rx_queue_count(wan_cfg->ifname);

    // Detach any existing XDP
    bpf_set_link_xdp_fd(iface->ifindex, -1, XDP_FLAGS_SKB_MODE);

    // Load WAN XDP program
    if (access(bpf_file, F_OK) != 0) {
        fprintf(stderr, "WAN XDP object not found: %s\n", bpf_file);
        return -1;
    }

    wan_bpf_obj = bpf_object__open_file(bpf_file, NULL);
    if (libbpf_get_error(wan_bpf_obj)) {
        fprintf(stderr, "Failed to open WAN BPF: %s\n", bpf_file);
        return -1;
    }

    ret = bpf_object__load(wan_bpf_obj);
    if (ret) {
        fprintf(stderr, "Failed to load WAN BPF object\n");
        bpf_object__close(wan_bpf_obj);
        return -1;
    }

    prog = bpf_object__find_program_by_name(wan_bpf_obj, "xdp_wan_redirect_prog");
    if (!prog) {
        fprintf(stderr, "WAN XDP program not found\n");
        bpf_object__close(wan_bpf_obj);
        return -1;
    }
    prog_fd = bpf_program__fd(prog);

    map = bpf_object__find_map_by_name(wan_bpf_obj, "wan_xsks_map");
    if (!map) {
        fprintf(stderr, "wan_xsks_map not found\n");
        bpf_object__close(wan_bpf_obj);
        return -1;
    }
    wan_xsk_map_fd = bpf_map__fd(map);

    // UMEM config with explicit ring sizes
    struct xsk_umem_config umem_cfg = {
        .fill_size = RING_SIZE,
        .comp_size = RING_SIZE,
        .frame_size = FRAME_SIZE,
        .frame_headroom = 0,
        .flags = 0
    };

    struct xsk_socket_config sock_cfg = {
        .rx_size = RING_SIZE,
        .tx_size = RING_SIZE,
        .libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,
        .bind_flags = XDP_COPY
    };

    // Create separate UMEM and socket for each queue
    for (int q = 0; q < queue_count; q++) {
        struct xsk_queue *queue = &iface->queues[q];
        uint32_t idx;

        // Allocate separate buffer for this queue
        ret = posix_memalign(&queue->bufs, getpagesize(), UMEM_SIZE);
        if (ret || !queue->bufs) {
            fprintf(stderr, "WAN Queue %d: posix_memalign failed\n", q);
            goto err_queues;
        }
        mlock(queue->bufs, UMEM_SIZE);

        // Create separate UMEM for this queue
        ret = xsk_umem__create(&queue->umem, queue->bufs, UMEM_SIZE,
                               &queue->fill, &queue->comp, &umem_cfg);
        if (ret) {
            fprintf(stderr, "WAN Queue %d: xsk_umem__create failed: %d\n", q, ret);
            munlock(queue->bufs, UMEM_SIZE);
            free(queue->bufs);
            queue->bufs = NULL;
            goto err_queues;
        }

        // Create socket for this queue
        ret = xsk_socket__create(&queue->xsk, iface->ifname, q, queue->umem,
                                 &queue->rx, &queue->tx, &sock_cfg);
        if (ret) {
            fprintf(stderr, "WAN Queue %d: xsk_socket__create failed: %d\n", q, ret);
            xsk_umem__delete(queue->umem);
            munlock(queue->bufs, UMEM_SIZE);
            free(queue->bufs);
            queue->bufs = NULL;
            goto err_queues;
        }

        // Register socket in wan_xsks_map
        int fd = xsk_socket__fd(queue->xsk);
        ret = bpf_map_update_elem(wan_xsk_map_fd, &q, &fd, 0);
        if (ret) {
            fprintf(stderr, "WAN Queue %d: bpf_map_update_elem failed\n", q);
            xsk_socket__delete(queue->xsk);
            xsk_umem__delete(queue->umem);
            munlock(queue->bufs, UMEM_SIZE);
            free(queue->bufs);
            queue->bufs = NULL;
            goto err_queues;
        }

        // Fill the fill queue
        ret = xsk_ring_prod__reserve(&queue->fill, RING_SIZE, &idx);
        if (ret != RING_SIZE) {
            fprintf(stderr, "WAN Queue %d: fill reserve got %d\n", q, ret);
        }
        for (int i = 0; i < ret; i++)
            *xsk_ring_prod__fill_addr(&queue->fill, idx++) = i * FRAME_SIZE;
        xsk_ring_prod__submit(&queue->fill, ret);

        // Initialize per-queue TX state
        queue->tx_slot = 0;
        queue->pending_tx_count = 0;

        iface->queue_count++;
    }

    // Attach XDP after all sockets created
    ret = bpf_set_link_xdp_fd(iface->ifindex, prog_fd, XDP_FLAGS_SKB_MODE);
    if (ret) {
        fprintf(stderr, "WAN bpf_set_link_xdp_fd failed: %d\n", ret);
        goto err_queues;
    }

    // Set aliases for TX (interface_send uses these fields)
    // Use queue 0 for TX
    iface->xsk = iface->queues[0].xsk;
    iface->tx = iface->queues[0].tx;
    iface->comp = iface->queues[0].comp;
    iface->bufs = iface->queues[0].bufs;
    iface->tx_slot = 0;
    iface->pending_tx_count = 0;
    pthread_mutex_init(&iface->tx_lock, NULL);

    return 0;

err_queues:
    for (int j = 0; j < iface->queue_count; j++) {
        struct xsk_queue *queue = &iface->queues[j];
        if (queue->xsk) xsk_socket__delete(queue->xsk);
        if (queue->umem) xsk_umem__delete(queue->umem);
        if (queue->bufs) {
            munlock(queue->bufs, UMEM_SIZE);
            free(queue->bufs);
        }
    }
    bpf_set_link_xdp_fd(iface->ifindex, -1, XDP_FLAGS_SKB_MODE);
    if (wan_bpf_obj) bpf_object__close(wan_bpf_obj);
    return -1;
}

void interface_cleanup(struct xsk_interface *iface)
{
    // Destroy TX mutex
    pthread_mutex_destroy(&iface->tx_lock);

    // Detach XDP first
    if (iface->ifindex)
        bpf_set_link_xdp_fd(iface->ifindex, -1, XDP_FLAGS_SKB_MODE);

    // Clean up multi-queue sockets - each queue has its own UMEM
    for (int q = 0; q < iface->queue_count; q++) {
        struct xsk_queue *queue = &iface->queues[q];
        if (queue->xsk)
            xsk_socket__delete(queue->xsk);
        if (queue->umem)
            xsk_umem__delete(queue->umem);
        if (queue->bufs) {
            munlock(queue->bufs, UMEM_SIZE);
            free(queue->bufs);
        }
    }

    // Clean up single socket (old WAN TX-only mode)
    // NOTE: For WAN with RX, iface->xsk and iface->bufs are aliases to queues[0]
    // so we should NOT free them again (already freed above)
    if (iface->queue_count == 0) {
        // Only cleanup if this is NOT a multi-queue interface
        if (iface->xsk)
            xsk_socket__delete(iface->xsk);

        if (iface->umem)
            xsk_umem__delete(iface->umem);

        if (iface->bufs) {
            munlock(iface->bufs, UMEM_SIZE);
            free(iface->bufs);
        }
    }

    memset(iface, 0, sizeof(*iface));
}

// Extended address encoding: [queue_id:8][addr:56]
#define ADDR_ENCODE(q, addr) (((uint64_t)(q) << 56) | ((addr) & 0x00FFFFFFFFFFFFFF))
#define ADDR_QUEUE(encoded)  ((int)((encoded) >> 56))
#define ADDR_OFFSET(encoded) ((encoded) & 0x00FFFFFFFFFFFFFF)

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
            // Encode queue ID in high bits of address
            addrs[total_rcvd + j] = ADDR_ENCODE(q, desc->addr);
            // Use this queue's buffer
            pkt_ptrs[total_rcvd + j] = (uint8_t *)queue->bufs + desc->addr;
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
                // Encode queue ID in high bits of address
                addrs[total_rcvd + j] = ADDR_ENCODE(q, desc->addr);
                // Use this queue's buffer
                pkt_ptrs[total_rcvd + j] = (uint8_t *)queue->bufs + desc->addr;
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
    // Guard against WAN interface (no queues)
    if (iface->queue_count == 0)
        return;

    // Group addresses by queue and return to each queue's fill ring
    for (int i = 0; i < count; i++) {
        int q = ADDR_QUEUE(addrs[i]);
        uint64_t addr = ADDR_OFFSET(addrs[i]);

        if (q >= iface->queue_count)
            continue;

        struct xsk_queue *queue = &iface->queues[q];
        uint32_t idx_fill;

        int ret = xsk_ring_prod__reserve(&queue->fill, 1, &idx_fill);
        if (ret != 1) {
            // Try releasing some completions first
            uint32_t comp_idx;
            int comp = xsk_ring_cons__peek(&queue->comp, BATCH_SIZE, &comp_idx);
            if (comp > 0)
                xsk_ring_cons__release(&queue->comp, comp);

            ret = xsk_ring_prod__reserve(&queue->fill, 1, &idx_fill);
            if (ret != 1)
                continue;
        }

        *xsk_ring_prod__fill_addr(&queue->fill, idx_fill) = addr;
        xsk_ring_prod__submit(&queue->fill, 1);
    }
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

    // Use TX buffer slots in SECOND HALF of UMEM to avoid RX overlap
    // RX uses frames 0 to RING_SIZE-1, TX uses frames RING_SIZE to 2*RING_SIZE-1
    uint64_t addr = ((iface->tx_slot % RING_SIZE) + RING_SIZE) * FRAME_SIZE;
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

// Send packet to LOCAL interface (uses local_config for MAC rewrite)
// LOCAL uses multi-queue, so we use queue 0 for TX
int interface_send_to_local(struct xsk_interface *iface,
                            const struct local_config *local_cfg,
                            void *pkt_data, uint32_t pkt_len)
{
    uint32_t idx;
    struct ether_header *eth;

    // LOCAL uses multi-queue - use queue 0 for TX
    if (iface->queue_count == 0)
        return -1;

    struct xsk_queue *queue = &iface->queues[0];

    // Release completed TX buffers
    uint32_t comp_idx;
    int completed = xsk_ring_cons__peek(&queue->comp, BATCH_SIZE, &comp_idx);
    if (completed > 0)
        xsk_ring_cons__release(&queue->comp, completed);

    int reserved = xsk_ring_prod__reserve(&queue->tx, 1, &idx);
    if (reserved < 1) {
        // Force kick and retry
        sendto(xsk_socket__fd(queue->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
        completed = xsk_ring_cons__peek(&queue->comp, BATCH_SIZE, &comp_idx);
        if (completed > 0)
            xsk_ring_cons__release(&queue->comp, completed);
        reserved = xsk_ring_prod__reserve(&queue->tx, 1, &idx);
        if (reserved < 1)
            return -1;
    }

    // Use rotating TX buffer slots (use second half of buffer)
    uint64_t addr = ((iface->tx_slot % (FRAME_COUNT / 2)) + FRAME_COUNT / 2) * FRAME_SIZE;
    iface->tx_slot++;

    void *tx_buf = (uint8_t *)queue->bufs + addr;
    memcpy(tx_buf, pkt_data, pkt_len);

    // Rewrite MAC using local_config
    eth = (struct ether_header *)tx_buf;
    memcpy(eth->ether_dhost, local_cfg->dst_mac, MAC_LEN);  // Client's MAC
    memcpy(eth->ether_shost, local_cfg->src_mac, MAC_LEN);  // LOCAL interface MAC

    xsk_ring_prod__tx_desc(&queue->tx, idx)->addr = addr;
    xsk_ring_prod__tx_desc(&queue->tx, idx)->len = pkt_len;
    xsk_ring_prod__submit(&queue->tx, 1);

    sendto(xsk_socket__fd(queue->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);

    iface->tx_packets++;
    iface->tx_bytes += pkt_len;

    return 0;
}

void interface_print_stats(struct xsk_interface *iface)
{
    (void)iface;  // Stats disabled for daemon mode
}

// ============== BATCH TX (High Performance, Thread-Safe) ==============

// Add packet to TX batch (no kick yet) - for WAN
// Thread-safe: uses mutex
int interface_send_batch(struct xsk_interface *iface,
                         void *pkt_data, uint32_t pkt_len)
{
    uint32_t idx;
    struct ether_header *eth;
    int ret = 0;

    pthread_mutex_lock(&iface->tx_lock);

    // ALWAYS drain completion ring to free up TX slots
    uint32_t comp_idx;
    int completed = xsk_ring_cons__peek(&iface->comp, RING_SIZE, &comp_idx);
    if (completed > 0)
        xsk_ring_cons__release(&iface->comp, completed);

    int reserved = xsk_ring_prod__reserve(&iface->tx, 1, &idx);
    if (reserved < 1) {
        // Flush pending and retry aggressively
        if (iface->pending_tx_count > 0) {
            sendto(xsk_socket__fd(iface->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
            iface->pending_tx_count = 0;
        }

        // Drain completion ring again
        completed = xsk_ring_cons__peek(&iface->comp, RING_SIZE, &comp_idx);
        if (completed > 0)
            xsk_ring_cons__release(&iface->comp, completed);

        // Retry multiple times with small delay
        for (int retry = 0; retry < 3; retry++) {
            reserved = xsk_ring_prod__reserve(&iface->tx, 1, &idx);
            if (reserved >= 1)
                break;
            // Small busy-wait to let kernel process
            for (volatile int i = 0; i < 100; i++);
            completed = xsk_ring_cons__peek(&iface->comp, RING_SIZE, &comp_idx);
            if (completed > 0)
                xsk_ring_cons__release(&iface->comp, completed);
        }

        if (reserved < 1) {
            ret = -1;
            goto unlock;
        }
    }

    // Use TX buffer slots in SECOND HALF of UMEM to avoid RX overlap
    // RX uses frames 0 to RING_SIZE-1, TX uses frames RING_SIZE to 2*RING_SIZE-1
    uint64_t addr = ((iface->tx_slot % RING_SIZE) + RING_SIZE) * FRAME_SIZE;
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

    iface->pending_tx_count++;
    __sync_fetch_and_add(&iface->tx_packets, 1);
    __sync_fetch_and_add(&iface->tx_bytes, pkt_len);

    // Auto-flush more frequently (every 64 packets) for lower latency
    if (iface->pending_tx_count >= 64) {
        sendto(xsk_socket__fd(iface->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
        iface->pending_tx_count = 0;
    }

unlock:
    pthread_mutex_unlock(&iface->tx_lock);
    return ret;
}

// Flush all pending TX packets (kick once)
// Thread-safe: uses mutex
void interface_send_flush(struct xsk_interface *iface)
{
    pthread_mutex_lock(&iface->tx_lock);
    if (iface->pending_tx_count > 0) {
        sendto(xsk_socket__fd(iface->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
        iface->pending_tx_count = 0;
    }
    pthread_mutex_unlock(&iface->tx_lock);
}

// Add packet to LOCAL TX batch
// Each caller should use a different tx_queue for parallel TX (NO MUTEX needed!)
int interface_send_to_local_batch(struct xsk_interface *iface,
                                  const struct local_config *local_cfg,
                                  void *pkt_data, uint32_t pkt_len,
                                  int tx_queue)
{
    uint32_t idx;
    struct ether_header *eth;

    if (iface->queue_count == 0)
        return -1;

    // Use specified queue (mod queue_count for safety)
    int q = tx_queue % iface->queue_count;
    struct xsk_queue *queue = &iface->queues[q];

    // ALWAYS drain completion ring to free up TX slots
    uint32_t comp_idx;
    int completed = xsk_ring_cons__peek(&queue->comp, RING_SIZE, &comp_idx);
    if (completed > 0)
        xsk_ring_cons__release(&queue->comp, completed);

    int reserved = xsk_ring_prod__reserve(&queue->tx, 1, &idx);
    if (reserved < 1) {
        // Flush pending and retry aggressively
        if (queue->pending_tx_count > 0) {
            sendto(xsk_socket__fd(queue->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
            queue->pending_tx_count = 0;
        }

        // Drain completion ring again
        completed = xsk_ring_cons__peek(&queue->comp, RING_SIZE, &comp_idx);
        if (completed > 0)
            xsk_ring_cons__release(&queue->comp, completed);

        // Retry multiple times with small delay
        for (int retry = 0; retry < 3; retry++) {
            reserved = xsk_ring_prod__reserve(&queue->tx, 1, &idx);
            if (reserved >= 1)
                break;
            // Small busy-wait to let kernel process
            for (volatile int i = 0; i < 100; i++);
            completed = xsk_ring_cons__peek(&queue->comp, RING_SIZE, &comp_idx);
            if (completed > 0)
                xsk_ring_cons__release(&queue->comp, completed);
        }

        if (reserved < 1) {
            return -1;
        }
    }

    // Use rotating TX buffer slots (second half of this queue's UMEM)
    // Each queue has its own tx_slot counter - no contention!
    uint64_t addr = ((queue->tx_slot % RING_SIZE) + RING_SIZE) * FRAME_SIZE;
    queue->tx_slot++;

    void *tx_buf = (uint8_t *)queue->bufs + addr;
    memcpy(tx_buf, pkt_data, pkt_len);

    // Rewrite MAC using local_config
    eth = (struct ether_header *)tx_buf;
    memcpy(eth->ether_dhost, local_cfg->dst_mac, MAC_LEN);
    memcpy(eth->ether_shost, local_cfg->src_mac, MAC_LEN);

    xsk_ring_prod__tx_desc(&queue->tx, idx)->addr = addr;
    xsk_ring_prod__tx_desc(&queue->tx, idx)->len = pkt_len;
    xsk_ring_prod__submit(&queue->tx, 1);

    queue->pending_tx_count++;
    __sync_fetch_and_add(&iface->tx_packets, 1);
    __sync_fetch_and_add(&iface->tx_bytes, pkt_len);

    // Auto-flush more frequently (every 64 packets) for lower latency
    if (queue->pending_tx_count >= 64) {
        sendto(xsk_socket__fd(queue->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
        queue->pending_tx_count = 0;
    }

    return 0;
}

// Flush LOCAL TX (specific queue - no mutex needed)
void interface_send_to_local_flush(struct xsk_interface *iface, int tx_queue)
{
    if (iface->queue_count == 0)
        return;

    int q = tx_queue % iface->queue_count;
    struct xsk_queue *queue = &iface->queues[q];

    if (queue->pending_tx_count > 0) {
        sendto(xsk_socket__fd(queue->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
        queue->pending_tx_count = 0;
    }
}
