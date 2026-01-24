#include "../inc/interface.h"
#include <poll.h>
#include <net/ethernet.h>
#include <unistd.h>

static struct bpf_object *bpf_obj = NULL;
static int xsk_map_fd = -1;
static int config_map_fd = -1;

// Initialize LOCAL interface with XDP program
int interface_init_local(struct xsk_interface *iface,
                         const struct app_config *cfg)
{
    int ret;
    struct bpf_program *prog;
    struct bpf_map *map;
    int prog_fd;
    uint32_t idx;

    memset(iface, 0, sizeof(*iface));
    iface->ifindex = if_nametoindex(cfg->local.ifname);
    strncpy(iface->ifname, cfg->local.ifname, IF_NAMESIZE - 1);
    memcpy(iface->src_mac, cfg->local.src_mac, MAC_LEN);
    memcpy(iface->dst_mac, cfg->local.dst_mac, MAC_LEN);

    if (iface->ifindex == 0) {
        fprintf(stderr, "Interface %s not found\n", cfg->local.ifname);
        return -1;
    }

    // Allocate UMEM buffer
    ret = posix_memalign(&iface->bufs, getpagesize(), UMEM_SIZE);
    if (ret || !iface->bufs) {
        perror("posix_memalign");
        return -1;
    }

    // Create UMEM
    ret = xsk_umem__create(&iface->umem, iface->bufs, UMEM_SIZE,
                           &iface->fill, &iface->comp, NULL);
    if (ret) {
        perror("xsk_umem__create");
        free(iface->bufs);
        return -1;
    }

    // Load BPF object (only once)
    if (!bpf_obj) {
        // Explicit path to XDP program
        const char *xdp_obj_file = "bpf/xdp_redirect.o";

        // Check file exists before loading
        if (access(xdp_obj_file, F_OK) != 0) {
            fprintf(stderr, "ERROR: XDP object file not found: %s\n", xdp_obj_file);
            fprintf(stderr, "Run: clang -O2 -target bpf -g -c bpf/xdp_redirect.c -o %s\n", xdp_obj_file);
            goto err;
        }

        printf("[XDP] Loading BPF object: %s\n", xdp_obj_file);
        bpf_obj = bpf_object__open_file(xdp_obj_file, NULL);
        if (libbpf_get_error(bpf_obj)) {
            fprintf(stderr, "Failed to open %s\n", xdp_obj_file);
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
        if (!map) {
            fprintf(stderr, "config_map not found\n");
            goto err;
        }
        config_map_fd = bpf_map__fd(map);

        // Load LOCAL network into BPF map
        // XDP will PASS packets to LOCAL network, REDIRECT others
        int key0 = 0, key1 = 1;
        ret = bpf_map_update_elem(config_map_fd, &key0, &cfg->local.network, 0);
        if (ret) {
            perror("bpf_map_update_elem local_network");
            goto err;
        }
        ret = bpf_map_update_elem(config_map_fd, &key1, &cfg->local.netmask, 0);
        if (ret) {
            perror("bpf_map_update_elem local_netmask");
            goto err;
        }

        printf("[XDP] Filter loaded: LOCAL network %d.%d.%d.%d/%d.%d.%d.%d\n",
               ((uint8_t*)&cfg->local.network)[0], ((uint8_t*)&cfg->local.network)[1],
               ((uint8_t*)&cfg->local.network)[2], ((uint8_t*)&cfg->local.network)[3],
               ((uint8_t*)&cfg->local.netmask)[0], ((uint8_t*)&cfg->local.netmask)[1],
               ((uint8_t*)&cfg->local.netmask)[2], ((uint8_t*)&cfg->local.netmask)[3]);
        printf("[XDP] Packets IN local network -> PASS | Packets OUT -> REDIRECT\n");

        // Attach XDP program
        ret = bpf_set_link_xdp_fd(iface->ifindex, prog_fd, XDP_FLAGS_SKB_MODE);
        if (ret) {
            fprintf(stderr, "bpf_set_link_xdp_fd failed on %s: %d\n", iface->ifname, ret);
            goto err;
        }
        printf("[XDP] Attached to %s\n", iface->ifname);
    }

    // Create XSK socket
    struct xsk_socket_config sock_cfg = {
        .rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
        .tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS,
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

    // Update xsks_map with socket fd
    int key = 0;
    int fd = xsk_socket__fd(iface->xsk);
    ret = bpf_map_update_elem(xsk_map_fd, &key, &fd, 0);
    if (ret) {
        perror("bpf_map_update_elem xsks_map");
        xsk_socket__delete(iface->xsk);
        bpf_set_link_xdp_fd(iface->ifindex, -1, XDP_FLAGS_SKB_MODE);
        goto err;
    }

    // Fill the fill queue
    ret = xsk_ring_prod__reserve(&iface->fill, XSK_RING_PROD__DEFAULT_NUM_DESCS, &idx);
    for (uint32_t i = 0; i < XSK_RING_PROD__DEFAULT_NUM_DESCS; i++)
        *xsk_ring_prod__fill_addr(&iface->fill, idx++) = i * FRAME_SIZE;
    xsk_ring_prod__submit(&iface->fill, XSK_RING_PROD__DEFAULT_NUM_DESCS);

    printf("[LOCAL] %s initialized (MAC: %02x:%02x:%02x:%02x:%02x:%02x)\n",
           iface->ifname,
           iface->src_mac[0], iface->src_mac[1], iface->src_mac[2],
           iface->src_mac[3], iface->src_mac[4], iface->src_mac[5]);

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

    // Allocate UMEM buffer
    ret = posix_memalign(&iface->bufs, getpagesize(), UMEM_SIZE);
    if (ret || !iface->bufs) {
        perror("posix_memalign");
        return -1;
    }

    // Create UMEM
    ret = xsk_umem__create(&iface->umem, iface->bufs, UMEM_SIZE,
                           &iface->fill, &iface->comp, NULL);
    if (ret) {
        perror("xsk_umem__create");
        free(iface->bufs);
        return -1;
    }

    // Create XSK socket (TX only)
    struct xsk_socket_config sock_cfg = {
        .rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
        .tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS,
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

    // Fill the fill queue
    ret = xsk_ring_prod__reserve(&iface->fill, XSK_RING_PROD__DEFAULT_NUM_DESCS, &idx);
    for (uint32_t i = 0; i < XSK_RING_PROD__DEFAULT_NUM_DESCS; i++)
        *xsk_ring_prod__fill_addr(&iface->fill, idx++) = i * FRAME_SIZE;
    xsk_ring_prod__submit(&iface->fill, XSK_RING_PROD__DEFAULT_NUM_DESCS);

    printf("[WAN] %s initialized\n", iface->ifname);
    printf("      SRC MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           iface->src_mac[0], iface->src_mac[1], iface->src_mac[2],
           iface->src_mac[3], iface->src_mac[4], iface->src_mac[5]);
    printf("      DST MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           iface->dst_mac[0], iface->dst_mac[1], iface->dst_mac[2],
           iface->dst_mac[3], iface->dst_mac[4], iface->dst_mac[5]);

    return 0;
}

void interface_cleanup(struct xsk_interface *iface)
{
    if (iface->xsk) xsk_socket__delete(iface->xsk);
    if (iface->umem) xsk_umem__delete(iface->umem);
    if (iface->bufs) free(iface->bufs);

    // Detach XDP if this was LOCAL
    if (iface->ifindex && bpf_obj) {
        bpf_set_link_xdp_fd(iface->ifindex, -1, XDP_FLAGS_SKB_MODE);
    }

    printf("[IFACE] %s cleaned up\n", iface->ifname);
    memset(iface, 0, sizeof(*iface));
}

// Receive packets from LOCAL interface
int interface_recv(struct xsk_interface *iface,
                   void **pkt_ptrs, uint32_t *pkt_lens,
                   uint64_t *addrs, int max_pkts)
{
    uint32_t idx_rx = 0;

    struct pollfd fds = {
        .fd = xsk_socket__fd(iface->xsk),
        .events = POLLIN
    };

    int ret = poll(&fds, 1, 100);
    if (ret <= 0)
        return 0;

    int rcvd = xsk_ring_cons__peek(&iface->rx, max_pkts, &idx_rx);
    if (rcvd == 0)
        return 0;

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

// Release RX buffers back to fill queue
void interface_recv_release(struct xsk_interface *iface,
                            uint64_t *addrs, int count)
{
    uint32_t idx_fill = 0;

    int ret = xsk_ring_prod__reserve(&iface->fill, count, &idx_fill);
    if (ret != count)
        return;

    for (int i = 0; i < count; i++)
        *xsk_ring_prod__fill_addr(&iface->fill, idx_fill + i) = addrs[i];

    xsk_ring_prod__submit(&iface->fill, count);
}

// Send packet through WAN interface (rewrites MAC)
int interface_send(struct xsk_interface *iface,
                   void *pkt_data, uint32_t pkt_len)
{
    uint32_t idx;
    struct ether_header *eth;

    if (xsk_ring_prod__reserve(&iface->tx, 1, &idx) < 1)
        return -1;

    // Copy packet to TX buffer
    memcpy(iface->bufs, pkt_data, pkt_len);

    // Rewrite MAC addresses
    eth = (struct ether_header *)iface->bufs;
    memcpy(eth->ether_dhost, iface->dst_mac, MAC_LEN);  // Remote MAC
    memcpy(eth->ether_shost, iface->src_mac, MAC_LEN);  // Local MAC

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

void interface_print_stats(struct xsk_interface *iface)
{
    printf("[STATS] %s: RX=%lu TX=%lu\n",
           iface->ifname, iface->rx_packets, iface->tx_packets);
}
