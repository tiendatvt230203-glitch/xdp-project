#include "../inc/forwarder.h"
#include "../inc/packet_crypto.h"
#include "../inc/flow_table.h"
#include "../inc/fragment.h"
#include "../inc/config.h"
#include "../inc/crypto_layer2.h"
#include "../inc/crypto_layer3.h"
#include "../inc/crypto_layer4.h"
#include <signal.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <time.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netpacket/packet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <net/if_arp.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>

#define NUM_WORKERS 4
#define WORKER_RING_SIZE 4096

static volatile int running = 1;

static struct packet_crypto_ctx crypto_ctx;
static int crypto_enabled = 0;
static int crypto_layer = 0;

static struct flow_table g_flow_table;

/* Crypto contexts per DB policy (used for per-policy key). */
static struct packet_crypto_ctx g_policy_crypto_ctx[MAX_CRYPTO_POLICIES];
static int g_policy_crypto_ctx_ready[MAX_CRYPTO_POLICIES];

/* Used to keep thread-local crypto params in sync for legacy paths. */
static struct app_config *g_cfg_ptr = NULL;

static int select_wan_idx_for_packet(struct forwarder *fwd,
                                     uint32_t src_ip, uint32_t dst_ip,
                                     uint16_t src_port, uint16_t dst_port,
                                     uint8_t protocol, uint32_t pkt_len) {
    /* Keep crypto policy selection independent from WAN selection.
     * WAN selection is handled by flow_table to preserve packet order:
     * packets of a single flow stay on one WAN until the per-WAN byte quota
     * is reached, then rotate to the next WAN. */
    (void)pkt_len;
    return flow_table_get_wan(&g_flow_table,
                               src_ip, dst_ip, src_port, dst_port,
                               protocol, pkt_len);
}

static const struct crypto_policy *select_crypto_policy_for_packet(struct forwarder *fwd,
                                                                       uint32_t src_ip, uint32_t dst_ip,
                                                                       uint16_t src_port, uint16_t dst_port,
                                                                       uint8_t protocol) {
    if (!fwd || !fwd->cfg)
        return NULL;
    if (fwd->cfg->profile_count <= 0)
        return NULL;

    int profile_idx = config_select_profile_for_flow(fwd->cfg, src_ip, dst_ip);
    if (profile_idx < 0)
        return NULL;

    return config_select_crypto_policy(fwd->cfg, profile_idx,
                                       src_ip, dst_ip,
                                       src_port, dst_port,
                                       protocol);
}

static void apply_default_crypto_params(struct forwarder *fwd) {
    if (!fwd || !fwd->cfg)
        return;
    packet_crypto_set_mode(fwd->cfg->crypto_mode);
    packet_crypto_set_aes_bits(fwd->cfg->aes_bits);
    packet_crypto_set_nonce_size(fwd->cfg->nonce_size);
    packet_crypto_set_fake_protocol((uint8_t)(fwd->cfg->fake_protocol & 0xFF));
    packet_crypto_set_policy_id(0);
}

static void apply_crypto_params_from_policy(const struct crypto_policy *cp) {
    if (!cp) return;
    packet_crypto_set_mode(cp->crypto_mode);
    packet_crypto_set_aes_bits(cp->aes_bits);
    packet_crypto_set_nonce_size(cp->nonce_size);
    if (cp->action == POLICY_ACTION_ENCRYPT_L3)
        packet_crypto_set_fake_protocol(99);
    else
        packet_crypto_set_fake_protocol((uint8_t)(cp->id & 0xFF));
    packet_crypto_set_policy_id((uint8_t)(cp->id & 0x7F));
}

static int encrypt_packet_with_ctx(struct packet_crypto_ctx *ctx,
                                     void *pkt_data, uint32_t *pkt_len) {
    if (!crypto_enabled || !ctx) return 0;
    int new_len = packet_encrypt(ctx, (uint8_t *)pkt_data, *pkt_len);
    if (new_len < 0)
        return -1;
    *pkt_len = (uint32_t)new_len;
    return 0;
}

#define ARP_CACHE_SIZE 2048
#define ARP_PERSIST_DIR "/var/lib/network-encryptor"

struct arp_entry {
    uint32_t ip; 
    uint8_t mac[6];
    uint32_t last_seen_sec;
};

struct arp_cache {
    struct arp_entry entries[ARP_CACHE_SIZE];
    pthread_mutex_t lock;
    int raw_fd;             
    int ifindex;
    char ifname[IF_NAMESIZE];
    uint8_t if_mac[6];
    uint32_t if_ip;         
    uint32_t persist_dirty;
};

static struct arp_cache g_arp[MAX_INTERFACES];
static struct arp_cache g_wan_arp[MAX_INTERFACES];
static int g_arp_inited = 0;

static int mac_is_nonzero6(const uint8_t mac[6]) {
    return mac[0] | mac[1] | mac[2] | mac[3] | mac[4] | mac[5];
}

static int get_iface_mac_and_ip(const char *ifname, uint8_t mac_out[6], uint32_t *ip_out) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IF_NAMESIZE - 1);

    if (ioctl(fd, SIOCGIFHWADDR, &ifr) != 0) {
        close(fd);
        return -1;
    }
    memcpy(mac_out, (uint8_t *)ifr.ifr_hwaddr.sa_data, 6);

    if (ioctl(fd, SIOCGIFADDR, &ifr) != 0) {
        close(fd);
        return -1;
    }
    struct sockaddr_in *sin = (struct sockaddr_in *)&ifr.ifr_addr;
    *ip_out = sin->sin_addr.s_addr; 

    close(fd);
    return 0;
}

static uint32_t arp_hash(uint32_t ip) {
    uint32_t x = ip;
    x ^= x >> 16;
    x *= 0x7feb352d;
    x ^= x >> 15;
    x *= 0x846ca68b;
    x ^= x >> 16;
    return x;
}

static int arp_cache_lookup(struct arp_cache *c, uint32_t ip, uint8_t mac_out[6]) {
    uint32_t h = arp_hash(ip);
    pthread_mutex_lock(&c->lock);
    for (uint32_t i = 0; i < ARP_CACHE_SIZE; i++) {
        uint32_t idx = (h + i) & (ARP_CACHE_SIZE - 1);
        if (c->entries[idx].ip == 0) break;
        if (c->entries[idx].ip == ip) {
            memcpy(mac_out, c->entries[idx].mac, 6);
            pthread_mutex_unlock(&c->lock);
            return 1;
        }
    }
    pthread_mutex_unlock(&c->lock);
    return 0;
}

static void arp_cache_insert(struct arp_cache *c, uint32_t ip, const uint8_t mac[6]) {
    uint32_t h = arp_hash(ip);
    uint32_t now = (uint32_t)time(NULL);
    pthread_mutex_lock(&c->lock);
    for (uint32_t i = 0; i < ARP_CACHE_SIZE; i++) {
        uint32_t idx = (h + i) & (ARP_CACHE_SIZE - 1);
        if (c->entries[idx].ip == 0 || c->entries[idx].ip == ip) {
            c->entries[idx].ip = ip;
            memcpy(c->entries[idx].mac, mac, 6);
            c->entries[idx].last_seen_sec = now;
            c->persist_dirty = 1;
            break;
        }
    }
    pthread_mutex_unlock(&c->lock);
}

static void arp_cache_persist_path(const char *ifname, char *out, size_t out_sz) {
    snprintf(out, out_sz, "%s/arp_%s.txt", ARP_PERSIST_DIR, ifname);
}

static void arp_cache_load(struct arp_cache *c) {
    char path[256];
    arp_cache_persist_path(c->ifname, path, sizeof(path));
    FILE *f = fopen(path, "r");
    if (!f) return;

    uint32_t ip_host;
    unsigned int b0, b1, b2, b3, b4, b5;
    while (fscanf(f, "%u %x:%x:%x:%x:%x:%x\n",
                  &ip_host, &b0, &b1, &b2, &b3, &b4, &b5) == 7) {
        uint32_t ip = htonl(ip_host);
        uint8_t mac[6] = {(uint8_t)b0,(uint8_t)b1,(uint8_t)b2,(uint8_t)b3,(uint8_t)b4,(uint8_t)b5};
        arp_cache_insert(c, ip, mac);
    }
    fclose(f);
    c->persist_dirty = 0;
}

static void arp_cache_save(struct arp_cache *c) {
    if (!c->persist_dirty) return;

    (void)mkdir(ARP_PERSIST_DIR, 0755);

    char path[256];
    arp_cache_persist_path(c->ifname, path, sizeof(path));
    FILE *f = fopen(path, "w");
    if (!f) return;

    pthread_mutex_lock(&c->lock);
    for (uint32_t i = 0; i < ARP_CACHE_SIZE; i++) {
        if (c->entries[i].ip == 0) continue;
        uint32_t ip_host = ntohl(c->entries[i].ip);
        fprintf(f, "%u %02x:%02x:%02x:%02x:%02x:%02x\n",
                ip_host,
                c->entries[i].mac[0], c->entries[i].mac[1], c->entries[i].mac[2],
                c->entries[i].mac[3], c->entries[i].mac[4], c->entries[i].mac[5]);
    }
    c->persist_dirty = 0;
    pthread_mutex_unlock(&c->lock);
    fclose(f);
}

static void arp_send_request(struct arp_cache *c, uint32_t target_ip) {
    if (c->raw_fd < 0 || c->ifindex <= 0 || !mac_is_nonzero6(c->if_mac) || c->if_ip == 0)
        return;

    uint8_t frame[42];
    struct ether_header *eth = (struct ether_header *)frame;
    memset(eth->ether_dhost, 0xff, 6);
    memcpy(eth->ether_shost, c->if_mac, 6);
    eth->ether_type = htons(ETH_P_ARP);

    struct ether_arp *arp = (struct ether_arp *)(frame + sizeof(struct ether_header));
    memset(arp, 0, sizeof(*arp));
    arp->ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
    arp->ea_hdr.ar_pro = htons(ETHERTYPE_IP);
    arp->ea_hdr.ar_hln = 6;
    arp->ea_hdr.ar_pln = 4;
    arp->ea_hdr.ar_op  = htons(ARPOP_REQUEST);
    memcpy(arp->arp_sha, c->if_mac, 6);
    memcpy(arp->arp_spa, &c->if_ip, 4);
    memset(arp->arp_tha, 0x00, 6);
    memcpy(arp->arp_tpa, &target_ip, 4);

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = c->ifindex;
    sll.sll_halen = 6;
    memset(sll.sll_addr, 0xff, 6);

    (void)sendto(c->raw_fd, frame, sizeof(frame), 0, (struct sockaddr *)&sll, sizeof(sll));
}

static void *arp_listener_thread(void *arg) {
    struct arp_cache *c = (struct arp_cache *)arg;
    uint8_t buf[2048];

    uint32_t last_save = (uint32_t)time(NULL);
    while (running) {
        ssize_t n = recv(c->raw_fd, buf, sizeof(buf), 0);
        if (n < (ssize_t)(sizeof(struct ether_header) + sizeof(struct ether_arp)))
            continue;

        struct ether_header *eth = (struct ether_header *)buf;
        if (ntohs(eth->ether_type) != ETH_P_ARP)
            continue;

        struct ether_arp *arp = (struct ether_arp *)(buf + sizeof(struct ether_header));
        if (ntohs(arp->ea_hdr.ar_op) != ARPOP_REPLY)
            continue;

        uint32_t spa;
        memcpy(&spa, arp->arp_spa, 4);
        uint8_t mac[6];
        memcpy(mac, arp->arp_sha, 6);
        if (!mac_is_nonzero6(mac))
            continue;

        arp_cache_insert(c, spa, mac);

        uint32_t now = (uint32_t)time(NULL);
        if (now - last_save >= 2) {
            arp_cache_save(c);
            last_save = now;
        }
    }
    arp_cache_save(c);
    return NULL;
}

static int arp_init_for_local(struct arp_cache *c, const struct xsk_interface *local_iface) {
    memset(c, 0, sizeof(*c));
    pthread_mutex_init(&c->lock, NULL);
    c->raw_fd = -1;
    c->ifindex = local_iface->ifindex;
    strncpy(c->ifname, local_iface->ifname, IF_NAMESIZE - 1);

    if (get_iface_mac_and_ip(c->ifname, c->if_mac, &c->if_ip) != 0) {
        fprintf(stderr, "[ARP] cannot read MAC/IP for %s\n", c->ifname);
        return -1;
    }

    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (fd < 0) {
        fprintf(stderr, "[ARP] cannot open raw socket for %s\n", c->ifname);
        return -1;
    }
    c->raw_fd = fd;

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ARP);
    sll.sll_ifindex = c->ifindex;
    if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) != 0) {
        fprintf(stderr, "[ARP] bind failed for %s\n", c->ifname);
        close(fd);
        c->raw_fd = -1;
        return -1;
    }

    arp_cache_load(c);
    return 0;
}

static int set_wan_l2_addrs(struct forwarder *fwd, int wan_idx, uint8_t *pkt) {
    if (!fwd || !pkt || wan_idx < 0 || wan_idx >= fwd->wan_count)
        return -1;

    struct xsk_interface *wan = &fwd->wans[wan_idx];
    const struct wan_config *wan_cfg = &fwd->cfg->wans[wan_idx];

    if (wan_cfg->next_hop_ip != 0) {
        uint8_t dst_mac[6];
        if (arp_cache_lookup(&g_wan_arp[wan_idx], wan_cfg->next_hop_ip, dst_mac)) {
            memcpy(pkt, dst_mac, 6);
            memcpy(pkt + 6, g_wan_arp[wan_idx].if_mac, 6);
            return 0;
        }
        arp_send_request(&g_wan_arp[wan_idx], wan_cfg->next_hop_ip);
        return -1;
    }

    /* Backward-compatible fallback: static WAN MACs. */
    memcpy(pkt, wan->dst_mac, 6);
    memcpy(pkt + 6, wan->src_mac, 6);
    return 0;
}

static void log_wan_next_hop_mac(struct forwarder *fwd, int wan_idx) {
    if (!fwd || wan_idx < 0 || wan_idx >= fwd->wan_count)
        return;
    const struct wan_config *wc = &fwd->cfg->wans[wan_idx];
    if (wc->next_hop_ip == 0)
        return;

    char ipbuf[INET_ADDRSTRLEN] = {0};
    struct in_addr a = { .s_addr = wc->next_hop_ip };
    inet_ntop(AF_INET, &a, ipbuf, sizeof(ipbuf));

    uint8_t mac[6];
    for (int tries = 0; tries < 10; tries++) {
        if (arp_cache_lookup(&g_wan_arp[wan_idx], wc->next_hop_ip, mac)) {
            fprintf(stderr,
                    "[WAN ARP] if=%s src_ip=%u dst_ip=%u next_hop=%s mac=%02x:%02x:%02x:%02x:%02x:%02x\n",
                    fwd->wans[wan_idx].ifname,
                    (unsigned)ntohl(wc->src_ip),
                    (unsigned)ntohl(wc->dst_ip),
                    ipbuf,
                    mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
            return;
        }
        arp_send_request(&g_wan_arp[wan_idx], wc->next_hop_ip);
        usleep(100000);
    }
    fprintf(stderr,
            "[WAN ARP] if=%s src_ip=%u dst_ip=%u next_hop=%s mac=UNRESOLVED\n",
            fwd->wans[wan_idx].ifname,
            (unsigned)ntohl(wc->src_ip),
            (unsigned)ntohl(wc->dst_ip),
            ipbuf);
}

struct packet_job {
    struct forwarder *fwd;
    int local_idx;
    int queue_idx;
    int tx_queue_base;
    void *pkt_ptr;
    uint32_t pkt_len;
    uint64_t addr;
};

struct worker_ring {
    struct packet_job jobs[WORKER_RING_SIZE];
    uint32_t head;
    uint32_t tail;
    pthread_mutex_t lock;
} __attribute__((aligned(64)));

static struct worker_ring g_worker_rings[NUM_WORKERS];
static uint32_t g_dispatch_counter = 0;

struct queue_thread_args {
    struct forwarder *fwd;
    int iface_idx;
    int queue_idx;
    int tx_queue_base;
    int core_id;
    int wan_worker_index;
    int worker_id;
};

static void pin_thread_to_core(int core_id) {
    if (core_id < 0)
        return;

    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(core_id, &cpuset);
    (void)pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
}

static int encrypt_packet(void *pkt_data, uint32_t *pkt_len) {
    if (!crypto_enabled) return 0;

    if (g_cfg_ptr) {
        packet_crypto_set_mode(g_cfg_ptr->crypto_mode);
        packet_crypto_set_aes_bits(g_cfg_ptr->aes_bits);
        packet_crypto_set_nonce_size(g_cfg_ptr->nonce_size);
        packet_crypto_set_fake_protocol((uint8_t)(g_cfg_ptr->fake_protocol & 0xFF));
        packet_crypto_set_policy_id(0);
    }

    int new_len = packet_encrypt(&crypto_ctx, (uint8_t *)pkt_data, *pkt_len);
    if (new_len < 0) {
        return -1;
    }
    *pkt_len = (uint32_t)new_len;
    return 0;
}

static int decrypt_packet(void *pkt_data, uint32_t *pkt_len) {
    if (!crypto_enabled) return 0;

    if (g_cfg_ptr) {
        packet_crypto_set_mode(g_cfg_ptr->crypto_mode);
        packet_crypto_set_aes_bits(g_cfg_ptr->aes_bits);
        packet_crypto_set_nonce_size(g_cfg_ptr->nonce_size);
        packet_crypto_set_fake_protocol((uint8_t)(g_cfg_ptr->fake_protocol & 0xFF));
        packet_crypto_set_policy_id(0);
    }

    int new_len = packet_decrypt(&crypto_ctx, (uint8_t *)pkt_data, *pkt_len);
    if (new_len < 0) {
        return -1;
    }
    *pkt_len = (uint32_t)new_len;
    return 0;
}

static int decrypt_packet_auto_l2(struct forwarder *fwd,
                                  uint8_t *pkt, uint32_t *pkt_len,
                                  uint8_t *scratch, size_t scratch_sz) {
    if (!crypto_enabled || !fwd || !fwd->cfg || !pkt || !pkt_len)
        return -1;

    /* If it's not L2-encrypted (fake ethertype marker not present), decrypt is a no-op. */
    uint8_t pkt_marker = pkt[12];
    uint16_t fake_ipv4 = packet_crypto_get_fake_ethertype_ipv4();
    uint16_t fake_ipv6 = packet_crypto_get_fake_ethertype_ipv6();
    if (!((fake_ipv4 && pkt_marker == (uint8_t)(fake_ipv4 >> 8)) ||
          (fake_ipv6 && pkt_marker == (uint8_t)(fake_ipv6 >> 8)))) {
        return 0;
    }

    if (fwd->cfg->policy_count <= 0) {
        apply_default_crypto_params(fwd);
        int new_len = packet_decrypt(&crypto_ctx, pkt, *pkt_len);
        if (new_len < 0) return -1;
        *pkt_len = (uint32_t)new_len;
        return 0;
    }

    /* L2 policy id is stored in dedicated byte offset 13. */
    uint8_t policy_id = (uint8_t)(pkt[13] & 0x7F);

    for (int pi = 0; pi < fwd->cfg->policy_count && pi < MAX_CRYPTO_POLICIES; pi++) {
        const struct crypto_policy *cp = &fwd->cfg->policies[pi];
        if (!cp || cp->action != POLICY_ACTION_ENCRYPT_L2)
            continue;
        if (!g_policy_crypto_ctx_ready[pi])
            continue;
        if ( (uint8_t)(cp->id & 0x7F) != policy_id)
            continue;

        apply_crypto_params_from_policy(cp);
        int new_len = packet_decrypt(&g_policy_crypto_ctx[pi], pkt, *pkt_len);
        if (new_len < 0)
            return -1;
        *pkt_len = (uint32_t)new_len;
        return 0;
    }

    /* marker matches but policy not found => cannot decrypt. */
    return -1;
}

/* Extract L4 tunnel policy_id and nonce_size from IPv4 packet.
 * We use: tunnel_off + nonce_size + 1 == L4_TUNNEL_MAGIC
 * policy_id is stored at tunnel_off + nonce_size. */
static int l4_extract_policy_id_ipv4(uint8_t *pkt, uint32_t pkt_len,
                                       uint8_t *policy_id_out, int *nonce_size_out) {
    if (!pkt || !policy_id_out || !nonce_size_out)
        return -1;

    int l3_off = crypto_eth_ipv4_offset(pkt, pkt_len);
    if (l3_off < 0)
        return -1;
    if (pkt_len < (uint32_t)(l3_off + 20))
        return -1;

    uint8_t ip_hdr_len = (pkt[l3_off] & 0x0F) * 4;
    if (ip_hdr_len < 20)
        return -1;
    if (pkt_len < (uint32_t)(l3_off + ip_hdr_len + 8))
        return -1;

    uint8_t ip_proto = pkt[l3_off + 9];
    int transport_off = l3_off + ip_hdr_len;
    const uint8_t L4_TUNNEL_MAGIC = 0xA5;
    int candidates[4] = {4, 8, 12, 16};

    if (ip_proto == 6) {
        if (pkt_len < (uint32_t)(transport_off + 20))
            return -1;
        uint8_t tcp_hdr_len = ((pkt[transport_off + 12] >> 4) & 0x0F) * 4;
        if (tcp_hdr_len < 20)
            return -1;
        int legacy_tun = transport_off + tcp_hdr_len;

        for (int i = 0; i < 4; i++) {
            int ns = candidates[i];
            /* Full-segment L4 TCP: tunnel immediately after IP (SYN/ACK included). */
            if (transport_off + ns + 1 < (int)pkt_len &&
                pkt[transport_off + ns + 1] == L4_TUNNEL_MAGIC) {
                *nonce_size_out = ns;
                *policy_id_out = (uint8_t)(pkt[transport_off + ns] & 0x7F);
                return 0;
            }
            /* Legacy: tunnel after TCP header. */
            if (legacy_tun + ns + 1 < (int)pkt_len &&
                pkt[legacy_tun + ns + 1] == L4_TUNNEL_MAGIC) {
                *nonce_size_out = ns;
                *policy_id_out = (uint8_t)(pkt[legacy_tun + ns] & 0x7F);
                return 0;
            }
        }
        return -1;
    }

    if (ip_proto == 17) {
        int tunnel_off = transport_off + 8;
        if (tunnel_off >= (int)pkt_len)
            return -1;
        for (int i = 0; i < 4; i++) {
            int ns = candidates[i];
            if (tunnel_off + ns + 1 >= (int)pkt_len)
                continue;
            if (pkt[tunnel_off + ns + 1] == L4_TUNNEL_MAGIC) {
                *nonce_size_out = ns;
                *policy_id_out = (uint8_t)(pkt[tunnel_off + ns] & 0x7F);
                return 0;
            }
        }
    }

    return -1;
}

static int l3_extract_policy_id(uint8_t *pkt, uint32_t pkt_len,
                                uint8_t *policy_id_out) {
    if (!pkt || !policy_id_out || pkt_len < 14 + 20)
        return -1;

    uint16_t ether_type = ((uint16_t)pkt[12] << 8) | pkt[13];
    int l3_off;
    int ip_hdr_len;
    uint8_t proto;
    uint8_t marker = 99;
    int nonce_size = packet_crypto_get_nonce_size();

    if (ether_type == 0x0800) {
        l3_off = 14;
        ip_hdr_len = (pkt[l3_off] & 0x0F) * 4;
        if (ip_hdr_len < 20 || pkt_len < (uint32_t)(l3_off + ip_hdr_len + 1))
            return -1;
        proto = pkt[l3_off + 9];
    } else if (ether_type == 0x86DD) {
        l3_off = 14;
        ip_hdr_len = 40;
        if (pkt_len < (uint32_t)(l3_off + ip_hdr_len + 1))
            return -1;
        proto = pkt[l3_off + 6];
    } else {
        return -1;
    }

    if (proto != marker)
        return -1;

    int tunnel_off = l3_off + ip_hdr_len;
    if (tunnel_off + nonce_size >= (int)pkt_len)
        return -1;

    *policy_id_out = (uint8_t)(pkt[tunnel_off + nonce_size] & 0x7F);
    return 0;
}

static int decrypt_packet_auto_by_action(struct forwarder *fwd,
                                           uint8_t *pkt, uint32_t *pkt_len,
                                           int action_layer,
                                           uint8_t *scratch, size_t scratch_sz) {
    if (!crypto_enabled || !fwd || !fwd->cfg || !pkt || !pkt_len)
        return -1;

    if (fwd->cfg->policy_count <= 0) {
        apply_default_crypto_params(fwd);
        int new_len = packet_decrypt(&crypto_ctx, pkt, *pkt_len);
        if (new_len < 0) return -1;
        *pkt_len = (uint32_t)new_len;
        return 0;
    }

    if (action_layer == POLICY_ACTION_ENCRYPT_L3) {
        uint8_t policy_id = 0;
        if (l3_extract_policy_id(pkt, *pkt_len, &policy_id) != 0)
            return 0;

        for (int pi = 0; pi < fwd->cfg->policy_count && pi < MAX_CRYPTO_POLICIES; pi++) {
            const struct crypto_policy *cp = &fwd->cfg->policies[pi];
            if (!cp || cp->action != POLICY_ACTION_ENCRYPT_L3)
                continue;
            if (!g_policy_crypto_ctx_ready[pi])
                continue;
            if ((uint8_t)(cp->id & 0x7F) != policy_id)
                continue;

            apply_crypto_params_from_policy(cp);
            int new_len = packet_decrypt(&g_policy_crypto_ctx[pi], pkt, *pkt_len);
            if (new_len < 0)
                return -1;
            *pkt_len = (uint32_t)new_len;
            return 0;
        }
        return -1;
    }

    if (action_layer == POLICY_ACTION_ENCRYPT_L4) {
        int l3_off = crypto_eth_ipv4_offset(pkt, *pkt_len);
        if (l3_off < 0)
            return 0;

        uint8_t ip_hdr_len = (pkt[l3_off] & 0x0F) * 4;
        if (ip_hdr_len < 20)
            return 0;

        if (*pkt_len < (uint32_t)(l3_off + ip_hdr_len + 8))
            return 0;

        uint8_t ip_proto = pkt[l3_off + 9];
        if (ip_proto != 6 && ip_proto != 17)
            return 0;

        int transport_off = l3_off + ip_hdr_len;
        const uint8_t L4_TUNNEL_MAGIC = 0xA5;

        int tcp_hdr_len = 0;
        if (ip_proto == 6) {
            if (*pkt_len < (uint32_t)(transport_off + 20))
                return 0;
            tcp_hdr_len = ((pkt[transport_off + 12] >> 4) & 0x0F) * 4;
            if (tcp_hdr_len < 20)
                return 0;
        }

        /* Strict match: only decrypt when magic + policy_id match same L4 policy.
         * This avoids false-positive "magic" hits on plain TCP bytes. */
        for (int pi = 0; pi < fwd->cfg->policy_count && pi < MAX_CRYPTO_POLICIES; pi++) {
            const struct crypto_policy *cp = &fwd->cfg->policies[pi];
            if (!cp || cp->action != POLICY_ACTION_ENCRYPT_L4)
                continue;
            if (!g_policy_crypto_ctx_ready[pi] || cp->nonce_size <= 0)
                continue;

            int ns = cp->nonce_size;
            int tunnel_off = -1;

            if (ip_proto == 6) {
                int off_new = transport_off;
                if (off_new + ns + 1 < (int)*pkt_len &&
                    pkt[off_new + ns + 1] == L4_TUNNEL_MAGIC &&
                    ((uint8_t)(pkt[off_new + ns] & 0x7F) == (uint8_t)(cp->id & 0x7F)) &&
                    ((pkt[off_new] & 0x80) == 0)) {
                    tunnel_off = off_new;
                } else {
                    int off_legacy = transport_off + tcp_hdr_len;
                    if (off_legacy + ns + 1 < (int)*pkt_len &&
                        pkt[off_legacy + ns + 1] == L4_TUNNEL_MAGIC &&
                        ((uint8_t)(pkt[off_legacy + ns] & 0x7F) == (uint8_t)(cp->id & 0x7F)) &&
                        ((pkt[off_legacy] & 0x80) == 0)) {
                        tunnel_off = off_legacy;
                    }
                }
            } else {
                int off_udp = transport_off + 8;
                if (off_udp + ns + 1 < (int)*pkt_len &&
                    pkt[off_udp + ns + 1] == L4_TUNNEL_MAGIC &&
                    ((uint8_t)(pkt[off_udp + ns] & 0x7F) == (uint8_t)(cp->id & 0x7F)) &&
                    ((pkt[off_udp] & 0x80) == 0)) {
                    tunnel_off = off_udp;
                }
            }

            if (tunnel_off < 0)
                continue;

            apply_crypto_params_from_policy(cp);
            int new_len = packet_decrypt(&g_policy_crypto_ctx[pi], pkt, *pkt_len);
            if (new_len < 0)
                return -1;
            *pkt_len = (uint32_t)new_len;
            return 0;
        }

        /* Not an L4-encrypted packet for any configured policy => pass through. */
        return 0;
    }

    /* Fallback brute-force for non-implemented cases (mainly L4). */
    for (int pi = 0; pi < fwd->cfg->policy_count && pi < MAX_CRYPTO_POLICIES; pi++) {
        const struct crypto_policy *cp = &fwd->cfg->policies[pi];
        if (!cp || cp->action != action_layer)
            continue;
        if (!g_policy_crypto_ctx_ready[pi])
            continue;

        if (*pkt_len > scratch_sz)
            return -1;

        memcpy(scratch, pkt, *pkt_len);
        apply_crypto_params_from_policy(cp);
        int new_len = packet_decrypt(&g_policy_crypto_ctx[pi], pkt, *pkt_len);
        if (new_len < 0) {
            memcpy(pkt, scratch, *pkt_len);
            continue;
        }
        *pkt_len = (uint32_t)new_len;
        return 0;
    }

    return -1;
}

static int frag_decrypt_fragment_auto_l3(struct forwarder *fwd,
                                          uint8_t *pkt, size_t pkt_len,
                                          uint16_t *frag_pkt_id,
                                          uint8_t *frag_index,
                                          uint8_t *scratch, size_t scratch_sz) {
    if (!crypto_enabled || !fwd || !fwd->cfg || !pkt || !frag_pkt_id || !frag_index)
        return -1;

    if (fwd->cfg->policy_count <= 0) {
        apply_default_crypto_params(fwd);
        return frag_decrypt_fragment(&crypto_ctx, pkt, pkt_len, frag_pkt_id, frag_index);
    }

    uint8_t policy_id = 0;
    if (l3_extract_policy_id(pkt, (uint32_t)pkt_len, &policy_id) != 0) {
        return -1;
    }

    for (int pi = 0; pi < fwd->cfg->policy_count && pi < MAX_CRYPTO_POLICIES; pi++) {
        const struct crypto_policy *cp = &fwd->cfg->policies[pi];
        if (!cp || cp->action != POLICY_ACTION_ENCRYPT_L3)
            continue;
        if (!g_policy_crypto_ctx_ready[pi])
            continue;
        if ((uint8_t)(cp->id & 0x7F) != policy_id)
            continue;

        apply_crypto_params_from_policy(cp);
        int dec_len = frag_decrypt_fragment(&g_policy_crypto_ctx[pi],
                                             pkt, pkt_len, frag_pkt_id, frag_index);
        if (dec_len < 0)
            return -1;
        return dec_len;
    }

    return -1;
}

static int frag_decrypt_fragment_auto_l4(struct forwarder *fwd,
                                           uint8_t *pkt, size_t pkt_len,
                                           uint16_t *frag_pkt_id,
                                           uint8_t *frag_index) {
    if (!crypto_enabled || !fwd || !fwd->cfg || !pkt || !frag_pkt_id || !frag_index)
        return -1;

    if (fwd->cfg->policy_count <= 0) {
        apply_default_crypto_params(fwd);
        return frag_decrypt_fragment_l4(&crypto_ctx, pkt, pkt_len, frag_pkt_id, frag_index);
    }

    uint8_t policy_id = 0;
    int nonce_size = 0;
    if (l4_extract_policy_id_ipv4(pkt, (uint32_t)pkt_len, &policy_id, &nonce_size) != 0) {
        return -1;
    }

    for (int pi = 0; pi < fwd->cfg->policy_count && pi < MAX_CRYPTO_POLICIES; pi++) {
        const struct crypto_policy *cp = &fwd->cfg->policies[pi];
        if (!cp || cp->action != POLICY_ACTION_ENCRYPT_L4)
            continue;
        if (!g_policy_crypto_ctx_ready[pi])
            continue;
        if ((uint8_t)(cp->id & 0x7F) != policy_id)
            continue;
        if (cp->nonce_size != nonce_size)
            continue;

        apply_crypto_params_from_policy(cp);
        int dec_len = frag_decrypt_fragment_l4(&g_policy_crypto_ctx[pi],
                                                 pkt, pkt_len,
                                                 frag_pkt_id, frag_index);
        if (dec_len < 0)
            return -1;
        return dec_len;
    }

    return -1;
}

static void sigint_handler(int sig) {
    (void)sig;
    running = 0;
}

static uint32_t get_dest_ip(void *pkt_data, uint32_t pkt_len) {
    if (pkt_len < sizeof(struct ether_header) + sizeof(struct iphdr))
        return 0;
    struct ether_header *eth = (struct ether_header *)pkt_data;
    if (ntohs(eth->ether_type) != ETHERTYPE_IP)
        return 0;
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    return ip->daddr;
}

static int parse_flow(void *pkt_data, uint32_t pkt_len,
                      uint32_t *src_ip, uint32_t *dst_ip,
                      uint16_t *src_port, uint16_t *dst_port,
                      uint8_t *protocol) {
    uint8_t *pkt = (uint8_t *)pkt_data;
    int l3_off = crypto_eth_ipv4_offset(pkt, pkt_len);
    if (l3_off < 0)
        return -1;
    if (pkt_len < (uint32_t)(l3_off + 20))
        return -1;

    struct iphdr *ip = (struct iphdr *)(pkt + l3_off);
    *src_ip = ip->saddr;
    *dst_ip = ip->daddr;
    *protocol = ip->protocol;

    int ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < 20)
        return -1;
    uint8_t *transport = pkt + l3_off + ip_hdr_len;

    if (ip->protocol == IPPROTO_TCP) {
        if (pkt_len < (uint32_t)(l3_off + ip_hdr_len + (int)sizeof(struct tcphdr)))
            return -1;
        struct tcphdr *tcp = (struct tcphdr *)transport;
        *src_port = ntohs(tcp->source);
        *dst_port = ntohs(tcp->dest);
    } else if (ip->protocol == IPPROTO_UDP) {
        if (pkt_len < (uint32_t)(l3_off + ip_hdr_len + (int)sizeof(struct udphdr)))
            return -1;
        struct udphdr *udp = (struct udphdr *)transport;
        *src_port = ntohs(udp->source);
        *dst_port = ntohs(udp->dest);
    } else {
        *src_port = 0;
        *dst_port = 0;
    }

    return 0;
}

static inline uint32_t flow_hash_local_tq(uint32_t src_ip, uint32_t dst_ip,
                                          uint16_t src_port, uint16_t dst_port,
                                          uint8_t protocol) {
    uint32_t h = src_ip ^ dst_ip;
    h ^= ((uint32_t)src_port << 16) | dst_port;
    h ^= protocol;
    h ^= (h >> 16);
    h *= 0x85ebca6b;
    h ^= (h >> 13);
    h *= 0xc2b2ae35;
    h ^= (h >> 16);
    return h;
}

static void *gc_thread(void *arg) {
    (void)arg;
    while (running) {
        sleep(60); 
        flow_table_gc(&g_flow_table);
    }
    return NULL;
}



static void *local_queue_thread_no_crypto(void *arg) {
    struct queue_thread_args *args = (struct queue_thread_args *)arg;
    struct forwarder *fwd = args->fwd;

    pin_thread_to_core(args->core_id);
    int local_idx = args->iface_idx;
    int queue_idx = args->queue_idx;
    int tx_base = args->tx_queue_base;

    struct xsk_interface *local = &fwd->locals[local_idx];
    int batch_size = local->batch_size;

    void *pkt_ptrs[MAX_BATCH_SIZE];
    uint32_t pkt_lens[MAX_BATCH_SIZE];
    uint64_t addrs[MAX_BATCH_SIZE];

    while (running) {
        int rcvd = interface_recv_single_queue(local, queue_idx,
                                               pkt_ptrs, pkt_lens, addrs, batch_size);
        if (rcvd <= 0)
            continue;

        int wan_used[MAX_INTERFACES] = {0};
        int wan_tx_q[MAX_INTERFACES];
        for (int w = 0; w < fwd->wan_count; w++)
            wan_tx_q[w] = tx_base % fwd->wans[w].queue_count;

        for (int i = 0; i < rcvd; i++) {
            uint32_t src_ip, dst_ip;
            uint16_t src_port, dst_port;
            uint8_t protocol;

            int wan_idx;
            if (parse_flow(pkt_ptrs[i], pkt_lens[i],
                           &src_ip, &dst_ip, &src_port, &dst_port, &protocol) == 0) {
                wan_idx = select_wan_idx_for_packet(fwd,
                                                    src_ip, dst_ip, src_port, dst_port,
                                                    protocol, pkt_lens[i]);
            } else {
                wan_idx = 0;
            }

            if (wan_idx < 0 || wan_idx >= fwd->wan_count)
                wan_idx = 0;

            struct xsk_interface *wan = &fwd->wans[wan_idx];
            int tq = wan_tx_q[wan_idx];
            uint8_t *pkt = (uint8_t *)pkt_ptrs[i];

            if (set_wan_l2_addrs(fwd, wan_idx, pkt) != 0) {
                __sync_fetch_and_add(&fwd->total_dropped, 1);
                continue;
            }

            if (interface_send_batch_queue(wan, tq, pkt, pkt_lens[i]) == 0) {
                __sync_fetch_and_add(&fwd->local_to_wan, 1);
                wan_used[wan_idx] = 1;
            } else {
                __sync_fetch_and_add(&fwd->total_dropped, 1);
            }
        }

        for (int w = 0; w < fwd->wan_count; w++) {
            if (wan_used[w])
                interface_send_flush_queue(&fwd->wans[w], wan_tx_q[w]);
        }

        interface_recv_release_single_queue(local, queue_idx, addrs, rcvd);
    }

    return NULL;
}

static void *wan_queue_thread_no_crypto(void *arg) {
    struct queue_thread_args *args = (struct queue_thread_args *)arg;
    struct forwarder *fwd = args->fwd;
    pin_thread_to_core(args->core_id);
    int wan_idx = args->iface_idx;
    int queue_idx = args->queue_idx;
    int tx_base = args->tx_queue_base;

    struct xsk_interface *wan = &fwd->wans[wan_idx];
    int batch_size = wan->batch_size;

    void *pkt_ptrs[MAX_BATCH_SIZE];
    uint32_t pkt_lens[MAX_BATCH_SIZE];
    uint64_t addrs[MAX_BATCH_SIZE];

    while (running) {
        int rcvd = interface_recv_single_queue(wan, queue_idx,
                                                pkt_ptrs, pkt_lens, addrs, batch_size);
        if (rcvd <= 0)
            continue;

        uint32_t local_used_queues[MAX_INTERFACES] = {0};

        for (int i = 0; i < rcvd; i++) {
            uint8_t *pkt = (uint8_t *)pkt_ptrs[i];
            uint32_t pkt_len = pkt_lens[i];

            uint32_t dest_ip = get_dest_ip(pkt, pkt_len);
            if (dest_ip == 0) {
                __sync_fetch_and_add(&fwd->total_dropped, 1);
                __sync_fetch_and_add(&fwd->dropped_bad_ip, 1);
                continue;
            }

            int local_idx = config_find_local_for_ip(fwd->cfg, dest_ip);
            if (local_idx < 0) {
                __sync_fetch_and_add(&fwd->total_dropped, 1);
                __sync_fetch_and_add(&fwd->dropped_no_local_match, 1);
                continue;
            }

            struct xsk_interface *local_iface = &fwd->locals[local_idx];
            struct local_config  *local_cfg   = &fwd->cfg->locals[local_idx];
            int nq = local_iface->queue_count;
            if (nq <= 0) nq = 1;

            int tq;
            {
                uint32_t src_ip, dst_ip;
                uint16_t src_port, dst_port;
                uint8_t protocol;
                if (parse_flow(pkt, pkt_len, &src_ip, &dst_ip, &src_port, &dst_port, &protocol) == 0)
                    tq = (int)(flow_hash_local_tq(src_ip, dst_ip, src_port, dst_port, protocol) % (uint32_t)nq);
                else
                    tq = args->wan_worker_index >= 0 ? (args->wan_worker_index % nq) : (tx_base % nq);
            }

            
            uint8_t dst_mac[6];
            if (arp_cache_lookup(&g_arp[local_idx], dest_ip, dst_mac)) {
                memcpy(pkt, dst_mac, 6);
                memcpy(pkt + 6, g_arp[local_idx].if_mac, 6);
            } else {
                arp_send_request(&g_arp[local_idx], dest_ip);
                __sync_fetch_and_add(&fwd->total_dropped, 1);
                interface_recv_release_single_queue(wan, queue_idx, &addrs[i], 1);
                continue;
            }

            if (interface_send_to_local_batch_queue(local_iface, tq, local_cfg, pkt, pkt_len) == 0) {
                __sync_fetch_and_add(&fwd->wan_to_local, 1);
                local_used_queues[local_idx] |= (1u << tq);
            } else {
                __sync_fetch_and_add(&fwd->total_dropped, 1);
                __sync_fetch_and_add(&fwd->dropped_local_tx_fail, 1);
            }
        }

        for (int l = 0; l < fwd->local_count; l++) {
            if (local_used_queues[l]) {
                for (int q = 0; q < fwd->locals[l].queue_count && q < 32; q++) {
                    if (local_used_queues[l] & (1u << q))
                        interface_send_flush_queue(&fwd->locals[l], q);
                }
            }
        }

        interface_recv_release_single_queue(wan, queue_idx, addrs, rcvd);
    }

    return NULL;
}

static void *local_queue_thread_l2(void *arg) {
    struct queue_thread_args *args = (struct queue_thread_args *)arg;
    struct forwarder *fwd = args->fwd;

    pin_thread_to_core(args->core_id);
    int local_idx = args->iface_idx;
    int queue_idx = args->queue_idx;
    int tx_base = args->tx_queue_base;

    struct xsk_interface *local = &fwd->locals[local_idx];
    int batch_size = local->batch_size;

    void *pkt_ptrs[MAX_BATCH_SIZE];
    uint32_t pkt_lens[MAX_BATCH_SIZE];
    uint64_t addrs[MAX_BATCH_SIZE];

    while (running) {
        int rcvd = interface_recv_single_queue(local, queue_idx,
                                               pkt_ptrs, pkt_lens, addrs, batch_size);
        if (rcvd <= 0)
            continue;

        int wan_used[MAX_INTERFACES] = {0};
        int wan_tx_q[MAX_INTERFACES];
        for (int w = 0; w < fwd->wan_count; w++)
            wan_tx_q[w] = tx_base % fwd->wans[w].queue_count;

        for (int i = 0; i < rcvd; i++) {
            uint32_t src_ip, dst_ip;
            uint16_t src_port, dst_port;
            uint8_t protocol;

            int wan_idx;
            if (parse_flow(pkt_ptrs[i], pkt_lens[i],
                           &src_ip, &dst_ip, &src_port, &dst_port, &protocol) == 0) {
                wan_idx = select_wan_idx_for_packet(fwd,
                                                    src_ip, dst_ip, src_port, dst_port,
                                                    protocol, pkt_lens[i]);
            } else {
                wan_idx = 0;
            }

            if (wan_idx < 0 || wan_idx >= fwd->wan_count)
                wan_idx = 0;

            struct xsk_interface *wan = &fwd->wans[wan_idx];
            int tq = wan_tx_q[wan_idx];

            uint32_t pkt_len = pkt_lens[i];
            uint8_t *pkt = (uint8_t *)pkt_ptrs[i];

            if (set_wan_l2_addrs(fwd, wan_idx, pkt) != 0) {
                __sync_fetch_and_add(&fwd->total_dropped, 1);
                continue;
            }

            const struct crypto_policy *cp = select_crypto_policy_for_packet(fwd,
                                                                             src_ip, dst_ip,
                                                                             src_port, dst_port,
                                                                             protocol);
            struct packet_crypto_ctx *use_ctx = &crypto_ctx;
            int bypass_crypto = 0;

            if (cp) {
                if (cp->action == POLICY_ACTION_BYPASS) {
                    bypass_crypto = 1;
                } else if (cp->action != POLICY_ACTION_ENCRYPT_L2) {
                    /* Mixed layers within a single forwarder instance are not supported yet. */
                    bypass_crypto = 1;
                } else {
                    int pi = (int)(cp - fwd->cfg->policies);
                    if (pi >= 0 && pi < MAX_CRYPTO_POLICIES && g_policy_crypto_ctx_ready[pi]) {
                        use_ctx = &g_policy_crypto_ctx[pi];
                    } else {
                        bypass_crypto = 1;
                    }
                    if (!bypass_crypto)
                        apply_crypto_params_from_policy(cp);
                }
            } else {
                /* If no policy matches (e.g. redirect-all debugging), do not encrypt. */
                bypass_crypto = 1;
            }

            if (bypass_crypto) {
                if (interface_send_batch_queue(wan, tq, pkt_ptrs[i], pkt_len) == 0) {
                    __sync_fetch_and_add(&fwd->local_to_wan, 1);
                    wan_used[wan_idx] = 1;
                } else {
                    __sync_fetch_and_add(&fwd->total_dropped, 1);
                }
                continue;
            }
            if (encrypt_packet_with_ctx(use_ctx, pkt_ptrs[i], &pkt_len) != 0) {
                __sync_fetch_and_add(&fwd->total_dropped, 1);
                continue;
            }

            if (interface_send_batch_queue(wan, tq, pkt_ptrs[i], pkt_len) == 0) {
                __sync_fetch_and_add(&fwd->local_to_wan, 1);
                wan_used[wan_idx] = 1;
            } else {
                __sync_fetch_and_add(&fwd->total_dropped, 1);
            }
        }

        for (int w = 0; w < fwd->wan_count; w++) {
            if (wan_used[w])
                interface_send_flush_queue(&fwd->wans[w], wan_tx_q[w]);
        }

        interface_recv_release_single_queue(local, queue_idx, addrs, rcvd);
    }

    return NULL;
}

static void *local_queue_thread_l3l4(void *arg) {
    struct queue_thread_args *args = (struct queue_thread_args *)arg;
    struct forwarder *fwd = args->fwd;

    pin_thread_to_core(args->core_id);
    int local_idx = args->iface_idx;
    int queue_idx = args->queue_idx;
    int tx_base = args->tx_queue_base;

    struct xsk_interface *local = &fwd->locals[local_idx];
    int batch_size = local->batch_size;

    void *pkt_ptrs[MAX_BATCH_SIZE];
    uint32_t pkt_lens[MAX_BATCH_SIZE];
    uint64_t addrs[MAX_BATCH_SIZE];

    while (running) {
        int rcvd = interface_recv_single_queue(local, queue_idx,
                                               pkt_ptrs, pkt_lens, addrs, batch_size);
        if (rcvd <= 0)
            continue;

        /* L3/L4: enqueue to worker ring */
        for (int i = 0; i < rcvd; i++) {
            struct packet_job job;
            job.fwd = fwd;
            job.local_idx = local_idx;
            job.queue_idx = queue_idx;
            job.tx_queue_base = tx_base;
            job.pkt_ptr = pkt_ptrs[i];
            job.pkt_len = pkt_lens[i];
            job.addr = addrs[i];

            uint32_t src_ip, dst_ip;
            uint16_t src_port, dst_port;
            uint8_t protocol;
            uint32_t key_hash;
            if (parse_flow(job.pkt_ptr, job.pkt_len,
                           &src_ip, &dst_ip,
                           &src_port, &dst_port,
                           &protocol) == 0) {
                key_hash = flow_hash_local_tq(src_ip, dst_ip, src_port, dst_port, protocol);
            } else {
                key_hash = __sync_fetch_and_add(&g_dispatch_counter, 1);
            }

            uint32_t target = key_hash % NUM_WORKERS;
            struct worker_ring *ring = &g_worker_rings[target];

            int enqueued = 0;
            pthread_mutex_lock(&ring->lock);
            uint32_t next_tail = (ring->tail + 1) % WORKER_RING_SIZE;
            if (next_tail != ring->head) {
                ring->jobs[ring->tail] = job;
                ring->tail = next_tail;
                enqueued = 1;
            }
            pthread_mutex_unlock(&ring->lock);

            if (!enqueued) {
                __sync_fetch_and_add(&fwd->total_dropped, 1);
                interface_recv_release_single_queue(local, queue_idx, &addrs[i], 1);
            }
        }
    }

    return NULL;
}



static void *wan_queue_thread_l2(void *arg) {
    struct queue_thread_args *args = (struct queue_thread_args *)arg;
    struct forwarder *fwd = args->fwd;
    pin_thread_to_core(args->core_id);
    int wan_idx = args->iface_idx;
    int queue_idx = args->queue_idx;
    int tx_base = args->tx_queue_base;

    struct xsk_interface *wan = &fwd->wans[wan_idx];
    int batch_size = wan->batch_size;

    void *pkt_ptrs[MAX_BATCH_SIZE];
    uint32_t pkt_lens[MAX_BATCH_SIZE];
    uint64_t addrs[MAX_BATCH_SIZE];
    uint8_t decrypt_scratch[8192];

    while (running) {
        int rcvd = interface_recv_single_queue(wan, queue_idx,
                                                pkt_ptrs, pkt_lens, addrs, batch_size);
        if (rcvd <= 0)
            continue;

        uint32_t local_used_queues[MAX_INTERFACES] = {0};

        for (int i = 0; i < rcvd; i++) {
            uint8_t *pkt = (uint8_t *)pkt_ptrs[i];
            uint32_t pkt_len = pkt_lens[i];
            uint8_t *final_pkt = pkt;
            uint32_t final_len = pkt_len;

            /* L2 decrypt */
            if (decrypt_packet_auto_l2(fwd, pkt, &pkt_len,
                                        decrypt_scratch, sizeof(decrypt_scratch)) != 0) {
                __sync_fetch_and_add(&fwd->total_dropped, 1);
                continue;
            }
            final_pkt = pkt;
            final_len = pkt_len;

            /* Forward to local */
            uint32_t dest_ip = get_dest_ip(final_pkt, final_len);
            if (dest_ip == 0) {
                __sync_fetch_and_add(&fwd->total_dropped, 1);
                __sync_fetch_and_add(&fwd->dropped_bad_ip, 1);
                continue;
            }

            int local_idx = config_find_local_for_ip(fwd->cfg, dest_ip);
            if (local_idx < 0) {
                __sync_fetch_and_add(&fwd->total_dropped, 1);
                __sync_fetch_and_add(&fwd->dropped_no_local_match, 1);
                continue;
            }

            struct xsk_interface *local_iface = &fwd->locals[local_idx];
            struct local_config  *local_cfg   = &fwd->cfg->locals[local_idx];
            int nq = local_iface->queue_count;
            if (nq <= 0) nq = 1;

            int tq;
            {
                uint32_t src_ip, dst_ip;
                uint16_t src_port, dst_port;
                uint8_t protocol;
                if (parse_flow(final_pkt, final_len, &src_ip, &dst_ip, &src_port, &dst_port, &protocol) == 0)
                    tq = (int)(flow_hash_local_tq(src_ip, dst_ip, src_port, dst_port, protocol) % (uint32_t)nq);
                else
                    tq = args->wan_worker_index >= 0 ? (args->wan_worker_index % nq) : (tx_base % nq);
            }

            uint8_t dst_mac[6];
            if (arp_cache_lookup(&g_arp[local_idx], dest_ip, dst_mac)) {
                memcpy(final_pkt, dst_mac, 6);
                memcpy(final_pkt + 6, g_arp[local_idx].if_mac, 6);
            } else {
                arp_send_request(&g_arp[local_idx], dest_ip);
                __sync_fetch_and_add(&fwd->total_dropped, 1);
                continue;
            }

            if (interface_send_to_local_batch_queue(local_iface, tq, local_cfg, final_pkt, final_len) == 0) {
                __sync_fetch_and_add(&fwd->wan_to_local, 1);
                if (tq < 32)
                    local_used_queues[local_idx] |= (1u << tq);
            } else {
                __sync_fetch_and_add(&fwd->total_dropped, 1);
                __sync_fetch_and_add(&fwd->dropped_local_tx_fail, 1);
            }
        }

        for (int l = 0; l < fwd->local_count; l++) {
            for (int q = 0; q < fwd->locals[l].queue_count && q < 32; q++)
                if (local_used_queues[l] & (1u << q))
                    interface_send_to_local_flush_queue(&fwd->locals[l], q);
        }

        interface_recv_release_single_queue(wan, queue_idx, addrs, rcvd);

    }
    return NULL;
}



static void *wan_queue_thread_l3l4(void *arg) {
    struct queue_thread_args *args = (struct queue_thread_args *)arg;
    struct forwarder *fwd = args->fwd;
    pin_thread_to_core(args->core_id);
    int wan_idx = args->iface_idx;
    int queue_idx = args->queue_idx;
    int tx_base = args->tx_queue_base;

    struct xsk_interface *wan = &fwd->wans[wan_idx];
    int batch_size = wan->batch_size;

    void *pkt_ptrs[MAX_BATCH_SIZE];
    uint32_t pkt_lens[MAX_BATCH_SIZE];
    uint64_t addrs[MAX_BATCH_SIZE];
    uint8_t decrypt_scratch[8192];

    while (running) {
        int rcvd = interface_recv_single_queue(wan, queue_idx,
                                                pkt_ptrs, pkt_lens, addrs, batch_size);
        if (rcvd <= 0)
            continue;

        uint32_t local_used_queues[MAX_INTERFACES] = {0};

        for (int i = 0; i < rcvd; i++) {
            uint8_t *pkt = (uint8_t *)pkt_ptrs[i];
            uint32_t pkt_len = pkt_lens[i];
            uint8_t *final_pkt = pkt;
            uint32_t final_len = pkt_len;

            (void)0;

            if (crypto_enabled && crypto_layer == POLICY_ACTION_ENCRYPT_L3 &&
                fwd->cfg && fwd->cfg->policy_count > 0) {
                uint8_t policy_id = 0;
                int found = 0;
                if (l3_extract_policy_id(pkt, pkt_len, &policy_id) == 0) {
                    for (int pi = 0; pi < fwd->cfg->policy_count && pi < MAX_CRYPTO_POLICIES; pi++) {
                        const struct crypto_policy *cp = &fwd->cfg->policies[pi];
                        if (!cp || cp->action != POLICY_ACTION_ENCRYPT_L3)
                            continue;
                        if (!g_policy_crypto_ctx_ready[pi])
                            continue;
                        if ((uint8_t)(cp->id & 0x7F) != policy_id)
                            continue;
                        apply_crypto_params_from_policy(cp);
                        found = 1;
                        break;
                    }
                }
                if (!found)
                    apply_default_crypto_params(fwd);
            }

            /* Mixed-layer decrypt dispatch:
             * 1) If L2 marker present, decrypt L2 first.
             * 2) Then attempt L3 decrypt (auto bypass if not encrypted/matching).
             * 3) Then attempt L4 decrypt (auto bypass if not encrypted/matching).
             */
            {
                uint8_t pkt_marker = pkt[12];
                uint16_t fake_ipv4 = packet_crypto_get_fake_ethertype_ipv4();
                uint16_t fake_ipv6 = packet_crypto_get_fake_ethertype_ipv6();
                int has_l2_marker =
                    ((fake_ipv4 && pkt_marker == (uint8_t)(fake_ipv4 >> 8)) ||
                     (fake_ipv6 && pkt_marker == (uint8_t)(fake_ipv6 >> 8)));
                if (has_l2_marker) {
                    if (decrypt_packet_auto_l2(fwd, pkt, &pkt_len,
                                               decrypt_scratch,
                                               sizeof(decrypt_scratch)) != 0) {
                        __sync_fetch_and_add(&fwd->total_dropped, 1);
                        continue;
                    }
                }
            }

            if (decrypt_packet_auto_by_action(fwd, pkt, &pkt_len,
                                                POLICY_ACTION_ENCRYPT_L3,
                                                decrypt_scratch,
                                                sizeof(decrypt_scratch)) != 0) {
                __sync_fetch_and_add(&fwd->total_dropped, 1);
                continue;
            }

            if (decrypt_packet_auto_by_action(fwd, pkt, &pkt_len,
                                                POLICY_ACTION_ENCRYPT_L4,
                                                decrypt_scratch,
                                                sizeof(decrypt_scratch)) != 0) {
                __sync_fetch_and_add(&fwd->total_dropped, 1);
                continue;
            }
            final_pkt = pkt;
            final_len = pkt_len;

            /*
             * final_pkt/final_len set above for either:
             * - L4 fragment reassembled
             * - L4 non-fragment decrypted
             * - L3 fragment reassembled
             * - L3 non-fragment decrypted
             */

            /* Forward to local */
            uint32_t dest_ip = get_dest_ip(final_pkt, final_len);
            if (dest_ip == 0) {
                __sync_fetch_and_add(&fwd->total_dropped, 1);
                __sync_fetch_and_add(&fwd->dropped_bad_ip, 1);
                continue;
            }

            int local_idx = config_find_local_for_ip(fwd->cfg, dest_ip);
            if (local_idx < 0) {
                __sync_fetch_and_add(&fwd->total_dropped, 1);
                __sync_fetch_and_add(&fwd->dropped_no_local_match, 1);
                continue;
            }

            struct xsk_interface *local_iface = &fwd->locals[local_idx];
            struct local_config  *local_cfg   = &fwd->cfg->locals[local_idx];
            int nq = local_iface->queue_count;
            if (nq <= 0) nq = 1;

            int tq;
            {
                uint32_t src_ip, dst_ip;
                uint16_t src_port, dst_port;
                uint8_t protocol;
                if (parse_flow(final_pkt, final_len, &src_ip, &dst_ip, &src_port, &dst_port, &protocol) == 0)
                    tq = (int)(flow_hash_local_tq(src_ip, dst_ip, src_port, dst_port, protocol) % (uint32_t)nq);
                else
                    tq = args->wan_worker_index >= 0 ? (args->wan_worker_index % nq) : (tx_base % nq);
            }

            uint8_t dst_mac[6];
            if (arp_cache_lookup(&g_arp[local_idx], dest_ip, dst_mac)) {
                memcpy(final_pkt, dst_mac, 6);
                memcpy(final_pkt + 6, g_arp[local_idx].if_mac, 6);
            } else {
                arp_send_request(&g_arp[local_idx], dest_ip);
                __sync_fetch_and_add(&fwd->total_dropped, 1);
                continue;
            }

            if (interface_send_to_local_batch_queue(local_iface, tq, local_cfg, final_pkt, final_len) == 0) {
                __sync_fetch_and_add(&fwd->wan_to_local, 1);
                if (tq < 32)
                    local_used_queues[local_idx] |= (1u << tq);
            } else {
                __sync_fetch_and_add(&fwd->total_dropped, 1);
                __sync_fetch_and_add(&fwd->dropped_local_tx_fail, 1);
            }
        }

        for (int l = 0; l < fwd->local_count; l++) {
            for (int q = 0; q < fwd->locals[l].queue_count && q < 32; q++)
                if (local_used_queues[l] & (1u << q))
                    interface_send_to_local_flush_queue(&fwd->locals[l], q);
        }

        interface_recv_release_single_queue(wan, queue_idx, addrs, rcvd);

    }
    return NULL;
}

static void *worker_thread(void *arg) {
    struct queue_thread_args *args = (struct queue_thread_args *)arg;
    int worker_id = args->worker_id;

    if (worker_id < 0 || worker_id >= NUM_WORKERS)
        return NULL;

    pin_thread_to_core(args->core_id);

    struct worker_ring *ring = &g_worker_rings[worker_id];
    uint8_t frag1_buf[2048];
    uint8_t frag2_buf[2048];

    while (running) {
        struct packet_job job;
        int has_job = 0;

        pthread_mutex_lock(&ring->lock);
        if (ring->head != ring->tail) {
            job = ring->jobs[ring->head];
            ring->head = (ring->head + 1) % WORKER_RING_SIZE;
            has_job = 1;
        }
        pthread_mutex_unlock(&ring->lock);

        if (!has_job) {
            sched_yield();
            continue;
        }

        struct forwarder *fwd = job.fwd;
        if (!fwd) {
            continue;
        }

        uint32_t wan_tx_q[MAX_INTERFACES];
        int wan_used[MAX_INTERFACES] = {0};
        for (int w = 0; w < fwd->wan_count; w++)
            wan_tx_q[w] = job.tx_queue_base % fwd->wans[w].queue_count;

        uint32_t src_ip = 0, dst_ip = 0;
        uint16_t src_port = 0, dst_port = 0;
        uint8_t protocol = 0;

        int flow_ok = (parse_flow(job.pkt_ptr, job.pkt_len,
                                  &src_ip, &dst_ip, &src_port, &dst_port, &protocol) == 0);

        int wan_idx;
        if (flow_ok) {
            wan_idx = select_wan_idx_for_packet(fwd,
                                                src_ip, dst_ip, src_port, dst_port,
                                                protocol, job.pkt_len);
        } else {
            wan_idx = 0;
        }

        if (wan_idx < 0 || wan_idx >= fwd->wan_count) {
            wan_idx = 0;
        }

        struct xsk_interface *wan = &fwd->wans[wan_idx];
        int tq = wan_tx_q[wan_idx];

        uint32_t pkt_len = job.pkt_len;

        /* Per-packet crypto policy selection (keys/mode/aes_bits/nonce + bypass). */
        const struct crypto_policy *cp = NULL;
        struct packet_crypto_ctx *use_ctx = &crypto_ctx;
        int bypass_crypto = 0;
        if (crypto_enabled) {
            if (!flow_ok) {
                bypass_crypto = 1;
            } else {
                cp = select_crypto_policy_for_packet(fwd,
                                                     src_ip, dst_ip,
                                                     src_port, dst_port,
                                                     protocol);
                if (cp) {
                    if (cp->action == POLICY_ACTION_BYPASS) {
                        bypass_crypto = 1;
                    } else {
                        int pi = (int)(cp - fwd->cfg->policies);
                        if (pi >= 0 && pi < MAX_CRYPTO_POLICIES && g_policy_crypto_ctx_ready[pi]) {
                            use_ctx = &g_policy_crypto_ctx[pi];
                        } else {
                            bypass_crypto = 1;
                        }
                        if (!bypass_crypto)
                            apply_crypto_params_from_policy(cp);
                    }
                } else {
                    /* If no policy matches, do not encrypt (redirect-all debugging). */
                    bypass_crypto = 1;
                }
            }

            if (bypass_crypto) {
                uint8_t *pkt = (uint8_t *)job.pkt_ptr;
                if (set_wan_l2_addrs(fwd, wan_idx, pkt) != 0) {
                    __sync_fetch_and_add(&fwd->total_dropped, 1);
                    goto release_local;
                }

                if (interface_send_batch_queue(wan, tq, job.pkt_ptr, pkt_len) == 0) {
                    __sync_fetch_and_add(&fwd->local_to_wan, 1);
                    wan_used[wan_idx] = 1;
                } else {
                    __sync_fetch_and_add(&fwd->total_dropped, 1);
                }
                goto skip_encrypt_flush;
            }
        }

        if (!crypto_enabled) {
            uint8_t *pkt = (uint8_t *)job.pkt_ptr;
            if (set_wan_l2_addrs(fwd, wan_idx, pkt) != 0) {
                __sync_fetch_and_add(&fwd->total_dropped, 1);
                goto release_local;
            }

            if (interface_send_batch_queue(wan, tq, pkt, pkt_len) == 0) {
                __sync_fetch_and_add(&fwd->local_to_wan, 1);
                wan_used[wan_idx] = 1;
            } else {
                __sync_fetch_and_add(&fwd->total_dropped, 1);
            }
        } else if (crypto_layer == 3 && 0) {

            uint8_t *pkt = (uint8_t *)job.pkt_ptr;
            if (set_wan_l2_addrs(fwd, wan_idx, pkt) != 0) {
                __sync_fetch_and_add(&fwd->total_dropped, 1);
                goto release_local;
            }

            uint32_t f1_len = 0, f2_len = 0;
            if (frag_split_and_encrypt(use_ctx,
                                       pkt, pkt_len,
                                       frag1_buf, &f1_len,
                                       frag2_buf, &f2_len) != 0) {
                __sync_fetch_and_add(&fwd->total_dropped, 1);
                goto release_local;
            }

            if (set_wan_l2_addrs(fwd, wan_idx, frag1_buf) != 0 ||
                set_wan_l2_addrs(fwd, wan_idx, frag2_buf) != 0) {
                __sync_fetch_and_add(&fwd->total_dropped, 1);
                goto release_local;
            }

            uint32_t wire_total = f1_len + f2_len;
            if (wire_total > pkt_len) {
                flow_table_add_bytes(&g_flow_table,
                                     src_ip, dst_ip, src_port, dst_port,
                                     protocol, wire_total - pkt_len);
            }

            if (interface_send_batch_queue(wan, tq, frag1_buf, f1_len) == 0) {
                __sync_fetch_and_add(&fwd->local_to_wan, 1);
                wan_used[wan_idx] = 1;
            } else {
                __sync_fetch_and_add(&fwd->total_dropped, 1);
            }

            if (interface_send_batch_queue(wan, tq, frag2_buf, f2_len) == 0) {
                __sync_fetch_and_add(&fwd->local_to_wan, 1);
            } else {
                __sync_fetch_and_add(&fwd->total_dropped, 1);
            }

        } else if (crypto_layer == 2 && 0) {

            uint8_t *pkt = (uint8_t *)job.pkt_ptr;
            if (set_wan_l2_addrs(fwd, wan_idx, pkt) != 0) {
                __sync_fetch_and_add(&fwd->total_dropped, 1);
                goto release_local;
            }

            uint32_t f1_len = 0, f2_len = 0;
            if (frag_split_and_encrypt_l2(&crypto_ctx,
                                          pkt, pkt_len,
                                          frag1_buf, &f1_len,
                                          frag2_buf, &f2_len) != 0) {
                __sync_fetch_and_add(&fwd->total_dropped, 1);
                goto release_local;
            }

            if (set_wan_l2_addrs(fwd, wan_idx, frag1_buf) != 0 ||
                set_wan_l2_addrs(fwd, wan_idx, frag2_buf) != 0) {
                __sync_fetch_and_add(&fwd->total_dropped, 1);
                goto release_local;
            }

            uint32_t wire_total = f1_len + f2_len;
            if (wire_total > pkt_len) {
                flow_table_add_bytes(&g_flow_table,
                                     src_ip, dst_ip, src_port, dst_port,
                                     protocol, wire_total - pkt_len);
            }

            if (interface_send_batch_queue(wan, tq, frag1_buf, f1_len) == 0) {
                __sync_fetch_and_add(&fwd->local_to_wan, 1);
                wan_used[wan_idx] = 1;
            } else {
                __sync_fetch_and_add(&fwd->total_dropped, 1);
            }

            if (interface_send_batch_queue(wan, tq, frag2_buf, f2_len) == 0) {
                __sync_fetch_and_add(&fwd->local_to_wan, 1);
            } else {
                __sync_fetch_and_add(&fwd->total_dropped, 1);
            }

        } else {
            uint8_t *pkt = (uint8_t *)job.pkt_ptr;
            if (set_wan_l2_addrs(fwd, wan_idx, pkt) != 0) {
                __sync_fetch_and_add(&fwd->total_dropped, 1);
                goto release_local;
            }

            int new_len = -1;
            if (cp) {
                if (cp->action == POLICY_ACTION_ENCRYPT_L2) {
                    new_len = crypto_layer2_encrypt(use_ctx, job.pkt_ptr, pkt_len);
                } else if (cp->action == POLICY_ACTION_ENCRYPT_L3) {
                    new_len = crypto_layer3_encrypt(use_ctx, job.pkt_ptr, pkt_len);
                } else if (cp->action == POLICY_ACTION_ENCRYPT_L4) {
                    new_len = crypto_layer4_encrypt(use_ctx, job.pkt_ptr, pkt_len);
                }
            }

            if (new_len < 0) {
                __sync_fetch_and_add(&fwd->total_dropped, 1);
                goto release_local;
            }
            pkt_len = (uint32_t)new_len;

            if (interface_send_batch_queue(wan, tq, job.pkt_ptr, pkt_len) == 0) {
                __sync_fetch_and_add(&fwd->local_to_wan, 1);
                wan_used[wan_idx] = 1;
            } else {
                __sync_fetch_and_add(&fwd->total_dropped, 1);
            }
        }

skip_encrypt_flush:
        for (int w = 0; w < fwd->wan_count; w++) {
            if (wan_used[w])
                interface_send_flush_queue(&fwd->wans[w], wan_tx_q[w]);
        }

release_local:
        if (job.fwd && job.local_idx >= 0 &&
            job.local_idx < job.fwd->local_count) {
            struct xsk_interface *local = &job.fwd->locals[job.local_idx];
            interface_recv_release_single_queue(local, job.queue_idx, &job.addr, 1);
        }
    }

    return NULL;
}

int forwarder_init(struct forwarder *fwd, struct app_config *cfg) {
    memset(fwd, 0, sizeof(*fwd));
    fwd->cfg = cfg;
    g_cfg_ptr = cfg;

    crypto_enabled = cfg->crypto_enabled;
    crypto_layer = cfg->encrypt_layer;
    int has_encrypt_l2 = 0;
    if (crypto_enabled) {
        packet_crypto_set_aes_bits(cfg->aes_bits);
        if (packet_crypto_init(&crypto_ctx, cfg->crypto_key) != 0) {
            fprintf(stderr, "Failed to initialize AES-%d encryption\n", cfg->aes_bits);
            return -1;
        }

        /* Initialize per-policy crypto contexts (keys derived by AES bits). */
        memset(g_policy_crypto_ctx_ready, 0, sizeof(g_policy_crypto_ctx_ready));
        for (int pi = 0; pi < cfg->policy_count && pi < MAX_CRYPTO_POLICIES; pi++) {
            const struct crypto_policy *cp = &cfg->policies[pi];
            if (!cp)
                continue;
            if (cp->action == POLICY_ACTION_BYPASS)
                continue;

            int key_nonzero = 0;
            for (int k = 0; k < AES_KEY_LEN; k++) {
                if (cp->key[k] != 0) { key_nonzero = 1; break; }
            }
            if (!key_nonzero)
                continue;

            packet_crypto_set_aes_bits(cp->aes_bits);
            if (packet_crypto_init(&g_policy_crypto_ctx[pi], cp->key) != 0) {
                fprintf(stderr, "[DB CRYPTO] Failed to init policy ctx id=%d (AES=%d)\n",
                        cp->id, cp->aes_bits);
                continue;
            }
            g_policy_crypto_ctx_ready[pi] = 1;
        }

        /* Check whether we need L2 fake ethertype markers. */
        for (int pi = 0; pi < cfg->policy_count && pi < MAX_CRYPTO_POLICIES; pi++) {
            if (cfg->policies[pi].action == POLICY_ACTION_ENCRYPT_L2 && g_policy_crypto_ctx_ready[pi]) {
                has_encrypt_l2 = 1;
                break;
            }
        }

        packet_crypto_set_encrypt_layer(cfg->encrypt_layer);
        packet_crypto_set_mode(cfg->crypto_mode);
        packet_crypto_set_nonce_size(cfg->nonce_size);
        if (has_encrypt_l2) {
            if (cfg->fake_ethertype_ipv4 == 0 && cfg->fake_ethertype_ipv6 == 0) {
                /* Runtime default for configs that only set encrypt_layer=2 in DB. */
                cfg->fake_ethertype_ipv4 = 0x88b5;
                cfg->fake_ethertype_ipv6 = 0x88b6;
            }
            packet_crypto_set_ethertype(cfg->fake_ethertype_ipv4, cfg->fake_ethertype_ipv6);
        }
        if (crypto_layer == 2 || crypto_layer == 3) {
            if (cfg->fake_protocol != 0)
                packet_crypto_set_fake_protocol(cfg->fake_protocol);
            else
                packet_crypto_set_fake_protocol(99);
        }
    }

    
    for (int i = 0; i < cfg->local_count; i++) {
        if (cfg->locals[i].queue_count <= 1) {
            int want = 4;
            interface_set_queue_count(cfg->locals[i].ifname, want);
            int hwq = interface_get_queue_count(cfg->locals[i].ifname);
            if (hwq > 1)
                cfg->locals[i].queue_count = hwq;
        }
    }

    
    if (!crypto_enabled) {
        for (int i = 0; i < cfg->wan_count; i++) {
            if (cfg->wans[i].queue_count <= 1) {
                int hwq = interface_get_queue_count(cfg->wans[i].ifname);
                if (hwq > 1)
                    cfg->wans[i].queue_count = hwq;
            }
        }
    }

    uint32_t wan_window_sizes[MAX_INTERFACES] = {0};
    for (int i = 0; i < cfg->wan_count && i < MAX_INTERFACES; i++)
        wan_window_sizes[i] = cfg->wans[i].window_size;
    flow_table_init(&g_flow_table, wan_window_sizes, cfg->wan_count);

    int total_threads = 0;
    for (int i = 0; i < cfg->local_count; i++) {
        interface_set_queue_count(cfg->locals[i].ifname, cfg->locals[i].queue_count);
        total_threads += cfg->locals[i].queue_count;
    }
    for (int i = 0; i < cfg->wan_count; i++) {
        interface_set_queue_count(cfg->wans[i].ifname, cfg->wans[i].queue_count);
        total_threads += cfg->wans[i].queue_count;
    }
    total_threads += NUM_WORKERS;

    for (int i = 0; i < cfg->local_count; i++) {
        if (interface_init_local(&fwd->locals[i], &cfg->locals[i], cfg->bpf_file) != 0) {
            fprintf(stderr, "Failed to init LOCAL %s\n", cfg->locals[i].ifname);
            goto err_locals;
        }
        fwd->local_count++;
    }

    /* Push redirect CIDR rules to XDP config_map after BPF object is loaded. */
    if (cfg->redirect.src_count > 0 || cfg->redirect.dst_count > 0) {
        if (interface_push_redirect_cfg(&cfg->redirect) != 0) {
            fprintf(stderr, "[XDP] Failed to push redirect rules to config_map\n");
            /* Không fail hẳn forwarder: chỉ mất tính năng redirect. */
        }
    }

    
    for (int i = 0; i < fwd->local_count; i++) {
        if (arp_init_for_local(&g_arp[i], &fwd->locals[i]) == 0) {
            pthread_t tid;
            pthread_create(&tid, NULL, arp_listener_thread, &g_arp[i]);
            pthread_detach(tid);
            g_arp_inited = 1;
            fprintf(stderr, "[ARP] ready on %s (ip=%u)\n",
                    g_arp[i].ifname, (unsigned)ntohl(g_arp[i].if_ip));
        }
    }

    for (int i = 0; i < cfg->wan_count; i++) {
        uint16_t wan_fake4 = (crypto_enabled && has_encrypt_l2) ? cfg->fake_ethertype_ipv4 : 0;
        uint16_t wan_fake6 = (crypto_enabled && has_encrypt_l2) ? cfg->fake_ethertype_ipv6 : 0;
        if (interface_init_wan_rx(&fwd->wans[i], &cfg->wans[i], "bpf/xdp_wan_redirect.o", wan_fake4, wan_fake6) != 0) {
            fprintf(stderr, "Failed to init WAN %s\n", cfg->wans[i].ifname);
            goto err_wans;
        }
        fwd->wan_count++;
    }

    /* Optional WAN next-hop ARP (per WAN interface). */
    for (int i = 0; i < fwd->wan_count; i++) {
        if (cfg->wans[i].next_hop_ip == 0)
            continue;
        if (arp_init_for_local(&g_wan_arp[i], &fwd->wans[i]) == 0) {
            pthread_t tid;
            pthread_create(&tid, NULL, arp_listener_thread, &g_wan_arp[i]);
            pthread_detach(tid);
            g_arp_inited = 1;
            log_wan_next_hop_mac(fwd, i);
        } else {
            fprintf(stderr, "[ARP] WARN: cannot init WAN ARP on %s\n", cfg->wans[i].ifname);
        }
    }

    return 0;

err_wans:
    for (int j = 0; j < fwd->wan_count; j++)
        interface_cleanup(&fwd->wans[j]);
err_locals:
    for (int j = 0; j < fwd->local_count; j++)
        interface_cleanup(&fwd->locals[j]);
    flow_table_cleanup(&g_flow_table);
    return -1;
}

void forwarder_cleanup(struct forwarder *fwd) {
    if (crypto_enabled) {
        packet_crypto_cleanup(&crypto_ctx);
    }

    flow_table_cleanup(&g_flow_table);

    for (int i = 0; i < fwd->local_count; i++)
        interface_cleanup(&fwd->locals[i]);
    for (int i = 0; i < fwd->wan_count; i++)
        interface_cleanup(&fwd->wans[i]);
}


static void forwarder_run_no_crypto(struct forwarder *fwd) {
    int total_local_queues = 0;
    for (int i = 0; i < fwd->local_count; i++)
        total_local_queues += fwd->locals[i].queue_count;

    int total_wan_queues = 0;
    for (int i = 0; i < fwd->wan_count; i++)
        total_wan_queues += fwd->wans[i].queue_count;

    int total_threads = total_local_queues + total_wan_queues;

    pthread_t *threads = calloc(total_threads, sizeof(pthread_t));
    struct queue_thread_args *args = calloc(total_threads, sizeof(struct queue_thread_args));
    if (!threads || !args) {
        fprintf(stderr, "[NO-CRYPTO] Failed to allocate thread arrays\n");
        free(threads); free(args);
        return;
    }

    pthread_t gc_tid;
    pthread_create(&gc_tid, NULL, gc_thread, NULL);

    int thread_idx = 0;


    int local_rx_idx = 0;
    for (int i = 0; i < fwd->local_count; i++) {
        struct xsk_interface *local = &fwd->locals[i];
        for (int q = 0; q < local->queue_count; q++) {
            args[thread_idx].fwd = fwd;
            args[thread_idx].iface_idx = i;
            args[thread_idx].queue_idx = q;
            args[thread_idx].tx_queue_base = q;
            args[thread_idx].core_id = local_rx_idx % 4;
            args[thread_idx].wan_worker_index = -1;
            args[thread_idx].worker_id = -1;
            pthread_create(&threads[thread_idx], NULL, local_queue_thread_no_crypto, &args[thread_idx]);
            thread_idx++;
            local_rx_idx++;
        }
    }


    int wan_worker_idx = 0;
    for (int i = 0; i < fwd->wan_count; i++) {
        struct xsk_interface *wan = &fwd->wans[i];
        for (int q = 0; q < wan->queue_count; q++) {
            args[thread_idx].fwd = fwd;
            args[thread_idx].iface_idx = i;
            args[thread_idx].queue_idx = q;
            args[thread_idx].tx_queue_base = q;
            args[thread_idx].core_id = 4 + (wan_worker_idx % 4);
            args[thread_idx].wan_worker_index = wan_worker_idx;
            args[thread_idx].worker_id = -1;
            pthread_create(&threads[thread_idx], NULL, wan_queue_thread_no_crypto, &args[thread_idx]);
            wan_worker_idx++;
            thread_idx++;
        }
    }

    while (running)
        sleep(1);

    for (int i = 0; i < total_threads; i++)
        pthread_join(threads[i], NULL);
    pthread_join(gc_tid, NULL);

    free(threads);
    free(args);
}


static void forwarder_run_l2(struct forwarder *fwd) {
    int total_local_queues = 0;
    for (int i = 0; i < fwd->local_count; i++)
        total_local_queues += fwd->locals[i].queue_count;

    int total_wan_queues = 0;
    for (int i = 0; i < fwd->wan_count; i++)
        total_wan_queues += fwd->wans[i].queue_count;


    fprintf(stderr, "[L2 DEBUG] total_local_queues=%d, total_wan_queues=%d\n",
            total_local_queues, total_wan_queues);
    for (int i = 0; i < fwd->local_count; i++) {
        fprintf(stderr, "[L2 DEBUG] local[%d] ifname=%s queue_count=%d\n",
                i, fwd->locals[i].ifname, fwd->locals[i].queue_count);
    }
    for (int i = 0; i < fwd->wan_count; i++) {
        fprintf(stderr, "[L2 DEBUG] wan[%d] ifname=%s queue_count=%d\n",
                i, fwd->wans[i].ifname, fwd->wans[i].queue_count);
    }


    int total_threads = total_local_queues + total_wan_queues;

    pthread_t *threads = calloc(total_threads, sizeof(pthread_t));
    struct queue_thread_args *args = calloc(total_threads, sizeof(struct queue_thread_args));
    if (!threads || !args) {
        fprintf(stderr, "[L2] Failed to allocate thread arrays\n");
        free(threads); free(args);
        return;
    }

    pthread_t gc_tid;
    pthread_create(&gc_tid, NULL, gc_thread, NULL);

    int thread_idx = 0;


    int local_rx_idx = 0;
    for (int i = 0; i < fwd->local_count; i++) {
        struct xsk_interface *local = &fwd->locals[i];
        for (int q = 0; q < local->queue_count; q++) {
            args[thread_idx].fwd = fwd;
            args[thread_idx].iface_idx = i;
            args[thread_idx].queue_idx = q;
            args[thread_idx].tx_queue_base = q;
            args[thread_idx].core_id = local_rx_idx % 4;
            args[thread_idx].wan_worker_index = -1;
            args[thread_idx].worker_id = -1;
            pthread_create(&threads[thread_idx], NULL, local_queue_thread_l2, &args[thread_idx]);
            thread_idx++;
            local_rx_idx++;
        }
    }


    int wan_worker_idx = 0;
    for (int i = 0; i < fwd->wan_count; i++) {
        struct xsk_interface *wan = &fwd->wans[i];
        for (int q = 0; q < wan->queue_count; q++) {
            args[thread_idx].fwd = fwd;
            args[thread_idx].iface_idx = i;
            args[thread_idx].queue_idx = q;
            args[thread_idx].tx_queue_base = q;
            args[thread_idx].core_id = 6 + (wan_worker_idx % 6);
            args[thread_idx].wan_worker_index = wan_worker_idx;
            args[thread_idx].worker_id = -1;
            pthread_create(&threads[thread_idx], NULL, wan_queue_thread_l2, &args[thread_idx]);
            wan_worker_idx++;
            thread_idx++;
        }
    }

    while (running)
        sleep(1);

    for (int i = 0; i < total_threads; i++)
        pthread_join(threads[i], NULL);
    pthread_join(gc_tid, NULL);

    free(threads);
    free(args);
}


static void forwarder_run_l3(struct forwarder *fwd) {
    int total_local_queues = 0;
    for (int i = 0; i < fwd->local_count; i++)
        total_local_queues += fwd->locals[i].queue_count;

    int total_wan_queues = 0;
    for (int i = 0; i < fwd->wan_count; i++)
        total_wan_queues += fwd->wans[i].queue_count;

    int total_threads = total_local_queues + total_wan_queues + NUM_WORKERS;

    pthread_t *threads = calloc(total_threads, sizeof(pthread_t));
    struct queue_thread_args *args = calloc(total_threads, sizeof(struct queue_thread_args));
    if (!threads || !args) {
        fprintf(stderr, "[L3] Failed to allocate thread arrays\n");
        free(threads); free(args);
        return;
    }

    for (int w = 0; w < NUM_WORKERS; w++) {
        g_worker_rings[w].head = 0;
        g_worker_rings[w].tail = 0;
        pthread_mutex_init(&g_worker_rings[w].lock, NULL);
    }

    pthread_t gc_tid;
    pthread_create(&gc_tid, NULL, gc_thread, NULL);

    int thread_idx = 0;


    int local_rx_idx = 0;
    for (int i = 0; i < fwd->local_count; i++) {
        struct xsk_interface *local = &fwd->locals[i];
        for (int q = 0; q < local->queue_count; q++) {
            args[thread_idx].fwd = fwd;
            args[thread_idx].iface_idx = i;
            args[thread_idx].queue_idx = q;
            args[thread_idx].tx_queue_base = q;
            args[thread_idx].core_id = local_rx_idx % 4;
            args[thread_idx].wan_worker_index = -1;
            args[thread_idx].worker_id = -1;
            pthread_create(&threads[thread_idx], NULL, local_queue_thread_l3l4, &args[thread_idx]);
            thread_idx++;
            local_rx_idx++;
        }
    }


    int wan_worker_idx = 0;
    for (int i = 0; i < fwd->wan_count; i++) {
        struct xsk_interface *wan = &fwd->wans[i];
        for (int q = 0; q < wan->queue_count; q++) {
            args[thread_idx].fwd = fwd;
            args[thread_idx].iface_idx = i;
            args[thread_idx].queue_idx = q;
            args[thread_idx].tx_queue_base = q;
            args[thread_idx].core_id = 8 + (wan_worker_idx % 4);
            args[thread_idx].wan_worker_index = wan_worker_idx;
            args[thread_idx].worker_id = -1;
            pthread_create(&threads[thread_idx], NULL, wan_queue_thread_l3l4, &args[thread_idx]);
            wan_worker_idx++;
            thread_idx++;
        }
    }


    for (int w = 0; w < NUM_WORKERS; w++) {
        args[thread_idx].fwd = fwd;
        args[thread_idx].iface_idx = -1;
        args[thread_idx].queue_idx = -1;
        args[thread_idx].tx_queue_base = 0;
        args[thread_idx].core_id = 4 + w;
        args[thread_idx].wan_worker_index = -1;
        args[thread_idx].worker_id = w;
        pthread_create(&threads[thread_idx], NULL, worker_thread, &args[thread_idx]);
        thread_idx++;
    }

    while (running)
        sleep(1);

    for (int i = 0; i < total_threads; i++)
        pthread_join(threads[i], NULL);
    pthread_join(gc_tid, NULL);

    free(threads);
    free(args);
}


static void forwarder_run_l4(struct forwarder *fwd) {
    int total_local_queues = 0;
    for (int i = 0; i < fwd->local_count; i++)
        total_local_queues += fwd->locals[i].queue_count;

    int total_wan_queues = 0;
    for (int i = 0; i < fwd->wan_count; i++)
        total_wan_queues += fwd->wans[i].queue_count;

    int total_threads = total_local_queues + total_wan_queues + NUM_WORKERS;

    pthread_t *threads = calloc(total_threads, sizeof(pthread_t));
    struct queue_thread_args *args = calloc(total_threads, sizeof(struct queue_thread_args));
    if (!threads || !args) {
        fprintf(stderr, "[L4] Failed to allocate thread arrays\n");
        free(threads); free(args);
        return;
    }

    for (int w = 0; w < NUM_WORKERS; w++) {
        g_worker_rings[w].head = 0;
        g_worker_rings[w].tail = 0;
        pthread_mutex_init(&g_worker_rings[w].lock, NULL);
    }

    pthread_t gc_tid;
    pthread_create(&gc_tid, NULL, gc_thread, NULL);

    int thread_idx = 0;


    int local_rx_idx = 0;
    for (int i = 0; i < fwd->local_count; i++) {
        struct xsk_interface *local = &fwd->locals[i];
        for (int q = 0; q < local->queue_count; q++) {
            args[thread_idx].fwd = fwd;
            args[thread_idx].iface_idx = i;
            args[thread_idx].queue_idx = q;
            args[thread_idx].tx_queue_base = q;
            args[thread_idx].core_id = local_rx_idx % 4;
            args[thread_idx].wan_worker_index = -1;
            args[thread_idx].worker_id = -1;
            pthread_create(&threads[thread_idx], NULL, local_queue_thread_l3l4, &args[thread_idx]);
            thread_idx++;
            local_rx_idx++;
        }
    }


    int wan_worker_idx = 0;
    for (int i = 0; i < fwd->wan_count; i++) {
        struct xsk_interface *wan = &fwd->wans[i];
        for (int q = 0; q < wan->queue_count; q++) {
            args[thread_idx].fwd = fwd;
            args[thread_idx].iface_idx = i;
            args[thread_idx].queue_idx = q;
            args[thread_idx].tx_queue_base = q;
            args[thread_idx].core_id = 8 + (wan_worker_idx % 4);
            args[thread_idx].wan_worker_index = wan_worker_idx;
            args[thread_idx].worker_id = -1;
            pthread_create(&threads[thread_idx], NULL, wan_queue_thread_l3l4, &args[thread_idx]);
            wan_worker_idx++;
            thread_idx++;
        }
    }


    for (int w = 0; w < NUM_WORKERS; w++) {
        args[thread_idx].fwd = fwd;
        args[thread_idx].iface_idx = -1;
        args[thread_idx].queue_idx = -1;
        args[thread_idx].tx_queue_base = 0;
        args[thread_idx].core_id = 4 + w;
        args[thread_idx].wan_worker_index = -1;
        args[thread_idx].worker_id = w;
        pthread_create(&threads[thread_idx], NULL, worker_thread, &args[thread_idx]);
        thread_idx++;
    }

    while (running)
        sleep(1);

    for (int i = 0; i < total_threads; i++)
        pthread_join(threads[i], NULL);
    pthread_join(gc_tid, NULL);

    free(threads);
    free(args);
}



void forwarder_run(struct forwarder *fwd) {
    signal(SIGINT, sigint_handler);
    signal(SIGTERM, sigint_handler);

    if (!crypto_enabled) {
        forwarder_run_no_crypto(fwd);
    } else if (crypto_layer == 2) {
        forwarder_run_l2(fwd);
    } else if (crypto_layer == 3) {
        forwarder_run_l3(fwd);
    } else if (crypto_layer == 4) {
        forwarder_run_l4(fwd);
    } else {
        forwarder_run_l3(fwd);
    }
}

void forwarder_print_stats(struct forwarder *fwd) {
    if (!fwd) return;

    int nq = (fwd->local_count > 0 && fwd->locals[0].queue_count <= FORWARDER_MAX_LOCAL_QUEUES)
             ? fwd->locals[0].queue_count : 0;
    if (nq <= 0) nq = 1;

    uint64_t tx_wait_loops = 0;
    for (int i = 0; i < fwd->local_count; i++) {
        for (int q = 0; q < fwd->locals[i].queue_count && q < MAX_QUEUES; q++)
            tx_wait_loops += fwd->locals[i].queues[q].tx_wait_loops;
    }

    fprintf(stdout,
            "[STATS] local_to_wan=%lu wan_to_local=%lu total_dropped=%lu "
            "dropped_bad_ip=%lu dropped_no_local_match=%lu dropped_local_tx_fail=%lu",
            fwd->local_to_wan,
            fwd->wan_to_local,
            fwd->total_dropped,
            fwd->dropped_bad_ip,
            fwd->dropped_no_local_match,
            fwd->dropped_local_tx_fail);
    for (int i = 0; i < nq && i < FORWARDER_MAX_LOCAL_QUEUES; i++)
        fprintf(stdout, " q%d=%lu", i, (unsigned long)fwd->dropped_local_tx_fail_by_queue[i]);
    fprintf(stdout, " tx_wait_loops=%lu\n", (unsigned long)tx_wait_loops);
}