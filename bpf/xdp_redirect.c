// XDP Program - Redirect packets to AF_XDP socket
//
// LOGIC:
// 1. ARP packets           -> PASS (để kernel trả lời ARP cho client)
// 2. Broadcast/Multicast   -> PASS (DHCP, ARP broadcast, etc.)
// 3. dst_ip IN LOCAL net   -> PASS (packet đến server hoặc client cùng LAN)
// 4. dst_ip OUT LOCAL net  -> REDIRECT (packet cần forward qua WAN)
//
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// XSK map for AF_XDP sockets
struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 64);
    __type(key, int);
    __type(value, int);
} xsks_map SEC(".maps");

// Config map for LOCAL network
// Key 0: local_network (e.g., 192.168.9.0)
// Key 1: local_netmask (e.g., 255.255.255.0)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, int);
    __type(value, __u32);
} config_map SEC(".maps");

// Check if MAC is broadcast (ff:ff:ff:ff:ff:ff)
static __always_inline int is_broadcast_mac(unsigned char *mac)
{
    return (mac[0] & mac[1] & mac[2] & mac[3] & mac[4] & mac[5]) == 0xff;
}

// Check if MAC is multicast (bit 0 of first byte is 1)
static __always_inline int is_multicast_mac(unsigned char *mac)
{
    return mac[0] & 0x01;
}

SEC("xdp")
int xdp_redirect_prog(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    int index = ctx->rx_queue_index;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // ARP -> PASS (kernel trả lời ARP)
    if (eth->h_proto == bpf_htons(ETH_P_ARP))
        return XDP_PASS;

    // Broadcast/Multicast -> PASS
    if (is_broadcast_mac(eth->h_dest) || is_multicast_mac(eth->h_dest))
        return XDP_PASS;

    // Không phải IPv4 -> PASS
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    // Lấy config LOCAL network
    int key0 = 0, key1 = 1;
    __u32 *local_network = bpf_map_lookup_elem(&config_map, &key0);
    __u32 *local_netmask = bpf_map_lookup_elem(&config_map, &key1);
    if (!local_network || !local_netmask)
        return XDP_PASS;

    // dst_ip thuộc LOCAL network -> PASS (đến server hoặc LAN)
    __u32 dst_network = ip->daddr & *local_netmask;
    if (dst_network == *local_network)
        return XDP_PASS;

    // dst_ip NGOÀI LOCAL network -> REDIRECT lên userspace (bypass kernel)
    if (bpf_map_lookup_elem(&xsks_map, &index))
        return bpf_redirect_map(&xsks_map, index, 0);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
