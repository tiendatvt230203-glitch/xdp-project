// XDP Program - Redirect packets to AF_XDP socket
// Only redirect packets with destination IP outside LOCAL subnet
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

// Config map for LOCAL subnet
// Key 0: local_ip (network address, e.g., 192.168.9.0)
// Key 1: local_mask (e.g., 0xFFFFFF00 for /24)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, int);
    __type(value, __u32);
} config_map SEC(".maps");

SEC("xdp")
int xdp_redirect_prog(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // Only handle IPv4
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    // Parse IP header
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    // Get LOCAL subnet config from map
    int key0 = 0, key1 = 1;
    __u32 *local_net = bpf_map_lookup_elem(&config_map, &key0);
    __u32 *local_mask = bpf_map_lookup_elem(&config_map, &key1);

    if (!local_net || !local_mask) {
        // No config, pass all packets
        return XDP_PASS;
    }

    // Get destination IP
    __u32 dst_ip = ip->daddr;

    // Check if destination is in LOCAL subnet
    // If (dst_ip & mask) == local_net -> same subnet -> XDP_PASS
    // If different subnet -> redirect to userspace
    if ((dst_ip & *local_mask) == *local_net) {
        // Destination is in LOCAL subnet, let kernel handle it
        return XDP_PASS;
    }

    // Destination is outside LOCAL subnet, redirect to AF_XDP
    int index = ctx->rx_queue_index;
    if (bpf_map_lookup_elem(&xsks_map, &index))
        return bpf_redirect_map(&xsks_map, index, 0);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
