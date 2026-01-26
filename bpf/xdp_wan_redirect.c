// SPDX-License-Identifier: GPL-2.0
// XDP program for WAN interfaces - redirect incoming packets to userspace

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>

// XDP socket map - one per queue
struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 8);
    __type(key, int);
    __type(value, int);
} wan_xsks_map SEC(".maps");

// Stats for debugging
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 4);
    __type(key, int);
    __type(value, __u64);
} wan_stats_map SEC(".maps");

// Stats indices
#define STAT_TOTAL      0
#define STAT_NON_IP     1
#define STAT_REDIRECT   2
#define STAT_NO_SOCK    3

static __always_inline void inc_stat(int idx)
{
    __u64 *val = bpf_map_lookup_elem(&wan_stats_map, &idx);
    if (val)
        __sync_fetch_and_add(val, 1);
}

SEC("xdp")
int xdp_wan_redirect_prog(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    inc_stat(STAT_TOTAL);

    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // Only handle IPv4
    if (eth->h_proto != __constant_htons(ETH_P_IP)) {
        inc_stat(STAT_NON_IP);
        return XDP_PASS;
    }

    // Verify IP header
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    // Redirect to userspace via AF_XDP
    int queue_id = ctx->rx_queue_index;
    int ret = bpf_redirect_map(&wan_xsks_map, queue_id, XDP_PASS);

    if (ret == XDP_REDIRECT) {
        inc_stat(STAT_REDIRECT);
    } else {
        inc_stat(STAT_NO_SOCK);
    }

    return ret;
}

char _license[] SEC("license") = "GPL";
