#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>

#define FAKE_ETHERTYPE_88B5 0xB588
#define FAKE_ETHERTYPE_88B6 0xB688
#define FAKE_ETHERTYPE_9000 0x0090

struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 8);
    __type(key, int);
    __type(value, int);
} wan_xsks_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 4);
    __type(key, int);
    __type(value, __u64);
} wan_stats_map SEC(".maps");

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

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    __u16 proto = eth->h_proto;
    if (proto != __constant_htons(ETH_P_IP) &&
        proto != FAKE_ETHERTYPE_88B5 &&
        proto != FAKE_ETHERTYPE_88B6 &&
        proto != FAKE_ETHERTYPE_9000) {
        inc_stat(STAT_NON_IP);
        return XDP_PASS;
    }

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
