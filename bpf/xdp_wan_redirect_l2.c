/*
 * XDP redirect cho WAN khi mã hóa Layer 2.
 * Mỗi card WAN chỉ 1 queue; chương trình hash gói và redirect vào 5 slot XSK (0..4)
 * tương ứng 5 core xử lý WAN->Local, tránh nghẽn 1 queue.
 * Giữ nguyên xdp_wan_redirect.c cho no-crypto và Layer 4.
 */
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define L2_WAN_XSK_SLOTS  5

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

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, int);
    __type(value, __u16);
} wan_config_map SEC(".maps");

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
int xdp_wan_redirect_l2_prog(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    inc_stat(STAT_TOTAL);

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    __u16 proto = eth->h_proto;

    /* Chỉ redirect IP hoặc fake-ethertype (L2 tunnel) */
    if (proto != __constant_htons(ETH_P_IP) &&
        proto != __constant_htons(ETH_P_IPV6)) {
        int key0 = 0, key1 = 1;
        __u16 *fake4 = bpf_map_lookup_elem(&wan_config_map, &key0);
        if (!(fake4 && *fake4 != 0 &&
              (proto & __constant_htons(0xFF00)) == (*fake4 & __constant_htons(0xFF00)))) {
            __u16 *fake6 = bpf_map_lookup_elem(&wan_config_map, &key1);
            if (!(fake6 && *fake6 != 0 &&
                  (proto & __constant_htons(0xFF00)) == (*fake6 & __constant_htons(0xFF00)))) {
                inc_stat(STAT_NON_IP);
                return XDP_PASS;
            }
        }
    }

    /* Hash flow → redirect vào 1 trong 5 slot XSK (5 core WAN->Local) */
    __u32 h = 0;

    if (proto == __constant_htons(ETH_P_IP)) {
        struct iphdr *iph = (void *)(eth + 1);
        if ((void *)(iph + 1) > data_end)
            return XDP_PASS;

        h = iph->saddr ^ iph->daddr;
        if (iph->protocol == 6 || iph->protocol == 17) {
            __u8 *trans = (void *)iph + iph->ihl * 4;
            if (trans + 4 <= (unsigned char *)data_end) {
                __u16 sport = *(__u16 *)trans;
                __u16 dport = *(__u16 *)(trans + 2);
                h ^= ((__u32)sport << 16) | dport;
            }
        }
    } 
    else {
        /*
         * Fake ethertype (L2 encrypted): MAC giống nhau cho mọi gói cùng WAN
         * → hash payload (nonce + ciphertext) để phân tán đều 5 core.
         */
        unsigned char *pay = (unsigned char *)(eth + 1);
        if (pay + 8 <= (unsigned char *)data_end) {
            h = *(__u32 *)pay ^ (*(__u32 *)(pay + 4));
        } else if (pay + 4 <= (unsigned char *)data_end) {
            h = *(__u32 *)pay;
        }
    }

    h ^= h >> 16;
    h *= 0x85ebca6b;
    h ^= h >> 13;
    h *= 0xc2b2ae35;
    h ^= h >> 16;

    /* 5 slot: core 5,6,7,8,9 */
    int queue_id = (int)(h % L2_WAN_XSK_SLOTS);
    int ret = bpf_redirect_map(&wan_xsks_map, queue_id, XDP_PASS);

    if (ret == XDP_REDIRECT)
        inc_stat(STAT_REDIRECT);
    else
        inc_stat(STAT_NO_SOCK);

    return ret;
}

char _license[] SEC("license") = "GPL";
