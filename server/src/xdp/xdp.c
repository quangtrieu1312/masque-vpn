//go:build ignore

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u32);
} xsks_map SEC(".maps");

SEC("xdp")
int masque_xdp_prog(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    if (eth->h_proto != __constant_htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;

    __u32 ihl = (ip->ihl & 0x0f) * 4;
    if (ihl < 20) return XDP_PASS;
    if (ip->protocol != IPPROTO_UDP) return XDP_PASS;

    struct udphdr *udp = (void *)ip + ihl;
    if ((void *)(udp + 1) > data_end) return XDP_PASS;

    if (udp->dest == __constant_htons(443)) {
        __u32 queue_id = ctx->rx_queue_index;
        if (bpf_map_lookup_elem(&xsks_map, &queue_id)) {
            return bpf_redirect_map(&xsks_map, queue_id, XDP_PASS);
        }
    }
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
