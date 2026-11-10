// XDP program compiled at runtime by BCC.
// Drops UDP packets whose source IP is in the blocklist hash map,
// at the XDP layer (before skb allocation).
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>

BPF_HASH(blocklist, u32, u64, 200000);   // key: src IPv4 (network order), value: drop counter
BPF_ARRAY(filter_port, u32, 1);          // optional UDP dest port (0 = any)

int xdp_filter(struct xdp_md *ctx) {
    void *data_end=(void*)(long)ctx->data_end, *data=(void*)(long)ctx->data;
    struct ethhdr *eth=data;
    if ((void*)(eth+1)>data_end) return XDP_PASS;
    if (eth->h_proto!=bpf_htons(ETH_P_IP)) return XDP_PASS;
    struct iphdr *ip=(void*)(eth+1);
    if ((void*)(ip+1)>data_end) return XDP_PASS;
    if (ip->protocol!=IPPROTO_UDP) return XDP_PASS;
    void *l4=(void*)ip+(ip->ihl*4); struct udphdr *udp=l4;
    if ((void*)(udp+1)>data_end) return XDP_PASS;
    int z=0; u32 *wp=filter_port.lookup(&z);
    if (wp && *wp!=0 && udp->dest!=bpf_htons((u16)*wp)) return XDP_PASS;
    u32 s=ip->saddr; u64 *c=blocklist.lookup(&s);
    if (c) { __sync_fetch_and_add(c,1); return XDP_DROP; }
    return XDP_PASS;
}
