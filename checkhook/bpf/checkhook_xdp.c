// SPDX-License-Identifier: MIT OR GPL-2.0
/* CheckHook XDP enforcement program.
 *
 * Drops IPv4 packets whose source address is in the pinned hash map
 * `checkhook_block` (key: IPv4 address in network byte order, value: expiry as
 * CLOCK_MONOTONIC nanoseconds; 0 = never expires). Expired entries are
 * removed lazily here, on the next packet from that source.
 *
 * Built and loaded by `python3 -m checkhook.xdp load`; maps are pinned under
 * /sys/fs/bpf/checkhook so detectors can update them with bpftool.
 * Dual-licensed MIT/GPL: MIT like the rest of CheckHook, and "Dual MIT/GPL" is
 * on the kernel's list of GPL-compatible BPF program licenses.
 */
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 200000);
	__type(key, __u32);
	__type(value, __u64);
} checkhook_block SEC(".maps");

/* [0] packets dropped, [1] expired entries removed */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 2);
	__type(key, __u32);
	__type(value, __u64);
} checkhook_stats SEC(".maps");

static __always_inline void count(__u32 idx)
{
	__u64 *c = bpf_map_lookup_elem(&checkhook_stats, &idx);
	if (c)
		(*c)++;
}

SEC("xdp")
int checkhook_xdp(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;
	struct iphdr *ip;
	__u64 *expiry;
	__u32 src;

	if ((void *)(eth + 1) > data_end)
		return XDP_PASS;
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;
	ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end)
		return XDP_PASS;

	src = ip->saddr;
	expiry = bpf_map_lookup_elem(&checkhook_block, &src);
	if (!expiry)
		return XDP_PASS;
	if (*expiry && bpf_ktime_get_ns() > *expiry) {
		bpf_map_delete_elem(&checkhook_block, &src);
		count(1);
		return XDP_PASS;
	}
	count(0);
	return XDP_DROP;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
