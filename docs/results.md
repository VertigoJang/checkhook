# Benchmark results

Environment: VirtualBox Rocky Linux 10.2 guest (kernel 6.12), 4 vCPU, two
busybox containers on a 10.200.0.0/24 bridge; XDP generic (skb) mode; 64-byte
UDP flood; metrics sampled from `/proc` (mean of the steady window, excluding
the first/last 20%). 3 repetitions; values are mean +/- stdev.

CPU cost = softirq CPU-seconds per million packets (lower is better).

## Attack traffic (dropped)

| treatment | N | rx_pps | cpu/Mpkt |
|---|---|---|---|
| XDP+eBPF map | 10 | 887,111 | 0.404 |
| XDP+eBPF map | 1,000 | 909,001 | 0.396 |
| XDP+eBPF map | 10,000 | 910,921 | 0.398 |
| XDP+eBPF map | 100,000 | 899,351 | 0.403 |
| nftables set | 10 | 701,955 | 0.717 |
| nftables set | 10,000 | 699,929 | 0.717 |
| nftables set | 100,000 | 687,814 | 0.730 |
| iptables+ipset | 10 | 673,780 | 0.786 |
| iptables+ipset | 100,000 | 654,933 | 0.813 |
| iptables (linear) | 10 | 708,881 | 0.738 |
| iptables (linear) | 1,000 | 217,390 | 3.855 |
| iptables (linear) | 10,000 | 28,650 | 34.507 |

## Legit traffic (passed)

| treatment | N | rx_pps | cpu/Mpkt |
|---|---|---|---|
| baseline (no enforce) | 0 | 567,020 | 1.028 |
| nftables set | 100,000 | 552,095 | 1.065 |
| XDP+eBPF map | 100,000 | 555,746 | 1.094 |
| iptables+ipset | 100,000 | 532,953 | 1.130 |
| iptables (linear) | 1,000 | 196,599 | 4.360 |
| iptables (linear) | 10,000 | 27,919 | 35.836 |

## Reading of the data

1. Hash-based enforcement (XDP, nftables set, ipset) is O(1) in N: performance
   is essentially constant from N=10 to N=100,000.
2. Linear iptables is O(n): throughput falls roughly as 1/N and per-packet CPU
   rises proportionally, for both dropped and passed traffic.
3. XDP is fastest on dropped traffic because it discards before `skb`
   allocation (~half the per-packet CPU of in-stack hash layers). On passed
   traffic the stack cost dominates, so all hash layers converge.

See `figures/` for the four plotted figures.
