# Enforcement-layer benchmark

Compares five enforcement layers (none, iptables linear, iptables+ipset,
nftables set, XDP+eBPF map) across blocklist size N and traffic class
(attack=dropped, legit=passed). All enforcement and measurement happen in the
host kernel via `nsenter` into a target container's netns, so the container OS
is irrelevant.

## Requirements (host)

Linux with: BCC (`python3-bcc`, `bcc-tools`) + matching kernel headers,
`nftables`, `ipset`, `iptables`, Docker, `gcc`, Python 3 (+ `matplotlib` for
figures). On RHEL/Rocky, BCC matches the distro kernel; on Ubuntu a non-HWE
kernel may be required.

## Setup

```bash
gcc -O2 -o udpflood udpflood.c
sudo docker network create --subnet 10.200.0.0/24 benchnet
sudo docker run -dit --name target --network benchnet --ip 10.200.0.100 busybox tail -f /dev/null
sudo docker run -dit --name tester --network benchnet --ip 10.200.0.5  busybox tail -f /dev/null
```

## Run

```bash
./run_bench.sh [REPS] [DUR]          # default 3 reps x 15 s
python3 summary.py                   # text table
python3 plot_bench.py --dir results  # 4 PNGs + results/summary.csv
```

Override sizes, e.g. a quick smoke run:
`SIZES_HASH="100 10000" SIZES_LINEAR="100 10000" ./run_bench.sh 1 8`

## Notes

- `udpflood` is a trivial UDP load generator for **isolated lab networks only**.
- XDP runs in generic (skb) mode on veth; native-mode numbers require a
  physical NIC with an XDP-capable driver.
