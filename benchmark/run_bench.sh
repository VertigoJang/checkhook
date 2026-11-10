#!/usr/bin/env bash
# Enforcement-layer benchmark: treatment x N x traffic-class x reps
# Requires two containers "target" and "tester" on a bridge network (see README).
set -uo pipefail
cd "$(dirname "$0")"
REPS="${1:-3}"; DUR="${2:-15}"
SIZES_HASH="${SIZES_HASH:-10 100 1000 10000 100000}"
SIZES_LINEAR="${SIZES_LINEAR:-10 100 1000 10000}"
TPID=$(sudo docker inspect -f '{{.State.Pid}}' target)
SPID=$(sudo docker inspect -f '{{.State.Pid}}' tester)
NS="sudo nsenter -t $TPID -n"; NST="sudo nsenter -t $SPID -n"
echo "target=$TPID tester=$SPID REPS=$REPS DUR=$DUR"
gen_bl(){ python3 - "$1" "$2" > /tmp/blocklist.txt << 'PY'
import sys, ipaddress
N=int(sys.argv[1]); cls=sys.argv[2]; base=int(ipaddress.ip_address("10.210.0.0"))
cnt=N-1 if cls=="drop" else N
for i in range(cnt): print(ipaddress.ip_address(base+i))
if cls=="drop": print("10.200.0.5")
PY
}
flood(){ $NST ./udpflood 10.200.0.100 9000 >/dev/null 2>&1 & }
stopflood(){ sudo pkill -f 'udpflood 10.200.0.100' 2>/dev/null || true; }
cleanup(){ stopflood; sudo pkill -f xdp_loader.py 2>/dev/null||true
  $NS ip link set dev eth0 xdp off 2>/dev/null||true; $NS ip link set dev eth0 xdpgeneric off 2>/dev/null||true
  $NS bash enforce.sh teardown ipt 2>/dev/null||true; $NS bash enforce.sh teardown ipset 2>/dev/null||true; $NS bash enforce.sh teardown nft 2>/dev/null||true; }
measure(){ flood; sleep 2; $NS python3 collect.py --label "$1" --iface eth0 --duration "$DUR" --out results; stopflood; }
run_sw(){ local tr="$1" N="$2" cls="$3" r="$4" lbl="${1}_n${2}_${3}_r${4}"; gen_bl "$N" "$cls"
  if [ "$tr" = xdp ]; then
    $NS python3 xdp_loader.py -i eth0 --block-file /tmp/blocklist.txt --port 9000 --mode skb --quiet > /tmp/xdp.log 2>&1 &
    local pid=$!; sleep 3; measure "$lbl"
    sudo kill "$pid" 2>/dev/null||true; sleep 1
    $NS ip link set dev eth0 xdp off 2>/dev/null||true; $NS ip link set dev eth0 xdpgeneric off 2>/dev/null||true
  else
    $NS bash enforce.sh setup "$tr"; measure "$lbl"; $NS bash enforce.sh teardown "$tr"
  fi; }
[ -d results ] && mv results "results.bench.$(date +%H%M%S)"; mkdir -p results
echo "=== initial cleanup ==="; cleanup
for r in $(seq 1 "$REPS"); do
  echo "########## rep $r/$REPS ##########"
  measure "baseline_n0_pass_r$r"
  for cls in pass drop; do
    for N in $SIZES_LINEAR; do run_sw ipt   "$N" "$cls" "$r"; done
    for N in $SIZES_HASH;   do run_sw ipset "$N" "$cls" "$r"; done
    for N in $SIZES_HASH;   do run_sw nft   "$N" "$cls" "$r"; done
    for N in $SIZES_HASH;   do run_sw xdp   "$N" "$cls" "$r"; done
  done
done
echo "=== cleanup ==="; cleanup
sudo chown -R "$(id -un):$(id -gn)" results 2>/dev/null||true
echo "=== done: $(ls results | wc -l) files ==="
