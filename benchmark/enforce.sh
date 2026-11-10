#!/usr/bin/env bash
# Enforcement-layer setup/teardown, run inside the target netns. Reads /tmp/blocklist.txt
set -uo pipefail
BL=/tmp/blocklist.txt; act="${1:?}"; tr="${2:?}"
case "$tr" in
 ipt)
  case "$act" in
   setup)
     iptables -N XDP_BENCH 2>/dev/null || iptables -F XDP_BENCH
     { echo "*filter"; echo ":XDP_BENCH - [0:0]"
       while read -r ip; do echo "-A XDP_BENCH -s $ip -p udp -j DROP"; done < "$BL"
       echo COMMIT; } | iptables-restore --noflush
     iptables -C INPUT -j XDP_BENCH 2>/dev/null || iptables -I INPUT 1 -j XDP_BENCH ;;
   teardown)
     iptables -D INPUT -j XDP_BENCH 2>/dev/null||true; iptables -F XDP_BENCH 2>/dev/null||true; iptables -X XDP_BENCH 2>/dev/null||true ;;
  esac ;;
 ipset)
  case "$act" in
   setup)
     ipset create blockset hash:ip maxelem 300000 -exist
     { echo "flush blockset"; while read -r ip; do echo "add blockset $ip"; done < "$BL"; } | ipset restore
     iptables -C INPUT -m set --match-set blockset src -p udp -j DROP 2>/dev/null || iptables -I INPUT 1 -m set --match-set blockset src -p udp -j DROP ;;
   teardown)
     iptables -D INPUT -m set --match-set blockset src -p udp -j DROP 2>/dev/null||true; ipset destroy blockset 2>/dev/null||true ;;
  esac ;;
 nft)
  case "$act" in
   setup)
     nft delete table ip bench 2>/dev/null || true
     nft add table ip bench
     nft 'add set ip bench blockset { type ipv4_addr; }'
     { echo "add element ip bench blockset {"; paste -sd, "$BL"; echo "}"; } > /tmp/nft_e.txt
     nft -f /tmp/nft_e.txt
     nft 'add chain ip bench input { type filter hook input priority 0; }'
     nft 'add rule ip bench input ip saddr @blockset udp dport 9000 drop' ;;
   teardown)
     nft delete table ip bench 2>/dev/null || true ;;
  esac ;;
esac
