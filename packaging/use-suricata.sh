#!/usr/bin/env bash
# use-suricata.sh — use the distro's Suricata as CheckHook's signature IDS
# (instead of Snort 3, which most distros don't package).
#
#   sudo bash packaging/use-suricata.sh [--eve /var/log/suricata/eve.json]
#
# Install and start Suricata with your package manager first; its packaged
# service writes eve.json. This script points CheckHook's ids/triage alert_file at
# it (backup kept) and restarts the bridge. If checkhook-ids (Snort) is installed,
# it is stopped so only one IDS feeds the blocklist.

set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "run with sudo." >&2; exit 1; }
HERE="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
. "$HERE/lib/common.sh"
CONF=/etc/checkhook/checkhook.yaml
EVE=/var/log/suricata/eve.json
[[ "${1:-}" == "--eve" ]] && EVE="$2"

[[ -f "$CONF" ]] || { echo "run packaging/install-services.sh first ($CONF missing)" >&2; exit 1; }
need_cmd suricata suricata
if ! systemctl is-active --quiet suricata 2>/dev/null; then
  echo "[!] suricata.service is not active. Set the capture interface in /etc/suricata/suricata.yaml" >&2
  echo "    (af-packet: - interface: <iface>), then: sudo systemctl enable --now suricata" >&2
fi

cp "$CONF" "$CONF.bak"
sed -i "s|^  alert_file: .*|  alert_file: $EVE|" "$CONF"
echo "[+] $CONF: alert_file -> $EVE  (backup: $CONF.bak)"

if systemctl is-enabled --quiet checkhook-ids 2>/dev/null; then
  systemctl disable --now checkhook-ids
  echo "[+] checkhook-ids (Snort) stopped and disabled"
fi
systemctl restart checkhookd 2>/dev/null || true

sleep 2
echo "suricata      : $(systemctl is-active suricata 2>/dev/null || true)"
echo "checkhookd    : $(systemctl is-active checkhookd 2>/dev/null || true)   (reads Snort or Suricata alerts)"
