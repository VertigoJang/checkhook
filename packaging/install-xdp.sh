#!/usr/bin/env bash
# install-xdp.sh — switch CheckHook's enforcement backend to XDP.
#
#   sudo bash packaging/install-xdp.sh [--iface IFACE] [--mode generic|native]
#   sudo bash packaging/install-xdp.sh --revert        # back to nftables
#
# Builds checkhook/bpf/checkhook_xdp.c, installs checkhook-xdp.service (attaches the
# program at boot), sets `backend: xdp` in /etc/checkhook/checkhook.yaml (backup
# kept) and restarts the detectors. `enforce:` is NOT changed — if it is false,
# nothing is blocked either way.

set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "run with sudo." >&2; exit 1; }
HERE="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
. "$HERE/lib/common.sh"
ROOT="$(cd "$HERE/.." && pwd)"
CONF=/etc/checkhook/checkhook.yaml
UNIT=/etc/systemd/system/checkhook-xdp.service
[[ -f "$CONF" ]] || { echo "run packaging/install-services.sh first ($CONF missing)" >&2; exit 1; }

restart_detectors() {
  for s in checkhookd; do
    systemctl is-enabled --quiet "$s" 2>/dev/null && systemctl restart "$s" || true
  done
}

if [[ "${1:-}" == "--revert" ]]; then
  cp "$CONF" "$CONF.bak"
  sed -i 's/^backend: .*/backend: nft              # enforcement backend (nft | xdp)/' "$CONF"
  restart_detectors
  systemctl disable --now checkhook-xdp 2>/dev/null || true
  rm -f "$UNIT"; systemctl daemon-reload
  echo "backend -> nft; XDP detached and checkhook-xdp removed."
  exit 0
fi

IFACE=""; MODE="generic"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --iface) IFACE="$2"; shift 2 ;;
    --mode)  MODE="$2"; shift 2 ;;
    *) echo "unknown option: $1" >&2; exit 1 ;;
  esac
done
[[ -z "$IFACE" ]] && IFACE="$(ip -o -4 route show default | awk '{print $5; exit}')"

missing=()
command -v clang   >/dev/null || missing+=("$(pkg_name clang)")
command -v bpftool >/dev/null || missing+=("$(pkg_name bpftool)")
[[ -f /usr/include/bpf/bpf_helpers.h ]] || missing+=("$(pkg_name libbpf)")
if (( ${#missing[@]} )); then
  echo "missing build tools  ->  $(pkg_install_cmd) ${missing[*]}" >&2
  [[ "$(distro_family)" == rhel ]] && echo "  (RHEL: libbpf-devel is in the CodeReady Builder repo)" >&2
  exit 1
fi

# config: backend + xdp section
cp "$CONF" "$CONF.bak"
sed -i 's/^backend: .*/backend: xdp              # enforcement backend (nft | xdp)/' "$CONF"
if grep -q '^xdp:' "$CONF"; then
  sed -i "/^xdp:/,/^[^ ]/{s|^  iface: .*|  iface: $IFACE|;s|^  mode: .*|  mode: $MODE|}" "$CONF"
else
  printf '\nxdp:                      # XDP enforcement (used when backend: xdp)\n  iface: %s\n  mode: %s            # generic works on any NIC (Wi-Fi too); native needs driver support\n' "$IFACE" "$MODE" >> "$CONF"
fi
echo "[+] $CONF: backend: xdp, xdp.iface: $IFACE, xdp.mode: $MODE  (backup: $CONF.bak)"

# build + service
( cd "$ROOT" && python3 -m checkhook.xdp build )
sed "s|__ROOT__|$ROOT|g" "$HERE/checkhook-xdp.service" > "$UNIT"; chmod 0644 "$UNIT"
systemctl daemon-reload
systemctl enable checkhook-xdp >/dev/null 2>&1
systemctl restart checkhook-xdp
restart_detectors

sleep 2
echo
echo "checkhook-xdp   : $(systemctl is-active checkhook-xdp || true)"
echo "checkhookd    : $(systemctl is-active checkhookd || true)"
( cd "$ROOT" && python3 -m checkhook.xdp status ) || true
echo
echo "revert to nftables: sudo bash packaging/install-xdp.sh --revert"
