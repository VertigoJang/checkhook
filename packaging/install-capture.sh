#!/usr/bin/env bash
# install-capture.sh — register the boot-time benign-traffic capture service.
#
# Captures headers only (no payload) on the given interface as a ring buffer
# (40 x 25 MB) in /var/lib/checkhook, for make_dataset to label later.
#
#   sudo bash packaging/install-capture.sh <iface>
#   sudo bash packaging/install-capture.sh --uninstall
#
# Find your interface with:  ip -o -4 route show default   (the 'dev' name)

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "run with sudo (installs a systemd service)." >&2
  exit 1
fi

HERE="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
. "$HERE/lib/common.sh"
UNIT=/etc/systemd/system/checkhook-capture.service
DATA=/var/lib/checkhook

if [[ "${1:-}" == "--uninstall" ]]; then
  systemctl disable --now checkhook-capture 2>/dev/null || true
  rm -f "$UNIT"
  systemctl daemon-reload
  command -v semanage >/dev/null 2>&1 && semanage fcontext -d "$DATA(/.*)?" 2>/dev/null || true
  [[ -d "$DATA" ]] && command -v restorecon >/dev/null 2>&1 && restorecon -R "$DATA" || true
  echo "checkhook-capture removed. Captured files are left in $DATA."
  exit 0
fi

IFACE="${1:-}"
[[ -z "$IFACE" ]] && IFACE="$(ip -o -4 route show default | awk '{print $5; exit}')"
if [[ -z "$IFACE" || ! -e "/sys/class/net/$IFACE" ]]; then
  echo "usage: sudo bash packaging/install-capture.sh [iface]   (default: the interface of the default route)" >&2
  echo "no usable interface found${IFACE:+ ($IFACE does not exist)}; interfaces:" >&2
  ip -br link >&2
  exit 1
fi

need_cmd tcpdump tcpdump
TCPDUMP="$(command -v tcpdump)"
ip link show "$IFACE" >/dev/null 2>&1 || { echo "interface '$IFACE' not found (see: ip -o link show)" >&2; exit 1; }

# unprivileged user tcpdump drops to: the distro's 'tcpdump' user if it exists
# (RHEL, Debian, Ubuntu...), otherwise a dedicated system user.
if id tcpdump >/dev/null 2>&1; then
  CAPUSER=tcpdump
else
  CAPUSER=checkhook-cap
  id "$CAPUSER" >/dev/null 2>&1 || useradd --system --no-create-home --shell "$(nologin_shell)" "$CAPUSER"
fi

# a directory left by an earlier version (other owner) would block that user
[[ -d "$DATA" ]] && chown -R "$CAPUSER:$CAPUSER" "$DATA"

# SELinux (RHEL/Fedora): tcpdump runs confined as netutils_t and may not write
# ordinary /var/lib files (var_lib_t). Instead of widening its permissions, label
# ONLY our directory with tcpdump's own writable type, netutils_tmp_t.
RESTORECON=""
if selinux_on; then
  need_cmd semanage semanage
  RESTORECON="$(command -v restorecon)"
  mkdir -p "$DATA"
  semanage fcontext -a -t netutils_tmp_t "$DATA(/.*)?" 2>/dev/null \
    || semanage fcontext -m -t netutils_tmp_t "$DATA(/.*)?"
  restorecon -R "$DATA"
  echo "[+] SELinux: $DATA labelled netutils_tmp_t (only this directory; no new permissions)"
fi

# AppArmor (Ubuntu/Debian/openSUSE ship a tcpdump profile): allow our directory only
mkdir -p "$DATA"
apparmor_allow_tcpdump "$DATA"

sed -e "s|__TCPDUMP__|$TCPDUMP|g" -e "s|__IFACE__|$IFACE|g" -e "s|__CAPUSER__|$CAPUSER|g" \
    "$HERE/checkhook-capture.service" > "$UNIT"
if [[ -n "$RESTORECON" ]]; then
  sed -i "s|__RESTORECON__|$RESTORECON|" "$UNIT"
else
  sed -i '/__RESTORECON__/d' "$UNIT"        # no SELinux: no relabel step
fi
chmod 0644 "$UNIT"

systemctl daemon-reload
systemctl enable checkhook-capture >/dev/null 2>&1
systemctl restart checkhook-capture

sleep 3
echo
if systemctl is-active --quiet checkhook-capture; then
  echo "RUNNING: checkhook-capture"
else
  echo "NOT running — see:  sudo journalctl -eu checkhook-capture --no-pager | tail"
fi
echo "  interface : $IFACE   (headers only, snaplen 128B — no payload saved; runs as $CAPUSER)"
echo "  files     : $DATA/benign.pcap00..39  (ring buffer, 40 x 25 MB, oldest overwritten)"
echo
echo "check it:   systemctl status checkhook-capture"
echo "pause it:   sudo systemctl stop checkhook-capture     # before attack practice!"
echo "resume:     sudo systemctl start checkhook-capture"
