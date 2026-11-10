#!/usr/bin/env bash
# install-services.sh — install checkhookd (the CheckHook daemon) and the config.
#
#   sudo bash packaging/install-services.sh [--iface IFACE] [--alert-file PATH]
#   sudo bash packaging/install-services.sh --uninstall
#
# Installs:
#   /etc/checkhook/checkhook.yaml   (only if absent — never overwrites yours)
#   checkhookd.service              IDS bridge + ML detector + block expiry +
#                                   hourly read-only LLM triage, one process
#   /usr/local/bin/checkhook        launcher  -> <repo>/bin/checkhook
#   /usr/local/bin/checkhookd       daemon    -> <repo>/bin/checkhookd
#
# The packet capture (install-capture.sh), the Snort sensor (install-snort.sh)
# and the XDP loader (install-xdp.sh) are separate units.
#
# Safety: the config ships with `enforce: false`, so checkhookd starts in
# dry-run and blocks nothing until you change it.

set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "run with sudo." >&2; exit 1; }

HERE="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
. "$HERE/lib/common.sh"
ROOT="$(cd "$HERE/.." && pwd)"
CONF_DIR=/etc/checkhook
CONF="$CONF_DIR/checkhook.yaml"
UNIT=/etc/systemd/system/checkhookd.service
BIN=/usr/local/bin

if [[ "${1:-}" == "--uninstall" ]]; then
  systemctl disable --now checkhookd 2>/dev/null || true
  rm -f "$UNIT"
  systemctl daemon-reload
  for l in checkhook checkhookd; do
    [[ -L "$BIN/$l" ]] && rm -f "$BIN/$l"
  done
  echo "checkhookd removed. Config kept at $CONF; the nft table is left as is"
  echo "(remove it with: sudo $ROOT/bin/checkhook teardown)."
  exit 0
fi

IFACE=""; ALERT=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --iface)      IFACE="$2"; shift 2 ;;
    --alert-file) ALERT="$2"; shift 2 ;;
    *) echo "unknown option: $1" >&2; exit 1 ;;
  esac
done
[[ -z "$IFACE" ]] && IFACE="$(ip -o -4 route show default | awk '{print $5; exit}')"

# --- prerequisites -----------------------------------------------------------
need_cmd nft nftables
python3 -c "import yaml" 2>/dev/null || { echo "PyYAML missing  ->  $(pkg_install_cmd) $(pkg_name pyyaml)" >&2; exit 1; }
python3 -c "import nfstream, sklearn, joblib" 2>/dev/null || \
  echo "[i] ML detector needs: $(pip_hint nfstream scikit-learn joblib)   (only when you train a model)"

# --- config (never overwrite an existing one) --------------------------------
mkdir -p "$CONF_DIR"
if [[ -f "$CONF" ]]; then
  echo "[=] keeping existing $CONF"
else
  cp "$HERE/checkhook.example.yaml" "$CONF"
  [[ -n "$IFACE" ]] && sed -i "s|^  iface: .*|  iface: $IFACE|" "$CONF"   # ml.iface and xdp.iface
  [[ -n "$ALERT" ]] && sed -i "s|^  alert_file: .*|  alert_file: $ALERT|" "$CONF"
  chmod 0644 "$CONF"
  echo "[+] wrote $CONF  (iface: ${IFACE:-?}, enforce: false)"
fi

# --- commands on PATH ------------------------------------------------------------
chmod +x "$ROOT/bin/checkhook" "$ROOT/bin/checkhookd"
for l in checkhook checkhookd; do
  ln -sfn "$ROOT/bin/$l" "$BIN/$l"
done
echo "[+] $BIN/checkhook, $BIN/checkhookd -> $ROOT/bin/"

# --- daemon ------------------------------------------------------------------------
sed "s|__ROOT__|$ROOT|g" "$HERE/checkhookd.service" > "$UNIT"
chmod 0644 "$UNIT"
systemctl daemon-reload
systemctl enable checkhookd >/dev/null 2>&1
systemctl restart checkhookd

MODEL="$(cd "$ROOT" && python3 -c "from checkhook import config; print(config.load('$CONF')['ml']['model'])")"
sleep 2
echo
echo "checkhookd : $(systemctl is-active checkhookd 2>/dev/null || true)"
if [[ -f "$MODEL" ]]; then
  echo "ML model   : $MODEL (ML detection on)"
else
  echo "ML model   : none at $MODEL yet — ML detection is off until you train one"
  echo "             (then: sudo systemctl restart checkhookd)"
fi
echo
echo "config  : $CONF   (enforce: false = dry-run; edit, then: sudo systemctl restart checkhookd)"
echo "logs    : checkhook logs        (journalctl -fu checkhookd)"
echo "report  : sudo checkhook report"
