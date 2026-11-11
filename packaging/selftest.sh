#!/usr/bin/env bash
# selftest.sh — check a CheckHook install end to end (Linux).
#
#   sudo bash packaging/selftest.sh
#
# Safe to run on a live system:
#   * the enforcement test adds and removes 203.0.113.250, an address reserved
#     for documentation (RFC 5737) that no real host uses, with a 2-minute
#     timeout so it expires even if the script is interrupted
#   * nothing else is changed: config, rules and services are only read
#
# Prints PASS / WARN / FAIL per check and a summary. Paste the whole output
# when reporting a problem. Exit code = number of FAILs.
set -u
HERE="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
cd "$ROOT" || exit 1
# shellcheck source=lib/common.sh
. "$HERE/lib/common.sh"

[[ $EUID -eq 0 ]] || { echo "run as root: sudo bash packaging/selftest.sh" >&2; exit 1; }

PASS=0; WARN=0; FAIL=0
pass() { PASS=$((PASS+1)); printf '  [PASS] %s\n' "$*"; }
warn() { WARN=$((WARN+1)); printf '  [WARN] %s\n' "$*"; }
fail() { FAIL=$((FAIL+1)); printf '  [FAIL] %s\n' "$*"; }
section() { printf '\n== %s ==\n' "$*"; }
TEST_IP=203.0.113.250

# ---------------------------------------------------------------- system ----
section "system"
VER="$(python3 -m checkhook.diag version 2>/dev/null || echo '?')"
echo "  checkhook : $VER"
echo "  distro    : $(. /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-unknown}") (family: $(distro_family))"
echo "  kernel    : $(uname -r)"
echo "  python    : $(python3 --version 2>&1)"
echo "  virt      : $(systemd-detect-virt 2>/dev/null; true)"
python3 -c 'import sys; sys.exit(sys.version_info < (3, 9))' \
  && pass "python >= 3.9" || fail "python 3.9 or newer needed"
python3 -c 'import yaml' 2>/dev/null && pass "PyYAML" \
  || fail "PyYAML missing -> $(pkg_install_cmd) $(pkg_name pyyaml)"
command -v nft >/dev/null && pass "nft" || fail "nft missing -> $(pkg_install_cmd) nftables"

# ---------------------------------------------------------------- config ----
section "config"
CONF_JSON="$(python3 -m checkhook.diag config 2>&1)"
if ! printf '%s' "$CONF_JSON" | python3 -c 'import json,sys; json.load(sys.stdin)' 2>/dev/null; then
  fail "config does not load: $CONF_JSON"
  printf '\nsummary: %d pass, %d warn, %d fail\n' "$PASS" "$WARN" "$FAIL"; exit "$FAIL"
fi
cfg() { printf '%s' "$CONF_JSON" | python3 -c "import json,sys; v=json.load(sys.stdin)['$1']; print(','.join(map(str,v)) if isinstance(v,list) else v)"; }
BACKEND="$(cfg backend)"; ALERT="$(cfg alert)"
pass "config loads: backend=$BACKEND enforce=$(cfg enforce) skip=[$(cfg skip)]"
for k in iface xdp_iface; do
  IF="$(cfg $k)"
  if [[ -e "/sys/class/net/$IF" ]]; then pass "$k: $IF exists"
  else
    if [[ "$k" == xdp_iface && "$BACKEND" != xdp ]]; then warn "$k: $IF does not exist (unused: backend is $BACKEND)"
    else fail "$k: interface $IF does not exist (ip -br link)"; fi
  fi
done

# -------------------------------------------------------------- services ----
section "services"
unit_state() { systemctl is-active "$1" 2>/dev/null; }
installed() { [[ -f "/etc/systemd/system/$1.service" ]]; }
[[ "$(unit_state checkhookd)" == active ]] && pass "checkhookd active" \
  || fail "checkhookd not active -> journalctl -u checkhookd -n 30"
for u in checkhook-capture checkhook-ids checkhook-xdp; do
  if installed "$u"; then
    [[ "$(unit_state $u)" == active ]] && pass "$u active" || fail "$u installed but not active -> journalctl -u $u -n 30"
  else
    case "$u" in
      checkhook-xdp) [[ "$BACKEND" == xdp ]] && fail "backend is xdp but checkhook-xdp is not installed" || echo "  [ -- ] $u not installed (backend $BACKEND)";;
      *) echo "  [ -- ] $u not installed";;
    esac
  fi
done

# ----------------------------------------------------------- enforcement ----
section "enforcement ($BACKEND)"
if [[ "$BACKEND" == xdp ]]; then
  python3 -m checkhook.xdp status >/tmp/checkhook-selftest.$$ 2>&1
  grep -q "loaded (" /tmp/checkhook-selftest.$$ \
    && pass "XDP loaded: $(grep -m1 'attached to' /tmp/checkhook-selftest.$$ | sed 's/^ *//')" \
    || fail "XDP not loaded: $(head -1 /tmp/checkhook-selftest.$$)"
  rm -f /tmp/checkhook-selftest.$$
fi
if [[ "$BACKEND" == nft ]] && ! nft list table ip checkhook >/dev/null 2>&1; then
  warn "nft table 'ip checkhook' not there yet (checkhookd creates it on start)"
fi
BL=(python3 -m checkhook.blocklist --backend "$BACKEND")
if "${BL[@]}" add "$TEST_IP" --timeout 2m >/dev/null 2>&1; then
  if "${BL[@]}" list 2>/dev/null | grep -qw "$TEST_IP"; then pass "add $TEST_IP -> listed"
  else fail "added $TEST_IP but it is not listed"; fi
  "${BL[@]}" remove "$TEST_IP" >/dev/null 2>&1
  if "${BL[@]}" list 2>/dev/null | grep -qw "$TEST_IP"; then fail "remove $TEST_IP failed (expires in 2 min anyway)"
  else pass "remove $TEST_IP -> gone"; fi
else
  fail "could not add $TEST_IP: $("${BL[@]}" add "$TEST_IP" --timeout 2m 2>&1 | tail -1)"
fi

# --------------------------------------------------------------- detection ---
section "detection"
python3 -m checkhook.diag parse >/dev/null 2>&1 && pass "alert parser reads Snort 3 and Suricata lines" || fail "alert parser"
if [[ "$(cfg ids)" != True ]]; then
  echo "  [ -- ] ids disabled in config"
elif [[ -r "$ALERT" ]]; then
  N="$(wc -l <"$ALERT")"; AGE=$(( $(date +%s) - $(stat -c %Y "$ALERT") ))
  pass "alert file $ALERT ($N lines, last write ${AGE}s ago)"
else
  warn "alert file $ALERT not there yet (created on the first alert; test: see local.rules)"
fi
command -v snort >/dev/null || [[ -x /usr/local/bin/snort ]] || command -v suricata >/dev/null \
  || warn "neither snort nor suricata found: signature detection has no input"
if [[ -f "$(cfg model)" ]]; then pass "ML model $(cfg model)"
else echo "  [ -- ] no ML model yet ($(cfg model)) — ML detection off until trained"; fi

# ---------------------------------------------------------------- capture ----
section "capture"
if installed checkhook-capture; then
  NEWEST="$(ls -t /var/lib/checkhook/benign*.pcap* 2>/dev/null | head -1)"
  if [[ -n "$NEWEST" ]]; then
    AGE=$(( $(date +%s) - $(stat -c %Y "$NEWEST") ))
    SIZE="$(du -sh /var/lib/checkhook 2>/dev/null | cut -f1)"
    (( AGE < 600 )) && pass "capture writing: $NEWEST (${AGE}s ago, total $SIZE)" \
      || warn "newest capture file is ${AGE}s old: $NEWEST (no traffic, or tcpdump stuck)"
  else
    fail "checkhook-capture installed but no /var/lib/checkhook/benign*.pcap* (SELinux/AppArmor? journalctl -u checkhook-capture)"
  fi
else
  echo "  [ -- ] checkhook-capture not installed"
fi

FLOWDIR="$(printf '%s' "$CONF_JSON" | python3 -c 'import json,sys; print(json.load(sys.stdin)["flows"])')"
if python3 -c 'import nfstream' 2>/dev/null; then
  NEWEST="$(ls -t "$FLOWDIR"/flows-*.csv 2>/dev/null | head -1)"
  if [[ -n "$NEWEST" ]]; then
    ROWS=0
    for f in "$FLOWDIR"/flows-*.csv; do n=$(wc -l <"$f"); (( n > 1 )) && ROWS=$(( ROWS + n - 1 )); done
    AGE=$(( $(date +%s) - $(stat -c %Y "$NEWEST") ))
    (( AGE < 900 )) && pass "flow log: $ROWS flows in $FLOWDIR (newest ${AGE}s ago)" \
      || warn "flow log: newest file is ${AGE}s old ($NEWEST)"
  else
    warn "flow log: no CSV in $FLOWDIR yet (written as flows finish; journalctl -u checkhookd | grep flows)"
  fi
else
  warn "nfstream not installed: no flow log and no ML (pip install nfstream)"
fi

# ----------------------------------------------------------- check (LLM) ----
section "check (LLM triage)"
CTX="$(python3 -m checkhook.diag network)"
[[ "$CTX" == *"dns=-"* ]] && warn "could not read this host's DNS servers ($CTX)" || pass "local network: $CTX"
HOST="$(cfg host)"; LLM="$(cfg llm)"
TAGS="$(python3 -c "import urllib.request,sys; print(urllib.request.urlopen('$HOST/api/tags', timeout=5).read().decode())" 2>/dev/null)"
if [[ -z "$TAGS" ]]; then
  warn "Ollama not reachable at $HOST (reports will have the local-network part only)"
elif printf '%s' "$TAGS" | grep -q "\"$LLM\""; then
  pass "Ollama at $HOST has model $LLM"
else
  warn "Ollama at $HOST is up but model $LLM is missing -> ollama pull $LLM"
fi
if python3 -m checkhook.triage --print-prompt --alert-file "$ALERT" --backend "$BACKEND" >/dev/null 2>&1; then
  pass "triage builds its prompt"
else
  fail "triage: $(python3 -m checkhook.triage --print-prompt --alert-file "$ALERT" --backend "$BACKEND" 2>&1 | tail -1)"
fi

printf '\nsummary: %d pass, %d warn, %d fail\n' "$PASS" "$WARN" "$FAIL"
exit "$FAIL"
