#!/usr/bin/env python3
"""Shared enforcement blocklist.

A single kernel-side blocklist that every detector feeds and that drops
matching source traffic. Entries carry a timeout so a dynamic,
detector-driven blocklist expires on its own.

Backends:
  nft  - nftables set in an isolated table 'ip checkhook' (input hook, prio -150).
         Separate from firewalld's tables; removed with `nft delete table ip checkhook`.
  xdp  - XDP program + pinned eBPF hash map (/sys/fs/bpf/checkhook), loaded by
         `python3 -m checkhook.xdp load`. Drops before the kernel allocates an skb.
         Expiry is checked in-kernel against CLOCK_MONOTONIC.
  winfw - Windows Defender Firewall rules (group "CheckHook"), see checkhook.winfw.
         Expiry is enforced by checkhookd (reconcile every minute).

CLI:
  python3 -m checkhook.blocklist [--backend nft|xdp] {setup|add IP|remove IP|list|flush|teardown}
"""
import ipaddress
import json
import re
import subprocess
import sys
import time

TABLE = "checkhook"
SETNAME = "blocklist"
BACKENDS = ("nft", "xdp", "winfw")


def _run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True)


_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}


def parse_timeout(t):
    """'90s' / '30m' / '1h' / '2d' / '1h30m' -> seconds (0 = never)."""
    t = str(t).strip().lower()
    if t in ("0", "never", "none", ""):
        return 0
    parts = re.findall(r"(\d+)([smhd])", t)
    if not parts or "".join(n + u for n, u in parts) != t:
        raise ValueError(f"bad timeout: {t!r} (use e.g. 90s, 30m, 1h, 2d)")
    return sum(int(n) * _UNITS[u] for n, u in parts)


class Blocklist:
    def __init__(self, backend="nft", default_timeout="1h"):
        if backend not in BACKENDS:
            raise ValueError(f"unknown backend {backend!r} (use one of {BACKENDS})")
        self.backend = backend
        self.default_timeout = default_timeout
        self._win = None
        if backend == "winfw":
            from checkhook.winfw import WinFirewall
            self._win = WinFirewall()

    # ------------------------------------------------------------------ setup
    def exists(self):
        if self.backend == "winfw":
            return True                       # the Windows firewall is always there
        if self.backend == "xdp":
            from checkhook import xdp
            return xdp.loaded()
        return _run(["nft", "list", "table", "ip", TABLE]).returncode == 0

    def setup(self, reset=False):
        """Make sure the enforcement point exists.

        nft: create table/set/chain/rule. reset=False (what detectors use)
        keeps an existing table and its entries so several detectors share one
        blocklist and a restart doesn't wipe active blocks. reset=True
        recreates it (CLI `setup`).
        xdp: the program is attached by `checkhook.xdp load` (checkhook-xdp service);
        here we only check it is there (reset=True also empties the map).
        """
        if self.backend == "winfw":
            if reset:
                self.flush()
            return
        if self.backend == "xdp":
            if not self.exists():
                import sys
                print("[x] XDP backend not loaded — sudo systemctl start checkhook-xdp "
                      "(or: sudo python3 -m checkhook.xdp load)", file=sys.stderr, flush=True)
                sys.exit(2)   # misconfiguration: services don't restart-loop on 2
            if reset:
                self.flush()
            return
        if not reset and self.exists():
            return
        _run(["nft", "delete", "table", "ip", TABLE])  # clean slate
        _run(["nft", "add", "table", "ip", TABLE])
        _run(["nft", "add", "set", "ip", TABLE, SETNAME,
              "{ type ipv4_addr; flags timeout; }"])
        _run(["nft", "add", "chain", "ip", TABLE, "input",
              "{ type filter hook input priority -150; }"])
        _run(["nft", "add", "rule", "ip", TABLE, "input",
              "ip saddr @" + SETNAME, "drop"])

    # ------------------------------------------------------------- entries
    def add(self, ip, timeout=None):
        to = timeout or self.default_timeout
        if self.backend == "winfw":
            self._win.add(ip, parse_timeout(to))
            return
        if self.backend == "xdp":
            secs = parse_timeout(to)
            expiry = time.monotonic_ns() + secs * 1_000_000_000 if secs else 0
            r = _run(["bpftool", "map", "update", "pinned", _xdp_map(), "key"] + _key(ip)
                     + ["value"] + _hexbytes(expiry.to_bytes(8, sys.byteorder)))
            if r.returncode != 0:
                raise RuntimeError(f"bpftool map update failed: {r.stderr.strip()}")
            return
        _run(["nft", "add", "element", "ip", TABLE, SETNAME,
              "{ %s timeout %s }" % (ip, to)])

    def remove(self, ip):
        if self.backend == "winfw":
            self._win.remove(ip)
            return
        if self.backend == "xdp":
            _run(["bpftool", "map", "delete", "pinned", _xdp_map(), "key"] + _key(ip))
            return
        _run(["nft", "delete", "element", "ip", TABLE, SETNAME, "{ %s }" % ip])

    def ips(self):
        """Currently blocked IPv4 addresses (expired entries excluded)."""
        if self.backend == "winfw":
            return [ip for ip, _ in self._win.entries()]
        if self.backend == "xdp":
            now = time.monotonic_ns()
            return sorted((ip for ip, exp in _xdp_entries() if exp == 0 or exp > now),
                          key=ipaddress.ip_address)
        text = self.list()
        return sorted(set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)),
                      key=ipaddress.ip_address)

    def list(self):
        """Human-readable contents (empty string if absent)."""
        if self.backend == "winfw":
            now = time.time()
            return "".join(f"{ip}  (no expiry)\n" if exp == 0 else
                           f"{ip}  (expires in {int(exp - now)}s)\n"
                           for ip, exp in self._win.entries())
        if self.backend == "xdp":
            if not self.exists():
                return ""
            now = time.monotonic_ns()
            lines = []
            for ip, exp in sorted(_xdp_entries(), key=lambda e: ipaddress.ip_address(e[0])):
                if exp == 0:
                    lines.append(f"{ip}  (no expiry)")
                elif exp > now:
                    lines.append(f"{ip}  (expires in {(exp - now) // 1_000_000_000}s)")
            return "".join(l + "\n" for l in lines)
        return _run(["nft", "list", "set", "ip", TABLE, SETNAME]).stdout

    def flush(self):
        if self.backend == "winfw":
            self._win.flush()
            return
        if self.backend == "xdp":
            for ip, _ in _xdp_entries():
                self.remove(ip)
            return
        _run(["nft", "flush", "set", "ip", TABLE, SETNAME])

    def reconcile(self):
        """Expire entries where the kernel can't (winfw). No-op elsewhere."""
        return self._win.reconcile() if self.backend == "winfw" else 0

    def teardown(self):
        if self.backend == "winfw":
            self._win.flush()                 # removes all CheckHook firewall rules
            return
        if self.backend == "xdp":
            raise SystemExit("XDP is detached by: sudo systemctl stop checkhook-xdp "
                             "(or: sudo python3 -m checkhook.xdp unload)")
        _run(["nft", "delete", "table", "ip", TABLE])


# ---------------------------------------------------------------- xdp helpers
def _xdp_map():
    from checkhook import xdp
    return xdp.BLOCK_MAP


def _hexbytes(b):
    return ["0x%02x" % x for x in b]


def _key(ip):
    addr = ipaddress.ip_address(ip)
    if addr.version != 4:
        raise ValueError(f"XDP backend is IPv4-only: {ip}")
    return _hexbytes(addr.packed)          # network byte order, as in iphdr->saddr


def _bytes_of(v, n):
    """bpftool JSON field -> raw bytes (accepts ['0x..',...] or an integer)."""
    if isinstance(v, list):
        return bytes(int(x, 16) for x in v)
    return int(v).to_bytes(n, sys.byteorder)


def _xdp_entries():
    """[(ip, expiry_ns)] from the pinned map."""
    r = _run(["bpftool", "-j", "map", "dump", "pinned", _xdp_map()])
    if r.returncode != 0 or not r.stdout.strip():
        return []
    out = []
    for e in json.loads(r.stdout):
        k = e["key"] if "key" in e else e["formatted"]["key"]
        v = e["value"] if "value" in e else e["formatted"]["value"]
        ip = str(ipaddress.IPv4Address(_bytes_of(k, 4)))
        out.append((ip, int.from_bytes(_bytes_of(v, 8), sys.byteorder)))
    return out


def _cli():
    import argparse
    ap = argparse.ArgumentParser(description="manage the CheckHook enforcement blocklist")
    ap.add_argument("cmd", choices=["setup", "add", "remove", "list", "flush", "teardown"])
    ap.add_argument("ip", nargs="?")
    ap.add_argument("--timeout", default="1h")
    ap.add_argument("--backend", choices=BACKENDS, default=None,
                    help="default: 'backend' from /etc/checkhook/checkhook.yaml, else nft")
    a = ap.parse_args()
    backend = a.backend
    if backend is None:
        try:
            from checkhook import config
            backend = config.load()["backend"]
        except SystemExit:
            backend = "nft"
    bl = Blocklist(backend=backend, default_timeout=a.timeout)
    if a.cmd == "setup":
        bl.setup(reset=True); print(f"[+] enforcement set up ({backend})")
    elif a.cmd == "add":
        if not a.ip: ap.error("add needs an IP")
        bl.setup()  # create (nft) / verify loaded (xdp); keeps existing entries
        bl.add(a.ip); print(f"[+] blocked {a.ip} (timeout {a.timeout}, {backend})")
    elif a.cmd == "remove":
        if not a.ip: ap.error("remove needs an IP")
        bl.remove(a.ip); print(f"[+] removed {a.ip}")
    elif a.cmd == "list":
        print(bl.list(), end="")
    elif a.cmd == "flush":
        bl.flush(); print("[+] flushed")
    elif a.cmd == "teardown":
        bl.teardown(); print("[+] torn down")


if __name__ == "__main__":
    _cli()
