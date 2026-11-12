#!/usr/bin/env python3
"""XDP enforcement backend: build, attach, inspect and detach.

  sudo python3 -m checkhook.xdp load   [--iface IF] [--mode generic|native] [--config PATH]
  sudo python3 -m checkhook.xdp unload [--iface IF] [--config PATH]
  sudo python3 -m checkhook.xdp status

How it works
  * checkhook/bpf/checkhook_xdp.c is compiled with clang to an eBPF object.
  * `bpftool prog load ... pinmaps` loads it and pins its maps under
    /sys/fs/bpf/checkhook, so they outlive this process.
  * `bpftool net attach` hooks it to the interface. The attachment stays in
    the kernel until `unload`, independent of any CheckHook process.
  * Detectors add/remove blocked IPs by updating the pinned map (see
    checkhook.blocklist, backend "xdp"); the program drops matching sources before
    the kernel allocates an skb.

Wi-Fi drivers usually lack native XDP, so the default mode is "generic".
Requires: clang, bpftool, libbpf headers (RHEL: clang bpftool libbpf-devel).
"""
import argparse
import json
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "bpf", "checkhook_xdp.c")
OBJ_DIR = "/usr/local/lib/checkhook"
OBJ = os.path.join(OBJ_DIR, "checkhook_xdp.o")
PIN_DIR = "/sys/fs/bpf/checkhook"
PROG_PIN = os.path.join(PIN_DIR, "prog")
BLOCK_MAP = os.path.join(PIN_DIR, "checkhook_block")
STATS_MAP = os.path.join(PIN_DIR, "checkhook_stats")
ATTACH = {"generic": "xdpgeneric", "native": "xdpdrv"}


def _run(cmd, check=True):
    r = subprocess.run(cmd, capture_output=True, text=True)
    if check and r.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd)}\n{r.stderr.strip() or r.stdout.strip()}")
    return r


def need(tool, pkg):
    if not shutil.which(tool):
        sys.exit(f"[x] '{tool}' not found — install the '{pkg}' package "
                 "(packaging/install-xdp.sh prints the exact command for your distro)")


IFACE_FILE = "/run/checkhook-xdp.iface"   # where the program is attached right now


def loaded():
    return os.path.exists(BLOCK_MAP) and os.path.exists(PROG_PIN)


def build():
    """Compile the program if the object is missing or older than the source."""
    if os.path.exists(OBJ) and os.path.getmtime(OBJ) >= os.path.getmtime(SRC):
        return
    need("clang", "clang")
    os.makedirs(OBJ_DIR, exist_ok=True)
    arch_inc = f"/usr/include/{os.uname().machine}-linux-gnu"  # Debian layout; harmless elsewhere
    cmd = ["clang", "-O2", "-g", "-target", "bpf", "-c", SRC, "-o", OBJ]
    if os.path.isdir(arch_inc):
        cmd[1:1] = ["-I", arch_inc]
    try:
        _run(cmd)
    except RuntimeError as e:
        if "bpf_helpers.h" in str(e):
            sys.exit("[x] libbpf headers missing — install libbpf-devel (RHEL/openSUSE), "
                     "libbpf-dev (Debian/Ubuntu) or libbpf (Arch)")
        raise
    print(f"[+] built {OBJ}")


def load(iface, mode="generic"):
    need("bpftool", "bpftool")
    if mode not in ATTACH:
        sys.exit(f"[x] mode must be one of {list(ATTACH)}")
    if loaded():
        print(f"[=] already loaded ({PIN_DIR}); entries kept")
        return
    build()
    os.makedirs(PIN_DIR, exist_ok=True)
    _run(["bpftool", "prog", "load", OBJ, PROG_PIN, "type", "xdp", "pinmaps", PIN_DIR])
    try:
        _run(["bpftool", "net", "attach", ATTACH[mode], "pinned", PROG_PIN, "dev", iface])
    except RuntimeError:
        _cleanup_pins()
        raise
    try:
        with open(IFACE_FILE, "w") as f:
            f.write(iface + "\n")
    except OSError:
        pass
    print(f"[+] XDP attached to {iface} ({mode}); blocklist map: {BLOCK_MAP}")


def _cleanup_pins():
    for p in (PROG_PIN, BLOCK_MAP, STATS_MAP):
        if os.path.exists(p):
            os.unlink(p)
    if os.path.isdir(PIN_DIR) and not os.listdir(PIN_DIR):
        os.rmdir(PIN_DIR)


def unload(iface):
    # detach from the interface it was actually attached to (the config may
    # already name a different one, e.g. when switching interfaces)
    try:
        with open(IFACE_FILE) as f:
            iface = f.read().strip() or iface
    except OSError:
        pass
    if shutil.which("bpftool"):
        for mode in ("xdpgeneric", "xdpdrv", "xdp"):
            _run(["bpftool", "net", "detach", mode, "dev", iface], check=False)
    try:
        os.unlink(IFACE_FILE)
    except OSError:
        pass
    _cleanup_pins()
    print(f"[+] XDP detached from {iface}; pins removed")


def stats():
    """(dropped, expired) summed over CPUs; (None, None) if not loaded."""
    if not os.path.exists(STATS_MAP):
        return None, None
    out = json.loads(_run(["bpftool", "-j", "map", "dump", "pinned", STATS_MAP]).stdout or "[]")
    totals = [0, 0]
    for e in out:
        f = e.get("formatted", e)
        idx = f.get("key")
        if isinstance(idx, list):
            idx = int(idx[0], 16)
        vals = f.get("values", e.get("values", []))
        s = 0
        for v in vals:
            val = v.get("value")
            if isinstance(val, list):
                val = int.from_bytes(bytes(int(b, 16) for b in val), sys.byteorder)
            s += int(val)
        if idx in (0, 1):
            totals[idx] = s
    return tuple(totals)


def status():
    if not loaded():
        print("XDP enforcement: not loaded")
        return
    from checkhook.blocklist import Blocklist
    ips = Blocklist(backend="xdp").ips()
    dropped, expired = stats()
    print(f"XDP enforcement: loaded ({PIN_DIR})")
    print(f"  blocked IPs : {len(ips)}")
    print(f"  dropped pkts: {dropped}   expired entries removed: {expired}")
    net = _run(["bpftool", "net", "show"], check=False).stdout.splitlines()
    xdp_lines, in_xdp = [], False
    for line in net:                       # print the "xdp:" section only
        if line.rstrip().endswith(":") and not line.startswith(" "):
            in_xdp = line.strip().lower() == "xdp:"
            continue
        if in_xdp and line.strip():
            xdp_lines.append(line.strip())
    print("  attached to : " + (", ".join(xdp_lines) or "(none found)"))


def main():
    ap = argparse.ArgumentParser(description="CheckHook XDP enforcement backend")
    ap.add_argument("cmd", choices=["load", "unload", "status", "build"])
    ap.add_argument("--iface")
    ap.add_argument("--mode", choices=list(ATTACH))
    ap.add_argument("--config", default=None)
    a = ap.parse_args()
    if os.geteuid() != 0 and a.cmd != "build":
        sys.exit("[x] needs root")
    if a.cmd in ("load", "unload") and not (a.iface and a.mode):
        from checkhook import config
        c = config.load(a.config)
        a.iface = a.iface or c["xdp"]["iface"]
        a.mode = a.mode or c["xdp"]["mode"]
    if a.cmd == "build":
        build()
    elif a.cmd == "load":
        load(a.iface, a.mode)
    elif a.cmd == "unload":
        unload(a.iface)
    else:
        status()


if __name__ == "__main__":
    main()
