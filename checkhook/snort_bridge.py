#!/usr/bin/env python3
"""IDS alert -> shared blocklist bridge (detector).

Tails an IDS JSON alert stream (Snort 3 alert_json or Suricata eve.json,
auto-detected per line), extracts malicious source IPs, and feeds them to the
shared enforcement blocklist (checkhook.blocklist).

Safety: loopback / link-local / multicast / RFC1918 private IPs are never
blocked. Default mode is --dry-run (log decisions, do not block).

Run from the project root:
  sudo python3 -m checkhook.snort_bridge --alert-file /var/log/snort/alert_json.txt --dry-run
  sudo python3 -m checkhook.snort_bridge --alert-file /var/log/snort/alert_json.txt --backend nft --timeout 1h
"""
import argparse
import os
import time

from checkhook.alerts import Ignore, parse_alert
from checkhook.blocklist import Blocklist
from checkhook.policy import should_skip


def follow(path, from_start, stop=None):
    """tail -F: survives truncation AND rotation (Snort renames the file when
    alert_json's size limit is hit and starts a new one under the same name)."""
    if not os.path.exists(path):
        print(f"[*] waiting for {path} to appear (is the IDS running?)", flush=True)
        from_start = True        # a file that appears later is new: read all of it
    while not os.path.exists(path):
        if stop is not None and stop.is_set():
            return
        time.sleep(0.5)
    f = open(path, encoding="utf-8", errors="replace")
    ino = os.fstat(f.fileno()).st_ino
    if not from_start:
        f.seek(0, 2)
    while stop is None or not stop.is_set():
        line = f.readline()
        if line:
            yield line
            continue
        time.sleep(0.3)
        try:
            st = os.stat(path)
        except FileNotFoundError:
            continue                      # mid-rotation; wait for the new file
        if st.st_ino != ino:              # rotated: drain nothing more, reopen new
            f.close()
            f = open(path, encoding="utf-8", errors="replace")
            ino = os.fstat(f.fileno()).st_ino
        elif st.st_size < f.tell():       # truncated in place
            f.seek(0)


def run(alert_file, bl=None, skip=(), block_private=False, from_start=False,
        log=print, stop=None, ignore_gids=(), refresh=3600, clock=time.monotonic,
        ignore_rules=(), local=None, on_event=None):
    """Follow an IDS alert file and block (bl given) or only report sources.

    bl: a Blocklist to enforce with, or None for dry-run.
    stop: optional threading.Event to end the loop (checked between lines).
    ignore_gids / ignore_rules: Snort generator ids (e.g. the packet decoder)
      and single "gid:sid" rules that never lead to a block; their alerts are
      still kept for the triage.
    local: optional container of this host's own infrastructure IPs (DNS
      servers, gateway, own addresses; see netinfo.LocalInfra), never blocked.
    on_event: optional callback(alert, action) for every alert, action one of
      blocked, would-block, skip, ignored, recent (feeds the status board).
    refresh: seconds after which a source that keeps alerting is added again
      (= block_timeout, so an attacker is blocked again once its block expired).
    """
    seen = {}; skip = set(skip); ignore = Ignore(ignore_gids, ignore_rules)
    log(f"[*] tail {alert_file}" + (f" (not blocking on: {ignore})" if ignore else ""))
    for line in follow(alert_file, from_start, stop):
        al = parse_alert(line)                 # Snort alert_json or Suricata eve.json
        if not al:
            continue
        ev = on_event or (lambda a, act: None)
        src = al["src"]
        if not src:
            continue
        if ignore(al):
            ev(al, "ignored"); continue
        now = clock()
        if src in seen and now - seen[src] < refresh:
            ev(al, "recent"); continue
        seen[src] = now
        if src in skip or should_skip(src, block_private) or (local is not None and src in local):
            if bl is None:
                log(f"[skip]        {src}")
            ev(al, "skip"); continue
        tag = "[BLOCK]" if bl is not None else "[would-block]"
        if bl is not None:
            bl.add(src)
        ev(al, "blocked" if bl is not None else "would-block")
        log(f"{tag} {src}  ({al['ids']} sid={al['sid']} {al['msg']})")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--alert-file", required=True)
    ap.add_argument("--backend", choices=["nft", "xdp", "winfw", "none"], default="none")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--timeout", default="1h")
    ap.add_argument("--block-private", action="store_true")
    ap.add_argument("--from-start", action="store_true")
    ap.add_argument("--skip", nargs="*", default=[])
    a = ap.parse_args()

    bl = None
    if a.backend != "none" and not a.dry_run:
        bl = Blocklist(backend=a.backend, default_timeout=a.timeout)
        bl.setup()
        print(f"[+] {a.backend} enforcement active (timeout {a.timeout})", flush=True)
    else:
        print("[*] DRY-RUN: no blocking, decisions only", flush=True)
    run(a.alert_file, bl, a.skip, a.block_private, a.from_start,
        log=lambda m: print(m, flush=True))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[+] bridge stopped")
