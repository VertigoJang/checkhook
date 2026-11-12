#!/usr/bin/env python3
"""ML flow detector: classify live flows and feed the shared blocklist.

Uses nfstream for live flow features (same 57 features as training), a trained
RandomForest, and checkhook.blocklist for enforcement. Same safety rules as the
IDS bridge (loopback / RFC1918 never blocked; default --dry-run).

  sudo python3 -m checkhook.ml_detector -i eth0 --model model.joblib --dry-run
  sudo python3 -m checkhook.ml_detector -i eth0 --model model.joblib --backend nft --threshold 0.9
"""
import argparse

from checkhook.blocklist import Blocklist
from checkhook.features import FEATURES
from checkhook.policy import should_skip  # noqa: F401  (kept importable from here)


def attack_proba(clf, flow):
    """Attack-class probability for a single nfstream flow object."""
    x = [[getattr(flow, f, 0) or 0 for f in FEATURES]]
    classes = list(clf.classes_)
    if 1 in classes:
        return float(clf.predict_proba(x)[0][classes.index(1)])
    return float(clf.predict(x)[0])


ML_GID = 9000   # gid used for ML detections in the shared alert format


class AlertWriter:
    """Append ML detections as Snort-style JSON lines, so the LLM triage and
    the alert parser treat them like any other alert (gid 9000)."""

    def __init__(self, path, max_bytes=50 * 1024 * 1024):
        import os
        self.path, self.max = path, max_bytes
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)

    def write(self, src, dst, port, proto, p):
        import json, os, time
        try:
            if os.path.exists(self.path) and os.path.getsize(self.path) > self.max:
                os.replace(self.path, self.path + ".1")
            msg = f"CHECKHOOK-ML attack-like flow p={p:.2f} -> {dst}:{port}"
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps({"timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
                                    "gid": ML_GID, "sid": 1, "rev": 1, "msg": msg,
                                    "src_addr": src, "dst_addr": dst, "dst_port": port,
                                    "proto": proto, "score": round(p, 4)}) + "\n")
        except OSError:
            pass


def run(iface, clf=None, bl=None, threshold=0.9, block_private=False,
        idle=15, active=120, log=print, on_flow=None, stop=None,
        skip=(), local=None, refresh=3600, on_event=None, alerts=None, clock=None):
    """Classify live flows on `iface`.

    clf: trained classifier, or None to only observe flows (e.g. for logging).
    bl:  Blocklist to enforce with, or None for dry-run.
    on_flow: optional callback(flow) for every finished flow (flow logging).
    stop: optional threading.Event; checked between flows.
    skip / local: never-block IPs (config skip:, and this host's DNS servers,
      gateway and own addresses); same rules as the IDS bridge.
    refresh: seconds before a source that keeps scoring high is acted on again
      (= block_timeout, so it is blocked again once the block expired).
    on_event: optional callback(alert_dict, action) for the status board.
    alerts: optional AlertWriter; every high-scoring flow is recorded there.
    """
    import time
    from nfstream import NFStreamer
    clock = clock or time.monotonic
    seen = {}; skip = set(skip)
    ev = on_event or (lambda a, act: None)
    what = f"classifying (threshold {threshold})" if clf is not None else "observing"
    log(f"[*] {what} live flows on {iface}")
    for flow in NFStreamer(source=iface, statistical_analysis=True,
                           idle_timeout=idle, active_timeout=active):
        if stop is not None and stop.is_set():
            break
        if on_flow is not None:
            on_flow(flow)
        if clf is None:
            continue
        p = attack_proba(clf, flow)
        if p < threshold:
            continue
        src = flow.src_ip
        al = {"src": src, "gid": ML_GID, "sid": 1, "ids": "ml",
              "msg": f"CHECKHOOK-ML attack-like flow p={p:.2f} -> {flow.dst_ip}:{flow.dst_port}"}
        if alerts is not None:
            alerts.write(src, flow.dst_ip, flow.dst_port, flow.protocol, p)
        now = clock()
        if src in seen and now - seen[src] < refresh:
            ev(al, "recent"); continue
        if src in skip or should_skip(src, block_private) or (local is not None and src in local):
            ev(al, "skip"); continue
        seen[src] = now
        tag = "[BLOCK]" if bl is not None else "[would-block]"
        if bl is not None:
            bl.add(src)
        ev(al, "blocked" if bl is not None else "would-block")
        log(f"{tag} {src}  (ml p={p:.2f} -> {flow.dst_ip}:{flow.dst_port})")


def main():
    import joblib
    ap = argparse.ArgumentParser()
    ap.add_argument("-i", "--iface", required=True)
    ap.add_argument("--model", required=True)
    ap.add_argument("--backend", choices=["nft", "xdp", "winfw", "none"], default="none")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--timeout", default="1h")
    ap.add_argument("--threshold", type=float, default=0.9)
    ap.add_argument("--block-private", action="store_true")
    ap.add_argument("--idle", type=int, default=15, help="nfstream idle timeout (s)")
    ap.add_argument("--active", type=int, default=120, help="nfstream active timeout (s)")
    a = ap.parse_args()
    clf = joblib.load(a.model)["clf"]
    bl = None
    if a.backend != "none" and not a.dry_run:
        bl = Blocklist(backend=a.backend, default_timeout=a.timeout)
        bl.setup()
        print(f"[+] {a.backend} enforcement active (timeout {a.timeout})", flush=True)
    else:
        print("[*] DRY-RUN: no blocking, decisions only", flush=True)
    run(a.iface, clf, bl, a.threshold, a.block_private, a.idle, a.active,
        log=lambda m: print(m, flush=True))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[+] detector stopped")
