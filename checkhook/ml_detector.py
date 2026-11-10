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


def run(iface, clf=None, bl=None, threshold=0.9, block_private=False,
        idle=15, active=120, log=print, on_flow=None, stop=None):
    """Classify live flows on `iface`.

    clf: trained classifier, or None to only observe flows (e.g. for logging).
    bl:  Blocklist to enforce with, or None for dry-run.
    on_flow: optional callback(flow) for every finished flow (flow logging).
    stop: optional threading.Event; checked between flows.
    """
    from nfstream import NFStreamer
    seen = set()
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
        if src in seen or should_skip(src, block_private):
            continue
        seen.add(src)
        tag = "[BLOCK]" if bl is not None else "[would-block]"
        if bl is not None:
            bl.add(src)
        log(f"{tag} {src}  (p={p:.2f} -> {flow.dst_ip}:{flow.dst_port})")


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
