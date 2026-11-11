#!/usr/bin/env python3
"""checkhookd — the CheckHook daemon: every detector in one long-running process.

Linux: started by systemd (checkhookd.service), logs to the journal.
Windows: started at boot by the "checkhookd" SYSTEM scheduled task, logs to
%ProgramData%/CheckHook/logs/checkhookd.log.

  checkhookd [--config PATH]          (= python3 -m checkhook.daemon)

Workers (each restarts itself with back-off if it fails):
  ids     follow the IDS alert file (Suricata eve.json / Snort alert_json)
  flows   one live nfstream capture: ML classification (if a model exists)
          and flow logging for training data (capture.enabled)
  expiry  remove expired blocks every daemon.expiry_interval seconds
          (needed for the Windows firewall, which has no timeouts)
  triage  read-only LLM report every daemon.triage_interval seconds

Safety is the same as everywhere else: with `enforce: false` nothing is
blocked; detectors only log what they would block.
"""
import argparse
import logging
import logging.handlers
import os
import signal
import subprocess
import sys
import threading
import time

from checkhook import config


def setup_logging(c):
    """Windows: rotating log file (+ console). Linux: stdout only — systemd
    puts it in the journal (journalctl -u checkhookd)."""
    log = logging.getLogger("checkhook")
    log.setLevel(logging.INFO)
    sh = logging.StreamHandler(sys.stdout)
    if config.WINDOWS:
        log_dir = os.path.join(config.PROGRAMDATA, "logs")
        os.makedirs(log_dir, exist_ok=True)
        path = os.path.join(log_dir, "checkhookd.log")
        fmt = logging.Formatter("%(asctime)s %(threadName)-6s %(message)s")
        fh = logging.handlers.RotatingFileHandler(path, maxBytes=5_000_000, backupCount=5,
                                                  encoding="utf-8")
        fh.setFormatter(fmt)
        log.addHandler(fh)
        sh.setFormatter(fmt)
    else:
        path = "journal (journalctl -u checkhookd)"
        sh.setFormatter(logging.Formatter("%(threadName)-6s %(message)s"))
    log.addHandler(sh)
    return log, path


def supervised(name, fn, stop, log):
    """Run fn() in a thread; restart it with back-off until stop is set."""
    # keep the daemon alive: a failing worker never takes the others down
    def loop():
        delay = 5
        while not stop.is_set():
            try:
                fn()
                if stop.is_set():
                    return
                log.info(f"{name} returned; restarting in {delay}s")
            except Exception as e:
                log.error(f"{name} failed: {e!r}; restarting in {delay}s")
            if stop.wait(delay):
                return
            delay = min(delay * 2, 300)
    t = threading.Thread(target=loop, name=name, daemon=True)
    t.start()
    return t


def main():
    ap = argparse.ArgumentParser(prog="checkhookd", description="CheckHook daemon (all detectors in one process)")
    ap.add_argument("--config", default=None)
    a = ap.parse_args()
    c = config.load(a.config)
    log, log_path = setup_logging(c)
    stop = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(sig, lambda *_: stop.set())
        except (ValueError, OSError):
            pass

    from checkhook.blocklist import Blocklist
    backend, timeout = c["backend"], c["block_timeout"]
    enforcer = Blocklist(backend=backend, default_timeout=timeout)
    bl = None
    if c["enforce"]:
        enforcer.setup()
        bl = enforcer
    log.info(f"checkhookd start: backend={backend} enforce={c['enforce']} "
             f"({'ENFORCING' if bl else 'dry-run'}); log {log_path}")

    workers = []

    # ---- ids ------------------------------------------------------------------
    if c["ids"].get("enabled", True):
        from checkhook import snort_bridge
        from checkhook.blocklist import parse_timeout
        refresh = parse_timeout(c["block_timeout"]) or 3600
        workers.append(supervised("ids", lambda: snort_bridge.run(
            c["ids"]["alert_file"], bl, c["skip"], c["block_private"],
            log=log.info, stop=stop, ignore_gids=c["ids"].get("ignore_gids") or [],
            ignore_rules=c["ids"].get("ignore_rules") or [], refresh=refresh), stop, log))

    # ---- flows: ML + flow logging, one capture ---------------------------------
    ml, cap = c["ml"], c["capture"]
    model_ok = ml.get("enabled", True) and os.path.exists(ml["model"])
    if ml.get("enabled", True) and not model_ok:
        log.info(f"ml: no model at {ml['model']} yet — classification off")
    if model_ok or cap.get("enabled"):
        def flows():
            from checkhook import ml_detector
            clf = None
            if model_ok:
                import joblib
                clf = joblib.load(ml["model"])["clf"]
            iface = ml["iface"]
            if os.name == "nt":
                from checkhook.winnet import capture_device
                iface = capture_device(iface)
            logger = None
            if cap.get("enabled"):
                from checkhook.flowlog import FlowLogger
                logger = FlowLogger(cap["dir"])
                log.info(f"flow logging -> {cap['dir']}")
            try:
                ml_detector.run(iface, clf, bl, ml["threshold"], c["block_private"],
                                ml["idle"], ml["active"], log=log.info,
                                on_flow=logger.write if logger else None, stop=stop)
            finally:
                if logger:
                    logger.close()
        workers.append(supervised("flows", flows, stop, log))

    # ---- expiry ---------------------------------------------------------------
    def expiry():
        while not stop.wait(c["daemon"]["expiry_interval"]):
            n = enforcer.reconcile()
            if n:
                log.info(f"expired {n} block(s)")
    workers.append(supervised("expiry", expiry, stop, log))

    # ---- triage (separate process: a hung or crashing LLM call can't hurt us) --
    if c["triage"].get("enabled", True):
        def triage():
            while not stop.wait(c["daemon"]["triage_interval"]):
                cmd = [sys.executable, "-m", "checkhook.service", "triage"]
                if a.config:
                    cmd += ["--config", a.config]
                r = subprocess.run(cmd, capture_output=True, text=True,
                                   cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
                tail = (r.stdout + r.stderr).strip().splitlines()[-1:] or [""]
                log.info(f"triage exit {r.returncode}: {tail[0]}")
        workers.append(supervised("triage", triage, stop, log))

    try:
        while not stop.wait(1):
            pass
    except KeyboardInterrupt:
        stop.set()
    log.info("checkhookd stopping")
    time.sleep(1)


if __name__ == "__main__":
    main()
