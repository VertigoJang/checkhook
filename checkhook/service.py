#!/usr/bin/env python3
"""Run a CheckHook component from the YAML config (used by the systemd units).

  python3 -m checkhook.service ids    [--config PATH]   (alias: snort)
  python3 -m checkhook.service ml     [--config PATH]
  python3 -m checkhook.service triage [--config PATH]
  python3 -m checkhook.service show   [--config PATH]   # print the effective config

It translates the config into the component's normal command-line arguments,
so every component still behaves exactly as when run by hand.

Exit status 2 = misconfiguration (missing model, component disabled...). The
units treat it as final and do not restart-loop on it.
"""
import argparse
import os
import sys

from checkhook import config

EXIT_CONFIG = 2


def common_enforce_args(c):
    args = ["--timeout", str(c["block_timeout"])]
    if c["enforce"]:
        args += ["--backend", c["backend"]]
    else:
        args += ["--backend", "none", "--dry-run"]
    if c["block_private"]:
        args.append("--block-private")
    return args


def run(module_main, argv):
    sys.argv = [sys.argv[0]] + argv
    print("[checkhook] args:", " ".join(argv), flush=True)
    rc = module_main()
    if isinstance(rc, int) and rc:
        sys.exit(rc)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("component", choices=["ids", "snort", "ml", "triage", "show"])
    ap.add_argument("--config", default=None)
    a = ap.parse_args()
    if a.component == "snort":                # old name, same component
        a.component = "ids"
    c = config.load(a.config)

    if a.component == "show":
        import yaml
        print(yaml.safe_dump(c, sort_keys=False, allow_unicode=True), end="")
        return

    sect = c[a.component]
    if not sect.get("enabled", True):
        print(f"[checkhook] '{a.component}' is disabled in the config", flush=True)
        sys.exit(EXIT_CONFIG)

    mode = "ENFORCING" if c["enforce"] else "dry-run (enforce: false)"
    if a.component in ("ids", "ml"):
        print(f"[checkhook] {a.component}: {mode}", flush=True)

    if a.component == "ids":
        from checkhook.snort_bridge import main as m
        argv = ["--alert-file", sect["alert_file"]] + common_enforce_args(c)
        if c["skip"]:
            argv += ["--skip"] + [str(x) for x in c["skip"]]
        run(m, argv)

    elif a.component == "ml":
        if not os.path.exists(sect["model"]):
            print(f"[checkhook] model not found: {sect['model']} — train one first:\n"
                  f"  ./checkhook train --data ... --out {sect['model']}", flush=True)
            sys.exit(EXIT_CONFIG)
        from checkhook.ml_detector import main as m
        argv = ["-i", sect["iface"], "--model", sect["model"],
                "--threshold", str(sect["threshold"]),
                "--idle", str(sect["idle"]), "--active", str(sect["active"])]
        argv += common_enforce_args(c)
        run(m, argv)

    elif a.component == "triage":
        out = sect.get("out")
        if out:
            os.makedirs(os.path.dirname(out), exist_ok=True)
        from checkhook.triage import main as m
        argv = ["--alert-file", sect["alert_file"], "--last", str(sect["last"]),
                "--model", sect["model"], "--host", sect["host"],
                "--lang", sect["lang"], "--backend", c["backend"]]
        skip = [str(x) for x in (c.get("skip") or [])]
        if skip:
            argv += ["--skip", ",".join(skip)]
        if c.get("block_private"):
            argv.append("--block-private")
        if c.get("enforce"):
            argv.append("--enforce")
        gids = c["ids"].get("ignore_gids") or []
        if gids:
            argv += ["--ignore-gids", ",".join(str(g) for g in gids)]
        if out:
            argv += ["--out", out]
        run(m, argv)


if __name__ == "__main__":
    main()
