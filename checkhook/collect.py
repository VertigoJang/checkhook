"""Pause and resume training-data collection (attack practice on the same host).

While paused, checkhookd keeps detecting but writes no flow rows, and on Linux
the checkhook-capture packet capture is stopped. Every pause and resume is
appended to pauses.log, so a dataset can also drop that window afterwards.

  python3 -m checkhook.collect pause [reason...]
  python3 -m checkhook.collect resume
  python3 -m checkhook.collect status
"""
import os, subprocess, sys, time
from checkhook.config import WINDOWS, PROGRAMDATA

DATA = os.path.join(PROGRAMDATA, "") if WINDOWS else "/var/lib/checkhook"
FLAG = os.path.join(DATA, "collection.paused")
LOG = os.path.join(DATA, "pauses.log")


def paused():
    return os.path.exists(FLAG)


def _log(what):
    line = f"{time.strftime('%Y-%m-%dT%H:%M:%S%z')} {what}\n"
    with open(LOG, "a", encoding="utf-8") as f:
        f.write(line)


def _capture(action):
    if WINDOWS:
        return
    subprocess.run(["systemctl", action, "checkhook-capture"],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    cmd = argv[0] if argv else "status"
    os.makedirs(DATA, exist_ok=True)
    if cmd == "pause":
        reason = " ".join(argv[1:]) or "-"
        if not paused():
            with open(FLAG, "w", encoding="utf-8") as f:
                f.write(reason + "\n")
            _log(f"pause {reason}")
        _capture("stop")
        print("[=] training-data collection PAUSED (detection keeps running).")
        print("    resume with: checkhook resume")
    elif cmd == "resume":
        if paused():
            os.unlink(FLAG)
            _log("resume")
        _capture("start")
        print("[+] training-data collection resumed.")
    elif cmd == "status":
        print("paused" if paused() else "collecting")
    else:
        print(__doc__, file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
