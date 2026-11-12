"""Demo mode: point CheckHook at an isolated lab interface for a presentation.

  sudo checkhook demo on vboxnet0     # VirtualBox host-only network to a Kali VM
  sudo checkhook demo on vboxnet0 --model ~/checkhook-data/checkhook-model-v1.joblib
                                      # ... and use this ML model only while in demo mode
  sudo checkhook demo status
  sudo checkhook demo off             # put everything back exactly as it was

`on` saves the config and the Snort unit, pauses training-data collection (lab
attacks must never end up in the benign data), and switches the IDS, the ML
detector and XDP to the given interface with:
  enforce: false        nothing is blocked automatically; a person blocks from
                        the app after reading the LLM review
  block_private: true   the lab attacker has a private address (192.168.56.x)
protect_local still keeps this host's own address on that network safe.
"""
import os, re, shutil, subprocess, sys
from checkhook import config

STATE = "/var/lib/checkhook/demo"
CONF = config.DEFAULT_PATH
IDS_UNIT = "/etc/systemd/system/checkhook-ids.service"


def sh(*cmd, check=False):
    r = subprocess.run(cmd, capture_output=True, text=True)
    if check and r.returncode:
        sys.exit(f"[x] {' '.join(cmd)}: {r.stderr.strip()}")
    return r


def set_top(text, key, value):
    pat = re.compile(rf"^{key}:[^\n]*$", re.M)
    if pat.search(text):
        return pat.sub(f"{key}: {value}", text, count=1)
    return text.rstrip("\n") + f"\n{key}: {value}\n"


def set_in_section(text, section, key, value):
    m = re.search(rf"^{section}:[^\n]*\n((?:[ \t#][^\n]*\n|\n)*)", text, re.M)
    if not m:
        return text.rstrip("\n") + f"\n{section}:\n  {key}: {value}\n"
    body = m.group(1)
    pat = re.compile(rf"^  {key}:[^\n]*$", re.M)
    new = pat.sub(f"  {key}: {value}", body, count=1) if pat.search(body) else f"  {key}: {value}\n" + body
    return text[:m.start(1)] + new + text[m.end(1):]


def restart(*units):
    for u in units:
        if os.path.exists(f"/etc/systemd/system/{u}.service"):
            sh("systemctl", "restart", u)


MODEL_SAVED = "model.before"   # in STATE: the model that was installed before (if any)


def on(iface, model=None):
    if os.path.exists(STATE):
        sys.exit("[x] demo mode is already on (sudo checkhook demo off first)")
    if not os.path.exists(f"/sys/class/net/{iface}"):
        sys.exit(f"[x] no interface {iface}. Start the Kali VM with its host-only adapter first "
                 "(VirtualBox creates vboxnet0 then); ip -br link")
    os.makedirs(STATE)
    shutil.copy2(CONF, os.path.join(STATE, "checkhook.yaml"))
    if os.path.exists(IDS_UNIT):
        shutil.copy2(IDS_UNIT, os.path.join(STATE, "checkhook-ids.service"))
    from checkhook import collect
    collect.main(["pause", "demo", iface])

    c = config.load(CONF)
    if model:
        if not os.path.isfile(model):
            shutil.rmtree(STATE)
            sys.exit(f"[x] no model file {model}")
        live = c["ml"]["model"]
        if os.path.exists(live):
            shutil.copy2(live, os.path.join(STATE, MODEL_SAVED))
        with open(os.path.join(STATE, "model.path"), "w") as f:
            f.write(live + "\n")
        os.makedirs(os.path.dirname(live), exist_ok=True)
        shutil.copy2(model, live)
        print(f"[+] demo model installed: {model} -> {live}")
    with open(CONF, encoding="utf-8-sig") as f:
        t = f.read()
    t = set_top(t, "enforce", "false")
    t = set_top(t, "block_private", "true")
    t = set_in_section(t, "ml", "iface", iface)
    t = set_in_section(t, "xdp", "iface", iface)
    with open(CONF, "w", encoding="utf-8") as f:
        f.write(t)
    if os.path.exists(IDS_UNIT):
        with open(IDS_UNIT) as f:
            u = f.read()
        with open(IDS_UNIT, "w") as f:
            f.write(re.sub(r"(-i )\S+", rf"\g<1>{iface}", u, count=1))
        sh("systemctl", "daemon-reload")
    if c["backend"] == "xdp":
        restart("checkhook-xdp")
    restart("checkhook-ids", "checkhookd")
    print(f"[+] demo mode ON: IDS, ML and {c['backend']} on {iface}; enforce: false, "
          "block_private: true; training-data collection paused.")
    print("    back to normal: sudo checkhook demo off")


def off():
    if not os.path.exists(STATE):
        sys.exit("[x] demo mode is not on")
    backend_before = config.load(CONF)["backend"]
    shutil.copy2(os.path.join(STATE, "checkhook.yaml"), CONF)
    mpath = os.path.join(STATE, "model.path")
    if os.path.exists(mpath):
        with open(mpath) as f:
            live = f.read().strip()
        saved = os.path.join(STATE, MODEL_SAVED)
        if os.path.exists(saved):
            shutil.copy2(saved, live)
            print(f"[+] previous model restored: {live}")
        elif os.path.exists(live):
            os.unlink(live)
            print(f"[+] demo model removed: {live}")
    saved_unit = os.path.join(STATE, "checkhook-ids.service")
    if os.path.exists(saved_unit):
        shutil.copy2(saved_unit, IDS_UNIT)
        sh("systemctl", "daemon-reload")
    if backend_before == "xdp" or config.load(CONF)["backend"] == "xdp":
        restart("checkhook-xdp")
    restart("checkhook-ids", "checkhookd")
    from checkhook import collect
    collect.main(["resume"])
    shutil.rmtree(STATE)
    print("[+] demo mode OFF: config, Snort interface and XDP restored; collection resumed.")


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if os.geteuid() != 0:
        sys.exit("[x] needs root: sudo checkhook demo ...")
    cmd = argv[0] if argv else "status"
    if cmd == "on" and len(argv) > 1 and re.fullmatch(r"[\w.:-]{1,15}", argv[1]):
        model = None
        if "--model" in argv:
            i = argv.index("--model")
            model = os.path.expanduser(argv[i + 1]) if i + 1 < len(argv) else None
        on(argv[1], model)
    elif cmd == "off":
        off()
    elif cmd == "status":
        print("demo mode ON (saved state in %s)" % STATE if os.path.exists(STATE) else "demo mode off")
    else:
        print(__doc__, file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
