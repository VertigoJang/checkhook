"""Privileged actions for the desktop app (run as root / Administrator).

The app runs as the normal user and calls this through pkexec (Linux) or from
an elevated process (Windows). Every argument is validated here; nothing from
the caller reaches a shell.

  checkhook ctl block <ip>            block an IP now, for block_timeout (a person's decision,
                                      e.g. after reading the LLM review; works with enforce off)
  checkhook ctl unblock <ip>          remove an IP from the blocklist now
  checkhook ctl skip-add <ip>         never block this IP (config skip:), restart
  checkhook ctl skip-remove <ip>
  checkhook ctl enforce on|off        turn blocking on/off (config enforce:), restart
  checkhook ctl pause [reason] | resume
  checkhook ctl triage                run the LLM review now
  checkhook ctl restart               restart checkhookd
"""
import ipaddress, os, re, subprocess, sys
import yaml
from checkhook import config


def die(msg, code=2):
    print(f"[x] {msg}", file=sys.stderr)
    sys.exit(code)


def need_ip(s):
    try:
        ip = ipaddress.IPv4Address(s.strip())
    except (ValueError, AttributeError):
        die(f"not an IPv4 address: {s!r}")
    return str(ip)


# ------------------------------------------------------------- config edit ---
def _read(path):
    with open(path, encoding="utf-8-sig") as f:
        return f.read()


def _write(path, text):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(text)
    try:
        os.chmod(tmp, os.stat(path).st_mode & 0o777)
    except OSError:
        pass
    os.replace(tmp, path)


def set_top_key(text, key, value_text):
    """Replace `key: ...` at the top level, keeping a trailing comment; append if missing."""
    pat = re.compile(rf"^{key}:[^\n#]*(#[^\n]*)?$", re.M)
    m = pat.search(text)
    if m:
        comment = m.group(1) or ""
        line = f"{key}: {value_text}"
        if comment:
            line = line.ljust(26) + " " + comment
        return text[:m.start()] + line + text[m.end():]
    return text.rstrip("\n") + f"\n{key}: {value_text}\n"


def edit_skip(path, ip, add):
    text = _read(path)
    cur = (yaml.safe_load(text) or {}).get("skip") or []
    cur = [str(x) for x in cur]
    if add and ip not in cur:
        cur.append(ip)
    if not add:
        cur = [x for x in cur if x != ip]
    _write(path, set_top_key(text, "skip", "[" + ", ".join(cur) + "]"))
    return cur


def edit_enforce(path, on):
    text = _read(path)
    _write(path, set_top_key(text, "enforce", "true" if on else "false"))


# ----------------------------------------------------------------- actions ---
def restart():
    if config.WINDOWS:
        ps = ("$all = Get-CimInstance Win32_Process; "
              "$d = $all | Where-Object { $_.CommandLine -match 'checkhook\\.daemon' }; "
              "foreach ($a in $d) { $all | Where-Object { $_.ParentProcessId -eq $a.ProcessId } | "
              "ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue } }; "
              "Stop-ScheduledTask -TaskName checkhookd -ErrorAction SilentlyContinue; "
              "Start-ScheduledTask -TaskName checkhookd")
        subprocess.run(["powershell", "-NoProfile", "-Command", ps], check=False)
    else:
        subprocess.run(["systemctl", "restart", "checkhookd"], check=False)


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if not argv:
        print(__doc__, file=sys.stderr)
        return 2
    if not config.WINDOWS and os.geteuid() != 0:
        die("needs root (the app asks for it through pkexec)")
    cmd, args = argv[0], argv[1:]
    path = config.DEFAULT_PATH
    c = config.load(path)

    if cmd == "block" and args:
        ip = need_ip(args[0])
        from checkhook.netinfo import local_context
        try:
            ctx = local_context()
            infra = set(ctx["dns"] + ctx["gateway"] + ctx["own"])
        except Exception:
            infra = set()
        if ip in infra or ip in [str(x) for x in c["skip"]]:
            die(f"{ip} is this host's own DNS server/gateway/address or in skip:; not blocking it")
        if ipaddress.IPv4Address(ip).is_loopback:
            die("refusing to block a loopback address")
        from checkhook.blocklist import Blocklist
        bl = Blocklist(backend=c["backend"], default_timeout=c["block_timeout"])
        bl.setup()
        bl.add(ip)
        print(f"[+] blocked {ip} for {c['block_timeout']} (manual)")
    elif cmd == "unblock" and args:
        ip = need_ip(args[0])
        from checkhook.blocklist import Blocklist
        Blocklist(backend=c["backend"]).remove(ip)
        print(f"[+] unblocked {ip}")
    elif cmd in ("skip-add", "skip-remove") and args:
        ip = need_ip(args[0])
        cur = edit_skip(path, ip, cmd == "skip-add")
        if cmd == "skip-add":
            try:
                from checkhook.blocklist import Blocklist
                Blocklist(backend=c["backend"]).remove(ip)
            except Exception:
                pass
        restart()
        print(f"[+] skip: [{', '.join(cur)}]")
    elif cmd == "enforce" and args and args[0] in ("on", "off"):
        edit_enforce(path, args[0] == "on")
        restart()
        print(f"[+] enforce: {'true' if args[0] == 'on' else 'false'}")
    elif cmd in ("pause", "resume"):
        from checkhook import collect
        return collect.main([cmd] + [re.sub(r"[^\w .:-]", "", a)[:60] for a in args])
    elif cmd == "triage":
        from checkhook import service
        sys.argv = ["checkhook.service", "triage"]
        return service.main() or 0
    elif cmd == "restart":
        restart()
        print("[+] checkhookd restarted")
    else:
        die(f"unknown or incomplete command: {' '.join(argv)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
