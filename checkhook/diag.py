"""Small read-only probes for the self-test scripts (packaging/selftest.sh,
packaging/windows/selftest.ps1). Kept here so the scripts never have to pass
quoted Python code on the command line (Windows PowerShell 5.1 mangles quotes
in native-command arguments).

  python -m checkhook.diag config          # config summary as JSON
  python -m checkhook.diag parse           # alert parser self-check
  python -m checkhook.diag network         # this host's DNS servers and gateway
  python -m checkhook.diag device IFACE    # Windows: config iface -> Npcap device
"""
import json, sys


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    cmd = argv[0] if argv else ""
    if cmd == "config":
        from checkhook import config
        c = config.load()
        print(json.dumps({
            "backend": c["backend"], "enforce": c["enforce"], "skip": c["skip"],
            "alert": c["ids"]["alert_file"], "ids": bool(c["ids"].get("enabled", True)),
            "iface": c["ml"]["iface"], "xdp_iface": c["xdp"]["iface"], "model": c["ml"]["model"],
            "host": c["triage"]["host"], "llm": c["triage"]["model"],
            "flows": c["capture"]["dir"]}))
    elif cmd == "version":
        import checkhook
        print(checkhook.__version__)
    elif cmd == "parse":
        from checkhook.alerts import parse_alert as p
        s = p('{"sid":1,"msg":"t","src_addr":"203.0.113.9","dst_addr":"10.0.0.1"}')
        e = p('{"event_type":"alert","src_ip":"203.0.113.9",'
              '"alert":{"signature_id":2,"signature":"t"}}')
        assert s and s["src"] == "203.0.113.9" and s["ids"] == "snort", s
        assert e and e["src"] == "203.0.113.9" and e["ids"] == "suricata", e
        assert p('{"event_type":"flow"}') is None
        print("ok")
    elif cmd == "network":
        from checkhook.netinfo import local_context
        c = local_context()
        print("dns=%s gateway=%s" % (",".join(c["dns"]) or "-", ",".join(c["gateway"]) or "-"))
    elif cmd == "device" and len(argv) > 1:
        from checkhook.winnet import capture_device
        print(capture_device(argv[1]))
    else:
        print(__doc__, file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
