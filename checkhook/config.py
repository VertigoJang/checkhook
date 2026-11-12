"""Load the CheckHook YAML config (/etc/checkhook/checkhook.yaml by default).

Missing keys fall back to the defaults below, so a minimal config works.
"""
import copy
import os

WINDOWS = os.name == "nt"
PROGRAMDATA = os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"), "CheckHook")

DEFAULT_PATH = os.environ.get(
    "CHECKHOOK_CONFIG",
    os.path.join(PROGRAMDATA, "checkhook.yaml") if WINDOWS else "/etc/checkhook/checkhook.yaml")

DEFAULTS = {
    "enforce": False,
    "backend": "nft",
    "block_timeout": "1h",
    "block_private": False,
    "skip": [],
    # never block this host's current DNS servers, default gateway and own
    # addresses (re-read every minute, so it follows the laptop between networks)
    "protect_local": True,
    # signature IDS: Snort 3 alert_json or Suricata eve.json (auto-detected).
    # Older configs call this section "snort:"; that is still accepted.
    # Alerts that never lead to a block (the triage still sees them):
    #   ignore_gids  - Snort built-in inspectors that flag protocol anomalies on
    #                  normal traffic: 116 packet decoder, 119 http_inspect,
    #                  128 ssh, 129 stream_tcp, 137 ssl. Kept: 1/3 rules,
    #                  112 arp_spoof, 122 port_scan.
    #   ignore_rules - single rules as "gid:sid" (Suricata rules are gid 1).
    #                  Default: 1:402 ICMP port unreachable and 1:408 ICMP echo
    #                  reply, i.e. replies to this host's own traffic.
    "ids": {"enabled": True, "alert_file": "/var/log/checkhook/snort/alert_json.txt",
            "ignore_gids": [116, 119, 128, 129, 137], "ignore_rules": ["1:402", "1:408"]},
    "ml": {"enabled": True, "iface": "eth0",
           "model": "/var/lib/checkhook/model.joblib",
           "threshold": 0.9, "idle": 15, "active": 120,
           # ML detections in the same JSON-lines format as Snort alerts (gid 9000),
           # read by the LLM triage together with ids.alert_file
           "alert_file": "/var/log/checkhook/ml_alerts.json"},
    "xdp": {"iface": "eth0", "mode": "generic"},
    "triage": {"enabled": True, "alert_file": "/var/log/snort/alert_json.txt",
               "last": 500, "model": "qwen2.5:7b",
               "host": "http://localhost:11434", "lang": "English",
               "out": "/var/lib/checkhook/triage/report.txt"},
    # flow logging for ML training data: every finished flow's features go to
    # CSV (a few hundred bytes per flow, versus megabytes of raw packets).
    # enabled: true / false / auto (= on when nfstream is installed).
    # rows_per_file x keep bounds the disk use (~20 MB per 50000 rows).
    "capture": {"enabled": "auto", "dir": "/var/lib/checkhook/flows",
                "rows_per_file": 50000, "keep": 100},
    "daemon": {"expiry_interval": 60, "triage_interval": 3600},
}

if WINDOWS:   # same structure, Windows locations and enforcement
    DEFAULTS["backend"] = "winfw"
    DEFAULTS["ids"]["alert_file"] = os.path.join(PROGRAMDATA, "suricata", "eve.json")
    DEFAULTS["ml"]["iface"] = "auto"
    DEFAULTS["ml"]["model"] = os.path.join(PROGRAMDATA, "model.joblib")
    DEFAULTS["ml"]["alert_file"] = os.path.join(PROGRAMDATA, "logs", "ml_alerts.json")
    DEFAULTS["triage"]["alert_file"] = DEFAULTS["ids"]["alert_file"]
    DEFAULTS["triage"]["out"] = os.path.join(PROGRAMDATA, "triage", "report.txt")
    DEFAULTS["capture"].update({"enabled": True, "dir": os.path.join(PROGRAMDATA, "flows")})


def _merge(base, over):
    out = copy.deepcopy(base)
    for k, v in (over or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _merge(out[k], v)
        else:
            out[k] = v
    return out


def load(path=None):
    path = path or DEFAULT_PATH
    try:
        import yaml
    except ImportError:
        raise SystemExit("PyYAML is missing: install python3-pyyaml (RHEL/Fedora), python3-yaml "
                         "(Debian/Ubuntu), python-yaml (Arch), python3-PyYAML (openSUSE), "
                         "or: pip install pyyaml")
    if not os.path.exists(path):
        hint = ("packaging\\windows\\install.ps1" if WINDOWS
                else "sudo bash packaging/install-services.sh")
        raise SystemExit(f"config not found: {path} (install: {hint})")
    with open(path, encoding="utf-8-sig") as f:   # BOM: PowerShell 5.1 writes one
        data = yaml.safe_load(f) or {}
    if not isinstance(data, dict):
        raise SystemExit(f"config {path}: top level must be a mapping")
    if "snort" in data:                       # backward compatibility (<= 1.0)
        legacy = data.pop("snort")
        data.setdefault("ids", legacy)
    return _merge(DEFAULTS, data)
