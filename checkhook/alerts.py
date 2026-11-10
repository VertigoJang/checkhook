"""IDS alert parsing shared by the bridge and the triage.

Understands, line by line (auto-detected):
  * Snort 3 alert_json:   {"src_addr": "...", "sid": 1000001, "msg": "...", ...}
  * Suricata eve.json:    {"event_type": "alert", "src_ip": "...",
                           "alert": {"signature_id": 2001219, "signature": "..."}, ...}
Other eve.json events (flow, dns, http, stats ...) are ignored.
"""
import json
import os


def parse_alert(line):
    """Return {"src", "sid", "msg", "ids"} for an alert line, else None."""
    line = line.strip()
    if not line or line[0] != "{":
        return None
    try:
        ev = json.loads(line)
    except json.JSONDecodeError:
        return None
    if not isinstance(ev, dict):
        return None
    if "event_type" in ev:                       # Suricata eve.json
        if ev.get("event_type") != "alert":
            return None
        al = ev.get("alert") or {}
        return {"src": ev.get("src_ip"), "sid": al.get("signature_id"),
                "msg": al.get("signature", ""), "ids": "suricata"}
    if "src_addr" in ev or "sid" in ev:          # Snort 3 alert_json
        return {"src": ev.get("src_addr"), "sid": ev.get("sid"),
                "msg": ev.get("msg", ""), "ids": "snort"}
    return None


def tail_alerts(path, last, max_bytes=64 * 1024 * 1024, block=1024 * 1024):
    """The newest `last` alerts in `path`, oldest first.

    Reads backwards from the end in blocks and stops once enough alerts are
    found or `max_bytes` were scanned, so a multi-GB eve.json full of flow and
    dns events is never read whole.
    """
    try:
        f = open(path, "rb")
    except FileNotFoundError:
        return []
    found = []
    with f:
        end = f.seek(0, os.SEEK_END)
        pos, scanned, rest = end, 0, b""
        while pos > 0 and len(found) < last and scanned < max_bytes:
            step = min(block, pos)
            pos -= step
            f.seek(pos)
            chunk = f.read(step) + rest
            lines = chunk.split(b"\n")
            rest = lines.pop(0) if pos > 0 else b""   # first piece may be partial
            for raw in reversed(lines):
                al = parse_alert(raw.decode("utf-8", "replace"))
                if al:
                    found.append(al)
                    if len(found) >= last:
                        break
            scanned += step
        if rest and len(found) < last:
            al = parse_alert(rest.decode("utf-8", "replace"))
            if al:
                found.append(al)
    found.reverse()
    return found
