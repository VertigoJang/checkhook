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
    """Return {"src", "gid", "sid", "msg", "ids"} for an alert line, else None.

    gid: Snort generator id (1 = text rules, 3 = shared-object rules, others
    are built-in inspectors such as the packet decoder or port_scan). Suricata
    rules use gid 1."""
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
        return {"src": ev.get("src_ip"), "gid": _int(al.get("gid"), 1),
                "sid": al.get("signature_id"), "msg": al.get("signature", ""),
                "ids": "suricata"}
    if "src_addr" in ev or "sid" in ev:          # Snort 3 alert_json
        return {"src": ev.get("src_addr"), "gid": _int(ev.get("gid"), 1),
                "sid": ev.get("sid"), "msg": ev.get("msg", ""), "ids": "snort"}
    return None


class Ignore:
    """Which alerts never lead to a block: whole generators (Snort gid, e.g. the
    packet decoder) and single rules written "gid:sid" (Suricata rules are gid 1)."""

    def __init__(self, gids=(), rules=()):
        self.gids = {int(g) for g in gids}
        self.rules = set()
        for r in rules:
            g, _, s = str(r).partition(":")
            self.rules.add((int(g), int(s)) if s else (1, int(g)))

    def __call__(self, al):
        gid = al.get("gid", 1)
        return gid in self.gids or (gid, _int(al.get("sid"), -1)) in self.rules

    def __bool__(self):
        return bool(self.gids or self.rules)

    def __str__(self):
        parts = [f"gid {g}" for g in sorted(self.gids)]
        parts += [f"{g}:{s}" for g, s in sorted(self.rules)]
        return ", ".join(parts)


def _int(v, default):
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


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
