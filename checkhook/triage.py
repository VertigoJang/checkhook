#!/usr/bin/env python3
"""LLM triage (read-only): summarize recent detections and flag likely false
positives using a local Ollama model. Never changes the blocklist.

  python3 -m checkhook.triage --alert-file /var/log/snort/alert_json.txt
  python3 -m checkhook.triage --model qwen3:8b --lang Korean --out report.md
"""
import argparse, json, re, subprocess, collections, urllib.request
from checkhook.alerts import tail_alerts

def recent_alerts(path, last):
    """Aggregate the newest `last` alerts (Snort alert_json or Suricata eve.json)
    by signature and by source."""
    alerts = tail_alerts(path, last)
    sig = collections.Counter(); src = collections.Counter()
    for al in alerts:
        sig[(al["sid"], al["msg"])] += 1
        if al["src"]:
            src[al["src"]] += 1
    return len(alerts), sig.most_common(10), src.most_common(10)

def blocked_ips(backend="nft"):
    """Read-only view of the current blocklist (nft set or XDP map)."""
    from checkhook.blocklist import Blocklist
    try:
        bl = Blocklist(backend=backend)
        return bl.ips() if bl.exists() else []
    except Exception:
        return []

def build_prompt(n, top_sig, top_src, blocked, lang):
    L = []
    L.append("You are a SOC triage assistant for an AI-driven firewall.")
    L.append("Detection and enforcement are separate: detectors flag source IPs, "
             "and the kernel drops them. Your job is review, not enforcement.\n")
    L.append(f"## Recent alerts (total parsed: {n})")
    L.append("Top signatures (sid, message, count):")
    for (sid, msg), c in top_sig:
        L.append(f"  - sid={sid} \"{msg}\": {c}")
    L.append("Top alerting sources (ip, count):")
    for ip, c in top_src:
        L.append(f"  - {ip}: {c}")
    L.append(f"\n## Currently blocked IPs ({len(blocked)})")
    L.append(", ".join(blocked) if blocked else "(none)")
    L.append(f"\n## Task (answer in {lang}, concise Markdown)")
    L.append("1. **Situation**: 2-3 sentences on what the activity looks like.")
    L.append("2. **Likely false positives**: among the blocked IPs, list any that are "
             "probably benign (well-known services, CDNs, DNS resolvers, internal hosts) "
             "with a one-line reason each. If none, say so.")
    L.append("3. **Suggested actions**: 1-3 concrete follow-ups or rule ideas. "
             "Do NOT claim to have changed anything — enforcement stays manual.")
    return "\n".join(L)

def ask_ollama(host, model, prompt, timeout):
    data = json.dumps({"model": model, "prompt": prompt, "stream": False}).encode()
    req = urllib.request.Request(host.rstrip("/") + "/api/generate", data=data,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read()).get("response", "").strip()

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--alert-file", default="/var/log/snort/alert_json.txt")
    ap.add_argument("--last", type=int, default=500, help="use the newest N alerts")
    ap.add_argument("--model", default="qwen2.5:7b")
    ap.add_argument("--host", default="http://localhost:11434")
    ap.add_argument("--lang", default="English")
    ap.add_argument("--timeout", type=int, default=180)
    ap.add_argument("--out", default=None, help="write report to file (else stdout)")
    ap.add_argument("--print-prompt", action="store_true", help="just print the prompt and exit")
    ap.add_argument("--backend", choices=["nft", "xdp"], default="nft",
                    help="which blocklist to read (read-only)")
    a = ap.parse_args()

    n, top_sig, top_src = recent_alerts(a.alert_file, a.last)
    blocked = blocked_ips(a.backend)
    prompt = build_prompt(n, top_sig, top_src, blocked, a.lang)
    if a.print_prompt:
        print(prompt); return
    print(f"[*] triage: {n} alerts, {len(blocked)} blocked IPs -> {a.model}")
    try:
        report = ask_ollama(a.host, a.model, prompt, a.timeout)
    except Exception as e:  # Ollama down, model missing, timeout...
        raise SystemExit(f"[!] Ollama request to {a.host} failed: {e}\n"
                         f"    check:  curl {a.host}/api/tags   (model '{a.model}' must be listed)")
    header = f"# AI firewall triage report\n\n_model: {a.model}_\n\n"
    out = header + report + "\n"
    if a.out:
        with open(a.out, "w") as f:
            f.write(out)
        print(f"[+] wrote {a.out}")
    else:
        print("\n" + out)

if __name__ == "__main__":
    main()
