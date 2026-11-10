#!/usr/bin/env python3
"""LLM triage (read-only): the "Check" in CheckHook.

Looks at the IPs the detectors flagged (blocked, or would-be-blocked in
dry-run), compares them with this host's own network infrastructure (DNS
servers, default gateway, own addresses), and asks a local Ollama model which
of them are probably false positives. The report ends with a ready-to-paste
`skip:` line. It never changes the blocklist or the config: applying the
suggestion is left to a person.

  python3 -m checkhook.triage --alert-file /var/log/checkhook/snort/alert_json.txt
  python3 -m checkhook.triage --lang Korean --out report.md --skip 192.168.0.1
  python3 -m checkhook.triage --print-prompt
"""
import argparse, collections, ipaddress, json, os, re, subprocess, urllib.request
from checkhook.alerts import tail_alerts
from checkhook.policy import should_skip

WINDOWS = os.name == "nt"


# ----------------------------------------------------------------- inputs ----
def recent_alerts(path, last):
    """Newest `last` alerts, aggregated by signature, by source, and per source."""
    alerts = tail_alerts(path, last)
    sig = collections.Counter(); src = collections.Counter()
    per_src = collections.defaultdict(collections.Counter)
    for al in alerts:
        sig[(al["sid"], al["msg"])] += 1
        if al["src"]:
            src[al["src"]] += 1
            per_src[al["src"]][(al["sid"], al["msg"])] += 1
    return len(alerts), sig, src, per_src


def blocked_ips(backend="nft"):
    """Read-only view of the current blocklist (nft set, XDP map or Windows rules)."""
    from checkhook.blocklist import Blocklist
    try:
        bl = Blocklist(backend=backend)
        return bl.ips() if bl.exists() else []
    except Exception:
        return []


def _run(cmd, timeout=10):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout
    except Exception:
        return ""


def _ipv4s(text):
    out = []
    for tok in re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", text or ""):
        try:
            ipaddress.IPv4Address(tok)
        except ValueError:
            continue
        if tok not in out:
            out.append(tok)
    return out


def local_context():
    """This host's DNS servers, default gateways and own IPv4 addresses.

    Best effort: anything that can't be read is left empty."""
    dns, gw, own = [], [], []
    if WINDOWS:
        ps = ["powershell", "-NoProfile", "-Command"]
        dns = _ipv4s(_run(ps + ["Get-DnsClientServerAddress -AddressFamily IPv4 | "
                                "ForEach-Object { $_.ServerAddresses }"]))
        gw = _ipv4s(_run(ps + ["Get-NetRoute -DestinationPrefix 0.0.0.0/0 "
                               "-ErrorAction SilentlyContinue | ForEach-Object { $_.NextHop }"]))
        own = _ipv4s(_run(ps + ["Get-NetIPAddress -AddressFamily IPv4 | "
                                "ForEach-Object { $_.IPAddress }"]))
    else:
        for f in ("/etc/resolv.conf", "/run/systemd/resolve/resolv.conf"):
            try:
                with open(f, encoding="utf-8", errors="replace") as fh:
                    for line in fh:
                        if line.startswith("nameserver"):
                            dns += [ip for ip in _ipv4s(line) if ip not in dns]
            except OSError:
                pass
        # systemd-resolved stub (127.0.0.53) hides the real servers; ask NetworkManager too
        dns += [ip for ip in _ipv4s(_run(["nmcli", "-t", "-f", "IP4.DNS", "dev", "show"]))
                if ip not in dns]
        try:
            for r in json.loads(_run(["ip", "-j", "-4", "route", "show", "default"]) or "[]"):
                if r.get("gateway") and r["gateway"] not in gw:
                    gw.append(r["gateway"])
        except ValueError:
            pass
        try:
            for link in json.loads(_run(["ip", "-j", "-4", "addr"]) or "[]"):
                for a in link.get("addr_info", []):
                    if a.get("local") and a["local"] not in own:
                        own.append(a["local"])
        except ValueError:
            pass
    dns = [ip for ip in dns if not ipaddress.IPv4Address(ip).is_loopback]
    own = [ip for ip in own if not ipaddress.IPv4Address(ip).is_loopback]
    return {"dns": dns, "gateway": gw, "own": own}


# ----------------------------------------------------------------- analysis --
def flagged_ips(src, blocked, skip, block_private):
    """IPs a detector blocked or would block: blocked ones first, then every
    alerting source that the policy and the skip list would let through."""
    out = list(blocked)
    for ip, _ in src.most_common():
        if ip in out or ip in skip or should_skip(ip, block_private):
            continue
        out.append(ip)
    return out


def infra_hits(flagged, ctx):
    """Flagged IPs that are this host's own DNS server, gateway or address.
    These are false positives no matter what the model says."""
    role = {}
    for ip in ctx["dns"]:
        role.setdefault(ip, []).append("DNS server")
    for ip in ctx["gateway"]:
        role.setdefault(ip, []).append("default gateway")
    for ip in ctx["own"]:
        role.setdefault(ip, []).append("this host")
    return [(ip, role[ip]) for ip in flagged if ip in role]


def skip_line(skip, add):
    merged = list(skip) + [ip for ip in add if ip not in skip]
    return "skip: [" + ", ".join(merged) + "]"


# ----------------------------------------------------------------- prompt ----
def build_prompt(n, sig, src, per_src, flagged, blocked, enforce, ctx, skip, lang):
    L = []
    L.append("You are a SOC triage assistant for an AI-driven firewall.")
    L.append("Detection and enforcement are separate: detectors flag source IPs and the "
             "kernel drops them. Your job is review only: you cannot change anything.\n")
    L.append("## This host's network")
    L.append(f"- DNS servers: {', '.join(ctx['dns']) or '(unknown)'}")
    L.append(f"- default gateway: {', '.join(ctx['gateway']) or '(unknown)'}")
    L.append(f"- own addresses: {', '.join(ctx['own']) or '(unknown)'}")
    L.append(f"- never-block list (skip): {', '.join(skip) or '(empty)'}")
    L.append(f"\n## Recent alerts (total parsed: {n})")
    L.append("Top signatures (sid, message, count):")
    for (sid, msg), c in sig.most_common(10):
        L.append(f"  - sid={sid} \"{msg}\": {c}")
    mode = "blocked" if enforce else "would be blocked (dry-run, enforcement is off)"
    L.append(f"\n## Flagged IPs: {mode} ({len(flagged)})")
    if not flagged:
        L.append("(none)")
    for ip in flagged[:15]:
        tag = " [in blocklist]" if ip in blocked else ""
        top = "; ".join(f"sid={s} \"{m}\" x{c}" for (s, m), c in per_src[ip].most_common(3))
        L.append(f"  - {ip}{tag}: {src.get(ip, 0)} alerts: {top or '(no alert in window)'}")
    L.append(f"\n## Task (answer in {lang}, concise Markdown)")
    L.append("1. **Situation**: 2-3 sentences on what the activity looks like.")
    L.append("2. **Likely false positives**: for each flagged IP that is probably benign, one "
             "line: the IP and why (this host's DNS server or gateway, a public DNS resolver, "
             "a CDN or cloud service, an update server, a signature known to be noisy). "
             "Only judge the IPs listed above. Say how sure you are. If none, say so.")
    L.append("3. **Likely real attacks**: flagged IPs that look hostile, one line each.")
    L.append("4. **Suggested actions**: 1-3 concrete follow-ups (a skip entry, a rule to "
             "tune). Do NOT claim to have changed anything: a person applies changes.")
    return "\n".join(L)


def ask_ollama(host, model, prompt, timeout):
    data = json.dumps({"model": model, "prompt": prompt, "stream": False}).encode()
    req = urllib.request.Request(host.rstrip("/") + "/api/generate", data=data,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read()).get("response", "").strip()


# ----------------------------------------------------------------- report ----
TEXT = {
    "Korean": {
        "title": "# CheckHook 검토 보고서",
        "mode_on": "차단 켜짐", "mode_off": "기록만 함, enforce: false",
        "summary": "경보 {n}건, 차단 대상 IP {f}개 ({mode})",
        "infra": "## 이 컴퓨터의 네트워크 장비와 겹치는 IP",
        "infra_note": "아래 IP는 이 컴퓨터가 쓰는 DNS 서버, 게이트웨이, 자기 주소입니다. "
                      "차단하면 인터넷이 끊길 수 있으므로 오탐으로 보고 예외 목록에 넣는 것을 권합니다.",
        "infra_none": "차단 대상 중 이 컴퓨터의 DNS 서버, 게이트웨이, 자기 주소는 없습니다.",
        "apply": "적용하려면 설정 파일의 `skip:` 줄을 아래처럼 바꾸고 `sudo systemctl restart checkhookd`를 실행합니다.",
        "llm": "## LLM 검토",
        "llm_fail": "LLM에 연결하지 못해 이 부분은 비어 있습니다: {e}",
        "roles": {"DNS server": "DNS 서버", "default gateway": "게이트웨이", "this host": "이 컴퓨터"},
    },
    "English": {
        "title": "# CheckHook triage report",
        "mode_on": "enforcing", "mode_off": "log only, enforce: false",
        "summary": "{n} alerts, {f} flagged IPs ({mode})",
        "infra": "## Flagged IPs that are this host's own network infrastructure",
        "infra_note": "These are this host's DNS servers, gateway or own addresses. Blocking them "
                      "can cut the connection; treat them as false positives and add them to skip.",
        "infra_none": "No flagged IP is this host's DNS server, gateway or own address.",
        "apply": "To apply, change the `skip:` line in the config as below, then restart checkhookd.",
        "llm": "## LLM review",
        "llm_fail": "Could not reach the LLM, so this part is empty: {e}",
        "roles": {},
    },
}


def render(t, model, n, flagged, enforce, hits, skip, llm_text, llm_err):
    mode = t["mode_on"] if enforce else t["mode_off"]
    L = [t["title"], "", f"_model: {model}_", "", t["summary"].format(n=n, f=len(flagged), mode=mode), ""]
    L.append(t["infra"])
    if hits:
        L.append(t["infra_note"]); L.append("")
        for ip, roles in hits:
            L.append(f"- {ip}: {', '.join(t['roles'].get(r, r) for r in roles)}")
        L.append(""); L.append(t["apply"]); L.append("")
        L.append("```yaml"); L.append(skip_line(skip, [ip for ip, _ in hits])); L.append("```")
    else:
        L.append(t["infra_none"])
    L.append(""); L.append(t["llm"])
    L.append(llm_text if llm_text else t["llm_fail"].format(e=llm_err))
    return "\n".join(L) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--alert-file", default="/var/log/checkhook/snort/alert_json.txt")
    ap.add_argument("--last", type=int, default=500, help="use the newest N alerts")
    ap.add_argument("--model", default="qwen2.5:7b")
    ap.add_argument("--host", default="http://localhost:11434")
    ap.add_argument("--lang", default="English")
    ap.add_argument("--timeout", type=int, default=180)
    ap.add_argument("--out", default=None, help="write report to file (else stdout)")
    ap.add_argument("--print-prompt", action="store_true", help="just print the prompt and exit")
    ap.add_argument("--backend", choices=["nft", "xdp", "winfw"], default="nft",
                    help="which blocklist to read (read-only)")
    ap.add_argument("--skip", default="", help="comma-separated never-block IPs (config skip:)")
    ap.add_argument("--block-private", action="store_true")
    ap.add_argument("--enforce", action="store_true", help="enforcement is on (else dry-run)")
    a = ap.parse_args(argv)

    skip = [s.strip() for s in a.skip.split(",") if s.strip()]
    n, sig, src, per_src = recent_alerts(a.alert_file, a.last)
    blocked = blocked_ips(a.backend)
    flagged = flagged_ips(src, blocked, skip, a.block_private)
    ctx = local_context()
    hits = infra_hits(flagged, ctx)
    prompt = build_prompt(n, sig, src, per_src, flagged, blocked, a.enforce, ctx, skip, a.lang)
    if a.print_prompt:
        print(prompt); return 0
    print(f"[*] triage: {n} alerts, {len(flagged)} flagged IPs, "
          f"{len(hits)} on local infrastructure -> {a.model}")
    llm_text, llm_err = "", ""
    if flagged:
        try:
            llm_text = ask_ollama(a.host, a.model, prompt, a.timeout)
        except Exception as e:  # Ollama down, model missing, timeout...
            llm_err = f"{a.host}: {e} (check: curl {a.host}/api/tags)"
            print(f"[!] Ollama request failed: {llm_err}")
    else:
        llm_text = "-"
    t = TEXT.get(a.lang, TEXT["English"])
    out = render(t, a.model, n, flagged, a.enforce, hits, skip, llm_text, llm_err)
    if a.out:
        with open(a.out, "w", encoding="utf-8") as f:
            f.write(out)
        print(f"[+] wrote {a.out}")
    else:
        print("\n" + out)
    return 1 if llm_err else 0


if __name__ == "__main__":
    raise SystemExit(main())
