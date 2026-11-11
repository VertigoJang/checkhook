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
import argparse, collections, json, re, urllib.request
from checkhook.alerts import Ignore, tail_alerts
from checkhook.policy import should_skip
from checkhook.netinfo import local_context



# ----------------------------------------------------------------- inputs ----
def recent_alerts(path, last, ignore=None):
    """Newest `last` alerts, aggregated by signature, by source, and per source.

    Only alerts whose gid is not ignored count towards `src` (the sources the
    bridge would block); `per_src` keeps every alert for context."""
    ignore = ignore or Ignore()
    alerts = tail_alerts(path, last)
    sig = collections.Counter(); src = collections.Counter()
    per_src = collections.defaultdict(collections.Counter)
    for al in alerts:
        key = (al.get("gid", 1), al["sid"], al["msg"])
        sig[key] += 1
        if al["src"]:
            per_src[al["src"]][key] += 1
            if not ignore(al):
                src[al["src"]] += 1
    return len(alerts), sig, src, per_src


def blocked_ips(backend="nft"):
    """Read-only view of the current blocklist (nft set, XDP map or Windows rules)."""
    from checkhook.blocklist import Blocklist
    try:
        bl = Blocklist(backend=backend)
        return bl.ips() if bl.exists() else []
    except Exception:
        return []


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
LLM_LIMIT = 15          # flagged IPs sent to the model (most alerts first)
VERDICTS = ("false_positive", "attack", "unclear")
CONFIDENCE = ("high", "medium", "low")


def _sigs(counter, k=3):
    return "; ".join(f"gid={g} sid={s} \"{m}\" x{c}" for (g, s, m), c in counter.most_common(k))


def build_prompt(n, sig, src, per_src, flagged, blocked, enforce, ctx, lang):
    L = []
    L.append("You review alerts for a host firewall. Detectors flagged the source IPs below; "
             "you judge, for each of them, whether it is a false positive or a real attack. "
             "You cannot change anything; a person reads your answer.\n")
    L.append("Context about this host (these addresses are NOT under review):")
    L.append(f"- its DNS servers: {', '.join(ctx['dns']) or 'unknown'}")
    L.append(f"- its default gateway: {', '.join(ctx['gateway']) or 'unknown'}")
    L.append("Snort gid 1 and 3 are signature rules; other gids are built-in inspectors "
             "(packet decoder, stream, protocol anomalies, port_scan). Protocol anomalies on "
             "ordinary HTTPS/CDN/update traffic are usually not attacks; a port scan is.\n")
    L.append(f"Alerts in the window: {n}. Most frequent:")
    for (g, s, m), c in sig.most_common(8):
        L.append(f"- gid={g} sid={s} \"{m}\": {c}")
    mode = "blocked" if enforce else "would be blocked (dry-run)"
    L.append(f"\nIPs to review ({mode}):")
    for ip in flagged[:LLM_LIMIT]:
        L.append(f"- {ip}: {src.get(ip, 0)} alerts; {_sigs(per_src[ip]) or 'no alert in window'}")
    L.append(f"""
Answer with JSON only, in this shape:
{{"situation": "<2-3 sentences in {lang}>",
 "verdicts": [{{"ip": "<one of the IPs to review>",
               "verdict": "false_positive" | "attack" | "unclear",
               "confidence": "high" | "medium" | "low",
               "reason": "<one short sentence in {lang}>"}}],
 "actions": ["<up to 3 short follow-ups in {lang}, e.g. a rule to tune>"]}}
Give exactly one verdict per IP to review and no other IPs. Use "unclear" when
the alerts do not say enough. Never claim to have changed anything.""")
    return "\n".join(L)


def parse_review(text, flagged):
    """Validate the model's JSON. Unknown IPs, bad verdicts and duplicates are
    dropped, so the report only ever states things about the reviewed IPs."""
    try:
        data = json.loads(text)
    except (TypeError, ValueError):
        m = re.search(r"\{.*\}", text or "", re.S)
        if not m:
            return None
        try:
            data = json.loads(m.group(0))
        except ValueError:
            return None
    if not isinstance(data, dict):
        return None
    allowed = set(flagged[:LLM_LIMIT]); verdicts = {}
    for v in data.get("verdicts") or []:
        if not isinstance(v, dict):
            continue
        ip = str(v.get("ip", "")).strip()
        if ip not in allowed or ip in verdicts or v.get("verdict") not in VERDICTS:
            continue
        conf = v.get("confidence") if v.get("confidence") in CONFIDENCE else "low"
        verdicts[ip] = {"verdict": v["verdict"], "confidence": conf,
                        "reason": str(v.get("reason", "")).strip()[:300]}
    actions = [str(x).strip()[:300] for x in (data.get("actions") or [])
               if isinstance(x, (str, int, float)) and str(x).strip()][:3]
    return {"situation": str(data.get("situation", "")).strip()[:800],
            "verdicts": verdicts, "actions": actions}


def ask_ollama(host, model, prompt, timeout):
    data = json.dumps({"model": model, "prompt": prompt, "stream": False,
                       "format": "json", "options": {"temperature": 0}}).encode()
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
        "infra": "## 1. 이 컴퓨터의 네트워크 장비와 겹치는 IP",
        "infra_note": "아래 IP는 이 컴퓨터가 지금 쓰는 DNS 서버, 게이트웨이, 자기 주소이므로 오탐입니다. "
                      "`protect_local: true`(기본값)이면 차단되지 않습니다. 이 설정을 껐다면 예외 목록에 넣습니다.",
        "infra_none": "차단 대상 중 이 컴퓨터의 DNS 서버, 게이트웨이, 자기 주소는 없습니다.",
        "llm": "## 2. LLM 판단 ({model})",
        "llm_fail": "LLM에 연결하지 못해 이 부분은 비어 있습니다: {e}",
        "llm_bad": "LLM 답변을 해석하지 못했습니다. 원문:",
        "llm_none": "검토할 IP가 없습니다.",
        "more": "경보가 많은 순서로 {k}개만 LLM에 보냈습니다. 나머지 {r}개는 판단하지 않았습니다.",
        "head": "| IP | 판단 | 확신 | 경보 | 근거 |",
        "verdict": {"false_positive": "오탐", "attack": "공격", "unclear": "불분명"},
        "conf": {"high": "높음", "medium": "보통", "low": "낮음"},
        "nov": "(판단 없음)",
        "actions": "권장 조치 (LLM 제안):",
        "skip": "## 3. 예외 목록 제안",
        "skip_sure": "확실한 것만 (이 컴퓨터의 네트워크 장비):",
        "skip_llm": "LLM이 확신 '높음'으로 오탐이라고 본 IP까지 포함:",
        "skip_none": "제안할 예외가 없습니다.",
        "apply": "적용은 사람이 합니다. 설정 파일의 `skip:` 줄을 바꾼 뒤 `sudo systemctl restart checkhookd`를 실행합니다.",
        "roles": {"DNS server": "DNS 서버", "default gateway": "게이트웨이", "this host": "이 컴퓨터"},
    },
    "English": {
        "title": "# CheckHook triage report",
        "mode_on": "enforcing", "mode_off": "log only, enforce: false",
        "summary": "{n} alerts, {f} flagged IPs ({mode})",
        "infra": "## 1. Flagged IPs that are this host's own network infrastructure",
        "infra_note": "These are this host's current DNS servers, gateway or own addresses, so false "
                      "positives. With `protect_local: true` (default) they are never blocked.",
        "infra_none": "No flagged IP is this host's DNS server, gateway or own address.",
        "llm": "## 2. LLM review ({model})",
        "llm_fail": "Could not reach the LLM, so this part is empty: {e}",
        "llm_bad": "Could not parse the LLM answer. Raw text:",
        "llm_none": "No IP to review.",
        "more": "Only the {k} IPs with the most alerts were sent to the LLM; {r} were not reviewed.",
        "head": "| IP | verdict | confidence | alerts | reason |",
        "verdict": {"false_positive": "false positive", "attack": "attack", "unclear": "unclear"},
        "conf": {"high": "high", "medium": "medium", "low": "low"},
        "nov": "(no verdict)",
        "actions": "Suggested actions (from the LLM):",
        "skip": "## 3. Suggested skip list",
        "skip_sure": "Certain only (this host's network infrastructure):",
        "skip_llm": "Also with the IPs the LLM called false positives with high confidence:",
        "skip_none": "Nothing to suggest.",
        "apply": "A person applies it: change the `skip:` line in the config, then restart checkhookd.",
        "roles": {},
    },
}


def render(t, model, n, flagged, review_ips, src, enforce, hits, skip, review, llm_raw, llm_err):
    mode = t["mode_on"] if enforce else t["mode_off"]
    L = [t["title"], "", t["summary"].format(n=n, f=len(flagged), mode=mode), ""]
    L.append(t["infra"])
    if hits:
        L.append(t["infra_note"]); L.append("")
        for ip, roles in hits:
            L.append(f"- {ip}: {', '.join(t['roles'].get(r, r) for r in roles)}")
    else:
        L.append(t["infra_none"])
    L.append(""); L.append(t["llm"].format(model=model))
    llm_fp = []
    if not review_ips:
        L.append(t["llm_none"])
    elif llm_err:
        L.append(t["llm_fail"].format(e=llm_err))
    elif review is None:
        L.append(t["llm_bad"]); L.append(""); L.append("```"); L.append((llm_raw or "")[:2000]); L.append("```")
    else:
        if review["situation"]:
            L.append(review["situation"]); L.append("")
        L.append(t["head"]); L.append("|---|---|---|---|---|")
        for ip in review_ips[:LLM_LIMIT]:
            v = review["verdicts"].get(ip)
            if v:
                if v["verdict"] == "false_positive" and v["confidence"] == "high":
                    llm_fp.append(ip)
                reason = v["reason"].replace("|", "/").replace("\n", " ")
                L.append(f"| {ip} | {t['verdict'][v['verdict']]} | {t['conf'][v['confidence']]} "
                         f"| {src.get(ip, 0)} | {reason} |")
            else:
                L.append(f"| {ip} | {t['nov']} | | {src.get(ip, 0)} | |")
        if len(review_ips) > LLM_LIMIT:
            L.append(""); L.append(t["more"].format(k=LLM_LIMIT, r=len(review_ips) - LLM_LIMIT))
        if review["actions"]:
            L.append(""); L.append(t["actions"])
            L += [f"- {x}" for x in review["actions"]]
    L.append(""); L.append(t["skip"])
    sure = [ip for ip, _ in hits]
    if sure or llm_fp:
        if sure:
            L.append(t["skip_sure"]); L.append("```yaml"); L.append(skip_line(skip, sure)); L.append("```")
        if llm_fp:
            L.append(t["skip_llm"]); L.append("```yaml"); L.append(skip_line(skip, sure + llm_fp)); L.append("```")
        L.append(t["apply"])
    else:
        L.append(t["skip_none"])
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
    ap.add_argument("--ignore-gids", default="",
                    help="comma-separated Snort gids that never lead to a block (config ids.ignore_gids)")
    ap.add_argument("--ignore-rules", default="",
                    help='comma-separated "gid:sid" rules that never lead to a block (config ids.ignore_rules)')
    a = ap.parse_args(argv)

    skip = [s.strip() for s in a.skip.split(",") if s.strip()]
    ignore = Ignore([g for g in a.ignore_gids.split(",") if g.strip()],
                    [r for r in a.ignore_rules.split(",") if r.strip()])
    n, sig, src, per_src = recent_alerts(a.alert_file, a.last, ignore)
    blocked = blocked_ips(a.backend)
    flagged = flagged_ips(src, blocked, skip, a.block_private)
    ctx = local_context()
    hits = infra_hits(flagged, ctx)
    infra = {ip for ip, _ in hits}
    review_ips = [ip for ip in flagged if ip not in infra]   # infra is decided without the LLM
    prompt = build_prompt(n, sig, src, per_src, review_ips, blocked, a.enforce, ctx, a.lang)
    if a.print_prompt:
        print(prompt); return 0
    print(f"[*] triage: {n} alerts, {len(flagged)} flagged IPs, "
          f"{len(hits)} on local infrastructure -> {a.model}")
    llm_raw, llm_err, review = "", "", None
    if review_ips:
        try:
            llm_raw = ask_ollama(a.host, a.model, prompt, a.timeout)
            review = parse_review(llm_raw, review_ips)
        except Exception as e:  # Ollama down, model missing, timeout...
            llm_err = f"{a.host}: {e} (check: curl {a.host}/api/tags)"
            print(f"[!] Ollama request failed: {llm_err}")
    t = TEXT.get(a.lang, TEXT["English"])
    out = render(t, a.model, n, flagged, review_ips, src, a.enforce, hits, skip, review, llm_raw, llm_err)
    if a.out:
        with open(a.out, "w", encoding="utf-8") as f:
            f.write(out)
        print(f"[+] wrote {a.out}")
    else:
        print("\n" + out)
    return 1 if llm_err else 0


if __name__ == "__main__":
    raise SystemExit(main())
