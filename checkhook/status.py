"""Live status for the desktop app and `checkhook stats`.

checkhookd keeps a small in-memory board (recent alerts, what it blocked or
would block, flow count) and writes it to status.json every few seconds. The
file is world-readable so the app can show status without root; it holds only
what `checkhook logs` already shows. Changing anything still needs root (see
checkhook.ctl).

  python3 -m checkhook.status          # Korean summary (checkhook stats)
  python3 -m checkhook.status --json   # raw status.json
"""
import collections, datetime, glob, json, os, subprocess, sys, threading, time
from checkhook.config import WINDOWS, PROGRAMDATA

DATA = PROGRAMDATA if WINDOWS else "/var/lib/checkhook"
PATH = os.path.join(DATA, "status.json")
UNITS = ["checkhookd", "checkhook-ids", "checkhook-xdp", "checkhook-capture"]
TASKS = ["checkhookd", "checkhook-suricata"]


def count_flows(flow_dir):
    n = 0
    for f in glob.glob(os.path.join(flow_dir, "flows-*.csv")):
        try:
            with open(f, "rb") as fh:
                lines = sum(1 for _ in fh)
            n += max(0, lines - 1)
        except OSError:
            pass
    return n


def service_states():
    out = {}
    if WINDOWS:
        ps = ("$ErrorActionPreference='SilentlyContinue'; foreach ($t in '"
              + "','".join(TASKS) + "') { $x = Get-ScheduledTask -TaskName $t; "
              "if ($x) { $t + '=' + $x.State } else { $t + '=missing' } }")
        try:
            r = subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                               capture_output=True, text=True, timeout=20)
            for line in r.stdout.splitlines():
                k, _, v = line.strip().partition("=")
                if k:
                    out[k] = {"Running": "active", "Ready": "inactive"}.get(v, v.lower())
        except Exception:
            pass
        return out
    for u in UNITS:
        if not os.path.exists(f"/etc/systemd/system/{u}.service"):
            out[u] = "missing"
            continue
        try:
            r = subprocess.run(["systemctl", "is-active", u], capture_output=True,
                               text=True, timeout=5)
            out[u] = r.stdout.strip() or "unknown"
        except Exception:
            out[u] = "unknown"
    return out


class Board:
    """Thread-safe record of what the daemon saw and did."""

    def __init__(self, cfg, keep=200):
        self.cfg = cfg
        self.lock = threading.Lock()
        self.started = time.time()
        self.alerts = collections.deque(maxlen=keep)      # recent alerts with the action taken
        self.flagged = {}                                 # ip -> {first, last, count, reason, action}
        self.counts = collections.Counter()               # per local day: alerts, blocked, would_block
        self.day = datetime.date.today().isoformat()
        self.flows = None                                 # filled in by a background count
        self.flow_logging = False
        self.services = {}

    def _rollover(self):
        today = datetime.date.today().isoformat()
        if today != self.day:
            self.day, self.counts = today, collections.Counter()

    def alert(self, al, action):
        """action: blocked | would-block | skip | ignored | recent (already acted on)."""
        now = time.time()
        with self.lock:
            self._rollover()
            self.counts["alerts"] += 1
            self.alerts.append({"t": now, "src": al.get("src"), "gid": al.get("gid", 1),
                                "sid": al.get("sid"), "msg": al.get("msg", ""),
                                "ids": al.get("ids"), "action": action})
            if action in ("blocked", "would-block"):
                self.counts["blocked" if action == "blocked" else "would_block"] += 1
                f = self.flagged.setdefault(al["src"], {"first": now, "count": 0})
                f.update(last=now, reason=f"sid={al.get('sid')} {al.get('msg', '')}"[:160],
                         action=action)
                f["count"] += 1

    def flow(self):
        with self.lock:
            if self.flows is not None:
                self.flows += 1

    def snapshot(self, blocklist=None, paused=False):
        c = self.cfg
        with self.lock:
            self._rollover()
            try:
                rep = c["triage"]["out"]
                report = {"path": rep, "mtime": os.path.getmtime(rep)} if os.path.exists(rep) else None
            except Exception:
                report = None
            from checkhook import __version__
            return {
                "version": __version__, "written": time.time(), "started": self.started,
                "enforce": bool(c["enforce"]), "backend": c["backend"], "paused": paused,
                "protect_local": bool(c.get("protect_local", True)), "skip": list(c["skip"]),
                "block_timeout": c["block_timeout"], "services": dict(self.services),
                "day": self.day, "today": dict(self.counts), "flows": self.flows,
                "flow_logging": self.flow_logging,
                "blocklist": sorted(blocklist) if blocklist is not None else None,
                "flagged": [dict(ip=ip, **v) for ip, v in
                            sorted(self.flagged.items(), key=lambda kv: -kv[1]["last"])][:100],
                "alerts": list(self.alerts)[-100:][::-1], "report": report,
            }


def writer(board, bl, stop, flow_dir=None, interval=5):
    """Daemon worker: refresh service states and write status.json."""
    from checkhook.collect import paused
    board.flow_logging = bool(flow_dir)
    if flow_dir and board.flows is None:
        n = count_flows(flow_dir)
        with board.lock:
            board.flows = n
    last_svc = 0
    while True:
        if time.time() - last_svc > (30 if WINDOWS else 10):
            states = service_states()
            with board.lock:
                board.services = states
            last_svc = time.time()
        try:
            ips = bl.ips() if bl is not None else None
        except Exception:
            ips = None
        snap = board.snapshot(ips, paused())
        tmp = PATH + ".tmp"
        try:
            os.makedirs(DATA, exist_ok=True)
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(snap, f, ensure_ascii=False)
            if not WINDOWS:
                os.chmod(tmp, 0o644)
            os.replace(tmp, PATH)
        except OSError:
            pass
        if stop.wait(interval):
            return


def read(path=None):
    with open(path or PATH, encoding="utf-8") as f:
        return json.load(f)


ACTION_KO = {"blocked": "차단", "would-block": "차단 예정(기록만)", "skip": "예외",
             "ignored": "무시 규칙", "recent": "이미 처리"}
STATE_KO = {"active": "실행 중", "inactive": "멈춤", "failed": "실패", "missing": "설치 안 됨",
            "activating": "시작 중", "unknown": "알 수 없음"}


def summary(s):
    age = time.time() - s["written"]
    L = [f"CheckHook {s['version']}  (상태 갱신 {age:.0f}초 전)"]
    if age > 60:
        L.append("  ! 상태 파일이 오래됐습니다. checkhookd가 멈췄을 수 있습니다: systemctl status checkhookd")
    mode = "차단 켜짐" if s["enforce"] else "기록만 함 (enforce: false)"
    L.append(f"  모드          : {mode}, 집행 방식 {s['backend']}")
    if not s.get("flow_logging"):
        L.append("  학습 데이터   : flow 기록 꺼짐 (nfstream 없음 또는 capture.enabled: false)")
    else:
        L.append(f"  학습 데이터   : {'일시정지' if s['paused'] else '수집 중'}, 누적 flow "
                 + (f"{s['flows']:,}개" if s.get("flows") is not None else "(세는 중)"))
    t = s.get("today", {})
    L.append(f"  오늘          : 경보 {t.get('alerts', 0):,}건, 차단 {t.get('blocked', 0)}건, "
             f"차단 예정 {t.get('would_block', 0)}건")
    if s.get("blocklist") is not None:
        L.append(f"  차단 목록     : {len(s['blocklist'])}개 IP")
    for name, st in s.get("services", {}).items():
        L.append(f"  {name:<20}: {STATE_KO.get(st, st)}")
    if s.get("report"):
        L.append("  마지막 검토   : " + datetime.datetime.fromtimestamp(s["report"]["mtime"])
                 .strftime("%m-%d %H:%M"))
    if s.get("flagged"):
        L.append("  최근 차단 대상:")
        for f in s["flagged"][:5]:
            when = datetime.datetime.fromtimestamp(f["last"]).strftime("%H:%M")
            L.append(f"    {when} {f['ip']:<16} {ACTION_KO.get(f['action'], f['action'])}  {f['reason']}")
    return "\n".join(L)


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    try:
        s = read()
    except FileNotFoundError:
        print(f"{PATH} 없음: checkhookd가 아직 상태를 쓰지 않았습니다 (3.0 이상, 실행 중인지 확인).")
        return 1
    print(json.dumps(s, ensure_ascii=False, indent=1) if "--json" in argv else summary(s))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
