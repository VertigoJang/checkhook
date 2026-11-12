"""CheckHook desktop app (Linux and Windows).

Shows what checkhookd is doing (status.json, readable without root) and offers
the everyday actions as buttons. Anything that changes the system goes through
`checkhook ctl` with elevated rights: pkexec on Linux (the desktop asks for the
password or fingerprint), an elevated process on Windows.

  checkhook gui            (Linux)
  checkhook.cmd gui        (Windows)

Needs PySide6:  python3 -m pip install --user PySide6-Essentials
"""
import datetime, os, shutil, sys, time

try:
    from PySide6.QtCore import Qt, QTimer, QProcess, QSize
    from PySide6.QtGui import QIcon, QFont, QColor
    from PySide6.QtWidgets import (
        QApplication, QWidget, QMainWindow, QLabel, QPushButton, QVBoxLayout, QHBoxLayout,
        QGridLayout, QTabWidget, QTableWidget, QTableWidgetItem, QHeaderView, QTextBrowser,
        QMessageBox, QFrame, QAbstractItemView, QInputDialog, QSizePolicy)
except ImportError:
    sys.exit("PySide6 is not installed:  python3 -m pip install --user PySide6-Essentials")

from checkhook import status
from checkhook.config import WINDOWS

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ICON = os.path.join(ROOT, "assets", "checkhook.svg")

BG, PANEL, LINE, TEXT, DIM = "#14171d", "#1c2029", "#2b303b", "#e6e9ee", "#8b95a3"
STEEL, RED, GREEN, AMBER = "#c9d1d9", "#e23b2e", "#3fb950", "#d29922"

STYLE = f"""
QWidget {{ background: {BG}; color: {TEXT}; font-size: 10.5pt; }}
QTabWidget::pane {{ border: 1px solid {LINE}; border-radius: 8px; top: -1px; }}
QTabBar::tab {{ background: transparent; color: {DIM}; padding: 8px 18px; border: none; }}
QTabBar::tab:selected {{ color: {TEXT}; border-bottom: 2px solid {RED}; }}
QFrame#card {{ background: {PANEL}; border: 1px solid {LINE}; border-radius: 10px; }}
QLabel#cardTitle {{ color: {DIM}; font-size: 9.5pt; background: transparent; }}
QLabel#cardValue {{ font-size: 17pt; font-weight: 600; background: transparent; }}
QLabel#cardNote {{ color: {DIM}; font-size: 9pt; background: transparent; }}
QPushButton {{ background: {LINE}; border: 1px solid {LINE}; border-radius: 6px; padding: 6px 14px; }}
QPushButton:hover {{ border-color: {STEEL}; }}
QPushButton:disabled {{ color: {DIM}; }}
QPushButton#danger {{ background: {RED}; border-color: {RED}; color: white; }}
QTableWidget {{ background: {PANEL}; border: 1px solid {LINE}; border-radius: 8px;
               gridline-color: {LINE}; selection-background-color: #33394a; }}
QTableWidget::item {{ padding: 3px 8px; }}
QHeaderView::section {{ background: {PANEL}; color: {DIM}; border: none;
                        border-bottom: 1px solid {LINE}; padding: 6px; }}
QTextBrowser {{ background: {PANEL}; border: 1px solid {LINE}; border-radius: 8px; padding: 10px; }}
"""

ACTION = {"blocked": ("차단", RED), "would-block": ("차단 예정", AMBER), "skip": ("예외", DIM),
          "ignored": ("무시 규칙", DIM), "recent": ("이미 처리", DIM)}
STATE = {"active": ("실행 중", GREEN), "inactive": ("멈춤", AMBER), "failed": ("실패", RED),
         "missing": ("설치 안 됨", DIM), "activating": ("시작 중", AMBER)}


def hhmm(t):
    return datetime.datetime.fromtimestamp(t).strftime("%m-%d %H:%M") if t else ""


def card(title):
    f = QFrame(); f.setObjectName("card")
    lay = QVBoxLayout(f); lay.setContentsMargins(16, 12, 16, 12); lay.setSpacing(4)
    t = QLabel(title); t.setObjectName("cardTitle")
    v = QLabel("-"); v.setObjectName("cardValue")
    n = QLabel(""); n.setObjectName("cardNote"); n.setWordWrap(True)
    lay.addWidget(t); lay.addWidget(v); lay.addWidget(n)
    f.value, f.note, f.lay = v, n, lay
    return f


def table(headers):
    t = QTableWidget(0, len(headers))
    t.setHorizontalHeaderLabels(headers)
    t.verticalHeader().setVisible(False)
    t.setEditTriggers(QAbstractItemView.NoEditTriggers)
    t.setSelectionBehavior(QAbstractItemView.SelectRows)
    t.setSelectionMode(QAbstractItemView.SingleSelection)
    t.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
    t.horizontalHeader().setStretchLastSection(True)
    t.setShowGrid(False)
    return t


def cell(text, color=None):
    it = QTableWidgetItem(str(text))
    if color:
        it.setForeground(QColor(color))
    return it


class App(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("CheckHook")
        self.setWindowIcon(QIcon(ICON))
        self.resize(980, 680)
        self.s = None
        self.proc = None
        self.report_mtime = None

        root = QWidget(); self.setCentralWidget(root)
        outer = QVBoxLayout(root); outer.setContentsMargins(18, 14, 18, 14); outer.setSpacing(12)

        # header
        head = QHBoxLayout()
        logo = QLabel(); logo.setPixmap(QIcon(ICON).pixmap(QSize(40, 40)))
        name = QLabel("<span style='font-size:18pt;font-weight:700;color:%s'>CHECK</span>"
                      "<span style='font-size:18pt;font-weight:700;color:%s'>HOOK</span>" % (STEEL, RED))
        self.version = QLabel(""); self.version.setStyleSheet(f"color:{DIM}")
        self.pill = QLabel(""); self.pill.setAlignment(Qt.AlignCenter)
        self.updated = QLabel(""); self.updated.setStyleSheet(f"color:{DIM}")
        head.addWidget(logo); head.addSpacing(6); head.addWidget(name); head.addSpacing(8)
        head.addWidget(self.version); head.addStretch(1); head.addWidget(self.updated)
        head.addSpacing(10); head.addWidget(self.pill)
        outer.addLayout(head)

        self.warn = QLabel(""); self.warn.setWordWrap(True)
        self.warn.setStyleSheet(f"background:#3a1d1b;color:{TEXT};border:1px solid {RED};"
                                "border-radius:8px;padding:8px 12px;")
        self.warn.hide(); outer.addWidget(self.warn)

        tabs = QTabWidget(); outer.addWidget(tabs, 1)
        tabs.addTab(self._status_tab(), "상태")
        tabs.addTab(self._blocks_tab(), "차단 · 경보")
        tabs.addTab(self._report_tab(), "검토 보고서")

        self.msg = QLabel(""); self.msg.setStyleSheet(f"color:{DIM}")
        outer.addWidget(self.msg)

        self.timer = QTimer(self); self.timer.timeout.connect(self.refresh); self.timer.start(3000)
        self.refresh()

    # ------------------------------------------------------------- tabs -----
    def _status_tab(self):
        w = QWidget(); g = QGridLayout(w); g.setContentsMargins(14, 14, 14, 14); g.setSpacing(12)
        self.c_mode = card("차단 모드")
        self.b_enforce = QPushButton(""); self.b_enforce.clicked.connect(self.toggle_enforce)
        self.c_mode.lay.addWidget(self.b_enforce)
        self.c_data = card("학습 데이터 (정상 트래픽 flow)")
        self.b_pause = QPushButton(""); self.b_pause.clicked.connect(self.toggle_pause)
        self.c_data.lay.addWidget(self.b_pause)
        self.c_alerts = card("오늘 경보")
        self.c_blocked = card("오늘 차단 / 차단 예정")
        self.c_list = card("지금 차단 목록")
        self.c_report = card("마지막 LLM 검토")
        g.addWidget(self.c_mode, 0, 0); g.addWidget(self.c_data, 0, 1); g.addWidget(self.c_report, 0, 2)
        g.addWidget(self.c_alerts, 1, 0); g.addWidget(self.c_blocked, 1, 1); g.addWidget(self.c_list, 1, 2)

        svc = QFrame(); svc.setObjectName("card")
        sl = QVBoxLayout(svc); sl.setContentsMargins(16, 12, 16, 12)
        t = QLabel("서비스"); t.setObjectName("cardTitle"); sl.addWidget(t)
        self.svc_rows = QLabel(""); self.svc_rows.setTextFormat(Qt.RichText)
        self.svc_rows.setStyleSheet("background:transparent"); sl.addWidget(self.svc_rows)
        b = QPushButton("checkhookd 다시 시작"); b.clicked.connect(lambda: self.ctl(["restart"]))
        b.setSizePolicy(QSizePolicy.Maximum, QSizePolicy.Fixed); sl.addWidget(b)
        g.addWidget(svc, 2, 0, 1, 3)
        g.setRowStretch(3, 1)
        return w

    def _blocks_tab(self):
        w = QWidget(); v = QVBoxLayout(w); v.setContentsMargins(14, 14, 14, 14); v.setSpacing(8)
        v.addWidget(QLabel("차단했거나 차단할 뻔한 IP (최근 순)"))
        self.t_flag = table(["IP", "처리", "횟수", "마지막", "이유"])
        v.addWidget(self.t_flag, 3)
        row = QHBoxLayout()
        b0 = QPushButton("선택한 IP 차단"); b0.setObjectName("danger"); b0.clicked.connect(self.block)
        b1 = QPushButton("선택한 IP 차단 해제"); b1.clicked.connect(self.unblock)
        b2 = QPushButton("선택한 IP를 예외에 추가 (앞으로 차단 안 함)"); b2.clicked.connect(self.add_skip)
        row.addWidget(b0); row.addWidget(b1); row.addWidget(b2); row.addStretch(1)
        v.addLayout(row)
        v.addSpacing(6)
        v.addWidget(QLabel("최근 경보"))
        self.t_alert = table(["시각", "출발지", "처리", "규칙", "내용"])
        v.addWidget(self.t_alert, 4)
        return w

    def _report_tab(self):
        w = QWidget(); v = QVBoxLayout(w); v.setContentsMargins(14, 14, 14, 14)
        row = QHBoxLayout()
        self.l_report = QLabel(""); self.l_report.setStyleSheet(f"color:{DIM}")
        b = QPushButton("지금 검토 실행"); b.clicked.connect(lambda: self.ctl(["triage"], "검토 중… (1~3분)"))
        row.addWidget(self.l_report); row.addStretch(1); row.addWidget(b)
        v.addLayout(row)
        self.report = QTextBrowser(); self.report.setOpenExternalLinks(False)
        v.addWidget(self.report, 1)
        return w

    # ---------------------------------------------------------- refresh -----
    def refresh(self):
        try:
            s = status.read()
        except FileNotFoundError:
            self._warn(f"상태 파일({status.PATH})이 없습니다. checkhookd가 실행 중인지 확인하세요."
                       + ("" if WINDOWS else "  →  systemctl status checkhookd"))
            return
        except Exception as e:
            self._warn(f"상태 파일을 읽지 못했습니다: {e}")
            return
        self.s = s
        age = time.time() - s["written"]
        self._warn("" if age < 60 else
                   f"상태가 {int(age // 60)}분 동안 갱신되지 않았습니다. checkhookd가 멈췄을 수 있습니다.")
        self.version.setText(f"v{s['version']}")
        self.updated.setText("갱신 " + datetime.datetime.fromtimestamp(s["written"]).strftime("%H:%M:%S"))

        if s.get("demo"):
            text, color = ("시연 모드 · 차단 켜짐" if s["enforce"] else "시연 모드 · 기록만 함"), AMBER
        elif s["paused"]:
            text, color = "학습 데이터 수집 일시정지", AMBER
        elif s["enforce"]:
            text, color = "보호 중 · 차단 켜짐", RED
        else:
            text, color = "감시 중 · 기록만 함", STEEL
        self.pill.setText(text)
        self.pill.setStyleSheet(f"border:1px solid {color};color:{color};border-radius:12px;padding:4px 12px;")

        # cards
        self.c_mode.value.setText("차단 켜짐" if s["enforce"] else "기록만 함")
        self.c_mode.value.setStyleSheet(f"color:{RED if s['enforce'] else STEEL};background:transparent")
        self.c_mode.note.setText(f"집행 방식 {s['backend']}, 차단은 {s['block_timeout']} 뒤 자동 해제")
        self.b_enforce.setText("차단 끄기 (기록만)" if s["enforce"] else "차단 켜기")
        self.b_enforce.setObjectName("" if s["enforce"] else "danger")
        self.b_enforce.style().unpolish(self.b_enforce); self.b_enforce.style().polish(self.b_enforce)

        flows = s.get("flows")
        if not s.get("flow_logging"):
            self.c_data.value.setText("꺼짐")
            self.c_data.note.setText("flow 기록이 꺼져 있습니다 (nfstream 설치 필요)")
        else:
            self.c_data.value.setText(f"{flows:,}" if flows is not None else "세는 중")
            self.c_data.note.setText("일시정지됨: 탐지는 계속, 저장만 멈춤" if s["paused"]
                                     else "평소 사용 트래픽을 학습용으로 모으는 중")
        self.b_pause.setText("수집 다시 시작" if s["paused"] else "수집 일시정지 (공격 실습 전)")

        t = s.get("today", {})
        self.c_alerts.value.setText(f"{t.get('alerts', 0):,}")
        self.c_alerts.note.setText("탐지기가 낸 경보 수 (차단과 무관한 것 포함)")
        self.c_blocked.value.setText(f"{t.get('blocked', 0)} / {t.get('would_block', 0)}")
        self.c_blocked.note.setText("차단 예정 = 기록만 함 상태에서 차단했을 IP")
        bl = s.get("blocklist")
        self.c_list.value.setText(str(len(bl)) if bl is not None else "-")
        note = ", ".join(bl[:3]) if bl else "커널 차단 목록에 들어 있는 IP 수"
        if s.get("xdp_dropped") is not None:
            note += f"\nXDP가 버린 패킷 {s['xdp_dropped']:,}개"
        self.c_list.note.setText(note)
        rep = s.get("report")
        self.c_report.value.setText(hhmm(rep["mtime"]) if rep else "없음")
        self.c_report.note.setText("한 시간마다 자동 실행")

        rows = []
        for name, st in s.get("services", {}).items():
            label, col = STATE.get(st, (st, DIM))
            rows.append(f"<span style='color:{col}'>●</span>&nbsp; {name} "
                        f"<span style='color:{DIM}'>— {label}</span>")
        self.svc_rows.setText("<br>".join(rows) or "-")

        # tables
        flagged = s.get("flagged", [])
        inlist = set(s.get("blocklist") or [])
        self.t_flag.setRowCount(len(flagged))
        for r, f in enumerate(flagged):
            label, col = ACTION.get(f["action"], (f["action"], None))
            if f["ip"] in inlist:
                label, col = "차단 중", RED
            for c, val in enumerate([cell(f["ip"]), cell(label, col), cell(f["count"]),
                                     cell(hhmm(f["last"])), cell(f["reason"])]):
                self.t_flag.setItem(r, c, val)
        alerts = s.get("alerts", [])
        self.t_alert.setRowCount(len(alerts))
        for r, a in enumerate(alerts):
            label, col = ACTION.get(a["action"], (a["action"], None))
            for c, val in enumerate([cell(hhmm(a["t"])), cell(a["src"]), cell(label, col),
                                     cell(f"{a['gid']}:{a['sid']}"), cell(a["msg"])]):
                self.t_alert.setItem(r, c, val)

        # report
        if rep and rep["mtime"] != self.report_mtime:
            try:
                with open(rep["path"], encoding="utf-8") as fh:
                    self.report.setMarkdown(fh.read())
                self.report_mtime = rep["mtime"]
            except OSError as e:
                self.report.setPlainText(f"보고서를 열지 못했습니다: {e}")
        self.l_report.setText(f"작성: {hhmm(rep['mtime'])}" if rep else "아직 보고서가 없습니다")

    def _warn(self, text):
        self.warn.setText(text); self.warn.setVisible(bool(text))

    # ---------------------------------------------------------- actions -----
    def selected_ip(self):
        rows = self.t_flag.selectionModel().selectedRows()
        if not rows:
            QMessageBox.information(self, "CheckHook", "먼저 표에서 IP를 하나 고르세요.")
            return None
        return self.t_flag.item(rows[0].row(), 0).text()

    def block(self):
        ip = self.selected_ip()
        if not ip or not self.s:
            return
        if QMessageBox.question(
                self, "차단",
                f"{ip}를 지금 차단합니다 ({self.s['block_timeout']} 뒤 자동 해제).\n\n"
                "LLM 검토 보고서에서 이 IP의 판단을 확인했나요?") == QMessageBox.Yes:
            self.ctl(["block", ip], f"{ip} 차단 중…")

    def unblock(self):
        ip = self.selected_ip()
        if ip:
            self.ctl(["unblock", ip], f"{ip} 차단 해제 중…")

    def add_skip(self):
        ip = self.selected_ip()
        if ip and QMessageBox.question(
                self, "예외에 추가",
                f"{ip}는 앞으로 차단하지 않습니다.\n설정 파일의 skip 목록에 넣고 checkhookd를 다시 시작합니다.") \
                == QMessageBox.Yes:
            self.ctl(["skip-add", ip], f"{ip} 예외 추가 중…")

    def toggle_enforce(self):
        if not self.s:
            return
        if self.s["enforce"]:
            self.ctl(["enforce", "off"], "차단 끄는 중…")
            return
        if QMessageBox.warning(
                self, "차단 켜기",
                "이제부터 탐지된 IP를 실제로 차단합니다.\n\n"
                "켜기 전에 '차단 · 경보' 탭에서 차단 예정 IP가 정말 수상한지 확인하세요. "
                "DNS 서버나 자주 쓰는 사이트가 섞여 있으면 인터넷이 끊길 수 있습니다.\n\n켤까요?",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No) == QMessageBox.Yes:
            self.ctl(["enforce", "on"], "차단 켜는 중…")

    def toggle_pause(self):
        if not self.s:
            return
        if self.s["paused"]:
            self.ctl(["resume"], "수집 다시 시작 중…")
        else:
            reason, ok = QInputDialog.getText(self, "수집 일시정지", "메모 (예: 칼리 실습):")
            if ok:
                self.ctl(["pause"] + reason.split()[:6], "수집 일시정지 중…")

    def ctl(self, args, busy="처리 중…"):
        if self.proc is not None:
            QMessageBox.information(self, "CheckHook", "앞의 작업이 아직 끝나지 않았습니다.")
            return
        if WINDOWS:
            prog, argv = sys.executable, ["-m", "checkhook.ctl"] + args
        else:
            launcher = "/usr/local/bin/checkhook"
            if not os.path.exists(launcher):
                launcher = os.path.join(ROOT, "bin", "checkhook")
            if not shutil.which("pkexec"):
                QMessageBox.warning(self, "CheckHook", "pkexec이 없어 권한을 얻을 수 없습니다 (polkit 설치 필요).")
                return
            prog, argv = "pkexec", [launcher, "ctl"] + args
        self.msg.setText(busy)
        self.proc = QProcess(self)
        self.proc.setWorkingDirectory(ROOT)
        self.proc.setProcessChannelMode(QProcess.MergedChannels)
        self.proc.finished.connect(lambda code, _st: self._done(code, args))
        self.proc.start(prog, argv)

    def _done(self, code, args):
        out = bytes(self.proc.readAll()).decode("utf-8", "replace").strip()
        self.proc = None
        if code == 0:
            self.msg.setText("완료: " + (out.splitlines()[-1] if out else " ".join(args)))
        elif code in (126, 127) and not WINDOWS:
            self.msg.setText("취소됨 (권한 요청을 닫았거나 인증에 실패했습니다)")
        else:
            self.msg.setText("실패")
            QMessageBox.warning(self, "CheckHook", f"작업이 실패했습니다 (코드 {code}).\n\n{out[-1500:]}")
        self.refresh()


def main():
    app = QApplication(sys.argv)
    app.setApplicationName("CheckHook")
    app.setDesktopFileName("checkhook")
    f = QFont(); f.setFamilies(["Pretendard", "Noto Sans CJK KR", "Malgun Gothic", "Sans Serif"])
    app.setFont(f)
    app.setStyleSheet(STYLE)
    w = App(); w.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
