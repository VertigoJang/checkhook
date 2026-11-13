# Changelog

## 3.0.0 (in testing)

**Check: the LLM review now does what the name says**
- Reviews the IPs that were blocked, or with `enforce: false` would have been
  blocked; before, dry-run left nothing to review.
- Compares flagged IPs with this host's DNS servers, default gateway and own
  addresses (Linux and Windows) and marks those as false positives without
  waiting for the model.
- Gives the model each flagged IP with its top signatures plus the local
  network context, and asks for false positives and likely real attacks.
- The model now sees the evidence per IP: how many distinct destination
  ports it reached, how many ML flows it triggered and the highest ML
  probability. ML detections are counted as one signature instead of one per
  port, and the prompt names this host's own addresses (rc16: a clear port
  scan plus SYN flood from the lab VM had come back as "unclear").
- The report ends with a ready-to-paste `skip:` line. Still read-only: the
  blocklist and the config are only changed by a person.
- If Ollama is unreachable the report is still written (local part only) and
  the run exits non-zero.
- Reports in Korean when `triage.lang: Korean`.
- The model answers in JSON (one verdict per reviewed IP: false positive,
  attack or unclear, with confidence and reason). Verdicts about IPs that were
  not under review are dropped, so the report never states things about the
  gateway, the skip list or made-up addresses. The host's own DNS servers and
  gateway are decided without the model and are not sent for review.
- The skip suggestion comes in two lines: certain (local infrastructure) and
  with the IPs the model called false positives with high confidence.

**Detection**
- `ids.ignore_gids` (default 116 decoder, 119 http_inspect, 128 ssh,
  129 stream_tcp, 137 ssl) and `ids.ignore_rules` ("gid:sid"): alerts that
  never lead to a block. The triage still sees them. Alerts now carry their
  gid. On the RHEL test machine these inspectors produced most alerts and, with
  ssl alone, 505 distinct "attacker" IPs from ordinary HTTPS traffic.
- `protect_local` (default on): never block this host's current DNS servers,
  default gateway and own addresses; re-read every minute so it follows a
  laptop between networks. On the test machine the DNS-spoof rule 1:254 fired
  on four different resolvers over two networks, which a static skip list
  cannot keep up with.
- Default `ids.ignore_rules`: 1:402 (ICMP port unreachable) and 1:408 (ICMP
  echo reply), replies to this host's own traffic.
- A source that keeps alerting is blocked again once its block expired. Before,
  each source was acted on only once per daemon run.

**Testing**
- `packaging/selftest.sh` and `packaging/windows/selftest.ps1`: end-to-end
  checks (config, services, enforcement round trip with 203.0.113.250,
  alert parsing, capture, local network, Ollama). `docs/testing.md`.
- `checkhook.diag`: read-only probes used by the self-tests.

**Capture**
- Fixed: every restart of `checkhook-capture` (each boot) started the ring
  buffer again at `benign.pcap00`, overwriting what earlier boots captured, so
  the benign data set never grew past one session. Files are now named
  `benign-<start time>.pcapNN`; old files are removed only to stay near the size
  cap (default 4 GB, `CHECKHOOK_CAPTURE_GB`). Reinstall with
  `install-capture.sh` to switch.
- Flow logging now also runs on Linux (`capture.enabled: auto`, on when
  nfstream is installed): one CSV row of features per finished flow. Raw
  headers on the test machine grew by about 1 GB per hour of heavy use, so the
  packet ring only ever held the last hour or so; flow rows are what builds a
  multi-week benign set. `capture.rows_per_file` and `capture.keep` bound the
  disk use (default ~2 GB). The self-test reports how many flows are logged.
- The flow CSV header is written at once and rows reach the disk at least
  every 30 s.

**Shutdown**
- Fixed: stopping or restarting checkhookd took 90 s and ended in SIGKILL once
  flow logging was on, because nfstream's capture worker processes ignore
  SIGTERM and Python waited for them at exit. The daemon now flushes the flow
  CSV, kills its own worker processes and exits at once; the unit also sets
  `TimeoutStopSec=15`.

**ML detector**
- Fixed: the ML detector ignored `skip:` and `protect_local`, and never acted
  on a source again after its block expired. It now follows the same rules as
  the IDS bridge.
- ML detections are written to `ml.alert_file` in the Snort JSON format with
  gid 9000, so the LLM triage reviews them with the IDS alerts, and they show
  in the app and `checkhook stats`.

**Human-in-the-loop blocking**
- `checkhook ctl block <ip>` and a "선택한 IP 차단" button in the app: a person
  blocks an IP for `block_timeout` after reading the LLM review, also with
  `enforce: false`. Refuses this host's DNS servers, gateway, own addresses,
  skip-listed and loopback IPs.
- The app shows IPs currently in the kernel list as "차단 중" and the XDP
  dropped-packet counter.

**Demo mode**
- `checkhook demo on <iface>` / `off`: move IDS, ML and XDP to an isolated lab
  interface (e.g. a VirtualBox host-only network), with enforce off,
  block_private on and training-data collection paused; `off` restores the
  saved config and Snort unit.
- `checkhook demo on <iface> --model FILE`: use an ML model only while in
  demo mode; `off` removes it again or restores the model that was there.
- `ml.eval` no longer prints the old `checkhook detect` command, warns when
  the held-out benign set is too small to support a 0% false-positive claim,
  and says so when no held-out attacks were given.
- Fixed: `checkhook-xdp` stop detached from the interface named in the config
  instead of the one it was attached to, so switching interfaces left the old
  attachment behind.
- local.rules: SYN flood and SSH brute-force rules (detection_filter).
- Default `ids.ignore_rules` extended with what the test laptop raised on
  ordinary use and on plain pings: 1:399 (ICMP host unreachable), the
  informational PING rules 1:366/1:384/1:480/1:29456, and the port_scan sweep
  alerts 122:3/7/19/23. Port scans against this host still block.
- SYN-flood rule threshold raised to 1500 SYN in 2 s: at 200 a plain
  `nmap -sS` scan already triggered it.

**Desktop app**
- `checkhook gui` (PySide6, Linux and Windows): status, alerts, blocked and
  would-be-blocked IPs with unblock and add-to-skip, the LLM report with a
  run-now button, enforce on/off and collection pause/resume. Runs as the
  user; changes go through `checkhook ctl` with pkexec (Linux) or UAC (Windows).
- checkhookd writes `status.json` (world-readable) every 5 s: today's alert,
  block and would-block counts, recent alerts with the action taken, flow
  count, services, blocklist.
- `checkhook stats`: the same summary in the terminal.
- Today's counts, flagged IPs and recent alerts survive daemon restarts.

**Triage schedule**
- Fixed: the hourly LLM review only ran after a full hour of uninterrupted
  uptime, and its timer stopped while a laptop was suspended, so on the test
  machine the report was a day old. It is now scheduled by the report's age
  (checked every minute, first run 2 minutes after start), retrying after
  10 minutes if a run produced no report.
- Menu entries: "CheckHook" opens the app, "CheckHook (terminal)" the banner
  launcher. Windows installs PySide6 and both Start-menu shortcuts.

**Collection control**
- `checkhook pause [reason]` / `checkhook resume` (Linux and Windows): stop
  saving training data during attack practice on the same host while detection
  keeps running. Pauses are logged to `pauses.log`.

**Other**
- The terminal banner (Linux and Windows) shows only the logo, the name and
  the version; the taglines are gone.
- `install-capture.sh` picks the default-route interface when none is given.
- The example config uses `eth0` instead of a machine-specific interface.

## 2.0.0

First public release of CheckHook.

**Daemon**
- `checkhookd`: one daemon with supervised workers: IDS alert bridge, ML flow
  detection with flow logging, block expiry, and hourly local-LLM triage.
- Enforcement is off by default (`enforce: false`, log only). Private,
  loopback, link-local and multicast addresses are never blocked unless
  `block_private: true`. Every block expires after `block_timeout`.
- The triage (Ollama) is read-only: it reads alerts and the block list and
  writes a report.

**Detection**
- Reads Snort 3 `alert_json` and Suricata `eve.json` (auto-detected per line),
  following rotation and truncation.
- `checkhook-ids`: a Snort 3 sensor managed by CheckHook (generated config,
  `port_scan`, local rules, optional community rules; validated with `-T`).
- ML detector: nfstream statistical features and a RandomForest classifier;
  `ml.make_dataset`, `ml.train` and `ml.eval` (false-positive rate and
  threshold choice).
- `checkhook-capture`: boot-time benign-traffic capture (headers only, ring
  buffer), with SELinux and AppArmor handling.

**Enforcement**
- nftables: isolated table `ip checkhook`, input hook at priority -150, set
  with timeouts.
- XDP: `checkhook_xdp.c` with pinned maps in `/sys/fs/bpf/checkhook`; expiry
  is checked in the kernel. `checkhook-xdp` re-attaches it at boot.
- Windows: Windows Defender Firewall rules in group `CheckHook`, expiry
  reconciled by the daemon.

**Platforms**
- Linux: RHEL/Rocky/Fedora, Debian/Ubuntu, Arch, openSUSE. Installers detect
  the distro and print the right package names. Tested on RHEL 10.2.
- Windows 10/11: `install.ps1`, scheduled tasks `checkhookd` and
  `checkhook-suricata`, Npcap capture. Not yet tested on real hardware.

**Tools**
- `checkhook` launcher with banner and menu (`services`, `logs`, `report`,
  `xdp`), desktop entry and icon.
- `benchmark/`: enforcement-layer benchmarks (nftables vs XDP).
