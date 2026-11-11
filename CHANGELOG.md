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

**Collection control**
- `checkhook pause [reason]` / `checkhook resume` (Linux and Windows): stop
  saving training data during attack practice on the same host while detection
  keeps running. Pauses are logged to `pauses.log`.

**Other**
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
