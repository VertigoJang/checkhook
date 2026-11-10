# Changelog

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
