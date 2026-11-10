# checkhook — firewall service package

- `blocklist.py` — shared enforcement core. A kernel set (nftables; XDP planned)
  that every detector feeds, with per-entry timeouts for a dynamic blocklist.
  CLI: `sudo python3 -m checkhook.blocklist {setup|add IP|remove IP|list|flush|teardown}`
- `features.py` — the nfstream flow-feature list shared by training and inference.
- `snort_bridge.py` — Snort 3 signature detector. Tails `alert_json`, feeds the
  blocklist. Default `--dry-run`; loopback and RFC1918 are never blocked.
- `ml_detector.py` — ML flow detector. Classifies live nfstream flows with a
  trained RandomForest and feeds the blocklist. See `ml/` to build the model.
- `triage.py` — read-only LLM triage. Summarises recent detections and flags
  likely false positives via a local Ollama model. Never changes the blocklist.

Run modules from the project root, e.g.
`sudo python3 -m checkhook.triage --alert-file /var/log/snort/alert_json.txt --model qwen2.5:7b`.
