#!/usr/bin/env python3
"""Turn PCAP(s) or agent flow CSVs into a labelled nfstream flow dataset.

A flow is labelled attack (1) if its source OR destination IP is in the given
attacker set (exact IPs and/or CIDRs); otherwise benign (0). This works for
self-generated lab captures (you know the attacker IP) and for CIC-IDS2017
PCAPs (use the documented attacker IPs; note external attacks are NAT'd and
appear as 172.16.0.1 in victim-side captures).

  python3 -m ml.make_dataset --pcap attack.pcap --pcap benign.pcap \
      --attacker-ip 203.0.113.66 --out flows.csv
  python  -m ml.make_dataset --flows "C:/ProgramData/CheckHook/flows/*.csv" --label 0 --out benign.csv
"""
import argparse, ipaddress
import pandas as pd
from checkhook.features import FEATURES

def matcher(ips, nets):
    ipset = set(ips); nets = [ipaddress.ip_network(n) for n in nets]
    def m(s):
        try: ip = ipaddress.ip_address(s)
        except ValueError: return False
        return s in ipset or any(ip in n for n in nets)
    return m

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pcap", action="append", default=[], help="PCAP file (repeatable)")
    ap.add_argument("--flows", action="append", default=[],
                    help="flow CSV written by the agent's flow logging (repeatable; globs ok)")
    ap.add_argument("--attacker-ip", nargs="*", default=[])
    ap.add_argument("--attacker-net", nargs="*", default=[])
    ap.add_argument("--label", type=int, choices=[0, 1], default=None,
                    help="force this label on all flows (else label by attacker IP)")
    ap.add_argument("--out", default="flows.csv")
    a = ap.parse_args()
    import glob
    flow_files = [f for pat in a.flows for f in sorted(glob.glob(pat))]
    if not a.pcap and not flow_files:
        ap.error("give at least one --pcap or --flows file")
    att = matcher(a.attacker_ip, a.attacker_net)
    parts = []
    sources = [("pcap", p) for p in a.pcap] + [("flows", f) for f in flow_files]
    for kind, pc in sources:
        if kind == "pcap":
            from nfstream import NFStreamer   # only needed for PCAP input
            df = NFStreamer(source=pc, statistical_analysis=True).to_pandas()
        else:
            df = pd.read_csv(pc)
        if a.label is not None:
            lbl = pd.Series(a.label, index=df.index)
        else:
            lbl = (df["src_ip"].apply(att) | df["dst_ip"].apply(att)).astype(int)
        df = df[FEATURES + ["src_ip", "dst_ip"]].copy(); df["label"] = lbl
        parts.append(df)
        print(f"[+] {pc}: {len(df)} flows, attack={int(lbl.sum())}")
    out = pd.concat(parts, ignore_index=True)
    out.to_csv(a.out, index=False)
    print(f"[+] wrote {a.out}: {len(out)} flows, attack={int(out['label'].sum())}, benign={int((out['label']==0).sum())}")

if __name__ == "__main__":
    main()
