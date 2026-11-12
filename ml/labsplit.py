#!/usr/bin/env python3
"""Inspect a lab capture and, if needed, split it into benign and attack parts.

The lab "benign" session only pings the host and opens TCP/22 (ssh banner);
the attack session starts with SYNs to many other ports. This tool finds the
first SYN from the lab client to a port other than the allowed ones and can
split the capture there.

  python3 -m ml.labsplit lab.pcap --client 172.28.128.10
  python3 -m ml.labsplit lab.pcap --client 172.28.128.10 --split benign.pcap attack.pcap
"""
import argparse, collections, datetime, socket, sys

import dpkt


def frames(path):
    with open(path, "rb") as f:
        try:
            rd = dpkt.pcap.Reader(f)
        except ValueError:
            f.seek(0)
            rd = dpkt.pcapng.Reader(f)
        for ts, buf in rd:
            yield ts, buf, rd.datalink()


def ip_of(buf, link):
    try:
        if link == dpkt.pcap.DLT_EN10MB:
            eth = dpkt.ethernet.Ethernet(buf)
            return eth.data if isinstance(eth.data, dpkt.ip.IP) else None
        if link in (dpkt.pcap.DLT_LINUX_SLL,):
            sll = dpkt.sll.SLL(buf)
            return sll.data if isinstance(sll.data, dpkt.ip.IP) else None
    except (dpkt.UnpackError, IndexError):
        return None
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pcap")
    ap.add_argument("--client", required=True, help="lab client (Kali) IP")
    ap.add_argument("--benign-ports", default="22", help="TCP ports the benign session uses")
    ap.add_argument("--split", nargs=2, metavar=("BENIGN_OUT", "ATTACK_OUT"))
    a = ap.parse_args()
    client = socket.inet_aton(a.client)
    ok_ports = {int(p) for p in a.benign_ports.split(",") if p}

    first = last = cut = None
    per_min = collections.Counter()
    kinds = collections.Counter()
    for ts, buf, link in frames(a.pcap):
        first = first if first is not None else ts
        last = ts
        per_min[datetime.datetime.fromtimestamp(ts).strftime("%H:%M")] += 1
        ip = ip_of(buf, link)
        if ip is None or ip.src != client:
            continue
        if isinstance(ip.data, dpkt.icmp.ICMP):
            kinds["icmp from client"] += 1
        elif isinstance(ip.data, dpkt.tcp.TCP):
            t = ip.data
            if t.flags & dpkt.tcp.TH_SYN and not t.flags & dpkt.tcp.TH_ACK:
                if t.dport in ok_ports:
                    kinds[f"SYN to {t.dport}"] += 1
                else:
                    kinds["SYN to other ports"] += 1
                    if cut is None:
                        cut = ts
        elif isinstance(ip.data, dpkt.udp.UDP):
            kinds["udp from client"] += 1
    if first is None:
        sys.exit("[x] empty capture")
    fmt = lambda t: datetime.datetime.fromtimestamp(t).strftime("%H:%M:%S")
    print(f"capture : {fmt(first)} - {fmt(last)}")
    print("per minute: " + ", ".join(f"{m} {n}" for m, n in sorted(per_min.items())))
    for k, n in kinds.most_common():
        print(f"  {k:<20} {n}")
    print(f"first SYN to a non-benign port: {fmt(cut) if cut else 'none'}")

    if a.split:
        if cut is None:
            sys.exit("[x] no attack part found; nothing to split")
        outs = [open(p, "wb") for p in a.split]
        writers = [dpkt.pcap.Writer(o, snaplen=65535, linktype=link) for o in outs]
        n = [0, 0]
        for ts, buf, link in frames(a.pcap):
            i = 0 if ts < cut else 1
            writers[i].writepkt(buf, ts=ts); n[i] += 1
        for o in outs:
            o.close()
        print(f"[+] {a.split[0]}: {n[0]} packets (before {fmt(cut)})")
        print(f"[+] {a.split[1]}: {n[1]} packets (from {fmt(cut)})")


if __name__ == "__main__":
    main()
