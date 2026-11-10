#!/usr/bin/env python3
"""Compile xdp_filter.c via BCC, attach to an interface, load a blocklist."""
import argparse, ctypes as ct, ipaddress, socket, struct, time
from bcc import BPF
SKB=(1<<1); DRV=(1<<2)
def key(ip): return struct.unpack("I", socket.inet_aton(ip))[0]
def expand(items):
    o=[]
    for it in items:
        if "/" in it: o+=[str(h) for h in ipaddress.ip_network(it,strict=False).hosts()]
        else: o.append(it)
    return o
def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("-i","--iface",required=True)
    ap.add_argument("--block",nargs="*",default=[])
    ap.add_argument("--block-file",default=None)
    ap.add_argument("--port",type=int,default=0)
    ap.add_argument("--mode",choices=["skb","drv"],default="skb")
    ap.add_argument("--quiet",action="store_true")
    a=ap.parse_args()
    flags=SKB if a.mode=="skb" else DRV
    b=BPF(src_file="xdp_filter.c"); fn=b.load_func("xdp_filter",BPF.XDP)
    b.attach_xdp(a.iface,fn,flags)
    bl=b["blocklist"]; b["filter_port"][ct.c_int(0)]=ct.c_uint(a.port)
    tg=expand(a.block)
    if a.block_file:
        with open(a.block_file) as f: tg+=[ln.strip() for ln in f if ln.strip()]
    for ip in tg: bl[ct.c_uint(key(ip))]=ct.c_ulonglong(0)
    print(f"[+] XDP {a.iface} mode={a.mode} blocklist={len(tg)}")
    try:
        while True:
            time.sleep(1)
            if not a.quiet: print(f"  drop_total={sum(v.value for _,v in bl.items())}")
    except KeyboardInterrupt: pass
    finally:
        b.remove_xdp(a.iface,flags); print("[+] detached")
if __name__=="__main__": main()
