#!/usr/bin/env python3
"""Sample target RX PPS and softirq CPU cost per million packets from /proc."""
import argparse, os, time, csv
CLK=os.sysconf("SC_CLK_TCK")
def read_rx(iface):
    with open("/proc/net/dev") as f:
        for line in f:
            if ":" not in line: continue
            n,rest=line.split(":",1)
            if n.strip()!=iface: continue
            v=rest.split(); return int(v[1]),int(v[3])
    raise FileNotFoundError(iface)
def read_cpu():
    o={}
    with open("/proc/stat") as f:
        for line in f:
            if line.startswith("cpu") and line[3].isdigit():
                v=list(map(int,line.split()[1:])); o[line.split()[0]]=(v[6],sum(v))
    return o
def spct(p,c):
    r=[]
    for k in c:
        if k in p and c[k][1]-p[k][1]>0: r.append(100.0*(c[k][0]-p[k][0])/(c[k][1]-p[k][1]))
    return r
def sjif(p,c): return sum(c[k][0]-p[k][0] for k in c if k in p)
def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--label",required=True); ap.add_argument("--iface",default="eth0")
    ap.add_argument("--duration",type=int,default=15); ap.add_argument("--out",default="results")
    a=ap.parse_args(); os.makedirs(a.out,exist_ok=True)
    path=os.path.join(a.out,f"{a.label}.csv")
    pp,pd=read_rx(a.iface); pc=read_cpu(); rows=[]
    for t in range(1,a.duration+1):
        time.sleep(1)
        pk,dr=read_rx(a.iface); cu=read_cpu()
        rx=pk-pp; dd=dr-pd; s=spct(pc,cu); smax=max(s) if s else 0.0
        cpm=((sjif(pc,cu)/CLK)/rx*1e6) if rx>0 else 0.0
        rows.append([t,rx,dd,round(smax,2),round(cpm,3)]); pp,pd,pc=pk,dr,cu
    with open(path,"w",newline="") as f:
        w=csv.writer(f); w.writerow(["t","rx_pps","drop_pps","soft_max","cpu_per_mpps"]); w.writerows(rows)
    n=len(rows); lo,hi=int(n*0.2),int(n*0.8) or n; core=rows[lo:hi] if hi>lo else rows
    av=lambda i: sum(r[i] for r in core)/len(core)
    print(f"[+] {a.label}: rx={av(1):,.0f} cpu/Mpkt={av(4):.3f}s")
if __name__=="__main__": main()
