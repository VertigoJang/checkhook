#!/usr/bin/env python3
"""Generate N-sweep comparison figures (mean +/- stdev) from results/*.csv."""
import os, csv, glob, re, statistics, argparse
import matplotlib; matplotlib.use("Agg")
import matplotlib.pyplot as plt
PAT=re.compile(r'^(?P<tr>[a-z]+)_n(?P<N>\d+)_(?P<cls>pass|drop)_r\d+$')
def cmean(xs):
    n=len(xs)
    if n==0: return 0.0
    lo,hi=int(n*0.2),int(n*0.8) or n; core=xs[lo:hi] if hi>lo else xs
    return sum(core)/len(core)
def metric(path,col):
    xs=[]
    with open(path) as f:
        for r in csv.DictReader(f): xs.append(float(r[col]))
    return cmean(xs)
def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--dir",default="results"); a=ap.parse_args()
    data={}; base={}
    for f in glob.glob(os.path.join(a.dir,"*.csv")):
        nm=os.path.splitext(os.path.basename(f))[0]; m=PAT.match(nm)
        if not m: continue
        tr,N,cls=m["tr"],int(m["N"]),m["cls"]; rx=metric(f,"rx_pps"); cpu=metric(f,"cpu_per_mpps")
        if tr=="baseline": base.setdefault("rx_pps",[]).append(rx); base.setdefault("cpu_per_mpps",[]).append(cpu); continue
        d=data.setdefault((tr,cls),{}).setdefault(N,{}); d.setdefault("rx_pps",[]).append(rx); d.setdefault("cpu_per_mpps",[]).append(cpu)
    trs=["ipt","ipset","nft","xdp"]; nm={"ipt":"iptables (linear)","ipset":"iptables+ipset","nft":"nftables set","xdp":"XDP+eBPF map"}
    sd=lambda xs: statistics.stdev(xs) if len(xs)>1 else 0.0
    def plot(cls,col,yl,tt,fn):
        fig,ax=plt.subplots(figsize=(9,5.5))
        for tr in trs:
            if (tr,cls) not in data: continue
            Ns=sorted(data[(tr,cls)]); ys=[statistics.mean(data[(tr,cls)][N][col]) for N in Ns]; es=[sd(data[(tr,cls)][N][col]) for N in Ns]
            ax.errorbar(Ns,ys,yerr=es,marker="o",capsize=4,label=nm[tr])
        if base.get(col): ax.axhline(statistics.mean(base[col]),ls="--",color="gray",label="baseline (no enforce)")
        ax.set_xscale("log"); ax.set_xlabel("Blocklist size N (log)"); ax.set_ylabel(yl); ax.set_title(tt); ax.legend(); ax.grid(True,alpha=0.3)
        fig.tight_layout(); fig.savefig(os.path.join(a.dir,fn),dpi=130); plt.close(fig)
    plot("pass","rx_pps","Mean RX PPS","Legit traffic: N vs throughput","bench_pass_pps.png")
    plot("pass","cpu_per_mpps","softirq CPU-sec per Mpkt","Legit traffic: N vs CPU cost","bench_pass_cpu.png")
    plot("drop","rx_pps","Mean RX PPS","Attack traffic: N vs drop throughput","bench_drop_pps.png")
    plot("drop","cpu_per_mpps","softirq CPU-sec per Mpkt","Attack traffic: N vs CPU cost","bench_drop_cpu.png")
    with open(os.path.join(a.dir,"summary.csv"),"w",newline="") as f:
        w=csv.writer(f); w.writerow(["treatment","class","N","n","rx_pps","rx_sd","cpu_per_mpps","cpu_sd"])
        for (tr,cls),dd in sorted(data.items()):
            for N in sorted(dd):
                rx=dd[N]["rx_pps"]; cpu=dd[N]["cpu_per_mpps"]
                w.writerow([tr,cls,N,len(rx),round(statistics.mean(rx)),round(sd(rx)),round(statistics.mean(cpu),3),round(sd(cpu),3)])
    print("[+] 4 PNG + summary.csv")
if __name__=="__main__": main()
