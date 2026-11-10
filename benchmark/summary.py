#!/usr/bin/env python3
"""Print a text summary table from results/*.csv (no matplotlib)."""
import os, csv, glob, re, statistics
PAT=re.compile(r'^(?P<tr>[a-z]+)_n(?P<N>\d+)_(?P<cls>pass|drop)_r\d+$')
def cmean(xs):
    n=len(xs)
    if n==0: return 0.0
    lo,hi=int(n*0.2),int(n*0.8) or n; c=xs[lo:hi] if hi>lo else xs
    return sum(c)/len(c)
def metric(p,col):
    xs=[]
    with open(p) as f:
        for r in csv.DictReader(f): xs.append(float(r[col]))
    return cmean(xs)
data={}
for f in glob.glob("results/*.csv"):
    nm=os.path.splitext(os.path.basename(f))[0]; m=PAT.match(nm)
    if not m: continue
    k=(m["tr"],m["cls"],int(m["N"])); data.setdefault(k,{"rx":[],"cpu":[]})
    data[k]["rx"].append(metric(f,"rx_pps")); data[k]["cpu"].append(metric(f,"cpu_per_mpps"))
print(f"{'treat':<8}{'cls':<5}{'N':>7}{'n':>3}{'rx_pps':>12}{'cpu/Mpkt':>10}")
for key in sorted(data):
    d=data[key]
    print(f"{key[0]:<8}{key[1]:<5}{key[2]:>7}{len(d['rx']):>3}{statistics.mean(d['rx']):>12,.0f}{statistics.mean(d['cpu']):>10.3f}")
