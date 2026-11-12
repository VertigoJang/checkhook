#!/usr/bin/env python3
"""Evaluate a trained model on HELD-OUT flows and pick an operating threshold.

This step exists for ONE reason: false positives. Run it on benign captures the
model did NOT see during training to measure the real over-flagging rate, and to
choose the --threshold that keeps that rate under a target you set.

  python3 -m ml.eval --model model.joblib \
      --data holdout_benign.csv --data holdout_attack.csv --target-fpr 0.01

A held-out benign capture (normal traffic from a *different* session than the
one you trained on) is the honest test of over-flagging. Attack held-out is
optional but lets the tool report how many attacks survive at each threshold.
"""
import argparse
import numpy as np
import pandas as pd
import joblib
from checkhook.features import FEATURES


def load(model_path):
    d = joblib.load(model_path)
    return d["clf"], d.get("features", FEATURES)


def attack_proba(clf, X):
    classes = list(clf.classes_)
    if 1 in classes:
        return clf.predict_proba(X)[:, classes.index(1)]
    return clf.predict(X).astype(float)


def row(t, p, y, n0, n1):
    pred = (p >= t).astype(int)
    tp = int(((pred == 1) & (y == 1)).sum())
    fp = int(((pred == 1) & (y == 0)).sum())
    fpr = fp / n0 if n0 else 0.0
    tpr = tp / n1 if n1 else 0.0
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    return fp, tp, fpr, tpr, prec


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="model.joblib")
    ap.add_argument("--data", action="append", required=True,
                    help="held-out labelled CSV (repeatable)")
    ap.add_argument("--target-fpr", type=float, default=0.01,
                    help="max tolerated false-positive rate (default 1%%)")
    ap.add_argument("--grid", type=int, default=50,
                    help="threshold-sweep resolution for the recommendation")
    a = ap.parse_args()

    clf, feats = load(a.model)
    df = pd.concat([pd.read_csv(d) for d in a.data], ignore_index=True)
    X = df[feats].fillna(0.0).values
    y = df["label"].astype(int).values
    n0 = int((y == 0).sum())
    n1 = int((y == 1).sum())
    print(f"[i] held-out flows: benign={n0}  attack={n1}")
    if n0 == 0:
        print("[!] no benign flows here — FPR cannot be measured. "
              "Add a held-out benign capture; that is the whole point.")
    p = attack_proba(clf, X)

    print("\n  thr    FPR      TPR(recall)  precision   (benign flagged / attacks caught)")
    print("  ----  -------  -----------  ---------   --------------------------------")
    for t in [0.50, 0.60, 0.70, 0.80, 0.90, 0.95, 0.99]:
        fp, tp, fpr, tpr, prec = row(t, p, y, n0, n1)
        print(f"  {t:.2f}  {fpr:6.2%}   {tpr:7.2%}      {prec:6.2%}     "
              f"({fp}/{n0} benign, {tp}/{n1} atk)")

    # finest grid: smallest threshold whose FPR <= target
    best = None
    for t in np.linspace(0.50, 0.995, a.grid):
        fp, tp, fpr, tpr, prec = row(t, p, y, n0, n1)
        if fpr <= a.target_fpr:
            best = (t, fpr, tpr, prec)
            break
    print()
    if n0 == 0:
        return
    if best:
        t, fpr, tpr, prec = best
        print(f"[+] lowest threshold meeting the target: {t:.2f}")
        print(f"    FPR {fpr:.2%} (<= target {a.target_fpr:.2%})"
              + (f"; catches {tpr:.1%} of held-out attacks at precision {prec:.1%}" if n1 else
                 "; no held-out attack flows given, so detection was not measured"))
        if n0 < 300:
            print(f"[!] only {n0} held-out benign flows: 0 false positives here still allows a "
                  f"true rate up to ~{3 / n0:.1%} (rule of three). Hold out more benign traffic.")
        print(f"    use it: copy the model to ml.model and set ml.threshold: {max(t, 0.9):.2f} "
              "in the config (0.90 or higher keeps a safety margin)")
    else:
        print(f"[!] NO threshold in [0.50, 0.99] gets FPR down to {a.target_fpr:.2%}.")
        print("    The model over-flags normal traffic even when almost certain. "
              "Capture MORE DIVERSE benign traffic and retrain — the data is the fix, "
              "not the threshold.")


if __name__ == "__main__":
    main()
