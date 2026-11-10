#!/usr/bin/env python3
"""Train a RandomForest flow classifier on a labelled nfstream dataset.

  python3 -m ml.train --data flows.csv --out model.joblib
"""
import argparse, joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import sys
from checkhook.features import FEATURES

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", action="append", required=True, help="labelled CSV (repeatable)")
    ap.add_argument("--out", default="model.joblib")
    ap.add_argument("--trees", type=int, default=100)
    a = ap.parse_args()
    df = pd.concat([pd.read_csv(d) for d in a.data], ignore_index=True)
    X = df[FEATURES].fillna(0.0); y = df["label"].astype(int)
    strat = y if y.nunique() > 1 and (y.value_counts().min() >= 2) else None
    if len(df) >= 10 and strat is not None:
        Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.3, random_state=42, stratify=strat)
    else:
        Xtr, Xte, ytr, yte = X, X, y, y  # tiny smoke dataset
    n0 = int((y == 0).sum()); n1 = int((y == 1).sum())
    print(f"[i] dataset: benign={n0} attack={n1}")
    if n0 == 0 or n1 == 0:
        sys.exit("[!] need both benign (0) and attack (1) flows to train")
    minor = min(n0, n1) / (n0 + n1)
    if minor < 0.2:
        print(f"[!] WARNING: classes are imbalanced (minority {minor:.1%}). "
              "The model will over-predict the majority class; gather more balanced data.")
    clf = RandomForestClassifier(n_estimators=a.trees, n_jobs=-1, random_state=42, class_weight="balanced")
    clf.fit(Xtr.values, ytr)

    yp = clf.predict(Xte.values)
    print(classification_report(yte, yp, zero_division=0))

    # confusion matrix: the off-diagonals are the mistakes we care about
    cm = confusion_matrix(yte, yp, labels=[0, 1])
    (tn, fp), (fn, tp) = cm
    print("confusion (held-out split):")
    print(f"             pred_benign  pred_attack")
    print(f"  benign     {tn:>10}  {fp:>10}   <- {fp} false positives")
    print(f"  attack     {fn:>10}  {tp:>10}   <- {fn} missed attacks")

    # which features the model leans on (over-reliance on one is a red flag)
    imp = sorted(zip(FEATURES, clf.feature_importances_), key=lambda x: -x[1])[:10]
    print("top features:", ", ".join(f"{f}={w:.2f}" for f, w in imp))

    if strat is not None and len(df) >= 10:
        print("[i] this split came from the SAME captures. For an honest false-positive "
              "number, run: python3 -m ml.eval --model {} --data <held-out benign>.csv".format(a.out))

    joblib.dump({"clf": clf, "features": FEATURES}, a.out)
    print(f"[+] saved {a.out}")

if __name__ == "__main__":
    main()
