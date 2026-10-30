"""Trenowanie: podzial po domenach (bez wycieku), wybor modelu i progu, zapis modelu.

    python -m phish_detector.train --data data/dataset.csv --out models/model.joblib
"""
import argparse
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, precision_recall_curve
from sklearn.model_selection import GroupShuffleSplit
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

from .evaluate import compute_metrics
from .features import FEATURE_NAMES, extract, registered_domain


def make_models(seed: int) -> dict:
    return {
        "logreg": make_pipeline(StandardScaler(), LogisticRegression(max_iter=2000, class_weight="balanced")),
        "hist_gb": HistGradientBoostingClassifier(max_iter=300, learning_rate=0.08, random_state=seed),
    }


def pick_threshold(y, p, min_precision: float = 0.98) -> float:
    """Najwiekszy recall przy precyzji >= min_precision; gdy sie nie da - maksimum F1."""
    prec, rec, thr = precision_recall_curve(y, p)
    prec, rec = prec[:-1], rec[:-1]
    ok = np.where(prec >= min_precision)[0]
    if len(ok):
        return float(thr[ok[np.argmax(rec[ok])]])
    f1 = 2 * prec * rec / (prec + rec + 1e-12)
    return float(thr[int(np.argmax(f1))])


def split_by_domain(groups: np.ndarray, y: np.ndarray, seed: int):
    """Podzial 70/15/15, w ktorym ta sama domena nigdy nie trafia do dwoch zbiorow."""
    idx = np.arange(len(y))
    tv, te = next(GroupShuffleSplit(1, test_size=0.15, random_state=seed).split(idx, y, groups))
    tr_rel, va_rel = next(GroupShuffleSplit(1, test_size=0.1765, random_state=seed).split(tv, y[tv], groups[tv]))
    return tv[tr_rel], tv[va_rel], te


def train(data_path: str, out_path: str, seed: int = 42, min_precision: float = 0.98) -> dict:
    df = pd.read_csv(data_path).dropna(subset=["url", "label"]).drop_duplicates("url").reset_index(drop=True)
    X = pd.DataFrame([extract(u) for u in df["url"]], columns=FEATURE_NAMES)
    y = df["label"].astype(int).to_numpy()
    groups = np.array([registered_domain(u) for u in df["url"]])

    tr, va, te = split_by_domain(groups, y, seed)
    overlap = set(groups[tr]) & set(groups[te])
    assert not overlap, "wyciek: te same domeny w train i test"

    results, fitted = {}, {}
    for name, model in make_models(seed).items():
        model.fit(X.iloc[tr], y[tr])
        fitted[name] = model
        results[name] = {"val_pr_auc": float(average_precision_score(y[va], model.predict_proba(X.iloc[va])[:, 1]))}

    best = max(results, key=lambda n: results[n]["val_pr_auc"])
    threshold = pick_threshold(y[va], fitted[best].predict_proba(X.iloc[va])[:, 1], min_precision)

    for name, model in fitted.items():  # ocena na zbiorze testowym, z progiem wybranym na walidacji
        results[name]["test"] = compute_metrics(y[te], model.predict_proba(X.iloc[te])[:, 1], threshold)

    bundle = {
        "model_name": best,
        "model": fitted[best],
        "feature_names": FEATURE_NAMES,
        "baseline": X.iloc[tr][y[tr] == 0].median().to_dict(),  # "typowy legalny adres"
        "threshold": threshold,
        "metrics": results,
        "sizes": {"train": len(tr), "val": len(va), "test": len(te)},
    }
    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, out_path)
    Path(out_path).with_suffix(".metrics.json").write_text(
        json.dumps({"model": best, "sizes": bundle["sizes"], "results": results}, indent=2), encoding="utf-8"
    )
    return bundle


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", required=True)
    ap.add_argument("--out", default="models/model.joblib")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--min-precision", type=float, default=0.98)
    args = ap.parse_args()
    b = train(args.data, args.out, args.seed, args.min_precision)
    print(f"Najlepszy model: {b['model_name']}, prog = {b['threshold']:.3f}")
    print(json.dumps(b["metrics"][b["model_name"]]["test"], indent=2))


if __name__ == "__main__":
    main()
