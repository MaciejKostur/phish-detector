"""Metryki oceny. Nie raportujemy samej accuracy - patrz PR-AUC i odsetek falszywych alarmow."""
import argparse
import json

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, confusion_matrix, roc_auc_score

from .features import FEATURE_NAMES, extract


def compute_metrics(y_true, proba, threshold: float, prevalence: float = 0.01) -> dict:
    y_true = np.asarray(y_true)
    proba = np.asarray(proba)
    pred = proba >= threshold
    tn, fp, fn, tp = confusion_matrix(y_true, pred, labels=[0, 1]).ravel()
    div = lambda a, b: float(a / b) if b else 0.0
    precision, recall = div(tp, tp + fp), div(tp, tp + fn)
    fpr = div(fp, fp + tn)
    return {
        "threshold": float(threshold),
        "precision": precision,
        "recall": recall,
        "f1": div(2 * precision * recall, precision + recall),
        "false_positive_rate": fpr,
        "pr_auc": float(average_precision_score(y_true, proba)),
        "roc_auc": float(roc_auc_score(y_true, proba)),
        # precyzja przy realistycznej czestosci phishingu (zbior testowy jest zbalansowany)
        f"precision_at_{prevalence:.0%}_prevalence": div(recall * prevalence, recall * prevalence + fpr * (1 - prevalence)),
        "confusion": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
    }


def main() -> None:
    ap = argparse.ArgumentParser(description="Ocena zapisanego modelu na innym zbiorze CSV")
    ap.add_argument("--model", default="models/model.joblib")
    ap.add_argument("--data", required=True)
    args = ap.parse_args()
    bundle = joblib.load(args.model)
    df = pd.read_csv(args.data).dropna(subset=["url", "label"])
    X = pd.DataFrame([extract(u) for u in df["url"]], columns=FEATURE_NAMES)
    proba = bundle["model"].predict_proba(X)[:, 1]
    print(json.dumps(compute_metrics(df["label"], proba, bundle["threshold"]), indent=2))


if __name__ == "__main__":
    main()
