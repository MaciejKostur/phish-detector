"""Trenuje maly model na danych syntetycznych i sprawdza caly potok."""
import json
import tempfile
from pathlib import Path

from phish_detector.predictor import Predictor
from phish_detector.synth import generate
from phish_detector.train import split_by_domain, train
from phish_detector.features import registered_domain

_cache = {}


def _model_path() -> str:
    if "path" not in _cache:
        tmp = Path(tempfile.mkdtemp())
        csv = tmp / "synthetic.csv"
        generate(600).to_csv(csv, index=False)
        bundle = train(str(csv), str(tmp / "model.joblib"))
        _cache.update(path=str(tmp / "model.joblib"), bundle=bundle, tmp=tmp)
    return _cache["path"]


def test_split_has_no_domain_leakage():
    import numpy as np
    df = generate(300)
    groups = np.array([registered_domain(u) for u in df["url"]])
    tr, va, te = split_by_domain(groups, df["label"].to_numpy(), seed=1)
    assert not set(groups[tr]) & set(groups[te])
    assert not set(groups[tr]) & set(groups[va])
    assert not set(groups[va]) & set(groups[te])


def test_training_quality_on_synthetic():
    _model_path()
    best = _cache["bundle"]["model_name"]
    m = _cache["bundle"]["metrics"][best]["test"]
    assert m["pr_auc"] > 0.9
    assert m["recall"] > 0.8
    assert (_cache["tmp"] / "model.metrics.json").exists()


def test_predictor_ranks_phishing_above_legit():
    p = Predictor(_model_path())
    bad = p.predict("http://paypa1-secure-login.xyz/verify/account")
    good = p.predict("https://www.wikipedia.org/")
    assert bad["probability"] > good["probability"]
    assert bad["verdict"] == "phishing"
    assert good["verdict"] == "legitimate"
    assert bad["reasons"], "phishing powinien miec wyjasnienie"


def test_predictor_rejects_bad_input():
    p = Predictor(_model_path())
    for bad in ["", "   ", "http://a b.com", "x" * 3000, None]:
        try:
            p.predict(bad)
        except ValueError:
            continue
        raise AssertionError(f"powinien odrzucic: {bad!r}")
