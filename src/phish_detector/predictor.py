import os
from pathlib import Path

import joblib
import pandas as pd

from .explain import contributions, top_reasons
from .features import FEATURE_NAMES, extract

MAX_URL_LEN = 2048


def validate_url(url) -> str:
    if not isinstance(url, str) or not url.strip():
        raise ValueError("Adres URL nie może być pusty")
    url = url.strip()
    if len(url) > MAX_URL_LEN:
        raise ValueError(f"Adres jest dłuższy niż {MAX_URL_LEN} znaków")
    if any(ord(c) < 32 or c.isspace() for c in url):
        raise ValueError("Adres zawiera białe lub niedozwolone znaki")
    return url


class Predictor:
    """Ocenia wylacznie tekst adresu. Nigdy nie laczy sie z podanym adresem (ochrona przed SSRF)."""

    def __init__(self, model_path: str | None = None):
        path = Path(model_path or os.getenv("MODEL_PATH", "models/model.joblib"))
        if not path.exists():
            raise FileNotFoundError(f"Brak modelu: {path}. Uruchom phish_detector.train.")
        self.bundle = joblib.load(path)

    @property
    def model_name(self) -> str:
        return self.bundle["model_name"]

    def predict(self, url: str, top_k: int = 3) -> dict:
        url = validate_url(url)
        row = extract(url)
        names = self.bundle["feature_names"]
        proba = float(self.bundle["model"].predict_proba(pd.DataFrame([row], columns=names))[0, 1])
        contribs = contributions(self.bundle["model"], row, names, self.bundle["baseline"])
        reasons, reassuring = top_reasons(contribs, row, k=top_k)
        threshold = self.bundle["threshold"]
        is_phishing = proba >= threshold
        return {
            "url": url,
            "verdict": "phishing" if is_phishing else "legitimate",
            "probability": round(proba, 4),
            "threshold": round(threshold, 4),
            # powody blokady tylko przy werdykcie "phishing"; inaczej to tylko drobne sygnaly
            "reasons": reasons if is_phishing else [],
            "minor_signals": [] if is_phishing else reasons,
            "reassuring_features": reassuring,
        }
