"""Wyjasnianie decyzji metoda ablacyjna (niezalezna od modelu).

Dla kazdej cechy: o ile spadlaby ocena modelu, gdyby ta jedna cecha miala wartosc "typowego
legalnego adresu" (mediana z klasy 0)? Liczymy w skali log-odds (decision_function), a nie
w prawdopodobienstwie, bo przy pewnych decyzjach (p ~ 1.0) prawdopodobienstwo jest nasycone
i usuniecie jednej cechy nic w nim nie zmienia. Ograniczenie: przy skorelowanych cechach
pojedyncza ablacja nadal zanizy wklad - dokladniejsza alternatywa to SHAP.
"""
import numpy as np
import pandas as pd

REASONS = {
    "host_is_ip": lambda v: "Adres używa numeru IP zamiast nazwy domeny",
    "has_at": lambda v: "Adres zawiera znak „@”, który potrafi ukryć prawdziwy host",
    "brand_lookalike": lambda v: "Domena udaje znaną markę (literówka lub podmienione znaki)",
    "brand_in_host_not_owned": lambda v: "Nazwa znanej marki występuje w domenie, która do niej nie należy",
    "brand_in_path_not_owned": lambda v: "Nazwa znanej marki pojawia się w ścieżce obcej domeny",
    "n_subdomains": lambda v: f"Bardzo dużo subdomen ({int(v)})",
    "url_len": lambda v: f"Nietypowo długi adres ({int(v)} znaków)",
    "host_len": lambda v: f"Nietypowo długa nazwa hosta ({int(v)} znaków)",
    "suspicious_tld": lambda v: "Domena w strefie często nadużywanej przez wyłudzenia",
    "n_kw_host": lambda v: "W nazwie domeny są słowa typowe dla wyłudzeń (np. login, verify, konto)",
    "n_kw_path": lambda v: "W ścieżce adresu są słowa typowe dla wyłudzeń (np. login, verify, konto)",
    "has_punycode": lambda v: "Domena zawiera znaki spoza ASCII/punycode (możliwy atak homograficzny)",
    "is_shortener": lambda v: "Adres to skrócony link, który ukrywa cel",
    "n_hyphens_host": lambda v: f"Dużo myślników w nazwie domeny ({int(v)})",
    "n_digits_host": lambda v: f"Dużo cyfr w nazwie domeny ({int(v)})",
    "digit_ratio_url": lambda v: "Nietypowo duży udział cyfr w adresie",
    "entropy_host": lambda v: "Nazwa domeny wygląda na losową (wysoka entropia)",
    "entropy_path": lambda v: "Ścieżka wygląda na losową (wysoka entropia)",
    "has_port": lambda v: "Adres używa nietypowego portu",
    "n_pct_encoded": lambda v: f"Dużo zakodowanych znaków (%xx): {int(v)}",
    "has_double_slash_path": lambda v: "Podwójny ukośnik w ścieżce (możliwe przekierowanie)",
    "path_depth": lambda v: f"Głęboka ścieżka ({int(v)} poziomów)",
    "path_len": lambda v: f"Długa ścieżka ({int(v)} znaków)",
    "query_len": lambda v: f"Długi ciąg parametrów ({int(v)} znaków)",
    "n_special_chars": lambda v: "Dużo znaków specjalnych w ścieżce lub parametrach",
    "n_dots_host": lambda v: f"Dużo kropek w nazwie hosta ({int(v)})",
}


def _score(model, frame: pd.DataFrame) -> np.ndarray:
    """Ocena w skali log-odds (bez nasycenia)."""
    if hasattr(model, "decision_function"):
        return np.asarray(model.decision_function(frame), dtype=float)
    p = np.clip(model.predict_proba(frame)[:, 1], 1e-9, 1 - 1e-9)
    return np.log(p / (1 - p))


def contributions(model, row: dict, feature_names: list[str], baseline: dict) -> dict[str, float]:
    """Wklad cechy = score(x) - score(x z ta cecha ustawiona na wartosc bazowa), w log-odds."""
    frame = pd.DataFrame([row] * (len(feature_names) + 1), columns=feature_names).astype(float)
    for i, name in enumerate(feature_names, start=1):
        frame.iat[i, frame.columns.get_loc(name)] = float(baseline[name])
    score = _score(model, frame)
    return {name: float(score[0] - score[i]) for i, name in enumerate(feature_names, start=1)}


def top_reasons(contribs: dict[str, float], row: dict, k: int = 3, min_delta: float = 0.5):
    """(powody za phishingiem, powody uspokajajace) jako czytelne zdania."""
    ranked = sorted(contribs.items(), key=lambda kv: kv[1], reverse=True)
    why = [REASONS.get(n, lambda v, n=n: f"Nietypowa wartość cechy {n}")(row[n])
           for n, d in ranked if d >= min_delta][:k]
    ok = [n for n, d in reversed(ranked) if d <= -min_delta][:k]
    return why, ok
