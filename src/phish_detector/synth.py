"""Generator SYNTETYCZNYCH danych - tylko do sprawdzenia, ze caly potok dziala.

Wyniki na tych danych NIE nadaja sie do README (zbior jest zbyt latwy). Do metryk uzyj
prawdziwych danych z phish_detector.data.

    python -m phish_detector.synth --out data/synthetic.csv --n 3000
"""
import argparse
import random

import pandas as pd

from .brands import BRANDS
from .data import WORDS, random_path

POPULAR = [
    "google.com", "youtube.com", "wikipedia.org", "amazon.com", "github.com", "reddit.com",
    "microsoft.com", "apple.com", "netflix.com", "linkedin.com", "allegro.pl", "olx.pl",
    "onet.pl", "wp.pl", "interia.pl", "gov.pl", "mbank.pl", "pkobp.pl", "inpost.pl", "bbc.co.uk",
    "nytimes.com", "stackoverflow.com", "twitter.com", "paypal.com", "dropbox.com", "ing.pl",
]
LEGIT_TLDS = ["com", "pl", "org", "net", "eu", "de", "io", "co.uk", "com.pl"]
PHISH_TLDS = ["xyz", "top", "tk", "click", "icu", "buzz", "online", "site", "info", "com", "net", "pl"]
VERBS = ["login", "verify", "secure", "update", "confirm", "account", "weryfikacja", "konto", "blik"]


def _legit(rng: random.Random) -> str:
    if rng.random() < 0.4:
        host = rng.choice(POPULAR)
        host = rng.choice(["", "www.", "blog.", "accounts.", "support."]) + host
    else:
        sep = rng.choice(["", "", "-"])
        host = rng.choice(WORDS) + sep + rng.choice(WORDS) + str(rng.choice(["", "", "24"])) + "." + rng.choice(LEGIT_TLDS)
    return f"{rng.choice(['https', 'https', 'http'])}://{host}{random_path(rng)}"


def _phish(rng: random.Random) -> str:
    brand = rng.choice(list(BRANDS))
    verb, word = rng.choice(VERBS), rng.choice(WORDS)
    tld = rng.choice(PHISH_TLDS)
    kind = rng.randrange(7)
    if kind == 0:  # literowka / podmiana znakow
        typo = brand.replace("l", "1", 1) if "l" in brand else brand.replace("o", "0", 1)
        host = f"{typo}-{verb}.{tld}"
        path = f"/{verb}"
    elif kind == 1:  # marka + slowo wabik
        host = f"{brand}-{verb}-{word}.{tld}"
        path = f"/{verb}/{rng.randint(100, 99999)}"
    elif kind == 2:  # marka jako subdomena obcej domeny
        host = f"{brand}.com.{verb}-{word}.{tld}"
        path = f"/{verb}.php"
    elif kind == 3:  # adres IP
        host = ".".join(str(rng.randint(1, 254)) for _ in range(4))
        path = f"/{brand}/{verb}/index.html"
    elif kind == 4:  # trik z @
        host = f"{brand}.com@{word}{rng.randint(10, 999)}.{tld}"
        path = f"/{verb}"
    elif kind == 5:  # wiele subdomen
        host = ".".join([verb, brand, "secure", word]) + f".{rng.choice(WORDS)}{rng.randint(1, 99)}.{tld}"
        path = f"/{verb}"
    else:  # przejeta zwykla strona
        host = f"{rng.choice(WORDS)}{rng.choice(WORDS)}.{rng.choice(LEGIT_TLDS)}"
        path = f"/wp-content/plugins/{word}/{verb}.php?id={rng.getrandbits(40):x}"
    return f"{rng.choice(['http', 'https'])}://{host}{path}"


def generate(n_per_class: int = 3000, seed: int = 42) -> pd.DataFrame:
    rng = random.Random(seed)
    legit = {_legit(rng) for _ in range(n_per_class * 2)}
    phish = {_phish(rng) for _ in range(n_per_class * 2)}
    legit, phish = sorted(legit)[:n_per_class], sorted(phish)[:n_per_class]
    df = pd.DataFrame({"url": legit + phish, "label": [0] * len(legit) + [1] * len(phish)})
    return df.sample(frac=1, random_state=seed).reset_index(drop=True)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="data/synthetic.csv")
    ap.add_argument("--n", type=int, default=3000)
    args = ap.parse_args()
    df = generate(args.n)
    df.to_csv(args.out, index=False)
    print(f"Zapisano {len(df)} wierszy -> {args.out}")


if __name__ == "__main__":
    main()
