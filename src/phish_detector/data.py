"""Budowa zbioru danych z prawdziwych zrodel: Tranco (legalne) + OpenPhish/PhishTank (phishing).

    python -m phish_detector.data --tranco data/raw/top-1m.csv \
        --phishing data/raw/openphish.txt --out data/dataset.csv --n 50000

UWAGA (pulapka): Tranco to same domeny, a phishing ma dlugie sciezki. Aby model nie uczyl sie
"ma sciezke = phishing", do legalnych domen doklejamy realistyczne sciezki (LEGIT_PATH_TEMPLATES).
To nadal przyblizenie - opisz je w README jako ograniczenie.
"""
import argparse
import random
from pathlib import Path
from urllib.parse import urlsplit

import pandas as pd

WORDS = ["news", "shop", "home", "garden", "travel", "music", "photo", "tech", "food", "city",
         "sport", "auto", "health", "book", "game", "art", "film", "blog", "market", "design"]

LEGIT_PATH_TEMPLATES = [
    "", "", "/", "/about", "/contact", "/products/{n}", "/blog/{w}-{w2}", "/search?q={w}",
    "/account/settings", "/login", "/help/{w}", "/news/2024/{w}", "/category/{w}/page/{n}",
    "/user/{n}/profile", "/{w}/{w2}/{n}.html",
]


def random_path(rng: random.Random) -> str:
    tpl = rng.choice(LEGIT_PATH_TEMPLATES)
    return tpl.format(n=rng.randint(1, 99999), w=rng.choice(WORDS), w2=rng.choice(WORDS))


def load_tranco(path: str, top_n: int) -> list[str]:
    df = pd.read_csv(path, header=None, names=["rank", "domain"], nrows=top_n)
    return df["domain"].astype(str).str.lower().tolist()


def load_phishing(path: str) -> list[str]:
    urls = []
    for line in Path(path).read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if line.startswith(("http://", "https://")):
            urls.append(line)
    return urls


def build_dataset(tranco_csv: str, phishing_file: str, n_per_class: int, seed: int = 42) -> pd.DataFrame:
    rng = random.Random(seed)
    domains = load_tranco(tranco_csv, top_n=max(n_per_class * 3, 1000))
    rng.shuffle(domains)
    legit = []
    for d in domains[:n_per_class]:
        scheme = "https" if rng.random() < 0.9 else "http"
        prefix = "www." if rng.random() < 0.3 else ""
        legit.append(f"{scheme}://{prefix}{d}{random_path(rng)}")
    phish = list(dict.fromkeys(u for u in load_phishing(phishing_file) if urlsplit(u).hostname))
    rng.shuffle(phish)
    phish = phish[:n_per_class]
    df = pd.DataFrame({"url": legit + phish, "label": [0] * len(legit) + [1] * len(phish)})
    return df.drop_duplicates("url").sample(frac=1, random_state=seed).reset_index(drop=True)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--tranco", required=True)
    ap.add_argument("--phishing", required=True)
    ap.add_argument("--out", default="data/dataset.csv")
    ap.add_argument("--n", type=int, default=50000, help="maks. liczba URL na klase")
    args = ap.parse_args()
    df = build_dataset(args.tranco, args.phishing, args.n)
    df.to_csv(args.out, index=False)
    print(f"Zapisano {len(df)} wierszy ({df.label.sum()} phishing) -> {args.out}")


if __name__ == "__main__":
    main()
