"""Znane marki (w tym polskie) i sygnaly podszywania sie pod nie."""
import re

# nazwa marki -> oficjalne domeny rejestrowalne
BRANDS: dict[str, set[str]] = {
    "paypal": {"paypal.com", "paypal.me"},
    "google": {"google.com", "google.pl", "gmail.com"},
    "microsoft": {"microsoft.com", "live.com", "office.com", "outlook.com", "microsoftonline.com"},
    "apple": {"apple.com", "icloud.com"},
    "amazon": {"amazon.com", "amazon.de", "amazon.pl", "amazon.co.uk"},
    "facebook": {"facebook.com", "fb.com"},
    "instagram": {"instagram.com"},
    "whatsapp": {"whatsapp.com"},
    "netflix": {"netflix.com"},
    "linkedin": {"linkedin.com"},
    "dropbox": {"dropbox.com"},
    "github": {"github.com"},
    "dhl": {"dhl.com", "dhl.de", "dhl.pl"},
    "fedex": {"fedex.com"},
    "allegro": {"allegro.pl", "allegro.com"},
    "olx": {"olx.pl", "olx.com"},
    "inpost": {"inpost.pl", "inpost.eu"},
    "pocztex": {"pocztex.pl", "poczta-polska.pl"},
    "dpd": {"dpd.com", "dpd.com.pl"},
    "blik": {"blik.com"},
    "mbank": {"mbank.pl"},
    "santander": {"santander.pl", "santander.com"},
    "pkobp": {"pkobp.pl", "iko.pkobp.pl"},
    "ing": {"ing.pl", "ing.com"},
    "millennium": {"bankmillennium.pl"},
    "aliorbank": {"aliorbank.pl"},
    "mobywatel": {"gov.pl", "mobywatel.gov.pl"},
    "orlen": {"orlen.pl"},
}

_HOMOGLYPHS = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "$": "s", "@": "a"})
_SPLIT = re.compile(r"[^a-z0-9]+")


def normalize_homoglyphs(text: str) -> str:
    text = text.lower().translate(_HOMOGLYPHS)
    return text.replace("rn", "m").replace("vv", "w")


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a or not b:
        return max(len(a), len(b))
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _tokens(text: str) -> list[str]:
    return [t for t in _SPLIT.split(text.lower()) if t]


def _mentions(brand: str, tokens: list[str]) -> bool:
    """Krotkie nazwy tylko jako cale tokeny, dlugie takze jako fragment tokenu."""
    if len(brand) >= 6:
        return any(brand in t for t in tokens)
    return brand in tokens


def brand_signals(registered: str, subdomain: str, label: str, path: str) -> dict[str, int]:
    """Zwraca flagi 0/1: marka w hoscie / sciezce na cudzej domenie oraz literowka."""
    in_host = in_path = lookalike = 0
    host_tokens = _tokens(f"{subdomain}.{label}")
    path_tokens = _tokens(path)
    label_tokens = _tokens(label)

    for brand, officials in BRANDS.items():
        if registered in officials:
            continue
        if _mentions(brand, host_tokens):
            in_host = 1
        if _mentions(brand, path_tokens):
            in_path = 1
        if len(brand) >= 5:
            max_dist = 1 if len(brand) < 8 else 2
            for tok in label_tokens:
                norm = normalize_homoglyphs(tok)
                if tok != brand and abs(len(norm) - len(brand)) <= 2 and levenshtein(norm, brand) <= max_dist:
                    lookalike = 1
    return {
        "brand_in_host_not_owned": in_host,
        "brand_in_path_not_owned": in_path,
        "brand_lookalike": lookalike,
    }
