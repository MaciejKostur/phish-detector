"""Zamiana adresu URL na wektor cech. Cechy leksykalne - bez odwiedzania strony."""
import ipaddress
import math
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from .brands import brand_signals

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "buff.ly", "cutt.ly",
    "rebrand.ly", "tiny.cc", "shorturl.at", "rb.gy", "lnkd.in", "t.ly",
}
SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "click", "link", "work", "zip", "mov",
    "icu", "buzz", "cyou", "rest", "monster", "sbs", "loan", "men", "kim", "country",
}
KEYWORDS = [
    "login", "signin", "sign-in", "logowanie", "verify", "verification", "weryfikacja",
    "secure", "security", "account", "konto", "update", "confirm", "banking", "password",
    "haslo", "wallet", "billing", "suspend", "unlock", "invoice", "payment", "platnosc",
    "doplata", "oplata", "przesylka", "paczka", "blik",
]
_MULTI_SUFFIX = {
    "co.uk", "org.uk", "com.pl", "net.pl", "org.pl", "edu.pl", "gov.pl",
    "com.au", "co.jp", "com.br", "co.in", "com.tr",
}

FEATURE_NAMES = [
    "url_len", "host_len", "path_len", "query_len",
    "n_dots_host", "n_hyphens_host", "n_digits_host", "digit_ratio_url", "n_subdomains",
    "n_special_chars", "has_at", "host_is_ip", "has_port", "has_punycode",
    "entropy_host", "entropy_path", "n_kw_host", "n_kw_path",
    "is_shortener", "suspicious_tld", "path_depth", "n_pct_encoded", "has_double_slash_path",
    "brand_in_host_not_owned", "brand_in_path_not_owned", "brand_lookalike",
]

_extractor = None


@dataclass
class ParsedUrl:
    host: str = ""
    port: int | None = None
    path: str = ""
    query: str = ""
    has_at: bool = False
    subdomain: str = ""
    label: str = ""        # domena bez sufiksu, np. "paypal"
    suffix: str = ""       # np. "com" albo "com.pl"
    registered: str = ""   # np. "paypal.com"
    is_ip: bool = False


def _split_host(host: str) -> tuple[str, str, str]:
    """(subdomena, label, sufiks). Uzywa tldextract, a bez niego prostej heurystyki."""
    global _extractor
    try:
        if _extractor is None:
            import tldextract
            _extractor = tldextract.TLDExtract(suffix_list_urls=())  # snapshot offline
        r = _extractor(host)
        if r.suffix and r.domain:
            return r.subdomain, r.domain, r.suffix
    except Exception:
        pass
    parts = host.split(".")
    if len(parts) < 2:
        return "", host, ""
    n = 3 if ".".join(parts[-2:]) in _MULTI_SUFFIX and len(parts) >= 3 else 2
    suffix = ".".join(parts[-(n - 1):])
    return ".".join(parts[:-n]), parts[-n], suffix


def parse_url(url: str) -> ParsedUrl:
    url = url.strip()
    if "://" not in url:
        url = "http://" + url
    try:
        parts = urlsplit(url)
        host = (parts.hostname or "").lower().rstrip(".")
        try:
            port = parts.port
        except ValueError:
            port = None
    except ValueError:
        return ParsedUrl()
    p = ParsedUrl(host=host, port=port, path=parts.path, query=parts.query, has_at="@" in parts.netloc)
    try:
        ipaddress.ip_address(host)
        p.is_ip, p.label, p.registered = True, host, host
        return p
    except ValueError:
        pass
    if host:
        p.subdomain, p.label, p.suffix = _split_host(host)
        p.registered = f"{p.label}.{p.suffix}" if p.suffix else p.label
    return p


def registered_domain(url: str) -> str:
    """Uzywane do grupowania przy podziale train/test."""
    return parse_url(url).registered or url


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in (s.count(ch) for ch in set(s)))


def extract(url: str) -> dict[str, float]:
    p = parse_url(url)
    full = url.strip()
    host, path_q = p.host, f"{p.path}?{p.query}".lower() if p.query else p.path.lower()
    subs = [s for s in p.subdomain.split(".") if s and s != "www"]
    digits_url = sum(c.isdigit() for c in full)

    feats = {
        "url_len": len(full),
        "host_len": len(host),
        "path_len": len(p.path),
        "query_len": len(p.query),
        "n_dots_host": host.count("."),
        "n_hyphens_host": host.count("-"),
        "n_digits_host": sum(c.isdigit() for c in host),
        "digit_ratio_url": digits_url / len(full) if full else 0.0,
        "n_subdomains": len(subs),
        "n_special_chars": sum(c in "@&=_~!$*" for c in p.path + p.query),
        "has_at": int(p.has_at),
        "host_is_ip": int(p.is_ip),
        "has_port": int(p.port not in (None, 80, 443)),
        "has_punycode": int("xn--" in host or any(ord(c) > 127 for c in host)),
        "entropy_host": _entropy(host),
        "entropy_path": _entropy(p.path),
        "n_kw_host": sum(k in host for k in KEYWORDS),
        "n_kw_path": sum(k in path_q for k in KEYWORDS),
        "is_shortener": int(p.registered in SHORTENERS),
        "suspicious_tld": int(p.suffix.rsplit(".", 1)[-1] in SUSPICIOUS_TLDS),
        "path_depth": len([s for s in p.path.split("/") if s]),
        "n_pct_encoded": len(re.findall(r"%[0-9a-fA-F]{2}", full)),
        "has_double_slash_path": int("//" in p.path),
    }
    if p.is_ip:  # adres IP z marka w sciezce nadal jest podejrzany
        feats.update(brand_signals("", "", "", p.path))
    elif p.label:
        feats.update(brand_signals(p.registered, p.subdomain, p.label, p.path))
    else:
        feats.update(brand_in_host_not_owned=0, brand_in_path_not_owned=0, brand_lookalike=0)
    return {k: float(feats[k]) for k in FEATURE_NAMES}
