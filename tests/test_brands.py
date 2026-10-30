from phish_detector.brands import brand_signals, levenshtein, normalize_homoglyphs
from phish_detector.features import extract


def test_levenshtein_and_homoglyphs():
    assert levenshtein("paypal", "paypa1") == 1
    assert normalize_homoglyphs("paypa1") == "paypal"
    assert normalize_homoglyphs("rnicrosoft") == "microsoft"


def test_official_domain_not_flagged():
    for url in ["https://www.paypal.com/signin", "https://accounts.google.com/login",
                "https://allegro.pl/konto", "https://olx.pl/"]:
        f = extract(url)
        assert f["brand_lookalike"] == 0.0, url
        assert f["brand_in_host_not_owned"] == 0.0, url


def test_typosquat_flagged():
    assert extract("http://paypa1.com/")["brand_lookalike"] == 1.0
    assert extract("http://rnicrosoft-support.com/")["brand_lookalike"] == 1.0


def test_brand_on_foreign_domain_flagged():
    assert extract("http://paypal-secure-login.xyz/")["brand_in_host_not_owned"] == 1.0
    assert extract("http://paypal.com.verify-now.top/")["brand_in_host_not_owned"] == 1.0
    assert extract("http://random-site.com/paypal/login")["brand_in_path_not_owned"] == 1.0
    assert extract("http://olx-pl.top/")["brand_in_host_not_owned"] == 1.0  # krotka marka jako token


def test_unrelated_domains_not_flagged():
    for url in ["http://pineapple.com/", "http://playground.org/", "http://singing.pl/"]:
        f = extract(url)
        assert f["brand_in_host_not_owned"] == 0.0, url
        assert f["brand_lookalike"] == 0.0, url


def test_brand_signals_direct():
    s = brand_signals("evil.xyz", "", "evil", "/allegro/konto")
    assert s["brand_in_path_not_owned"] == 1
