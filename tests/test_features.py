from phish_detector.features import FEATURE_NAMES, extract, parse_url, registered_domain


def test_all_features_present_and_numeric():
    f = extract("https://www.example.com/a/b?x=1")
    assert list(f) == FEATURE_NAMES
    assert all(isinstance(v, float) for v in f.values())


def test_ip_host():
    assert extract("http://192.168.1.10/login")["host_is_ip"] == 1.0
    assert extract("http://example.com/login")["host_is_ip"] == 0.0


def test_at_sign_trick():
    assert extract("http://google.com@evil.xyz/x")["has_at"] == 1.0
    assert parse_url("http://google.com@evil.xyz/x").host == "evil.xyz"


def test_subdomains_and_registered_domain():
    p = parse_url("https://a.b.c.example.com/x")
    assert p.registered == "example.com"
    assert extract("https://a.b.c.example.com/x")["n_subdomains"] == 3.0
    assert registered_domain("https://shop.example.com.pl/x") == "example.com.pl"


def test_punycode_and_tld():
    assert extract("http://xn--pypal-4ve.com/")["has_punycode"] == 1.0
    assert extract("http://something.xyz/")["suspicious_tld"] == 1.0
    assert extract("http://something.pl/")["suspicious_tld"] == 0.0


def test_keywords_and_shortener():
    f = extract("http://bit.ly/abc")
    assert f["is_shortener"] == 1.0
    assert extract("http://site.com/login/verify")["n_kw_path"] >= 2.0


def test_scheme_less_url_is_handled():
    assert parse_url("example.com/path").host == "example.com"


def test_garbage_does_not_crash():
    for bad in ["", "   ", "http://[::1", "://", "http://", "%%%", "a" * 5000]:
        f = extract(bad)
        assert list(f) == FEATURE_NAMES
