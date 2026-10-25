"""Tests de l'extracteur de features URL (étape 1.5)."""

import json
import math
import os
import socket
from pathlib import Path

import pandas as pd
import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from phishguard.data.urls import make_domain_extractor, registered_domain
from phishguard.urls import idn
from phishguard.urls.brands import (
    GENERIC_USE_CCTLDS,
    Brand,
    BrandIndex,
    brands_from_dict,
    load_brands,
    load_shorteners,
)
from phishguard.urls.features import (
    FAMILIES,
    FEATURE_NAMES,
    FEATURES,
    GROUPS,
    InvalidUrlError,
    UrlFeatureExtractor,
    entropy,
    feature_names,
    is_ip_host,
    url_features,
)
from phishguard.urls.tld import TldRiskTable, top_level_domain

GOLDEN = Path(__file__).parent / "fixtures" / "url_features_golden.json"
UPDATE_GOLDEN = os.environ.get("PHISHGUARD_UPDATE_GOLDEN") == "1"


def f(url: str) -> dict[str, float]:
    return url_features(url)


# --------------------------------------------------------------------------- #
# Contrat
# --------------------------------------------------------------------------- #


def test_every_feature_has_a_known_group_and_family():
    assert len(set(FEATURE_NAMES)) == len(FEATURE_NAMES)
    assert {spec.group for spec in FEATURES} == set(GROUPS)
    assert {spec.family for spec in FEATURES} == set(FAMILIES)
    assert all(spec.description for spec in FEATURES)


def test_feature_names_select_families_and_drop_groups():
    base = feature_names(["base"])
    assert "brand_in_host" not in base and "is_https" in base
    no_bias = feature_names(exclude_groups=["path", "length"])
    assert not {"path_depth", "path_len", "brand_in_path"} & set(no_bias)
    assert "host_n_hyphens" in no_bias
    with pytest.raises(ValueError, match="inconnus"):
        feature_names(exclude_groups=["chemin"])


def test_tld_family_requires_a_fitted_table():
    assert "tld_phish_rate" not in UrlFeatureExtractor().feature_names
    with pytest.raises(ValueError, match="tld_table"):
        UrlFeatureExtractor(families=["base", "tld"])


def test_extract_returns_floats_in_declared_order():
    values = f("https://example.com/")
    assert list(values) == list(UrlFeatureExtractor().feature_names)
    assert all(isinstance(v, float) for v in values.values())


def test_transform_matches_extract_and_keeps_index():
    urls = pd.Series(["https://a.example.com/x", "http://b.org/"], index=[10, 20])
    ex = UrlFeatureExtractor()
    frame = ex.transform(urls)
    assert list(frame.index) == [10, 20]
    assert list(frame.columns) == list(ex.feature_names)
    assert frame.loc[20].to_dict() == ex.extract("http://b.org/")
    assert (frame.dtypes == "float64").all()


def test_extraction_never_uses_the_network(monkeypatch):
    def refuse(*args, **kwargs):
        raise AssertionError("accès réseau interdit")

    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket, "getaddrinfo", refuse)
    ex = UrlFeatureExtractor(domain_extractor=make_domain_extractor())
    assert ex.extract("https://login.paypal.com.evil.co.uk/a")["brand_in_host"] == 1.0


# --------------------------------------------------------------------------- #
# Schéma, hôte, identifiants, port
# --------------------------------------------------------------------------- #


def test_scheme():
    assert f("https://example.com/")["is_https"] == 1.0
    assert f("http://example.com/")["is_https"] == 0.0


def test_url_without_scheme_is_read_as_http():
    assert f("example.com/login") == f("http://example.com/login")


def test_uppercase_host_and_scheme_are_normalized():
    assert f("HTTPS://WWW.Example.COM/Path") == f("https://www.example.com/Path")


@pytest.mark.parametrize(
    "url",
    [
        "http://192.168.0.1/admin",
        "http://[::1]:8080/x",
        "http://[2001:db8::1]/",
        "http://3232235777/",  # 192.168.1.1 en décimal
        "http://0x7f000001/",  # 127.0.0.1 en hexadécimal
        "http://10.0.0.1./",
    ],
)
def test_ip_hosts(url):
    values = f(url)
    assert values["host_is_ip"] == 1.0
    assert values["host_n_subdomains"] == 0.0
    assert values["brand_in_host"] == 0.0


@pytest.mark.parametrize("host", ["example.com", "1password.com", "123.example", "0xbad.com"])
def test_domain_names_are_not_ip(host):
    assert not is_ip_host(host)


def test_ipv6_with_port():
    values = f("http://[::1]:8080/x")
    assert values["has_port"] == 1.0
    assert values["host_len"] == 3.0  # « ::1 », sans crochets


def test_default_port_is_not_reported():
    assert f("https://example.com:443/")["has_port"] == 0.0
    assert f("http://example.com:80/")["has_port"] == 0.0
    assert f("https://example.com:8443/")["has_port"] == 1.0


def test_userinfo_trick_reads_the_real_host():
    values = f("http://a@b.com")
    assert values["has_userinfo"] == 1.0
    assert values["host_len"] == 5.0  # « b.com »
    tricked = f("https://paypal.com@evil.example/")
    assert tricked["has_userinfo"] == 1.0
    assert tricked["host_len"] == len("evil.example")


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://example.com/", 0),
        ("https://www.example.com/", 0),  # www ne compte pas
        ("https://mail.example.com/", 1),
        ("https://www.a.b.example.co.uk/", 2),
        ("https://alice.github.io/", 0),  # suffixe privé : alice.github.io est le domaine
        ("https://x.alice.github.io/", 1),
    ],
)
def test_subdomain_count(url, expected):
    assert f(url)["host_n_subdomains"] == expected


def test_host_counts():
    values = f("http://secure-login-2fa.example-1.com/")
    assert values["host_n_hyphens"] == 3.0
    assert values["host_n_digits"] == 2.0
    assert values["host_kw_hits"] == 2.0  # secure, login


def test_entropy():
    assert entropy("") == 0.0
    assert entropy("aaaa") == 0.0
    assert math.copysign(1.0, entropy("a")) == 1.0  # pas de -0.0
    assert entropy("ab") == pytest.approx(1.0)
    assert entropy("abcd") == pytest.approx(2.0)


# --------------------------------------------------------------------------- #
# Chemin, requête, longueurs
# --------------------------------------------------------------------------- #


def test_path_and_query_structure():
    values = f("https://example.com/a//b/?x=1&&y=2&")
    assert values["path_depth"] == 2.0
    assert values["query_n_params"] == 2.0
    assert values["path_n_digits"] == 2.0


def test_keywords_are_found_in_percent_encoded_paths_and_counted_once():
    values = f("https://example.com/%6Cogin/login/verify")
    assert values["path_kw_hits"] == 2.0  # login (une fois), verify
    assert values["host_kw_hits"] == 0.0


def test_french_keywords():
    assert f("https://example.fr/connexion-compte")["path_kw_hits"] == 2.0


def test_embedded_url_in_encoded_query():
    assert f("https://example.com/r?u=https%3A%2F%2Fevil.com")["path_has_embedded_url"] == 1.0
    assert f("https://example.com/www.evil.com/")["path_has_embedded_url"] == 1.0
    assert f("https://example.com/shop?id=12")["path_has_embedded_url"] == 0.0


def test_lengths_are_measured_per_component():
    values = f("https://example.com/abc?q=1#fragment-ignored")
    assert values["host_len"] == 11.0
    assert values["path_len"] == 4.0
    assert values["query_len"] == 3.0


def test_very_long_url():
    path = "/" + "a" * 10_000
    values = f(f"https://example.com{path}?{'k=v&' * 500}")
    assert values["path_len"] == len(path)
    assert values["query_n_params"] == 500.0


@pytest.mark.parametrize(
    "url",
    ["", "   ", "javascript:alert(1)", "ftp://example.com/", "http://exa mple.com/", "http://"],
)
def test_invalid_urls_raise(url):
    with pytest.raises(InvalidUrlError):
        f(url)


# --------------------------------------------------------------------------- #
# Marques et typosquatting
# --------------------------------------------------------------------------- #


def test_official_domain_is_not_an_impersonation():
    values = f("https://www.paypal.com/signin")
    assert values["brand_in_host"] == 0.0
    assert values["is_typosquat"] == 0.0
    assert values["brand_min_distance"] == 3.0


@pytest.mark.parametrize(
    "url",
    [
        "http://paypal.com.evil.ru/",
        "https://secure-paypal-login.example.com/",
        "https://paypal-login.github.io/",  # hébergement gratuit : le domaine est l'utilisateur
        "https://login.microsoftonline.com.evil.ru/",
        "https://credit-agricole-securite.com/",  # tirets ignorés
        "https://paypal.xyz/",  # le nom exact sur un autre TLD
    ],
)
def test_brand_outside_its_official_domain(url):
    assert f(url)["brand_in_host"] == 1.0


def test_strict_brand_must_be_a_whole_word():
    assert f("https://groups.example.com/")["brand_in_host"] == 0.0  # « ups » dans un mot
    assert f("https://ups-suivi.com/")["brand_in_host"] == 1.0


def test_brand_owning_country_domains():
    assert f("https://maps.google.co.th/")["brand_in_host"] == 0.0
    assert f("https://www.amazon.com.mx/")["brand_in_host"] == 0.0
    # .co se vend comme une extension générique : pas présumé officiel.
    assert "co" in GENERIC_USE_CCTLDS
    assert f("https://google.co/")["brand_in_host"] == 1.0


@pytest.mark.parametrize(
    ("url", "distance"),
    [("http://paypa1.com/", 1), ("http://amazom.com/", 1), ("http://secure-paypa1-login.com/", 1)],
)
def test_typosquatting(url, distance):
    values = f(url)
    assert values["brand_min_distance"] == distance
    assert values["is_typosquat"] == 1.0


def test_exact_brand_name_is_not_a_typo():
    values = f("https://paypal.xyz/")
    assert values["brand_min_distance"] == 0.0
    assert values["is_typosquat"] == 0.0


def test_word_contained_in_a_brand_name_is_not_a_typo():
    # « cloud » est à une lettre d'« icloud », « mobile » de « tmobile » : ce sont des mots.
    assert f("https://cloud.com/")["is_typosquat"] == 0.0
    assert f("https://mobile.de/")["is_typosquat"] == 0.0


def test_brand_in_path():
    assert f("https://sites.google.com/view/paypal-login")["brand_in_path"] == 1.0
    assert f("https://example.com/?next=%2Fnetflix%2Fbilling")["brand_in_path"] == 1.0
    assert f("https://www.paypal.com/paypal/help")["brand_in_path"] == 0.0


# --------------------------------------------------------------------------- #
# Homographes et noms internationalisés
# --------------------------------------------------------------------------- #

CYRILLIC_APPLE = "аpple.com"  # « а » cyrillique


def test_unicode_and_punycode_hosts_give_the_same_features():
    assert idn.to_ascii(CYRILLIC_APPLE) == "xn--pple-43d.com"
    assert f(f"http://{CYRILLIC_APPLE}/") == f("http://xn--pple-43d.com/")


def test_homograph_attack():
    values = f("http://xn--pple-43d.com/")
    assert values["host_is_idn"] == 1.0
    assert values["host_mixed_script"] == 1.0
    assert values["homograph_brand"] == 1.0
    # Les caractères sont comptés sur la forme lue : « xn-- » n'ajoute ni tiret ni chiffre.
    assert values["host_n_hyphens"] == 0.0
    assert values["host_n_digits"] == 0.0
    assert values["host_len"] == len(CYRILLIC_APPLE)


def test_whole_script_idn_is_not_mixed():
    values = f("https://пример.рф/")
    assert values["host_is_idn"] == 1.0
    assert values["host_mixed_script"] == 0.0
    assert values["homograph_brand"] == 0.0


def test_scripts_allowed_together():
    assert not idn.is_mixed_script("東京tokyo.jp")  # han + latin, admis par UTS #39
    assert not idn.is_mixed_script("例えば.jp")  # han + hiragana
    assert idn.is_mixed_script("pаypal.com")  # latin + cyrillique
    assert idn.is_mixed_script("αpple.com")  # latin + grec


def test_skeleton():
    assert idn.skeleton("раураl") == "paypal"  # tout cyrillique sauf « l »
    assert idn.skeleton("PàyPal") == "paypal"
    assert idn.skeleton("ｐａｙｐａｌ") == "paypal"  # pleine chasse


def test_accented_lookalike_of_a_brand():
    assert f("http://pàypal.com/")["homograph_brand"] == 1.0


@pytest.mark.parametrize("label", ["xn--", "xn--99999999999", "xn--a-é", "xn--zz"])
def test_broken_punycode_never_raises(label):
    assert isinstance(idn.label_to_unicode(label), str)
    assert f(f"http://{label}.com/")["host_len"] > 0


# --------------------------------------------------------------------------- #
# Raccourcisseurs
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("url", "expected"),
    [("https://bit.ly/3xYz", 1.0), ("https://www.bit.ly/x", 1.0), ("https://bitlyfan.com/", 0.0)],
)
def test_shorteners(url, expected):
    assert f(url)["is_shortener"] == expected


# --------------------------------------------------------------------------- #
# TLD
# --------------------------------------------------------------------------- #


def test_top_level_domain():
    assert top_level_domain("a.example.co.uk") == "uk"
    assert top_level_domain("example.com.") == "com"
    assert top_level_domain("192.168.0.1") == ""
    assert top_level_domain("::1") == ""


def test_tld_table_is_smoothed_towards_the_prior():
    table = TldRiskTable.fit(["com"] * 8 + ["xyz"] * 2, [0] * 7 + [1] + [1, 1], smoothing=10)
    assert table.prior == pytest.approx(0.3)
    assert table.rate("xyz") == pytest.approx((2 + 10 * 0.3) / (2 + 10))
    assert table.rate("com") == pytest.approx((1 + 10 * 0.3) / (8 + 10))
    assert table.rate("jamais-vu") == table.prior
    assert TldRiskTable.from_dict(json.loads(json.dumps(table.to_dict()))).rate(
        "xyz"
    ) == pytest.approx(table.rate("xyz"), abs=1e-6)


def test_tld_table_rejects_bad_input():
    with pytest.raises(ValueError):
        TldRiskTable.fit([], [])
    with pytest.raises(ValueError):
        TldRiskTable.fit(["com"], [2])
    with pytest.raises(ValueError):
        TldRiskTable.fit(["com", "fr"], [1])


def test_tld_feature_uses_the_table():
    table = TldRiskTable.fit(["com", "xyz", "xyz"], [0, 1, 1], smoothing=1)
    ex = UrlFeatureExtractor(tld_table=table)
    assert ex.feature_names[-2:] == ("tld_phish_rate", "is_shortener")
    assert ex.extract("https://a.xyz/")["tld_phish_rate"] == pytest.approx(table.rate("xyz"))
    assert ex.extract("http://10.0.0.1/")["tld_phish_rate"] == pytest.approx(table.prior)


# --------------------------------------------------------------------------- #
# Listes embarquées
# --------------------------------------------------------------------------- #


def test_embedded_brand_list():
    brands = load_brands()
    assert 100 <= len(brands) <= 200
    extractor = make_domain_extractor()
    for brand in brands.brands:
        for domain in brand.domains:
            # Sinon la marque ne serait jamais reconnue comme officielle sur ce domaine.
            assert registered_domain(domain, extractor) == domain, (brand.name, domain)


def test_embedded_shortener_list():
    extractor = make_domain_extractor()
    shorteners = load_shorteners()
    assert "bit.ly" in shorteners
    assert all(registered_domain(d, extractor) == d for d in shorteners)


def test_brand_index_validation():
    with pytest.raises(ValueError, match="double"):
        BrandIndex([Brand("paypal", frozenset({"paypal.com"}), False)] * 2)
    with pytest.raises(ValueError, match="invalide"):
        Brand("pay-pal", frozenset({"paypal.com"}), False)
    with pytest.raises(ValueError, match="strict"):
        Brand("ups", frozenset({"ups.com"}), strict=False)
    with pytest.raises(ValueError, match="officiel"):
        Brand("paypal", frozenset({"PayPal.com"}), False)
    index = brands_from_dict({"brands": [{"name": "ups", "domains": ["ups.com"]}]})
    assert index.brands[0].strict  # nom court : strict par défaut


# --------------------------------------------------------------------------- #
# Propriétés et valeurs de référence
# --------------------------------------------------------------------------- #

url_text = st.one_of(
    st.text(max_size=80),
    st.builds(
        lambda scheme, host, path: f"{scheme}{host}{path}",
        st.sampled_from(["", "http://", "https://", "HTTP://", "ftp://"]),
        st.text(alphabet=st.characters(blacklist_categories=("Cs",)), min_size=1, max_size=30),
        st.text(max_size=40).map(lambda p: "/" + p),
    ),
)


@settings(max_examples=300, deadline=None)
@given(url_text)
def test_any_input_gives_finite_features_or_a_clean_error(text):
    try:
        values = f(text)
    except InvalidUrlError:
        return
    assert set(values) == set(UrlFeatureExtractor().feature_names)
    assert all(math.isfinite(v) and v >= 0 for v in values.values())


GOLDEN_URLS = [
    "https://www.paypal.com/signin",
    "http://paypa1-secure.com/login",
    "http://xn--pple-43d.com/",
    "https://пример.рф/",
    "http://192.168.0.1/admin",
    "http://[::1]:8080/x",
    "http://0x7f000001/",
    "example.com",
    "http://a@b.com",
    "https://bit.ly/3xYz",
    "https://sites.google.com/view/paypal-login?next=https%3A%2F%2Fevil.com",
    "https://maps.google.co.th/maps?q=1",
    "https://login.microsoftonline.com.secure-verify.ru:8443/common/oauth2",
    "https://ups-suivi.com/colis/123456",
    "https://alice.github.io/",
    "HTTPS://WWW.Example.COM/%6Cogin",
]


def test_golden_values_for_the_typescript_port():
    """Valeurs de référence : l'extension (module 5) devra produire exactement les mêmes.

    Pour régénérer après un changement voulu : ``PHISHGUARD_UPDATE_GOLDEN=1 pytest``.
    """
    actual = {
        url: {k: round(v, 6) for k, v in UrlFeatureExtractor().extract(url).items()}
        for url in GOLDEN_URLS
    }
    if UPDATE_GOLDEN:
        GOLDEN.parent.mkdir(parents=True, exist_ok=True)
        GOLDEN.write_text(json.dumps(actual, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    expected = json.loads(GOLDEN.read_text(encoding="utf-8"))
    assert actual == expected
