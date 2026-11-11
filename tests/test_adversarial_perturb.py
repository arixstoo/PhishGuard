"""Tests de la bibliothèque de perturbations (étape 3.6).

Critère de l'étape : chaque perturbation modifie l'échantillon sans le rendre vide. On
vérifie aussi qu'elle est déterministe et qu'elle garde le sens (une URL reste valide et
garde son domaine, un message se relit à l'identique une fois la perturbation retirée).
"""

import os
import re
import subprocess
import sys
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from phishguard.adversarial import perturb as P
from phishguard.urls.features import parse_url
from phishguard.urls.idn import skeleton

MESSAGES = (
    "URGENT: your account is suspended, confirm your password at http://verify.example/x",
    "Congratulations! You have won a free prize, call 09061234567 now to claim",
    "Votre colis est en attente, payez 2 EUR sur suivi-colis.example",
    "see you at the cinema tonight",
)
# Domaines inventés, mais sur de vrais suffixes publics : ``.example`` n'en est pas un, et
# le domaine enregistré y serait l'hôte entier.
URLS = (
    "http://paypal.com.secure-login.xyz/login.php",
    "https://account-verify-4471.com/webscr?cmd=login",
    "http://user@bank-update-77.top:8080/a/b/index.html?x=1#top",
    "secure-wallet-connect.net/connect",
    "https://phishguard-test.co.uk/",
)
ZW_RE = re.compile("[\u200b\u200c\u200d\u2060\ufeff]")


def unhomoglyph(text: str) -> str:
    reverse = {v: k for k, v in P.HOMOGLYPHS.items()}
    return "".join(reverse.get(c, c) for c in text)


# --------------------------------------------------------------------------- #
# Critère de l'étape : chaque perturbation modifie sans vider
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("name", sorted(P.PERTURBATIONS))
def test_every_registered_perturbation_changes_without_emptying(name):
    perturbation = P.PERTURBATIONS[name]
    samples = MESSAGES if perturbation.vector == "text" else URLS
    for sample in samples:
        out = perturbation(sample, seed=0)
        assert out.strip(), f"{name} a vidé {sample!r}"
        assert out != sample, f"{name} n'a pas modifié {sample!r}"


@pytest.mark.parametrize("name", sorted(P.PERTURBATIONS))
def test_every_registered_perturbation_is_deterministic(name):
    perturbation = P.PERTURBATIONS[name]
    samples = MESSAGES if perturbation.vector == "text" else URLS
    for sample in samples:
        assert perturbation(sample, seed=7) == perturbation(sample, seed=7)


def test_registry_covers_catalog_techniques():
    assert {p.technique for p in P.PERTURBATIONS.values()} == {
        "TXT-01", "TXT-02", "TXT-03", "TXT-04", "TXT-05",
        "URL-02", "URL-03", "URL-04", "URL-06", "URL-07",
    }  # fmt: skip
    assert all(p.description for p in P.PERTURBATIONS.values())
    assert [p.name for p in P.perturbations_for("url")] == [
        n for n, p in P.PERTURBATIONS.items() if p.vector == "url"
    ]


def test_registered_techniques_exist_in_catalog():
    catalog = (Path(__file__).resolve().parents[1] / "docs/evasion-catalog.md").read_text(
        encoding="utf-8"
    )
    for p in P.PERTURBATIONS.values():
        assert f"### {p.technique} —" in catalog
        assert f"`{p.name}`" in catalog, f"{p.name} absent du catalogue"


def test_sample_seed_is_stable_across_processes():
    code = "from phishguard.adversarial.perturb import sample_seed; print(sample_seed(3, 'abc'))"
    outputs = {
        subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
            check=True,
            env={**os.environ, "PYTHONHASHSEED": str(h)},
        ).stdout.strip()
        for h in (1, 2)
    }
    assert outputs == {str(P.sample_seed(3, "abc"))}


def test_seeds_differ_between_samples_and_seeds():
    assert P.sample_seed(0, "a") != P.sample_seed(0, "b")
    assert P.sample_seed(0, "a") != P.sample_seed(1, "a")


def test_apply_counts_unchanged_samples():
    applied = P.apply("homoglyphs", ["hello world", "12345", "zzz"], seed=0)
    assert applied.changed == [True, False, False]
    assert applied.n_changed == 1
    assert applied.samples[1:] == ["12345", "zzz"]
    with pytest.raises(ValueError, match="inconnue"):
        P.apply("nope", ["x"])


# --------------------------------------------------------------------------- #
# Texte
# --------------------------------------------------------------------------- #


def test_zero_width_inside_words_only_and_removable():
    text = "your account is blocked"
    out = P.insert_zero_width(text, every=3)
    assert ZW_RE.sub("", out) == text
    assert out.count(P.ZW) == 5  # you|r acc|oun|t blo|cke|d : jamais en fin de mot
    for word in out.split(" "):
        assert not word.endswith(P.ZW) and not word.startswith(P.ZW)
    assert P.insert_zero_width("ab cd", every=3) == "ab cd"  # mots trop courts
    with pytest.raises(ValueError):
        P.insert_zero_width(text, every=0)
    with pytest.raises(ValueError):
        P.insert_zero_width(text, char="x")


def test_homoglyphs_read_the_same():
    text = MESSAGES[0]
    out = P.swap_homoglyphs(text, rate=0.3, seed=1)
    assert out != text and len(out) == len(text)
    assert unhomoglyph(out) == text
    assert skeleton(out) == skeleton(text)  # même squelette visuel (étape 3.8)
    assert P.swap_homoglyphs(text, rate=1.0) == "".join(P.HOMOGLYPHS.get(c, c) for c in text)
    with pytest.raises(ValueError):
        P.swap_homoglyphs(text, rate=0)


def test_low_rate_still_changes_one_position():
    assert sum(a != b for a, b in zip(P.swap_homoglyphs("pop", 1e-9), "pop", strict=True)) == 1


def test_leetspeak_only_lowercase_letters():
    out = P.leetspeak("Verify your ACCOUNT", rate=1.0)
    assert out == "V3r1fy y0ur ACCOUNT"
    assert P.leetspeak("compte", rate=1.0) == "c0mp73"


def test_split_with_symbols_keeps_numbers_and_links():
    text = "call 0800123456 at http://x.example to claim your prize"
    out = P.split_with_symbols(text, ".", min_length=4, rate=1.0)
    assert out == "c.a.l.l 0800123456 at http://x.example to c.l.a.i.m y.o.u.r p.r.i.z.e"
    assert P.split_with_symbols("a bc def", min_length=4) == "a bc def"  # aucun mot assez long
    with pytest.raises(ValueError):
        P.split_with_symbols(text, "a")


def test_pad_benign_appends_words():
    out = P.pad_benign("win now", ["ok", "home"], n=5)
    assert out == "win now ok home ok home ok"
    assert out.startswith("win now ")
    with pytest.raises(ValueError):
        P.pad_benign("x", [" "], n=3)
    with pytest.raises(ValueError):
        P.pad_benign("x", n=0)


# --------------------------------------------------------------------------- #
# URL : toujours valide, même serveur
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("url", URLS)
@pytest.mark.parametrize("name", [p.name for p in P.perturbations_for("url")])
def test_url_perturbations_stay_valid(name, url):
    out = P.PERTURBATIONS[name](url, seed=3)
    parsed = parse_url(out)  # lève InvalidUrlError si l'URL n'est plus valide
    before = parse_url(url)
    assert parsed.scheme == before.scheme
    assert parsed.has_userinfo == before.has_userinfo
    assert parsed.port == before.port
    if name != "url_homoglyphs":  # l'homographe désigne un autre domaine, c'est voulu
        assert parsed.registered_domain == before.registered_domain


def test_add_subdomains_keeps_registered_domain_and_userinfo():
    url = "http://user@bank-update-77.com:8080/a?b=1"
    out = P.add_subdomains(url, n=2, labels=["fr", "help"], seed=0)
    parsed = parse_url(out)
    assert parsed.registered_domain == "bank-update-77.com"
    assert len(parsed.subdomains) == 2 and set(parsed.subdomains) <= {"fr", "help"}
    assert out.startswith("http://user@") and ":8080/a?b=1" in out
    assert P.add_subdomains("http://192.168.1.1/x") == "http://192.168.1.1/x"
    assert P.add_subdomains("http://[::1]/x") == "http://[::1]/x"
    # Hôte qui est lui-même un suffixe privé : un sous-domaine serait le site d'un autre.
    assert P.add_subdomains("https://github.io/x") == "https://github.io/x"


def test_add_benign_path_keeps_page_and_query():
    out = P.add_benign_path("https://a-site.com/login.php?x=1#f", depth=3, segments=["help"])
    assert out == "https://a-site.com/help/help/help/login.php?x=1#f"
    assert P.add_benign_path("a-site.com", depth=1, segments=["fr"]) == "a-site.com/fr/"


def test_add_long_param_appends_to_query():
    out = P.add_long_param("https://a-site.com/p?x=1", length=50, seed=0)
    parts = parse_url(out)
    assert parts.path == "/p"
    assert parts.query.startswith("x=1&")
    name, value = parts.query.split("&")[1].split("=")
    assert name in P.TRACKING_PARAMS and len(value) == 50 and value.isalnum()
    assert "?" in P.add_long_param("https://a-site.com/", length=5)


def test_partial_uppercase_only_touches_host():
    url = "https://login.bank-site.com/Path/page?q=abc"
    out = P.partial_uppercase(url, rate=1.0)
    assert out == "https://LOGIN.BANK-SITE.COM/Path/page?q=abc"
    assert parse_url(out).url == parse_url(url).url  # même URL normalisée
    assert P.partial_uppercase("http://10.0.0.1/a") == "http://10.0.0.1/a"


def test_swap_host_homoglyphs_builds_idn_lookalike():
    url = "https://paypal.com/signin"
    out = P.swap_host_homoglyphs(url, rate=1.0)
    host = parse_url(out).host_unicode
    assert host.endswith(".com") and host != "paypal.com"
    assert skeleton(host) == "paypal.com"
    assert parse_url(out).host.startswith("xn--")
    assert P.swap_host_homoglyphs("http://8.8.8.8/") == "http://8.8.8.8/"
    assert P.swap_host_homoglyphs("http://localhost/") == "http://localhost/"
    uk = parse_url(P.swap_host_homoglyphs("https://shop-site.co.uk/", rate=1.0)).host_unicode
    assert uk.endswith(".co.uk") and uk != "shop-site.co.uk"


# --------------------------------------------------------------------------- #
# Propriétés
# --------------------------------------------------------------------------- #

_words = st.text(alphabet=st.characters(categories=("Ll", "Lu", "Nd")), min_size=1, max_size=12)
_messages = st.lists(_words, min_size=1, max_size=12).map(" ".join)


@settings(max_examples=150, deadline=None)
@given(text=_messages, seed=st.integers(0, 2**31))
def test_text_perturbations_are_reversible_and_never_empty(text, seed):
    assert ZW_RE.sub("", P.insert_zero_width(text)) == text
    assert unhomoglyph(P.swap_homoglyphs(text, seed=seed)) == unhomoglyph(text)
    for name in ("zero_width", "homoglyphs", "leetspeak", "split_symbols", "pad_benign"):
        out = P.PERTURBATIONS[name](text, seed)
        assert out.strip()
        assert out == P.PERTURBATIONS[name](text, seed)


_labels = st.from_regex(r"[a-z][a-z0-9-]{0,10}[a-z0-9]", fullmatch=True)


@settings(max_examples=150, deadline=None)
@given(
    labels=st.lists(_labels, min_size=1, max_size=3),
    path=st.from_regex(r"(/[a-z0-9._-]{1,8}){0,3}", fullmatch=True),
    seed=st.integers(0, 2**31),
)
def test_url_perturbations_keep_urls_valid(labels, path, seed):
    url = f"https://{'.'.join(labels)}.com{path or '/'}"
    before = parse_url(url)
    host_is_suffix = before.registered_domain != f"{before.domain_label}.com"
    for p in P.perturbations_for("url"):
        out = p(url, seed)
        # Sans lettre remplaçable, ou sur un suffixe privé (x0.com), rien à perturber.
        assert out != url or p.name == "url_homoglyphs" or host_is_suffix
        after = parse_url(out)
        if p.name != "url_homoglyphs":
            assert after.registered_domain == before.registered_domain
