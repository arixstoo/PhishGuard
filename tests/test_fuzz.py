"""Fuzzing par propriétés (étape 4.7) : les parseurs sont la cible classique des attaquants.

Propriété commune : **ne lève jamais d'exception inattendue et renvoie une sortie
bornée**. « Inattendue » : toute exception autre que l'erreur documentée de la fonction
(``InvalidUrlError``, ``EmailTooLargeError``) ; pour ``parse_eml``, qui rattrape les
défaillances de ses étapes et les note dans ``defects`` (``body_failed:…``), une étape
défaillante compte aussi comme un échec.

Les entrées ne sont pas seulement aléatoires : les stratégies fabriquent des URLs et des
emails MIME *presque* valides (encodages RFC 2047 inconnus, délimiteurs manquants,
base64 tronqué, ports hors bornes, IPv4 en hexadécimal, IDN…), là où se cachent les
bogues.

Nombre d'exemples : celui du profil ``hypothesis`` (100 par défaut, 1 000 avec
``make fuzz``, soit ``--hypothesis-profile=fuzz``, profils enregistrés dans
``conftest.py``). Un bogue trouvé devient un exemple fixe (``@example``) : il est rejoué
à chaque exécution, quel que soit le profil.
"""

from __future__ import annotations

import base64
import json
import math
import unicodedata
from pathlib import Path

import pytest
from api_support import EMAILS, settings_for
from fastapi.testclient import TestClient
from hypothesis import HealthCheck, example, given, settings
from hypothesis import strategies as st

from phishguard.api.main import create_app
from phishguard.email.parser import EmailLimits, EmailTooLargeError, parse_eml
from phishguard.schema import AnalysisResponse
from phishguard.security import normalize as N
from phishguard.urls.features import InvalidUrlError, UrlFeatureExtractor, parse_url, url_features

pytestmark = pytest.mark.fuzz

FUZZ = settings(
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large],
)
# NFKC peut multiplier une longueur par 18 au plus (U+FDFA) : borne de toute sortie.
NFKC_MAX_EXPANSION = 18
FEATURE_NAMES = frozenset(UrlFeatureExtractor().feature_names)
LONE_SURROGATES = st.characters(categories=["Cs"])


# --------------------------------------------------------------------------- #
# URLs
# --------------------------------------------------------------------------- #

_ascii_label = st.from_regex(r"[a-zA-Z0-9-]{1,24}", fullmatch=True)
_unicode_label = st.text(
    alphabet=st.characters(categories=["Ll", "Lu", "Lo", "Nd", "Mn", "Cf"]),
    min_size=1,
    max_size=12,
)
_hosts = st.one_of(
    st.lists(st.one_of(_ascii_label, _unicode_label), min_size=1, max_size=6).map(".".join),
    st.ip_addresses(v=4).map(str),
    st.ip_addresses(v=6).map(lambda ip: f"[{ip}]"),
    st.integers(0, 2**40).map(str),  # IPv4 décimale (WHATWG)
    st.integers(0, 2**40).map(hex),  # IPv4 hexadécimale
    st.sampled_from(
        ["", ".", "..", "xn--", "xn--zz", "xn--pple-43d.com", "a..b", "-a-.com", "localhost",
         "[::1", "[]", "%31%32%37.0.0.1", "0177.0.0.1", "exa mple.com", "a" * 300]
    ),
    st.text(max_size=30),
)  # fmt: skip
_ports = st.one_of(
    st.just(""),
    st.integers(-1, 100_000).map(lambda p: f":{p}"),
    st.sampled_from([":", "::", ":0x50", ":８０"]),
)
_segments = st.one_of(
    st.text(max_size=20),
    st.from_regex(r"(%[0-9A-Fa-f]{2}){1,6}", fullmatch=True),
    st.sampled_from(["..", ".", "%", "%zz", "%00", "%2e%2e", "https:", "www.", "@"]),
)
_paths = st.lists(_segments, max_size=8).map(lambda parts: "/" + "/".join(parts))
_queries = st.one_of(
    st.just(""),
    st.lists(st.tuples(st.text(max_size=10), st.text(max_size=12)), max_size=12).map(
        lambda pairs: "?" + "&".join(f"{k}={v}" for k, v in pairs)
    ),
)
_urls = st.builds(
    lambda scheme, userinfo, host, port, path, query, fragment: (
        f"{scheme}{userinfo}{host}{port}{path}{query}{fragment}"
    ),
    st.sampled_from(
        ["http://", "https://", "HTTP://", "hTtPs://", "ftp://", "javascript:", "file:///",
         "//", "", "http:/", "https:\\\\", "hxxp://", "http://http://", " https://"]
    ),
    st.one_of(st.just(""), st.sampled_from(["@", "a@", "a:b@", "a@b@", ":@"]),
              st.text(max_size=12).map(lambda u: u + "@")),
    _hosts,
    _ports,
    _paths,
    _queries,
    st.one_of(st.just(""), st.text(max_size=12).map(lambda f: "#" + f)),
)  # fmt: skip
_long_urls = st.builds(
    lambda head, chunk, n: head + chunk * n,
    st.sampled_from(["https://a.example/", "http://", "https://"]),
    st.text(min_size=1, max_size=4),
    st.integers(0, 600),
)
URL_INPUTS = st.one_of(_urls, _long_urls, st.text(max_size=200))


def _bound(text: str) -> float:
    return NFKC_MAX_EXPANSION * len(text) + 64


@FUZZ
@given(URL_INPUTS)
@example("http://\u00ad.com/")  # hôte vide après retrait des invisibles
@example("http://[::ffff:127.0.0.1]:99999/")
@example("http://xn--/")
def test_url_features_are_finite_and_bounded(url):
    try:
        values = url_features(url)
    except InvalidUrlError:
        return
    assert set(values) == FEATURE_NAMES
    bound = _bound(url)
    for name, value in values.items():
        assert isinstance(value, float | int), name
        assert math.isfinite(value) and 0 <= value <= bound, (name, value)


@FUZZ
@given(URL_INPUTS)
@example("http://" + "00\u0186\U000271cd" * 60)  # hôte Punycode de plus de 253 octets
def test_parse_url_gives_an_ascii_host_or_a_clean_error(url):
    try:
        parsed = parse_url(url)
    except InvalidUrlError:
        return
    assert parsed.host and parsed.host.isascii()
    assert parsed.host == parsed.host.lower()
    # Pas de borne DNS (253 octets, labels de 63) : comme le standard WHATWG que suivent
    # les navigateurs, le parseur ne les vérifie pas, et une URL ainsi formée s'ouvre.
    assert len(parsed.host) <= _bound(url)
    assert len(parsed.path) <= _bound(url)


@FUZZ
@given(st.text(alphabet=LONE_SURROGATES | st.characters(), min_size=1, max_size=40))
def test_url_parsing_survives_lone_surrogates(fragment):
    """L'API les refuse dès le schéma (étape 4.2), mais la bibliothèque reste sûre."""
    for url in (fragment, f"https://{fragment}.example/", f"https://a.example/{fragment}"):
        try:
            url_features(url)
        except InvalidUrlError:
            pass


# --------------------------------------------------------------------------- #
# Normalisation
# --------------------------------------------------------------------------- #

ANY_TEXT = st.text(alphabet=st.characters(), max_size=200)  # toutes catégories, sauf Cs
KEPT_CONTROLS = {"\t", "\n", "\r"}


def _assert_clean(text: str) -> None:
    for c in text:
        category = unicodedata.category(c)
        assert category != "Cf", repr(c)
        assert category != "Cc" or c in KEPT_CONTROLS, repr(c)


@FUZZ
@given(ANY_TEXT)
@example("e\u200b\u0301")  # un invisible séparait la lettre de son accent
@example("\ufdfa")  # expansion NFKC maximale
def test_text_normalization_is_idempotent_clean_and_bounded(text):
    result = N.normalize_text(text)
    _assert_clean(result.text)
    assert len(result.text) <= NFKC_MAX_EXPANSION * len(text)
    assert N.normalize_text(result.text).text == result.text
    report = result.report
    assert 0 <= report.format_chars + report.control_chars <= NFKC_MAX_EXPANSION * len(text)
    assert report.confusables >= 0
    assert report.changed == (result.text != text or report.nfkc)


@FUZZ
@given(ANY_TEXT)
def test_url_text_normalization_never_folds_and_is_clean(text):
    result = N.normalize_url_text(text)
    _assert_clean(result.text)
    assert result.report.confusables == 0
    assert len(result.text) <= NFKC_MAX_EXPANSION * len(text)
    assert N.normalize_url_text(result.text).text == result.text


@FUZZ
@given(st.one_of(ANY_TEXT, _hosts))
def test_host_script_alert_never_raises(host):
    assert N.host_script_alert(host) in {None, "mixed_script_label", "lookalike_label"}


# --------------------------------------------------------------------------- #
# Emails : MIME presque valide
# --------------------------------------------------------------------------- #

_charsets = st.sampled_from(
    ["utf-8", "UTF-8", "iso-8859-1", "windows-1252", "utf-7", "gb2312", "x-unknown", "", "utf-16"]
)
_words = st.text(alphabet=st.characters(codec="utf-8"), max_size=24)
_encoded_word = st.builds(
    lambda charset, kind, payload: f"=?{charset}?{kind}?{payload}?=",
    _charsets,
    st.sampled_from(["B", "Q", "b", "q", "X"]),
    st.one_of(
        st.binary(max_size=24).map(lambda b: base64.b64encode(b).decode()),
        st.text(alphabet="=ABCDEFabcdef0123456789_?", max_size=24),
    ),
)
_domains = st.one_of(
    st.lists(_ascii_label, min_size=1, max_size=4).map(".".join),
    st.sampled_from(["paypal.com", "pаypal.com", "xn--pypal-4ve.com", "[192.0.2.1]", ""]),
)
_addresses = st.one_of(
    st.builds(
        lambda name, local, domain: f'"{name}" <{local}@{domain}>',
        st.one_of(_words, _encoded_word),
        st.from_regex(r"[a-z0-9.+_-]{0,12}", fullmatch=True),
        _domains,
    ),
    st.builds(lambda local, domain: f"{local}@{domain}", _ascii_label, _domains),
    st.sampled_from(["<>", "<<<@@@>>>", "undisclosed-recipients:;", "a@b, c@d", '"" <@>']),
    _words,
)
_auth_results = st.builds(
    lambda authserv, spf, dkim, dmarc: (
        f"{authserv}; spf={spf} smtp.mailfrom=a.example; dkim={dkim} header.d=a.example; "
        f"dmarc={dmarc}"
    ),
    st.one_of(_ascii_label, _words),
    *[st.sampled_from(["pass", "fail", "softfail", "none", "neutral", "", "PASS (x)"])] * 3,
)
_header_values = {
    "From": _addresses,
    "Reply-To": _addresses,
    "Return-Path": _addresses,
    "To": _addresses,
    "Subject": st.one_of(_words, _encoded_word, st.lists(_encoded_word, max_size=4).map(" ".join)),
    "Date": st.one_of(_words, st.just("Thu, 12 Nov 2026 10:00:00 +0000"), st.just("31 Feb 99")),
    "Message-ID": st.one_of(_words, st.just("<a@b>")),
    "Authentication-Results": _auth_results,
    "List-Id": _words,
    "MIME-Version": st.sampled_from(["1.0", "2.0", ""]),
}
_headers = st.lists(
    st.one_of(
        st.sampled_from(sorted(_header_values)).flatmap(
            lambda name: _header_values[name].map(lambda value: (name, value))
        ),
        st.tuples(_ascii_label, _words),
    ),
    max_size=10,
)

_html = st.builds(
    lambda shown, href, hidden, form: (
        f'<html><body><a href="{href}">{shown}</a>'
        f'<div style="{hidden}">caché</div>{form}</body></html>'
    ),
    st.one_of(_urls, _words),
    st.one_of(_urls, _words),
    st.sampled_from(["display:none", "font-size:0", "color:#fff;background:#fff", "", "x"]),
    st.sampled_from(["", '<form action="http://a.example/x"><input type=password></form>',
                     "<form>", "<script>alert(1)</script>", "<a href=", "<!--", "<![CDATA["]),
)  # fmt: skip
_leaf_types = st.sampled_from(
    ["text/plain", "text/html", "application/pdf", "application/octet-stream",
     "application/zip", "application/msword", "image/png", "message/rfc822", "x/y", ""]
)  # fmt: skip
_encodings = st.sampled_from(["7bit", "8bit", "base64", "quoted-printable", "binary", "x-uue", ""])
_filenames = st.one_of(
    st.just(None),
    st.sampled_from(["facture.pdf", "facture.pdf.exe", "facture\u202efdp.exe", "a.html",
                     "doc.docm", "x.zip", "=?utf-8?B?ZmFjdHVyZS5leGU=?=", "", "../../etc/passwd"]),
    _words,
)  # fmt: skip
_payloads = st.one_of(
    _words,
    _html,
    st.binary(max_size=200).map(lambda b: base64.b64encode(b).decode()),
    st.binary(max_size=200).map(lambda b: base64.b64encode(b).decode()[:-3]),  # tronqué
    st.binary(max_size=200).map(lambda b: b.decode("latin-1")),
    st.sampled_from(["=", "=3D=\r\n=ZZ", "begin 644 x\n`\nend"]),
)


def _leaf(content_type: str, charset: str, encoding: str, filename: str | None, body: str) -> str:
    lines = [f'Content-Type: {content_type}; charset="{charset}"']
    if encoding:
        lines.append(f"Content-Transfer-Encoding: {encoding}")
    if filename is not None:
        lines.append(f'Content-Disposition: attachment; filename="{filename}"')
    return "\r\n".join(lines) + "\r\n\r\n" + body


def _multipart(subtype: str, boundary: str, parts: list[str], closed: bool) -> str:
    body = "".join(f"--{boundary}\r\n{part}\r\n" for part in parts)
    end = f"--{boundary}--\r\n" if closed else ""
    return (
        f'Content-Type: multipart/{subtype}; boundary="{boundary}"\r\n\r\npréambule\r\n{body}{end}'
    )


_mime = st.recursive(
    st.builds(_leaf, _leaf_types, _charsets, _encodings, _filenames, _payloads),
    lambda children: st.builds(
        _multipart,
        st.sampled_from(["mixed", "alternative", "related", "x-unknown", "digest"]),
        st.one_of(st.from_regex(r"[A-Za-z0-9'()+_,./:=?-]{1,40}", fullmatch=True), st.just("")),
        st.lists(children, max_size=4),
        st.booleans(),
    ),
    max_leaves=8,
)


def _email(headers: list[tuple[str, str]], mime: str, newline: str) -> bytes:
    head = "".join(f"{name}: {value}\r\n" for name, value in headers)
    text = (head + mime).replace("\r\n", newline)
    return text.encode("utf-8", "surrogateescape")


EMAILS_STRATEGY = st.builds(_email, _headers, _mime, st.sampled_from(["\r\n", "\n", "\r"]))
LIMITS = EmailLimits()


def _assert_bounded(result, limits: EmailLimits = LIMITS) -> None:
    failed = [d for d in result.defects if "_failed:" in d]
    assert not failed, failed  # une étape a levé une exception inattendue
    assert len(result.links) <= limits.max_links
    assert len(result.attachments) <= limits.max_attachments
    assert len(result.text) <= limits.max_text_chars
    assert result.parts <= limits.max_parts
    json.dumps(result.to_dict())  # sérialisable tel quel (CLI, API)


@FUZZ
@given(EMAILS_STRATEGY)
def test_parse_eml_survives_structured_mime(raw):
    _assert_bounded(parse_eml(raw))


@FUZZ
@given(st.binary(max_size=4000))
def test_parse_eml_survives_random_bytes(raw):
    _assert_bounded(parse_eml(raw))


FIXTURE_EMAILS = sorted(EMAILS.glob("*.eml"))


@FUZZ
@given(
    st.sampled_from(FIXTURE_EMAILS),
    st.lists(st.tuples(st.integers(0, 10**6), st.binary(min_size=1, max_size=32)), max_size=5),
)
def test_parse_eml_survives_corrupted_real_emails(path: Path, edits):
    raw = bytearray(path.read_bytes())
    for position, garbage in edits:
        position %= len(raw)
        raw[position : position + len(garbage)] = garbage
    _assert_bounded(parse_eml(bytes(raw)))


@FUZZ
@given(EMAILS_STRATEGY, st.integers(1, 6))
def test_parse_eml_honours_tight_limits(raw, n):
    limits = EmailLimits(
        max_bytes=10_000, max_parts=n, max_links=n, max_attachments=n, max_text_chars=50 * n
    )
    try:
        result = parse_eml(raw, limits)
    except EmailTooLargeError:
        assert len(raw) > limits.max_bytes
        return
    _assert_bounded(result, limits)


# --------------------------------------------------------------------------- #
# API : jamais de 500
# --------------------------------------------------------------------------- #

ERROR_CODES = {
    "bad_request",
    "invalid_input",
    "payload_too_large",
    "unsupported_media_type",
    "validation_error",
}


@pytest.fixture(scope="module")
def fuzz_client(api_models_dir, tmp_path_factory):
    settings = settings_for(
        api_models_dir, tmp_path_factory.mktemp("fuzz"), rate_limit_enabled=False
    )
    with TestClient(create_app(settings)) as client:
        yield client


def post_json(client, route: str, body: object):
    """Corps JSON encodé ici : ``ensure_ascii`` transmet les demi-codets isolés en
    ``\\ud800`` (JSON valide), là où httpx échouerait avant l'envoi ; ``null`` est un
    corps comme un autre."""
    return client.post(
        route, content=json.dumps(body).encode(), headers={"Content-Type": "application/json"}
    )


def _assert_contract(response, allowed: set[int]) -> None:
    assert response.status_code in allowed, (response.status_code, response.text[:300])
    body = response.json()
    if response.status_code == 200:
        AnalysisResponse.model_validate(body)
    elif response.status_code != 202:
        assert set(body) == {"error"} and body["error"]["code"] in ERROR_CODES, body


_json = st.recursive(
    st.none() | st.booleans() | st.integers() | st.floats(allow_nan=False) | st.text(max_size=40),
    lambda children: (
        st.lists(children, max_size=4) | st.dictionaries(st.text(max_size=12), children, max_size=4)
    ),
    max_leaves=12,
)
_request_fields = st.fixed_dictionaries(
    {},
    optional={
        "url": URL_INPUTS | _json,
        "text": ANY_TEXT | _json,
        "language": st.sampled_from(["fr", "en", "ar", "de", ""]) | _json,
        "analyst": st.booleans() | _json,
        "use_threat_intel": st.booleans() | _json,
        "channel": st.sampled_from(["sms", "email", "chat", ""]) | _json,
        "domain": _hosts | _json,
        "verdict": _json,
        "judgement": _json,
    },
)


@FUZZ
@given(URL_INPUTS | st.text(alphabet=LONE_SURROGATES | st.characters(), max_size=60))
def test_url_endpoint_never_fails(fuzz_client, url):
    response = post_json(fuzz_client, "/v1/analyze/url", {"url": url, "analyst": True})
    _assert_contract(response, {200, 400, 422})


@FUZZ
@given(st.text(alphabet=LONE_SURROGATES | st.characters(), max_size=300))
def test_text_endpoint_never_fails(fuzz_client, text):
    response = post_json(fuzz_client, "/v1/analyze/text", {"text": text, "analyst": True})
    _assert_contract(response, {200, 422})


@FUZZ
@given(
    st.sampled_from(["/v1/analyze/url", "/v1/analyze/text", "/v1/feedback"]),
    _request_fields | _json,
)
def test_json_endpoints_never_fail_on_arbitrary_json(fuzz_client, route, body):
    response = post_json(fuzz_client, route, body)
    _assert_contract(response, {200, 202, 400, 422})


@FUZZ
@given(
    st.sampled_from(["/v1/analyze/url", "/v1/analyze/text", "/v1/feedback"]),
    st.binary(max_size=300),
)
def test_json_endpoints_never_fail_on_raw_bytes(fuzz_client, route, body):
    response = fuzz_client.post(route, content=body, headers={"Content-Type": "application/json"})
    _assert_contract(response, {200, 202, 400, 422})


@FUZZ
@given(st.one_of(EMAILS_STRATEGY, st.binary(max_size=2000)))
def test_email_endpoint_never_fails(fuzz_client, raw):
    response = fuzz_client.post(
        "/v1/analyze/email",
        files={"file": ("m.eml", raw, "message/rfc822")},
        data={"language": "en", "analyst": "true"},
    )
    _assert_contract(response, {200, 413, 422})
