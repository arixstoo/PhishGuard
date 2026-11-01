"""Tests de l'enrichisseur Google Safe Browsing (étape 2.4), réponses simulées par respx.

La v5 répond en protobuf. Les réponses ``REAL_*`` ont été capturées sur l'API réelle le
01/11/2026 avec les URLs de test de Google (testsafebrowsing.appspot.com) ; les autres
sont construites par ``search_response()``.
"""

import asyncio

import httpx
import pytest
import respx

from phishguard.config import Settings
from phishguard.enrichers.http import MalformedResponse
from phishguard.enrichers.safe_browsing import (
    ENDPOINT,
    SafeBrowsingEnricher,
    parse_search_response,
    sanitize_url,
)

KEY = "test-key-not-a-real-secret"
URL = "http://phish.example.test/login"


class FakeClock:
    def __init__(self):
        self.now = 1_000.0

    def __call__(self):
        return self.now


def run(coro):
    return asyncio.run(coro)


def enricher(**kwargs):
    return SafeBrowsingEnricher(KEY, **kwargs)


# --------------------------------------------------------------------------- #
# Encodage protobuf des réponses simulées
# --------------------------------------------------------------------------- #


def varint(n):
    out = bytearray()
    while True:
        byte, n = n & 0x7F, n >> 7
        out.append(byte | (0x80 if n else 0))
        if not n:
            return bytes(out)


def field(number, payload):
    """Champ de type « longueur + octets » (wire type 2)."""
    return varint(number << 3 | 2) + varint(len(payload)) + payload


def search_response(threats=(), seconds=300, nanos=0):
    """``SearchUrlsResponse`` : ``threats`` est une liste de ``(url, [types])``."""
    body = b""
    for url, types in threats:
        body += field(1, field(1, url.encode()) + field(2, b"".join(varint(t) for t in types)))
    duration = varint(1 << 3) + varint(seconds) + (varint(2 << 3) + varint(nanos) if nanos else b"")
    return body + field(2, duration)


def proto(content, status=200):
    return httpx.Response(
        status, content=content, headers={"content-type": "application/x-protobuf"}
    )


MALWARE, SOCIAL_ENGINEERING, UNWANTED_SOFTWARE, HARMFUL = 1, 2, 3, 4
FOUND = search_response([("phish.example.test/login", [SOCIAL_ENGINEERING])])
NOT_FOUND = search_response(seconds=600)

# Réponses réelles (voir la docstring du module).
REAL_PHISHING = bytes.fromhex(
    "0a310a2c746573747361666562726f7773696e672e61707073706f742e636f6d2f732f7068697368696e67"
    "2e68746d6c120102120308ac02"
)
REAL_MALWARE = bytes.fromhex(
    "0a310a2b746573747361666562726f7773696e672e61707073706f742e636f6d2f732f6d616c7761726"
    "52e68746d6c12020104120308ac02"
)
REAL_CLEAN = bytes.fromhex("120308ac02")
# google.rpc.Status renvoyé à une clé invalide (HTTP 400, en protobuf lui aussi).
REAL_INVALID_KEY = bytes.fromhex(
    "0803122f415049206b6579206e6f742076616c69642e20506c65617365207061737320612076616c6964"
    "20415049206b65792e1a750a28747970652e676f6f676c65617069732e636f6d2f676f6f676c652e727063"
    "2e4572726f72496e666f12490a0f4150495f4b45595f494e56414c4944120e676f6f676c65617069732e63"
    "6f6d1a260a0773657276696365121b7361666562726f7773696e672e676f6f676c65617069732e636f6d"
)


# --------------------------------------------------------------------------- #
# Critère de l'étape : trouvé, non trouvé, 429, timeout
# --------------------------------------------------------------------------- #


@respx.mock
def test_found_is_a_hard_phishing_signal():
    respx.get(ENDPOINT).mock(return_value=proto(FOUND))
    signal = run(enricher().enrich(URL, "example.test"))
    assert (signal.source, signal.status, signal.risk) == ("google_safe_browsing", "ok", 1.0)
    assert signal.evidence["listed"] is True
    assert signal.evidence["threat_types"] == ["SOCIAL_ENGINEERING"]
    assert signal.evidence["matched_urls"] == ["phish.example.test/login"]


@respx.mock
def test_not_found_is_a_clean_signal():
    respx.get(ENDPOINT).mock(return_value=proto(NOT_FOUND))
    signal = run(enricher().enrich("https://example.com/", "example.com"))
    assert (signal.status, signal.risk) == ("ok", 0.0)
    assert signal.evidence["listed"] is False and signal.evidence["threat_types"] == []


@respx.mock
def test_rate_limited_is_an_error_without_risk():
    respx.get(ENDPOINT).mock(return_value=httpx.Response(429, json={"error": {"code": 429}}))
    signal = run(enricher().enrich(URL, "example.test"))
    assert (signal.status, signal.risk) == ("error", 0.0)
    assert signal.evidence == {"reason": "rate_limited", "http_status": 429}


@respx.mock
def test_timeout_is_a_timeout_signal():
    respx.get(ENDPOINT).mock(side_effect=httpx.ReadTimeout("lent"))
    signal = run(enricher().enrich(URL, "example.test"))
    assert (signal.status, signal.risk) == ("timeout", 0.0)


# --------------------------------------------------------------------------- #
# Requête envoyée
# --------------------------------------------------------------------------- #


@respx.mock
def test_request_uses_v5_and_keeps_the_key_out_of_the_url():
    route = respx.get(ENDPOINT).mock(return_value=proto(REAL_CLEAN))
    run(enricher().enrich(URL, "example.test"))
    request = route.calls.last.request
    assert request.url.params["urls"] == URL
    assert "alt" not in request.url.params  # alt=json est refusé par la v5 (400)
    assert request.headers["x-goog-api-key"] == KEY
    assert KEY not in str(request.url)


@respx.mock
def test_fragment_and_credentials_are_never_sent():
    route = respx.get(ENDPOINT).mock(return_value=proto(REAL_CLEAN))
    run(enricher().enrich("HTTP://alice:s3cret@Phish.example.test:8080/a?b=1#token", "x"))
    sent = route.calls.last.request.url.params["urls"]
    assert sent == "http://phish.example.test:8080/a?b=1"
    assert "s3cret" not in sent and "token" not in sent


@pytest.mark.parametrize("url", ["ftp://example.com/", "mailto:a@example.com", "not a url", ""])
@respx.mock
def test_non_web_urls_are_skipped_without_a_request(url):
    route = respx.get(ENDPOINT)
    signal = run(enricher().enrich(url, "example.com"))
    assert (signal.status, signal.evidence) == ("skipped", {"reason": "unsupported_url"})
    assert not route.called


def test_without_key_the_source_is_skipped():
    with respx.mock:
        route = respx.get(ENDPOINT)
        signal = run(SafeBrowsingEnricher(None).enrich(URL, "example.test"))
        assert signal.status == "skipped" and not route.called


def test_from_settings_reads_the_gsb_key(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("GSB_API_KEY", KEY)
    assert SafeBrowsingEnricher.from_settings(Settings()).is_enabled()
    monkeypatch.delenv("GSB_API_KEY")
    assert not SafeBrowsingEnricher.from_settings(Settings()).is_enabled()


# --------------------------------------------------------------------------- #
# Réponses d'erreur et réponses inattendues
# --------------------------------------------------------------------------- #


@respx.mock
def test_invalid_key_is_reported_as_such():
    respx.get(ENDPOINT).mock(return_value=proto(REAL_INVALID_KEY, status=400))
    signal = run(enricher().enrich(URL, "example.test"))
    assert signal.evidence == {"reason": "invalid_api_key", "http_status": 400}


@pytest.mark.parametrize(
    ("status", "reason"),
    [(400, "http_400"), (403, "unauthorized"), (500, "server_error"), (503, "server_error")],
)
@respx.mock
def test_http_errors_become_error_signals(status, reason):
    respx.get(ENDPOINT).mock(return_value=httpx.Response(status, text="error"))
    signal = run(enricher().enrich(URL, "example.test"))
    assert (signal.status, signal.evidence["reason"], signal.risk) == ("error", reason, 0.0)


@pytest.mark.parametrize(
    "body",
    [
        b"\x0a\x31\x0a",  # message tronqué
        b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x01",  # varint trop long
        b"\x0b",  # type de fil 3 (groupe), jamais utilisé par cette API
    ],
)
@respx.mock
def test_malformed_responses_become_error_signals(body):
    respx.get(ENDPOINT).mock(return_value=proto(body))
    signal = run(enricher().enrich(URL, "example.test"))
    assert (signal.status, signal.evidence["error"]) == ("error", "MalformedResponse")


@respx.mock
def test_json_response_is_refused():
    # Ce que la version précédente attendait : la v5 ne répond jamais ainsi.
    respx.get(ENDPOINT).mock(return_value=httpx.Response(200, json={"threats": []}))
    signal = run(enricher().enrich(URL, "example.test"))
    assert (signal.status, signal.evidence["error"]) == ("error", "MalformedResponse")


@respx.mock
def test_unspecified_threat_type_is_ignored():
    payload = search_response([("x", [0])])  # THREAT_TYPE_UNSPECIFIED
    respx.get(ENDPOINT).mock(return_value=proto(payload))
    signal = run(enricher().enrich(URL, "example.test"))
    assert (signal.risk, signal.evidence["listed"]) == (0.0, False)


@respx.mock
def test_several_matches_are_merged():
    payload = search_response(
        [
            ("phish.example.test/", [MALWARE]),
            ("phish.example.test/login", [SOCIAL_ENGINEERING, MALWARE]),
        ]
    )
    respx.get(ENDPOINT).mock(return_value=proto(payload))
    signal = run(enricher().enrich(URL, "example.test"))
    assert signal.evidence["threat_types"] == ["MALWARE", "SOCIAL_ENGINEERING"]
    assert len(signal.evidence["matched_urls"]) == 2


# --------------------------------------------------------------------------- #
# Décodage protobuf, sur les réponses réelles
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("content", "listed", "types", "matched"),
    [
        (
            REAL_PHISHING,
            True,
            ["SOCIAL_ENGINEERING"],
            ["testsafebrowsing.appspot.com/s/phishing.html"],
        ),
        (
            REAL_MALWARE,
            True,
            ["MALWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            ["testsafebrowsing.appspot.com/s/malware.html"],
        ),
        (REAL_CLEAN, False, [], []),
    ],
)
def test_real_responses_are_decoded(content, listed, types, matched):
    assert parse_search_response(content) == {
        "listed": listed,
        "threat_types": types,
        "matched_urls": matched,
        "cache_seconds": 300.0,
    }


def test_threat_types_unpacked_and_unknown_values_count_as_a_match():
    # Un type non « packed » (wire type 0) et une valeur que Google ajouterait plus tard.
    threat = field(1, b"x.test/") + varint(2 << 3) + varint(UNWANTED_SOFTWARE) + field(2, b"\x09")
    result = parse_search_response(field(1, threat))
    assert result["threat_types"] == ["THREAT_TYPE_9", "UNWANTED_SOFTWARE"]
    assert result["listed"] is True


def test_unknown_fields_are_ignored():
    unknown = varint(7 << 3) + varint(42) + varint(8 << 3 | 5) + b"abcd" + field(9, b"zz")
    result = parse_search_response(unknown + search_response([("x.test/", [HARMFUL])]))
    assert result["threat_types"] == ["POTENTIALLY_HARMFUL_APPLICATION"]


def test_duration_with_nanoseconds_and_default():
    assert parse_search_response(search_response(seconds=1, nanos=500_000_000))[
        "cache_seconds"
    ] == pytest.approx(1.5)
    assert parse_search_response(b"")["cache_seconds"] == 300.0  # durée absente


def test_field_number_zero_is_refused():
    with pytest.raises(MalformedResponse):
        parse_search_response(varint(0) + varint(1))


# --------------------------------------------------------------------------- #
# Cache
# --------------------------------------------------------------------------- #


@respx.mock
def test_response_is_cached_for_the_duration_given_by_google():
    clock = FakeClock()
    route = respx.get(ENDPOINT).mock(return_value=proto(FOUND))
    source = enricher(clock=clock)
    first = run(source.enrich(URL, "example.test"))
    clock.now += 299
    second = run(source.enrich(URL, "example.test"))
    assert route.call_count == 1
    assert (first.evidence["cached"], second.evidence["cached"]) == (False, True)
    assert second.risk == 1.0
    clock.now += 2  # 301 s : la durée de 300 s est dépassée
    run(source.enrich(URL, "example.test"))
    assert route.call_count == 2


@respx.mock
def test_clean_result_is_cached_at_most_24_hours():
    clock = FakeClock()
    route = respx.get(ENDPOINT).mock(return_value=proto(search_response(seconds=604_800)))
    source = enricher(clock=clock)
    run(source.enrich(URL, "example.test"))
    clock.now += 24 * 3600
    run(source.enrich(URL, "example.test"))
    assert route.call_count == 2


@respx.mock
def test_errors_are_not_cached():
    route = respx.get(ENDPOINT).mock(side_effect=[httpx.Response(429), proto(FOUND)])
    source = enricher()
    assert run(source.enrich(URL, "example.test")).status == "error"
    assert run(source.enrich(URL, "example.test")).risk == 1.0
    assert route.call_count == 2


# --------------------------------------------------------------------------- #
# Fonctions utilitaires
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://example.com", "https://example.com"),
        ("https://[2606:4700::1]:443/x", "https://[2606:4700::1]:443/x"),
        ("http://example.com:99999/", None),
        ("https://" + "a" * 9000 + ".com/", None),
    ],
)
def test_sanitize_url(url, expected):
    assert sanitize_url(url) == expected
