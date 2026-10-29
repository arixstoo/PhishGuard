"""Tests de l'enrichisseur Google Safe Browsing (étape 2.4), réponses simulées par respx."""

import asyncio

import httpx
import pytest
import respx

from phishguard.config import Settings
from phishguard.enrichers.safe_browsing import (
    ENDPOINT,
    SafeBrowsingEnricher,
    parse_duration,
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


FOUND = {
    "threats": [{"url": "phish.example.test/login", "threatTypes": ["SOCIAL_ENGINEERING"]}],
    "cacheDuration": "300s",
}


# --------------------------------------------------------------------------- #
# Critère de l'étape : trouvé, non trouvé, 429, timeout
# --------------------------------------------------------------------------- #


@respx.mock
def test_found_is_a_hard_phishing_signal():
    respx.get(ENDPOINT).mock(return_value=httpx.Response(200, json=FOUND))
    signal = run(enricher().enrich(URL, "example.test"))
    assert (signal.source, signal.status, signal.risk) == ("google_safe_browsing", "ok", 1.0)
    assert signal.evidence["listed"] is True
    assert signal.evidence["threat_types"] == ["SOCIAL_ENGINEERING"]
    assert signal.evidence["matched_urls"] == ["phish.example.test/login"]


@respx.mock
def test_not_found_is_a_clean_signal():
    respx.get(ENDPOINT).mock(return_value=httpx.Response(200, json={"cacheDuration": "600s"}))
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
def test_request_uses_v5_json_and_keeps_the_key_out_of_the_url():
    route = respx.get(ENDPOINT).mock(return_value=httpx.Response(200, json={}))
    run(enricher().enrich(URL, "example.test"))
    request = route.calls.last.request
    assert request.url.params["urls"] == URL
    assert request.url.params["alt"] == "json"
    assert request.headers["x-goog-api-key"] == KEY
    assert KEY not in str(request.url)


@respx.mock
def test_fragment_and_credentials_are_never_sent():
    route = respx.get(ENDPOINT).mock(return_value=httpx.Response(200, json={}))
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


# Forme réelle de la réponse de Google à une clé invalide (vérifiée le 28/10/2026).
INVALID_KEY = {
    "error": {
        "code": 400,
        "message": "API key not valid. Please pass a valid API key.",
        "status": "INVALID_ARGUMENT",
        "details": [
            {
                "@type": "type.googleapis.com/google.rpc.ErrorInfo",
                "reason": "API_KEY_INVALID",
                "domain": "googleapis.com",
                "metadata": {"service": "safebrowsing.googleapis.com"},
            }
        ],
    }
}


@respx.mock
def test_invalid_key_is_reported_as_such():
    respx.get(ENDPOINT).mock(return_value=httpx.Response(400, json=INVALID_KEY))
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


@pytest.mark.parametrize("body", [b"not json", b"[1, 2]", b'{"threats": "oops"}'])
@respx.mock
def test_malformed_responses_become_error_signals(body):
    respx.get(ENDPOINT).mock(return_value=httpx.Response(200, content=body))
    assert run(enricher().enrich(URL, "example.test")).status == "error"


@respx.mock
def test_unspecified_threat_type_is_ignored():
    payload = {"threats": [{"url": "x", "threatTypes": ["THREAT_TYPE_UNSPECIFIED"]}]}
    respx.get(ENDPOINT).mock(return_value=httpx.Response(200, json=payload))
    signal = run(enricher().enrich(URL, "example.test"))
    assert (signal.risk, signal.evidence["listed"]) == (0.0, False)


@respx.mock
def test_several_matches_are_merged():
    payload = {
        "threats": [
            {"url": "phish.example.test/", "threatTypes": ["MALWARE"]},
            {"url": "phish.example.test/login", "threatTypes": ["SOCIAL_ENGINEERING", "MALWARE"]},
        ]
    }
    respx.get(ENDPOINT).mock(return_value=httpx.Response(200, json=payload))
    signal = run(enricher().enrich(URL, "example.test"))
    assert signal.evidence["threat_types"] == ["MALWARE", "SOCIAL_ENGINEERING"]
    assert len(signal.evidence["matched_urls"]) == 2


# --------------------------------------------------------------------------- #
# Cache
# --------------------------------------------------------------------------- #


@respx.mock
def test_response_is_cached_for_the_duration_given_by_google():
    clock = FakeClock()
    route = respx.get(ENDPOINT).mock(return_value=httpx.Response(200, json=FOUND))
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
    route = respx.get(ENDPOINT).mock(
        return_value=httpx.Response(200, json={"cacheDuration": "604800s"})
    )
    source = enricher(clock=clock)
    run(source.enrich(URL, "example.test"))
    clock.now += 24 * 3600
    run(source.enrich(URL, "example.test"))
    assert route.call_count == 2


@respx.mock
def test_errors_are_not_cached():
    route = respx.get(ENDPOINT).mock(
        side_effect=[httpx.Response(429), httpx.Response(200, json=FOUND)]
    )
    source = enricher()
    assert run(source.enrich(URL, "example.test")).status == "error"
    assert run(source.enrich(URL, "example.test")).risk == 1.0
    assert route.call_count == 2


# --------------------------------------------------------------------------- #
# Fonctions utilitaires
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("value", "expected"),
    [("300s", 300.0), ("1.5s", 1.5), (" 60s ", 60.0), ("5m", 300.0), (None, 300.0), (12, 300.0)],
)
def test_parse_duration(value, expected):
    assert parse_duration(value) == expected


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
