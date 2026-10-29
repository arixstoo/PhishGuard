"""Tests de l'enrichisseur VirusTotal (étape 2.5), réponses simulées par respx."""

import asyncio
import base64
from datetime import date

import httpx
import pytest
import respx

from phishguard.config import Settings
from phishguard.enrichers.virustotal import (
    API,
    DailyQuota,
    VirusTotalEnricher,
    risk_from_stats,
    url_id,
)

KEY = "test-key-not-a-real-secret"
URL = "http://phish.example.test/login"
URL_ROUTE = f"{API}/urls/{url_id(URL)}"
DOMAIN_ROUTE = f"{API}/domains/example.test"


def run(coro):
    return asyncio.run(coro)


def report(object_id, malicious=0, suspicious=0, harmless=60, results=None, when=1_761_609_600):
    return {
        "data": {
            "id": object_id,
            "type": "url",
            "attributes": {
                "last_analysis_stats": {
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "harmless": harmless,
                    "undetected": 10,
                    "timeout": 0,
                },
                "last_analysis_results": results or {},
                "last_analysis_date": when,
                "reputation": -12,
            },
        }
    }


NOT_FOUND = {"error": {"code": "NotFoundError", "message": "URL not found"}}


def enricher(**kwargs):
    kwargs.setdefault("per_minute", 100)
    return VirusTotalEnricher(KEY, **kwargs)


# --------------------------------------------------------------------------- #
# Identifiant d'URL et calcul du risque
# --------------------------------------------------------------------------- #


def test_url_id_is_unpadded_urlsafe_base64():
    value = url_id("http://example.com/?a=b")
    assert "=" not in value and "+" not in value and "/" not in value
    padded = value + "=" * (-len(value) % 4)
    assert base64.urlsafe_b64decode(padded).decode() == "http://example.com/?a=b"


@pytest.mark.parametrize(
    ("malicious", "suspicious", "risk"),
    [(0, 0, 0.0), (1, 0, 0.2), (0, 1, 0.1), (2, 2, 0.6), (5, 0, 1.0), (40, 3, 1.0)],
)
def test_risk_formula(malicious, suspicious, risk):
    assert risk_from_stats({"malicious": malicious, "suspicious": suspicious}) == pytest.approx(
        risk
    )


# --------------------------------------------------------------------------- #
# Recherche URL puis domaine
# --------------------------------------------------------------------------- #


@respx.mock
def test_known_url_report():
    results = {
        "EngineA": {"category": "malicious", "result": "phishing"},
        "EngineB": {"category": "suspicious", "result": "suspicious"},
        "EngineC": {"category": "harmless", "result": "clean"},
    }
    route = respx.get(URL_ROUTE).mock(
        return_value=httpx.Response(200, json=report("abc123", 6, 1, results=results))
    )
    signal = run(enricher().enrich(URL, "example.test"))
    assert (signal.source, signal.status, signal.risk) == ("virustotal", "ok", 1.0)
    evidence = signal.evidence
    assert evidence["object"] == "url" and evidence["found"] is True
    assert evidence["stats"] == {"malicious": 6, "suspicious": 1, "harmless": 60, "undetected": 10}
    assert evidence["flagged_by"] == ["EngineA", "EngineB"]
    assert evidence["permalink"] == "https://www.virustotal.com/gui/url/abc123"
    assert evidence["last_analysis_date"] == "2025-10-28T00:00:00+00:00"
    assert route.calls.last.request.headers["x-apikey"] == KEY


@respx.mock
def test_unknown_url_falls_back_to_the_domain():
    respx.get(URL_ROUTE).mock(return_value=httpx.Response(404, json=NOT_FOUND))
    domain = respx.get(DOMAIN_ROUTE).mock(
        return_value=httpx.Response(200, json=report("example.test", 2))
    )
    signal = run(enricher().enrich(URL, "example.test"))
    assert domain.called
    assert (signal.risk, signal.evidence["object"]) == (pytest.approx(0.4), "domain")
    assert signal.evidence["permalink"].endswith("/gui/domain/example.test")


@respx.mock
def test_unknown_everywhere_is_a_clean_signal():
    respx.get(URL_ROUTE).mock(return_value=httpx.Response(404, json=NOT_FOUND))
    respx.get(DOMAIN_ROUTE).mock(return_value=httpx.Response(404, json=NOT_FOUND))
    signal = run(enricher().enrich(URL, "example.test"))
    assert (signal.status, signal.risk) == ("ok", 0.0)
    assert signal.evidence == {"found": False, "checked": ["url", "domain"]}


@respx.mock
def test_domain_only_mode_never_sends_the_url():
    url_route = respx.get(URL_ROUTE)
    respx.get(DOMAIN_ROUTE).mock(return_value=httpx.Response(200, json=report("example.test")))
    signal = run(enricher(lookups=("domain",)).enrich(URL, "example.test"))
    assert not url_route.called and signal.evidence["object"] == "domain"


@respx.mock
def test_fragment_and_credentials_are_removed_before_lookup():
    clean = respx.get(f"{API}/urls/{url_id('http://phish.example.test/a')}").mock(
        return_value=httpx.Response(200, json=report("x"))
    )
    run(enricher(lookups=("url",)).enrich("http://bob:pw@phish.example.test/a#tok", "x"))
    assert clean.called


@pytest.mark.parametrize(("url", "domain"), [("ftp://x.test/", "127.0.0.1"), ("", "")])
@respx.mock
def test_unusable_input_is_skipped(url, domain):
    signal = run(enricher().enrich(url, domain))
    assert (signal.status, signal.evidence) == ("skipped", {"reason": "unsupported_input"})


def test_without_key_the_source_is_skipped(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("VT_API_KEY", raising=False)
    assert not VirusTotalEnricher.from_settings(Settings()).is_enabled()
    monkeypatch.setenv("VT_API_KEY", KEY)
    assert VirusTotalEnricher.from_settings(Settings()).is_enabled()


def test_invalid_lookups_are_rejected():
    with pytest.raises(ValueError):
        VirusTotalEnricher(KEY, lookups=())
    with pytest.raises(ValueError):
        VirusTotalEnricher(KEY, lookups=("ip",))


# --------------------------------------------------------------------------- #
# Erreurs
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("status", "code", "reason"),
    [
        (401, "WrongCredentialsError", "unauthorized"),
        (429, "QuotaExceededError", "rate_limited"),
        (503, "TransientError", "server_error"),
    ],
)
@respx.mock
def test_api_errors_become_error_signals(status, code, reason):
    respx.get(URL_ROUTE).mock(
        return_value=httpx.Response(status, json={"error": {"code": code, "message": "x"}})
    )
    signal = run(enricher().enrich(URL, "example.test"))
    assert signal.status == "error" and signal.risk == 0.0
    assert signal.evidence == {"reason": reason, "http_status": status, "vt_error": code}


@pytest.mark.parametrize(
    "body",
    [
        {"data": {}},
        {"data": {"id": "x", "attributes": {"last_analysis_stats": {"malicious": "many"}}}},
        {"data": {"id": "x", "attributes": {"last_analysis_stats": {"malicious": -1}}}},
        [1, 2],
    ],
)
@respx.mock
def test_malformed_reports_become_error_signals(body):
    respx.get(URL_ROUTE).mock(return_value=httpx.Response(200, json=body))
    signal = run(enricher().enrich(URL, "example.test"))
    assert signal.status == "error"


# --------------------------------------------------------------------------- #
# Limite de débit : critère de l'étape
# --------------------------------------------------------------------------- #


@respx.mock
def test_fifth_call_in_a_minute_is_skipped():
    respx.get(url__startswith=f"{API}/urls/").mock(
        return_value=httpx.Response(200, json=report("x"))
    )
    source = VirusTotalEnricher(KEY, lookups=("url",))  # palier public : 4 par minute

    async def five_calls():
        return [
            await source.enrich(f"https://site{i}.example.test/", "example.test") for i in range(5)
        ]

    signals = run(five_calls())
    assert [s.status for s in signals] == ["ok"] * 4 + ["skipped"]
    assert signals[-1].evidence == {"reason": "local_rate_limit", "checked": []}
    assert len(respx.calls) == 4


@respx.mock
def test_fifth_call_can_wait_for_capacity():
    respx.get(url__startswith=f"{API}/urls/").mock(
        return_value=httpx.Response(200, json=report("x"))
    )
    # 4 requêtes par 2 s : une place se libère toutes les 0,5 s.
    source = VirusTotalEnricher(KEY, lookups=("url",), rate_period=2.0, max_wait=1.5)

    async def five_calls():
        return [
            await source.enrich(f"https://site{i}.example.test/", "example.test") for i in range(5)
        ]

    signals = run(five_calls())
    assert [s.status for s in signals] == ["ok"] * 5
    assert signals[-1].latency_ms >= 100  # le cinquième appel a attendu sa place


@respx.mock
def test_daily_quota_is_enforced_and_reset_the_next_day():
    respx.get(url__startswith=f"{API}/urls/").mock(
        return_value=httpx.Response(200, json=report("x"))
    )
    day = [date(2026, 10, 28)]
    source = enricher(lookups=("url",), per_day=2, today=lambda: day[0])

    async def call(i):
        return await source.enrich(f"https://site{i}.example.test/", "example.test")

    async def scenario():
        before = [await call(i) for i in range(3)]
        day[0] = date(2026, 10, 29)
        return before, await call(99)

    before, after = run(scenario())
    assert [s.status for s in before] == ["ok", "ok", "skipped"]
    assert after.status == "ok"


def test_daily_quota_counter():
    day = [date(2026, 1, 1)]
    quota = DailyQuota(3, lambda: day[0])
    quota.consume()
    quota.consume()
    assert quota.remaining() == 1
    day[0] = date(2026, 1, 2)
    assert quota.remaining() == 3


# --------------------------------------------------------------------------- #
# Cache
# --------------------------------------------------------------------------- #


@respx.mock
def test_reports_and_misses_are_cached_to_save_quota():
    url_route = respx.get(URL_ROUTE).mock(return_value=httpx.Response(404, json=NOT_FOUND))
    domain_route = respx.get(DOMAIN_ROUTE).mock(
        return_value=httpx.Response(200, json=report("example.test", 1))
    )
    source = enricher()

    async def twice():
        return [await source.enrich(URL, "example.test") for _ in range(2)]

    first, second = run(twice())
    assert (url_route.call_count, domain_route.call_count) == (1, 1)
    assert (first.evidence["cached"], second.evidence["cached"]) == (False, True)
    assert first.risk == second.risk == pytest.approx(0.2)


@respx.mock
def test_cache_expires():
    now = [0.0]
    route = respx.get(URL_ROUTE).mock(return_value=httpx.Response(200, json=report("x")))
    source = enricher(lookups=("url",), clock=lambda: now[0])

    async def scenario():
        await source.enrich(URL, "x")
        now[0] = 6 * 3600 + 1
        await source.enrich(URL, "x")

    run(scenario())
    assert route.call_count == 2
