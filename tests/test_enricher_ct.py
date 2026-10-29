"""Tests de l'enrichisseur Certificate Transparency / crt.sh (étape 2.7)."""

import asyncio
from datetime import UTC, datetime

import httpx
import pytest
import respx

from phishguard.config import Settings
from phishguard.enrichers.ct import ENDPOINT, CertificateTransparencyEnricher, risk_from_first_seen
from phishguard.enrichers.registry import build_enrichers

NOW = datetime(2026, 10, 29, 12, 0, tzinfo=UTC)


def run(coro):
    return asyncio.run(coro)


def cert(not_before, cert_id=1):
    return {
        "id": cert_id,
        "issuer_name": "C=US, O=Let's Encrypt, CN=R11",
        "common_name": "example.test",
        "name_value": "example.test",
        "entry_timestamp": not_before + ".123",
        "not_before": not_before,
        "not_after": "2027-01-01T00:00:00",
    }


def enricher(**kwargs):
    return CertificateTransparencyEnricher(now=lambda: NOW, **kwargs)


@respx.mock
def test_first_certificate_date():
    certs = [cert("2024-03-01T00:00:00", 1), cert("2019-06-10T08:00:00", 2), {"junk": True}]
    route = respx.get(ENDPOINT).mock(return_value=httpx.Response(200, json=certs))
    signal = run(enricher().enrich("https://example.test/", "example.test"))
    assert route.calls.last.request.url.params["q"] == "example.test"
    assert route.calls.last.request.url.params["output"] == "json"
    assert (signal.source, signal.status, signal.risk) == ("certificate_transparency", "ok", 0.0)
    assert signal.evidence["first_seen"].startswith("2019-06-10")
    assert signal.evidence["certificates"] == 3


@respx.mock
def test_brand_new_certificate_is_a_signal():
    respx.get(ENDPOINT).mock(return_value=httpx.Response(200, json=[cert("2026-10-27T10:00:00")]))
    signal = run(enricher().enrich("https://new.test/", "new.test"))
    assert (signal.evidence["first_seen_days"], signal.risk) == (2, 0.6)


@pytest.mark.parametrize(
    ("days", "risk"), [(None, 0.0), (0, 0.6), (6, 0.6), (7, 0.3), (29, 0.3), (30, 0.0)]
)
def test_first_seen_risk_scale(days, risk):
    assert risk_from_first_seen(days) == risk


@respx.mock
def test_no_certificate_gives_no_risk():
    respx.get(ENDPOINT).mock(return_value=httpx.Response(200, json=[]))
    signal = run(enricher().enrich("https://none.test/", "none.test"))
    assert (signal.risk, signal.evidence["first_seen"]) == (0.0, None)


@respx.mock
def test_huge_answer_means_an_old_popular_domain():
    big = [cert(f"2015-01-01T00:00:{i % 60:02d}", i) for i in range(5_000)]
    respx.get(ENDPOINT).mock(return_value=httpx.Response(200, json=big))
    signal = run(enricher(max_bytes=10_000).enrich("https://google.test/", "google.test"))
    assert (signal.status, signal.risk) == ("ok", 0.0)
    assert signal.evidence["many_certificates"] is True


@respx.mock
def test_slow_or_failing_service_never_blocks():
    respx.get(ENDPOINT).mock(side_effect=httpx.ReadTimeout("crt.sh lent"))
    assert run(enricher().enrich("https://x.test/", "x.test")).status == "timeout"
    respx.get(ENDPOINT).mock(return_value=httpx.Response(502))
    signal = run(enricher().enrich("https://x.test/", "x.test"))
    assert (signal.status, signal.evidence["reason"]) == ("error", "server_error")


@respx.mock
def test_results_are_cached():
    route = respx.get(ENDPOINT).mock(
        return_value=httpx.Response(200, json=[cert("2020-01-01T00:00:00")])
    )
    source = enricher()

    async def twice():
        return [await source.enrich("https://x.test/", "x.test") for _ in range(2)]

    first, second = run(twice())
    assert route.call_count == 1 and second.evidence["cached"] is True
    assert first.evidence["cached"] is False


def test_disabled_by_default_in_the_registry(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("CRTSH_ENABLED", raising=False)
    ct = next(e for e in build_enrichers(Settings()) if e.name == "certificate_transparency")
    assert not ct.is_enabled()
    monkeypatch.setenv("CRTSH_ENABLED", "true")
    ct = next(e for e in build_enrichers(Settings()) if e.name == "certificate_transparency")
    assert ct.is_enabled()


def test_registry_lists_every_source(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    names = [e.name for e in build_enrichers(Settings())]
    assert names == [
        "google_safe_browsing",
        "virustotal",
        "urlscan",
        "rdap",
        "dns",
        "certificate_transparency",
    ]
