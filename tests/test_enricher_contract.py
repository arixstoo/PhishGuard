"""Tests de contrat communs à toutes les sources (étape 2.12).

Chaque enrichisseur a ses propres tests (étapes 2.4 à 2.7). Ceux-ci vérifient, pour
**toutes** les sources du registre à la fois, que le contrat de l'étape 2.2 tient face à
chaque forme de panne, et que chaque source ne parle qu'à son propre service.
"""

import asyncio
import json

import httpx
import pytest
import respx

from phishguard.config import Settings
from phishguard.enrichers import Signal
from phishguard.enrichers.registry import build_enrichers

KEY = "contract-test-key-not-a-real-secret"
URL = "https://login.example.com/verify?session=abc"
DOMAIN = "example.com"

# Hôtes que chaque source a le droit de contacter, et rien d'autre.
ALLOWED_HOSTS = {
    "google_safe_browsing": {"safebrowsing.googleapis.com"},
    "virustotal": {"www.virustotal.com"},
    "urlscan": {"urlscan.io"},
    "rdap": {"data.iana.org", "rdap.verisign.com"},
    "certificate_transparency": {"crt.sh"},
}
BOOTSTRAP = {"services": [[["com"], ["https://rdap.verisign.com/com/v1/"]]]}


def run(coro):
    return asyncio.run(coro)


@pytest.fixture
def sources(monkeypatch, tmp_path):
    """Les six sources, toutes activées avec de fausses clés, DNS simulé."""
    monkeypatch.chdir(tmp_path)
    for var in ("GSB_API_KEY", "VT_API_KEY", "URLSCAN_API_KEY"):
        monkeypatch.setenv(var, KEY)
    monkeypatch.setenv("CRTSH_ENABLED", "true")
    enrichers = build_enrichers(Settings())

    async def unreachable_dns(name, rdtype):
        raise OSError("DNS injoignable")

    next(e for e in enrichers if e.name == "dns")._lookup = unreachable_dns
    return enrichers


def test_every_source_is_enabled_in_this_suite(sources):
    assert [e.name for e in sources] == [
        "google_safe_browsing",
        "virustotal",
        "urlscan",
        "rdap",
        "dns",
        "certificate_transparency",
    ]
    assert all(e.is_enabled() for e in sources)


FAILURES = {
    "server_error": lambda: httpx.Response(503),
    "rate_limited": lambda: httpx.Response(429),
    "unauthorized": lambda: httpx.Response(401, json={"error": "bad key"}),
    "garbage": lambda: httpx.Response(200, content=b"\x00\xff<html>not json</html>"),
    "wrong_json": lambda: httpx.Response(200, json=[1, 2, 3]),
    "empty": lambda: httpx.Response(200, content=b""),
    "connect_error": httpx.ConnectError("refusée"),
    "read_timeout": httpx.ReadTimeout("lent"),
    "protocol_error": httpx.RemoteProtocolError("connexion rompue"),
}


@pytest.mark.parametrize("failure", list(FAILURES))
@respx.mock
def test_no_source_ever_raises(sources, failure):
    effect = FAILURES[failure]
    route = respx.route()
    if callable(effect) and not isinstance(effect, Exception):
        route.mock(side_effect=lambda request: effect())
    else:
        route.mock(side_effect=effect)

    for source in sources:
        signal = run(source.enrich(URL, DOMAIN))
        assert isinstance(signal, Signal)
        assert signal.source == source.name
        assert 0.0 <= signal.risk <= 1.0 and signal.latency_ms >= 0
        if signal.status != "ok":
            assert signal.risk == 0.0  # un signal manquant n'est pas un risque
        payload = signal.model_dump_json()
        assert KEY not in payload  # aucune clé dans le signal, même en erreur
        json.loads(payload)


@respx.mock
def test_each_source_talks_only_to_its_own_service(sources):
    respx.get("https://data.iana.org/rdap/dns.json").mock(
        return_value=httpx.Response(200, json=BOOTSTRAP)
    )
    respx.route().mock(return_value=httpx.Response(404))
    for source in sources:
        if source.name not in ALLOWED_HOSTS:
            continue
        before = len(respx.calls)
        run(source.enrich(URL, DOMAIN))
        hosts = {call.request.url.host for call in respx.calls[before:]}
        assert hosts, f"{source.name} n'a fait aucune requête"
        assert hosts <= ALLOWED_HOSTS[source.name], (source.name, hosts)


@respx.mock
def test_no_api_key_ever_travels_in_a_url(sources):
    respx.get("https://data.iana.org/rdap/dns.json").mock(
        return_value=httpx.Response(200, json=BOOTSTRAP)
    )
    respx.route().mock(return_value=httpx.Response(404))
    for source in sources:
        run(source.enrich(URL, DOMAIN))
    assert respx.calls
    for call in respx.calls:
        assert KEY not in str(call.request.url)  # en-tête seulement : jamais dans les journaux


@respx.mock
def test_disabled_sources_make_no_request(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    for var in ("GSB_API_KEY", "VT_API_KEY", "URLSCAN_API_KEY", "CRTSH_ENABLED"):
        monkeypatch.delenv(var, raising=False)
    respx.route().mock(side_effect=AssertionError("requête d'une source désactivée"))
    keyed = [
        e
        for e in build_enrichers(Settings())
        if e.name in {"google_safe_browsing", "virustotal", "urlscan", "certificate_transparency"}
    ]
    signals = [run(e.enrich(URL, DOMAIN)) for e in keyed]
    assert [s.evidence for s in signals] == [{"reason": "disabled"}] * 4
    assert not respx.calls
