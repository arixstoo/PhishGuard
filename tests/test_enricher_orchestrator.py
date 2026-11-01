"""Tests de l'orchestrateur des enrichisseurs (étape 2.9)."""

import asyncio
import time

import httpx
import pytest
import respx

from phishguard.config import Settings
from phishguard.enrichers import Enricher, Signal
from phishguard.enrichers.http import HttpEnricher
from phishguard.enrichers.orchestrator import (
    DEFAULT_BUDGET_S,
    Orchestrator,
    registered_domain,
)

URL = "https://login.example.test/verify"


def run(coro):
    return asyncio.run(coro)


class Fixed(Enricher):
    """Source simulée : répond après ``delay`` secondes, ou lève ``fail``."""

    name = "fixed"  # exigé par le contrat ; chaque instance reçoit ensuite son propre nom

    def __init__(self, name, delay=0.0, risk=0.0, fail=None):
        self.name = name  # attribut d'instance : plusieurs sources simulées d'une même classe
        self.delay = delay
        self.risk = risk
        self.fail = fail
        self.calls = []
        self.cancelled = False

    async def _enrich(self, url, domain):
        self.calls.append((url, domain))
        try:
            await asyncio.sleep(self.delay)
        except asyncio.CancelledError:
            self.cancelled = True
            raise
        if self.fail:
            raise self.fail
        return self.ok(self.risk, {"delay": self.delay})


# --------------------------------------------------------------------------- #
# Critère de l'étape : une source de 10 s ne retarde pas la réponse
# --------------------------------------------------------------------------- #


def test_slow_source_is_marked_timeout_and_the_answer_comes_in_time():
    slow = Fixed("slow", delay=10)
    fast = Fixed("fast", delay=0.05, risk=0.4)
    orchestrator = Orchestrator([slow, fast])  # budget par défaut : 2,5 s

    start = time.perf_counter()
    result = run(orchestrator.enrich(URL))
    elapsed = time.perf_counter() - start

    assert DEFAULT_BUDGET_S == 2.5
    assert elapsed < 3.0
    assert result.by_source["slow"].status == "timeout"
    assert result.by_source["slow"].evidence == {"reason": "budget_exceeded", "budget_ms": 2500}
    assert result.by_source["fast"].status == "ok" and result.by_source["fast"].risk == 0.4
    assert result.timed_out == ("slow",)
    assert [s.source for s in result.usable] == ["fast"]
    assert slow.cancelled  # la source lente est vraiment arrêtée, pas abandonnée


# --------------------------------------------------------------------------- #
# Parallélisme et dégradation
# --------------------------------------------------------------------------- #


def test_sources_run_in_parallel():
    sources = [Fixed(f"s{i}", delay=0.3) for i in range(5)]
    start = time.perf_counter()
    result = run(Orchestrator(sources, budget_s=2).enrich(URL))
    assert time.perf_counter() - start < 0.9  # 5 × 0,3 s en série ferait 1,5 s
    assert [s.status for s in result.signals] == ["ok"] * 5


def test_order_follows_the_sources_not_the_answers():
    sources = [Fixed("late", delay=0.2), Fixed("early", delay=0.0)]
    result = run(Orchestrator(sources).enrich(URL))
    assert [s.source for s in result.signals] == ["late", "early"]


def test_failing_source_degrades_without_raising():
    sources = [Fixed("broken", fail=RuntimeError("panne")), Fixed("fine", risk=0.2)]
    result = run(Orchestrator(sources).enrich(URL))
    assert result.by_source["broken"].status == "error"
    assert result.by_source["fine"].status == "ok"
    assert result.enrichment == "used"


def test_all_sources_down_still_gives_a_result():
    sources = [
        Fixed("a", fail=httpx.ConnectError("refusée")),
        Fixed("b", fail=httpx.ReadTimeout("lent")),
        Fixed("c", delay=10),
    ]
    result = run(Orchestrator(sources, budget_s=0.2).enrich(URL))
    assert [s.status for s in result.signals] == ["error", "timeout", "timeout"]
    assert result.usable == ()


def test_source_breaking_the_contract_is_contained(monkeypatch):
    rogue = Fixed("rogue")

    async def raising(url, domain):
        raise RuntimeError("enrich() a levé malgré le contrat")

    monkeypatch.setattr(rogue, "enrich", raising)
    result = run(Orchestrator([rogue, Fixed("fine")]).enrich(URL))
    assert result.by_source["rogue"].status == "error"
    assert result.by_source["rogue"].evidence == {"error": "RuntimeError"}
    assert result.by_source["fine"].status == "ok"


def test_caller_cancellation_cancels_every_source():
    slow = [Fixed("a", delay=10), Fixed("b", delay=10)]

    async def scenario():
        task = asyncio.create_task(Orchestrator(slow).enrich(URL))
        await asyncio.sleep(0.05)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    run(scenario())
    assert all(source.cancelled for source in slow)


def test_latency_and_budget_are_reported():
    result = run(Orchestrator([Fixed("a", delay=0.1)], budget_s=1).enrich(URL))
    assert result.budget_ms == 1000
    assert 90 <= result.latency_ms < 1000


# --------------------------------------------------------------------------- #
# Opt-in, choix des sources, domaine
# --------------------------------------------------------------------------- #


def test_disabled_enrichment_calls_no_source():
    sources = [Fixed("a"), Fixed("b")]
    result = run(Orchestrator(sources).enrich(URL, enabled=False))
    assert (result.enrichment, result.signals, result.latency_ms) == ("skipped", (), 0)
    assert all(source.calls == [] for source in sources)


def test_sources_can_be_selected():
    sources = [Fixed("a"), Fixed("b"), Fixed("c")]
    result = run(Orchestrator(sources).enrich(URL, sources={"a", "c"}))
    assert [s.source for s in result.signals] == ["a", "c"]
    assert sources[1].calls == []
    with pytest.raises(ValueError, match="inconnues"):
        run(Orchestrator(sources).enrich(URL, sources={"shodan"}))


def test_registered_domain_is_derived_from_the_url():
    source = Fixed("a")
    run(Orchestrator([source]).enrich("https://login.secure.example.co.uk/x"))
    assert source.calls == [("https://login.secure.example.co.uk/x", "example.co.uk")]
    run(Orchestrator([source]).enrich(URL, domain="override.test"))
    assert source.calls[-1] == (URL, "override.test")


@pytest.mark.parametrize("url", ["", "not a url", "javascript:alert(1)"])
def test_invalid_url_gives_an_empty_domain(url):
    assert registered_domain(url) == ""


def test_no_source_at_all():
    result = run(Orchestrator([]).enrich(URL))
    assert (result.signals, result.enrichment) == ((), "used")


def test_invalid_configuration_is_rejected():
    with pytest.raises(ValueError, match="budget"):
        Orchestrator([], budget_s=0)
    with pytest.raises(ValueError, match="double"):
        Orchestrator([Fixed("a"), Fixed("a")])


# --------------------------------------------------------------------------- #
# Construction depuis la configuration : client partagé
# --------------------------------------------------------------------------- #


def test_from_settings_shares_one_client_and_closes_it(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    orchestrator = Orchestrator.from_settings(Settings())
    http_sources = [e for e in orchestrator.enrichers if isinstance(e, HttpEnricher)]
    clients = {id(e._client) for e in http_sources}
    assert len(http_sources) == 5 and len(clients) == 1
    assert orchestrator.sources == (
        "google_safe_browsing",
        "virustotal",
        "urlscan",
        "rdap",
        "dns",
        "certificate_transparency",
    )

    async def scenario():
        async with orchestrator:
            pass
        return http_sources[0]._client.is_closed

    assert run(scenario()) is True


@respx.mock
def test_end_to_end_without_keys_only_keyless_sources_answer(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    for var in ("GSB_API_KEY", "VT_API_KEY", "URLSCAN_API_KEY", "CRTSH_ENABLED"):
        monkeypatch.delenv(var, raising=False)
    respx.get("https://data.iana.org/rdap/dns.json").mock(
        return_value=httpx.Response(
            200, json={"services": [[["com"], ["https://rdap.verisign.com/com/v1/"]]]}
        )
    )
    # Le domaine enregistré de login.example.com est interrogé, pas l'hôte complet.
    rdap = respx.get("https://rdap.verisign.com/com/v1/domain/example.com").mock(
        return_value=httpx.Response(404)
    )

    async def no_dns(name, rdtype):
        return 0, []

    async def scenario():
        async with Orchestrator.from_settings(Settings()) as orchestrator:
            dns = next(e for e in orchestrator.enrichers if e.name == "dns")
            dns._lookup = no_dns
            return await orchestrator.enrich("https://login.example.com/verify")

    result = run(scenario())
    assert rdap.called
    statuses = {s.source: (s.status, s.evidence.get("reason")) for s in result.signals}
    assert statuses["google_safe_browsing"] == ("skipped", "disabled")
    assert statuses["virustotal"] == ("skipped", "disabled")
    assert statuses["urlscan"] == ("skipped", "disabled")
    assert statuses["certificate_transparency"] == ("skipped", "disabled")
    assert statuses["rdap"][0] == "ok" and statuses["dns"][0] == "ok"
    assert all(isinstance(s, Signal) for s in result.signals)
