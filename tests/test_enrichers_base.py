"""Tests du contrat commun des enrichisseurs (étape 2.2)."""

import asyncio

import httpx
import pytest
from pydantic import ValidationError

from phishguard.enrichers import Enricher, Signal, SignalStatus

URL, DOMAIN = "https://login.example.test/verify", "example.test"
SECRET = "test-key-not-a-real-secret"


def run(coro):
    return asyncio.run(coro)


class FakeEnricher(Enricher):
    """Faux enrichisseur : liste noire en mémoire."""

    name = "fake"

    def __init__(self, blocklist=(), enabled=True):
        self.blocklist = set(blocklist)
        self.enabled = enabled
        self.calls = []

    def is_enabled(self):
        return self.enabled

    async def _enrich(self, url, domain):
        self.calls.append((url, domain))
        listed = domain in self.blocklist
        return self.ok(risk=1.0 if listed else 0.0, evidence={"listed": listed})


class RaisingEnricher(Enricher):
    name = "raising"

    def __init__(self, exc):
        self.exc = exc

    async def _enrich(self, url, domain):
        raise self.exc


# --------------------------------------------------------------------------- #
# Signal
# --------------------------------------------------------------------------- #


def test_signal_defaults():
    signal = Signal(source="x", status="ok")
    assert signal.status is SignalStatus.OK
    assert (signal.risk, signal.evidence, signal.latency_ms) == (0.0, {}, 0)
    assert signal.usable


def test_signal_evidence_default_is_not_shared():
    a, b = Signal(source="a", status="ok"), Signal(source="b", status="ok")
    a.evidence["k"] = 1
    assert b.evidence == {}


@pytest.mark.parametrize(
    "kwargs",
    [
        {"risk": 1.5},
        {"risk": -0.1},
        {"latency_ms": -1},
        {"status": "unknown"},
        {"source": ""},
        {"unexpected": True},
    ],
)
def test_signal_rejects_invalid_values(kwargs):
    with pytest.raises(ValidationError):
        Signal(**{"source": "x", "status": "ok", **kwargs})


def test_signal_is_immutable_and_serializes_status_as_string():
    signal = Signal(source="x", status="timeout")
    with pytest.raises(ValidationError):
        signal.risk = 1.0
    assert signal.model_dump(mode="json")["status"] == "timeout"
    assert not signal.usable


# --------------------------------------------------------------------------- #
# Enricher : contrat respecté par un faux enrichisseur
# --------------------------------------------------------------------------- #


def test_fake_enricher_respects_the_interface():
    enricher = FakeEnricher(blocklist={DOMAIN})
    hit = run(enricher.enrich(URL, DOMAIN))
    miss = run(enricher.enrich("https://other.test/", "other.test"))
    assert isinstance(enricher, Enricher)
    assert (hit.source, hit.status, hit.risk, hit.evidence) == ("fake", "ok", 1.0, {"listed": True})
    assert (miss.status, miss.risk) == ("ok", 0.0)
    assert hit.latency_ms >= 0
    assert enricher.calls == [(URL, DOMAIN), ("https://other.test/", "other.test")]


def test_disabled_enricher_is_skipped_without_being_called():
    enricher = FakeEnricher(blocklist={DOMAIN}, enabled=False)
    signal = run(enricher.enrich(URL, DOMAIN))
    assert (signal.status, signal.risk, signal.evidence) == ("skipped", 0.0, {"reason": "disabled"})
    assert enricher.calls == []


def test_latency_is_measured():
    class Slow(Enricher):
        name = "slow"

        async def _enrich(self, url, domain):
            await asyncio.sleep(0.05)
            return self.ok()

    assert run(Slow().enrich(URL, DOMAIN)).latency_ms >= 40


# --------------------------------------------------------------------------- #
# Enricher : une exception interne devient un signal, jamais une exception
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "exc",
    [
        RuntimeError("boom"),
        ValueError("réponse JSON invalide"),
        KeyError("last_analysis_stats"),
        httpx.ConnectError("connexion refusée"),
        httpx.HTTPStatusError(
            "429", request=httpx.Request("GET", URL), response=httpx.Response(429)
        ),
    ],
)
def test_internal_exception_becomes_an_error_signal(exc):
    signal = run(RaisingEnricher(exc).enrich(URL, DOMAIN))
    assert signal.source == "raising"
    assert signal.status is SignalStatus.ERROR
    assert signal.risk == 0.0
    assert signal.evidence == {"error": type(exc).__name__}


@pytest.mark.parametrize(
    "exc", [TimeoutError(), httpx.ReadTimeout("lent"), httpx.ConnectTimeout("lent")]
)
def test_timeouts_become_a_timeout_signal(exc):
    signal = run(RaisingEnricher(exc).enrich(URL, DOMAIN))
    assert signal.status is SignalStatus.TIMEOUT
    assert signal.risk == 0.0


def test_error_signal_never_copies_the_exception_message():
    # Les erreurs HTTP contiennent l'URL de la requête, et parfois la clé d'API.
    exc = httpx.ConnectError(f"échec de https://api.example.test/v4?key={SECRET}")
    signal = run(RaisingEnricher(exc).enrich(URL, DOMAIN))
    assert SECRET not in signal.model_dump_json()


def test_cancellation_is_not_swallowed():
    # L'orchestrateur (étape 2.9) annule les sources trop lentes : l'annulation doit passer.
    with pytest.raises(asyncio.CancelledError):
        run(RaisingEnricher(asyncio.CancelledError()).enrich(URL, DOMAIN))


def test_wrong_return_type_becomes_an_error_signal():
    class Broken(Enricher):
        name = "broken"

        async def _enrich(self, url, domain):
            return {"risk": 1.0}

    signal = run(Broken().enrich(URL, DOMAIN))
    assert (signal.status, signal.evidence) == ("error", {"error": "TypeError"})


def test_invalid_risk_from_a_source_becomes_an_error_signal():
    class OutOfRange(Enricher):
        name = "out_of_range"

        async def _enrich(self, url, domain):
            return self.ok(risk=7.0)  # bug de normalisation dans la source

    signal = run(OutOfRange().enrich(URL, DOMAIN))
    assert (signal.status, signal.evidence) == ("error", {"error": "ValidationError"})


def test_source_and_risk_are_enforced_by_the_base_class():
    class Liar(Enricher):
        name = "liar"

        async def _enrich(self, url, domain):
            return Signal(source="virustotal", status="error", risk=0.9)

    signal = run(Liar().enrich(URL, DOMAIN))
    assert (signal.source, signal.status, signal.risk) == ("liar", "error", 0.0)


def test_expected_failures_have_a_readable_reason():
    class QuotaExceeded(Enricher):
        name = "quota"

        async def _enrich(self, url, domain):
            return self.error("quota_exceeded")

    signal = run(QuotaExceeded().enrich(URL, DOMAIN))
    assert (signal.status, signal.evidence) == ("error", {"reason": "quota_exceeded"})


# --------------------------------------------------------------------------- #
# Enricher : erreurs de définition détectées à l'import
# --------------------------------------------------------------------------- #


def test_subclass_without_name_is_rejected():
    with pytest.raises(TypeError, match="name"):

        class Nameless(Enricher):
            async def _enrich(self, url, domain):
                return self.ok()


def test_subclass_overriding_enrich_is_rejected():
    with pytest.raises(TypeError, match="enrich"):

        class Unsafe(Enricher):
            name = "unsafe"

            async def enrich(self, url, domain):
                return Signal(source="unsafe", status="ok")

            async def _enrich(self, url, domain):
                return self.ok()


def test_synchronous_enrich_is_rejected():
    with pytest.raises(TypeError, match="coroutine"):

        class Blocking(Enricher):
            name = "blocking"

            def _enrich(self, url, domain):
                return self.ok()


def test_abstract_intermediate_class_is_allowed():
    class KeyedEnricher(Enricher):
        """Base intermédiaire sans nom, encore abstraite."""

        def is_enabled(self):
            return False

    class Concrete(KeyedEnricher):
        name = "concrete"

        async def _enrich(self, url, domain):
            return self.ok()

    with pytest.raises(TypeError):
        KeyedEnricher()
    assert run(Concrete().enrich(URL, DOMAIN)).status == "skipped"
