"""Vie privée et dégradation de l'analyse complète d'une URL (étape 2.12).

- **Vie privée** : sans enrichissement, aucune requête ne part, ni HTTP ni DNS ni même
  une ouverture de socket. Avec l'enrichissement, ce qui part est le strict nécessaire.
- **Dégradation** : toutes les sources en panne, le verdict du modèle seul est renvoyé.
"""

import asyncio
import json
import socket
import time

import httpx
import numpy as np
import pytest
import respx

from phishguard.analysis import UrlAnalyzer
from phishguard.config import Settings
from phishguard.enrichers.orchestrator import Orchestrator
from phishguard.fusion.calibration import ScoreCalibrator
from phishguard.fusion.score import fuse
from phishguard.urls.features import InvalidUrlError

KEY = "privacy-test-key-not-a-real-secret"
# Une URL de phishing typique : identifiants, adresse de la victime, jeton dans le fragment.
URL = "https://alice:s3cret-pass@login.example.com/verify?email=victim%40mail.test#token-42"
BOOTSTRAP = {"services": [[["com"], ["https://rdap.verisign.com/com/v1/"]]]}


def run(coro):
    return asyncio.run(coro)


class FixedModel:
    """Modèle URL simulé : le même score pour toutes les URLs."""

    def __init__(self, score):
        self.value = score
        self.calls = 0

    def score(self, urls):
        self.calls += 1
        return np.array([self.value for _ in urls])


class NetworkGuard:
    """Fait échouer toute tentative d'accès au réseau, HTTP, DNS ou socket brute."""

    def __init__(self, monkeypatch):
        self.attempts = []

        def refuse(kind):
            def blocked(*args, **kwargs):
                self.attempts.append(kind)
                raise AssertionError(f"accès réseau interdit : {kind}")

            return blocked

        monkeypatch.setattr(socket, "getaddrinfo", refuse("getaddrinfo"))
        monkeypatch.setattr(socket.socket, "connect", refuse("connect"))
        monkeypatch.setattr(socket.socket, "connect_ex", refuse("connect_ex"))
        monkeypatch.setattr(socket.socket, "sendto", refuse("sendto"))
        monkeypatch.setattr(httpx.AsyncClient, "send", refuse("httpx.send"))


@pytest.fixture
def keyed_env(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    for var in ("GSB_API_KEY", "VT_API_KEY", "URLSCAN_API_KEY"):
        monkeypatch.setenv(var, KEY)
    monkeypatch.setenv("CRTSH_ENABLED", "true")


def orchestrator(dns_lookup=None, budget_s=2.5):
    orch = Orchestrator.from_settings(Settings(), budget_s=budget_s)
    if dns_lookup is not None:
        next(e for e in orch.enrichers if e.name == "dns")._lookup = dns_lookup
    return orch


# --------------------------------------------------------------------------- #
# Vie privée : enrichissement désactivé, aucune requête sortante
# --------------------------------------------------------------------------- #


def test_without_enrichment_nothing_leaves_the_machine(keyed_env, monkeypatch):
    """Critère de l'étape : toutes les sources configurées, mais aucune n'est appelée."""
    orch = orchestrator()  # six sources prêtes, clés présentes
    guard = NetworkGuard(monkeypatch)
    model = FixedModel(0.9)

    async def scenario():
        async with orch:
            return await UrlAnalyzer(model, orchestrator=orch).analyze(URL)

    analysis = run(scenario())
    assert guard.attempts == []
    assert analysis.enrichment.enrichment == "skipped"
    assert analysis.enrichment.signals == ()
    assert (analysis.verdict, analysis.score, model.calls) == ("phishing", 90, 1)


def test_enrichment_is_off_by_default(keyed_env):
    with respx.mock:
        respx.route().mock(side_effect=AssertionError("requête sortante sans opt-in"))

        async def scenario():
            async with orchestrator() as orch:
                return await UrlAnalyzer(FixedModel(0.1), orchestrator=orch).analyze(URL)

        assert run(scenario()).enrichment.enrichment == "skipped"
        assert not respx.calls


def test_analysis_without_any_orchestrator_is_local(monkeypatch):
    guard = NetworkGuard(monkeypatch)
    analysis = run(UrlAnalyzer(FixedModel(0.5)).analyze(URL, enrichment=True))
    assert guard.attempts == [] and analysis.enrichment.enrichment == "skipped"


# --------------------------------------------------------------------------- #
# Vie privée : avec enrichissement, le strict nécessaire
# --------------------------------------------------------------------------- #


@respx.mock
def test_what_is_sent_when_enrichment_is_enabled(keyed_env):
    respx.get("https://data.iana.org/rdap/dns.json").mock(
        return_value=httpx.Response(200, json=BOOTSTRAP)
    )
    respx.get(url__startswith="https://safebrowsing.googleapis.com/").mock(
        return_value=httpx.Response(200, content=b"")  # protobuf vide : aucune menace
    )
    respx.get(url__startswith="https://urlscan.io/").mock(
        return_value=httpx.Response(200, json={"results": [], "total": 0})
    )
    respx.get(url__startswith="https://crt.sh/").mock(return_value=httpx.Response(200, json=[]))
    respx.route().mock(return_value=httpx.Response(404))
    queried_names = []

    async def dns_lookup(name, rdtype):
        queried_names.append(name)
        return 300, []

    async def scenario():
        async with orchestrator(dns_lookup) as orch:
            return await UrlAnalyzer(FixedModel(0.2), orchestrator=orch).analyze(
                URL, enrichment=True
            )

    analysis = run(scenario())
    assert analysis.enrichment.enrichment == "used"

    sent = {}
    for call in respx.calls:
        request = call.request
        text = str(request.url) + " " + request.content.decode("utf-8", "replace")
        text += " " + " ".join(f"{k}={v}" for k, v in request.headers.items() if k != "x-goog-api-key"
                               and k != "x-apikey" and k != "api-key")  # fmt: skip
        sent.setdefault(request.url.host, []).append(text)
        assert "s3cret-pass" not in text and "alice" not in text  # identifiants
        assert "token-42" not in text  # fragment
        assert KEY not in str(request.url)  # clé dans un en-tête, jamais dans l'URL

    # Les sources qui n'ont besoin que du domaine ne reçoivent ni le chemin ni la requête.
    for host in ("urlscan.io", "rdap.verisign.com", "crt.sh"):
        for text in sent[host]:
            assert "verify" not in text and "victim" not in text, (host, text)
    # Safe Browsing et VirusTotal reçoivent l'URL (documenté, opt-in), nettoyée.
    assert any("verify" in text for text in sent["safebrowsing.googleapis.com"])
    assert set(queried_names) == {"example.com"}  # DNS : le domaine enregistré seul


# --------------------------------------------------------------------------- #
# Dégradation : toutes les sources en panne
# --------------------------------------------------------------------------- #


@respx.mock
def test_all_sources_down_still_returns_the_model_verdict(keyed_env):
    """Critère de l'étape : le verdict du modèle seul est renvoyé."""
    respx.route().mock(side_effect=httpx.ConnectError("réseau coupé"))

    async def dns_down(name, rdtype):
        raise OSError("DNS injoignable")

    async def scenario():
        async with orchestrator(dns_down) as orch:
            return await UrlAnalyzer(FixedModel(0.85), orchestrator=orch).analyze(
                URL, enrichment=True
            )

    start = time.perf_counter()
    analysis = run(scenario())
    assert time.perf_counter() - start < 3.0
    assert analysis.enrichment.enrichment == "used"
    assert analysis.enrichment.usable == ()
    assert {s.status for s in analysis.enrichment.signals} == {"error"}
    alone = fuse(0.85)
    assert (analysis.score, analysis.verdict) == (alone.score, alone.verdict) == (85, "phishing")
    assert analysis.mitre  # un phishing garde ses techniques ATT&CK
    json.dumps(analysis.to_dict())


def test_slow_sources_degrade_within_the_budget(keyed_env):
    async def slow_dns(name, rdtype):
        await asyncio.sleep(10)

    with respx.mock:

        async def hang(request):
            await asyncio.sleep(10)
            return httpx.Response(200)

        respx.route().mock(side_effect=hang)

        async def scenario():
            async with orchestrator(slow_dns, budget_s=0.3) as orch:
                return await UrlAnalyzer(FixedModel(0.25), orchestrator=orch).analyze(
                    URL, enrichment=True
                )

        start = time.perf_counter()
        analysis = run(scenario())
    assert time.perf_counter() - start < 1.5
    assert set(analysis.enrichment.timed_out) == {
        "google_safe_browsing",
        "virustotal",
        "urlscan",
        "rdap",
        "dns",
        "certificate_transparency",
    }
    assert (analysis.score, analysis.verdict) == (25, "safe")


# --------------------------------------------------------------------------- #
# Assemblage : calibration, règles, techniques, sérialisation
# --------------------------------------------------------------------------- #


def test_calibration_is_applied_before_fusion():
    calibrator = ScoreCalibrator("isotonic", x=(0.0, 1.0), y=(0.0, 0.5))
    analysis = run(UrlAnalyzer(FixedModel(0.9), calibrator=calibrator).analyze(URL))
    assert analysis.model_score == 0.9 and analysis.calibrated
    assert analysis.model_probability == pytest.approx(0.45)
    assert (analysis.score, analysis.verdict) == (45, "suspicious")


def test_personal_lists_are_honoured():
    analyzer = UrlAnalyzer(FixedModel(0.95))
    assert run(analyzer.analyze(URL, allowlisted=True)).verdict == "safe"
    assert run(analyzer.analyze(URL, blocklisted=True)).fusion.hard_rule == "blocklist"


def test_mitre_techniques_follow_the_verdict():
    lookalike = "https://paypa1-login.com/verify/account"
    phishing = run(UrlAnalyzer(FixedModel(0.9)).analyze(lookalike))
    assert [t.id for t in phishing.mitre] == ["T1204.001", "T1598.003", "T1583.001"]
    assert run(UrlAnalyzer(FixedModel(0.05)).analyze(lookalike)).mitre == ()


def test_analysis_serializes_without_secrets(keyed_env):
    with respx.mock:
        respx.route().mock(return_value=httpx.Response(503))

        async def empty_dns(name, rdtype):
            return 0, []

        async def scenario():
            async with orchestrator(empty_dns) as orch:
                return await UrlAnalyzer(FixedModel(0.4), orchestrator=orch).analyze(
                    URL, enrichment=True
                )

        payload = json.dumps(run(scenario()).to_dict())
    assert KEY not in payload
    assert json.loads(payload)["enrichment"]["status"] == "used"


@pytest.mark.parametrize("url", ["", "not a url", "javascript:alert(1)"])
def test_invalid_url_is_an_input_error(url):
    with pytest.raises(InvalidUrlError):
        run(UrlAnalyzer(FixedModel(0.5)).analyze(url))
