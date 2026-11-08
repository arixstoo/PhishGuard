"""Tests du schéma de réponse (étape 2.11 bis).

Le schéma est un contrat : l'extension et le bot en dépendront. Ces tests figent ses
champs, vérifient ses règles de cohérence et que le schéma JSON versionné est à jour.
"""

import asyncio
import json
from pathlib import Path

import numpy as np
import pytest
from pydantic import ValidationError

from phishguard.analysis import UrlAnalyzer
from phishguard.enrichers import Signal
from phishguard.enrichers.orchestrator import EnrichmentResult
from phishguard.explain.reasons import ReasonBuilder
from phishguard.fusion.score import default_config, fuse
from phishguard.schema import (
    SCHEMA_VERSION,
    AnalysisResponse,
    confidence,
    json_schema_text,
    reasons,
)

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_FILE = ROOT / "docs/schema/analysis-response.v1.json"
URL = "https://login.example.com/verify"
# Champs exigés par le cahier des charges (étape 2.11 bis), plus les trois du projet.
SPEC_FIELDS = {
    "verdict",
    "score",
    "confidence",
    "reasons",
    "signals",
    "mitre",
    "model_version",
    "enrichment",
    "latency_ms",
}
PROJECT_FIELDS = {"schema_version", "channel", "fusion_version"}
# Ajoutés par la version 1.1.0 (étape 3.2).
EXPLANATION_FIELDS = {"language", "advice"}


class FixedModel:
    def __init__(self, score):
        self.value = score
        self.metadata = {"model_version": "url_test"}

    def score(self, urls):
        return np.array([self.value for _ in urls])


class FixedOrchestrator:
    """Orchestrateur simulé : renvoie des signaux donnés, sans réseau."""

    budget_s = 2.5

    def __init__(self, *signals):
        self.signals = signals

    async def enrich(self, url, domain):
        return EnrichmentResult(self.signals, "used", 12, 2500)


def analyze(score, *signals, **options):
    orchestrator = FixedOrchestrator(*signals) if signals else None
    analyzer = UrlAnalyzer(FixedModel(score), orchestrator=orchestrator)
    return asyncio.run(analyzer.analyze(URL, enrichment=bool(signals), **options))


def ok(source, risk, **evidence):
    return Signal(source=source, status="ok", risk=risk, evidence=evidence, latency_ms=40)


# --------------------------------------------------------------------------- #
# Contrat : les champs du cahier des charges, et rien d'autre
# --------------------------------------------------------------------------- #


def test_response_has_exactly_the_contract_fields():
    payload = json.loads(analyze(0.9).to_response().to_json())
    assert set(payload) == SPEC_FIELDS | PROJECT_FIELDS | EXPLANATION_FIELDS
    assert payload["schema_version"] == SCHEMA_VERSION
    assert payload["channel"] == "url"
    assert payload["model_version"] == "url_test"
    assert payload["fusion_version"] == default_config().version


def test_enriched_phishing_response():
    analysis = analyze(0.2, ok("rdap", 1.0, age_days=3), ok("virustotal", 1.0))
    response = analysis.to_response()
    assert (response.verdict, response.score, response.enrichment) == ("phishing", 97, "used")
    assert set(response.signals) == {"rdap", "virustotal"}
    assert response.signals["rdap"].evidence == {"age_days": 3}
    codes = [r.code for r in response.reasons]
    assert codes == ["signal.virustotal", "signal.domain_age", "model"]
    assert response.reasons[1].params == {"n": 3}
    assert "3 jours" in response.reasons[1].message
    assert sum(r.points for r in response.reasons) == pytest.approx(97, abs=0.5)
    assert any(t.id == "T1583.001" for t in response.mitre)  # domaine de 3 jours


def test_local_only_response_has_no_signals():
    response = analyze(0.05).to_response()
    assert (response.verdict, response.enrichment, response.signals) == ("safe", "skipped", {})
    assert response.mitre == []


def test_failed_sources_are_listed_but_give_no_reason():
    down = Signal(source="urlscan", status="timeout")
    response = analyze(0.5, down).to_response()
    assert response.signals["urlscan"].status == "timeout"
    assert [r.code for r in response.reasons] == ["model"]


def test_hard_rule_is_the_only_reason():
    response = analyze(0.01, ok("google_safe_browsing", 1.0, listed=True)).to_response()
    assert response.verdict == "phishing" and response.confidence == "high"
    (reason,) = response.reasons
    assert (reason.code, reason.points) == ("hard_rule.google_safe_browsing", 100)
    allow = analyze(0.95, allowlisted=True).to_response()
    assert [(r.code, r.points) for r in allow.reasons] == [("hard_rule.allowlist", 0)]


def test_response_round_trips_through_json():
    response = analyze(0.2, ok("rdap", 1.0, age_days=3), ok("virustotal", 1.0)).to_response()
    assert AnalysisResponse.model_validate_json(response.to_json()) == response


def test_model_version_falls_back_when_the_model_has_none():
    class Bare:
        def score(self, urls):
            return np.array([0.1])

    analysis = asyncio.run(UrlAnalyzer(Bare()).analyze(URL))
    assert analysis.to_response().model_version == "unknown"
    assert AnalysisResponse.from_url_analysis(analysis, model_version="v9").model_version == "v9"


# --------------------------------------------------------------------------- #
# Confiance
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("probability", "expected"),
    [
        (0.05, "high"),  # 25 points sous le seuil de 30
        (0.10, "high"),
        (0.15, "medium"),
        (0.25, "low"),  # trop près du seuil
        (0.50, "low"),  # suspect : la zone d'incertitude
        (0.75, "low"),
        (0.80, "medium"),
        (0.95, "high"),
    ],
)
def test_confidence_follows_the_distance_to_the_thresholds(probability, expected):
    assert confidence(fuse(probability), default_config().thresholds) == expected


def test_small_contributions_are_not_reasons():
    result = fuse(0.004)  # 0,4 point
    assert reasons(ReasonBuilder().for_fusion(result)) == []


def test_response_always_carries_an_advice_in_the_requested_language():
    for score in (0.05, 0.5, 0.95):
        analysis = analyze(score)
        french, english = analysis.to_response(), analysis.to_response("en")
        assert french.language == "fr" and english.language == "en"
        assert french.advice and english.advice and french.advice != english.advice
    with pytest.raises(ValueError):
        analyze(0.5).to_response("de")


# --------------------------------------------------------------------------- #
# Règles de cohérence : une réponse incohérente est refusée
# --------------------------------------------------------------------------- #


def _payload(**overrides):
    payload = json.loads(analyze(0.9).to_response().to_json())
    payload.update(overrides)
    return payload


@pytest.mark.parametrize(
    "overrides",
    [
        {"mitre": []},  # phishing sans technique (critère de l'étape 2.11)
        {"verdict": "safe"},  # sûr, mais avec des techniques
        {"signals": {"dns": {"status": "ok", "risk": 0.2, "latency_ms": 3}}},  # sans enrichissement
        {"score": 101},
        {"confidence": "certain"},
        {"enrichment": "partial"},
        {"channel": "fax"},
        {"schema_version": "v1"},
        {"unexpected": True},  # aucun champ inconnu
        {"advice": ""},  # le conseil est obligatoire (1.1.0)
        {"language": "de"},
        {"reasons": [{"code": "model", "source": "model", "points": 1, "message": "m"}] * 4},
        {"mitre": [{"id": "X1", "name": "n", "tactic": "t", "url": "https://x", "reason": "r"}]},
    ],
)
def test_inconsistent_responses_are_rejected(overrides):
    with pytest.raises(ValidationError):
        AnalysisResponse.model_validate(_payload(**overrides))


def test_response_is_immutable():
    response = analyze(0.9).to_response()
    with pytest.raises(ValidationError):
        response.score = 0


# --------------------------------------------------------------------------- #
# Schéma JSON versionné
# --------------------------------------------------------------------------- #


def test_versioned_json_schema_is_up_to_date():
    assert SCHEMA_FILE.read_text(encoding="utf-8") == json_schema_text(), (
        "schéma JSON périmé : lancez `make schema` et commitez docs/schema/"
    )


def test_json_schema_requires_the_contract_fields():
    schema = json.loads(SCHEMA_FILE.read_text(encoding="utf-8"))
    assert set(schema["required"]) >= SPEC_FIELDS
    assert schema["additionalProperties"] is False
    assert schema["$id"].endswith(SCHEMA_VERSION)
