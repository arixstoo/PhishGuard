"""Schéma de la réponse d'analyse (étape 2.11 bis).

C'est le **contrat** entre le moteur et ses clients : l'API (module 4), l'extension et le
bot (module 5) en dépendent. Il est donc strict (aucun champ inconnu, types et bornes
vérifiés) et versionné par :data:`SCHEMA_VERSION`, en suivant le versionnage sémantique :

- ajout d'un champ **facultatif** : version mineure (``1.1.0``), les clients existants
  continuent de fonctionner ;
- suppression, renommage ou changement de sens d'un champ : version majeure (``2.0.0``).

Le schéma JSON correspondant est versionné dans ``docs/schema/analysis-response.v1.json``
(``make schema`` le régénère, un test vérifie qu'il est à jour). La description complète
des champs est dans ``docs/response-schema.md``.

Les réponses sont construites par :meth:`AnalysisResponse.from_url_analysis` (URL) ; les
analyses de SMS et d'emails rempliront le même contrat au module 4.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from phishguard.enrichers.base import SignalStatus
from phishguard.fusion.mitre import Channel
from phishguard.fusion.score import MODEL, FusionResult, Thresholds, Verdict

if TYPE_CHECKING:
    from phishguard.analysis import UrlAnalysis

SCHEMA_VERSION = "1.0.0"
Confidence = Literal["low", "medium", "high"]
Enrichment = Literal["used", "skipped"]

# Écart au seuil le plus proche (en points de score) à partir duquel un verdict sûr ou
# phishing est donné avec une confiance moyenne, puis haute.
CONFIDENCE_MARGINS = {"medium": 10, "high": 20}
# Une contribution plus petite (en points de score) n'est pas citée comme raison.
MIN_REASON_POINTS = 0.5

HARD_RULE_MESSAGES = {
    "blocklist": "Le domaine figure dans votre liste noire personnelle.",
    "google_safe_browsing": "Google Safe Browsing signale cette page comme dangereuse.",
    "allowlist": "Le domaine figure dans votre liste blanche personnelle.",
}
SIGNAL_MESSAGES = {
    "virustotal": "Des moteurs antivirus de VirusTotal signalent cette adresse.",
    "urlscan": "urlscan.io a jugé la page suspecte lors d'une visite isolée.",
    "rdap": "Le domaine a été enregistré récemment.",
    "dns": "La configuration DNS du domaine ressemble à celle de domaines jetables.",
    "certificate_transparency": "Le premier certificat du domaine est très récent.",
}


class _Strict(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class Reason(_Strict):
    """Une raison du verdict. Le code est stable ; le message peut être reformulé."""

    code: str = Field(min_length=1, pattern=r"^[a-z0-9_]+(\.[a-z0-9_]+)*$")
    source: str = Field(min_length=1)
    points: float = Field(ge=0, le=100, description="Part du score attribuée à cette raison")
    message: str = Field(min_length=1)


class SignalOut(_Strict):
    """Réponse d'une source de Threat Intelligence (étapes 2.4 à 2.7)."""

    status: SignalStatus
    risk: float = Field(ge=0, le=1)
    latency_ms: int = Field(ge=0)
    evidence: dict[str, Any] = Field(default_factory=dict)


class TechniqueOut(_Strict):
    """Technique MITRE ATT&CK illustrée par la détection (étape 2.11)."""

    id: str = Field(pattern=r"^T\d{4}(\.\d{3})?$")
    name: str = Field(min_length=1)
    tactic: str = Field(min_length=1)
    url: str = Field(pattern=r"^https://attack\.mitre\.org/techniques/")
    reason: str = Field(min_length=1)


class AnalysisResponse(_Strict):
    """Réponse d'une analyse, quel que soit le canal (URL, SMS, email)."""

    schema_version: str = Field(default=SCHEMA_VERSION, pattern=r"^\d+\.\d+\.\d+$")
    channel: Channel
    verdict: Verdict
    score: int = Field(ge=0, le=100)
    confidence: Confidence
    reasons: list[Reason]
    signals: dict[str, SignalOut] = Field(description="Une entrée par source interrogée")
    mitre: list[TechniqueOut]
    model_version: str = Field(min_length=1)
    fusion_version: str = Field(pattern=r"^\d+\.\d+\.\d+$")
    enrichment: Enrichment
    latency_ms: int = Field(ge=0)

    @model_validator(mode="after")
    def _consistent(self) -> AnalysisResponse:
        # Critère de l'étape 2.11 : tout verdict phishing nomme au moins une technique.
        if self.verdict == "phishing" and not self.mitre:
            raise ValueError("un verdict phishing doit citer au moins une technique ATT&CK")
        if self.verdict == "safe" and self.mitre:
            raise ValueError("un verdict sûr ne cite aucune technique ATT&CK")
        if self.enrichment == "skipped" and self.signals:
            raise ValueError("sans enrichissement, aucune source n'a pu répondre")
        return self

    # ------------------------------------------------------------------ #

    @classmethod
    def from_url_analysis(
        cls, analysis: UrlAnalysis, *, model_version: str | None = None
    ) -> AnalysisResponse:
        """Réponse d'une analyse d'URL. ``model_version`` remplace celle du modèle analysé."""
        fusion = analysis.fusion
        return cls(
            channel="url",
            verdict=analysis.verdict,
            score=analysis.score,
            confidence=confidence(fusion, Thresholds(**fusion.thresholds)),
            reasons=reasons(fusion),
            signals={
                s.source: SignalOut(
                    status=s.status, risk=s.risk, latency_ms=s.latency_ms, evidence=s.evidence
                )
                for s in analysis.enrichment.signals
            },
            mitre=[TechniqueOut(**t.to_dict()) for t in analysis.mitre],
            model_version=model_version or analysis.model_version,
            fusion_version=fusion.config_version,
            enrichment=analysis.enrichment.enrichment,
            latency_ms=analysis.latency_ms,
        )

    def to_json(self) -> str:
        return self.model_dump_json()


def confidence(fusion: FusionResult, thresholds: Thresholds) -> Confidence:
    """Confiance dans le verdict, d'après son écart aux seuils de décision.

    - règle dure appliquée (Safe Browsing, listes personnelles) : ``high`` ;
    - verdict ``suspicious`` : ``low``, par définition (la zone d'incertitude) ;
    - sinon, écart au seuil le plus proche : 20 points ou plus ``high``, 10 ou plus
      ``medium``, moins ``low``. Avec les seuils 30 et 70 : un score de 5 ou de 95 donne
      ``high``, 25 ou 75 donne ``low``.
    """
    if fusion.hard_rule is not None:
        return "high"
    if fusion.verdict == "suspicious":
        return "low"
    margin = min(abs(fusion.score - thresholds.suspicious), abs(fusion.score - thresholds.phishing))
    if margin >= CONFIDENCE_MARGINS["high"]:
        return "high"
    if margin >= CONFIDENCE_MARGINS["medium"]:
        return "medium"
    return "low"


def reasons(fusion: FusionResult) -> list[Reason]:
    """Raisons du verdict, de la plus forte à la plus faible.

    Une règle dure est l'unique raison. Sinon, chaque source qui a fait monter le score
    (au moins un demi-point) est citée avec sa part du score. Les phrases restent
    sobres : le module 3 (explicabilité) les détaillera.
    """
    if fusion.hard_rule is not None:
        points = 100.0 if fusion.verdict == "phishing" else 0.0
        message = HARD_RULE_MESSAGES.get(fusion.hard_rule, f"Règle appliquée : {fusion.hard_rule}.")
        return [
            Reason(
                code=f"hard_rule.{fusion.hard_rule}",
                source=fusion.hard_rule,
                points=points,
                message=message,
            )
        ]
    found = []
    for c in fusion.contributions:  # déjà triées par points décroissants
        if c.points < MIN_REASON_POINTS:
            continue
        if c.source == MODEL:
            message = f"Le modèle local estime la probabilité de phishing à {c.risk:.0%}."
            code = "model"
        else:
            message = SIGNAL_MESSAGES.get(c.source, f"La source {c.source} signale un risque.")
            code = f"signal.{c.source}"
        found.append(
            Reason(
                code=code, source=c.source, points=round(min(c.points, 100.0), 1), message=message
            )
        )
    return found


def json_schema() -> dict[str, Any]:
    """Schéma JSON (draft 2020-12) de :class:`AnalysisResponse`, tel que versionné."""
    schema = AnalysisResponse.model_json_schema(mode="serialization")
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    schema["$id"] = (
        f"https://github.com/arixstoo/PhishGuard/schema/analysis-response/{SCHEMA_VERSION}"
    )
    return schema


def json_schema_text() -> str:
    return json.dumps(json_schema(), indent=2, ensure_ascii=False, sort_keys=True) + "\n"
