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

Historique :

- ``1.1.0`` (étape 3.2) : raisons en langage simple, au plus trois, avec leurs variables
  (``params``) ; ``language`` et ``advice`` (conseil d'action, toujours présent) ajoutés ;
- ``1.0.0`` (étape 2.11 bis) : contrat initial.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from phishguard.enrichers.base import SignalStatus
from phishguard.explain.reasons import (
    DEFAULT_LANGUAGE,
    MAX_REASONS,
    Explanation,
    Language,
    ReasonBuilder,
)
from phishguard.fusion.mitre import Channel
from phishguard.fusion.score import FusionResult, Thresholds, Verdict

if TYPE_CHECKING:
    from phishguard.analysis import UrlAnalysis

SCHEMA_VERSION = "1.1.0"
Confidence = Literal["low", "medium", "high"]
Enrichment = Literal["used", "skipped"]

# Écart au seuil le plus proche (en points de score) à partir duquel un verdict sûr ou
# phishing est donné avec une confiance moyenne, puis haute.
CONFIDENCE_MARGINS = {"medium": 10, "high": 20}
MESSAGE_MAX_LENGTH = 300


class _Strict(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class Reason(_Strict):
    """Une raison du verdict, en langage simple (étape 3.2).

    Le ``code`` est stable : un client peut s'en servir pour traduire ou choisir une
    icône, avec les variables de ``params``. Le ``message`` est déjà rédigé dans la langue
    de la réponse et peut être reformulé d'une version à l'autre. C'est du **texte
    brut** : à insérer comme texte, jamais comme HTML.
    """

    code: str = Field(min_length=1, pattern=r"^[a-z0-9_]+(\.[a-z0-9_]+)*$")
    source: str = Field(min_length=1)
    points: float = Field(ge=0, le=100, description="Part du score attribuée à cette raison")
    message: str = Field(min_length=1, max_length=MESSAGE_MAX_LENGTH)
    params: dict[str, str | int] = Field(
        default_factory=dict, description="Variables de la phrase (marque, nombre de jours…)"
    )


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
    reasons: list[Reason] = Field(
        max_length=MAX_REASONS, description="Au plus trois raisons, de la plus forte"
    )
    signals: dict[str, SignalOut] = Field(description="Une entrée par source interrogée")
    mitre: list[TechniqueOut]
    model_version: str = Field(min_length=1)
    fusion_version: str = Field(pattern=r"^\d+\.\d+\.\d+$")
    enrichment: Enrichment
    latency_ms: int = Field(ge=0)
    language: Language = Field(default=DEFAULT_LANGUAGE, description="Langue des phrases")
    advice: str = Field(
        min_length=1,
        max_length=MESSAGE_MAX_LENGTH,
        description="Conseil d'action, toujours présent, selon le canal et le verdict",
    )

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
        cls,
        analysis: UrlAnalysis,
        *,
        model_version: str | None = None,
        language: str = DEFAULT_LANGUAGE,
    ) -> AnalysisResponse:
        """Réponse d'une analyse d'URL. ``model_version`` remplace celle du modèle analysé ;
        ``language`` choisit la langue des raisons et du conseil (``fr``, ``en``, ``ar``)."""
        fusion = analysis.fusion
        explanation = ReasonBuilder(language).for_fusion(
            fusion,
            channel="url",
            signals=analysis.enrichment.signals,
            url=analysis.url,
            explanation=analysis.explanation,
        )
        return cls(
            channel="url",
            verdict=analysis.verdict,
            score=analysis.score,
            confidence=confidence(fusion, Thresholds(**fusion.thresholds)),
            reasons=reasons(explanation),
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
            language=explanation.language,
            advice=explanation.advice,
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


def reasons(explanation: Explanation) -> list[Reason]:
    """Raisons du contrat, à partir de l'explication de l'étape 3.2
    (:class:`~phishguard.explain.reasons.ReasonBuilder`)."""
    return [
        Reason(
            code=r.code, source=r.source, points=r.points, message=r.message, params=dict(r.params)
        )
        for r in explanation.reasons
    ]


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
