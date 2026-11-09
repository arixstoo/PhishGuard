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

Les réponses sont construites par :meth:`AnalysisResponse.from_url_analysis` (URL),
:meth:`AnalysisResponse.from_text_analysis` (SMS, messageries, étape 3.3) et
:meth:`AnalysisResponse.from_email_analysis` (email, étape 3.12).

Historique :

- ``1.3.0`` (étape 3.12) : ``analyst.normalization``, facultatif (ce que la
  normalisation de l'étape 3.8 a changé, en comptes, et l'alerte d'hôte) ; réponses
  du canal ``email`` ;
- ``1.2.0`` (étape 3.4) : vue analyste ``analyst``, facultative (modèle, explication,
  fusion, versions) ;
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
    FRAGMENT_MAX_LENGTH,
    MAX_REASONS,
    Explanation,
    Language,
    ReasonBuilder,
    load_templates,
    safe_fragment,
)
from phishguard.fusion.mitre import Channel
from phishguard.fusion.score import FusionResult, Thresholds, Verdict

if TYPE_CHECKING:
    from phishguard.analysis import EmailAnalysis, TextAnalysis, UrlAnalysis
    from phishguard.explain.shap_url import UrlExplanation
    from phishguard.explain.text import TextExplanation
    from phishguard.security.normalize import NormalizationReport

SCHEMA_VERSION = "1.3.0"
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


# --------------------------------------------------------------------------- #
# Vue analyste (étape 3.4)
# --------------------------------------------------------------------------- #

ANALYST_TERMS = 10  # mots les plus influents dans chaque sens (texte)
ExplanationMethod = Literal["tree_shap", "linear"]
ExplanationSpace = Literal["log_odds", "probability", "margin"]


class FeatureOut(_Strict):
    """Une feature du modèle URL : sa valeur et sa contribution SHAP (étape 3.1)."""

    name: str = Field(min_length=1)
    value: float
    contribution: float


class TermOut(_Strict):
    """Un mot du message et sa contribution au score (étape 3.3), nettoyé comme les
    raisons : à afficher comme texte, jamais comme HTML."""

    term: str = Field(min_length=1, max_length=FRAGMENT_MAX_LENGTH)
    contribution: float


class ExplanationOut(_Strict):
    """Décomposition du score brut du modèle : ``base_value + somme des contributions``.

    ``features`` (URL) les donne toutes, de la plus forte en valeur absolue à la plus
    faible ; ``terms_phishing`` et ``terms_safe`` (texte) les mots les plus influents dans
    chaque sens.
    """

    method: ExplanationMethod
    space: ExplanationSpace
    base_value: float
    output: float = Field(description="Score brut du modèle, dans ``space``")
    features: list[FeatureOut] = Field(default_factory=list)
    terms_phishing: list[TermOut] = Field(default_factory=list, max_length=ANALYST_TERMS)
    terms_safe: list[TermOut] = Field(default_factory=list, max_length=ANALYST_TERMS)


class ModelOut(_Strict):
    """Sortie du modèle local, avant la fusion."""

    version: str = Field(min_length=1)
    raw_score: float = Field(description="Probabilité (URL) ou marge du SVM (texte)")
    probability: float = Field(ge=0, le=1, description="Après calibration (étape 2.10)")
    calibrated: bool
    thresholds: dict[str, float] = Field(
        default_factory=dict, description="Seuils de décision du modèle seul, sur son score brut"
    )


class ContributionOut(_Strict):
    """Part d'une source (ou du modèle) dans le score fusionné (étape 2.10)."""

    source: str = Field(min_length=1)
    risk: float = Field(ge=0, le=1)
    weight: float = Field(ge=0, le=1)
    points: float = Field(ge=0, le=100)


class FusionOut(_Strict):
    """Détail de la fusion : probabilité, seuils, règle dure, contributions."""

    probability: float = Field(ge=0, le=1)
    thresholds: dict[str, int]
    hard_rule: str | None = None
    contributions: list[ContributionOut] = Field(default_factory=list)
    ignored: list[str] = Field(default_factory=list, description="Sources non utilisables")


HostAlertOut = Literal["mixed_script_label", "lookalike_label"]


class NormalizationOut(_Strict):
    """Ce que la normalisation de l'étape 3.8 a changé dans l'entrée : des comptes.

    Une entrée modifiée est en soi un indice (caractères invisibles, homoglyphes) ; le
    contenu, lui, n'est jamais recopié.
    """

    changed: bool
    nfkc: bool = Field(description="NFKC a modifié l'entrée (pleine chasse, ligatures…)")
    format_chars: int = Field(ge=0, description="Caractères de format retirés (largeur nulle…)")
    control_chars: int = Field(ge=0, description="Caractères de contrôle retirés")
    confusables: int = Field(ge=0, description="Homoglyphes repliés vers le latin (texte)")
    host_alert: HostAlertOut | None = Field(
        default=None, description="Hôte qui imite des lettres latines (règle lookalike_host)"
    )
    version: str = Field(pattern=r"^\d+\.\d+\.\d+$")


class AnalystView(_Strict):
    """Ce que voit un analyste, ou l'utilisateur qui déplie « Détails techniques ».

    Les signaux bruts des sources restent dans ``signals`` (contrat 1.0.0) ; la vue
    analyste ajoute le modèle, son explication, la fusion et les versions.
    """

    model: ModelOut
    explanation: ExplanationOut | None = None
    fusion: FusionOut
    normalization: NormalizationOut | None = Field(
        default=None, description="Ce que la normalisation a changé (étape 3.12)"
    )
    versions: dict[str, str] = Field(
        description="Versions du schéma, du modèle, de la fusion, des gabarits, de l'explication"
    )


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
    analyst: AnalystView | None = Field(
        default=None,
        description="Détails techniques (étape 3.4) : à n'afficher qu'à la demande",
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
        if self.analyst is not None:
            if self.analyst.model.version != self.model_version:
                raise ValueError("la vue analyste décrit un autre modèle que la réponse")
            if self.analyst.versions.get("fusion") != self.fusion_version:
                raise ValueError("la vue analyste décrit une autre fusion que la réponse")
        return self

    # ------------------------------------------------------------------ #

    @classmethod
    def from_url_analysis(
        cls,
        analysis: UrlAnalysis,
        *,
        model_version: str | None = None,
        language: str = DEFAULT_LANGUAGE,
        analyst: bool = True,
    ) -> AnalysisResponse:
        """Réponse d'une analyse d'URL. ``model_version`` remplace celle du modèle analysé ;
        ``language`` choisit la langue des raisons et du conseil (``fr``, ``en``, ``ar``) ;
        ``analyst=False`` omet la vue analyste (un bot qui ne l'affiche jamais)."""
        fusion = analysis.fusion
        version = model_version or analysis.model_version
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
            model_version=version,
            fusion_version=fusion.config_version,
            enrichment=analysis.enrichment.enrichment,
            latency_ms=analysis.latency_ms,
            language=explanation.language,
            advice=explanation.advice,
            analyst=analyst_view(
                version=version,
                raw_score=analysis.model_score,
                probability=analysis.model_probability,
                calibrated=analysis.calibrated,
                thresholds=analysis.model_thresholds,
                fusion=fusion,
                language=explanation.language,
                explanation=url_explanation_out(analysis.explanation),
                normalization=normalization_out(analysis.normalization, analysis.host_alert),
            )
            if analyst
            else None,
        )

    @classmethod
    def from_text_analysis(
        cls,
        analysis: TextAnalysis,
        *,
        model_version: str | None = None,
        language: str = DEFAULT_LANGUAGE,
        analyst: bool = True,
    ) -> AnalysisResponse:
        """Réponse d'une analyse de message (étape 3.3). L'analyse est locale : aucun
        signal, enrichissement ``skipped``. ``analyst=False`` omet la vue analyste."""
        fusion = analysis.fusion
        version = model_version or analysis.model_version
        explanation = ReasonBuilder(language).for_fusion(
            fusion,
            channel=analysis.channel,
            text_explanation=analysis.explanation,
            model_code="text.model",
        )
        return cls(
            channel=analysis.channel,
            verdict=analysis.verdict,
            score=analysis.score,
            confidence=confidence(fusion, Thresholds(**fusion.thresholds)),
            reasons=reasons(explanation),
            signals={},
            mitre=[TechniqueOut(**t.to_dict()) for t in analysis.mitre],
            model_version=version,
            fusion_version=fusion.config_version,
            enrichment="skipped",
            latency_ms=analysis.latency_ms,
            language=explanation.language,
            advice=explanation.advice,
            analyst=analyst_view(
                version=version,
                raw_score=analysis.model_score,
                probability=analysis.model_probability,
                calibrated=analysis.calibrated,
                thresholds=analysis.model_thresholds,
                fusion=fusion,
                language=explanation.language,
                explanation=text_explanation_out(analysis.explanation),
                normalization=normalization_out(analysis.normalization),
            )
            if analyst
            else None,
        )

    @classmethod
    def from_email_analysis(
        cls,
        analysis: EmailAnalysis,
        *,
        model_version: str | None = None,
        language: str = DEFAULT_LANGUAGE,
        analyst: bool = True,
    ) -> AnalysisResponse:
        """Réponse d'une analyse d'email (étape 3.12). Le score vient des règles de
        l'étape 1.11, chacune avec sa raison ; une règle dure (hôte qui imite le latin)
        devient l'unique raison. L'analyse est locale : enrichissement ``skipped``."""
        fusion = analysis.fusion
        version = model_version or analysis.model_version
        builder = ReasonBuilder(language)
        if fusion.hard_rule is not None:
            explanation = builder.for_fusion(fusion, channel="email")
        else:
            explanation = builder.email_rules(analysis.triggered, fusion.verdict)
        return cls(
            channel="email",
            verdict=analysis.verdict,
            score=analysis.score,
            confidence=confidence(fusion, Thresholds(**fusion.thresholds)),
            reasons=reasons(explanation),
            signals={},
            mitre=[TechniqueOut(**t.to_dict()) for t in analysis.mitre],
            model_version=version,
            fusion_version=fusion.config_version,
            enrichment="skipped",
            latency_ms=analysis.latency_ms,
            language=explanation.language,
            advice=explanation.advice,
            analyst=analyst_view(
                version=version,
                raw_score=float(analysis.rule_score),
                probability=analysis.rule_score / 100,
                calibrated=False,
                thresholds={},
                fusion=fusion,
                language=explanation.language,
                explanation=None,
                normalization=normalization_out(analysis.normalization, analysis.host_alert),
            )
            if analyst
            else None,
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


def url_explanation_out(explanation: UrlExplanation | None) -> ExplanationOut | None:
    """Explication SHAP du modèle URL, toutes les features, par contribution absolue."""
    if explanation is None:
        return None
    ranked = sorted(explanation.attributions, key=lambda a: (-abs(a.shap), a.name))
    return ExplanationOut(
        method="tree_shap",
        space=explanation.space,
        base_value=round(explanation.base_value, 6),
        output=round(explanation.raw_score, 6),
        features=[
            FeatureOut(name=a.name, value=a.value, contribution=round(a.shap, 6)) for a in ranked
        ],
    )


def _terms_out(terms: Any) -> list[TermOut]:
    found = []
    for term in terms:
        cleaned = safe_fragment(term.term)
        if cleaned:
            found.append(TermOut(term=cleaned, contribution=round(term.contribution, 6)))
    return found


def text_explanation_out(explanation: TextExplanation | None) -> ExplanationOut | None:
    """Contributions du modèle de texte : les mots les plus influents dans chaque sens.

    Les mots sont nettoyés par :func:`~phishguard.explain.reasons.safe_fragment` : ce
    sont ceux de l'utilisateur, renvoyés à lui seul, mais jamais insérables comme HTML.
    """
    if explanation is None:
        return None
    return ExplanationOut(
        method="linear",
        space=explanation.space,
        base_value=round(explanation.intercept, 6),
        output=round(explanation.decision, 6),
        terms_phishing=_terms_out(explanation.top(ANALYST_TERMS)),
        terms_safe=_terms_out(explanation.top(ANALYST_TERMS, direction="safe")),
    )


def normalization_out(
    report: NormalizationReport | None, host_alert: str | None = None
) -> NormalizationOut | None:
    """Comptes de la normalisation et alerte d'hôte, pour la vue analyste."""
    from phishguard.security.normalize import NORMALIZATION_VERSION

    if report is None:
        return None
    return NormalizationOut(
        changed=report.changed,
        nfkc=report.nfkc,
        format_chars=report.format_chars,
        control_chars=report.control_chars,
        confusables=report.confusables,
        host_alert=host_alert,
        version=NORMALIZATION_VERSION,
    )


def analyst_view(
    *,
    version: str,
    raw_score: float,
    probability: float,
    calibrated: bool,
    thresholds: Any,
    fusion: FusionResult,
    language: str,
    explanation: ExplanationOut | None,
    normalization: NormalizationOut | None = None,
) -> AnalystView:
    """Vue analyste d'une analyse, quel que soit le canal."""
    return AnalystView(
        normalization=normalization,
        model=ModelOut(
            version=version,
            raw_score=raw_score,
            probability=probability,
            calibrated=calibrated,
            thresholds={str(k): float(v) for k, v in dict(thresholds or {}).items()},
        ),
        explanation=explanation,
        fusion=FusionOut(
            probability=min(1.0, max(0.0, fusion.probability)),
            thresholds=dict(fusion.thresholds),
            hard_rule=fusion.hard_rule,
            contributions=[
                ContributionOut(
                    source=c.source,
                    risk=c.risk,
                    weight=c.weight,
                    points=round(min(max(c.points, 0.0), 100.0), 3),
                )
                for c in fusion.contributions
            ],
            ignored=list(fusion.ignored),
        ),
        versions={
            "schema": SCHEMA_VERSION,
            "model": version,
            "fusion": fusion.config_version,
            "templates": f"{language}-{load_templates(language).version}",
            "explanation": explanation.method if explanation is not None else "none",
        },
    )


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
