"""Analyse complète d'une URL ou d'un message : modèle local, Threat Intelligence,
fusion, ATT&CK, explication.

Point d'entrée unique que l'API (module 4), l'extension et le bot (module 5)
appelleront. Il assemble les briques du module 2 :

1. **modèle local** (étape 1.6), toujours : score de l'URL, sans réseau ;
2. **calibration** (étape 2.10), si elle est fournie : score → probabilité ;
3. **enrichissement** (étapes 2.4 à 2.9), **seulement si l'utilisateur l'a activé** ;
4. **fusion** (étape 2.10) : score de 0 à 100 et verdict ;
5. **techniques MITRE ATT&CK** (étape 2.11) pour un verdict suspect ou phishing ;
6. **explication SHAP** du score du modèle (étape 3.1), quand le modèle s'y prête, que
   la réponse traduit en phrases (étape 3.2).

Garanties, vérifiées par ``tests/test_privacy_and_degradation.py`` (étape 2.12) :

- **vie privée** : sans enrichissement, aucune requête ne quitte la machine, ni HTTP ni
  DNS. Le modèle et la fusion sont entièrement locaux ;
- **vie privée, avec l'enrichissement** : une URL interne (adresse IP privée ou de
  bouclage, hôte sans suffixe public comme ``localhost`` ou ``intranet.corp.local``)
  n'est envoyée à aucune source. Aucun service public ne la connaît, et son nom
  révélerait le réseau de l'utilisateur ;
- **dégradation** : si toutes les sources sont en panne, l'analyse aboutit quand même,
  avec le verdict du modèle seul. Une explication impossible à calculer ne fait pas
  non plus échouer l'analyse : la réponse cite alors une raison générale.

Une URL invalide lève :class:`~phishguard.urls.features.InvalidUrlError` : c'est une
erreur de l'entrée, pas d'une source, et l'API la renverra comme telle (400).
"""

from __future__ import annotations

import logging
import math
import time
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal, Protocol

import numpy as np
import tldextract

from phishguard.data.urls import make_domain_extractor
from phishguard.enrichers.orchestrator import EnrichmentResult, Orchestrator
from phishguard.explain.shap_url import UnsupportedModelError, UrlExplainer, UrlExplanation
from phishguard.explain.text import TextExplainer, TextExplanation, message_categories
from phishguard.fusion.calibration import ScoreCalibrator
from phishguard.fusion.mitre import (
    Channel,
    Observations,
    Technique,
    domain_observations,
    map_techniques,
)
from phishguard.fusion.score import FusionConfig, FusionResult, Verdict, fuse
from phishguard.security.netguard import NetGuardError, is_public_ip, parse_ip_literal
from phishguard.urls.features import ParsedUrl, UrlFeatureExtractor, parse_url

if TYPE_CHECKING:
    from phishguard.schema import AnalysisResponse

logger = logging.getLogger(__name__)

# Mots de connexion, de vérification ou de compte dans l'URL (features de l'étape 1.5) :
# la page demande probablement des informations (T1598.003).
INFORMATION_FEATURES = ("host_kw_hits", "path_kw_hits")

# Pourquoi l'enrichissement n'a pas eu lieu : non demandé (ou aucune source configurée),
# ou URL interne, jamais envoyée à des tiers.
SkipReason = Literal["not_requested", "internal_host"]


def is_internal_host(parsed: ParsedUrl) -> bool:
    """Vrai si l'hôte n'est pas joignable sur Internet : IP non publique, ou nom sans
    suffixe public (``localhost``, ``nas.lan``, ``intranet.corp.local``).

    Les IP écrites en hexadécimal ou en entier (``0x7f000001``) sont décodées comme le
    ferait un navigateur, par le garde-fou réseau de l'étape 2.3.
    """
    if parsed.is_ip:
        try:
            ip = parse_ip_literal(parsed.host)
        except NetGuardError:
            return True
        return ip is None or not is_public_ip(ip)
    return not _suffix_extractor()(parsed.host).suffix


@lru_cache(maxsize=1)
def _suffix_extractor() -> tldextract.TLDExtract:
    """Liste des suffixes publics embarquée : aucune requête réseau."""
    return make_domain_extractor()


class UrlScorer(Protocol):
    """Ce que l'analyse attend du modèle URL (:class:`~phishguard.urls.model.UrlModel`)."""

    def score(self, urls: Iterable[str]) -> np.ndarray: ...


@dataclass(frozen=True)
class UrlAnalysis:
    url: str
    domain: str
    verdict: Verdict
    score: int
    model_score: float  # score brut du modèle
    model_probability: float  # après calibration (égal au score brut sans calibration)
    calibrated: bool
    fusion: FusionResult
    enrichment: EnrichmentResult
    mitre: tuple[Technique, ...]
    latency_ms: int
    enrichment_skipped: SkipReason | None = None  # None : les sources ont été interrogées
    model_version: str = "unknown"  # ``metadata["model_version"]`` du modèle (``url_v1``)
    explanation: UrlExplanation | None = None  # valeurs SHAP du score brut (étape 3.1)

    def to_response(self, language: str = "fr") -> AnalysisResponse:
        """Réponse au format figé de l'étape 2.11 bis (``phishguard.schema``), raisons et
        conseil rédigés dans ``language`` (``fr``, ``en`` ou ``ar``)."""
        from phishguard.schema import AnalysisResponse

        return AnalysisResponse.from_url_analysis(self, language=language)

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "domain": self.domain,
            "verdict": self.verdict,
            "score": self.score,
            "model": {
                "score": self.model_score,
                "probability": self.model_probability,
                "calibrated": self.calibrated,
            },
            "fusion": self.fusion.to_dict(),
            "enrichment": {
                "status": self.enrichment.enrichment,
                "skipped_reason": self.enrichment_skipped,
                "latency_ms": self.enrichment.latency_ms,
                "signals": [s.model_dump(mode="json") for s in self.enrichment.signals],
            },
            "mitre": [t.to_dict() for t in self.mitre],
            "explanation": None if self.explanation is None else self.explanation.to_dict(),
            "latency_ms": self.latency_ms,
        }


class UrlAnalyzer:
    """Analyse d'URLs. ``orchestrator`` peut être absent : l'analyse reste alors locale.

    ``explain`` : calculer les valeurs SHAP du score (étape 3.1). Elles ne sont
    disponibles que pour un :class:`~phishguard.urls.model.UrlModel` à base d'arbres ;
    pour tout autre modèle, l'analyse se fait sans explication.
    """

    def __init__(
        self,
        model: UrlScorer,
        *,
        calibrator: ScoreCalibrator | None = None,
        orchestrator: Orchestrator | None = None,
        config: FusionConfig | None = None,
        explain: bool = True,
    ) -> None:
        self.model = model
        self.calibrator = calibrator
        self.orchestrator = orchestrator
        self.config = config
        self.explainer = _explainer_for(model) if explain else None
        metadata = getattr(model, "metadata", None)
        self.model_version = str(
            (metadata.get("model_version") if isinstance(metadata, Mapping) else None) or "unknown"
        )
        self._features = UrlFeatureExtractor()  # constats ATT&CK (marques, mots-clés)
        if calibrator is None:
            logger.warning("modèle URL non calibré : la fusion reçoit le score brut")

    @classmethod
    def from_files(
        cls,
        model_path: Path,
        calibration_path: Path | None = None,
        *,
        orchestrator: Orchestrator | None = None,
    ) -> UrlAnalyzer:
        """Modèle (**pickle** : fichier de confiance seulement) et calibration (JSON)."""
        from phishguard.urls.model import UrlModel

        calibrator = ScoreCalibrator.load(calibration_path) if calibration_path else None
        return cls(UrlModel.load(model_path), calibrator=calibrator, orchestrator=orchestrator)

    async def analyze(
        self,
        url: str,
        *,
        enrichment: bool = False,
        allowlisted: bool = False,
        blocklisted: bool = False,
    ) -> UrlAnalysis:
        """Analyse ``url``. L'enrichissement (envoi à des tiers) est désactivé par défaut."""
        start = time.perf_counter()
        parsed = parse_url(url)  # lève InvalidUrlError si l'URL est invalide
        domain = parsed.registered_domain
        raw, explanation = self._score(url)
        if not math.isfinite(raw):
            # min/max transformeraient NaN en 0, donc en verdict « sûr » : on refuse.
            raise ValueError(f"score du modèle non fini : {raw!r}")
        probability = self.calibrator(raw) if self.calibrator else min(1.0, max(0.0, raw))

        skipped: SkipReason | None = None
        if not enrichment or self.orchestrator is None:
            skipped = "not_requested"
        elif is_internal_host(parsed):
            skipped = "internal_host"
            logger.info("URL interne : enrichissement ignoré, rien n'est envoyé aux sources")
        if skipped is None:
            enriched = await self.orchestrator.enrich(url, domain)
        else:
            budget_ms = round(self.orchestrator.budget_s * 1000) if self.orchestrator else 0
            enriched = EnrichmentResult((), "skipped", 0, budget_ms)

        fusion = fuse(
            probability,
            enriched.signals,
            allowlisted=allowlisted,
            blocklisted=blocklisted,
            config=self.config,
        )
        mitre = map_techniques(fusion.verdict, self._observations(url, enriched))
        return UrlAnalysis(
            url=url,
            domain=domain,
            verdict=fusion.verdict,
            score=fusion.score,
            model_score=raw,
            model_probability=probability,
            calibrated=self.calibrator is not None,
            fusion=fusion,
            enrichment=enriched,
            mitre=mitre,
            latency_ms=round((time.perf_counter() - start) * 1000),
            enrichment_skipped=skipped,
            model_version=self.model_version,
            explanation=explanation,
        )

    def _score(self, url: str) -> tuple[float, UrlExplanation | None]:
        """Score brut du modèle et, si possible, son explication SHAP.

        Les features ne sont extraites qu'une fois pour les deux. Une erreur de
        l'explication est journalisée sans faire échouer l'analyse ; une URL invalide
        reste une erreur de l'entrée.
        """
        if self.explainer is None:
            return float(self.model.score([url])[0]), None
        model = self.explainer.model
        x = model.features([url])  # lève InvalidUrlError si l'URL est invalide
        raw = float(model.score_features(x)[0])
        try:
            explanation = self.explainer.explain_features(x)[0]
        except Exception:  # l'explication est un plus, jamais une cause d'échec
            logger.exception("explication SHAP impossible : analyse sans explication")
            explanation = None
        return raw, explanation

    def _observations(self, url: str, enriched: EnrichmentResult) -> Observations:
        features: Mapping[str, float] = self._features.transform([url]).iloc[0].to_dict()
        return Observations(
            channel="url",
            has_link=True,
            requests_information=any(features.get(name, 0) > 0 for name in INFORMATION_FEATURES),
            **domain_observations(enriched.signals, features),
        )


def _explainer_for(model: UrlScorer) -> UrlExplainer | None:
    """Explicateur SHAP du modèle, ou ``None`` s'il ne s'y prête pas."""
    from phishguard.urls.model import UrlModel

    if not isinstance(model, UrlModel):
        return None
    try:
        return UrlExplainer(model)
    except UnsupportedModelError as exc:
        logger.info("modèle URL sans explication SHAP : %s", exc)
        return None


# --------------------------------------------------------------------------- #
# Messages (SMS, messageries) : étape 3.3
# --------------------------------------------------------------------------- #

TextChannel = Literal["sms", "messaging"]
TEXT_CHANNELS: tuple[TextChannel, ...] = ("sms", "messaging")
# Au-delà, ce n'est plus un SMS : l'API du module 4 bornera aussi l'entrée.
MAX_TEXT_CHARS = 5_000


class TextScorer(Protocol):
    """Ce que l'analyse attend du modèle texte (:class:`~phishguard.text.models.TextModel`)."""

    def score(self, texts: Iterable[str]) -> np.ndarray: ...


@dataclass(frozen=True)
class TextAnalysis:
    """Résultat de l'analyse d'un message. **Le texte lui-même n'est pas conservé.**

    ``explanation`` contient des mots du message : elle ne doit jamais être journalisée.
    """

    channel: Channel
    verdict: Verdict
    score: int
    model_score: float  # marge du SVM ou probabilité, selon le modèle
    model_probability: float
    calibrated: bool
    fusion: FusionResult
    mitre: tuple[Technique, ...]
    categories: tuple[str, ...]
    text_length: int
    latency_ms: int
    model_version: str = "unknown"
    explanation: TextExplanation | None = None

    def to_response(self, language: str = "fr") -> AnalysisResponse:
        """Réponse au format de l'étape 2.11 bis, raisons rédigées dans ``language``."""
        from phishguard.schema import AnalysisResponse

        return AnalysisResponse.from_text_analysis(self, language=language)

    def to_dict(self) -> dict[str, Any]:
        """Résumé sans le texte ni ses mots (journalisable)."""
        return {
            "channel": self.channel,
            "verdict": self.verdict,
            "score": self.score,
            "model": {
                "score": self.model_score,
                "probability": self.model_probability,
                "calibrated": self.calibrated,
            },
            "fusion": self.fusion.to_dict(),
            "mitre": [t.to_dict() for t in self.mitre],
            "categories": list(self.categories),
            "text_length": self.text_length,
            "latency_ms": self.latency_ms,
        }


class TextAnalyzer:
    """Analyse locale d'un SMS ou d'un message : aucun appel réseau, jamais.

    Le score du modèle passe par ``calibrator`` s'il est fourni (``make calibrate-text``).
    Sinon, un modèle qui renvoie déjà une probabilité (régression logistique) est
    utilisé tel quel ; une marge de SVM est ramenée à une probabilité par une sigmoïde
    centrée sur le seuil de décision du modèle, approximation signalée dans le journal.
    """

    def __init__(
        self,
        model: TextScorer,
        *,
        calibrator: ScoreCalibrator | None = None,
        config: FusionConfig | None = None,
        explain: bool = True,
    ) -> None:
        self.model = model
        self.calibrator = calibrator
        self.config = config
        metadata = getattr(model, "metadata", None)
        self.model_version = str(
            (metadata.get("model_version") if isinstance(metadata, Mapping) else None) or "unknown"
        )
        estimator = getattr(model, "estimator", None)
        self._outputs_probability = hasattr(estimator, "predict_proba")
        self._threshold = float(getattr(model, "threshold", 0.0))
        if calibrator is None and not self._outputs_probability:
            logger.warning("modèle texte non calibré : marge ramenée par une sigmoïde au seuil")
        self.explainer = _text_explainer_for(model) if explain else None

    @classmethod
    def from_files(cls, model_path: Path, calibration_path: Path | None = None) -> TextAnalyzer:
        """Modèle (**pickle** : fichier de confiance seulement) et calibration (JSON)."""
        from phishguard.text.models import TextModel

        calibrator = ScoreCalibrator.load(calibration_path) if calibration_path else None
        return cls(TextModel.load(model_path), calibrator=calibrator)

    def _probability(self, raw: float) -> float:
        if self.calibrator is not None:
            return self.calibrator(raw)
        if self._outputs_probability:
            return min(1.0, max(0.0, raw))
        return 1.0 / (1.0 + math.exp(-min(500.0, max(-500.0, raw - self._threshold))))

    def analyze(self, text: str, *, channel: TextChannel = "sms") -> TextAnalysis:
        """Analyse ``text`` reçu par ``channel`` (``sms`` ou ``messaging``)."""
        start = time.perf_counter()
        if not isinstance(text, str):
            raise TypeError("le message doit être une chaîne")
        if not text.strip():
            raise ValueError("message vide")
        if len(text) > MAX_TEXT_CHARS:
            raise ValueError(f"message trop long : plus de {MAX_TEXT_CHARS} caractères")
        if channel not in TEXT_CHANNELS:
            raise ValueError(f"canal {channel!r} : {TEXT_CHANNELS} attendus")

        raw = float(self.model.score([text])[0])
        if not math.isfinite(raw):
            raise ValueError(f"score du modèle non fini : {raw!r}")
        probability = self._probability(raw)
        fusion = fuse(probability, (), config=self.config)

        explanation: TextExplanation | None = None
        if self.explainer is not None:
            try:
                explanation = self.explainer.explain(text)
            except Exception:  # l'explication est un plus, jamais une cause d'échec
                logger.exception("explication du message impossible : analyse sans explication")
        categories = explanation.categories if explanation is not None else message_categories(text)
        observations = Observations(
            channel=channel,
            has_link="link" in categories,
            requests_information=bool({"code", "account"} & set(categories)),
        )
        return TextAnalysis(
            channel=channel,
            verdict=fusion.verdict,
            score=fusion.score,
            model_score=raw,
            model_probability=probability,
            calibrated=self.calibrator is not None,
            fusion=fusion,
            mitre=map_techniques(fusion.verdict, observations),
            categories=tuple(categories),
            text_length=len(text),
            latency_ms=round((time.perf_counter() - start) * 1000),
            model_version=self.model_version,
            explanation=explanation,
        )


def _text_explainer_for(model: TextScorer) -> TextExplainer | None:
    """Explicateur du modèle texte, ou ``None`` s'il ne s'y prête pas."""
    from phishguard.text.models import TextModel

    if not isinstance(model, TextModel):
        return None
    try:
        return TextExplainer(model)
    except UnsupportedModelError as exc:
        logger.info("modèle texte sans explication par mots : %s", exc)
        return None
