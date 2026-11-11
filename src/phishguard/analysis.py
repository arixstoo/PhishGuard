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

**Normalisation (étape 3.8), branchée ici à l'étape 3.12.** Les modèles normalisent
eux-mêmes leur entrée (NFKC, caractères invisibles retirés, homoglyphes repliés pour le
texte). L'analyse garde le compte de ce qui a changé (jamais le contenu), le journalise et
l'expose dans la vue analyste. Un hôte qui imite des lettres latines (``аpple.com``)
déclenche la règle dure ``lookalike_host`` de la fusion : verdict phishing, raison dédiée.

Trois analyseurs remplissent le même contrat de réponse : :class:`UrlAnalyzer`,
:class:`TextAnalyzer` (SMS, messageries) et :class:`EmailAnalyzer` (email brut, ``.eml``).

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
from collections.abc import Awaitable, Callable, Iterable, Mapping
from dataclasses import dataclass, field
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
from phishguard.fusion.score import (
    FusionConfig,
    FusionResult,
    Verdict,
    fuse,
    lookalike_host_signal,
)
from phishguard.security.netguard import NetGuardError, is_public_ip, parse_ip_literal
from phishguard.security.normalize import (
    HostAlert,
    NormalizationReport,
    host_script_alert,
    log_normalization,
    normalize_text,
    normalize_url_text,
)
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

# Exécute une fonction synchrone hors de la boucle asynchrone et attend son résultat :
# ``starlette.concurrency.run_in_threadpool`` (API, étape 4.3) ou ``asyncio.to_thread``.
SyncRunner = Callable[..., Awaitable[Any]]


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
    model_thresholds: Mapping[str, float] = field(default_factory=dict)  # vue analyste
    # Hôte qui imite des lettres latines (étape 3.8) : règle dure ``lookalike_host`` de
    # la fusion depuis l'étape 3.12.
    host_alert: HostAlert | None = None
    # Ce que la normalisation a changé dans l'URL : des comptes, jamais le contenu.
    normalization: NormalizationReport = field(default_factory=NormalizationReport)

    def to_response(self, language: str = "fr", *, analyst: bool = True) -> AnalysisResponse:
        """Réponse au format figé de l'étape 2.11 bis (``phishguard.schema``), raisons et
        conseil rédigés dans ``language`` (``fr``, ``en`` ou ``ar``), avec la vue analyste
        de l'étape 3.4 sauf ``analyst=False``."""
        from phishguard.schema import AnalysisResponse

        return AnalysisResponse.from_url_analysis(self, language=language, analyst=analyst)

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
            "host_alert": self.host_alert,
            "normalization": self.normalization.to_dict(),
            "latency_ms": self.latency_ms,
        }


@dataclass(frozen=True)
class _LocalUrlScore:
    """Partie locale de l'analyse d'une URL, calculée avant l'enrichissement."""

    parsed: ParsedUrl
    normalization: NormalizationReport
    host_alert: HostAlert | None
    raw: float
    probability: float
    explanation: UrlExplanation | None
    features: Mapping[str, float]  # constats ATT&CK (marques, mots-clés)


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
        thresholds = getattr(model, "thresholds", None)
        self.model_thresholds = dict(thresholds) if isinstance(thresholds, Mapping) else {}
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
        run_sync: SyncRunner | None = None,
    ) -> UrlAnalysis:
        """Analyse ``url``. L'enrichissement (envoi à des tiers) est désactivé par défaut.

        ``run_sync`` : exécuteur du calcul local (features, modèle, SHAP), qui occupe le
        processeur plusieurs millisecondes. Un serveur asynchrone passe un pool de threads
        (``run_in_threadpool``) pour ne pas bloquer sa boucle ; l'enrichissement reste,
        lui, sur la boucle de l'appelant, propriétaire du client HTTP partagé.
        """
        start = time.perf_counter()
        local = (
            self._score_locally(url)
            if run_sync is None
            else await run_sync(self._score_locally, url)
        )
        parsed, host_alert = local.parsed, local.host_alert
        domain = parsed.registered_domain

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

        # La règle dure locale passe par la fusion, pas par les signaux de la réponse :
        # aucune source externe n'a été interrogée pour elle.
        local_signal = lookalike_host_signal(host_alert)
        fusion = fuse(
            local.probability,
            (*enriched.signals, *((local_signal,) if local_signal is not None else ())),
            allowlisted=allowlisted,
            blocklisted=blocklisted,
            config=self.config,
        )
        mitre = map_techniques(
            fusion.verdict,
            self._observations(local.features, enriched, lookalike=host_alert is not None),
        )
        return UrlAnalysis(
            url=url,
            domain=domain,
            verdict=fusion.verdict,
            score=fusion.score,
            model_score=local.raw,
            model_probability=local.probability,
            calibrated=self.calibrator is not None,
            fusion=fusion,
            enrichment=enriched,
            mitre=mitre,
            latency_ms=round((time.perf_counter() - start) * 1000),
            enrichment_skipped=skipped,
            model_version=self.model_version,
            explanation=local.explanation,
            model_thresholds=self.model_thresholds,
            host_alert=host_alert,
            normalization=local.normalization,
        )

    def _score_locally(self, url: str) -> _LocalUrlScore:
        """Tout le calcul local, sans réseau : normalisation, score, explication, constats.

        Synchrone et sans état partagé modifiable : sûr dans un thread de travail.
        """
        parsed = parse_url(url)  # lève InvalidUrlError si l'URL est invalide
        # Normalisation (étape 3.8) : faite par parse_url ; journalisée ici, une fois.
        normalization = normalize_url_text(url).report
        log_normalization(normalization, "url")
        host_alert = host_script_alert(parsed.host)
        if host_alert is not None:
            logger.info("hôte qui imite des lettres latines (%s)", host_alert)
        raw, explanation = self._score(url)
        if not math.isfinite(raw):
            # min/max transformeraient NaN en 0, donc en verdict « sûr » : on refuse.
            raise ValueError(f"score du modèle non fini : {raw!r}")
        probability = self.calibrator(raw) if self.calibrator else min(1.0, max(0.0, raw))
        features: Mapping[str, float] = self._features.transform([url]).iloc[0].to_dict()
        return _LocalUrlScore(
            parsed=parsed,
            normalization=normalization,
            host_alert=host_alert,
            raw=raw,
            probability=probability,
            explanation=explanation,
            features=features,
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

    @staticmethod
    def _observations(
        features: Mapping[str, float], enriched: EnrichmentResult, *, lookalike: bool = False
    ) -> Observations:
        domain = domain_observations(enriched.signals, features)
        domain["lookalike_domain"] = domain["lookalike_domain"] or lookalike
        return Observations(
            channel="url",
            has_link=True,
            requests_information=any(features.get(name, 0) > 0 for name in INFORMATION_FEATURES),
            **domain,
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
    model_thresholds: Mapping[str, float] = field(default_factory=dict)  # vue analyste
    # Ce que la normalisation a changé dans le message (étape 3.8) : des comptes.
    normalization: NormalizationReport = field(default_factory=NormalizationReport)

    def to_response(self, language: str = "fr", *, analyst: bool = True) -> AnalysisResponse:
        """Réponse au format de l'étape 2.11 bis, raisons rédigées dans ``language``, avec
        la vue analyste de l'étape 3.4 sauf ``analyst=False``."""
        from phishguard.schema import AnalysisResponse

        return AnalysisResponse.from_text_analysis(self, language=language, analyst=analyst)

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
            "normalization": self.normalization.to_dict(),
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
        # Le modèle normalise lui-même le texte (étape 3.8) ; le fait est journalisé ici.
        normalization = normalize_text(text).report
        log_normalization(normalization, channel)

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
            model_thresholds=(
                {"decision": self._threshold} if hasattr(self.model, "threshold") else {}
            ),
            normalization=normalization,
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


# --------------------------------------------------------------------------- #
# Email (étape 3.12)
# --------------------------------------------------------------------------- #

# Le score email est celui des règles transparentes de l'étape 1.11, chacune avec sa
# raison lisible. Sa version change avec les règles ou leurs poids.
EMAIL_RULES_VERSION = "email_rules_v1"
# Règles qui montrent que l'email demande des informations (T1598).
EMAIL_INFORMATION_RULES = frozenset(
    {"form", "credential_form_attachment", "urgent_account_request"}
)


@dataclass(frozen=True)
class EmailAnalysis:
    """Résultat de l'analyse d'un email. **Ni le texte ni les adresses ne sont conservés.**"""

    verdict: Verdict
    score: int
    rule_score: int  # score des règles de l'étape 1.11, avant la fusion
    triggered: tuple[str, ...]  # règles déclenchées, de la plus lourde à la plus légère
    fusion: FusionResult
    mitre: tuple[Technique, ...]
    links: int
    attachments: int
    latency_ms: int
    host_alert: HostAlert | None = None  # un lien vers un hôte qui imite le latin
    normalization: NormalizationReport = field(default_factory=NormalizationReport)
    model_version: str = EMAIL_RULES_VERSION
    url_model_version: str | None = None  # modèle URL de la règle ``url_model``

    def to_response(self, language: str = "fr", *, analyst: bool = True) -> AnalysisResponse:
        """Réponse au format de l'étape 2.11 bis, raisons rédigées dans ``language``."""
        from phishguard.schema import AnalysisResponse

        return AnalysisResponse.from_email_analysis(self, language=language, analyst=analyst)

    def to_dict(self) -> dict[str, Any]:
        """Résumé sans contenu (journalisable)."""
        return {
            "verdict": self.verdict,
            "score": self.score,
            "rule_score": self.rule_score,
            "triggered": list(self.triggered),
            "fusion": self.fusion.to_dict(),
            "mitre": [t.to_dict() for t in self.mitre],
            "links": self.links,
            "attachments": self.attachments,
            "host_alert": self.host_alert,
            "normalization": self.normalization.to_dict(),
            "model_version": self.model_version,
            "url_model_version": self.url_model_version,
            "latency_ms": self.latency_ms,
        }


class EmailAnalyzer:
    """Analyse locale d'un email brut (``.eml``) : aucun appel réseau, jamais.

    Le score est celui des règles transparentes de l'étape 1.11 (authentification,
    expéditeurs, liens, formulaires, pièces jointes, texte caché), avec la règle
    ``url_model`` si un modèle URL est fourni. Il passe ensuite par la même fusion que
    les autres canaux, ce qui y ajoute la règle dure ``lookalike_host`` : un lien vers
    un hôte qui imite des lettres latines suffit au verdict phishing.

    L'entrée est bornée par :class:`~phishguard.email.parser.EmailLimits` (taille,
    parties, en-têtes) : :class:`~phishguard.email.parser.EmailTooLargeError` est une
    erreur de l'entrée, que l'API renverra comme telle (413).
    """

    def __init__(
        self,
        url_model: Any = None,
        *,
        config: FusionConfig | None = None,
        limits: Any = None,
        trusted_authserv_ids: list[str] | None = None,
    ) -> None:
        self.url_model = url_model
        self.config = config
        self.limits = limits
        self.trusted_authserv_ids = trusted_authserv_ids
        metadata = getattr(url_model, "metadata", None)
        self.url_model_version = (
            str(metadata.get("model_version", "unknown")) if isinstance(metadata, Mapping) else None
        )

    @classmethod
    def from_files(cls, url_model_path: Path | None = None) -> EmailAnalyzer:
        """Modèle URL facultatif (**pickle** : fichier de confiance seulement)."""
        if url_model_path is None:
            return cls()
        from phishguard.urls.model import UrlModel

        return cls(UrlModel.load(url_model_path))

    def analyze(self, raw: bytes) -> EmailAnalysis:
        """Analyse l'email brut ``raw`` (octets d'un fichier ``.eml``)."""
        from phishguard.email.html import link_target
        from phishguard.email.parser import parse_eml
        from phishguard.email.score import score_email

        start = time.perf_counter()
        email = parse_eml(raw, self.limits, trusted_authserv_ids=self.trusted_authserv_ids)
        rules = score_email(email, self.url_model)

        normalization = normalize_text(f"{email.subject}\n{email.text}").report
        log_normalization(normalization, "email")
        host_alert: HostAlert | None = None
        for link in email.links:
            if link.scheme not in ("http", "https"):
                continue
            try:
                host_alert = host_script_alert(parse_url(link_target(link)).host)
            except ValueError:  # InvalidUrlError en hérite : lien illisible, ignoré
                continue
            if host_alert is not None:
                logger.info("lien vers un hôte qui imite des lettres latines (%s)", host_alert)
                break

        local = lookalike_host_signal(host_alert)
        fusion = fuse(rules.score / 100, (local,) if local is not None else (), config=self.config)
        observations = Observations(
            channel="email",
            has_link=bool(email.links),
            risky_attachment=bool(email.risky_attachments),
            requests_information=bool(EMAIL_INFORMATION_RULES & set(rules.triggered)),
            lookalike_domain=host_alert is not None,
        )
        return EmailAnalysis(
            verdict=fusion.verdict,
            score=fusion.score,
            rule_score=rules.score,
            triggered=rules.triggered,
            fusion=fusion,
            mitre=map_techniques(fusion.verdict, observations),
            links=len(email.links),
            attachments=len(email.attachments),
            latency_ms=round((time.perf_counter() - start) * 1000),
            host_alert=host_alert,
            normalization=normalization,
            url_model_version=self.url_model_version,
        )
