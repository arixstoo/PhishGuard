"""Analyse complète d'une URL : modèle local, Threat Intelligence, fusion, ATT&CK.

Point d'entrée unique que l'API (module 4), l'extension et le bot (module 5)
appelleront. Il assemble les briques du module 2 :

1. **modèle local** (étape 1.6), toujours : score de l'URL, sans réseau ;
2. **calibration** (étape 2.10), si elle est fournie : score → probabilité ;
3. **enrichissement** (étapes 2.4 à 2.9), **seulement si l'utilisateur l'a activé** ;
4. **fusion** (étape 2.10) : score de 0 à 100 et verdict ;
5. **techniques MITRE ATT&CK** (étape 2.11) pour un verdict suspect ou phishing.

Garanties, vérifiées par ``tests/test_privacy_and_degradation.py`` (étape 2.12) :

- **vie privée** : sans enrichissement, aucune requête ne quitte la machine, ni HTTP ni
  DNS. Le modèle et la fusion sont entièrement locaux ;
- **dégradation** : si toutes les sources sont en panne, l'analyse aboutit quand même,
  avec le verdict du modèle seul.

Une URL invalide lève :class:`~phishguard.urls.features.InvalidUrlError` : c'est une
erreur de l'entrée, pas d'une source, et l'API la renverra comme telle (400).
"""

from __future__ import annotations

import logging
import time
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

import numpy as np

from phishguard.enrichers.orchestrator import EnrichmentResult, Orchestrator
from phishguard.fusion.calibration import ScoreCalibrator
from phishguard.fusion.mitre import Observations, Technique, domain_observations, map_techniques
from phishguard.fusion.score import FusionConfig, FusionResult, Verdict, fuse
from phishguard.urls.features import UrlFeatureExtractor, parse_url

logger = logging.getLogger(__name__)

# Mots de connexion, de vérification ou de compte dans l'URL (features de l'étape 1.5) :
# la page demande probablement des informations (T1598.003).
INFORMATION_FEATURES = ("host_kw_hits", "path_kw_hits")


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
                "latency_ms": self.enrichment.latency_ms,
                "signals": [s.model_dump(mode="json") for s in self.enrichment.signals],
            },
            "mitre": [t.to_dict() for t in self.mitre],
            "latency_ms": self.latency_ms,
        }


class UrlAnalyzer:
    """Analyse d'URLs. ``orchestrator`` peut être absent : l'analyse reste alors locale."""

    def __init__(
        self,
        model: UrlScorer,
        *,
        calibrator: ScoreCalibrator | None = None,
        orchestrator: Orchestrator | None = None,
        config: FusionConfig | None = None,
    ) -> None:
        self.model = model
        self.calibrator = calibrator
        self.orchestrator = orchestrator
        self.config = config
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
        domain = parse_url(url).registered_domain  # lève InvalidUrlError si l'URL est invalide
        raw = float(self.model.score([url])[0])
        probability = self.calibrator(raw) if self.calibrator else min(1.0, max(0.0, raw))

        if enrichment and self.orchestrator is not None:
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
        )

    def _observations(self, url: str, enriched: EnrichmentResult) -> Observations:
        features: Mapping[str, float] = self._features.transform([url]).iloc[0].to_dict()
        return Observations(
            channel="url",
            has_link=True,
            requests_information=any(features.get(name, 0) > 0 for name in INFORMATION_FEATURES),
            **domain_observations(enriched.signals, features),
        )
