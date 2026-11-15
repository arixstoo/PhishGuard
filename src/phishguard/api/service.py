"""Couche service de l'API (étape 4.3) : la logique, sans HTTP.

Les routes ne font que traduire HTTP vers ce module et retour ; ce module ne connaît ni
``Request`` ni code de statut. Il appelle les analyseurs du pipeline principal (étape
3.12, :mod:`phishguard.analysis`) et renvoie le contrat figé de l'étape 2.11 bis
(:class:`~phishguard.schema.AnalysisResponse`).

**Le calcul ML est synchrone** (features, LightGBM, TF-IDF, SHAP, parseur d'email) : il
est exécuté dans le pool de threads de Starlette (``run_in_threadpool``), jamais sur la
boucle asynchrone, où une analyse de 20 ms bloquerait toutes les autres requêtes
pendant 20 ms. L'enrichissement par la Threat Intelligence, lui, est asynchrone et reste
sur la boucle, propriétaire du client HTTP partagé.

Les modèles sont en lecture seule après le chargement : LightGBM (prédiction protégée par
un verrou partagé), scikit-learn (``decision_function``) et l'extracteur de features
peuvent servir plusieurs threads à la fois.

Erreurs de l'entrée, traduites par les routes : :class:`InvalidInputError` (400) et
:class:`InputTooLargeError` (413). Toute autre exception est un défaut du serveur (500).
"""

from __future__ import annotations

import hashlib
import logging
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from starlette.concurrency import run_in_threadpool

from phishguard.analysis import EMAIL_RULES_VERSION
from phishguard.api.schemas import ModelOut, ModelsInfo, TextRequest, UrlRequest
from phishguard.deployment import Analyzers, model_files
from phishguard.email.parser import EmailTooLargeError
from phishguard.fusion.score import default_config
from phishguard.schema import SCHEMA_VERSION, AnalysisResponse
from phishguard.urls.features import InvalidUrlError

logger = logging.getLogger(__name__)

ThreadRunner = Callable[..., Awaitable[Any]]
INVALID_URL_MESSAGE = "URL invalide : schéma http ou https et nom d'hôte valide attendus."


class InvalidInputError(ValueError):
    """Entrée bien formée mais inanalysable (URL au schéma non http, hôte vide…)."""


class InputTooLargeError(ValueError):
    """Entrée au-delà des bornes de l'analyseur."""


@dataclass(frozen=True)
class EmailUpload:
    content: bytes
    language: str = "fr"
    analyst: bool = False


class AnalysisService:
    """Les trois analyses, au contrat de réponse figé."""

    def __init__(self, analyzers: Analyzers, *, run_sync: ThreadRunner = run_in_threadpool) -> None:
        self.analyzers = analyzers
        self._run_sync = run_sync

    async def analyze_url(self, request: UrlRequest) -> AnalysisResponse:
        try:
            analysis = await self.analyzers.url.analyze(
                request.url, enrichment=request.use_threat_intel, run_sync=self._run_sync
            )
        except InvalidUrlError:
            # Message fixe : celui d'InvalidUrlError recopie l'URL, qui ne doit jamais
            # revenir dans une réponse (réflexion de l'entrée).
            raise InvalidInputError(INVALID_URL_MESSAGE) from None
        return await self._run_sync(analysis.to_response, request.language, analyst=request.analyst)

    async def analyze_text(self, request: TextRequest) -> AnalysisResponse:
        def run() -> AnalysisResponse:
            analysis = self.analyzers.text.analyze(request.text, channel=request.channel)
            return analysis.to_response(request.language, analyst=request.analyst)

        return await self._run_sync(run)

    async def analyze_email(self, upload: EmailUpload) -> AnalysisResponse:
        def run() -> AnalysisResponse:
            try:
                analysis = self.analyzers.email.analyze(upload.content)
            except EmailTooLargeError:
                raise InputTooLargeError("email trop volumineux") from None
            return analysis.to_response(upload.language, analyst=upload.analyst)

        return await self._run_sync(run)


# --------------------------------------------------------------------------- #
# Modèles déployés (GET /v1/model)
# --------------------------------------------------------------------------- #


def sha256_of(path: Path) -> str | None:
    """Empreinte SHA-256 d'un fichier, lue par blocs ; ``None`` s'il n'existe pas."""
    if not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _trained_at(model: object) -> str | None:
    metadata = getattr(model, "metadata", None)
    value = metadata.get("trained_at") if isinstance(metadata, Mapping) else None
    return str(value) if value else None


def describe_models(analyzers: Analyzers, models_dir: Path | None) -> ModelsInfo:
    """Fiche des modèles servis. Les empreintes sont celles des fichiers de ``models_dir``,
    calculées une fois au démarrage (``None`` pour des analyseurs construits en mémoire)."""
    files = model_files(models_dir) if models_dir is not None else {}

    def entry(kind: str, analyzer: Any, model_kind: str) -> ModelOut:
        item = files.get(kind)
        return ModelOut(
            version=analyzer.model_version,
            kind=model_kind,
            trained_at=_trained_at(analyzer.model),
            sha256=sha256_of(item.model) if item else None,
            calibrated=analyzer.calibrator is not None,
            calibration_sha256=(
                sha256_of(item.calibration) if item and analyzer.calibrator is not None else None
            ),
        )

    url_metadata = getattr(analyzers.url.model, "metadata", None)
    normalization = url_metadata.get("normalization") if isinstance(url_metadata, Mapping) else None
    return ModelsInfo(
        schema_version=SCHEMA_VERSION,
        fusion_version=default_config().version,
        normalization_version=str(normalization) if normalization else None,
        models={
            "url": entry("url", analyzers.url, "lightgbm"),
            "text": entry("text", analyzers.text, "text"),
            "email": ModelOut(version=EMAIL_RULES_VERSION, kind="rules"),
        },
    )
