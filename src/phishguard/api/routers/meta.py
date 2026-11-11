"""Routes de méta-informations : santé du service et modèles déployés."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends

from phishguard.api.dependencies import AppState, app_state
from phishguard.api.errors import ERROR_RESPONSES
from phishguard.api.schemas import Health, ModelsInfo

router = APIRouter(tags=["méta"])
# Santé : sans authentification ni limite de débit (sondes de l'orchestrateur, HEALTHCHECK
# Docker), et sans aucune information sur le déploiement.
health_router = APIRouter(tags=["méta"])


@health_router.get("/health", response_model=Health, summary="Le service répond")
async def health() -> Health:
    # Le lifespan a chargé les modèles avant la première requête : répondre suffit.
    return Health()


@router.get(
    "/model",
    response_model=ModelsInfo,
    responses=ERROR_RESPONSES,
    summary="Version, date d'entraînement et empreinte SHA-256 des modèles servis",
)
async def model(state: Annotated[AppState, Depends(app_state)]) -> ModelsInfo:
    return state.models
