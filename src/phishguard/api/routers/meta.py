"""Routes de méta-informations : santé du service."""

from __future__ import annotations

from fastapi import APIRouter

from phishguard.api.schemas import Health

router = APIRouter(tags=["méta"])
# Santé : sans authentification ni limite de débit (sondes de l'orchestrateur, HEALTHCHECK
# Docker), et sans aucune information sur le déploiement.
health_router = APIRouter(tags=["méta"])


@health_router.get("/health", response_model=Health, summary="Le service répond")
async def health() -> Health:
    # Le lifespan a chargé les modèles avant la première requête : répondre suffit.
    return Health()
