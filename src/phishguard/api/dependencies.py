"""Dépendances communes des routes."""

from __future__ import annotations

from dataclasses import dataclass

from fastapi import Request

from phishguard.api.errors import ApiError
from phishguard.api.settings import ApiSettings
from phishguard.deployment import Analyzers


@dataclass(frozen=True)
class AppState:
    """Ce que le démarrage (``lifespan``) prépare une fois pour toutes les requêtes."""

    settings: ApiSettings
    analyzers: Analyzers


def app_state(request: Request) -> AppState:
    return request.app.state.phishguard


async def require_json(request: Request) -> None:
    """Refuse (415) un corps qui n'est pas déclaré ``application/json``.

    Sans ce contrôle, un navigateur peut envoyer d'un autre site une requête
    ``text/plain`` contenant du JSON sans pré-vérification CORS (« simple request ») :
    exiger ``application/json`` force la pré-vérification.
    """
    media_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if media_type != "application/json":
        raise ApiError(415, "unsupported_media_type", "Corps JSON attendu (application/json).")
