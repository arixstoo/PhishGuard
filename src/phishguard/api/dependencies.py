"""Dépendances communes des routes."""

from __future__ import annotations

from dataclasses import dataclass

from fastapi import Request

from phishguard.api.settings import ApiSettings
from phishguard.deployment import Analyzers


@dataclass(frozen=True)
class AppState:
    """Ce que le démarrage (``lifespan``) prépare une fois pour toutes les requêtes."""

    settings: ApiSettings
    analyzers: Analyzers


def app_state(request: Request) -> AppState:
    return request.app.state.phishguard
