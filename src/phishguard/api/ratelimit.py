"""Limites de débit (étape 4.4), sur la bibliothèque ``limits``.

``limits`` est le moteur de ``slowapi``, utilisé ici directement, en mode asynchrone.
slowapi a été évalué puis écarté pour cette étape : ses limites **dynamiques** (une
limite par niveau de client, ``default_limits=[callable]``) rangent la requête courante
dans un objet partagé par toutes les requêtes (``LimitGroup.request``). Deux requêtes
concurrentes peuvent alors se voir appliquer la limite l'une de l'autre, et, par son
middleware, la limite n'était pas appliquée du tout (vérifié avec slowapi 0.1.10). Pour
un contrôle de sécurité, un middleware de 100 lignes que l'on maîtrise vaut mieux.

Les limites sont appliquées par un **middleware ASGI**, avant que le corps de la requête
ne soit lu ou validé : une rafale de JSON malformés ou de fichiers trop gros consomme le
quota comme une requête valide.

Trois niveaux, selon :func:`phishguard.api.security.resolve_client` :

=================  ==================  =======================================
Client             Compteur            Limite (défaut)
=================  ==================  =======================================
anonyme            IP (/64 en IPv6)    ``rate_limit_anonymous`` (30/minute)
clé valide         clé                 ``rate_limit_authenticated`` (300/minute)
clé refusée        IP (/64 en IPv6)    ``rate_limit_rejected`` (10/minute)
=================  ==================  =======================================

Un compteur par route : la clé de stockage est le **modèle de la route**
(``/v1/analyze/url``), jamais le chemin brut. Les chemins inconnus partagent un seul
compteur, sans quoi des URLs aléatoires créeraient autant d'entrées en mémoire.

Fenêtre glissante (``moving-window``) : pas de rafale double à la frontière de deux
fenêtres fixes. Au-delà : 429 avec ``Retry-After`` ; toujours : ``X-RateLimit-Limit``,
``X-RateLimit-Remaining`` et ``X-RateLimit-Reset``.

**Stockage indisponible** (Redis tombé) : la requête passe et l'incident est journalisé.
La limite de débit protège la capacité du service, elle n'est pas un contrôle d'accès :
l'authentification, elle, ne dépend pas de ce stockage.
"""

from __future__ import annotations

import logging
import math
import time
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from limits import RateLimitItem, parse_many
from limits.aio.strategies import MovingWindowRateLimiter
from limits.storage import StorageTypes, storage_from_string
from starlette.datastructures import MutableHeaders
from starlette.requests import Request
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from phishguard.api.errors import error_response
from phishguard.api.middleware import route_key
from phishguard.api.security import ClientKind, resolve_client
from phishguard.api.settings import ApiSettings

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class Decision:
    allowed: bool
    limit: RateLimitItem
    remaining: int
    reset_at: float  # horodatage Unix de la fin de la fenêtre


class RateLimiter:
    """Politique de limite par niveau de client, sur un stockage ``limits`` asynchrone."""

    def __init__(self, settings: ApiSettings) -> None:
        self.enabled = settings.rate_limit_enabled
        uri = settings.rate_limit_storage_uri
        storage = storage_from_string(uri if uri.startswith("async+") else f"async+{uri}")
        self._strategy = MovingWindowRateLimiter(storage)
        self._limits: dict[ClientKind, list[RateLimitItem]] = {
            "anonymous": parse_many(settings.rate_limit_anonymous),
            "authenticated": parse_many(settings.rate_limit_authenticated),
            "rejected": parse_many(settings.rate_limit_rejected),
            "unavailable": parse_many(settings.rate_limit_rejected),
        }

    @property
    def storage(self) -> StorageTypes:
        return self._strategy.storage

    async def hit(self, kind: ClientKind, key: str, route: str) -> Decision:
        """Compte une requête ; refusée dès qu'une des limites du niveau est atteinte."""
        decision: Decision | None = None
        for item in self._limits[kind]:
            allowed = await self._strategy.hit(item, key, route)
            reset_at, remaining = await self._strategy.get_window_stats(item, key, route)
            current = Decision(allowed, item, max(0, remaining), reset_at)
            if not allowed:
                return current
            # En-têtes : la limite la plus proche d'être atteinte.
            if decision is None or current.remaining < decision.remaining:
                decision = current
        assert decision is not None  # parse_many ne renvoie jamais une liste vide ici
        return decision


class RateLimitMiddleware:
    """Applique :class:`RateLimiter` à chaque requête HTTP, sauf ``exempt_paths``."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        limiter: RateLimiter,
        routes: Iterable[str],
        exempt_paths: Sequence[str] = (),
    ) -> None:
        self.app = app
        self.limiter = limiter
        self.routes = frozenset(routes)
        self.exempt_paths = frozenset(exempt_paths)

    def route_key(self, path: str) -> str:
        return route_key(path, self.routes)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or not self.limiter.enabled:
            await self.app(scope, receive, send)
            return
        path = scope.get("path", "/")
        if (path.rstrip("/") or "/") in self.exempt_paths:
            await self.app(scope, receive, send)
            return

        client = resolve_client(Request(scope))
        try:
            decision = await self.limiter.hit(client.kind, client.rate_key, self.route_key(path))
        except Exception:  # stockage indisponible : on laisse passer (voir le module)
            logger.exception("stockage des limites de débit indisponible")
            await self.app(scope, receive, send)
            return

        headers = _rate_headers(decision)
        if not decision.allowed:
            logger.info("limite de débit atteinte (%s, %s)", client.kind, self.route_key(path))
            retry_after = max(1, math.ceil(decision.reset_at - time.time()))
            response = error_response(
                429,
                "rate_limited",
                f"Trop de requêtes : limite de {decision.limit} atteinte.",
                headers={**headers, "Retry-After": str(retry_after)},
            )
            await response(scope, receive, send)
            return

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                response_headers = MutableHeaders(scope=message)
                for name, value in headers.items():
                    response_headers[name] = value
            await send(message)

        await self.app(scope, receive, send_with_headers)


def _rate_headers(decision: Decision) -> dict[str, str]:
    return {
        "X-RateLimit-Limit": str(decision.limit.amount),
        "X-RateLimit-Remaining": str(decision.remaining),
        "X-RateLimit-Reset": str(math.ceil(decision.reset_at)),
    }
