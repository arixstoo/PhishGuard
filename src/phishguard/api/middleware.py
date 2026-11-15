"""Limite de taille du corps des requêtes (étape 4.2), avant toute lecture.

Middleware ASGI pur, pour deux raisons :

- un ``Content-Length`` trop grand est refusé (413) **avant de lire un seul octet** ;
- sans ``Content-Length`` (envoi par morceaux), les octets sont comptés au fil de la
  lecture et la requête est coupée dès que la limite est franchie : un client ne peut
  pas faire mettre 1 Go en mémoire ou dans un fichier temporaire en omettant l'en-tête.

La limite dépend de la route : quelques dizaines de Ko pour le JSON, la taille maximale
d'un email (plus l'enveloppe multipart) pour le téléversement d'un ``.eml``.
"""

from __future__ import annotations

from collections.abc import Mapping

from starlette.exceptions import HTTPException
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from phishguard.api.errors import error_response

# Enveloppe multipart autour du fichier : délimiteurs, en-têtes de partie, champs.
MULTIPART_OVERHEAD = 16 * 1024


class BodySizeLimitMiddleware:
    def __init__(
        self, app: ASGIApp, *, default_limit: int, route_limits: Mapping[str, int] | None = None
    ) -> None:
        self.app = app
        self.default_limit = default_limit
        self.route_limits = dict(route_limits or {})

    def limit_for(self, path: str) -> int:
        return self.route_limits.get(path.rstrip("/") or "/", self.default_limit)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        limit = self.limit_for(scope.get("path", "/"))

        declared = _content_length(scope)
        if declared == -1:
            await _reject(scope, receive, send, 400, "bad_request", "Content-Length invalide.")
            return
        if declared is not None and declared > limit:
            await _reject(scope, receive, send, 413, "payload_too_large", _too_large(limit))
            return

        received = 0

        async def limited_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > limit:
                    # Levée pendant la lecture du corps : FastAPI la laisse passer, et le
                    # gestionnaire d'erreurs HTTP la met dans l'enveloppe commune.
                    raise HTTPException(413, _too_large(limit))
            return message

        await self.app(scope, limited_receive, send)


def _too_large(limit: int) -> str:
    return f"Corps de requête trop gros (limite : {limit} octets)."


def _content_length(scope: Scope) -> int | None:
    """Valeur de ``Content-Length`` ; ``None`` si absent, ``-1`` si invalide."""
    values = [v for k, v in scope.get("headers", ()) if k == b"content-length"]
    if not values:
        return None
    if len(set(values)) != 1:  # deux valeurs différentes : désynchronisation possible
        return -1
    raw = values[0].strip()
    if not raw.isdigit() or len(raw) > 18:
        return -1
    return int(raw)


async def _reject(
    scope: Scope, receive: Receive, send: Send, status: int, code: str, message: str
) -> None:
    response = error_response(status, code, message, headers={"Connection": "close"})
    await response(scope, receive, send)
