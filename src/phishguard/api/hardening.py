"""Durcissement HTTP (étape 4.5) : en-têtes de sécurité, CORS, délai et filet d'erreurs.

Trois middlewares ASGI purs, placés à l'extérieur de toutes les autres couches pour que
**chaque** réponse en profite, y compris un 429 du limiteur, un 413 de la limite de
taille ou un 500 :

- :class:`SecurityHeadersMiddleware` ajoute les en-têtes de sécurité (tableau de
  :data:`SECURITY_HEADERS`). L'API ne sert que du JSON : la politique de contenu
  (``Content-Security-Policy``) interdit tout (``default-src 'none'``), sauf pour la
  documentation interactive, qui n'existe qu'en développement ;
- CORS (:func:`cors_options`, middleware de Starlette) : une **liste explicite**
  d'origines, jamais ``*``. Pas d'identifiants de navigateur (cookies) : l'API
  s'authentifie par ``X-API-Key``, qu'aucun site ne peut lire ni envoyer à la place de
  l'utilisateur ;
- :class:`RequestGuardMiddleware` borne la durée d'une requête, **lecture du corps
  comprise** (un client qui envoie son corps octet par octet occupe sinon une connexion
  indéfiniment), et transforme toute exception non prévue en 500 sans aucun détail.

Pourquoi le filet d'erreurs est ici et pas seulement dans ``errors.py`` : Starlette
traite l'exception générique dans ``ServerErrorMiddleware``, qui est *à l'extérieur* des
middlewares de l'application. Sa réponse 500 ne passerait donc ni par les en-têtes de
sécurité ni par CORS.

**Limite connue du délai.** Le calcul ML tourne dans un thread (``run_in_threadpool``),
qu'on ne peut pas interrompre : une attente réseau (corps lent, enrichissement) est
coupée à l'échéance, mais un calcul en cours va à son terme, puis sa réponse tardive est
jetée et remplacée par un 503. Garder le thread jusqu'au bout est voulu : le pool reste
borné (40 threads), alors qu'abandonner les threads laisserait un attaquant en empiler
sans limite. Ce calcul est lui-même borné par la taille des entrées (étape 4.2).
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from typing import Any

import anyio
from starlette.datastructures import MutableHeaders
from starlette.responses import Response
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from phishguard.api.errors import error_response
from phishguard.api.security import API_KEY_HEADER
from phishguard.api.settings import ApiSettings

logger = logging.getLogger(__name__)

DOCS_PATHS = frozenset({"/docs", "/docs/oauth2-redirect", "/redoc"})
HSTS_MAX_AGE = 31_536_000  # un an

# API JSON : rien à charger, rien à encadrer, aucun formulaire.
API_CSP = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
# Swagger UI et ReDoc, tels que FastAPI les sert : scripts et feuilles de style du CDN
# jsDelivr, un script en ligne d'initialisation, polices Google pour ReDoc, qui utilise
# aussi un worker ``blob:``. Développement seulement (refusé en production).
DOCS_CSP = (
    "default-src 'none'; "
    "script-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; "
    "style-src 'self' https://cdn.jsdelivr.net https://fonts.googleapis.com 'unsafe-inline'; "
    "font-src https://fonts.gstatic.com; "
    "img-src 'self' data: https://fastapi.tiangolo.com https://cdn.redoc.ly; "
    "connect-src 'self'; worker-src blob:; "
    "frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
)

SECURITY_HEADERS: Mapping[str, str] = {
    # Le navigateur ne devine jamais un type : du JSON reste du JSON.
    "X-Content-Type-Options": "nosniff",
    # Les réponses parlent des messages des utilisateurs : aucun cache, ni navigateur ni
    # proxy intermédiaire.
    "Cache-Control": "no-store",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": (
        "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), "
        "microphone=(), payment=(), usb=()"
    ),
    "X-Permitted-Cross-Domain-Policies": "none",
}

# CORS : ce que l'API accepte et ce qu'un client navigateur peut lire.
CORS_METHODS = ("GET", "POST")
CORS_REQUEST_HEADERS = ("Content-Type", API_KEY_HEADER)
CORS_EXPOSED_HEADERS = (
    "Retry-After",
    "X-RateLimit-Limit",
    "X-RateLimit-Remaining",
    "X-RateLimit-Reset",
)


def security_headers(settings: ApiSettings) -> dict[str, str]:
    """En-têtes ajoutés à toute réponse (hors politique de contenu, qui dépend du chemin).

    ``Strict-Transport-Security`` en production seulement : l'API y est derrière un
    proxy TLS. Un navigateur l'ignore sur une connexion en clair (RFC 6797).
    """
    headers = dict(SECURITY_HEADERS)
    if settings.is_production:
        headers["Strict-Transport-Security"] = f"max-age={HSTS_MAX_AGE}"
    return headers


class SecurityHeadersMiddleware:
    """Ajoute les en-têtes de sécurité à toute réponse HTTP, sans écraser ceux d'une route."""

    def __init__(self, app: ASGIApp, *, headers: Mapping[str, str], docs_enabled: bool) -> None:
        self.app = app
        self.headers = dict(headers)
        self.docs_enabled = docs_enabled

    def csp_for(self, path: str) -> str:
        return DOCS_CSP if self.docs_enabled and path in DOCS_PATHS else API_CSP

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        csp = self.csp_for(scope.get("path", "/"))

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                for name, value in self.headers.items():
                    if name not in headers:
                        headers[name] = value
                if "content-security-policy" not in headers:
                    headers["Content-Security-Policy"] = csp
            await send(message)

        await self.app(scope, receive, send_with_headers)


def cors_options(settings: ApiSettings) -> dict[str, Any] | None:
    """Options de ``CORSMiddleware`` ; ``None`` sans origine autorisée (pas de CORS)."""
    if not settings.cors_allowed_origins:
        return None
    return {
        "allow_origins": list(settings.cors_allowed_origins),
        "allow_methods": list(CORS_METHODS),
        "allow_headers": list(CORS_REQUEST_HEADERS),
        "expose_headers": list(CORS_EXPOSED_HEADERS),
        # Pas de cookie, pas d'authentification HTTP du navigateur : la clé d'API est un
        # en-tête explicite. Ne jamais passer à True avec une liste d'origines élargie.
        "allow_credentials": False,
        "max_age": settings.cors_max_age_seconds,
    }


class _Expired(Exception):
    """Le délai est passé au moment où l'application commence sa réponse."""


class RequestGuardMiddleware:
    """Délai maximal par requête et filet des exceptions non prévues.

    - délai dépassé pendant la lecture du corps : **408** (client trop lent) ;
    - délai dépassé ensuite : **503** avec ``Retry-After`` (serveur trop lent). Une
      réponse qui arrive après le délai est jetée et remplacée par ce 503 : le
      comportement ne dépend pas du moment où l'annulation atteint la route ;
    - exception non prévue : **500**, enveloppe commune, sans message ni trace.

    Si la réponse a déjà commencé, rien ne peut plus être envoyé : l'incident est
    journalisé et la connexion est fermée par le serveur.
    """

    def __init__(self, app: ASGIApp, *, timeout_seconds: float) -> None:
        self.app = app
        self.timeout_seconds = timeout_seconds

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        deadline = anyio.current_time() + self.timeout_seconds
        started = completed = body_complete = False

        async def tracking_receive() -> Message:
            nonlocal body_complete
            message = await receive()
            if message["type"] == "http.disconnect" or (
                message["type"] == "http.request" and not message.get("more_body", False)
            ):
                body_complete = True
            return message

        async def tracking_send(message: Message) -> None:
            nonlocal started, completed
            if message["type"] == "http.response.start":
                if anyio.current_time() >= deadline:
                    raise _Expired
                started = True
            elif message["type"] == "http.response.body" and not message.get("more_body", False):
                completed = True
            await send(message)

        try:
            with anyio.fail_after(self.timeout_seconds):
                await self.app(scope, tracking_receive, tracking_send)
        except (TimeoutError, _Expired):
            if completed:  # annulation livrée après la fin de la réponse : rien à faire
                return
            reading = not body_complete and _has_body(scope)
            logger.warning(
                "délai de requête dépassé (%s s, %s)",
                self.timeout_seconds,
                "lecture du corps" if reading else "traitement",
            )
            if started:
                return
            await _timeout_response(reading)(scope, receive, send)
        except Exception:
            logger.exception("erreur interne")
            if not started:
                await error_response(500, "internal_error", "Erreur interne du serveur.")(
                    scope, receive, send
                )


def _timeout_response(reading: bool) -> Response:
    if reading:
        return error_response(
            408,
            "request_timeout",
            "Corps de requête reçu trop lentement.",
            headers={"Connection": "close"},
        )
    return error_response(
        503, "timeout", "Délai de traitement dépassé.", headers={"Retry-After": "5"}
    )


def _has_body(scope: Scope) -> bool:
    """La requête annonce un corps (``Content-Length`` non nul ou envoi par morceaux)."""
    for name, value in scope.get("headers", ()):
        if name == b"content-length":
            return value.strip() not in {b"", b"0"}
        if name == b"transfer-encoding":
            return True
    return False
