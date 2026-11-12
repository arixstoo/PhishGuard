"""Journalisation sans données personnelles (étape 4.6), avec ``structlog``.

Une ligne par requête (événement ``request``) :

=================  ==========================================================
Champ              Contenu
=================  ==========================================================
``request_id``     identifiant aléatoire, renvoyé au client (``X-Request-ID``)
``method``         méthode HTTP
``route``          **modèle** de la route (``/v1/analyze/url``), jamais le chemin
``status``         statut HTTP
``duration_ms``    latence côté serveur
``client``         niveau du client (``anonymous``, ``authenticated``…)
``key_id``         identifiant public de la clé d'API, jamais la clé
``channel``        canal analysé (``url``, ``sms``, ``email``…)
``verdict``        verdict, ``score`` (0 à 100)
``model_version``  version du modèle qui a répondu
=================  ==========================================================

**Ne sont jamais journalisés** : le contenu des messages, les URLs (ni complètes, ni
leur hôte), les emails, les clés d'API, l'adresse IP du client, les en-têtes et la
chaîne de requête. La règle est tenue par construction, à trois niveaux :

1. **liste blanche** : la ligne de requête n'a que les champs ci-dessus, et les routes ne
   peuvent y ajouter que des champs de :data:`ANNOTATION_KEYS` (:func:`annotate`) ;
2. **exceptions sans message** : une trace ne garde que les types et les emplacements
   (``fichier:ligne dans fonction``). Le message d'une exception recopie souvent
   l'entrée : ``InvalidUrlError`` cite l'URL, une erreur ``httpx`` l'URL de la source
   appelée (avec, pour Safe Browsing, la clé dans la chaîne de requête) ;
3. **caviardage en dernier recours** (:func:`redact`) sur *tous* les journaux, ceux de
   PhishGuard comme ceux des bibliothèques : URLs, adresses email et clés d'API
   remplacées, champs sensibles masqués, caractères de contrôle neutralisés (pas
   d'injection de fausses lignes), chaînes tronquées.

uvicorn n'écrit plus son propre journal d'accès (``access_log=False``) : il contient le
chemin brut, la chaîne de requête et l'IP du client.

Format : JSON (une ligne par événement, ``ensure_ascii``) en production, texte lisible en
développement. :func:`configure_logging` est appelée par les points d'entrée
(``python -m phishguard.api``, ``phishguard.api.main:app``), jamais à l'import.
"""

from __future__ import annotations

import logging
import re
import sys
import time
import traceback
import uuid
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import PurePath
from typing import IO, Any

import structlog
from starlette.datastructures import MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send
from structlog.typing import EventDict, Processor, WrappedLogger

from phishguard.api.middleware import route_key
from phishguard.api.settings import ApiSettings

REQUEST_ID_HEADER = "X-Request-ID"
ACCESS_LOGGER = "phishguard.api.access"
HANDLER_NAME = "phishguard"

# Champs qu'une route peut ajouter à la ligne de sa requête.
ANNOTATION_KEYS = frozenset({"channel", "verdict", "score", "model_version", "threat_intel"})

# Champs masqués où qu'ils apparaissent (journal structuré ou ``extra``).
SENSITIVE_KEYS = frozenset(
    {
        "api_key",
        "authorization",
        "body",
        "client_ip",
        "content",
        "cookie",
        "domain",
        "email",
        "headers",
        "host",
        "ip",
        "key",
        "password",
        "query",
        "secret",
        "sender",
        "subject",
        "text",
        "token",
        "url",
    }
)
REDACTED = "[redacted]"
MAX_STRING = 1000
MAX_FRAMES = 12
MAX_CHAINED = 4

# Toute URL à schéma (``https://``, ``hxxp://``, ``ftp://``…) ou commençant par ``www.``.
_URL = re.compile(r"(?i)\b(?:[a-z][a-z0-9+.\-]{1,15}://|www\.)[^\s\"'<>\]\)]*")
_EMAIL = re.compile(r"[\w.+\-]+@[\w\-]+(?:\.[\w\-]+)+")
_API_KEY = re.compile(r"\bpg_[A-Za-z0-9_\-]{16,}")
# C0 (sauf aucun), DEL, C1 : un retour à la ligne injecté créerait une fausse entrée.
_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]")

# Processeurs communs : identifiant de requête, niveau, nom du journal, horodatage UTC.
SHARED_PROCESSORS: tuple[Processor, ...] = (
    structlog.contextvars.merge_contextvars,
    structlog.stdlib.add_log_level,
    structlog.stdlib.add_logger_name,
    structlog.processors.TimeStamper(fmt="iso", utc=True),
)

_request_fields: ContextVar[dict[str, Any] | None] = ContextVar("_request_fields", default=None)


# --------------------------------------------------------------------------- #
# Caviardage et exceptions
# --------------------------------------------------------------------------- #


def scrub(text: str) -> str:
    """Chaîne sans URL, email, clé d'API ni caractère de contrôle, tronquée."""
    text = _API_KEY.sub("[api-key]", text)
    text = _URL.sub("[url]", text)
    text = _EMAIL.sub("[email]", text)
    text = _CONTROL.sub("\N{REPLACEMENT CHARACTER}", text)
    if len(text) > MAX_STRING:
        text = text[:MAX_STRING] + "…[tronqué]"
    return text


def _scrub_value(value: Any, depth: int = 0) -> Any:
    if isinstance(value, str):
        return scrub(value)
    if isinstance(value, bool | int | float) or value is None:
        return value
    if depth >= 4:
        return "[…]"
    if isinstance(value, Mapping):
        return {
            str(k): REDACTED if str(k).lower() in SENSITIVE_KEYS else _scrub_value(v, depth + 1)
            for k, v in value.items()
        }
    if isinstance(value, list | tuple | set | frozenset):
        return [_scrub_value(v, depth + 1) for v in list(value)[:50]]
    # Objet quelconque : sa représentation peut contenir n'importe quoi.
    return scrub(f"<{type(value).__name__}>")


def redact(_logger: WrappedLogger, _method: str, event_dict: EventDict) -> EventDict:
    """Processeur ``structlog`` : dernier filet avant l'écriture (voir le module)."""
    for key in list(event_dict):
        if key.startswith("_"):
            continue
        if key.lower() in SENSITIVE_KEYS:
            event_dict[key] = REDACTED
        else:
            event_dict[key] = _scrub_value(event_dict[key])
    return event_dict


def _exception_of(exc_info: Any) -> BaseException | None:
    if isinstance(exc_info, BaseException):
        return exc_info
    if isinstance(exc_info, tuple) and len(exc_info) == 3:
        return exc_info[1]
    if exc_info is True:
        return sys.exc_info()[1]
    return None


def describe_exception(exc: BaseException) -> list[dict[str, Any]]:
    """Types et emplacements de l'exception et de ses causes, **sans aucun message**."""
    chain: list[dict[str, Any]] = []
    seen: set[int] = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen and len(chain) < MAX_CHAINED:
        seen.add(id(current))
        frames = traceback.extract_tb(current.__traceback__)[-MAX_FRAMES:]
        chain.append(
            {
                "type": f"{type(current).__module__}.{type(current).__qualname__}",
                "frames": [
                    f"{'/'.join(PurePath(f.filename).parts[-2:])}:{f.lineno} in {f.name}"
                    for f in frames
                ],
            }
        )
        current = current.__cause__ or (
            None if current.__suppress_context__ else current.__context__
        )
    return chain


def safe_exceptions(_logger: WrappedLogger, _method: str, event_dict: EventDict) -> EventDict:
    """Remplace ``exc_info`` par ``exc_summary`` (types et emplacements, sans message)."""
    event_dict.pop("stack_info", None)
    exc_info = event_dict.pop("exc_info", None)
    exc = _exception_of(exc_info) if exc_info else None
    if exc is not None:
        event_dict["exc_summary"] = describe_exception(exc)
    return event_dict


# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #


def _processors(json_format: bool) -> list[Processor]:
    renderer: Processor = (
        structlog.processors.JSONRenderer(sort_keys=False)
        if json_format
        else structlog.dev.ConsoleRenderer(colors=False, exception_formatter=_no_traceback)
    )
    return [
        structlog.stdlib.ProcessorFormatter.remove_processors_meta,
        safe_exceptions,
        redact,
        renderer,
    ]


def _no_traceback(_stream: IO[str], _exc_info: Any) -> None:
    """Le rendu texte n'imprime jamais de trace : ``safe_exceptions`` l'a résumée."""


def configure_logging(settings: ApiSettings, *, stream: IO[str] | None = None) -> logging.Handler:
    """Installe le gestionnaire du processus sur le journal racine (idempotent).

    Tous les journaux, ``structlog`` comme ``logging`` (PhishGuard, uvicorn, httpx…),
    passent par les mêmes processeurs : horodatage UTC, identifiant de requête,
    exceptions sans message, caviardage.
    """
    shared = list(SHARED_PROCESSORS)
    formatter = structlog.stdlib.ProcessorFormatter(
        foreign_pre_chain=shared,
        processors=_processors(settings.log_json),
    )
    handler = logging.StreamHandler(stream or sys.stderr)
    handler.set_name(HANDLER_NAME)
    handler.setFormatter(formatter)

    root = logging.getLogger()
    for existing in list(root.handlers):
        if existing.get_name() == HANDLER_NAME:
            root.removeHandler(existing)
    root.addHandler(handler)
    root.setLevel(settings.log_level)
    # uvicorn configure d'ordinaire ses propres gestionnaires ; lancé avec
    # ``log_config=None``, ses journaux remontent ici et sont caviardés comme les autres.
    for name in ("uvicorn", "uvicorn.error"):
        logging.getLogger(name).handlers.clear()
        logging.getLogger(name).propagate = True

    structlog.configure(
        processors=[*shared, structlog.stdlib.ProcessorFormatter.wrap_for_formatter],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )
    return handler


# Indépendant de ``structlog.configure`` : passe toujours par ``logging``, donc par le
# gestionnaire ci-dessus quand il est installé (et par ``caplog`` dans les tests).
access_logger = structlog.wrap_logger(
    logging.getLogger(ACCESS_LOGGER),
    processors=[*SHARED_PROCESSORS, structlog.stdlib.ProcessorFormatter.wrap_for_formatter],
    wrapper_class=structlog.stdlib.BoundLogger,
)


# --------------------------------------------------------------------------- #
# Champs de la requête
# --------------------------------------------------------------------------- #


def annotate(**fields: Any) -> None:
    """Ajoute des champs (liste blanche) à la ligne de journal de la requête courante."""
    unknown = set(fields) - ANNOTATION_KEYS
    if unknown:
        raise KeyError(f"champs de journal non autorisés : {sorted(unknown)}")
    current = _request_fields.get()
    if current is not None:
        current.update(fields)


def annotate_analysis(response: Any, **extra: Any) -> None:
    """Champs d'une réponse d'analyse : canal, verdict, score, version du modèle."""
    annotate(
        channel=str(response.channel),
        verdict=str(response.verdict),
        score=int(response.score),
        model_version=str(response.model_version),
        **extra,
    )


@contextmanager
def _request_scope(request_id: str) -> Iterator[dict[str, Any]]:
    fields: dict[str, Any] = {}
    token = _request_fields.set(fields)
    with structlog.contextvars.bound_contextvars(request_id=request_id):
        try:
            yield fields
        finally:
            _request_fields.reset(token)


class RequestLogMiddleware:
    """Identifiant de requête et ligne de journal ``request`` (voir le module).

    L'identifiant est toujours tiré par le serveur : un identifiant fourni par le client
    permettrait de brouiller la corrélation des journaux, ou d'y glisser du texte.
    """

    def __init__(self, app: ASGIApp, *, routes: frozenset[str] | set[str]) -> None:
        self.app = app
        self.routes = frozenset(routes)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        request_id = uuid.uuid4().hex
        status = 500
        started = time.perf_counter()

        async def send_with_id(message: Message) -> None:
            nonlocal status
            if message["type"] == "http.response.start":
                status = message["status"]
                MutableHeaders(scope=message)[REQUEST_ID_HEADER] = request_id
            await send(message)

        with _request_scope(request_id) as fields:
            try:
                await self.app(scope, receive, send_with_id)
            finally:
                client = scope.get("state", {}).get("client")
                level = logging.ERROR if status >= 500 else logging.INFO
                access_logger.log(
                    level,
                    "request",
                    method=scope.get("method"),
                    route=route_key(scope.get("path", "/"), self.routes),
                    status=status,
                    duration_ms=round((time.perf_counter() - started) * 1000, 2),
                    client=getattr(client, "kind", None),
                    key_id=getattr(client, "key_id", None),
                    **fields,
                )
