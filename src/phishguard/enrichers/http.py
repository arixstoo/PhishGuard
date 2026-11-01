"""Socle HTTP commun des enrichisseurs qui appellent une API (étapes 2.4 à 2.7).

Les enrichisseurs contactent des **adresses fixes** (``safebrowsing.googleapis.com``,
``www.virustotal.com``…) : l'URL de l'utilisateur n'est qu'un paramètre de la requête,
jamais une destination. Ils n'ont donc pas besoin du garde-fou anti-SSRF de l'étape 2.3
(voir ``docs/ssrf.md``), mais ils partagent les mêmes règles : délais courts, pas de
redirection suivie, un ``User-Agent`` identifiable.

Un client ``httpx.AsyncClient`` peut être injecté (tests, client partagé de l'étape 2.8) ;
sinon, un client à durée de vie courte est créé pour chaque appel.
"""

from __future__ import annotations

import ipaddress
import re
import time
from collections import OrderedDict
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import Generic, TypeVar
from urllib.parse import urlsplit, urlunsplit

import httpx

from phishguard.enrichers.base import Enricher

USER_AGENT = "PhishGuard (+https://github.com/arixstoo/PhishGuard)"
DEFAULT_TIMEOUT = httpx.Timeout(connect=2.0, read=3.0, write=3.0, pool=2.0)
MAX_URL_LENGTH = 8_000
_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")

V = TypeVar("V")


class MalformedResponse(ValueError):
    """La source a répondu, mais pas dans le format documenté."""


class HttpEnricher(Enricher):
    """Enrichisseur qui interroge une API HTTP. Classe intermédiaire, encore abstraite."""

    def __init__(self, *, client: httpx.AsyncClient | None = None) -> None:
        self._client = client

    @asynccontextmanager
    async def http(self) -> AsyncIterator[httpx.AsyncClient]:
        if self._client is not None:
            yield self._client
            return
        async with httpx.AsyncClient(
            timeout=DEFAULT_TIMEOUT,
            headers={"User-Agent": USER_AGENT},
            follow_redirects=False,
        ) as client:
            yield client


def sanitize_url(url: str) -> str | None:
    """URL à envoyer à un tiers : sans fragment ni identifiants (``user:pass@``).

    Renvoie ``None`` si l'URL n'est pas une URL web (``http`` ou ``https``) valide.
    """
    try:
        parts = urlsplit(url.strip())
    except ValueError:
        return None
    if parts.scheme.lower() not in ("http", "https") or not parts.hostname:
        return None
    netloc = parts.hostname if ":" not in parts.hostname else f"[{parts.hostname}]"
    try:
        port = parts.port
    except ValueError:
        return None
    if port is not None:
        netloc = f"{netloc}:{port}"
    cleaned = urlunsplit((parts.scheme.lower(), netloc, parts.path, parts.query, ""))
    return cleaned if len(cleaned) <= MAX_URL_LENGTH else None


def normalize_domain(domain: str) -> str | None:
    """Nom de domaine en minuscules et en ASCII (punycode), ou ``None`` s'il est invalide.

    Une adresse IP n'est pas un nom de domaine : elle renvoie ``None``.
    """
    name = domain.strip().lower().rstrip(".")
    try:
        ipaddress.ip_address(name.strip("[]"))
        return None
    except ValueError:
        pass
    try:
        name = name.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    labels = name.split(".")
    if len(name) > 253 or len(labels) < 2 or not all(_LABEL.match(label) for label in labels):
        return None
    return name


def parse_iso_datetime(value: object) -> datetime | None:
    """Date ISO 8601 (``2026-10-29T12:00:00Z``) en ``datetime`` UTC, ou ``None``.

    Une date sans fuseau horaire est lue comme UTC.
    """
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def status_reason(status_code: int) -> str:
    """Code d'erreur stable pour une réponse HTTP non réussie."""
    if status_code in (401, 403):
        return "unauthorized"  # clé invalide, révoquée ou non autorisée pour cette API
    if status_code == 404:
        return "not_found"
    if status_code == 429:
        return "rate_limited"
    if status_code >= 500:
        return "server_error"
    return f"http_{status_code}"


class ExpiringCache(Generic[V]):
    """Cache mémoire à durée de vie par entrée et taille bornée (le plus ancien sort).

    Volontairement minimal : l'étape 2.8 le remplacera par un cache partagé.
    ``clock`` est injectable pour les tests.
    """

    def __init__(self, maxsize: int = 10_000, clock: Callable[[], float] = time.monotonic):
        if maxsize < 1:
            raise ValueError("maxsize doit être positif")
        self.maxsize = maxsize
        self._clock = clock
        self._data: OrderedDict[str, tuple[float, V]] = OrderedDict()

    def get(self, key: str) -> V | None:
        item = self._data.get(key)
        if item is None:
            return None
        expires, value = item
        if self._clock() >= expires:
            del self._data[key]
            return None
        return value

    def set(self, key: str, value: V, ttl: float) -> None:
        if ttl <= 0:
            return
        self._data.pop(key, None)
        self._data[key] = (self._clock() + ttl, value)
        while len(self._data) > self.maxsize:
            self._data.popitem(last=False)

    def __len__(self) -> int:
        return len(self._data)
