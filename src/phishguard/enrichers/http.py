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

import time
from collections import OrderedDict
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from typing import Generic, TypeVar

import httpx

from phishguard.enrichers.base import Enricher

USER_AGENT = "PhishGuard (+https://github.com/arixstoo/PhishGuard)"
DEFAULT_TIMEOUT = httpx.Timeout(connect=2.0, read=3.0, write=3.0, pool=2.0)

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
