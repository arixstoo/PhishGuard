"""Enrichisseur Google Safe Browsing (étape 2.4).

**Version de l'API.** Google propose aujourd'hui la v5 ; la v4 (Lookup et Update API)
fonctionne toujours. On utilise le mode « temps réel » de la v5, ``urls:search``, qui
remplace la recherche directe de la v4 (``threatMatches:find``) :

    GET https://safebrowsing.googleapis.com/v5/urls:search?urls=<url>
    X-Goog-Api-Key: <clé>

**La v5 ne répond qu'en protobuf** (``application/x-protobuf``) : ``alt=json`` est
refusé par un 400 « Unsupported Output Format » (vérifié contre l'API réelle le
01/11/2026). La réponse est un ``SearchUrlsResponse`` ::

    message SearchUrlsResponse {
      repeated ThreatUrl threats = 1;          // absent sans correspondance
      google.protobuf.Duration cache_duration = 2;
    }
    message ThreatUrl {
      string url = 1;
      repeated ThreatType threat_types = 2;    // encodage « packed »
    }

Ce message est assez petit pour être décodé ici, sans dépendre de ``protobuf`` ni de
fichiers générés. Le serveur vérifie l'URL et ses expressions « suffixe d'hôte / préfixe
de chemin », donc une correspondance peut porter sur une variante plus courte de l'URL.

Choix de mise en œuvre :

- la clé part dans l'en-tête ``X-Goog-Api-Key``, pas dans l'URL : elle n'apparaît
  ni dans les journaux d'accès ni dans le message d'une exception ``httpx`` ;
- les réponses sont mises en cache pour la durée ``cache_duration`` indiquée par Google
  (au plus 24 h sans correspondance), comme le demandent les conditions d'utilisation ;
- **vie privée** : l'URL complète est envoyée à Google. L'enrichissement n'est appelé que
  si l'utilisateur l'a activé (étape 2.9). On retire avant l'envoi le fragment et les
  identifiants (``user:pass@``), que la canonicalisation de Safe Browsing ignore de
  toute façon : la détection est la même, la fuite en moins.

**Conditions** : l'API Safe Browsing est réservée à un usage non commercial ; un usage
commercial passe par Web Risk. Une correspondance est une règle dure pour la fusion
(étape 2.10) : ``risk = 1.0`` et ``evidence["listed"] = True``.

Plus tard (version 2) : base locale de préfixes de hachage (``hashLists`` de la v5), qui
évite d'envoyer l'URL.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Iterator
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import httpx

from phishguard.config import Settings, get_settings
from phishguard.enrichers.base import Signal
from phishguard.enrichers.http import (
    ExpiringCache,
    HttpEnricher,
    MalformedResponse,
    status_reason,
)

ENDPOINT = "https://safebrowsing.googleapis.com/v5/urls:search"
PROTOBUF = "application/x-protobuf"
# Énumération ThreatType de la v5. 0 (THREAT_TYPE_UNSPECIFIED) est ignoré, d'après la
# documentation ; une valeur inconnue (ajoutée plus tard par Google) compte aussi comme
# une correspondance.
THREAT_TYPES = {
    1: "MALWARE",
    2: "SOCIAL_ENGINEERING",
    3: "UNWANTED_SOFTWARE",
    4: "POTENTIALLY_HARMFUL_APPLICATION",
}
DEFAULT_CACHE_SECONDS = 300.0
MAX_CLEAN_CACHE_SECONDS = 24 * 3600.0  # plafond fixé par Google pour un résultat négatif
MAX_URL_LENGTH = 8_000
_VARINT, _I64, _LEN, _I32 = 0, 1, 2, 5  # types de fil (wire types) protobuf


# --------------------------------------------------------------------------- #
# Décodage protobuf minimal
# --------------------------------------------------------------------------- #


def _varint(buf: bytes, pos: int) -> tuple[int, int]:
    result = shift = 0
    while True:
        if pos >= len(buf):
            raise MalformedResponse("varint protobuf tronqué")
        byte = buf[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, pos
        shift += 7
        if shift >= 64:
            raise MalformedResponse("varint protobuf trop long")


def _fields(buf: bytes) -> Iterator[tuple[int, int, int | bytes]]:
    """Champs ``(numéro, type de fil, valeur)`` d'un message protobuf, dans l'ordre."""
    pos = 0
    while pos < len(buf):
        key, pos = _varint(buf, pos)
        number, wire = key >> 3, key & 7
        value: int | bytes
        if wire == _VARINT:
            value, pos = _varint(buf, pos)
        elif wire in (_LEN, _I64, _I32):
            if wire == _LEN:
                size, pos = _varint(buf, pos)
            else:
                size = 8 if wire == _I64 else 4
            if pos + size > len(buf):
                raise MalformedResponse("champ protobuf tronqué")
            value, pos = buf[pos : pos + size], pos + size
        else:
            raise MalformedResponse(f"type de fil protobuf non géré : {wire}")
        if number == 0:
            raise MalformedResponse("numéro de champ protobuf invalide")
        yield number, wire, value


def _packed_varints(value: int | bytes) -> list[int]:
    """Champ ``repeated`` d'entiers : une valeur seule, ou une suite « packed »."""
    if isinstance(value, int):
        return [value]
    numbers, pos = [], 0
    while pos < len(value):
        number, pos = _varint(value, pos)
        numbers.append(number)
    return numbers


def _threat_url(buf: bytes) -> tuple[str | None, set[str]]:
    url: str | None = None
    types: set[str] = set()
    for number, wire, value in _fields(buf):
        if number == 1 and isinstance(value, bytes):
            url = value.decode("utf-8", errors="replace")
        elif number == 2 and wire in (_VARINT, _LEN):
            types |= {THREAT_TYPES.get(n, f"THREAT_TYPE_{n}") for n in _packed_varints(value) if n}
    return url, types


def _duration(buf: bytes) -> float:
    """``google.protobuf.Duration`` (secondes, nanosecondes) en secondes."""
    seconds = nanos = 0
    for number, _wire, value in _fields(buf):
        if number == 1 and isinstance(value, int):
            seconds = value
        elif number == 2 and isinstance(value, int):
            nanos = value
    return seconds + nanos / 1e9


def parse_search_response(content: bytes) -> dict[str, Any]:
    """Décode un ``SearchUrlsResponse``. Lève :class:`MalformedResponse` s'il est invalide.

    Les champs inconnus sont ignorés, comme le veut protobuf : un champ ajouté plus tard
    par Google ne casse pas le décodage.
    """
    types: set[str] = set()
    matched: list[str] = []
    cache_seconds = DEFAULT_CACHE_SECONDS
    for number, wire, value in _fields(content):
        if number == 1 and wire == _LEN and isinstance(value, bytes):
            url, found = _threat_url(value)
            if found:
                types |= found
                if url:
                    matched.append(url)
        elif number == 2 and wire == _LEN and isinstance(value, bytes):
            cache_seconds = _duration(value)
    return {
        "listed": bool(types),
        "threat_types": sorted(types),
        "matched_urls": matched[:10],
        "cache_seconds": cache_seconds,
    }


def sanitize_url(url: str) -> str | None:
    """URL à envoyer : sans fragment ni identifiants. ``None`` si elle n'est pas web."""
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


class SafeBrowsingEnricher(HttpEnricher):
    name = "google_safe_browsing"

    def __init__(
        self,
        api_key: str | None = None,
        *,
        client: httpx.AsyncClient | None = None,
        cache_size: int = 10_000,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        super().__init__(client=client)
        self._api_key = api_key or None
        self._cache: ExpiringCache[dict[str, Any]] = ExpiringCache(cache_size, clock)

    @classmethod
    def from_settings(cls, settings: Settings | None = None, **kwargs: Any) -> SafeBrowsingEnricher:
        settings = settings or get_settings()
        return cls(settings.api_key(cls.name), **kwargs)

    def is_enabled(self) -> bool:
        return self._api_key is not None

    async def _enrich(self, url: str, domain: str) -> Signal:
        query = sanitize_url(url)
        if query is None:
            return self.skipped("unsupported_url")
        if (cached := self._cache.get(query)) is not None:
            return self._signal(cached, cached=True)

        async with self.http() as client:
            response = await client.get(
                ENDPOINT,
                params={"urls": query},
                headers={"X-Goog-Api-Key": self._api_key or ""},
            )
        if response.status_code != 200:
            return self.error(_error_reason(response), {"http_status": response.status_code})

        if response.headers.get("content-type", "").split(";")[0].strip() != PROTOBUF:
            raise MalformedResponse("réponse Safe Browsing qui n'est pas du protobuf")
        result = parse_search_response(response.content)
        ttl = result.pop("cache_seconds")
        self._cache.set(
            query, result, ttl if result["listed"] else min(ttl, MAX_CLEAN_CACHE_SECONDS)
        )
        return self._signal(result, cached=False)

    def _signal(self, result: dict[str, Any], *, cached: bool) -> Signal:
        evidence = {**result, "cached": cached, "api": "v5"}
        return self.ok(risk=1.0 if result["listed"] else 0.0, evidence=evidence)


def _error_reason(response: httpx.Response) -> str:
    """Les API Google répondent 400 (et non 401) à une clé invalide : on le distingue."""
    if response.status_code == 400 and b"API_KEY_INVALID" in response.content[:4096]:
        return "invalid_api_key"
    return status_reason(response.status_code)
