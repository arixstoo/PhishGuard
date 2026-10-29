"""Enrichisseur Google Safe Browsing (étape 2.4).

**Version de l'API.** Google propose aujourd'hui la v5 ; la v4 (Lookup et Update API)
fonctionne toujours. On utilise le mode « temps réel » de la v5, ``urls:search``, qui
remplace la recherche directe de la v4 (``threatMatches:find``) :

    GET https://safebrowsing.googleapis.com/v5/urls:search?urls=<url>&alt=json
    X-Goog-Api-Key: <clé>

Réponse : ``{"threats": [{"url": …, "threatTypes": ["SOCIAL_ENGINEERING"]}],
"cacheDuration": "300s"}``. Sans correspondance, ``threats`` est absent. Le serveur
vérifie l'URL et ses expressions « suffixe d'hôte / préfixe de chemin », donc une
correspondance peut porter sur une variante plus courte de l'URL demandée.

Choix de mise en œuvre :

- ``alt=json`` : sans lui, la v5 répond en protobuf binaire ;
- la clé part dans l'en-tête ``X-Goog-Api-Key``, pas dans l'URL : elle n'apparaît
  ni dans les journaux d'accès ni dans le message d'une exception ``httpx`` ;
- les réponses sont mises en cache pour la durée ``cacheDuration`` indiquée par Google
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

import re
import time
from collections.abc import Callable
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
# Types connus : MALWARE, SOCIAL_ENGINEERING, UNWANTED_SOFTWARE, POTENTIALLY_HARMFUL_APPLICATION.
# Un type inconnu (ajouté plus tard par Google) compte aussi comme une correspondance.
UNSPECIFIED = "THREAT_TYPE_UNSPECIFIED"  # à ignorer, d'après la documentation
DEFAULT_CACHE_SECONDS = 300.0
MAX_CLEAN_CACHE_SECONDS = 24 * 3600.0  # plafond fixé par Google pour un résultat négatif
MAX_URL_LENGTH = 8_000
_DURATION = re.compile(r"^\s*(\d+(?:\.\d+)?)s\s*$")


def parse_duration(value: object, default: float = DEFAULT_CACHE_SECONDS) -> float:
    """Durée protobuf JSON (``"300s"``, ``"1.5s"``) en secondes."""
    if isinstance(value, str) and (match := _DURATION.match(value)):
        return float(match.group(1))
    return default


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
                params={"urls": query, "alt": "json"},
                headers={"X-Goog-Api-Key": self._api_key or ""},
            )
        if response.status_code != 200:
            return self.error(_error_reason(response), {"http_status": response.status_code})

        result = self._parse(response.json())
        ttl = result.pop("cache_seconds")
        self._cache.set(
            query, result, ttl if result["listed"] else min(ttl, MAX_CLEAN_CACHE_SECONDS)
        )
        return self._signal(result, cached=False)

    @staticmethod
    def _parse(payload: object) -> dict[str, Any]:
        if not isinstance(payload, dict):
            raise MalformedResponse("réponse Safe Browsing inattendue")
        threats = payload.get("threats") or []
        if not isinstance(threats, list):
            raise MalformedResponse("champ threats invalide")
        types: set[str] = set()
        matched: list[str] = []
        for threat in threats:
            if not isinstance(threat, dict):
                continue
            found = {t for t in threat.get("threatTypes") or [] if isinstance(t, str)}
            found.discard(UNSPECIFIED)
            if found:
                types |= found
                if isinstance(threat.get("url"), str):
                    matched.append(threat["url"])
        return {
            "listed": bool(types),
            "threat_types": sorted(types),
            "matched_urls": matched[:10],
            "cache_seconds": parse_duration(payload.get("cacheDuration")),
        }

    def _signal(self, result: dict[str, Any], *, cached: bool) -> Signal:
        evidence = {**result, "cached": cached, "api": "v5"}
        return self.ok(risk=1.0 if result["listed"] else 0.0, evidence=evidence)


def _error_reason(response: httpx.Response) -> str:
    """Les API Google répondent 400 (et non 401) à une clé invalide : on le distingue."""
    if response.status_code == 400 and b"API_KEY_INVALID" in response.content[:4096]:
        return "invalid_api_key"
    return status_reason(response.status_code)
