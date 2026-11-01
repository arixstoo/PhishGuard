"""Enrichisseur VirusTotal, API v3 (étape 2.5).

VirusTotal agrège les verdicts de plusieurs dizaines de moteurs. On lit le dernier
rapport existant, **sans jamais soumettre** l'URL à une nouvelle analyse :

    GET https://www.virustotal.com/api/v3/urls/{id}        x-apikey: <clé>
    GET https://www.virustotal.com/api/v3/domains/{domaine}

``id`` est l'URL encodée en base64 « url-safe », **sans** les ``=`` de remplissage.
On interroge d'abord l'URL, puis, si VirusTotal ne la connaît pas (404), le domaine.

Risque : ``min(1, (malicious + 0.5 * suspicious) / 5)`` sur ``last_analysis_stats``.
Cinq moteurs qui déclarent l'URL malveillante suffisent à atteindre 1 ; un moteur seul
(faux positifs fréquents) ne donne que 0,2.

**Quota.** Le palier public est d'environ 4 requêtes par minute et 500 par jour, pour
un usage **non commercial** seulement (voir les conditions de VirusTotal). Un limiteur
local (``aiolimiter``, seau percé) et un compteur journalier protègent ce quota : quand
il est atteint, la source renvoie ``skipped`` au lieu d'attendre (ou attend au plus
``max_wait`` secondes). Les résultats sont mis en cache pour économiser le quota.

**Vie privée.** L'URL est envoyée à VirusTotal, sans fragment ni identifiants ;
l'enrichissement n'est appelé que si l'utilisateur l'a activé (étape 2.9).
"""

from __future__ import annotations

import asyncio
import base64
import time
from collections.abc import Callable, Sequence
from datetime import UTC, date, datetime
from typing import Any, Literal

import httpx
from aiolimiter import AsyncLimiter

from phishguard.config import Settings, get_settings
from phishguard.enrichers.base import Signal
from phishguard.enrichers.http import (
    ExpiringCache,
    HttpEnricher,
    MalformedResponse,
    normalize_domain,
    sanitize_url,
    status_reason,
)

API = "https://www.virustotal.com/api/v3"
GUI = "https://www.virustotal.com/gui"
PUBLIC_PER_MINUTE = 4
PUBLIC_PER_DAY = 500
ENGINES_FOR_FULL_RISK = 5
FOUND_TTL = 6 * 3600.0
NOT_FOUND_TTL = 3600.0
MAX_FLAGGED_ENGINES = 10

Lookup = Literal["url", "domain"]
_NOT_FOUND: dict[str, Any] = {"found": False}


def url_id(url: str) -> str:
    """Identifiant VirusTotal d'une URL : base64 url-safe sans remplissage."""
    return base64.urlsafe_b64encode(url.encode()).decode("ascii").rstrip("=")


def risk_from_stats(stats: dict[str, Any]) -> float:
    malicious = _count(stats, "malicious")
    suspicious = _count(stats, "suspicious")
    return min(1.0, (malicious + 0.5 * suspicious) / ENGINES_FOR_FULL_RISK)


def _count(stats: dict[str, Any], key: str) -> int:
    value = stats.get(key, 0)
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise MalformedResponse(f"last_analysis_stats.{key} invalide")
    return value


class DailyQuota:
    """Compteur de requêtes remis à zéro chaque jour (UTC)."""

    def __init__(self, limit: int, today: Callable[[], date] | None = None) -> None:
        self.limit = limit
        self._today = today or (lambda: datetime.now(UTC).date())
        self._day = self._today()
        self.used = 0

    def _roll(self) -> None:
        if (day := self._today()) != self._day:
            self._day, self.used = day, 0

    def remaining(self) -> int:
        self._roll()
        return max(0, self.limit - self.used)

    def consume(self) -> None:
        self._roll()
        self.used += 1


class VirusTotalEnricher(HttpEnricher):
    name = "virustotal"

    def __init__(
        self,
        api_key: str | None = None,
        *,
        client: httpx.AsyncClient | None = None,
        lookups: Sequence[Lookup] = ("url", "domain"),
        per_minute: int = PUBLIC_PER_MINUTE,
        per_day: int = PUBLIC_PER_DAY,
        rate_period: float = 60.0,
        max_wait: float = 0.0,
        cache_size: int = 10_000,
        clock: Callable[[], float] = time.monotonic,
        today: Callable[[], date] | None = None,
    ) -> None:
        super().__init__(client=client)
        if not lookups or not set(lookups) <= {"url", "domain"}:
            raise ValueError("lookups doit contenir 'url' et/ou 'domain'")
        self._api_key = api_key or None
        self._lookups = tuple(lookups)
        self._limiter = AsyncLimiter(per_minute, rate_period)
        self._quota = DailyQuota(per_day, today)
        self._max_wait = max_wait
        self._cache: ExpiringCache[dict[str, Any]] = ExpiringCache(cache_size, clock)

    @classmethod
    def from_settings(cls, settings: Settings | None = None, **kwargs: Any) -> VirusTotalEnricher:
        settings = settings or get_settings()
        return cls(settings.api_key(cls.name), **kwargs)

    def is_enabled(self) -> bool:
        return self._api_key is not None

    async def _enrich(self, url: str, domain: str) -> Signal:
        targets = self._targets(url, domain)
        if not targets:
            return self.skipped("unsupported_input")
        checked: list[str] = []
        for kind, value, path in targets:
            key = f"{kind}:{value}"
            if (cached := self._cache.get(key)) is not None:
                if cached["found"]:
                    return self._signal(cached, cached=True)
                checked.append(kind)
                continue
            if not await self._reserve():
                return Signal(
                    source=self.name,
                    status="skipped",
                    evidence={"reason": "local_rate_limit", "checked": checked},
                )
            async with self.http() as client:
                response = await client.get(f"{API}/{path}", headers={"x-apikey": self._api_key})
            checked.append(kind)
            if response.status_code == 404:
                self._cache.set(key, _NOT_FOUND, NOT_FOUND_TTL)
                continue
            if response.status_code != 200:
                return self.error(
                    status_reason(response.status_code),
                    {"http_status": response.status_code, "vt_error": _vt_error(response)},
                )
            result = self._parse(kind, response.json())
            self._cache.set(key, result, FOUND_TTL)
            return self._signal(result, cached=False)
        return self.ok(0.0, {"found": False, "checked": checked})

    def _targets(self, url: str, domain: str) -> list[tuple[Lookup, str, str]]:
        targets: list[tuple[Lookup, str, str]] = []
        for kind in self._lookups:
            if kind == "url" and (clean := sanitize_url(url)):
                targets.append(("url", clean, f"urls/{url_id(clean)}"))
            elif kind == "domain" and (name := normalize_domain(domain)):
                targets.append(("domain", name, f"domains/{name}"))
        return targets

    async def _reserve(self) -> bool:
        """Réserve une requête dans le quota local, sans attendre plus de ``max_wait``."""
        if self._quota.remaining() <= 0:
            return False
        if not self._limiter.has_capacity():
            if self._max_wait <= 0:
                return False
            try:
                await asyncio.wait_for(self._limiter.acquire(), self._max_wait)
            except TimeoutError:
                return False
        else:
            await self._limiter.acquire()
        self._quota.consume()
        return True

    @staticmethod
    def _parse(kind: Lookup, payload: object) -> dict[str, Any]:
        try:
            data = payload["data"]  # type: ignore[index]
            attributes = data["attributes"]
            stats = attributes["last_analysis_stats"]
            object_id = data["id"]
        except (KeyError, TypeError):
            raise MalformedResponse("rapport VirusTotal incomplet") from None
        if not isinstance(stats, dict) or not isinstance(object_id, str):
            raise MalformedResponse("rapport VirusTotal invalide")
        results = attributes.get("last_analysis_results") or {}
        flagged = sorted(
            engine
            for engine, verdict in (results.items() if isinstance(results, dict) else ())
            if isinstance(verdict, dict) and verdict.get("category") in ("malicious", "suspicious")
        )
        analysed = attributes.get("last_analysis_date")
        return {
            "found": True,
            "object": kind,
            "stats": {
                k: _count(stats, k) for k in ("malicious", "suspicious", "harmless", "undetected")
            },
            "flagged_by": flagged[:MAX_FLAGGED_ENGINES],
            "reputation": attributes.get("reputation"),
            "last_analysis_date": (
                datetime.fromtimestamp(analysed, UTC).isoformat()
                if isinstance(analysed, int | float)
                else None
            ),
            "permalink": f"{GUI}/{kind}/{object_id}",
        }

    def _signal(self, result: dict[str, Any], *, cached: bool) -> Signal:
        return self.ok(risk_from_stats(result["stats"]), {**result, "cached": cached})


def _vt_error(response: httpx.Response) -> str | None:
    """Code d'erreur VirusTotal (``QuotaExceededError``, ``WrongCredentialsError``…)."""
    try:
        code = response.json()["error"]["code"]
    except (ValueError, KeyError, TypeError):
        return None
    return code if isinstance(code, str) else None
