"""Enrichisseur Certificate Transparency via crt.sh (étape 2.7, optionnel).

Les autorités de certification publient chaque certificat émis dans des journaux
publics (Certificate Transparency, RFC 6962). Le **premier certificat** d'un domaine
donne une idée de sa mise en service : un site de phishing obtient souvent son
certificat (Let's Encrypt, gratuit) quelques heures avant la campagne ::

    GET https://crt.sh/?q=exemple.com&output=json

crt.sh est un service gratuit, **lent et souvent instable**. D'où :

- source désactivée par défaut (``CRTSH_ENABLED``) ;
- délai strict, cache long (24 h), et jamais bloquant : un échec donne un signal
  ``error`` ou ``timeout``, sans risque ;
- réponse limitée à 2 Mo. Au-delà, le domaine a des milliers de certificats : c'est
  un domaine ancien et très utilisé, pas un domaine de quelques jours (``risk = 0``).

Barème : premier certificat de moins de 7 jours, ``risk`` 0,6 ; de moins de 30 jours,
0,3. C'est un signal plus faible que l'âge RDAP : un domaine ancien peut obtenir son
premier certificat tardivement.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

import httpx

from phishguard.enrichers.base import Signal
from phishguard.enrichers.http import (
    ExpiringCache,
    HttpEnricher,
    MalformedResponse,
    normalize_domain,
    parse_iso_datetime,
    status_reason,
)

ENDPOINT = "https://crt.sh/"
MAX_BYTES = 2_000_000
RESULT_TTL = 24 * 3600.0
TIMEOUT = httpx.Timeout(connect=2.0, read=5.0, write=2.0, pool=2.0)
AGE_RISK: tuple[tuple[int, float], ...] = ((7, 0.6), (30, 0.3))


class _TooLarge(Exception):
    pass


def risk_from_first_seen(days: int | None) -> float:
    if days is None or days < 0:
        return 0.0
    for limit, risk in AGE_RISK:
        if days < limit:
            return risk
    return 0.0


def parse_certificates(payload: object, now: datetime) -> dict[str, Any]:
    if not isinstance(payload, list):
        raise MalformedResponse("réponse crt.sh invalide")
    dates = [
        d
        for entry in payload
        if isinstance(entry, dict)
        and (d := parse_iso_datetime(entry.get("not_before") or entry.get("entry_timestamp")))
    ]
    first = min(dates) if dates else None
    return {
        "certificates": len(payload),
        "first_seen": first.isoformat() if first else None,
        "first_seen_days": (now - first).days if first else None,
        "many_certificates": False,
    }


async def _read_limited(response: httpx.Response, limit: int) -> bytes:
    body = bytearray()
    async for chunk in response.aiter_bytes():
        body.extend(chunk)
        if len(body) > limit:
            raise _TooLarge
    return bytes(body)


class CertificateTransparencyEnricher(HttpEnricher):
    name = "certificate_transparency"

    def __init__(
        self,
        *,
        enabled: bool = True,
        client: httpx.AsyncClient | None = None,
        max_bytes: int = MAX_BYTES,
        cache_size: int = 10_000,
        clock: Callable[[], float] = time.monotonic,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        super().__init__(client=client)
        self._enabled = enabled
        self._max_bytes = max_bytes
        self._now = now
        self._cache: ExpiringCache[dict[str, Any]] = ExpiringCache(cache_size, clock)

    def is_enabled(self) -> bool:
        return self._enabled

    async def _enrich(self, url: str, domain: str) -> Signal:
        name = normalize_domain(domain)
        if name is None:
            return self.skipped("unsupported_input")
        if (cached := self._cache.get(name)) is not None:
            return self._signal(cached, cached=True)

        async with self.http() as client:
            request = client.build_request(
                "GET", ENDPOINT, params={"q": name, "output": "json"}, timeout=TIMEOUT
            )
            response = await client.send(request, stream=True)
            try:
                if response.status_code != 200:
                    return self.error(
                        status_reason(response.status_code),
                        {"http_status": response.status_code},
                    )
                try:
                    body = await _read_limited(response, self._max_bytes)
                except _TooLarge:
                    body = None
            finally:
                await response.aclose()

        if body is None:
            result: dict[str, Any] = {
                "certificates": None,
                "first_seen": None,
                "first_seen_days": None,
                "many_certificates": True,
            }
        else:
            result = parse_certificates(json.loads(body) if body.strip() else [], self._now())
        self._cache.set(name, result, RESULT_TTL)
        return self._signal(result, cached=False)

    def _signal(self, result: dict[str, Any], *, cached: bool) -> Signal:
        return self.ok(
            risk_from_first_seen(result["first_seen_days"]), {**result, "cached": cached}
        )
