"""Enrichisseur urlscan.io (étape 2.6).

urlscan.io visite des pages dans un navigateur isolé et publie ce qu'il a vu : adresse
IP et pays du serveur, marques imitées, verdict, capture d'écran. Deux usages :

1. **Recherche des scans existants** (par défaut) : seul le **domaine** est envoyé ::

       GET https://urlscan.io/api/v1/search/?q=domain:exemple.com&size=10
       API-Key: <clé>

   ``domain:`` couvre aussi les domaines simplement *contactés* par une page (une
   police Google, un script de CDN) : on ne garde que les scans dont la page elle-même
   est sur le domaine (``page.domain`` égal au domaine ou à l'un de ses sous-domaines).
   Si le résultat le plus récent ne porte pas de verdict, on lit son rapport complet
   (``/api/v1/result/{uuid}/``).

2. **Soumission d'un scan** (option « analyse approfondie ») : désactivée par défaut
   (``URLSCAN_SUBMIT``). Elle envoie l'URL **complète** et fait visiter la page par
   urlscan, donc elle n'est jamais faite en visibilité ``public`` : un scan public
   expose l'URL, qui peut contenir l'adresse de la victime ou un jeton. Un scan prend
   plusieurs secondes : la soumission renvoie ``skipped`` avec l'identifiant du scan,
   que la recherche retrouvera aux appels suivants.

Risque : ``1.0`` si urlscan juge la page malveillante, sinon ``max(0, score) / 100``
(le score va de -100, légitime, à 100, malveillant). La capture d'écran est une simple
URL dans les preuves : à afficher comme une image, jamais à intégrer comme du HTML.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any, Literal

import httpx

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

API = "https://urlscan.io/api/v1"
SEARCH_SIZE = 10
SEARCH_TTL = 3600.0
MAX_SCANS_IN_EVIDENCE = 5
Visibility = Literal["unlisted", "private"]


class UrlscanEnricher(HttpEnricher):
    name = "urlscan"

    def __init__(
        self,
        api_key: str | None = None,
        *,
        client: httpx.AsyncClient | None = None,
        submit: bool = False,
        visibility: Visibility = "unlisted",
        cache_size: int = 10_000,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        super().__init__(client=client)
        if visibility not in ("unlisted", "private"):
            raise ValueError("visibilité refusée : seuls 'unlisted' et 'private' sont permis")
        self._api_key = api_key or None
        self._submit = submit
        self._visibility = visibility
        self._cache: ExpiringCache[dict[str, Any]] = ExpiringCache(cache_size, clock)
        # URL soumise -> uuid : évite de soumettre à nouveau un scan encore en cours.
        self._submitted: ExpiringCache[str] = ExpiringCache(cache_size, clock)

    @classmethod
    def from_settings(cls, settings: Settings | None = None, **kwargs: Any) -> UrlscanEnricher:
        settings = settings or get_settings()
        kwargs.setdefault("submit", settings.urlscan_submit)
        kwargs.setdefault("visibility", settings.urlscan_visibility)
        return cls(settings.api_key(cls.name), **kwargs)

    def is_enabled(self) -> bool:
        return self._api_key is not None

    @property
    def _headers(self) -> dict[str, str]:
        return {"API-Key": self._api_key or ""}

    async def _enrich(self, url: str, domain: str) -> Signal:
        name = normalize_domain(domain)
        if name is None:
            return self.skipped("unsupported_input")
        if (cached := self._cache.get(name)) is not None:
            return self._signal(cached, cached=True)

        async with self.http() as client:
            response = await client.get(
                f"{API}/search/",
                params={"q": f"domain:{name}", "size": SEARCH_SIZE},
                headers=self._headers,
            )
            if response.status_code != 200:
                return self._http_error(response)
            scans = _page_scans(response.json(), name)
            if not scans:
                if self._submit:
                    return await self._submit_scan(client, url)
                result: dict[str, Any] = {"found": False, "scans": []}
                self._cache.set(name, result, SEARCH_TTL)
                return self._signal(result, cached=False)

            latest = scans[0]
            if latest["verdict"] is None:
                latest["verdict"] = await self._fetch_verdict(client, latest["uuid"])

        result = {"found": True, "total": len(scans), "scans": scans[:MAX_SCANS_IN_EVIDENCE]}
        self._cache.set(name, result, SEARCH_TTL)
        return self._signal(result, cached=False)

    async def _fetch_verdict(self, client: httpx.AsyncClient, uuid: str) -> dict[str, Any] | None:
        """Verdict du rapport complet. Un rapport indisponible n'empêche pas le signal."""
        response = await client.get(f"{API}/result/{uuid}/", headers=self._headers)
        if response.status_code != 200:
            return None
        payload = response.json()
        return _verdict(payload.get("verdicts") if isinstance(payload, dict) else None)

    async def _submit_scan(self, client: httpx.AsyncClient, url: str) -> Signal:
        target = sanitize_url(url)
        if target is None:
            return self.ok(0.0, {"found": False, "scans": []})
        if (pending := self._submitted.get(target)) is not None:
            return Signal(
                source=self.name,
                status="skipped",
                evidence={"reason": "scan_pending", "uuid": pending},
            )
        response = await client.post(
            f"{API}/scan/",
            json={"url": target, "visibility": self._visibility},
            headers=self._headers,
        )
        if response.status_code != 200:
            return self._http_error(response)
        payload = response.json()
        if not isinstance(payload, dict) or not isinstance(payload.get("uuid"), str):
            raise MalformedResponse("réponse de soumission urlscan invalide")
        self._submitted.set(target, payload["uuid"], SEARCH_TTL)
        return Signal(
            source=self.name,
            status="skipped",
            evidence={
                "reason": "scan_submitted",
                "uuid": payload["uuid"],
                "requested_visibility": self._visibility,
                # urlscan peut imposer une autre visibilité : on garde celle qu'il annonce.
                "visibility": payload.get("visibility", self._visibility),
            },
        )

    def _http_error(self, response: httpx.Response) -> Signal:
        evidence: dict[str, Any] = {"http_status": response.status_code}
        if response.status_code == 429:
            evidence["retry_after_s"] = _float(response.headers.get("X-Rate-Limit-Reset-After"))
        return self.error(status_reason(response.status_code), evidence)

    def _signal(self, result: dict[str, Any], *, cached: bool) -> Signal:
        verdict = result["scans"][0]["verdict"] if result.get("scans") else None
        risk = 0.0
        if verdict:
            risk = 1.0 if verdict["malicious"] else max(0, verdict["score"]) / 100
        return self.ok(risk, {**result, "cached": cached})


# --------------------------------------------------------------------------- #
# Lecture des réponses
# --------------------------------------------------------------------------- #


def _page_scans(payload: object, domain: str) -> list[dict[str, Any]]:
    """Scans dont la page est sur ``domain`` ou un sous-domaine, du plus récent au plus ancien."""
    if not isinstance(payload, dict) or not isinstance(payload.get("results"), list):
        raise MalformedResponse("réponse de recherche urlscan invalide")
    scans = []
    for item in payload["results"]:
        if not isinstance(item, dict) or not isinstance(item.get("_id"), str):
            continue
        page = item.get("page") if isinstance(item.get("page"), dict) else {}
        task = item.get("task") if isinstance(item.get("task"), dict) else {}
        host = str(page.get("domain") or "").lower().rstrip(".")
        if host != domain and not host.endswith("." + domain):
            continue
        scans.append(
            {
                "uuid": item["_id"],
                "time": task.get("time"),
                "page_url": page.get("url"),
                "ip": page.get("ip"),
                "country": page.get("country"),
                "asn_name": page.get("asnname"),
                "server": page.get("server"),
                "status": page.get("status"),
                "verdict": _verdict(item.get("verdicts")),
                "screenshot": item.get("screenshot"),
            }
        )
    scans.sort(key=lambda s: str(s["time"] or ""), reverse=True)
    return scans


def _verdict(verdicts: object) -> dict[str, Any] | None:
    """Verdict global d'urlscan, ou ``None`` s'il n'y en a pas.

    Le rapport complet range le verdict sous ``verdicts.overall`` ; les résultats de
    recherche peuvent porter ``verdicts.malicious`` et ``verdicts.score`` directement.
    """
    if not isinstance(verdicts, dict):
        return None
    overall = verdicts.get("overall") if isinstance(verdicts.get("overall"), dict) else verdicts
    malicious, score = overall.get("malicious"), overall.get("score")
    if not isinstance(malicious, bool) and not isinstance(score, int | float):
        return None
    brands = overall.get("brands") or []
    return {
        "malicious": malicious is True,
        "score": int(score) if isinstance(score, int | float) else 0,
        "brands": sorted({_brand(b) for b in brands if _brand(b)})[:10],
        "categories": [c for c in overall.get("categories") or [] if isinstance(c, str)][:10],
    }


def _brand(value: object) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        return str(value.get("name") or value.get("key") or "")
    return ""


def _float(value: str | None) -> float | None:
    try:
        return float(value) if value is not None else None
    except ValueError:
        return None
