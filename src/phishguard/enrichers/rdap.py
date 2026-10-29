"""Enrichisseur RDAP : âge du domaine et registraire (étape 2.7).

RDAP (*Registration Data Access Protocol*, RFC 9082 et 9083) est le successeur de WHOIS :
même information, mais en JSON structuré. Le serveur RDAP de chaque TLD est publié par
l'IANA dans un fichier d'amorçage (RFC 9224) ::

    GET https://data.iana.org/rdap/dns.json
    {"services": [[["com", "net"], ["https://rdap.verisign.com/com/v1/"]], ...]}

On interroge ensuite **directement le registre** (``{base}domain/{nom}``), plutôt qu'un
relais comme ``rdap.org`` qui verrait passer toutes les requêtes. Le fichier d'amorçage
est gardé en cache 24 heures.

Le signal utile est la date de l'événement ``registration`` : un domaine de quelques
jours est un signal fort de phishing (préparation d'infrastructure, MITRE ATT&CK
T1583.001). Barème de ``risk`` selon l'âge :

    moins de 7 jours : 1.0 · moins de 30 : 0.8 · moins de 90 : 0.4 · moins d'un an : 0.1

**Un signal manquant n'est pas un signal de risque.** Certains registres ne publient pas
la date, d'autres n'ont pas de serveur RDAP : ``risk`` vaut alors 0, jamais 1.
"""

from __future__ import annotations

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

BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
BOOTSTRAP_TTL = 24 * 3600.0
RESULT_TTL = 24 * 3600.0
RDAP_HEADERS = {"Accept": "application/rdap+json, application/json"}
# (âge maximal en jours, risque) : le premier seuil atteint s'applique.
AGE_RISK: tuple[tuple[int, float], ...] = ((7, 1.0), (30, 0.8), (90, 0.4), (365, 0.1))


def risk_from_age(age_days: int | None) -> float:
    if age_days is None or age_days < 0:
        return 0.0
    for limit, risk in AGE_RISK:
        if age_days < limit:
            return risk
    return 0.0


def parse_bootstrap(payload: object) -> dict[str, str]:
    """``{tld: url de base HTTPS}`` depuis le fichier d'amorçage de l'IANA."""
    if not isinstance(payload, dict) or not isinstance(payload.get("services"), list):
        raise MalformedResponse("fichier d'amorçage RDAP invalide")
    servers: dict[str, str] = {}
    for service in payload["services"]:
        if not (isinstance(service, list) and len(service) == 2):
            continue
        tlds, urls = service
        https = [u for u in urls if isinstance(u, str) and u.startswith("https://")]
        if not https:
            continue  # on n'interroge jamais un registre en HTTP clair
        base = https[0] if https[0].endswith("/") else https[0] + "/"
        for tld in tlds:
            if isinstance(tld, str):
                servers[tld.lower()] = base
    return servers


def server_for(domain: str, servers: dict[str, str]) -> str | None:
    """Serveur du suffixe le plus long présent dans l'amorçage (``co.uk`` avant ``uk``)."""
    labels = domain.split(".")
    for i in range(1, len(labels)):
        if (base := servers.get(".".join(labels[i:]))) is not None:
            return base
    return None


def _event(events: object, action: str) -> datetime | None:
    for event in events if isinstance(events, list) else ():
        if isinstance(event, dict) and event.get("eventAction") == action:
            return parse_iso_datetime(event.get("eventDate"))
    return None


def _registrar(entities: object) -> dict[str, Any] | None:
    for entity in entities if isinstance(entities, list) else ():
        if not isinstance(entity, dict) or "registrar" not in (entity.get("roles") or []):
            continue
        name = None
        vcard = entity.get("vcardArray")
        if isinstance(vcard, list) and len(vcard) == 2 and isinstance(vcard[1], list):
            for prop in vcard[1]:
                if isinstance(prop, list) and len(prop) == 4 and prop[0] == "fn":
                    name = prop[3] if isinstance(prop[3], str) else None
        iana_id = next(
            (
                p.get("identifier")
                for p in entity.get("publicIds") or []
                if isinstance(p, dict) and p.get("type") == "IANA Registrar ID"
            ),
            None,
        )
        return {"name": name, "iana_id": iana_id}
    return None


def parse_domain(payload: object, now: datetime) -> dict[str, Any]:
    """Éléments utiles d'une réponse RDAP ``domain`` (RFC 9083)."""
    if not isinstance(payload, dict) or payload.get("objectClassName") not in ("domain", None):
        raise MalformedResponse("réponse RDAP invalide")
    registered = _event(payload.get("events"), "registration")
    expires = _event(payload.get("events"), "expiration")
    age_days = (now - registered).days if registered else None
    return {
        "found": True,
        "registration_date": registered.isoformat() if registered else None,
        "expiration_date": expires.isoformat() if expires else None,
        "age_days": age_days,
        "registrar": _registrar(payload.get("entities")),
        "status": [s for s in payload.get("status") or [] if isinstance(s, str)][:10],
        "nameservers": sorted(
            str(ns.get("ldhName", "")).lower()
            for ns in payload.get("nameservers") or []
            if isinstance(ns, dict) and ns.get("ldhName")
        )[:10],
    }


class RdapEnricher(HttpEnricher):
    name = "rdap"

    def __init__(
        self,
        *,
        client: httpx.AsyncClient | None = None,
        cache_size: int = 10_000,
        clock: Callable[[], float] = time.monotonic,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        super().__init__(client=client)
        self._now = now
        self._cache: ExpiringCache[dict[str, Any]] = ExpiringCache(cache_size, clock)
        self._bootstrap: ExpiringCache[dict[str, str]] = ExpiringCache(1, clock)

    async def _enrich(self, url: str, domain: str) -> Signal:
        name = normalize_domain(domain)
        if name is None:
            return self.skipped("unsupported_input")
        if (cached := self._cache.get(name)) is not None:
            return self._signal(cached, cached=True)

        async with self.http() as client:
            servers = await self._servers(client)
            base = server_for(name, servers)
            if base is None:
                return self.skipped("no_rdap_server")
            response = await client.get(f"{base}domain/{name}", headers=RDAP_HEADERS)

        if response.status_code == 404:
            result: dict[str, Any] = {"found": False, "server": base}
        elif response.status_code != 200:
            return self.error(
                status_reason(response.status_code), {"http_status": response.status_code}
            )
        else:
            result = {**parse_domain(response.json(), self._now()), "server": base}
        self._cache.set(name, result, RESULT_TTL)
        return self._signal(result, cached=False)

    async def _servers(self, client: httpx.AsyncClient) -> dict[str, str]:
        if (servers := self._bootstrap.get("dns")) is not None:
            return servers
        response = await client.get(BOOTSTRAP_URL)
        response.raise_for_status()
        servers = parse_bootstrap(response.json())
        self._bootstrap.set("dns", servers, BOOTSTRAP_TTL)
        return servers

    def _signal(self, result: dict[str, Any], *, cached: bool) -> Signal:
        evidence = {**result, "cached": cached}
        if result.get("found") and result.get("age_days") is None:
            evidence["note"] = "registration_date_missing"  # absence de date : pas un risque
        return self.ok(risk_from_age(result.get("age_days")), evidence)
