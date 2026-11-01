"""Enrichisseur DNS : enregistrements A, AAAA, MX et NS (étape 2.7).

Le DNS dit comment un domaine est hébergé. Ce sont des signaux **faibles**, utiles
surtout en combinaison :

- **NS d'un fournisseur de DNS gratuit ou dynamique** (afraid.org, DuckDNS…) : très
  courant pour des domaines jetables. ``risk`` 0,3 ;
- **allure de *fast flux*** : beaucoup d'adresses A (5 ou plus) avec un TTL très bas
  (moins de 300 s), pour faire tourner l'hébergement et résister aux blocages. ``risk``
  0,3. Un TTL bas seul n'est pas retenu : les CDN légitimes l'utilisent aussi ;
- **pas de MX**, ou un « MX nul » (RFC 7505) : le domaine ne reçoit pas d'email. Ce
  n'est pas un risque pour une URL, mais c'est une incohérence forte pour un domaine qui
  prétend envoyer des emails : l'information est gardée pour le score email.

Le risque est plafonné à 0,5 : le DNS seul ne suffit jamais à conclure. Un domaine qui
n'existe pas (NXDOMAIN) donne ``risk = 0`` : un signal manquant n'est pas un risque.

La résolution passe par ``dnspython`` et le résolveur du système. Elle est injectable
(``lookup``) pour les tests.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable

import dns.asyncresolver
import dns.exception
import dns.resolver

from phishguard.enrichers.base import Enricher, Signal
from phishguard.enrichers.http import normalize_domain

RECORD_TYPES = ("A", "AAAA", "MX", "NS")
LOOKUP_LIFETIME = 2.0
LOW_TTL = 300
FAST_FLUX_MIN_ADDRESSES = 5
MAX_RISK = 0.5
MAX_VALUES = 10
# Fournisseurs de DNS gratuits ou dynamiques, très utilisés pour des domaines jetables.
FREE_DNS_PROVIDERS = (
    "afraid.org",
    "duckdns.org",
    "freenom.com",
    "dynu.com",
    "no-ip.com",
    "changeip.com",
    "dnsexit.com",
)

#: ``(nom, type) -> (ttl, valeurs)``. Lève :class:`DomainDoesNotExist` si NXDOMAIN.
DnsLookup = Callable[[str, str], Awaitable[tuple[int, list[str]]]]


class DomainDoesNotExist(Exception):
    """Le domaine n'existe pas (NXDOMAIN)."""


def make_dnspython_lookup(lifetime: float = LOOKUP_LIFETIME) -> DnsLookup:
    """Résolution par ``dnspython``, avec la configuration DNS du système."""
    resolver: dns.asyncresolver.Resolver | None = None

    async def lookup(name: str, rdtype: str) -> tuple[int, list[str]]:
        nonlocal resolver
        resolver = resolver or dns.asyncresolver.Resolver()
        try:
            answer = await resolver.resolve(name, rdtype, lifetime=lifetime, search=False)
        except dns.resolver.NXDOMAIN:
            raise DomainDoesNotExist(name) from None
        except dns.resolver.NoAnswer:
            return 0, []
        except dns.exception.Timeout as exc:
            raise TimeoutError(f"DNS {rdtype} {name}") from exc
        ttl = answer.rrset.ttl if answer.rrset is not None else 0
        return ttl, [record.to_text() for record in answer]

    return lookup


def _host(value: str) -> str:
    return value.strip().rstrip(".").lower()


def _mx_hosts(values: list[str]) -> list[str]:
    hosts = []
    for value in values:
        parts = value.split()
        hosts.append(_host(parts[-1]) if parts else "")
    return hosts


def _free_dns(nameservers: list[str]) -> str | None:
    for ns in nameservers:
        for provider in FREE_DNS_PROVIDERS:
            if ns == provider or ns.endswith("." + provider):
                return provider
    return None


class DnsEnricher(Enricher):
    name = "dns"

    def __init__(self, *, lookup: DnsLookup | None = None) -> None:
        self._lookup = lookup or make_dnspython_lookup()

    async def _enrich(self, url: str, domain: str) -> Signal:
        name = normalize_domain(domain)
        if name is None:
            return self.skipped("unsupported_input")

        answers = await asyncio.gather(
            *(self._lookup(name, rdtype) for rdtype in RECORD_TYPES), return_exceptions=True
        )
        results: dict[str, tuple[int, list[str]]] = {}
        errors: dict[str, str] = {}
        for rdtype, answer in zip(RECORD_TYPES, answers, strict=True):
            if isinstance(answer, asyncio.CancelledError):
                raise answer
            if isinstance(answer, DomainDoesNotExist):
                return self.ok(0.0, {"exists": False})
            if isinstance(answer, BaseException):
                errors[rdtype] = type(answer).__name__
            else:
                results[rdtype] = answer
        if not results:
            first = answers[0]
            raise first if isinstance(first, Exception) else RuntimeError("DNS indisponible")

        a_ttl, a_values = results.get("A", (0, []))
        aaaa = results.get("AAAA", (0, []))[1]
        mx = _mx_hosts(results.get("MX", (0, []))[1])
        ns = sorted(_host(v) for v in results.get("NS", (0, []))[1])
        null_mx = mx == [""]  # « MX 0 . » : le domaine déclare ne recevoir aucun email
        free_provider = _free_dns(ns)
        fast_flux = len(a_values) >= FAST_FLUX_MIN_ADDRESSES and 0 < a_ttl < LOW_TTL

        risk = 0.0
        flags = []
        if free_provider:
            risk += 0.3
            flags.append("free_dns_provider")
        if fast_flux:
            risk += 0.3
            flags.append("fast_flux_like")
        if "MX" in results and (not mx or null_mx):
            flags.append("no_mx")  # pas un risque pour une URL ; utile au score email

        evidence = {
            "exists": True,
            "a": sorted(a_values)[:MAX_VALUES],
            "aaaa": sorted(aaaa)[:MAX_VALUES],
            "a_ttl": a_ttl if a_values else None,
            "mx": [h for h in mx if h][:MAX_VALUES],
            "null_mx": null_mx,
            "ns": ns[:MAX_VALUES],
            "free_dns_provider": free_provider,
            "flags": flags,
        }
        if errors:
            evidence["errors"] = errors
        return self.ok(min(risk, MAX_RISK), evidence)
