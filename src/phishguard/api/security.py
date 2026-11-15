"""Identité du client : adresse IP réelle et clé d'API (étape 4.4).

**Adresse IP derrière un proxy inverse.** L'API voit l'IP du proxy, pas celle du client ;
le proxy l'ajoute dans ``X-Forwarded-For``. Mais cet en-tête est écrit par le client
lui-même tant qu'aucun proxy ne l'a réécrit : le croire sans condition, c'est laisser
chacun choisir son IP, donc sa limite de débit. Les règles appliquées :

1. l'en-tête n'est lu **que si la connexion vient d'un proxy de confiance**
   (``trusted_proxies``, vide par défaut : l'en-tête est alors toujours ignoré) ;
2. il est lu **de droite à gauche** : chaque proxy de confiance ajoute à droite l'adresse
   qu'il a vue. La première adresse qui n'est pas un proxy de confiance est le client ;
   tout ce qui est à sa gauche a pu être inventé par lui ;
3. une valeur illisible arrête la lecture : on garde la dernière adresse sûre.

Uvicorn sait aussi réécrire l'IP du client (``--proxy-headers``). L'API se lance donc
avec ``proxy_headers=False`` (``python -m phishguard.api``) : une seule règle, ici.

**Regroupement IPv6.** Un abonné reçoit en général un /64 entier, soit 2^64 adresses :
limiter par adresse IPv6 ne limiterait rien. Les adresses IPv6 sont regroupées par /64,
les IPv4 comptées une par une.

**Clé d'API.** ``X-API-Key`` absent : client anonyme, limité par IP. Clé valide : client
authentifié, limité par clé. Clé présentée mais invalide ou révoquée : **refus (401)**,
jamais un retour silencieux au niveau anonyme, qui masquerait une erreur de
configuration et laisserait chercher des clés sans bruit. Ces tentatives ont leur propre
limite de débit, très basse, par IP.
"""

from __future__ import annotations

import logging
import sqlite3
from collections.abc import Sequence
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address, ip_address, ip_network
from typing import Literal

from fastapi import Request

from phishguard.api.errors import ApiError
from phishguard.api.settings import IPNetwork
from phishguard.api.storage import Database

logger = logging.getLogger(__name__)

API_KEY_HEADER = "X-API-Key"
FORWARDED_FOR_HEADER = "x-forwarded-for"
IPV6_BUCKET_PREFIX = 64
MAX_FORWARDED_HOPS = 20  # au-delà, l'en-tête est anormal : on s'arrête

ClientKind = Literal["anonymous", "authenticated", "rejected", "unavailable"]


def _parse_ip(value: str | None) -> IPv4Address | IPv6Address | None:
    if not value:
        return None
    try:
        ip = ip_address(value.strip())
    except ValueError:
        return None
    if isinstance(ip, IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped  # ::ffff:192.0.2.1 est 192.0.2.1
    return ip


def _trusted(ip: IPv4Address | IPv6Address, proxies: Sequence[IPNetwork]) -> bool:
    return any(ip.version == net.version and ip in net for net in proxies)


def client_ip(
    request: Request, trusted_proxies: Sequence[IPNetwork]
) -> IPv4Address | IPv6Address | None:
    """Adresse IP du client selon les règles du module ; ``None`` si inconnue."""
    peer = _parse_ip(request.client.host if request.client else None)
    if peer is None or not trusted_proxies or not _trusted(peer, trusted_proxies):
        return peer
    hops = [
        hop.strip()
        for value in request.headers.getlist(FORWARDED_FOR_HEADER)
        for hop in value.split(",")
    ]
    candidate = peer
    for hop in reversed(hops[-MAX_FORWARDED_HOPS:]):
        ip = _parse_ip(hop)
        if ip is None:
            break  # valeur illisible : rien à sa gauche n'est fiable
        candidate = ip
        if not _trusted(ip, trusted_proxies):
            break
    return candidate


def ip_bucket(ip: IPv4Address | IPv6Address | None) -> str:
    """Clé de limite de débit d'une IP : l'adresse en IPv4, son /64 en IPv6."""
    if ip is None:
        return "unknown"
    if isinstance(ip, IPv6Address):
        return str(ip_network(f"{ip}/{IPV6_BUCKET_PREFIX}", strict=False))
    return str(ip)


@dataclass(frozen=True)
class Client:
    """Qui fait la requête, du point de vue des quotas."""

    kind: ClientKind
    ip_bucket: str
    key_id: str | None = None

    @property
    def rate_key(self) -> str:
        """Compteur de limite de débit : la clé si elle est valide, sinon l'IP."""
        if self.kind == "authenticated":
            return f"key:{self.key_id}"
        return f"{self.kind}:{self.ip_bucket}"


def resolve_client(request: Request) -> Client:
    """Identité du client, calculée une fois par requête (``request.state.client``).

    Appelée par le limiteur de débit **avant** la lecture du corps, puis par la
    dépendance d'authentification. Ne lève jamais : une base indisponible donne
    ``unavailable``, que la dépendance transforme en 503.
    """
    cached = getattr(request.state, "client", None)
    if isinstance(cached, Client):
        return cached
    state = request.app.state.phishguard
    bucket = ip_bucket(client_ip(request, state.settings.trusted_proxies))
    presented = request.headers.getlist(API_KEY_HEADER)
    if not presented:
        client = Client("anonymous", bucket)
    elif len(presented) > 1:
        client = Client("rejected", bucket)  # deux clés : ambigu, donc refusé
    else:
        client = _client_for_key(state.database, presented[0], bucket)
    request.state.client = client
    return client


def _client_for_key(database: Database, key: str, bucket: str) -> Client:
    try:
        record = database.verify_key(key)
    except sqlite3.Error:
        logger.exception("base des clés d'API indisponible")
        return Client("unavailable", bucket)
    if record is None:
        logger.info("clé d'API refusée")  # jamais la clé, ni même son préfixe
        return Client("rejected", bucket)
    return Client("authenticated", bucket, key_id=record.key_id)


async def authenticated_client(request: Request) -> Client:
    """Dépendance des routes ``/v1`` : client anonyme ou authentifié, sinon erreur."""
    client = resolve_client(request)
    if client.kind == "rejected":
        raise ApiError(
            401,
            "invalid_api_key",
            "Clé d'API inconnue ou révoquée.",
            headers={"WWW-Authenticate": API_KEY_HEADER},
        )
    if client.kind == "unavailable":
        raise ApiError(503, "service_unavailable", "Authentification momentanément indisponible.")
    return client
