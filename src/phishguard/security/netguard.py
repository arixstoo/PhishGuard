"""Garde-fou réseau contre la falsification de requêtes côté serveur, ou SSRF (étape 2.3).

**Le serveur PhishGuard ne visite jamais l'URL analysée** : il interroge des tiers à son
sujet (voir ``docs/ssrf.md``). Ce module est le seul chemin autorisé pour tout code qui,
un jour, devra contacter une adresse fournie par un utilisateur (par exemple déplier un
lien raccourci, en option). Il applique, à chaque saut :

1. schéma ``http`` ou ``https`` seulement, ports autorisés seulement, pas d'identifiants
   dans l'URL ;
2. décodage des adresses IP écrites sous une forme ambiguë (``0x7f000001``,
   ``2130706433``, ``0177.0.0.1``, ``127.1``), que le résolveur système accepterait ;
3. résolution DNS **par nous**, et refus si **une seule** des adresses n'est pas publique
   (privée, boucle locale, lien local dont 169.254.169.254, réservée, multicast,
   non spécifiée, partagée) ; les adresses IPv4 cachées dans une adresse IPv6
   (``::ffff:127.0.0.1``, 6to4, Teredo, NAT64) sont vérifiées aussi ;
4. connexion à l'**adresse déjà validée**, pas au nom : l'URL de la requête porte l'IP,
   le nom part dans l'en-tête ``Host`` et dans le SNI TLS (le certificat reste vérifié
   pour le nom). Une seconde réponse DNS différente (*DNS rebinding*) ne sert donc à
   rien ;
5. redirections suivies à la main, en nombre limité, chacune revalidée depuis l'étape 1 ;
6. délais courts (connexion, lecture, et durée totale) et taille de réponse maximale,
   mesurée après décompression (une « bombe gzip » est arrêtée).

Le client HTTP ignore les variables de proxy de l'environnement (``trust_env=False``) et
ne réutilise aucune connexion : deux noms servis par la même IP n'échangent jamais une
connexion TLS ouverte pour l'autre.
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass, field

import httpx

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
#: Résout ``(nom, port)`` en adresses IP textuelles. Injectable pour les tests.
Resolver = Callable[[str, int], Awaitable[Sequence[str]]]

DEFAULT_PORTS = {"http": 80, "https": 443}
REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
# Noms qui ne désignent jamais un service public, refusés avant toute résolution :
# RFC 6761 (localhost), RFC 6762 (.local, mDNS), RFC 8375 (home.arpa) et .internal
# (réservé aux réseaux privés par l'ICANN, utilisé par les services de métadonnées).
BLOCKED_NAME_SUFFIXES = ("localhost", "localdomain", "local", "internal", "home.arpa")
# 64:ff9b::/96 (RFC 6052) : passerelles NAT64, l'IPv4 est dans les 32 derniers bits.
_NAT64 = ipaddress.IPv6Network("64:ff9b::/96")
_LABEL = re.compile(r"^(?!-)[a-z0-9_-]{1,63}(?<!-)$")
_IPV4_PART = re.compile(r"^(0x[0-9a-f]*|[0-9]+)$")


# --------------------------------------------------------------------------- #
# Erreurs
# --------------------------------------------------------------------------- #


class NetGuardError(Exception):
    """Requête refusée ou interrompue par le garde-fou. ``reason`` est un code stable."""

    def __init__(self, reason: str, detail: str = "") -> None:
        self.reason = reason
        self.detail = detail
        super().__init__(f"{reason} ({detail})" if detail else reason)


class BlockedDestination(NetGuardError):
    """Destination refusée : schéma, port, nom ou adresse non autorisés."""


class TooManyRedirects(NetGuardError):
    pass


class ResponseTooLarge(NetGuardError):
    pass


# --------------------------------------------------------------------------- #
# Politique
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class NetPolicy:
    allowed_schemes: frozenset[str] = frozenset({"http", "https"})
    allowed_ports: frozenset[int] = frozenset({80, 443})
    allowed_methods: frozenset[str] = frozenset({"GET", "HEAD"})
    max_redirects: int = 3
    max_bytes: int = 1_000_000
    dns_timeout: float = 2.0
    connect_timeout: float = 2.0
    read_timeout: float = 3.0
    total_timeout: float = 5.0  # borne la requête entière, redirections comprises
    user_agent: str = "PhishGuard-netguard (+https://github.com/arixstoo/PhishGuard)"

    @property
    def httpx_timeout(self) -> httpx.Timeout:
        return httpx.Timeout(
            connect=self.connect_timeout,
            read=self.read_timeout,
            write=self.read_timeout,
            pool=self.connect_timeout,
        )


DEFAULT_POLICY = NetPolicy()


# --------------------------------------------------------------------------- #
# Adresses IP
# --------------------------------------------------------------------------- #


def _embedded_ipv4(ip: ipaddress.IPv6Address) -> list[ipaddress.IPv4Address]:
    """Adresses IPv4 transportées par une adresse IPv6 de transition."""
    found = [ip.ipv4_mapped, ip.sixtofour]
    if ip.teredo:
        found.extend(ip.teredo)
    if ip in _NAT64:
        found.append(ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF))
    return [v4 for v4 in found if v4 is not None]


def is_public_ip(ip: IPAddress) -> bool:
    """Vrai seulement pour une adresse unicast routable sur Internet.

    Les drapeaux de :mod:`ipaddress` sont combinés avec ``is_global`` : ce dernier seul
    accepte par exemple le multicast global (``224.0.0.1``, ``ff0e::1``).
    """
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.scope_id:  # fe80::1%eth0 : désigne une interface locale
            return False
        if not all(is_public_ip(v4) for v4 in _embedded_ipv4(ip)):
            return False
    return ip.is_global and not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


def _ipv4_number(part: str) -> int:
    if part.startswith("0x"):
        return int(part[2:] or "0", 16)
    if len(part) > 1 and part.startswith("0"):
        if not set(part) <= set("01234567"):
            raise BlockedDestination("invalid_ip", part)
        return int(part, 8)
    return int(part)


def parse_legacy_ipv4(host: str) -> ipaddress.IPv4Address | None:
    """Décode une IPv4 écrite comme le résolveur système l'accepte, ou ``None``.

    Suit l'algorithme du standard URL du WHATWG (celui des navigateurs) : si le dernier
    label est numérique, l'hôte **est** une IPv4, éventuellement en hexadécimal
    (``0x7f000001``), en octal (``0177.0.0.1``), en entier (``2130706433``) ou abrégée
    (``127.1``). Si ce n'est pas une IPv4 valide, l'hôte est refusé, pas traité comme un
    nom.
    """
    parts = host.lower().split(".")
    if len(parts) > 1 and parts[-1] == "":
        parts.pop()
    if not _IPV4_PART.match(parts[-1]):
        return None  # un nom de domaine
    if len(parts) > 4 or not all(_IPV4_PART.match(p) for p in parts):
        raise BlockedDestination("invalid_ip", host)
    numbers = [_ipv4_number(p) for p in parts]
    if any(n > 255 for n in numbers[:-1]) or numbers[-1] >= 256 ** (5 - len(numbers)):
        raise BlockedDestination("invalid_ip", host)
    value = numbers[-1] + sum(n << (8 * (3 - i)) for i, n in enumerate(numbers[:-1]))
    return ipaddress.IPv4Address(value)


def parse_ip_literal(host: str) -> IPAddress | None:
    """Adresse IP désignée par ``host`` (sans crochets), ou ``None`` pour un nom."""
    if ":" in host:
        try:
            # httpx garde la zone d'une IPv6 encodée (%25) : fe80::1%25eth0.
            return ipaddress.IPv6Address(host.replace("%25", "%"))
        except ValueError:
            raise BlockedDestination("invalid_ip", host) from None
    return parse_legacy_ipv4(host)


def _check_hostname(host: str) -> None:
    name = host.removesuffix(".")
    labels = name.split(".")
    if len(name) > 253 or not all(_LABEL.match(label) for label in labels):
        raise BlockedDestination("invalid_host", host)
    if any(name == s or name.endswith("." + s) for s in BLOCKED_NAME_SUFFIXES):
        raise BlockedDestination("blocked_hostname", host)


# --------------------------------------------------------------------------- #
# Validation d'une URL
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Target:
    """URL validée et adresses vers lesquelles on a le droit de se connecter."""

    url: httpx.URL
    host: str  # nom ASCII (punycode) ou IP, sans crochets
    port: int
    addresses: tuple[IPAddress, ...]
    is_ip_literal: bool


async def system_resolver(host: str, port: int) -> list[str]:
    """Résolution par ``socket.getaddrinfo``, hors de la boucle asynchrone."""
    infos = await asyncio.get_running_loop().getaddrinfo(
        host, port, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP
    )
    return [str(info[4][0]) for info in infos]


def _parse_url(url: str | httpx.URL, policy: NetPolicy) -> tuple[httpx.URL, str, int]:
    try:
        parsed = httpx.URL(url)
    except (httpx.InvalidURL, TypeError, ValueError):
        raise BlockedDestination("invalid_url") from None
    scheme = parsed.scheme.lower()
    if scheme not in policy.allowed_schemes:
        raise BlockedDestination("scheme_not_allowed", scheme or "(vide)")
    if parsed.userinfo:
        # http://banque.example@10.0.0.1/ : trompe l'humain, et parfois les parseurs.
        raise BlockedDestination("credentials_in_url")
    host = parsed.raw_host.decode("ascii").lower()
    if not host:
        raise BlockedDestination("missing_host")
    port = parsed.port or DEFAULT_PORTS[scheme]
    if port not in policy.allowed_ports:
        raise BlockedDestination("port_not_allowed", str(port))
    return parsed, host, port


async def resolve_target(
    url: str | httpx.URL,
    *,
    policy: NetPolicy = DEFAULT_POLICY,
    resolver: Resolver = system_resolver,
) -> Target:
    """Valide ``url`` et résout son hôte. Lève :class:`BlockedDestination` sinon."""
    parsed, host, port = _parse_url(url, policy)
    literal = parse_ip_literal(host)
    if literal is not None:
        addresses: tuple[IPAddress, ...] = (literal,)
    else:
        _check_hostname(host)
        try:
            raw = await asyncio.wait_for(resolver(host, port), policy.dns_timeout)
        except TimeoutError:
            raise BlockedDestination("dns_timeout", host) from None
        except OSError:
            raise BlockedDestination("dns_failure", host) from None
        try:
            addresses = tuple(ipaddress.ip_address(a) for a in raw)
        except ValueError:
            raise BlockedDestination("dns_failure", host) from None
        if not addresses:
            raise BlockedDestination("dns_failure", host)
    for address in addresses:
        if not is_public_ip(address):
            raise BlockedDestination("blocked_address", f"{host} -> {address}")
    return Target(parsed, host, port, addresses, literal is not None)


# --------------------------------------------------------------------------- #
# Requête protégée
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class GuardedResponse:
    url: str  # URL finale, avec le nom d'hôte (pas l'IP)
    status_code: int
    headers: httpx.Headers
    content: bytes
    address: str  # IP à laquelle on s'est réellement connecté
    redirects: tuple[str, ...] = field(default=())


def _pinned_request(target: Target, method: str, policy: NetPolicy) -> httpx.Request:
    """Requête vers l'IP validée, avec le nom d'origine dans ``Host`` et le SNI."""
    address = target.addresses[0]
    host = f"[{target.host}]" if ":" in target.host else target.host
    host_header = host if target.url.port is None else f"{host}:{target.port}"
    extensions: dict[str, object] = {}
    if target.url.scheme == "https" and not target.is_ip_literal:
        extensions["sni_hostname"] = target.host  # certificat vérifié pour le nom
    return httpx.Request(
        method,
        target.url.copy_with(host=str(address)),
        headers={"Host": host_header, "User-Agent": policy.user_agent, "Accept": "*/*"},
        extensions=extensions,
    )


async def _read_limited(response: httpx.Response, max_bytes: int) -> bytes:
    declared = response.headers.get("content-length", "")
    if declared.isdigit() and int(declared) > max_bytes:
        raise ResponseTooLarge("content_length", declared)
    body = bytearray()
    async for chunk in response.aiter_bytes():  # octets décompressés
        body.extend(chunk)
        if len(body) > max_bytes:
            raise ResponseTooLarge("body", f"> {max_bytes}")
    return bytes(body)


async def guarded_request(
    url: str,
    *,
    method: str = "GET",
    policy: NetPolicy = DEFAULT_POLICY,
    resolver: Resolver = system_resolver,
    transport: httpx.AsyncBaseTransport | None = None,
) -> GuardedResponse:
    """Effectue une requête ``GET`` ou ``HEAD`` en appliquant toutes les protections.

    Lève :class:`NetGuardError` (destination refusée, trop de redirections, réponse trop
    grande), ``TimeoutError`` si ``policy.total_timeout`` est dépassé, ou une erreur
    ``httpx`` en cas d'échec réseau. Un enrichisseur (étape 2.2) les convertit en signal.
    """
    method = method.upper()
    if method not in policy.allowed_methods:
        raise NetGuardError("method_not_allowed", method)
    client = httpx.AsyncClient(
        transport=transport,
        trust_env=False,  # pas de proxy implicite : on maîtrise la destination
        follow_redirects=False,  # chaque saut est revalidé ici
        timeout=policy.httpx_timeout,
        limits=httpx.Limits(max_keepalive_connections=0),
    )
    async with asyncio.timeout(policy.total_timeout), client:
        current, redirects = url, []
        for _ in range(policy.max_redirects + 1):
            target = await resolve_target(current, policy=policy, resolver=resolver)
            request = _pinned_request(target, method, policy)
            response = await client.send(request, stream=True)
            try:
                location = response.headers.get("location")
                if response.status_code in REDIRECT_STATUSES and location:
                    current = str(target.url.join(location))
                    redirects.append(current)  # GET et HEAD gardent leur méthode
                    continue
                content = await _read_limited(response, policy.max_bytes)
            finally:
                await response.aclose()
            return GuardedResponse(
                url=str(target.url),
                status_code=response.status_code,
                headers=response.headers,
                content=content,
                address=str(target.addresses[0]),
                redirects=tuple(redirects),
            )
    raise TooManyRedirects("max_redirects", str(policy.max_redirects))
