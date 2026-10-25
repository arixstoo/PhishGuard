"""Features lexicales d'URL (étape 1.5).

Chaque feature est une fonction pure de l'URL : aucun accès réseau, aucune dépendance à
l'heure ou à l'état de la machine. Elles seront portées à l'identique en TypeScript pour
l'extension (module 5) ; :data:`FEATURES` en est le contrat, et
``tests/fixtures/url_features_golden.json`` les valeurs de référence.

Règles de conception, issues de l'audit des biais (``docs/data-bias.md``) :

- **Groupes.** Chaque feature appartient à un groupe (:data:`GROUPS` : schéma, hôte,
  chemin, longueur) pour entraîner et comparer les modèles avec et sans les groupes
  ``path`` et ``length``, porteurs du biais de chemin.
- **Familles.** Chaque feature appartient aussi à une famille (:data:`FAMILIES`) : les
  features de base du plan, puis les ajouts mesurés un par un (marques, homographes, TLD,
  raccourcisseurs).
- **Longueur par composant.** Longueur de l'hôte, du chemin et de la requête, jamais de
  l'URL entière, qui mélange les trois.
- **``www`` n'est pas un sous-domaine.** Il ne dit rien du risque, et sa présence dépend
  surtout de la source (100 % des URLs légitimes de PhiUSIIL commencent par ``www.``).
- **Forme Unicode de l'hôte** pour compter ses caractères (longueur, chiffres, tirets,
  entropie) : l'encodage Punycode ajoute ``xn--`` et des chiffres sans rapport avec ce
  que lit l'utilisateur.
- **Chemin décodé** (``%6Cogin`` → ``login``) pour chercher mots-clés, marques et URLs
  imbriquées ; les longueurs restent celles du texte brut.

L'URL est d'abord normalisée par :func:`phishguard.data.urls.normalize_url`, comme à la
construction du jeu : entraînement et production lisent l'URL de la même façon.
"""

from __future__ import annotations

import ipaddress
import math
import re
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass
from functools import lru_cache
from typing import Any
from urllib.parse import unquote, urlsplit

import pandas as pd
import tldextract

from phishguard.data.urls import make_domain_extractor, normalize_url
from phishguard.urls.brands import BrandIndex, load_brands, load_shorteners, max_typo_edits
from phishguard.urls.idn import is_mixed_script, skeleton, to_ascii, to_unicode
from phishguard.urls.tld import TldRiskTable, top_level_domain

GROUPS = ("scheme", "host", "path", "length")
FAMILIES = ("base", "brand", "homograph", "tld", "shortener")

# Mots fréquents dans les leurres, en anglais et en français. Comptés une fois chacun.
KEYWORDS = (
    "login",
    "signin",
    "logon",
    "verify",
    "verification",
    "secure",
    "account",
    "update",
    "bank",
    "confirm",
    "password",
    "webscr",
    "wallet",
    "connexion",
    "compte",
    "securite",
    "paiement",
    "identifiant",
)
# Distance maximale rapportée par ``brand_min_distance`` (au-delà : « aucune marque proche »).
BRAND_DISTANCE_CAP = 3
DEFAULT_PORTS = {"http": 80, "https": 443}

_HEX_NUMBER_RE = re.compile(r"0x[0-9a-f]*")
_EMBEDDED_URL_RE = re.compile(r"https?:|www\.")
_PATH_SEGMENT_SPLIT_RE = re.compile(r"[/?&=;#]")


@dataclass(frozen=True)
class FeatureSpec:
    name: str
    group: str
    family: str
    description: str

    def __post_init__(self) -> None:
        if self.group not in GROUPS:
            raise ValueError(f"{self.name} : groupe inconnu {self.group!r}")
        if self.family not in FAMILIES:
            raise ValueError(f"{self.name} : famille inconnue {self.family!r}")


FEATURES: tuple[FeatureSpec, ...] = (
    # --- base : features du plan --------------------------------------------------- #
    FeatureSpec("is_https", "scheme", "base", "1 si le schéma est https"),
    FeatureSpec(
        "host_is_ip",
        "host",
        "base",
        "1 si l'hôte est une adresse IPv6 ou se termine par un nombre (IPv4, y compris "
        "décimal ou hexadécimal, règle WHATWG)",
    ),
    FeatureSpec(
        "host_n_subdomains",
        "host",
        "base",
        "labels avant le domaine enregistré, sans un « www » initial",
    ),
    FeatureSpec("host_n_hyphens", "host", "base", "tirets dans l'hôte (forme Unicode)"),
    FeatureSpec("host_n_digits", "host", "base", "chiffres dans l'hôte (forme Unicode)"),
    FeatureSpec(
        "host_entropy", "host", "base", "entropie de Shannon des caractères de l'hôte (bits)"
    ),
    FeatureSpec("host_kw_hits", "host", "base", "mots-clés de KEYWORDS présents dans l'hôte"),
    FeatureSpec("host_is_idn", "host", "base", "1 si l'hôte contient un label internationalisé"),
    FeatureSpec(
        "has_userinfo", "host", "base", "1 si l'URL contient des identifiants avant l'hôte (@)"
    ),
    FeatureSpec(
        "has_port", "host", "base", "1 si un port différent du port par défaut est indiqué"
    ),
    FeatureSpec("path_depth", "path", "base", "segments non vides du chemin"),
    FeatureSpec("query_n_params", "path", "base", "paramètres non vides de la requête"),
    FeatureSpec("path_n_digits", "path", "base", "chiffres dans le chemin et la requête décodés"),
    FeatureSpec(
        "path_kw_hits", "path", "base", "mots-clés présents dans le chemin et la requête décodés"
    ),
    FeatureSpec(
        "path_has_embedded_url",
        "path",
        "base",
        "1 si le chemin ou la requête décodés contiennent « http: », « https: » ou « www. »",
    ),
    FeatureSpec("host_len", "length", "base", "caractères de l'hôte (forme Unicode)"),
    FeatureSpec("path_len", "length", "base", "caractères du chemin brut"),
    FeatureSpec("query_len", "length", "base", "caractères de la requête brute"),
    # --- marques ------------------------------------------------------------------- #
    FeatureSpec(
        "brand_in_host",
        "host",
        "brand",
        "1 si un label de l'hôte (hors suffixe) contient une marque dont ce n'est pas le "
        "domaine officiel",
    ),
    FeatureSpec(
        "brand_min_distance",
        "host",
        "brand",
        "distance de Levenshtein entre le label du domaine et la marque la plus proche dont "
        "ce n'est pas le domaine officiel, plafonnée à BRAND_DISTANCE_CAP",
    ),
    FeatureSpec(
        "is_typosquat",
        "host",
        "brand",
        "1 si le label du domaine est à 1 modification d'une marque (2 pour un nom d'au "
        "moins 9 caractères), sans être la marque elle-même",
    ),
    FeatureSpec(
        "brand_in_path",
        "path",
        "brand",
        "1 si le chemin ou la requête décodés contiennent une marque dont l'hôte n'est pas "
        "le domaine officiel",
    ),
    # --- homographes --------------------------------------------------------------- #
    FeatureSpec(
        "host_mixed_script",
        "host",
        "homograph",
        "1 si un label mêle des écritures non admises ensemble (UTS #39, Highly Restrictive)",
    ),
    FeatureSpec(
        "homograph_brand",
        "host",
        "homograph",
        "1 si l'hôte est internationalisé et que son squelette visuel contient une marque "
        "absente de sa forme réelle",
    ),
    # --- TLD ----------------------------------------------------------------------- #
    FeatureSpec(
        "tld_phish_rate",
        "host",
        "tld",
        "part de phishing du TLD à l'entraînement, lissée (voir phishguard.urls.tld)",
    ),
    # --- raccourcisseurs ----------------------------------------------------------- #
    FeatureSpec(
        "is_shortener",
        "host",
        "shortener",
        "1 si l'hôte ou son domaine enregistré est un raccourcisseur connu",
    ),
)
FEATURE_NAMES: tuple[str, ...] = tuple(f.name for f in FEATURES)
_SPECS = {f.name: f for f in FEATURES}


class InvalidUrlError(ValueError):
    """URL rejetée par la normalisation (schéma non http(s), hôte vide, espace…)."""


@dataclass(frozen=True)
class ParsedUrl:
    """Composants d'une URL normalisée, tels que les features les lisent."""

    url: str
    scheme: str
    host: str  # forme ASCII (Punycode), comme ``location.hostname`` dans un navigateur
    host_unicode: str
    is_ip: bool
    registered_domain: str  # l'hôte lui-même pour une IP ou un hôte sans suffixe connu
    domain_label: str  # label juste avant le suffixe public, forme Unicode (``""`` si IP)
    subdomains: tuple[str, ...]  # forme Unicode
    has_userinfo: bool
    port: int | None
    path: str
    query: str


def feature_names(
    families: Iterable[str] = FAMILIES, exclude_groups: Iterable[str] = ()
) -> tuple[str, ...]:
    """Noms des features des familles demandées, sans celles des groupes exclus."""
    families, exclude_groups = set(families), set(exclude_groups)
    unknown = (families - set(FAMILIES)) | (exclude_groups - set(GROUPS))
    if unknown:
        raise ValueError(f"familles ou groupes inconnus : {sorted(unknown)}")
    return tuple(f.name for f in FEATURES if f.family in families and f.group not in exclude_groups)


def feature_spec(name: str) -> FeatureSpec:
    return _SPECS[name]


# --------------------------------------------------------------------------- #
# Fonctions élémentaires
# --------------------------------------------------------------------------- #


def entropy(text: str) -> float:
    """Entropie de Shannon (bits par caractère) ; 0 pour une chaîne vide."""
    if not text:
        return 0.0
    n = len(text)
    # « 0.0 - » plutôt que « - » : un seul caractère distinct donne 0.0, pas -0.0.
    return 0.0 - sum((c / n) * math.log2(c / n) for c in Counter(text).values())


def is_ip_host(host: str) -> bool:
    """Vrai pour une IPv6 ou un hôte que le navigateur lit comme une IPv4.

    Règle WHATWG (« ends in a number ») : le dernier label est un nombre décimal ou
    hexadécimal (``0x7f000001``, ``3232235777``, ``192.168.1.1``).
    """
    if ":" in host:
        try:
            ipaddress.IPv6Address(host.split("%", 1)[0])
        except ValueError:
            return False
        return True
    labels = host.split(".")
    if len(labels) > 1 and labels[-1] == "":
        labels.pop()
    last = labels[-1]
    return (last.isascii() and last.isdigit()) or bool(_HEX_NUMBER_RE.fullmatch(last))


def keyword_hits(text: str) -> int:
    """Nombre de mots-clés distincts de :data:`KEYWORDS` présents dans ``text``."""
    lowered = text.lower()
    return sum(keyword in lowered for keyword in KEYWORDS)


def count_query_params(query: str) -> int:
    return sum(1 for pair in query.split("&") if pair)


@dataclass(frozen=True)
class ParsedHost:
    """Découpage d'un hôte (forme ASCII) selon la liste des suffixes publics."""

    host: str
    host_unicode: str
    is_ip: bool
    registered_domain: str
    domain_label: str
    subdomains: tuple[str, ...]


def parse_host(host: str, extractor: tldextract.TLDExtract | None = None) -> ParsedHost:
    """Découpe un hôte déjà normalisé (minuscules, forme ASCII ou Unicode)."""
    host_ascii = to_ascii(host)
    is_ip = is_ip_host(host_ascii)
    if is_ip:
        registered, domain_label, subdomain = host_ascii, "", ""
    else:
        ext = (extractor or _default_domain_extractor())(host_ascii)
        registered = ext.top_domain_under_public_suffix or host_ascii
        domain_label, subdomain = ext.domain, ext.subdomain
    return ParsedHost(
        host=host_ascii,
        host_unicode=to_unicode(host_ascii),
        is_ip=is_ip,
        registered_domain=registered,
        domain_label=to_unicode(domain_label),
        subdomains=tuple(to_unicode(s) for s in subdomain.split(".") if s),
    )


def parse_url(url: str, extractor: tldextract.TLDExtract | None = None) -> ParsedUrl:
    """Normalise et découpe une URL ; lève :class:`InvalidUrlError` si elle est invalide."""
    normalized = normalize_url(url)
    if normalized is None:
        raise InvalidUrlError(f"URL invalide : {url[:200]!r}")
    url, host = normalized
    parts = urlsplit(url)
    parsed_host = parse_host(host, extractor)
    port = parts.port
    return ParsedUrl(
        url=url,
        scheme=parts.scheme,
        host=parsed_host.host,
        host_unicode=parsed_host.host_unicode,
        is_ip=parsed_host.is_ip,
        registered_domain=parsed_host.registered_domain,
        domain_label=parsed_host.domain_label,
        subdomains=parsed_host.subdomains,
        has_userinfo="@" in parts.netloc,
        port=None if port == DEFAULT_PORTS.get(parts.scheme) else port,
        path=parts.path,
        query=parts.query,
    )


@lru_cache(maxsize=1)
def _default_domain_extractor() -> tldextract.TLDExtract:
    return make_domain_extractor()


# --------------------------------------------------------------------------- #
# Extracteur
# --------------------------------------------------------------------------- #


class UrlFeatureExtractor:
    """Calcule les features d'une URL ou d'une série d'URLs.

    ``families`` choisit les familles calculées ; par défaut toutes, sauf ``tld`` quand
    aucune table n'est fournie (elle doit être apprise sur l'entraînement, voir
    :meth:`TldRiskTable.fit`). Les features qui ne dépendent que de l'hôte sont mises en
    cache : un même domaine revient souvent.
    """

    def __init__(
        self,
        *,
        families: Iterable[str] | None = None,
        brands: BrandIndex | None = None,
        shorteners: frozenset[str] | None = None,
        tld_table: TldRiskTable | None = None,
        domain_extractor: tldextract.TLDExtract | None = None,
        host_cache_size: int = 2**17,
    ) -> None:
        if families is None:
            families = [f for f in FAMILIES if f != "tld" or tld_table is not None]
        self.families = tuple(f for f in FAMILIES if f in set(families))
        if "tld" in self.families and tld_table is None:
            raise ValueError("la famille « tld » demande une table apprise (tld_table)")
        self.feature_names = feature_names(self.families)

        self.brands = brands if brands is not None else load_brands()
        self.shorteners = shorteners if shorteners is not None else load_shorteners()
        self.tld_table = tld_table
        self._domain_extractor = domain_extractor or _default_domain_extractor()
        self._host_features = lru_cache(maxsize=host_cache_size)(self._compute_host_features)

    # ------------------------------------------------------------------- #

    def parse(self, url: str) -> ParsedUrl:
        return parse_url(url, self._domain_extractor)

    def extract(self, url: str) -> dict[str, float]:
        """Features d'une URL, dans l'ordre de :attr:`feature_names`."""
        parsed = self.parse(url)
        values = dict(self._host_features(parsed.host))
        values.update(self._url_features(parsed))
        return {name: float(values[name]) for name in self.feature_names}

    def transform(self, urls: Iterable[str]) -> pd.DataFrame:
        """Une ligne par URL, une colonne par feature (``float64``).

        Lève :class:`InvalidUrlError` à la première URL invalide : les jeux de
        ``data/processed/`` ne contiennent que des URLs déjà normalisées.
        """
        index = urls.index if isinstance(urls, pd.Series) else None
        rows = [self.extract(url) for url in urls]
        return pd.DataFrame(rows, columns=list(self.feature_names), index=index, dtype="float64")

    def cache_info(self) -> Any:
        return self._host_features.cache_info()

    # ------------------------------------------------------------------- #

    def _compute_host_features(self, host: str) -> dict[str, float]:
        """Features qui ne dépendent que de l'hôte (forme ASCII)."""
        parsed = parse_host(host, self._domain_extractor)
        unicode_host = parsed.host_unicode
        subdomains = list(parsed.subdomains)
        if subdomains and subdomains[0] == "www":
            subdomains.pop(0)

        values: dict[str, float] = {
            "host_is_ip": parsed.is_ip,
            "host_n_subdomains": len(subdomains),
            "host_n_hyphens": unicode_host.count("-"),
            "host_n_digits": sum(c.isdigit() for c in unicode_host),
            "host_entropy": entropy(unicode_host),
            "host_kw_hits": keyword_hits(unicode_host),
            "host_is_idn": unicode_host != parsed.host,
            "host_len": len(unicode_host),
        }

        families = self.families
        official = self.brands.official_for(parsed.registered_domain)
        labels = [*parsed.subdomains, parsed.domain_label]
        if "brand" in families:
            found = None if parsed.is_ip else self.brands.find(labels, exclude=official)
            distance, nearest = (
                (BRAND_DISTANCE_CAP, None)
                if parsed.is_ip
                else self.brands.nearest(parsed.domain_label, official, BRAND_DISTANCE_CAP)
            )
            values["brand_in_host"] = found is not None
            values["brand_min_distance"] = distance
            values["is_typosquat"] = nearest is not None and 1 <= distance <= max_typo_edits(
                nearest
            )
        if "homograph" in families:
            values["host_mixed_script"] = is_mixed_script(unicode_host)
            values["homograph_brand"] = bool(
                values["host_is_idn"]
                and self.brands.find(labels, exclude=official) is None
                and self.brands.find(map(skeleton, labels), exclude=official) is not None
            )
        if "tld" in families:
            assert self.tld_table is not None
            values["tld_phish_rate"] = self.tld_table.rate(top_level_domain(parsed.host))
        if "shortener" in families:
            values["is_shortener"] = (
                parsed.host in self.shorteners or parsed.registered_domain in self.shorteners
            )
        return values

    def _url_features(self, parsed: ParsedUrl) -> dict[str, float]:
        """Features qui dépendent du schéma, du port, des identifiants et du chemin."""
        decoded = unquote(f"{parsed.path}?{parsed.query}" if parsed.query else parsed.path)
        values: dict[str, float] = {
            "is_https": parsed.scheme == "https",
            "has_userinfo": parsed.has_userinfo,
            "has_port": parsed.port is not None,
            "path_depth": sum(1 for segment in parsed.path.split("/") if segment),
            "query_n_params": count_query_params(parsed.query),
            "path_n_digits": sum(c.isdigit() for c in decoded),
            "path_kw_hits": keyword_hits(decoded),
            "path_has_embedded_url": bool(_EMBEDDED_URL_RE.search(decoded.lower())),
            "path_len": len(parsed.path),
            "query_len": len(parsed.query),
        }
        if "brand" in self.families:
            official = self.brands.official_for(parsed.registered_domain)
            segments = _PATH_SEGMENT_SPLIT_RE.split(decoded)
            values["brand_in_path"] = self.brands.find(segments, exclude=official) is not None
        return values


@lru_cache(maxsize=1)
def default_extractor() -> UrlFeatureExtractor:
    """Extracteur partagé, avec les listes embarquées et sans la famille ``tld``."""
    return UrlFeatureExtractor()


def url_features(url: str) -> dict[str, float]:
    """Features d'une URL avec l'extracteur par défaut (sans ``tld_phish_rate``)."""
    return default_extractor().extract(url)
