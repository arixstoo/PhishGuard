"""Marques usurpées : nom de marque hors de son domaine officiel et typosquatting.

La liste des marques et celle des raccourcisseurs sont des fichiers JSON du dossier
``data/`` : l'extension (module 5) les relira telles quelles, sans copie à maintenir.

Deux façons de chercher un nom de marque dans un texte découpé en segments (labels de
l'hôte, segments du chemin) :

- marque **stricte** (nom court ou mot courant : ``ups``, ``orange``) : le nom doit être
  un mot entier, délimité par un caractère non alphanumérique (``ups-suivi.com``) ;
- autre marque : le nom peut apparaître dans le segment, tirets retirés
  (``secure-paypal-login`` contient ``paypal``, ``credit-agricole`` contient
  ``creditagricole``).

Le typosquatting (``paypa1.com``, ``arnazon.com``) ne porte que sur les marques non
strictes : à une ou deux lettres près, un nom court ou courant ressemble à trop de mots.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Any

from rapidfuzz import process
from rapidfuzz.distance import Levenshtein

DATA_PACKAGE = "phishguard.urls"
BRANDS_FILE = "brands.json"
SHORTENERS_FILE = "shorteners.json"

# Longueur minimale d'un nom de marque cherché comme sous-chaîne et soumis au
# typosquatting. En dessous, la marque est stricte par défaut.
MIN_LOOSE_NAME_LENGTH = 6
# Plus petite partie d'un domaine comparée aux marques : « mail » n'est pas « gmail ».
MIN_TYPO_TOKEN_LENGTH = 4

_NAME_RE = re.compile(r"[a-z0-9]+")
_TOKEN_SPLIT_RE = re.compile(r"[^0-9a-z]+")


# Domaines nationaux vendus comme des extensions génériques (.co, .io, .me…) : un nom de
# marque sous l'un d'eux n'est jamais présumé officiel, même avec ``any_cctld``.
GENERIC_USE_CCTLDS = frozenset(
    {"ai", "cc", "cf", "co", "ga", "gg", "gq", "io", "ly", "me", "ml", "nu", "pw", "sh", "so",
     "st", "tk", "to", "tv", "ws"}
)  # fmt: skip


@dataclass(frozen=True)
class Brand:
    """Une marque et ses domaines officiels.

    ``any_cctld`` : la marque possède son nom sous la plupart des domaines nationaux
    (``google.co.th``, ``amazon.com.mx``). ``<nom>.<suffixe>`` est alors officiel dès que
    le TLD est un code pays à deux lettres hors :data:`GENERIC_USE_CCTLDS`.
    """

    name: str
    domains: frozenset[str]
    strict: bool
    any_cctld: bool = False

    def __post_init__(self) -> None:
        if not _NAME_RE.fullmatch(self.name):
            raise ValueError(f"nom de marque invalide : {self.name!r} (a-z et 0-9 seulement)")
        if not self.domains:
            raise ValueError(f"{self.name} : au moins un domaine officiel est requis")
        for domain in self.domains:
            if domain != domain.strip().lower() or "." not in domain or "/" in domain:
                raise ValueError(f"{self.name} : domaine officiel invalide {domain!r}")
        if not self.strict and len(self.name) < MIN_LOOSE_NAME_LENGTH:
            raise ValueError(
                f"{self.name} : un nom de moins de {MIN_LOOSE_NAME_LENGTH} caractères "
                "doit être strict"
            )


def max_typo_edits(name: str) -> int:
    """Nombre de modifications au-delà duquel un domaine n'imite plus la marque."""
    return 1 if len(name) < 9 else 2


def tokens(segment: str) -> list[str]:
    """Mots alphanumériques d'un segment, en minuscules."""
    return [t for t in _TOKEN_SPLIT_RE.split(segment.lower()) if t]


class BrandIndex:
    """Index des marques, construit une fois et interrogé pour chaque URL."""

    def __init__(self, brands: Iterable[Brand]) -> None:
        self.brands: tuple[Brand, ...] = tuple(sorted(brands, key=lambda b: b.name))
        names = [b.name for b in self.brands]
        duplicates = sorted({n for n in names if names.count(n) > 1})
        if duplicates:
            raise ValueError(f"marques en double : {', '.join(duplicates)}")

        official: dict[str, set[str]] = {}
        for brand in self.brands:
            for domain in brand.domains:
                official.setdefault(domain, set()).add(brand.name)
        self._official = {d: frozenset(n) for d, n in official.items()}
        self._any_cctld = frozenset(b.name for b in self.brands if b.any_cctld)
        self._strict = frozenset(b.name for b in self.brands if b.strict)
        # Plus longs d'abord : à une même position, « paypal » passe avant un nom plus court.
        self._loose = tuple(
            sorted((b.name for b in self.brands if not b.strict), key=lambda n: (-len(n), n))
        )
        self._loose_re = re.compile("|".join(map(re.escape, self._loose))) if self._loose else None

    def __len__(self) -> int:
        return len(self.brands)

    def official_for(self, registered_domain: str) -> frozenset[str]:
        """Marques dont ``registered_domain`` est un domaine officiel."""
        official = self._official.get(registered_domain, frozenset())
        label, _, suffix = registered_domain.partition(".")
        tld = suffix.rsplit(".", 1)[-1]
        if (
            label in self._any_cctld
            and len(tld) == 2
            and tld.isascii()
            and tld.isalpha()
            and tld not in GENERIC_USE_CCTLDS
        ):
            official = official | {label}
        return official

    def find(self, segments: Iterable[str], exclude: frozenset[str] = frozenset()) -> str | None:
        """Première marque trouvée dans les segments, hors marques de ``exclude``."""
        for segment in segments:
            words = tokens(segment)
            if not words:
                continue
            for word in words:
                if word in self._strict and word not in exclude:
                    return word
            joined = "".join(words)
            if exclude:
                for name in self._loose:
                    if name not in exclude and name in joined:
                        return name
            elif self._loose_re is not None:
                match = self._loose_re.search(joined)
                if match:
                    return match.group()
        return None

    def nearest(
        self, domain_label: str, exclude: frozenset[str] = frozenset(), cap: int = 3
    ) -> tuple[int, str | None]:
        """Distance de Levenshtein minimale entre un label de domaine et une marque.

        Sont comparés le label entier (tirets retirés) et chacun de ses mots d'au moins
        :data:`MIN_TYPO_TOKEN_LENGTH` caractères. Un mot contenu dans le nom de la marque
        n'est pas comparé à cette marque : ``cloud`` n'imite pas ``icloud``, ni ``mobile``
        ``tmobile``. Retourne ``(distance, marque)``, ou ``(cap, None)`` si aucune marque
        n'est à moins de ``cap`` modifications. À distance égale, l'ordre alphabétique
        départage.
        """
        choices = [n for n in self._loose if n not in exclude] if exclude else self._loose
        words = tokens(domain_label)
        candidates = {"".join(words), *(w for w in words if len(w) >= MIN_TYPO_TOKEN_LENGTH)}
        found: list[tuple[int, str]] = []
        for candidate in candidates:
            if len(candidate) < MIN_TYPO_TOKEN_LENGTH:
                continue
            matches = process.extract(
                candidate, choices, scorer=Levenshtein.distance, score_cutoff=cap - 1, limit=None
            )
            found.extend(
                (int(distance), name)
                for name, distance, _ in matches
                if candidate == name or candidate not in name
            )
        if not found:
            return cap, None
        distance, name = min(found)
        return distance, name


# --------------------------------------------------------------------------- #
# Chargement des listes
# --------------------------------------------------------------------------- #


def _read_json(path: Path | None, default_name: str) -> Mapping[str, Any]:
    if path is not None:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    resource = resources.files(DATA_PACKAGE).joinpath("data", default_name)
    return json.loads(resource.read_text(encoding="utf-8"))


def brands_from_dict(data: Mapping[str, Any]) -> BrandIndex:
    """Index à partir du contenu de ``brands.json``."""
    return BrandIndex(
        Brand(
            name=entry["name"],
            domains=frozenset(entry["domains"]),
            strict=bool(entry.get("strict", len(entry["name"]) < MIN_LOOSE_NAME_LENGTH)),
            any_cctld=bool(entry.get("any_cctld", False)),
        )
        for entry in data["brands"]
    )


def load_brands(path: Path | None = None) -> BrandIndex:
    """Charge ``brands.json`` (celui du paquet par défaut)."""
    return brands_from_dict(_read_json(path, BRANDS_FILE))


def load_shorteners(path: Path | None = None) -> frozenset[str]:
    """Charge les domaines de raccourcisseurs (``shorteners.json`` du paquet par défaut)."""
    domains = _read_json(path, SHORTENERS_FILE)["domains"]
    invalid = [d for d in domains if d != d.strip().lower() or "." not in d]
    if invalid:
        raise ValueError(f"domaines de raccourcisseurs invalides : {invalid}")
    return frozenset(domains)


def list_versions() -> dict[str, Any]:
    """Version et taille des listes embarquées, pour les rapports."""
    brands = _read_json(None, BRANDS_FILE)
    shorteners = _read_json(None, SHORTENERS_FILE)
    return {
        "brands": {"version": brands["version"], "count": len(brands["brands"])},
        "shorteners": {"version": shorteners["version"], "count": len(shorteners["domains"])},
    }
