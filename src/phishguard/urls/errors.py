"""Analyse des erreurs du modèle URL (étape 1.8).

On extrait les pires erreurs au seuil de décision (étape 1.7) :

- **faux positifs** : URLs légitimes signalées, de la plus haute à la plus basse note ;
- **faux négatifs** : URLs de phishing non signalées, de la plus basse à la plus haute.

Chaque erreur est rangée dans une catégorie par des **règles explicites**, testées et
appliquées dans l'ordre de :data:`CATEGORIES` : la première règle vraie donne la
catégorie principale, toutes les règles vraies sont gardées comme étiquettes. Les
catégories viennent du plan (service légitime avec long paramètre, hébergeur détourné,
domaine neuf d'apparence honnête) et des biais mesurés aux étapes 1.3 à 1.5.

Les règles ne lisent que l'URL (features de l'étape 1.5 et liste ``hosting.json``) : une
catégorie dit ce que les features voient, pas la vérité du terrain. La relecture humaine
des exemples reste nécessaire, d'où l'export détaillé non versionné du script.

Publication : seuls des agrégats et quelques exemples **défangés** (``hxxps://exemple[.]com``)
sont versionnés, sans requête et avec les adresses email masquées, et uniquement pour
les sources dont la licence le permet (:data:`PUBLISHABLE_SOURCES`).
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import numpy as np
import pandas as pd

from phishguard.data.urls import LABEL_LEGITIMATE, LABEL_PHISHING
from phishguard.urls.features import ParsedUrl, UrlFeatureExtractor

FALSE_POSITIVE = "false_positive"
FALSE_NEGATIVE = "false_negative"
KINDS = (FALSE_POSITIVE, FALSE_NEGATIVE)
HOSTING_FILE = "hosting.json"
# OpenPhish interdit la redistribution de son flux (docs/data-sources.md) : aucun exemple.
PUBLISHABLE_SOURCES = frozenset({"phishtank", "urlhaus", "tranco", "commoncrawl"})
EXAMPLE_MAX_LENGTH = 90

# Seuils des règles. Ils décrivent une forme d'URL, ils ne sont pas appris.
LONG_QUERY_LENGTH = 50
MANY_QUERY_PARAMS = 3
DEEP_PATH_DEPTH = 4
LONG_PATH_LENGTH = 60
LONG_HOST_LENGTH = 20
MANY_HOST_HYPHENS = 2
MANY_HOST_DIGITS = 3
MANY_SUBDOMAINS = 2
RISKY_TLD_FACTOR = 2.0  # taux de phishing du TLD au moins double de l'a priori

_EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")


# --------------------------------------------------------------------------- #
# Plateformes d'hébergement
# --------------------------------------------------------------------------- #


def load_hosting_platforms(path: Path | None = None) -> frozenset[str]:
    """Domaines de ``hosting.json`` (celui du paquet par défaut)."""
    if path is None:
        text = resources.files("phishguard.urls").joinpath("data", HOSTING_FILE).read_text("utf-8")
    else:
        text = Path(path).read_text(encoding="utf-8")
    domains = json.loads(text)["domains"]
    invalid = [d for d in domains if d != d.strip().lower() or "." not in d]
    if invalid:
        raise ValueError(f"domaines d'hébergement invalides : {invalid}")
    return frozenset(domains)


def on_platform(host: str, platforms: frozenset[str]) -> bool:
    """Vrai si l'hôte est une plateforme de la liste ou l'un de ses sous-domaines."""
    labels = host.rstrip(".").split(".")
    return any(".".join(labels[i:]) in platforms for i in range(len(labels)))


# --------------------------------------------------------------------------- #
# Catégories
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Context:
    """Ce dont les règles ont besoin en plus des features."""

    platforms: frozenset[str]
    tld_prior: float | None  # part de phishing à l'entraînement ; None sans table des TLD


Rule = Callable[[Mapping[str, float], ParsedUrl, Context], bool]


@dataclass(frozen=True)
class ErrorCategory:
    name: str
    kind: str
    label: str
    rule: str  # la règle, en clair, pour la doc
    improvement: str
    matches: Rule


def _risky_tld(f: Mapping[str, float], ctx: Context) -> bool:
    rate = f.get("tld_phish_rate")
    return (
        rate is not None and ctx.tld_prior is not None and rate >= RISKY_TLD_FACTOR * ctx.tld_prior
    )


def _clean_host(f: Mapping[str, float], ctx: Context) -> bool:
    """Hôte sans aucun des signaux lexicaux que le modèle sait lire."""
    return (
        f["host_kw_hits"] == 0
        and f["host_n_hyphens"] <= 1
        and f["host_n_digits"] <= 1
        and not f.get("brand_in_host", 0)
        and not f["host_is_ip"]
        and not _risky_tld(f, ctx)
    )


CATEGORIES: tuple[ErrorCategory, ...] = (
    # --- faux positifs --------------------------------------------------------- #
    ErrorCategory(
        "legit_brand_lookalike",
        FALSE_POSITIVE,
        "Nom proche d'une marque",
        "`brand_in_host` ou `is_typosquat`",
        "Compléter `brands.json` avec les domaines secondaires et filiales des marques ; "
        "liste d'autorisation des domaines les plus visités.",
        lambda f, p, ctx: bool(f.get("brand_in_host") or f.get("is_typosquat")),
    ),
    ErrorCategory(
        "legit_hosted_platform",
        FALSE_POSITIVE,
        "Page légitime sur une plateforme d'hébergement",
        "hôte dans `hosting.json`",
        "Ne pas juger le domaine de la plateforme mais le sous-domaine ou le chemin ; "
        "réputation du compte (module 2).",
        lambda f, p, ctx: on_platform(p.host, ctx.platforms),
    ),
    ErrorCategory(
        "legit_long_query",
        FALSE_POSITIVE,
        "Service légitime avec long paramètre",
        f"requête d'au moins {LONG_QUERY_LENGTH} caractères ou {MANY_QUERY_PARAMS} paramètres",
        "Plus de pages légitimes avec requête à l'entraînement (Common Crawl) ; features "
        "sur la nature des paramètres (suivi, pagination) plutôt que leur longueur.",
        lambda f, p, ctx: (
            f["query_len"] >= LONG_QUERY_LENGTH or f["query_n_params"] >= MANY_QUERY_PARAMS
        ),
    ),
    ErrorCategory(
        "legit_deep_path",
        FALSE_POSITIVE,
        "Page interne profonde",
        f"au moins {DEEP_PATH_DEPTH} segments ou {LONG_PATH_LENGTH} caractères de chemin",
        "Biais de chemin (étape 1.3) : plus de pages internes légitimes, ou un modèle sans "
        "chemin ni longueur pour la navigation courante.",
        lambda f, p, ctx: f["path_depth"] >= DEEP_PATH_DEPTH or f["path_len"] >= LONG_PATH_LENGTH,
    ),
    ErrorCategory(
        "legit_unusual_host",
        FALSE_POSITIVE,
        "Domaine peu connu, long ou chargé",
        f"hôte d'au moins {LONG_HOST_LENGTH} caractères, {MANY_HOST_HYPHENS} tirets, "
        f"{MANY_HOST_DIGITS} chiffres ou {MANY_SUBDOMAINS} sous-domaines",
        "Biais de popularité (étape 1.5) : légitime moins visité à l'entraînement (bas du "
        "classement Tranco, Common Crawl au-delà des 5 000 premiers domaines).",
        lambda f, p, ctx: (
            f["host_len"] >= LONG_HOST_LENGTH
            or f["host_n_hyphens"] >= MANY_HOST_HYPHENS
            or f["host_n_digits"] >= MANY_HOST_DIGITS
            or f["host_n_subdomains"] >= MANY_SUBDOMAINS
        ),
    ),
    ErrorCategory(
        "legit_risky_tld",
        FALSE_POSITIVE,
        "Extension souvent vue dans le phishing",
        f"`tld_phish_rate` au moins {RISKY_TLD_FACTOR:g} fois l'a priori",
        "Lisser davantage la table des TLD ou plafonner le poids de la feature ; le taux "
        "mesure aussi nos sources (étape 1.5).",
        lambda f, p, ctx: _risky_tld(f, ctx),
    ),
    ErrorCategory(
        "legit_other",
        FALSE_POSITIVE,
        "Autre",
        "aucune règle précédente",
        "Relecture manuelle de l'export détaillé.",
        lambda f, p, ctx: True,
    ),
    # --- faux négatifs --------------------------------------------------------- #
    ErrorCategory(
        "phish_hosted_platform",
        FALSE_NEGATIVE,
        "Phishing sur une plateforme réputée",
        "hôte dans `hosting.json` (stockage, site gratuit, formulaire)",
        "Invisible pour des features lexicales : réputation de l'URL complète (Safe "
        "Browsing, urlscan.io, module 2) et analyse du contenu de la page.",
        lambda f, p, ctx: on_platform(p.host, ctx.platforms),
    ),
    ErrorCategory(
        "phish_shortener",
        FALSE_NEGATIVE,
        "Lien raccourci",
        "`is_shortener`",
        "Résoudre la redirection côté serveur, avec le garde-fou anti-SSRF (étape 2.3), "
        "puis analyser la destination.",
        lambda f, p, ctx: bool(f.get("is_shortener")),
    ),
    ErrorCategory(
        "phish_ip_host",
        FALSE_NEGATIVE,
        "Adresse IP",
        "`host_is_ip`",
        "Peu d'exemples à l'entraînement : règle explicite dans la fusion du score "
        "(étape 2.10) plutôt qu'un poids appris.",
        lambda f, p, ctx: bool(f["host_is_ip"]),
    ),
    ErrorCategory(
        "phish_compromised_site",
        FALSE_NEGATIVE,
        "Site honnête compromis",
        "hôte sans signal lexical et chemin d'au moins 2 segments",
        "Âge et historique du domaine (RDAP, étape 2.7) ne suffisent pas : c'est le "
        "chemin qui est nouveau. Réputation de l'URL et du contenu (module 2).",
        lambda f, p, ctx: _clean_host(f, ctx) and f["path_depth"] >= 2,
    ),
    ErrorCategory(
        "phish_clean_domain",
        FALSE_NEGATIVE,
        "Domaine neuf d'apparence honnête",
        "hôte sans signal lexical, chemin court, aucun mot-clé",
        "Date de création du domaine (RDAP) et certificat récent (journaux CT, module 2) : "
        "le signal est dans le temps, pas dans le texte.",
        lambda f, p, ctx: _clean_host(f, ctx) and f["path_depth"] <= 1 and f["path_kw_hits"] == 0,
    ),
    ErrorCategory(
        "phish_other",
        FALSE_NEGATIVE,
        "Autre",
        "aucune règle précédente",
        "Relecture manuelle de l'export détaillé.",
        lambda f, p, ctx: True,
    ),
)
CATEGORY_BY_NAME = {c.name: c for c in CATEGORIES}


def categories_for(kind: str) -> tuple[ErrorCategory, ...]:
    if kind not in KINDS:
        raise ValueError(f"type d'erreur inconnu : {kind!r}")
    return tuple(c for c in CATEGORIES if c.kind == kind)


def categorize(
    url: str, kind: str, extractor: UrlFeatureExtractor, ctx: Context
) -> tuple[str, tuple[str, ...]]:
    """Catégorie principale (première règle vraie) et toutes les catégories vraies."""
    features = extractor.extract(url)
    parsed = extractor.parse(url)
    matching = tuple(c.name for c in categories_for(kind) if c.matches(features, parsed, ctx))
    specific = tuple(name for name in matching if not name.endswith("_other"))
    return (specific or matching)[0], specific


# --------------------------------------------------------------------------- #
# Sélection et synthèse
# --------------------------------------------------------------------------- #


def worst_errors(
    y: np.ndarray, scores: np.ndarray, threshold: float, n: int
) -> dict[str, np.ndarray]:
    """Positions des ``n`` pires faux positifs et faux négatifs au seuil.

    Les ex aequo sont départagés par la position, pour un résultat stable.
    """
    if n <= 0:
        raise ValueError("n doit être strictement positif")
    y, scores = np.asarray(y), np.asarray(scores, dtype=float)
    positions = np.arange(len(y))
    fp = positions[(y == LABEL_LEGITIMATE) & (scores > threshold)]
    fn = positions[(y == LABEL_PHISHING) & (scores <= threshold)]
    fp = fp[np.lexsort((fp, -scores[fp]))][:n]
    fn = fn[np.lexsort((fn, scores[fn]))][:n]
    return {FALSE_POSITIVE: fp, FALSE_NEGATIVE: fn}


def analyze(
    block: pd.DataFrame,
    scores: np.ndarray,
    threshold: float,
    extractor: UrlFeatureExtractor,
    ctx: Context,
    n: int = 50,
) -> pd.DataFrame:
    """Une ligne par erreur retenue : URL, source, score, type, catégorie, étiquettes."""
    rows = []
    labels = block["label"].to_numpy()
    for kind, positions in worst_errors(labels, scores, threshold, n).items():
        for rank, pos in enumerate(positions, start=1):
            url = block["url"].iloc[pos]
            category, tags = categorize(url, kind, extractor, ctx)
            rows.append(
                {
                    "kind": kind,
                    "rank": rank,
                    "score": float(scores[pos]),
                    "category": category,
                    "tags": ";".join(tags),
                    "source": block["source"].iloc[pos],
                    "url": url,
                }
            )
    columns = ["kind", "rank", "score", "category", "tags", "source", "url"]
    return pd.DataFrame(rows, columns=columns)


def defang(url: str, max_length: int = EXAMPLE_MAX_LENGTH) -> str:
    """Forme publiable d'une URL : non cliquable, sans requête, emails masqués.

    ``https://login.example.com/a?x=1`` → ``hxxps://login[.]example[.]com/a?…``
    """
    parts = urlsplit(url)
    scheme = parts.scheme.replace("http", "hxxp", 1)
    host = (parts.hostname or "").replace(".", "[.]")
    port = f":{parts.port}" if parts.port else ""
    path = _EMAIL_RE.sub("<email>", parts.path)
    text = f"{scheme}://{host}{port}{path}" + ("?…" if parts.query else "")
    return text if len(text) <= max_length else text[: max_length - 1] + "…"


def summarize(
    errors: pd.DataFrame,
    totals: Mapping[str, int],
    *,
    examples_per_category: int = 3,
    publishable_sources: Iterable[str] = PUBLISHABLE_SOURCES,
) -> dict[str, Any]:
    """Agrégats publiables : effectifs, scores et quelques exemples défangés."""
    publishable = set(publishable_sources)
    summary: dict[str, Any] = {}
    for kind in KINDS:
        subset = errors[errors["kind"] == kind]
        categories = {}
        for category in categories_for(kind):
            rows = subset[subset["category"] == category.name]
            tagged = subset["tags"].str.split(";").map(lambda tags, c=category.name: c in tags)
            shown = rows[rows["source"].isin(publishable)].head(examples_per_category)
            categories[category.name] = {
                "label": category.label,
                "count": len(rows),
                "share": round(len(rows) / len(subset), 4) if len(subset) else None,
                "tagged": int(tagged.sum()) if len(subset) else 0,
                "median_score": round(float(rows["score"].median()), 4) if len(rows) else None,
                "by_source": {str(k): int(v) for k, v in rows["source"].value_counts().items()},
                "examples": [defang(u) for u in shown["url"]],
            }
        summary[kind] = {
            "total_errors": int(totals[kind]),
            "analyzed": len(subset),
            "categories": categories,
        }
    return summary


def category_definitions(kinds: Sequence[str] = KINDS) -> list[dict[str, str]]:
    """Définitions des catégories (pour la doc et le rapport)."""
    return [
        {
            "name": c.name,
            "kind": c.kind,
            "label": c.label,
            "rule": c.rule,
            "improvement": c.improvement,
        }
        for c in CATEGORIES
        if c.kind in kinds
    ]
