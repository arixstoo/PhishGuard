"""Jeu d'URLs étiquetées construit à partir des flux bruts collectés (étape 1.2).

Entrée : les fichiers de ``data/raw/`` décrits par les manifestes de ``fetch_feeds.py``.
Sortie : un DataFrame au schéma :data:`COLUMNS`, une ligne par URL normalisée.

Règles appliquées, dans l'ordre :

1. Seules les sources ``ok`` d'un manifeste sont lues, et leur SHA-256 est vérifié.
2. URLhaus recense surtout des téléchargements de malwares : seules les URLs portant
   une étiquette de phishing (:data:`URLHAUS_PHISHING_TAGS`) sont conservées.
3. Chaque URL est normalisée (:func:`normalize_url`) ; les URLs invalides sont écartées.
4. Une URL présente avec les deux étiquettes est retirée (étiquette incertaine).
5. Les doublons exacts sont fusionnés : ``first_seen`` est la plus ancienne observation
   et ``source`` celle qui l'a observée.
6. Au plus ``max_per_domain`` URLs par (étiquette, domaine enregistré), tirées au hasard
   avec une graine fixe, pour qu'un site très présent ne domine pas le jeu.
"""

from __future__ import annotations

import csv
import io
import ipaddress
import json
import logging
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import pandas as pd
import tldextract

from phishguard.data.integrity import DatasetIntegrityError, sha256_file

logger = logging.getLogger(__name__)

COLUMNS = ["url", "label", "source", "first_seen", "host", "registered_domain"]
LABEL_LEGITIMATE = 0
LABEL_PHISHING = 1

# Ordre de préférence quand plusieurs sources observent une URL au même instant :
# PhishTank est validé par des humains, OpenPhish est automatique.
SOURCES = ("phishtank", "openphish", "urlhaus", "tranco")
SOURCE_LABELS = {
    "phishtank": LABEL_PHISHING,
    "openphish": LABEL_PHISHING,
    "urlhaus": LABEL_PHISHING,
    "tranco": LABEL_LEGITIMATE,
}
# Étiquettes URLhaus qui désignent du vol d'identifiants. Les leurres de type ClickFix ou
# FakeCaptcha distribuent un malware : ils restent hors du jeu.
URLHAUS_PHISHING_TAGS = frozenset({"phishing", "pdf-link-phishing"})
URLHAUS_COLUMNS = [
    "id",
    "dateadded",
    "url",
    "url_status",
    "last_online",
    "threat",
    "tags",
    "urlhaus_link",
    "reporter",
]
# Fichiers bruts produits par fetch_feeds.py, pour signaler ceux qu'aucun manifeste ne décrit.
RAW_FEED_PATTERNS = ("openphish_*.txt", "phishtank_*.csv", "urlhaus_recent_*.csv", "tranco_*.csv")

ALLOWED_SCHEMES = frozenset({"http", "https"})
_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://")
_WHITESPACE_RE = re.compile(r"\s")

_OBSERVATION_COLUMNS = ["raw_url", "label", "source", "first_seen"]


@dataclass(frozen=True)
class RawFeed:
    """Un fichier brut décrit par un manifeste de collecte."""

    source: str
    path: Path
    collected_at: pd.Timestamp
    sha256: str | None = None


@dataclass
class FeedInventory:
    feeds: list[RawFeed] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


@dataclass
class BuildResult:
    dataset: pd.DataFrame
    steps: dict[str, int]
    inputs: list[dict[str, Any]]


# --------------------------------------------------------------------------- #
# Inventaire des fichiers bruts
# --------------------------------------------------------------------------- #


def parse_manifest(manifest: dict[str, Any]) -> tuple[pd.Timestamp, list[dict[str, Any]]]:
    """Retourne la date de collecte et les entrées réussies d'un manifeste.

    Trois formats coexistent dans les archives :

    - v0 : ``{"timestamp_utc": ..., "<source>": "<fichier>" | null}`` ;
    - 0.1.0 : ``{"metadata": {"timestamp_utc"}, "feeds": {"<source>": {"file", "sha256"}}}``,
      une source en échec étant absente ;
    - 0.2.0 et suivants : ``metadata.collected_at`` et un ``status`` par source.

    Chaque entrée retournée contient ``source``, ``file`` et ``sha256`` (ou ``None``).
    """
    if "feeds" in manifest:
        metadata = manifest["metadata"]
        raw_entries = manifest["feeds"]
    else:
        metadata = manifest
        raw_entries = {k: {"file": v} for k, v in manifest.items() if k in SOURCE_LABELS}

    if "collected_at" in metadata:
        collected_at = pd.Timestamp(metadata["collected_at"]).tz_convert("UTC")
    else:
        collected_at = pd.Timestamp(
            datetime.strptime(metadata["timestamp_utc"], "%Y%m%d_%H%M%S"), tz="UTC"
        )

    entries = []
    for source, entry in raw_entries.items():
        if source not in SOURCE_LABELS or not entry or not entry.get("file"):
            continue
        if entry.get("status", "ok") != "ok":
            continue
        entries.append({"source": source, "file": entry["file"], "sha256": entry.get("sha256")})
    return collected_at, entries


def discover_feeds(raw_dir: Path) -> FeedInventory:
    """Liste les fichiers bruts valides à partir des manifestes ``manifest_*.json``.

    Un fichier référencé mais absent est signalé puis ignoré ; un fichier présent sans
    manifeste aussi, car on ne connaît ni sa date de collecte ni son empreinte.
    """
    raw_dir = Path(raw_dir)
    inventory = FeedInventory()
    referenced: set[str] = set()

    for manifest_path in sorted(raw_dir.glob("manifest_*.json")):
        try:
            collected_at, entries = parse_manifest(
                json.loads(manifest_path.read_text(encoding="utf-8"))
            )
        except (ValueError, KeyError, TypeError, AttributeError) as exc:
            raise ValueError(f"manifeste illisible : {manifest_path.name} ({exc})") from exc

        for entry in entries:
            name = entry["file"]
            # Un manifeste ne doit désigner qu'un fichier du dossier, jamais un chemin.
            if Path(name).name != name or name in {".", ".."}:
                raise ValueError(f"{manifest_path.name} : nom de fichier refusé {name!r}")
            referenced.add(name)
            path = raw_dir / name
            if not path.is_file():
                inventory.warnings.append(f"{manifest_path.name} : fichier absent {name}")
                continue
            inventory.feeds.append(RawFeed(entry["source"], path, collected_at, entry["sha256"]))

    for pattern in RAW_FEED_PATTERNS:
        for path in sorted(raw_dir.glob(pattern)):
            if path.name not in referenced:
                inventory.warnings.append(f"fichier sans manifeste ignoré : {path.name}")
    return inventory


def verify_feed(feed: RawFeed) -> None:
    """Vérifie que le fichier n'a pas changé depuis sa collecte."""
    if feed.sha256 is None:
        return
    digest = sha256_file(feed.path)
    if digest != feed.sha256:
        raise DatasetIntegrityError(
            f"SHA-256 inattendu pour {feed.path.name} : {digest} (manifeste : {feed.sha256})"
        )


# --------------------------------------------------------------------------- #
# Lecture des sources
# --------------------------------------------------------------------------- #


def _observations(
    urls: Iterable[str], feed: RawFeed, first_seen: pd.Series | pd.Timestamp | None = None
) -> pd.DataFrame:
    df = pd.DataFrame({"raw_url": list(urls)}, dtype=str)
    df["label"] = SOURCE_LABELS[feed.source]
    df["source"] = feed.source
    if first_seen is None:
        df["first_seen"] = feed.collected_at
    else:
        # Date annoncée par la source, bornée par la date de collecte (horloges décalées,
        # valeurs manquantes) : on n'a pas pu voir l'URL après l'avoir collectée.
        seen = pd.Series(first_seen, index=df.index)
        df["first_seen"] = seen.where(seen <= feed.collected_at, feed.collected_at)
    return df[_OBSERVATION_COLUMNS]


def _parse_utc(values: pd.Series, fmt: str) -> pd.Series:
    return pd.to_datetime(values, format=fmt, utc=True, errors="coerce").reset_index(drop=True)


def load_openphish(feed: RawFeed) -> pd.DataFrame:
    """Une URL par ligne, sans date : ``first_seen`` est la date de collecte."""
    lines = feed.path.read_text(encoding="utf-8").splitlines()
    return _observations((line for line in lines if line.strip()), feed)


def load_phishtank(feed: RawFeed) -> pd.DataFrame:
    """Export ``online-valid`` : ``first_seen`` est la date de soumission."""
    df = pd.read_csv(feed.path, dtype=str, keep_default_na=False, encoding="utf-8")
    if "verified" in df.columns:
        df = df[df["verified"].str.lower() == "yes"]
    return _observations(df["url"], feed, _parse_utc(df["submission_time"], "ISO8601"))


def load_urlhaus(feed: RawFeed) -> tuple[pd.DataFrame, int]:
    """Export ``recent`` : ne garde que les URLs étiquetées phishing.

    Retourne aussi le nombre d'URLs écartées. Les lignes de commentaire sont retirées à la
    main : ``read_csv(comment="#")`` couperait les URLs qui contiennent un fragment.
    """
    text = feed.path.read_text(encoding="utf-8")
    body = "\n".join(line for line in text.splitlines() if not line.startswith("#"))
    df = pd.read_csv(
        io.StringIO(body),
        names=URLHAUS_COLUMNS,
        header=None,
        dtype=str,
        keep_default_na=False,
        quoting=csv.QUOTE_MINIMAL,
    )
    tags = df["tags"].str.lower().str.split(",")
    keep = tags.map(lambda values: any(t.strip() in URLHAUS_PHISHING_TAGS for t in values))
    kept = df[keep]
    observations = _observations(
        kept["url"], feed, _parse_utc(kept["dateadded"], "%Y-%m-%d %H:%M:%S")
    )
    return observations, int((~keep).sum())


def load_tranco(feed: RawFeed) -> pd.DataFrame:
    """CSV ``rang,domaine`` : chaque domaine devient ``https://<domaine>/``.

    Tranco ne fournit que des domaines. Ces URLs n'ont ni chemin ni paramètres, ce qui
    crée un biais de chemin à traiter à l'étape 1.3.
    """
    df = pd.read_csv(feed.path, names=["rank", "domain"], header=None, dtype=str)
    domains = df["domain"].dropna().str.strip()
    return _observations("https://" + domains[domains != ""] + "/", feed)


# --------------------------------------------------------------------------- #
# Normalisation
# --------------------------------------------------------------------------- #


def normalize_url(raw: str) -> tuple[str, str] | None:
    """Normalise une URL et retourne ``(url, hôte)``, ou ``None`` si elle est invalide.

    - espaces de bord retirés ; une URL contenant un espace ou un saut de ligne est rejetée ;
    - schéma absent : ``http://`` est ajouté (cas fréquent dans les signalements) ;
    - seuls ``http`` et ``https`` sont acceptés ;
    - schéma et hôte en minuscules, chemin vide remplacé par ``/`` (RFC 3986, § 6.2.3) ;
    - chemin, paramètres, fragment et informations d'utilisateur sont conservés tels quels :
      ``https://paypal.com@evil.example/`` reste reconnaissable.

    L'hôte retourné est sans port, sans informations d'utilisateur et sans point final.
    """
    candidate = raw.strip()
    if not candidate or _WHITESPACE_RE.search(candidate):
        return None
    if not _SCHEME_RE.match(candidate):
        candidate = f"http://{candidate}"
    try:
        parts = urlsplit(candidate)
        parts.port  # noqa: B018 - lève ValueError si le port est invalide
    except ValueError:
        return None

    scheme = parts.scheme.lower()
    host = (parts.hostname or "").rstrip(".")
    if scheme not in ALLOWED_SCHEMES or not host:
        return None

    userinfo, at, hostport = parts.netloc.rpartition("@")
    netloc = f"{userinfo}{at}{hostport.lower()}"
    url = urlunsplit((scheme, netloc, parts.path or "/", parts.query, parts.fragment))
    return url, host


def make_domain_extractor() -> tldextract.TLDExtract:
    """Extracteur hors ligne, basé sur la liste des suffixes embarquée dans tldextract.

    Les suffixes privés (``github.io``, ``blogspot.com``…) sont pris en compte :
    ``a.github.io`` et ``b.github.io`` appartiennent à deux personnes différentes et ne
    doivent pas être regroupés sous ``github.io``.
    """
    return tldextract.TLDExtract(
        cache_dir=None, suffix_list_urls=(), include_psl_private_domains=True
    )


def registered_domain(host: str, extractor: tldextract.TLDExtract) -> str | None:
    """Domaine enregistré d'un hôte.

    - une adresse IP est son propre domaine ;
    - un hôte qui est lui-même un suffixe privé (``github.io``, ``s3.amazonaws.com``) est
      son propre domaine : il appartient à l'opérateur de la plateforme ;
    - ``None`` si l'hôte n'a pas de suffixe connu (``localhost``) ou n'est qu'un suffixe
      public (``com``, ``co.uk``).
    """
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        return host
    parts = extractor(host)
    if parts.top_domain_under_public_suffix:
        return parts.top_domain_under_public_suffix
    if parts.is_private and parts.suffix == host:
        return host
    return None


# --------------------------------------------------------------------------- #
# Construction
# --------------------------------------------------------------------------- #


def collect_observations(
    feeds: Iterable[RawFeed], *, verify: bool = True
) -> tuple[pd.DataFrame, dict[str, int], list[dict[str, Any]]]:
    """Lit tous les fichiers et retourne ``(observations, statistiques, entrées lues)``.

    Les observations comptent une ligne par URL vue dans un fichier.
    """
    frames: list[pd.DataFrame] = []
    inputs: list[dict[str, Any]] = []
    urlhaus_excluded = 0
    for feed in feeds:
        if verify:
            verify_feed(feed)
        if feed.source == "urlhaus":
            frame, excluded = load_urlhaus(feed)
            urlhaus_excluded += excluded
        else:
            frame = {
                "openphish": load_openphish,
                "phishtank": load_phishtank,
                "tranco": load_tranco,
            }[feed.source](feed)
        frames.append(frame)
        inputs.append(
            {
                "source": feed.source,
                "file": feed.path.name,
                "sha256": feed.sha256,
                "collected_at": feed.collected_at.isoformat(),
                "rows": len(frame),
            }
        )
        logger.info("%s : %d URLs lues", feed.path.name, len(frame))

    observations = (
        pd.concat(frames, ignore_index=True)
        if frames
        else pd.DataFrame(columns=_OBSERVATION_COLUMNS)
    )
    steps = {"observations": len(observations), "urlhaus_malware_excluded": urlhaus_excluded}
    return observations, steps, inputs


def normalize_observations(
    observations: pd.DataFrame, extractor: tldextract.TLDExtract
) -> tuple[pd.DataFrame, dict[str, int]]:
    """Ajoute ``url``, ``host`` et ``registered_domain`` ; écarte les URLs invalides."""
    unique_raw = observations["raw_url"].drop_duplicates()
    normalized = {raw: normalize_url(raw) for raw in unique_raw}
    parsed = observations["raw_url"].map(normalized)
    valid_url = parsed.notna()

    df = observations[valid_url].copy()
    df["url"] = parsed[valid_url].map(lambda pair: pair[0])
    df["host"] = parsed[valid_url].map(lambda pair: pair[1])

    domains = {host: registered_domain(host, extractor) for host in df["host"].unique()}
    df["registered_domain"] = df["host"].map(domains)
    valid_host = df["registered_domain"].notna()

    stats = {
        "invalid_url": int((~valid_url).sum()),
        "unknown_suffix": int((~valid_host).sum()),
    }
    return df[valid_host].drop(columns="raw_url"), stats


def merge_duplicates(df: pd.DataFrame) -> tuple[pd.DataFrame, dict[str, int]]:
    """Fusionne les observations d'une même URL et retire les URLs aux étiquettes opposées."""
    labels_per_url = df.groupby("url")["label"].nunique()
    conflicting = labels_per_url.index[labels_per_url > 1]
    df = df[~df["url"].isin(conflicting)]

    source_rank = df["source"].map({name: rank for rank, name in enumerate(SOURCES)})
    earliest_first = df.assign(_rank=source_rank).sort_values(
        ["url", "first_seen", "_rank"], kind="stable"
    )
    merged = earliest_first.drop_duplicates("url", keep="first").drop(columns="_rank")

    stats = {
        "label_conflicts": len(conflicting),
        "duplicates_merged": len(df) - len(merged),
    }
    return merged, stats


def cap_per_domain(df: pd.DataFrame, max_per_domain: int, seed: int) -> pd.DataFrame:
    """Garde au plus ``max_per_domain`` URLs par (étiquette, domaine enregistré).

    Le tirage est aléatoire (graine fixe) plutôt que « les plus anciennes » : on garde ainsi
    la répartition dans le temps nécessaire au split temporel de l'étape 1.4. La limite
    s'applique par étiquette pour qu'un domaine hébergeant du phishing (``google.com`` via
    ``sites.google.com``) ne fasse pas disparaître sa page d'accueil légitime.
    """
    if max_per_domain < 1:
        raise ValueError("max_per_domain doit être >= 1")
    shuffled = df.sort_values("url", kind="stable").sample(frac=1.0, random_state=seed)
    return shuffled.groupby(["label", "registered_domain"], sort=False).head(max_per_domain)


def build_url_dataset(
    feeds: Iterable[RawFeed],
    *,
    max_per_domain: int = 5,
    seed: int = 42,
    verify: bool = True,
    extractor: tldextract.TLDExtract | None = None,
) -> BuildResult:
    """Construit le jeu d'URLs étiquetées à partir des fichiers bruts."""
    observations, read_stats, inputs = collect_observations(feeds, verify=verify)
    df, normalize_stats = normalize_observations(observations, extractor or make_domain_extractor())
    df, merge_stats = merge_duplicates(df)
    capped = cap_per_domain(df, max_per_domain, seed)

    dataset = capped.sort_values(["first_seen", "url"], kind="stable").reset_index(drop=True)
    dataset = dataset[COLUMNS].astype({"label": "int8"})
    steps = {
        **read_stats,
        **normalize_stats,
        **merge_stats,
        "capped_by_domain": len(df) - len(capped),
        "rows": len(dataset),
    }
    return BuildResult(dataset, steps, inputs)


def summarize(dataset: pd.DataFrame) -> dict[str, Any]:
    """Statistiques agrégées (aucune URL) destinées au rapport versionné."""
    by_label = dataset.groupby("label")
    domains_by_label = by_label["registered_domain"].unique()
    shared = set.intersection(*map(set, domains_by_label)) if len(domains_by_label) == 2 else set()
    return {
        "rows": len(dataset),
        "rows_by_label": {str(k): int(v) for k, v in by_label.size().items()},
        "rows_by_source": {str(k): int(v) for k, v in dataset.groupby("source").size().items()},
        "registered_domains": int(dataset["registered_domain"].nunique()),
        "registered_domains_by_label": {
            str(k): int(v) for k, v in by_label["registered_domain"].nunique().items()
        },
        # Domaines présents dans les deux classes : à surveiller pour le split groupé (1.4).
        "registered_domains_in_both_labels": len(shared),
        "first_seen_by_label": {
            str(label): {
                "min": group["first_seen"].min().isoformat(),
                "max": group["first_seen"].max().isoformat(),
            }
            for label, group in by_label
        },
    }
