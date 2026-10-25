"""Split temporel et groupé du jeu d'URLs (étape 1.4).

Découpe le jeu en trois blocs (entraînement, validation, test) avec deux garanties :

- **groupé** : un domaine enregistré n'appartient qu'à un seul bloc, toutes classes et
  sources confondues. Le test mesure donc la détection de sites jamais vus ;
- **temporel** : dans chaque strate (par défaut, chaque couple étiquette × source), les
  domaines apparus les premiers vont à l'entraînement, les plus récents au test.

Pourquoi découper par strate et non sur tout le jeu : les dates des sources ne suivent pas
la même horloge (date de signalement PhishTank depuis 2011, date de capture Common Crawl,
date de collecte Tranco). Un tri global mettrait presque tout le phishing à l'entraînement
et presque rien en validation (voir ``docs/data-bias.md``, biais temporel). Découper chaque
source dans le temps garde aussi la même composition de sources dans chaque bloc, pour
qu'un écart de score entre blocs ne vienne pas d'un changement de source.

Algorithme :

1. Les strates sont traitées de la plus petite à la plus grande.
2. Dans une strate, chaque domaine reçoit la date de sa première URL dans la strate.
   Les ex aequo (toutes les URLs d'une collecte Tranco ont la même date) sont départagés
   par un hachage du domaine et de la graine : le résultat ne dépend pas de l'ordre des
   lignes.
3. Un domaine déjà placé par une strate précédente garde son bloc ; ses lignes comptent
   dans les quotas de la strate courante. Les autres domaines remplissent, dans l'ordre
   chronologique, le reste du quota de l'entraînement, puis de la validation, puis du test.

Traiter les petites strates d'abord leur laisse le meilleur respect de l'ordre temporel ;
les grandes strates absorbent les écarts sans que leurs proportions bougent beaucoup.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

import numpy as np
import pandas as pd

from phishguard.data.urls import LABEL_LEGITIMATE

SPLITS = ("train", "validation", "test")
SPLIT_DTYPE = pd.CategoricalDtype(list(SPLITS), ordered=True)
GROUP_COLUMN = "registered_domain"
TIME_COLUMN = "first_seen"


class DomainLeakageError(AssertionError):
    """Un domaine enregistré apparaît dans plusieurs blocs."""


@dataclass(frozen=True)
class SplitConfig:
    """Paramètres du split.

    ``fractions`` est la part de lignes visée pour chaque bloc, dans chaque strate. Les
    parts obtenues s'en écartent un peu : un domaine n'est jamais coupé en deux.
    """

    fractions: tuple[float, float, float] = (0.70, 0.15, 0.15)
    strata: tuple[str, ...] = ("label", "source")
    seed: int = 42

    def __post_init__(self) -> None:
        if len(self.fractions) != len(SPLITS):
            raise ValueError(f"il faut {len(SPLITS)} fractions, une par bloc")
        if any(f <= 0 for f in self.fractions):
            raise ValueError("chaque fraction doit être strictement positive")
        if not np.isclose(sum(self.fractions), 1.0):
            raise ValueError("les fractions doivent sommer à 1")
        if not self.strata:
            raise ValueError("au moins une colonne de strate est requise")


# --------------------------------------------------------------------------- #
# Split
# --------------------------------------------------------------------------- #


def _validate(df: pd.DataFrame, strata: Sequence[str]) -> None:
    required = [GROUP_COLUMN, TIME_COLUMN, *strata]
    missing = [c for c in required if c not in df.columns]
    if missing:
        raise ValueError(f"colonnes absentes : {', '.join(missing)}")
    empty = [c for c in required if df[c].isna().any()]
    if empty:
        raise ValueError(f"valeurs manquantes dans : {', '.join(empty)}")


def _tiebreak(domains: pd.Index, seed: int) -> np.ndarray:
    """Clé pseudo-aléatoire stable par domaine, indépendante de l'ordre des lignes."""
    return np.array(
        [
            int.from_bytes(hashlib.blake2b(f"{seed}\0{d}".encode(), digest_size=8).digest(), "big")
            for d in domains
        ],
        dtype=np.uint64,
    )


def _quotas(rows: int, fractions: Sequence[float]) -> np.ndarray:
    """Nombre de lignes visé par bloc ; la somme vaut exactement ``rows``."""
    return np.diff(np.rint(np.cumsum([0.0, *fractions]) * rows).astype(np.int64))


def ordered_strata(df: pd.DataFrame, strata: Sequence[str]) -> list[tuple[str, pd.DataFrame]]:
    """Strates dans leur ordre de traitement : de la plus petite à la plus grande.

    À taille égale, l'ordre des clés départage (tri stable). Chaque clé est rendue sous la
    forme ``"valeur1/valeur2"``.
    """
    groups = [
        ("/".join(map(str, key if isinstance(key, tuple) else (key,))), stratum)
        for key, stratum in df.groupby(list(strata), sort=True)
    ]
    return sorted(groups, key=lambda item: len(item[1]))


def temporal_group_split(df: pd.DataFrame, cfg: SplitConfig | None = None) -> pd.Series:
    """Bloc (``train``, ``validation`` ou ``test``) de chaque ligne de ``df``.

    Retourne une série catégorielle ordonnée, de même index que ``df``.
    """
    cfg = cfg or SplitConfig()
    strata = list(cfg.strata)
    _validate(df, strata)
    if df.empty:
        return pd.Series(pd.Categorical([], dtype=SPLIT_DTYPE), index=df.index, name="split")

    assigned: dict[str, int] = {}
    for _, stratum in ordered_strata(df, strata):
        domains = stratum.groupby(GROUP_COLUMN, sort=True).agg(
            rows=(TIME_COLUMN, "size"), first=(TIME_COLUMN, "min")
        )
        placed = domains.index.map(assigned).to_numpy(dtype=float, na_value=np.nan)
        is_placed = ~np.isnan(placed)

        quotas = _quotas(len(stratum), cfg.fractions)
        already = np.bincount(
            placed[is_placed].astype(np.int64),
            weights=domains["rows"].to_numpy()[is_placed],
            minlength=len(SPLITS),
        )
        capacity = np.clip(quotas - already, 0, None)

        free = domains.loc[~is_placed].copy()
        free["tiebreak"] = _tiebreak(free.index, cfg.seed)
        free = free.sort_values(["first", "tiebreak"], kind="stable")
        # Un domaine va dans le bloc où commence sa première ligne : il n'est jamais coupé.
        start = free["rows"].cumsum().to_numpy() - free["rows"].to_numpy()
        blocks = np.searchsorted(np.cumsum(capacity), start, side="right")
        blocks = np.minimum(blocks, len(SPLITS) - 1)
        assigned.update(zip(free.index, blocks.tolist(), strict=True))

    codes = df[GROUP_COLUMN].map(assigned).to_numpy(dtype=np.int64)
    return pd.Series(
        pd.Categorical.from_codes(codes, dtype=SPLIT_DTYPE), index=df.index, name="split"
    )


def assert_no_domain_leakage(df: pd.DataFrame, split: pd.Series) -> None:
    """Lève :class:`DomainLeakageError` si un domaine enregistré est dans plusieurs blocs."""
    if not split.index.equals(df.index):
        raise ValueError("le split et le jeu n'ont pas le même index")
    if split.isna().any():
        raise ValueError(f"{int(split.isna().sum())} lignes sans bloc")
    blocks_per_domain = split.groupby(df[GROUP_COLUMN], observed=True).nunique()
    leaked = blocks_per_domain.index[blocks_per_domain > 1]
    if len(leaked):
        examples = ", ".join(map(str, leaked[:5]))
        raise DomainLeakageError(
            f"{len(leaked)} domaines présents dans plusieurs blocs (exemples : {examples})"
        )


def split_frames(df: pd.DataFrame, split: pd.Series) -> dict[str, pd.DataFrame]:
    """Les trois blocs de ``df``, dans l'ordre de :data:`SPLITS`."""
    return {name: df.loc[split == name] for name in SPLITS}


# --------------------------------------------------------------------------- #
# Rapport
# --------------------------------------------------------------------------- #


def _has_path(url: str) -> bool:
    parts = urlsplit(url)
    return parts.path not in ("", "/") or bool(parts.query)


def _date_range(seen: pd.Series) -> dict[str, str | None]:
    if seen.empty:
        return {"min": None, "max": None}
    return {"min": seen.min().isoformat(), "max": seen.max().isoformat()}


def constrained_rows(df: pd.DataFrame, strata: Sequence[str]) -> dict[str, int]:
    """Par strate, lignes dont le domaine a déjà été placé par une strate plus petite.

    Ce sont les seules lignes dont le bloc ne suit pas l'ordre temporel de leur strate :
    sans elles, l'entraînement ne contient que des domaines apparus avant ceux de la
    validation, eux-mêmes apparus avant ceux du test.
    """
    seen: set[str] = set()
    counts = {}
    for key, stratum in ordered_strata(df, strata):
        domains = stratum[GROUP_COLUMN]
        counts[key] = int(domains.isin(seen).sum())
        seen.update(domains)
    return counts


def split_report(df: pd.DataFrame, split: pd.Series, cfg: SplitConfig) -> dict[str, Any]:
    """Statistiques agrégées du split, sans aucune URL ni aucun domaine."""
    assert_no_domain_leakage(df, split)
    total = len(df)

    blocks = {}
    for name, block in split_frames(df, split).items():
        legit = block["label"] == LABEL_LEGITIMATE
        blocks[name] = {
            "rows": len(block),
            "share": round(len(block) / total, 4) if total else None,
            "domains": int(block[GROUP_COLUMN].nunique()),
            "phishing_rate": round(float(1 - legit.mean()), 4) if len(block) else None,
            # Pages internes légitimes : nécessaires pour régler un seuil réaliste (1.3 bis).
            "legitimate_with_path": int(block.loc[legit, "url"].map(_has_path).sum()),
            "by_source": {str(k): int(v) for k, v in block["source"].value_counts().items()},
            "first_seen": _date_range(block[TIME_COLUMN]),
        }

    constrained = constrained_rows(df, cfg.strata)
    strata = {}
    for key, stratum in ordered_strata(df, cfg.strata):
        in_block = split.loc[stratum.index]
        counts = in_block.value_counts().reindex(list(SPLITS), fill_value=0)
        strata[key] = {
            "rows": len(stratum),
            "target_rows": dict(
                zip(SPLITS, _quotas(len(stratum), cfg.fractions).tolist(), strict=True)
            ),
            "rows_per_block": {k: int(v) for k, v in counts.items()},
            "rows_placed_by_smaller_stratum": constrained[key],
            "first_seen": {
                name: _date_range(stratum.loc[in_block == name, TIME_COLUMN]) for name in SPLITS
            },
        }

    return {
        "params": {
            "fractions": dict(zip(SPLITS, cfg.fractions, strict=True)),
            "strata": list(cfg.strata),
            "group": GROUP_COLUMN,
            "time": TIME_COLUMN,
            "seed": cfg.seed,
        },
        "rows": total,
        "domains": int(df[GROUP_COLUMN].nunique()),
        "domains_in_several_blocks": 0,
        "blocks": blocks,
        "strata": strata,
    }
