"""Évaluation réaliste du modèle URL sur le test (étape 1.7).

Trois questions, dans cet ordre :

1. **Point de fonctionnement.** Avec les seuils réglés sur la validation (étape 1.6),
   quel rappel et quel taux de faux positifs obtient-on sur le test ? Le FPR est donné
   pour tout le légitime, pour les pages d'accueil (Tranco) et pour les pages internes
   (Common Crawl), avec un intervalle de confiance de Wilson.
2. **Prévalence.** Que vaut la précision quand le phishing n'est plus 20 % des URLs mais
   1 % ou 0,1 % (:mod:`phishguard.evaluation.prevalence`) ?
3. **Seuil de décision.** :func:`choose_decision_threshold` applique une règle écrite à
   l'avance, **sur la validation** : le test ne sert qu'à mesurer le seuil choisi.

S'y ajoutent deux mesures de biais promises à l'étape 1.5 : le rappel par source de
phishing et le FPR par rang de popularité Tranco (:func:`popularity_report`).
"""

from __future__ import annotations

import csv
import json
import math
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any

import numpy as np

from phishguard.data.bias import HOMEPAGE_SOURCE, INTERNAL_PAGE_SOURCE
from phishguard.data.integrity import sha256_file
from phishguard.data.urls import LABEL_LEGITIMATE, LABEL_PHISHING
from phishguard.evaluation.prevalence import (
    REALISTIC_PREVALENCES,
    alerts_per_urls,
    precision_at_prevalence,
    resample_at_prevalence,
    wilson_interval,
)

# Règle de choix du seuil : au moins une alerte vraie sur deux quand 1 % des URLs sont
# du phishing. En dessous, l'utilisateur apprend à ignorer les alertes.
DECISION_PREVALENCE = 0.01
DECISION_MIN_PRECISION = 0.5
# Rangs Tranco : du plus visité au moins visité. ``None`` : sans borne haute, pour que les
# listes de plus de 100 000 domaines (top 1 million) soient comptées en entier.
RANK_BUCKETS: tuple[tuple[int, int | None], ...] = (
    (1, 1_000),
    (1_001, 10_000),
    (10_001, 100_000),
    (100_001, None),
)


def _rate(flagged: np.ndarray) -> dict[str, Any]:
    n, k = int(flagged.size), int(flagged.sum())
    if n == 0:
        return {"n": 0, "flagged": 0, "rate": math.nan, "low": math.nan, "high": math.nan}
    low, high = wilson_interval(k, n)
    return {"n": n, "flagged": k, "rate": k / n, "low": low, "high": high}


def operating_point(
    y: np.ndarray, scores: np.ndarray, sources: np.ndarray, threshold: float
) -> dict[str, Any]:
    """Rappel et FPR (global, pages d'accueil, pages internes) à un seuil fixé."""
    flagged = scores > threshold
    legit = y == LABEL_LEGITIMATE
    return {
        "threshold": float(threshold),
        "recall": _rate(flagged[y == LABEL_PHISHING]),
        "fpr": _rate(flagged[legit]),
        "fpr_homepages": _rate(flagged[legit & (sources == HOMEPAGE_SOURCE)]),
        "fpr_internal_pages": _rate(flagged[legit & (sources == INTERNAL_PAGE_SOURCE)]),
    }


def operating_points(
    y: np.ndarray, scores: np.ndarray, sources: np.ndarray, thresholds: Mapping[str, float]
) -> dict[str, dict[str, Any]]:
    return {name: operating_point(y, scores, sources, t) for name, t in thresholds.items()}


def prevalence_table(
    y: np.ndarray,
    scores: np.ndarray,
    sources: np.ndarray,
    threshold: float,
    prevalences: Sequence[float] = REALISTIC_PREVALENCES,
    *,
    rounds: int = 2000,
    seed: int = 0,
) -> list[dict[str, Any]]:
    """Précision et alertes attendues à chaque prévalence, pour un seuil.

    Deux hypothèses sur le légitime visité : celui du test (90 % de pages d'accueil), ou
    uniquement des pages internes, plus proche de la navigation réelle et plus sévère.
    """
    point = operating_point(y, scores, sources, threshold)
    recall = point["recall"]["rate"]
    flagged = scores > threshold
    rows = []
    for p in prevalences:
        resampled = resample_at_prevalence(y, flagged, p, rounds=rounds, seed=seed)
        row: dict[str, Any] = {
            "prevalence": p,
            "precision": precision_at_prevalence(recall, point["fpr"]["rate"], p),
            "precision_resampled": resampled,
            **{
                f"per_10k_{k}": v
                for k, v in alerts_per_urls(recall, point["fpr"]["rate"], p).items()
            },
        }
        internal = point["fpr_internal_pages"]["rate"]
        if not math.isnan(internal):
            row["precision_internal_pages"] = precision_at_prevalence(recall, internal, p)
            row["false_per_true_internal_pages"] = alerts_per_urls(recall, internal, p)[
                "false_per_true"
            ]
        rows.append(row)
    return rows


def choose_decision_threshold(
    validation_points: Mapping[str, Mapping[str, Any]],
    *,
    prevalence: float = DECISION_PREVALENCE,
    min_precision: float = DECISION_MIN_PRECISION,
) -> dict[str, Any]:
    """Seuil de décision, choisi sur la **validation**.

    Parmi les seuils dont la précision attendue à ``prevalence`` atteint
    ``min_precision``, celui qui a le meilleur rappel. Si aucun ne l'atteint, le seuil le
    plus précis, et ``meets_target`` vaut ``False``.
    """
    if not validation_points:
        raise ValueError("aucun seuil candidat")
    candidates = []
    for name, point in validation_points.items():
        recall, fpr = point["recall"]["rate"], point["fpr"]["rate"]
        precision = precision_at_prevalence(recall, fpr, prevalence)
        candidates.append((name, recall, -1.0 if math.isnan(precision) else precision))
    eligible = [c for c in candidates if c[2] >= min_precision]
    if eligible:
        name, recall, precision = max(eligible, key=lambda c: (c[1], c[2]))
    else:
        name, recall, precision = max(candidates, key=lambda c: (c[2], c[1]))
    return {
        "name": name,
        "rule": {"prevalence": prevalence, "min_precision": min_precision},
        "meets_target": bool(eligible),
        "validation_recall": recall,
        "validation_precision_at_prevalence": precision,
    }


def per_source(
    y: np.ndarray, scores: np.ndarray, sources: np.ndarray, threshold: float
) -> dict[str, dict[str, Any]]:
    """Rappel par source de phishing, FPR par source de légitime."""
    flagged = scores > threshold
    result = {}
    for source in sorted(set(sources.tolist())):
        mask = sources == source
        label = int(np.bincount(y[mask]).argmax())
        metric = "recall" if label == LABEL_PHISHING else "fpr"
        result[source] = {"label": label, "metric": metric, **_rate(flagged[mask])}
    return result


# --------------------------------------------------------------------------- #
# Popularité (rang Tranco)
# --------------------------------------------------------------------------- #


def read_tranco_ranks(path: Path) -> dict[str, int]:
    """Rang de chaque domaine d'un fichier Tranco (``rang,domaine`` sans en-tête)."""
    ranks: dict[str, int] = {}
    with Path(path).open(encoding="utf-8", newline="") as handle:
        for row in csv.reader(handle):
            if len(row) >= 2 and row[0].strip().isdigit():
                ranks.setdefault(row[1].strip().lower(), int(row[0]))
    return ranks


def dataset_tranco_files(dataset_report: Path, raw_dir: Path) -> list[Path]:
    """Listes Tranco qui ont servi à construire le jeu, de la plus ancienne à la plus récente.

    Elles sont lues dans le rapport du jeu (``docs/metrics/urls_dataset.json``, étape 1.2),
    pas devinées dans ``data/raw/`` : la collecte quotidienne y ajoute des listes qui n'ont
    pas servi, et la date de modification d'un fichier change quand on le copie. L'empreinte
    SHA-256 de chaque fichier est vérifiée. Retourne une liste vide si le rapport est absent
    ou si l'un des fichiers manque (un rang partiel fausserait les tranches).
    """
    dataset_report = Path(dataset_report)
    if not dataset_report.is_file():
        return []
    inputs = json.loads(dataset_report.read_text(encoding="utf-8")).get("inputs", [])
    entries = sorted(
        (i for i in inputs if i.get("source") == HOMEPAGE_SOURCE), key=lambda i: i["collected_at"]
    )
    files = []
    for entry in entries:
        path = Path(raw_dir) / entry["file"]
        if not path.is_file():
            return []
        if entry.get("sha256") and sha256_file(path) != entry["sha256"]:
            raise ValueError(f"{path.name} : empreinte différente de celle du rapport du jeu")
        files.append(path)
    return files


def merge_tranco_ranks(paths: Sequence[Path]) -> dict[str, int]:
    """Rang de chaque domaine dans la liste la plus récente qui le contient.

    ``paths`` va de la plus ancienne à la plus récente. Le jeu réunit plusieurs listes
    quotidiennes : un domaine sorti de la dernière garde le rang de la précédente, au lieu
    d'être compté « hors liste ».
    """
    ranks: dict[str, int] = {}
    for path in reversed(list(paths)):
        for domain, rank in read_tranco_ranks(path).items():
            ranks.setdefault(domain, rank)
    return ranks


def popularity_report(
    domains: Iterable[str],
    scores: np.ndarray,
    threshold: float,
    ranks: Mapping[str, int],
    buckets: Sequence[tuple[int, int | None]] = RANK_BUCKETS,
) -> dict[str, dict[str, Any]]:
    """FPR des pages d'accueil légitimes par tranche de rang Tranco.

    Mesure le biais de popularité de l'étape 1.5 : si le modèle a appris « nom court =
    légitime », le FPR monte quand on descend dans le classement. Chaque domaine tombe
    dans exactement une tranche : celle de son rang, ou ``unranked`` s'il est absent de
    la liste. Une tranche sans borne haute s'écrit ``"100001+"``.
    """
    domains = list(domains)
    if len(domains) != len(scores):
        raise ValueError("domains et scores doivent avoir la même taille")
    rank = np.array([ranks.get(d, 0) for d in domains])
    flagged = np.asarray(scores) > threshold
    report = {}
    for low, high in buckets:
        mask = rank >= low if high is None else (rank >= low) & (rank <= high)
        report[f"{low}+" if high is None else f"{low}-{high}"] = _rate(flagged[mask])
    report["unranked"] = _rate(flagged[rank == 0])
    return report
