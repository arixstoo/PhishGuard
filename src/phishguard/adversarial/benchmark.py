"""Banc d'essai de robustesse (étape 3.7).

Pour chaque perturbation de :mod:`phishguard.adversarial.perturb`, le banc applique la
perturbation à **tous** les échantillons d'un bloc de test, phishing et légitimes, puis
mesure au seuil de décision du modèle :

- le **rappel** sur le phishing perturbé, et son écart au rappel sans perturbation
  (Δ rappel) : ce que l'attaquant gagne ;
- le **taux de faux positifs** sur le légitime perturbé de la même façon (Δ FPR) : une
  défense qui signale tout ce qui a été perturbé n'est pas une défense, puisque le texte
  légitime peut lui aussi contenir des majuscules, des sous-domaines ou de longs
  paramètres ;
- les **verdicts retournés** : phishing détecté sans perturbation, manqué avec ;
- le **décalage moyen du score** du phishing, plus sensible que le rappel à un seuil.

Rien n'est réglé sur le test : le seuil est celui du modèle (réglé sur la validation), et
les perturbations sont fixées à l'avance (étape 3.6). Un échantillon où la technique ne
s'applique pas reste dans le calcul, inchangé, et la part des échantillons réellement
modifiés est rapportée à côté.

Fonctions pures : le modèle n'est vu qu'à travers ``score(samples) → scores``.
"""

from __future__ import annotations

import math
from collections.abc import Callable, Sequence
from typing import Any

import numpy as np

from phishguard.adversarial.perturb import PERTURBATIONS, Perturbation, apply
from phishguard.evaluation.prevalence import wilson_interval

Scorer = Callable[[list[str]], np.ndarray]

LABEL_PHISHING = 1
LABEL_LEGITIMATE = 0


def rate(flagged: np.ndarray) -> dict[str, Any]:
    """Part de vrais dans ``flagged``, avec son intervalle de Wilson à 95 %."""
    flagged = np.asarray(flagged, dtype=bool)
    n, k = int(flagged.size), int(flagged.sum())
    if n == 0:
        return {"n": 0, "flagged": 0, "rate": None, "low": None, "high": None}
    low, high = wilson_interval(k, n)
    return {"n": n, "flagged": k, "rate": k / n, "low": low, "high": high}


def _delta(after: dict[str, Any], before: dict[str, Any]) -> float | None:
    if after["rate"] is None or before["rate"] is None:
        return None
    return after["rate"] - before["rate"]


def _mean(values: np.ndarray) -> float | None:
    return float(values.mean()) if values.size else None


def _scores(score: Scorer, samples: list[str]) -> np.ndarray:
    scores = np.asarray(score(samples), dtype=float)
    if scores.shape != (len(samples),):
        raise ValueError(f"score() doit renvoyer {len(samples)} scores, pas {scores.shape}")
    if not np.isfinite(scores).all():
        raise ValueError("score() a renvoyé des scores non finis")
    return scores


def evaluate_perturbations(
    score: Scorer,
    samples: Sequence[str],
    labels: Sequence[int] | np.ndarray,
    threshold: float,
    perturbations: Sequence[Perturbation | str],
    *,
    seed: int = 0,
) -> dict[str, Any]:
    """Rappel et FPR sans perturbation, puis sous chaque perturbation.

    Règle de décision du projet : un échantillon est signalé si son score est
    **strictement supérieur** au seuil.
    """
    samples = list(samples)
    y = np.asarray(labels).astype(int)
    if y.shape != (len(samples),):
        raise ValueError("une étiquette par échantillon est attendue")
    if not set(np.unique(y)) <= {LABEL_LEGITIMATE, LABEL_PHISHING}:
        raise ValueError("étiquettes 0 (légitime) et 1 (phishing) attendues")
    if not math.isfinite(threshold):
        raise ValueError(f"seuil non fini : {threshold!r}")
    positive, negative = y == LABEL_PHISHING, y == LABEL_LEGITIMATE

    base_scores = _scores(score, samples)
    base_flagged = base_scores > threshold
    baseline = {"recall": rate(base_flagged[positive]), "fpr": rate(base_flagged[negative])}

    rows = []
    for item in perturbations:
        perturbation = PERTURBATIONS[item] if isinstance(item, str) else item
        applied = apply(perturbation.name, samples, seed)
        scores = _scores(score, applied.samples)
        flagged = scores > threshold
        changed = np.asarray(applied.changed, dtype=bool)
        recall, fpr = rate(flagged[positive]), rate(flagged[negative])
        rows.append(
            {
                "perturbation": perturbation.name,
                "technique": perturbation.technique,
                "vector": perturbation.vector,
                "description": perturbation.description,
                "creates_lookalike": perturbation.creates_lookalike,
                "changed": {
                    "phishing": rate(changed[positive]),
                    "legitimate": rate(changed[negative]),
                },
                "recall": recall,
                "fpr": fpr,
                "delta_recall": _delta(recall, baseline["recall"]),
                "delta_fpr": _delta(fpr, baseline["fpr"]),
                # Détectés sans perturbation, manqués avec (et l'inverse).
                "evaded": int((base_flagged & ~flagged & positive).sum()),
                "newly_detected": int((~base_flagged & flagged & positive).sum()),
                "new_false_positives": int((~base_flagged & flagged & negative).sum()),
                "mean_score_shift": {
                    "phishing": _mean((scores - base_scores)[positive]),
                    "legitimate": _mean((scores - base_scores)[negative]),
                },
            }
        )
    return {
        "threshold": float(threshold),
        "seed": seed,
        "samples": {"phishing": int(positive.sum()), "legitimate": int(negative.sum())},
        "baseline": baseline,
        "perturbations": rows,
    }


def worst_perturbation(result: dict[str, Any]) -> dict[str, Any] | None:
    """La perturbation qui fait le plus baisser le rappel (``None`` sans perturbation)."""
    rows = [r for r in result["perturbations"] if r["delta_recall"] is not None]
    return min(rows, key=lambda r: r["delta_recall"]) if rows else None
