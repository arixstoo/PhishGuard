"""Métriques de détection orientées sécurité.

L'accuracy seule est trompeuse sur des classes déséquilibrées : un modèle qui répond
toujours « légitime » obtient 87 % sur le corpus SMS. On rapporte donc la précision,
le rappel et le F1 de la classe positive, la matrice de confusion, la PR-AUC et le
rappel à taux de faux positifs fixé (la métrique qui compte pour la confiance).
"""

from __future__ import annotations

import numpy as np
from numpy.typing import ArrayLike
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
)


def recall_at_fpr(y_true: ArrayLike, y_score: ArrayLike, max_fpr: float = 0.01) -> float:
    """Meilleur rappel atteignable sans dépasser ``max_fpr`` faux positifs."""
    if not 0.0 <= max_fpr <= 1.0:
        raise ValueError("max_fpr doit être compris entre 0 et 1")
    fpr, tpr, _ = roc_curve(y_true, y_score)
    return float(tpr[fpr <= max_fpr].max())


def threshold_at_fpr(legitimate_scores: ArrayLike, max_fpr: float) -> float:
    """Plus petit seuil laissant au plus ``max_fpr`` des scores légitimes au-dessus.

    La règle de décision associée est stricte : une URL est signalée si son score est
    **strictement supérieur** au seuil.
    """
    if not 0.0 <= max_fpr <= 1.0:
        raise ValueError("max_fpr doit être compris entre 0 et 1")
    scores = np.asarray(legitimate_scores, dtype=float)
    if scores.size == 0:
        raise ValueError("aucun score légitime")
    return float(np.quantile(scores, 1 - max_fpr, method="higher"))


def binary_report(
    y_true: ArrayLike, y_score: ArrayLike, *, threshold: float = 0.5, digits: int = 4
) -> dict:
    """Rapport complet pour un détecteur binaire (1 = malveillant).

    ``y_score`` est la probabilité (ou un score croissant) de la classe positive.
    """
    y_true = np.asarray(y_true).astype(int)
    y_score = np.asarray(y_score, dtype=float)
    if y_true.shape != y_score.shape:
        raise ValueError("y_true et y_score doivent avoir la même taille")
    if set(np.unique(y_true)) != {0, 1}:
        raise ValueError("y_true doit contenir les deux classes 0 et 1")

    y_pred = (y_score >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()

    def r(x: float) -> float:
        return round(float(x), digits)

    return {
        "threshold": threshold,
        "support": {"negative": int((y_true == 0).sum()), "positive": int((y_true == 1).sum())},
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        "precision": r(precision_score(y_true, y_pred, zero_division=0)),
        "recall": r(recall_score(y_true, y_pred, zero_division=0)),
        "f1": r(f1_score(y_true, y_pred, zero_division=0)),
        "fpr": r(fp / (fp + tn)),
        "accuracy": r(accuracy_score(y_true, y_pred)),
        "pr_auc": r(average_precision_score(y_true, y_score)),
        "roc_auc": r(roc_auc_score(y_true, y_score)),
        "recall_at_fpr_1pct": r(recall_at_fpr(y_true, y_score, 0.01)),
        "recall_at_fpr_0_1pct": r(recall_at_fpr(y_true, y_score, 0.001)),
    }
