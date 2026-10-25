"""Mesure de l'apport des features URL, sur la validation (étape 1.5).

Trois mesures, toutes avec le même modèle (LightGBM à paramètres fixes, non réglés) :

1. **Pouvoir séparateur de chaque feature seule** : ROC-AUC sur la validation (0,5 = aucun
   signal ; < 0,5 = la feature est plus élevée côté légitime) et moyenne par classe.
2. **Ajout des familles une par une** (base, puis marques, homographes, TLD,
   raccourcisseurs), comme le demande le plan, et retrait de chaque famille du modèle
   complet : l'ordre d'ajout favorise les premières familles, le retrait non.
3. **Retrait des groupes porteurs d'un biais de collecte** : ``path`` et ``length``
   (biais de chemin, demandé par l'audit ``docs/data-bias.md``) et ``scheme`` (voir
   :data:`GROUP_ABLATIONS`).

Chaque modèle rapporte, en plus des métriques globales, le taux de faux positifs sur les
pages d'accueil et sur les pages internes légitimes, au seuil qui donne 1 % de faux
positifs sur tout le légitime de validation. Le bloc de test n'est jamais utilisé : il
est réservé au rapport final (étape 1.7).
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

import lightgbm as lgb
import numpy as np
import pandas as pd
from sklearn.metrics import roc_auc_score

from phishguard.data.bias import HOMEPAGE_SOURCE, INTERNAL_PAGE_SOURCE
from phishguard.data.urls import LABEL_LEGITIMATE, LABEL_PHISHING
from phishguard.evaluation.metrics import binary_report
from phishguard.urls.features import FAMILIES, feature_names

FAMILY_STEPS: tuple[tuple[str, ...], ...] = tuple(FAMILIES[: i + 1] for i in range(len(FAMILIES)))
# ``scheme`` : les URLs Tranco sont construites en ``https://<domaine>/`` (étape 1.2), leur
# schéma ne vient donc pas des données. ``host_only`` ne garde que les features d'hôte
# hors longueur, les moins exposées aux biais de chemin et de schéma.
GROUP_ABLATIONS: dict[str, tuple[str, ...]] = {
    "all": (),
    "without_scheme": ("scheme",),
    "without_path": ("path",),
    "without_length": ("length",),
    "without_path_and_length": ("path", "length"),
    "host_only": ("scheme", "path", "length"),
}
_REPORTED = ("pr_auc", "roc_auc", "recall_at_fpr_1pct", "recall_at_fpr_0_1pct")


@dataclass(frozen=True)
class AblationConfig:
    max_fpr: float = 0.01
    n_estimators: int = 300
    learning_rate: float = 0.05
    num_leaves: int = 31
    seed: int = 42


def make_model(cfg: AblationConfig) -> lgb.LGBMClassifier:
    """LightGBM déterministe (un seul fil) : deux exécutions donnent les mêmes scores."""
    return lgb.LGBMClassifier(
        n_estimators=cfg.n_estimators,
        learning_rate=cfg.learning_rate,
        num_leaves=cfg.num_leaves,
        random_state=cfg.seed,
        deterministic=True,
        force_col_wise=True,
        n_jobs=1,
        verbose=-1,
    )


def _rate(mask: np.ndarray) -> float:
    return round(float(mask.mean()), 4) if mask.size else float("nan")


def score_report(
    y: np.ndarray, scores: np.ndarray, sources: np.ndarray, max_fpr: float
) -> dict[str, Any]:
    """Métriques globales et faux positifs par type de page légitime."""
    report = binary_report(y, scores)
    legit = scores[y == LABEL_LEGITIMATE]
    # Plus petit seuil laissant au plus max_fpr du légitime au-dessus.
    threshold = float(np.quantile(legit, 1 - max_fpr, method="higher"))
    flagged = scores > threshold
    homepages = (y == LABEL_LEGITIMATE) & (sources == HOMEPAGE_SOURCE)
    internal = (y == LABEL_LEGITIMATE) & (sources == INTERNAL_PAGE_SOURCE)
    return {
        **{key: report[key] for key in _REPORTED},
        "threshold": round(threshold, 6),
        "recall": _rate(flagged[y == LABEL_PHISHING]),
        "fpr_homepages": _rate(flagged[homepages]),
        "fpr_internal_pages": _rate(flagged[internal]),
    }


def fit_and_score(
    columns: Sequence[str],
    train: tuple[pd.DataFrame, np.ndarray],
    validation: tuple[pd.DataFrame, np.ndarray, np.ndarray],
    cfg: AblationConfig,
) -> dict[str, Any]:
    (x_train, y_train), (x_val, y_val, sources_val) = train, validation
    model = make_model(cfg).fit(x_train[list(columns)], y_train)
    scores = model.predict_proba(x_val[list(columns)])[:, 1]
    importance = dict(zip(columns, model.booster_.feature_importance("gain"), strict=True))
    total = sum(importance.values()) or 1.0
    return {
        "n_features": len(columns),
        **score_report(y_val, scores, sources_val, cfg.max_fpr),
        "gain_share": {k: round(v / total, 4) for k, v in sorted(importance.items())},
    }


def univariate(x: pd.DataFrame, y: np.ndarray) -> dict[str, dict[str, float]]:
    """ROC-AUC de chaque feature seule et moyenne par classe."""
    result = {}
    for name in x.columns:
        values = x[name].to_numpy()
        auc = roc_auc_score(y, values) if np.unique(values).size > 1 else 0.5
        result[name] = {
            "roc_auc": round(float(auc), 4),
            "mean_legitimate": round(float(values[y == LABEL_LEGITIMATE].mean()), 4),
            "mean_phishing": round(float(values[y == LABEL_PHISHING].mean()), 4),
        }
    return result


def run_ablation(
    x_train: pd.DataFrame,
    y_train: np.ndarray,
    x_val: pd.DataFrame,
    y_val: np.ndarray,
    sources_val: np.ndarray,
    cfg: AblationConfig | None = None,
) -> dict[str, Any]:
    """Les trois mesures du module, sur des features déjà extraites (toutes familles)."""
    cfg = cfg or AblationConfig()
    train, validation = (x_train, y_train), (x_val, y_val, sources_val)

    def run(columns: Sequence[str]) -> dict[str, Any]:
        return fit_and_score(columns, train, validation, cfg)

    every = feature_names()
    missing = set(every) - set(x_train.columns)
    if missing:
        raise ValueError(f"features absentes : {sorted(missing)}")

    return {
        "config": cfg.__dict__,
        "univariate": univariate(x_val[list(every)], y_val),
        "families_added": {"+".join(step): run(feature_names(step)) for step in FAMILY_STEPS},
        "families_removed": {
            family: run(feature_names([f for f in FAMILIES if f != family]))
            for family in FAMILIES
            if family != "base"
        },
        "groups_removed": {
            name: run(feature_names(exclude_groups=groups))
            for name, groups in GROUP_ABLATIONS.items()
        },
    }
