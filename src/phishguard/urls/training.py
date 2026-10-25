"""Entraînement et comparaison des modèles URL (étape 1.6).

Trois familles de modèles, de la plus simple à la plus expressive :

- **régression logistique** avec standardisation (référence linéaire, explicable) ;
- **Random Forest** ;
- **LightGBM** (gradient boosting).

Chacune est entraînée sur le bloc d'entraînement pour chaque combinaison de sa grille
d'hyperparamètres (:data:`MODEL_SPECS`) et pour chaque jeu de features
(:data:`FEATURE_SETS`, avec et sans les groupes exposés aux biais de collecte, comme
décidé à l'étape 1.5). Tous les scores sont mesurés **sur la validation** ; le test n'est
jamais lu, il est réservé à l'évaluation finale (étape 1.7).

Critère de sélection : le rappel à 1 % de faux positifs (:data:`SELECTION_METRIC`), puis
la PR-AUC pour départager. Le rappel à 0,1 % FPR est rapporté mais pas utilisé pour
choisir : sur la validation, 0,1 % du légitime représente une quinzaine d'URLs, et une
ou deux URLs suffisent à le déplacer de plusieurs points.

Le modèle retenu reste celui entraîné sur l'entraînement seul (pas de réentraînement sur
entraînement + validation) : ses seuils, réglés sur la validation, restent ainsi mesurés
sur des URLs qu'il n'a pas vues.
"""

from __future__ import annotations

import io
import itertools
import logging
import statistics
import time
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

import joblib
import lightgbm as lgb
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

from phishguard.data.urls import LABEL_LEGITIMATE
from phishguard.evaluation.metrics import threshold_at_fpr
from phishguard.urls.ablation import GROUP_ABLATIONS, score_report
from phishguard.urls.features import feature_names
from phishguard.urls.model import UrlModel

logger = logging.getLogger(__name__)

SELECTION_METRIC = "recall_at_fpr_1pct"
TIE_BREAK_METRIC = "pr_auc"
# Seuils enregistrés avec le modèle : nom → taux de faux positifs visé sur la validation.
# Le seuil de décision est choisi parmi eux à l'étape 1.7, sans toucher au modèle.
THRESHOLD_TARGETS: dict[str, float] = {
    "fpr_5pct": 0.05,
    "fpr_2pct": 0.02,
    "fpr_1pct": 0.01,
    "fpr_0_5pct": 0.005,
    "fpr_0_2pct": 0.002,
    "fpr_0_1pct": 0.001,
}
# Jeux de features comparés : ceux de l'ablation de l'étape 1.5 (groupes retirés).
FEATURE_SETS: dict[str, tuple[str, ...]] = {
    name: feature_names(exclude_groups=groups) for name, groups in GROUP_ABLATIONS.items()
}
# ``is_https`` est un artefact de construction (URLs Tranco fabriquées en https, étape
# 1.2, voir docs/url-features.md) : le modèle déployé ne l'utilise pas.
DEFAULT_DEPLOY_FEATURE_SET = "without_scheme"


def _grid(**axes: Sequence[Any]) -> tuple[dict[str, Any], ...]:
    """Produit cartésien des valeurs, dans l'ordre des axes (ordre stable)."""
    keys = list(axes)
    return tuple(
        dict(zip(keys, values, strict=True)) for values in itertools.product(*axes.values())
    )


def build_logistic_regression(params: Mapping[str, Any], seed: int) -> Any:
    return make_pipeline(
        StandardScaler(),
        LogisticRegression(C=params["C"], max_iter=5000, random_state=seed),
    )


def build_random_forest(params: Mapping[str, Any], seed: int) -> Any:
    return RandomForestClassifier(
        n_estimators=params["n_estimators"],
        max_depth=params["max_depth"],
        min_samples_leaf=params["min_samples_leaf"],
        max_features="sqrt",
        n_jobs=-1,  # le résultat ne dépend pas du nombre de fils (graine fixée)
        random_state=seed,
    )


def build_lightgbm(params: Mapping[str, Any], seed: int) -> Any:
    # Un seul fil et mode déterministe, comme l'ablation de l'étape 1.5.
    return lgb.LGBMClassifier(
        **params,
        random_state=seed,
        deterministic=True,
        force_col_wise=True,
        n_jobs=1,
        verbose=-1,
    )


@dataclass(frozen=True)
class ModelSpec:
    name: str
    label: str
    build: Callable[[Mapping[str, Any], int], Any]
    grid: tuple[dict[str, Any], ...]


MODEL_SPECS: dict[str, ModelSpec] = {
    spec.name: spec
    for spec in (
        ModelSpec(
            "logistic_regression",
            "Régression logistique",
            build_logistic_regression,
            _grid(C=(0.01, 0.1, 1.0, 10.0)),
        ),
        ModelSpec(
            "random_forest",
            "Random Forest",
            build_random_forest,
            _grid(n_estimators=(300,), max_depth=(None, 16), min_samples_leaf=(1, 5)),
        ),
        ModelSpec(
            "lightgbm",
            "LightGBM",
            build_lightgbm,
            _grid(
                n_estimators=(300, 800),
                learning_rate=(0.05, 0.1),
                num_leaves=(15, 63),
                min_child_samples=(20,),
            ),
        ),
    )
}
# Grilles réduites pour les tests et les essais rapides (``train_url.py --quick``).
QUICK_GRIDS: dict[str, tuple[dict[str, Any], ...]] = {
    "logistic_regression": _grid(C=(1.0,)),
    "random_forest": _grid(n_estimators=(50,), max_depth=(None,), min_samples_leaf=(1,)),
    "lightgbm": _grid(
        n_estimators=(50,), learning_rate=(0.1,), num_leaves=(15,), min_child_samples=(20,)
    ),
}


def single_threaded(estimator: Any) -> Any:
    """Passe un estimateur entraîné en un seul fil pour l'inférence.

    Démarrer un pool de fils coûte plus cher que scorer une URL : en production, une
    requête = une URL.
    """
    if isinstance(estimator, RandomForestClassifier):
        estimator.set_params(n_jobs=1)
    return estimator


# --------------------------------------------------------------------------- #
# Recherche
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Trial:
    """Un modèle, un jeu de features, une combinaison d'hyperparamètres."""

    model: str
    feature_set: str
    params: dict[str, Any]
    metrics: dict[str, Any]
    fit_seconds: float

    @property
    def key(self) -> tuple[float, float]:
        return (self.metrics[SELECTION_METRIC], self.metrics[TIE_BREAK_METRIC])

    def to_dict(self) -> dict[str, Any]:
        return {
            "model": self.model,
            "feature_set": self.feature_set,
            "params": self.params,
            "fit_seconds": round(self.fit_seconds, 2),
            **self.metrics,
        }


@dataclass
class SearchResult:
    trials: list[Trial] = field(default_factory=list)
    # Meilleur essai par (modèle, jeu de features).
    best: dict[tuple[str, str], Trial] = field(default_factory=dict)
    # Estimateur entraîné du meilleur essai de chaque modèle, sur le jeu à déployer.
    estimators: dict[str, Any] = field(default_factory=dict)
    # Scores de validation de ces estimateurs.
    validation_scores: dict[str, np.ndarray] = field(default_factory=dict)

    def best_model(self, feature_set: str) -> Trial:
        """Meilleur essai, tous modèles confondus, pour un jeu de features."""
        candidates = [t for (_, fs), t in self.best.items() if fs == feature_set]
        if not candidates:
            raise KeyError(f"aucun essai pour le jeu de features {feature_set!r}")
        return max(candidates, key=lambda t: t.key)


def search(
    x_train: pd.DataFrame,
    y_train: np.ndarray,
    x_val: pd.DataFrame,
    y_val: np.ndarray,
    sources_val: np.ndarray,
    *,
    models: Iterable[str] = tuple(MODEL_SPECS),
    feature_sets: Iterable[str] = tuple(FEATURE_SETS),
    deploy_feature_set: str = DEFAULT_DEPLOY_FEATURE_SET,
    grids: Mapping[str, Sequence[dict[str, Any]]] | None = None,
    max_fpr: float = 0.01,
    seed: int = 42,
) -> SearchResult:
    """Entraîne chaque combinaison sur l'entraînement et la mesure sur la validation.

    En cas d'égalité sur le critère, le premier essai de la grille l'emporte : le
    résultat ne dépend que des données et de la graine.
    """
    models, feature_sets = list(models), list(feature_sets)
    unknown = (set(models) - set(MODEL_SPECS)) | (set(feature_sets) - set(FEATURE_SETS))
    if unknown:
        raise ValueError(f"modèles ou jeux de features inconnus : {sorted(unknown)}")
    if deploy_feature_set not in feature_sets:
        raise ValueError(f"le jeu à déployer {deploy_feature_set!r} doit être évalué")
    grids = grids or {}

    result = SearchResult()
    for model_name in models:
        spec = MODEL_SPECS[model_name]
        grid = grids.get(model_name, spec.grid)
        for set_name in feature_sets:
            columns = list(FEATURE_SETS[set_name])
            for params in grid:
                start = time.perf_counter()
                estimator = spec.build(params, seed).fit(x_train[columns], y_train)
                fit_seconds = time.perf_counter() - start
                scores = estimator.predict_proba(x_val[columns])[:, 1]
                trial = Trial(
                    model=model_name,
                    feature_set=set_name,
                    params=dict(params),
                    metrics=score_report(y_val, scores, sources_val, max_fpr),
                    fit_seconds=fit_seconds,
                )
                result.trials.append(trial)
                logger.info(
                    "%s / %s %s : R@1%%FPR %.3f, PR-AUC %.3f (%.1f s)",
                    model_name,
                    set_name,
                    params,
                    trial.metrics[SELECTION_METRIC],
                    trial.metrics[TIE_BREAK_METRIC],
                    fit_seconds,
                )
                current = result.best.get((model_name, set_name))
                if current is None or trial.key > current.key:
                    result.best[(model_name, set_name)] = trial
                    if set_name == deploy_feature_set:
                        result.estimators[model_name] = single_threaded(estimator)
                        result.validation_scores[model_name] = scores
    return result


def thresholds_from_validation(
    y_val: np.ndarray, scores: np.ndarray, targets: Mapping[str, float] = THRESHOLD_TARGETS
) -> dict[str, float]:
    """Seuils de décision donnant chaque taux de faux positifs visé sur la validation."""
    legit = scores[np.asarray(y_val) == LABEL_LEGITIMATE]
    return {name: threshold_at_fpr(legit, fpr) for name, fpr in targets.items()}


# --------------------------------------------------------------------------- #
# Coût à l'inférence
# --------------------------------------------------------------------------- #


def serialized_size(estimator: Any) -> int:
    """Taille en octets de l'estimateur sérialisé (joblib, compression 3)."""
    buffer = io.BytesIO()
    joblib.dump(estimator, buffer, compress=3)
    return buffer.getbuffer().nbytes


def measure_inference(
    model: UrlModel, urls: Sequence[str], x: pd.DataFrame, *, single_calls: int = 200
) -> dict[str, float]:
    """Temps d'inférence, avec un seul fil.

    - ``predict_us_per_url`` : estimateur seul, sur un lot de features déjà extraites ;
    - ``latency_ms_p50`` / ``latency_ms_p95`` : une URL brute à la fois, extraction des
      features comprise, comme une requête de l'API ou un clic dans l'extension.
    """
    start = time.perf_counter()
    model.score_features(x)
    batch = (time.perf_counter() - start) / len(x) * 1e6

    timings = []
    for url in list(urls)[:single_calls]:
        start = time.perf_counter()
        model.score([url])
        timings.append((time.perf_counter() - start) * 1e3)
    quantiles = statistics.quantiles(timings, n=20) if len(timings) >= 2 else timings * 19
    return {
        "predict_us_per_url": round(batch, 2),
        "latency_ms_p50": round(statistics.median(timings), 3),
        "latency_ms_p95": round(quantiles[18], 3),
        "single_calls": len(timings),
    }
