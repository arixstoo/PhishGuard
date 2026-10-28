"""Score email appris, comparé aux règles (étape 1.11).

Le jeu est découpé en 70 / 15 / 15, stratifié par classe et **groupé par domaine
d'expéditeur** (:func:`sender_group`) : une campagne envoyée depuis un même domaine ne
peut pas être apprise à l'entraînement et « reconnue » au test.

Approches comparées :

- **règles** (:mod:`phishguard.email.score`) : aucun apprentissage, le score est la somme
  des points ;
- **régression logistique** standardisée, explicable poids par poids ;
- **LightGBM**, petit (au plus 31 feuilles).

Chaque modèle est entraîné sur plusieurs jeux de features (:func:`feature_sets`) : tous
les groupes, puis sans le groupe ``auth``, exposé au biais d'époque des corpus (voir
:mod:`phishguard.email.score`), et, si un modèle URL est fourni, avec ses features.
Le réglage se fait sur la PR-AUC de **validation** ; le seuil d'un modèle est celui qui
donne 1 % de faux positifs sur la validation ; le test n'est lu qu'une fois.
"""

from __future__ import annotations

import itertools
import logging
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import joblib
import lightgbm as lgb
import numpy as np
import pandas as pd
import sklearn
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

from phishguard.email.parser import ParsedEmail
from phishguard.email.score import (
    URL_MODEL_FEATURES,
    feature_names,
    rule_score,
)
from phishguard.evaluation.metrics import binary_report, threshold_at_fpr

logger = logging.getLogger(__name__)

FORMAT_VERSION = 1
SELECTION_METRIC = "pr_auc"
TIE_BREAK_METRIC = "recall_at_fpr_1pct"
DECISION_FPR = 0.01
RULES = "rules"


def sender_group(email: ParsedEmail, raw_sha256: str) -> str:
    """Domaine enregistré de l'expéditeur, ou l'empreinte de l'email s'il est illisible.

    Un email sans expéditeur lisible forme son propre groupe : on ne regroupe pas tous
    les inconnus ensemble, ce qui créerait un groupe géant dans un seul bloc.
    """
    sender = email.from_
    if sender is not None and sender.registered_domain:
        return sender.registered_domain
    return f"sha256:{raw_sha256}"


# Features dont la valeur dépend surtout de l'époque des corpus : SpamAssassin (2002)
# n'a presque pas de HTML (5 %), le phishing récent presque toujours (98 %). Seule,
# has_html sépare les deux corpus (AUC 0,97) : un modèle qui la garde apprend
# « HTML = phishing » et signale une newsletter légitime d'aujourd'hui.
ERA_BIASED_FEATURES = ("has_html",)
DEPLOYED_FEATURE_SET = "robust"


def cap_per_group(
    frame: pd.DataFrame, max_per_group: int, *, group: str = "group", order: str = "sha256"
) -> tuple[pd.DataFrame, int]:
    """Garde au plus ``max_per_group`` lignes par groupe (``0`` : pas de limite).

    Un expéditeur en masse pèse sinon plus que tous les autres : dans SpamAssassin, une
    seule passerelle RSS (``rssfeeds@spamassassin.taint.org``) envoie 623 résumés presque
    identiques. Groupée, elle tombe en entier dans un bloc et en fait les deux tiers. Les
    lignes gardées sont les premières par ``order`` (l'empreinte : choix déterministe et
    sans lien avec le contenu). Retourne le jeu réduit et le nombre de lignes retirées.
    """
    if max_per_group <= 0:
        return frame, 0
    ordered = frame.sort_values(order, kind="stable")
    kept = ordered[ordered.groupby(group).cumcount() < max_per_group]
    kept = kept.sort_index()
    return kept.reset_index(drop=True), len(frame) - len(kept)


def feature_sets(with_url_model: bool) -> dict[str, tuple[str, ...]]:
    """Jeux de features comparés.

    ``all`` : tout ; ``without_auth`` : sans le groupe auth ; ``robust`` : sans le groupe
    auth ni :data:`ERA_BIASED_FEATURES`, le jeu déployé. Avec un modèle URL, chaque jeu a
    aussi sa variante ``…_with_url_model``.
    """
    without_auth = feature_names(exclude_groups=("auth",))
    sets = {
        "all": feature_names(),
        "without_auth": without_auth,
        "robust": tuple(n for n in without_auth if n not in ERA_BIASED_FEATURES),
    }
    if with_url_model:
        for name in list(sets):
            sets[f"{name}_with_url_model"] = sets[name] + URL_MODEL_FEATURES
    return sets


def _grid(**axes: Sequence[Any]) -> tuple[dict[str, Any], ...]:
    keys = list(axes)
    return tuple(dict(zip(keys, v, strict=True)) for v in itertools.product(*axes.values()))


@dataclass(frozen=True)
class ModelSpec:
    name: str
    label: str
    grid: tuple[dict[str, Any], ...]

    def build(self, params: Mapping[str, Any], seed: int) -> Any:
        if self.name == "logistic_regression":
            return make_pipeline(
                StandardScaler(),
                LogisticRegression(
                    C=params["C"], class_weight="balanced", max_iter=5000, random_state=seed
                ),
            )
        if self.name == "lightgbm":
            return lgb.LGBMClassifier(
                **params,
                class_weight="balanced",
                random_state=seed,
                deterministic=True,
                force_col_wise=True,
                n_jobs=1,
                verbose=-1,
            )
        raise ValueError(f"modèle inconnu : {self.name}")


MODEL_SPECS: dict[str, ModelSpec] = {
    spec.name: spec
    for spec in (
        ModelSpec("logistic_regression", "Régression logistique", _grid(C=(0.1, 1.0, 10.0))),
        ModelSpec(
            "lightgbm",
            "LightGBM",
            _grid(n_estimators=(100, 300), num_leaves=(7, 31), learning_rate=(0.05,)),
        ),
    )
}
QUICK_GRIDS = {
    "logistic_regression": _grid(C=(1.0,)),
    "lightgbm": _grid(n_estimators=(50,), num_leaves=(7,), learning_rate=(0.1,)),
}


# --------------------------------------------------------------------------- #
# Mesures
# --------------------------------------------------------------------------- #

_THRESHOLD_FREE = ("pr_auc", "roc_auc", "recall_at_fpr_1pct", "recall_at_fpr_0_1pct")


def ranking_metrics(y: np.ndarray, scores: np.ndarray) -> dict[str, Any]:
    report = binary_report(y, scores)
    return {k: report[k] for k in _THRESHOLD_FREE}


def at_threshold(y: np.ndarray, scores: np.ndarray, threshold: float) -> dict[str, Any]:
    """Rappel, FPR et précision quand on signale ``score > threshold``."""
    y = np.asarray(y).astype(int)
    flagged = np.asarray(scores) > threshold
    tp, fp = int((flagged & (y == 1)).sum()), int((flagged & (y == 0)).sum())
    positives, negatives = int((y == 1).sum()), int((y == 0).sum())
    return {
        "threshold": float(threshold),
        "recall": round(tp / positives, 4) if positives else None,
        "fpr": round(fp / negatives, 4) if negatives else None,
        "precision": round(tp / (tp + fp), 4) if tp + fp else None,
        "flagged": int(flagged.sum()),
    }


def rule_scores(features: pd.DataFrame) -> np.ndarray:
    """Score des règles (0 à 100) de chaque ligne de features."""
    return np.array([rule_score(row).score for row in features.to_dict("records")], dtype=float)


# --------------------------------------------------------------------------- #
# Recherche
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Trial:
    model: str
    feature_set: str
    params: dict[str, Any]
    validation: dict[str, Any]

    @property
    def key(self) -> tuple[float, float]:
        return (self.validation[SELECTION_METRIC], self.validation[TIE_BREAK_METRIC])

    def to_dict(self) -> dict[str, Any]:
        return {
            "model": self.model,
            "feature_set": self.feature_set,
            "params": self.params,
            **self.validation,
        }


@dataclass
class SearchResult:
    trials: list[Trial] = field(default_factory=list)
    best: dict[tuple[str, str], Trial] = field(default_factory=dict)
    estimators: dict[tuple[str, str], Any] = field(default_factory=dict)

    def best_overall(self) -> Trial:
        return max(self.best.values(), key=lambda t: t.key)


def search(
    x_train: pd.DataFrame,
    y_train: np.ndarray,
    x_val: pd.DataFrame,
    y_val: np.ndarray,
    sets: Mapping[str, Sequence[str]],
    *,
    models: Iterable[str] = tuple(MODEL_SPECS),
    grids: Mapping[str, Sequence[dict[str, Any]]] | None = None,
    seed: int = 42,
) -> SearchResult:
    """Entraîne chaque modèle × jeu × réglage, garde le meilleur sur la validation."""
    grids = grids or {}
    result = SearchResult()
    for model_name in models:
        spec = MODEL_SPECS[model_name]
        for set_name, columns in sets.items():
            columns = list(columns)
            for params in grids.get(model_name, spec.grid):
                estimator = spec.build(params, seed).fit(x_train[columns], y_train)
                scores = estimator.predict_proba(x_val[columns])[:, 1]
                trial = Trial(model_name, set_name, dict(params), ranking_metrics(y_val, scores))
                result.trials.append(trial)
                key = (model_name, set_name)
                if key not in result.best or trial.key > result.best[key].key:
                    result.best[key] = trial
                    result.estimators[key] = estimator
    return result


def decision_threshold(y_val: np.ndarray, val_scores: np.ndarray) -> float:
    return threshold_at_fpr(np.asarray(val_scores)[np.asarray(y_val) == 0], DECISION_FPR)


# --------------------------------------------------------------------------- #
# Artefact
# --------------------------------------------------------------------------- #


def library_versions() -> dict[str, str]:
    return {"scikit-learn": sklearn.__version__, "lightgbm": lgb.__version__}


@dataclass
class EmailModel:
    """Score email appris : estimateur, features attendues, seuil réglé sur la validation.

    Si ``uses_url_model`` est vrai, les features du modèle URL doivent être calculées avec
    le modèle dont l'empreinte est ``metadata["url_model_sha256"]``. Fichier pickle :
    ne charger que des fichiers de confiance.
    """

    estimator: Any
    feature_names: tuple[str, ...]
    threshold: float
    metadata: Mapping[str, Any] = field(default_factory=dict)

    @property
    def uses_url_model(self) -> bool:
        return any(name in URL_MODEL_FEATURES for name in self.feature_names)

    def score_features(self, features: pd.DataFrame) -> np.ndarray:
        missing = set(self.feature_names) - set(features.columns)
        if missing:
            raise ValueError(f"features absentes : {sorted(missing)}")
        return self.estimator.predict_proba(features[list(self.feature_names)])[:, 1]

    def save(self, path: Path) -> Path:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(
            {
                "format_version": FORMAT_VERSION,
                "estimator": self.estimator,
                "feature_names": list(self.feature_names),
                "threshold": float(self.threshold),
                "metadata": dict(self.metadata),
                "library_versions": library_versions(),
            },
            path,
            compress=3,
        )
        return path

    @classmethod
    def load(cls, path: Path) -> EmailModel:
        """Charge un modèle. **Exécute du code (pickle)** : fichier de confiance seulement."""
        payload = joblib.load(Path(path))
        if not isinstance(payload, dict) or payload.get("format_version") != FORMAT_VERSION:
            raise ValueError(f"{path} : format de modèle non reconnu")
        for lib, version in payload.get("library_versions", {}).items():
            if library_versions().get(lib) != version:
                logger.warning("%s : enregistré avec %s %s", path, lib, version)
        return cls(
            estimator=payload["estimator"],
            feature_names=tuple(payload["feature_names"]),
            threshold=payload["threshold"],
            metadata=payload["metadata"],
        )
