"""Explications SHAP du modèle URL (étape 3.1).

Pour une URL, la valeur SHAP d'une feature est sa part dans l'écart entre le score de
cette URL et le score moyen du modèle. Les parts s'additionnent exactement :

    score brut = valeur de base + somme des valeurs SHAP

Le score brut est en **log-odds** (avant la sigmoïde) : c'est l'espace dans lequel les
arbres de LightGBM s'additionnent. Une valeur SHAP positive pousse vers « phishing ».

Deux moteurs donnent les mêmes valeurs (TreeSHAP exact, vérifié par les tests) :

- **LightGBM natif** (``predict(..., pred_contrib=True)``), utilisé par défaut pour
  ``url_v1`` : aucune dépendance de plus, une dizaine de millisecondes par URL ;
- **bibliothèque** ``shap`` (``TreeExplainer``), pour les autres modèles d'arbres
  (Random Forest, dont les valeurs s'additionnent alors en probabilité). Elle est
  facultative : ``pip install -e '.[explain]'``.

Selon la version de ``shap`` et le modèle, les valeurs reviennent par classe (liste de
deux tableaux), en un tableau à trois dimensions ou en un seul tableau, avec ou sans la
valeur de base en dernière colonne. :func:`normalize_shap_values` ramène toutes ces
formes à une matrice ``(URLs, features)`` pour la classe phishing, et refuse les autres.
"""

from __future__ import annotations

import math
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Literal

import numpy as np
import pandas as pd

if TYPE_CHECKING:
    from phishguard.urls.model import UrlModel

Backend = Literal["lightgbm", "shap"]
Direction = Literal["phishing", "safe"]
# Espace dans lequel les valeurs s'additionnent : log-odds (LightGBM, boosting) ou
# probabilité (forêts scikit-learn expliquées par ``shap``).
Space = Literal["log_odds", "probability"]
SHAP_SPACE: Space = "log_odds"
DEFAULT_TOP = 3


class UnsupportedModelError(TypeError):
    """Estimateur sans moteur SHAP disponible (ni LightGBM, ni ``shap`` installé)."""


@dataclass(frozen=True)
class FeatureAttribution:
    """Une feature, sa valeur pour l'URL et sa contribution SHAP (log-odds)."""

    name: str
    value: float
    shap: float

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "value": self.value, "shap": round(self.shap, 6)}


@dataclass(frozen=True)
class UrlExplanation:
    """Explication du score d'une URL : valeur de base et contribution de chaque feature.

    ``attributions`` suit l'ordre des features du modèle ; :meth:`top` les classe.
    """

    base_value: float
    attributions: tuple[FeatureAttribution, ...]
    backend: Backend = "lightgbm"
    space: Space = SHAP_SPACE

    @property
    def raw_score(self) -> float:
        """Sortie du modèle dans ``space`` : valeur de base plus toutes les contributions."""
        return self.base_value + math.fsum(a.shap for a in self.attributions)

    @property
    def probability(self) -> float:
        """Probabilité de phishing du modèle, retrouvée à partir des contributions."""
        if self.space == "probability":
            return min(1.0, max(0.0, self.raw_score))
        return 1.0 / (1.0 + math.exp(-self.raw_score))

    def top(
        self, n: int = DEFAULT_TOP, *, direction: Direction = "phishing"
    ) -> tuple[FeatureAttribution, ...]:
        """Les ``n`` features qui ont le plus poussé vers ``direction``.

        Seules les contributions de ce signe sont gardées : une URL très sûre peut n'avoir
        aucune raison de pencher vers « phishing ». À contribution égale, l'ordre
        alphabétique départage, pour une sortie reproductible.
        """
        if n < 0:
            raise ValueError("n doit être positif ou nul")
        sign = 1.0 if direction == "phishing" else -1.0
        pushing = [a for a in self.attributions if sign * a.shap > 0]
        pushing.sort(key=lambda a: (-sign * a.shap, a.name))
        return tuple(pushing[:n])

    def by_name(self) -> dict[str, FeatureAttribution]:
        return {a.name: a for a in self.attributions}

    def to_dict(self) -> dict[str, Any]:
        return {
            "space": self.space,
            "backend": self.backend,
            "base_value": round(self.base_value, 6),
            "raw_score": round(self.raw_score, 6),
            "features": [a.to_dict() for a in self.attributions],
        }


# --------------------------------------------------------------------------- #
# Formes renvoyées par les moteurs SHAP
# --------------------------------------------------------------------------- #


def _positive_class_base(expected_value: Any) -> float:
    base = np.asarray(expected_value, dtype=float).ravel()
    if base.size == 1:
        return float(base[0])
    if base.size == 2:
        return float(base[1])
    raise ValueError(f"valeur de base inattendue : {base.size} valeurs pour un modèle binaire")


def normalize_shap_values(
    values: Any, expected_value: Any, *, n_rows: int, n_features: int
) -> tuple[np.ndarray, float]:
    """Matrice ``(n_rows, n_features)`` de la classe phishing, et sa valeur de base.

    Formes acceptées (``n`` lignes, ``f`` features) :

    - liste de deux tableaux ``(n, f)``, un par classe (anciennes versions de ``shap``) ;
    - tableau ``(n, f, 2)`` (``shap`` récent, modèles à sortie par classe) ;
    - tableau ``(n, f)`` (sortie unique, en log-odds) ;
    - tableau ``(n, f + 1)`` dont la dernière colonne est la valeur de base
      (``pred_contrib`` de LightGBM) : ``expected_value`` est alors ignoré.

    Toute autre forme lève ``ValueError`` plutôt que d'indexer au hasard.
    """
    if isinstance(values, list | tuple):
        if len(values) not in (1, 2):
            raise ValueError(f"{len(values)} tableaux SHAP pour un modèle binaire")
        values = values[-1]  # la classe phishing est la dernière
    array = np.asarray(values, dtype=float)
    if array.ndim == 3:
        if array.shape[2] != 2:
            raise ValueError(f"forme SHAP inattendue {array.shape} : 2 classes attendues")
        array = array[:, :, 1]
    if array.ndim != 2 or array.shape[0] != n_rows:
        raise ValueError(f"forme SHAP inattendue {array.shape} pour {n_rows} lignes")

    if array.shape[1] == n_features + 1:
        bases = array[:, -1]
        if bases.size and not np.allclose(bases, bases[0]):
            raise ValueError("valeur de base différente d'une ligne à l'autre")
        base = float(bases[0]) if bases.size else _positive_class_base(expected_value)
        return array[:, :-1], base
    if array.shape[1] != n_features:
        raise ValueError(f"forme SHAP inattendue {array.shape} pour {n_features} features")
    return array, _positive_class_base(expected_value)


# --------------------------------------------------------------------------- #
# Explication
# --------------------------------------------------------------------------- #


def _is_lightgbm(estimator: Any) -> bool:
    try:
        import lightgbm
    except ImportError:  # pragma: no cover - LightGBM est une dépendance du paquet
        return False
    return isinstance(estimator, lightgbm.LGBMModel)


class UrlExplainer:
    """Valeurs SHAP du modèle URL, pour une ou plusieurs URLs.

    ``backend`` force un moteur ; par défaut, LightGBM natif si l'estimateur est un
    modèle LightGBM, la bibliothèque ``shap`` sinon.
    """

    def __init__(self, model: UrlModel, *, backend: Backend | None = None) -> None:
        self.model = model
        self.feature_names: tuple[str, ...] = tuple(model.feature_names)
        estimator = model.estimator
        if backend is None:
            backend = "lightgbm" if _is_lightgbm(estimator) else "shap"
        if backend == "lightgbm" and not _is_lightgbm(estimator):
            raise UnsupportedModelError("le moteur natif ne sert que pour un modèle LightGBM")
        self.backend: Backend = backend
        self.space: Space = SHAP_SPACE
        self._tree_explainer: Any = None
        if backend == "shap":
            try:
                import shap
            except ImportError as exc:
                raise UnsupportedModelError(
                    f"{type(estimator).__name__} : pip install -e '.[explain]' pour SHAP"
                ) from exc
            try:
                self._tree_explainer = shap.TreeExplainer(estimator)
            except Exception as exc:  # shap lève des types variés selon le modèle
                raise UnsupportedModelError(
                    f"{type(estimator).__name__} : modèle non pris en charge par TreeExplainer"
                ) from exc
            output = getattr(self._tree_explainer.model, "tree_output", None)
            if output not in ("log_odds", "probability"):
                raise UnsupportedModelError(f"sortie d'arbres non prise en charge : {output!r}")
            self.space = output

    def shap_values(self, x: pd.DataFrame) -> tuple[np.ndarray, float]:
        """Valeurs SHAP ``(URLs, features)`` et valeur de base, pour des features extraites."""
        x = x[list(self.feature_names)]
        if self.backend == "lightgbm":
            raw: Any = self.model.estimator.predict(x, pred_contrib=True)
            expected: Any = None
        else:
            raw = self._tree_explainer.shap_values(x)
            expected = self._tree_explainer.expected_value
        return normalize_shap_values(
            raw, expected, n_rows=len(x), n_features=len(self.feature_names)
        )

    def explain_features(self, x: pd.DataFrame) -> list[UrlExplanation]:
        """Une explication par ligne de ``x`` (features déjà extraites)."""
        values, base = self.shap_values(x)
        frame = x[list(self.feature_names)].to_numpy(dtype=float)
        return [
            UrlExplanation(
                base_value=base,
                attributions=tuple(
                    FeatureAttribution(name, float(value), float(contribution))
                    for name, value, contribution in zip(
                        self.feature_names, row_values, row_shap, strict=True
                    )
                ),
                backend=self.backend,
                space=self.space,
            )
            for row_values, row_shap in zip(frame, values, strict=True)
        ]

    def explain(self, urls: Iterable[str]) -> list[UrlExplanation]:
        """Explications d'URLs brutes (lève ``InvalidUrlError`` si l'une est invalide)."""
        return self.explain_features(self.model.features(urls))

    def explain_one(self, url: str) -> UrlExplanation:
        return self.explain([url])[0]


def global_importance(values: np.ndarray, feature_names: Sequence[str]) -> list[tuple[str, float]]:
    """Importance globale : moyenne de la valeur absolue SHAP, de la plus forte à la plus
    faible (ordre alphabétique à égalité)."""
    values = np.asarray(values, dtype=float)
    if values.ndim != 2 or values.shape[1] != len(feature_names):
        raise ValueError(f"forme {values.shape} pour {len(feature_names)} features")
    means = np.abs(values).mean(axis=0) if len(values) else np.zeros(len(feature_names))
    ranked = sorted(zip(feature_names, means.tolist(), strict=True), key=lambda t: (-t[1], t[0]))
    return [(name, float(mean)) for name, mean in ranked]
