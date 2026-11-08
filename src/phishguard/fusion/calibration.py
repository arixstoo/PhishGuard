"""Calibration des probabilités du modèle URL (étape 2.10).

Un score de 0,9 doit vouloir dire « environ 90 % des URLs de ce score sont du
phishing ». Les modèles à base d'arbres (LightGBM, ``url_v1``) ne le garantissent pas :
leurs scores classent bien les URLs, mais ne sont pas des probabilités. La fusion
(:mod:`phishguard.fusion.score`) combine le modèle avec d'autres sources : il lui faut
de vraies probabilités.

**Méthode.** On apprend, sur la **validation**, une fonction croissante qui transforme
le score brut en probabilité :

- ``isotonic`` : régression isotone (en escalier), sans hypothèse de forme ; il lui faut
  beaucoup d'exemples (la validation en a environ 21 000) ;
- ``sigmoid`` : méthode de Platt, une sigmoïde à deux paramètres ; plus robuste avec
  peu de données, mais elle suppose une forme.

C'est ce que fait ``sklearn.calibration.CalibratedClassifierCV`` sur un estimateur déjà
entraîné, à une différence près : on calibre le **score** (une seule colonne), pas
l'estimateur. Le résultat tient dans quelques points enregistrés en JSON, sans
``pickle`` : il se relit sans exécuter de code et se porte tel quel dans l'extension
(module 5). La fonction étant croissante, le classement des URLs ne change pas.

**Prévalence.** Une probabilité calibrée dépend de la proportion de phishing des
données de calibration (20 % sur la validation, environ 1 % ou moins dans la réalité,
voir ``docs/evaluation.md``). :func:`adjust_prevalence` corrige une probabilité vers
une autre prévalence (règle de Bayes sur les cotes).
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Literal

import numpy as np
from numpy.typing import ArrayLike
from sklearn.isotonic import IsotonicRegression
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedKFold

FORMAT_VERSION = 1
Method = Literal["isotonic", "sigmoid"]
METHODS: tuple[Method, ...] = ("isotonic", "sigmoid")
_EPS = 1e-6


def _arrays(scores: ArrayLike, labels: ArrayLike) -> tuple[np.ndarray, np.ndarray]:
    s = np.asarray(scores, dtype=float).ravel()
    y = np.asarray(labels, dtype=int).ravel()
    if s.shape != y.shape or s.size == 0:
        raise ValueError("scores et labels doivent avoir la même taille, non nulle")
    if not np.isfinite(s).all():
        raise ValueError("scores non finis")
    if set(np.unique(y)) != {0, 1}:
        raise ValueError("les labels doivent contenir les deux classes (0 et 1)")
    return s, y


@dataclass(frozen=True)
class ScoreCalibrator:
    """Fonction croissante score brut → probabilité, apprise sur des données étiquetées."""

    method: Method
    # isotonic : points (x, y) de la fonction en escalier, interpolée linéairement ;
    # sigmoid : y = 1 / (1 + exp(-(a·x + b))), stocké dans ``params``.
    x: tuple[float, ...] = ()
    y: tuple[float, ...] = ()
    params: dict[str, float] = field(default_factory=dict)
    prevalence: float = 0.0  # proportion de phishing des données de calibration
    samples: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.method not in METHODS:
            raise ValueError(f"méthode inconnue : {self.method!r}")
        if self.method == "isotonic":
            if len(self.x) < 2 or len(self.x) != len(self.y):
                raise ValueError("calibration isotone : au moins deux points (x, y)")
            if any(b < a for a, b in zip(self.x, self.x[1:], strict=False)) or any(
                b < a for a, b in zip(self.y, self.y[1:], strict=False)
            ):
                raise ValueError("calibration isotone : points non croissants")
        elif set(self.params) != {"a", "b"} or self.params["a"] < 0:
            raise ValueError("calibration sigmoïde : paramètres a ≥ 0 et b requis")

    # ------------------------------------------------------------------ #

    @classmethod
    def fit(
        cls,
        scores: ArrayLike,
        labels: ArrayLike,
        *,
        method: Method = "isotonic",
        metadata: dict[str, Any] | None = None,
    ) -> ScoreCalibrator:
        s, y = _arrays(scores, labels)
        common = {"prevalence": float(y.mean()), "samples": int(s.size)}
        if method == "isotonic":
            iso = IsotonicRegression(y_min=0.0, y_max=1.0, out_of_bounds="clip").fit(s, y)
            return cls(
                "isotonic",
                x=tuple(float(v) for v in iso.X_thresholds_),
                y=tuple(float(v) for v in iso.y_thresholds_),
                metadata=metadata or {},
                **common,
            )
        if method == "sigmoid":
            lr = LogisticRegression(C=1e6).fit(s.reshape(-1, 1), y)
            a, b = float(lr.coef_[0, 0]), float(lr.intercept_[0])
            if a < 0:  # score anti-corrélé au label : on refuse plutôt que d'inverser
                raise ValueError("le score n'augmente pas avec le phishing")
            return cls("sigmoid", params={"a": a, "b": b}, metadata=metadata or {}, **common)
        raise ValueError(f"méthode inconnue : {method!r}")

    def predict(self, scores: ArrayLike) -> np.ndarray:
        s = np.asarray(scores, dtype=float)
        if self.method == "isotonic":
            out = np.interp(s, self.x, self.y)
        else:
            z = self.params["a"] * s + self.params["b"]
            out = 1.0 / (1.0 + np.exp(-np.clip(z, -500, 500)))
        return np.clip(out, 0.0, 1.0)

    def __call__(self, score: float) -> float:
        return float(self.predict([score])[0])

    # ------------------------------------------------------------------ #
    # Sérialisation JSON (jamais de pickle)
    # ------------------------------------------------------------------ #

    def to_dict(self) -> dict[str, Any]:
        return {"format_version": FORMAT_VERSION, **asdict(self)}

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> ScoreCalibrator:
        if payload.get("format_version") != FORMAT_VERSION:
            raise ValueError("format de calibration non reconnu")
        fields = {k: v for k, v in payload.items() if k != "format_version"}
        fields["x"] = tuple(fields.get("x", ()))
        fields["y"] = tuple(fields.get("y", ()))
        return cls(**fields)

    def save(self, path: Path) -> Path:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_dict(), indent=2) + "\n", encoding="utf-8")
        return path

    @classmethod
    def load(cls, path: Path) -> ScoreCalibrator:
        return cls.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))


# --------------------------------------------------------------------------- #
# Prévalence et mesure de la calibration
# --------------------------------------------------------------------------- #


def adjust_prevalence(probability: float, from_prevalence: float, to_prevalence: float) -> float:
    """Probabilité calibrée à ``from_prevalence``, ramenée à ``to_prevalence``.

    Règle de Bayes sur les cotes : ``cote' = cote × (π' / (1 − π')) / (π / (1 − π))``.
    Exemple : 0,9 calibrée sur 20 % de phishing ne vaut plus que 0,27 à 1 %.
    """
    for value in (from_prevalence, to_prevalence):
        if not 0 < value < 1:
            raise ValueError("les prévalences doivent être strictement entre 0 et 1")
    if not 0 <= probability <= 1:
        raise ValueError("probabilité hors de [0, 1]")
    if probability in (0.0, 1.0):
        return probability
    odds = probability / (1 - probability)
    ratio = (to_prevalence / (1 - to_prevalence)) / (from_prevalence / (1 - from_prevalence))
    adjusted = odds * ratio
    return adjusted / (1 + adjusted)


def calibration_report(
    probabilities: ArrayLike, labels: ArrayLike, n_bins: int = 10
) -> dict[str, Any]:
    """Score de Brier, erreur de calibration attendue (ECE) et tableau de fiabilité.

    L'ECE est l'écart moyen, pondéré par l'effectif, entre la probabilité annoncée et la
    proportion observée de phishing dans chaque tranche de probabilité : 0 pour une
    calibration parfaite.
    """
    p, y = _arrays(probabilities, labels)
    if (p < 0).any() or (p > 1).any():
        raise ValueError("probabilités hors de [0, 1]")
    edges = np.linspace(0.0, 1.0, n_bins + 1)
    index = np.clip(np.digitize(p, edges[1:-1], right=True), 0, n_bins - 1)
    bins, ece = [], 0.0
    for b in range(n_bins):
        mask = index == b
        count = int(mask.sum())
        if count == 0:
            continue
        predicted, observed = float(p[mask].mean()), float(y[mask].mean())
        ece += count / p.size * abs(predicted - observed)
        bins.append(
            {
                "lower": float(edges[b]),
                "upper": float(edges[b + 1]),
                "count": count,
                "mean_predicted": predicted,
                "observed_rate": observed,
            }
        )
    return {
        "samples": int(p.size),
        "brier": float(np.mean((p - y) ** 2)),
        "ece": float(ece),
        "log_loss": float(
            -np.mean(y * np.log(np.clip(p, _EPS, 1)) + (1 - y) * np.log(np.clip(1 - p, _EPS, 1)))
        ),
        "bins": bins,
    }


def cross_validated_probabilities(
    scores: ArrayLike, labels: ArrayLike, *, method: Method, folds: int = 5, seed: int = 0
) -> np.ndarray:
    """Probabilités « hors pli » : chaque score est calibré sans avoir servi à l'apprentissage.

    Mesurer la calibration sur les données qui l'ont apprise la flatterait (une régression
    isotone colle à ses propres données) ; et le test, lui, ne se lit qu'une fois.
    """
    s, y = _arrays(scores, labels)
    out = np.empty_like(s)
    splitter = StratifiedKFold(n_splits=folds, shuffle=True, random_state=seed)
    for fit_idx, eval_idx in splitter.split(s.reshape(-1, 1), y):
        calibrator = ScoreCalibrator.fit(s[fit_idx], y[fit_idx], method=method)
        out[eval_idx] = calibrator.predict(s[eval_idx])
    return out


def compare_methods(
    scores: ArrayLike,
    labels: ArrayLike,
    *,
    methods: Sequence[Method] = METHODS,
    folds: int = 5,
    seed: int = 0,
    n_bins: int = 10,
) -> dict[str, dict[str, Any]]:
    """Rapports de calibration du score brut et de chaque méthode, en validation croisée."""
    s, y = _arrays(scores, labels)
    reports = {"raw": calibration_report(np.clip(s, 0.0, 1.0), y, n_bins)}
    for method in methods:
        probabilities = cross_validated_probabilities(s, y, method=method, folds=folds, seed=seed)
        reports[method] = calibration_report(probabilities, y, n_bins)
    return reports


def best_method(reports: dict[str, dict[str, Any]]) -> Method:
    """Méthode au plus petit score de Brier (le score brut n'est pas une méthode)."""
    candidates = {k: v for k, v in reports.items() if k in METHODS}
    if not candidates:
        raise ValueError("aucune méthode comparée")
    best = min(candidates, key=lambda k: (candidates[k]["brier"], k))
    return best  # type: ignore[return-value]
