"""Modèles de texte pour les SMS : comparaison et artefact (étape 1.9).

Approches comparées (:data:`APPROACHES`), toutes entraînées sur le même split groupé par
gabarit (:func:`phishguard.data.sms.split_sms`) :

- TF-IDF sur les **mots** (1-2 grammes) ou sur les **caractères** (``char_wb``, 2 à 5),
  avec une régression logistique ou un SVM linéaire. Les n-grammes de caractères résistent
  mieux aux fautes volontaires (``fr3e``, ``c0mpte``) et aux langues sans espaces nets ;
- les **features smishing** seules (:mod:`phishguard.text.smishing`), référence explicable
  et indépendante de la langue d'entraînement ;
- caractères **et** features smishing ;
- en option, des **embeddings multilingues** (``sentence-transformers``), pour mesurer le
  gain face au coût (taille, latence).

Sélection : pour chaque approche, le réglage de ``C`` qui maximise la PR-AUC de
**validation** (rappel à 1 % FPR pour départager). La validation ne compte qu'environ
680 messages légitimes : 1 % FPR, c'est 7 messages, trop peu pour choisir sur ce seul
critère. Le seuil de décision rapporté est celui qui donne 1 % de faux positifs sur la
validation ; le test n'est lu qu'une fois, pour le tableau final.
"""

from __future__ import annotations

import io
import itertools
import logging
import statistics
import time
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import sklearn
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import FeatureUnion, Pipeline, make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.svm import LinearSVC

from phishguard.data.urls import LABEL_LEGITIMATE
from phishguard.evaluation.metrics import binary_report, threshold_at_fpr
from phishguard.text.smishing import SmishingFeatureExtractor

logger = logging.getLogger(__name__)

FORMAT_VERSION = 1
DEFAULT_EMBEDDING_MODEL = "sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2"
SELECTION_METRIC = "pr_auc"
TIE_BREAK_METRIC = "recall_at_fpr_1pct"
DECISION_FPR = 0.01


# --------------------------------------------------------------------------- #
# Transformateurs
# --------------------------------------------------------------------------- #


@lru_cache(maxsize=1)
def _shared_extractor() -> SmishingFeatureExtractor:
    """Extracteur partagé : la liste des raccourcisseurs n'est lue qu'une fois."""
    return SmishingFeatureExtractor()


class SmishingFeatures(BaseEstimator, TransformerMixin):
    """Adaptateur scikit-learn de :class:`SmishingFeatureExtractor` (sans état appris)."""

    def fit(self, X: Iterable[str], y: Any = None) -> SmishingFeatures:
        return self

    def transform(self, X: Iterable[str]) -> np.ndarray:
        return _shared_extractor().to_array(list(X))


class SentenceEmbedder(BaseEstimator, TransformerMixin):
    """Embeddings multilingues d'un modèle ``sentence-transformers``.

    L'encodeur est chargé à la première utilisation et **jamais sérialisé** avec le
    modèle : le fichier ``.joblib`` ne contient que son nom, et le recharger demande
    ``pip install -e '.[embeddings]'``. ``encoder_factory`` remplace le chargement (tests).
    """

    def __init__(
        self,
        model_name: str = DEFAULT_EMBEDDING_MODEL,
        batch_size: int = 64,
        encoder_factory: Callable[[str], Any] | None = None,
    ) -> None:
        self.model_name = model_name
        self.batch_size = batch_size
        self.encoder_factory = encoder_factory

    def _encoder(self) -> Any:
        if getattr(self, "_model", None) is None:
            if self.encoder_factory is not None:
                self._model = self.encoder_factory(self.model_name)
            else:
                try:
                    from sentence_transformers import SentenceTransformer
                except ImportError as exc:
                    raise ImportError(
                        "approche embeddings : pip install -e '.[embeddings]'"
                    ) from exc
                self._model = SentenceTransformer(self.model_name)
        return self._model

    def fit(self, X: Iterable[str], y: Any = None) -> SentenceEmbedder:
        self._encoder()
        return self

    def transform(self, X: Iterable[str]) -> np.ndarray:
        vectors = self._encoder().encode(
            list(X),
            batch_size=self.batch_size,
            normalize_embeddings=True,
            show_progress_bar=False,
        )
        return np.asarray(vectors, dtype=np.float32)

    def __getstate__(self) -> dict[str, Any]:
        state = self.__dict__.copy()
        state.pop("_model", None)
        return state


# --------------------------------------------------------------------------- #
# Approches
# --------------------------------------------------------------------------- #


def word_tfidf() -> TfidfVectorizer:
    return TfidfVectorizer(
        lowercase=True, strip_accents="unicode", ngram_range=(1, 2), min_df=2, sublinear_tf=True
    )


def char_tfidf() -> TfidfVectorizer:
    return TfidfVectorizer(
        lowercase=True, analyzer="char_wb", ngram_range=(2, 5), min_df=2, sublinear_tf=True
    )


def smishing_scaled() -> Pipeline:
    return make_pipeline(SmishingFeatures(), StandardScaler())


def logistic(params: Mapping[str, Any], seed: int) -> LogisticRegression:
    return LogisticRegression(
        C=params["C"], class_weight="balanced", max_iter=5000, random_state=seed
    )


def linear_svm(params: Mapping[str, Any], seed: int) -> LinearSVC:
    return LinearSVC(C=params["C"], class_weight="balanced", max_iter=20000, random_state=seed)


@dataclass(frozen=True)
class Approach:
    name: str
    label: str
    representation: Callable[[], Any]
    classifier: Callable[[Mapping[str, Any], int], Any]
    grid: tuple[dict[str, Any], ...]
    optional: bool = False

    def build(self, params: Mapping[str, Any], seed: int) -> Pipeline:
        return Pipeline(
            [("representation", self.representation()), ("clf", self.classifier(params, seed))]
        )


def _grid(**axes: Sequence[Any]) -> tuple[dict[str, Any], ...]:
    keys = list(axes)
    return tuple(dict(zip(keys, v, strict=True)) for v in itertools.product(*axes.values()))


LOGREG_GRID = _grid(C=(0.3, 1.0, 3.0, 10.0))
SVM_GRID = _grid(C=(0.03, 0.1, 0.3, 1.0))

APPROACHES: dict[str, Approach] = {
    a.name: a
    for a in (
        Approach("word_logreg", "Mots + régression logistique", word_tfidf, logistic, LOGREG_GRID),
        Approach("word_svm", "Mots + SVM linéaire", word_tfidf, linear_svm, SVM_GRID),
        Approach(
            "char_logreg", "Caractères + régression logistique", char_tfidf, logistic, LOGREG_GRID
        ),
        Approach("char_svm", "Caractères + SVM linéaire", char_tfidf, linear_svm, SVM_GRID),
        Approach(
            "smishing_logreg",
            "Features smishing + régression logistique",
            smishing_scaled,
            logistic,
            LOGREG_GRID,
        ),
        Approach(
            "char_smishing_logreg",
            "Caractères + features smishing + régression logistique",
            lambda: FeatureUnion([("char", char_tfidf()), ("smishing", smishing_scaled())]),
            logistic,
            LOGREG_GRID,
        ),
        Approach(
            "embeddings_logreg",
            "Embeddings multilingues + régression logistique",
            SentenceEmbedder,
            logistic,
            LOGREG_GRID,
            optional=True,
        ),
    )
}
DEFAULT_APPROACHES = tuple(name for name, a in APPROACHES.items() if not a.optional)
QUICK_GRID = _grid(C=(1.0,))


def scores_of(estimator: Any, texts: Iterable[str]) -> np.ndarray:
    """Score croissant avec le risque : probabilité, ou marge du SVM."""
    texts = list(texts)
    if hasattr(estimator, "predict_proba"):
        return estimator.predict_proba(texts)[:, 1]
    return np.asarray(estimator.decision_function(texts), dtype=float)


# --------------------------------------------------------------------------- #
# Recherche
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Trial:
    approach: str
    params: dict[str, Any]
    validation: dict[str, Any]
    fit_seconds: float

    @property
    def key(self) -> tuple[float, float]:
        return (self.validation[SELECTION_METRIC], self.validation[TIE_BREAK_METRIC])

    def to_dict(self) -> dict[str, Any]:
        return {
            "approach": self.approach,
            "params": self.params,
            "fit_seconds": round(self.fit_seconds, 2),
            **self.validation,
        }


@dataclass
class SearchResult:
    trials: list[Trial] = field(default_factory=list)
    best: dict[str, Trial] = field(default_factory=dict)
    estimators: dict[str, Any] = field(default_factory=dict)
    validation_scores: dict[str, np.ndarray] = field(default_factory=dict)

    def best_approach(self) -> Trial:
        return max(self.best.values(), key=lambda t: t.key)


def _validation_metrics(y: np.ndarray, scores: np.ndarray) -> dict[str, Any]:
    report = binary_report(y, scores)
    keys = ("pr_auc", "roc_auc", "recall_at_fpr_1pct", "recall_at_fpr_0_1pct")
    return {k: report[k] for k in keys}


def search(
    train: tuple[Sequence[str], np.ndarray],
    validation: tuple[Sequence[str], np.ndarray],
    *,
    approaches: Iterable[str] = DEFAULT_APPROACHES,
    grids: Mapping[str, Sequence[dict[str, Any]]] | None = None,
    seed: int = 42,
    builders: Mapping[str, Approach] | None = None,
) -> SearchResult:
    """Entraîne chaque réglage sur l'entraînement, garde le meilleur sur la validation.

    À égalité, le premier réglage de la grille l'emporte. ``builders`` remplace des
    approches (tests, encodeur factice).
    """
    registry = {**APPROACHES, **(builders or {})}
    approaches = list(approaches)
    unknown = set(approaches) - set(registry)
    if unknown:
        raise ValueError(f"approches inconnues : {sorted(unknown)}")
    grids = grids or {}
    (x_train, y_train), (x_val, y_val) = train, validation
    x_train, x_val = list(x_train), list(x_val)

    result = SearchResult()
    for name in approaches:
        approach = registry[name]
        for params in grids.get(name, approach.grid):
            start = time.perf_counter()
            estimator = approach.build(params, seed).fit(x_train, y_train)
            fit_seconds = time.perf_counter() - start
            scores = scores_of(estimator, x_val)
            trial = Trial(name, dict(params), _validation_metrics(y_val, scores), fit_seconds)
            result.trials.append(trial)
            logger.info(
                "%s %s : PR-AUC %.3f, R@1%%FPR %.3f (%.1f s)",
                name,
                params,
                trial.validation["pr_auc"],
                trial.validation["recall_at_fpr_1pct"],
                fit_seconds,
            )
            if name not in result.best or trial.key > result.best[name].key:
                result.best[name] = trial
                result.estimators[name] = estimator
                result.validation_scores[name] = scores
    return result


# --------------------------------------------------------------------------- #
# Évaluation à seuil fixé et coût
# --------------------------------------------------------------------------- #


def decision_threshold(
    y_val: np.ndarray, val_scores: np.ndarray, fpr: float = DECISION_FPR
) -> float:
    """Seuil qui donne ``fpr`` faux positifs sur la validation (règle « score > seuil »)."""
    return threshold_at_fpr(np.asarray(val_scores)[np.asarray(y_val) == LABEL_LEGITIMATE], fpr)


def evaluate_at_threshold(y: np.ndarray, scores: np.ndarray, threshold: float) -> dict[str, Any]:
    """Précision, rappel, F1 et FPR à un seuil réglé ailleurs, plus les mesures sans seuil.

    Les mesures sans seuil (PR-AUC…) demandent les deux classes ; elles valent ``None``
    sinon (sous-ensemble d'une seule langue et d'une seule classe, par exemple).
    """
    y = np.asarray(y).astype(int)
    flagged = np.asarray(scores) > threshold
    tp = int((flagged & (y == 1)).sum())
    fp = int((flagged & (y == 0)).sum())
    fn = int((~flagged & (y == 1)).sum())
    tn = int((~flagged & (y == 0)).sum())
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision is not None and recall is not None and precision + recall
        else None
    )

    def r(value: float | None) -> float | None:
        return None if value is None else round(value, 4)

    result: dict[str, Any] = {
        "n": len(y),
        "positives": int(y.sum()),
        "confusion_matrix": {"tn": tn, "fp": fp, "fn": fn, "tp": tp},
        "precision": r(precision),
        "recall": r(recall),
        "f1": r(f1),
        "fpr": r(fp / (fp + tn) if fp + tn else None),
    }
    if len(set(y.tolist())) == 2:
        result.update(_validation_metrics(y, np.asarray(scores)))
    else:
        result.update(
            dict.fromkeys(("pr_auc", "roc_auc", "recall_at_fpr_1pct", "recall_at_fpr_0_1pct"))
        )
    return result


def serialized_size(estimator: Any) -> int:
    buffer = io.BytesIO()
    joblib.dump(estimator, buffer, compress=3)
    return buffer.getbuffer().nbytes


def measure_latency(
    estimator: Any, texts: Sequence[str], *, single_calls: int = 200
) -> dict[str, float]:
    """Latence d'un message à la fois (p50, p95) et coût par message sur un lot."""
    texts = list(texts)
    start = time.perf_counter()
    scores_of(estimator, texts)
    batch = (time.perf_counter() - start) / len(texts) * 1e6
    timings = []
    for text in texts[:single_calls]:
        start = time.perf_counter()
        scores_of(estimator, [text])
        timings.append((time.perf_counter() - start) * 1e3)
    p95 = statistics.quantiles(timings, n=20)[18] if len(timings) >= 2 else timings[0]
    return {
        "batch_us_per_message": round(batch, 1),
        "latency_ms_p50": round(statistics.median(timings), 3),
        "latency_ms_p95": round(p95, 3),
        "single_calls": len(timings),
    }


def directory_size(path: Path) -> int:
    return sum(p.stat().st_size for p in Path(path).rglob("*") if p.is_file())


# --------------------------------------------------------------------------- #
# Artefact
# --------------------------------------------------------------------------- #


def library_versions() -> dict[str, str]:
    return {"scikit-learn": sklearn.__version__, "numpy": np.__version__}


@dataclass
class TextModel:
    """Modèle SMS enregistré : estimateur, seuil réglé sur la validation, métadonnées.

    Règle de décision : message signalé si son score est **strictement supérieur** au
    seuil. Sérialisé avec joblib (pickle) : ne charger que des fichiers de confiance.
    """

    estimator: Any
    approach: str
    threshold: float
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def score(self, texts: Iterable[str]) -> np.ndarray:
        return scores_of(self.estimator, texts)

    def predict(self, texts: Iterable[str]) -> np.ndarray:
        return (self.score(texts) > self.threshold).astype(int)

    def save(self, path: Path) -> Path:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "format_version": FORMAT_VERSION,
            "estimator": self.estimator,
            "approach": self.approach,
            "threshold": float(self.threshold),
            "metadata": dict(self.metadata),
            "library_versions": library_versions(),
        }
        joblib.dump(payload, path, compress=3)
        return path

    @classmethod
    def load(cls, path: Path) -> TextModel:
        """Charge un modèle. **Exécute du code (pickle)** : fichier de confiance seulement."""
        payload = joblib.load(Path(path))
        if not isinstance(payload, dict) or payload.get("format_version") != FORMAT_VERSION:
            raise ValueError(f"{path} : format de modèle non reconnu")
        for lib, version in payload.get("library_versions", {}).items():
            if library_versions().get(lib) != version:
                logger.warning("%s : enregistré avec %s %s", path, lib, version)
        return cls(
            estimator=payload["estimator"],
            approach=payload["approach"],
            threshold=payload["threshold"],
            metadata=payload["metadata"],
        )
