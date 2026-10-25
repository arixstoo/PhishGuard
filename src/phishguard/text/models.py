"""Étape 1.9 : comparer plusieurs modèles de texte pour les SMS.

Protocole (le même pour toutes les approches) :

1. dédoublonnage du corpus *avant* tout split (voir ``phishguard.data.sms.deduplicate``) ;
2. split stratifié entraînement / validation / test (60 / 20 / 20) ;
3. l'hyperparamètre ``C`` est choisi sur la **validation** (critère : PR-AUC), jamais sur
   le test ;
4. le modèle retenu est réentraîné sur entraînement + validation, puis évalué une seule
   fois sur le test.

Pour chaque approche on rapporte la qualité (précision, rappel, F1, PR-AUC, rappel à 1 %
de faux positifs), la taille du modèle sérialisé et la latence par message.
Un jeu externe (par exemple le petit jeu français / arabe) peut être évalué en plus :
il mesure la capacité à généraliser hors de la langue d'entraînement.
"""

from __future__ import annotations

import io
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import FeatureUnion, Pipeline
from sklearn.svm import LinearSVC

from phishguard.data.sms import deduplicate
from phishguard.evaluation.metrics import binary_report
from phishguard.text.smishing import SmishingFeatures

C_GRID: tuple[float, ...] = (0.1, 1.0, 10.0)


@dataclass(frozen=True)
class TextConfig:
    val_size: float = 0.2
    test_size: float = 0.2
    seed: int = 42
    c_grid: tuple[float, ...] = C_GRID
    latency_samples: int = 200


@dataclass(frozen=True)
class Approach:
    """Une approche = une fabrique de pipeline paramétrée par ``C``.

    ``threshold`` est le seuil de décision sur le score renvoyé par :func:`scores` :
    0,5 pour une probabilité (régression logistique), 0 pour une marge (``LinearSVC``).
    """

    name: str
    description: str
    build: Callable[[float, int], Pipeline]
    threshold: float
    extra: dict = field(default_factory=dict)


def _word_tfidf() -> TfidfVectorizer:
    return TfidfVectorizer(lowercase=True, sublinear_tf=True, min_df=2)


def _char_tfidf() -> TfidfVectorizer:
    # char_wb : n-grammes à l'intérieur des mots, robustes aux fautes et aux variantes
    # (« fr33 », « c1ick ») et indépendants de la langue.
    return TfidfVectorizer(
        analyzer="char_wb", ngram_range=(2, 5), lowercase=True, sublinear_tf=True, min_df=2
    )


def _logreg(c: float, seed: int) -> LogisticRegression:
    return LogisticRegression(C=c, max_iter=2000, class_weight="balanced", random_state=seed)


def _svc(c: float, seed: int) -> LinearSVC:
    return LinearSVC(C=c, class_weight="balanced", random_state=seed)


def default_approaches() -> list[Approach]:
    return [
        Approach(
            "word_logreg",
            "TF-IDF mots + régression logistique (baseline de l'étape 0.7)",
            lambda c, s: Pipeline([("tfidf", _word_tfidf()), ("clf", _logreg(c, s))]),
            0.5,
        ),
        Approach(
            "word_svc",
            "TF-IDF mots + LinearSVC",
            lambda c, s: Pipeline([("tfidf", _word_tfidf()), ("clf", _svc(c, s))]),
            0.0,
        ),
        Approach(
            "char_logreg",
            "TF-IDF caractères (char_wb 2-5) + régression logistique",
            lambda c, s: Pipeline([("tfidf", _char_tfidf()), ("clf", _logreg(c, s))]),
            0.5,
        ),
        Approach(
            "char_svc",
            "TF-IDF caractères (char_wb 2-5) + LinearSVC",
            lambda c, s: Pipeline([("tfidf", _char_tfidf()), ("clf", _svc(c, s))]),
            0.0,
        ),
        Approach(
            "char_smishing_logreg",
            "TF-IDF caractères + features smishing + régression logistique",
            lambda c, s: Pipeline(
                [
                    (
                        "features",
                        FeatureUnion([("tfidf", _char_tfidf()), ("smishing", SmishingFeatures())]),
                    ),
                    ("clf", _logreg(c, s)),
                ]
            ),
            0.5,
        ),
    ]


class SentenceEmbedder(BaseEstimator, TransformerMixin):
    """Transformeur scikit-learn autour d'un modèle ``sentence-transformers``.

    ``encoder`` peut être injecté (tests) ; sinon le modèle ``model_name`` est chargé à la
    première utilisation. Le modèle n'est pas sérialisé avec le pipeline : il est rechargé.
    """

    def __init__(self, model_name: str = "paraphrase-multilingual-MiniLM-L12-v2", encoder=None):
        self.model_name = model_name
        self.encoder = encoder

    def _get_encoder(self):
        if self.encoder is None:
            from sentence_transformers import SentenceTransformer  # dépendance optionnelle

            self.encoder = SentenceTransformer(self.model_name, device="cpu")
        return self.encoder

    def fit(self, X, y=None):
        return self

    def transform(self, X):
        vectors = self._get_encoder().encode(
            list(X), batch_size=64, show_progress_bar=False, normalize_embeddings=True
        )
        return np.asarray(vectors, dtype=float)

    def __getstate__(self):
        state = self.__dict__.copy()
        state["encoder"] = None  # ne jamais embarquer le réseau dans le .joblib
        return state


def embedding_approach(encoder=None, model_name: str | None = None) -> Approach:
    name = model_name or "paraphrase-multilingual-MiniLM-L12-v2"
    return Approach(
        "embeddings_logreg",
        f"embeddings multilingues ({name}) + régression logistique",
        lambda c, s: Pipeline([("embed", SentenceEmbedder(name, encoder)), ("clf", _logreg(c, s))]),
        0.5,
        extra={"encoder_model": name},
    )


def scores(model: Pipeline, texts: Sequence[str]) -> np.ndarray:
    """Score croissant avec le risque : probabilité si disponible, sinon marge."""
    if hasattr(model, "predict_proba"):
        return model.predict_proba(texts)[:, 1]
    return model.decision_function(texts)


def serialized_size(model: Pipeline) -> int:
    buf = io.BytesIO()
    joblib.dump(model, buf)
    return buf.getbuffer().nbytes


def latency_ms(model: Pipeline, texts: Sequence[str]) -> dict[str, float]:
    """Latence d'un message traité seul (cas de l'extension), médiane et p95, en ms."""
    timings = []
    for text in texts:
        start = time.perf_counter()
        scores(model, [text])
        timings.append((time.perf_counter() - start) * 1000)
    return {
        "p50": round(float(np.median(timings)), 3),
        "p95": round(float(np.percentile(timings, 95)), 3),
    }


def split_three_ways(df: pd.DataFrame, cfg: TextConfig):
    rest, test = train_test_split(
        df, test_size=cfg.test_size, stratify=df["label"], random_state=cfg.seed
    )
    val_share = cfg.val_size / (1 - cfg.test_size)
    train, val = train_test_split(
        rest, test_size=val_share, stratify=rest["label"], random_state=cfg.seed
    )
    return train, val, test


def _select_c(approach: Approach, train: pd.DataFrame, val: pd.DataFrame, cfg: TextConfig):
    by_c = {}
    for c in cfg.c_grid:
        model = approach.build(c, cfg.seed).fit(train["text"], train["label"])
        by_c[c] = float(average_precision_score(val["label"], scores(model, val["text"])))
    best = max(by_c, key=lambda c: (by_c[c], -c))  # à égalité, le modèle le plus régularisé
    return best, {str(c): round(v, 4) for c, v in by_c.items()}


def evaluate_approach(
    approach: Approach,
    train: pd.DataFrame,
    val: pd.DataFrame,
    test: pd.DataFrame,
    cfg: TextConfig,
    external: pd.DataFrame | None = None,
) -> tuple[Pipeline, dict]:
    best_c, val_pr_auc = _select_c(approach, train, val, cfg)
    full = pd.concat([train, val])
    model = approach.build(best_c, cfg.seed).fit(full["text"], full["label"])

    report = binary_report(test["label"], scores(model, test["text"]), threshold=approach.threshold)
    sample = (
        test["text"].sample(n=min(cfg.latency_samples, len(test)), random_state=cfg.seed).tolist()
    )
    result = {
        "description": approach.description,
        "selected_C": best_c,
        "validation_pr_auc_by_C": val_pr_auc,
        "test": report,
        "model_size_bytes": serialized_size(model),
        "latency_ms_per_message": latency_ms(model, sample),
        **approach.extra,
    }
    if external is not None and external["label"].nunique() == 2:
        result["external"] = binary_report(
            external["label"], scores(model, external["text"]), threshold=approach.threshold
        )
    return model, result


def compare(
    raw: pd.DataFrame,
    cfg: TextConfig | None = None,
    approaches: Sequence[Approach] | None = None,
    external: pd.DataFrame | None = None,
) -> tuple[dict[str, Pipeline], dict]:
    """Entraîne et compare toutes les approches. Renvoie ``(modèles, métriques)``.

    Les métriques ne contiennent aucun texte de message : elles sont versionnées.
    """
    cfg = cfg or TextConfig()
    approaches = list(approaches) if approaches is not None else default_approaches()
    clean, dedup_stats = deduplicate(raw)
    train, val, test = split_three_ways(clean, cfg)

    models, results = {}, {}
    for approach in approaches:
        models[approach.name], results[approach.name] = evaluate_approach(
            approach, train, val, test, cfg, external
        )

    metrics = {
        "config": {
            "val_size": cfg.val_size,
            "test_size": cfg.test_size,
            "seed": cfg.seed,
            "c_grid": list(cfg.c_grid),
            "selection_metric": "validation PR-AUC",
        },
        "versions": {"scikit-learn": sklearn.__version__, "pandas": pd.__version__},
        "dataset": {
            "rows": len(raw),
            "spam_ratio": round(float(raw["label"].mean()), 4),
            "deduplication": dedup_stats,
            "n_train": len(train),
            "n_val": len(val),
            "n_test": len(test),
        },
        "approaches": results,
    }
    if external is not None:
        metrics["external_dataset"] = {
            "rows": len(external),
            "positives": int(external["label"].sum()),
            "languages": external["lang"].value_counts().to_dict() if "lang" in external else {},
        }
    return models, metrics


def markdown_table(metrics: dict) -> str:
    """Tableau comparatif prêt à coller dans la documentation."""
    has_ext = any("external" in r for r in metrics["approaches"].values())
    head = (
        "| approche | précision | rappel | F1 | PR-AUC | R@1%FPR | taille (Ko) | latence p50 (ms) |"
    )
    sep = "|---|---:|---:|---:|---:|---:|---:|---:|"
    if has_ext:
        head += " F1 FR/AR | R@1%FPR FR/AR |"
        sep += "---:|---:|"
    lines = [head, sep]
    for name, r in metrics["approaches"].items():
        t = r["test"]
        line = (
            f"| `{name}` | {t['precision']:.3f} | {t['recall']:.3f} | {t['f1']:.3f} "
            f"| {t['pr_auc']:.3f} | {t['recall_at_fpr_1pct']:.3f} "
            f"| {r['model_size_bytes'] / 1024:.0f} | {r['latency_ms_per_message']['p50']:.2f} |"
        )
        if has_ext:
            e = r.get("external")
            line += f" {e['f1']:.3f} | {e['recall_at_fpr_1pct']:.3f} |" if e else " – | – |"
        lines.append(line)
    return "\n".join(lines)
