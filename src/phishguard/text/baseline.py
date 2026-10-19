"""Baseline SMS : TF-IDF + régression logistique, évalué honnêtement.

Deux protocoles sont comparés :

- ``naive`` : split aléatoire sur le corpus brut, comme dans le projet d'origine.
  Les messages en double peuvent tomber à la fois dans l'entraînement et le test.
- ``deduplicated`` : dédoublonnage *avant* le split. C'est le protocole de référence.

L'écart entre les deux mesure l'effet de la fuite de données.
"""

from __future__ import annotations

from dataclasses import dataclass

import pandas as pd
import sklearn
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

from phishguard.data.sms import deduplicate
from phishguard.evaluation.metrics import binary_report

MODEL_NAME = "sms-baseline-tfidf-logreg"


@dataclass(frozen=True)
class BaselineConfig:
    test_size: float = 0.2
    seed: int = 42
    threshold: float = 0.5


def build_pipeline(seed: int = 42) -> Pipeline:
    return Pipeline(
        [
            ("tfidf", TfidfVectorizer(lowercase=True, sublinear_tf=True, min_df=2)),
            (
                "clf",
                LogisticRegression(max_iter=1000, class_weight="balanced", random_state=seed),
            ),
        ]
    )


def _split(df: pd.DataFrame, cfg: BaselineConfig):
    return train_test_split(
        df["text"],
        df["label"],
        test_size=cfg.test_size,
        stratify=df["label"],
        random_state=cfg.seed,
    )


def _overlap(train_texts: pd.Series, test_texts: pd.Series) -> int:
    """Nombre de messages du test déjà présents (au mot près) dans l'entraînement."""
    seen = set(train_texts.str.strip())
    return int(test_texts.str.strip().isin(seen).sum())


def _evaluate(df: pd.DataFrame, cfg: BaselineConfig) -> tuple[Pipeline, dict, dict]:
    x_tr, x_te, y_tr, y_te = _split(df, cfg)
    model = build_pipeline(cfg.seed).fit(x_tr, y_tr)
    scores = model.predict_proba(x_te)[:, 1]

    report = binary_report(y_te, scores, threshold=cfg.threshold)
    report["n_train"] = len(x_tr)
    report["n_test"] = len(x_te)
    report["test_messages_seen_in_train"] = _overlap(x_tr, x_te)

    # Pires erreurs, à relire à la main. Elles contiennent le texte brut des messages :
    # elles ne vont jamais dans les métriques versionnées.
    errors = pd.DataFrame({"text": x_te, "label": y_te, "score": scores.round(4)})
    pred = errors["score"] >= cfg.threshold
    worst = {
        "false_positives": errors[pred & (errors["label"] == 0)]
        .sort_values("score", ascending=False)
        .head(20)[["score", "text"]]
        .to_dict("records"),
        "false_negatives": errors[~pred & (errors["label"] == 1)]
        .sort_values("score")
        .head(20)[["score", "text"]]
        .to_dict("records"),
    }
    return model, report, worst


def train_and_evaluate(
    raw: pd.DataFrame, cfg: BaselineConfig | None = None
) -> tuple[Pipeline, dict, dict]:
    """Entraîne le baseline et renvoie ``(modèle, métriques, pires erreurs)``.

    Le modèle et les erreurs sont ceux du protocole ``deduplicated`` (la référence).
    """
    cfg = cfg or BaselineConfig()
    _, naive, _ = _evaluate(raw, cfg)

    clean, dedup_stats = deduplicate(raw)
    model, reference, errors = _evaluate(clean, cfg)

    metrics = {
        "model": MODEL_NAME,
        "config": {"test_size": cfg.test_size, "seed": cfg.seed, "threshold": cfg.threshold},
        "versions": {"scikit-learn": sklearn.__version__, "pandas": pd.__version__},
        "dataset": {
            "rows": len(raw),
            "spam_ratio": round(float(raw["label"].mean()), 4),
            "deduplication": dedup_stats,
        },
        "protocols": {"naive": naive, "deduplicated": reference},
    }
    return model, metrics, errors
