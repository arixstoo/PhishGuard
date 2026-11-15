"""Outils communs aux tests de l'API (module 4).

De petits modèles entraînés ici, enregistrés sous les noms des modèles déployés
(``url_v2``, ``text_v2``) : l'API les charge par le vrai chemin de démarrage
(:func:`phishguard.deployment.load_analyzers`), sans aucun fichier réel ni réseau.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import lightgbm as lgb
import numpy as np
from fastapi.testclient import TestClient
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import Pipeline
from sklearn.svm import LinearSVC

from phishguard.api.main import create_app
from phishguard.api.settings import ApiSettings
from phishguard.data.split import read_split_blocks
from phishguard.security.normalize import TextNormalizer
from phishguard.text.models import TextModel
from phishguard.urls.features import feature_names
from phishguard.urls.model import UrlModel

ROOT = Path(__file__).resolve().parents[1]
EMAILS = ROOT / "tests/fixtures/emails"
COLUMNS = feature_names(families=("base", "brand", "homograph", "shortener"))


def train_models(split_dataset_path: Path, models_dir: Path) -> Path:
    """Entraîne et enregistre ``url_v2`` et ``text_v2`` dans ``models_dir``."""
    data = read_split_blocks(split_dataset_path, ("train",), ["url", "label"])["train"]
    estimator = lgb.LGBMClassifier(n_estimators=30, num_leaves=15, verbose=-1, random_state=0)
    url_model = UrlModel(
        estimator,
        COLUMNS,
        thresholds={"fpr_1pct": 0.6, "fpr_0_5pct": 0.8, "fpr_0_1pct": 0.9},
        metadata={"model_version": "url_v2", "trained_at": "2026-11-01T00:00:00+00:00"},
    )
    estimator.fit(url_model.features(data["url"]), data["label"])

    texts = [
        "urgent your account is locked verify now http://verify.example",
        "you won a free prize claim it at prize.example",
        "see you at the station tonight",
        "thanks for the lovely dinner",
    ] * 10
    pipeline = Pipeline(
        [
            (
                "representation",
                TfidfVectorizer(
                    preprocessor=TextNormalizer(lowercase=True),
                    analyzer="char_wb",
                    ngram_range=(2, 4),
                ),
            ),
            ("clf", LinearSVC(random_state=0)),
        ]
    ).fit(texts, np.array([1, 1, 0, 0] * 10))
    text_model = TextModel(
        pipeline, "char_svm", threshold=-0.25, metadata={"model_version": "text_v2"}
    )

    models_dir.mkdir(parents=True, exist_ok=True)
    url_model.save(models_dir / "url_v2.joblib")
    text_model.save(models_dir / "text_v2.joblib")
    return models_dir


def settings_for(models_dir: Path, tmp_path: Path, **overrides: object) -> ApiSettings:
    """Configuration de test : modèles et base dans des dossiers temporaires, aucun .env."""
    values: dict[str, object] = {
        "models_dir": models_dir,
        "database_path": tmp_path / "api.sqlite3",
        **overrides,
    }
    return ApiSettings(_env_file=None, **values)


@contextmanager
def api_client(settings: ApiSettings, **client_options: object) -> Iterator[TestClient]:
    """Client de test, lifespan compris (chargement des modèles au démarrage)."""
    with TestClient(create_app(settings), **client_options) as client:
        yield client
