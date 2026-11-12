"""Fixtures partagées : un petit jeu d'URLs synthétique, découpé comme le vrai.

Les URLs sont fabriquées (domaines ``.example``-like inventés) : aucun test ne lit de
donnée réelle. Le jeu est volontairement bruité (phishing d'apparence propre, pages
légitimes longues) pour que les modèles fassent des erreurs à analyser.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from phishguard.data.split import temporal_group_split
from phishguard.data.urls import COLUMNS

START = pd.Timestamp("2026-01-01", tz="UTC")
_WORDS = ("alpha", "nova", "green", "pixel", "metro", "solar", "river", "lumen", "terra")


def synthetic_urls(n: int = 600, seed: int = 0) -> pd.DataFrame:
    """Jeu au schéma commun (étape 1.2), 20 % de phishing, quatre sources."""
    rng = np.random.default_rng(seed)
    rows = []
    for i in range(n):
        word = _WORDS[i % len(_WORDS)]
        kind = rng.random()
        day = int(rng.integers(0, 300))
        if kind < 0.20:
            noisy = rng.random() < 0.25  # phishing d'apparence propre
            domain = f"{word}{i}.com" if noisy else f"secure-{word}-login{i}.xyz"
            path = "/" if noisy else f"/verify/account/{rng.integers(1e6)}"
            source = "openphish" if rng.random() < 0.2 else "phishtank"
            scheme, label = "http" if rng.random() < 0.5 else "https", 1
        elif kind < 0.80:
            domain, path, scheme, label, source = f"{word}{i}.com", "/", "https", 0, "tranco"
            day = 290  # même date pour toute une collecte Tranco, comme dans le vrai jeu
        else:
            noisy = rng.random() < 0.3  # page interne longue
            domain = f"www.{word}{i}.org"
            path = f"/a/{word}/{i}?id={rng.integers(1e9)}&ref=x" if noisy else f"/blog/{word}"
            scheme, label, source = "https", 0, "commoncrawl"
        host = domain
        registered = domain.removeprefix("www.")
        rows.append(
            {
                "url": f"{scheme}://{host}{path}",
                "label": label,
                "source": source,
                "first_seen": START + pd.Timedelta(days=day, seconds=i),
                "host": host,
                "registered_domain": registered,
            }
        )
    return pd.DataFrame(rows, columns=COLUMNS).astype({"label": "int8"})


@pytest.fixture(scope="session")
def split_dataset_path(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Chemin d'un ``urls_split.parquet`` synthétique (blocs 70 / 15 / 15)."""
    df = synthetic_urls(n=900, seed=0)
    path = tmp_path_factory.mktemp("data") / "urls_split.parquet"
    df.assign(split=temporal_group_split(df)).to_parquet(path, index=False)
    return path


@pytest.fixture(autouse=True)
def _restore_logging() -> Iterator[None]:
    """Un test qui installe le journal de l'API (étape 4.6) ne le laisse pas aux suivants."""
    import logging

    import structlog

    root = logging.getLogger()
    handlers, level = list(root.handlers), root.level
    uvicorn_state = {
        name: (list(logging.getLogger(name).handlers), logging.getLogger(name).propagate)
        for name in ("uvicorn", "uvicorn.error")
    }
    yield
    root.handlers[:] = handlers
    root.setLevel(level)
    for name, (saved, propagate) in uvicorn_state.items():
        logging.getLogger(name).handlers[:] = saved
        logging.getLogger(name).propagate = propagate
    structlog.reset_defaults()


@pytest.fixture(autouse=True)
def instant_retry_sleep(monkeypatch: pytest.MonkeyPatch) -> None:
    """Les nouvelles tentatives des enrichisseurs (étape 2.8) n'attendent pas en test.

    Les tests du mécanisme lui-même injectent leur propre ``sleep`` pour mesurer les délais.
    """

    async def no_wait(_seconds: float) -> None:
        return None

    monkeypatch.setattr("phishguard.enrichers.resilience._sleep", no_wait)


@pytest.fixture(scope="session")
def api_models_dir(split_dataset_path: Path, tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Petits modèles ``url_v2`` et ``text_v2`` enregistrés pour les tests de l'API."""
    from api_support import train_models

    return train_models(split_dataset_path, tmp_path_factory.mktemp("models"))


@pytest.fixture(autouse=True)
def _isolated_api_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    """Aucun test ne lit la configuration de l'API du poste (variables PHISHGUARD_API_*)."""
    import os

    for name in [n for n in os.environ if n.startswith("PHISHGUARD_API_")]:
        monkeypatch.delenv(name)
