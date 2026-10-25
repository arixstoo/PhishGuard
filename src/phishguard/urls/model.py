"""Modèle URL prêt à l'emploi : de l'URL brute au score (étape 1.6).

Un :class:`UrlModel` réunit tout ce qu'il faut pour scorer une URL de la même façon
qu'à l'entraînement :

- l'estimateur scikit-learn ou LightGBM entraîné ;
- la liste ordonnée des features qu'il attend (un sous-ensemble de
  :data:`phishguard.urls.features.FEATURES`) ;
- la table des TLD apprise sur l'entraînement, si la feature ``tld_phish_rate`` est
  utilisée ;
- les seuils de décision réglés sur la validation (clé ``fpr_1pct`` : seuil qui donne
  1 % de faux positifs sur le légitime de validation) ;
- des métadonnées (modèle, hyperparamètres, empreinte du jeu, versions).

Règle de décision : une URL est signalée si son score est **strictement supérieur** au
seuil (voir :func:`phishguard.evaluation.metrics.threshold_at_fpr`).

**Sécurité.** Le fichier est sérialisé avec ``joblib``, donc ``pickle`` : le charger
exécute du code. Ne chargez que des fichiers produits par ``scripts/train_url.py`` sur
votre machine. La distribution signée des modèles arrive à l'étape 4.12.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import joblib
import lightgbm
import numpy as np
import pandas as pd
import sklearn

from phishguard.urls.features import FEATURE_NAMES, UrlFeatureExtractor, feature_spec
from phishguard.urls.tld import TldRiskTable

logger = logging.getLogger(__name__)

FORMAT_VERSION = 1
DEFAULT_THRESHOLD = "fpr_1pct"


def library_versions() -> dict[str, str]:
    """Versions des bibliothèques dont dépend la désérialisation de l'estimateur."""
    return {
        "scikit-learn": sklearn.__version__,
        "lightgbm": lightgbm.__version__,
        "numpy": np.__version__,
    }


def _exact_table(table: TldRiskTable) -> dict[str, Any]:
    return {
        "prior": table.prior,
        "smoothing": table.smoothing,
        "rates": dict(table.rates),
        "support": dict(table.support),
    }


@dataclass
class UrlModel:
    estimator: Any
    feature_names: tuple[str, ...]
    tld_table: TldRiskTable | None = None
    thresholds: Mapping[str, float] = field(default_factory=dict)
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.feature_names = tuple(self.feature_names)
        if not self.feature_names:
            raise ValueError("au moins une feature est requise")
        unknown = [n for n in self.feature_names if n not in FEATURE_NAMES]
        if unknown:
            raise ValueError(f"features inconnues : {unknown}")
        if len(set(self.feature_names)) != len(self.feature_names):
            raise ValueError("features en double")
        if not hasattr(self.estimator, "predict_proba"):
            raise TypeError("l'estimateur doit exposer predict_proba")

        # « base » est toujours calculée par l'extracteur ; on ne garde ensuite que les
        # colonnes attendues par l'estimateur.
        families = {"base"} | {feature_spec(n).family for n in self.feature_names}
        uses_tld = "tld" in families
        if uses_tld and self.tld_table is None:
            raise ValueError("tld_phish_rate est utilisée : la table des TLD est requise")
        self._extractor = UrlFeatureExtractor(
            families=families, tld_table=self.tld_table if uses_tld else None
        )

    # ------------------------------------------------------------------- #
    # Inférence
    # ------------------------------------------------------------------- #

    def features(self, urls: Iterable[str]) -> pd.DataFrame:
        """Features attendues par l'estimateur, dans son ordre (une ligne par URL)."""
        return self._extractor.transform(urls)[list(self.feature_names)]

    def score_features(self, x: pd.DataFrame) -> np.ndarray:
        """Probabilité de phishing pour des features déjà extraites."""
        return self.estimator.predict_proba(x[list(self.feature_names)])[:, 1]

    def score(self, urls: Iterable[str]) -> np.ndarray:
        """Probabilité de phishing de chaque URL (lève ``InvalidUrlError`` si invalide)."""
        return self.score_features(self.features(urls))

    def threshold(self, name: str = DEFAULT_THRESHOLD) -> float:
        try:
            return float(self.thresholds[name])
        except KeyError:
            raise KeyError(
                f"seuil inconnu {name!r} ; disponibles : {sorted(self.thresholds)}"
            ) from None

    def predict(
        self, urls: Iterable[str], threshold: str | float = DEFAULT_THRESHOLD
    ) -> np.ndarray:
        """1 si l'URL est signalée (score strictement supérieur au seuil), 0 sinon."""
        t = self.threshold(threshold) if isinstance(threshold, str) else float(threshold)
        return (self.score(urls) > t).astype(int)

    # ------------------------------------------------------------------- #
    # Sérialisation
    # ------------------------------------------------------------------- #

    def to_payload(self) -> dict[str, Any]:
        return {
            "format_version": FORMAT_VERSION,
            "estimator": self.estimator,
            "feature_names": list(self.feature_names),
            # Sans arrondi (contrairement à TldRiskTable.to_dict) : le modèle rechargé doit
            # voir exactement les valeurs de l'entraînement.
            "tld_table": None if self.tld_table is None else _exact_table(self.tld_table),
            "thresholds": {k: float(v) for k, v in self.thresholds.items()},
            "metadata": dict(self.metadata),
            "library_versions": library_versions(),
        }

    def save(self, path: Path) -> Path:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self.to_payload(), path, compress=3)
        return path

    @classmethod
    def load(cls, path: Path) -> UrlModel:
        """Charge un modèle. **Exécute du code (pickle)** : fichier de confiance seulement."""
        payload = joblib.load(Path(path))
        if not isinstance(payload, dict) or payload.get("format_version") != FORMAT_VERSION:
            raise ValueError(f"{path} : format de modèle non reconnu")
        saved = payload.get("library_versions", {})
        current = library_versions()
        for lib, version in saved.items():
            if current.get(lib) != version:
                logger.warning(
                    "%s : modèle enregistré avec %s %s, version installée %s",
                    path,
                    lib,
                    version,
                    current.get(lib),
                )
        table = payload["tld_table"]
        return cls(
            estimator=payload["estimator"],
            feature_names=tuple(payload["feature_names"]),
            tld_table=None if table is None else TldRiskTable.from_dict(table),
            thresholds=payload["thresholds"],
            metadata=payload["metadata"],
        )
