"""Export du modèle URL pour l'extension (étape 4.11) : arbres LightGBM en JSON.

L'extension fait l'inférence **localement**, sans envoyer l'URL nulle part. Pour un
modèle LightGBM, l'export le plus simple et le plus robuste n'est pas ONNX mais les
arbres eux-mêmes (``Booster.dump_model()``) : un fichier JSON, sans code exécutable, que
l'extension parcourt en une courte boucle (étape 5.3). ONNX (``onnxmltools``,
``onnxruntime-web``) reste possible plus tard pour d'autres types de modèles.

Le fichier contient tout ce qu'il faut pour reproduire le score Python :

- ``feature_names`` : l'ordre des colonnes attendu par les arbres ;
- ``booster`` : la sortie de ``dump_model()``, réduite aux champs de l'inférence (seuils
  en double précision, 17 chiffres significatifs : la relecture JSON est exacte) ;
- ``objective`` : la fonction de lien (sigmoïde et son paramètre) ;
- ``calibration`` : la fonction score → probabilité (étape 2.10), déjà en JSON ;
- ``tld_table`` : la table de risque des TLD si le modèle utilise ``tld_phish_rate`` ;
- ``feature_extractor`` : version et empreinte des listes de référence, pour refuser un
  modèle produit avec un autre extracteur que celui de l'extension.

:func:`predict_raw` est une **implémentation de référence en Python pur** du parcours
des arbres, sans LightGBM. Les tests la comparent à ``Booster.predict`` : si elle donne
les mêmes valeurs, le JSON exporté suffit, et l'implémentation TypeScript n'a qu'à la
traduire ligne à ligne. Les vecteurs de référence (``tests/golden/url_vectors.json``,
:mod:`scripts.export_model`) verrouillent ensuite les deux implémentations ensemble.
"""

from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
from typing import Any

import lightgbm

from phishguard.fusion.calibration import ScoreCalibrator
from phishguard.security.normalize import NORMALIZATION_VERSION
from phishguard.urls.features import FEATURE_EXTRACTOR_VERSION, reference_data_sha256
from phishguard.urls.model import UrlModel, _exact_table

EXPORT_FORMAT = "phishguard-url-lightgbm"
EXPORT_FORMAT_VERSION = 1
# Seuil sous lequel LightGBM considère une valeur comme nulle (kZeroThreshold).
ZERO_THRESHOLD = 1e-35


class UnsupportedModelError(ValueError):
    """Modèle que l'export (et donc l'extension) ne sait pas reproduire."""


def _booster(model: UrlModel) -> lightgbm.Booster:
    estimator = model.estimator
    booster = getattr(estimator, "booster_", estimator)
    if not isinstance(booster, lightgbm.Booster):
        raise UnsupportedModelError(
            f"estimateur {type(estimator).__name__} : seul LightGBM s'exporte en arbres JSON"
        )
    return booster


def _sigmoid_parameter(objective: str) -> float:
    """``"binary sigmoid:1"`` → 1.0. Toute autre fonction objectif est refusée."""
    parts = objective.split()
    if not parts or parts[0] != "binary":
        raise UnsupportedModelError(f"objectif {objective!r} : classification binaire attendue")
    for part in parts[1:]:
        if part.startswith("sigmoid:"):
            return float(part.removeprefix("sigmoid:"))
    return 1.0


# Champs d'un nœud nécessaires à l'inférence. Le reste de dump_model() (gain de la
# coupure, poids et effectifs par nœud) ne sert qu'à l'analyse de l'entraînement : il
# triplerait la taille du fichier que l'extension télécharge et vérifie.
_SPLIT_FIELDS = (
    "split_feature",
    "threshold",
    "decision_type",
    "default_left",
    "missing_type",
)
_TREE_FIELDS = ("tree_index", "num_leaves", "shrinkage")
_BOOSTER_FIELDS = (
    "name",
    "version",
    "num_class",
    "num_tree_per_iteration",
    "max_feature_idx",
    "objective",
    "feature_names",
)


def _prune(node: Mapping[str, Any]) -> dict[str, Any]:
    if "leaf_value" in node:
        return {"leaf_value": node["leaf_value"]}
    pruned = {key: node[key] for key in _SPLIT_FIELDS}
    pruned["left_child"] = _prune(node["left_child"])
    pruned["right_child"] = _prune(node["right_child"])
    return pruned


def _pruned_booster(dump: Mapping[str, Any]) -> dict[str, Any]:
    booster = {key: dump[key] for key in _BOOSTER_FIELDS}
    booster["tree_info"] = [
        {
            **{key: tree[key] for key in _TREE_FIELDS},
            "tree_structure": _prune(tree["tree_structure"]),
        }
        for tree in dump["tree_info"]
    ]
    return booster


def _check_tree(node: Mapping[str, Any]) -> None:
    stack = [node]
    while stack:
        current = stack.pop()
        if "leaf_value" in current:
            continue
        if current.get("decision_type") != "<=":
            raise UnsupportedModelError(
                f"décision {current.get('decision_type')!r} : seules les coupures numériques "
                "« <= » sont exportées (aucune feature catégorielle)"
            )
        if current.get("missing_type") not in {"None", "Zero", "NaN"}:
            raise UnsupportedModelError(f"missing_type {current.get('missing_type')!r}")
        stack.extend((current["left_child"], current["right_child"]))


def export_url_model(model: UrlModel, calibrator: ScoreCalibrator | None) -> dict[str, Any]:
    """Document JSON du modèle, prêt à être écrit (``json.dump``)."""
    booster = _booster(model)
    dump = booster.dump_model()
    if dump.get("num_class") != 1 or dump.get("num_tree_per_iteration") != 1:
        raise UnsupportedModelError("un seul arbre par itération attendu (binaire)")
    if list(dump["feature_names"]) != list(model.feature_names):
        raise UnsupportedModelError(
            "ordre des features du booster différent de celui du modèle : export refusé"
        )
    for tree in dump["tree_info"]:
        _check_tree(tree["tree_structure"])
    metadata = dict(model.metadata)
    return {
        "format": EXPORT_FORMAT,
        "format_version": EXPORT_FORMAT_VERSION,
        "model_version": metadata.get("model_version"),
        "trained_at": metadata.get("trained_at"),
        "feature_names": list(model.feature_names),
        "feature_extractor": {
            "version": FEATURE_EXTRACTOR_VERSION,
            "reference_data_sha256": reference_data_sha256(),
            "normalization_version": NORMALIZATION_VERSION,
        },
        "objective": {"name": "binary", "sigmoid": _sigmoid_parameter(dump["objective"])},
        "thresholds": {name: float(value) for name, value in model.thresholds.items()},
        "decision_rule": "score > threshold",
        "tld_table": None if model.tld_table is None else _exact_table(model.tld_table),
        "calibration": None if calibrator is None else calibrator.to_dict(),
        "lightgbm_version": lightgbm.__version__,
        "booster": _pruned_booster(dump),
    }


# --------------------------------------------------------------------------- #
# Implémentation de référence de l'inférence, en Python pur
# --------------------------------------------------------------------------- #


def _go_left(node: Mapping[str, Any], value: float) -> bool:
    """Décision numérique de LightGBM (``Tree::NumericalDecision``), à l'identique."""
    missing = node["missing_type"]
    if math.isnan(value) and missing != "NaN":
        value = 0.0
    if (missing == "Zero" and abs(value) <= ZERO_THRESHOLD) or (
        missing == "NaN" and math.isnan(value)
    ):
        return bool(node["default_left"])
    return value <= node["threshold"]


def predict_raw(exported: Mapping[str, Any], features: Sequence[float]) -> float:
    """Score brut (avant sigmoïde) : somme des feuilles atteintes dans chaque arbre."""
    booster = exported["booster"]
    if len(features) != len(exported["feature_names"]):
        raise ValueError(
            f"{len(features)} features reçues, {len(exported['feature_names'])} attendues"
        )
    total = 0.0
    for tree in booster["tree_info"]:
        node = tree["tree_structure"]
        while "leaf_value" not in node:
            value = float(features[node["split_feature"]])
            node = node["left_child"] if _go_left(node, value) else node["right_child"]
        total += node["leaf_value"]
    return total


def predict_probability(exported: Mapping[str, Any], features: Sequence[float]) -> float:
    """Probabilité de phishing (score du modèle, avant calibration)."""
    raw = predict_raw(exported, features)
    return 1.0 / (1.0 + math.exp(-exported["objective"]["sigmoid"] * raw))


def calibrated_probability(exported: Mapping[str, Any], features: Sequence[float]) -> float:
    """Probabilité calibrée, comme la reçoit la fusion (étape 2.10)."""
    score = predict_probability(exported, features)
    calibration = exported.get("calibration")
    if calibration is None:
        return min(1.0, max(0.0, score))
    return ScoreCalibrator.from_dict(dict(calibration))(score)
