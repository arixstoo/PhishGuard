"""Export du modèle URL pour l'extension (étape 4.11).

Trois garanties :

1. l'implémentation de référence en Python pur (:func:`predict_raw`), qui ne lit que le
   JSON exporté, retrouve **exactement** le score de LightGBM, valeurs manquantes et
   nulles comprises : le JSON suffit, l'extension n'a qu'à traduire la boucle ;
2. un modèle que l'extension ne saurait pas reproduire (catégoriel, multiclasse, autre
   estimateur, ordre des colonnes différent) est refusé à l'export, pas en production ;
3. les vecteurs de référence versionnés (``tests/golden/url_vectors.json``) restent
   cohérents avec l'extracteur Python : modifier une feature sans les régénérer fait
   échouer ce test, avant que l'extension ne diverge en silence.
"""

from __future__ import annotations

import importlib.util
import json
import math

import lightgbm as lgb
import numpy as np
import pandas as pd
import pytest
from api_support import COLUMNS, ROOT
from sklearn.linear_model import LogisticRegression

from phishguard.data.split import read_split_blocks
from phishguard.fusion.calibration import ScoreCalibrator
from phishguard.urls.export import (
    EXPORT_FORMAT,
    UnsupportedModelError,
    calibrated_probability,
    export_url_model,
    predict_probability,
    predict_raw,
)
from phishguard.urls.features import (
    FEATURE_EXTRACTOR_VERSION,
    UrlFeatureExtractor,
    reference_data_sha256,
)
from phishguard.urls.model import UrlModel

GOLDEN = ROOT / "tests/golden/url_vectors.json"


def _load_script(name: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


export_script = _load_script("export_model")


@pytest.fixture(scope="module")
def url_model(split_dataset_path) -> UrlModel:
    data = read_split_blocks(split_dataset_path, ("train",), ["url", "label"])["train"]
    estimator = lgb.LGBMClassifier(n_estimators=40, num_leaves=15, verbose=-1, random_state=0)
    model = UrlModel(
        estimator, COLUMNS, thresholds={"fpr_1pct": 0.6}, metadata={"model_version": "url_t"}
    )
    estimator.fit(model.features(data["url"]), data["label"])
    return model


@pytest.fixture(scope="module")
def calibrator(url_model, split_dataset_path) -> ScoreCalibrator:
    data = read_split_blocks(split_dataset_path, ("validation",), ["url", "label"])["validation"]
    return ScoreCalibrator.fit(url_model.score(data["url"]), data["label"], method="isotonic")


def _json_roundtrip(document: dict) -> dict:
    return json.loads(json.dumps(document))


# --------------------------------------------------------------------------- #
# 1. Le JSON suffit : implémentation de référence = LightGBM
# --------------------------------------------------------------------------- #


def test_reference_implementation_matches_lightgbm(url_model, calibrator):
    exported = _json_roundtrip(export_url_model(url_model, calibrator))
    urls = export_script.synthetic_urls(200)
    frame = url_model.features(urls)
    expected = url_model.score_features(frame)
    for values, want in zip(frame.to_numpy(dtype=float), expected, strict=True):
        assert predict_probability(exported, values.tolist()) == pytest.approx(want, abs=1e-12)
    # Score brut : celui de LightGBM avant la sigmoïde.
    raw = url_model.estimator.booster_.predict(frame, raw_score=True)
    for values, want in zip(frame.to_numpy(dtype=float), raw, strict=True):
        assert predict_raw(exported, values.tolist()) == pytest.approx(want, abs=1e-12)


def test_calibration_is_exported_and_applied(url_model, calibrator):
    exported = _json_roundtrip(export_url_model(url_model, calibrator))
    values = url_model.features(["http://secure-login-verify.example/verify"]).iloc[0].tolist()
    score = predict_probability(exported, values)
    assert calibrated_probability(exported, values) == pytest.approx(calibrator(score))
    uncalibrated = _json_roundtrip(export_url_model(url_model, None))
    assert uncalibrated["calibration"] is None
    assert calibrated_probability(uncalibrated, values) == pytest.approx(score)


@pytest.mark.parametrize("zero_as_missing", [False, True])
def test_missing_and_zero_values_follow_lightgbm(zero_as_missing):
    """Branches « valeur manquante » (NaN) et « zéro manquant » de NumericalDecision."""
    rng = np.random.default_rng(0)
    x = rng.normal(size=(600, 4))
    x[rng.random(x.shape) < 0.2] = np.nan
    x[rng.random(x.shape) < 0.2] = 0.0
    y = ((np.nan_to_num(x[:, 0]) + np.nan_to_num(x[:, 1]) > 0) ^ np.isnan(x[:, 2])).astype(int)
    columns = COLUMNS[:4]
    estimator = lgb.LGBMClassifier(
        n_estimators=30, num_leaves=8, verbose=-1, random_state=0, zero_as_missing=zero_as_missing
    ).fit(pd.DataFrame(x, columns=columns), y)
    model = UrlModel.__new__(UrlModel)  # pas d'extracteur : features fournies directement
    model.estimator, model.feature_names, model.thresholds = estimator, tuple(columns), {}
    model.tld_table, model.metadata = None, {"model_version": "nan_t"}
    exported = _json_roundtrip(export_url_model(model, None))
    missing_types = {
        node["missing_type"]
        for tree in exported["booster"]["tree_info"]
        for node in _internal_nodes(tree["tree_structure"])
    }
    assert ("Zero" if zero_as_missing else "NaN") in missing_types

    probe = rng.normal(size=(300, 4))
    probe[rng.random(probe.shape) < 0.3] = np.nan
    probe[rng.random(probe.shape) < 0.3] = 0.0
    expected = estimator.predict_proba(pd.DataFrame(probe, columns=columns))[:, 1]
    for values, want in zip(probe, expected, strict=True):
        assert predict_probability(exported, values.tolist()) == pytest.approx(want, abs=1e-12)


def _internal_nodes(node):
    if "leaf_value" in node:
        return []
    return [node, *_internal_nodes(node["left_child"]), *_internal_nodes(node["right_child"])]


def test_export_document_is_self_describing(url_model, calibrator):
    exported = export_url_model(url_model, calibrator)
    assert exported["format"] == EXPORT_FORMAT
    assert exported["feature_names"] == list(COLUMNS)
    assert exported["feature_extractor"]["version"] == FEATURE_EXTRACTOR_VERSION
    assert exported["feature_extractor"]["reference_data_sha256"] == reference_data_sha256()
    assert exported["objective"] == {"name": "binary", "sigmoid": 1.0}
    assert exported["thresholds"] == {"fpr_1pct": 0.6}
    # Rien d'exécutable : uniquement des types JSON.
    assert _json_roundtrip(exported) == json.loads(json.dumps(exported))


def test_wrong_feature_count_is_refused(url_model):
    exported = export_url_model(url_model, None)
    with pytest.raises(ValueError, match="features"):
        predict_raw(exported, [0.0] * (len(COLUMNS) - 1))


# --------------------------------------------------------------------------- #
# 2. Ce que l'extension ne saurait pas reproduire est refusé à l'export
# --------------------------------------------------------------------------- #


def _bare_model(estimator, columns) -> UrlModel:
    model = UrlModel.__new__(UrlModel)
    model.estimator, model.feature_names, model.thresholds = estimator, tuple(columns), {}
    model.tld_table, model.metadata = None, {}
    return model


def test_non_lightgbm_estimator_is_refused():
    estimator = LogisticRegression().fit([[0.0], [1.0]], [0, 1])
    with pytest.raises(UnsupportedModelError, match="LightGBM"):
        export_url_model(_bare_model(estimator, COLUMNS[:1]), None)


def test_categorical_splits_are_refused():
    rng = np.random.default_rng(1)
    frame = pd.DataFrame({COLUMNS[0]: rng.integers(0, 5, 400), COLUMNS[1]: rng.normal(size=400)})
    y = (frame[COLUMNS[0]].isin([1, 3])).astype(int)
    frame[COLUMNS[0]] = frame[COLUMNS[0]].astype("category")
    estimator = lgb.LGBMClassifier(n_estimators=5, verbose=-1, min_child_samples=5).fit(frame, y)
    with pytest.raises(UnsupportedModelError, match="catégorielle"):
        export_url_model(_bare_model(estimator, COLUMNS[:2]), None)


def test_multiclass_is_refused():
    rng = np.random.default_rng(2)
    x = pd.DataFrame(rng.normal(size=(300, 2)), columns=COLUMNS[:2])
    estimator = lgb.LGBMClassifier(n_estimators=3, verbose=-1).fit(x, rng.integers(0, 3, 300))
    with pytest.raises(UnsupportedModelError):
        export_url_model(_bare_model(estimator, COLUMNS[:2]), None)


def test_column_order_mismatch_is_refused(url_model):
    swapped = _bare_model(url_model.estimator, (COLUMNS[1], COLUMNS[0], *COLUMNS[2:]))
    with pytest.raises(UnsupportedModelError, match="ordre"):
        export_url_model(swapped, None)


# --------------------------------------------------------------------------- #
# 3. Vecteurs de référence versionnés
# --------------------------------------------------------------------------- #


def test_synthetic_urls_are_deterministic_and_unique():
    first = export_script.synthetic_urls(200)
    assert first == export_script.synthetic_urls(200)
    assert len(first) == len(set(first)) == 200


def test_export_script_end_to_end(url_model, calibrator, tmp_path):
    models_dir = tmp_path / "models"
    models_dir.mkdir()
    url_model.metadata = {**url_model.metadata, "model_version": "url_v2"}
    url_model.save(models_dir / "url_v2.joblib")
    calibrator.save(models_dir / "url_v2_calibration.json")
    golden_path = tmp_path / "golden.json"
    assert export_script.main(["--models-dir", str(models_dir), "--golden", str(golden_path)]) == 0
    exported = json.loads((models_dir / "url_v2.json").read_text(encoding="utf-8"))
    golden = json.loads(golden_path.read_text(encoding="utf-8"))
    assert len(golden["vectors"]) == 200 and golden["tolerance"] == 1e-6
    for vector in golden["vectors"][:50]:
        values = [vector["features"][name] for name in golden["feature_names"]]
        assert predict_probability(exported, values) == pytest.approx(vector["probability"])
        assert calibrated_probability(exported, values) == pytest.approx(
            vector["calibrated_probability"]
        )


@pytest.mark.skipif(not GOLDEN.is_file(), reason="vecteurs de référence pas encore générés")
def test_committed_golden_vectors_match_the_python_extractor():
    golden = json.loads(GOLDEN.read_text(encoding="utf-8"))
    assert golden["feature_extractor"]["version"] == FEATURE_EXTRACTOR_VERSION
    assert golden["feature_extractor"]["reference_data_sha256"] == reference_data_sha256(), (
        "listes de référence modifiées : régénérer les vecteurs (make export)"
    )
    assert len(golden["vectors"]) == 200
    # La table des TLD vient du modèle : ces colonnes sont vérifiées avec lui (ci-dessous).
    names = [n for n in golden["feature_names"] if n != "tld_phish_rate"]
    families = ("base", "brand", "homograph", "shortener")
    frame = UrlFeatureExtractor(families=families).transform([v["url"] for v in golden["vectors"]])
    for vector, (_, row) in zip(golden["vectors"], frame.iterrows(), strict=True):
        for name in names:
            assert row[name] == pytest.approx(vector["features"][name], abs=1e-9), (
                vector["url"],
                name,
            )


EXPORTED_MODEL = ROOT / "models/url_v2.json"


@pytest.mark.skipif(
    not (GOLDEN.is_file() and EXPORTED_MODEL.is_file()), reason="modèle exporté absent"
)
def test_committed_golden_scores_match_the_exported_model():
    golden = json.loads(GOLDEN.read_text(encoding="utf-8"))
    exported = json.loads(EXPORTED_MODEL.read_text(encoding="utf-8"))
    if exported.get("model_version") != golden["model_version"]:
        pytest.skip("modèle exporté local différent de celui des vecteurs")
    for vector in golden["vectors"]:
        values = [vector["features"][name] for name in golden["feature_names"]]
        assert math.isclose(
            predict_probability(exported, values), vector["probability"], abs_tol=1e-12
        )
