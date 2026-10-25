"""Tests de l'entraînement et de la comparaison des modèles URL (étape 1.6)."""

import importlib.util
import json
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from phishguard.data.split import read_split_blocks
from phishguard.evaluation.metrics import threshold_at_fpr
from phishguard.urls import training as T
from phishguard.urls.features import FEATURE_NAMES, UrlFeatureExtractor
from phishguard.urls.model import UrlModel
from phishguard.urls.tld import TldRiskTable

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "train_url.py"
spec = importlib.util.spec_from_file_location("train_url", SCRIPT)
train_script = importlib.util.module_from_spec(spec)
spec.loader.exec_module(train_script)

DOC_TEMPLATE = (
    "# Modèles\n\nTexte écrit à la main.\n\n"
    "<!-- generated:train-url:start -->\nancien\n<!-- generated:train-url:end -->\n\nFin.\n"
)


@pytest.fixture(scope="module")
def features(split_dataset_path):
    blocks = read_split_blocks(split_dataset_path, ("train", "validation"))
    train, val = blocks["train"], blocks["validation"]
    table = TldRiskTable.fit([h.rsplit(".", 1)[-1] for h in train["host"]], train["label"])
    extractor = UrlFeatureExtractor(tld_table=table)
    return (
        extractor.transform(train["url"]),
        train["label"].to_numpy(),
        extractor.transform(val["url"]),
        val["label"].to_numpy(),
        val["source"].to_numpy(),
        table,
        val["url"].tolist(),
    )


def run_search(features, **kwargs):
    x_train, y_train, x_val, y_val, sources_val, *_ = features
    kwargs.setdefault("grids", T.QUICK_GRIDS)
    return T.search(x_train, y_train, x_val, y_val, sources_val, **kwargs)


# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #


def test_three_model_families_with_non_empty_grids():
    assert list(T.MODEL_SPECS) == ["logistic_regression", "random_forest", "lightgbm"]
    for name, spec in T.MODEL_SPECS.items():
        assert spec.grid, name
        assert set(T.QUICK_GRIDS[name][0]) == set(spec.grid[0]), name


def test_logistic_regression_is_standardized():
    model = T.build_logistic_regression({"C": 1.0}, seed=0)
    assert [name for name, _ in model.steps] == ["standardscaler", "logisticregression"]


def test_deployed_feature_set_drops_the_https_artifact():
    deployed = T.FEATURE_SETS[T.DEFAULT_DEPLOY_FEATURE_SET]
    assert "is_https" not in deployed
    assert set(deployed) == set(FEATURE_NAMES) - {"is_https"}
    assert set(T.FEATURE_SETS["host_only"]) < set(deployed)


def test_grid_is_a_stable_cartesian_product():
    grid = T._grid(a=(1, 2), b=("x", "y"))
    assert grid == ({"a": 1, "b": "x"}, {"a": 1, "b": "y"}, {"a": 2, "b": "x"}, {"a": 2, "b": "y"})


# --------------------------------------------------------------------------- #
# Recherche
# --------------------------------------------------------------------------- #


def test_search_covers_every_model_and_feature_set(features):
    result = run_search(features)
    expected = {(m, fs) for m in T.MODEL_SPECS for fs in T.FEATURE_SETS}
    assert set(result.best) == expected
    assert len(result.trials) == len(expected)  # grilles réduites : un réglage chacune
    assert set(result.estimators) == set(T.MODEL_SPECS)
    for trial in result.trials:
        for key in ("pr_auc", "recall_at_fpr_1pct", "recall_at_fpr_0_1pct", "fpr_internal_pages"):
            assert key in trial.metrics


def test_search_keeps_the_best_trial_of_each_grid(features):
    grids = {"logistic_regression": T._grid(C=(0.001, 0.1, 10.0))}
    result = run_search(features, models=["logistic_regression"], grids=grids)
    for feature_set in T.FEATURE_SETS:
        trials = [t for t in result.trials if t.feature_set == feature_set]
        assert len(trials) == 3
        best = result.best[("logistic_regression", feature_set)]
        assert best.key == max(t.key for t in trials)
        # À égalité, le premier réglage de la grille l'emporte.
        assert best is next(t for t in trials if t.key == best.key)


def test_best_model_compares_models_on_one_feature_set(features):
    result = run_search(features)
    best = result.best_model("without_scheme")
    candidates = [result.best[(m, "without_scheme")] for m in T.MODEL_SPECS]
    assert best.key == max(t.key for t in candidates)
    with pytest.raises(KeyError):
        result.best_model("absent")


def test_search_is_deterministic(features):
    first = [t.to_dict() | {"fit_seconds": 0} for t in run_search(features).trials]
    second = [t.to_dict() | {"fit_seconds": 0} for t in run_search(features).trials]
    assert first == second


def test_search_rejects_unknown_names(features):
    with pytest.raises(ValueError, match="inconnus"):
        run_search(features, models=["svm"])
    with pytest.raises(ValueError, match="déployer"):
        run_search(features, feature_sets=["all"], deploy_feature_set="host_only")


def test_kept_estimators_score_like_the_trial(features):
    _, _, x_val, _, _, _, _ = features
    result = run_search(features, models=["random_forest"])
    estimator = result.estimators["random_forest"]
    assert estimator.n_jobs == 1  # inférence sur un seul fil
    columns = list(T.FEATURE_SETS[T.DEFAULT_DEPLOY_FEATURE_SET])
    np.testing.assert_allclose(
        estimator.predict_proba(x_val[columns])[:, 1], result.validation_scores["random_forest"]
    )


def test_thresholds_respect_their_false_positive_budget():
    rng = np.random.default_rng(0)
    y = np.array([0] * 2000 + [1] * 200)
    scores = np.concatenate([rng.random(2000) * 0.8, 0.5 + rng.random(200) / 2])
    thresholds = T.thresholds_from_validation(y, scores)
    assert set(thresholds) == set(T.THRESHOLD_TARGETS)
    for name, budget in T.THRESHOLD_TARGETS.items():
        assert (scores[y == 0] > thresholds[name]).mean() <= budget
    # Moins de faux positifs tolérés → seuil plus haut.
    ordered = [thresholds[n] for n in sorted(T.THRESHOLD_TARGETS, key=T.THRESHOLD_TARGETS.get)]
    assert ordered == sorted(ordered, reverse=True)


def test_threshold_at_fpr_validates_its_input():
    assert threshold_at_fpr([0.1, 0.2, 0.3, 0.4], 0.25) == pytest.approx(0.4)
    with pytest.raises(ValueError):
        threshold_at_fpr([], 0.01)
    with pytest.raises(ValueError):
        threshold_at_fpr([0.1], 1.5)


# --------------------------------------------------------------------------- #
# Coût à l'inférence
# --------------------------------------------------------------------------- #


def test_measure_inference_and_size(features):
    _, _, x_val, _, _, table, urls = features
    result = run_search(features, models=["lightgbm"])
    model = UrlModel(
        result.estimators["lightgbm"], T.FEATURE_SETS[T.DEFAULT_DEPLOY_FEATURE_SET], table
    )
    cost = T.measure_inference(model, urls, x_val, single_calls=20)
    assert cost["single_calls"] == 20
    assert 0 < cost["latency_ms_p50"] <= cost["latency_ms_p95"]
    assert cost["predict_us_per_url"] > 0
    assert T.serialized_size(model.estimator) > 0


# --------------------------------------------------------------------------- #
# Script
# --------------------------------------------------------------------------- #


def test_script_end_to_end(tmp_path, split_dataset_path):
    doc = tmp_path / "url-models.md"
    doc.write_text(DOC_TEMPLATE, encoding="utf-8")
    model_path, report_path = tmp_path / "url_v1.joblib", tmp_path / "url_v1.json"
    code = train_script.main(
        [
            "--dataset",
            str(split_dataset_path),
            "--model-out",
            str(model_path),
            "--report",
            str(report_path),
            "--doc",
            str(doc),
            "--quick",
        ]
    )
    assert code == 0

    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["metadata"]["splits_used"] == ["train", "validation"]
    assert set(report["rows"]) == {"train", "validation"}  # le test n'est jamais lu
    assert report["selection"]["evaluated_on"] == "validation"
    assert sum(entry["selected"] for entry in report["models"].values()) == 1
    assert report["selected"]["model"] in T.MODEL_SPECS
    assert len(report["trials"]) == len(T.MODEL_SPECS) * len(T.FEATURE_SETS)

    model = UrlModel.load(model_path)
    assert model.metadata["model"] == report["selected"]["model"]
    assert model.thresholds["fpr_1pct"] == pytest.approx(
        report["selected"]["thresholds"]["fpr_1pct"], abs=1e-6
    )
    assert "is_https" not in model.feature_names

    # Aucune URL dans le rapport versionné.
    df = pd.read_parquet(split_dataset_path)
    text = report_path.read_text(encoding="utf-8")
    assert not any(host in text for host in df["host"].unique())

    rendered = doc.read_text(encoding="utf-8")
    assert "Texte écrit à la main." in rendered and rendered.endswith("Fin.\n")
    assert "ancien" not in rendered
    assert "**(retenu)**" in rendered


def test_script_reports_a_missing_dataset(tmp_path):
    assert train_script.main(["--dataset", str(tmp_path / "absent.parquet"), "--doc", "none"]) == 1


def test_script_rejects_a_deploy_set_that_is_not_evaluated():
    with pytest.raises(SystemExit):
        train_script.parse_args(["--feature-sets", "all", "--deploy-feature-set", "host_only"])
