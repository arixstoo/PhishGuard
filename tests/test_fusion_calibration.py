"""Tests de la calibration des probabilités du modèle URL (étape 2.10)."""

import importlib.util
import json
from pathlib import Path

import numpy as np
import pytest
from sklearn.linear_model import LogisticRegression

from phishguard.data.split import read_split_blocks
from phishguard.fusion.calibration import (
    ScoreCalibrator,
    adjust_prevalence,
    best_method,
    calibration_report,
    compare_methods,
    cross_validated_probabilities,
)
from phishguard.urls.features import UrlFeatureExtractor, feature_names
from phishguard.urls.model import UrlModel

ROOT = Path(__file__).resolve().parents[1]


def overconfident(n=20_000, prevalence=0.2, seed=0):
    """Scores d'un modèle trop sûr de lui : bien classés, mais pas des probabilités.

    La vraie probabilité de phishing est ``q`` ; le modèle annonce ``q³`` sous 0,5 et
    ``1 − (1 − q)³`` au-dessus, beaucoup plus proche de 0 ou de 1, comme un modèle à arbres.
    """
    rng = np.random.default_rng(seed)
    logit = rng.normal(np.log(prevalence / (1 - prevalence)), 2.0, n)
    q = 1 / (1 + np.exp(-logit))
    labels = (rng.random(n) < q).astype(int)
    scores = np.where(q > 0.5, 1 - (1 - q) ** 3, q**3)
    return scores, labels


# --------------------------------------------------------------------------- #
# Apprentissage et prédiction
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("method", ["isotonic", "sigmoid"])
def test_calibration_reduces_the_calibration_error(method):
    scores, labels = overconfident()
    raw = calibration_report(scores, labels)
    calibrated = calibration_report(
        cross_validated_probabilities(scores, labels, method=method), labels
    )
    assert calibrated["ece"] < raw["ece"] / 2
    assert calibrated["brier"] < raw["brier"]


def test_calibrated_probability_means_what_it_says():
    """« 0,9 veut dire environ 90 % » : critère de l'étape, sur des scores mal calibrés."""
    scores, labels = overconfident(n=50_000)
    calibrator = ScoreCalibrator.fit(scores[:25_000], labels[:25_000])
    p, y = calibrator.predict(scores[25_000:]), labels[25_000:]
    for low, high in ((0.85, 0.95), (0.45, 0.55), (0.05, 0.15)):
        mask = (p >= low) & (p < high)
        assert mask.sum() > 200
        assert abs(y[mask].mean() - p[mask].mean()) < 0.05


def test_calibration_keeps_the_ranking():
    scores, labels = overconfident(n=5_000)
    for method in ("isotonic", "sigmoid"):
        calibrator = ScoreCalibrator.fit(scores, labels, method=method)
        order = np.argsort(scores)
        assert np.all(np.diff(calibrator.predict(scores[order])) >= -1e-12)


def test_predictions_stay_probabilities_outside_the_fitted_range():
    calibrator = ScoreCalibrator.fit([0.2, 0.3, 0.7, 0.8], [0, 0, 1, 1])
    assert calibrator(-5) == calibrator(0.2) and calibrator(9) == calibrator(0.8)
    assert all(0 <= v <= 1 for v in calibrator.predict([-1, 0, 0.5, 1, 2]))


def test_prevalence_is_recorded():
    scores, labels = overconfident(prevalence=0.2)
    calibrator = ScoreCalibrator.fit(scores, labels)
    assert calibrator.prevalence == pytest.approx(labels.mean())
    assert calibrator.samples == len(labels)


@pytest.mark.parametrize(
    ("scores", "labels"),
    [([], []), ([0.1, 0.2], [0]), ([0.1, 0.2], [1, 1]), ([0.1, np.nan], [0, 1])],
)
def test_invalid_training_data_is_rejected(scores, labels):
    with pytest.raises(ValueError):
        ScoreCalibrator.fit(scores, labels)


def test_anti_correlated_score_is_refused_by_platt():
    with pytest.raises(ValueError, match="n'augmente pas"):
        ScoreCalibrator.fit([0.1, 0.2, 0.8, 0.9] * 10, [1, 1, 0, 0] * 10, method="sigmoid")


def test_unknown_method_and_invalid_tables_are_rejected():
    with pytest.raises(ValueError):
        ScoreCalibrator.fit([0.1, 0.9], [0, 1], method="beta")
    with pytest.raises(ValueError):
        ScoreCalibrator("isotonic", x=(0.0, 1.0), y=(0.9, 0.1))
    with pytest.raises(ValueError):
        ScoreCalibrator("sigmoid", params={"a": -1.0, "b": 0.0})


# --------------------------------------------------------------------------- #
# JSON sans pickle
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("method", ["isotonic", "sigmoid"])
def test_json_round_trip_gives_identical_probabilities(tmp_path, method):
    scores, labels = overconfident(n=4_000)
    calibrator = ScoreCalibrator.fit(scores, labels, method=method, metadata={"model": "x"})
    path = calibrator.save(tmp_path / "calibration.json")
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["format_version"] == 1 and payload["method"] == method
    reloaded = ScoreCalibrator.load(path)
    np.testing.assert_array_equal(reloaded.predict(scores), calibrator.predict(scores))
    assert reloaded.metadata == {"model": "x"}


def test_unknown_format_is_rejected():
    with pytest.raises(ValueError, match="format"):
        ScoreCalibrator.from_dict({"format_version": 99, "method": "isotonic"})


# --------------------------------------------------------------------------- #
# Prévalence et mesures
# --------------------------------------------------------------------------- #


def test_prevalence_adjustment_follows_bayes():
    # 0,9 calibrée sur 20 % de phishing ne vaut plus que 0,27 environ à 1 %.
    assert adjust_prevalence(0.9, 0.2, 0.01) == pytest.approx(0.2667, abs=1e-4)
    assert adjust_prevalence(0.9, 0.2, 0.2) == pytest.approx(0.9)
    assert adjust_prevalence(0.0, 0.2, 0.01) == 0.0 and adjust_prevalence(1.0, 0.2, 0.01) == 1.0
    assert adjust_prevalence(adjust_prevalence(0.6, 0.2, 0.01), 0.01, 0.2) == pytest.approx(0.6)
    with pytest.raises(ValueError):
        adjust_prevalence(0.5, 0.0, 0.1)
    with pytest.raises(ValueError):
        adjust_prevalence(1.5, 0.2, 0.1)


def test_report_of_a_perfect_calibration():
    rng = np.random.default_rng(1)
    p = rng.random(200_000)
    y = (rng.random(p.size) < p).astype(int)
    report = calibration_report(p, y, n_bins=10)
    assert report["ece"] < 0.01
    assert len(report["bins"]) == 10 and sum(b["count"] for b in report["bins"]) == p.size
    with pytest.raises(ValueError):
        calibration_report([1.2, 0.1], [1, 0])


def test_method_comparison_and_selection():
    scores, labels = overconfident(n=8_000)
    reports = compare_methods(scores, labels, folds=3)
    assert set(reports) == {"raw", "isotonic", "sigmoid"}
    assert best_method(reports) in {"isotonic", "sigmoid"}
    assert reports[best_method(reports)]["brier"] < reports["raw"]["brier"]
    with pytest.raises(ValueError):
        best_method({"raw": reports["raw"]})


# --------------------------------------------------------------------------- #
# Script de calibration, de bout en bout sur le jeu synthétique
# --------------------------------------------------------------------------- #


def _load_script():
    spec = importlib.util.spec_from_file_location(
        "calibrate_url", ROOT / "scripts/calibrate_url.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_script_calibrates_on_validation_only(split_dataset_path, tmp_path, monkeypatch):
    train = read_split_blocks(split_dataset_path, ("train",), ["url", "label"])["train"]
    columns = feature_names(families=("base",), exclude_groups=("scheme",))
    x = UrlFeatureExtractor(families=("base",)).transform(train["url"])[list(columns)]
    estimator = LogisticRegression(max_iter=1000).fit(x, train["label"])
    model_path = UrlModel(estimator, columns, thresholds={"fpr_1pct": 0.5}).save(
        tmp_path / "url_v1.joblib"
    )

    read_blocks = []
    original = read_split_blocks

    def spy(path, names, columns=None):
        read_blocks.append(tuple(names))
        return original(path, names, columns)

    script = _load_script()
    monkeypatch.setattr(script, "read_split_blocks", spy)
    output, report_path = tmp_path / "calibration.json", tmp_path / "report.json"
    code = script.main(
        [
            "--dataset",
            str(split_dataset_path),
            "--model",
            str(model_path),
            "--output",
            str(output),
            "--report",
            str(report_path),
            "--folds",
            "3",
        ]
    )
    assert code == 0
    assert read_blocks == [("validation",)]  # le test n'est jamais chargé
    calibrator = ScoreCalibrator.load(output)
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["selected"] == calibrator.method
    assert set(report["methods"]) == {"raw", "isotonic", "sigmoid"}
    assert report["metadata"]["fitted_on"] == "validation"


def test_script_reports_missing_inputs(tmp_path):
    assert _load_script().main(["--dataset", str(tmp_path / "absent.parquet")]) == 1
