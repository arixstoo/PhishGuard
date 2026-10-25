"""Tests de la précision à prévalence réaliste (étape 1.7)."""

import math

import numpy as np
import pytest

from phishguard.evaluation import prevalence as P


def test_precision_formula_matches_the_plan_example():
    # Rappel 85 %, FPR 1 %, prévalence 0,1 % : environ douze fausses alertes pour une vraie.
    assert P.precision_at_prevalence(0.85, 0.01, 0.001) == pytest.approx(0.0784, abs=1e-4)
    alerts = P.alerts_per_urls(0.85, 0.01, 0.001)
    assert alerts["true_alerts"] == pytest.approx(8.5)
    assert alerts["false_alerts"] == pytest.approx(99.9)
    assert alerts["false_per_true"] == pytest.approx(11.75, abs=0.01)


def test_precision_edge_cases():
    assert P.precision_at_prevalence(0.5, 0.0, 0.01) == 1.0
    assert math.isnan(P.precision_at_prevalence(0.0, 0.0, 0.01))
    assert P.alerts_per_urls(0.0, 0.01, 0.01)["false_per_true"] == math.inf


@pytest.mark.parametrize(
    ("recall", "fpr", "prevalence"),
    [(1.2, 0.1, 0.1), (0.5, -0.1, 0.1), (0.5, 0.1, 0.0), (0.5, 0.1, 1.0)],
)
def test_precision_rejects_invalid_rates(recall, fpr, prevalence):
    with pytest.raises(ValueError):
        P.precision_at_prevalence(recall, fpr, prevalence)


def test_wilson_interval():
    low, high = P.wilson_interval(0, 1000)
    assert low == 0.0 and 0 < high < 0.005
    low, high = P.wilson_interval(50, 100)
    assert low < 0.5 < high and high - low == pytest.approx(0.19, abs=0.01)
    with pytest.raises(ValueError):
        P.wilson_interval(5, 0)
    with pytest.raises(ValueError):
        P.wilson_interval(11, 10)


def test_resampling_agrees_with_the_formula():
    rng = np.random.default_rng(0)
    y = np.array([0] * 20_000 + [1] * 5_000)
    flagged = np.concatenate([rng.random(20_000) < 0.01, rng.random(5_000) < 0.8])
    recall, fpr = flagged[y == 1].mean(), flagged[y == 0].mean()
    for prevalence in (0.01, 0.001):
        result = P.resample_at_prevalence(y, flagged, prevalence, rounds=4000, seed=1)
        expected = P.precision_at_prevalence(recall, fpr, prevalence)
        assert result["precision_mean"] == pytest.approx(expected, rel=0.15)
        assert result["precision_low"] < expected < result["precision_high"]
        assert result["phishing_per_sample"] == round(20_000 * prevalence / (1 - prevalence))


def test_resampling_is_deterministic_and_wider_at_low_prevalence():
    y = np.array([0] * 5000 + [1] * 1000)
    flagged = np.zeros(6000, dtype=bool)
    flagged[:50] = True
    flagged[5000:5800] = True
    first = P.resample_at_prevalence(y, flagged, 0.01, rounds=500, seed=3)
    assert first == P.resample_at_prevalence(y, flagged, 0.01, rounds=500, seed=3)
    rare = P.resample_at_prevalence(y, flagged, 0.001, rounds=500, seed=3)

    def relative_width(r):
        return (r["precision_high"] - r["precision_low"]) / r["precision_mean"]

    # Moins de phishing par échantillon : intervalle relatif plus large.
    assert relative_width(rare) > relative_width(first)


def test_resampling_without_any_alert():
    y = np.array([0, 0, 1, 1])
    result = P.resample_at_prevalence(y, np.zeros(4, dtype=bool), 0.1, rounds=10)
    assert math.isnan(result["precision_mean"])
    assert result["rounds_without_alert"] == 10


def test_resampling_validates_its_input():
    with pytest.raises(ValueError, match="deux classes"):
        P.resample_at_prevalence([0, 0], [True, False], 0.1)
    with pytest.raises(ValueError, match="même taille"):
        P.resample_at_prevalence([0, 1], [True], 0.1)
