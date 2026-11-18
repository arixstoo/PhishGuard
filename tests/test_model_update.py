"""Garde-fou de non-régression et test figé (étape 6.8)."""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path
from urllib.parse import urlsplit

import numpy as np
import pandas as pd
import pytest

from phishguard import model_update as M


class FakeModel:
    """Score = table fixe par URL ; ``predict`` : score > 0,5."""

    def __init__(self, scores: dict[str, float]) -> None:
        self.scores = scores

    def score(self, urls: Iterable[str]) -> np.ndarray:
        return np.array([self.scores.get(u, 0.0) for u in urls])

    def predict(self, urls: Iterable[str]) -> np.ndarray:
        return self.score(urls) > 0.5


def frame(rows: list[tuple[str, int]]) -> pd.DataFrame:
    return pd.DataFrame(
        {
            "url": [u for u, _ in rows],
            "label": [lab for _, lab in rows],
            "source": ["phishtank" if lab else "tranco" for _, lab in rows],
            "first_seen": pd.Timestamp("2026-10-01", tz="UTC"),
            "registered_domain": [urlsplit(u).hostname for u, _ in rows],
        }
    )


TEST = frame(
    [(f"https://phish{i}.example/login", 1) for i in range(10)]
    + [(f"https://legit{i}.example/", 0) for i in range(200)]
)
LEGIT = ["https://accounts.google.com/signin", "https://www.paypal.com/signin"]


def evaluation(recall: float, recent: float, fps: tuple[str, ...] = ()) -> M.ModelEvaluation:
    return M.ModelEvaluation("url_v2", recall, recent, fps)


# --------------------------------------------------------------------------- #
# Décision
# --------------------------------------------------------------------------- #


def test_identical_models_pass() -> None:
    same = evaluation(0.75, 0.70, ("https://a.example/",))
    decision = M.decide(same, same)
    assert decision.passed
    assert all(c.passed for c in decision.checks)


@pytest.mark.parametrize(
    ("candidate", "failed"),
    [
        (evaluation(0.749, 0.70), "recall_at_fpr_1pct_frozen"),
        (evaluation(0.75, 0.699), "recall_at_fpr_1pct_recent"),
        (evaluation(0.80, 0.80, ("https://b.example/",)), "legitimate_false_positives"),
    ],
)
def test_any_regression_blocks_publication(candidate: M.ModelEvaluation, failed: str) -> None:
    decision = M.decide(evaluation(0.75, 0.70), candidate)
    assert not decision.passed
    assert [c.name for c in decision.checks if not c.passed] == [failed]


def test_better_recall_does_not_buy_more_false_positives() -> None:
    """Le cas réel url_v1 contre url_v2 : plus de rappel, mais des pages de connexion signalées."""
    current = evaluation(0.668, 0.668, ("https://x.example/",))
    candidate = evaluation(0.755, 0.755, ("https://x.example/", "https://www.paypal.com/signin"))
    decision = M.decide(current, candidate)
    assert not decision.passed
    assert decision.new_false_positives == ("https://www.paypal.com/signin",)


def test_tolerance_is_explicit_and_bounded() -> None:
    current, candidate = evaluation(0.75, 0.70), evaluation(0.745, 0.70)
    assert not M.decide(current, candidate).passed
    assert M.decide(current, candidate, recall_tolerance=0.01).passed
    with pytest.raises(ValueError):
        M.decide(current, candidate, recall_tolerance=0.2)
    with pytest.raises(ValueError):
        M.decide(current, candidate, recall_tolerance=float("nan"))


def test_floating_point_noise_is_not_a_regression() -> None:
    assert M.decide(evaluation(0.1 + 0.2, 0.5), evaluation(0.3, 0.5)).passed


# --------------------------------------------------------------------------- #
# Évaluation
# --------------------------------------------------------------------------- #


def test_evaluate_model_measures_recall_and_legitimate_false_positives() -> None:
    scores = {u: 0.9 for u in TEST.loc[TEST.label == 1, "url"]} | {LEGIT[1]: 0.8}
    result = M.evaluate_model(
        FakeModel(scores), model_version="url_v2", frozen=TEST, recent=TEST, legitimate_urls=LEGIT
    )
    assert result.recall_frozen == pytest.approx(1.0)
    assert result.recall_recent == pytest.approx(1.0)
    assert result.legitimate_false_positives == (LEGIT[1],)


def test_evaluation_needs_both_classes() -> None:
    only_legit = TEST[TEST.label == 0]
    with pytest.raises(ValueError, match="deux classes"):
        M.evaluate_model(
            FakeModel({}), model_version="v", frozen=only_legit, recent=TEST, legitimate_urls=LEGIT
        )


def test_report_and_markdown_have_no_dataset_urls() -> None:
    current, candidate = evaluation(0.7, 0.7), evaluation(0.6, 0.7, (LEGIT[0],))
    decision = M.decide(current, candidate)
    report = M.gate_report(
        decision, current, candidate, frozen_rows=210, recent_rows=210, legitimate_rows=2
    )
    assert report["passed"] is False
    assert report["new_false_positives"] == [LEGIT[0]]
    text = M.render_markdown(report)
    assert "refusé" in text and LEGIT[0] in text
    assert "phish0.example" not in text  # seules les URLs de la liste publique apparaissent


# --------------------------------------------------------------------------- #
# Test figé
# --------------------------------------------------------------------------- #


@pytest.fixture
def split_file(tmp_path: Path) -> Path:
    data = pd.concat(
        [
            TEST.assign(split="test"),
            frame([("https://train.example/", 0), ("https://t.example/x", 1)]).assign(
                split="train"
            ),
        ]
    )
    path = tmp_path / "urls_split.parquet"
    data.to_parquet(path, index=False)
    return path


def test_freeze_keeps_only_the_test_block_and_round_trips(split_file: Path, tmp_path: Path) -> None:
    out = tmp_path / "frozen.parquet"
    report = M.freeze_test_set(split_file, out)
    assert report["rows"] == len(TEST) and report["phishing"] == 10
    assert "url" not in report and "registered_domain" not in report["sources"]
    frozen = M.load_frozen_test_set(out, report["content_sha256"])
    assert set(frozen["url"]) == set(TEST["url"])


def test_frozen_set_refuses_any_modification(split_file: Path, tmp_path: Path) -> None:
    out = tmp_path / "frozen.parquet"
    report = M.freeze_test_set(split_file, out)
    tampered = pd.read_parquet(out)
    tampered.loc[0, "label"] = 1 - tampered.loc[0, "label"]
    tampered.to_parquet(out, index=False)
    with pytest.raises(ValueError, match="test figé modifié"):
        M.load_frozen_test_set(out, report["content_sha256"])


def test_frozen_hash_ignores_row_order(split_file: Path, tmp_path: Path) -> None:
    out = tmp_path / "frozen.parquet"
    report = M.freeze_test_set(split_file, out)
    pd.read_parquet(out).iloc[::-1].to_parquet(out, index=False)
    M.load_frozen_test_set(out, report["content_sha256"])


def test_frozen_domains_never_reach_training() -> None:
    dataset = pd.concat(
        [TEST, frame([("https://new.example/a", 1), ("https://phish3.example/other", 1)])]
    )
    kept, removed = M.exclude_frozen_domains(dataset, TEST)
    assert removed == len(TEST) + 1  # phish3.example a une autre URL : retirée aussi
    assert list(kept["url"]) == ["https://new.example/a"]


# --------------------------------------------------------------------------- #
# Liste des sites légitimes courants
# --------------------------------------------------------------------------- #


def test_legitimate_urls_are_https_unique_and_numerous() -> None:
    urls = M.load_legitimate_urls()
    assert len(urls) >= 100
    assert len(set(urls)) == len(urls)
    for url in urls:
        parts = urlsplit(url)
        assert parts.scheme == "https" and parts.hostname, url
        assert not parts.query and not parts.fragment and not parts.username, url
