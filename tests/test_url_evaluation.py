"""Tests de l'évaluation réaliste du modèle URL (étape 1.7)."""

import importlib.util
import json
import math
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from phishguard.urls import evaluation as E

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"


def load_script(name):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


evaluate_script = load_script("evaluate_url")
train_script = load_script("train_url")

DOC = "# Éval\n\n<!-- generated:evaluate-url:start -->\n<!-- generated:evaluate-url:end -->\n"

Y = np.array([0, 0, 0, 0, 0, 0, 1, 1, 1, 1])
SCORES = np.array([0.1, 0.2, 0.3, 0.9, 0.4, 0.95, 0.8, 0.85, 0.99, 0.2])
SOURCES = np.array(["tranco"] * 4 + ["commoncrawl"] * 2 + ["phishtank"] * 3 + ["openphish"])


def test_operating_point_splits_false_positives_by_page_type():
    point = E.operating_point(Y, SCORES, SOURCES, threshold=0.5)
    assert point["recall"]["flagged"] == 3 and point["recall"]["n"] == 4
    assert point["fpr"]["rate"] == pytest.approx(2 / 6)
    assert point["fpr_homepages"]["rate"] == pytest.approx(1 / 4)
    assert point["fpr_internal_pages"]["rate"] == pytest.approx(1 / 2)
    assert point["fpr"]["low"] < point["fpr"]["rate"] < point["fpr"]["high"]


def test_operating_point_uses_a_strict_threshold():
    point = E.operating_point(Y, SCORES, SOURCES, threshold=0.9)
    assert point["fpr_homepages"]["flagged"] == 0  # 0,9 n'est pas > 0,9


def test_operating_point_without_internal_pages():
    point = E.operating_point(Y[:4], SCORES[:4], SOURCES[:4], 0.5)
    assert point["fpr_internal_pages"]["n"] == 0
    assert math.isnan(point["fpr_internal_pages"]["rate"])


def point(recall, fpr):
    return {"recall": {"rate": recall}, "fpr": {"rate": fpr}}


def test_decision_takes_the_best_recall_meeting_the_precision_target():
    # À 1 % de prévalence, précision >= 50 % ⇔ FPR <= 0,0101 × rappel.
    points = {
        "fpr_5pct": point(0.95, 0.05),
        "fpr_0_5pct": point(0.85, 0.005),
        "fpr_0_1pct": point(0.60, 0.001),
    }
    decision = E.choose_decision_threshold(points)
    assert decision["name"] == "fpr_0_5pct"
    assert decision["meets_target"]
    assert decision["validation_precision_at_prevalence"] >= 0.5


def test_decision_falls_back_to_the_most_precise_threshold():
    points = {"fpr_5pct": point(0.95, 0.05), "fpr_1pct": point(0.9, 0.01)}
    decision = E.choose_decision_threshold(points)
    assert decision["name"] == "fpr_1pct"
    assert not decision["meets_target"]
    with pytest.raises(ValueError):
        E.choose_decision_threshold({})


def test_prevalence_table_has_both_legitimate_hypotheses():
    rows = E.prevalence_table(Y, SCORES, SOURCES, 0.5, rounds=200)
    assert [r["prevalence"] for r in rows] == [0.01, 0.001]
    for row in rows:
        assert row["precision_internal_pages"] <= row["precision"] + 1e-12  # FPR interne plus haut
        assert row["per_10k_false_per_true"] > 0
        assert set(row["precision_resampled"]) >= {"precision_low", "precision_high"}


def test_per_source():
    result = E.per_source(Y, SCORES, SOURCES, 0.5)
    assert result["openphish"] == result["openphish"] | {"metric": "recall", "flagged": 0, "n": 1}
    assert result["tranco"]["metric"] == "fpr"
    assert result["phishtank"]["rate"] == 1.0


def test_tranco_ranks_and_popularity(tmp_path):
    path = tmp_path / "tranco_abc_100_x.csv"
    path.write_text(
        "1,google.com\n2,Example.org\n5000,rare.net\n250000,tail.org\nbad,line\n", encoding="utf-8"
    )
    ranks = E.read_tranco_ranks(path)
    assert ranks == {"google.com": 1, "example.org": 2, "rare.net": 5000, "tail.org": 250000}

    report = E.popularity_report(
        ["google.com", "example.org", "rare.net", "tail.org", "unknown.io"],
        np.array([0.1, 0.9, 0.9, 0.9, 0.1]),
        0.5,
        ranks,
    )
    assert report["1-1000"]["n"] == 2 and report["1-1000"]["flagged"] == 1
    assert report["1001-10000"]["rate"] == 1.0
    assert report["100001+"]["n"] == 1 and report["100001+"]["flagged"] == 1
    assert report["unranked"]["n"] == 1
    # Chaque domaine est compté dans une seule tranche, y compris au-delà de 100 000.
    assert sum(bucket["n"] for bucket in report.values()) == 5
    with pytest.raises(ValueError):
        E.popularity_report(["a.com"], np.array([0.1, 0.2]), 0.5, ranks)


def _dataset_report(tmp_path, files):
    """Rapport de jeu minimal : ``files`` = [(nom, contenu, date de collecte)]."""
    inputs = [{"source": "phishtank", "file": "phishtank_x.csv", "collected_at": "2026-10-01"}]
    for name, content, collected_at in files:
        (tmp_path / name).write_text(content, encoding="utf-8")
        sha = E.sha256_file(tmp_path / name)
        inputs.append(
            {"source": "tranco", "file": name, "sha256": sha, "collected_at": collected_at}
        )
    report = tmp_path / "urls_dataset.json"
    report.write_text(json.dumps({"inputs": inputs}), encoding="utf-8")
    return report


def test_dataset_tranco_files_come_from_the_dataset_report(tmp_path):
    # Listés dans le désordre : triés par date de collecte, pas par nom ni par mtime.
    report = _dataset_report(
        tmp_path,
        [("tranco_B.csv", "1,b.com\n", "2026-10-23"), ("tranco_A.csv", "1,a.com\n", "2026-10-22")],
    )
    # Une liste plus récente collectée après la construction du jeu est ignorée.
    (tmp_path / "tranco_C.csv").write_text("1,c.com\n", encoding="utf-8")
    files = E.dataset_tranco_files(report, tmp_path)
    assert [p.name for p in files] == ["tranco_A.csv", "tranco_B.csv"]
    assert E.dataset_tranco_files(tmp_path / "absent.json", tmp_path) == []


def test_dataset_tranco_files_need_every_file_with_its_fingerprint(tmp_path):
    report = _dataset_report(
        tmp_path,
        [("tranco_A.csv", "1,a.com\n", "2026-10-22"), ("tranco_B.csv", "1,b.com\n", "2026-10-23")],
    )
    (tmp_path / "tranco_B.csv").write_text("1,changed.com\n", encoding="utf-8")
    with pytest.raises(ValueError, match="empreinte"):
        E.dataset_tranco_files(report, tmp_path)
    (tmp_path / "tranco_B.csv").unlink()
    assert E.dataset_tranco_files(report, tmp_path) == []


def test_merge_tranco_ranks_prefers_the_most_recent_list(tmp_path):
    old, new = tmp_path / "old.csv", tmp_path / "new.csv"
    old.write_text("1,a.com\n2,gone.com\n", encoding="utf-8")
    new.write_text("5,a.com\n", encoding="utf-8")
    assert E.merge_tranco_ranks([old, new]) == {"a.com": 5, "gone.com": 2}


# --------------------------------------------------------------------------- #
# Script
# --------------------------------------------------------------------------- #


@pytest.fixture(scope="module")
def trained_model(split_dataset_path, tmp_path_factory):
    out = tmp_path_factory.mktemp("model")
    model = out / "url_v1.joblib"
    args = ["--dataset", str(split_dataset_path), "--model-out", str(model)]
    args += ["--report", str(out / "url_v1.json"), "--doc", "none", "--quick"]
    assert train_script.main(args) == 0
    return model


def test_script_end_to_end(tmp_path, split_dataset_path, trained_model):
    doc, report_path = tmp_path / "evaluation.md", tmp_path / "url_v1_test.json"
    doc.write_text(DOC, encoding="utf-8")
    df = pd.read_parquet(split_dataset_path)
    tranco = tmp_path / "tranco_x_100_y.csv"
    homepages = df.loc[df["source"] == "tranco", "registered_domain"].unique()
    tranco.write_text("".join(f"{i + 1},{d}\n" for i, d in enumerate(homepages)), encoding="utf-8")

    args = ["--dataset", str(split_dataset_path), "--model", str(trained_model)]
    args += ["--report", str(report_path), "--doc", str(doc), "--tranco", str(tranco)]
    args += ["--rounds", "200"]
    assert evaluate_script.main(args) == 0

    text = report_path.read_text(encoding="utf-8")
    assert "NaN" not in text and "Infinity" not in text  # JSON strict
    report = json.loads(text)
    assert report["metadata"]["splits_used"] == ["validation", "test"]
    assert report["decision"]["name"] in report["test"]["operating_points"]
    assert set(report["test"]["prevalence"]) == set(report["test"]["operating_points"])
    assert report["test"]["popularity"]["buckets"]["1-1000"]["n"] > 0
    assert report["test"]["popularity"]["tranco_files"] == [tranco.name]
    assert not any(host in text for host in df["host"].unique())

    rendered = doc.read_text(encoding="utf-8")
    assert "**(décision)**" in rendered
    assert "Prévalence et précision" in rendered and "1 à 1 000" in rendered


def test_script_without_tranco_list(tmp_path, split_dataset_path, trained_model):
    report_path = tmp_path / "report.json"
    args = ["--dataset", str(split_dataset_path), "--model", str(trained_model)]
    args += ["--report", str(report_path), "--doc", "none", "--raw-dir", str(tmp_path)]
    args += ["--dataset-report", str(tmp_path / "absent.json"), "--rounds", "50"]
    assert evaluate_script.main(args) == 0
    assert "popularity" not in json.loads(report_path.read_text(encoding="utf-8"))["test"]


def test_script_reports_missing_inputs(tmp_path, split_dataset_path):
    absent = str(tmp_path / "absent")
    assert evaluate_script.main(["--dataset", absent, "--doc", "none"]) == 1
    args = ["--dataset", str(split_dataset_path), "--model", absent, "--doc", "none"]
    assert evaluate_script.main(args) == 1


def test_clean_replaces_non_finite_numbers():
    assert evaluate_script.clean({"a": [math.nan, 1.0, math.inf], "b": (2,)}) == {
        "a": [None, 1.0, None],
        "b": [2],
    }
