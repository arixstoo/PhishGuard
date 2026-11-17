"""Score SUS des tests utilisateurs (étape 5.13) : calcul de Brooke, refus des réponses
incomplètes ou nominatives, résumé par groupe et critère de fin (SUS ≥ 70)."""

from __future__ import annotations

import importlib.util
import math
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "sus_score.py"
_spec = importlib.util.spec_from_file_location("sus_score", SCRIPT)
sus = importlib.util.module_from_spec(_spec)
sys.modules["sus_score"] = sus  # dataclasses résout ses annotations par le module
_spec.loader.exec_module(sus)

COLUMNS, SusError, grade, main = sus.COLUMNS, sus.SusError, sus.grade, sus.main
read_responses, summarize, sus_score = sus.read_responses, sus.summarize, sus.sus_score

HEADER = ",".join(COLUMNS)


def write(tmp_path: Path, *rows: str) -> Path:
    path = tmp_path / "sus.csv"
    path.write_text("\n".join([HEADER, *rows]) + "\n", encoding="utf-8")
    return path


@pytest.mark.parametrize(
    ("answers", "expected"),
    [
        ([5, 1, 5, 1, 5, 1, 5, 1, 5, 1], 100.0),  # le meilleur possible
        ([1, 5, 1, 5, 1, 5, 1, 5, 1, 5], 0.0),  # le pire
        ([3] * 10, 50.0),  # neutre partout
        ([4, 2, 4, 2, 4, 2, 4, 2, 4, 2], 75.0),
        ([5, 2, 4, 1, 4, 2, 5, 1, 4, 3], 82.5),  # calculé à la main : (17 + 16) × 2,5
    ],
)
def test_brooke_scoring(answers, expected):
    assert sus_score(answers) == expected


@pytest.mark.parametrize("answers", [[3] * 9, [3] * 11, [0] + [3] * 9, [6] + [3] * 9])
def test_invalid_answers(answers):
    with pytest.raises(SusError):
        sus_score(answers)


def test_grades_of_sauro_and_lewis():
    assert [grade(s) for s in (90, 82, 72.6, 70, 68, 63, 52, 40)] == [
        "A+", "A", "B-", "C", "C", "C-", "D", "F",
    ]  # fmt: skip


def test_group_summary_with_student_interval():
    summary = summarize([70.0, 75.0, 80.0, 85.0, 90.0], "2")
    assert (summary.n, summary.mean, summary.minimum, summary.maximum) == (5, 80.0, 70.0, 90.0)
    # t(0,975 ; 4) = 2,776 ; écart type 7,906 ; demi-largeur 9,82.
    assert summary.ci_low == pytest.approx(70.18, abs=0.01)
    assert summary.ci_high == pytest.approx(89.82, abs=0.01)
    single = summarize([60.0], "1")
    assert math.isnan(single.ci_low) and single.mean == 60.0


@pytest.mark.parametrize(
    ("row", "message"),
    [
        ("Marie Dupont,1,4,2,4,2,4,2,4,2,4,2", "identifiant anonyme"),
        ("P01,1,4,2,4,2,,2,4,2,4,2", "10 réponses"),
        ("P01,1,4,2,4,2,7,2,4,2,4,2", "10 réponses"),
    ],
)
def test_rows_are_refused_not_guessed(tmp_path, row, message):
    with pytest.raises(SusError, match=message):
        read_responses(write(tmp_path, row))


def test_duplicate_participant_and_wrong_columns(tmp_path):
    with pytest.raises(SusError, match="deux fois"):
        read_responses(write(tmp_path, "P01,1" + ",3" * 10, "P01,1" + ",3" * 10))
    path = tmp_path / "bad.csv"
    path.write_text("participant,q1\nP01,3\n", encoding="utf-8")
    with pytest.raises(SusError, match="colonnes"):
        read_responses(path)


def test_cli_reports_and_applies_the_criterion_to_the_last_group(tmp_path, capsys):
    path = write(
        tmp_path,
        "P01,1,3,3,3,3,3,3,3,3,3,3",  # 50
        "P02,1,4,2,4,2,4,2,4,2,4,2",  # 75
        "P03,2,5,1,5,1,5,1,5,1,5,1",  # 100
        "P04,2,4,2,4,2,4,2,4,2,4,2",  # 75
    )
    assert main([str(path), "--min-score", "70"]) == 0  # groupe 2 : 87,5
    out = capsys.readouterr().out
    assert "| 1 | 2 | **62,5** |" in out and "| 2 | 2 | **87,5** |" in out
    assert "Groupe 2 : SUS 87,5 ≥ 70,0" in out
    assert main([str(path), "--group", "1", "--min-score", "70"]) == 1
    assert main([str(path), "--group", "9", "--min-score", "70"]) == 2


def test_cli_fails_cleanly_on_a_bad_file(tmp_path, capsys):
    assert main([str(tmp_path / "absent.csv")]) == 2
    assert "sus_score" in capsys.readouterr().err
