"""Tests du rendu des résultats dans la documentation."""

import pytest

from phishguard import reporting as R

DOC = "Avant\n<!-- generated:demo:start -->\nvieux\n<!-- generated:demo:end -->\nAprès\n"


@pytest.mark.parametrize(
    ("value", "digits", "expected"),
    [(0.95234, 3, "0,952"), (1234.5, 1, "1 234,5"), (None, 3, "n/d"), (float("nan"), 2, "n/d")],
)
def test_fr_number(value, digits, expected):
    assert R.fr_number(value, digits) == expected


def test_fr_percent_and_int():
    assert R.fr_percent(0.0687) == "6,9 %"
    assert R.fr_percent(0.5, 0) == "50 %"
    assert R.fr_int(21007) == "21 007"


def test_markdown_table():
    table = R.markdown_table(["a", "b"], [["x|y", 1]])
    assert table.splitlines() == ["| a | b |", "| :--- | ---: |", "| x\\|y | 1 |"]
    with pytest.raises(ValueError):
        R.markdown_table(["a", "b"], [["x"]])
    with pytest.raises(ValueError):
        R.markdown_table(["a"], [], align=["left", "right"])


def test_replace_generated_block_keeps_hand_written_text():
    out = R.replace_generated_block(DOC, "demo", "nouveau\n")
    assert (
        out == "Avant\n<!-- generated:demo:start -->\nnouveau\n<!-- generated:demo:end -->\nAprès\n"
    )
    assert R.replace_generated_block(out, "demo", "nouveau") == out  # idempotent


@pytest.mark.parametrize(
    "text",
    [
        "pas de marqueur",
        DOC + DOC,
        "<!-- generated:demo:end -->\n<!-- generated:demo:start -->",
    ],
)
def test_replace_generated_block_requires_one_pair_of_markers(text):
    with pytest.raises(R.MissingMarkersError):
        R.replace_generated_block(text, "demo", "x")


def test_block_names_are_restricted():
    with pytest.raises(ValueError):
        R.replace_generated_block(DOC, "Demo -->", "x")


def test_update_generated_block_preserves_line_endings(tmp_path):
    path = tmp_path / "doc.md"
    path.write_bytes(DOC.replace("\n", "\r\n").encode())
    R.update_generated_block(path, "demo", "nouveau")
    data = path.read_bytes().decode()
    assert "nouveau" in data and "vieux" not in data
    assert "\n" not in data.replace("\r\n", "")
    assert data.startswith("Avant\r\n") and data.endswith("Après\r\n")


def test_update_generated_block_reports_changes(tmp_path):
    path = tmp_path / "doc.md"
    path.write_bytes(DOC.encode())
    assert R.update_generated_block(path, "demo", "nouveau") is True
    assert R.update_generated_block(path, "demo", "nouveau") is False
