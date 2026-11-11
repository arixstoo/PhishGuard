"""Tests du graphique du rapport de robustesse (étape 3.11)."""

import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "plot_robustness", ROOT / "scripts/plot_robustness.py"
)
script = importlib.util.module_from_spec(spec)
spec.loader.exec_module(script)


def entry(rate):
    return {"rate": rate}


def run(recall_shift):
    rows = [
        {"perturbation": "url_subdomains", "recall": entry(0.6 + recall_shift), "fpr": entry(0.05)},
        {
            "perturbation": "url_homoglyphs",
            "recall": entry(0.9),
            "fpr": entry(0.97),
            "creates_lookalike": True,
        },
    ]
    baseline = {"recall": entry(0.7), "fpr": entry(0.01)}
    return {"blocks": {"url": {"baseline": baseline, "perturbations": rows}}}


def test_series_orders_clean_first_and_flags_lookalikes():
    data = script.series({"baseline": run(0.0), "adversarial": run(0.1)}, "url")
    assert data["names"] == ["aucune", "url_subdomains", "url_homoglyphs"]
    assert data["lookalike"] == {"url_homoglyphs"}
    assert data["values"]["adversarial"]["recall"][1] == pytest.approx(0.7)
    assert data["values"]["baseline"]["fpr"][0] == 0.01


def test_fpr_axis_ignores_lookalikes():
    data = script.series({"baseline": run(0.0)}, "url")
    assert script._fpr_limit(data) < 0.2  # 97 % d'imitations ne fixe pas l'échelle


def test_plot_writes_a_png(tmp_path):
    pytest.importorskip("matplotlib")
    for label in ("baseline", "normalization", "adversarial"):
        (tmp_path / f"robustness_{label}.json").write_text(json.dumps(run(0.0)))
    out = tmp_path / "img" / "chart.png"
    assert script.main(["--metrics-dir", str(tmp_path), "--output", str(out)]) == 0
    assert out.read_bytes()[:8] == b"\x89PNG\r\n\x1a\n"


def test_no_runs_is_an_error(tmp_path):
    assert script.main(["--metrics-dir", str(tmp_path), "--output", str(tmp_path / "x.png")]) == 1


def test_report_embeds_the_chart_and_follows_the_plan_structure():
    doc = (ROOT / "docs/robustness-report.md").read_text(encoding="utf-8")
    assert "](img/robustness_by_technique.png)" in doc
    assert (ROOT / "docs/img/robustness_by_technique.png").is_file()
    sections = [
        "## 1. Modèle de menace",
        "## 2. Méthodologie",
        "## 3. Jeux de données",
        "## 4. Résultats avant défenses",
        "## 5. Défenses",
        "## 6. Résultats après défenses",
        "## 7. Phishing rédigé par un LLM",
        "## 8. Limites",
        "## 9. Pistes futures",
    ]
    positions = [doc.index(section) for section in sections]
    assert positions == sorted(positions)
