"""Tests du banc d'essai de robustesse (étape 3.7).

Le banc est testé avec un « modèle » transparent : le score est la part de lettres
latines a, e, o dans l'échantillon. Les homoglyphes le font baisser, la dilution aussi :
on sait d'avance ce que le banc doit mesurer.
"""

import importlib.util
import json
from pathlib import Path

import numpy as np
import pytest

from phishguard.adversarial import benchmark as B
from phishguard.adversarial import perturb as P

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "robustness_benchmark", ROOT / "scripts/robustness_benchmark.py"
)
script = importlib.util.module_from_spec(spec)
spec.loader.exec_module(script)

PHISHING = ["aaaa eeee oooo", "aeo aeo aeo aeo", "oooooooo aaaa", "eeee aaaa"]
LEGITIMATE = ["xyz hjk", "bcd fgh tt", "zzzz qq", "mmm nn ae"]
SAMPLES = PHISHING + LEGITIMATE
LABELS = np.array([1] * len(PHISHING) + [0] * len(LEGITIMATE))
THRESHOLD = 0.5


def vowel_score(samples):
    return np.array([sum(c in "aeo" for c in s) / max(1, len(s.replace(" ", ""))) for s in samples])


def run(perturbations=("homoglyphs_full", "pad_benign", "split_symbols")):
    return B.evaluate_perturbations(
        vowel_score, SAMPLES, LABELS, THRESHOLD, list(perturbations), seed=0
    )


def test_baseline_recall_and_fpr():
    result = run()
    assert result["samples"] == {"phishing": 4, "legitimate": 4}
    assert result["baseline"]["recall"]["rate"] == 1.0
    assert result["baseline"]["fpr"]["rate"] == 0.0
    assert result["threshold"] == THRESHOLD and result["seed"] == 0


def test_homoglyphs_evade_a_letter_model():
    row = run()["perturbations"][0]
    assert row["perturbation"] == "homoglyphs_full" and row["technique"] == "TXT-01"
    assert row["recall"]["rate"] == 0.0
    assert row["delta_recall"] == -1.0
    assert row["evaded"] == 4 and row["newly_detected"] == 0
    assert row["changed"]["phishing"]["rate"] == 1.0
    assert row["mean_score_shift"]["phishing"] < 0


def test_unchanged_samples_stay_in_the_measure():
    row = run()["perturbations"][2]  # split_symbols : aucun mot alphabétique de 4 lettres
    assert row["changed"]["legitimate"]["rate"] == 0.25  # seul « zzzz qq » est touché
    assert row["recall"]["n"] == 4 and row["fpr"]["n"] == 4


def test_new_false_positives_are_counted():
    def flag_long(samples):
        return np.array([len(s) > 40 for s in samples], dtype=float)

    result = B.evaluate_perturbations(flag_long, SAMPLES, LABELS, 0.5, ["pad_benign"])
    row = result["perturbations"][0]
    assert row["new_false_positives"] == 4 and row["delta_fpr"] == 1.0
    assert row["newly_detected"] == 4 and row["delta_recall"] == 1.0


def test_wilson_intervals_bracket_the_rate():
    entry = B.rate(np.array([True, False, True, True]))
    assert entry["n"] == 4 and entry["flagged"] == 3 and entry["rate"] == 0.75
    assert entry["low"] < 0.75 < entry["high"]
    assert B.rate(np.array([], dtype=bool))["rate"] is None


def test_worst_perturbation():
    assert B.worst_perturbation(run())["perturbation"] == "homoglyphs_full"
    assert B.worst_perturbation({"perturbations": []}) is None


def test_deterministic():
    assert run() == run()


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"labels": [1, 0]}, "une étiquette"),
        ({"labels": [2] * 8}, "étiquettes"),
        ({"threshold": float("nan")}, "seuil"),
        ({"score": lambda s: np.zeros(3)}, "scores"),
        ({"score": lambda s: np.full(len(s), np.nan)}, "non finis"),
    ],
)
def test_invalid_inputs_are_refused(kwargs, message):
    args = {"score": vowel_score, "labels": LABELS, "threshold": THRESHOLD, **kwargs}
    with pytest.raises(ValueError, match=message):
        B.evaluate_perturbations(
            args["score"], SAMPLES, args["labels"], args["threshold"], ["homoglyphs"]
        )


def test_unknown_perturbation_is_refused():
    with pytest.raises(KeyError):
        B.evaluate_perturbations(vowel_score, SAMPLES, LABELS, THRESHOLD, ["nope"])


# --------------------------------------------------------------------------- #
# Script : rendu et comparaison des passages
# --------------------------------------------------------------------------- #


def report(label, recall_drop=0.0):
    result = run()
    result["perturbations"][0]["recall"]["rate"] += recall_drop
    result["threshold_name"] = "decision"
    result["model"] = {"version": "text_test", "sha256": "0" * 64}
    return {
        "report_version": script.REPORT_VERSION,
        "metadata": {
            "generated_at": "2026-11-09T00:00:00+00:00",
            "label": label,
            "description": f"passage {label}",
            "seed": 0,
        },
        "blocks": {"sms": result},
    }


def test_render_run_lists_every_perturbation_without_samples():
    text = script.render_run(report("baseline"))
    assert "#### SMS (test UCI, anglais)" in text
    assert "4 spams et 4 légitimes" in text
    for name in ("homoglyphs_full", "pad_benign", "split_symbols"):
        assert f"`{name}`" in text
    assert "**−100,0 pts**" in text
    assert "Pire perturbation : `homoglyphs_full`" in text
    for sample in SAMPLES:
        assert sample not in text  # aucun échantillon dans le rapport


def test_signed_points():
    assert script._signed_points(-0.125) == "−12,5 pts"
    assert script._signed_points(0.0483, 2) == "+4,83 pts"
    assert script._signed_points(0.0) == "±0,0 pts"
    assert script._signed_points(None) == "n/d"


def test_comparison_orders_runs_and_aligns_rows(tmp_path):
    for label in ("zeta", "normalization", "baseline"):
        path = tmp_path / f"robustness_{label}.json"
        path.write_text(json.dumps(report(label, 0.5 if label != "baseline" else 0.0)))
    runs = script.load_runs(tmp_path)
    assert list(runs) == ["baseline", "normalization", "zeta"]
    text = script.render_comparison(runs)
    header = next(line for line in text.splitlines() if line.startswith("| Perturbation"))
    assert header.count("Rappel `") == 3
    row = next(line for line in text.splitlines() if "`homoglyphs_full`" in line)
    assert row.split(" | ")[1:3] == ["0,0 %", "0,00 %"]  # baseline : tout le phishing passe
    assert row.split(" | ")[3] == "50,0 %"


def test_cli_rejects_bad_labels():
    with pytest.raises(SystemExit):
        script.parse_args(["--label", "Bad Label"])
    assert script.parse_args(["--label", "normalization", "--doc", "none"]).doc is None


def test_report_document_has_both_blocks():
    doc = (ROOT / "docs/robustness-report.md").read_text(encoding="utf-8")
    for block in ("robustness-baseline", "robustness-comparison"):
        assert doc.count(f"<!-- generated:{block}:start -->") == 1


def test_every_perturbation_has_a_catalog_entry():
    catalog = (ROOT / "docs/evasion-catalog.md").read_text(encoding="utf-8")
    for name in P.PERTURBATIONS:
        assert f"`{name}`" in catalog
