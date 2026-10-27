"""Tests de la génération des chiffres des model cards (étape 1.12)."""

import importlib.util
import json
import shutil
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("model_cards", ROOT / "scripts" / "model_cards.py")
cards = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cards)

CARDS = ("model-card-url.md", "model-card-text.md", "model-card-email.md")


@pytest.fixture
def workspace(tmp_path):
    docs, metrics = tmp_path / "docs", tmp_path / "docs" / "metrics"
    metrics.mkdir(parents=True)
    for name in CARDS:
        shutil.copy(ROOT / "docs" / name, docs / name)
    readme = tmp_path / "README.md"
    readme.write_bytes((ROOT / "README.md").read_bytes())
    args = ["--metrics-dir", str(metrics), "--docs-dir", str(docs), "--readme", str(readme)]
    return docs, metrics, readme, args


def block(path, name):
    text = path.read_text(encoding="utf-8")
    start, end = f"<!-- generated:{name}:start -->", f"<!-- generated:{name}:end -->"
    return text[text.index(start) + len(start) : text.index(end)]


def test_every_card_and_the_readme_have_their_markers():
    for name, marker in zip(CARDS, ("card-url", "card-text", "card-email"), strict=True):
        assert f"<!-- generated:{marker}:start -->" in (ROOT / "docs" / name).read_text("utf-8")
    assert "<!-- generated:current-results-url:start -->" in (ROOT / "README.md").read_text("utf-8")


def test_missing_reports_give_explicit_placeholders(workspace):
    docs, _, readme, args = workspace
    assert cards.main(args) == 0
    assert "Pas encore généré" in block(docs / "model-card-url.md", "card-url")
    assert "make train-email" in block(docs / "model-card-email.md", "card-email")
    assert "make train-url" in block(readme, "current-results-url")


def test_url_card_uses_the_versioned_reports(workspace):
    docs, metrics, readme, args = workspace
    for name in ("url_v1.json", "url_v1_test.json", "urls_split.json"):
        shutil.copy(ROOT / "docs" / "metrics" / name, metrics / name)
    assert cards.main(args) == 0
    test = json.loads((metrics / "url_v1_test.json").read_text(encoding="utf-8"))
    rendered = block(docs / "model-card-url.md", "card-url")
    assert cards.fr_number(test["test"]["threshold_free"]["pr_auc"]) in rendered
    assert test["decision"]["name"] in rendered and "pages internes" in rendered
    readme_block = block(readme, "current-results-url")
    assert f"{test['test']['threshold_free']['pr_auc']:.3f}" in readme_block
    # Les fins de ligne CRLF du README sont conservées.
    assert b"\r\n" in readme.read_bytes() and b"\n\n" not in readme.read_bytes().replace(
        b"\r\n", b""
    )


def test_text_card_falls_back_on_the_sms_baseline(workspace):
    docs, metrics, _, args = workspace
    shutil.copy(ROOT / "docs" / "metrics" / "sms_baseline.json", metrics / "sms_baseline.json")
    assert cards.main(args) == 0
    rendered = block(docs / "model-card-text.md", "card-text")
    assert "baseline de l'étape 0.7" in rendered and "0,889" in rendered


def test_text_and_email_cards_from_their_reports(workspace):
    docs, metrics, _, args = workspace
    lang = {"n": 60, "precision": 0.8, "recall": 0.7, "fpr": 0.2, "pr_auc": 0.85}
    text = {
        "metadata": {"sms_sha256": "a" * 64},
        "selected": {
            "approach": "char_svm",
            "params": {"C": 0.1},
            "threshold": -0.27,
            "sha256": "b" * 64,
        },
        "approaches": {
            "char_svm": {
                "test": {
                    "n": 774,
                    "precision": 0.9,
                    "recall": 0.98,
                    "fpr": 0.0147,
                    "pr_auc": 0.989,
                },
                "fr_ar": {"fr": lang, "ar": {**lang, "n": 40}},
                "size_bytes": 396_000,
                "latency": {"latency_ms_p50": 0.74},
            }
        },
    }
    (metrics / "text_v1.json").write_text(json.dumps(text), encoding="utf-8")
    point = {"recall": 0.6, "fpr": 0.01, "precision": 0.9}
    email = {
        "dataset": {"blocks": {"test": {"rows": 900, "phishing": 300}}},
        "rules": {"test": {"pr_auc": 0.8}, "suspicious_or_more": point},
        "models": [
            {
                "deployed": True,
                "model": "lightgbm",
                "feature_set": "without_auth",
                "threshold": 0.7,
                "test": {"pr_auc": 0.95},
                "test_at_threshold": point,
            }
        ],
    }
    (metrics / "email_v1.json").write_text(json.dumps(email), encoding="utf-8")
    assert cards.main(args) == 0
    assert "char_svm" in block(docs / "model-card-text.md", "card-text")
    assert "Jeu arabe rédigé" in block(docs / "model-card-text.md", "card-text")
    rendered = block(docs / "model-card-email.md", "card-email")
    assert "without_auth" in rendered and "0,950" in rendered


def test_makefile_has_the_module_1_commands():
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    for target in ("data:", "train:", "test:", "cards:", "collect:"):
        assert f"\n{target}" in makefile
