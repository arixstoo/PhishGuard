"""Tests de la mesure d'apport des features URL (étape 1.5), sur des données synthétiques."""

import importlib.util
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from phishguard.urls import ablation as A
from phishguard.urls.features import FAMILIES, UrlFeatureExtractor
from phishguard.urls.tld import TldRiskTable

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "evaluate_url_features.py"
spec = importlib.util.spec_from_file_location("evaluate_url_features", SCRIPT)
evaluate_script = importlib.util.module_from_spec(spec)
spec.loader.exec_module(evaluate_script)

FAST = A.AblationConfig(n_estimators=10, num_leaves=4)


def synthetic(n: int, seed: int) -> tuple[pd.DataFrame, np.ndarray, np.ndarray]:
    rng = np.random.default_rng(seed)
    urls, labels, sources = [], [], []
    for i in range(n):
        if i % 3 == 0:
            urls.append(f"http://secure-login-{rng.integers(1e6)}.xyz/verify/{i}")
            labels.append(1)
            sources.append("phishtank")
        elif i % 3 == 1:
            urls.append(f"https://site{i}.com/")
            labels.append(0)
            sources.append("tranco")
        else:
            urls.append(f"https://www.site{i}.org/blog/article-{i}")
            labels.append(0)
            sources.append("commoncrawl")
    table = TldRiskTable.fit(["xyz", "com", "org"], [1, 0, 0])
    features = UrlFeatureExtractor(tld_table=table).transform(urls)
    return features, np.array(labels), np.array(sources)


def test_score_report_measures_false_positives_per_page_type():
    y = np.array([0, 0, 0, 0, 1, 1])
    scores = np.array([0.1, 0.2, 0.9, 0.3, 0.8, 0.95])
    sources = np.array(["tranco", "tranco", "commoncrawl", "commoncrawl", "x", "x"])
    report = A.score_report(y, scores, sources, max_fpr=0.25)
    # Seuil = 0,9 (au plus 25 % du légitime au-dessus) : seule la page interne à 0,9 l'atteint.
    assert report["threshold"] == pytest.approx(0.9)
    assert report["fpr_homepages"] == 0.0
    assert report["recall"] == 0.5


def test_run_ablation_covers_every_family_and_group():
    x_train, y_train, _ = synthetic(150, seed=1)
    x_val, y_val, sources_val = synthetic(60, seed=2)
    results = A.run_ablation(x_train, y_train, x_val, y_val, sources_val, FAST)

    assert list(results["families_added"]) == ["+".join(s) for s in A.FAMILY_STEPS]
    assert set(results["families_removed"]) == set(FAMILIES) - {"base"}
    assert set(results["groups_removed"]) == set(A.GROUP_ABLATIONS)
    assert results["groups_removed"]["host_only"]["n_features"] < len(x_train.columns)
    assert set(results["univariate"]) == set(x_train.columns)
    for key in ("pr_auc", "recall_at_fpr_1pct", "fpr_internal_pages"):
        assert key in results["groups_removed"]["all"]


def test_run_ablation_is_deterministic():
    x_train, y_train, _ = synthetic(90, seed=3)
    x_val, y_val, sources_val = synthetic(45, seed=4)
    first = A.run_ablation(x_train, y_train, x_val, y_val, sources_val, FAST)
    second = A.run_ablation(x_train, y_train, x_val, y_val, sources_val, FAST)
    assert first == second


def test_run_ablation_requires_every_feature():
    x_train, y_train, _ = synthetic(30, seed=5)
    with pytest.raises(ValueError, match="absentes"):
        A.run_ablation(x_train.drop(columns="tld_phish_rate"), y_train, x_train, y_train, y_train)


def test_script_never_reads_the_test_block(tmp_path):
    df = pd.DataFrame(
        {
            "url": ["https://a.com/", "http://b.xyz/x", "https://c.com/", "http://d.xyz/y"] * 2,
            "label": [0, 1, 0, 1] * 2,
            "source": ["tranco", "phishtank"] * 4,
            "host": ["a.com", "b.xyz", "c.com", "d.xyz"] * 2,
            "split": ["train"] * 4 + ["validation"] * 2 + ["test"] * 2,
        }
    )
    path = tmp_path / "split.parquet"
    df.to_parquet(path)
    blocks = evaluate_script.load_blocks(path)
    assert set(blocks) == {"train", "validation"}
    assert len(blocks["train"]) == 4 and len(blocks["validation"]) == 2
