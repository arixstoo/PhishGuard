"""Tests des explications SHAP du modèle URL (étape 3.1)."""

import importlib.util
import json
import math
from pathlib import Path

import lightgbm as lgb
import numpy as np
import pytest
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression

from phishguard.data.split import read_split_blocks
from phishguard.explain import shap_url as S
from phishguard.urls.features import feature_names
from phishguard.urls.model import UrlModel

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "explain_url.py"
spec = importlib.util.spec_from_file_location("explain_url", SCRIPT)
explain_url = importlib.util.module_from_spec(spec)
spec.loader.exec_module(explain_url)

# Sans la famille « tld » : pas de table des TLD à apprendre pour ces tests.
COLUMNS = feature_names(families=("base", "brand", "homograph", "shortener"))
URLS = [
    "http://secure-paypal-login-1.xyz/verify/account?id=42",
    "https://alpha.com/",
    "https://www.nova.org/blog/post",
    "http://203.0.113.7/login",
]


def train(estimator, dataset: Path) -> UrlModel:
    data = read_split_blocks(dataset, ("train",), ["url", "label"])["train"]
    model = UrlModel(estimator, COLUMNS, thresholds={"fpr_1pct": 0.5})
    estimator.fit(model.features(data["url"]), data["label"])
    return model


@pytest.fixture(scope="module")
def lgbm_model(split_dataset_path) -> UrlModel:
    estimator = lgb.LGBMClassifier(n_estimators=40, num_leaves=15, verbose=-1, random_state=0)
    return train(estimator, split_dataset_path)


@pytest.fixture(scope="module")
def forest_model(split_dataset_path) -> UrlModel:
    estimator = RandomForestClassifier(n_estimators=20, max_depth=6, random_state=0)
    return train(estimator, split_dataset_path)


# --------------------------------------------------------------------------- #
# Formes des valeurs SHAP
# --------------------------------------------------------------------------- #

N, F = 4, 3
VALUES = np.arange(N * F, dtype=float).reshape(N, F)


def test_normalize_accepts_a_single_matrix():
    values, base = S.normalize_shap_values(VALUES, -1.5, n_rows=N, n_features=F)
    assert np.array_equal(values, VALUES) and base == -1.5


def test_normalize_takes_the_phishing_class_from_a_list():
    values, base = S.normalize_shap_values(
        [-VALUES, VALUES], np.array([0.7, 0.3]), n_rows=N, n_features=F
    )
    assert np.array_equal(values, VALUES) and base == 0.3


def test_normalize_takes_the_phishing_class_from_a_3d_array():
    stacked = np.stack([-VALUES, VALUES], axis=2)  # (n, f, classes)
    values, base = S.normalize_shap_values(stacked, [0.6, 0.4], n_rows=N, n_features=F)
    assert np.array_equal(values, VALUES) and base == 0.4


def test_normalize_splits_the_base_column_of_pred_contrib():
    contrib = np.hstack([VALUES, np.full((N, 1), -2.0)])
    values, base = S.normalize_shap_values(contrib, None, n_rows=N, n_features=F)
    assert np.array_equal(values, VALUES) and base == -2.0


@pytest.mark.parametrize(
    "values, expected",
    [
        (np.zeros((N, F + 2)), 0.0),  # trop de colonnes
        (np.zeros((N - 1, F)), 0.0),  # mauvais nombre de lignes
        (np.zeros((N, F, 3)), 0.0),  # trois classes
        ([np.zeros((N, F))] * 3, 0.0),  # trois tableaux
        (np.zeros(N), 0.0),  # une seule dimension
        (np.zeros((N, F)), [0.1, 0.2, 0.3]),  # trois valeurs de base
    ],
)
def test_normalize_rejects_unexpected_shapes(values, expected):
    with pytest.raises(ValueError):
        S.normalize_shap_values(values, expected, n_rows=N, n_features=F)


def test_normalize_rejects_a_base_column_that_varies():
    contrib = np.hstack([VALUES, np.arange(N, dtype=float)[:, None]])
    with pytest.raises(ValueError, match="valeur de base"):
        S.normalize_shap_values(contrib, None, n_rows=N, n_features=F)


# --------------------------------------------------------------------------- #
# Explications du modèle LightGBM
# --------------------------------------------------------------------------- #


def test_contributions_add_up_to_the_model_output(lgbm_model):
    explanations = S.UrlExplainer(lgbm_model).explain(URLS)
    raw = lgbm_model.estimator.predict(lgbm_model.features(URLS), raw_score=True)
    for explanation, expected_raw, score in zip(
        explanations, raw, lgbm_model.score(URLS), strict=True
    ):
        assert explanation.raw_score == pytest.approx(expected_raw, abs=1e-9)
        assert explanation.probability == pytest.approx(score, abs=1e-9)
        assert explanation.backend == "lightgbm" and explanation.space == "log_odds"


def test_attributions_follow_the_model_feature_order(lgbm_model):
    explanation = S.UrlExplainer(lgbm_model).explain_one(URLS[0])
    assert tuple(a.name for a in explanation.attributions) == lgbm_model.feature_names
    features = lgbm_model.features([URLS[0]]).iloc[0]
    assert all(a.value == features[a.name] for a in explanation.attributions)


# shap prévient que sa sortie pour LightGBM a changé de forme : c'est ce que l'on teste.
@pytest.mark.filterwarnings("ignore:LightGBM binary classifier:UserWarning")
def test_native_values_match_the_shap_library(lgbm_model):
    shap = pytest.importorskip("shap")
    x = lgbm_model.features(URLS)
    native, native_base = S.UrlExplainer(lgbm_model).shap_values(x)
    tree = shap.TreeExplainer(lgbm_model.estimator)
    library, library_base = S.normalize_shap_values(
        tree.shap_values(x), tree.expected_value, n_rows=len(x), n_features=x.shape[1]
    )
    assert np.allclose(native, library, atol=1e-9)
    assert native_base == pytest.approx(library_base)


def test_explainer_reads_only_the_model_columns(lgbm_model):
    x = lgbm_model.features(URLS).assign(extra=1.0)
    values, _ = S.UrlExplainer(lgbm_model).shap_values(x[["extra", *lgbm_model.feature_names]])
    assert values.shape == (len(URLS), len(lgbm_model.feature_names))


# --------------------------------------------------------------------------- #
# Autres modèles
# --------------------------------------------------------------------------- #


def test_forest_is_explained_by_shap_in_probability_space(forest_model):
    pytest.importorskip("shap")
    explainer = S.UrlExplainer(forest_model)
    assert (explainer.backend, explainer.space) == ("shap", "probability")
    for explanation, score in zip(explainer.explain(URLS), forest_model.score(URLS), strict=True):
        assert explanation.probability == pytest.approx(score, abs=1e-6)


def test_native_backend_refuses_a_non_lightgbm_model(forest_model):
    with pytest.raises(S.UnsupportedModelError):
        S.UrlExplainer(forest_model, backend="lightgbm")


def test_linear_model_is_not_supported(split_dataset_path):
    model = train(LogisticRegression(max_iter=500), split_dataset_path)
    with pytest.raises(S.UnsupportedModelError):
        S.UrlExplainer(model)


def test_missing_shap_library_is_reported(forest_model, monkeypatch):
    import builtins

    real_import = builtins.__import__

    def without_shap(name, *args, **kwargs):
        if name == "shap":
            raise ImportError("pas de shap")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", without_shap)
    with pytest.raises(S.UnsupportedModelError, match="explain"):
        S.UrlExplainer(forest_model)


# --------------------------------------------------------------------------- #
# Classement des raisons
# --------------------------------------------------------------------------- #


def explanation_of(**contributions: float) -> S.UrlExplanation:
    return S.UrlExplanation(
        base_value=-1.0,
        attributions=tuple(S.FeatureAttribution(n, 1.0, v) for n, v in contributions.items()),
    )


def test_top_ranks_the_strongest_phishing_contributions():
    e = explanation_of(a=0.2, b=1.5, c=-3.0, d=0.9, e=0.0)
    assert [a.name for a in e.top(3)] == ["b", "d", "a"]
    assert [a.name for a in e.top(3, direction="safe")] == ["c"]


def test_top_keeps_only_contributions_of_the_requested_sign():
    e = explanation_of(a=-0.5, b=-0.1)
    assert e.top(3) == ()


def test_top_breaks_ties_alphabetically():
    e = explanation_of(zeta=1.0, alpha=1.0, mid=1.0)
    assert [a.name for a in e.top(2)] == ["alpha", "mid"]


def test_top_validates_n():
    e = explanation_of(a=1.0)
    assert e.top(0) == ()
    with pytest.raises(ValueError):
        e.top(-1)


def test_probability_is_the_sigmoid_of_the_raw_score():
    e = explanation_of(a=1.0, b=0.5)
    assert e.raw_score == pytest.approx(0.5)
    assert e.probability == pytest.approx(1 / (1 + math.exp(-0.5)))


def test_to_dict_is_json_serializable(lgbm_model):
    payload = S.UrlExplainer(lgbm_model).explain_one(URLS[0]).to_dict()
    assert json.loads(json.dumps(payload))["space"] == "log_odds"
    assert len(payload["features"]) == len(lgbm_model.feature_names)


def test_global_importance_ranks_by_mean_absolute_value():
    values = np.array([[1.0, -4.0, 0.0], [-3.0, 2.0, 0.0]])
    assert S.global_importance(values, ["a", "b", "c"]) == [("b", 3.0), ("a", 2.0), ("c", 0.0)]
    with pytest.raises(ValueError):
        S.global_importance(values, ["a", "b"])


# --------------------------------------------------------------------------- #
# Script
# --------------------------------------------------------------------------- #


def test_pick_examples_varies_the_first_reason():
    explanations = [explanation_of(a=2.0, b=1.0)] * 6 + [explanation_of(b=2.0)] * 2
    explanations += [explanation_of(c=2.0)]
    candidates = list(range(len(explanations)))
    picked = explain_url.pick_examples(candidates, explanations, 3, seed=0)
    assert len(set(picked)) == 3
    assert {explanations[i].top(1)[0].name for i in picked} == {"a", "b", "c"}


def test_pick_examples_returns_fewer_when_candidates_run_out():
    explanations = [explanation_of(a=1.0)] * 2
    assert len(explain_url.pick_examples([0, 1], explanations, 5, seed=0)) == 2


def test_script_explains_the_validation_block(split_dataset_path, lgbm_model):
    validation = read_split_blocks(split_dataset_path, ("validation",), ["url", "label", "source"])[
        "validation"
    ]
    report, values, x = explain_url.explain(lgbm_model, validation, sample=50, examples=4, seed=0)
    assert values.shape == (50, len(lgbm_model.feature_names)) == x.shape
    assert next(i["feature"] for i in report["global_importance"]) in lgbm_model.feature_names
    assert len(report["examples"]) <= 4
    for example in report["examples"]:
        assert example["url"].startswith("hxxp")  # défangée
        assert example["source"] in explain_url.PUBLISHABLE_SOURCES
        assert 1 <= len(example["top"]) <= 3


def test_script_writes_report_and_doc(split_dataset_path, lgbm_model, tmp_path):
    model_path = lgbm_model.save(tmp_path / "url.joblib")
    doc = tmp_path / "explain.md"
    doc.write_text(
        "# Titre\n\n<!-- generated:explain-url:start -->\n<!-- generated:explain-url:end -->\n",
        "utf-8",
    )
    report = tmp_path / "shap.json"
    code = explain_url.main(
        [
            "--dataset",
            str(split_dataset_path),
            "--model",
            str(model_path),
            "--sample",
            "40",
            "--examples",
            "3",
            "--report",
            str(report),
            "--doc",
            str(doc),
            "--plot",
            "none",
        ]
    )
    assert code == 0
    payload = json.loads(report.read_text("utf-8"))
    assert payload["metadata"]["split"] == "validation"
    assert payload["metadata"]["sample_rows"] == 40
    text = doc.read_text("utf-8")
    assert "Importance globale" in text and "| Rang |" in text


def test_script_saves_the_summary_plot(split_dataset_path, lgbm_model, tmp_path):
    pytest.importorskip("shap")
    pytest.importorskip("matplotlib")
    model_path = lgbm_model.save(tmp_path / "url.joblib")
    plot = tmp_path / "img" / "summary.png"
    code = explain_url.main(
        [
            "--dataset",
            str(split_dataset_path),
            "--model",
            str(model_path),
            "--sample",
            "30",
            "--examples",
            "2",
            "--report",
            str(tmp_path / "shap.json"),
            "--doc",
            "none",
            "--plot",
            str(plot),
        ]
    )
    assert code == 0
    assert plot.read_bytes()[:8] == b"\x89PNG\r\n\x1a\n"


def test_script_reports_missing_inputs(tmp_path):
    assert explain_url.main(["--dataset", str(tmp_path / "absent.parquet")]) == 1
