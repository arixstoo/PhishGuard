"""Tests de la vue analyste du schéma de réponse (étape 3.4)."""

import asyncio
import json
import math

import lightgbm as lgb
import numpy as np
import pytest
from pydantic import ValidationError
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import Pipeline
from sklearn.svm import LinearSVC

from phishguard.analysis import TextAnalyzer, UrlAnalyzer
from phishguard.data.split import read_split_blocks
from phishguard.enrichers import Signal
from phishguard.enrichers.orchestrator import EnrichmentResult
from phishguard.schema import ANALYST_TERMS, SCHEMA_VERSION, AnalysisResponse
from phishguard.text.models import TextModel
from phishguard.urls.features import feature_names
from phishguard.urls.model import UrlModel

PHISHY = "http://secure-paypal-login-42.xyz/verify/account/123456"
COLUMNS = feature_names(families=("base", "brand", "homograph", "shortener"))


@pytest.fixture(scope="module")
def url_model(split_dataset_path) -> UrlModel:
    data = read_split_blocks(split_dataset_path, ("train",), ["url", "label"])["train"]
    estimator = lgb.LGBMClassifier(n_estimators=40, num_leaves=15, verbose=-1, random_state=0)
    model = UrlModel(
        estimator,
        COLUMNS,
        thresholds={"fpr_1pct": 0.6, "fpr_0_5pct": 0.8},
        metadata={"model_version": "url_test"},
    )
    estimator.fit(model.features(data["url"]), data["label"])
    return model


@pytest.fixture(scope="module")
def text_model() -> TextModel:
    texts = [
        "urgent votre compte est bloque cliquez http://verif.example",
        "gagnez un cadeau maintenant sur cadeau.example",
        "a ce soir a la gare",
        "merci pour le diner",
    ] * 10
    labels = np.array([1, 1, 0, 0] * 10)
    pipeline = Pipeline(
        [
            ("representation", TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 4))),
            ("clf", LinearSVC(random_state=0)),
        ]
    ).fit(texts, labels)
    return TextModel(pipeline, "char_svm", threshold=-0.25, metadata={"model_version": "text_t"})


def ok(source, risk, **evidence):
    return Signal(source=source, status="ok", risk=risk, evidence=evidence, latency_ms=10)


class Orchestrator:
    budget_s = 2.5

    def __init__(self, *signals):
        self.signals = signals

    async def enrich(self, url, domain):
        return EnrichmentResult(self.signals, "used", 5, 2500)


def url_response(model, *signals, **options):
    analyzer = UrlAnalyzer(model, orchestrator=Orchestrator(*signals) if signals else None)
    analysis = asyncio.run(analyzer.analyze(PHISHY, enrichment=bool(signals)))
    return analysis, analysis.to_response(**options)


# --------------------------------------------------------------------------- #
# URL
# --------------------------------------------------------------------------- #


def test_url_analyst_view_describes_model_explanation_and_fusion(url_model):
    analysis, response = url_response(url_model)
    analyst = response.analyst
    assert analyst is not None
    assert analyst.model.version == response.model_version == "url_test"
    assert analyst.model.raw_score == pytest.approx(analysis.model_score)
    assert analyst.model.thresholds == {"fpr_1pct": 0.6, "fpr_0_5pct": 0.8}
    assert analyst.fusion.thresholds == {"suspicious": 30, "phishing": 70}

    explanation = analyst.explanation
    assert (explanation.method, explanation.space) == ("tree_shap", "log_odds")
    assert {f.name for f in explanation.features} == set(url_model.feature_names)
    magnitudes = [abs(f.contribution) for f in explanation.features]
    assert magnitudes == sorted(magnitudes, reverse=True)
    total = explanation.base_value + math.fsum(f.contribution for f in explanation.features)
    assert total == pytest.approx(explanation.output, abs=1e-4)
    assert 1 / (1 + math.exp(-explanation.output)) == pytest.approx(analysis.model_score, abs=1e-4)


def test_versions_are_listed(url_model):
    _, response = url_response(url_model, language="en")
    assert response.analyst.versions == {
        "schema": SCHEMA_VERSION,
        "model": "url_test",
        "fusion": response.fusion_version,
        "templates": "en-1",
        "explanation": "tree_shap",
    }


def test_fusion_details_match_the_score(url_model):
    down = Signal(source="urlscan", status="timeout")
    _, response = url_response(url_model, ok("rdap", 1.0, age_days=2), down)
    fusion = response.analyst.fusion
    assert {c.source for c in fusion.contributions} == {"model", "rdap"}
    assert sum(c.points for c in fusion.contributions) == pytest.approx(response.score, abs=0.6)
    assert fusion.ignored == ["urlscan"] and fusion.hard_rule is None


def test_hard_rule_is_visible_to_the_analyst(url_model):
    _, response = url_response(url_model, ok("google_safe_browsing", 1.0))
    assert response.analyst.fusion.hard_rule == "google_safe_browsing"
    assert response.analyst.fusion.contributions == []


def test_analyst_view_can_be_omitted(url_model):
    analysis, _ = url_response(url_model)
    response = analysis.to_response(analyst=False)
    assert response.analyst is None
    assert json.loads(response.to_json())["analyst"] is None


def test_model_without_explanation_still_has_an_analyst_view():
    class Fixed:
        metadata = None

        def score(self, urls):
            return np.array([0.8 for _ in urls])

    analysis = asyncio.run(UrlAnalyzer(Fixed()).analyze(PHISHY))
    analyst = analysis.to_response().analyst
    assert analyst.explanation is None and analyst.versions["explanation"] == "none"
    assert analyst.model.thresholds == {} and analyst.model.calibrated is False


# --------------------------------------------------------------------------- #
# Texte
# --------------------------------------------------------------------------- #


def test_text_analyst_view_lists_terms_both_ways(text_model):
    analysis = TextAnalyzer(text_model).analyze("URGENT : votre compte est bloque, cliquez")
    analyst = analysis.to_response().analyst
    explanation = analyst.explanation
    assert (explanation.method, explanation.space) == ("linear", "margin")
    assert explanation.output == pytest.approx(analysis.model_score, abs=1e-6)
    assert explanation.features == []
    assert 0 < len(explanation.terms_phishing) <= ANALYST_TERMS
    assert all(t.contribution > 0 for t in explanation.terms_phishing)
    assert all(t.contribution < 0 for t in explanation.terms_safe)
    assert analyst.model.thresholds == {"decision": -0.25}


def test_text_terms_are_sanitised(text_model):
    text = "<b>urgent</b> verifiez http://evil.example\u202e maintenant"
    analyst = TextAnalyzer(text_model).analyze(text).to_response().analyst
    shown = [t.term for t in analyst.explanation.terms_phishing + analyst.explanation.terms_safe]
    assert shown and not any(set("<>\"'`&\u202e") & set(term) for term in shown)
    assert not any("http" in term or ".example" in term for term in shown)


# --------------------------------------------------------------------------- #
# Contrat
# --------------------------------------------------------------------------- #


def _payload(url_model, **analyst_overrides):
    _, response = url_response(url_model)
    payload = json.loads(response.to_json())
    for path, value in analyst_overrides.items():
        target = payload["analyst"]
        *parents, leaf = path.split("__")
        for key in parents:
            target = target[key]
        target[leaf] = value
    return payload


@pytest.mark.parametrize(
    "overrides",
    [
        {"model__version": "autre_modele"},  # ne décrit pas le modèle de la réponse
        {"versions__fusion": "9.9.9"},  # ni sa fusion
        {"model__probability": 1.5},
        {"fusion__contributions": [{"source": "x", "risk": 2, "weight": 1, "points": 1}]},
        {"explanation__method": "lime"},
        {"unexpected": 1},
    ],
)
def test_inconsistent_analyst_views_are_rejected(url_model, overrides):
    with pytest.raises(ValidationError):
        AnalysisResponse.model_validate(_payload(url_model, **overrides))


def test_analyst_view_round_trips_through_json(url_model):
    _, response = url_response(url_model, ok("rdap", 1.0, age_days=2))
    assert AnalysisResponse.model_validate_json(response.to_json()) == response


def test_old_clients_can_ignore_the_analyst_view(url_model):
    _, response = url_response(url_model)
    payload = json.loads(response.to_json())
    payload.pop("analyst")
    assert AnalysisResponse.model_validate(payload).analyst is None
