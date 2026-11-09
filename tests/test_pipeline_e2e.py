"""Tests de bout en bout du pipeline principal (étape 3.12).

URL, message et email, de l'entrée brute à la réponse au format figé : normalisation,
règle dure ``lookalike_host``, explications, techniques ATT&CK et vue analyste. Les
modèles sont de petits modèles entraînés ici (les vrais ne sont pas versionnés), et
rien ne sort de la machine.
"""

import asyncio
import json
from pathlib import Path

import lightgbm as lgb
import numpy as np
import pytest
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import Pipeline
from sklearn.svm import LinearSVC

from phishguard import deployment
from phishguard.analysis import EmailAnalyzer, TextAnalyzer, UrlAnalyzer
from phishguard.data.split import read_split_blocks
from phishguard.fusion.score import LOOKALIKE_HOST, default_config, lookalike_host_signal
from phishguard.schema import SCHEMA_VERSION, AnalysisResponse
from phishguard.security.normalize import TextNormalizer
from phishguard.text.models import TextModel
from phishguard.urls.features import feature_names
from phishguard.urls.model import UrlModel

ROOT = Path(__file__).resolve().parents[1]
EMAILS = ROOT / "tests/fixtures/emails"
COLUMNS = feature_names(families=("base", "brand", "homograph", "shortener"))
LOOKALIKE = "https://\u0430pple.com/login"  # premier « a » : lettre cyrillique U+0430
CLEAN_TEXT = "Your account is locked, verify it now at http://verify.example"
# Même message : homoglyphes cyrilliques et caractère de largeur nulle.
DISGUISED_TEXT = "Y\u043eur acc\u043eunt is l\u200bocked, verify it now at http://verify.example"


@pytest.fixture(scope="module")
def url_model(split_dataset_path) -> UrlModel:
    data = read_split_blocks(split_dataset_path, ("train",), ["url", "label"])["train"]
    estimator = lgb.LGBMClassifier(n_estimators=40, num_leaves=15, verbose=-1, random_state=0)
    model = UrlModel(
        estimator,
        COLUMNS,
        thresholds={"fpr_1pct": 0.6, "fpr_0_5pct": 0.8, "fpr_0_1pct": 0.9},
        metadata={"model_version": "url_v2"},
    )
    estimator.fit(model.features(data["url"]), data["label"])
    return model


@pytest.fixture(scope="module")
def text_model() -> TextModel:
    texts = [
        "urgent your account is locked verify now http://verify.example",
        "you won a free prize claim it at prize.example",
        "see you at the station tonight",
        "thanks for the lovely dinner",
    ] * 10
    labels = np.array([1, 1, 0, 0] * 10)
    pipeline = Pipeline(
        [
            (
                "representation",
                TfidfVectorizer(
                    preprocessor=TextNormalizer(lowercase=True),
                    analyzer="char_wb",
                    ngram_range=(2, 4),
                ),
            ),
            ("clf", LinearSVC(random_state=0)),
        ]
    ).fit(texts, labels)
    return TextModel(pipeline, "char_svm", threshold=-0.25, metadata={"model_version": "text_v2"})


def analyze_url(model, url, **options):
    return asyncio.run(UrlAnalyzer(model).analyze(url, **options))


def roundtrip(response: AnalysisResponse) -> AnalysisResponse:
    """La réponse sérialisée se relit à l'identique : le contrat tient."""
    again = AnalysisResponse.model_validate_json(response.to_json())
    assert again == response
    assert again.schema_version == SCHEMA_VERSION
    return again


# --------------------------------------------------------------------------- #
# Fusion
# --------------------------------------------------------------------------- #


def test_lookalike_host_is_a_hard_rule_of_the_versioned_config():
    config = default_config()
    assert config.version == "1.1.0"
    assert LOOKALIKE_HOST in config.hard_rules.phishing_sources
    assert LOOKALIKE_HOST in config.rationale
    assert lookalike_host_signal(None) is None
    signal = lookalike_host_signal("mixed_script_label")
    assert signal.risk == 1.0 and signal.evidence == {"alert": "mixed_script_label"}


# --------------------------------------------------------------------------- #
# URL
# --------------------------------------------------------------------------- #


def test_lookalike_host_gives_a_phishing_verdict_with_its_reason(url_model):
    analysis = analyze_url(url_model, LOOKALIKE)
    assert analysis.host_alert == "mixed_script_label"
    assert analysis.verdict == "phishing" and analysis.score == 100
    assert analysis.fusion.hard_rule == LOOKALIKE_HOST
    for language in ("fr", "en", "ar"):
        response = roundtrip(analysis.to_response(language))
        assert [r.code for r in response.reasons] == ["hard_rule.lookalike_host"]
        assert response.signals == {}  # règle locale : aucune source interrogée
        assert response.analyst.fusion.hard_rule == LOOKALIKE_HOST
        assert response.analyst.normalization.host_alert == "mixed_script_label"
        assert "T1583.001" in {t.id for t in response.mitre}  # domaine d'imitation


def test_lookalike_host_beats_the_allowlist(url_model):
    analysis = analyze_url(url_model, LOOKALIKE, allowlisted=True)
    assert analysis.verdict == "phishing" and analysis.fusion.hard_rule == LOOKALIKE_HOST


@pytest.mark.parametrize("url", ["https://xn--e1afmkfd.xn--p1ai/", "https://www.example.com/"])
def test_legitimate_hosts_raise_no_alert(url_model, url):
    analysis = analyze_url(url_model, url)
    assert analysis.host_alert is None
    assert analysis.fusion.hard_rule is None
    response = roundtrip(analysis.to_response())
    assert response.analyst.normalization.host_alert is None


def test_invisible_characters_in_a_url_are_normalized_and_counted(url_model):
    clean = analyze_url(url_model, "https://www.example.com/account")
    hidden = analyze_url(url_model, "https://www.exam\u200bple.com/account")
    assert hidden.model_score == pytest.approx(clean.model_score)
    assert hidden.normalization.format_chars == 1 and hidden.normalization.changed
    assert not clean.normalization.changed
    normalization = roundtrip(hidden.to_response()).analyst.normalization
    assert normalization.changed and normalization.format_chars == 1


# --------------------------------------------------------------------------- #
# Message
# --------------------------------------------------------------------------- #


def test_disguised_message_scores_like_the_clean_one(text_model):
    analyzer = TextAnalyzer(text_model)
    clean, disguised = analyzer.analyze(CLEAN_TEXT), analyzer.analyze(DISGUISED_TEXT)
    assert disguised.model_score == pytest.approx(clean.model_score)
    assert disguised.verdict == clean.verdict
    assert disguised.normalization.confusables == 2
    assert disguised.normalization.format_chars == 1
    response = roundtrip(disguised.to_response("en"))
    assert response.reasons and response.analyst.normalization.changed
    assert response.analyst.explanation is not None  # explications branchées
    # Ni le message ni ses mots déguisés dans le résumé journalisable.
    summary = json.dumps(disguised.to_dict(), ensure_ascii=False)
    assert "locked" not in summary and "verify.example" not in summary


# --------------------------------------------------------------------------- #
# Email
# --------------------------------------------------------------------------- #


def analyze_email(name, url_model=None):
    return EmailAnalyzer(url_model).analyze((EMAILS / name).read_bytes())


def test_email_with_a_lookalike_link_is_phishing(url_model):
    analysis = analyze_email("11_arabic_idn.eml", url_model)
    assert analysis.host_alert == "mixed_script_label"
    assert analysis.verdict == "phishing" and analysis.fusion.hard_rule == LOOKALIKE_HOST
    response = roundtrip(analysis.to_response())
    assert response.channel == "email"
    assert [r.code for r in response.reasons] == ["hard_rule.lookalike_host"]
    assert response.analyst.model.version == "email_rules_v1"


def test_email_rules_become_reasons_and_techniques(url_model):
    analysis = analyze_email("02_phish_link_mismatch.eml", url_model)
    assert analysis.fusion.hard_rule is None
    assert analysis.score == analysis.rule_score  # la fusion reprend le score des règles
    response = roundtrip(analysis.to_response("en"))
    assert response.verdict == "phishing"
    assert response.reasons[0].code == "email.mismatched_link"
    assert "T1566.002" in {t.id for t in response.mitre}
    assert response.enrichment == "skipped" and response.signals == {}


def test_legitimate_email_is_safe_without_techniques():
    response = roundtrip(analyze_email("01_legit_newsletter.eml").to_response())
    assert response.verdict == "safe" and response.mitre == [] and response.reasons == []
    assert response.advice  # toujours un conseil


def test_email_summary_has_no_content():
    raw = (EMAILS / "02_phish_link_mismatch.eml").read_bytes().decode("utf-8", "replace")
    summary = json.dumps(analyze_email("02_phish_link_mismatch.eml").to_dict())
    subject = next(line for line in raw.splitlines() if line.lower().startswith("subject:"))
    assert subject.split(":", 1)[1].strip() not in summary
    assert "@" not in summary


@pytest.mark.parametrize("path", sorted(EMAILS.glob("*.eml")), ids=lambda p: p.name)
def test_every_fixture_email_gives_a_valid_response(path, url_model):
    response = EmailAnalyzer(url_model).analyze(path.read_bytes()).to_response()
    roundtrip(response)


def test_email_input_errors_are_input_errors():
    from phishguard.email.parser import EmailLimits, EmailTooLargeError

    with pytest.raises(TypeError):
        EmailAnalyzer().analyze("not bytes")
    with pytest.raises(EmailTooLargeError):
        EmailAnalyzer(limits=EmailLimits(max_bytes=10)).analyze(b"Subject: x\n\n" + b"a" * 50)


# --------------------------------------------------------------------------- #
# Modèles déployés
# --------------------------------------------------------------------------- #


def test_deployed_models_are_the_robust_ones():
    assert deployment.DEPLOYED_MODELS == {"url": "url_v2", "text": "text_v2"}
    files = deployment.model_files(Path("m"))
    assert files["url"].model == Path("m/url_v2.joblib")
    assert files["text"].calibration == Path("m/text_v2_calibration.json")


def test_load_analyzers_explains_a_missing_model(tmp_path):
    with pytest.raises(FileNotFoundError, match="make train train-adversarial"):
        deployment.load_analyzers(tmp_path)


def test_load_analyzers_runs_the_three_channels(tmp_path, url_model, text_model):
    url_model.save(tmp_path / "url_v2.joblib")
    text_model.save(tmp_path / "text_v2.joblib")
    analyzers = deployment.load_analyzers(tmp_path)
    assert analyzers.email.url_model_version == "url_v2"
    url = asyncio.run(analyzers.url.analyze(LOOKALIKE))
    assert url.verdict == "phishing" and url.model_version == "url_v2"
    assert analyzers.text.analyze(CLEAN_TEXT).model_version == "text_v2"
    email = analyzers.email.analyze((EMAILS / "01_legit_newsletter.eml").read_bytes())
    assert email.url_model_version == "url_v2"


def test_load_analyzers_refuses_a_mislabelled_model(tmp_path, url_model, text_model):
    url_model.save(tmp_path / "url_v2.joblib")
    TextModel(text_model.estimator, "char_svm", -0.25, {"model_version": "text_v1"}).save(
        tmp_path / "text_v2.joblib"
    )
    with pytest.raises(ValueError, match="text_v1"):
        deployment.load_analyzers(tmp_path)
