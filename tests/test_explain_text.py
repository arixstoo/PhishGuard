"""Tests des explications du modèle de texte (étape 3.3)."""

import importlib.util
import itertools
import json
import socket
from pathlib import Path

import numpy as np
import pytest
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import FeatureUnion, Pipeline
from sklearn.svm import LinearSVC

from phishguard.analysis import MAX_TEXT_CHARS, TextAnalyzer
from phishguard.explain import reasons as R
from phishguard.explain import text as T
from phishguard.explain.shap_url import UnsupportedModelError
from phishguard.fusion.calibration import ScoreCalibrator
from phishguard.text.models import TextModel

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "calibrate_text.py"
spec = importlib.util.spec_from_file_location("calibrate_text", SCRIPT)
calibrate_text = importlib.util.module_from_spec(spec)
spec.loader.exec_module(calibrate_text)

SPAM_OPENERS = ("urgent", "felicitations", "dernier rappel", "alerte", "winner", "congrats")
SPAM_BODIES = (
    "vous avez gagne un cadeau, cliquez sur http://cadeau-gratuit.example/x",
    "votre compte est bloque, verifiez votre code sur http://banque-verif.example",
    "colis en attente, payez 2 € sur suivi-colis.example/p",
    "claim your free prize now at http://prize.example",
    "your account is suspended, confirm your password at verify.example",
)
HAM = (
    "on se retrouve a la gare ce soir",
    "merci pour le diner, a bientot",
    "la reunion est deplacee a demain matin",
    "tu peux acheter du pain en rentrant",
    "see you at the cinema tonight",
    "call me when you get home",
    "le match commence a quelle heure",
    "bon anniversaire, gros bisous",
)
SPAM = [f"{o} : {b}" for o, b in itertools.product(SPAM_OPENERS, SPAM_BODIES)]
TEXTS = SPAM + list(HAM) * 4
LABELS = np.array([1] * len(SPAM) + [0] * len(HAM) * 4)
EXAMPLES = [
    "URGENT : votre compte est bloque, verifiez votre code sur http://banque-verif.example",
    "Felicitations, vous avez gagne 500 € ! Cliquez ici",
    "On se retrouve a la gare ce soir ?",
    "Votre code est 482913.",
]


def text_model(vectorizer, classifier, approach="test") -> TextModel:
    pipeline = Pipeline([("representation", vectorizer), ("clf", classifier)])
    pipeline.fit(TEXTS, LABELS)
    return TextModel(pipeline, approach, threshold=0.0, metadata={"model_version": "text_test"})


def char_wb(**options):
    return TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 5), sublinear_tf=True, **options)


def words():
    return TfidfVectorizer(strip_accents="unicode", ngram_range=(1, 2), sublinear_tf=True)


@pytest.fixture(scope="module")
def svm_model():
    return text_model(char_wb(), LinearSVC(C=0.5, random_state=0), "char_svm")


@pytest.fixture(scope="module")
def logreg_model():
    return text_model(char_wb(), LogisticRegression(max_iter=2000), "char_logreg")


@pytest.fixture(scope="module")
def word_model():
    return text_model(words(), LogisticRegression(max_iter=2000), "word_logreg")


# --------------------------------------------------------------------------- #
# Exactitude : les contributions des mots redonnent le score
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("fixture", ["svm_model", "logreg_model", "word_model"])
def test_word_contributions_add_up_to_the_decision(fixture, request):
    model = request.getfixturevalue(fixture)
    explainer = T.TextExplainer(model)
    decisions = model.estimator.decision_function(EXAMPLES)
    for text, decision in zip(EXAMPLES, decisions, strict=True):
        assert explainer.explain(text).decision == pytest.approx(decision, abs=1e-9)


def test_char_wb_ngrams_match_scikit_learn():
    vectorizer = char_wb()
    analyzer = vectorizer.build_analyzer()
    document = "ab colis  x verification"
    expected = analyzer(document)
    ours = [g for w in document.split() for g in T.char_wb_ngrams(w, (2, 5))]
    assert ours == expected


def test_repeated_word_gets_all_its_occurrences(svm_model):
    explainer = T.TextExplainer(svm_model)
    once = explainer.explain("urgent compte")
    twice = explainer.explain("urgent urgent compte")
    assert [t.term for t in twice.terms] == ["urgent", "compte"]  # un élément par mot
    assert twice.decision == pytest.approx(
        svm_model.estimator.decision_function(["urgent urgent compte"])[0]
    )
    assert once.contribution_of("urgent") != twice.contribution_of("urgent")


def test_bigram_contribution_is_shared_between_its_words(word_model):
    explanation = T.TextExplainer(word_model).explain("votre compte est bloque")
    assert {t.term for t in explanation.terms} == {"votre", "compte", "est", "bloque"}


def test_top_ranks_terms_in_each_direction(svm_model):
    explanation = T.TextExplainer(svm_model).explain(EXAMPLES[0])
    top = explanation.top(3)
    assert len(top) == 3
    assert [t.contribution for t in top] == sorted((t.contribution for t in top), reverse=True)
    assert all(t.contribution < 0 for t in explanation.top(3, direction="safe"))
    with pytest.raises(ValueError):
        explanation.top(-1)


def test_to_dict_is_the_analyst_view(svm_model):
    payload = T.TextExplainer(svm_model).explain(EXAMPLES[0]).to_dict(top=2)
    assert json.loads(json.dumps(payload))["analyzer"] == "char_wb"
    assert len(payload["top_phishing"]) == 2
    assert "link" in payload["categories"]


@pytest.mark.parametrize(
    "estimator",
    [
        LogisticRegression(),  # pas un pipeline
        Pipeline([("a", TfidfVectorizer()), ("b", TfidfVectorizer()), ("c", LinearSVC())]),
        Pipeline(
            [("representation", FeatureUnion([("c", char_wb())])), ("clf", LogisticRegression())]
        ),
        Pipeline([("representation", TfidfVectorizer(analyzer="char")), ("clf", LinearSVC())]),
    ],
)
def test_unsupported_models_are_refused(estimator):
    with pytest.raises(UnsupportedModelError):
        T.TextExplainer(TextModel(estimator, "x", 0.0))


def test_unfitted_classifier_is_refused():
    pipeline = Pipeline([("representation", char_wb()), ("clf", LinearSVC())])
    pipeline.steps[0][1].fit(TEXTS)
    with pytest.raises(UnsupportedModelError):
        T.TextExplainer(TextModel(pipeline, "x", 0.0))


# --------------------------------------------------------------------------- #
# Catégories
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (EXAMPLES[0], ("urgency", "link", "code", "account")),
        ("Félicitations, vous avez gagné 500 € !", ("money",)),
        ("Votre code est 482913.", ("code",)),
        ("A ce soir à la gare", ()),
        ("Mise à jour : caf-verification.example", ("link",)),  # le lien n'est pas un code
        ("تم تعليق حسابك فوراً", ("urgency", "account")),
    ],
)
def test_message_categories(text, expected):
    assert T.message_categories(text) == expected


@pytest.mark.parametrize(
    ("word", "expected"),
    [
        ("urgent", {"urgency"}),
        ("50€", {"money"}),
        ("gagne", {"money"}),
        ("http://compte-code.example", {"link"}),  # un lien n'évoque que le lien
        ("code", {"code"}),
        ("compte", {"account"}),
        ("bonjour", set()),
    ],
)
def test_word_categories(word, expected):
    assert T.word_categories(word) == expected


def test_amount_numbers_are_money_words(svm_model):
    assert T.amount_numbers("Payez 1,99 € ou €5 ou 2,49 EUR, pas 15h") == {"1,99", "5", "2,49"}
    explanation = T.TextExplainer(svm_model).explain("vous avez un remboursement de 500 €")
    assert "500" in explanation.category_terms["money"]


# --------------------------------------------------------------------------- #
# Raisons du texte
# --------------------------------------------------------------------------- #


def text_explanation(terms: dict, categories=(), category_terms=None) -> T.TextExplanation:
    return T.TextExplanation(
        intercept=-1.0,
        terms=tuple(T.TermContribution(k, v) for k, v in terms.items()),
        categories=tuple(categories),
        category_terms=category_terms or {},
    )


def test_categories_share_the_model_points():
    e = text_explanation(
        {"urgent": 2.0, "gagnez": 1.0, "http://x.example": 1.0, "salut": -1.0},
        categories=("urgency", "link"),
        category_terms={"urgency": ("urgent",), "link": ("http://x.example",)},
    )
    found = R.text_candidates(e, 40.0, alarming=True)
    assert [(c.code, c.points) for c in found] == [
        ("text.urgency", 20.0),
        ("text.link", 10.0),
        ("text.terms", 10.0),
    ]
    assert found[-1].params == {"terms": "gagnez"}


def test_terms_are_only_cited_for_an_alarming_verdict():
    e = text_explanation({"gagnez": 2.0, "cadeau": 1.0})
    assert R.text_candidates(e, 30.0, alarming=False) == []
    (terms,) = R.text_candidates(e, 30.0, alarming=True)
    assert terms.params == {"terms": "gagnez, cadeau"}


def test_category_without_weight_is_an_observation_when_alarming():
    e = text_explanation({"code": -0.5, "gagnez": 2.0}, ("code",), {"code": ("code",)})
    assert [c.code for c in R.text_candidates(e, 30.0)] == []
    found = R.text_candidates(e, 30.0, alarming=True)
    assert ("text.code", 0.0) in [(c.code, c.points) for c in found]


@pytest.mark.parametrize(
    ("term", "expected"),
    [
        ("gagnez!", "gagnez"),
        ("«cadeau»", "cadeau"),
        ("http://evil.example/x", None),  # jamais de lien recopié
        ("bit.ly/abc", None),
        ("482913", None),  # un code reçu n'est pas recopié
        ("votre", None),
        ("ok", None),
        ("connectez-vous-immediatement", "connectez-vous-…"),
        ("a\u202eb<c>d", "abcd"),
    ],
)
def test_display_term_filters_and_cleans(term, expected):
    assert R.display_term(term) == expected


def test_text_reasons_in_the_full_explanation():
    e = text_explanation({"urgent": 3.0, "gagnez": 1.0}, ("urgency",), {"urgency": ("urgent",)})
    from phishguard.fusion.score import fuse

    result = R.ReasonBuilder("en").for_fusion(
        fuse(0.9), channel="sms", text_explanation=e, model_code="text.model"
    )
    assert [r.code for r in result.reasons] == ["text.urgency", "text.terms"]
    assert result.reasons[0].message.startswith("The message pressures you")
    assert result.advice.startswith("Do not click the link")


def test_generic_text_reason_when_nothing_explains_the_verdict():
    from phishguard.fusion.score import fuse

    e = text_explanation({"ok": 1.0})  # mot trop court pour être cité
    result = R.ReasonBuilder().for_fusion(
        fuse(0.9), channel="sms", text_explanation=e, model_code="text.model"
    )
    assert [r.code for r in result.reasons] == ["text.model"]


# --------------------------------------------------------------------------- #
# Analyse d'un message
# --------------------------------------------------------------------------- #


class NoNetwork:
    def __init__(self, monkeypatch):
        def refuse(*args, **kwargs):
            raise AssertionError("accès réseau interdit")

        monkeypatch.setattr(socket, "getaddrinfo", refuse)
        monkeypatch.setattr(socket.socket, "connect", refuse)


def test_text_analysis_is_local_and_explained(svm_model, monkeypatch):
    NoNetwork(monkeypatch)
    analysis = TextAnalyzer(svm_model).analyze(EXAMPLES[0])
    assert analysis.explanation is not None
    assert analysis.channel == "sms" and analysis.text_length == len(EXAMPLES[0])
    response = analysis.to_response()
    assert response.channel == "sms" and response.enrichment == "skipped"
    assert response.signals == {} and response.advice
    if response.verdict != "safe":
        assert all(r.code.startswith("text.") for r in response.reasons)
        assert any(t.id == "T1566.003" for t in response.mitre)


def test_text_analysis_summary_never_contains_the_message(svm_model):
    analysis = TextAnalyzer(svm_model).analyze(EXAMPLES[0])
    dumped = json.dumps(analysis.to_dict(), ensure_ascii=False)
    assert "banque-verif" not in dumped and "bloque" not in dumped


def test_probability_modes(svm_model, logreg_model, caplog):
    text = EXAMPLES[0]
    margin = float(svm_model.score([text])[0])
    with caplog.at_level("WARNING"):
        uncalibrated = TextAnalyzer(svm_model).analyze(text)
    assert "non calibré" in caplog.text
    assert uncalibrated.model_probability == pytest.approx(1 / (1 + np.exp(-margin)))
    calibrator = ScoreCalibrator("sigmoid", params={"a": 2.0, "b": 0.0})
    calibrated = TextAnalyzer(svm_model, calibrator=calibrator).analyze(text)
    assert calibrated.calibrated
    assert calibrated.model_probability == pytest.approx(1 / (1 + np.exp(-2 * margin)))
    proba = TextAnalyzer(logreg_model).analyze(text)
    assert proba.model_probability == pytest.approx(proba.model_score)


@pytest.mark.parametrize(
    ("text", "options", "error"),
    [
        ("", {}, ValueError),
        ("   ", {}, ValueError),
        ("x" * (MAX_TEXT_CHARS + 1), {}, ValueError),
        (42, {}, TypeError),
        ("bonjour", {"channel": "email"}, ValueError),
    ],
)
def test_text_analysis_validates_its_input(svm_model, text, options, error):
    with pytest.raises(error):
        TextAnalyzer(svm_model).analyze(text, **options)


def test_messaging_channel_is_kept(svm_model):
    response = TextAnalyzer(svm_model).analyze(EXAMPLES[1], channel="messaging").to_response("ar")
    assert response.channel == "messaging" and response.language == "ar"


def test_explanation_failure_does_not_break_the_text_analysis(svm_model, monkeypatch, caplog):
    analyzer = TextAnalyzer(svm_model)

    def broken(_text):
        raise RuntimeError("boom")

    monkeypatch.setattr(analyzer.explainer, "explain", broken)
    analysis = analyzer.analyze(EXAMPLES[0])
    assert analysis.explanation is None and "link" in analysis.categories
    assert "explication du message impossible" in caplog.text
    analysis.to_response()


def test_unexplainable_model_still_gets_categories():
    class Fixed:
        def score(self, texts):
            return np.array([0.95 for _ in texts])

    analysis = TextAnalyzer(Fixed()).analyze(EXAMPLES[0])
    assert analysis.explanation is None and "link" in analysis.categories
    assert [r.code for r in analysis.to_response().reasons] == ["text.model"]


def test_nan_score_is_refused():
    class Broken:
        def score(self, texts):
            return np.array([np.nan])

    with pytest.raises(ValueError, match="non fini"):
        TextAnalyzer(Broken()).analyze("bonjour")


# --------------------------------------------------------------------------- #
# Script de calibration
# --------------------------------------------------------------------------- #


def write_corpus(path: Path) -> None:
    hams = [
        f"{a} {b} {c}"
        for a, b, c in itertools.product(
            ("salut", "coucou", "bonsoir", "hello", "yo", "re"),
            ("on mange", "tu viens", "je rentre", "rdv gare", "merci", "a demain"),
            ("ce soir", "demain", "bientot", "vite", "plus tard"),
        )
    ]
    spams = [
        f"{a} {b} {c}"
        for a, b, c in itertools.product(
            ("urgent", "gagnant", "alerte", "felicitations"),
            ("cliquez", "verifiez", "reclamez", "payez"),
            ("http://cadeau.example", "votre compte", "votre prix", "ce lien"),
        )
    ]
    lines = [f"ham\t{t}" for t in hams] + [f"spam\t{t}" for t in spams]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def test_calibration_script_fits_on_the_validation_block(tmp_path):
    data = tmp_path / "SMSSpamCollection"
    write_corpus(data)
    corpus = calibrate_text.load_sms_collection(data)
    model = text_model(char_wb(), LinearSVC(random_state=0))
    model.estimator.fit(corpus["text"], corpus["label"])
    model.metadata = {"model_version": "text_test", "seed": 42}
    model_path = model.save(tmp_path / "text.joblib")
    output, report = tmp_path / "cal.json", tmp_path / "report.json"
    code = calibrate_text.main(
        ["--data", str(data), "--model", str(model_path), "--output", str(output)]
        + ["--report", str(report), "--folds", "3"]
    )
    assert code == 0
    calibrator = ScoreCalibrator.load(output)
    assert 0 <= calibrator(0.0) <= 1
    payload = json.loads(report.read_text("utf-8"))
    assert payload["metadata"]["fitted_on"] == "validation"
    assert payload["selected"] in payload["methods"]
    assert "cliquez" not in report.read_text("utf-8")  # aucun texte de message


def test_calibration_script_refuses_another_corpus(tmp_path):
    data = tmp_path / "SMSSpamCollection"
    write_corpus(data)
    model = text_model(char_wb(), LinearSVC(random_state=0))
    model.metadata = {"sms_sha256": "0" * 64}
    model_path = model.save(tmp_path / "text.joblib")
    assert calibrate_text.main(["--data", str(data), "--model", str(model_path)]) == 1


def test_calibration_script_reports_missing_inputs(tmp_path):
    assert calibrate_text.main(["--data", str(tmp_path / "absent")]) == 1
