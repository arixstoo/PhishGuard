"""Tests de la normalisation défensive (étape 3.8)."""

import asyncio
import logging
import pickle
from types import MappingProxyType

import numpy as np
import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from sklearn.pipeline import Pipeline
from sklearn.svm import LinearSVC

from phishguard.adversarial import perturb as P
from phishguard.analysis import TextAnalyzer, UrlAnalyzer
from phishguard.explain.text import TextExplainer
from phishguard.security import normalize as N
from phishguard.text import models as M
from phishguard.text.models import TextModel
from phishguard.text.smishing import normalize as smishing_normalize
from phishguard.urls.features import parse_url

ZW = "\u200b"
MESSAGES = (
    "URGENT: your account is suspended, confirm your password at http://verify.example/x",
    "Votre colis est en attente, payez 2 EUR pour la livraison",
    "Congratulations! You have won a free prize, call now to claim",
)


# --------------------------------------------------------------------------- #
# Les cinq étapes
# --------------------------------------------------------------------------- #


def test_nfkc_folds_compatibility_forms():
    result = N.normalize_text("ｌｏｇｉｎ ｎｏｗ ﬁle ²")
    assert result.text == "login now file 2"
    assert result.report.nfkc and result.report.changed


def test_format_and_control_characters_are_removed_and_counted():
    text = f"blo{ZW}qu\u200dé\u2060 \ufeffcompte\x07\x00 ok\tfin\nsuite\r"
    result = N.normalize_text(text)
    assert result.text == "bloqué compte ok\tfin\nsuite\r"
    assert result.report.format_chars == 4
    assert result.report.control_chars == 2


def test_stripping_a_format_char_recomposes_accents():
    # « e » + U+200B + accent aigu combinant : une fois l'invisible retiré, NFKC recolle.
    assert N.normalize_text(f"e{ZW}́").text == "é"


def test_mixed_script_words_are_folded():
    result = N.normalize_text("Vоtre cоmpte est blоqué")  # « о » cyrilliques
    assert result.text == "Votre compte est bloqué"
    assert result.report.confusables == 3


def test_all_confusable_word_in_latin_text_is_folded():
    # « соре » : quatre lettres cyrilliques, toutes confusables, dans une phrase latine.
    assert N.normalize_text("the соре is here").text == "the cope is here"


@pytest.mark.parametrize(
    "text",
    [
        "Привет, как дела? Сок и кофе",  # russe : jamais replié
        "Καλημέρα, το κινητό σου",  # grec
        "Zażółć gęślą jaźń łódź",  # polonais : lettres latines étendues
        "مرحبا، حسابك موقوف",  # arabe
        "東京で会いましょう",
    ],
)
def test_genuine_foreign_text_is_untouched(text):
    result = N.normalize_text(text)
    assert result.text == text
    assert not result.report.changed


def test_plain_ascii_is_unchanged():
    result = N.normalize_text(MESSAGES[0])
    assert result.text == MESSAGES[0]
    assert result.report == N.NormalizationReport()
    assert result.report.to_dict()["changed"] is False


def test_fold_can_be_disabled():
    assert N.normalize_text("Vоtre", fold=False).text == "Vоtre"


@pytest.mark.parametrize("message", MESSAGES)
@pytest.mark.parametrize(
    "name", ["homoglyphs", "homoglyphs_full", "zero_width", "zero_width_dense"]
)
def test_normalization_undoes_the_character_perturbations(name, message):
    perturbed = P.PERTURBATIONS[name](message, seed=0)
    assert perturbed != message
    assert N.normalize_text(perturbed).text == N.normalize_text(message).text


def test_every_perturbation_homoglyph_is_folded():
    for latin, glyph in P.HOMOGLYPHS.items():
        assert N.TEXT_CONFUSABLES[glyph] == latin
        assert N.normalize_text(f"ab{glyph}cd").text == f"ab{latin}cd"


_text = st.text(
    alphabet=st.characters(categories=("L", "N", "Zs", "Cf", "P")), min_size=0, max_size=40
)


@settings(max_examples=300, deadline=None)
@given(text=_text)
def test_normalization_is_idempotent_and_leaves_no_format_char(text):
    once = N.normalize_text(text).text
    assert N.normalize_text(once).text == once
    assert not any(N.unicodedata.category(c) == "Cf" for c in once)


# --------------------------------------------------------------------------- #
# URL : invisibles retirés, homographes jamais repliés
# --------------------------------------------------------------------------- #


def test_url_text_is_cleaned_but_not_folded():
    result = N.normalize_url_text(f"http://pay{ZW}pal.com/ｌogin")
    assert result.text == "http://paypal.com/login"
    assert result.report.format_chars == 1 and result.report.nfkc
    assert N.normalize_url_text("http://аpple.com/").text == "http://аpple.com/"


def test_parse_url_applies_the_normalization():
    parsed = parse_url(f"http://pay{ZW}pal.com/lo{ZW}gin")
    assert parsed.host == "paypal.com" and parsed.path == "/login"
    assert parse_url("http://аpple.com/").host.startswith("xn--")  # homographe conservé


@pytest.mark.parametrize(
    ("host", "alert"),
    [
        ("аpple.com", "mixed_script_label"),  # « а » cyrillique
        ("xn--pple-43d.com", "mixed_script_label"),  # même hôte en Punycode
        ("раура.com", "lookalike_label"),  # tout cyrillique, squelette « paypa »
        ("login.раура.com", "lookalike_label"),
        ("пример.рф", None),  # tout cyrillique, rien de latin
        ("пример.com", None),  # label cyrillique qui n'imite pas le latin
        ("paypal.com", None),
        ("bücher.de", None),
        ("東京tokyo.jp", None),  # mélange admis par UTS #39
        ("192.168.1.1", None),
        ("", None),
    ],
)
def test_host_script_alert(host, alert):
    assert N.host_script_alert(host) == alert


def test_every_url_homoglyph_perturbation_is_alerted():
    for url in ("https://paypal.com/signin", "http://secure-bank-login.net/a", "https://ab.co.uk/"):
        out = P.PERTURBATIONS["url_homoglyphs"](url, seed=0)
        assert N.host_script_alert(parse_url(out).host) is not None


# --------------------------------------------------------------------------- #
# Modèles de texte : même normalisation à l'entraînement, à l'inférence, aux explications
# --------------------------------------------------------------------------- #


def test_text_normalizer_lowercases_strips_accents_and_pickles():
    normalizer = N.TextNormalizer(lowercase=True, accents=True)
    assert normalizer(f"Sécu{ZW}rité Vоtre") == "securite votre"
    assert N.TextNormalizer(lowercase=False)("ÀB") == "ÀB"
    assert pickle.loads(pickle.dumps(normalizer)) == normalizer
    assert normalizer != N.TextNormalizer()
    assert "accents=True" in repr(normalizer)


@pytest.mark.parametrize("factory", [M.char_tfidf, M.word_tfidf])
def test_vectorizers_see_through_character_perturbations(factory):
    vectorizer = factory().fit(list(MESSAGES) * 3)
    clean = vectorizer.transform(MESSAGES).toarray()
    for name in ("homoglyphs_full", "zero_width_dense"):
        perturbed = [P.PERTURBATIONS[name](m, 0) for m in MESSAGES]
        assert np.allclose(vectorizer.transform(perturbed).toarray(), clean)


def test_explanations_use_the_normalized_words():
    pipeline = Pipeline([("representation", M.char_tfidf()), ("clf", LinearSVC())])
    texts = [*MESSAGES, "see you tonight", "call me when home", "dinner at eight"] * 3
    pipeline.fit(texts, [1, 1, 1, 0, 0, 0] * 3)
    model = TextModel(pipeline, "char_svm", threshold=0.0)
    explanation = TextExplainer(model).explain(P.PERTURBATIONS["homoglyphs_full"](MESSAGES[0], 0))
    words = {t.term for t in explanation.terms}
    assert "account" in words and "password" in words  # latin, sans homoglyphe
    assert all(N.normalize_text(w).text == w for w in words)


def test_smishing_keywords_see_through_homoglyphs():
    assert smishing_normalize("blоqué") == smishing_normalize("bloqué") == "bloque"


# --------------------------------------------------------------------------- #
# Journalisation : des comptes, jamais le contenu
# --------------------------------------------------------------------------- #


class _Margin:
    estimator = None
    threshold = 0.0
    metadata = MappingProxyType({"model_version": "text_test"})

    def score(self, texts):
        return np.zeros(len(list(texts)))


def test_text_analysis_logs_counts_only(caplog):
    secret = f"votre code se{ZW}cret 482913 pour Jean"
    with caplog.at_level(logging.INFO, logger="phishguard.security.normalize"):
        TextAnalyzer(_Margin(), explain=False).analyze(secret)
    messages = [r.getMessage() for r in caplog.records if r.name == "phishguard.security.normalize"]
    assert messages == ["entrée sms normalisée : NFKC non, 1 format, 0 contrôle, 0 confusables"]
    assert all("482913" not in m and "Jean" not in m for m in messages)


def test_clean_text_is_not_logged(caplog):
    with caplog.at_level(logging.INFO, logger="phishguard.security.normalize"):
        TextAnalyzer(_Margin(), explain=False).analyze("see you tonight")
    assert not [r for r in caplog.records if r.name == "phishguard.security.normalize"]


class _UrlScore:
    def score(self, urls):
        return np.full(len(list(urls)), 0.1)


def test_url_analysis_reports_host_alert_without_logging_the_url(caplog):
    analyzer = UrlAnalyzer(_UrlScore(), explain=False)
    with caplog.at_level(logging.INFO):
        result = asyncio.run(analyzer.analyze(f"https://аpple.com/sign{ZW}in"))
    assert result.host_alert == "mixed_script_label"
    assert result.to_dict()["host_alert"] == "mixed_script_label"
    logged = " ".join(r.getMessage() for r in caplog.records)
    assert "1 format" in logged and "mixed_script_label" in logged
    assert "apple" not in logged and "xn--" not in logged and "sign" not in logged
    clean = asyncio.run(analyzer.analyze("https://apple.com/"))
    assert clean.host_alert is None
