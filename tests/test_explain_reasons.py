"""Tests des raisons lisibles et du conseil d'action (étape 3.2)."""

import asyncio

import lightgbm as lgb
import numpy as np
import pytest

from phishguard.analysis import UrlAnalyzer
from phishguard.data.split import read_split_blocks
from phishguard.email.score import RULES
from phishguard.enrichers import Signal
from phishguard.enrichers.orchestrator import EnrichmentResult
from phishguard.explain import reasons as R
from phishguard.explain.shap_url import FeatureAttribution, UrlExplanation
from phishguard.fusion.mitre import CHANNELS
from phishguard.fusion.score import FusionResult, default_config, fuse
from phishguard.urls.features import feature_names
from phishguard.urls.model import UrlModel

VERDICTS = ("safe", "suspicious", "phishing")


def ok(source, risk, **evidence):
    return Signal(source=source, status="ok", risk=risk, evidence=evidence, latency_ms=10)


def explanation_of(values: dict, shap: dict) -> UrlExplanation:
    names = sorted(set(values) | set(shap))
    return UrlExplanation(
        base_value=-2.0,
        attributions=tuple(
            FeatureAttribution(n, float(values.get(n, 0.0)), float(shap.get(n, 0.0))) for n in names
        ),
    )


# --------------------------------------------------------------------------- #
# Gabarits
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("language", R.LANGUAGES)
def test_every_language_has_the_same_keys_and_placeholders(language):
    reference, other = R.load_templates("fr"), R.load_templates(language)
    assert other.language == language
    assert set(other.reasons) == set(reference.reasons)
    assert set(other.advice) == set(reference.advice)
    for code, template in reference.reasons.items():
        assert R.placeholders(other.reasons[code]) == R.placeholders(template), code


def test_every_reason_the_code_can_produce_has_a_template():
    templates = R.load_templates("fr")
    codes = {rule.code for rule in R.FEATURE_REASONS}
    codes |= {f"email.{rule.name}" for rule in RULES}
    codes |= {"model", "signal.domain_age", "signal.rdap", "signal.virustotal"}
    codes |= {"signal.virustotal_engines", "signal.urlscan", "signal.dns", "signal.other"}
    codes |= {"signal.certificate_transparency"}
    config = default_config()
    rules = {"blocklist", "allowlist", *config.hard_rules.phishing_sources}
    codes |= {f"hard_rule.{rule}" for rule in rules}
    assert codes <= set(templates.reasons)


@pytest.mark.parametrize("channel", CHANNELS)
@pytest.mark.parametrize("verdict", VERDICTS)
def test_every_channel_and_verdict_has_an_advice(channel, verdict):
    for language in R.LANGUAGES:
        assert R.load_templates(language).advice_for(channel, verdict)


def test_unknown_language_is_refused():
    with pytest.raises(ValueError, match="langue"):
        R.load_templates("de")


VALID = 'language: fr\nversion: 1\nreasons:\n  a: "x"\nadvice:\n  url.safe: "y"\n'


@pytest.mark.parametrize(
    "text",
    [
        VALID.replace("language: fr", "language: en"),
        VALID.replace("version: 1", "version: un"),
        'language: fr\nversion: 1\nadvice:\n  url.safe: "y"\n',  # pas de raisons
        VALID.replace('a: "x"', "a: 3"),
        VALID.replace('a: "x"', 'a: "  "'),
        VALID.replace('a: "x"', 'a: "{x.__class__}"'),
        VALID.replace('a: "x"', 'a: "{x[0]}"'),
        VALID.replace('a: "x"', 'a: "{x!r}"'),
        VALID.replace('a: "x"', 'a: "{x:>9}"'),
        VALID.replace('a: "x"', 'a: "{0}"'),
        VALID.replace('a: "x"', 'a: "{"'),
        "language: [fr",  # YAML invalide
        "- une liste",
        "!!python/object/apply:os.system ['echo pwned']",  # safe_load refuse
    ],
)
def test_invalid_template_files_are_rejected(text):
    with pytest.raises(R.TemplateError):
        R.parse_templates(text, "fr")


def test_template_needs_its_placeholders():
    templates = R.load_templates("fr")
    with pytest.raises(R.TemplateError, match="manquantes"):
        templates.reason("url.risky_tld")
    with pytest.raises(R.TemplateError, match="aucun gabarit"):
        templates.reason("url.unknown")
    with pytest.raises(R.TemplateError):
        templates.reason("url.long_host", {"n": 2.5})


# --------------------------------------------------------------------------- #
# Nettoyage : aucune injection par l'entrée
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("top", "top"),
        ("ｔｏｐ", "top"),  # pleine chasse ramenée par NFKC
        ("to\u200bp", "top"),  # espace sans chasse
        ("evil\u202egnp.exe", "evilgnp[.]exe"),  # inversion du sens d'écriture
        ("a\x00b\x1bc", "abc"),
        ("  deux   mots\n", "deux mots"),
        ("<script>alert(1)</script>", "scriptalert(1)/script"),
        ('" onmouseover="x', "onmouseover=x"),
        ("http://evil.example/a", "hxxp://evil[.]example/a"),
        ("HTTPS://x", "HxxPS://x"),
        ("moi@exemple.fr", "moi[@]exemple[.]fr"),
        ("{brand.__class__}", "brand[.]__class__"),
    ],
)
def test_safe_fragment_neutralises_input(raw, expected):
    assert R.safe_fragment(raw) == expected


def test_safe_fragment_truncates_long_input():
    assert R.safe_fragment("a" * 100, max_length=10) == "a" * 9 + "…"
    with pytest.raises(ValueError):
        R.safe_fragment("a", max_length=0)


def test_message_never_contains_markup_from_the_url():
    templates = R.load_templates("fr")
    message = templates.reason("url.risky_tld", {"tld": "<img src=x onerror=alert(1)>"})
    fragment = message.split("«")[1].split("»")[0]  # la partie venue de l'URL
    assert not set("<>\"'`&") & set(fragment)
    assert "onerror" in fragment  # le texte reste lisible, désarmé


# --------------------------------------------------------------------------- #
# Constats sur l'URL
# --------------------------------------------------------------------------- #


def test_url_facts_find_the_imitated_brands():
    facts = R.url_facts("http://paypa1.example.xyz/login")
    assert facts.tld == "xyz"
    assert R.url_facts("https://paypal.secure-update.top/").brand_in_host == "paypal"
    assert R.url_facts("https://paypa1.com/").lookalike_brand == "paypal"
    assert R.url_facts("https://files.example.com/paypal/login").brand_in_path == "paypal"
    assert R.url_facts("https://www.paypal.com/signin") == R.UrlFacts(tld="com")


def test_url_facts_of_an_ip_or_invalid_url_are_empty():
    assert R.url_facts("http://203.0.113.9/login") == R.UrlFacts()
    assert R.url_facts("ftp://nope") == R.UrlFacts()


# --------------------------------------------------------------------------- #
# Raisons du modèle URL
# --------------------------------------------------------------------------- #

FACTS = R.UrlFacts(tld="top", brand_in_host="paypal", lookalike_brand="paypal")


def test_feature_reasons_share_the_model_points_by_shap():
    e = explanation_of(
        {"tld_phish_rate": 0.8, "host_kw_hits": 1, "path_len": 4},
        {"tld_phish_rate": 2.0, "host_kw_hits": 1.0, "path_len": 1.0},
    )
    found = R.feature_candidates(e, FACTS, 40.0)
    assert [(c.code, round(c.points, 6)) for c in found] == [
        ("url.risky_tld", 20.0),
        ("url.login_keywords", 10.0),
    ]  # path_len (10 points) n'est pas compréhensible : il n'est pas cité
    assert found[0].params == {"tld": "top"}


def test_shape_reasons_come_after_precise_cues():
    e = explanation_of(
        {"host_len": 40, "brand_in_host": 1},
        {"host_len": 5.0, "brand_in_host": 0.5},
    )
    assert [c.code for c in R.feature_candidates(e, FACTS, 50.0)] == [
        "url.brand_in_host",
        "url.long_host",
    ]


def test_cues_that_lowered_the_score_are_observations_only():
    e = explanation_of({"is_shortener": 1, "path_len": 4}, {"is_shortener": -0.1, "path_len": 3})
    assert R.feature_candidates(e, FACTS, 90.0) == []
    (observation,) = R.feature_candidates(e, FACTS, 90.0, observations=True)
    assert (observation.code, observation.points) == ("url.shortener", 0.0)


def test_conditions_must_hold_even_with_a_positive_contribution():
    e = explanation_of(
        {"host_len": 12, "tld_phish_rate": 0.2, "host_n_subdomains": 1},
        {"host_len": 2.0, "tld_phish_rate": 1.0, "host_n_subdomains": 0.5},
    )
    assert R.feature_candidates(e, FACTS, 60.0, observations=True) == []


def test_ip_address_is_not_described_by_its_digits():
    e = explanation_of(
        {"host_is_ip": 1, "host_n_digits": 8}, {"host_is_ip": 1.0, "host_n_digits": 2.0}
    )
    assert [c.code for c in R.feature_candidates(e, R.UrlFacts(), 50.0)] == ["url.ip_host"]


def test_one_sentence_per_imitated_brand():
    e = explanation_of(
        {"is_typosquat": 1, "brand_in_host": 1},
        {"is_typosquat": 1.0, "brand_in_host": 2.0},
    )
    assert [c.code for c in R.feature_candidates(e, FACTS, 50.0)] == ["url.brand_in_host"]


def test_brand_reason_without_a_brand_name_is_omitted():
    e = explanation_of({"brand_in_host": 1}, {"brand_in_host": 2.0})
    assert R.feature_candidates(e, R.UrlFacts(), 50.0) == []


# --------------------------------------------------------------------------- #
# Explication complète
# --------------------------------------------------------------------------- #


def test_hard_rule_is_the_only_reason():
    fusion = fuse(0.1, [ok("google_safe_browsing", 1.0)])
    result = R.ReasonBuilder().for_fusion(fusion, signals=[ok("google_safe_browsing", 1.0)])
    (reason,) = result.reasons
    assert (reason.code, reason.points) == ("hard_rule.google_safe_browsing", 100.0)
    assert "N'entrez aucun mot de passe" in result.advice


def test_unknown_hard_rule_falls_back_to_a_generic_sentence():
    fusion = FusionResult(100, "phishing", 1.0, hard_rule="new_source")
    (reason,) = R.ReasonBuilder("en").for_fusion(fusion).reasons
    assert reason.code == "signal.other" and "new_source" in reason.message


def test_signal_reasons_use_their_evidence():
    signals = [
        ok("rdap", 1.0, age_days=2),
        ok("virustotal", 1.0, stats={"malicious": 5, "suspicious": 1}),
        ok("urlscan", 0.5),
    ]
    result = R.ReasonBuilder().for_fusion(fuse(0.1, signals), signals=signals)
    by_code = {r.code: r for r in result.reasons}
    assert set(by_code) == {"signal.virustotal_engines", "signal.domain_age", "signal.urlscan"}
    assert by_code["signal.domain_age"].message == "Ce site a été créé il y a seulement 2 jours."
    assert by_code["signal.virustotal_engines"].params == {"n": 6}


def test_signal_without_usable_evidence_gets_a_generic_sentence():
    signals = [ok("rdap", 1.0, age_days="?"), ok("virustotal", 1.0, stats={"malicious": 0})]
    result = R.ReasonBuilder().for_fusion(fuse(0.1, signals), signals=signals)
    assert {"signal.rdap", "signal.virustotal"} <= {r.code for r in result.reasons}


def test_at_most_three_reasons_by_decreasing_points():
    signals = [
        ok("rdap", 1.0, age_days=2),
        ok("virustotal", 0.6),
        ok("urlscan", 0.5),
        ok("dns", 0.5),
    ]
    reasons = R.ReasonBuilder().for_fusion(fuse(0.5, signals), signals=signals).reasons
    assert len(reasons) == R.MAX_REASONS
    assert [r.points for r in reasons] == sorted((r.points for r in reasons), reverse=True)


def test_generic_model_reason_only_for_an_alarming_verdict():
    builder = R.ReasonBuilder()
    assert [r.code for r in builder.for_fusion(fuse(0.9)).reasons] == ["model"]
    assert builder.for_fusion(fuse(0.2)).reasons == ()
    assert "Aucun signal inquiétant" in builder.for_fusion(fuse(0.2)).advice


def test_feature_reasons_replace_the_generic_model_reason():
    e = explanation_of({"host_is_ip": 1, "path_len": 3}, {"host_is_ip": 2.0, "path_len": 2.0})
    result = R.ReasonBuilder().for_fusion(fuse(0.9), url="http://203.0.113.9/x", explanation=e)
    assert [r.code for r in result.reasons] == ["url.ip_host"]
    assert result.reasons[0].points == pytest.approx(45.0)


def test_observation_completes_the_generic_model_reason():
    e = explanation_of({"is_shortener": 1, "path_len": 3}, {"is_shortener": -0.1, "path_len": 2})
    result = R.ReasonBuilder().for_fusion(fuse(0.9), url="https://bit.ly/abc", explanation=e)
    assert [(r.code, r.points) for r in result.reasons] == [("model", 90.0), ("url.shortener", 0.0)]


@pytest.mark.parametrize("language", R.LANGUAGES)
def test_explanations_are_written_in_the_requested_language(language):
    signals = [ok("rdap", 1.0, age_days=4)]
    result = R.ReasonBuilder(language).for_fusion(fuse(0.5, signals), signals=signals)
    templates = R.load_templates(language)
    assert result.language == language
    assert result.reasons[0].message == templates.reason("signal.domain_age", {"n": 4})
    assert result.advice == templates.advice_for("url", fuse(0.5, signals).verdict)


def test_email_rules_are_translated_and_ranked():
    result = R.ReasonBuilder("en").email_rules(
        ["urgent_account_request", "mismatched_link", "dmarc_fail", "spf_softfail"], "phishing"
    )
    assert [r.code for r in result.reasons] == [
        "email.mismatched_link",
        "email.dmarc_fail",
        "email.urgent_account_request",
    ]
    assert result.reasons[0].message == "The link shown does not lead where it claims to."
    assert result.advice.startswith("Do not open any link")


def test_builder_validates_its_options():
    with pytest.raises(ValueError):
        R.ReasonBuilder(max_reasons=0)


# --------------------------------------------------------------------------- #
# Intégration : l'analyse d'une URL produit des raisons lisibles
# --------------------------------------------------------------------------- #

COLUMNS = feature_names(families=("base", "brand", "homograph", "shortener"))


@pytest.fixture(scope="module")
def url_model(split_dataset_path) -> UrlModel:
    data = read_split_blocks(split_dataset_path, ("train",), ["url", "label"])["train"]
    estimator = lgb.LGBMClassifier(n_estimators=40, num_leaves=15, verbose=-1, random_state=0)
    model = UrlModel(estimator, COLUMNS, thresholds={"fpr_1pct": 0.5})
    estimator.fit(model.features(data["url"]), data["label"])
    return model


PHISHY = "http://secure-paypal-login-42.xyz/verify/account/123456"


def test_analysis_carries_its_shap_explanation(url_model):
    analysis = asyncio.run(UrlAnalyzer(url_model).analyze(PHISHY))
    assert analysis.explanation is not None
    assert analysis.explanation.probability == pytest.approx(analysis.model_score)
    assert analysis.to_dict()["explanation"]["space"] == "log_odds"
    response = analysis.to_response()
    assert 1 <= len(response.reasons) <= R.MAX_REASONS and response.advice
    assert all(r.message for r in response.reasons)


def test_analysis_can_skip_the_explanation(url_model):
    analysis = asyncio.run(UrlAnalyzer(url_model, explain=False).analyze(PHISHY))
    assert analysis.explanation is None


def test_explanation_failure_does_not_break_the_analysis(url_model, monkeypatch, caplog):
    analyzer = UrlAnalyzer(url_model)

    def broken(_x):
        raise RuntimeError("boom")

    monkeypatch.setattr(analyzer.explainer, "explain_features", broken)
    analysis = asyncio.run(analyzer.analyze(PHISHY))
    assert analysis.explanation is None
    assert analysis.verdict in VERDICTS and "explication SHAP impossible" in caplog.text
    analysis.to_response()  # raison générale, réponse valide


def test_model_without_shap_support_is_analysed_without_explanation():
    class Fixed:
        def __init__(self):
            self.metadata = {"model_version": "fixed"}

        def score(self, urls):
            return np.array([0.9 for _ in urls])

    analyzer = UrlAnalyzer(Fixed())
    assert analyzer.explainer is None
    analysis = asyncio.run(analyzer.analyze(PHISHY))
    assert [r.code for r in analysis.to_response().reasons] == ["model"]


def test_enriched_analysis_mixes_signals_and_features(url_model):
    class Orchestrator:
        budget_s = 2.5

        async def enrich(self, url, domain):
            return EnrichmentResult((ok("rdap", 1.0, age_days=1),), "used", 5, 2500)

    analyzer = UrlAnalyzer(url_model, orchestrator=Orchestrator())
    response = asyncio.run(analyzer.analyze(PHISHY, enrichment=True)).to_response()
    assert "signal.domain_age" in {r.code for r in response.reasons}
