"""Tests de la fusion du score (étape 2.10) : table de vérité et propriétés.

Chaque ligne de la table documente un comportement voulu, avec les poids de
``fusion/fusion.json`` : modèle 1,0 ; VirusTotal 0,9 ; urlscan 0,8 ; RDAP 0,6 ;
DNS 0,5 ; Certificate Transparency 0,4. Risques des sources (étapes 2.4 à 2.7) :
VirusTotal 1 moteur = 0,2 et 5 moteurs ou plus = 1 ; RDAP moins de 7 jours = 1,0,
moins de 30 jours = 0,8 ; premier certificat de moins de 7 jours = 0,6.
"""

import json

import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydantic import ValidationError

from phishguard.enrichers import Signal
from phishguard.fusion.score import (
    FusionConfig,
    default_config,
    fuse,
    to_score,
    verdict_for,
)


def ok(source, risk):
    return Signal(source=source, status="ok", risk=risk)


def down(source, status="error"):
    return Signal(source=source, status=status)


GSB_LISTED = ok("google_safe_browsing", 1.0)
GSB_CLEAN = ok("google_safe_browsing", 0.0)

# (cas, probabilité du modèle, signaux, options, score attendu, verdict attendu)
TRUTH_TABLE = [
    (
        "exemple du plan : modèle 0,2 + domaine de 3 jours + 6 moteurs VirusTotal",
        0.2,
        [ok("rdap", 1.0), ok("virustotal", 1.0)],
        {},
        97,
        "phishing",
    ),
    ("modèle seul, très bas", 0.05, [], {}, 5, "safe"),
    ("modèle seul, incertain", 0.5, [], {}, 50, "suspicious"),
    ("modèle seul, très haut", 0.85, [], {}, 85, "phishing"),
    ("Safe Browsing l'emporte sur un modèle confiant", 0.01, [GSB_LISTED], {}, 100, "phishing"),
    ("liste blanche personnelle", 0.95, [], {"allowlisted": True}, 0, "safe"),
    (
        "Safe Browsing l'emporte sur la liste blanche",
        0.1,
        [GSB_LISTED],
        {"allowlisted": True},
        100,
        "phishing",
    ),
    ("liste noire personnelle", 0.01, [], {"blocklisted": True}, 100, "phishing"),
    ("un seul moteur VirusTotal ne suffit pas", 0.1, [ok("virustotal", 0.2)], {}, 26, "safe"),
    ("deux moteurs VirusTotal rendent suspect", 0.1, [ok("virustotal", 0.4)], {}, 42, "suspicious"),
    ("verdict malveillant d'urlscan", 0.1, [ok("urlscan", 1.0)], {}, 82, "phishing"),
    ("domaine de 20 jours", 0.2, [ok("rdap", 0.8)], {}, 58, "suspicious"),
    ("DNS gratuit seul : signal faible", 0.1, [ok("dns", 0.3)], {}, 24, "safe"),
    (
        "infrastructure neuve : domaine de 5 jours et premier certificat récent",
        0.05,
        [ok("rdap", 1.0), ok("certificate_transparency", 0.6)],
        {},
        71,
        "phishing",
    ),
    (
        "toutes les sources en panne : le modèle seul décide",
        0.6,
        [down("virustotal"), down("urlscan", "timeout"), down("rdap", "skipped")],
        {},
        60,
        "suspicious",
    ),
    (
        "signaux rassurants : ne font pas baisser le score (sites compromis)",
        0.3,
        [ok("virustotal", 0.0), ok("rdap", 0.0), GSB_CLEAN],
        {},
        30,
        "suspicious",
    ),
    ("limite basse : 29 reste sûr", 0.29, [], {}, 29, "safe"),
    ("limite haute : 70 reste suspect, 71 est du phishing", 0.70, [], {}, 70, "suspicious"),
]


@pytest.mark.parametrize(
    ("probability", "signals", "options", "score", "verdict"),
    [case[1:] for case in TRUTH_TABLE],
    ids=[case[0] for case in TRUTH_TABLE],
)
def test_truth_table(probability, signals, options, score, verdict):
    result = fuse(probability, signals, **options)
    assert (result.score, result.verdict) == (score, verdict)


def test_truth_table_has_at_least_fifteen_cases():
    assert len(TRUTH_TABLE) >= 15


def test_seventy_one_is_phishing():
    assert fuse(0.71).verdict == "phishing"


# --------------------------------------------------------------------------- #
# Règles dures et détails du résultat
# --------------------------------------------------------------------------- #


def test_hard_rules_are_reported():
    assert fuse(0.1, [GSB_LISTED]).hard_rule == "google_safe_browsing"
    assert fuse(0.1, blocklisted=True).hard_rule == "blocklist"
    assert fuse(0.9, allowlisted=True).hard_rule == "allowlist"
    assert fuse(0.9).hard_rule is None


def test_unusable_safe_browsing_answer_is_not_a_match():
    # Une erreur Safe Browsing ne déclenche pas la règle dure : le modèle décide.
    result = fuse(0.1, [down("google_safe_browsing")])
    assert (result.hard_rule, result.verdict, result.ignored) == (
        None,
        "safe",
        ("google_safe_browsing",),
    )


def test_contributions_explain_the_score():
    result = fuse(0.2, [ok("rdap", 1.0), ok("virustotal", 1.0), ok("dns", 0.0)])
    sources = [c.source for c in result.contributions]
    assert sources == ["virustotal", "rdap", "model"]  # triées par points
    assert sum(c.points for c in result.contributions) == pytest.approx(result.probability * 100)
    virustotal = result.contributions[0]
    assert (virustotal.weight, virustotal.risk, virustotal.effect) == (0.9, 1.0, 0.9)


def test_sources_without_weight_are_ignored():
    # AbuseIPDB n'a pas de poids : il n'influence pas le score.
    assert fuse(0.2, [ok("abuseipdb", 1.0)]).score == 20


def test_result_is_serializable():
    result = fuse(0.2, [ok("rdap", 1.0)])
    payload = json.loads(json.dumps(result.to_dict()))
    assert payload["verdict"] == result.verdict
    assert payload["config_version"] == default_config().version
    assert payload["thresholds"] == {"suspicious": 30, "phishing": 70}


@pytest.mark.parametrize("bad", [-0.1, 1.1, float("nan"), "0.5", None])
def test_invalid_model_probability_is_rejected(bad):
    with pytest.raises(ValueError):
        fuse(bad)


# --------------------------------------------------------------------------- #
# Propriétés : bornes, monotonie, déterminisme
# --------------------------------------------------------------------------- #

SOURCES = ("virustotal", "urlscan", "rdap", "dns", "certificate_transparency")
risks = st.floats(min_value=0, max_value=1, allow_nan=False)
signal_sets = st.dictionaries(st.sampled_from(SOURCES), risks)


@given(st.floats(min_value=0, max_value=1, allow_nan=False), signal_sets)
def test_score_is_bounded_and_never_below_the_model(probability, signal_risks):
    result = fuse(probability, [ok(s, r) for s, r in signal_risks.items()])
    assert 0 <= result.score <= 100
    assert result.probability >= probability - 1e-12


@given(
    st.floats(min_value=0, max_value=1, allow_nan=False),
    signal_sets,
    st.sampled_from(SOURCES),
    risks,
)
def test_more_risk_never_lowers_the_score(probability, signal_risks, source, extra):
    base = fuse(probability, [ok(s, r) for s, r in signal_risks.items()])
    raised = dict(signal_risks)
    raised[source] = max(raised.get(source, 0.0), extra)
    higher = fuse(probability, [ok(s, r) for s, r in raised.items()])
    assert higher.probability >= base.probability - 1e-12


@given(st.floats(min_value=0, max_value=1, allow_nan=False), signal_sets)
def test_fusion_is_deterministic_and_order_independent(probability, signal_risks):
    signals = [ok(s, r) for s, r in signal_risks.items()]
    assert fuse(probability, signals) == fuse(probability, list(reversed(signals)))


def test_score_rounding_and_verdicts():
    thresholds = default_config().thresholds
    assert [to_score(p) for p in (0.0, 0.004, 0.005, 0.295, 0.705, 1.0)] == [0, 0, 1, 30, 71, 100]
    assert [verdict_for(s, thresholds) for s in (0, 29, 30, 70, 71, 100)] == [
        "safe",
        "safe",
        "suspicious",
        "suspicious",
        "phishing",
        "phishing",
    ]


# --------------------------------------------------------------------------- #
# Configuration versionnée
# --------------------------------------------------------------------------- #


def test_default_config_is_valid_and_justified():
    config = default_config()
    assert config.version == "1.0.0"
    assert config.weights["model"] == 1.0
    assert set(config.rationale) == set(config.weights)
    assert config.hard_rules.phishing_sources == ("google_safe_browsing",)


def _config(**overrides):
    payload = default_config().model_dump()
    payload.update(overrides)
    return payload


@pytest.mark.parametrize(
    "overrides",
    [
        {"version": "v1"},
        {"thresholds": {"suspicious": 70, "phishing": 30}},
        {"thresholds": {"suspicious": 0, "phishing": 70}},
        {"weights": {"model": 1.0, "virustotal": 1.5}},
        {"weights": {"virustotal": 0.9}},  # poids du modèle manquant
        {"rationale": {"model": "x"}},  # poids non justifiés
        {"hard_rules": {"phishing_sources": ["virustotal"]}},  # à la fois règle et poids
        {"unexpected": True},
    ],
)
def test_invalid_configurations_are_rejected(overrides):
    with pytest.raises(ValidationError):
        FusionConfig.model_validate(_config(**overrides))


def test_custom_configuration_changes_the_behaviour(tmp_path):
    payload = _config(version="1.1.0", thresholds={"suspicious": 20, "phishing": 50})
    path = tmp_path / "fusion.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    config = FusionConfig.load(path)
    assert fuse(0.55, config=config).verdict == "phishing"
    assert fuse(0.55).verdict == "suspicious"
    assert fuse(0.55, config=config).config_version == "1.1.0"
