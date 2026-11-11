"""Tests de l'augmentation adversarial de l'entraînement (étape 3.9).

La garantie centrale : le générateur d'entraînement ne partage **aucun** vocabulaire ni
aucune graine avec celui du banc d'essai. Sinon, le banc mesurerait la mémoire du
modèle et non sa robustesse.
"""

import importlib.util
from pathlib import Path

import numpy as np
import pytest

from phishguard.adversarial import augment as A
from phishguard.adversarial import perturb as P
from phishguard.urls.features import parse_url

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "train_adversarial", ROOT / "scripts/train_adversarial.py"
)
script = importlib.util.module_from_spec(spec)
spec.loader.exec_module(script)

URLS = [
    "http://login-secure.example.xyz/verify.php?id=1",
    "https://bank.example.test/account",
    "http://192.0.2.10/paypal/",
    "https://www.example.com/",
    "https://news.example.org/2026/article",
    "http://update.example.net",
]
URL_LABELS = np.array([1, 1, 1, 0, 0, 0])
TEXTS = [
    "URGENT your account is locked click here to verify your password now",
    "Congratulations you won a free prize call this number to claim",
    "Your bank code expires today send it back to confirm your identity",
    "see you at lunch tomorrow",
    "thanks for the lovely dinner last night",
    "running late will be there soon",
]
TEXT_LABELS = np.array([1, 1, 1, 0, 0, 0])


# --------------------------------------------------------------------------- #
# Un générateur que le banc ne connaît pas
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("training", "benchmark"),
    [
        (A.TRAINING_BENIGN_WORDS, P.BENIGN_WORDS),
        (A.TRAINING_SUBDOMAINS, P.BENIGN_SUBDOMAINS),
        (A.TRAINING_PATH_SEGMENTS, P.BENIGN_PATH_SEGMENTS),
        (A.TRAINING_TRACKING_PARAMS, P.TRACKING_PARAMS),
    ],
)
def test_training_vocabularies_are_disjoint_from_the_benchmark(training, benchmark):
    assert not set(training) & set(benchmark)
    assert len(set(training)) == len(training)  # pas de doublon


def test_training_settings_differ_from_the_benchmark():
    assert A.TRAINING_SEED != 0  # graine par défaut du banc
    assert "." not in A.TRAINING_SEPARATORS  # séparateur du banc
    assert A.TRAINING_LEET != P.LEET
    assert any(A.TRAINING_LEET.get(k) != v for k, v in P.LEET.items())


def test_character_techniques_are_not_used():
    """Homoglyphes, largeur nulle, casse : annulés par la normalisation (3.8)."""
    techniques = {r.technique for r in A.RECIPES.values()}
    assert not techniques & {"TXT-01", "TXT-02", "URL-02", "URL-07"}


def test_every_recipe_names_a_catalog_technique():
    catalog = (ROOT / "docs/evasion-catalog.md").read_text(encoding="utf-8")
    for recipe in A.RECIPES.values():
        assert f"[{recipe.technique}]" in catalog


# --------------------------------------------------------------------------- #
# Augmentation
# --------------------------------------------------------------------------- #


def test_phishing_only_copies_phishing_with_the_same_label():
    out = A.augment(TEXTS, TEXT_LABELS, "text", classes="phishing")
    assert out.samples[: len(TEXTS)] == TEXTS  # originaux d'abord, intacts
    assert out.n_original == len(TEXTS) and out.n_added == 3
    assert out.labels[out.is_copy].tolist() == [1, 1, 1]
    assert out.origin[out.is_copy].tolist() == [0, 1, 2]
    for i in np.flatnonzero(out.is_copy):
        assert out.samples[i] != TEXTS[out.origin[i]]
        assert out.labels[i] == TEXT_LABELS[out.origin[i]]


def test_both_classes_copies_every_sample():
    out = A.augment(TEXTS, TEXT_LABELS, "text", classes="both", copies=2)
    assert out.n_added == 2 * len(TEXTS) - out.skipped
    assert sorted(out.labels[out.is_copy].tolist()) == [0] * 6 + [1] * 6
    assert sum(out.by_recipe.values()) == out.n_added


def test_augmentation_is_deterministic_and_seeded():
    a = A.augment(TEXTS, TEXT_LABELS, "text", classes="both")
    b = A.augment(TEXTS, TEXT_LABELS, "text", classes="both")
    c = A.augment(TEXTS, TEXT_LABELS, "text", classes="both", seed=A.TRAINING_SEED + 1)
    assert a.samples == b.samples and a.recipe == b.recipe
    assert a.samples != c.samples


def test_url_copies_stay_valid_and_keep_their_registered_domain():
    out = A.augment(URLS, URL_LABELS, "url", classes="both", copies=3)
    assert out.n_added > 0
    for i in np.flatnonzero(out.is_copy):
        original = parse_url(URLS[out.origin[i]])
        copy = parse_url(out.samples[i])  # lève une erreur si l'URL est invalide
        assert copy.registered_domain == original.registered_domain


def test_url_copies_never_use_benchmark_vocabulary():
    out = A.augment(URLS, URL_LABELS, "url", classes="both", copies=5)
    for i in np.flatnonzero(out.is_copy):
        original, copy = parse_url(URLS[out.origin[i]]), parse_url(out.samples[i])
        if out.recipe[i] == "subdomains":
            added = set(copy.host.split(".")) - set(original.host.split("."))
            assert added and added <= set(A.TRAINING_SUBDOMAINS)
        elif out.recipe[i] == "benign_path":
            added = set(copy.path.split("/")) - set(original.path.split("/"))
            assert added <= set(A.TRAINING_PATH_SEGMENTS)
            assert not added & set(P.BENIGN_PATH_SEGMENTS)
        else:
            name = out.samples[i].rsplit("&", 1)[-1].rsplit("?", 1)[-1].split("=")[0]
            assert name in A.TRAINING_TRACKING_PARAMS


def test_text_copies_never_use_benchmark_padding_words():
    out = A.augment(TEXTS, TEXT_LABELS, "text", classes="both", copies=4)
    for i in np.flatnonzero(out.is_copy):
        if out.recipe[i] != "pad_words":
            continue
        original = set(TEXTS[out.origin[i]].split())
        added = set(out.samples[i].split()) - original
        assert added and not added & set(P.BENIGN_WORDS)


def test_unchangeable_samples_are_skipped_not_duplicated():
    # Aucune lettre à remplacer, aucun mot de 4 lettres : seule la dilution s'applique.
    only_digits = ["123 45", "6 78"]
    out = A.augment(only_digits, [1, 1], "text", recipes=[A.RECIPES["leet_symbols"]])
    assert out.n_added == 0 and out.skipped == 2
    assert out.samples == only_digits


def test_summary_has_counts_only():
    summary = A.augment(TEXTS, TEXT_LABELS, "text", classes="both").summary()
    assert set(summary) == {
        "original",
        "added",
        "added_phishing",
        "added_legitimate",
        "skipped",
        "by_recipe",
    }
    flat = repr(summary)
    for text in TEXTS:
        assert text not in flat


@pytest.mark.parametrize(
    ("kwargs", "error"),
    [
        ({"copies": 0}, "copies"),
        ({"classes": "legitimate"}, "classes"),
        ({"labels": [1, 0]}, "étiquette"),
        ({"recipes": []}, "aucune recette"),
        ({"recipes": [A.RECIPES["subdomains"]]}, "autre vecteur"),
    ],
)
def test_invalid_arguments_are_refused(kwargs, error):
    args = {"labels": TEXT_LABELS, **kwargs}
    labels = args.pop("labels")
    with pytest.raises(ValueError, match=error):
        A.augment(TEXTS, labels, "text", **args)


def test_recipes_for_splits_by_vector():
    assert {r.vector for r in A.recipes_for("url")} == {"url"}
    assert {r.vector for r in A.recipes_for("text")} == {"text"}
    assert len(A.recipes_for("url")) + len(A.recipes_for("text")) == len(A.RECIPES)


def test_perturb_accepts_training_tables():
    assert P.leetspeak("tags", rate=1.0, table={"a": "@", "s": "$"}) == "t@g$"
    url = P.add_long_param("https://example.com/", length=5, names=("cid",))
    assert "?cid=" in url and len(url.split("cid=")[1]) == 5
    with pytest.raises(ValueError, match="names"):
        P.add_long_param("https://example.com/", names=())


# --------------------------------------------------------------------------- #
# Script
# --------------------------------------------------------------------------- #


def test_trained_models_get_a_new_version():
    assert script._version_after("url_v1") == "url_v2"
    assert script._version_after("text_v9") == "text_v10"
    assert script._version_after("url_v1", "_phishing_only") == "url_v2_phishing_only"
    assert script._version_after("custom") == "custom_adv"


def test_cli_refuses_the_benchmark_seed_and_bad_suffixes():
    with pytest.raises(SystemExit):
        script.parse_args(["--seed", "0"])
    with pytest.raises(SystemExit):
        script.parse_args(["--version-suffix", "Bad"])
    args = script.parse_args(["--doc", "none"])
    assert args.doc is None and args.classes == "both" and args.seed == A.TRAINING_SEED


def test_report_document_has_the_training_block():
    doc = (ROOT / "docs/robustness-report.md").read_text(encoding="utf-8")
    assert doc.count(f"<!-- generated:{script.DOC_BLOCK}:start -->") == 1
