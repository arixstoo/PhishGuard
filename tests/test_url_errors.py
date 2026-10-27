"""Tests de l'analyse d'erreurs du modèle URL (étape 1.8)."""

import importlib.util
import json
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from phishguard.urls import errors as X
from phishguard.urls.features import UrlFeatureExtractor
from phishguard.urls.tld import TldRiskTable

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"

TABLE = TldRiskTable.fit(["xyz"] * 30 + ["com"] * 70, [1] * 27 + [0] * 3 + [1] * 3 + [0] * 67)
EXTRACTOR = UrlFeatureExtractor(tld_table=TABLE)
CTX = X.Context(platforms=X.load_hosting_platforms(), tld_prior=TABLE.prior)


def load_script(name):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def category(url, kind):
    return X.categorize(url, kind, EXTRACTOR, CTX)[0]


# --------------------------------------------------------------------------- #
# Plateformes
# --------------------------------------------------------------------------- #


def test_embedded_hosting_list():
    platforms = X.load_hosting_platforms()
    assert {"web.app", "docs.google.com", "ipfs.io", "github.io"} <= platforms
    assert all(d == d.lower().strip() for d in platforms)


def test_on_platform_matches_by_host_suffix():
    platforms = frozenset({"web.app", "docs.google.com"})
    assert X.on_platform("web.app", platforms)
    assert X.on_platform("login-secure.web.app", platforms)
    assert X.on_platform("docs.google.com", platforms)
    assert not X.on_platform("google.com", platforms)
    assert not X.on_platform("myweb.app", platforms)  # pas un sous-domaine


def test_invalid_hosting_list_is_rejected(tmp_path):
    path = tmp_path / "hosting.json"
    path.write_text(json.dumps({"domains": ["Web.App"]}), encoding="utf-8")
    with pytest.raises(ValueError, match="invalides"):
        X.load_hosting_platforms(path)


# --------------------------------------------------------------------------- #
# Catégories
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://paypal-help.com/", "legit_brand_lookalike"),
        ("https://myblog.blogspot.com/2026/10/post.html", "legit_hosted_platform"),
        ("https://shop.com/search?q=shoes&page=2&sort=price", "legit_long_query"),
        ("https://news.com/world/europe/france/2026/article", "legit_deep_path"),
        ("https://my-local-bakery-shop.com/", "legit_unusual_host"),
        ("https://bakery.xyz/", "legit_risky_tld"),
        ("https://bakery.com/about", "legit_other"),
    ],
)
def test_false_positive_categories(url, expected):
    assert category(url, X.FALSE_POSITIVE) == expected


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://account-verify.web.app/login", "phish_hosted_platform"),
        ("https://docs.google.com/forms/d/e/abc/viewform", "phish_hosted_platform"),
        ("https://bit.ly/3xYz", "phish_shortener"),
        ("http://192.168.10.5/bank/login", "phish_ip_host"),
        ("https://bakery.com/wp-content/plugins/x/index.html", "phish_compromised_site"),
        ("https://santandder.net/", "phish_signal_ignored"),  # typosquat vu, pas écouté
        ("https://logindirect.net/", "phish_signal_ignored"),  # mot-clé dans l'hôte
        ("https://renew-myflix.net/", "phish_compound_name"),
        ("https://bakery.com/", "phish_clean_domain"),
        ("https://bakery22.com/", "phish_other"),
    ],
)
def test_false_negative_categories(url, expected):
    assert category(url, X.FALSE_NEGATIVE) == expected


def test_rules_are_applied_in_order_and_all_tags_are_kept():
    primary, tags = X.categorize(
        "https://paypal-help.blogspot.com/a/b/c/d/e", X.FALSE_POSITIVE, EXTRACTOR, CTX
    )
    # La plateforme passe avant la marque : c'est elle qui explique la page.
    assert primary == "legit_hosted_platform"
    assert tags[:2] == ("legit_hosted_platform", "legit_brand_lookalike")
    assert "legit_deep_path" in tags and "legit_other" not in tags


def test_clean_host_rules_exclude_every_brand_signal():
    _, tags = X.categorize("https://santandder.net/", X.FALSE_NEGATIVE, EXTRACTOR, CTX)
    assert "phish_clean_domain" not in tags and "phish_compound_name" not in tags
    _, tags = X.categorize("https://renew-myflix.net/", X.FALSE_NEGATIVE, EXTRACTOR, CTX)
    assert "phish_clean_domain" not in tags  # « sans tiret »


def test_user_content_hosts_are_platforms():
    platforms = X.load_hosting_platforms()
    assert X.on_platform("ibb.co", platforms)
    assert X.on_platform("site.user1.chatgpt.site", platforms)


def test_other_has_no_tag():
    assert X.categorize("https://bakery.com/about", X.FALSE_POSITIVE, EXTRACTOR, CTX) == (
        "legit_other",
        (),
    )


def test_risky_tld_rule_needs_a_table():
    ctx = X.Context(platforms=frozenset(), tld_prior=None)
    extractor = UrlFeatureExtractor()  # sans famille tld
    assert X.categorize("https://bakery.xyz/", X.FALSE_POSITIVE, extractor, ctx)[0] == "legit_other"


def test_every_kind_ends_with_a_catch_all():
    for kind in X.KINDS:
        assert X.categories_for(kind)[-1].name.endswith("_other")
    with pytest.raises(ValueError):
        X.categories_for("true_positive")
    names = [c.name for c in X.CATEGORIES]
    assert len(names) == len(set(names))


# --------------------------------------------------------------------------- #
# Sélection, synthèse, défangage
# --------------------------------------------------------------------------- #


def test_worst_errors_are_sorted_and_stable():
    y = np.array([0, 0, 0, 0, 1, 1, 1])
    scores = np.array([0.9, 0.95, 0.9, 0.1, 0.05, 0.4, 0.05])
    worst = X.worst_errors(y, scores, threshold=0.5, n=2)
    assert worst[X.FALSE_POSITIVE].tolist() == [1, 0]  # 0,95 puis 0,9 (position 0 avant 2)
    assert worst[X.FALSE_NEGATIVE].tolist() == [4, 6]
    assert X.worst_errors(y, scores, 0.5, n=10)[X.FALSE_POSITIVE].tolist() == [1, 0, 2]
    with pytest.raises(ValueError):
        X.worst_errors(y, scores, 0.5, n=0)


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://login.example.com/a/b?x=1", "hxxps://login[.]example[.]com/a/b?…"),
        ("http://evil.com/u/victim@mail.com/x", "hxxp://evil[.]com/u/<email>/x"),
        ("http://10.0.0.1:8080/", "hxxp://10[.]0[.]0[.]1:8080/"),
    ],
)
def test_defang(url, expected):
    assert X.defang(url) == expected


def test_defang_truncates_long_urls():
    text = X.defang("https://a.com/" + "x" * 200, max_length=40)
    assert len(text) == 40 and text.endswith("…")


def test_summarize_publishes_only_allowed_sources():
    errors = pd.DataFrame(
        {
            "kind": [X.FALSE_NEGATIVE] * 3 + [X.FALSE_POSITIVE],
            "rank": [1, 2, 3, 1],
            "score": [0.01, 0.02, 0.03, 0.99],
            "category": ["phish_clean_domain"] * 3 + ["legit_deep_path"],
            "tags": ["phish_clean_domain"] * 3 + ["legit_deep_path;legit_long_query"],
            "source": ["openphish", "phishtank", "phishtank", "commoncrawl"],
            "url": [
                "https://secret.com/",
                "https://a.com/",
                "https://b.com/",
                "https://c.org/a/b/c/d?x=1",
            ],
        }
    )
    totals = {X.FALSE_POSITIVE: 10, X.FALSE_NEGATIVE: 3}
    summary = X.summarize(errors, totals, examples_per_category=5)
    clean = summary[X.FALSE_NEGATIVE]["categories"]["phish_clean_domain"]
    assert clean["count"] == 3 and clean["share"] == 1.0
    assert clean["by_source"] == {"phishtank": 2, "openphish": 1}
    assert clean["examples"] == ["hxxps://a[.]com/", "hxxps://b[.]com/"]
    assert "secret" not in json.dumps(summary)
    fp = summary[X.FALSE_POSITIVE]
    assert fp["total_errors"] == 10 and fp["analyzed"] == 1
    assert fp["categories"]["legit_long_query"]["tagged"] == 1
    assert fp["categories"]["legit_other"]["count"] == 0
    assert "count_all" not in fp["categories"]["legit_other"]


def test_summarize_compares_the_worst_errors_with_all_errors():
    def frame(kind, categories):
        n = len(categories)
        return pd.DataFrame(
            {
                "kind": [kind] * n,
                "rank": range(1, n + 1),
                "score": [0.5] * n,
                "category": categories,
                "tags": categories,
                "source": ["phishtank"] * n,
                "url": [f"https://x{i}.com/" for i in range(n)],
            }
        )

    worst = frame(X.FALSE_NEGATIVE, ["phish_clean_domain"] * 2)
    every = frame(X.FALSE_NEGATIVE, ["phish_clean_domain"] * 2 + ["phish_compromised_site"] * 6)
    totals = {X.FALSE_POSITIVE: 0, X.FALSE_NEGATIVE: 8}
    categories = X.summarize(worst, totals, all_errors=every)[X.FALSE_NEGATIVE]["categories"]
    assert categories["phish_clean_domain"]["count_all"] == 2
    assert categories["phish_compromised_site"]["count"] == 0
    assert categories["phish_compromised_site"]["count_all"] == 6
    assert categories["phish_compromised_site"]["share_all"] == 0.75


def test_analyze_returns_one_row_per_error():
    block = pd.DataFrame(
        {
            "url": ["https://bakery.com/", "https://news.com/a/b/c/d/e", "https://bit.ly/x"],
            "label": [0, 0, 1],
            "source": ["tranco", "commoncrawl", "phishtank"],
        }
    )
    rows = X.analyze(block, np.array([0.2, 0.9, 0.1]), 0.5, EXTRACTOR, CTX, n=50)
    assert rows["kind"].tolist() == [X.FALSE_POSITIVE, X.FALSE_NEGATIVE]
    assert rows["category"].tolist() == ["legit_deep_path", "phish_shortener"]


def test_definitions_cover_every_category():
    definitions = X.category_definitions()
    assert [d["name"] for d in definitions] == [c.name for c in X.CATEGORIES]
    assert all(d["rule"] and d["improvement"] for d in definitions)


# --------------------------------------------------------------------------- #
# Script
# --------------------------------------------------------------------------- #

DOC = (
    "# Erreurs\n\n<!-- generated:errors-url-categories:start -->\n"
    "<!-- generated:errors-url-categories:end -->\n\n"
    "<!-- generated:errors-url:start -->\n<!-- generated:errors-url:end -->\n"
)


@pytest.fixture(scope="module")
def trained_model(split_dataset_path, tmp_path_factory):
    out = tmp_path_factory.mktemp("model")
    model = out / "url_v1.joblib"
    args = ["--dataset", str(split_dataset_path), "--model-out", str(model)]
    args += ["--report", str(out / "url_v1.json"), "--doc", "none", "--quick"]
    assert load_script("train_url").main(args) == 0
    return model


@pytest.mark.parametrize("split", ["validation", "test"])
def test_script_end_to_end(tmp_path, split_dataset_path, trained_model, split):
    doc, report_path = tmp_path / "errors.md", tmp_path / "url_errors.json"
    doc.write_text(DOC, encoding="utf-8")
    args = ["--dataset", str(split_dataset_path), "--model", str(trained_model), "--split", split]
    args += ["--report", str(report_path), "--doc", str(doc), "--details-dir", str(tmp_path)]
    args += ["--worst", "10"]
    assert load_script("analyze_url_errors").main(args) == 0

    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["metadata"]["split"] == split
    for kind in X.KINDS:
        entry = report["errors"][kind]
        assert entry["analyzed"] == min(10, entry["total_errors"])
        assert sum(c["count"] for c in entry["categories"].values()) == entry["analyzed"]

    details = pd.read_csv(tmp_path / f"url_errors_{split}.csv")
    assert len(details) == sum(report["errors"][k]["analyzed"] for k in X.KINDS)
    # Les URLs complètes restent dans l'export local, jamais dans le rapport versionné.
    text = report_path.read_text(encoding="utf-8")
    assert not any(url in text for url in details["url"])

    rendered = doc.read_text(encoding="utf-8")
    assert "Piste d'amélioration" in rendered and "Faux négatifs" in rendered


def test_script_reports_missing_inputs(tmp_path):
    script = load_script("analyze_url_errors")
    assert script.main(["--dataset", str(tmp_path / "absent"), "--doc", "none"]) == 1
    with pytest.raises(SystemExit):
        script.parse_args(["--worst", "0"])
