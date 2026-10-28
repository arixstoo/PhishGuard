"""Tests du score email : règles, features, corpus et modèle (étape 1.11)."""

import importlib.util
import io
import json
import mailbox
import tarfile
from pathlib import Path

import httpx
import numpy as np
import pandas as pd
import pytest
from sklearn.linear_model import LogisticRegression

from phishguard.email import corpus as C
from phishguard.email import model as M
from phishguard.email import parse_eml
from phishguard.email import score as S
from phishguard.evaluation.splits import stratified_group_blocks
from phishguard.urls.features import UrlFeatureExtractor, feature_names
from phishguard.urls.model import UrlModel

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "emails"


def load_script(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def fixture(name):
    return parse_eml((FIXTURES / name).read_bytes())


def features(**overrides):
    values = dict.fromkeys(S.FEATURE_NAMES, 0.0)
    values.update(overrides)
    return values


# --------------------------------------------------------------------------- #
# Features
# --------------------------------------------------------------------------- #


def test_feature_contract():
    names = [n for group in S.FEATURE_GROUPS.values() for n in group]
    assert tuple(names) == S.FEATURE_NAMES and len(set(names)) == len(names)
    assert not set(S.feature_names(exclude_groups=("auth",))) & set(S.FEATURE_GROUPS["auth"])
    with pytest.raises(ValueError):
        S.feature_names(exclude_groups=("inconnu",))
    values = S.email_features(fixture("01_legit_newsletter.eml"))
    assert tuple(values) == S.FEATURE_NAMES and all(isinstance(v, float) for v in values.values())


def test_features_of_the_fixtures():
    legit = S.email_features(fixture("01_legit_newsletter.eml"))
    assert legit["dmarc_pass"] == legit["dkim_pass"] == 1 and legit["auth_missing"] == 0
    assert legit["mismatched_links"] == 0 and legit["link_domains"] == 1
    phish = S.email_features(fixture("02_phish_link_mismatch.eml"))
    assert phish["dmarc_fail"] == phish["spf_fail"] == 1 and phish["mismatched_links"] == 1
    attach = S.email_features(fixture("04_phish_double_extension.eml"))
    assert attach["dangerous_attachment"] == attach["disguised_attachment"] == 1
    assert attach["archive_attachment"] == 1 and attach["auth_missing"] == 1


def test_javascript_link_is_not_counted_twice():
    values = S.email_features(fixture("12_javascript_form.eml"))
    assert values["non_web_link"] == 1 and values["mismatched_links"] == 0
    assert values["forms"] == 1


def test_zero_width_characters_do_not_hide_keywords():
    values = S.email_features(fixture("06_phish_hidden_text.eml"))  # « bloqu<U+200B>ée »
    assert values["urgency_hits"] >= 1 and values["account_hits"] >= 1


def test_ip_and_shortener_links():
    raw = (
        b"From: a@example.com\r\nContent-Type: text/html\r\n\r\n"
        b'<a href="http://192.0.2.10/login">x</a><a href="https://bit.ly/abc">y</a>'
    )
    values = S.email_features(parse_eml(raw))
    assert values["ip_link"] == values["shortener_link"] == 1


# --------------------------------------------------------------------------- #
# Règles
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("score", "verdict"),
    [(0, "safe"), (29, "safe"), (30, "suspicious"), (70, "suspicious"), (71, "phishing")],
)
def test_verdict_boundaries(score, verdict):
    assert S.verdict(score) == verdict


def test_rule_score_is_capped_sorted_and_explained():
    result = S.rule_score(
        features(dmarc_fail=1, mismatched_links=2, dangerous_attachment=1, reply_to_differs=1)
    )
    assert result.score == 100 and result.verdict == "phishing"
    assert result.triggered == (
        "dangerous_attachment",
        "mismatched_link",
        "dmarc_fail",
        "reply_to_differs",
    )
    assert len(result.reasons) == 4 and all(r.endswith(".") for r in result.reasons)
    assert json.loads(json.dumps(result.to_dict()))["verdict"] == "phishing"
    assert S.rule_score(features()).score == 0


def test_rule_names_and_points():
    names = [rule.name for rule in S.RULES]
    assert len(names) == len(set(names))
    assert all(0 < rule.points <= 40 for rule in S.RULES)


def test_hidden_text_rule_ignores_a_short_preview_line():
    assert "hidden_text" not in S.score_email(fixture("01_legit_newsletter.eml")).triggered
    assert "hidden_text" in S.score_email(fixture("06_phish_hidden_text.eml")).triggered


@pytest.mark.parametrize(
    ("name", "verdict"),
    [
        ("01_legit_newsletter.eml", "safe"),
        ("02_phish_link_mismatch.eml", "phishing"),
        ("03_phish_reply_to.eml", "suspicious"),
        ("04_phish_double_extension.eml", "phishing"),
        ("11_arabic_idn.eml", "phishing"),
        ("12_javascript_form.eml", "suspicious"),
        ("13_display_name_spoof.eml", "suspicious"),
    ],
)
def test_rule_verdicts_on_the_fixtures(name, verdict):
    assert S.score_email(fixture(name)).verdict == verdict


# --------------------------------------------------------------------------- #
# Modèle URL appliqué aux liens
# --------------------------------------------------------------------------- #


class StubUrlModel:
    def score(self, urls):
        url = urls[0]
        if "invalide" in url:
            raise ValueError("URL refusée")
        return np.array([0.9 if "evil" in url else 0.1])

    def threshold(self, name):
        assert name == S.DEFAULT_URL_THRESHOLD
        return 0.5


def test_url_model_features():
    raw = (
        b"From: a@example.com\r\nContent-Type: text/html\r\n\r\n"
        b'<a href="https://ok.example.com/">a</a><a href="https://evil.example.net/x">b</a>'
        b'<a href="https://invalide.example.org/">c</a><a href="mailto:x@example.com">d</a>'
    )
    email = parse_eml(raw)
    values = S.url_model_features(email, StubUrlModel())
    assert values == {"max_link_url_score": 0.9, "link_flagged_by_url_model": 1.0}
    assert "url_model" in S.score_email(email, StubUrlModel()).triggered
    no_links = S.url_model_features(parse_eml(b"From: a@example.com\r\n\r\nx"), StubUrlModel())
    assert no_links == {"max_link_url_score": 0.0, "link_flagged_by_url_model": 0.0}


def test_url_model_rule_uses_the_strict_per_link_threshold():
    # Un email a souvent des dizaines de liens : 1 % de faux positifs par lien en ferait
    # bien plus par email.
    assert S.DEFAULT_URL_THRESHOLD == "fpr_0_1pct"


def test_rewritten_links_are_scored_by_their_real_target():
    href = "https://eur01.safelinks.protection.outlook.com/?url=https%3A%2F%2Fevil.example.net%2F"
    raw = (
        b"From: a@example.com\r\nContent-Type: text/html\r\n\r\n"
        + f'<a href="{href}">Ouvrir</a>'.encode()
    )
    assert S.url_model_features(parse_eml(raw), StubUrlModel())["max_link_url_score"] == 0.9


def test_reply_to_of_a_mailing_list_is_not_a_signal():
    headers = b"From: Alice <alice@a.example.com>\r\nReply-To: liste@lists.example.org\r\n"
    body = b"\r\nBonjour"
    assert S.email_features(parse_eml(headers + body))["reply_to_differs"] == 1
    listed = parse_eml(headers + b"List-Id: Discussion <liste.lists.example.org>\r\n" + body)
    assert listed.mailing_list and listed.reply_to_differs  # le fait reste noté
    assert S.email_features(listed)["reply_to_differs"] == 0


# --------------------------------------------------------------------------- #
# Corpus
# --------------------------------------------------------------------------- #


def email_bytes(i, phishing=False):
    # 40 domaines enregistrés distincts par classe, pour que le split groupé ait des groupes.
    domain = f"mail.sender{i % 40}{'-alerte' if phishing else ''}.fr"
    body = (
        f'<a href="http://evil{i}.example.net/login">https://www.paypal.com</a> urgent compte'
        if phishing
        else f'<a href="https://{domain}/n/{i}">Lire la lettre {i}</a>'
    )
    auth = "fail" if phishing and i % 2 else "pass"
    return (
        f"Authentication-Results: mx.example.com; spf={auth}; dkim={auth}; dmarc={auth}\r\n"
        f"From: Service <info@{domain}>\r\nSubject: message {i}\r\n"
        f"Content-Type: text/html; charset=utf-8\r\n\r\n<p>Bonjour {i}</p>{body}\r\n"
    ).encode()


def write_dir(folder, n, phishing):
    folder.mkdir(parents=True)
    for i in range(n):
        (folder / f"{i:04d}").write_bytes(email_bytes(i, phishing))
    (folder / "cmds").write_text("index SpamAssassin, pas un email")
    return folder


def test_read_directory_tar_and_mbox_without_duplicates(tmp_path):
    folder = write_dir(tmp_path / "ham", 5, phishing=False)
    archive = tmp_path / "ham.tar.bz2"
    with tarfile.open(archive, "w:bz2") as tar:
        for i in range(3, 8):  # 3 et 4 sont des doublons du dossier
            data = email_bytes(i)
            info = tarfile.TarInfo(f"easy_ham/{i:04d}")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        evil = tarfile.TarInfo("../../evil.txt")  # jamais écrit : l'archive n'est pas extraite
        evil.size = 3
        tar.addfile(evil, io.BytesIO(b"bad"))
    box = mailbox.mbox(tmp_path / "phish.mbox")
    for i in range(4):
        box.add(email_bytes(i, phishing=True))
    box.close()

    emails, stats = C.read_corpus(
        [("ham", folder), ("archive", archive), ("nazario", tmp_path / "phish.mbox")]
    )
    assert stats.by_source == {"ham": 5, "archive": 4, "nazario": 4}
    assert stats.duplicates == 2 and stats.skipped == 1
    assert not (tmp_path.parent / "evil.txt").exists()
    assert len({e.sha256 for e in emails}) == len(emails)


def test_read_corpus_limits_and_errors(tmp_path):
    folder = tmp_path / "x"
    folder.mkdir()
    (folder / "big").write_bytes(b"x" * 200)
    (folder / "small").write_bytes(b"From: a@example.com\r\n\r\nok")
    emails, stats = C.read_corpus([("x", folder)], max_bytes=100)
    assert len(emails) == 1 and stats.too_large == 1
    with pytest.raises(FileNotFoundError):
        C.read_corpus([("absent", tmp_path / "absent")])


def test_mbox_without_extension_is_detected(tmp_path):
    path = tmp_path / "phishing-2023"
    box = mailbox.mbox(path)
    box.add(email_bytes(1, phishing=True))
    box.close()
    emails, _ = C.read_corpus([("nazario", path)])
    assert len(emails) == 1 and emails[0].name.startswith("phishing-2023#")


# --------------------------------------------------------------------------- #
# Split, modèle, artefact
# --------------------------------------------------------------------------- #


def test_stratified_group_blocks():
    labels = np.array([0, 1] * 200)
    groups = np.array([f"g{i // 4}" for i in range(400)])
    blocks = stratified_group_blocks(labels, groups, seed=1)
    for block in range(3):
        assert set(labels[blocks == block]) == {0, 1}
    per_group = pd.Series(blocks).groupby(groups).nunique()
    assert (per_group == 1).all()
    with pytest.raises(ValueError):
        stratified_group_blocks(labels, groups, fractions=(0.72, 0.14, 0.14))
    with pytest.raises(ValueError):
        stratified_group_blocks(labels, groups[:10])


def test_sender_group():
    assert M.sender_group(fixture("02_phish_link_mismatch.eml"), "abc") == "example.net"
    assert M.sender_group(fixture("07_malformed_headers.eml"), "abc") == "sha256:abc"


def test_feature_sets():
    assert set(M.feature_sets(False)) == {"all", "without_auth", "robust"}
    sets = M.feature_sets(True)
    assert set(sets["all_with_url_model"]) - set(sets["all"]) == set(S.URL_MODEL_FEATURES)
    # Le jeu déployé n'a ni le groupe auth ni les features d'époque (has_html).
    robust = set(sets[M.DEPLOYED_FEATURE_SET])
    assert not robust & (set(S.FEATURE_GROUPS["auth"]) | set(M.ERA_BIASED_FEATURES))
    assert robust | set(S.FEATURE_GROUPS["auth"]) | {"has_html"} == set(sets["all"])


def test_cap_per_group_keeps_a_deterministic_sample():
    frame = pd.DataFrame(
        {"group": ["a"] * 5 + ["b"] * 2, "sha256": ["5", "1", "4", "2", "3", "x", "y"]}
    )
    kept, removed = M.cap_per_group(frame, 2)
    assert removed == 3 and kept["group"].value_counts().to_dict() == {"a": 2, "b": 2}
    assert sorted(kept.loc[kept["group"] == "a", "sha256"]) == ["1", "2"]
    assert M.cap_per_group(frame, 0) == (frame, 0)


def test_at_threshold_is_strict():
    result = M.at_threshold(np.array([0, 0, 1, 1]), np.array([0.2, 0.5, 0.5, 0.9]), 0.5)
    assert result == {"threshold": 0.5, "recall": 0.5, "fpr": 0.0, "precision": 1.0, "flagged": 1}


def frame(n=120):
    rows = []
    for i in range(n):
        phishing = i % 2 == 1
        values = S.email_features(parse_eml(email_bytes(i, phishing)))
        values.update(label=int(phishing))
        rows.append(values)
    return pd.DataFrame(rows)


def test_search_and_email_model_round_trip(tmp_path):
    data = frame()
    train, val = data.iloc[:80], data.iloc[80:]
    sets = M.feature_sets(False)
    result = M.search(
        train, train["label"].to_numpy(), val, val["label"].to_numpy(), sets, grids=M.QUICK_GRIDS
    )
    assert set(result.best) == {(m, s) for m in M.MODEL_SPECS for s in sets}
    best = result.best_overall()
    assert best.key == max(t.key for t in result.best.values())

    key = ("logistic_regression", "without_auth")
    model = M.EmailModel(result.estimators[key], tuple(sets["without_auth"]), threshold=0.5)
    assert not model.uses_url_model
    loaded = M.EmailModel.load(model.save(tmp_path / "e.joblib"))
    np.testing.assert_allclose(loaded.score_features(val), model.score_features(val))
    with pytest.raises(ValueError, match="absentes"):
        model.score_features(val.drop(columns="forms"))


def test_rule_scores_match_rule_score():
    data = frame(10)
    expected = [S.rule_score(r).score for r in data.to_dict("records")]
    assert M.rule_scores(data).tolist() == expected


# --------------------------------------------------------------------------- #
# Scripts
# --------------------------------------------------------------------------- #

DOC = "# Score\n\n<!-- generated:train-email:start -->\n<!-- generated:train-email:end -->\n"


def tiny_url_model(path):
    names = feature_names(families=("base",))
    urls = [f"https://site{i}.example.org/" for i in range(30)]
    urls += [f"http://evil{i}-login-secure.example.net/verify/{i}" for i in range(30)]
    x = UrlFeatureExtractor(families=("base",)).transform(urls)[list(names)]
    estimator = LogisticRegression().fit(x, [0] * 30 + [1] * 30)
    return UrlModel(estimator, names, thresholds={"fpr_1pct": 0.5, "fpr_0_1pct": 0.5}).save(path)


@pytest.mark.parametrize("with_url_model", [False, True])
def test_train_email_end_to_end(tmp_path, with_url_model):
    ham = write_dir(tmp_path / "ham", 160, phishing=False)
    phish = write_dir(tmp_path / "phish", 160, phishing=True)
    doc = tmp_path / "email-score.md"
    doc.write_text(DOC, encoding="utf-8")
    args = [
        "--source",
        f"ham:spamassassin:{ham}",
        "--source",
        f"phishing:nazario:{phish}",
        "--source",
        f"phishing:absent:{tmp_path / 'absent'}",
        "--model-out",
        str(tmp_path / "email_v1.joblib"),
        "--report",
        str(tmp_path / "email_v1.json"),
        "--doc",
        str(doc),
        "--quick",
    ]
    if with_url_model:
        args += ["--url-model", str(tiny_url_model(tmp_path / "url.joblib"))]
    else:
        args += ["--no-url-model"]
    assert load_script("train_email").main(args) == 0

    report = json.loads((tmp_path / "email_v1.json").read_text(encoding="utf-8"))
    expected_set = "robust_with_url_model" if with_url_model else "robust"
    assert report["deployed"]["feature_set"] == expected_set
    assert sum(m["deployed"] for m in report["models"]) == 1
    assert report["dataset"]["corpus"]["by_source"] == {"spamassassin": 160, "nazario": 160}
    rates = {r["rule"]: r for r in report["rule_rates"]}
    assert rates["mismatched_link"]["phishing"] == 1.0 and rates["mismatched_link"]["ham"] == 0.0
    assert rates["url_model"]["available"] is with_url_model
    text = (tmp_path / "email_v1.json").read_text(encoding="utf-8")
    assert "Bonjour" not in text and "info@" not in text  # aucun contenu d'email

    model = M.EmailModel.load(tmp_path / "email_v1.joblib")
    assert model.uses_url_model is with_url_model
    rendered = doc.read_text(encoding="utf-8")
    assert "**(déployé)**" in rendered and "Déclenchement des règles" in rendered


def test_train_email_needs_both_classes(tmp_path):
    ham = write_dir(tmp_path / "ham", 20, phishing=False)
    args = ["--source", f"ham:a:{ham}", "--no-url-model", "--doc", "none"]
    args += ["--report", str(tmp_path / "r.json"), "--model-out", str(tmp_path / "m.joblib")]
    assert load_script("train_email").main(args) == 1


def test_train_email_rejects_bad_sources():
    script = load_script("train_email")
    with pytest.raises(SystemExit):
        script.parse_args(["--source", "spam:x:y"])
    with pytest.raises(SystemExit):
        script.parse_args(["--source", "ham"])


def test_fetch_email_corpora_with_a_fake_network(tmp_path):
    script = load_script("fetch_email_corpora")

    def handler(request):
        if request.url.path.endswith("phishing-2021"):
            return httpx.Response(404)
        return httpx.Response(200, content=b"data " + request.url.path.encode())

    args = script.parse_args(["--output-dir", str(tmp_path), "--nazario-years", "2020", "2021"])
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        entries = script.fetch(client, args)
    files = [e["file"] for e in entries]
    assert "nazario/phishing-2020.mbox" in files and "nazario/phishing-2021.mbox" not in files
    assert sum(e["label"] == "ham" for e in entries) == len(script.SPAMASSASSIN_FILES)
    assert (tmp_path / "spamassassin" / script.SPAMASSASSIN_FILES[0]).is_file()
