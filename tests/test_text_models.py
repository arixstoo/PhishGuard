"""Tests des modèles de texte SMS, du split par gabarit et du jeu FR/AR (étape 1.9)."""

import importlib.util
import json
import re
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from phishguard.data import sms as D
from phishguard.text import models as M

ROOT = Path(__file__).resolve().parents[1]
FR_AR = ROOT / "datasets" / "sms_fr_ar.csv"
spec = importlib.util.spec_from_file_location("train_text", ROOT / "scripts" / "train_text.py")
train_script = importlib.util.module_from_spec(spec)
spec.loader.exec_module(train_script)

SPAM = [
    "WINNER! You have won a £{n} prize, call 0906170{n} now",
    "URGENT: your account is suspended, verify at http://acc-{n}.example",
    "Free entry to win {n} cash, text WIN to 8{n}",
    "Claim your bonus of ${n} today, reply YES",
]
HAM = [
    "see you at {n} tonight",
    "can you buy bread on the way home {n}",
    "the meeting moved to room {n}",
    "thanks for dinner yesterday, see you {n}",
    "I am running late by {n} minutes",
]


def corpus(n_per_template: int = 12) -> pd.DataFrame:
    """Corpus synthétique en anglais, au format de load_sms_collection."""
    rows = []
    words = ("alpha", "bravo", "delta", "echo", "golf", "hotel", "kilo", "lima", "oscar")
    for templates, label in ((SPAM, 1), (HAM, 0)):
        for t in templates:
            for i in range(n_per_template):
                # Un mot différent par message : autant de gabarits que de messages, sauf
                # les variantes de campagne ajoutées plus bas.
                text = f"{t.format(n=100 + 37 * i)} {words[i % len(words)]}{i}"
                rows.append({"label": label, "text": text})
                if i % 4 == 0:  # variante de campagne : même gabarit, autre nombre
                    rows.append({"label": label, "text": text.replace(str(100 + 37 * i), "7")})
    for i in range(60):  # gabarits uniques, pour que chaque bloc ait des deux classes
        rows.append({"label": 0, "text": f"note {chr(97 + i % 26)}{chr(97 + i // 26)} ok"})
    return pd.DataFrame(rows)


def write_uci(df: pd.DataFrame, path: Path) -> Path:
    names = {0: "ham", 1: "spam"}
    path.write_text(
        "".join(f"{names[label]}\t{text}\n" for label, text in zip(df["label"], df["text"])),
        encoding="utf-8",
    )
    return path


# --------------------------------------------------------------------------- #
# Split par gabarit
# --------------------------------------------------------------------------- #


def test_template_key_merges_campaign_variants():
    a = D.template_key("WIN £500 now, call 0906170123")
    b = D.template_key("win £1000 now,  call 0906170999")
    assert a == b == "win £0 now, call 0"
    assert D.template_key("ＷＩＮ") == "win"  # NFKC


def test_split_is_grouped_stratified_and_deterministic():
    df = corpus()
    split = D.split_sms(df, seed=1)
    assert list(split.cat.categories) == list(D.SMS_SPLITS)
    keys = df["text"].map(D.template_key)
    assert (
        keys.groupby(split, observed=True).apply(set).pipe(lambda s: len(set.intersection(*s)))
    ) == 0
    blocks = {name: df[split == name] for name in D.SMS_SPLITS}
    assert D.template_overlap(blocks["train"]["text"], blocks["test"]["text"]) == 0
    for block in blocks.values():
        assert block["label"].nunique() == 2
    assert split.equals(D.split_sms(df, seed=1))


@pytest.mark.parametrize("fractions", [(0.7, 0.2, 0.2), (0.72, 0.14, 0.14), (1.0, 0.0, 0.0)])
def test_split_rejects_invalid_fractions(fractions):
    with pytest.raises(ValueError):
        D.split_sms(corpus(), fractions=fractions)


def test_split_rejects_an_empty_frame():
    with pytest.raises(ValueError):
        D.split_sms(pd.DataFrame({"label": [], "text": []}))


def test_template_overlap_counts_leaks():
    train = pd.Series(["win £5 now", "hello"])
    other = pd.Series(["WIN £900 now", "bye"])
    assert D.template_overlap(train, other) == 1


# --------------------------------------------------------------------------- #
# Jeu français / arabe
# --------------------------------------------------------------------------- #


def test_fr_ar_dataset_is_valid_and_balanced():
    df = D.load_sms_fr_ar(FR_AR)
    counts = df.groupby(["lang", "label"]).size().to_dict()
    assert counts == {("ar", 0): 20, ("ar", 1): 20, ("fr", 0): 30, ("fr", 1): 30}
    assert not df["text"].duplicated().any()
    assert df["id"].str.fullmatch(r"(fr|ar)-\d{3}").all()


_LINK_RE = re.compile(r"(?:https?://|www\.)?[\w.-]+\.[a-z]{2,}(?:/\S*)?", re.IGNORECASE)
_FICTION_PHONES = (
    re.compile(r"0[1-9](?: ?\d\d){4}"),  # français, vérifié ci-dessous
    re.compile(r"0[567][5-7]0000\d\d\d?"),  # algériens fictifs
)


def test_fr_ar_dataset_is_anonymized():
    df = D.load_sms_fr_ar(FR_AR)
    for text in df["text"]:
        for match in _LINK_RE.finditer(text):
            host = re.sub(r"^(?:https?://)?", "", match.group(0)).split("/")[0].rstrip(".,")
            if re.fullmatch(r"[\d.,]+", host) or not re.search(r"[a-z]", host, re.IGNORECASE):
                continue  # nombre décimal (« 1.99 »), pas un domaine
            assert host.endswith(".example"), f"domaine non réservé : {host!r}"
        for match in re.finditer(r"\+?\d[\d ]{7,}\d", text):
            digits = match.group(0).replace(" ", "")
            if len(digits) < 9:
                continue
            fictitious_fr = digits.startswith(("019900", "063998"))
            fictitious_dz = re.fullmatch(r"0[567][567]00000\d\d", digits) is not None
            assert fictitious_fr or fictitious_dz, f"numéro non fictif : {digits}"


def test_fr_ar_loader_rejects_bad_files(tmp_path):
    path = tmp_path / "x.csv"
    path.write_text("id,lang,label,category,text\nx-1,es,1,a,hola\n", encoding="utf-8")
    with pytest.raises(ValueError, match="langues"):
        D.load_sms_fr_ar(path)
    path.write_text("id,lang,label,category,text\nx-1,fr,2,a,salut\n", encoding="utf-8")
    with pytest.raises(ValueError, match="étiquettes"):
        D.load_sms_fr_ar(path)
    path.write_text("id,lang,label,category,text\nx,fr,1,a,a\nx,fr,0,a,b\n", encoding="utf-8")
    with pytest.raises(ValueError, match="double"):
        D.load_sms_fr_ar(path)
    path.write_text("id,lang,label\nx,fr,1\n", encoding="utf-8")
    with pytest.raises(ValueError, match="colonnes"):
        D.load_sms_fr_ar(path)


# --------------------------------------------------------------------------- #
# Approches et recherche
# --------------------------------------------------------------------------- #


@pytest.fixture(scope="module")
def blocks():
    df = corpus()
    split = D.split_sms(df, seed=0)
    return {name: df[split == name].reset_index(drop=True) for name in D.SMS_SPLITS}


def xy(block):
    return block["text"], block["label"].to_numpy()


def test_registry():
    assert set(M.DEFAULT_APPROACHES) == set(M.APPROACHES) - {"embeddings_logreg"}
    for approach in M.APPROACHES.values():
        assert approach.grid and all("C" in p for p in approach.grid)


@pytest.mark.parametrize("name", M.DEFAULT_APPROACHES)
def test_every_default_approach_trains_and_scores(name, blocks):
    estimator = M.APPROACHES[name].build({"C": 1.0}, seed=0).fit(*xy(blocks["train"]))
    scores = M.scores_of(estimator, blocks["test"]["text"])
    assert scores.shape == (len(blocks["test"]),) and np.isfinite(scores).all()


def test_search_keeps_the_best_setting_and_is_deterministic(blocks):
    grids = {"char_logreg": M._grid(C=(0.001, 1.0)), "word_svm": M._grid(C=(0.1,))}
    first = M.search(xy(blocks["train"]), xy(blocks["validation"]), approaches=grids, grids=grids)
    second = M.search(xy(blocks["train"]), xy(blocks["validation"]), approaches=grids, grids=grids)
    assert [t.to_dict() | {"fit_seconds": 0} for t in first.trials] == [
        t.to_dict() | {"fit_seconds": 0} for t in second.trials
    ]
    trials = [t for t in first.trials if t.approach == "char_logreg"]
    assert first.best["char_logreg"].key == max(t.key for t in trials)
    assert first.best_approach().key == max(t.key for t in first.best.values())
    with pytest.raises(ValueError, match="inconnues"):
        M.search(xy(blocks["train"]), xy(blocks["validation"]), approaches=["bert"])


def test_decision_threshold_and_evaluation():
    y = np.array([0] * 100 + [1] * 10)
    scores = np.concatenate([np.linspace(0, 0.5, 100), np.linspace(0.4, 1, 10)])
    t = M.decision_threshold(y, scores, fpr=0.05)
    assert (scores[y == 0] > t).mean() <= 0.05
    result = M.evaluate_at_threshold(y, scores, t)
    assert result["fpr"] <= 0.05 and 0 < result["recall"] <= 1
    assert result["confusion_matrix"]["tp"] + result["confusion_matrix"]["fn"] == 10
    one_class = M.evaluate_at_threshold(np.ones(3), np.array([0.1, 0.9, 0.95]), 0.5)
    assert one_class["pr_auc"] is None and one_class["fpr"] is None
    assert one_class["recall"] == pytest.approx(2 / 3, abs=1e-4)


def test_cost_measures(blocks):
    estimator = M.APPROACHES["word_logreg"].build({"C": 1.0}, 0).fit(*xy(blocks["train"]))
    latency = M.measure_latency(estimator, blocks["test"]["text"].tolist(), single_calls=10)
    assert 0 < latency["latency_ms_p50"] <= latency["latency_ms_p95"]
    assert latency["single_calls"] == 10
    assert M.serialized_size(estimator) > 0


def test_directory_size(tmp_path):
    (tmp_path / "a").write_bytes(b"x" * 10)
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "b").write_bytes(b"y" * 5)
    assert M.directory_size(tmp_path) == 15


# --------------------------------------------------------------------------- #
# Embeddings (encodeur factice : aucun téléchargement)
# --------------------------------------------------------------------------- #


class FakeEncoder:
    def __init__(self, name):
        self.name = name

    def encode(self, texts, batch_size, normalize_embeddings, show_progress_bar):
        return np.array([[len(t), t.count("!"), sum(c.isdigit() for c in t)] for t in texts], float)


def fake_factory(name):
    return FakeEncoder(name)


def test_embedder_is_never_serialized_with_its_encoder(tmp_path, blocks):
    embedder = M.SentenceEmbedder("fake-model", encoder_factory=fake_factory)
    vectors = embedder.fit(["a"]).transform(["hello!", "123"])
    assert vectors.shape == (2, 3) and vectors.dtype == np.float32
    assert "_model" not in embedder.__getstate__()

    approach = M.Approach(
        "embeddings_logreg",
        "test",
        lambda: M.SentenceEmbedder("fake-model", encoder_factory=fake_factory),
        M.logistic,
        M.QUICK_GRID,
    )
    result = M.search(
        xy(blocks["train"]),
        xy(blocks["validation"]),
        approaches=["embeddings_logreg"],
        builders={"embeddings_logreg": approach},
    )
    model = M.TextModel(result.estimators["embeddings_logreg"], "embeddings_logreg", 0.5)
    loaded = M.TextModel.load(model.save(tmp_path / "emb.joblib"))
    np.testing.assert_allclose(loaded.score(["hi"]), model.score(["hi"]))


def test_embedder_without_the_library_says_how_to_install(monkeypatch):
    import builtins

    real_import = builtins.__import__

    def no_sentence_transformers(name, *args, **kwargs):
        if name.startswith("sentence_transformers"):
            raise ImportError(name)
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", no_sentence_transformers)
    with pytest.raises(ImportError, match="embeddings"):
        M.SentenceEmbedder().transform(["x"])


# --------------------------------------------------------------------------- #
# Artefact
# --------------------------------------------------------------------------- #


def test_text_model_round_trip(tmp_path, blocks):
    estimator = M.APPROACHES["char_svm"].build({"C": 0.1}, 0).fit(*xy(blocks["train"]))
    model = M.TextModel(estimator, "char_svm", threshold=0.0, metadata={"a": 1})
    loaded = M.TextModel.load(model.save(tmp_path / "sub" / "text.joblib"))
    texts = blocks["test"]["text"]
    np.testing.assert_allclose(loaded.score(texts), model.score(texts))
    np.testing.assert_array_equal(loaded.predict(texts), (model.score(texts) > 0.0).astype(int))
    assert loaded.approach == "char_svm" and loaded.metadata == {"a": 1}


def test_text_model_rejects_unknown_files(tmp_path):
    import joblib

    path = tmp_path / "x.joblib"
    joblib.dump({"format_version": 0}, path)
    with pytest.raises(ValueError, match="format"):
        M.TextModel.load(path)


# --------------------------------------------------------------------------- #
# Script
# --------------------------------------------------------------------------- #

DOC = (
    "# T\n\nÀ la main.\n\n<!-- generated:train-text:start -->\n<!-- generated:train-text:end -->\n"
)


def test_script_end_to_end(tmp_path):
    data = write_uci(corpus(), tmp_path / "SMSSpamCollection")
    doc = tmp_path / "text-models.md"
    doc.write_text(DOC, encoding="utf-8")
    report_path, model_path = tmp_path / "text_v1.json", tmp_path / "text_v1.joblib"
    args = ["--offline", "--data", str(data), "--model-out", str(model_path)]
    args += ["--report", str(report_path), "--doc", str(doc), "--quick"]
    assert train_script.main(args) == 0

    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert set(report["approaches"]) == set(M.DEFAULT_APPROACHES)
    assert sum(e["selected"] for e in report["approaches"].values()) == 1
    for name in ("validation", "test"):
        assert report["dataset"]["blocks"][name]["templates_seen_in_train"] == 0
    for entry in report["approaches"].values():
        assert set(entry["fr_ar"]) == {"fr", "ar", "all"}
        assert entry["fr_ar"]["fr"]["n"] == 60 and entry["fr_ar"]["ar"]["n"] == 40
    text = report_path.read_text(encoding="utf-8")
    for message in list(corpus()["text"][:20]) + list(D.load_sms_fr_ar(FR_AR)["text"][:20]):
        assert message not in text  # aucun texte de message dans le rapport versionné

    model = M.TextModel.load(model_path)
    assert model.approach == report["selected"]["approach"]
    rendered = doc.read_text(encoding="utf-8")
    assert "À la main." in rendered and "**(retenu)**" in rendered and "arabe" in rendered


def test_script_requires_its_inputs(tmp_path):
    assert (
        train_script.main(["--offline", "--data", str(tmp_path / "absent"), "--doc", "none"]) == 1
    )
    data = write_uci(corpus(), tmp_path / "SMSSpamCollection")
    args = ["--offline", "--data", str(data), "--fr-ar", str(tmp_path / "absent.csv")]
    assert train_script.main([*args, "--doc", "none"]) == 1


def test_embeddings_flag_adds_the_approach():
    args = train_script.parse_args(["--embeddings", "--doc", "none"])
    assert "embeddings_logreg" in args.approaches and args.doc is None
