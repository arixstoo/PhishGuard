import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import pytest

from phishguard.data.sms import load_fr_ar_sms
from phishguard.text.models import (
    SentenceEmbedder,
    TextConfig,
    compare,
    embedding_approach,
    markdown_table,
)

ROOT = Path(__file__).resolve().parents[1]

HAM = [
    "are we still meeting for lunch tomorrow",
    "can you pick up some bread on the way home",
    "the meeting moved to room four",
    "happy birthday hope you have a great day",
    "i will call you after class",
    "thanks for dinner yesterday it was lovely",
]
SPAM = [
    "congratulations you won a free prize call 87121 now to claim",
    "urgent your account is suspended verify now at http://x.example",
    "free entry win £500 cash reply win to claim your reward",
    "you have been selected for a free gift click www.gift.example now",
]
CFG = TextConfig(seed=0, c_grid=(1.0,), latency_samples=5)


@pytest.fixture
def corpus() -> pd.DataFrame:
    rows = [(0, f"{t} {i}") for i in range(25) for t in HAM]
    rows += [(1, f"{t} {i}") for i in range(25) for t in SPAM]
    rows += [(0, HAM[0])] * 3
    return pd.DataFrame(rows, columns=["label", "text"])


@pytest.fixture
def external() -> pd.DataFrame:
    return load_fr_ar_sms(ROOT / "datasets/sms_fr_ar.csv")


def test_fr_ar_dataset_is_balanced_and_clean(external):
    assert set(external["lang"]) == {"fr", "ar"}
    assert external.groupby("lang")["label"].mean().between(0.4, 0.6).all()
    assert not external["text"].duplicated().any()
    # Anonymisation : liens uniquement sur le TLD réservé .example, numéros fictifs.
    urls = external["text"].str.findall(r"(?:https?://|www\.)([^/\s:]+)").explode().dropna()
    assert urls.str.endswith(".example").all()
    assert not external["text"].str.contains("@").any()


def test_compare_all_default_approaches(corpus, external):
    models, metrics = compare(corpus, CFG, external=external)

    assert set(models) == {
        "word_logreg", "word_svc", "char_logreg", "char_svc", "char_smishing_logreg"
    }  # fmt: skip
    d = metrics["dataset"]
    assert d["n_train"] + d["n_val"] + d["n_test"] == d["deduplication"]["rows_after"]
    for name, r in metrics["approaches"].items():
        assert r["test"]["f1"] > 0.9, name
        assert r["model_size_bytes"] > 0
        assert r["latency_ms_per_message"]["p50"] >= 0
        assert "external" in r
    assert metrics["external_dataset"]["languages"] == {"fr": 40, "ar": 30}

    text = json.dumps(metrics, ensure_ascii=False)
    assert "lunch" not in text and "colis" not in text  # aucun texte de message versionné
    table = markdown_table(metrics)
    assert table.count("\n") == 1 + len(models) and "FR/AR" in table


def test_c_is_selected_on_validation(corpus):
    _, metrics = compare(corpus, TextConfig(seed=0, c_grid=(0.1, 1.0), latency_samples=2))
    r = metrics["approaches"]["word_logreg"]
    assert set(r["validation_pr_auc_by_C"]) == {"0.1", "1.0"}
    assert r["selected_C"] in (0.1, 1.0)


def test_is_deterministic(corpus):
    def strip(m):
        for r in m["approaches"].values():
            r.pop("latency_ms_per_message")
        return m

    _, a = compare(corpus, CFG)
    _, b = compare(corpus, CFG)
    assert strip(a) == strip(b)


class FakeEncoder:
    """Remplace sentence-transformers : un vecteur par mot-clé, sans réseau."""

    KEYS = ("free", "win", "urgent", "claim", "lunch", "meeting", "bread", "call")

    def encode(self, texts, **_):
        return np.array([[float(k in t) for k in self.KEYS] + [1.0] for t in texts])


def test_embedding_approach_with_injected_encoder(corpus, tmp_path):
    models, metrics = compare(corpus, CFG, approaches=[embedding_approach(FakeEncoder())])
    r = metrics["approaches"]["embeddings_logreg"]
    assert r["test"]["recall"] > 0.9
    assert r["encoder_model"] == "paraphrase-multilingual-MiniLM-L12-v2"

    # Le .joblib ne doit pas embarquer l'encodeur (des centaines de Mo).
    path = tmp_path / "m.joblib"
    joblib.dump(models["embeddings_logreg"], path)
    assert joblib.load(path).named_steps["embed"].encoder is None


def test_embedder_pickles_without_encoder():
    emb = SentenceEmbedder(encoder=FakeEncoder())
    assert emb.__getstate__()["encoder"] is None
