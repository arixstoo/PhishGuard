import json

import pandas as pd
import pytest

from phishguard.text.baseline import BaselineConfig, train_and_evaluate

HAM = [
    "are we still meeting for lunch tomorrow",
    "can you pick up some bread on the way home",
    "the meeting moved to room four",
    "happy birthday hope you have a great day",
    "i will call you after class",
    "thanks for dinner yesterday it was lovely",
]
SPAM = [
    "congratulations you won a free prize call now to claim",
    "urgent your account is suspended verify now at this link",
    "free entry win cash reply win to claim your reward",
    "you have been selected for a free gift click the link now",
]


@pytest.fixture
def corpus() -> pd.DataFrame:
    # Variantes uniques + quelques doublons volontaires pour exercer la déduplication.
    rows = [(0, f"{t} {i}") for i in range(20) for t in HAM]
    rows += [(1, f"{t} {i}") for i in range(20) for t in SPAM]
    rows += [(0, HAM[0])] * 5 + [(1, SPAM[0])] * 5
    return pd.DataFrame(rows, columns=["label", "text"])


def test_end_to_end(corpus):
    model, metrics, errors = train_and_evaluate(corpus, BaselineConfig(seed=0))

    assert metrics["dataset"]["deduplication"]["duplicates_removed"] == 8
    ref = metrics["protocols"]["deduplicated"]
    assert ref["test_messages_seen_in_train"] == 0
    assert ref["recall"] > 0.9 and ref["precision"] > 0.9
    assert model.predict(["claim your free prize now"])[0] == 1
    json.dumps(metrics)  # doit être sérialisable tel quel
    # Les métriques versionnées ne doivent contenir aucun texte de message.
    assert "claim" not in json.dumps(metrics)
    assert set(errors) == {"false_positives", "false_negatives"}


def test_is_deterministic(corpus):
    _, a, _ = train_and_evaluate(corpus, BaselineConfig(seed=1))
    _, b, _ = train_and_evaluate(corpus, BaselineConfig(seed=1))
    assert a == b
