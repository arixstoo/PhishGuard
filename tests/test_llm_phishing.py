"""Tests du jeu « phishing rédigé par un LLM » et de sa mesure (étape 3.10).

Les garde-fous du chargeur sont la promesse du protocole : un fichier qui cite un vrai
domaine, une vraie adresse ou un numéro de téléphone est refusé en entier, sans que
son texte apparaisse dans l'erreur.
"""

import importlib.util
import json
from pathlib import Path

import numpy as np
import pytest

from phishguard.data import llm_phishing as L
from phishguard.text import models as M

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "evaluate_llm_phishing", ROOT / "scripts/evaluate_llm_phishing.py"
)
script = importlib.util.module_from_spec(spec)
spec.loader.exec_module(script)

PHISHING = [
    "Your Globex account is locked. Verify your password at https://globex.example.net/verify",
    "Northwind Bank: confirm the code we sent you at https://nw-bank.test/code to stop the transfer",
    "Acme Parcel: pay the $1.99 delivery fee at https://acme-parcel.test/fee",
    "Hi, I need a quick favour: can you buy gift cards for a client today?",
]
LEGITIMATE = [
    "Reminder: the team meeting starts at 10 am in room 4B.",
    "Your Contoso order has shipped and will arrive on Thursday.",
    "Thanks for covering my shift on Saturday, see you Monday.",
    "Your statement is available in your account at https://portal.example.com/statements",
]


def write(path, texts_labels, **extra):
    with path.open("w", encoding="utf-8") as handle:
        for i, (text, label) in enumerate(texts_labels):
            row = {
                "id": f"m{i}",
                "label": label,
                "family": "f" + str(label),
                "channel": "sms" if i % 2 else "email",
                "text": text,
                **extra,
            }
            handle.write(json.dumps(row) + "\n")
    return path


@pytest.fixture
def dataset(tmp_path):
    return write(
        tmp_path / "messages.jsonl", [(t, 1) for t in PHISHING] + [(t, 0) for t in LEGITIMATE]
    )


# --------------------------------------------------------------------------- #
# Garde-fous
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "host",
    ["example.com", "www.example.net", "a.b.example.org", "bank.test", "x.example", "y.invalid"],
)
def test_reserved_hosts_are_accepted(host):
    assert L.is_reserved_host(host)


@pytest.mark.parametrize("host", ["paypal.com", "example.co.uk", "example.com.evil.net", "test.io"])
def test_real_hosts_are_refused(host):
    assert not L.is_reserved_host(host)


@pytest.mark.parametrize(
    ("text", "problem"),
    [
        ("Log in at https://paypal.com/login now", "domaine non réservé"),
        ("Visit secure-bank.net today", "domaine non réservé"),
        ("Write to support@gmail.com", "adresse email"),
        ("Call us on +33 6 12 34 56 78", "téléphone"),
        ("Call 202 555 0234 now", "téléphone"),  # hors de la plage fictive 555-01xx
    ],
)
def test_safety_violations_are_reported(text, problem):
    assert any(problem in p for p in L.safety_violations(text))


@pytest.mark.parametrize(
    "text",
    [
        "Invoice 2026-118 is due, total $1,240.00, ref 48-2207.",
        "Your code is 482913.",
        "Call the fictional line 555-0123.",
        "Call 202 555 0187, a fictional number.",
        "See https://portal.example.com/a/b?x=1 or write to help@example.org",
        "Read the report.pdf, e.g. page 3.",
    ],
)
def test_harmless_text_passes(text):
    assert L.safety_violations(text) == []


def test_loader_accepts_a_balanced_safe_set(dataset):
    frame = L.load_llm_messages(dataset)
    assert len(frame) == 8 and frame["label"].sum() == 4
    assert list(frame.columns) == list(L.REQUIRED_FIELDS)


def test_unsafe_message_refuses_the_whole_file_without_echoing_it(tmp_path):
    secret = "Pay now at https://real-bank.com/pay"
    path = write(tmp_path / "bad.jsonl", [(secret, 1), ("hello there", 0)])
    with pytest.raises(L.UnsafeMessageError) as error:
        L.load_llm_messages(path)
    assert "m0" in str(error.value) and "real-bank.com" in str(error.value)
    assert secret not in str(error.value)


@pytest.mark.parametrize(
    ("rows", "message"),
    [
        ([("a", 1), ("b", 1), ("c", 0)], "tailles différentes"),
        ([("a", 2), ("b", 0)], "label"),
        ([("", 1), ("b", 0)], "vide"),
        ([("x" * (L.MAX_TEXT_CHARS + 1), 1), ("b", 0)], "caractères"),
    ],
)
def test_invalid_sets_are_refused(tmp_path, rows, message):
    with pytest.raises(ValueError, match=message):
        L.load_llm_messages(write(tmp_path / "bad.jsonl", rows))


def test_duplicate_ids_and_bad_channels_are_refused(tmp_path):
    path = tmp_path / "dup.jsonl"
    row = {"id": "a", "label": 1, "family": "f", "channel": "sms", "text": "hi"}
    path.write_text(json.dumps(row) + "\n" + json.dumps({**row, "label": 0}) + "\n")
    with pytest.raises(ValueError, match="double"):
        L.load_llm_messages(path)
    path.write_text(json.dumps({**row, "channel": "fax"}) + "\n")
    with pytest.raises(ValueError, match="canal"):
        L.load_llm_messages(path, balanced=False)
    path.write_text("{not json\n")
    with pytest.raises(ValueError, match="JSON"):
        L.load_llm_messages(path)


def test_control_set_may_hold_a_single_class(tmp_path):
    path = write(tmp_path / "control.jsonl", [(t, 0) for t in LEGITIMATE])
    assert len(L.load_llm_messages(path, balanced=False)) == 4
    with pytest.raises(ValueError, match="tailles"):
        L.load_llm_messages(path)


def test_dataset_files_are_never_versioned():
    ignored = (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
    assert "/data/" in ignored


# --------------------------------------------------------------------------- #
# Mesure
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("categories", "expected"),
    [
        (("link", "account"), True),
        (("link", "code"), True),
        (("link", "money"), False),
        (("account", "code"), False),
        ((), False),
    ],
)
def test_lure_rule(categories, expected):
    assert script.lure_rule(categories) is expected


def test_detection_counts_recall_and_fpr():
    result = script.detection(np.array([1, 0, 1, 1]), np.array([1, 1, 0, 0]))
    assert result["recall"]["rate"] == 0.5 and result["fpr"]["rate"] == 1.0


@pytest.fixture
def tiny_model(tmp_path):
    texts = PHISHING + LEGITIMATE
    labels = np.array([1] * len(PHISHING) + [0] * len(LEGITIMATE))
    estimator = M.APPROACHES["word_logreg"].build({"C": 1.0}, 0).fit(texts, labels)
    model = M.TextModel(estimator, "word_logreg", 0.5, {"model_version": "text_tiny"})
    return model.save(tmp_path / "text_tiny.joblib")


def test_end_to_end_report_has_no_message_text(tmp_path, dataset, tiny_model):
    control = write(tmp_path / "control.jsonl", [(LEGITIMATE[-1], 0), (LEGITIMATE[0], 0)])
    report_path = tmp_path / "llm.json"
    doc = tmp_path / "report.md"
    doc.write_text(
        "# R\n\n<!-- generated:llm-phishing:start -->\n<!-- generated:llm-phishing:end -->\n",
        encoding="utf-8",
    )
    code = script.main(
        [
            "--data",
            str(dataset),
            "--control",
            str(control),
            "--models",
            str(tiny_model),
            "--sms-data",
            str(tmp_path / "absent"),
            "--report",
            str(report_path),
            "--doc",
            str(doc),
        ]
    )
    assert code == 0
    report = json.loads(report_path.read_text(encoding="utf-8"))
    entry = report["models"]["text_tiny"]
    assert entry["llm"]["recall"]["n"] == 4 and entry["llm"]["fpr"]["n"] == 4
    assert entry["control"]["model"]["n"] == 2
    assert report["control"]["added_after_first_measurement"] is True
    assert report["rule"]["definition"] == "link and (code or account)"
    rendered = doc.read_text(encoding="utf-8")
    assert "#### Ce qui compense" in rendered and "`text_tiny`" in rendered
    for text in PHISHING + LEGITIMATE:
        assert text not in report_path.read_text(encoding="utf-8")
        assert text not in rendered


def test_missing_dataset_is_an_error(tmp_path):
    assert script.main(["--data", str(tmp_path / "absent.jsonl"), "--doc", "none"]) == 1


def test_report_document_has_the_llm_block():
    doc = (ROOT / "docs/robustness-report.md").read_text(encoding="utf-8")
    assert doc.count(f"<!-- generated:{script.DOC_BLOCK}:start -->") == 1
