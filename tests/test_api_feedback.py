"""Retours sans risque (étape 4.10) : quarantaine, limites, relecture, non-influence.

Critère de fin du cahier des charges : le retour est limité en débit, validé, et **un
test vérifie qu'il n'influence pas le modèle en cours d'utilisation**. Ce dernier point
est vérifié deux fois : par le comportement (rafale de faux retours, puis acceptation de
tous, sans qu'aucun verdict ni aucune empreinte ne bouge) et par la structure (aucun code
d'analyse ou d'entraînement ne lit la quarantaine).
"""

from __future__ import annotations

import ast
import csv
import hashlib
import sqlite3
from datetime import date, timedelta
from pathlib import Path

import pytest
from api_support import ROOT, api_client, settings_for

from phishguard.api.feedback import main as feedback_cli
from phishguard.api.feedback import parse_ids
from phishguard.api.pseudonym import ReporterPseudonyms
from phishguard.api.security import Client
from phishguard.api.storage import SCHEMA_VERSION, Database, QuarantineFullError

PHISHING_URL = "http://secure-login-verify.xyz/verify/account/123456"
PROBE_URLS = [
    PHISHING_URL,
    "https://alpha12.com/",
    "http://secure-nova-login7.xyz/verify/account/42",
    "https://www.green3.org/blog/green",
]


def feedback(domain="paypal-secure.example", verdict="phishing", judgement="false_positive"):
    return {"domain": domain, "verdict": verdict, "judgement": judgement}


def rows(database: Database) -> list[sqlite3.Row]:
    db = sqlite3.connect(database.path)
    db.row_factory = sqlite3.Row
    try:
        return db.execute("SELECT * FROM feedback_quarantine ORDER BY id").fetchall()
    finally:
        db.close()


# --------------------------------------------------------------------------- #
# Limites et validation
# --------------------------------------------------------------------------- #


def test_feedback_has_its_own_low_quota(api_models_dir, tmp_path):
    settings = settings_for(
        api_models_dir,
        tmp_path,
        rate_limit_anonymous="100/minute",
        rate_limit_feedback="3/minute",
        feedback_dedup_seconds=0,
    )
    with api_client(settings) as client:
        statuses = [
            client.post("/v1/feedback", json=feedback(f"d{i}.example")).status_code
            for i in range(5)
        ]
        assert statuses == [202, 202, 202, 429, 429]
        limited = client.post("/v1/feedback", json=feedback("d9.example"))
        assert limited.json()["error"]["code"] == "rate_limited"
        assert "retry-after" in limited.headers
        # Le quota des retours ne consomme pas celui des analyses.
        assert client.post("/v1/analyze/url", json={"url": PHISHING_URL}).status_code == 200


def test_route_quota_and_tier_quota_do_not_share_a_counter(api_models_dir, tmp_path):
    # Même valeur pour les deux limites : chacune compte une fois par requête.
    settings = settings_for(
        api_models_dir,
        tmp_path,
        rate_limit_anonymous="4/minute",
        rate_limit_feedback="4/minute",
        feedback_dedup_seconds=0,
    )
    with api_client(settings) as client:
        statuses = [
            client.post("/v1/feedback", json=feedback(f"e{i}.example")).status_code
            for i in range(5)
        ]
    assert statuses == [202, 202, 202, 202, 429]


def test_repeated_report_is_stored_once_and_answered_identically(api_models_dir, tmp_path):
    with api_client(settings_for(api_models_dir, tmp_path)) as client:
        database = client.app.state.phishguard.database
        answers = [client.post("/v1/feedback", json=feedback()) for _ in range(3)]
        assert {a.status_code for a in answers} == {202}
        assert {a.json()["status"] for a in answers} == {"quarantined"}
        assert database.count_feedback() == 1
        # Autre jugement ou autre domaine : un nouveau signalement.
        client.post("/v1/feedback", json=feedback(verdict="safe", judgement="false_negative"))
        client.post("/v1/feedback", json=feedback("autre.example"))
        assert database.count_feedback() == 3


def test_full_quarantine_refuses_new_reports(api_models_dir, tmp_path):
    settings = settings_for(api_models_dir, tmp_path, feedback_max_pending=2)
    with api_client(settings) as client:
        assert client.post("/v1/feedback", json=feedback("a.example")).status_code == 202
        assert client.post("/v1/feedback", json=feedback("b.example")).status_code == 202
        refused = client.post("/v1/feedback", json=feedback("c.example"))
        assert refused.status_code == 503
        assert refused.json()["error"]["code"] == "feedback_unavailable"
        assert refused.headers["retry-after"] == "3600"
        assert refused.headers["x-content-type-options"] == "nosniff"
        # Une fois le lot relu, la quarantaine accepte à nouveau.
        database = client.app.state.phishguard.database
        database.decide_feedback([r.id for r in database.pending_feedback()], "rejected")
        assert client.post("/v1/feedback", json=feedback("c.example")).status_code == 202


def test_quarantine_cap_is_atomic(tmp_path):
    database = Database(tmp_path / "db.sqlite3")
    for i in range(3):
        database.quarantine_feedback(
            domain=f"x{i}.example",
            verdict="phishing",
            judgement="false_positive",
            key_id=None,
            max_pending=3,
        )
    with pytest.raises(QuarantineFullError):
        database.quarantine_feedback(
            domain="y.example",
            verdict="phishing",
            judgement="false_positive",
            key_id=None,
            max_pending=3,
        )
    assert database.count_feedback() == 3


# --------------------------------------------------------------------------- #
# Vie privée : ni IP ni clé, un pseudonyme du jour
# --------------------------------------------------------------------------- #


def test_reporter_is_a_pseudonym_never_the_ip_or_the_key(api_models_dir, tmp_path):
    with api_client(settings_for(api_models_dir, tmp_path)) as client:
        state = client.app.state.phishguard
        record, key = state.database.create_key("feedback-test")
        client.post("/v1/feedback", json=feedback("anon.example"))
        client.post("/v1/feedback", json=feedback("keyed.example"), headers={"X-API-Key": key})
        stored = rows(state.database)
    anonymous, keyed = stored
    assert anonymous["reporter"].startswith("anon:") and anonymous["client_tier"] == "anonymous"
    assert anonymous["key_id"] is None
    assert keyed["reporter"] == f"key:{record.key_id}"
    assert keyed["client_tier"] == "authenticated"
    # Ni l'adresse du client (« testclient » pour TestClient) ni la clé, nulle part.
    for row in stored:
        assert "testclient" not in str(tuple(row)) and key not in str(tuple(row))


def test_pseudonyms_are_stable_within_a_day_and_unlinkable_across_days():
    today = [date(2026, 11, 12)]
    pseudonyms = ReporterPseudonyms(today=lambda: today[0])
    alice, bob = Client("anonymous", "192.0.2.1"), Client("anonymous", "192.0.2.2")
    first = pseudonyms(alice)
    assert pseudonyms(alice) == first and pseudonyms(bob) != first
    assert first.startswith("anon:") and "192.0.2.1" not in first
    today[0] += timedelta(days=1)
    assert pseudonyms(alice) != first  # nouvelle clé : plus de lien avec la veille
    # Deux processus (deux clés) ne produisent pas le même pseudonyme.
    assert ReporterPseudonyms(today=lambda: today[0])(alice) != pseudonyms(alice)


# --------------------------------------------------------------------------- #
# Non-influence sur le modèle en cours d'utilisation
# --------------------------------------------------------------------------- #


def _fingerprints(models_dir: Path) -> dict[str, str]:
    return {
        p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(models_dir.iterdir())
    }


def test_feedback_never_influences_the_running_model(api_models_dir, tmp_path):
    """Rafale de faux retours (empoisonnement), puis acceptation de tous : ni les fichiers
    des modèles, ni ``GET /v1/model``, ni aucun score ne change."""
    settings = settings_for(
        api_models_dir, tmp_path, rate_limit_enabled=False, feedback_dedup_seconds=0
    )
    files_before = _fingerprints(api_models_dir)
    with api_client(settings) as client:
        model_before = client.get("/v1/model").json()
        before = [client.post("/v1/analyze/url", json={"url": u}).json() for u in PROBE_URLS]

        for i in range(300):
            response = client.post(
                "/v1/feedback",
                json=feedback("secure-login-verify.xyz", "phishing", "false_positive"),
                headers={"X-Forwarded-For": f"198.51.100.{i % 250}"},  # ignoré : aucun proxy
            )
            assert response.status_code == 202
        database = client.app.state.phishguard.database
        assert database.count_feedback() == 300
        # Même après une relecture qui accepte tout, rien ne bouge : accepter n'est
        # qu'une décision humaine enregistrée.
        assert database.decide_feedback(range(1, 301), "accepted") == 300

        after = [client.post("/v1/analyze/url", json={"url": u}).json() for u in PROBE_URLS]
        assert client.get("/v1/model").json() == model_before
    assert _fingerprints(api_models_dir) == files_before
    for b, a in zip(before, after, strict=True):
        a.pop("latency_ms"), b.pop("latency_ms")
        assert a == b


ALLOWED_READERS = {
    "src/phishguard/api/storage.py",
    "src/phishguard/api/feedback.py",
    "src/phishguard/api/routers/feedback.py",
}
QUARANTINE_API = {"quarantine_feedback", "pending_feedback", "feedback_summary", "decide_feedback"}


def _python_files() -> list[Path]:
    return sorted([*(ROOT / "src/phishguard").rglob("*.py"), *(ROOT / "scripts").rglob("*.py")])


def test_no_analysis_or_training_code_reads_the_quarantine():
    """Seuls la route, le stockage et l'outil de relecture touchent la quarantaine ; aucun
    module hors de ``phishguard.api`` n'importe le stockage de l'API."""
    offenders = []
    for path in _python_files():
        relative = path.relative_to(ROOT).as_posix()
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source)
        if relative not in ALLOWED_READERS:
            if "feedback_quarantine" in source:
                offenders.append(f"{relative} : table feedback_quarantine")
            for node in ast.walk(tree):
                if isinstance(node, ast.Attribute) and node.attr in QUARANTINE_API:
                    offenders.append(f"{relative} : {node.attr}")
        if not relative.startswith("src/phishguard/api/"):
            for node in ast.walk(tree):
                module = node.module if isinstance(node, ast.ImportFrom) else None
                names = [a.name for a in node.names] if isinstance(node, ast.Import) else []
                if any((m or "").startswith("phishguard.api") for m in [module, *names]):
                    offenders.append(f"{relative} : importe phishguard.api")
    assert offenders == []


# --------------------------------------------------------------------------- #
# Schéma : migration d'une base de l'étape 4.4
# --------------------------------------------------------------------------- #


V1_SCHEMA = """
CREATE TABLE api_keys (key_id TEXT PRIMARY KEY, key_hash TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL, created_at TEXT NOT NULL, revoked_at TEXT);
CREATE TABLE feedback_quarantine (id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL, verdict TEXT NOT NULL, judgement TEXT NOT NULL,
    received_at TEXT NOT NULL, key_id TEXT, reviewed INTEGER NOT NULL DEFAULT 0);
INSERT INTO feedback_quarantine (domain, verdict, judgement, received_at)
    VALUES ('old.example', 'phishing', 'false_positive', '2026-11-01T00:00:00+00:00');
PRAGMA user_version=1;
"""


def test_version_1_database_is_migrated_in_place(tmp_path):
    path = tmp_path / "v1.sqlite3"
    db = sqlite3.connect(path)
    db.executescript(V1_SCHEMA)
    db.close()

    database = Database(path)
    [old] = database.pending_feedback()
    assert (old.domain, old.reporter, old.decision) == ("old.example", None, None)
    database.quarantine_feedback(
        domain="new.example",
        verdict="safe",
        judgement="false_negative",
        key_id=None,
        reporter="anon:0123456789abcdef",
        client_tier="anonymous",
    )
    assert database.count_feedback() == 2
    Database(path)  # réouverture : migration déjà faite, rien ne casse
    db = sqlite3.connect(path)
    assert db.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
    db.close()


def test_newer_schema_is_refused(tmp_path):
    path = tmp_path / "future.sqlite3"
    db = sqlite3.connect(path)
    db.execute(f"PRAGMA user_version={SCHEMA_VERSION + 1}")
    db.close()
    with pytest.raises(RuntimeError, match="plus récent"):
        Database(path)


def test_bad_decision_and_ranges_are_refused(tmp_path):
    database = Database(tmp_path / "db.sqlite3")
    with pytest.raises(ValueError):
        database.decide_feedback([1], "maybe")  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        database.pending_feedback(limit=0)
    with pytest.raises(ValueError):
        database.purge_feedback(-1)
    assert database.decide_feedback([], "accepted") == 0


# --------------------------------------------------------------------------- #
# Relecture par lots (python -m phishguard.api.feedback)
# --------------------------------------------------------------------------- #


@pytest.fixture
def reviewed_db(tmp_path) -> Path:
    database = Database(tmp_path / "review.sqlite3")
    for i, reporter in enumerate(["anon:a", "anon:a", "anon:a", "anon:b"]):
        database.quarantine_feedback(
            domain="flood.example" if i < 3 else "single.example",
            verdict="phishing",
            judgement="false_positive",
            key_id=None,
            reporter=reporter,
            client_tier="anonymous",
        )
    return database.path


def test_summary_shows_distinct_sources(reviewed_db, capsys):
    assert feedback_cli(["--database", str(reviewed_db), "summary"]) == 0
    out = capsys.readouterr().out
    assert "4 retours en attente" in out
    flood = next(line for line in out.splitlines() if "flood.example" in line)
    assert "     3     1 source(s)" in flood  # trois signalements, une seule source


def test_review_cycle(reviewed_db, tmp_path, capsys):
    base = ["--database", str(reviewed_db)]
    assert feedback_cli([*base, "list", "--limit", "2"]) == 0
    assert len(capsys.readouterr().out.strip().splitlines()) == 2
    out = tmp_path / "lot.csv"
    assert feedback_cli([*base, "export", "--out", str(out)]) == 0
    with out.open(encoding="utf-8") as handle:
        exported = list(csv.DictReader(handle))
    assert [r["id"] for r in exported] == ["1", "2", "3", "4"]
    assert feedback_cli([*base, "reject", "1-3"]) == 0
    assert feedback_cli([*base, "accept", "4,3"]) == 0  # 3 déjà décidé : inchangé
    assert "1 retour(s) acceptés" in capsys.readouterr().out.splitlines()[-1]
    database = Database(reviewed_db)
    assert database.count_feedback(pending_only=True) == 0
    assert feedback_cli([*base, "purge", "--older-than", "0"]) == 0
    assert database.count_feedback() == 0
    assert feedback_cli([*base, "accept", "x"]) == 2


def test_csv_export_neutralizes_formulas(tmp_path):
    from phishguard.api.feedback import write_csv
    from phishguard.api.storage import FeedbackRecord

    record = FeedbackRecord(
        1, '=HYPERLINK("x")', "phishing", "false_positive", "2026-11-12", None, "+cmd", None, None
    )
    out = tmp_path / "x.csv"
    write_csv([record], out)
    text = out.read_text(encoding="utf-8")
    assert "'=HYPERLINK" in text and "'+cmd" in text


@pytest.mark.parametrize(
    ("spec", "expected"), [("1-3,7", [1, 2, 3, 7]), ("5", [5]), (" 2 , 2-3 ", [2, 3])]
)
def test_parse_ids(spec, expected):
    assert parse_ids(spec) == expected


@pytest.mark.parametrize("spec", ["", "0", "3-1", "a", "1-100000", ","])
def test_parse_ids_refuses(spec):
    with pytest.raises(ValueError):
        parse_ids(spec)
