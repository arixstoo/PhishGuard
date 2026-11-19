"""Totaux d'usage sans identifiant (étape 6.12, ``phishguard.api.usage``).

Ce que l'on vérifie :

- la table ne **peut** contenir que des totaux : colonnes fermées par des ``CHECK``, aucune
  colonne d'identifiant, une URL ou un domaine sont refusés par SQLite lui-même ;
- l'API compte chaque analyse réussie (route, verdict, palier) sans écrire en base à chaque
  requête, écrit à l'arrêt, et ne compte rien si ``usage_stats`` est désactivé ;
- une base de schéma 2 (avant cette étape) est migrée sans perte ;
- rétention bornée, rapport hebdomadaire et taux de faux positifs signalés exacts.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import UTC, date, datetime, timedelta

import pytest
from api_support import api_client, settings_for

from phishguard.api import usage as usage_cli
from phishguard.api.storage import SCHEMA_VERSION, Database, UsageRow
from phishguard.api.usage import UsageCounter, WeekUsage, format_report, week_label, weekly_report

TODAY = date(2026, 11, 19)  # un jeudi, semaine ISO 2026-W47


def _columns(database: Database) -> list[str]:
    db = sqlite3.connect(database.path)
    try:
        return [row[1] for row in db.execute("PRAGMA table_info(usage_daily)")]
    finally:
        db.close()


# --------------------------------------------------------------------------- #
# Compteur en mémoire
# --------------------------------------------------------------------------- #


def test_counter_aggregates_by_day_route_verdict_and_tier():
    counter = UsageCounter()
    for _ in range(3):
        counter.record("url", "safe", "anonymous", today=TODAY)
    counter.record("url", "phishing", "authenticated", today=TODAY)
    counter.record("text", "safe", "anonymous", today=TODAY + timedelta(days=1))
    assert counter.drain() == {
        ("2026-11-19", "url", "safe", "anonymous"): 3,
        ("2026-11-19", "url", "phishing", "authenticated"): 1,
        ("2026-11-20", "text", "safe", "anonymous"): 1,
    }
    assert counter.drain() == {}  # remis à zéro


@pytest.mark.parametrize(
    ("channel", "verdict", "tier"),
    [
        ("https://phishing.example/login", "safe", "anonymous"),  # une URL n'est pas un canal
        ("url", "phishing.example", "anonymous"),
        ("url", "safe", "203.0.113.7"),  # une IP n'est pas un palier
        ("sms", "safe", "anonymous"),
    ],
)
def test_counter_refuses_any_value_outside_closed_lists(channel, verdict, tier):
    with pytest.raises(ValueError):
        UsageCounter().record(channel, verdict, tier)


def test_disabled_counter_records_nothing():
    counter = UsageCounter(enabled=False)
    counter.record("url", "safe", "anonymous")
    assert counter.drain() == {}


def test_flush_writes_and_accumulates(tmp_path):
    database = Database(tmp_path / "db.sqlite3")
    counter = UsageCounter()
    counter.record("email", "suspicious", "anonymous", today=TODAY)
    assert counter.flush(database) == 1
    counter.record("email", "suspicious", "anonymous", today=TODAY)
    counter.record("email", "suspicious", "anonymous", today=TODAY)
    assert counter.flush(database) == 2
    assert counter.flush(database) == 0
    assert database.usage_since("2026-01-01") == [
        UsageRow("2026-11-19", "email", "suspicious", "anonymous", 3)
    ]


def test_flush_failure_keeps_the_counts_for_next_time(tmp_path):
    class BrokenDatabase:
        def add_usage(self, counts):
            raise sqlite3.OperationalError("database is locked")

    counter = UsageCounter()
    counter.record("url", "safe", "anonymous", today=TODAY)
    with pytest.raises(sqlite3.OperationalError):
        counter.flush(BrokenDatabase())  # type: ignore[arg-type]
    database = Database(tmp_path / "db.sqlite3")
    assert counter.flush(database) == 1


# --------------------------------------------------------------------------- #
# Base : la table ne peut contenir que des totaux
# --------------------------------------------------------------------------- #


def test_table_has_no_column_that_could_identify_anyone(tmp_path):
    assert _columns(Database(tmp_path / "db.sqlite3")) == [
        "day",
        "channel",
        "verdict",
        "tier",
        "count",
    ]


@pytest.mark.parametrize(
    "row",
    [
        ("2026-11-19", "phishing.example", "safe", "anonymous", 1),
        ("2026-11-19", "url", "safe", "pg_key-of-someone", 1),
        ("2026-11-19T10:42:00", "url", "safe", "anonymous", 1),  # pas d'heure
        ("2026-11-19", "url", "safe", "anonymous", -1),
    ],
)
def test_sqlite_itself_refuses_anything_but_a_total(tmp_path, row):
    database = Database(tmp_path / "db.sqlite3")
    db = sqlite3.connect(database.path)
    try:
        with pytest.raises(sqlite3.IntegrityError):
            db.execute("INSERT INTO usage_daily VALUES (?, ?, ?, ?, ?)", row)
    finally:
        db.close()


def test_schema_2_database_is_migrated_without_losing_feedback(tmp_path):
    path = tmp_path / "db.sqlite3"
    database = Database(path)
    database.quarantine_feedback(
        domain="kept.example", verdict="phishing", judgement="false_positive", key_id=None
    )
    db = sqlite3.connect(path)
    db.execute("DROP TABLE usage_daily")
    db.execute("PRAGMA user_version=2")
    db.commit()
    db.close()

    migrated = Database(path)
    assert _columns(migrated)
    assert migrated.count_feedback() == 1
    db = sqlite3.connect(path)
    assert db.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION == 3
    db.close()


def test_usage_retention_removes_old_days_only(tmp_path):
    database = Database(tmp_path / "db.sqlite3")
    today = datetime.now(UTC).date()
    database.add_usage(
        {
            ((today - timedelta(days=400)).isoformat(), "url", "safe", "anonymous"): 5,
            ((today - timedelta(days=10)).isoformat(), "url", "safe", "anonymous"): 2,
        }
    )
    assert database.enforce_usage_retention(365) == 1
    assert [r.count for r in database.usage_since("2000-01-01")] == [2]
    with pytest.raises(ValueError):
        database.enforce_usage_retention(0)


def test_feedback_by_day_counts_without_domain(tmp_path):
    database = Database(tmp_path / "db.sqlite3")
    for judgement in ("false_positive", "false_positive", "false_negative"):
        database.quarantine_feedback(
            domain="a.example",
            verdict="suspicious" if judgement == "false_positive" else "safe",
            judgement=judgement,
            key_id=None,
        )
    today = datetime.now(UTC).date().isoformat()
    assert sorted(database.feedback_by_day(today)) == [
        (today, "false_negative", 1),
        (today, "false_positive", 2),
    ]


# --------------------------------------------------------------------------- #
# Rapport hebdomadaire
# --------------------------------------------------------------------------- #


def test_weekly_report_groups_by_iso_week_and_computes_reported_fp_rate():
    rows = [
        UsageRow("2026-11-16", "url", "safe", "anonymous", 90),  # lundi W47
        UsageRow("2026-11-19", "url", "phishing", "authenticated", 6),
        UsageRow("2026-11-19", "text", "suspicious", "anonymous", 4),
        UsageRow("2026-11-15", "url", "safe", "anonymous", 7),  # dimanche W46
        UsageRow("2025-01-01", "url", "safe", "anonymous", 99),  # hors période : ignorée
    ]
    feedback = [("2026-11-18", "false_positive", 1), ("2026-11-18", "false_negative", 2)]
    weeks = weekly_report(rows, feedback, weeks=2, today=TODAY)
    assert [w.week for w in weeks] == ["2026-W46", "2026-W47"]
    w46, w47 = weeks
    assert (w46.analyses, w46.flagged, w46.reported_fp_rate) == (7, 0, None)
    assert w47.analyses == 100
    assert w47.by_channel == {"url": 96, "text": 4}
    assert w47.by_tier == {"anonymous": 94, "authenticated": 6}
    assert w47.flagged == 10
    assert w47.reported_fp_rate == pytest.approx(0.1)
    assert w47.false_negative_reports == 2
    assert w47.start == "2026-11-16"
    assert "2026-W47" in format_report(weeks) and "10.0%" in format_report(weeks)


def test_week_label_follows_iso_calendar_across_years():
    assert week_label(date(2026, 12, 31)) == "2026-W53"
    assert week_label(date(2027, 1, 4)) == "2027-W01"


def test_week_to_dict_is_json_ready():
    data = WeekUsage(week="2026-W47", start="2026-11-16", analyses=3).to_dict()
    assert json.loads(json.dumps(data))["reported_fp_rate"] is None


def test_cli_summary_json(tmp_path, capsys):
    database = Database(tmp_path / "db.sqlite3")
    today = datetime.now(UTC).date().isoformat()
    database.add_usage({(today, "url", "phishing", "anonymous"): 4})
    assert (
        usage_cli.main(["--database", str(database.path), "summary", "--weeks", "2", "--json"]) == 0
    )
    weeks = json.loads(capsys.readouterr().out)
    assert len(weeks) == 2 and weeks[-1]["analyses"] == 4 and weeks[-1]["flagged"] == 4


# --------------------------------------------------------------------------- #
# Dans l'API
# --------------------------------------------------------------------------- #


def test_api_counts_each_analysis_and_writes_at_shutdown(api_models_dir, tmp_path):
    settings = settings_for(api_models_dir, tmp_path)
    with api_client(settings) as client:
        verdict = client.post("/v1/analyze/url", json={"url": "https://www.wikipedia.org/"}).json()[
            "verdict"
        ]
        assert client.post("/v1/analyze/text", json={"text": "see you tonight"}).status_code == 200
        assert client.post("/v1/analyze/url", json={}).status_code == 422
        # Rien en base pendant le service : aucune écriture SQLite par requête.
        assert Database(settings.database_path).usage_since("2000-01-01") == []
    rows = Database(settings.database_path).usage_since("2000-01-01")
    assert {(r.channel, r.tier) for r in rows} == {("url", "anonymous"), ("text", "anonymous")}
    assert sum(r.count for r in rows) == 2  # l'entrée refusée n'est pas comptée
    assert any(r.channel == "url" and r.verdict == verdict for r in rows)


def test_api_counts_nothing_when_disabled(api_models_dir, tmp_path):
    settings = settings_for(api_models_dir, tmp_path, usage_stats=False)
    with api_client(settings) as client:
        assert (
            client.post("/v1/analyze/url", json={"url": "https://example.org/"}).status_code == 200
        )
    assert Database(settings.database_path).usage_since("2000-01-01") == []


def test_usage_retention_is_bounded_by_settings(api_models_dir, tmp_path):
    from pydantic import ValidationError

    assert settings_for(api_models_dir, tmp_path).usage_retention_days == 365
    for value in (0, 731):
        with pytest.raises(ValidationError):
            settings_for(api_models_dir, tmp_path, usage_retention_days=value)
