"""Rapport d'adoption (étape 6.12, ``scripts/adoption_report.py``) contre une API simulée."""

from __future__ import annotations

import importlib.util
import json
import sys
from datetime import date
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location(
    "adoption_report", ROOT / "scripts/adoption_report.py"
)
adoption = importlib.util.module_from_spec(_spec)
assert _spec.loader is not None
sys.modules["adoption_report"] = adoption
_spec.loader.exec_module(adoption)

TODAY = date(2026, 11, 23)  # lundi : la semaine rapportée est 2026-W47 (16 au 22)

GITHUB = {
    "/repos/arixstoo/PhishGuard": {
        "stargazers_count": 52,
        "forks_count": 7,
        "subscribers_count": 4,
        "open_issues_count": 12,
    },
    "/repos/arixstoo/PhishGuard/releases?per_page=100": [
        {
            "assets": [
                {"name": "phishguard-extension-1.0.0.zip", "download_count": 30},
                {"name": "phishguard-firefox-1.0.0.zip", "download_count": 5},
                {"name": "phishguard-source-1.0.0.zip", "download_count": 99},
                {"name": "SHA256SUMS", "download_count": 1},
            ]
        },
        {"assets": [{"name": "phishguard-extension-0.5.0-beta.1.zip", "download_count": 10}]},
    ],
    "/repos/arixstoo/PhishGuard/traffic/views": {"count": 300, "uniques": 120},
    "/repos/arixstoo/PhishGuard/traffic/clones": {"count": 20, "uniques": 9},
}


def fake_fetch(responses: dict, calls: list[str] | None = None):
    def fetch(path: str):
        if calls is not None:
            calls.append(path)
        if path.startswith("/search/issues"):
            return {"total_count": 2 if "detection-feedback" in path else 6}
        if path not in responses:
            raise adoption.UnavailableError(f"{path} : HTTP 403")
        return responses[path]

    return fetch


USAGE = [
    {"week": "2026-W46", "analyses": 10},
    {
        "week": "2026-W47",
        "analyses": 400,
        "flagged": 40,
        "false_positive_reports": 2,
        "false_negative_reports": 1,
        "reported_fp_rate": 0.05,
    },
]


def test_collects_the_previous_complete_iso_week():
    calls: list[str] = []
    report = adoption.collect(
        fake_fetch(GITHUB, calls),
        "arixstoo/PhishGuard",
        today=TODAY,
        usage=USAGE,
        chrome_users=120,
        firefox_users=15,
    )
    assert (report.week, report.since) == ("2026-W47", "2026-11-16")
    assert (report.stars, report.forks, report.watchers, report.open_issues) == (52, 7, 4, 12)
    assert report.extension_downloads == 45  # archives de l'extension seulement
    assert (report.issues_opened, report.feedback_issues_opened) == (6, 2)
    assert report.views_14d == {"count": 300, "uniques": 120}
    assert report.api_week["analyses"] == 400
    assert report.unavailable == []
    search = [c for c in calls if c.startswith("/search")]
    assert all("created%3A2026-11-16..2026-11-22" in c for c in search)


def test_missing_sources_are_reported_not_fatal():
    responses = {k: v for k, v in GITHUB.items() if "traffic" not in k}
    report = adoption.collect(fake_fetch(responses), "arixstoo/PhishGuard", today=TODAY)
    assert report.views_14d is None and report.stars == 52
    text = "\n".join(report.unavailable)
    assert "ADOPTION_TOKEN" in text and "--usage" in text and "--chrome-users" in text


def test_rendered_report_holds_totals_only_and_the_triage_checklist():
    report = adoption.collect(
        fake_fetch(GITHUB), "arixstoo/PhishGuard", today=TODAY, usage=USAGE, chrome_users=1200
    )
    text = adoption.render(report)
    assert text.startswith("# Adoption de PhishGuard, semaine 2026-W47")
    assert "| Utilisateurs hebdomadaires, Chrome Web Store | 1 200 |" in text
    assert "| Faux positifs signalés (taux) | 2 (5.0%) |" in text
    assert "| Visites du dépôt, 14 jours (visiteurs uniques) | 300 (120) |" in text
    assert "## Tri de la semaine (1 heure)" in text
    assert "- [ ] **Faux positifs signalés**" in text
    assert "AMO : --firefox-users non fourni" in text


def test_cli_writes_json(tmp_path, monkeypatch):
    usage = tmp_path / "usage.json"
    usage.write_text(json.dumps(USAGE), encoding="utf-8")
    monkeypatch.setattr(adoption, "github_fetcher", lambda token: fake_fetch(GITHUB))
    out = tmp_path / "report.json"
    code = adoption.main(
        [
            "--repo",
            "arixstoo/PhishGuard",
            "--usage",
            str(usage),
            "--json",
            "--out",
            str(out),
            "--today",
            "2026-11-23",
            "--firefox-users",
            "3",
        ]
    )
    assert code == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["week"] == "2026-W47" and data["firefox_weekly_users"] == 3


def test_cli_refuses_negative_user_counts():
    with pytest.raises(SystemExit):
        adoption.main(["--chrome-users", "-1"])
