"""Gouvernance du dépôt (étape 6.6) : labels et issues « good first issue ».

Critère de l'étape : « un inconnu peut contribuer sans te poser une seule question ».
Une issue qui cite un fichier disparu, un label inexistant, ou qui ne dit pas quand elle
est terminée, oblige justement à poser une question : ce test le refuse.
"""

from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location(
    "setup_community", ROOT / "scripts/setup_community.py"
)
assert _spec is not None and _spec.loader is not None
community = importlib.util.module_from_spec(_spec)
sys.modules["setup_community"] = community
_spec.loader.exec_module(community)

LABELS = {label.name for label in community.load_labels()}
ISSUES = community.load_issues()
REPO_PATH = re.compile(r"`((?:src|extension|docs|tests|scripts|deploy|\.github)/[\w./-]+)`")
LINK = re.compile(r"\]\(((?!https?://|#)[^)\s]+)\)")


def test_required_labels_exist() -> None:
    assert {"bug", "enhancement", "good first issue", "help wanted", "security"} <= LABELS


def test_issue_templates_only_use_known_labels() -> None:
    for template in (ROOT / ".github/ISSUE_TEMPLATE").glob("*.yml"):
        match = re.search(
            r"^labels:\s*\[(.*)\]", template.read_text(encoding="utf-8"), re.MULTILINE
        )
        if match:
            used = {label.strip().strip("\"'") for label in match.group(1).split(",")}
            assert used <= LABELS, template.name


def test_at_least_ten_good_first_issues_with_known_labels() -> None:
    good = [issue for issue in ISSUES if "good first issue" in issue.labels]
    assert len(good) >= 10
    for issue in ISSUES:
        assert set(issue.labels) <= LABELS, issue.path.name
        assert len(issue.title) <= 100, issue.path.name


@pytest.mark.parametrize("issue", ISSUES, ids=lambda i: i.path.stem)
def test_issue_is_self_contained(issue) -> None:
    body = issue.body
    assert len(body) > 400, "trop courte pour être prise sans question"
    assert re.search(r"^## (Terminé quand|Done when)$", body, re.MULTILINE), "critère de fin absent"
    assert re.search(r"^## (Contexte|Context)$", body, re.MULTILINE), "contexte absent"
    assert re.search(r"^## (À faire|To do)$", body, re.MULTILINE), "liste des tâches absente"


@pytest.mark.parametrize("issue", ISSUES, ids=lambda i: i.path.stem)
def test_files_cited_by_an_issue_exist(issue) -> None:
    """Chaque fichier cité existe, sauf ceux que l'issue demande justement de créer."""
    lines = issue.body.splitlines()
    to_create = {
        path
        for line in lines
        if re.search(r"(?<!\w)(Créez|Create)(?!\w)", line)
        for path in REPO_PATH.findall(line)
    }
    for line in lines:
        for path in REPO_PATH.findall(line):
            if path in to_create or path.endswith(".png"):
                continue
            assert (ROOT / path).exists(), f"{issue.path.name} cite {path}, introuvable"
        for target in LINK.findall(line):
            path = target.split("#", 1)[0]
            assert (ROOT / path).exists(), f"{issue.path.name} renvoie vers {path}, introuvable"


def test_front_matter_is_strict(tmp_path) -> None:
    bad = tmp_path / "x.md"
    bad.write_text("---\ntitle: X\nlabels: bug\nassignee: me\n---\nbody\n", encoding="utf-8")
    with pytest.raises(ValueError, match="title et labels"):
        community.parse_issue(bad)
    bad.write_text("pas d'en-tête\n", encoding="utf-8")
    with pytest.raises(ValueError, match="en-tête"):
        community.parse_issue(bad)


def test_simulation_writes_nothing(capsys) -> None:
    """Par défaut, aucune commande d'écriture ne part vers GitHub."""
    assert community.main(["--only", "labels", "security"]) == 0
    out = capsys.readouterr().out
    assert "Simulation" in out
    assert "[simulation] gh label create" in out
    assert (
        "[simulation] gh api -X PUT repos/arixstoo/PhishGuard/private-vulnerability-reporting"
        in out
    )
