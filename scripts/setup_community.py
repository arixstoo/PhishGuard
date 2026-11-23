"""Labels, issues « good first issue » et réglages de sécurité du dépôt (étape 6.6).

    python scripts/setup_community.py            # affiche ce qui serait fait (par défaut)
    python scripts/setup_community.py --apply    # le fait

Sources versionnées, relues comme du code :

- ``.github/labels.json`` : labels (créés, ou mis à jour : couleur et description) ;
- ``.github/good-first-issues/*.md`` : une issue par fichier (en-tête ``title`` et
  ``labels``), créée si aucune issue ne porte déjà ce titre ;
- réglages de sécurité : signalement privé des vulnérabilités, alertes Dependabot et
  correctifs automatiques, analyse des secrets et protection à l'envoi.

**Sans ``--apply``, rien n'est écrit** : ces actions sont publiques et visibles de tous.
Idempotent : relancer ne recrée rien. Prérequis : ``gh`` connecté, droits
d'administration du dépôt pour les réglages de sécurité. Bibliothèque standard seule.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_REPO = "arixstoo/PhishGuard"
LABELS_FILE = ROOT / ".github/labels.json"
ISSUES_DIR = ROOT / ".github/good-first-issues"

_FRONT_MATTER = re.compile(r"\A---\n(?P<head>.*?)\n---\n(?P<body>.*)\Z", re.DOTALL)


@dataclass(frozen=True)
class Label:
    name: str
    color: str
    description: str


@dataclass(frozen=True)
class Issue:
    path: Path
    title: str
    labels: tuple[str, ...]
    body: str


def load_labels(path: Path = LABELS_FILE) -> list[Label]:
    document = json.loads(path.read_text(encoding="utf-8"))
    labels = [Label(**item) for item in document["labels"]]
    names = [label.name for label in labels]
    if len(set(names)) != len(names):
        raise ValueError(f"{path.name} : label en double")
    for label in labels:
        if not re.fullmatch(r"[0-9a-f]{6}", label.color):
            raise ValueError(f"{label.name} : couleur hexadécimale sur 6 caractères attendue")
        if len(label.description) > 100:
            raise ValueError(
                f"{label.name} : description de plus de 100 caractères (limite GitHub)"
            )
    return labels


def parse_issue(path: Path) -> Issue:
    text = path.read_text(encoding="utf-8").replace("\r\n", "\n")
    match = _FRONT_MATTER.match(text)
    if not match:
        raise ValueError(f"{path.name} : en-tête « --- » attendu")
    head: dict[str, str] = {}
    for line in match.group("head").splitlines():
        key, sep, value = line.partition(":")
        if not sep:
            raise ValueError(f"{path.name} : ligne d'en-tête invalide : {line!r}")
        head[key.strip()] = value.strip()
    if set(head) != {"title", "labels"} or not head["title"]:
        raise ValueError(f"{path.name} : en-tête title et labels, et eux seuls")
    labels = tuple(label.strip() for label in head["labels"].split(",") if label.strip())
    return Issue(path, head["title"], labels, match.group("body").strip() + "\n")


def load_issues(directory: Path = ISSUES_DIR) -> list[Issue]:
    issues = [parse_issue(path) for path in sorted(directory.glob("*.md"))]
    titles = [issue.title for issue in issues]
    if len(set(titles)) != len(titles):
        raise ValueError("deux issues portent le même titre")
    return issues


class GitHub:
    def __init__(self, repo: str, apply: bool) -> None:
        self.repo = repo
        self.apply = apply

    def gh(self, *args: str, stdin: str | None = None, write: bool = True) -> str:
        if write and not self.apply:
            shown = " ".join(a if len(a) < 60 else a[:57] + "…" for a in args)
            print(f"  [simulation] gh {shown}")
            return ""
        result = subprocess.run(
            ["gh", *args],
            check=False,
            input=stdin,
            capture_output=True,
            text=True,
            encoding="utf-8",
        )
        if result.returncode != 0:
            raise RuntimeError(f"gh {' '.join(args[:3])} : {result.stderr.strip()}")
        return result.stdout

    def labels(self, labels: list[Label]) -> None:
        for label in labels:
            print(f"label    {label.name}")
            # --force : crée, ou met à jour couleur et description d'un label existant.
            self.gh("label", "create", label.name, "-R", self.repo, "--force",
                    "-c", label.color, "-d", label.description)  # fmt: skip

    def issues(self, issues: list[Issue]) -> None:
        try:
            listed = self.gh("issue", "list", "-R", self.repo, "--state", "all", "-L", "1000",
                             "--json", "title", write=False)  # fmt: skip
        except (RuntimeError, FileNotFoundError):
            if self.apply:
                raise
            print("  (simulation : gh indisponible, issues existantes non lues)")
            listed = "[]"
        existing = {item["title"] for item in json.loads(listed or "[]")}
        for issue in issues:
            if issue.title in existing:
                print(f"issue    = {issue.title}")
                continue
            print(f"issue    + {issue.title}")
            self.gh("issue", "create", "-R", self.repo, "--title", issue.title,
                    "--label", ",".join(issue.labels), "--body-file", "-",
                    stdin=issue.body)  # fmt: skip

    def security(self) -> None:
        repo = f"repos/{self.repo}"
        steps = [
            ("signalement privé des vulnérabilités", ["-X", "PUT", f"{repo}/private-vulnerability-reporting"]),
            ("alertes Dependabot", ["-X", "PUT", f"{repo}/vulnerability-alerts"]),
            ("correctifs de sécurité Dependabot", ["-X", "PUT", f"{repo}/automated-security-fixes"]),
            ("analyse des secrets et protection à l'envoi", [
                "-X", "PATCH", repo,
                "-f", "security_and_analysis[secret_scanning][status]=enabled",
                "-f", "security_and_analysis[secret_scanning_push_protection][status]=enabled",
            ]),
        ]  # fmt: skip
        for label, args in steps:
            print(f"sécurité {label}")
            self.gh("api", *args)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--repo", default=DEFAULT_REPO)
    parser.add_argument(
        "--apply", action="store_true", help="écrire sur GitHub (sinon : simulation)"
    )
    parser.add_argument("--only", choices=["labels", "issues", "security"], nargs="+")
    args = parser.parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    labels, issues = load_labels(), load_issues()
    known = {label.name for label in labels}
    for issue in issues:
        if unknown := set(issue.labels) - known:
            raise SystemExit(
                f"{issue.path.name} : labels absents de labels.json : {sorted(unknown)}"
            )
    wanted = set(args.only or ["labels", "issues", "security"])
    github = GitHub(args.repo, args.apply)
    if not args.apply:
        print("Simulation : rien n'est écrit. Relancez avec --apply.\n")
    if "labels" in wanted:
        github.labels(labels)
    if "issues" in wanted:
        github.issues(issues)
    if "security" in wanted:
        github.security()
    return 0


if __name__ == "__main__":
    sys.exit(main())
