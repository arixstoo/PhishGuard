"""Crée labels, jalons et issues GitHub à partir du cahier des charges (étape 0.9).

Chaque « Étape X.Y » de la partie II devient une issue rattachée au jalon de son module.
Le script est idempotent : il ne recrée jamais un label, un jalon ou une issue existants.

    python scripts/bootstrap_github.py --dry-run     # affiche ce qui serait créé
    python scripts/bootstrap_github.py               # crée labels, jalons, issues
    python scripts/bootstrap_github.py --project     # + tableau GitHub Project
                                                     #   (gh auth refresh -s project)

Prérequis : GitHub CLI (`gh`) authentifié avec accès au dépôt. Bibliothèque standard seule.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT / "PhishGuard — Cahier des charges et plan de réalisation.md"
REPO = "arixstoo/PhishGuard"

MODULE_RE = re.compile(r"^## Module (\d+) — (.+?)(?: \((.+)\))?$")
STEP_RE = re.compile(r"^### Étape (\d+\.\d+(?: bis)?) — (.+?)(?: \(([^()]*)\))?$")

LABELS = {
    **{f"module:m{i}": ("1d76db", f"Module {i} du plan de réalisation") for i in range(7)},
    "triage": ("fbca04", "À trier par le mainteneur"),
    "detection-feedback": ("d93f0b", "Faux positif ou faux négatif signalé"),
    "security": ("b60205", "Sujet lié à la sécurité"),
    "roadmap": ("0e8a16", "Étape du plan de réalisation"),
}


@dataclass
class Step:
    number: str
    title: str
    duration: str | None
    module: int
    body: str

    @property
    def issue_title(self) -> str:
        return f"[{self.number}] {self.title}"


def parse_spec(text: str) -> tuple[dict[int, str], list[Step]]:
    """Extrait les modules et les étapes de la partie II du cahier des charges."""
    part2 = text.split("# Partie II", 1)[1]
    modules: dict[int, str] = {}
    steps: list[Step] = []
    current_module: int | None = None
    current: Step | None = None

    for line in part2.splitlines():
        if m := MODULE_RE.match(line):
            current_module = int(m.group(1))
            modules[current_module] = m.group(2).strip()
            current = None
            continue
        if line.startswith("## ") or line.strip() == "---":
            current = None
            continue
        if (m := STEP_RE.match(line)) and current_module is not None:
            current = Step(m.group(1), m.group(2).strip(), m.group(3), current_module, "")
            steps.append(current)
            continue
        if current is not None:
            current.body += line + "\n"

    for step in steps:
        step.body = step.body.strip()
    return modules, steps


def milestone_title(module: int, name: str) -> str:
    return f"M{module} — {name}"


def issue_body(step: Step) -> str:
    duration = f"**Durée estimée** : {step.duration}\n\n" if step.duration else ""
    return (
        f"{duration}{step.body}\n\n---\n"
        f"*Source : cahier des charges, partie II, étape {step.number}. "
        "Une étape = une branche = une PR. Fermer l'issue quand le critère "
        "« Terminé quand » est rempli.*"
    )


class GitHub:
    def __init__(self, repo: str, dry_run: bool):
        self.repo = repo
        self.dry_run = dry_run

    def gh(self, *args: str, stdin: str | None = None, write: bool = True) -> str:
        if write and self.dry_run:
            print("  [dry-run] gh", " ".join(a if len(a) < 60 else a[:57] + "..." for a in args))
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
            raise RuntimeError(f"gh {' '.join(args[:3])} a échoué : {result.stderr.strip()}")
        if write:
            time.sleep(1)  # reste sous les limites « secondaires » de création de contenu
        return result.stdout

    def ensure_labels(self) -> None:
        existing = {
            lbl["name"]
            for lbl in json.loads(
                self.gh(
                    "label", "list", "-R", self.repo, "-L", "200", "--json", "name", write=False
                )
            )
        }
        for name, (color, description) in LABELS.items():
            if name not in existing:
                print(f"label   + {name}")
                self.gh("label", "create", name, "-R", self.repo, "-c", color, "-d", description)

    def ensure_milestones(self, modules: dict[int, str]) -> None:
        existing = {
            m["title"]
            for m in json.loads(
                self.gh("api", f"repos/{self.repo}/milestones?state=all&per_page=100", write=False)
            )
        }
        for number, name in sorted(modules.items()):
            title = milestone_title(number, name)
            if title not in existing:
                print(f"jalon   + {title}")
                self.gh("api", f"repos/{self.repo}/milestones", "-f", f"title={title}")

    def ensure_issues(self, modules: dict[int, str], steps: list[Step]) -> list[str]:
        existing = {
            i["title"]: i["url"]
            for i in json.loads(
                self.gh(
                    "issue", "list", "-R", self.repo, "--state", "all", "-L", "1000",
                    "--json", "title,url", write=False,
                )
            )
        }  # fmt: skip
        urls = []
        for step in steps:
            if step.issue_title in existing:
                urls.append(existing[step.issue_title])
                continue
            print(f"issue   + {step.issue_title}")
            out = self.gh(
                "issue", "create", "-R", self.repo,
                "--title", step.issue_title,
                "--body-file", "-",
                "--milestone", milestone_title(step.module, modules[step.module]),
                "--label", f"roadmap,module:m{step.module}",
                stdin=issue_body(step),
            )  # fmt: skip
            urls.append(out.strip())
        return urls

    def ensure_project(self, owner: str, title: str, urls: list[str]) -> None:
        projects = json.loads(
            self.gh("project", "list", "--owner", owner, "--format", "json", write=False)
        )["projects"]
        project = next((p for p in projects if p["title"] == title), None)
        if project is None:
            print(f"projet  + {title}")
            out = self.gh(
                "project", "create", "--owner", owner, "--title", title, "--format", "json"
            )
            if self.dry_run:
                return
            project = json.loads(out)
            self.gh("project", "link", str(project["number"]), "--owner", owner, "-R", self.repo)
        for url in urls:
            if url:  # item-add est idempotent côté GitHub
                self.gh(
                    "project", "item-add", str(project["number"]), "--owner", owner, "--url", url
                )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("--repo", default=REPO)
    parser.add_argument("--spec", type=Path, default=SPEC)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--project", action="store_true", help="créer/remplir le GitHub Project")
    args = parser.parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    modules, steps = parse_spec(args.spec.read_text(encoding="utf-8"))
    print(f"{len(modules)} modules, {len(steps)} étapes trouvées dans le cahier des charges")

    github = GitHub(args.repo, args.dry_run)
    github.ensure_labels()
    github.ensure_milestones(modules)
    urls = github.ensure_issues(modules, steps)
    if args.project:
        github.ensure_project(args.repo.split("/")[0], "PhishGuard roadmap", urls)
    return 0


if __name__ == "__main__":
    sys.exit(main())
