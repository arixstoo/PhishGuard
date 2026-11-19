"""Rapport d'adoption hebdomadaire, sans pister personne (étape 6.12, docs/measure.md).

::

    python scripts/adoption_report.py                                  # GitHub seul
    python scripts/adoption_report.py --usage usage.json \\
        --chrome-users 120 --firefox-users 15 --out rapport.md
    python scripts/adoption_report.py --json                           # pour un tableur

Sources, toutes **agrégées** et publiques ou déjà collectées par l'hébergeur :

- **GitHub** (API REST) : étoiles, forks, observateurs, issues ouvertes, téléchargements
  des archives de l'extension dans les releases, issues ouvertes dans la semaine (dont les
  signalements de détection). Les visites et clones des 14 derniers jours exigent un jeton
  ayant le droit « Administration : lecture » (``ADOPTION_TOKEN``) ; sans lui, ils sont
  marqués indisponibles, le reste du rapport est produit ;
- **API PhishGuard** : la sortie de ``python -m phishguard.api.usage summary --json`` sur
  le serveur (analyses, verdicts, faux positifs signalés), passée par ``--usage`` ;
- **stores** : utilisateurs hebdomadaires lus dans les tableaux de bord du Chrome Web Store
  et d'AMO (aucune API ne les expose), passés à la main.

Le rapport se termine par la liste de tri de l'heure hebdomadaire. Aucune donnée
personnelle n'y entre : ni identifiant GitHub, ni titre d'issue, ni domaine signalé.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Sequence
from dataclasses import asdict, dataclass, field
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any

DEFAULT_REPO = "arixstoo/PhishGuard"
API = "https://api.github.com"
EXTENSION_ASSET_PREFIXES = ("phishguard-extension-", "phishguard-firefox-")
FEEDBACK_LABEL = "detection-feedback"
TIMEOUT_SECONDS = 20

Fetch = Callable[[str], Any]


class UnavailableError(RuntimeError):
    """Une source refuse ou manque : le rapport le dit au lieu d'échouer."""


@dataclass
class Report:
    repo: str
    week: str
    since: str
    generated_at: str
    stars: int | None = None
    forks: int | None = None
    watchers: int | None = None
    open_issues: int | None = None
    issues_opened: int | None = None
    feedback_issues_opened: int | None = None
    extension_downloads: int | None = None
    views_14d: dict[str, int] | None = None
    clones_14d: dict[str, int] | None = None
    chrome_weekly_users: int | None = None
    firefox_weekly_users: int | None = None
    api_week: dict[str, Any] | None = None
    unavailable: list[str] = field(default_factory=list)


def github_fetcher(token: str | None) -> Fetch:
    """``GET`` JSON sur l'API GitHub, jeton facultatif ; ni cookie ni redirection hors d'API."""

    def fetch(path: str) -> Any:
        url = f"{API}{path}"
        request = urllib.request.Request(url, method="GET")
        request.add_header("Accept", "application/vnd.github+json")
        request.add_header("X-GitHub-Api-Version", "2022-11-28")
        request.add_header("User-Agent", "phishguard-adoption-report")
        if token:
            request.add_header("Authorization", f"Bearer {token}")
        try:
            # Schéma et hôte fixés par API (https://api.github.com) : ni file:// ni autre hôte.
            with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:  # nosec B310
                if not response.geturl().startswith(API):
                    raise UnavailableError(f"{path} : redirection refusée")
                return json.load(response)
        except urllib.error.HTTPError as exc:
            raise UnavailableError(f"{path} : HTTP {exc.code}") from None
        except (urllib.error.URLError, TimeoutError) as exc:
            raise UnavailableError(f"{path} : {exc}") from None

    return fetch


def iso_week(day: date) -> str:
    year, week, _ = day.isocalendar()
    return f"{year}-W{week:02d}"


def collect(
    fetch: Fetch,
    repo: str,
    *,
    today: date,
    usage: Sequence[dict[str, Any]] | None = None,
    chrome_users: int | None = None,
    firefox_users: int | None = None,
) -> Report:
    """Semaine ISO **précédente** (complète) : du lundi au dimanche avant ``today``."""
    last_monday = today - timedelta(days=today.weekday(), weeks=1)
    report = Report(
        repo=repo,
        week=iso_week(last_monday),
        since=last_monday.isoformat(),
        generated_at=datetime.now(UTC).isoformat(timespec="seconds"),
        chrome_weekly_users=chrome_users,
        firefox_weekly_users=firefox_users,
    )
    quoted = urllib.parse.quote(repo, safe="/")

    def attempt(label: str, action: Callable[[], None]) -> None:
        try:
            action()
        except UnavailableError as exc:
            report.unavailable.append(f"{label} ({exc})")

    def repository() -> None:
        data = fetch(f"/repos/{quoted}")
        report.stars = int(data["stargazers_count"])
        report.forks = int(data["forks_count"])
        report.watchers = int(data["subscribers_count"])
        report.open_issues = int(data["open_issues_count"])

    def releases() -> None:
        total = 0
        for release in fetch(f"/repos/{quoted}/releases?per_page=100"):
            for asset in release.get("assets", []):
                name = str(asset.get("name", ""))
                if name.startswith(EXTENSION_ASSET_PREFIXES) and name.endswith(".zip"):
                    total += int(asset.get("download_count", 0))
        report.extension_downloads = total

    def issues() -> None:
        end = (last_monday + timedelta(days=6)).isoformat()
        base = f"repo:{repo} is:issue created:{last_monday.isoformat()}..{end}"
        query = urllib.parse.quote(base)
        report.issues_opened = int(fetch(f"/search/issues?q={query}&per_page=1")["total_count"])
        labelled = urllib.parse.quote(f'{base} label:"{FEEDBACK_LABEL}"')
        report.feedback_issues_opened = int(
            fetch(f"/search/issues?q={labelled}&per_page=1")["total_count"]
        )

    def traffic() -> None:
        views = fetch(f"/repos/{quoted}/traffic/views")
        clones = fetch(f"/repos/{quoted}/traffic/clones")
        report.views_14d = {"count": int(views["count"]), "uniques": int(views["uniques"])}
        report.clones_14d = {"count": int(clones["count"]), "uniques": int(clones["uniques"])}

    attempt("dépôt", repository)
    attempt("téléchargements des releases", releases)
    attempt("issues de la semaine", issues)
    attempt("visites et clones (jeton ADOPTION_TOKEN requis)", traffic)
    if usage:
        report.api_week = next((w for w in usage if w.get("week") == report.week), None)
        if report.api_week is None:
            report.unavailable.append(f"API : semaine {report.week} absente de --usage")
    else:
        report.unavailable.append("API : --usage non fourni")
    if chrome_users is None:
        report.unavailable.append("Chrome Web Store : --chrome-users non fourni")
    if firefox_users is None:
        report.unavailable.append("AMO : --firefox-users non fourni")
    return report


def _n(value: object) -> str:
    if value is None:
        return "—"
    if isinstance(value, float):
        return f"{value:.1%}"
    return f"{value:,}".replace(",", " ") if isinstance(value, int) else str(value)


TRIAGE = """\
## Tri de la semaine (1 heure)

- [ ] **Faux positifs signalés** : `python -m phishguard.api.feedback summary` sur le serveur,
      puis les issues `detection-feedback`. Domaine vérifié à la main, dans un environnement
      isolé ; `accept` / `reject` (docs/feedback.md). Plusieurs signalements d'une seule
      source : une campagne, pas un consensus.
- [ ] **Faux négatifs signalés** : même relecture ; un cas confirmé rejoint l'analyse
      d'erreurs et le prochain jeu d'entraînement, jamais directement le modèle.
- [ ] **Bogues** : issues `bug` reproduites, étiquetées, priorisées.
- [ ] **Demandes de langue et de fonctionnalité** : regroupées, rattachées à
      [docs/roadmap.md](docs/roadmap.md).
- [ ] **Avis des stores** : réponse à chaque avis du Chrome Web Store et d'AMO.
- [ ] **Chiffres** : une ligne de plus dans le suivi (README, article, CV) si un palier est
      franchi.
"""


def render(report: Report) -> str:
    api = report.api_week or {}
    rate = api.get("reported_fp_rate")
    lines = [
        f"# Adoption de PhishGuard, semaine {report.week}",
        "",
        (
            f"Semaine du {report.since} (lundi) ; généré le {report.generated_at}. "
            "Totaux agrégés seulement (docs/measure.md)."
        ),
        "",
        "| Indicateur | Valeur |",
        "|---|---:|",
        f"| Utilisateurs hebdomadaires, Chrome Web Store | {_n(report.chrome_weekly_users)} |",
        f"| Utilisateurs hebdomadaires, Firefox (AMO) | {_n(report.firefox_weekly_users)} |",
        f"| Téléchargements des archives de l'extension (cumul) | {_n(report.extension_downloads)} |",
        f"| Étoiles GitHub | {_n(report.stars)} |",
        f"| Forks | {_n(report.forks)} |",
        f"| Observateurs | {_n(report.watchers)} |",
        (
            f"| Issues ouvertes dans la semaine (dont signalements de détection) | "
            f"{_n(report.issues_opened)} ({_n(report.feedback_issues_opened)}) |"
        ),
        f"| Issues et PR ouvertes au total | {_n(report.open_issues)} |",
    ]
    if report.views_14d and report.clones_14d:
        lines.append(
            f"| Visites du dépôt, 14 jours (visiteurs uniques) | "
            f"{_n(report.views_14d['count'])} ({_n(report.views_14d['uniques'])}) |"
        )
        lines.append(
            f"| Clones, 14 jours (uniques) | "
            f"{_n(report.clones_14d['count'])} ({_n(report.clones_14d['uniques'])}) |"
        )
    lines += [
        f"| Analyses par l'API | {_n(api.get('analyses'))} |",
        f"| Verdicts « suspect » ou « phishing » de l'API | {_n(api.get('flagged'))} |",
        (
            f"| Faux positifs signalés (taux) | {_n(api.get('false_positive_reports'))} "
            f"({_n(rate) if rate is not None else '—'}) |"
        ),
        f"| Faux négatifs signalés | {_n(api.get('false_negative_reports'))} |",
        "",
    ]
    if report.unavailable:
        lines += ["**Sources indisponibles** :", ""]
        lines += [f"- {item}" for item in report.unavailable]
        lines.append("")
    lines.append(TRIAGE)
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY", DEFAULT_REPO))
    parser.add_argument("--usage", type=Path, help="JSON de « phishguard.api.usage summary »")
    parser.add_argument(
        "--chrome-users", type=int, help="utilisateurs hebdomadaires (tableau de bord)"
    )
    parser.add_argument("--firefox-users", type=int, help="utilisateurs hebdomadaires (AMO)")
    parser.add_argument("--out", type=Path, help="fichier Markdown (défaut : sortie standard)")
    parser.add_argument("--json", action="store_true", help="sortie JSON au lieu de Markdown")
    parser.add_argument("--today", type=date.fromisoformat, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)

    for value in (args.chrome_users, args.firefox_users):
        if value is not None and value < 0:
            parser.error("un nombre d'utilisateurs est positif")
    usage = json.loads(args.usage.read_text(encoding="utf-8")) if args.usage else None
    token = os.environ.get("ADOPTION_TOKEN") or os.environ.get("GH_TOKEN") or None
    report = collect(
        github_fetcher(token),
        args.repo,
        today=args.today or datetime.now(UTC).date(),
        usage=usage,
        chrome_users=args.chrome_users,
        firefox_users=args.firefox_users,
    )
    text = json.dumps(asdict(report), ensure_ascii=False, indent=2) if args.json else render(report)
    if args.out:
        args.out.write_text(text + "\n", encoding="utf-8")
    else:
        sys.stdout.write(text + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
