"""Score SUS des tests utilisateurs (étape 5.13, docs/user-tests.md).

    python scripts/sus_score.py docs/user-tests/sus.csv            # tableau Markdown
    python scripts/sus_score.py docs/user-tests/sus.csv --group 2 --min-score 70

Entrée : un CSV anonymisé, une ligne par participant ::

    participant,group,q1,q2,q3,q4,q5,q6,q7,q8,q9,q10
    P01,1,4,2,5,1,4,2,5,1,4,2

Réponses de 1 (pas du tout d'accord) à 5 (tout à fait d'accord). Calcul de Brooke (1996) :
items impairs ``réponse - 1``, items pairs ``5 - réponse``, somme × 2,5, de 0 à 100.

Une ligne incomplète ou hors bornes est **refusée** (et le script échoue) plutôt que
complétée : un score calculé sur des réponses inventées n'est pas un score.

Pour chaque groupe : nombre de participants, moyenne, intervalle de confiance à 95 %
(loi de Student, petits échantillons), minimum, maximum, et la lettre de l'échelle de
Sauro et Lewis (2016). ``--min-score`` fait échouer le script si la moyenne du groupe
choisi est en dessous : c'est le critère de fin de l'étape (SUS ≥ 70 sur le dernier
groupe).
"""

from __future__ import annotations

import argparse
import csv
import math
import re
import statistics
import sys
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path

from scipy import stats

ITEMS = tuple(f"q{i}" for i in range(1, 11))
COLUMNS = ("participant", "group", *ITEMS)
# Identifiant anonyme : P suivi de chiffres. Un nom ou une adresse ne passe pas.
PARTICIPANT_RE = re.compile(r"^P\d{2,3}$")
# Échelle de Sauro et Lewis (Quantifying the User Experience, 2e éd., 2016), seuil bas.
GRADES: tuple[tuple[float, str], ...] = (
    (84.1, "A+"), (80.8, "A"), (78.9, "A-"), (77.2, "B+"), (74.1, "B"), (72.6, "B-"),
    (71.1, "C+"), (65.0, "C"), (62.7, "C-"), (51.7, "D"), (0.0, "F"),
)  # fmt: skip


class SusError(ValueError):
    """Fichier de réponses invalide."""


@dataclass(frozen=True)
class Participant:
    participant: str
    group: str
    score: float


@dataclass(frozen=True)
class GroupSummary:
    group: str
    n: int
    mean: float
    ci_low: float
    ci_high: float
    minimum: float
    maximum: float

    @property
    def grade(self) -> str:
        return grade(self.mean)


def sus_score(answers: Sequence[int]) -> float:
    """Score SUS de 10 réponses de 1 à 5."""
    if len(answers) != len(ITEMS) or any(a not in (1, 2, 3, 4, 5) for a in answers):
        raise SusError("10 réponses de 1 à 5 attendues")
    total = sum(a - 1 if i % 2 == 0 else 5 - a for i, a in enumerate(answers))
    return total * 2.5


def grade(score: float) -> str:
    return next(letter for floor, letter in GRADES if score >= floor)


def read_responses(path: Path) -> list[Participant]:
    with path.open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        if tuple(reader.fieldnames or ()) != COLUMNS:
            raise SusError(f"colonnes attendues : {','.join(COLUMNS)}")
        out: list[Participant] = []
        seen: set[str] = set()
        for line, row in enumerate(reader, start=2):
            who = (row["participant"] or "").strip()
            if not PARTICIPANT_RE.match(who):
                raise SusError(f"ligne {line} : identifiant anonyme attendu (P01…), pas un nom")
            if who in seen:
                raise SusError(f"ligne {line} : {who} apparaît deux fois")
            seen.add(who)
            try:
                answers = [int((row[item] or "").strip()) for item in ITEMS]
                score = sus_score(answers)
            except (ValueError, SusError):
                raise SusError(f"ligne {line} ({who}) : 10 réponses de 1 à 5 attendues") from None
            out.append(Participant(who, (row["group"] or "").strip() or "1", score))
    if not out:
        raise SusError("aucune réponse")
    return out


def summarize(scores: Iterable[float], group: str) -> GroupSummary:
    values = list(scores)
    n = len(values)
    mean = statistics.fmean(values)
    if n > 1:
        half = stats.t.ppf(0.975, n - 1) * statistics.stdev(values) / math.sqrt(n)
    else:
        half = math.nan  # un seul participant : pas d'intervalle
    return GroupSummary(
        group=group,
        n=n,
        mean=mean,
        ci_low=max(0.0, mean - half) if n > 1 else math.nan,
        ci_high=min(100.0, mean + half) if n > 1 else math.nan,
        minimum=min(values),
        maximum=max(values),
    )


def summaries(participants: Sequence[Participant]) -> list[GroupSummary]:
    groups: dict[str, list[float]] = {}
    for p in participants:
        groups.setdefault(p.group, []).append(p.score)
    return [summarize(groups[g], g) for g in sorted(groups, key=lambda g: (len(g), g))]


def _fmt(value: float) -> str:
    return "—" if math.isnan(value) else f"{value:.1f}".replace(".", ",")


def markdown(participants: Sequence[Participant], groups: Sequence[GroupSummary]) -> str:
    lines = [
        "| Groupe | Participants | SUS moyen | IC 95 % | Min | Max | Lettre |",
        "|---|---|---|---|---|---|---|",
    ]
    for g in groups:
        ci = f"{_fmt(g.ci_low)} – {_fmt(g.ci_high)}"
        lines.append(
            f"| {g.group} | {g.n} | **{_fmt(g.mean)}** | {ci} | {_fmt(g.minimum)} "
            f"| {_fmt(g.maximum)} | {g.grade} |"
        )
    lines += ["", "| Participant | Groupe | SUS |", "|---|---|---|"]
    lines += [f"| {p.participant} | {p.group} | {_fmt(p.score)} |" for p in participants]
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("responses", type=Path, help="CSV anonymisé des réponses")
    parser.add_argument(
        "--group", help="groupe auquel s'applique --min-score (défaut : le dernier)"
    )
    parser.add_argument(
        "--min-score", type=float, help="échoue si la moyenne du groupe est en dessous"
    )
    args = parser.parse_args(argv)
    try:
        participants = read_responses(args.responses)
    except (OSError, SusError) as exc:
        print(f"sus_score : {exc}", file=sys.stderr)
        return 2
    groups = summaries(participants)
    print(markdown(participants, groups))
    if args.min_score is not None:
        target = (
            next((g for g in groups if g.group == args.group), None) if args.group else groups[-1]
        )
        if target is None:
            print(f"sus_score : groupe {args.group!r} absent", file=sys.stderr)
            return 2
        if target.mean < args.min_score:
            print(
                f"\nGroupe {target.group} : SUS {_fmt(target.mean)} < {_fmt(args.min_score)}",
                file=sys.stderr,
            )
            return 1
        print(f"\nGroupe {target.group} : SUS {_fmt(target.mean)} ≥ {_fmt(args.min_score)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
