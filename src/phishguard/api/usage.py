"""Mesure de l'usage de l'API sans pister personne (étape 6.12).

::

    python -m phishguard.api.usage summary              # 8 dernières semaines, par semaine ISO
    python -m phishguard.api.usage summary --weeks 4 --json

**Ce qui est compté** : pour chaque jour (UTC), le nombre d'analyses par route
(``/v1/analyze/url``, ``text``, ``email``, appelée « canal » ici), par verdict et par palier du client (anonyme ou avec clé). Rien
d'autre : ni adresse IP, ni clé, ni pseudonyme, ni URL, ni domaine, ni heure. Une ligne de
la table est un total ; elle ne peut pas désigner une requête, encore moins une personne.

**Comment** : les compteurs vivent en mémoire (:class:`UsageCounter`) et sont ajoutés à la
base une fois par minute, puis à l'arrêt du service. Aucune écriture SQLite par requête :
la latence d'analyse n'en dépend pas (étape 4.13). Un arrêt brutal perd au plus une minute
de comptage, ce qui est acceptable pour une statistique.

**Combien de temps** : ``PHISHGUARD_API_USAGE_RETENTION_DAYS`` (365 jours par défaut),
appliqué au démarrage puis toutes les 6 heures, comme la rétention des retours.
``PHISHGUARD_API_USAGE_STATS=false`` coupe tout comptage.

Le rapport combine ces totaux avec les signalements de la quarantaine (étape 4.10) : le
**taux de faux positifs signalés** est le nombre de signalements « faux positif » rapporté
au nombre de verdicts « suspect » ou « phishing » rendus la même semaine.
"""

from __future__ import annotations

import argparse
import json
import threading
from collections import Counter
from collections.abc import Sequence
from dataclasses import asdict, dataclass, field
from datetime import UTC, date, datetime, timedelta
from typing import Literal

from phishguard.api.settings import get_api_settings
from phishguard.api.storage import Database, UsageRow

UsageChannel = Literal["url", "text", "email"]
UsageTier = Literal["anonymous", "authenticated"]
CHANNELS: tuple[UsageChannel, ...] = ("url", "text", "email")
VERDICTS = ("safe", "suspicious", "phishing")
TIERS: tuple[UsageTier, ...] = ("anonymous", "authenticated")
FLUSH_INTERVAL_SECONDS = 60

UsageKey = tuple[str, str, str, str]  # (jour ISO, canal, verdict, palier)


class UsageCounter:
    """Totaux d'analyses du jour, en mémoire, partagés par toutes les requêtes.

    ``record`` est appelé depuis la boucle asynchrone et ``drain`` depuis un thread : un
    verrou protège le dictionnaire. Chaque valeur est validée contre une liste fermée :
    une valeur inattendue ne peut pas créer de colonne libre dans la base.
    """

    def __init__(self, *, enabled: bool = True) -> None:
        self.enabled = enabled
        self._counts: Counter[UsageKey] = Counter()
        self._lock = threading.Lock()

    def record(
        self,
        channel: str,
        verdict: str,
        tier: str,
        *,
        today: date | None = None,
    ) -> None:
        if not self.enabled:
            return
        if channel not in CHANNELS or verdict not in VERDICTS or tier not in TIERS:
            raise ValueError(f"comptage refusé : {channel!r}, {verdict!r}, {tier!r}")
        day = (today or datetime.now(UTC).date()).isoformat()
        with self._lock:
            self._counts[(day, channel, verdict, tier)] += 1

    def drain(self) -> dict[UsageKey, int]:
        """Totaux accumulés depuis le dernier appel, remis à zéro."""
        with self._lock:
            counts, self._counts = dict(self._counts), Counter()
        return counts

    def restore(self, counts: dict[UsageKey, int]) -> None:
        """Remet des totaux non écrits (base indisponible) : rien n'est perdu au passage suivant."""
        with self._lock:
            self._counts.update(counts)

    def flush(self, database: Database) -> int:
        """Ajoute les totaux à la base ; renvoie le nombre d'analyses écrites."""
        counts = self.drain()
        if not counts:
            return 0
        try:
            database.add_usage(counts)
        except Exception:
            self.restore(counts)
            raise
        return sum(counts.values())


# --------------------------------------------------------------------------- #
# Rapport hebdomadaire
# --------------------------------------------------------------------------- #


@dataclass
class WeekUsage:
    """Une semaine ISO : analyses, verdicts, signalements."""

    week: str  # « 2026-W47 »
    start: str
    analyses: int = 0
    by_channel: dict[str, int] = field(default_factory=dict)
    by_verdict: dict[str, int] = field(default_factory=dict)
    by_tier: dict[str, int] = field(default_factory=dict)
    false_positive_reports: int = 0
    false_negative_reports: int = 0

    @property
    def flagged(self) -> int:
        return self.by_verdict.get("suspicious", 0) + self.by_verdict.get("phishing", 0)

    @property
    def reported_fp_rate(self) -> float | None:
        """Signalements « faux positif » / verdicts inquiétants (``None`` sans verdict)."""
        return self.false_positive_reports / self.flagged if self.flagged else None

    def to_dict(self) -> dict[str, object]:
        return {**asdict(self), "flagged": self.flagged, "reported_fp_rate": self.reported_fp_rate}


def week_label(day: date) -> str:
    year, week, _ = day.isocalendar()
    return f"{year}-W{week:02d}"


def weekly_report(
    rows: Sequence[UsageRow],
    feedback: Sequence[tuple[str, str, int]],
    *,
    weeks: int,
    today: date,
) -> list[WeekUsage]:
    """Semaines ISO des ``weeks`` dernières semaines (la courante comprise), anciennes d'abord.

    ``feedback`` : ``(jour ISO, jugement, nombre)`` des signalements reçus.
    """
    monday = today - timedelta(days=today.weekday())
    report = {
        week_label(start): WeekUsage(week=week_label(start), start=start.isoformat())
        for start in (monday - timedelta(weeks=n) for n in range(weeks - 1, -1, -1))
    }
    for row in rows:
        week = report.get(week_label(date.fromisoformat(row.day)))
        if week is None:
            continue
        week.analyses += row.count
        week.by_channel[row.channel] = week.by_channel.get(row.channel, 0) + row.count
        week.by_verdict[row.verdict] = week.by_verdict.get(row.verdict, 0) + row.count
        week.by_tier[row.tier] = week.by_tier.get(row.tier, 0) + row.count
    for day, judgement, count in feedback:
        week = report.get(week_label(date.fromisoformat(day)))
        if week is None:
            continue
        if judgement == "false_positive":
            week.false_positive_reports += count
        elif judgement == "false_negative":
            week.false_negative_reports += count
    return list(report.values())


def format_report(weeks: Sequence[WeekUsage]) -> str:
    header = (
        "semaine     analyses   url  texte  email   inquiétants  FP signalés  FN signalés  taux FP"
    )
    lines = [header]
    for w in weeks:
        rate = f"{w.reported_fp_rate:.1%}" if w.reported_fp_rate is not None else "—"
        lines.append(
            f"{w.week:<10} {w.analyses:>9} {w.by_channel.get('url', 0):>5} "
            f"{w.by_channel.get('text', 0):>6} {w.by_channel.get('email', 0):>6} "
            f"{w.flagged:>13} {w.false_positive_reports:>12} {w.false_negative_reports:>12} "
            f"{rate:>8}"
        )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m phishguard.api.usage")
    parser.add_argument("--database", help="base SQLite (défaut : celle de l'API)")
    commands = parser.add_subparsers(dest="command", required=True)
    summary = commands.add_parser("summary", help="totaux par semaine ISO")
    summary.add_argument("--weeks", type=int, default=8, choices=range(1, 54), metavar="1-53")
    summary.add_argument("--json", action="store_true", help="sortie JSON (rapport d'adoption)")
    args = parser.parse_args(argv)

    database = Database(args.database or get_api_settings().database_path)
    today = datetime.now(UTC).date()
    since = (today - timedelta(days=today.weekday()) - timedelta(weeks=args.weeks - 1)).isoformat()
    weeks = weekly_report(
        database.usage_since(since),
        database.feedback_by_day(since),
        weeks=args.weeks,
        today=today,
    )
    if args.json:
        print(json.dumps([w.to_dict() for w in weeks], ensure_ascii=False, indent=2))
    else:
        print(format_report(weeks))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
