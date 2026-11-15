"""Relecture des retours en quarantaine, par lots (étape 4.10).

::

    python -m phishguard.api.feedback summary              # par domaine, sources distinctes
    python -m phishguard.api.feedback list --limit 50      # un lot, les plus anciens d'abord
    python -m phishguard.api.feedback export --out lot.csv # le même lot, pour un tableur
    python -m phishguard.api.feedback accept 1-40,42
    python -m phishguard.api.feedback reject 41,43-50
    python -m phishguard.api.feedback purge --older-than 90

Rien ici ne touche un modèle : **accepter** un retour signifie seulement qu'un humain l'a
jugé fondé. Il peut alors nourrir, à la main, l'analyse d'erreurs ou le prochain jeu
d'entraînement (docs/feedback.md), qui repassera par l'évaluation complète. Aucun code du
pipeline d'analyse ni des scripts d'entraînement ne lit cette table : un test le vérifie.

La base est celle de l'API (``PHISHGUARD_API_DATABASE_PATH``), ou ``--database``.
"""

from __future__ import annotations

import argparse
import csv
import sys
from collections.abc import Sequence
from dataclasses import asdict, fields
from pathlib import Path

from phishguard.api.settings import get_api_settings
from phishguard.api.storage import Database, FeedbackRecord

MAX_ID_RANGE = 10_000
# Début de cellule qu'un tableur interprète comme une formule (injection CSV).
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def parse_ids(spec: str) -> list[int]:
    """``"1-3,7"`` → ``[1, 2, 3, 7]``. Plage bornée : une faute de frappe ne décide pas
    d'un million de lignes."""
    ids: set[int] = set()
    for part in (p.strip() for p in spec.split(",")):
        if not part:
            continue
        start, sep, end = part.partition("-")
        try:
            low, high = int(start), int(end) if sep else int(start)
        except ValueError:
            raise ValueError(f"identifiant invalide : {part!r}") from None
        if low < 1 or high < low or high - low >= MAX_ID_RANGE:
            raise ValueError(f"plage invalide : {part!r}")
        ids.update(range(low, high + 1))
    if not ids:
        raise ValueError("aucun identifiant")
    return sorted(ids)


def _cell(value: object) -> object:
    if isinstance(value, str) and value.startswith(_FORMULA_PREFIXES):
        return "'" + value
    return value


def write_csv(records: Sequence[FeedbackRecord], out: Path) -> None:
    with out.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow([f.name for f in fields(FeedbackRecord)])
        for record in records:
            writer.writerow([_cell(v) for v in asdict(record).values()])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m phishguard.api.feedback")
    parser.add_argument("--database", type=Path, help="base SQLite (défaut : celle de l'API)")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("summary", help="retours en attente, par domaine et jugement")
    for name, help_text in (("list", "un lot de retours en attente"), ("export", "lot en CSV")):
        command = commands.add_parser(name, help=help_text)
        command.add_argument("--limit", type=int, default=100)
        command.add_argument("--after", type=int, default=0, help="après cet identifiant")
        if name == "export":
            command.add_argument("--out", type=Path, required=True)
    for name in ("accept", "reject"):
        command = commands.add_parser(name, help=f"{name} : identifiants « 1-40,42 »")
        command.add_argument("ids")
    purge = commands.add_parser("purge", help="supprime les retours relus anciens")
    purge.add_argument("--older-than", type=int, required=True, metavar="JOURS")
    purge.add_argument(
        "--include-pending", action="store_true", help="aussi les retours jamais relus"
    )
    args = parser.parse_args(argv)

    database = Database(args.database or get_api_settings().database_path)
    if args.command == "summary":
        rows = database.feedback_summary()
        print(f"{database.count_feedback(pending_only=True)} retours en attente")
        for row in rows:
            print(
                f"{row.reports:>6}  {row.reporters:>4} source(s)  {row.judgement:<15}  "
                f"{row.domain}  ({row.first_at} → {row.last_at})"
            )
        return 0
    if args.command in {"list", "export"}:
        records = database.pending_feedback(limit=args.limit, after_id=args.after)
        if args.command == "export":
            write_csv(records, args.out)
            print(f"{len(records)} retours écrits dans {args.out}")
            return 0
        for r in records:
            print(
                f"{r.id:>6}  {r.received_at}  {r.judgement:<15} {r.verdict:<10} "
                f"{r.client_tier or '?':<13} {r.reporter or '?':<22} {r.domain}"
            )
        return 0
    if args.command in {"accept", "reject"}:
        try:
            ids = parse_ids(args.ids)
        except ValueError as exc:
            print(exc, file=sys.stderr)
            return 2
        decided = database.decide_feedback(
            ids, "accepted" if args.command == "accept" else "rejected"
        )
        print(f"{decided} retour(s) {'acceptés' if args.command == 'accept' else 'rejetés'}")
        return 0
    removed = database.purge_feedback(args.older_than, include_pending=args.include_pending)
    print(f"{removed} retour(s) supprimé(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
