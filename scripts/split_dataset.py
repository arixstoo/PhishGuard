"""Découpe le jeu d'URLs en entraînement, validation et test (étape 1.4).

    python scripts/split_dataset.py

Lit data/processed/urls.parquet (étape 1.2), applique le split temporel et groupé de
phishguard.data.split, vérifie qu'aucun domaine enregistré n'est dans deux blocs, puis
écrit :

- data/processed/urls_split.parquet : le jeu avec une colonne ``split`` (non versionné,
  comme urls.parquet) ;
- docs/metrics/urls_split.json : statistiques agrégées, sans aucune URL ni aucun domaine.

La méthode est décrite dans docs/split.md.

Code de sortie : 0 si le split est valide et qu'aucun bloc n'est vide, 1 sinon.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from datetime import UTC, datetime
from pathlib import Path

import pandas as pd

from phishguard.data.integrity import sha256_file
from phishguard.data.split import (
    SPLITS,
    SplitConfig,
    assert_no_domain_leakage,
    split_report,
    temporal_group_split,
)

ROOT = Path(__file__).resolve().parents[1]
SPLIT_VERSION = "1.0.0"

logger = logging.getLogger("split_dataset")


def _fraction(value: str) -> float:
    f = float(value)
    if not 0.0 < f < 1.0:
        raise argparse.ArgumentTypeError("doit être strictement compris entre 0 et 1")
    return f


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    p.add_argument("--dataset", type=Path, default=ROOT / "data/processed/urls.parquet")
    p.add_argument("--output", type=Path, default=ROOT / "data/processed/urls_split.parquet")
    p.add_argument("--report", type=Path, default=ROOT / "docs/metrics/urls_split.json")
    p.add_argument("--validation", type=_fraction, default=0.15, help="part de validation")
    p.add_argument("--test", type=_fraction, default=0.15, help="part de test")
    p.add_argument(
        "--strata",
        nargs="+",
        default=["label", "source"],
        help="colonnes découpées séparément dans le temps (défaut : label source)",
    )
    p.add_argument("--seed", type=int, default=42, help="graine du départage des ex aequo")
    args = p.parse_args(argv)
    if args.validation + args.test >= 1.0:
        p.error("--validation + --test doit rester inférieur à 1")
    return args


def print_summary(report: dict) -> None:
    print(f"\n{'':<12}{'URLs':>9}{'part':>8}{'domaines':>10}{'phishing':>10}{'internes':>10}")
    for name, block in report["blocks"].items():
        print(
            f"  {name:<10}{block['rows']:>9}{block['share']:>8.1%}{block['domains']:>10}"
            f"{block['phishing_rate']:>10.1%}{block['legitimate_with_path']:>10}"
        )
    print("\nPar strate (lignes entraînement / validation / test) :")
    for name, stratum in report["strata"].items():
        counts = " / ".join(str(stratum["rows_per_block"][s]) for s in SPLITS)
        print(f"  {name:<16}{counts}")
    print(f"\nDomaines dans plusieurs blocs : {report['domains_in_several_blocks']}")


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")  # accents lisibles sous Windows
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    args = parse_args(argv)

    if not args.dataset.is_file():
        logger.error("%s introuvable : lancez d'abord scripts/build_dataset.py", args.dataset)
        return 1
    dataset = pd.read_parquet(args.dataset)

    cfg = SplitConfig(
        fractions=(1.0 - args.validation - args.test, args.validation, args.test),
        strata=tuple(args.strata),
        seed=args.seed,
    )
    split = temporal_group_split(dataset, cfg)
    assert_no_domain_leakage(dataset, split)

    report = {
        "metadata": {
            "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
            "split_version": SPLIT_VERSION,
            "python": sys.version.split()[0],
            "pandas": pd.__version__,
            "dataset_sha256": sha256_file(args.dataset),
        },
        **split_report(dataset, split, cfg),
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    dataset.assign(split=split).to_parquet(args.output, index=False)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", "utf-8")

    print_summary(report)
    print(f"\nJeu découpé : {args.output}\nRapport : {args.report}")

    empty = [name for name, block in report["blocks"].items() if block["rows"] == 0]
    if empty:
        logger.error("blocs vides : %s", ", ".join(empty))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
