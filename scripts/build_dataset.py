"""Construit le jeu d'URLs étiquetées à partir des flux bruts (étape 1.2).

    python scripts/build_dataset.py

Lit les fichiers de data/raw/ décrits par les manifestes de fetch_feeds.py, vérifie
leur SHA-256, normalise et dédoublonne les URLs, limite le nombre d'URLs par domaine
enregistré, puis écrit :

- data/processed/urls.parquet : url, label (1 = phishing), source, first_seen, host,
  registered_domain (non versionné : les conditions d'OpenPhish interdisent de le publier) ;
- docs/metrics/urls_dataset.json : statistiques agrégées, sans aucune URL.

Code de sortie : 0 si le jeu contient les deux classes, 1 sinon.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from datetime import UTC, datetime
from pathlib import Path

import pandas as pd
import tldextract

from phishguard.data.urls import (
    URLHAUS_PHISHING_TAGS,
    BuildResult,
    build_url_dataset,
    discover_feeds,
    summarize,
)

ROOT = Path(__file__).resolve().parents[1]
BUILDER_VERSION = "1.1.0"

logger = logging.getLogger("build_dataset")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    p.add_argument("--raw-dir", type=Path, default=ROOT / "data/raw")
    p.add_argument("--output", type=Path, default=ROOT / "data/processed/urls.parquet")
    p.add_argument("--report", type=Path, default=ROOT / "docs/metrics/urls_dataset.json")
    p.add_argument(
        "--max-per-domain",
        type=int,
        default=5,
        help="URLs gardées au plus par (étiquette, domaine enregistré) (défaut : 5)",
    )
    p.add_argument("--seed", type=int, default=42, help="graine du tirage par domaine")
    p.add_argument(
        "--no-verify", action="store_true", help="ne pas vérifier les SHA-256 des manifestes"
    )
    args = p.parse_args(argv)
    if args.max_per_domain < 1:
        p.error("--max-per-domain doit être >= 1")
    return args


def build_report(args: argparse.Namespace, result: BuildResult, warnings: list[str]) -> dict:
    return {
        "metadata": {
            "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
            "builder_version": BUILDER_VERSION,
            "python": sys.version.split()[0],
            "pandas": pd.__version__,
            # La liste des suffixes embarquée dépend de la version de tldextract.
            "tldextract": tldextract.__version__,
            "params": {
                "max_per_domain": args.max_per_domain,
                "seed": args.seed,
                "psl_private_domains": True,
                "urlhaus_phishing_tags": sorted(URLHAUS_PHISHING_TAGS),
                "sha256_verified": not args.no_verify,
            },
        },
        "inputs": result.inputs,
        "warnings": warnings,
        "steps": result.steps,
        "dataset": summarize(result.dataset),
    }


def print_summary(dataset: pd.DataFrame, steps: dict[str, int]) -> None:
    print("\nÉtapes :")
    for name, value in steps.items():
        print(f"  {name:<26}{value:>10}")
    print("\nURLs par étiquette (1 = phishing) :")
    print(dataset.groupby("label").size().to_string())
    print("\nURLs par source :")
    print(dataset.groupby("source").size().to_string())
    print(f"\nDomaines enregistrés distincts : {dataset['registered_domain'].nunique()}")


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    args = parse_args(argv)

    inventory = discover_feeds(args.raw_dir)
    for warning in inventory.warnings:
        logger.warning(warning)
    if not inventory.feeds:
        logger.error("aucun fichier brut exploitable dans %s", args.raw_dir)
        return 1

    result = build_url_dataset(
        inventory.feeds,
        max_per_domain=args.max_per_domain,
        seed=args.seed,
        verify=not args.no_verify,
    )
    dataset = result.dataset

    args.output.parent.mkdir(parents=True, exist_ok=True)
    dataset.to_parquet(args.output, index=False)
    report = build_report(args, result, inventory.warnings)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", "utf-8")

    print_summary(dataset, result.steps)
    print(f"\nJeu : {args.output}\nRapport : {args.report}")

    if dataset["label"].nunique() < 2:
        logger.error("le jeu ne contient qu'une seule classe : vérifiez la collecte")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
