"""Mesure l'apport de chaque feature URL sur la validation (étape 1.5).

    python scripts/evaluate_url_features.py

Lit data/processed/urls_split.parquet (étape 1.4), calcule les features de
phishguard.urls.features sur l'entraînement et la validation, apprend la table des TLD
sur l'entraînement seul, puis lance les mesures de phishguard.urls.ablation. Le bloc de
test n'est pas lu.

Écrit docs/metrics/url_features.json : statistiques agrégées, sans URL ni domaine. Les
résultats sont commentés dans docs/url-features.md.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

import lightgbm
import pandas as pd

from phishguard.data.integrity import sha256_file
from phishguard.urls.ablation import AblationConfig, run_ablation
from phishguard.urls.brands import list_versions
from phishguard.urls.features import FEATURES, UrlFeatureExtractor
from phishguard.urls.idn import to_ascii
from phishguard.urls.tld import TldRiskTable, top_level_domain

ROOT = Path(__file__).resolve().parents[1]
REPORT_VERSION = "1.0.0"
USED_SPLITS = ("train", "validation")

logger = logging.getLogger("evaluate_url_features")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    p.add_argument("--dataset", type=Path, default=ROOT / "data/processed/urls_split.parquet")
    p.add_argument("--report", type=Path, default=ROOT / "docs/metrics/url_features.json")
    p.add_argument("--seed", type=int, default=42)
    return p.parse_args(argv)


def load_blocks(path: Path) -> dict[str, pd.DataFrame]:
    """Blocs d'entraînement et de validation ; le test est écarté dès la lecture."""
    df = pd.read_parquet(path, columns=["url", "label", "source", "host", "split"])
    blocks = {name: df[df["split"] == name].reset_index(drop=True) for name in USED_SPLITS}
    for name, block in blocks.items():
        if block.empty or block["label"].nunique() != 2:
            raise ValueError(f"bloc {name} vide ou sans les deux classes")
    return blocks


def print_summary(results: dict) -> None:
    header = f"  {'':<34}{'PR-AUC':>8}{'R@1%':>8}{'R@0,1%':>8}{'FPR acc.':>10}{'FPR int.':>10}"
    for title, key in (
        ("Familles ajoutées une par une", "families_added"),
        ("Famille retirée du modèle complet", "families_removed"),
        ("Groupe retiré (biais de collecte)", "groups_removed"),
    ):
        print(f"\n{title} :\n{header}")
        for name, r in results[key].items():
            print(
                f"  {name:<34}{r['pr_auc']:>8.3f}{r['recall_at_fpr_1pct']:>8.3f}"
                f"{r['recall_at_fpr_0_1pct']:>8.3f}{r['fpr_homepages']:>10.2%}"
                f"{r['fpr_internal_pages']:>10.2%}"
            )


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")  # accents lisibles sous Windows
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    args = parse_args(argv)

    if not args.dataset.is_file():
        logger.error("%s introuvable : lancez d'abord scripts/split_dataset.py", args.dataset)
        return 1
    blocks = load_blocks(args.dataset)
    train, validation = blocks["train"], blocks["validation"]

    # La table des TLD n'apprend que sur l'entraînement (sinon : fuite d'étiquette).
    tld_table = TldRiskTable.fit(
        (top_level_domain(to_ascii(host)) for host in train["host"]),
        train["label"].astype(int),
    )
    extractor = UrlFeatureExtractor(tld_table=tld_table)

    logger.info("features : %d URLs d'entraînement", len(train))
    x_train = extractor.transform(train["url"])
    start = time.perf_counter()
    logger.info("features : %d URLs de validation", len(validation))
    x_val = UrlFeatureExtractor(tld_table=tld_table).transform(validation["url"])
    micros_per_url = (time.perf_counter() - start) / len(validation) * 1e6

    cfg = AblationConfig(seed=args.seed)
    results = run_ablation(
        x_train,
        train["label"].to_numpy(),
        x_val,
        validation["label"].to_numpy(),
        validation["source"].to_numpy(),
        cfg,
    )

    report = {
        "metadata": {
            "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
            "report_version": REPORT_VERSION,
            "python": sys.version.split()[0],
            "pandas": pd.__version__,
            "lightgbm": lightgbm.__version__,
            "dataset_sha256": sha256_file(args.dataset),
            "splits_used": list(USED_SPLITS),
            "lists": list_versions(),
        },
        "rows": {
            name: {
                "total": len(block),
                "phishing": int(block["label"].sum()),
                "by_source": {str(k): int(v) for k, v in block.groupby("source").size().items()},
            }
            for name, block in blocks.items()
        },
        "features": [
            {"name": s.name, "group": s.group, "family": s.family, "description": s.description}
            for s in FEATURES
        ],
        "extraction_us_per_url": round(micros_per_url, 1),
        "tld_table": {"prior": round(tld_table.prior, 4), "tlds": len(tld_table.rates)},
        **results,
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", "utf-8")

    print_summary(results)
    print(f"\nExtraction : {micros_per_url:.0f} µs par URL (cache par hôte compris)")
    print(f"Rapport : {args.report}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
