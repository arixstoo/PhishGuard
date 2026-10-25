"""Cherche les biais du jeu d'URLs avant tout entraînement (étape 1.3).

    python scripts/audit_bias.py                  # avec la comparaison PhiUSIIL
    python scripts/audit_bias.py --no-external    # sans téléchargement

Lit data/processed/urls.parquet (étape 1.2), télécharge si besoin le jeu UCI PhiUSIIL
dans data/external/ (empreinte vérifiée), puis écrit docs/metrics/data_bias.json :
statistiques agrégées uniquement, sans aucune URL ni aucun domaine.

L'analyse et les remèdes sont décrits dans docs/data-bias.md.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from datetime import UTC, datetime
from pathlib import Path

import pandas as pd
import sklearn

from phishguard.data.bias import REPRESENTATIONS, ProbeConfig, audit
from phishguard.data.integrity import sha256_file
from phishguard.data.phiusiil import download_phiusiil, load_phiusiil

ROOT = Path(__file__).resolve().parents[1]
AUDIT_VERSION = "1.1.0"

logger = logging.getLogger("audit_bias")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    p.add_argument("--dataset", type=Path, default=ROOT / "data/processed/urls.parquet")
    p.add_argument(
        "--phiusiil",
        type=Path,
        default=ROOT / "data/external/PhiUSIIL_Phishing_URL_Dataset.csv",
        help="CSV PhiUSIIL (téléchargé s'il est absent)",
    )
    p.add_argument("--no-external", action="store_true", help="ignorer la comparaison PhiUSIIL")
    p.add_argument("--report", type=Path, default=ROOT / "docs/metrics/data_bias.json")
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--test-size", type=float, default=0.2)
    args = p.parse_args(argv)
    if not 0.0 < args.test_size < 1.0:
        p.error("--test-size doit être strictement compris entre 0 et 1")
    return args


def _row(name: str, metrics: dict) -> str:
    return (
        f"  {name:<24}{metrics['pr_auc']:>8.3f}{metrics['roc_auc']:>9.3f}"
        f"{metrics['recall_at_fpr_1pct']:>10.3f}{metrics['test_rows']:>9}"
    )


def print_summary(report: dict) -> None:
    header = f"  {'':<24}{'PR-AUC':>8}{'ROC-AUC':>9}{'R@1%FPR':>10}{'test':>9}"
    structure = report["structure"]

    print("\nStructure par étiquette (part des URLs) :")
    for label, profile in structure["by_label"].items():
        traits = ", ".join(
            f"{name} {profile[name]:.0%}" for name in ("has_path", "is_http", "has_subdomain")
        )
        print(f"  label {label} : {traits}")

    print("\nModèle sonde selon la partie de l'URL visible (split groupé par domaine) :")
    print(header)
    for name, metrics in structure["representation_ablation"].items():
        print(_row(name, metrics))

    internal = structure.get("internal_page_fpr")
    if internal:
        print(
            "\nPages internes légitimes signalées à tort "
            f"(seuil : {internal['max_fpr_on_homepages']:.0%} FPR sur les pages d'accueil) :"
        )
        print(f"  {'':<24}{'FPR accueil':>12}{'FPR internes':>14}{'rappel':>9}")
        for name in ("without_internal_pages", "with_internal_pages"):
            m = internal[name]
            print(
                f"  {name:<24}{m['fpr_homepages']:>12.3f}"
                f"{m['fpr_internal_pages']:>14.3f}{m['recall_phishing']:>9.3f}"
            )

    print("\nFuite par domaine :")
    print(header)
    for name, metrics in report["domain"]["leakage"].items():
        print(_row(name, metrics))

    print("\nBiais de source (même test, avec ou sans la source cible à l'entraînement) :")
    print(header)
    for target, result in report["source"]["cross_source"].items():
        for name in ("with_target", "without_target"):
            print(_row(f"{target} / {name}", result[name]))
    for source, auc in report["source"]["fingerprint_roc_auc"].items():
        print(f"  empreinte de source {source} : ROC-AUC {auc:.3f}")

    blocks = report["time"]["naive_temporal_split"]
    rates = ", ".join(f"{name} {block['phishing_rate']:.0%}" for name, block in blocks.items())
    print(f"\nSplit temporel naïf, part de phishing : {rates}")

    external = report.get("external_validation")
    if external and external["probe"]:
        print("\nValidation externe (entraîné ici, testé sur PhiUSIIL) :")
        print(header)
        for level in REPRESENTATIONS:
            print(_row(level, external["probe"][level]))


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

    external = external_meta = None
    if not args.no_external:
        path = download_phiusiil(args.phiusiil)
        external, load_stats = load_phiusiil(path)
        external_meta = {"name": "UCI PhiUSIIL", "sha256": sha256_file(path), **load_stats}

    cfg = ProbeConfig(test_size=args.test_size, seed=args.seed)
    report = {
        "metadata": {
            "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
            "audit_version": AUDIT_VERSION,
            "python": sys.version.split()[0],
            "pandas": pd.__version__,
            "scikit_learn": sklearn.__version__,
            "dataset_sha256": sha256_file(args.dataset),
            "external_dataset": external_meta,
        },
        **audit(dataset, cfg, external),
    }

    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", "utf-8")
    print_summary(report)
    print(f"\nRapport : {args.report}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
