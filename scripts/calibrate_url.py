"""Calibration des probabilités du modèle URL sur la validation (étape 2.10).

    python scripts/calibrate_url.py            # ou : make calibrate-url

Lit le modèle de l'étape 1.6 et le bloc **validation** de
data/processed/urls_split.parquet. Le test n'est jamais chargé : il a été lu une fois à
l'étape 1.7.

1. Compare le score brut, la régression isotone et la méthode de Platt, en validation
   croisée sur la validation (5 plis) : chaque probabilité est mesurée sur un pli qui
   n'a pas servi à l'apprendre.
2. Retient la méthode au plus petit score de Brier, et l'apprend sur toute la validation.

Écrit :

- models/url_v1_calibration.json : la calibration (points ou paramètres, en JSON, sans
  pickle), relue par l'analyse et portable dans l'extension ;
- docs/metrics/url_calibration.json : Brier, ECE, perte logarithmique et tableau de
  fiabilité de chaque méthode.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from phishguard.data.integrity import sha256_file
from phishguard.data.split import read_split_blocks
from phishguard.fusion.calibration import ScoreCalibrator, best_method, compare_methods
from phishguard.urls.model import UrlModel

ROOT = Path(__file__).resolve().parents[1]
REPORT_VERSION = "1.0.0"

logger = logging.getLogger("calibrate_url")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    p.add_argument("--dataset", type=Path, default=ROOT / "data/processed/urls_split.parquet")
    p.add_argument("--model", type=Path, default=ROOT / "models/url_v1.joblib")
    p.add_argument("--output", type=Path, default=ROOT / "models/url_v1_calibration.json")
    p.add_argument("--report", type=Path, default=ROOT / "docs/metrics/url_calibration.json")
    p.add_argument("--folds", type=int, default=5)
    p.add_argument("--seed", type=int, default=0)
    return p.parse_args(argv)


def calibrate(
    scores: Any,
    labels: Any,
    *,
    folds: int = 5,
    seed: int = 0,
    metadata: dict[str, Any] | None = None,
) -> tuple[ScoreCalibrator, dict[str, Any]]:
    """Compare les méthodes, apprend la meilleure sur tout le bloc. Sans entrée-sortie."""
    reports = compare_methods(scores, labels, folds=folds, seed=seed)
    method = best_method(reports)
    calibrator = ScoreCalibrator.fit(scores, labels, method=method, metadata=metadata or {})
    return calibrator, {"selected": method, "methods": reports}


def summary_lines(report: dict[str, Any]) -> list[str]:
    lines = [f"{'méthode':<10}{'Brier':>9}{'ECE':>9}{'log loss':>10}"]
    for name, metrics in report["methods"].items():
        mark = "  ← retenue" if name == report["selected"] else ""
        lines.append(
            f"{name:<10}{metrics['brier']:>9.4f}{metrics['ece']:>9.4f}"
            f"{metrics['log_loss']:>10.4f}{mark}"
        )
    return lines


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")  # accents lisibles sous Windows
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    args = parse_args(argv)
    for path, hint in ((args.dataset, "split_dataset.py"), (args.model, "train_url.py")):
        if not path.is_file():
            logger.error("%s introuvable : lancez d'abord scripts/%s", path, hint)
            return 1

    model = UrlModel.load(args.model)
    validation = read_split_blocks(args.dataset, ("validation",), ["url", "label"])["validation"]
    scores = model.score(validation["url"])
    labels = validation["label"].to_numpy()
    metadata = {
        "model_sha256": sha256_file(args.model),
        "dataset_sha256": sha256_file(args.dataset),
        "fitted_on": "validation",
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
    }
    calibrator, report = calibrate(
        scores, labels, folds=args.folds, seed=args.seed, metadata=metadata
    )
    calibrator.save(args.output)

    full_report = {
        "metadata": {
            **metadata,
            "report_version": REPORT_VERSION,
            "folds": args.folds,
            "rows": len(labels),
            "prevalence": calibrator.prevalence,
        },
        **report,
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(full_report, indent=2, ensure_ascii=False) + "\n", "utf-8")

    print("\n".join(summary_lines(report)))
    print(f"\nCalibration : {args.output}\nRapport : {args.report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
