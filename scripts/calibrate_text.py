"""Calibration du score du modèle SMS sur la validation (étape 3.3).

    python scripts/calibrate_text.py            # ou : make calibrate-text

Le modèle retenu à l'étape 1.9 (``char_svm``) renvoie une **marge** de SVM, pas une
probabilité : la fusion (étape 2.10) ne peut pas l'utiliser telle quelle. Ce script
apprend la fonction marge → probabilité, comme ``scripts/calibrate_url.py`` pour l'URL.

Lit le modèle et reconstruit le split de l'étape 1.9 (même corpus, mêmes doublons
retirés, même graine) : seul le bloc **validation** sert. Le test n'est jamais lu.

1. Compare la régression isotone et la méthode de Platt, en validation croisée sur la
   validation (5 plis) : chaque probabilité est mesurée sur un pli qui n'a pas servi à
   l'apprendre.
2. Retient la méthode au plus petit score de Brier, et l'apprend sur toute la validation.

Écrit :

- models/text_v1_calibration.json : la calibration, en JSON (sans pickle) ;
- docs/metrics/text_calibration.json : Brier, ECE, perte logarithmique et tableau de
  fiabilité de chaque méthode, sans aucun texte de message.
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
from phishguard.data.sms import deduplicate, load_sms_collection, split_sms
from phishguard.fusion.calibration import ScoreCalibrator, best_method, compare_methods
from phishguard.text.models import TextModel

ROOT = Path(__file__).resolve().parents[1]
REPORT_VERSION = "1.0.0"

logger = logging.getLogger("calibrate_text")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    p.add_argument("--data", type=Path, default=ROOT / "data/raw/SMSSpamCollection")
    p.add_argument("--model", type=Path, default=ROOT / "models/text_v1.joblib")
    p.add_argument("--output", type=Path, default=ROOT / "models/text_v1_calibration.json")
    p.add_argument("--report", type=Path, default=ROOT / "docs/metrics/text_calibration.json")
    p.add_argument("--folds", type=int, default=5)
    p.add_argument("--seed", type=int, default=0, help="graine des plis de calibration")
    return p.parse_args(argv)


def validation_block(data: Path, split_seed: int) -> Any:
    """Bloc validation du split de l'étape 1.9, reconstruit à l'identique."""
    corpus, _stats = deduplicate(load_sms_collection(data))
    split = split_sms(corpus, seed=split_seed)
    return corpus[split == "validation"].reset_index(drop=True)


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")  # accents lisibles sous Windows
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    args = parse_args(argv)
    for path, hint in ((args.data, "train_text.py"), (args.model, "train_text.py")):
        if not path.is_file():
            logger.error("%s introuvable : lancez d'abord scripts/%s", path, hint)
            return 1

    model = TextModel.load(args.model)
    data_sha = sha256_file(args.data)
    trained_on = model.metadata.get("sms_sha256")
    if trained_on and trained_on != data_sha:
        logger.error("%s n'est pas le corpus d'entraînement du modèle", args.data)
        return 1
    split_seed = int(model.metadata.get("seed", 42))
    validation = validation_block(args.data, split_seed)
    scores = model.score(validation["text"])
    labels = validation["label"].to_numpy()

    reports = compare_methods(scores, labels, folds=args.folds, seed=args.seed)
    method = best_method(reports)
    metadata = {
        "model_sha256": sha256_file(args.model),
        "sms_sha256": data_sha,
        "fitted_on": "validation",
        "split_seed": split_seed,
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
    }
    calibrator = ScoreCalibrator.fit(scores, labels, method=method, metadata=metadata)
    calibrator.save(args.output)

    report = {
        "metadata": {
            **metadata,
            "report_version": REPORT_VERSION,
            "model_version": str(model.metadata.get("model_version", "unknown")),
            "approach": model.approach,
            "folds": args.folds,
            "rows": len(labels),
            "prevalence": calibrator.prevalence,
        },
        "selected": method,
        "methods": reports,
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", "utf-8")

    print(f"{'méthode':<10}{'Brier':>9}{'ECE':>9}{'log loss':>10}")
    for name, metrics in reports.items():
        mark = "  ← retenue" if name == method else ""
        print(
            f"{name:<10}{metrics['brier']:>9.4f}{metrics['ece']:>9.4f}"
            f"{metrics['log_loss']:>10.4f}{mark}"
        )
    print(f"\nCalibration : {args.output}\nRapport : {args.report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
