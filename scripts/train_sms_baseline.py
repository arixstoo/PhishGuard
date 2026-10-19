"""Reproduit le baseline SMS en une commande.

    python scripts/train_sms_baseline.py

Télécharge (si besoin) la UCI SMS Spam Collection dans data/raw/, vérifie son empreinte,
entraîne TF-IDF + régression logistique et écrit les métriques dans
docs/metrics/sms_baseline.json.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import joblib

from phishguard.data.sms import download_sms_collection, load_sms_collection, sha256_bytes
from phishguard.text.baseline import BaselineConfig, train_and_evaluate

ROOT = Path(__file__).resolve().parents[1]


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    p.add_argument("--data", type=Path, default=ROOT / "data/raw/SMSSpamCollection")
    p.add_argument("--metrics-out", type=Path, default=ROOT / "docs/metrics/sms_baseline.json")
    p.add_argument("--model-out", type=Path, default=ROOT / "models/sms_baseline.joblib")
    p.add_argument(
        "--errors-out",
        type=Path,
        default=ROOT / "data/interim/sms_baseline_errors.json",
        help="pires erreurs (texte brut, non versionné)",
    )
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--test-size", type=float, default=0.2)
    p.add_argument("--threshold", type=float, default=0.5)
    p.add_argument(
        "--offline", action="store_true", help="ne pas télécharger, utiliser --data tel quel"
    )
    return p.parse_args(argv)


def print_summary(metrics: dict) -> None:
    dedup = metrics["dataset"]["deduplication"]
    print(
        f"Corpus : {dedup['rows_before']} messages, "
        f"{dedup['duplicates_removed']} doublons retirés -> {dedup['rows_after']}"
    )
    header = f"{'protocole':<14}{'précision':>10}{'rappel':>9}{'F1':>8}{'FP':>5}{'FN':>5}"
    header += f"{'PR-AUC':>9}{'R@1%FPR':>9}{'fuite':>7}"
    print(header)
    for name, m in metrics["protocols"].items():
        cm = m["confusion_matrix"]
        print(
            f"{name:<14}{m['precision']:>10.3f}{m['recall']:>9.3f}{m['f1']:>8.3f}"
            f"{cm['fp']:>5}{cm['fn']:>5}{m['pr_auc']:>9.3f}{m['recall_at_fpr_1pct']:>9.3f}"
            f"{m['test_messages_seen_in_train']:>7}"
        )


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")  # accents lisibles sous Windows
    data_path = args.data if args.offline else download_sms_collection(args.data)

    raw = load_sms_collection(data_path)
    cfg = BaselineConfig(test_size=args.test_size, seed=args.seed, threshold=args.threshold)
    model, metrics, errors = train_and_evaluate(raw, cfg)
    metrics["dataset"]["sha256"] = sha256_bytes(Path(data_path).read_bytes())

    args.metrics_out.parent.mkdir(parents=True, exist_ok=True)
    args.metrics_out.write_text(
        json.dumps(metrics, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    args.errors_out.parent.mkdir(parents=True, exist_ok=True)
    args.errors_out.write_text(json.dumps(errors, indent=2, ensure_ascii=False), encoding="utf-8")
    # Attention : joblib = pickle. Ne jamais charger un .joblib d'origine inconnue,
    # cela revient à exécuter du code arbitraire.
    args.model_out.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, args.model_out)

    print_summary(metrics)
    print(f"\nMétriques : {args.metrics_out}")
    print(f"Erreurs   : {args.errors_out}  (texte brut, non versionné)")
    print(f"Modèle    : {args.model_out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
