"""Entraînement adversarial des modèles URL et SMS (étape 3.9).

    python scripts/train_adversarial.py                 # ou : make train-adversarial
    python scripts/train_adversarial.py --only text --classes phishing

Réentraîne la configuration **déjà retenue** de chaque modèle (même famille, mêmes
hyperparamètres, mêmes features, même graine, lus dans les métadonnées du modèle de
référence) sur le bloc d'entraînement augmenté par phishguard.adversarial.augment.
Seule la donnée change : l'écart mesuré ensuite est celui de l'augmentation.

- URL : bloc d'entraînement de data/processed/urls_split.parquet. La table des TLD est
  apprise sur les originaux seuls (les perturbations ne changent pas le TLD) ;
- SMS : bloc d'entraînement de la SMS Spam Collection, même dédoublonnage et même split
  groupé par gabarit que scripts/train_text.py.

Les seuils sont réglés sur la validation **non perturbée**, comme à l'origine. Le test
n'est pas lu : le banc d'essai (scripts/robustness_benchmark.py --label adversarial)
l'évalue ensuite, propre et perturbé, avec le générateur de l'étape 3.7, que le modèle
n'a pas vu.

Écrit :

- models/url_v2.joblib et models/text_v2.joblib (non versionnés) ;
- docs/metrics/adversarial_training.json : comptes de l'augmentation et métriques de
  validation, référence et modèle augmenté, sans aucun texte ni URL ;
- le bloc généré « adversarial-training » de docs/robustness-report.md.
"""

from __future__ import annotations

import argparse
import json
import logging
import re
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from phishguard.adversarial import augment as A
from phishguard.data.integrity import sha256_file
from phishguard.data.sms import deduplicate, load_sms_collection, split_sms
from phishguard.data.split import read_split_blocks
from phishguard.reporting import (
    fr_int,
    fr_number,
    fr_percent,
    markdown_table,
    update_generated_block,
)
from phishguard.security.normalize import NORMALIZATION_VERSION
from phishguard.text import models as M
from phishguard.urls import training as T
from phishguard.urls.ablation import score_report
from phishguard.urls.features import UrlFeatureExtractor
from phishguard.urls.idn import to_ascii
from phishguard.urls.model import UrlModel
from phishguard.urls.tld import TldRiskTable, top_level_domain

ROOT = Path(__file__).resolve().parents[1]
REPORT_VERSION = "1.0.0"
DOC_BLOCK = "adversarial-training"
VECTORS = ("url", "text")
LABELS = {"url": "URL", "text": "SMS"}

logger = logging.getLogger("train_adversarial")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    p.add_argument("--only", nargs="+", choices=VECTORS, default=list(VECTORS))
    p.add_argument(
        "--classes",
        choices=("phishing", "both"),
        default="both",
        help="échantillons copiés : phishing seul, ou les deux classes (défaut : %(default)s)",
    )
    p.add_argument("--copies", type=int, default=1, help="copies perturbées par échantillon")
    p.add_argument(
        "--version-suffix",
        default="",
        help="ajouté à la version des modèles (ablations : « _phishing_only »)",
    )
    p.add_argument("--seed", type=int, default=A.TRAINING_SEED, help="graine de l'augmentation")
    p.add_argument("--url-dataset", type=Path, default=ROOT / "data/processed/urls_split.parquet")
    p.add_argument("--url-reference", type=Path, default=ROOT / "models/url_v1.joblib")
    p.add_argument("--url-out", type=Path, default=ROOT / "models/url_v2.joblib")
    p.add_argument("--sms-data", type=Path, default=ROOT / "data/raw/SMSSpamCollection")
    p.add_argument("--text-reference", type=Path, default=ROOT / "models/text_v1.joblib")
    p.add_argument("--text-out", type=Path, default=ROOT / "models/text_v2.joblib")
    p.add_argument("--split-seed", type=int, default=42, help="graine du split SMS (train_text)")
    p.add_argument("--report", type=Path, default=ROOT / "docs/metrics/adversarial_training.json")
    p.add_argument(
        "--doc",
        type=Path,
        default=ROOT / "docs/robustness-report.md",
        help="document dont le bloc généré est réécrit (« none » pour ne rien écrire)",
    )
    args = p.parse_args(argv)
    if args.copies < 1:
        p.error("--copies doit être au moins 1")
    if args.seed == 0:
        p.error(
            "--seed 0 est la graine du banc d'essai : l'entraînement doit en utiliser une autre"
        )
    if args.version_suffix and not re.fullmatch(r"_[a-z0-9_]+", args.version_suffix):
        p.error("--version-suffix : « _ » suivi de minuscules, chiffres et « _ »")
    if str(args.doc).lower() == "none":
        args.doc = None
    return args


def _version_after(version: str, suffix: str = "") -> str:
    """``url_v1`` → ``url_v2`` : le modèle augmenté est une nouvelle version."""
    stem, _, number = version.rpartition("_v")
    base = f"{stem}_v{int(number) + 1}" if stem and number.isdigit() else f"{version}_adv"
    return base + suffix


# --------------------------------------------------------------------------- #
# URL
# --------------------------------------------------------------------------- #


def train_url(args: argparse.Namespace) -> dict[str, Any]:
    reference = UrlModel.load(args.url_reference)
    meta = dict(reference.metadata)
    name, params, seed = meta["model"], meta["params"], int(meta.get("seed", 42))
    columns = list(reference.feature_names)

    blocks = read_split_blocks(
        args.url_dataset, ("train", "validation"), ["url", "label", "source", "host"]
    )
    train, validation = blocks["train"], blocks["validation"]
    y_val = validation["label"].to_numpy()

    # La table des TLD n'apprend que sur les originaux : une copie a le TLD de son
    # original, la compter deux fois changerait les taux sans rien apprendre de neuf.
    tld_table = TldRiskTable.fit(
        (top_level_domain(to_ascii(h)) for h in train["host"]), train["label"].astype(int)
    )
    augmented = A.augment(
        train["url"].tolist(),
        train["label"].to_numpy(),
        "url",
        classes=args.classes,
        copies=args.copies,
        seed=args.seed,
    )
    logger.info("URL : %s", augmented.summary())

    extractor = UrlFeatureExtractor(tld_table=tld_table)
    x_train = extractor.transform(augmented.samples)
    x_val = extractor.transform(validation["url"])
    estimator = T.MODEL_SPECS[name].build(params, seed).fit(x_train[columns], augmented.labels)
    estimator = T.single_threaded(estimator)
    scores = estimator.predict_proba(x_val[columns])[:, 1]
    sources = validation["source"].to_numpy()

    version = _version_after(str(meta.get("model_version", "url_v1")), args.version_suffix)
    trained = UrlModel(
        estimator=estimator,
        feature_names=columns,
        tld_table=tld_table,
        thresholds=T.thresholds_from_validation(y_val, scores),
        metadata={
            **{k: meta[k] for k in ("model", "params", "feature_set") if k in meta},
            "model_version": version,
            "derived_from": meta.get("model_version"),
            "trained_at": datetime.now(UTC).isoformat(timespec="seconds"),
            "dataset_sha256": sha256_file(args.url_dataset),
            "seed": seed,
            "validation": score_report(y_val, scores, sources, 0.01),
            "normalization": NORMALIZATION_VERSION,
            "adversarial": _augmentation_metadata(args, augmented),
        },
    )
    trained.save(args.url_out)
    return {
        "reference": {
            "version": meta.get("model_version"),
            "sha256": sha256_file(args.url_reference),
            "validation": score_report(y_val, reference.score(validation["url"]), sources, 0.01),
        },
        "trained": {
            "version": version,
            "sha256": sha256_file(args.url_out),
            "validation": trained.metadata["validation"],
            "thresholds": {k: round(v, 6) for k, v in trained.thresholds.items()},
        },
        "config": {"model": name, "params": params, "feature_set": meta.get("feature_set")},
        "augmentation": augmented.summary(),
    }


# --------------------------------------------------------------------------- #
# SMS
# --------------------------------------------------------------------------- #


def train_text(args: argparse.Namespace) -> dict[str, Any]:
    reference = M.TextModel.load(args.text_reference)
    meta = dict(reference.metadata)
    approach, params = reference.approach, meta["params"]
    seed = int(meta.get("seed", args.split_seed))

    corpus, _ = deduplicate(load_sms_collection(args.sms_data))
    split = split_sms(corpus, seed=args.split_seed)
    train = corpus[split == "train"].reset_index(drop=True)
    validation = corpus[split == "validation"].reset_index(drop=True)
    y_val = validation["label"].to_numpy()

    augmented = A.augment(
        train["text"].tolist(),
        train["label"].to_numpy(),
        "text",
        classes=args.classes,
        copies=args.copies,
        seed=args.seed,
    )
    logger.info("SMS : %s", augmented.summary())
    estimator = M.APPROACHES[approach].build(params, seed).fit(augmented.samples, augmented.labels)
    scores = M.scores_of(estimator, validation["text"])
    threshold = M.decision_threshold(y_val, scores)

    version = _version_after(str(meta.get("model_version", "text_v1")), args.version_suffix)
    trained = M.TextModel(
        estimator=estimator,
        approach=approach,
        threshold=threshold,
        metadata={
            "model_version": version,
            "derived_from": meta.get("model_version"),
            "params": params,
            "trained_at": datetime.now(UTC).isoformat(timespec="seconds"),
            "sms_sha256": sha256_file(args.sms_data),
            "seed": seed,
            "validation": M.evaluate_at_threshold(y_val, scores, threshold),
            "normalization": NORMALIZATION_VERSION,
            "adversarial": _augmentation_metadata(args, augmented),
        },
    )
    trained.save(args.text_out)
    reference_scores = reference.score(validation["text"])
    return {
        "reference": {
            "version": meta.get("model_version"),
            "sha256": sha256_file(args.text_reference),
            "validation": M.evaluate_at_threshold(y_val, reference_scores, reference.threshold),
        },
        "trained": {
            "version": version,
            "sha256": sha256_file(args.text_out),
            "validation": trained.metadata["validation"],
            "threshold": threshold,
        },
        "config": {"approach": approach, "params": params},
        "augmentation": augmented.summary(),
    }


def _augmentation_metadata(args: argparse.Namespace, augmented: A.Augmentation) -> dict[str, Any]:
    return {
        "generator_version": A.GENERATOR_VERSION,
        "classes": args.classes,
        "copies": args.copies,
        "seed": args.seed,
        **augmented.summary(),
    }


# --------------------------------------------------------------------------- #
# Rendu
# --------------------------------------------------------------------------- #


def _recall(entry: dict[str, Any]) -> float | None:
    if "recall" not in entry:
        return None
    recall = entry["recall"]
    return recall["rate"] if isinstance(recall, dict) else recall


def render_markdown(report: dict[str, Any]) -> str:
    meta = report["metadata"]
    lines = [
        (
            f"*Généré par `scripts/train_adversarial.py` le {meta['generated_at'][:10]} : "
            f"générateur d'entraînement {meta['generator_version']}, graine {meta['seed']}, "
            f"{meta['copies']} copie(s) par échantillon, classes perturbées : "
            f"{'phishing seul' if meta['classes'] == 'phishing' else 'phishing et légitime'}. "
            "Chiffres complets : [`metrics/adversarial_training.json`]"
            "(metrics/adversarial_training.json).*"
        ),
        "",
    ]
    rows = []
    for vector, entry in report["models"].items():
        aug = entry["augmentation"]
        ref, new = entry["reference"]["validation"], entry["trained"]["validation"]
        rows.append(
            [
                LABELS[vector],
                f"`{entry['reference']['version']}` → `{entry['trained']['version']}`",
                fr_int(aug["original"]),
                f"{fr_int(aug['added_phishing'])} / {fr_int(aug['added_legitimate'])}",
                ", ".join(f"`{k}` {fr_int(v)}" for k, v in aug["by_recipe"].items()),
                f"{fr_number(ref['pr_auc'])} → {fr_number(new['pr_auc'])}",
                f"{fr_number(ref['recall_at_fpr_1pct'])} → {fr_number(new['recall_at_fpr_1pct'])}",
            ]
        )
    lines.append(
        markdown_table(
            [
                "Modèle",
                "Version",
                "Entraînement",
                "Copies phishing / légitime",
                "Recettes",
                "PR-AUC validation",
                "R@1%FPR validation",
            ],
            rows,
            ["left", "left", "right", "right", "left", "right", "right"],
        )
    )
    return "\n".join(lines)


def print_summary(report: dict[str, Any]) -> None:
    for vector, entry in report["models"].items():
        ref, new = entry["reference"]["validation"], entry["trained"]["validation"]
        print(
            f"\n{LABELS[vector]} : {entry['augmentation']['added']} copies ajoutées ; "
            f"PR-AUC {ref['pr_auc']:.4f} → {new['pr_auc']:.4f}, "
            f"R@1%FPR {ref['recall_at_fpr_1pct']:.4f} → {new['recall_at_fpr_1pct']:.4f}"
        )
        recall = _recall(new)
        if recall is not None:
            print(f"  rappel au seuil de validation : {fr_percent(recall)}")


# --------------------------------------------------------------------------- #


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")  # accents lisibles sous Windows
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    args = parse_args(argv)

    required = []
    if "url" in args.only:
        required += [(args.url_dataset, "split_dataset.py"), (args.url_reference, "train_url.py")]
    if "text" in args.only:
        required += [(args.sms_data, "train_text.py"), (args.text_reference, "train_text.py")]
    for path, hint in required:
        if not path.is_file():
            logger.error("%s introuvable : lancez d'abord scripts/%s", path, hint)
            return 1

    models: dict[str, Any] = {}
    if "url" in args.only:
        models["url"] = train_url(args)
    if "text" in args.only:
        models["text"] = train_text(args)

    report = {
        "report_version": REPORT_VERSION,
        "metadata": {
            "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
            "generator_version": A.GENERATOR_VERSION,
            "classes": args.classes,
            "copies": args.copies,
            "seed": args.seed,
            "splits_augmented": ["train"],
            "recipes": {
                r.name: {"vector": r.vector, "technique": r.technique, "description": r.description}
                for r in A.RECIPES.values()
            },
        },
        "models": models,
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", "utf-8")
    logger.info("rapport écrit : %s", args.report)
    if args.doc is not None:
        update_generated_block(args.doc, DOC_BLOCK, render_markdown(report))
    print_summary(report)
    return 0


if __name__ == "__main__":
    sys.exit(main())
