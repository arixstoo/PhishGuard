"""Entraîne et compare les modèles URL, puis enregistre le meilleur (étape 1.6).

    python scripts/train_url.py            # ou : make train-url
    python scripts/train_url.py --quick    # grilles réduites, pour vérifier le pipeline

Lit les blocs d'entraînement et de validation de data/processed/urls_split.parquet
(étape 1.4) ; le bloc de test n'est pas chargé. Apprend la table des TLD sur
l'entraînement, extrait les features (étape 1.5), puis entraîne régression logistique,
Random Forest et LightGBM pour chaque combinaison d'hyperparamètres et chaque jeu de
features (phishguard.urls.training). Le choix se fait sur la validation.

Écrit :

- models/url_v1.joblib : le modèle retenu, ses features, sa table des TLD et ses seuils
  (non versionné) ;
- docs/metrics/url_v1.json : tous les essais et le choix final, sans URL ni domaine ;
- le bloc généré de docs/url-models.md (tableaux de résultats).
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pandas as pd

from phishguard.data.integrity import sha256_file
from phishguard.data.split import read_split_blocks
from phishguard.reporting import (
    fr_int,
    fr_number,
    fr_percent,
    markdown_table,
    update_generated_block,
)
from phishguard.urls import training as T
from phishguard.urls.brands import list_versions
from phishguard.urls.features import UrlFeatureExtractor
from phishguard.urls.idn import to_ascii
from phishguard.urls.model import UrlModel, library_versions
from phishguard.urls.tld import TldRiskTable, top_level_domain

ROOT = Path(__file__).resolve().parents[1]
REPORT_VERSION = "1.0.0"
MODEL_VERSION = "url_v1"
USED_SPLITS = ("train", "validation")
DOC_BLOCK = "train-url"
FEATURE_SET_LABELS = {
    "all": "toutes",
    "without_scheme": "sans schéma",
    "without_path": "sans chemin",
    "without_length": "sans longueur",
    "without_path_and_length": "sans chemin ni longueur",
    "host_only": "hôte seul",
}

logger = logging.getLogger("train_url")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    p.add_argument("--dataset", type=Path, default=ROOT / "data/processed/urls_split.parquet")
    p.add_argument("--model-out", type=Path, default=ROOT / f"models/{MODEL_VERSION}.joblib")
    p.add_argument("--report", type=Path, default=ROOT / f"docs/metrics/{MODEL_VERSION}.json")
    p.add_argument(
        "--doc",
        type=Path,
        default=ROOT / "docs/url-models.md",
        help="document dont le bloc généré est réécrit (« none » pour ne rien écrire)",
    )
    p.add_argument("--models", nargs="+", choices=list(T.MODEL_SPECS), default=list(T.MODEL_SPECS))
    p.add_argument(
        "--feature-sets", nargs="+", choices=list(T.FEATURE_SETS), default=list(T.FEATURE_SETS)
    )
    p.add_argument(
        "--deploy-feature-set",
        choices=list(T.FEATURE_SETS),
        default=T.DEFAULT_DEPLOY_FEATURE_SET,
        help="jeu de features du modèle enregistré (défaut : %(default)s)",
    )
    p.add_argument("--quick", action="store_true", help="grilles réduites (vérification rapide)")
    p.add_argument("--seed", type=int, default=42)
    args = p.parse_args(argv)
    if args.deploy_feature_set not in args.feature_sets:
        p.error("--deploy-feature-set doit faire partie de --feature-sets")
    if str(args.doc).lower() == "none":
        args.doc = None
    return args


# --------------------------------------------------------------------------- #
# Rendu
# --------------------------------------------------------------------------- #


def _params(params: dict[str, Any]) -> str:
    return ", ".join(f"{k}={v}" for k, v in params.items())


def render_markdown(report: dict[str, Any]) -> str:
    """Tableaux du bloc généré de docs/url-models.md."""
    deploy = report["selection"]["deploy_feature_set"]
    rows = report["rows"]
    lines = [
        (
            f"*Généré par `scripts/train_url.py` le {report['metadata']['generated_at'][:10]} "
            f"(jeu `{report['metadata']['dataset_sha256'][:12]}`, "
            f"{'grilles réduites, ' if report['metadata']['quick'] else ''}"
            f"validation : {fr_int(rows['validation']['total'])} URLs dont "
            f"{fr_int(rows['validation']['phishing'])} de phishing). "
            f"Chiffres complets : [`metrics/{MODEL_VERSION}.json`](metrics/{MODEL_VERSION}.json).*"
        ),
        "",
        f"### Les trois modèles (jeu de features « {FEATURE_SET_LABELS[deploy]} »)",
        "",
    ]
    table = []
    for name, entry in report["models"].items():
        m = entry["validation"]
        cost = entry["inference"]
        table.append(
            [
                T.MODEL_SPECS[name].label + (" **(retenu)**" if entry["selected"] else ""),
                f"`{_params(entry['params'])}`",
                fr_number(m["pr_auc"]),
                fr_number(m["recall_at_fpr_1pct"]),
                fr_number(m["recall_at_fpr_0_1pct"]),
                fr_percent(m["fpr_internal_pages"]),
                f"{fr_number(cost['latency_ms_p50'], 2)} ms",
                f"{fr_number(cost['predict_us_per_url'], 1)} µs",
                f"{fr_int(round(entry['size_bytes'] / 1024))} Kio",
            ]
        )
    lines.append(
        markdown_table(
            [
                "Modèle",
                "Hyperparamètres retenus",
                "PR-AUC",
                "R@1%FPR",
                "R@0,1%FPR",
                "FPR pages internes",
                "Latence p50 (1 URL)",
                "Modèle seul (lot)",
                "Taille",
            ],
            table,
            ["left", "left"] + ["right"] * 7,
        )
    )

    sets = report["selection"]["feature_sets"]
    models = list(report["models"])
    lines += [
        "",
        "### Rappel à 1 % FPR selon le jeu de features",
        "",
        (
            "Meilleur réglage de chaque modèle pour chaque jeu ; entre parenthèses, le taux de "
            "faux positifs sur les pages internes légitimes au même seuil."
        ),
        "",
    ]
    best = {(b["model"], b["feature_set"]): b for b in report["best_per_model_and_feature_set"]}
    grid_rows = []
    for set_name in sets:
        cells = [FEATURE_SET_LABELS[set_name]]
        for name in models:
            b = best[(name, set_name)]
            cells.append(
                f"{fr_number(b['recall_at_fpr_1pct'])} ({fr_percent(b['fpr_internal_pages'])})"
            )
        grid_rows.append(cells)
    lines.append(
        markdown_table(["Jeu de features", *(T.MODEL_SPECS[m].label for m in models)], grid_rows)
    )

    selected = report["selected"]
    lines += [
        "",
        (
            f"**Modèle retenu** : {T.MODEL_SPECS[selected['model']].label} "
            f"(`{_params(selected['params'])}`), {selected['n_features']} features. "
            f"Seuil à 1 % FPR sur la validation : {fr_number(selected['thresholds']['fpr_1pct'], 4)} ; "
            f"à 0,1 % : {fr_number(selected['thresholds']['fpr_0_1pct'], 4)}."
        ),
    ]
    return "\n".join(lines)


def print_summary(report: dict[str, Any]) -> None:
    print(f"\n  {'':<24}{'PR-AUC':>8}{'R@1%':>8}{'R@0,1%':>8}{'FPR int.':>10}{'p50 ms':>9}")
    for name, entry in report["models"].items():
        m = entry["validation"]
        mark = " *" if entry["selected"] else ""
        print(
            f"  {name + mark:<24}{m['pr_auc']:>8.3f}{m['recall_at_fpr_1pct']:>8.3f}"
            f"{m['recall_at_fpr_0_1pct']:>8.3f}{m['fpr_internal_pages']:>10.2%}"
            f"{entry['inference']['latency_ms_p50']:>9.2f}"
        )
    print(f"\n  * retenu ; jeu de features : {report['selection']['deploy_feature_set']}")


# --------------------------------------------------------------------------- #


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")  # accents lisibles sous Windows
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    args = parse_args(argv)

    if not args.dataset.is_file():
        logger.error("%s introuvable : lancez d'abord scripts/split_dataset.py", args.dataset)
        return 1
    blocks = read_split_blocks(args.dataset, USED_SPLITS, ["url", "label", "source", "host"])
    train, validation = blocks["train"], blocks["validation"]
    y_train, y_val = train["label"].to_numpy(), validation["label"].to_numpy()

    # La table des TLD n'apprend que sur l'entraînement (sinon : fuite d'étiquette).
    tld_table = TldRiskTable.fit(
        (top_level_domain(to_ascii(host)) for host in train["host"]), train["label"].astype(int)
    )
    extractor = UrlFeatureExtractor(tld_table=tld_table)
    logger.info("features : %d URLs d'entraînement, %d de validation", len(train), len(validation))
    x_train = extractor.transform(train["url"])
    x_val = extractor.transform(validation["url"])

    result = T.search(
        x_train,
        y_train,
        x_val,
        y_val,
        validation["source"].to_numpy(),
        models=args.models,
        feature_sets=args.feature_sets,
        deploy_feature_set=args.deploy_feature_set,
        grids=T.QUICK_GRIDS if args.quick else None,
        seed=args.seed,
    )

    deploy = args.deploy_feature_set
    columns = T.FEATURE_SETS[deploy]
    selected = result.best_model(deploy)
    dataset_sha = sha256_file(args.dataset)

    models_report: dict[str, Any] = {}
    selected_model: UrlModel | None = None
    for name in args.models:
        trial = result.best[(name, deploy)]
        scores = result.validation_scores[name]
        candidate = UrlModel(
            estimator=result.estimators[name],
            feature_names=columns,
            tld_table=tld_table,
            thresholds=T.thresholds_from_validation(y_val, scores),
            metadata={
                "model_version": MODEL_VERSION,
                "model": name,
                "params": trial.params,
                "feature_set": deploy,
                "trained_at": datetime.now(UTC).isoformat(timespec="seconds"),
                "dataset_sha256": dataset_sha,
                "seed": args.seed,
                "validation": trial.metrics,
            },
        )
        models_report[name] = {
            "selected": name == selected.model,
            "params": trial.params,
            "validation": trial.metrics,
            "inference": T.measure_inference(candidate, validation["url"].tolist(), x_val),
            "size_bytes": T.serialized_size(candidate.estimator),
        }
        if name == selected.model:
            selected_model = candidate
    assert selected_model is not None

    selected_model.save(args.model_out)
    report = {
        "metadata": {
            "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
            "report_version": REPORT_VERSION,
            "python": sys.version.split()[0],
            "pandas": pd.__version__,
            **library_versions(),
            "dataset_sha256": dataset_sha,
            "splits_used": list(USED_SPLITS),
            "lists": list_versions(),
            "seed": args.seed,
            "quick": args.quick,
        },
        "rows": {
            name: {
                "total": len(block),
                "phishing": int(block["label"].sum()),
                "by_source": {str(k): int(v) for k, v in block.groupby("source").size().items()},
            }
            for name, block in blocks.items()
        },
        "selection": {
            "metric": T.SELECTION_METRIC,
            "tie_break": T.TIE_BREAK_METRIC,
            "evaluated_on": "validation",
            "deploy_feature_set": deploy,
            "feature_sets": {name: list(T.FEATURE_SETS[name]) for name in args.feature_sets},
        },
        "models": models_report,
        "best_per_model_and_feature_set": [t.to_dict() for t in result.best.values()],
        "trials": [t.to_dict() for t in result.trials],
        "selected": {
            "model": selected.model,
            "params": selected.params,
            "feature_set": deploy,
            "n_features": len(columns),
            "thresholds": {k: round(v, 6) for k, v in selected_model.thresholds.items()},
            "path": args.model_out.resolve().relative_to(ROOT).as_posix()
            if args.model_out.resolve().is_relative_to(ROOT)
            else args.model_out.name,
            "sha256": sha256_file(args.model_out),
        },
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", "utf-8")
    if args.doc is not None:
        update_generated_block(args.doc, DOC_BLOCK, render_markdown(report))

    print_summary(report)
    print(f"\nModèle : {args.model_out}\nRapport : {args.report}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
