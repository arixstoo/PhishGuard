"""Analyse des pires erreurs du modèle URL (étape 1.8).

    python scripts/analyze_url_errors.py            # ou : make errors-url
    python scripts/analyze_url_errors.py --split test

Lit le modèle de l'étape 1.6 et data/processed/urls_split.parquet. Le seuil de décision
est recalculé sur la validation avec la règle de l'étape 1.7
(phishguard.urls.evaluation.choose_decision_threshold). Les 50 pires faux positifs et
faux négatifs du bloc analysé sont rangés par catégorie (phishguard.urls.errors).

Bloc analysé : la **validation** par défaut. L'analyse d'erreurs sert à décider des
prochaines améliorations ; la mener sur le test reviendrait à régler le modèle sur lui.

Écrit :

- data/reports/url_errors_<bloc>.csv : les erreurs avec leur URL complète, pour la
  relecture (non versionné) ;
- docs/metrics/url_errors.json : effectifs par catégorie et exemples défangés ;
- le bloc généré de docs/error-analysis-url.md.
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
from phishguard.reporting import (
    fr_int,
    fr_number,
    fr_percent,
    markdown_table,
    update_generated_block,
)
from phishguard.urls import errors as X
from phishguard.urls.evaluation import choose_decision_threshold, operating_points
from phishguard.urls.features import UrlFeatureExtractor
from phishguard.urls.model import UrlModel

ROOT = Path(__file__).resolve().parents[1]
REPORT_VERSION = "1.0.0"
DOC_BLOCK = "errors-url"
KIND_TITLES = {
    X.FALSE_POSITIVE: "Faux positifs (légitime signalé)",
    X.FALSE_NEGATIVE: "Faux négatifs (phishing manqué)",
}

logger = logging.getLogger("analyze_url_errors")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    p.add_argument("--dataset", type=Path, default=ROOT / "data/processed/urls_split.parquet")
    p.add_argument("--model", type=Path, default=ROOT / "models/url_v1.joblib")
    p.add_argument("--split", choices=("validation", "test"), default="validation")
    p.add_argument("-n", "--worst", type=int, default=50, help="erreurs analysées par type")
    p.add_argument("--report", type=Path, default=ROOT / "docs/metrics/url_errors.json")
    p.add_argument("--doc", type=Path, default=ROOT / "docs/error-analysis-url.md")
    p.add_argument("--details-dir", type=Path, default=ROOT / "data/reports")
    args = p.parse_args(argv)
    if args.worst <= 0:
        p.error("--worst doit être strictement positif")
    if str(args.doc).lower() == "none":
        args.doc = None
    return args


# --------------------------------------------------------------------------- #
# Rendu
# --------------------------------------------------------------------------- #


def _count(n: int, word: str) -> str:
    return f"{fr_int(n)} {word}{'s' if n > 1 else ''}"


def _all(category: dict[str, Any]) -> str:
    """Effectif et part de la catégorie sur toutes les erreurs du seuil."""
    if category.get("count_all") is None:
        return "n/d"
    return f"{fr_int(category['count_all'])} ({fr_percent(category['share_all'], 0)})"


def _worst(analyzed: int, total: int) -> str:
    if analyzed == total:
        return "toutes sont classées"
    return f"les {fr_int(analyzed)} pires sont classées"


def render_markdown(report: dict[str, Any]) -> str:
    meta, decision = report["metadata"], report["decision"]
    lines = [
        (
            f"*Généré par `scripts/analyze_url_errors.py` le {meta['generated_at'][:10]} "
            f"(modèle `{meta['model_sha256'][:12]}`, bloc **{meta['split']}**, seuil "
            f"`{decision['name']}` : score > {fr_number(decision['threshold'], 4)}). "
            "Exemples défangés, sans requête, hors OpenPhish. "
            "Chiffres complets : [`metrics/url_errors.json`](metrics/url_errors.json).*"
        ),
    ]
    for kind, title in KIND_TITLES.items():
        entry = report["errors"][kind]
        lines += ["", f"### {title}", ""]
        if entry["analyzed"]:
            lines += [
                (
                    f"{_count(entry['total_errors'], 'erreur')} au seuil de décision ; "
                    f"{_worst(entry['analyzed'], entry['total_errors'])}."
                ),
                "",
            ]
        rows = []
        for category in entry["categories"].values():
            if category["count"] == 0 and not category.get("count_all"):
                continue
            sources = ", ".join(f"{k} {v}" for k, v in category["by_source"].items())
            examples = "<br>".join(f"`{e}`" for e in category["examples"]) or "—"
            rows.append(
                [
                    category["label"],
                    fr_int(category["count"]),
                    fr_percent(category["share"], 0),
                    _all(category),
                    fr_number(category["median_score"], 3),
                    sources,
                    examples,
                ]
            )
        if rows:
            lines.append(
                markdown_table(
                    [
                        "Catégorie",
                        "Erreurs",
                        "Part",
                        "Toutes les erreurs",
                        "Score médian",
                        "Sources",
                        "Exemples",
                    ],
                    rows,
                    ["left", "right", "right", "right", "right", "left", "left"],
                )
            )
        else:
            lines.append("*Aucune erreur de ce type au seuil de décision.*")
    return "\n".join(lines)


def render_definitions() -> str:
    """Tableau des règles et pistes, tiré de phishguard.urls.errors (source unique)."""
    rows = [
        [
            "faux positif" if c["kind"] == X.FALSE_POSITIVE else "faux négatif",
            c["label"],
            c["rule"],
            c["improvement"],
        ]
        for c in X.category_definitions()
    ]
    return markdown_table(
        ["Type", "Catégorie", "Règle (dans l'ordre)", "Piste d'amélioration"],
        rows,
        ["left"] * 4,
    )


# --------------------------------------------------------------------------- #


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

    names = ("validation",) if args.split == "validation" else ("validation", "test")
    blocks = read_split_blocks(args.dataset, names, ["url", "label", "source"])
    validation = blocks["validation"]
    val_scores = model.score(validation["url"])
    decision = choose_decision_threshold(
        operating_points(
            validation["label"].to_numpy(),
            val_scores,
            validation["source"].to_numpy(dtype=str),
            model.thresholds,
        )
    )
    threshold = model.thresholds[decision["name"]]

    block = blocks[args.split]
    scores = val_scores if args.split == "validation" else model.score(block["url"])
    ctx = X.Context(
        platforms=X.load_hosting_platforms(),
        tld_prior=None if model.tld_table is None else model.tld_table.prior,
    )
    extractor = UrlFeatureExtractor(tld_table=model.tld_table)
    errors = X.analyze(block, scores, threshold, extractor, ctx, n=args.worst)

    labels = block["label"].to_numpy()
    totals = {
        X.FALSE_POSITIVE: int(((labels == 0) & (scores > threshold)).sum()),
        X.FALSE_NEGATIVE: int(((labels == 1) & (scores <= threshold)).sum()),
    }
    # Toutes les erreurs au seuil, pour comparer leur répartition à celle des pires.
    every_error = X.analyze(block, scores, threshold, extractor, ctx, n=max(1, *totals.values()))
    report = {
        "metadata": {
            "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
            "report_version": REPORT_VERSION,
            "dataset_sha256": sha256_file(args.dataset),
            "model_sha256": sha256_file(args.model),
            "split": args.split,
            "worst_per_kind": args.worst,
            "rows": len(block),
            "publishable_sources": sorted(X.PUBLISHABLE_SOURCES),
        },
        "decision": {**decision, "threshold": threshold},
        "categories": X.category_definitions(),
        "errors": X.summarize(errors, totals, all_errors=every_error),
    }

    args.details_dir.mkdir(parents=True, exist_ok=True)
    details = args.details_dir / f"url_errors_{args.split}.csv"
    errors.to_csv(details, index=False)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", "utf-8")
    if args.doc is not None:
        update_generated_block(args.doc, DOC_BLOCK, render_markdown(report))
        update_generated_block(args.doc, "errors-url-categories", render_definitions())

    for kind, title in KIND_TITLES.items():
        print(f"\n{title} : {totals[kind]} au total")
        for name, category in report["errors"][kind]["categories"].items():
            if category["count"]:
                print(f"  {name:<26}{category['count']:>4}")
    print(f"\nDétail (URLs complètes, non versionné) : {details}\nRapport : {args.report}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
