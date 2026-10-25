"""Évaluation réaliste du modèle URL sur le test (étape 1.7).

    python scripts/evaluate_url.py         # ou : make evaluate-url

Lit le modèle de l'étape 1.6 (models/url_v1.joblib) et les blocs de validation et de test
de data/processed/urls_split.parquet. La validation sert à choisir le seuil de décision
(règle de phishguard.urls.evaluation.choose_decision_threshold) ; le test sert seulement
à mesurer : point de fonctionnement de chaque seuil, précision aux prévalences de 1 % et
0,1 %, rappel et FPR par source, FPR par rang Tranco si une liste Tranco brute est
disponible dans data/raw/ (ou --tranco).

Écrit docs/metrics/url_v1_test.json (sans URL ni domaine) et le bloc généré de
docs/evaluation.md.
"""

from __future__ import annotations

import argparse
import json
import logging
import math
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from phishguard.data.integrity import sha256_file
from phishguard.data.split import read_split_blocks
from phishguard.evaluation.metrics import binary_report
from phishguard.evaluation.prevalence import REALISTIC_PREVALENCES, precision_at_prevalence
from phishguard.reporting import (
    fr_int,
    fr_number,
    fr_percent,
    markdown_table,
    update_generated_block,
)
from phishguard.urls import evaluation as E
from phishguard.urls.model import UrlModel

ROOT = Path(__file__).resolve().parents[1]
REPORT_VERSION = "1.0.0"
USED_SPLITS = ("validation", "test")
DOC_BLOCK = "evaluate-url"
THRESHOLD_LABELS = {
    "fpr_5pct": "5 %",
    "fpr_2pct": "2 %",
    "fpr_1pct": "1 %",
    "fpr_0_5pct": "0,5 %",
    "fpr_0_2pct": "0,2 %",
    "fpr_0_1pct": "0,1 %",
}

logger = logging.getLogger("evaluate_url")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    p.add_argument("--dataset", type=Path, default=ROOT / "data/processed/urls_split.parquet")
    p.add_argument("--model", type=Path, default=ROOT / "models/url_v1.joblib")
    p.add_argument("--report", type=Path, default=ROOT / "docs/metrics/url_v1_test.json")
    p.add_argument("--doc", type=Path, default=ROOT / "docs/evaluation.md")
    p.add_argument(
        "--tranco",
        type=Path,
        default=None,
        help="liste Tranco brute (rang,domaine) ; par défaut la plus récente de data/raw/",
    )
    p.add_argument("--raw-dir", type=Path, default=ROOT / "data/raw")
    p.add_argument("--rounds", type=int, default=2000, help="échantillons bootstrap")
    p.add_argument("--seed", type=int, default=0)
    args = p.parse_args(argv)
    if str(args.doc).lower() == "none":
        args.doc = None
    return args


def clean(value: Any) -> Any:
    """NaN et infini → None : le JSON produit reste valide."""
    if isinstance(value, float) and not math.isfinite(value):
        return None
    if isinstance(value, dict):
        return {k: clean(v) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [clean(v) for v in value]
    return value


# --------------------------------------------------------------------------- #
# Rendu
# --------------------------------------------------------------------------- #


def _ci(rate: dict[str, Any], digits: int = 1) -> str:
    if rate["n"] == 0:
        return "n/d"
    return (
        f"{fr_percent(rate['rate'], digits)} "
        f"[{fr_number(rate['low'] * 100, digits)}–{fr_percent(rate['high'], digits)}]"
    )


def _label(name: str) -> str:
    return f"FPR {THRESHOLD_LABELS.get(name, name)} (val.)"


def _ratio(value: float | None) -> str:
    if value is None or not math.isfinite(value):
        return "∞"
    return fr_number(value, 1)


def render_markdown(report: dict[str, Any]) -> str:
    rows, meta = report["rows"], report["metadata"]
    decision = report["decision"]
    test = report["test"]
    lines = [
        (
            f"*Généré par `scripts/evaluate_url.py` le {meta['generated_at'][:10]} (modèle "
            f"`{meta['model_sha256'][:12]}`, jeu `{meta['dataset_sha256'][:12]}`, test : "
            f"{fr_int(rows['test']['total'])} URLs dont {fr_int(rows['test']['phishing'])} de "
            f"phishing, soit {fr_percent(rows['test']['phishing'] / rows['test']['total'])}). "
            "Chiffres complets : [`metrics/url_v1_test.json`](metrics/url_v1_test.json).*"
        ),
        "",
        "### Sur le test, sans seuil",
        "",
        markdown_table(
            ["PR-AUC", "ROC-AUC", "R@1%FPR", "R@0,1%FPR"],
            [
                [
                    fr_number(test["threshold_free"][k])
                    for k in ("pr_auc", "roc_auc", "recall_at_fpr_1pct", "recall_at_fpr_0_1pct")
                ]
            ],
            ["right"] * 4,
        ),
        "",
        "### Seuils réglés sur la validation, mesurés sur le test",
        "",
        "Intervalles de confiance à 95 % (Wilson) entre crochets.",
        "",
    ]
    point_rows = []
    for name, point in test["operating_points"].items():
        mark = " **(décision)**" if name == decision["name"] else ""
        point_rows.append(
            [
                _label(name) + mark,
                fr_number(point["threshold"], 4),
                _ci(point["recall"]),
                _ci(point["fpr"], 2),
                _ci(point["fpr_homepages"], 2),
                _ci(point["fpr_internal_pages"], 1),
            ]
        )
    lines.append(
        markdown_table(
            [
                "Seuil",
                "Score",
                "Rappel",
                "FPR légitime",
                "FPR pages d'accueil",
                "FPR pages internes",
            ],
            point_rows,
        )
    )

    p1, p01 = REALISTIC_PREVALENCES
    lines += [
        "",
        "### Prévalence et précision",
        "",
        (
            f"Précision attendue quand {fr_percent(p1, 0)} ou {fr_percent(p01)} des URLs sont "
            "du phishing (formule ; entre crochets, intervalle bootstrap à 95 %). « Pages "
            "internes » : même calcul si le légitime visité ne contenait que des pages "
            "internes, plus proche de la navigation réelle."
        ),
        "",
    ]
    prev_rows = []
    for name, table in test["prevalence"].items():
        by_p = {row["prevalence"]: row for row in table}
        cells = [_label(name) + (" **(décision)**" if name == decision["name"] else "")]
        cells.append(fr_percent(test["operating_points"][name]["precision_at_test_prevalence"]))
        for p in (p1, p01):
            row = by_p[p]
            r = row["precision_resampled"]
            cells.append(
                f"{fr_percent(row['precision'])} "
                f"[{fr_number(_pct(r['precision_low']), 1)}–{fr_percent(r['precision_high'])}]"
            )
        cells.append(_ratio(by_p[p01]["per_10k_false_per_true"]))
        cells.append(fr_percent(by_p[p1].get("precision_internal_pages")))
        cells.append(_ratio(by_p[p01].get("false_per_true_internal_pages")))
        prev_rows.append(cells)
    lines.append(
        markdown_table(
            [
                "Seuil",
                f"Précision au test ({fr_percent(rows['test']['phishing'] / rows['test']['total'], 0)})",
                f"Précision à {fr_percent(p1, 0)}",
                f"Précision à {fr_percent(p01)}",
                f"Fausses alertes par vraie à {fr_percent(p01)}",
                f"Précision à {fr_percent(p1, 0)}, pages internes",
                f"Fausses par vraie à {fr_percent(p01)}, pages internes",
            ],
            prev_rows,
        )
    )

    rule = decision["rule"]
    lines += [
        "",
        f"**Seuil de décision** : `{decision['name']}` (score > "
        f"{fr_number(decision['threshold'], 4)}). Règle appliquée sur la validation : meilleur "
        f"rappel parmi les seuils dont la précision attendue à {fr_percent(rule['prevalence'], 0)} "
        f"de phishing atteint {fr_percent(rule['min_precision'], 0)} ; "
        + (
            f"précision attendue sur la validation : "
            f"{fr_percent(decision['validation_precision_at_prevalence'])}, rappel "
            f"{fr_percent(decision['validation_recall'])}."
            if decision["meets_target"]
            else "**aucun seuil ne l'atteint**, le plus précis est retenu."
        ),
        "",
        "### Par source (seuil de décision)",
        "",
    ]
    source_rows = [
        [
            f"`{source}`",
            "phishing" if entry["label"] == 1 else "légitime",
            "rappel" if entry["metric"] == "recall" else "FPR",
            fr_int(entry["n"]),
            _ci(entry, 1),
        ]
        for source, entry in test["per_source"].items()
    ]
    lines.append(
        markdown_table(
            ["Source", "Classe", "Mesure", "URLs", "Valeur"],
            source_rows,
            ["left", "left", "left", "right", "right"],
        )
    )

    popularity = test.get("popularity")
    lines += ["", "### Pages d'accueil légitimes par rang Tranco (seuil de décision)", ""]
    if popularity is None:
        lines.append(
            "*Non mesuré : aucune liste Tranco brute dans `data/raw/` (option `--tranco`).*"
        )
    else:
        lines.append(
            markdown_table(
                ["Rang Tranco", "URLs", "FPR"],
                [
                    [_bucket(bucket), fr_int(r["n"]), _ci(r, 2)]
                    for bucket, r in popularity["buckets"].items()
                ],
            )
        )
    return "\n".join(lines)


def _bucket(name: str) -> str:
    if name == "unranked":
        return "hors liste"
    low, high = (int(v) for v in name.split("-"))
    return f"{fr_int(low)} à {fr_int(high)}"


def _pct(value: float | None) -> float | None:
    return None if value is None or not math.isfinite(value) else value * 100


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
    dataset_sha = sha256_file(args.dataset)
    if model.metadata.get("dataset_sha256") not in (None, dataset_sha):
        logger.warning("le modèle a été entraîné sur un autre jeu : relancez make train-url")

    columns = ["url", "label", "source", "registered_domain"]
    blocks = read_split_blocks(args.dataset, USED_SPLITS, columns)
    data = {}
    for name, block in blocks.items():
        logger.info("scores : %d URLs de %s", len(block), name)
        data[name] = (
            block["label"].to_numpy(),
            model.score(block["url"]),
            block["source"].to_numpy(dtype=str),
        )

    # 1. Choix du seuil, sur la validation seule.
    validation_points = E.operating_points(*data["validation"], model.thresholds)
    decision = E.choose_decision_threshold(validation_points)
    decision["threshold"] = model.thresholds[decision["name"]]

    # 2. Mesures sur le test.
    y, scores, sources = data["test"]
    prevalence_test = float(y.mean())
    points = E.operating_points(y, scores, sources, model.thresholds)
    for point in points.values():
        point["precision_at_test_prevalence"] = precision_at_prevalence(
            point["recall"]["rate"], point["fpr"]["rate"], prevalence_test
        )
    report_free = binary_report(y, scores)
    test: dict[str, Any] = {
        "threshold_free": {
            k: report_free[k]
            for k in ("pr_auc", "roc_auc", "recall_at_fpr_1pct", "recall_at_fpr_0_1pct")
        },
        "operating_points": points,
        "prevalence": {
            name: E.prevalence_table(y, scores, sources, t, rounds=args.rounds, seed=args.seed)
            for name, t in model.thresholds.items()
        },
        "per_source": E.per_source(y, scores, sources, decision["threshold"]),
    }

    tranco = args.tranco or E.latest_tranco_file(args.raw_dir)
    if tranco is not None and tranco.is_file():
        test_block = blocks["test"]
        homepages = (test_block["label"] == 0).to_numpy() & (sources == "tranco")
        test["popularity"] = {
            "tranco_file": tranco.name,
            "buckets": E.popularity_report(
                test_block.loc[homepages, "registered_domain"],
                scores[homepages],
                decision["threshold"],
                E.read_tranco_ranks(tranco),
            ),
        }
    else:
        logger.info("aucune liste Tranco brute : FPR par rang non mesuré")

    report = clean(
        {
            "metadata": {
                "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
                "report_version": REPORT_VERSION,
                "python": sys.version.split()[0],
                "dataset_sha256": dataset_sha,
                "model_sha256": sha256_file(args.model),
                "model": dict(model.metadata),
                "splits_used": list(USED_SPLITS),
                "bootstrap_rounds": args.rounds,
                "seed": args.seed,
            },
            "rows": {
                name: {
                    "total": len(block),
                    "phishing": int(block["label"].sum()),
                    "by_source": {
                        str(k): int(v) for k, v in block.groupby("source").size().items()
                    },
                }
                for name, block in blocks.items()
            },
            "decision": decision,
            "validation_operating_points": validation_points,
            "test": test,
        }
    )
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", "utf-8")
    if args.doc is not None:
        update_generated_block(args.doc, DOC_BLOCK, render_markdown(report))

    point = report["test"]["operating_points"][decision["name"]]
    print(
        f"\nSeuil de décision : {decision['name']} ({decision['threshold']:.4f})"
        f"\n  test : rappel {point['recall']['rate']:.3f}, FPR {point['fpr']['rate']:.4f}, "
        f"FPR pages internes {point['fpr_internal_pages']['rate'] or 0:.4f}"
    )
    for row in report["test"]["prevalence"][decision["name"]]:
        print(f"  prévalence {row['prevalence']:.1%} : précision {row['precision'] or 0:.3f}")
    print(f"\nRapport : {args.report}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
