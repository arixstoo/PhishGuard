"""Compare les modèles de texte pour les SMS et enregistre le meilleur (étape 1.9).

    python scripts/train_text.py                  # ou : make train-text
    python scripts/train_text.py --embeddings     # ajoute l'approche par embeddings
    python scripts/train_text.py --quick          # un seul réglage par approche

Télécharge (si besoin) la UCI SMS Spam Collection dans data/raw/ et vérifie son
empreinte, retire les doublons, puis découpe le corpus en 70 / 15 / 15, groupé par
gabarit de message (phishguard.data.sms.split_sms). Chaque approche de
phishguard.text.models est réglée sur la validation ; le test n'est lu qu'une fois.
Le jeu français / arabe (datasets/sms_fr_ar.csv) sert de test hors distribution :
aucun modèle ne l'a vu, et aucun seuil n'est réglé dessus.

Écrit :

- models/text_v1.joblib : l'approche retenue et son seuil (non versionné) ;
- docs/metrics/text_v1.json : essais, résultats et coûts, sans aucun texte de message ;
- le bloc généré de docs/text-models.md.
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
from phishguard.data.sms import (
    deduplicate,
    download_sms_collection,
    load_sms_collection,
    load_sms_fr_ar,
    split_sms,
    template_overlap,
)
from phishguard.reporting import (
    fr_int,
    fr_number,
    fr_percent,
    markdown_table,
    update_generated_block,
)
from phishguard.text import models as M

ROOT = Path(__file__).resolve().parents[1]
REPORT_VERSION = "1.0.0"
MODEL_VERSION = "text_v1"
DOC_BLOCK = "train-text"
LANG_LABELS = {"fr": "français", "ar": "arabe"}

logger = logging.getLogger("train_text")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    p.add_argument("--data", type=Path, default=ROOT / "data/raw/SMSSpamCollection")
    p.add_argument(
        "--offline", action="store_true", help="ne pas télécharger, utiliser --data tel quel"
    )
    p.add_argument("--fr-ar", type=Path, default=ROOT / "datasets/sms_fr_ar.csv")
    p.add_argument("--model-out", type=Path, default=ROOT / f"models/{MODEL_VERSION}.joblib")
    p.add_argument("--report", type=Path, default=ROOT / f"docs/metrics/{MODEL_VERSION}.json")
    p.add_argument("--doc", type=Path, default=ROOT / "docs/text-models.md")
    p.add_argument(
        "--approaches",
        nargs="+",
        choices=list(M.APPROACHES),
        default=list(M.DEFAULT_APPROACHES),
    )
    p.add_argument("--embeddings", action="store_true", help="ajoute embeddings_logreg")
    p.add_argument("--embedding-model", default=M.DEFAULT_EMBEDDING_MODEL)
    p.add_argument("--quick", action="store_true", help="un seul réglage par approche")
    p.add_argument("--seed", type=int, default=42)
    args = p.parse_args(argv)
    if args.embeddings and "embeddings_logreg" not in args.approaches:
        args.approaches.append("embeddings_logreg")
    if str(args.doc).lower() == "none":
        args.doc = None
    return args


# --------------------------------------------------------------------------- #
# Rendu
# --------------------------------------------------------------------------- #


def _params(params: dict[str, Any]) -> str:
    return ", ".join(f"{k}={v}" for k, v in params.items())


def _size(entry: dict[str, Any]) -> str:
    size = entry["size_bytes"]
    text = f"{fr_int(round(size / 1024))} Kio"
    encoder = entry.get("encoder_size_bytes")
    if encoder:
        text += f" + encodeur {fr_int(round(encoder / 1024**2))} Mio"
    elif entry["approach"] == "embeddings_logreg":
        text += " + encodeur (n/d)"
    return text


def render_markdown(report: dict[str, Any]) -> str:
    meta, data = report["metadata"], report["dataset"]
    blocks = data["blocks"]
    lines = [
        (
            f"*Généré par `scripts/train_text.py` le {meta['generated_at'][:10]} (corpus "
            f"`{meta['sms_sha256'][:12]}`, {fr_int(data['deduplication']['rows_after'])} "
            f"messages après dédoublonnage ; test : {fr_int(blocks['test']['rows'])} messages "
            f"dont {fr_int(blocks['test']['spam'])} spams"
            f"{', grilles réduites' if meta['quick'] else ''}). Seuil de chaque approche : "
            "1 % de faux positifs sur la validation. Chiffres complets : "
            f"[`metrics/{MODEL_VERSION}.json`](metrics/{MODEL_VERSION}.json).*"
        ),
        "",
        "### Test (UCI, anglais)",
        "",
    ]
    rows = []
    for name, entry in report["approaches"].items():
        test = entry["test"]
        rows.append(
            [
                M.APPROACHES[name].label + (" **(retenu)**" if entry["selected"] else ""),
                f"`{_params(entry['params'])}`",
                fr_number(test["precision"]),
                fr_number(test["recall"]),
                fr_number(test["f1"]),
                fr_percent(test["fpr"], 2),
                fr_number(test["pr_auc"]),
                fr_number(test["recall_at_fpr_1pct"]),
                _size(entry),
                f"{fr_number(entry['latency']['latency_ms_p50'], 2)} ms",
            ]
        )
    lines.append(
        markdown_table(
            [
                "Approche",
                "Réglage",
                "Précision",
                "Rappel",
                "F1",
                "FPR",
                "PR-AUC",
                "R@1%FPR",
                "Taille",
                "Latence p50",
            ],
            rows,
            ["left", "left"] + ["right"] * 8,
        )
    )

    fr_ar = report["fr_ar"]
    lines += [
        "",
        "### Hors distribution : jeu français / arabe",
        "",
        (
            f"{fr_int(fr_ar['rows'])} messages rédigés à la main (voir "
            "[`../datasets/README.md`](../datasets/README.md)), jamais vus à l'entraînement, "
            "même seuil qu'au-dessus. Rappel = part du smishing détectée, FPR = part du "
            "légitime signalée."
        ),
        "",
    ]
    rows = []
    for name, entry in report["approaches"].items():
        cells = [M.APPROACHES[name].label]
        for lang in ("fr", "ar"):
            r = entry["fr_ar"][lang]
            cells += [fr_number(r["recall"]), fr_percent(r["fpr"], 0), fr_number(r["pr_auc"])]
        rows.append(cells)
    headers = ["Approche"]
    for lang in ("fr", "ar"):
        label = LANG_LABELS[lang]
        headers += [f"Rappel {label}", f"FPR {label}", f"PR-AUC {label}"]
    lines.append(markdown_table(headers, rows))

    selected = report["selected"]
    lines += [
        "",
        (
            f"**Approche retenue** (meilleure PR-AUC de validation) : "
            f"{M.APPROACHES[selected['approach']].label} (`{_params(selected['params'])}`), "
            f"seuil {fr_number(selected['threshold'], 4)}."
        ),
    ]
    return "\n".join(lines)


def print_summary(report: dict[str, Any]) -> None:
    print(
        f"\n  {'':<24}{'préc.':>7}{'rappel':>8}{'PR-AUC':>8}{'R@1%':>7}{'FR rap.':>9}{'AR rap.':>9}"
    )
    for name, entry in report["approaches"].items():
        t = entry["test"]
        mark = " *" if entry["selected"] else ""

        def f(v: float | None) -> str:
            return "  n/d" if v is None else f"{v:.3f}"

        print(
            f"  {name + mark:<24}{f(t['precision']):>7}{f(t['recall']):>8}{f(t['pr_auc']):>8}"
            f"{f(t['recall_at_fpr_1pct']):>7}{f(entry['fr_ar']['fr']['recall']):>9}"
            f"{f(entry['fr_ar']['ar']['recall']):>9}"
        )
    print("  * retenu (validation)")


# --------------------------------------------------------------------------- #


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")  # accents lisibles sous Windows
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    args = parse_args(argv)

    if args.offline:
        if not args.data.is_file():
            logger.error("%s introuvable (mode --offline)", args.data)
            return 1
        data_path = args.data
    else:
        data_path = download_sms_collection(args.data)
    if not args.fr_ar.is_file():
        logger.error("%s introuvable", args.fr_ar)
        return 1

    corpus, dedup_stats = deduplicate(load_sms_collection(data_path))
    split = split_sms(corpus, seed=args.seed)
    blocks = {name: corpus[split == name].reset_index(drop=True) for name in split.cat.categories}
    train, validation, test = blocks["train"], blocks["validation"], blocks["test"]
    for name in ("validation", "test"):
        leaked = template_overlap(train["text"], blocks[name]["text"])
        if leaked:  # garantie de split_sms : ne doit jamais arriver
            raise AssertionError(f"{leaked} gabarits du bloc {name} vus à l'entraînement")
    fr_ar = load_sms_fr_ar(args.fr_ar)

    builders = {}
    if "embeddings_logreg" in args.approaches:
        base = M.APPROACHES["embeddings_logreg"]
        builders["embeddings_logreg"] = M.Approach(
            base.name,
            base.label,
            lambda: M.SentenceEmbedder(args.embedding_model),
            base.classifier,
            base.grid,
            optional=True,
        )
    grids = dict.fromkeys(args.approaches, M.QUICK_GRID) if args.quick else None
    result = M.search(
        (train["text"], train["label"].to_numpy()),
        (validation["text"], validation["label"].to_numpy()),
        approaches=args.approaches,
        grids=grids,
        seed=args.seed,
        builders=builders,
    )
    selected = result.best_approach()

    approaches_report: dict[str, Any] = {}
    for name in args.approaches:
        trial, estimator = result.best[name], result.estimators[name]
        threshold = M.decision_threshold(
            validation["label"].to_numpy(), result.validation_scores[name]
        )
        test_scores = M.scores_of(estimator, test["text"])
        fr_ar_scores = M.scores_of(estimator, fr_ar["text"])
        per_lang = {
            lang: M.evaluate_at_threshold(
                fr_ar.loc[mask, "label"].to_numpy(), fr_ar_scores[mask.to_numpy()], threshold
            )
            for lang, mask in (("fr", fr_ar["lang"] == "fr"), ("ar", fr_ar["lang"] == "ar"))
        }
        per_lang["all"] = M.evaluate_at_threshold(
            fr_ar["label"].to_numpy(), fr_ar_scores, threshold
        )
        encoder = Path(args.embedding_model) if name == "embeddings_logreg" else None
        approaches_report[name] = {
            "approach": name,
            "selected": name == selected.approach,
            "params": trial.params,
            "threshold": round(threshold, 6),
            "validation": trial.validation,
            "test": M.evaluate_at_threshold(test["label"].to_numpy(), test_scores, threshold),
            "fr_ar": per_lang,
            "size_bytes": M.serialized_size(estimator),
            "encoder_size_bytes": M.directory_size(encoder)
            if encoder is not None and encoder.is_dir()
            else None,
            "latency": M.measure_latency(estimator, test["text"].tolist()),
        }

    sms_sha = sha256_file(data_path)
    best = approaches_report[selected.approach]
    model = M.TextModel(
        estimator=result.estimators[selected.approach],
        approach=selected.approach,
        threshold=best["threshold"],
        metadata={
            "model_version": MODEL_VERSION,
            "params": selected.params,
            "trained_at": datetime.now(UTC).isoformat(timespec="seconds"),
            "sms_sha256": sms_sha,
            "seed": args.seed,
            "validation": selected.validation,
        },
    )
    model.save(args.model_out)

    report = {
        "metadata": {
            "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
            "report_version": REPORT_VERSION,
            "python": sys.version.split()[0],
            "pandas": pd.__version__,
            **M.library_versions(),
            "sms_sha256": sms_sha,
            "fr_ar_sha256": sha256_file(args.fr_ar),
            "seed": args.seed,
            "quick": args.quick,
        },
        "dataset": {
            "deduplication": dedup_stats,
            "split": {
                "group": "template_key",
                "stratified_by": "label",
                "fractions": [0.7, 0.15, 0.15],
            },
            "blocks": {
                name: {
                    "rows": len(block),
                    "spam": int(block["label"].sum()),
                    "templates_seen_in_train": 0
                    if name == "train"
                    else template_overlap(train["text"], block["text"]),
                }
                for name, block in blocks.items()
            },
        },
        "fr_ar": {
            "rows": len(fr_ar),
            "by_lang_and_label": {
                f"{lang}/{label}": int(n)
                for (lang, label), n in fr_ar.groupby(["lang", "label"]).size().items()
            },
        },
        "selection": {
            "metric": M.SELECTION_METRIC,
            "tie_break": M.TIE_BREAK_METRIC,
            "evaluated_on": "validation",
            "decision_fpr_on_validation": M.DECISION_FPR,
        },
        "approaches": approaches_report,
        "trials": [t.to_dict() for t in result.trials],
        "selected": {
            "approach": selected.approach,
            "params": selected.params,
            "threshold": best["threshold"],
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
