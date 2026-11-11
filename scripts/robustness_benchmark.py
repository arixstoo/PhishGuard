"""Banc d'essai de robustesse des modèles URL et SMS (étape 3.7).

    python scripts/robustness_benchmark.py                    # ou : make robustness
    python scripts/robustness_benchmark.py --label normalization --description "…"

Applique chaque perturbation de phishguard.adversarial.perturb (étape 3.6) aux blocs de
test, phishing **et** légitime, et mesure au seuil de décision de chaque modèle le rappel
avant / après (Δ rappel) et le taux de faux positifs avant / après (Δ FPR) :

- URL : bloc de test de data/processed/urls_split.parquet, modèle models/url_v1.joblib,
  seuil de décision choisi sur la validation à l'étape 1.7 (docs/metrics/url_v1_test.json) ;
- SMS : bloc de test de la SMS Spam Collection (même dédoublonnage et même split groupé
  par gabarit que scripts/train_text.py), modèle models/text_v1.joblib et son seuil ;
- SMS français / arabe (datasets/sms_fr_ar.csv) : hors distribution, 100 messages, à lire
  avec ses intervalles de confiance.

Rien n'est réglé sur le test. Écrit, sans aucun texte ni URL :

- docs/metrics/robustness_<label>.json : chiffres complets du passage ;
- le bloc généré « robustness-<label> » de docs/robustness-report.md, et le bloc
  « robustness-comparison » qui compare tous les passages présents dans docs/metrics/.
"""

from __future__ import annotations

import argparse
import json
import logging
import re
import sys
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import numpy as np

from phishguard.adversarial import perturb as P
from phishguard.adversarial.benchmark import evaluate_perturbations, worst_perturbation
from phishguard.data.integrity import sha256_file
from phishguard.data.sms import deduplicate, load_sms_collection, load_sms_fr_ar, split_sms
from phishguard.data.split import read_split_blocks
from phishguard.reporting import (
    fr_int,
    fr_number,
    fr_percent,
    markdown_table,
    update_generated_block,
)
from phishguard.security.normalize import host_script_alert
from phishguard.text.models import TextModel
from phishguard.urls.features import parse_url
from phishguard.urls.model import UrlModel

ROOT = Path(__file__).resolve().parents[1]
REPORT_VERSION = "1.0.0"
DEFAULT_URL_THRESHOLD = "fpr_0_5pct"
# Ordre des passages dans la comparaison : avant défenses, puis chaque défense. Les
# autres passages (ablations) n'apparaissent que dans le résumé.
RUN_ORDER = ("baseline", "normalization", "adversarial")
RUN_LABELS = {
    "baseline": "modèle d'origine",
    "normalization": "normalisation seule",
    "adversarial": "normalisation + entraînement adversarial",
    "adversarial_phishing_only": "ablation : augmentation du phishing seul",
}
BLOCK_LABELS = {
    "url": "URL (test)",
    "sms": "SMS (test UCI, anglais)",
    "sms_fr_ar": "SMS français / arabe (hors distribution)",
}

# Classe positive de chaque bloc : la SMS Spam Collection étiquette du spam, dont le
# smishing n'est qu'une partie.
POSITIVE_LABELS = {"url": "URLs de phishing", "sms": "spams", "sms_fr_ar": "messages frauduleux"}

logger = logging.getLogger("robustness_benchmark")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    p.add_argument("--label", default="baseline", help="nom du passage (baseline, normalization…)")
    p.add_argument(
        "--description",
        default="modèles d'origine, avant toute défense",
        help="ce qui distingue ce passage (repris dans le rapport)",
    )
    p.add_argument("--url-dataset", type=Path, default=ROOT / "data/processed/urls_split.parquet")
    p.add_argument("--url-model", type=Path, default=ROOT / "models/url_v1.joblib")
    p.add_argument(
        "--url-evaluation",
        type=Path,
        default=ROOT / "docs/metrics/url_v1_test.json",
        help="rapport de l'étape 1.7, qui donne le nom du seuil de décision",
    )
    p.add_argument("--sms-data", type=Path, default=ROOT / "data/raw/SMSSpamCollection")
    p.add_argument("--fr-ar", type=Path, default=ROOT / "datasets/sms_fr_ar.csv")
    p.add_argument("--text-model", type=Path, default=ROOT / "models/text_v1.joblib")
    p.add_argument("--split-seed", type=int, default=42, help="graine du split SMS (train_text)")
    p.add_argument("--seed", type=int, default=0, help="graine des perturbations")
    p.add_argument("--metrics-dir", type=Path, default=ROOT / "docs/metrics")
    p.add_argument("--doc", type=Path, default=ROOT / "docs/robustness-report.md")
    p.add_argument(
        "--skip", nargs="*", default=[], choices=list(BLOCK_LABELS), help="blocs à ne pas évaluer"
    )
    p.add_argument(
        "--url-host-rule",
        action="store_true",
        help="règle d'alerte de l'étape 3.8 : un hôte qui imite des lettres latines est signalé",
    )
    args = p.parse_args(argv)
    if not re.fullmatch(r"[a-z0-9][a-z0-9_]*", args.label):
        p.error("--label : minuscules, chiffres et « _ » seulement")
    if str(args.doc).lower() == "none":
        args.doc = None
    return args


# --------------------------------------------------------------------------- #
# Blocs évalués
# --------------------------------------------------------------------------- #


def url_threshold_name(path: Path) -> str:
    """Nom du seuil de décision retenu à l'étape 1.7, ou celui par défaut."""
    try:
        return json.loads(path.read_text(encoding="utf-8"))["decision"]["name"]
    except (OSError, KeyError, ValueError):
        logger.warning("%s illisible : seuil %s", path, DEFAULT_URL_THRESHOLD)
        return DEFAULT_URL_THRESHOLD


def with_host_rule(model: UrlModel) -> Callable[[list[str]], np.ndarray]:
    """Score du modèle, porté à 1 quand l'hôte imite des lettres latines (étape 3.8)."""

    def score(urls: list[str]) -> np.ndarray:
        scores = np.asarray(model.score(urls), dtype=float)
        alerts = np.array([host_script_alert(parse_url(u).host) is not None for u in urls])
        return np.where(alerts, 1.0, scores)

    return score


def _adversarial_info(metadata: Any) -> dict[str, Any] | None:
    """Réglages de l'entraînement adversarial (étape 3.9), comptes seulement."""
    info = metadata.get("adversarial") if hasattr(metadata, "get") else None
    if not info:
        return None
    keys = ("generator_version", "classes", "copies", "seed", "added")
    return {k: info[k] for k in keys if k in info}


def url_block(args: argparse.Namespace) -> dict[str, Any]:
    model = UrlModel.load(args.url_model)
    name = url_threshold_name(args.url_evaluation)
    test = read_split_blocks(args.url_dataset, ("test",), ["url", "label"])["test"]
    logger.info("URL : %d échantillons de test, seuil %s", len(test), name)
    result = evaluate_perturbations(
        with_host_rule(model) if args.url_host_rule else (lambda urls: model.score(urls)),
        test["url"].tolist(),
        test["label"].to_numpy(),
        model.thresholds[name],
        P.perturbations_for("url"),
        seed=args.seed,
    )
    result["threshold_name"] = name
    result["model"] = {
        "version": model.metadata.get("model_version", "unknown"),
        "sha256": sha256_file(args.url_model),
        "normalization": model.metadata.get("normalization"),
        "adversarial": _adversarial_info(model.metadata),
    }
    result["host_rule"] = bool(args.url_host_rule)
    result["dataset_sha256"] = sha256_file(args.url_dataset)
    return result


def text_blocks(args: argparse.Namespace, skip: set[str]) -> dict[str, dict[str, Any]]:
    model = TextModel.load(args.text_model)
    model_info = {
        "version": model.metadata.get("model_version", "unknown"),
        "sha256": sha256_file(args.text_model),
        "approach": model.approach,
        "normalization": model.metadata.get("normalization"),
        "adversarial": _adversarial_info(model.metadata),
    }
    blocks: dict[str, tuple[list[str], np.ndarray, str]] = {}
    if "sms" not in skip:
        corpus, _ = deduplicate(load_sms_collection(args.sms_data))
        test = corpus[split_sms(corpus, seed=args.split_seed) == "test"]
        blocks["sms"] = (
            test["text"].tolist(),
            test["label"].to_numpy(),
            sha256_file(args.sms_data),
        )
    if "sms_fr_ar" not in skip:
        fr_ar = load_sms_fr_ar(args.fr_ar)
        blocks["sms_fr_ar"] = (
            fr_ar["text"].tolist(),
            fr_ar["label"].to_numpy(),
            sha256_file(args.fr_ar),
        )
    results = {}
    for name, (texts, labels, sha) in blocks.items():
        logger.info("%s : %d échantillons", name, len(texts))
        result = evaluate_perturbations(
            lambda t: model.score(t),
            texts,
            labels,
            model.threshold,
            P.perturbations_for("text"),
            seed=args.seed,
        )
        result["threshold_name"] = "decision"
        result["model"] = model_info
        result["dataset_sha256"] = sha
        results[name] = result
    return results


# --------------------------------------------------------------------------- #
# Rendu
# --------------------------------------------------------------------------- #


def _ci(entry: dict[str, Any], digits: int = 1) -> str:
    if entry["rate"] is None:
        return "n/d"
    return (
        f"{fr_percent(entry['rate'], digits)} "
        f"[{fr_number(entry['low'] * 100, digits)}–{fr_percent(entry['high'], digits)}]"
    )


def _signed_points(delta: float | None, digits: int = 1) -> str:
    """Écart de deux taux en points de pourcentage, signé : ``-12,3 pts``."""
    if delta is None:
        return "n/d"
    value = delta * 100
    sign = "+" if value > 0 else ("−" if value < 0 else "±")
    return f"{sign}{fr_number(abs(value), digits)} pts"


def render_block(name: str, result: dict[str, Any]) -> str:
    base = result["baseline"]
    rows = [
        [
            "*aucune*",
            "",
            "",
            _ci(base["recall"]),
            "",
            _ci(base["fpr"], 2),
            "",
            "",
        ]
    ]
    for r in result["perturbations"]:
        rows.append(
            [
                f"`{r['perturbation']}`",
                r["technique"],
                fr_percent(r["changed"]["phishing"]["rate"], 0),
                _ci(r["recall"]),
                f"**{_signed_points(r['delta_recall'])}**",
                _ci(r["fpr"], 2) + (" ¹" if r.get("creates_lookalike") else ""),
                _signed_points(r["delta_fpr"], 2),
                fr_int(r["evaded"]),
            ]
        )
    samples = result["samples"]
    lines = [
        f"#### {BLOCK_LABELS.get(name, name)}",
        "",
        (
            f"Modèle `{result['model']['version']}` (`{result['model']['sha256'][:12]}`), seuil "
            f"`{result['threshold_name']}` (score > {fr_number(result['threshold'], 4)}), "
            f"{fr_int(samples['phishing'])} {POSITIVE_LABELS.get(name, 'positifs')} et "
            f"{fr_int(samples['legitimate'])} légitimes."
        ),
        "",
        markdown_table(
            [
                "Perturbation",
                "Technique",
                "Phishing modifié",
                "Rappel",
                "Δ rappel",
                "FPR",
                "Δ FPR",
                "Échappés",
            ],
            rows,
            ["left", "left", "right", "right", "right", "right", "right", "right"],
        ),
    ]
    if any(r.get("creates_lookalike") for r in result["perturbations"]):
        lines += [
            "",
            (
                "¹ La perturbation fabrique une imitation : une URL légitime réécrite en "
                "homoglyphes désigne un autre domaine, et la signaler est juste. Ce FPR ne "
                "mesure pas de fausses alertes."
            ),
        ]
    if result.get("host_rule"):
        lines += [
            "",
            (
                "Règle d'alerte de l'étape 3.8 appliquée : un hôte qui imite des lettres "
                "latines est signalé quel que soit le score du modèle."
            ),
        ]
    worst = worst_perturbation(result)
    if worst is not None and worst["delta_recall"] < 0:
        lines += [
            "",
            (
                f"Pire perturbation : `{worst['perturbation']}` ({worst['technique']}), "
                f"{_signed_points(worst['delta_recall'])} de rappel ; "
                f"{fr_int(worst['evaded'])} phishing détectés sans perturbation passent."
            ),
        ]
    return "\n".join(lines)


def render_run(report: dict[str, Any]) -> str:
    meta = report["metadata"]
    lines = [
        (
            f"*Généré par `scripts/robustness_benchmark.py` le {meta['generated_at'][:10]}, "
            f"passage `{meta['label']}` : {meta['description']}. Graine des perturbations : "
            f"{meta['seed']}. Intervalles de Wilson à 95 % entre crochets ; « Échappés » : "
            "phishing détecté sans perturbation, manqué avec. Chiffres complets : "
            f"[`metrics/robustness_{meta['label']}.json`](metrics/robustness_{meta['label']}.json).*"
        ),
    ]
    for name, result in report["blocks"].items():
        lines += ["", render_block(name, result)]
    return "\n".join(lines)


def load_runs(metrics_dir: Path) -> dict[str, dict[str, Any]]:
    """Passages enregistrés, dans l'ordre de :data:`RUN_ORDER` puis alphabétique."""
    runs = {}
    for path in sorted(metrics_dir.glob("robustness_*.json")):
        report = json.loads(path.read_text(encoding="utf-8"))
        runs[report["metadata"]["label"]] = report
    order = {label: i for i, label in enumerate(RUN_ORDER)}
    return dict(sorted(runs.items(), key=lambda kv: (order.get(kv[0], len(order)), kv[0])))


def render_comparison(runs: dict[str, dict[str, Any]]) -> str:
    """Rappel sous chaque perturbation, un passage par colonne, FPR à côté.

    Seuls les passages de :data:`RUN_ORDER` y figurent ; les ablations sont dans le résumé.
    """
    runs = {label: run for label, run in runs.items() if label in RUN_ORDER} or runs
    labels = list(runs)
    lines = [
        (
            "*Généré par `scripts/robustness_benchmark.py` à partir de "
            + ", ".join(f"`robustness_{label}.json`" for label in labels)
            + ". Rappel et FPR au seuil de décision de chaque modèle.*"
        )
    ]
    blocks = [b for b in BLOCK_LABELS if any(b in r["blocks"] for r in runs.values())]
    for block in blocks:
        names: list[str] = []
        for run in runs.values():
            for row in run["blocks"].get(block, {}).get("perturbations", []):
                if row["perturbation"] not in names:
                    names.append(row["perturbation"])
        table = []
        for name in [None, *names]:
            cells = ["*aucune*" if name is None else f"`{name}`"]
            for label in labels:
                result = runs[label]["blocks"].get(block)
                if result is None:
                    cells += ["n/d", "n/d"]
                    continue
                if name is None:
                    entry = result["baseline"]
                else:
                    entry = next(
                        (r for r in result["perturbations"] if r["perturbation"] == name), None
                    )
                if entry is None:
                    cells += ["n/d", "n/d"]
                else:
                    cells += [
                        fr_percent(entry["recall"]["rate"]),
                        fr_percent(entry["fpr"]["rate"], 2),
                    ]
            table.append(cells)
        headers = ["Perturbation"]
        for label in labels:
            headers += [f"Rappel `{label}`", f"FPR `{label}`"]
        lines += [
            "",
            f"#### {BLOCK_LABELS[block]}",
            "",
            markdown_table(headers, table, ["left"] + ["right"] * (len(headers) - 1)),
        ]
    return "\n".join(lines)


def summarize(result: dict[str, Any]) -> dict[str, Any]:
    """Une ligne du résumé : propre, moyenne et pire cas sous perturbation.

    Les perturbations qui fabriquent une imitation (``creates_lookalike``) sont exclues
    du FPR sous perturbation : leur légitime perturbé n'est plus légitime.
    """
    rows = result["perturbations"]
    recalls = [r for r in rows if r["recall"]["rate"] is not None]
    fprs = [r for r in rows if r["fpr"]["rate"] is not None and not r.get("creates_lookalike")]
    worst = min(recalls, key=lambda r: r["recall"]["rate"], default=None)
    worst_fpr = max(fprs, key=lambda r: r["fpr"]["rate"], default=None)
    return {
        "clean_recall": result["baseline"]["recall"]["rate"],
        "clean_fpr": result["baseline"]["fpr"]["rate"],
        "mean_recall": float(np.mean([r["recall"]["rate"] for r in recalls])) if recalls else None,
        "worst_recall": None if worst is None else worst["recall"]["rate"],
        "worst_recall_perturbation": None if worst is None else worst["perturbation"],
        "max_fpr": None if worst_fpr is None else worst_fpr["fpr"]["rate"],
        "max_fpr_perturbation": None if worst_fpr is None else worst_fpr["perturbation"],
    }


def render_summary(runs: dict[str, dict[str, Any]]) -> str:
    """Un passage par ligne : l'effet de chaque défense en un coup d'œil."""
    lines = [
        (
            "*Généré par `scripts/robustness_benchmark.py`. « Sous perturbation » : moyenne "
            "et pire cas sur toutes les perturbations du bloc ; le FPR sous perturbation "
            "exclut celles qui fabriquent une imitation (note ¹).*"
        )
    ]
    blocks = [b for b in BLOCK_LABELS if any(b in r["blocks"] for r in runs.values())]
    for block in blocks:
        table = []
        for label, run in runs.items():
            result = run["blocks"].get(block)
            if result is None:
                continue
            s = summarize(result)
            table.append(
                [
                    f"`{label}` ({RUN_LABELS.get(label, run['metadata']['description'])})",
                    fr_percent(s["clean_recall"]),
                    fr_percent(s["clean_fpr"], 2),
                    "n/d" if s["mean_recall"] is None else fr_percent(s["mean_recall"]),
                    "n/d"
                    if s["worst_recall"] is None
                    else f"{fr_percent(s['worst_recall'])} (`{s['worst_recall_perturbation']}`)",
                    "n/d"
                    if s["max_fpr"] is None
                    else f"{fr_percent(s['max_fpr'], 2)} (`{s['max_fpr_perturbation']}`)",
                ]
            )
        lines += [
            "",
            f"#### {BLOCK_LABELS[block]}",
            "",
            markdown_table(
                [
                    "Passage",
                    "Rappel propre",
                    "FPR propre",
                    "Rappel moyen sous perturbation",
                    "Pire rappel",
                    "Pire FPR sous perturbation",
                ],
                table,
                ["left", "right", "right", "right", "right", "right"],
            ),
        ]
    return "\n".join(lines)


def print_summary(report: dict[str, Any]) -> None:
    for name, result in report["blocks"].items():
        base = result["baseline"]
        print(
            f"\n{BLOCK_LABELS.get(name, name)} : rappel {fr_percent(base['recall']['rate'])}, "
            f"FPR {fr_percent(base['fpr']['rate'], 2)}"
        )
        for r in result["perturbations"]:
            print(
                f"  {r['perturbation']:<16} rappel {fr_percent(r['recall']['rate']):>8} "
                f"({_signed_points(r['delta_recall']):>11})  FPR "
                f"{fr_percent(r['fpr']['rate'], 2):>8} ({_signed_points(r['delta_fpr'], 2)})"
            )


# --------------------------------------------------------------------------- #


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")  # accents lisibles sous Windows
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    args = parse_args(argv)
    skip = set(args.skip)

    required = []
    if "url" not in skip:
        required += [(args.url_dataset, "split_dataset.py"), (args.url_model, "train_url.py")]
    if not {"sms", "sms_fr_ar"} <= skip:
        required.append((args.text_model, "train_text.py"))
        if "sms" not in skip:
            required.append((args.sms_data, "train_text.py"))
        if "sms_fr_ar" not in skip:
            required.append((args.fr_ar, "train_text.py"))
    for path, hint in required:
        if not path.is_file():
            logger.error("%s introuvable : lancez d'abord scripts/%s", path, hint)
            return 1

    blocks: dict[str, Any] = {}
    if "url" not in skip:
        blocks["url"] = url_block(args)
    if not {"sms", "sms_fr_ar"} <= skip:
        blocks.update(text_blocks(args, skip))

    report = {
        "report_version": REPORT_VERSION,
        "metadata": {
            "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
            "label": args.label,
            "description": args.description,
            "seed": args.seed,
            "perturbations": {
                name: {"technique": p.technique, "vector": p.vector, "description": p.description}
                for name, p in P.PERTURBATIONS.items()
            },
        },
        "blocks": blocks,
    }
    args.metrics_dir.mkdir(parents=True, exist_ok=True)
    out = args.metrics_dir / f"robustness_{args.label}.json"
    out.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    logger.info("rapport écrit : %s", out)

    if args.doc is not None:
        update_generated_block(
            args.doc, f"robustness-{args.label.replace('_', '-')}", render_run(report)
        )
        runs = load_runs(args.metrics_dir)
        update_generated_block(args.doc, "robustness-comparison", render_comparison(runs))
        update_generated_block(args.doc, "robustness-summary", render_summary(runs))
        logger.info("document mis à jour : %s", args.doc)
    print_summary(report)
    return 0


if __name__ == "__main__":
    sys.exit(main())
