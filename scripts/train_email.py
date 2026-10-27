"""Score email : règles puis modèle, comparés sur des corpus publics (étape 1.11).

    python scripts/fetch_email_corpora.py      # SpamAssassin (légitime) et Nazario (phishing)
    python scripts/train_email.py              # ou : make train-email
    python scripts/train_email.py --source phishing:phishing_pot:data/raw/emails/phishing_pot

Lit les corpus de data/raw/emails/, analyse chaque email (phishguard.email.parse_eml),
calcule ses features, puis découpe le jeu en 70 / 15 / 15, groupé par domaine
d'expéditeur. Les règles de phishguard.email.score sont mesurées telles quelles ; la
régression logistique et LightGBM sont réglés sur la validation. Le test n'est lu qu'une
fois. Avec un modèle URL (étape 1.6, models/url_v1.joblib s'il existe), ses features
sont ajoutées et la règle « url_model » peut s'appliquer.

Écrit :

- models/email_v1.joblib : le modèle déployé et son seuil (non versionné) ;
- docs/metrics/email_v1.json : effectifs, déclenchement des règles, essais, résultats,
  sans aucun contenu d'email ;
- le bloc généré de docs/email-score.md.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from phishguard.data.integrity import sha256_file
from phishguard.email import EmailTooLargeError, parse_eml
from phishguard.email import model as M
from phishguard.email.corpus import read_corpus
from phishguard.email.score import (
    PHISHING_ABOVE,
    RULES,
    SAFE_BELOW,
    email_features,
    url_model_features,
)
from phishguard.evaluation.splits import BLOCKS, stratified_group_blocks
from phishguard.reporting import (
    fr_int,
    fr_number,
    fr_percent,
    markdown_table,
    update_generated_block,
)

ROOT = Path(__file__).resolve().parents[1]
REPORT_VERSION = "1.0.0"
MODEL_VERSION = "email_v1"
DOC_BLOCK = "train-email"
LABELS = {"ham": 0, "phishing": 1}
DEFAULT_SOURCES = (
    "ham:spamassassin:data/raw/emails/spamassassin",
    "phishing:nazario:data/raw/emails/nazario",
    "phishing:phishing_pot:data/raw/emails/phishing_pot",
)
SET_LABELS = {
    "all": "toutes",
    "without_auth": "sans authentification",
    "all_with_url_model": "toutes + modèle URL",
    "without_auth_with_url_model": "sans authentification + modèle URL",
}

logger = logging.getLogger("train_email")


def _source(value: str) -> tuple[int, str, Path]:
    try:
        label, name, path = value.split(":", 2)
    except ValueError:
        raise argparse.ArgumentTypeError("format attendu : ham|phishing:nom:chemin") from None
    if label not in LABELS or not name:
        raise argparse.ArgumentTypeError("étiquette attendue : ham ou phishing")
    path = Path(path)
    return LABELS[label], name, path if path.is_absolute() else ROOT / path


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    p.add_argument(
        "--source",
        dest="sources",
        type=_source,
        action="append",
        help="ham|phishing:nom:chemin (dossier, mbox ou archive tar) ; répétable",
    )
    p.add_argument("--url-model", type=Path, default=ROOT / "models/url_v1.joblib")
    p.add_argument("--no-url-model", action="store_true")
    p.add_argument("--deploy-feature-set", default=None, help="défaut : sans authentification")
    p.add_argument("--model-out", type=Path, default=ROOT / f"models/{MODEL_VERSION}.joblib")
    p.add_argument("--report", type=Path, default=ROOT / f"docs/metrics/{MODEL_VERSION}.json")
    p.add_argument("--doc", type=Path, default=ROOT / "docs/email-score.md")
    p.add_argument("--quick", action="store_true", help="un seul réglage par modèle")
    p.add_argument("--seed", type=int, default=42)
    args = p.parse_args(argv)
    args.sources = args.sources or [_source(s) for s in DEFAULT_SOURCES]
    if str(args.doc).lower() == "none":
        args.doc = None
    return args


# --------------------------------------------------------------------------- #
# Chargement
# --------------------------------------------------------------------------- #


def load(args: argparse.Namespace, url_model: Any) -> tuple[pd.DataFrame, dict[str, Any]]:
    """Une ligne par email : features, étiquette, source, groupe (aucun contenu)."""
    present = [(label, name, path) for label, name, path in args.sources if path.exists()]
    for label, name, path in args.sources:
        if not path.exists():
            logger.warning("source absente, ignorée : %s (%s)", name, path)
    labels = {name: label for label, name, _ in present}
    emails, stats = read_corpus([(name, path) for _, name, path in present])

    rows, too_large = [], 0
    for item in emails:
        try:
            parsed = parse_eml(item.raw)
        except EmailTooLargeError:
            too_large += 1
            continue
        features = email_features(parsed)
        if url_model is not None:
            features.update(url_model_features(parsed, url_model))
        features.update(
            label=labels[item.source],
            source=item.source,
            group=M.sender_group(parsed, item.sha256),
            parse_failed=any("_failed:" in d for d in parsed.defects),
        )
        rows.append(features)
    info = {
        "read": stats.read,
        "duplicates_removed": stats.duplicates,
        "too_large": stats.too_large + too_large,
        "skipped_files": stats.skipped,
        "by_source": stats.by_source,
    }
    return pd.DataFrame(rows), info


# --------------------------------------------------------------------------- #
# Rendu
# --------------------------------------------------------------------------- #


def _metric_row(name: str, entry: dict[str, Any]) -> list[str]:
    test, point = entry["test"], entry["test_at_threshold"]
    return [
        name,
        fr_number(test["pr_auc"]),
        fr_number(test["recall_at_fpr_1pct"]),
        fr_number(point["recall"]),
        fr_percent(point["fpr"], 2),
        fr_number(point["precision"]),
    ]


def render_markdown(report: dict[str, Any]) -> str:
    rows = report["dataset"]["blocks"]
    lines = [
        (
            f"*Généré par `scripts/train_email.py` le {report['metadata']['generated_at'][:10]} "
            f"(test : {fr_int(rows['test']['rows'])} emails dont "
            f"{fr_int(rows['test']['phishing'])} de phishing"
            f"{', grilles réduites' if report['metadata']['quick'] else ''}). Seuil des modèles "
            "et ligne « règles, seuil réglé » : 1 % de faux positifs sur la validation. "
            "Chiffres complets : "
            f"[`metrics/{MODEL_VERSION}.json`](metrics/{MODEL_VERSION}.json).*"
        ),
        "",
        "### Règles contre modèles (test)",
        "",
    ]
    table = []
    rules = report["rules"]
    for key, label in (
        ("suspicious_or_more", f"Règles, score ≥ {SAFE_BELOW} (suspect ou phishing)"),
        ("phishing", f"Règles, score > {PHISHING_ABOVE} (phishing)"),
        ("tuned", "Règles, seuil réglé"),
    ):
        table.append(_metric_row(label, {"test": rules["test"], "test_at_threshold": rules[key]}))
    for entry in report["models"]:
        label = f"{M.MODEL_SPECS[entry['model']].label}, {SET_LABELS[entry['feature_set']]}"
        if entry["deployed"]:
            label += " **(déployé)**"
        table.append(_metric_row(label, entry))
    lines.append(
        markdown_table(
            ["Approche", "PR-AUC", "R@1%FPR", "Rappel", "FPR", "Précision"],
            table,
        )
    )

    lines += [
        "",
        "### Déclenchement des règles",
        "",
        "Part des emails de chaque classe (tout le jeu) sur lesquels la règle s'applique.",
        "",
    ]
    lines.append(
        markdown_table(
            ["Règle", "Points", "Légitime", "Phishing"],
            [
                [
                    f"`{r['rule']}`",
                    str(r["points"]),
                    fr_percent(r["ham"]) if r["available"] else "—",
                    fr_percent(r["phishing"]) if r["available"] else "—",
                ]
                for r in report["rule_rates"]
            ],
        )
    )

    lines += ["", "### Par source (test, modèle déployé)", ""]
    lines.append(
        markdown_table(
            ["Source", "Classe", "Emails", "Rappel ou FPR"],
            [
                [
                    f"`{s}`",
                    "phishing" if e["label"] == 1 else "légitime",
                    fr_int(e["n"]),
                    fr_percent(e["rate"]),
                ]
                for s, e in report["per_source"].items()
            ],
            ["left", "left", "right", "right"],
        )
    )
    return "\n".join(lines)


# --------------------------------------------------------------------------- #


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")  # accents lisibles sous Windows
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    args = parse_args(argv)

    url_model = None
    if not args.no_url_model and args.url_model.is_file():
        from phishguard.urls.model import UrlModel

        url_model = UrlModel.load(args.url_model)
        logger.info("modèle URL : %s", args.url_model)

    frame, corpus_info = load(args, url_model)
    if frame.empty or frame["label"].nunique() != 2:
        logger.error("il faut des emails légitimes et de phishing (voir fetch_email_corpora.py)")
        return 1

    try:
        blocks_idx = stratified_group_blocks(frame["label"], frame["group"], seed=args.seed)
    except ValueError as exc:  # moins de 20 domaines d'expéditeur, par exemple
        logger.error("split impossible : %s", exc)
        return 1
    blocks = {name: frame[blocks_idx == i].reset_index(drop=True) for i, name in enumerate(BLOCKS)}
    for name, block in blocks.items():
        if block["label"].nunique() != 2:
            logger.error("bloc %s sans les deux classes : corpus trop petit", name)
            return 1
    train, validation, test = blocks["train"], blocks["validation"], blocks["test"]
    y = {name: block["label"].to_numpy() for name, block in blocks.items()}

    # Règles : rien à apprendre, mesurées sur la validation (seuil réglé) et le test.
    rule_val, rule_test = M.rule_scores(validation), M.rule_scores(test)
    rules = {
        "validation": M.ranking_metrics(y["validation"], rule_val),
        "test": M.ranking_metrics(y["test"], rule_test),
        "suspicious_or_more": M.at_threshold(y["test"], rule_test, SAFE_BELOW - 0.5),
        "phishing": M.at_threshold(y["test"], rule_test, PHISHING_ABOVE),
        "tuned": M.at_threshold(
            y["test"], rule_test, M.decision_threshold(y["validation"], rule_val)
        ),
    }

    sets = M.feature_sets(with_url_model=url_model is not None)
    deploy_set = args.deploy_feature_set or (
        "without_auth_with_url_model" if url_model is not None else "without_auth"
    )
    if deploy_set not in sets:
        logger.error("jeu de features inconnu : %s (choix : %s)", deploy_set, ", ".join(sets))
        return 1
    result = M.search(
        train,
        y["train"],
        validation,
        y["validation"],
        sets,
        grids=M.QUICK_GRIDS if args.quick else None,
        seed=args.seed,
    )
    deployed_key = max(
        ((m, s) for (m, s) in result.best if s == deploy_set), key=lambda k: result.best[k].key
    )

    models_report = []
    for key, trial in result.best.items():
        estimator, columns = result.estimators[key], list(sets[key[1]])
        threshold = M.decision_threshold(
            y["validation"], estimator.predict_proba(validation[columns])[:, 1]
        )
        scores = estimator.predict_proba(test[columns])[:, 1]
        models_report.append(
            {
                "model": key[0],
                "feature_set": key[1],
                "deployed": key == deployed_key,
                "params": trial.params,
                "threshold": round(threshold, 6),
                "validation": trial.validation,
                "test": M.ranking_metrics(y["test"], scores),
                "test_at_threshold": M.at_threshold(y["test"], scores, threshold),
            }
        )
    deployed = next(e for e in models_report if e["deployed"])
    deployed_scores = result.estimators[deployed_key].predict_proba(
        test[list(sets[deployed_key[1]])]
    )[:, 1]
    flagged = deployed_scores > deployed["threshold"]
    per_source = {}
    for source in sorted(test["source"].unique()):
        mask = (test["source"] == source).to_numpy()
        per_source[source] = {
            "label": int(test.loc[mask, "label"].iloc[0]),
            "n": int(mask.sum()),
            "rate": round(float(flagged[mask].mean()), 4),
        }

    rule_rates = []
    triggered = [set(M.rule_score(r).triggered) for r in frame.to_dict("records")]
    for rule in RULES:
        fires = np.array([rule.name in t for t in triggered])
        rule_rates.append(
            {
                "rule": rule.name,
                "points": rule.points,
                "available": rule.name != "url_model" or url_model is not None,
                "ham": round(float(fires[frame["label"].to_numpy() == 0].mean()), 4),
                "phishing": round(float(fires[frame["label"].to_numpy() == 1].mean()), 4),
            }
        )

    metadata = {
        "model_version": MODEL_VERSION,
        "trained_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "feature_set": deploy_set,
        "params": deployed["params"],
        "seed": args.seed,
        "url_model_sha256": sha256_file(args.url_model) if url_model is not None else None,
    }
    M.EmailModel(
        estimator=result.estimators[deployed_key],
        feature_names=tuple(sets[deploy_set]),
        threshold=deployed["threshold"],
        metadata=metadata,
    ).save(args.model_out)

    report = {
        "metadata": {
            "generated_at": metadata["trained_at"],
            "report_version": REPORT_VERSION,
            "python": sys.version.split()[0],
            **M.library_versions(),
            "seed": args.seed,
            "quick": args.quick,
            "url_model_sha256": metadata["url_model_sha256"],
        },
        "dataset": {
            "corpus": corpus_info,
            "parse_failed": int(frame["parse_failed"].sum()),
            "split": {"group": "sender registered domain", "fractions": [0.7, 0.15, 0.15]},
            "blocks": {
                name: {
                    "rows": len(block),
                    "phishing": int(block["label"].sum()),
                    "groups": int(block["group"].nunique()),
                    "by_source": {
                        str(k): int(v) for k, v in block["source"].value_counts().items()
                    },
                }
                for name, block in blocks.items()
            },
        },
        "rules": rules,
        "rule_rates": rule_rates,
        "feature_sets": {name: list(cols) for name, cols in sets.items()},
        "models": models_report,
        "per_source": per_source,
        "trials": [t.to_dict() for t in result.trials],
        "deployed": {
            "model": deployed_key[0],
            "feature_set": deploy_set,
            "threshold": deployed["threshold"],
            "sha256": sha256_file(args.model_out),
        },
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", "utf-8")
    if args.doc is not None:
        update_generated_block(args.doc, DOC_BLOCK, render_markdown(report))

    print(f"\n{'':<44}{'PR-AUC':>8}{'rappel':>8}{'FPR':>8}")
    print(
        f"  {'règles (≥ 30)':<42}{rules['test']['pr_auc']:>8.3f}"
        f"{rules['suspicious_or_more']['recall'] or 0:>8.3f}{rules['suspicious_or_more']['fpr'] or 0:>8.3f}"
    )
    for entry in models_report:
        point = entry["test_at_threshold"]
        name = f"{entry['model']} / {entry['feature_set']}" + (" *" if entry["deployed"] else "")
        print(
            f"  {name:<42}{entry['test']['pr_auc']:>8.3f}{point['recall'] or 0:>8.3f}{point['fpr'] or 0:>8.3f}"
        )
    print(f"\nModèle : {args.model_out}\nRapport : {args.report}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
