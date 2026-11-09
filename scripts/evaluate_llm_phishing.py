"""Phishing rédigé par un LLM : dégradation du modèle SMS et ce qui la compense (étape 3.10).

    python scripts/evaluate_llm_phishing.py            # ou : make llm-phishing

Lit le jeu défensif et local data/llm_phishing/messages.jsonl (non versionné, protocole :
docs/llm-phishing.md), le valide (domaines réservés, aucune coordonnée réelle, deux
familles de même taille), puis mesure pour chaque modèle SMS, au seuil de décision réglé
sur la validation :

- rappel et FPR sur les messages LLM, comparés au bloc de test de la SMS Spam Collection
  (même dédoublonnage et même split que scripts/train_text.py) : la dégradation ;
- le détail par canal (SMS, email) et par famille de leurre ou de courrier ;
- ce qui compense, sans regarder les étiquettes pour le régler :
  - la **règle de leurre** fixée à l'avance : lien **et** demande d'information
    (code ou compte), les constats que le pipeline relie déjà à ATT&CK T1598 ;
  - l'**ensemble** modèle + règle (signalé si l'un ou l'autre signale) ;
  - un **scénario d'infrastructure** : la fusion du module 2 avec un signal RDAP
    « domaine de moins de 7 jours » pour les liens du phishing. Ce n'est pas une
    mesure : les liens du jeu sont sur des domaines réservés, sans âge réel.

Écrit, sans aucun texte de message :

- docs/metrics/llm_phishing.json ;
- le bloc généré « llm-phishing » de docs/robustness-report.md.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from phishguard.adversarial.benchmark import rate
from phishguard.analysis import TextAnalyzer
from phishguard.data.integrity import sha256_file
from phishguard.data.llm_phishing import load_llm_messages
from phishguard.data.sms import deduplicate, load_sms_collection, split_sms
from phishguard.enrichers.base import Signal, SignalStatus
from phishguard.enrichers.rdap import risk_from_age
from phishguard.evaluation.metrics import binary_report
from phishguard.explain.text import message_categories
from phishguard.fusion.score import fuse
from phishguard.reporting import (
    fr_int,
    fr_number,
    fr_percent,
    markdown_table,
    update_generated_block,
)
from phishguard.text.models import TextModel

ROOT = Path(__file__).resolve().parents[1]
REPORT_VERSION = "1.0.0"
DOC_BLOCK = "llm-phishing"
# Âge du domaine du scénario d'infrastructure : sous 7 jours, risque RDAP maximal.
SCENARIO_DOMAIN_AGE_DAYS = 3
FLAGGED_VERDICTS = ("suspicious", "phishing")

logger = logging.getLogger("evaluate_llm_phishing")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    p.add_argument("--data", type=Path, default=ROOT / "data/llm_phishing/messages.jsonl")
    p.add_argument(
        "--models",
        nargs="+",
        type=Path,
        default=[ROOT / "models/text_v1.joblib", ROOT / "models/text_v2.joblib"],
        help="modèles SMS ; la calibration est cherchée à côté (<nom>_calibration.json)",
    )
    p.add_argument(
        "--control",
        type=Path,
        default=ROOT / "data/llm_phishing/legit_links_control.jsonl",
        help="jeu de contrôle, légitime seulement (« none » pour l'ignorer)",
    )
    p.add_argument("--sms-data", type=Path, default=ROOT / "data/raw/SMSSpamCollection")
    p.add_argument("--split-seed", type=int, default=42, help="graine du split SMS (train_text)")
    p.add_argument("--report", type=Path, default=ROOT / "docs/metrics/llm_phishing.json")
    p.add_argument(
        "--doc",
        type=Path,
        default=ROOT / "docs/robustness-report.md",
        help="document dont le bloc généré est réécrit (« none » pour ne rien écrire)",
    )
    args = p.parse_args(argv)
    if str(args.doc).lower() == "none":
        args.doc = None
    if str(args.control).lower() == "none":
        args.control = None
    return args


# --------------------------------------------------------------------------- #
# Mesures
# --------------------------------------------------------------------------- #


def lure_rule(categories: Sequence[str]) -> bool:
    """Règle fixée avant la mesure : un lien **et** une demande de code ou de compte.

    Ce sont les constats que :class:`~phishguard.analysis.TextAnalyzer` relie déjà à
    T1598 (``has_link`` et ``requests_information``) : la règle n'est pas réglée sur
    ce jeu.
    """
    present = set(categories)
    return "link" in present and bool({"code", "account"} & present)


def detection(flagged: np.ndarray, labels: np.ndarray) -> dict[str, Any]:
    """Rappel sur le phishing, FPR sur le légitime, avec leurs intervalles de Wilson."""
    flagged, labels = np.asarray(flagged, dtype=bool), np.asarray(labels).astype(int)
    return {"recall": rate(flagged[labels == 1]), "fpr": rate(flagged[labels == 0])}


def by_group(flagged: np.ndarray, frame: pd.DataFrame, column: str) -> dict[str, Any]:
    out = {}
    for value, index in frame.groupby(column).groups.items():
        rows = frame.index.get_indexer(index)
        out[str(value)] = {
            "label": int(frame["label"].iloc[rows[0]]),
            **detection(flagged[rows], frame["label"].to_numpy()[rows]),
        }
    return out


@dataclass(frozen=True)
class Block:
    """Messages évalués et la règle de leurre déjà appliquée à chacun."""

    frame: pd.DataFrame
    rule: np.ndarray

    @property
    def texts(self) -> list[str]:
        return self.frame["text"].tolist()

    @property
    def labels(self) -> np.ndarray:
        return self.frame["label"].to_numpy()


def make_block(frame: pd.DataFrame) -> Block:
    return Block(frame, np.array([lure_rule(message_categories(t)) for t in frame["text"]]))


def separation(labels: np.ndarray, scores: np.ndarray) -> dict[str, float]:
    """PR-AUC et ROC-AUC : le modèle sépare-t-il les classes, quel que soit le seuil ?"""
    report = binary_report(labels, scores)
    return {"pr_auc": report["pr_auc"], "roc_auc": report["roc_auc"]}


def evaluate_model(
    path: Path, llm: Block, sms_test: Block | None, control: Block | None
) -> dict[str, Any]:
    model = TextModel.load(path)
    calibration = path.with_name(f"{path.stem}_calibration.json")
    analyzer = TextAnalyzer(model, calibrator=_calibrator(calibration), explain=False)
    scores = model.score(llm.texts)
    flagged = scores > model.threshold
    result: dict[str, Any] = {
        "version": model.metadata.get("model_version", "unknown"),
        "sha256": sha256_file(path),
        "threshold": float(model.threshold),
        "calibrated": analyzer.calibrator is not None,
        "llm": detection(flagged, llm.labels),
        "llm_separation": separation(llm.labels, scores),
        "by_channel": by_group(flagged, llm.frame, "channel"),
        "by_family": by_group(flagged, llm.frame, "family"),
        "ensemble": detection(flagged | llm.rule, llm.labels),
    }
    if sms_test is not None:
        sms_scores = model.score(sms_test.texts)
        sms_flagged = sms_scores > model.threshold
        result["sms_test"] = detection(sms_flagged, sms_test.labels)
        result["sms_separation"] = separation(sms_test.labels, sms_scores)
        result["ensemble_sms_test"] = detection(sms_flagged | sms_test.rule, sms_test.labels)
        result["degradation"] = {
            "recall": _delta(result["llm"]["recall"], result["sms_test"]["recall"]),
            "fpr": _delta(result["llm"]["fpr"], result["sms_test"]["fpr"]),
        }
    result["scenario"] = infrastructure_scenario(analyzer, llm.frame)
    if control is not None:
        control_flagged = model.score(control.texts) > model.threshold
        verdicts = np.array(
            [analyzer.analyze(t).verdict in FLAGGED_VERDICTS for t in control.texts]
        )
        result["control"] = {
            "model": rate(control_flagged),
            "ensemble": rate(control_flagged | control.rule),
            "verdict": rate(verdicts),
        }
    return result


def _calibrator(path: Path):
    from phishguard.fusion.calibration import ScoreCalibrator

    if path.is_file():
        return ScoreCalibrator.load(path)
    logger.warning("%s introuvable : marge ramenée par une sigmoïde au seuil", path.name)
    return None


def _delta(after: dict[str, Any], before: dict[str, Any]) -> float | None:
    if after["rate"] is None or before["rate"] is None:
        return None
    return after["rate"] - before["rate"]


def infrastructure_scenario(analyzer: TextAnalyzer, llm: pd.DataFrame) -> dict[str, Any]:
    """Verdicts de l'analyse, puis avec un signal « domaine récent » sur le lien.

    Seul le phishing **avec un lien** reçoit le signal (un domaine d'attaquant de
    :data:`SCENARIO_DOMAIN_AGE_DAYS` jours). Le légitime garde ses verdicts : ses liens
    sont supposés sur des domaines anciens, de risque RDAP nul. C'est un scénario, pas
    une mesure : il montre ce que la fusion ferait du signal, pas sa fréquence réelle.
    """
    young = Signal(
        source="rdap",
        status=SignalStatus.OK,
        risk=risk_from_age(SCENARIO_DOMAIN_AGE_DAYS),
    )
    before, after, has_link = [], [], []
    for text, label in zip(llm["text"], llm["label"], strict=True):
        analysis = analyzer.analyze(text, channel="sms")
        link = "link" in analysis.categories
        has_link.append(link)
        before.append(analysis.verdict in FLAGGED_VERDICTS)
        if label == 1 and link:
            fused = fuse(analysis.model_probability, [young], config=analyzer.config)
            after.append(fused.verdict in FLAGGED_VERDICTS)
        else:
            after.append(before[-1])
    labels = llm["label"].to_numpy()
    has_link = np.asarray(has_link)
    missed_without_link = (labels == 1) & ~np.asarray(before) & ~has_link
    return {
        "domain_age_days": SCENARIO_DOMAIN_AGE_DAYS,
        "rdap_risk": young.risk,
        "verdicts": detection(np.asarray(before), labels),
        "with_young_domain": detection(np.asarray(after), labels),
        "phishing_with_link": rate(has_link[labels == 1]),
        "missed_without_link": int(missed_without_link.sum()),
    }


def categories_report(llm: pd.DataFrame, categories: list[tuple[str, ...]]) -> dict[str, Any]:
    labels = llm["label"].to_numpy()
    names = ("urgency", "money", "link", "code", "account")
    present = {c: np.array([c in cats for cats in categories]) for c in names}
    return {
        c: {"phishing": rate(flag[labels == 1]), "legitimate": rate(flag[labels == 0])}
        for c, flag in present.items()
    }


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


def _points(delta: float | None) -> str:
    if delta is None:
        return "n/d"
    value = delta * 100
    sign = "+" if value > 0 else ("−" if value < 0 else "±")
    return f"{sign}{fr_number(abs(value), 1)} pts"


CATEGORY_LABELS = {
    "urgency": "urgence",
    "money": "argent",
    "link": "lien",
    "code": "code",
    "account": "compte",
}


def render_markdown(report: dict[str, Any]) -> str:
    meta = report["metadata"]
    data = meta["dataset"]
    models = report["models"]
    names = list(models)
    lines = [
        (
            f"*Généré par `scripts/evaluate_llm_phishing.py` le {meta['generated_at'][:10]}, "
            f"jeu `{data['sha256'][:12]}` : {fr_int(data['phishing'])} phishing et "
            f"{fr_int(data['legitimate'])} légitimes, {fr_int(data['families'])} familles, "
            f"{fr_int(data['by_channel'].get('sms', 0))} SMS et "
            f"{fr_int(data['by_channel'].get('email', 0))} emails. Seuil de décision de "
            "chaque modèle, intervalles de Wilson à 95 %. Chiffres complets : "
            "[`metrics/llm_phishing.json`](metrics/llm_phishing.json).*"
        ),
        "",
        "#### Dégradation",
        "",
    ]
    rows = []
    for entry in models.values():
        sms = entry.get("sms_test")
        degradation = entry.get("degradation", {})
        rows.append(
            [
                f"`{entry['version']}`",
                _ci(sms["recall"]) if sms else "n/d",
                _ci(entry["llm"]["recall"]),
                _points(degradation.get("recall")),
                _ci(sms["fpr"], 2) if sms else "n/d",
                _ci(entry["llm"]["fpr"], 2),
                f"**{_points(degradation.get('fpr'))}**",
                f"{fr_number(entry['sms_separation']['roc_auc'])} → "
                f"{fr_number(entry['llm_separation']['roc_auc'])}"
                if sms
                else fr_number(entry["llm_separation"]["roc_auc"]),
            ]
        )
    lines.append(
        markdown_table(
            [
                "Modèle",
                "Rappel SMS (UCI)",
                "Rappel LLM",
                "Δ rappel",
                "FPR SMS (UCI)",
                "FPR LLM",
                "Δ FPR",
                "ROC-AUC SMS → LLM",
            ],
            rows,
            ["left"] + ["right"] * 7,
        )
    )

    lines += ["", "#### Par canal", ""]
    rows = [
        [f"`{entry['version']}`", channel, _ci(values["recall"]), _ci(values["fpr"], 2)]
        for entry in models.values()
        for channel, values in entry["by_channel"].items()
    ]
    lines.append(
        markdown_table(
            ["Modèle", "Canal", "Rappel", "FPR"], rows, ["left", "left", "right", "right"]
        )
    )

    lines += [
        "",
        "#### Par famille",
        "",
        "Rappel pour une famille de phishing, FPR pour une famille légitime (10 messages chacune).",
        "",
    ]
    families = models[names[0]]["by_family"]
    rows = []
    for family in sorted(families, key=lambda f: (-families[f]["label"], f)):
        phishing = families[family]["label"] == 1
        cells = [f"`{family}`", "phishing" if phishing else "légitime"]
        for name in names:
            values = models[name]["by_family"][family]
            cells.append(fr_percent(values["recall" if phishing else "fpr"]["rate"], 0))
        rows.append(cells)
    lines.append(
        markdown_table(
            ["Famille", "Classe", *(f"`{models[n]['version']}`" for n in names)],
            rows,
            ["left", "left"] + ["right"] * len(names),
        )
    )

    lines += [
        "",
        "#### Catégories de leurre",
        "",
        "Part des messages où chaque catégorie est repérée (`explain.text.message_categories`).",
        "",
    ]
    control = report.get("control")
    rows = [
        [
            CATEGORY_LABELS[c],
            fr_percent(v["phishing"]["rate"], 0),
            fr_percent(v["legitimate"]["rate"], 0),
            fr_percent(control["categories"][c]["rate"], 0) if control else "n/d",
        ]
        for c, v in report["categories"].items()
    ]
    lines.append(
        markdown_table(
            ["Catégorie", "Phishing", "Légitime", "Contrôle (légitime avec lien)"],
            rows,
            ["left", "right", "right", "right"],
        )
    )

    rule = report["rule"]
    lines += [
        "",
        "#### Ce qui compense",
        "",
        (
            "Règle de leurre fixée avant la mesure : **lien et demande de code ou de compte**. "
            "Ensemble : signalé par le modèle **ou** par la règle. Verdict : celui de "
            "l'analyse complète (`TextAnalyzer`, fusion), suspect ou phishing. Scénario "
            f"d'infrastructure : signal RDAP « domaine de {report['scenario_domain_age_days']} "
            "jours » ajouté aux liens du phishing, le légitime n'étant pas modifié. Contrôle : "
            f"{fr_int(control['messages']) if control else 0} messages légitimes **avec lien**, "
            "ajoutés après la première mesure (voir la lecture)."
        ),
        "",
    ]

    def row(label: str, version: str, llm: dict, sms: dict | None, ctrl: dict | None) -> list:
        return [
            label,
            version,
            _ci(llm["recall"]),
            _ci(llm["fpr"], 2),
            _ci(sms["fpr"], 2) if sms else "",
            _ci(ctrl, 1) if ctrl else "",
        ]

    rows = [
        row(
            "règle seule",
            "",
            rule["llm"],
            rule.get("sms_test"),
            control["rule"] if control else None,
        )
    ]
    for entry in models.values():
        version = f"`{entry['version']}`"
        ctrl = entry.get("control", {})
        scenario = entry["scenario"]
        rows += [
            row("modèle seul", version, entry["llm"], entry.get("sms_test"), ctrl.get("model")),
            row(
                "modèle + règle",
                version,
                entry["ensemble"],
                entry.get("ensemble_sms_test"),
                ctrl.get("ensemble"),
            ),
            row("verdict de l'analyse", version, scenario["verdicts"], None, ctrl.get("verdict")),
            row(
                "verdict + domaine récent (scénario)",
                version,
                scenario["with_young_domain"],
                None,
                ctrl.get("verdict"),
            ),
        ]
    lines.append(
        markdown_table(
            ["Signal", "Modèle", "Rappel LLM", "FPR LLM", "FPR SMS (UCI)", "FPR contrôle"],
            rows,
            ["left", "left", "right", "right", "right", "right"],
        )
    )
    first = models[names[0]]["scenario"]
    lines += [
        "",
        (
            f"{fr_percent(first['phishing_with_link']['rate'], 0)} du phishing LLM contient un "
            f"lien. Avec `{models[names[0]]['version']}`, {fr_int(first['missed_without_link'])} "
            "phishing que l'analyse ne signale pas n'en ont aucun : aucun signal "
            "d'infrastructure de lien ne peut les rattraper."
        ),
    ]
    return "\n".join(lines)


def print_summary(report: dict[str, Any]) -> None:
    for entry in report["models"].values():
        sms = entry.get("sms_test")
        print(
            f"\n{entry['version']} : rappel LLM {fr_percent(entry['llm']['recall']['rate'])}"
            + (f" (SMS {fr_percent(sms['recall']['rate'])})" if sms else "")
            + f", FPR LLM {fr_percent(entry['llm']['fpr']['rate'], 2)}"
            + (f" (SMS {fr_percent(sms['fpr']['rate'], 2)})" if sms else "")
            + f", ROC-AUC LLM {entry['llm_separation']['roc_auc']:.3f}"
        )
        print(
            f"  modèle + règle : rappel {fr_percent(entry['ensemble']['recall']['rate'])}, "
            f"FPR {fr_percent(entry['ensemble']['fpr']['rate'], 2)}"
        )
        s = entry["scenario"]
        print(
            f"  verdict : rappel {fr_percent(s['verdicts']['recall']['rate'])} → "
            f"{fr_percent(s['with_young_domain']['recall']['rate'])} avec domaine récent, "
            f"FPR {fr_percent(s['verdicts']['fpr']['rate'], 2)}"
        )
        if "control" in entry:
            c = entry["control"]
            print(
                f"  contrôle : FPR modèle {fr_percent(c['model']['rate'])}, "
                f"ensemble {fr_percent(c['ensemble']['rate'])}, "
                f"verdict {fr_percent(c['verdict']['rate'])}"
            )


# --------------------------------------------------------------------------- #


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")  # accents lisibles sous Windows
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    args = parse_args(argv)
    if not args.data.is_file():
        logger.error("%s introuvable : voir docs/llm-phishing.md (jeu local)", args.data)
        return 1
    models = [m for m in args.models if m.is_file()]
    for missing in sorted(set(args.models) - set(models)):
        logger.warning("%s introuvable : modèle ignoré", missing)
    if not models:
        logger.error("aucun modèle SMS : lancez d'abord scripts/train_text.py")
        return 1

    llm_frame = load_llm_messages(args.data)
    llm = make_block(llm_frame)
    categories = [message_categories(t) for t in llm.texts]

    sms_test = None
    if args.sms_data.is_file():
        corpus, _ = deduplicate(load_sms_collection(args.sms_data))
        frame = corpus[split_sms(corpus, seed=args.split_seed) == "test"].reset_index(drop=True)
        sms_test = make_block(frame)
    else:
        logger.warning("%s introuvable : pas de comparaison avec le SMS", args.sms_data)

    control = None
    if args.control is not None and args.control.is_file():
        control_frame = load_llm_messages(args.control, balanced=False)
        if (control_frame["label"] != 0).any():
            logger.error("%s : le contrôle ne doit contenir que du légitime", args.control)
            return 1
        control = make_block(control_frame)
    elif args.control is not None:
        logger.warning("%s introuvable : pas de jeu de contrôle", args.control)

    results: dict[str, Any] = {}
    for path in models:
        entry = evaluate_model(path, llm, sms_test, control)
        results[entry["version"]] = entry

    report: dict[str, Any] = {
        "report_version": REPORT_VERSION,
        "metadata": {
            "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
            "dataset": {
                "sha256": sha256_file(args.data),
                "messages": len(llm_frame),
                "phishing": int(llm_frame["label"].sum()),
                "legitimate": int((llm_frame["label"] == 0).sum()),
                "families": int(llm_frame["family"].nunique()),
                "by_channel": {k: int(v) for k, v in llm_frame["channel"].value_counts().items()},
                "median_chars": {
                    str(label): float(group.str.len().median())
                    for label, group in llm_frame.groupby("label")["text"]
                },
            },
            "sms_sha256": sha256_file(args.sms_data) if sms_test is not None else None,
        },
        "scenario_domain_age_days": SCENARIO_DOMAIN_AGE_DAYS,
        "categories": categories_report(llm_frame, categories),
        "rule": {
            "definition": "link and (code or account)",
            "llm": detection(llm.rule, llm.labels),
            "sms_test": detection(sms_test.rule, sms_test.labels) if sms_test else None,
        },
        "models": results,
    }
    if control is not None:
        control_categories = [message_categories(t) for t in control.texts]
        report["control"] = {
            "sha256": sha256_file(args.control),
            "messages": len(control.frame),
            "added_after_first_measurement": True,
            "rule": rate(control.rule),
            "categories": {
                c: rate(np.array([c in cats for cats in control_categories]))
                for c in CATEGORY_LABELS
            },
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
