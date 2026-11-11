"""Explications SHAP du modèle URL sur la validation (étape 3.1).

    python scripts/explain_url.py            # ou : make explain-url

Lit le modèle de l'étape 1.6 et le bloc **validation** de
data/processed/urls_split.parquet. Le test n'est jamais chargé : il a été lu une fois à
l'étape 1.7.

1. **Vue globale** : valeurs SHAP d'un échantillon aléatoire de la validation (2 000 URLs
   par défaut), importance de chaque feature (moyenne de la valeur absolue) et graphique
   « beeswarm » de ``shap.summary_plot``.
2. **Vue locale** : pour 10 URLs de phishing détectées, les 3 features qui ont le plus
   poussé vers « phishing ». Les exemples sont choisis pour varier (première raison
   différente autant que possible) et ne viennent que des sources dont la licence permet
   la publication ; ils sont défangés, sans requête.

Le graphique demande la bibliothèque ``shap`` et ``matplotlib`` :
``pip install -e '.[explain]'``. Les valeurs elles-mêmes sont calculées par LightGBM.

Écrit :

- docs/img/url_v1_shap_summary.png : le graphique global, repris par la model card ;
- docs/metrics/url_v1_shap.json : importance globale et exemples défangés ;
- le bloc généré de docs/explain-url.md.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from phishguard.data.integrity import sha256_file
from phishguard.data.split import read_split_blocks
from phishguard.explain.shap_url import (
    FeatureAttribution,
    UrlExplainer,
    UrlExplanation,
    global_importance,
)
from phishguard.reporting import fr_int, fr_number, markdown_table, update_generated_block
from phishguard.urls.errors import PUBLISHABLE_SOURCES, defang
from phishguard.urls.evaluation import choose_decision_threshold, operating_points
from phishguard.urls.features import feature_spec
from phishguard.urls.model import UrlModel

ROOT = Path(__file__).resolve().parents[1]
REPORT_VERSION = "1.0.0"
DOC_BLOCK = "explain-url"
TOP = 3

logger = logging.getLogger("explain_url")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    p.add_argument("--dataset", type=Path, default=ROOT / "data/processed/urls_split.parquet")
    p.add_argument("--model", type=Path, default=ROOT / "models/url_v1.joblib")
    p.add_argument("--sample", type=int, default=2000, help="URLs de la vue globale")
    p.add_argument("--examples", type=int, default=10, help="URLs de la vue locale")
    p.add_argument("--seed", type=int, default=0)
    p.add_argument("--plot", type=Path, default=ROOT / "docs/img/url_v1_shap_summary.png")
    p.add_argument("--report", type=Path, default=ROOT / "docs/metrics/url_v1_shap.json")
    p.add_argument("--doc", type=Path, default=ROOT / "docs/explain-url.md")
    args = p.parse_args(argv)
    if args.sample <= 0 or args.examples <= 0:
        p.error("--sample et --examples doivent être strictement positifs")
    for name in ("plot", "doc"):
        if str(getattr(args, name)).lower() == "none":
            setattr(args, name, None)
    return args


# --------------------------------------------------------------------------- #
# Sélection des exemples
# --------------------------------------------------------------------------- #


def pick_examples(
    candidates: pd.DataFrame, explanations: Sequence[UrlExplanation], n: int, seed: int
) -> list[int]:
    """Positions de ``n`` exemples variés : un par première raison, à tour de rôle.

    Les candidats sont mélangés (graine fixe), puis regroupés par feature de plus forte
    contribution ; on prend un exemple de chaque groupe, puis un deuxième, et ainsi de
    suite. Sans cela, dix exemples tirés au hasard montreraient presque tous la même
    raison (la plus fréquente).
    """
    if len(candidates) != len(explanations):
        raise ValueError("un candidat par explication attendu")
    order = np.random.default_rng(seed).permutation(len(candidates))
    groups: dict[str, list[int]] = {}
    for position in order.tolist():
        top = explanations[position].top(1)
        groups.setdefault(top[0].name if top else "", []).append(position)
    # Groupes les plus fournis d'abord : leur raison est la plus représentative.
    queues = sorted(groups.values(), key=lambda g: (-len(g), g[0]))
    picked: list[int] = []
    while len(picked) < n and any(queues):
        for queue in queues:
            if queue and len(picked) < n:
                picked.append(queue.pop(0))
    return picked


# --------------------------------------------------------------------------- #
# Rendu
# --------------------------------------------------------------------------- #


def format_value(value: float) -> str:
    return fr_int(int(value)) if float(value).is_integer() else fr_number(value, 2)


def format_reason(a: FeatureAttribution) -> str:
    sign = "+" if a.shap >= 0 else "−"
    return f"`{a.name}` = {format_value(a.value)} ({sign}{fr_number(abs(a.shap), 2)})"


def render_markdown(report: dict[str, Any]) -> str:
    meta = report["metadata"]
    space = "log-odds" if report["space"] == "log_odds" else "probabilité"
    engine = "LightGBM (TreeSHAP natif)" if meta["backend"] == "lightgbm" else "shap"
    lines = [
        (
            f"*Généré par `scripts/explain_url.py` depuis "
            f"[`metrics/url_v1_shap.json`](metrics/url_v1_shap.json) : modèle "
            f"`{meta['model_version']}` (SHA-256 `{meta['model_sha256'][:12]}`), jeu "
            f"`{meta['dataset_sha256'][:12]}`, {fr_int(meta['sample_rows'])} URLs de validation "
            f"tirées au hasard (graine {meta['seed']}). Valeurs SHAP en {space}, calculées par "
            f"{engine}.*"
        ),
        "",
        "### Importance globale",
        "",
        (
            "Moyenne de la valeur absolue SHAP sur l'échantillon : de combien, en moyenne, la "
            "feature déplace le score d'une URL, dans un sens ou dans l'autre."
        ),
        "",
    ]
    total = sum(item["mean_abs_shap"] for item in report["global_importance"]) or 1.0
    rows = [
        [
            str(rank),
            f"`{item['feature']}`",
            fr_number(item["mean_abs_shap"], 3),
            f"{fr_number(100 * item['mean_abs_shap'] / total, 1)} %",
            item["description"],
        ]
        for rank, item in enumerate(report["global_importance"], start=1)
    ]
    lines.append(
        markdown_table(
            ["Rang", "Feature", "Moyenne de |SHAP|", "Part", "Ce qu'elle mesure"],
            rows,
            align=["right", "left", "right", "right", "left"],
        )
    )
    lines += [
        "",
        f"### {len(report['examples'])} URLs de phishing détectées et leurs 3 raisons principales",
        "",
        (
            f"Seuil de décision `{meta['decision']['name']}` (score > "
            f"{fr_number(meta['decision']['threshold'], 4)}), réglé sur la validation à "
            "l'étape 1.7. Chaque raison est notée `feature` = valeur (contribution SHAP). "
            "Exemples défangés et sans requête ; données de phishing fournies par PhishTank, "
            "phishtank.org."
        ),
        "",
    ]
    rows = [
        [
            f"`{example['url']}`",
            fr_number(example["score"], 3),
            *[
                format_reason(FeatureAttribution(r["feature"], r["value"], r["shap"]))
                for r in example["top"]
            ],
            *([""] * (TOP - len(example["top"]))),
        ]
        for example in report["examples"]
    ]
    lines.append(
        markdown_table(
            ["URL", "Score", "Raison 1", "Raison 2", "Raison 3"],
            rows,
            align=["left", "right", "left", "left", "left"],
        )
    )
    return "\n".join(lines)


def save_summary_plot(values: np.ndarray, x: pd.DataFrame, path: Path) -> None:
    """Graphique « beeswarm » de ``shap.summary_plot``, enregistré en PNG."""
    import matplotlib

    matplotlib.use("Agg")  # aucun affichage : le script tourne aussi sans écran
    import matplotlib.pyplot as plt
    import shap

    path.parent.mkdir(parents=True, exist_ok=True)
    shap.summary_plot(values, x, max_display=x.shape[1], show=False, plot_size=(9, 9))
    figure = plt.gcf()
    figure.suptitle("url_v1 : contribution SHAP de chaque feature (validation)", fontsize=12)
    figure.savefig(path, dpi=110, bbox_inches="tight")
    plt.close(figure)


# --------------------------------------------------------------------------- #
# Programme
# --------------------------------------------------------------------------- #


def explain(
    model: UrlModel, validation: pd.DataFrame, *, sample: int, examples: int, seed: int
) -> tuple[dict[str, Any], np.ndarray, pd.DataFrame]:
    """Rapport (sans métadonnées de fichiers), valeurs SHAP et features de l'échantillon."""
    explainer = UrlExplainer(model)
    drawn = validation.sample(n=min(sample, len(validation)), random_state=seed)
    x = model.features(drawn["url"])
    values, base = explainer.shap_values(x)
    importance = [
        {
            "feature": name,
            "mean_abs_shap": round(mean, 6),
            "description": feature_spec(name).description,
        }
        for name, mean in global_importance(values, explainer.feature_names)
    ]

    scores = model.score(validation["url"])
    decision = choose_decision_threshold(
        operating_points(
            validation["label"].to_numpy(),
            scores,
            validation["source"].to_numpy(dtype=str),
            model.thresholds,
        )
    )
    threshold = float(model.thresholds[decision["name"]])
    detected = (
        (validation["label"].to_numpy() == 1)
        & (scores > threshold)
        & validation["source"].isin(PUBLISHABLE_SOURCES).to_numpy()
    )
    candidates = validation[detected].assign(score=scores[detected]).reset_index(drop=True)
    candidate_explanations = explainer.explain(candidates["url"])
    chosen = pick_examples(candidates, candidate_explanations, examples, seed)
    example_rows = []
    for position in chosen:
        row, explanation = candidates.iloc[position], candidate_explanations[position]
        example_rows.append(
            {
                "url": defang(row["url"]),
                "source": row["source"],
                "score": round(float(row["score"]), 4),
                "top": [
                    {"feature": a.name, "value": a.value, "shap": round(a.shap, 4)}
                    for a in explanation.top(TOP)
                ],
            }
        )
    report = {
        "space": explainer.space,
        "backend": explainer.backend,
        "base_value": round(base, 6),
        "global_importance": importance,
        "decision": {"name": decision["name"], "threshold": threshold},
        "candidates": len(candidates),
        "examples": example_rows,
    }
    return report, values, x


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
    validation = read_split_blocks(args.dataset, ("validation",), ["url", "label", "source"])[
        "validation"
    ]
    report, values, x = explain(
        model, validation, sample=args.sample, examples=args.examples, seed=args.seed
    )
    full = {
        "metadata": {
            "report_version": REPORT_VERSION,
            "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
            "model_version": str(model.metadata.get("model_version", "unknown")),
            "model_sha256": sha256_file(args.model),
            "dataset_sha256": sha256_file(args.dataset),
            "split": "validation",
            "sample_rows": len(x),
            "seed": args.seed,
            "backend": report.pop("backend"),
            "decision": report.pop("decision"),
        },
        **report,
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(full, indent=2, ensure_ascii=False) + "\n", "utf-8")
    if args.plot is not None:
        save_summary_plot(values, x, args.plot)
    if args.doc is not None:
        update_generated_block(args.doc, DOC_BLOCK, render_markdown(full))

    for item in full["global_importance"][:5]:
        print(f"{item['feature']:<24}{item['mean_abs_shap']:>8.3f}")
    print(f"\nRapport : {args.report}")
    if args.plot is not None:
        print(f"Graphique : {args.plot}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
