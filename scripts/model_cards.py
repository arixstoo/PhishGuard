"""Met à jour les chiffres des model cards et du README (étape 1.12).

    python scripts/model_cards.py        # ou : make cards (appelé par make train)

Lit les rapports de docs/metrics/ et réécrit les blocs générés de :

- docs/model-card-url.md   (url_v1.json, url_v1_test.json, urls_split.json) ;
- docs/model-card-text.md  (text_v1.json, à défaut sms_baseline.json) ;
- docs/model-card-email.md (email_v1.json) ;
- README.md, section « Current results » (URL).

Aucun chiffre n'est recopié à la main : un rapport absent donne un bloc qui le dit. Le
texte des cards hors des blocs (usage prévu, biais, limites) est écrit à la main.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from phishguard.reporting import (
    fr_int,
    fr_number,
    fr_percent,
    markdown_table,
    update_generated_block,
)

ROOT = Path(__file__).resolve().parents[1]
THRESHOLD_LABELS = {
    "fpr_5pct": "5 %",
    "fpr_2pct": "2 %",
    "fpr_1pct": "1 %",
    "fpr_0_5pct": "0,5 %",
    "fpr_0_2pct": "0,2 %",
    "fpr_0_1pct": "0,1 %",
}
URL_MODEL_LABELS = {
    "logistic_regression": "régression logistique",
    "random_forest": "Random Forest",
    "lightgbm": "LightGBM",
}


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    p.add_argument("--metrics-dir", type=Path, default=ROOT / "docs/metrics")
    p.add_argument("--docs-dir", type=Path, default=ROOT / "docs")
    p.add_argument("--readme", type=Path, default=ROOT / "README.md")
    return p.parse_args(argv)


def read(path: Path) -> dict[str, Any] | None:
    return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else None


def _date(value: str | None) -> str:
    return "n/d" if not value else f"{value[8:10]}/{value[5:7]}/{value[:4]}"


def _ci(rate: dict[str, Any], digits: int = 1) -> str:
    if not rate or rate.get("rate") is None:
        return "n/d"
    return (
        f"{fr_percent(rate['rate'], digits)} "
        f"[{fr_number(rate['low'] * 100, digits)}–{fr_percent(rate['high'], digits)}]"
    )


def _missing(command: str) -> str:
    return f"*Pas encore généré : lancez `{command}`, puis `make cards`.*"


# --------------------------------------------------------------------------- #
# URL
# --------------------------------------------------------------------------- #


def url_figures(train: dict[str, Any], test: dict[str, Any], split: dict | None) -> str:
    selected = train["selected"]
    decision = test["decision"]
    point = test["test"]["operating_points"][decision["name"]]
    free = test["test"]["threshold_free"]
    validation = train["models"][selected["model"]]["validation"]
    params = ", ".join(f"{k}={v}" for k, v in selected["params"].items())
    lines = [
        (
            "*Généré par `scripts/model_cards.py` depuis "
            "[`metrics/url_v1.json`](metrics/url_v1.json) et "
            "[`metrics/url_v1_test.json`](metrics/url_v1_test.json).*"
        ),
        "",
        (
            "**Modèle** : "
            f"{URL_MODEL_LABELS.get(selected['model'], selected['model'])} (`{params}`), "
            f"{selected['n_features']} features (jeu `{selected['feature_set']}`), fichier "
            f"`{selected['path']}` (SHA-256 `{selected['sha256'][:12]}`), jeu "
            f"`{train['metadata']['dataset_sha256'][:12]}`, scikit-learn "
            f"{train['metadata']['scikit-learn']}, LightGBM {train['metadata']['lightgbm']}."
        ),
        "",
        "**Données**",
        "",
    ]
    rows = []
    sizes = {**train["rows"], "test": test["rows"]["test"]}
    for name, label in (("train", "entraînement"), ("validation", "validation"), ("test", "test")):
        block = sizes[name]
        dates = (split or {}).get("blocks", {}).get(name, {}).get("first_seen", {})
        sources = ", ".join(f"{k} {fr_int(v)}" for k, v in block["by_source"].items())
        rows.append(
            [
                label,
                fr_int(block["total"]),
                fr_percent(block["phishing"] / block["total"]),
                f"{_date(dates.get('min'))} – {_date(dates.get('max'))}",
                sources,
            ]
        )
    lines.append(
        markdown_table(
            ["Bloc", "URLs", "Phishing", "Première apparition", "Sources"],
            rows,
            ["left", "right", "right", "left", "left"],
        )
    )
    lines += [
        "",
        "**Sans seuil** (validation → test)",
        "",
        markdown_table(
            ["Mesure", "Validation", "Test"],
            [
                [label, fr_number(validation[key]), fr_number(free[key])]
                for key, label in (
                    ("pr_auc", "PR-AUC"),
                    ("roc_auc", "ROC-AUC"),
                    ("recall_at_fpr_1pct", "Rappel à 1 % FPR"),
                    ("recall_at_fpr_0_1pct", "Rappel à 0,1 % FPR"),
                )
            ],
        ),
        "",
        (
            f"**Au seuil de décision** (`{decision['name']}` : score > "
            f"{fr_number(decision['threshold'], 4)}, réglé sur la validation ; test, IC à 95 %)"
        ),
        "",
        markdown_table(
            ["Mesure", "Valeur"],
            [
                ["Rappel", _ci(point["recall"])],
                ["FPR, tout le légitime", _ci(point["fpr"], 2)],
                ["FPR, pages d'accueil", _ci(point["fpr_homepages"], 2)],
                ["FPR, pages internes", _ci(point["fpr_internal_pages"])],
            ],
        ),
        "",
        "**Précision à la prévalence réelle** (même seuil)",
        "",
    ]
    rows = []
    for row in test["test"]["prevalence"][decision["name"]]:
        rows.append(
            [
                fr_percent(row["prevalence"], 1 if row["prevalence"] < 0.01 else 0),
                fr_percent(row["precision"]),
                fr_number(row["per_10k_false_per_true"], 1),
                fr_percent(row.get("precision_internal_pages")),
                fr_number(row.get("false_per_true_internal_pages"), 0),
            ]
        )
    lines.append(
        markdown_table(
            [
                "Phishing parmi les URLs",
                "Précision",
                "Fausses alertes par vraie",
                "Précision, pages internes",
                "Fausses par vraie, pages internes",
            ],
            rows,
        )
    )
    per_source = test["test"]["per_source"]
    lines += [
        "",
        "**Par source** (test, seuil de décision) : "
        + " ; ".join(
            f"`{name}` {'rappel' if e['metric'] == 'recall' else 'FPR'} "
            f"{fr_percent(e['rate'])} ({fr_int(e['n'])} URLs)"
            for name, e in per_source.items()
            if e["n"] >= 20
        )
        + ".",
    ]
    return "\n".join(lines)


def readme_url_results(train: dict[str, Any], test: dict[str, Any]) -> str:
    decision = test["decision"]
    point = test["test"]["operating_points"][decision["name"]]
    free = test["test"]["threshold_free"]
    prevalence = {r["prevalence"]: r for r in test["test"]["prevalence"][decision["name"]]}

    def pct(value: float | None) -> str:
        return "n/a" if value is None else f"{value * 100:.1f} %"

    selected = train["selected"]
    lines = [
        (
            f"**URL model** (`url_v1`, {URL_MODEL_LABELS.get(selected['model'], selected['model'])}, "
            f"{selected['n_features']} offline lexical features), measured once on the most recent "
            f"{test['rows']['test']['total']:,} URLs (temporal, domain-grouped test set). "
            "Full numbers and caveats: [`docs/model-card-url.md`](docs/model-card-url.md)."
        ),
        "",
        (
            "| PR-AUC | Recall @ 1 % FPR | Recall at decision threshold | FPR (homepages / internal pages) "
            "| Precision if 1 % of URLs are phishing |"
        ),
        "| ---: | ---: | ---: | ---: | ---: |",
        (
            f"| {free['pr_auc']:.3f} | {free['recall_at_fpr_1pct']:.3f} | {pct(point['recall']['rate'])} "
            f"| {pct(point['fpr_homepages']['rate'])} / {pct(point['fpr_internal_pages']['rate'])} "
            f"| {pct(prevalence[0.01]['precision'])} |"
        ),
    ]
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Texte et email
# --------------------------------------------------------------------------- #


def text_figures(text: dict[str, Any] | None, baseline: dict[str, Any] | None) -> str:
    if text is None:
        lines = [_missing("make train-text")]
        if baseline is not None:
            ref = baseline["protocols"]["deduplicated"]
            lines += [
                "",
                (
                    "En attendant, le **baseline de l'étape 0.7** (TF-IDF mots + régression "
                    "logistique, seuil 0,5, corpus dédoublonné, "
                    f"[`metrics/sms_baseline.json`](metrics/sms_baseline.json)) : précision "
                    f"{fr_number(ref['precision'])}, rappel {fr_number(ref['recall'])}, PR-AUC "
                    f"{fr_number(ref['pr_auc'])}, FPR {fr_percent(ref['fpr'], 1)}."
                ),
            ]
        return "\n".join(lines)
    selected = text["selected"]
    entry = text["approaches"][selected["approach"]]
    t = entry["test"]
    lines = [
        "*Généré par `scripts/model_cards.py` depuis [`metrics/text_v1.json`](metrics/text_v1.json).*",
        "",
        (
            f"**Modèle** : approche `{selected['approach']}` "
            f"(`{', '.join(f'{k}={v}' for k, v in selected['params'].items())}`), seuil "
            f"{fr_number(selected['threshold'], 4)} (1 % FPR sur la validation), SHA-256 "
            f"`{selected['sha256'][:12]}`, corpus `{text['metadata']['sms_sha256'][:12]}`."
        ),
        "",
        markdown_table(
            ["Jeu", "Messages", "Précision", "Rappel", "FPR", "PR-AUC"],
            [
                [
                    "Test UCI (anglais)",
                    fr_int(t["n"]),
                    fr_number(t["precision"]),
                    fr_number(t["recall"]),
                    fr_percent(t["fpr"], 2),
                    fr_number(t["pr_auc"]),
                ],
                *[
                    [
                        f"Jeu {label} rédigé (hors distribution)",
                        fr_int(entry["fr_ar"][lang]["n"]),
                        fr_number(entry["fr_ar"][lang]["precision"]),
                        fr_number(entry["fr_ar"][lang]["recall"]),
                        fr_percent(entry["fr_ar"][lang]["fpr"], 0),
                        fr_number(entry["fr_ar"][lang]["pr_auc"]),
                    ]
                    for lang, label in (("fr", "français"), ("ar", "arabe"))
                ],
            ],
        ),
        "",
        (
            f"Taille {fr_int(round(entry['size_bytes'] / 1024))} Kio, latence p50 "
            f"{fr_number(entry['latency']['latency_ms_p50'], 2)} ms par message."
        ),
    ]
    return "\n".join(lines)


def email_figures(email: dict[str, Any] | None) -> str:
    if email is None:
        return _missing("make email-corpora && make train-email")
    deployed = next(m for m in email["models"] if m["deployed"])
    rules = email["rules"]
    blocks = email["dataset"]["blocks"]
    lines = [
        "*Généré par `scripts/model_cards.py` depuis [`metrics/email_v1.json`](metrics/email_v1.json).*",
        "",
        (
            f"**Modèle déployé** : `{deployed['model']}`, jeu `{deployed['feature_set']}`, seuil "
            f"{fr_number(deployed['threshold'], 4)} (1 % FPR sur la validation). Test : "
            f"{fr_int(blocks['test']['rows'])} emails dont {fr_int(blocks['test']['phishing'])} de "
            "phishing."
        ),
        "",
        markdown_table(
            ["Approche", "PR-AUC", "Rappel", "FPR"],
            [
                [
                    "Règles, score ≥ 30",
                    fr_number(rules["test"]["pr_auc"]),
                    fr_number(rules["suspicious_or_more"]["recall"]),
                    fr_percent(rules["suspicious_or_more"]["fpr"], 2),
                ],
                [
                    "Modèle déployé",
                    fr_number(deployed["test"]["pr_auc"]),
                    fr_number(deployed["test_at_threshold"]["recall"]),
                    fr_percent(deployed["test_at_threshold"]["fpr"], 2),
                ],
            ],
        ),
    ]
    return "\n".join(lines)


# --------------------------------------------------------------------------- #


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")  # accents lisibles sous Windows
    args = parse_args(argv)
    metrics = args.metrics_dir
    url_train, url_test = read(metrics / "url_v1.json"), read(metrics / "url_v1_test.json")

    if url_train is not None and url_test is not None:
        url_block = url_figures(url_train, url_test, read(metrics / "urls_split.json"))
        readme_block = readme_url_results(url_train, url_test)
    else:
        url_block = _missing("make train-url && make evaluate-url")
        readme_block = "*URL model results: run `make train-url evaluate-url cards`.*"

    updates = {
        args.docs_dir / "model-card-url.md": ("card-url", url_block),
        args.docs_dir / "model-card-text.md": (
            "card-text",
            text_figures(read(metrics / "text_v1.json"), read(metrics / "sms_baseline.json")),
        ),
        args.docs_dir / "model-card-email.md": (
            "card-email",
            email_figures(read(metrics / "email_v1.json")),
        ),
        args.readme: ("current-results-url", readme_block),
    }
    for path, (block, content) in updates.items():
        update_generated_block(path, block, content)
        print(f"{path.name} : bloc {block} mis à jour")
    return 0


if __name__ == "__main__":
    sys.exit(main())
