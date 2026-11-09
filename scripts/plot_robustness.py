"""Graphique du rapport de robustesse : rappel et FPR par technique (étape 3.11).

    python scripts/plot_robustness.py            # ou : make plot-robustness

Lit les passages du banc d'essai (docs/metrics/robustness_<label>.json) et trace, pour
les URLs et les SMS du test UCI, le rappel et le taux de faux positifs sous chaque
perturbation, un passage par couleur : modèle d'origine, normalisation, normalisation +
entraînement adversarial. Écrit docs/img/robustness_by_technique.png.

Les chiffres exacts sont dans les tableaux du rapport (vue tableau du graphique). Le
FPR des perturbations qui fabriquent une imitation n'est pas tracé : leur légitime
perturbé n'est plus légitime (note ¹ du rapport).

Demande matplotlib (``pip install -e '.[explain]'``).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
RUNS = ("baseline", "normalization", "adversarial")
RUN_LABELS = {
    "baseline": "modèle d'origine",
    "normalization": "normalisation",
    "adversarial": "normalisation + entraînement adversarial",
}
BLOCKS = {"url": "URL (test, 21 004 URLs)", "sms": "SMS (test UCI, 774 messages)"}
CLEAN = "aucune"

# Palette catégorielle de référence, emplacements 1 à 3 (validés deux à deux, y compris
# en vision des couleurs altérée), sur la surface claire du rapport.
COLORS = {"baseline": "#2a78d6", "normalization": "#eb6834", "adversarial": "#1baf7a"}
SURFACE = "#fcfcfb"
TEXT = "#0b0b0b"
TEXT_SECONDARY = "#52514e"
GRID = "#e4e3df"


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    p.add_argument("--metrics-dir", type=Path, default=ROOT / "docs/metrics")
    p.add_argument("--output", type=Path, default=ROOT / "docs/img/robustness_by_technique.png")
    return p.parse_args(argv)


def series(runs: dict[str, dict[str, Any]], block: str) -> dict[str, Any]:
    """Perturbations du bloc (dans l'ordre du banc) et rappel / FPR de chaque passage."""
    names: list[str] = [CLEAN]
    lookalike: set[str] = set()
    for run in runs.values():
        for row in run["blocks"][block]["perturbations"]:
            if row["perturbation"] not in names:
                names.append(row["perturbation"])
            if row.get("creates_lookalike"):
                lookalike.add(row["perturbation"])
    values: dict[str, dict[str, list[float | None]]] = {}
    for label, run in runs.items():
        result = run["blocks"][block]
        rows = {r["perturbation"]: r for r in result["perturbations"]}
        rows[CLEAN] = result["baseline"]
        values[label] = {
            metric: [
                None
                if n not in rows or rows[n][metric]["rate"] is None
                else rows[n][metric]["rate"]
                for n in names
            ]
            for metric in ("recall", "fpr")
        }
    return {"names": names, "lookalike": lookalike, "values": values}


def plot(runs: dict[str, dict[str, Any]], output: Path) -> Path:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib.ticker import PercentFormatter

    blocks = [b for b in BLOCKS if all(b in r["blocks"] for r in runs.values())]
    data = {b: series(runs, b) for b in blocks}
    heights = [len(data[b]["names"]) for b in blocks]
    fig, axes = plt.subplots(
        len(blocks),
        2,
        figsize=(11, 0.42 * sum(heights) + 2.2),
        gridspec_kw={"height_ratios": heights, "width_ratios": [1.15, 1]},
        facecolor=SURFACE,
        squeeze=False,
    )
    bar = 0.26
    for row, block in enumerate(blocks):
        d = data[block]
        for col, metric in enumerate(("recall", "fpr")):
            ax = axes[row][col]
            ax.set_facecolor(SURFACE)
            for i, label in enumerate(runs):
                ys, xs = [], []
                for j, value in enumerate(d["values"][label][metric]):
                    if value is None or (metric == "fpr" and d["names"][j] in d["lookalike"]):
                        continue
                    ys.append(j + (i - 1) * (bar + 0.02))
                    xs.append(value)
                ax.barh(
                    ys,
                    xs,
                    height=bar,
                    color=COLORS.get(label, TEXT_SECONDARY),
                    edgecolor=SURFACE,
                    linewidth=1,
                    label=RUN_LABELS.get(label, label),
                    zorder=2,
                )
            labels = [
                ("propre" if n == CLEAN else n)
                + (" ¹" if metric == "fpr" and n in d["lookalike"] else "")
                for n in d["names"]
            ]
            ax.set_yticks(range(len(d["names"])))
            ax.set_yticklabels(labels if col == 0 else [""] * len(labels), color=TEXT, fontsize=9)
            ax.invert_yaxis()
            ax.xaxis.set_major_formatter(PercentFormatter(1.0, decimals=0))
            ax.set_xlim(0, 1.0 if metric == "recall" else _fpr_limit(d))
            ax.grid(axis="x", color=GRID, linewidth=0.8, zorder=0)
            ax.tick_params(colors=TEXT_SECONDARY, labelsize=8.5, length=0)
            for side in ("top", "right", "left"):
                ax.spines[side].set_visible(False)
            ax.spines["bottom"].set_color(GRID)
            ax.axhline(0.5, color=TEXT_SECONDARY, linewidth=0.6, linestyle=(0, (2, 2)), zorder=1)
            title = "Rappel" if metric == "recall" else "Taux de faux positifs"
            ax.set_title(f"{BLOCKS[block]} · {title}", loc="left", color=TEXT, fontsize=10.5, pad=8)
    handles, legend_labels = axes[0][0].get_legend_handles_labels()
    fig.legend(
        handles,
        legend_labels,
        loc="upper left",
        ncol=len(runs),
        frameon=False,
        fontsize=9.5,
        labelcolor=TEXT,
        bbox_to_anchor=(0.01, 0.995),
    )
    fig.text(
        0.01,
        0.005,
        "Seuil de décision de chaque modèle, réglé sur la validation. « propre » : aucune "
        "perturbation. ¹ Imitation : FPR non tracé.\nChiffres exacts et intervalles de "
        "confiance : docs/robustness-report.md.",
        color=TEXT_SECONDARY,
        fontsize=8,
        va="bottom",
    )
    fig.tight_layout(rect=(0, 0.04, 1, 0.95), h_pad=2.0, w_pad=1.5)
    output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output, dpi=150, facecolor=SURFACE, metadata={"Software": None})
    plt.close(fig)
    return output


def _fpr_limit(d: dict[str, Any]) -> float:
    values = [
        v
        for label in d["values"]
        for n, v in zip(d["names"], d["values"][label]["fpr"], strict=True)
        if v is not None and n not in d["lookalike"]
    ]
    top = max(values, default=0.1)
    return min(1.0, max(0.1, top * 1.08))


def load(metrics_dir: Path) -> dict[str, dict[str, Any]]:
    runs = {}
    for label in RUNS:
        path = metrics_dir / f"robustness_{label}.json"
        if path.is_file():
            runs[label] = json.loads(path.read_text(encoding="utf-8"))
    return runs


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    runs = load(args.metrics_dir)
    if not runs:
        print(f"aucun passage dans {args.metrics_dir} : lancez scripts/robustness_benchmark.py")
        return 1
    try:
        out = plot(runs, args.output)
    except ImportError:
        print("matplotlib est requis : pip install -e '.[explain]'")
        return 1
    print(f"Graphique : {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
