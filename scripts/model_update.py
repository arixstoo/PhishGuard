"""Réentraînement mensuel du modèle URL : test figé et garde-fou (étape 6.8).

    # Une fois (machine de l'auteur) : geler le test actuel, versionner son empreinte.
    python scripts/model_update.py freeze

    # Chaque mois (workflow model-update.yml) :
    python scripts/model_update.py exclude-frozen --frozen build/frozen/url_test_frozen.parquet
    python scripts/model_update.py gate --current-models-dir build/current \\
        --candidate-model build/candidate/url_v2.joblib \\
        --frozen build/frozen/url_test_frozen.parquet

Codes de sortie de ``gate`` : 0 candidat accepté, 1 candidat refusé, 2 erreur.

Le modèle **en service** est un pickle téléchargé : il n'est désérialisé qu'après
vérification de la signature de son manifeste (``phishguard.registry``). Le candidat
vient d'être produit par le même job.
"""

from __future__ import annotations

import argparse
import io
import json
import logging
import sys
from pathlib import Path

import pandas as pd

from phishguard import model_update as M
from phishguard.data.split import read_split_blocks
from phishguard.deployment import DEPLOYED_MODELS
from phishguard.registry import load_public_key, verify_manifest
from phishguard.urls.model import UrlModel

ROOT = Path(__file__).resolve().parents[1]
FROZEN_REPORT = ROOT / "docs/metrics/frozen_test.json"
logger = logging.getLogger("model_update")


def _frozen_sha256(report: Path) -> str:
    return json.loads(report.read_text(encoding="utf-8"))["content_sha256"]


def cmd_freeze(args: argparse.Namespace) -> int:
    report = M.freeze_test_set(args.split, args.output)
    args.report.write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    print(f"test figé : {report['rows']} URLs → {args.output} ; empreinte dans {args.report}")
    print("Chiffrez-le avant de le publier (docs/model-updates.md), jamais en clair.")
    return 0


def cmd_exclude(args: argparse.Namespace) -> int:
    frozen = M.load_frozen_test_set(args.frozen, _frozen_sha256(args.frozen_report))
    dataset = pd.read_parquet(args.dataset)
    kept, removed = M.exclude_frozen_domains(dataset, frozen)
    kept.to_parquet(args.output or args.dataset, index=False)
    print(f"{removed} URLs des domaines du test figé retirées ({len(kept)} restantes)")
    return 0


def load_current_model(models_dir: Path, public_key: Path) -> UrlModel:
    """Modèle en service, désérialisé depuis les octets dont l'empreinte est signée."""
    manifest = verify_manifest(models_dir, load_public_key(public_key))
    return UrlModel.load(io.BytesIO(manifest.read(f"{DEPLOYED_MODELS['url']}.joblib")))


def cmd_gate(args: argparse.Namespace) -> int:
    frozen = M.load_frozen_test_set(args.frozen, _frozen_sha256(args.frozen_report))
    recent = read_split_blocks(args.recent, ["test"], columns=["url"])["test"]
    legitimate = M.load_legitimate_urls()
    current_model = load_current_model(args.current_models_dir, args.public_key)
    candidate_model = UrlModel.load(args.candidate_model)

    def evaluate(model: UrlModel) -> M.ModelEvaluation:
        return M.evaluate_model(
            model,
            model_version=str(model.metadata.get("model_version", "inconnu")),
            frozen=frozen,
            recent=recent,
            legitimate_urls=legitimate,
        )

    current, candidate = evaluate(current_model), evaluate(candidate_model)
    decision = M.decide(current, candidate, recall_tolerance=args.recall_tolerance)
    report = M.gate_report(
        decision,
        current,
        candidate,
        frozen_rows=len(frozen),
        recent_rows=len(recent),
        legitimate_rows=len(legitimate),
        extra={"candidate_trained_at": candidate_model.metadata.get("trained_at")},
    )
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    summary = M.render_markdown(report)
    if args.summary:
        with args.summary.open("a", encoding="utf-8") as out:
            out.write(summary)
    print(summary)
    return 0 if decision.passed else 1


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)

    freeze = sub.add_parser("freeze", help="gèle le bloc de test actuel")
    freeze.add_argument("--split", type=Path, default=ROOT / "data/processed/urls_split.parquet")
    freeze.add_argument("--output", type=Path, default=ROOT / "data/frozen/url_test_frozen.parquet")
    freeze.add_argument("--report", type=Path, default=FROZEN_REPORT)
    freeze.set_defaults(func=cmd_freeze)

    exclude = sub.add_parser("exclude-frozen", help="retire les domaines du test figé du jeu")
    exclude.add_argument("--dataset", type=Path, default=ROOT / "data/processed/urls.parquet")
    exclude.add_argument("--frozen", type=Path, required=True)
    exclude.add_argument("--frozen-report", type=Path, default=FROZEN_REPORT)
    exclude.add_argument("--output", type=Path, help="par défaut : réécrit --dataset")
    exclude.set_defaults(func=cmd_exclude)

    gate = sub.add_parser("gate", help="compare le candidat au modèle en service")
    gate.add_argument("--current-models-dir", type=Path, required=True)
    gate.add_argument("--public-key", type=Path, default=ROOT / "keys/model-signing.pub")
    gate.add_argument("--candidate-model", type=Path, required=True)
    gate.add_argument("--frozen", type=Path, required=True)
    gate.add_argument("--frozen-report", type=Path, default=FROZEN_REPORT)
    gate.add_argument("--recent", type=Path, default=ROOT / "data/processed/urls_split.parquet")
    gate.add_argument("--recall-tolerance", type=float, default=0.0)
    gate.add_argument("--report", type=Path, default=ROOT / "build/candidate/gate_report.json")
    gate.add_argument(
        "--summary", type=Path, help="fichier Markdown complété (GITHUB_STEP_SUMMARY)"
    )
    gate.set_defaults(func=cmd_gate)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    args = parse_args(argv)
    try:
        return args.func(args)
    except (OSError, ValueError, KeyError) as error:
        print(f"model_update : {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
