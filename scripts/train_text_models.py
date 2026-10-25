"""Compare les modèles de texte SMS (étape 1.9) en une commande.

    python scripts/train_text_models.py                 # 5 approches TF-IDF
    python scripts/train_text_models.py --embeddings    # + embeddings multilingues

Télécharge (si besoin) la UCI SMS Spam Collection, vérifie son empreinte, entraîne chaque
approche, l'évalue sur le test UCI puis sur le jeu français / arabe (datasets/sms_fr_ar.csv),
et écrit docs/metrics/text_models.json. Le tableau comparatif est imprimé en Markdown.

--embeddings demande `pip install -e '.[embeddings]'` et l'accès à huggingface.co.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import joblib

from phishguard.data.sms import (
    download_sms_collection,
    load_fr_ar_sms,
    load_sms_collection,
    sha256_bytes,
)
from phishguard.text.models import (
    TextConfig,
    compare,
    default_approaches,
    embedding_approach,
    markdown_table,
)

ROOT = Path(__file__).resolve().parents[1]


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    p.add_argument("--data", type=Path, default=ROOT / "data/raw/SMSSpamCollection")
    p.add_argument("--external", type=Path, default=ROOT / "datasets/sms_fr_ar.csv")
    p.add_argument("--metrics-out", type=Path, default=ROOT / "docs/metrics/text_models.json")
    p.add_argument("--models-dir", type=Path, default=ROOT / "models")
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--embeddings", action="store_true", help="ajoute l'approche embeddings")
    p.add_argument(
        "--offline", action="store_true", help="ne pas télécharger, utiliser --data tel quel"
    )
    return p.parse_args(argv)


def _encoder_info(model) -> dict:
    encoder = model.named_steps["embed"].encoder
    n_params = sum(p.numel() for p in encoder.parameters())
    return {"encoder_parameters": int(n_params), "encoder_size_bytes_fp32": int(n_params * 4)}


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    data_path = args.data if args.offline else download_sms_collection(args.data)
    raw = load_sms_collection(data_path)
    external = load_fr_ar_sms(args.external) if args.external.exists() else None

    approaches = default_approaches()
    if args.embeddings:
        approaches.append(embedding_approach())

    models, metrics = compare(raw, TextConfig(seed=args.seed), approaches, external)
    metrics["dataset"]["sha256"] = sha256_bytes(Path(data_path).read_bytes())
    if "embeddings_logreg" in models:
        metrics["approaches"]["embeddings_logreg"].update(
            _encoder_info(models["embeddings_logreg"])
        )

    args.metrics_out.parent.mkdir(parents=True, exist_ok=True)
    args.metrics_out.write_text(
        json.dumps(metrics, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    # Attention : joblib = pickle. Ne jamais charger un .joblib d'origine inconnue.
    args.models_dir.mkdir(parents=True, exist_ok=True)
    for name, model in models.items():
        joblib.dump(model, args.models_dir / f"text_{name}.joblib")

    print(markdown_table(metrics))
    print(f"\nMétriques : {args.metrics_out}")
    print(f"Modèles   : {args.models_dir}/text_*.joblib")
    return 0


if __name__ == "__main__":
    sys.exit(main())
