"""Petits modèles synthétiques pour le test de démarrage de l'image (étape 4.9).

::

    python scripts/smoke_models.py --output-dir build/smoke-models
    PHISHGUARD_MODELS_HOST_DIR=build/smoke-models docker compose up --wait

Les modèles déployés (``url_v2``, ``text_v2``) ne sont pas versionnés : une machine propre,
la CI par exemple, n'en a pas. Ce script en entraîne de minuscules, sous les mêmes noms,
sur le jeu synthétique des tests (domaines inventés, aucune donnée réelle). Ils servent à
vérifier que l'image démarre, charge ses modèles par le vrai chemin
(:func:`phishguard.deployment.load_analyzers`) et répond ; leurs verdicts n'ont **aucune
valeur**. Ne jamais les déployer.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args(argv)

    # Mêmes fabriques que les tests de l'API : un seul jeu synthétique à maintenir.
    sys.path.insert(0, str(ROOT / "tests"))
    from api_support import train_models
    from conftest import synthetic_urls

    from phishguard.data.split import temporal_group_split

    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    df = synthetic_urls(n=900, seed=0)
    split_path = output / "urls_split.parquet"
    df.assign(split=temporal_group_split(df)).to_parquet(split_path, index=False)
    train_models(split_path, output)
    split_path.unlink()
    print(f"modèles de test (sans valeur de détection) écrits dans {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
