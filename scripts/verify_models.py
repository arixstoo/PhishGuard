"""Vérifie le manifeste signé des modèles (étape 4.12, docs/model-registry.md).

::

    python scripts/verify_models.py [--models-dir models] [--public-key keys/model-signing.pub]

Code de sortie 0 si la signature Ed25519 du manifeste est valide **et** que chaque
fichier listé a exactement la taille et l'empreinte SHA-256 signées ; 1 sinon, avec la
raison. Un seul octet modifié, dans le manifeste, la signature ou un modèle, suffit à
échouer. Rien n'est désérialisé : la vérification ne lit que des octets.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from phishguard.registry import ManifestError, load_public_key, verify_manifest

ROOT = Path(__file__).resolve().parents[1]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--models-dir", type=Path, default=ROOT / "models")
    parser.add_argument("--public-key", type=Path, default=ROOT / "keys/model-signing.pub")
    args = parser.parse_args(argv)
    try:
        verified = verify_manifest(args.models_dir, load_public_key(args.public_key))
    except (ManifestError, OSError, ValueError, TypeError) as exc:
        print(f"ÉCHEC : {exc}", file=sys.stderr)
        return 1
    print(
        f"manifeste {verified.release} valide (clé {verified.key_id}) : "
        f"{len(verified.artifacts)} fichiers vérifiés"
    )
    for artifact in verified.artifacts.values():
        print(f"  {artifact.sha256}  {artifact.size:>10}  {artifact.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
