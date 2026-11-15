"""Signature des modèles déployés (étape 4.12, docs/model-registry.md).

::

    # Une fois : paire de clés. La clé privée reste hors du dépôt (refusée dedans).
    PHISHGUARD_SIGNING_PASSPHRASE=... python scripts/sign_models.py keygen \\
        --private-key ~/.config/phishguard/model-signing.key --public-key keys/model-signing.pub

    # À chaque publication : manifeste et signature dans models/.
    PHISHGUARD_SIGNING_PASSPHRASE=... python scripts/sign_models.py sign \\
        --private-key ~/.config/phishguard/model-signing.key [--release 2026.11.12]

Le manifeste liste les modèles déployés (``phishguard.deployment``), leurs calibrations
et l'export JSON destiné à l'extension s'il existe (``make export``), avec version, date
d'entraînement, extracteur de features et métriques de test (``docs/metrics/``).

La phrase de passe se lit dans ``PHISHGUARD_SIGNING_PASSPHRASE``, jamais en argument : un
argument est visible de tous les utilisateurs (``ps``) et reste dans l'historique du shell.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from phishguard.registry import (
    PASSPHRASE_ENV,
    build_manifest,
    key_id,
    load_private_key,
    passphrase_from_env,
    public_key_raw_base64,
    write_private_key,
    write_public_key,
    write_signed_manifest,
)

ROOT = Path(__file__).resolve().parents[1]
METRICS_DIR = ROOT / "docs/metrics"
MAX_EMBEDDED_METRICS_BYTES = 64 * 1024


def _metrics(version: str) -> dict[str, Any] | None:
    """Métriques de test publiées du modèle, si elles existent et restent petites."""
    path = METRICS_DIR / f"{version}_test.json"
    if not path.is_file() or path.stat().st_size > MAX_EMBEDDED_METRICS_BYTES:
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def _model_entry(kind: str, version: str, models_dir: Path) -> dict[str, Any]:
    """Métadonnées d'un modèle, lues dans son fichier (de confiance : c'est le nôtre)."""
    from phishguard.deployment import model_files
    from phishguard.text.models import TextModel
    from phishguard.urls.features import FEATURE_EXTRACTOR_VERSION, reference_data_sha256
    from phishguard.urls.model import UrlModel

    path = model_files(models_dir)[kind].model
    model = (UrlModel if kind == "url" else TextModel).load(path)
    metadata = dict(model.metadata)
    if metadata.get("model_version") != version:
        raise SystemExit(f"{path} contient {metadata.get('model_version')!r}, {version!r} attendu")
    entry: dict[str, Any] = {
        "version": version,
        "trained_at": metadata.get("trained_at"),
        "metrics": _metrics(version),
    }
    if kind == "url":
        entry["feature_extractor"] = {
            "version": FEATURE_EXTRACTOR_VERSION,
            "reference_data_sha256": reference_data_sha256(),
            "features": list(model.feature_names),
        }
    return json.loads(json.dumps(entry, default=str))  # dates et numpy en JSON simple


def artifacts_to_sign(models_dir: Path) -> list[tuple[str, str]]:
    from phishguard.deployment import model_files

    artifacts: list[tuple[str, str]] = []
    for kind, files in model_files(models_dir).items():
        if not files.model.is_file():
            raise SystemExit(f"{files.model} introuvable : rien à signer")
        artifacts.append((files.model.name, f"{kind}-model"))
        if files.calibration.is_file():
            artifacts.append((files.calibration.name, f"{kind}-calibration"))
        exported = models_dir / f"{files.version}.json"
        if exported.is_file():
            artifacts.append((exported.name, f"{kind}-export"))
    return artifacts


def sign(models_dir: Path, private_key: Ed25519PrivateKey, release: str) -> Path:
    # Imports du pipeline ici seulement : keygen n'en a pas besoin et démarre en une
    # seconde, au lieu d'une minute depuis /mnt/c sous WSL.
    from phishguard.deployment import model_files
    from phishguard.fusion.score import default_config
    from phishguard.schema import SCHEMA_VERSION
    from phishguard.security.normalize import NORMALIZATION_VERSION

    models = {
        kind: _model_entry(kind, files.version, models_dir)
        for kind, files in model_files(models_dir).items()
    }
    manifest = build_manifest(
        models_dir,
        artifacts_to_sign(models_dir),
        release=release,
        models=models,
        extra={
            "schema_version": SCHEMA_VERSION,
            "fusion_version": default_config().version,
            "normalization_version": NORMALIZATION_VERSION,
        },
    )
    manifest_path, _ = write_signed_manifest(models_dir, manifest, private_key)
    return manifest_path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    keygen = commands.add_parser("keygen", help="crée la paire de clés Ed25519")
    keygen.add_argument("--private-key", type=Path, required=True)
    keygen.add_argument("--public-key", type=Path, required=True)
    signer = commands.add_parser("sign", help="écrit et signe models/manifest.json")
    signer.add_argument("--private-key", type=Path, required=True)
    signer.add_argument("--models-dir", type=Path, default=ROOT / "models")
    signer.add_argument("--release", default=datetime.now(UTC).strftime("%Y.%m.%d"))
    args = parser.parse_args(argv)
    passphrase = passphrase_from_env()

    if args.command == "keygen":
        if passphrase is None:
            print(
                f"attention : {PASSPHRASE_ENV} vide, clé privée NON chiffrée (droits 600)",
                file=sys.stderr,
            )
        key = Ed25519PrivateKey.generate()
        write_private_key(
            key, args.private_key.expanduser(), passphrase=passphrase, forbidden_dir=ROOT
        )
        write_public_key(key.public_key(), args.public_key)
        print(
            f"clé {key_id(key.public_key())} : privée {args.private_key}, publique {args.public_key}"
        )
        print(
            f"clé publique brute (extension, WebCrypto) : {public_key_raw_base64(key.public_key())}"
        )
        return 0

    key = load_private_key(args.private_key.expanduser(), passphrase=passphrase)
    manifest = sign(args.models_dir, key, args.release)
    print(f"{manifest} signé (clé {key_id(key.public_key())}, publication {args.release})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
