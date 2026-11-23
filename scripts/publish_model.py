"""Signe et publie un modèle candidat du workflow model-update (étape 6.8).

À lancer **sur la machine de signature**, la seule qui a la clé privée :

    export PHISHGUARD_SIGNING_PASSPHRASE='…'
    python scripts/publish_model.py publish 2026.12.02 \\
        --private-key ~/.config/phishguard/model-signing.key [--dry-run]

    # Une fois, avant le premier réentraînement : publier les modèles signés actuels
    # (models/) comme canal « models-stable », référence du garde-fou et des extensions.
    python scripts/publish_model.py bootstrap

``publish`` refuse de signer si une seule vérification échoue :

1. empreintes de ``SHA256SUMS`` (fichiers téléchargés intacts) ;
2. **provenance** : ``gh attestation verify`` prouve que le modèle sort du workflow
   ``model-update.yml`` de ce dépôt, et pas d'un fichier déposé à la main dans la
   release brouillon ;
3. rapport du garde-fou : ``passed`` vrai ;
4. modèle texte inchangé, repris du canal en service **après** vérification de sa
   signature.

Puis il écrit le manifeste (``phishguard.registry``), le signe, le revérifie, l'ajoute à
la release datée, la publie, et remplace les fichiers du canal ``models-stable`` que
lisent l'API et les extensions. Pendant le remplacement, un client peut voir un manifeste
et un modèle de deux publications différentes : il les refuse (empreinte), sans danger,
et réessaie le lendemain.

Prérequis : ``gh`` connecté avec accès en écriture au dépôt.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from phishguard.deployment import DEPLOYED_MODELS, model_files
from phishguard.registry import (
    MANIFEST_NAME,
    SIGNATURE_NAME,
    build_manifest,
    key_id,
    load_private_key,
    load_public_key,
    passphrase_from_env,
    verify_manifest,
    write_signed_manifest,
)

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_REPO = "arixstoo/PhishGuard"
CHANNEL = "models-stable"
WORKFLOW = ".github/workflows/model-update.yml"
RELEASE_RE = re.compile(r"^\d{4}\.\d{2}\.\d{2}(?:\.\d{1,3})?$")
ATTESTED = ("url_v2.joblib", "url_v2_calibration.json", "url_v2.json", "gate_report.json")


class PublishError(RuntimeError):
    pass


def gh(*args: str, capture: bool = False) -> str:
    """Appel de GitHub CLI ; liste d'arguments, jamais de shell."""
    result = subprocess.run(["gh", *args], check=False, text=True, capture_output=True)
    if result.returncode != 0:
        raise PublishError(f"gh {' '.join(args[:3])}… : {result.stderr.strip()}")
    return result.stdout if capture else ""


def check_sums(directory: Path) -> None:
    """Chaque fichier listé correspond à son empreinte, et rien n'est en trop."""
    listed: dict[str, str] = {}
    for line in (directory / "SHA256SUMS").read_text(encoding="utf-8").splitlines():
        digest, name = line.split(maxsplit=1)
        listed[name.lstrip("*")] = digest
    present = {p.name for p in directory.iterdir() if p.name != "SHA256SUMS"}
    if missing := set(listed) - present:
        raise PublishError(f"fichiers absents de la release : {sorted(missing)}")
    if unlisted := present - set(listed):
        raise PublishError(f"fichiers non listés dans SHA256SUMS : {sorted(unlisted)}")
    for name, digest in listed.items():
        if hashlib.sha256((directory / name).read_bytes()).hexdigest() != digest:
            raise PublishError(f"{name} : empreinte différente de SHA256SUMS")


def check_gate(directory: Path) -> dict:
    report = json.loads((directory / "gate_report.json").read_text(encoding="utf-8"))
    if report.get("passed") is not True:
        raise PublishError("le rapport du garde-fou ne dit pas « passed » : publication refusée")
    return report


def stage_text_model(staging: Path, repo: str, public_key: Path) -> None:
    """Le modèle texte ne change pas : repris du canal en service, signature vérifiée."""
    current = staging / "_current"
    current.mkdir()
    text = model_files(current)["text"]
    names = [MANIFEST_NAME, SIGNATURE_NAME, text.model.name, text.calibration.name]
    gh("release", "download", CHANNEL, "--repo", repo, "--dir", str(current),
       *[arg for name in names for arg in ("--pattern", name)])  # fmt: skip
    verified = verify_manifest(current, load_public_key(public_key))
    for name in names[2:]:
        (staging / name).write_bytes(verified.read(name))
    shutil.rmtree(current)


def url_model_entry(staging: Path, gate: dict) -> dict:
    """Entrée du manifeste : métadonnées du modèle et chiffres **du garde-fou**."""
    sys.path.insert(0, str(Path(__file__).parent))
    from sign_models import _model_entry  # même description que `make sign`

    entry = _model_entry("url", DEPLOYED_MODELS["url"], staging)
    candidate = gate["candidate"]
    entry["metrics"] = {
        "gate_version": gate["gate_version"],
        "recall_at_fpr_1pct_frozen": candidate["recall_frozen"],
        "recall_at_fpr_1pct_recent": candidate["recall_recent"],
        "legitimate_false_positives": len(candidate["legitimate_false_positives"]),
    }
    return entry


def sign_staging(staging: Path, release: str, gate: dict, private_key: Path) -> None:
    sys.path.insert(0, str(Path(__file__).parent))
    from sign_models import _model_entry, artifacts_to_sign

    from phishguard.fusion.score import default_config
    from phishguard.schema import SCHEMA_VERSION
    from phishguard.security.normalize import NORMALIZATION_VERSION

    key = load_private_key(private_key, passphrase=passphrase_from_env())
    manifest = build_manifest(
        staging,
        artifacts_to_sign(staging),
        release=release,
        models={
            "url": url_model_entry(staging, gate),
            "text": _model_entry("text", DEPLOYED_MODELS["text"], staging),
        },
        extra={
            "schema_version": SCHEMA_VERSION,
            "fusion_version": default_config().version,
            "normalization_version": NORMALIZATION_VERSION,
        },
    )
    write_signed_manifest(staging, manifest, key)  # relu et vérifié avant de rendre la main
    print(f"manifeste signé : publication {release}, clé {key_id(key.public_key())}")


def channel_files(staging: Path) -> list[Path]:
    """Fichiers du canal : artefacts signés, puis manifeste et signature en dernier."""
    manifest = json.loads((staging / MANIFEST_NAME).read_text(encoding="utf-8"))
    artifacts = [staging / a["name"] for a in manifest["artifacts"]]
    return [*artifacts, staging / MANIFEST_NAME, staging / SIGNATURE_NAME]


def publish(args: argparse.Namespace) -> int:
    if not RELEASE_RE.fullmatch(args.release):
        raise PublishError(f"publication invalide : {args.release} (attendu AAAA.MM.JJ[.N])")
    tag = f"model-{args.release}"
    with tempfile.TemporaryDirectory(prefix="phishguard-publish-") as tmp:
        downloaded = Path(tmp) / "release"
        downloaded.mkdir()
        gh("release", "download", tag, "--repo", args.repo, "--dir", str(downloaded))
        check_sums(downloaded)
        for name in ATTESTED:
            gh("attestation", "verify", str(downloaded / name), "--repo", args.repo,
               "--signer-workflow", f"{args.repo}/{WORKFLOW}")  # fmt: skip
        gate = check_gate(downloaded)
        print("empreintes, provenance et garde-fou : vérifiés")

        staging = Path(tmp) / "staging"
        staging.mkdir()
        for name in ("url_v2.joblib", "url_v2_calibration.json", "url_v2.json"):
            shutil.copy2(downloaded / name, staging / name)
        stage_text_model(staging, args.repo, args.public_key)
        sign_staging(staging, args.release, gate, args.private_key)
        # Contrôle final avec la clé publique **du dépôt** (celle des extensions et de l'API).
        verify_manifest(staging, load_public_key(args.public_key)).verify_all()

        if args.dry_run:
            print(f"--dry-run : rien n'est publié ({staging} est effacé)")
            return 0
        signature = [str(staging / MANIFEST_NAME), str(staging / SIGNATURE_NAME)]
        gh("release", "upload", tag, *signature, "--repo", args.repo, "--clobber")
        gh("release", "edit", tag, "--repo", args.repo, "--draft=false", "--latest=false",
           "--title", f"Modèle URL {args.release}")  # fmt: skip
        upload_channel(staging, args.repo, args.release)
    print(f"publié : {tag}, et canal {CHANNEL} mis à jour")
    return 0


def upload_channel(staging: Path, repo: str, release: str) -> None:
    exists = subprocess.run(
        ["gh", "release", "view", CHANNEL, "--repo", repo], check=False, capture_output=True
    )
    if exists.returncode != 0:
        gh("release", "create", CHANNEL, "--repo", repo, "--prerelease", "--latest=false",
           "--title", "Modèles en service (canal signé)",
           "--notes", "Modèles signés lus par l'API et par l'extension (mises à jour du "
           "modèle). Chaque fichier est vérifié par la signature Ed25519 de manifest.json.")  # fmt: skip
    for path in channel_files(staging):
        gh("release", "upload", CHANNEL, str(path), "--repo", repo, "--clobber")
    gh("release", "edit", CHANNEL, "--repo", repo, "--notes",
       f"Publication en service : {release}. Fichiers vérifiés par la signature Ed25519 de "
       "manifest.json (clé : keys/model-signing.pub).")  # fmt: skip


def bootstrap(args: argparse.Namespace) -> int:
    """Publie les modèles signés locaux comme canal en service (première fois)."""
    verified = verify_manifest(args.models_dir, load_public_key(args.public_key))
    verified.verify_all()
    if not RELEASE_RE.fullmatch(verified.release):
        raise PublishError(f"publication {verified.release} : format daté AAAA.MM.JJ requis")
    print(f"modèles signés vérifiés : publication {verified.release}")
    if args.dry_run:
        print("--dry-run : rien n'est publié")
        return 0
    upload_channel(args.models_dir, args.repo, verified.release)
    print(f"canal {CHANNEL} publié")
    return 0


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--repo", default=DEFAULT_REPO)
    parser.add_argument("--public-key", type=Path, default=ROOT / "keys/model-signing.pub")
    parser.add_argument("--dry-run", action="store_true", help="tout vérifier, ne rien publier")
    sub = parser.add_subparsers(dest="command", required=True)

    pub = sub.add_parser("publish", help="signe et publie un candidat du workflow")
    pub.add_argument("release", help="AAAA.MM.JJ[.N], celle de la release brouillon")
    pub.add_argument(
        "--private-key",
        type=Path,
        default=Path.home() / ".config/phishguard/model-signing.key",
    )
    pub.set_defaults(func=publish)

    boot = sub.add_parser("bootstrap", help="publie models/ comme canal en service")
    boot.add_argument("--models-dir", type=Path, default=ROOT / "models")
    boot.set_defaults(func=bootstrap)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        return args.func(args)
    except (PublishError, OSError, ValueError) as error:
        print(f"publish_model : {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
