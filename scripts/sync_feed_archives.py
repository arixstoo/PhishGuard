"""Rapatrie en local les archives chiffrées produites par le workflow fetch-feeds.

Les artefacts GitHub expirent après 90 jours : lance ce script au moins une fois par mois
pour conserver tout l'historique dans data/raw/ (nécessaire au split temporel).

Prérequis : `gh` connecté (gh auth login), `openssl` dans le PATH (fourni par Git for
Windows), et la variable ARCHIVE_PASSPHRASE (dans .env ou l'environnement), identique au
secret du dépôt.

Usage:
    python scripts/sync_feed_archives.py
    python scripts/sync_feed_archives.py --output-dir data/raw --repo arixstoo/PhishGuard
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path, PurePosixPath

logger = logging.getLogger("sync_feed_archives")

DEFAULT_REPO = "arixstoo/PhishGuard"
ARTIFACT_PREFIX = "feeds-"
STATE_FILE = ".synced_artifacts"
OPENSSL_CANDIDATES = [
    r"C:\Program Files\Git\usr\bin\openssl.exe",
    r"C:\Program Files\Git\mingw64\bin\openssl.exe",
]


def load_env_file(path: Path = Path(".env")) -> None:
    """Charge les variables d'un fichier .env s'il existe (sans écraser l'environnement)."""
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, val = line.split("=", 1)
            os.environ.setdefault(key.strip(), val.strip().strip('"').strip("'"))


def find_openssl() -> str:
    found = os.environ.get("OPENSSL") or shutil.which("openssl")
    if found:
        return found
    for candidate in OPENSSL_CANDIDATES:
        if Path(candidate).exists():
            return candidate
    raise FileNotFoundError("openssl introuvable : installez Git for Windows ou définissez OPENSSL")


def list_artifacts(repo: str) -> list[dict]:
    """Artefacts fetch-feeds encore disponibles, du plus ancien au plus récent."""
    out = subprocess.run(
        ["gh", "api", f"repos/{repo}/actions/artifacts", "--paginate", "--jq", ".artifacts[]"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    artifacts = [json.loads(line) for line in out.splitlines() if line.strip()]
    return sorted(
        (a for a in artifacts if a["name"].startswith(ARTIFACT_PREFIX) and not a["expired"]),
        key=lambda a: a["created_at"],
    )


def decrypt(src: Path, dest: Path, passphrase: str, openssl: str) -> None:
    """Déchiffre une archive produite par `openssl enc -aes-256-cbc -pbkdf2 -iter 200000`."""
    subprocess.run(
        [openssl, "enc", "-d", "-aes-256-cbc", "-pbkdf2", "-iter", "200000"]
        + ["-in", str(src), "-out", str(dest), "-pass", "env:ARCHIVE_PASSPHRASE"],
        check=True,
        capture_output=True,
        env={**os.environ, "ARCHIVE_PASSPHRASE": passphrase},
    )


def extract_feeds(tar_path: Path, output_dir: Path) -> list[str]:
    """Copie les fichiers raw/<nom> de l'archive dans output_dir, sans rien écraser.

    Seuls les fichiers réguliers directement sous raw/ sont acceptés : une archive
    malformée ne peut pas écrire ailleurs (chemins absolus, '..', liens).
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    added = []
    with tarfile.open(tar_path, "r:gz") as tar:
        for member in tar.getmembers():
            parts = PurePosixPath(member.name).parts
            if not member.isfile() or len(parts) != 2 or parts[0] != "raw":
                continue
            name = parts[1]
            if name.startswith(".") or "\\" in name:
                continue
            dest = output_dir / name
            if dest.exists():
                continue
            source = tar.extractfile(member)
            if source is None:
                continue
            dest.write_bytes(source.read())
            added.append(name)
    return added


def read_state(output_dir: Path) -> set[str]:
    path = output_dir / STATE_FILE
    return set(path.read_text(encoding="utf-8").split()) if path.exists() else set()


def sync(repo: str, output_dir: Path, passphrase: str, openssl: str) -> int:
    done = read_state(output_dir)
    pending = [a for a in list_artifacts(repo) if a["name"] not in done]
    logger.info("%d archive(s) à rapatrier", len(pending))
    for artifact in pending:
        name = artifact["name"]
        run_id = str(artifact["workflow_run"]["id"])
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            subprocess.run(
                ["gh", "run", "download", run_id, "-R", repo, "-n", name, "-D", str(tmp_dir)],
                check=True,
                capture_output=True,
            )
            encrypted = next(tmp_dir.glob("*.tar.gz.enc"), None)
            if encrypted is None:
                logger.warning("%s : pas d'archive chiffrée (ancien format ?), ignoré", name)
                continue
            archive = tmp_dir / "feeds.tar.gz"
            decrypt(encrypted, archive, passphrase, openssl)
            added = extract_feeds(archive, output_dir)
        with (output_dir / STATE_FILE).open("a", encoding="utf-8") as fh:
            fh.write(name + "\n")
        logger.info("%s : %d fichier(s) ajouté(s)", name, len(added))
    return 0


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    load_env_file()
    parser = argparse.ArgumentParser(description="Rapatrie les archives fetch-feeds.")
    parser.add_argument("--repo", default=DEFAULT_REPO)
    parser.add_argument("--output-dir", default="data/raw")
    args = parser.parse_args(argv)

    passphrase = os.environ.get("ARCHIVE_PASSPHRASE")
    if not passphrase:
        logger.error("ARCHIVE_PASSPHRASE absent (.env ou environnement)")
        return 1
    try:
        return sync(args.repo, Path(args.output_dir), passphrase, find_openssl())
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        logger.error("Échec : %s", exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
