"""Rapatrie en local les archives chiffrées produites par le workflow fetch-feeds.

Les artefacts GitHub expirent après 90 jours : lance ce script au moins une fois par mois
pour conserver tout l'historique dans data/raw/ (nécessaire au split temporel).
Seuls les artefacts du workflow fetch-feeds.yml lui-même (planifié ou manuel, sur la branche
par défaut du dépôt) sont acceptés : ceux d'une PR, d'un fork ou d'un autre workflow sont ignorés.

Prérequis : `gh` connecté (gh auth login), `openssl` dans le PATH (fourni par Git for
Windows), et la variable ARCHIVE_PASSPHRASE (dans .env ou l'environnement), identique au
secret du dépôt.

Usage:
    python scripts/sync_feed_archives.py
    python scripts/sync_feed_archives.py --output-dir data/raw --repo arixstoo/PhishGuard
"""

from __future__ import annotations

import argparse
import gzip
import json
import logging
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import zlib
from pathlib import Path, PurePosixPath

logger = logging.getLogger("sync_feed_archives")

DEFAULT_REPO = "arixstoo/PhishGuard"
ARTIFACT_PREFIX = "feeds-"
STATE_FILE = ".synced_artifacts"
# Le nom « feeds-* » ne prouve rien : une PR (y compris depuis un fork) exécute sa propre
# copie des workflows et peut déposer un artefact de ce nom dans le dépôt. Seuls les runs de
# ce workflow, planifiés ou lancés à la main sur la branche par défaut du dépôt, sont acceptés.
WORKFLOW_FILE = "fetch-feeds.yml"
TRUSTED_EVENTS = ("schedule", "workflow_dispatch")
# Archive indéchiffrable ou tar.gz corrompu : on l'ignore sans bloquer les suivantes.
ARCHIVE_ERRORS = (
    subprocess.CalledProcessError,
    tarfile.TarError,
    EOFError,
    zlib.error,
    gzip.BadGzipFile,
)
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


class GitHubApiError(RuntimeError):
    """Réponse de l'API GitHub inexploitable."""


def gh_api(path: str) -> dict:
    # L'API répond en UTF-8 ; sans ``encoding``, Windows décoderait en cp1252 et un titre de
    # commit avec un emoji ferait échouer la lecture (``stdout`` vaudrait ``None``).
    out = subprocess.run(
        ["gh", "api", path], check=True, capture_output=True, encoding="utf-8", errors="replace"
    ).stdout
    try:
        data = json.loads(out or "")
    except json.JSONDecodeError as exc:
        raise GitHubApiError(f"réponse JSON invalide pour {path}") from exc
    if not isinstance(data, dict):
        raise GitHubApiError(f"réponse inattendue pour {path}")
    return data


def trusted_origin(repo: str) -> dict:
    """Identifiants attendus d'un run légitime : dépôt, branche par défaut et workflow."""
    info = gh_api(f"repos/{repo}")
    workflow = gh_api(f"repos/{repo}/actions/workflows/{WORKFLOW_FILE}")
    origin = {
        "repo_id": info.get("id"),
        "default_branch": info.get("default_branch"),
        "workflow_id": workflow.get("id"),
    }
    if not (
        isinstance(origin["repo_id"], int)
        and isinstance(origin["workflow_id"], int)
        and isinstance(origin["default_branch"], str)
        and origin["default_branch"]
    ):
        raise GitHubApiError(f"identifiants du dépôt {repo} ou de {WORKFLOW_FILE} introuvables")
    return origin


def is_trusted_run(run: dict, origin: dict) -> bool:
    """Vrai si le run vient de fetch-feeds.yml, planifié ou manuel, sur la branche par défaut
    du dépôt lui-même (ni fork, ni PR, ni autre workflow, ni autre branche)."""
    head_repo = run.get("head_repository")
    repository = run.get("repository")
    return (
        run.get("workflow_id") == origin["workflow_id"]
        and run.get("event") in TRUSTED_EVENTS
        and run.get("head_branch") == origin["default_branch"]
        and isinstance(head_repo, dict)
        and head_repo.get("id") == origin["repo_id"]
        and isinstance(repository, dict)
        and repository.get("id") == origin["repo_id"]
    )


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


def copy_plain_files(src_dir: Path, output_dir: Path) -> list[str]:
    """Copie les fichiers d'un artefact non chiffré (ancien format), sans rien écraser."""
    output_dir.mkdir(parents=True, exist_ok=True)
    added = []
    for path in sorted(src_dir.iterdir()):
        dest = output_dir / path.name
        if path.is_file() and not path.is_symlink() and not dest.exists():
            shutil.copyfile(path, dest)
            added.append(path.name)
    return added


def read_state(output_dir: Path) -> set[str]:
    path = output_dir / STATE_FILE
    return set(path.read_text(encoding="utf-8").split()) if path.exists() else set()


def sync(repo: str, output_dir: Path, passphrase: str, openssl: str) -> int:
    done = read_state(output_dir)
    pending = [a for a in list_artifacts(repo) if a["name"] not in done]
    logger.info("%d archive(s) à rapatrier", len(pending))
    if not pending:
        return 0
    origin = trusted_origin(repo)
    failed = 0
    for artifact in pending:
        name = artifact["name"]
        run_id = (artifact.get("workflow_run") or {}).get("id")
        # Provenance vérifiée avant tout téléchargement ; un artefact refusé n'est pas noté
        # dans STATE_FILE (il ne peut donc pas masquer un artefact légitime du même nom).
        if not isinstance(run_id, int) or not is_trusted_run(
            gh_api(f"repos/{repo}/actions/runs/{run_id}"), origin
        ):
            logger.warning(
                "%s ignoré : ne provient pas de %s (planifié ou manuel, branche par défaut)",
                name,
                WORKFLOW_FILE,
            )
            continue
        run_id = str(run_id)
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            subprocess.run(
                ["gh", "run", "download", run_id, "-R", repo, "-n", name, "-D", str(tmp_dir)],
                check=True,
                capture_output=True,
            )
            encrypted = next(tmp_dir.glob("*.tar.gz.enc"), None)
            if encrypted is None:
                # Ancien format (avant chiffrement) : fichiers bruts à la racine de l'artefact,
                # acceptés uniquement parce que le run a été vérifié ci-dessus.
                added = copy_plain_files(tmp_dir, output_dir)
            else:
                archive = tmp_dir / "feeds.tar.gz"
                try:
                    decrypt(encrypted, archive, passphrase, openssl)
                    added = extract_feeds(archive, output_dir)
                except ARCHIVE_ERRORS as exc:
                    # Non noté dans STATE_FILE : retenté au prochain passage.
                    logger.error("%s : archive illisible, ignorée (%s)", name, exc)
                    failed += 1
                    continue
        with (output_dir / STATE_FILE).open("a", encoding="utf-8") as fh:
            fh.write(name + "\n")
        logger.info("%s : %d fichier(s) ajouté(s)", name, len(added))
    if failed:
        logger.error(
            "%d archive(s) illisible(s), retentée(s) au prochain passage (ARCHIVE_PASSPHRASE ?)",
            failed,
        )
        return 1
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
    except (subprocess.CalledProcessError, FileNotFoundError, GitHubApiError) as exc:
        logger.error("Échec : %s", exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
