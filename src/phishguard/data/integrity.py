"""Contrôles d'intégrité communs aux jeux de données."""

from __future__ import annotations

import hashlib
from pathlib import Path

_CHUNK_SIZE = 1024 * 1024


class DatasetIntegrityError(RuntimeError):
    """Le fichier obtenu ne correspond pas à l'empreinte attendue."""


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    """Empreinte SHA-256 d'un fichier, lu par blocs pour borner la mémoire."""
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        while chunk := handle.read(_CHUNK_SIZE):
            digest.update(chunk)
    return digest.hexdigest()
