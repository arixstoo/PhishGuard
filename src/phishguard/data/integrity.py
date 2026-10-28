"""Contrôles d'intégrité communs aux jeux de données."""

from __future__ import annotations

import hashlib
import io
import zipfile
from pathlib import Path

import httpx

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


def download_bounded(client: httpx.Client, url: str, max_bytes: int) -> bytes:
    """Télécharge ``url`` en flux et s'arrête dès que ``max_bytes`` est dépassé."""
    buffer = bytearray()
    with client.stream("GET", url) as response:
        response.raise_for_status()
        for chunk in response.iter_bytes():
            buffer.extend(chunk)
            if len(buffer) > max_bytes:
                raise DatasetIntegrityError(f"archive anormalement volumineuse : {url}")
    return bytes(buffer)


def download_zip_member(
    url: str,
    member: str,
    expected_sha256: str,
    dest: Path,
    *,
    max_download_bytes: int,
    max_member_bytes: int,
    client: httpx.Client | None = None,
    timeout: float = 60.0,
) -> Path:
    """Télécharge une archive zip, en extrait ``member`` et vérifie son SHA-256.

    - ne fait rien si ``dest`` existe déjà avec la bonne empreinte ;
    - le téléchargement est interrompu au-delà de ``max_download_bytes`` ;
    - seul ``member`` est lu, sans ``extractall()`` : pas de « zip slip » (chemins ``../``) ;
    - sa taille déclarée est bornée par ``max_member_bytes`` avant décompression (bombe zip) ;
    - ``dest`` n'est écrit que si l'empreinte correspond : jamais de fichier inconnu sur disque.
    """
    dest = Path(dest)
    if dest.is_file() and sha256_file(dest) == expected_sha256:
        return dest

    owns_client = client is None
    client = client or httpx.Client(timeout=timeout, follow_redirects=True)
    try:
        content = download_bounded(client, url, max_download_bytes)
    finally:
        if owns_client:
            client.close()

    try:
        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            if archive.getinfo(member).file_size > max_member_bytes:
                raise DatasetIntegrityError(f"{member} anormalement volumineux")
            payload = archive.read(member)
    except (zipfile.BadZipFile, KeyError) as exc:
        raise DatasetIntegrityError(f"archive invalide ou sans {member} : {url}") from exc

    digest = sha256_bytes(payload)
    if digest != expected_sha256:
        raise DatasetIntegrityError(
            f"SHA-256 inattendu pour {member} : {digest} (attendu {expected_sha256})"
        )

    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(payload)
    return dest
