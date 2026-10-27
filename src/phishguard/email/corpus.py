"""Lecture des corpus d'emails : dossiers, mbox et archives tar (étape 1.11).

Formats des corpus publics :

- **dossier** d'un fichier par email (SpamAssassin une fois extrait, Phishing Pot) ;
- **mbox** (Nazario) : emails concaténés, chacun commençant par une ligne ``From `` ;
- **archive** ``.tar``, ``.tar.gz``, ``.tar.bz2`` (SpamAssassin tel que publié), lue
  **en mémoire, sans extraction** : aucun chemin de l'archive n'est écrit sur le disque,
  ce qui écarte les attaques par chemin (``../../``) et par lien symbolique.

Chaque email est lu comme des octets, borné à ``max_bytes`` (les plus gros sont ignorés
et comptés). Les doublons exacts (même SHA-256) sont retirés à la lecture : un même email
publié deux fois ne doit pas tomber à la fois en entraînement et en test.
"""

from __future__ import annotations

import hashlib
import mailbox
import tarfile
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_MAX_BYTES = 10 * 1024 * 1024
# Fichiers d'index des corpus, qui ne sont pas des emails.
SKIPPED_NAMES = frozenset({"cmds", "manifest.json", "readme", "readme.txt", "license"})
TAR_SUFFIXES = (".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2")
MBOX_SUFFIXES = (".mbox", ".mbx")


@dataclass(frozen=True)
class RawEmail:
    source: str
    name: str  # chemin dans le corpus, pour retrouver l'email (jamais publié)
    raw: bytes

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.raw).hexdigest()


@dataclass
class ReadStats:
    read: int = 0
    duplicates: int = 0
    too_large: int = 0
    skipped: int = 0
    by_source: dict[str, int] = field(default_factory=dict)


def _is_tar(path: Path) -> bool:
    return path.name.lower().endswith(TAR_SUFFIXES)


def _is_mbox(path: Path) -> bool:
    if path.name.lower().endswith(MBOX_SUFFIXES):
        return True
    # Les fichiers de Nazario n'ont pas toujours d'extension (« phishing-2023 ») :
    # une mbox commence par une ligne « From ».
    try:
        with path.open("rb") as handle:
            return handle.read(5) == b"From "
    except OSError:
        return False


def _iter_tar(path: Path, max_bytes: int, stats: ReadStats) -> Iterator[tuple[str, bytes]]:
    with tarfile.open(path, mode="r:*") as archive:
        for member in archive:
            if not member.isfile() or Path(member.name).name.lower() in SKIPPED_NAMES:
                stats.skipped += 1
                continue
            if member.size > max_bytes:
                stats.too_large += 1
                continue
            handle = archive.extractfile(member)
            if handle is not None:
                yield member.name, handle.read(max_bytes + 1)


def _iter_mbox(path: Path, max_bytes: int, stats: ReadStats) -> Iterator[tuple[str, bytes]]:
    box = mailbox.mbox(path, create=False)
    try:
        for key in box.iterkeys():
            data = box.get_bytes(key)
            if len(data) > max_bytes:
                stats.too_large += 1
                continue
            yield f"{path.name}#{key}", data
    finally:
        box.close()


def _iter_dir(path: Path, max_bytes: int, stats: ReadStats) -> Iterator[tuple[str, bytes]]:
    for file in sorted(p for p in path.rglob("*") if p.is_file() and not p.is_symlink()):
        if file.name.lower() in SKIPPED_NAMES or file.name.startswith("."):
            stats.skipped += 1
            continue
        if _is_tar(file) or (file.suffix.lower() in MBOX_SUFFIXES):
            yield from iter_path(file, max_bytes, stats)
            continue
        if file.stat().st_size > max_bytes:
            stats.too_large += 1
            continue
        yield str(file.relative_to(path)), file.read_bytes()


def iter_path(path: Path, max_bytes: int, stats: ReadStats) -> Iterator[tuple[str, bytes]]:
    """``(nom, octets)`` de chaque email d'un dossier, d'une mbox ou d'une archive."""
    path = Path(path)
    if path.is_dir():
        yield from _iter_dir(path, max_bytes, stats)
    elif _is_tar(path):
        yield from _iter_tar(path, max_bytes, stats)
    elif _is_mbox(path):
        yield from _iter_mbox(path, max_bytes, stats)
    elif path.is_file():
        if path.stat().st_size > max_bytes:
            stats.too_large += 1
        else:
            yield path.name, path.read_bytes()
    else:
        raise FileNotFoundError(path)


def read_corpus(
    sources: list[tuple[str, Path]], *, max_bytes: int = DEFAULT_MAX_BYTES
) -> tuple[list[RawEmail], ReadStats]:
    """Emails de chaque ``(nom de source, chemin)``, sans doublon exact entre sources.

    Un email présent dans deux sources est gardé dans la première : l'ordre des sources
    est donc une priorité.
    """
    stats = ReadStats()
    seen: set[str] = set()
    emails: list[RawEmail] = []
    for source, path in sources:
        for name, raw in iter_path(path, max_bytes, stats):
            if len(raw) > max_bytes:
                stats.too_large += 1
                continue
            email = RawEmail(source, name, raw)
            if email.sha256 in seen:
                stats.duplicates += 1
                continue
            seen.add(email.sha256)
            emails.append(email)
            stats.read += 1
            stats.by_source[source] = stats.by_source.get(source, 0) + 1
    return emails, stats
