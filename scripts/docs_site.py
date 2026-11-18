"""Crochets MkDocs du site de documentation (étape 6.7).

Les documents du dépôt sont écrits pour être lus **sur GitHub** : ils renvoient à des
fichiers hors de ``docs/`` (``../SECURITY.md``, ``../src/…``). Sur le site, ces liens
seraient cassés. Deux crochets, sans dupliquer aucun fichier :

- ``on_files`` publie les documents de la racine (politique de confidentialité,
  sécurité, contribution, journal des versions, code de conduite) comme pages du site ;
- ``on_page_markdown`` réécrit chaque lien relatif qui sort de ``docs/`` : vers la page
  du site s'il s'agit d'un de ces documents, sinon vers le fichier sur GitHub.

``mkdocs build --strict`` (CI) échoue sur tout lien restant introuvable.
"""

from __future__ import annotations

import os
import re
from pathlib import Path, PurePosixPath

from mkdocs.structure.files import File, Files

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
REPO_URL = "https://github.com/arixstoo/PhishGuard"
BRANCH = "master"

# Document de la racine → page du site (chemin dans docs/).
ROOT_PAGES = {
    "PRIVACY.md": "privacy.md",
    "SECURITY.md": "security.md",
    "CONTRIBUTING.md": "contributing.md",
    "CHANGELOG.md": "changelog.md",
    "CODE_OF_CONDUCT.md": "code-of-conduct.md",
}
_LINK = re.compile(r"(?<!!)\]\((?P<target>[^)\s]+)\)")
_FENCE = re.compile(r"^(```|~~~)", re.MULTILINE)
_EXTERNAL = re.compile(r"^(?:[a-z][a-z0-9+.-]*:|#|/)", re.IGNORECASE)


def on_files(files: Files, config) -> Files:
    for source, destination in ROOT_PAGES.items():
        files.append(File.generated(config, destination, abs_src_path=str(ROOT / source)))
    return files


def _rewrite(target: str, source: Path, page_dir: PurePosixPath) -> str:
    """Nouvelle cible d'un lien, ou la même s'il n'y a rien à changer."""
    if _EXTERNAL.match(target):
        return target
    path, _, anchor = target.partition("#")
    suffix = f"#{anchor}" if anchor else ""
    resolved = (source.parent / path).resolve()
    try:
        relative = resolved.relative_to(ROOT)
    except ValueError:
        return target  # hors du dépôt : laissé tel quel, le build strict le signalera
    if resolved.is_relative_to(DOCS):
        if source.is_relative_to(DOCS):
            return target  # lien interne au site, déjà correct
        destination = PurePosixPath(resolved.relative_to(DOCS).as_posix())
    elif relative.as_posix() in ROOT_PAGES:
        destination = PurePosixPath(ROOT_PAGES[relative.as_posix()])
    else:
        kind = "tree" if resolved.is_dir() else "blob"
        return f"{REPO_URL}/{kind}/{BRANCH}/{relative.as_posix()}{suffix}"
    return os.path.relpath(destination, page_dir).replace(os.sep, "/") + suffix


def on_page_markdown(markdown: str, page, config, files) -> str:
    source = Path(page.file.abs_src_path).resolve()
    page_dir = PurePosixPath(page.file.src_uri).parent
    # Les blocs de code ne sont pas touchés : un exemple peut contenir « ](… ».
    parts = _FENCE.split(markdown)
    out, inside = [], False
    for part in parts:
        if _FENCE.fullmatch(part):
            inside = not inside
            out.append(part)
        elif inside:
            out.append(part)
        else:
            out.append(
                _LINK.sub(
                    lambda m: f"]({_rewrite(m.group('target'), source, page_dir)})",
                    part,
                )
            )
    return "".join(out)
