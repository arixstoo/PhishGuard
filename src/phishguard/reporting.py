"""Rendu des résultats dans la documentation.

Les tableaux de résultats de ``docs/`` sont produits par les scripts, jamais recopiés à
la main : un chiffre de la doc correspond toujours au rapport JSON de
``docs/metrics/``. Chaque document contient un bloc délimité par deux marqueurs :

    <!-- generated:train-url:start -->
    ...remplacé à chaque exécution...
    <!-- generated:train-url:end -->

Le texte hors des marqueurs (méthode, lecture des résultats) reste écrit à la main.
Les nombres suivent la typographie française des autres documents (``0,952``, ``6,9 %``).
"""

from __future__ import annotations

import math
import re
from collections.abc import Sequence
from pathlib import Path

_ALIGN = {"left": ":---", "right": "---:", "center": ":---:"}


class MissingMarkersError(ValueError):
    """Le document ne contient pas (ou pas une seule fois) les marqueurs du bloc."""


def fr_number(value: float | None, digits: int = 3) -> str:
    """``0.9523`` → ``0,952`` ; ``None`` ou NaN → ``n/d``."""
    if value is None or (isinstance(value, float) and math.isnan(value)):
        return "n/d"
    return f"{value:,.{digits}f}".replace(",", " ").replace(".", ",")


def fr_percent(value: float | None, digits: int = 1) -> str:
    """``0.0687`` → ``6,9 %`` (espace avant le signe, comme dans les autres documents)."""
    if value is None or (isinstance(value, float) and math.isnan(value)):
        return "n/d"
    return f"{fr_number(value * 100, digits)} %"


def fr_int(value: int) -> str:
    """``21007`` → ``21 007``."""
    return f"{value:,d}".replace(",", " ")


def markdown_table(
    headers: Sequence[str], rows: Sequence[Sequence[object]], align: Sequence[str] | None = None
) -> str:
    """Tableau Markdown ; ``align`` donne ``left``, ``right`` ou ``center`` par colonne."""
    align = align or ["left"] + ["right"] * (len(headers) - 1)
    if len(align) != len(headers):
        raise ValueError("align doit avoir une entrée par colonne")
    for row in rows:
        if len(row) != len(headers):
            raise ValueError("chaque ligne doit avoir une cellule par colonne")

    def line(cells: Sequence[object]) -> str:
        return "| " + " | ".join(str(c).replace("|", "\\|") for c in cells) + " |"

    return "\n".join(
        [line(headers), "| " + " | ".join(_ALIGN[a] for a in align) + " |", *map(line, rows)]
    )


def _markers(name: str) -> tuple[str, str]:
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]*", name):
        raise ValueError(f"nom de bloc invalide : {name!r}")
    return f"<!-- generated:{name}:start -->", f"<!-- generated:{name}:end -->"


def replace_generated_block(text: str, name: str, content: str) -> str:
    """Remplace le contenu du bloc ``name`` de ``text`` par ``content``."""
    start, end = _markers(name)
    if text.count(start) != 1 or text.count(end) != 1 or text.index(start) > text.index(end):
        raise MissingMarkersError(f"marqueurs du bloc {name!r} absents, répétés ou inversés")
    before, rest = text.split(start, 1)
    _, after = rest.split(end, 1)
    return f"{before}{start}\n{content.strip()}\n{end}{after}"


def update_generated_block(path: Path, name: str, content: str) -> None:
    """Réécrit le bloc ``name`` du fichier ``path`` (UTF-8, fins de ligne conservées)."""
    path = Path(path)
    text = path.read_bytes().decode("utf-8")
    newline = "\r\n" if "\r\n" in text else "\n"
    updated = replace_generated_block(text.replace("\r\n", "\n"), name, content)
    path.write_bytes(updated.replace("\n", newline).encode("utf-8"))
