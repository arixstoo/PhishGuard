"""Liens d'un message Telegram (étape 5.11).

Deux sources, dans l'ordre du message :

1. **les entités de Telegram** : ``url`` (adresse écrite dans le texte, que Telegram a
   reconnue, avec ou sans schéma) et surtout ``text_link``, un lien **caché derrière un
   texte**. C'est le leurre le plus courant d'un message transféré : « Suivre mon colis »
   qui mène ailleurs. Le texte seul ne le montre pas ; seule l'entité porte la cible ;
2. une expression régulière, en secours, pour un ``http(s)://`` que Telegram n'aurait
   pas marqué.

Telegram compte les positions des entités en **unités UTF-16** : un émoji avant le lien
décale de deux unités, pas d'un caractère Python. Les découper avec des indices Python
donnerait un autre lien que celui affiché (testé).
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass

from phishguard.bot.telegram import Entity

# Adresses écrites en clair : jusqu'au premier espace ou délimiteur courant.
URL_RE = re.compile(r"https?://[^\s<>\"'«»“”‘’]+", re.IGNORECASE)
# Ponctuation de fin de phrase, jamais retenue en fin de lien écrit.
TRAILING = ".,;:!?)]}…"
MAX_URL_CHARS = 2048  # borne de l'API (MAX_URL_CHARS, étape 4.2)
WEB_SCHEMES = ("http://", "https://")
# Un schéma écrit (« tg: », « mailto: »), pas un port (« exemple.fr:8080 »).
SCHEME_RE = re.compile(r"^[a-z][a-z0-9+.-]*:(?!\d)", re.IGNORECASE)


@dataclass(frozen=True)
class FoundLink:
    url: str
    # Texte affiché à la place de l'adresse (lien caché derrière un texte), sinon None.
    shown_as: str | None = None


@dataclass(frozen=True)
class Extraction:
    links: tuple[FoundLink, ...]
    # Liens trouvés en plus de ceux retenus (limite par message), et liens écartés parce
    # qu'ils ne mènent pas au web (tg://, mailto:…) ou sont trop longs pour l'API.
    skipped: int = 0
    not_web: int = 0


def utf16_slice(text: str, offset: int, length: int) -> str:
    """``text[offset:offset+length]`` en unités UTF-16, comme les entités de Telegram."""
    encoded = text.encode("utf-16-le")
    return encoded[2 * offset : 2 * (offset + length)].decode("utf-16-le", errors="replace")


def _with_scheme(url: str) -> str:
    return url if url.lower().startswith(WEB_SCHEMES) else f"http://{url}"


def _clean_written(url: str) -> str:
    # Une parenthèse fermante n'est gardée que si le lien en ouvre une (Wikipédia…).
    while url and url[-1] in TRAILING:
        if url[-1] == ")" and url.count("(") >= url.count(")"):
            break
        url = url[:-1]
    return url


def _candidates(text: str, entities: Iterable[Entity]) -> list[tuple[int, FoundLink | None]]:
    """(position, lien) dans l'ordre du texte ; ``None`` pour un lien qui ne mène pas au web."""
    found: list[tuple[int, FoundLink | None]] = []
    covered: list[tuple[int, int]] = []
    for entity in entities:
        shown = utf16_slice(text, entity.offset, entity.length).strip()
        if entity.type == "text_link" and entity.url is not None:
            target = entity.url.strip()
            link = (
                FoundLink(target, shown_as=shown or None)
                if target.lower().startswith(WEB_SCHEMES)
                else None
            )
        else:  # url : l'adresse est le texte lui-même, schéma facultatif
            written = _clean_written(shown)
            other_scheme = SCHEME_RE.match(written) and not written.lower().startswith(WEB_SCHEMES)
            link = FoundLink(_with_scheme(written)) if written and not other_scheme else None
        position = len(
            text.encode("utf-16-le")[: 2 * entity.offset].decode("utf-16-le", errors="replace")
        )
        found.append((position, link))
        covered.append((position, position + len(shown) + 1))
    for match in URL_RE.finditer(text):
        if any(start <= match.start() < end for start, end in covered):
            continue  # déjà vu par une entité
        found.append((match.start(), FoundLink(_clean_written(match.group()))))
    return sorted(found, key=lambda item: item[0])


def extract_links(text: str, entities: Iterable[Entity] = (), *, limit: int) -> Extraction:
    """Liens distincts du message, dans l'ordre, ``limit`` au plus."""
    kept: list[FoundLink] = []
    seen: set[str] = set()
    skipped = not_web = 0
    for _, link in _candidates(text, entities):
        if link is None or len(link.url) > MAX_URL_CHARS:
            not_web += 1
            continue
        key = link.url
        if key in seen:
            continue
        seen.add(key)
        if len(kept) >= limit:
            skipped += 1
            continue
        kept.append(link)
    return Extraction(links=tuple(kept), skipped=skipped, not_web=not_web)


__all__ = ["Extraction", "FoundLink", "extract_links", "utf16_slice"]
