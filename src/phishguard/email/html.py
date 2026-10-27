"""Liens et texte masqué dans le HTML d'un email (étape 1.10).

Le HTML n'est **jamais rendu** : BeautifulSoup (``html.parser``, en Python pur) en lit
l'arbre, rien n'est chargé ni exécuté.

- **Liens** : pour chaque ``<a href>`` et ``<area href>``, la cible réelle et le texte
  affiché. Si le texte ressemble à une adresse (``www.paypal.com``) dont le domaine
  enregistré diffère de celui de la cible, le lien est marqué ``mismatch`` : c'est le
  leurre le plus courant (« le lien affiché n'est pas le lien réel »). Les formulaires
  (``<form action>``) sont relevés aussi : un email légitime n'en contient presque jamais.
- **Texte masqué** : éléments dont le style **en ligne** les cache (``display:none``,
  ``visibility:hidden``, ``opacity:0``, police de taille nulle ou de 1 px, hauteur nulle
  avec débordement caché, couleur du texte égale à celle du fond) ou portant l'attribut
  ``hidden``. Il sert à glisser du texte anodin pour tromper les filtres. Les feuilles
  ``<style>`` ne sont pas interprétées (limite documentée).
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import asdict, dataclass, field
from functools import lru_cache
from urllib.parse import urlsplit

import tldextract
from bs4 import BeautifulSoup, Tag

from phishguard.data.urls import make_domain_extractor, normalize_url
from phishguard.data.urls import registered_domain as _registered_domain
from phishguard.urls.idn import to_ascii

ZERO_WIDTH = "\u200b‌‍⁠﻿­"
_ZERO_WIDTH_RE = re.compile(f"[{ZERO_WIDTH}]")
# Texte qui ressemble à une adresse : schéma, « www. » ou nom de domaine avec un TLD.
_ADDRESS_LIKE_RE = re.compile(
    r"^(?:https?://|www\.)\S+$|^[\w-]+(?:\.[\w-]+)*\.[a-z]{2,24}(?:[/:?#]\S*)?$", re.IGNORECASE
)
_TEXT_URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
_SIZE_RE = re.compile(r"^\s*([0-9]*\.?[0-9]+)\s*(px|pt|em|rem|%)?\s*$")
_NAMED_COLORS = {
    "white": "#ffffff",
    "black": "#000000",
    "red": "#ff0000",
    "blue": "#0000ff",
    "green": "#008000",
    "gray": "#808080",
    "grey": "#808080",
    "silver": "#c0c0c0",
    "yellow": "#ffff00",
}


@dataclass(frozen=True)
class Link:
    kind: str  # "a", "area", "form" ou "text" (URL écrite dans un texte brut)
    href: str
    text: str
    scheme: str
    href_domain: str | None  # domaine enregistré de la cible
    text_domain: str | None  # domaine enregistré du texte affiché, s'il ressemble à une URL
    mismatch: bool

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass
class HiddenText:
    elements: int = 0
    chars: int = 0
    reasons: Counter[str] = field(default_factory=Counter)

    def to_dict(self) -> dict[str, object]:
        return {"elements": self.elements, "chars": self.chars, "reasons": dict(self.reasons)}


@lru_cache(maxsize=1)
def _extractor() -> tldextract.TLDExtract:
    return make_domain_extractor()


def registered_domain(url_or_host: str) -> str | None:
    """Domaine enregistré d'une URL ou d'un hôte.

    ``None`` si rien n'est lisible ou si l'hôte n'a pas de suffixe public connu
    (``Bradesco.recompensas``, ``www``, ``localhost``) : un nom sans suffixe n'est pas une
    adresse que l'on peut comparer.
    """
    candidate = url_or_host.strip()
    if not candidate:
        return None
    normalized = normalize_url(candidate)
    if normalized is None:
        return None
    try:
        return _registered_domain(to_ascii(normalized[1]), _extractor())
    except (ValueError, UnicodeError):
        return None


def _scheme(href: str) -> str:
    try:
        return urlsplit(href.strip()).scheme.lower()
    except ValueError:
        return ""


def make_link(kind: str, href: str, text: str) -> Link:
    href, text = href.strip(), " ".join(text.split())
    scheme = _scheme(href)
    # Un href relatif (« page.html », « /aide ») n'a pas de domaine : seuls les liens web
    # absolus, y compris « //hote » et « www.hote », sont comparés.
    absolute = scheme in ("http", "https") or href.startswith(("//", "www."))
    href_domain = registered_domain(href.removeprefix("//")) if absolute else None
    shown = text.strip("<>()[]\"'.,;")
    text_domain = registered_domain(shown) if _ADDRESS_LIKE_RE.match(shown) else None
    mismatch = text_domain is not None and href_domain is not None and text_domain != href_domain
    # Un texte qui affiche une adresse web alors que la cible n'est pas du web
    # (javascript:, data:…) est aussi un leurre.
    if text_domain is not None and scheme not in ("http", "https", "", "mailto"):
        mismatch = True
    return Link(kind, href, text, scheme, href_domain, text_domain, mismatch)


def text_links(text: str, limit: int) -> list[Link]:
    """URLs écrites dans un texte brut (le texte affiché est l'URL elle-même)."""
    links = []
    for match in _TEXT_URL_RE.finditer(text):
        url = match.group(0).rstrip(".,;:!?)»]")
        links.append(make_link("text", url, ""))
        if len(links) >= limit:
            break
    return links


# --------------------------------------------------------------------------- #
# Styles
# --------------------------------------------------------------------------- #


def parse_style(style: str) -> dict[str, str]:
    """Déclarations CSS d'un attribut ``style`` (clés en minuscules, ``!important`` retiré)."""
    declarations = {}
    for item in style.split(";"):
        if ":" not in item:
            continue
        key, value = item.split(":", 1)
        value = value.replace("!important", "").strip().lower()
        declarations[key.strip().lower()] = value
    return declarations


def normalize_color(value: str | None) -> str | None:
    """``#FFF``, ``white``, ``rgb(255,255,255)`` → ``#ffffff`` ; ``None`` si illisible."""
    if not value:
        return None
    value = value.strip().lower()
    if value in _NAMED_COLORS:
        return _NAMED_COLORS[value]
    if re.fullmatch(r"#[0-9a-f]{3}", value):
        return "#" + "".join(c * 2 for c in value[1:])
    if re.fullmatch(r"#[0-9a-f]{6}", value):
        return value
    match = re.fullmatch(r"rgba?\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*(?:,\s*[\d.]+\s*)?\)", value)
    if match:
        return "#" + "".join(f"{min(int(c), 255):02x}" for c in match.groups())
    return None


def _tiny(value: str | None) -> bool:
    if value is None:
        return False
    match = _SIZE_RE.match(value)
    if not match:
        return False
    number, unit = float(match.group(1)), match.group(2) or "px"
    limit = {"px": 1.0, "pt": 1.0, "em": 0.1, "rem": 0.1, "%": 10.0}[unit]
    return number <= limit


def _background(tag: Tag) -> str | None:
    """Couleur de fond la plus proche : l'élément, puis ses ancêtres."""
    node: Tag | None = tag
    while isinstance(node, Tag):
        style = parse_style(node.get("style", "") if isinstance(node.get("style"), str) else "")
        color = style.get("background-color") or style.get("background", "").split(" ")[0]
        bgcolor = node.get("bgcolor")
        found = normalize_color(color) or normalize_color(
            bgcolor if isinstance(bgcolor, str) else None
        )
        if found:
            return found
        node = node.parent
    return None


def hiding_reason(tag: Tag) -> str | None:
    """Raison pour laquelle un élément est invisible, ou ``None``."""
    if tag.has_attr("hidden"):
        return "hidden_attribute"
    raw = tag.get("style")
    if not isinstance(raw, str) or not raw:
        return None
    style = parse_style(raw)
    if style.get("display") == "none":
        return "display_none"
    if style.get("visibility") in ("hidden", "collapse"):
        return "visibility_hidden"
    opacity = _SIZE_RE.match(style.get("opacity", ""))
    if opacity is not None and float(opacity.group(1)) == 0:
        return "opacity_zero"
    if _tiny(style.get("font-size")):
        return "tiny_font"
    overflow_hidden = style.get("overflow") == "hidden"
    if overflow_hidden and (_tiny(style.get("max-height")) or _tiny(style.get("height"))):
        return "zero_height"
    color = normalize_color(style.get("color"))
    if color is not None and color == _background(tag):
        return "same_color_as_background"
    return None


# --------------------------------------------------------------------------- #
# Analyse d'un document
# --------------------------------------------------------------------------- #


@dataclass
class HtmlAnalysis:
    text: str = ""
    links: list[Link] = field(default_factory=list)
    hidden: HiddenText = field(default_factory=HiddenText)
    forms: int = 0
    truncated_links: bool = False


def analyze_html(html: str, *, max_links: int) -> HtmlAnalysis:
    """Texte visible, liens, formulaires et texte masqué d'un document HTML."""
    soup = BeautifulSoup(html, "html.parser")
    for node in soup(["script", "style", "head", "title", "noscript", "template"]):
        node.decompose()
    result = HtmlAnalysis()

    for tag in soup.find_all(["a", "area", "form"]):
        if len(result.links) >= max_links:
            result.truncated_links = True
            break
        attribute = "action" if tag.name == "form" else "href"
        value = tag.get(attribute)
        if tag.name == "form":
            result.forms += 1
        if isinstance(value, str) and value.strip():
            result.links.append(make_link(tag.name, value, tag.get_text(" ", strip=True)))

    hidden_tops: list[Tag] = []
    hidden_ids: set[int] = set()
    for tag in soup.find_all(True):
        if any(id(parent) in hidden_ids for parent in tag.parents):
            continue  # déjà compté avec l'élément masqué qui le contient
        reason = hiding_reason(tag)
        if reason is None:
            continue
        hidden_ids.add(id(tag))
        hidden_tops.append(tag)
        result.hidden.elements += 1
        result.hidden.chars += len(tag.get_text(" ", strip=True))
        result.hidden.reasons[reason] += 1
    for tag in hidden_tops:
        tag.decompose()  # le texte masqué ne fait pas partie du texte visible

    result.text = soup.get_text(" ", strip=True)
    return result


def count_zero_width(text: str) -> int:
    return len(_ZERO_WIDTH_RE.findall(text))
