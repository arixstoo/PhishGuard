"""Normalisation défensive des entrées (étape 3.8).

Une évasion de forme (``docs/evasion-catalog.md``, TXT-01, TXT-02, URL-02) change les
caractères d'un leurre sans changer ce que lit la victime. La défense consiste à ramener
l'entrée à ce qu'elle *montre*, **à l'entraînement comme à l'inférence**, pour que le
modèle lise ce que lit l'utilisateur :

1. ``unicodedata.normalize("NFKC", s)`` : formes de compatibilité (pleine chasse, ligatures,
   exposants) ramenées à leur forme ordinaire ;
2. suppression des caractères de **format** (catégorie Unicode Cf : largeur nulle,
   marques de direction, U+FEFF) et de **contrôle** (Cc, sauf tabulation et sauts de
   ligne) ;
3. **repli des caractères confusables** vers leur squelette latin, d'après la table de
   :mod:`phishguard.urls.idn` (sous-ensemble d'UTS #39) étendue aux majuscules. Seulement
   dans un mot qui mêle déjà le latin à une autre écriture (``Vоtre``), ou dans un mot fait
   uniquement de confusables au milieu d'un texte latin : un texte russe ou grec reste
   intact ;
4. **règle explicite** pour les noms d'hôte : un hôte qui mêle des écritures, ou dont un
   label étranger imite des lettres latines, reçoit une alerte forte
   (:func:`host_script_alert`). Les confusables d'un hôte ne sont **jamais** repliés : ce
   serait rendre ``аpple.com`` identique à ``apple.com``, donc l'innocenter ;
5. **journalisation** quand la normalisation a modifié l'entrée, ce qui est en soi un
   indice (:func:`log_normalization`). Le journal ne contient que des comptes, jamais le
   texte ni l'URL.

Les fonctions sont pures et hors ligne, et simples à porter en TypeScript (module 5).
"""

from __future__ import annotations

import logging
import re
import unicodedata
from dataclasses import asdict, dataclass
from typing import Literal

from phishguard.urls.idn import CONFUSABLES, char_script, is_mixed_script, skeleton, to_unicode

logger = logging.getLogger(__name__)

NORMALIZATION_VERSION = "1.0.0"

# Contrôles conservés : ils séparent des mots, un modèle de texte les lit comme des espaces.
_KEPT_CONTROLS = frozenset("\t\n\r")

# Majuscules confusables : la table de l'étape 1.5 ne contient que des minuscules (le
# squelette d'un hôte est en minuscules). Un texte, lui, garde sa casse.
_UPPER_CONFUSABLES: dict[str, str] = {
    # cyrillique
    "А": "A", "В": "B", "С": "C", "Е": "E", "Н": "H", "І": "I", "Ј": "J", "К": "K",
    "М": "M", "О": "O", "Р": "P", "Ѕ": "S", "Т": "T", "Х": "X", "У": "Y", "Ԛ": "Q",
    "Ԝ": "W",
    # grec
    "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I", "Κ": "K", "Μ": "M",
    "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X",
}  # fmt: skip
TEXT_CONFUSABLES: dict[str, str] = {**CONFUSABLES, **_UPPER_CONFUSABLES}

_LETTER_RUN_RE = re.compile(r"[^\W\d_]+")

HostAlert = Literal["mixed_script_label", "lookalike_label"]


@dataclass(frozen=True)
class NormalizationReport:
    """Ce que la normalisation a changé : des comptes, jamais le contenu."""

    nfkc: bool = False  # NFKC a modifié l'entrée
    format_chars: int = 0  # catégorie Cf retirés
    control_chars: int = 0  # catégorie Cc retirés
    confusables: int = 0  # caractères repliés vers leur squelette latin

    @property
    def changed(self) -> bool:
        return self.nfkc or bool(self.format_chars or self.control_chars or self.confusables)

    def to_dict(self) -> dict[str, int | bool]:
        return {**asdict(self), "changed": self.changed}


@dataclass(frozen=True)
class Normalized:
    text: str
    report: NormalizationReport


# --------------------------------------------------------------------------- #
# Étapes
# --------------------------------------------------------------------------- #


def strip_invisible(text: str) -> tuple[str, int, int]:
    """Texte sans caractères de format (Cf) ni de contrôle (Cc, sauf ``\\t\\n\\r``).

    Renvoie aussi le nombre de caractères de chaque sorte retirés.
    """
    kept: list[str] = []
    format_chars = control_chars = 0
    for c in text:
        category = unicodedata.category(c)
        if category == "Cf":
            format_chars += 1
        elif category == "Cc" and c not in _KEPT_CONTROLS:
            control_chars += 1
        else:
            kept.append(c)
    return "".join(kept), format_chars, control_chars


def _looks_latin(text: str) -> bool:
    """Vrai si le texte a plus de lettres latines que de lettres étrangères *non*
    confusables : un texte latin dont certains mots sont écrits en homoglyphes."""
    latin = foreign = 0
    for c in text:
        script = char_script(c)
        if script == "LATIN":
            latin += 1
        elif script is not None and c not in TEXT_CONFUSABLES:
            foreign += 1
    return latin > foreign


def fold_confusables(text: str) -> tuple[str, int]:
    """Replie les confusables des mots qui imitent l'écriture latine.

    Un mot est replié s'il mêle le latin et une autre écriture (``Vоtre``), ou s'il n'est
    fait que de confusables dans un texte d'allure latine (``соре`` au milieu d'une
    phrase française). Un mot entièrement cyrillique ou grec d'un texte dans cette langue
    reste intact. Renvoie aussi le nombre de caractères repliés.
    """
    looks_latin: bool | None = None  # calculé seulement si besoin
    folded = 0
    pieces: list[str] = []
    last = 0
    for match in _LETTER_RUN_RE.finditer(text):
        word = match.group()
        if not any(c in TEXT_CONFUSABLES and char_script(c) != "LATIN" for c in word):
            continue
        scripts = {char_script(c) for c in word} - {None}
        mixed = "LATIN" in scripts and len(scripts) > 1
        if not mixed:
            if not all(c in TEXT_CONFUSABLES for c in word):
                continue
            if looks_latin is None:
                looks_latin = _looks_latin(text)
            if not looks_latin:
                continue
        replaced = "".join(
            TEXT_CONFUSABLES[c] if c in TEXT_CONFUSABLES and char_script(c) != "LATIN" else c
            for c in word
        )
        folded += sum(a != b for a, b in zip(word, replaced, strict=True))
        pieces += [text[last : match.start()], replaced]
        last = match.end()
    if not folded:
        return text, 0
    pieces.append(text[last:])
    return "".join(pieces), folded


# --------------------------------------------------------------------------- #
# Points d'entrée
# --------------------------------------------------------------------------- #


def normalize_text(text: str, *, fold: bool = True) -> Normalized:
    """Normalise un message (SMS, email) : NFKC, invisibles retirés, confusables repliés."""
    nfkc = unicodedata.normalize("NFKC", text)
    stripped, format_chars, control_chars = strip_invisible(nfkc)
    # NFKC à nouveau : retirer un caractère de format peut recoller une lettre et un
    # accent combinant qu'il séparait.
    stripped = unicodedata.normalize("NFKC", stripped)
    folded, confusables = fold_confusables(stripped) if fold else (stripped, 0)
    report = NormalizationReport(
        nfkc=nfkc != text,
        format_chars=format_chars,
        control_chars=control_chars,
        confusables=confusables,
    )
    return Normalized(folded, report)


def normalize_url_text(url: str) -> Normalized:
    """Normalise le texte brut d'une URL : NFKC et invisibles retirés, **sans repli**.

    Un hôte homographe doit rester visible pour les features ``host_mixed_script`` et
    ``homograph_brand`` et pour :func:`host_script_alert`.
    """
    nfkc = unicodedata.normalize("NFKC", url)
    stripped, format_chars, control_chars = strip_invisible(nfkc)
    report = NormalizationReport(
        nfkc=nfkc != url, format_chars=format_chars, control_chars=control_chars
    )
    return Normalized(stripped, report)


def host_script_alert(host: str) -> HostAlert | None:
    """Alerte forte si l'hôte (forme ASCII ou Unicode) imite des lettres latines.

    - ``mixed_script_label`` : un label mêle des écritures non admises ensemble
      (UTS #39, *Highly Restrictive*) : ``аpple.com`` ;
    - ``lookalike_label`` : un label est entièrement dans une autre écriture mais son
      squelette est fait de lettres latines, alors que l'hôte contient du latin :
      ``раураl.com``, tout cyrillique sauf le TLD.

    Un hôte entièrement dans une autre écriture (``пример.рф``) ou un label étranger qui
    n'imite pas le latin (``пример.com``) ne déclenche rien.
    """
    unicode_host = to_unicode(host.lower().rstrip("."))
    if is_mixed_script(unicode_host):
        return "mixed_script_label"
    labels = [label for label in unicode_host.split(".") if label]
    label_scripts = [{char_script(c) for c in label} - {None} for label in labels]
    if not any("LATIN" in scripts for scripts in label_scripts):
        return None
    for label, scripts in zip(labels, label_scripts, strict=True):
        if not scripts or "LATIN" in scripts:
            continue
        letters = skeleton("".join(c for c in label if c.isalpha()))
        if letters.isascii() and letters.isalpha():
            return "lookalike_label"
    return None


def log_normalization(report: NormalizationReport, channel: str) -> None:
    """Journalise une entrée modifiée par la normalisation : des comptes seulement."""
    if report.changed:
        logger.info(
            "entrée %s normalisée : NFKC %s, %d format, %d contrôle, %d confusables",
            channel,
            "oui" if report.nfkc else "non",
            report.format_chars,
            report.control_chars,
            report.confusables,
        )


# --------------------------------------------------------------------------- #
# Modèles de texte
# --------------------------------------------------------------------------- #


def strip_accents(text: str) -> str:
    """Accents retirés (NFKD puis marques combinantes ôtées), comme
    ``strip_accents="unicode"`` de scikit-learn."""
    decomposed = unicodedata.normalize("NFKD", text)
    if decomposed == text:
        return text
    return "".join(c for c in decomposed if not unicodedata.combining(c))


class TextNormalizer:
    """Prétraitement des vectoriseurs TF-IDF (paramètre ``preprocessor``).

    Le même objet sert à l'entraînement, à l'inférence et aux explications
    (``TfidfVectorizer.build_preprocessor``) : le modèle, et les mots qu'il cite, sont
    ceux du texte normalisé. Un ``preprocessor`` remplace ``lowercase`` et
    ``strip_accents`` du vectoriseur : ils sont donc refaits ici. Sans état, sérialisable.
    """

    def __init__(self, *, lowercase: bool = True, accents: bool = False) -> None:
        self.lowercase = lowercase
        self.accents = accents
        self.version = NORMALIZATION_VERSION

    def __call__(self, document: str) -> str:
        text = normalize_text(document).text
        if self.accents:
            text = strip_accents(text)
        return text.lower() if self.lowercase else text

    def __eq__(self, other: object) -> bool:
        return isinstance(other, TextNormalizer) and vars(self) == vars(other)

    def __hash__(self) -> int:
        return hash((self.lowercase, self.accents, self.version))

    def __repr__(self) -> str:
        return f"TextNormalizer(lowercase={self.lowercase}, accents={self.accents})"
