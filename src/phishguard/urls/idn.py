"""Noms de domaine internationalisés : Punycode, écritures et homographes.

Une attaque par homographe remplace une lettre latine par une lettre identique d'une autre
écriture (``аpple.com`` commence par un « а » cyrillique). Le navigateur transmet ces
hôtes en Punycode (``xn--pple-43d.com``), l'utilisateur les lit en Unicode.

Toutes les fonctions sont pures et hors ligne. Elles doivent rester simples à porter en
TypeScript (module 5) : Punycode (RFC 3492), normalisation NFKC / NFKD et une table de
lettres confusables écrite à la main.
"""

from __future__ import annotations

import hashlib
import unicodedata

_ACE_PREFIX = "xn--"
_MAX_LABEL_LENGTH = 63  # RFC 1035, § 2.3.4

# Combinaisons d'écritures admises dans un même label : profil « Highly Restrictive »
# d'Unicode UTS #39, § 5.2 (le japonais, le chinois et le coréen mêlent légitimement
# plusieurs écritures, et le latin y est courant).
_ALLOWED_SCRIPT_MIXES = (
    frozenset({"LATIN", "HAN", "HIRAGANA", "KATAKANA"}),
    frozenset({"LATIN", "HAN", "BOPOMOFO"}),
    frozenset({"LATIN", "HAN", "HANGUL"}),
)
# Premiers mots de nom Unicode qui ne désignent pas une écriture.
_NAME_PREFIXES_TO_SKIP = frozenset({"FULLWIDTH", "HALFWIDTH", "SMALL", "CAPITAL"})
_SCRIPT_ALIASES = {"CJK": "HAN"}

# Lettres d'autres écritures qui se lisent comme une lettre latine minuscule. Sous-ensemble
# volontairement court de la table « confusables » d'Unicode, limité aux cas utilisés dans
# les attaques connues (cyrillique, grec, quelques lettres latines spéciales).
CONFUSABLES: dict[str, str] = {
    # cyrillique
    "а": "a", "е": "e", "ё": "e", "һ": "h", "і": "i", "ї": "i", "ј": "j", "к": "k",
    "ӏ": "l", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "ѕ": "s", "ԁ": "d",
    "ԛ": "q", "ԝ": "w", "ь": "b",
    # grec
    "α": "a", "ε": "e", "η": "n", "ι": "i", "κ": "k", "ν": "v", "ο": "o", "ρ": "p",
    "τ": "t", "υ": "u", "χ": "x", "γ": "y", "ω": "w",
    # latin étendu et symboles
    "ı": "i", "ȷ": "j", "ɡ": "g", "ł": "l", "ℓ": "l", "ø": "o", "đ": "d", "ħ": "h",
}  # fmt: skip


def label_to_ascii(label: str) -> str:
    """Forme ASCII d'un label : NFKC, minuscules, puis Punycode s'il reste du non-ASCII.

    Approximation d'IDNA / UTS #46, suffisante pour des features : pas de contrôle
    bidirectionnel ni de rejet des caractères interdits.
    """
    if label.isascii():
        return label.lower()
    folded = unicodedata.normalize("NFKC", label).lower()
    if folded.isascii():
        return folded
    if len(folded) > _MAX_LABEL_LENGTH:
        # Un tel label ne peut pas exister en DNS, et l'encodeur Punycode de CPython est
        # quadratique (déni de service). On ne rejette pas l'URL pour autant : cela
        # cacherait le lien aux règles de détection. Une forme ASCII courte et stable
        # le garde comparable (il ne ressemblera jamais à « paypal.com »).
        digest = hashlib.sha256(folded.encode("utf-8", "surrogatepass")).hexdigest()[:32]
        return f"{_ACE_PREFIX}oversized-{digest}"
    return _ACE_PREFIX + folded.encode("punycode").decode("ascii")


def label_to_unicode(label: str) -> str:
    """Forme Unicode d'un label ``xn--`` ; un label mal encodé est rendu tel quel."""
    # Au-delà de 63 caractères, le label est mal encodé par définition, et le décodeur
    # Punycode de CPython est quadratique.
    if not label.startswith(_ACE_PREFIX) or len(label) > _MAX_LABEL_LENGTH:
        return label
    try:
        return label[len(_ACE_PREFIX) :].encode("ascii").decode("punycode")
    except (UnicodeError, ValueError, IndexError):
        return label


def to_ascii(host: str) -> str:
    """Hôte sous la forme transmise par le navigateur (labels Punycode)."""
    return ".".join(label_to_ascii(label) for label in host.split("."))


def to_unicode(host: str) -> str:
    """Hôte sous la forme lue par l'utilisateur."""
    return ".".join(label_to_unicode(label) for label in host.split("."))


def char_script(char: str) -> str | None:
    """Écriture d'une lettre, déduite de son nom Unicode ; ``None`` si ce n'est pas une lettre.

    ``LATIN SMALL LETTER A`` → ``LATIN`` ; ``CJK UNIFIED IDEOGRAPH-4E00`` → ``HAN``.
    """
    if not char.isalpha():
        return None
    words = unicodedata.name(char, "UNKNOWN").split()
    while len(words) > 1 and words[0] in _NAME_PREFIXES_TO_SKIP:
        words = words[1:]
    return _SCRIPT_ALIASES.get(words[0], words[0])


def label_scripts(label: str) -> frozenset[str]:
    """Écritures des lettres d'un label (chiffres et tirets ignorés)."""
    return frozenset(s for s in map(char_script, label) if s is not None)


def is_mixed_script(host: str) -> bool:
    """Vrai si un label de l'hôte (forme Unicode) mêle des écritures non admises ensemble.

    ``аpple.com`` (cyrillique + latin) est mixte ; ``пример.рф`` (tout cyrillique) et
    ``東京tokyo.jp`` (han + latin, admis par UTS #39) ne le sont pas.
    """
    for label in host.split("."):
        scripts = label_scripts(label)
        if len(scripts) > 1 and not any(scripts <= allowed for allowed in _ALLOWED_SCRIPT_MIXES):
            return True
    return False


def skeleton(text: str) -> str:
    """Squelette visuel en minuscules : accents retirés, lettres confusables remplacées.

    ``раураl`` (cyrillique) et ``pàypal`` donnent tous deux ``paypal``.
    """
    decomposed = unicodedata.normalize("NFKD", text.lower())
    stripped = "".join(c for c in decomposed if not unicodedata.combining(c))
    return "".join(CONFUSABLES.get(c, c) for c in stripped)
