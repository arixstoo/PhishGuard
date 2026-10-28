"""Features « smishing » d'un SMS, écrites à la main (étape 1.9).

Treize signaux lisibles, en anglais, en français et en arabe : un lien, un raccourcisseur,
un numéro court, un numéro de téléphone, un montant, des mots d'urgence, de gain ou de
compte, des majuscules, des chiffres, des points d'exclamation, la longueur. Ils servent
deux fois :

- comme modèle seul (référence explicable) et en complément des n-grammes (étape 1.9) ;
- comme raisons lisibles d'un verdict (module 3) : « demande d'agir vite » parle à
  l'utilisateur, un poids de n-gramme non.

Fonctions pures, sans réseau ni état, comme les features URL : elles seront portées à
l'identique dans l'extension et le bot (module 5). :data:`FEATURES` en est le contrat.

Normalisation avant la recherche des mots-clés (:func:`normalize`) : minuscules (casefold),
caractères de format invisibles retirés (espace sans chasse U+200B…),
accents latins retirés (``sécurité`` → ``securite``), signes diacritiques arabes (tashkil,
tatwil) retirés et formes de l'alif unifiées (``أ إ آ`` → ``ا``). Un mot-clé latin doit
commencer un mot (``free`` dans ``freedom`` compte, dans ``carefree`` non) ; un mot-clé
arabe est cherché tel quel, l'arabe collant souvent les particules au mot (``بحسابك``).
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterable
from dataclasses import dataclass

import numpy as np
import pandas as pd

from phishguard.urls.brands import load_shorteners

URGENCY_KEYWORDS = (
    # anglais
    "urgent",
    "immediately",
    "asap",
    "expire",
    "suspend",
    "locked",
    "blocked",
    "final notice",
    "last chance",
    "act now",
    "within 24",
    # français
    "immediatement",
    "dernier rappel",
    "derniere relance",
    "sous 24",
    "sous 48",
    "bloque",
    "expire",
    "suspendu",
    "amende",
    "majoration",
    # arabe : عاجل, فورا, آخر أجل, تعليق, إيقاف, حظر, غرامة
    "عاجل",
    "فورا",
    "اخر اجل",
    "تعليق",
    "ايقاف",
    "حظر",
    "غرامة",
)
REWARD_KEYWORDS = (
    "won",
    "winner",
    "prize",
    "claim",
    "free",
    "bonus",
    "reward",
    "cash",
    "congratulations",
    "selected",
    "gagne",
    "gagnant",
    "felicitations",
    "cadeau",
    "gratuit",
    "remboursement",
    "rembourse",
    # arabe : ربحت, فزت, جائزة, مبروك, هدية, مجانا, تعويض
    "ربحت",
    "فزت",
    "جائزة",
    "مبروك",
    "هدية",
    "مجانا",
    "تعويض",
)
ACCOUNT_KEYWORDS = (
    "account",
    "password",
    "verify",
    "confirm",
    "login",
    "bank",
    "card",
    "pin",
    "compte",
    "mot de passe",
    "verifier",
    "verifiez",
    "confirmer",
    "identifiant",
    "carte",
    "banque",
    "colis",
    "livraison",
    # arabe : حساب, كلمة السر, تحقق, تأكيد, بطاقة, بنك, طرد
    "حساب",
    "كلمة السر",
    "تحقق",
    "تاكيد",
    "بطاقة",
    "بنك",
    "طرد",
)

_ARABIC_DIACRITICS_RE = re.compile("[ً-ٰٟـ]")  # tashkil, alif suscrit, tatwil
_ALIF_FORMS = str.maketrans({"أ": "ا", "إ": "ا", "آ": "ا", "ٱ": "ا"})
# Chiffres arabes orientaux et persans vers ASCII : ١٢٣ → 123.
_DIGITS = str.maketrans("٠١٢٣٤٥٦٧٨٩۰۱۲۳۴۵۶۷۸۹", "01234567890123456789")

# Lien : schéma, « www. », ou nom de domaine nu suivi d'un chemin ou d'un TLD courant.
# Un domaine nu ne suit ni « @ » (adresse email) ni une lettre ou un point. Sans chemin,
# seuls les TLD de la liste comptent ; « it », « be » et « me » en sont exclus, car les SMS
# collent souvent deux phrases (« pain.it will », « reply.Be »). « example » et « test »
# sont réservés (RFC 2606) et servent dans les jeux rédigés pour le projet.
_BARE_DOMAIN_START = r"(?<![@\w.-])[a-z0-9][a-z0-9-]*"
_URL_RE = re.compile(
    r"(?:https?://|www\.)\S+"
    rf"|{_BARE_DOMAIN_START}(?:\.[a-z0-9-]+)*\.(?:[a-z]{{2,24}})/\S*"
    rf"|{_BARE_DOMAIN_START}(?:\.[a-z0-9-]+)*\.(?:com|net|org|info|biz|xyz|top|online|site"
    r"|live|shop|app|click|link|icu|vip|ly|co|io|fr|dz|ma|tn|uk|de|es|ch|ca|example|test)\b",
    re.IGNORECASE,
)
_HOST_RE = re.compile(r"^(?:https?://)?([^/\s:?#]+)", re.IGNORECASE)
# Nombre isolé de 4 à 6 chiffres : numéro court (« text WIN to 87121 ») ou code à usage
# unique. Exclus : partie d'un nombre, d'une heure (10:30), d'un prix (1.99) ou d'un montant
# (£1000). Un point final de phrase reste permis.
_SHORT_CODE_RE = re.compile(r"(?<![\d+£$€.,:/-])\d{4,6}(?!\d|[.,:/-]\d)")
# Téléphone : 9 à 15 chiffres, espaces, points ou tirets permis, préfixe + facultatif.
_PHONE_RE = re.compile(r"(?<!\w)\+?\d(?:[ .-]?\d){8,14}(?!\w)")
# Montant : un nombre collé à une devise, avant ou après. Une devise en lettres doit être un
# mot entier (ni « Jada 3 » ni « data »). « da », « dh » et « mad » sont aussi de l'argot
# anglais (« 2 da report » = « to the report ») : il leur faut au moins deux chiffres.
_NOT_AFTER_LETTER = r"(?<![^\W\d_])"
_NOT_BEFORE_LETTER = r"(?![^\W\d_])"
_CURRENCY_WORD = r"(?:euros?|eur|usd|gbp|dzd|dinars?|دج|دينار|يورو)"
_AMBIGUOUS_CURRENCY = r"(?:da|dh|mad)"
_AMOUNT_RE = re.compile(
    r"[£$€]\s?\d|\d\s?[£$€]"
    rf"|{_NOT_AFTER_LETTER}{_CURRENCY_WORD}\s?\d|\d\s?{_CURRENCY_WORD}{_NOT_BEFORE_LETTER}"
    rf"|{_NOT_AFTER_LETTER}{_AMBIGUOUS_CURRENCY}\s?\d\d"
    rf"|\d\d\s?{_AMBIGUOUS_CURRENCY}{_NOT_BEFORE_LETTER}",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class FeatureSpec:
    name: str
    description: str


FEATURES: tuple[FeatureSpec, ...] = (
    FeatureSpec("has_url", "1 si le message contient un lien (schéma, www. ou domaine nu)"),
    FeatureSpec("n_urls", "nombre de liens"),
    FeatureSpec("has_shortener", "1 si un lien pointe vers un raccourcisseur connu"),
    FeatureSpec(
        "has_short_code", "1 si un nombre isolé de 4 à 6 chiffres (numéro court, code) est présent"
    ),
    FeatureSpec("has_phone", "1 si un numéro de téléphone (9 à 15 chiffres) est présent"),
    FeatureSpec("has_amount", "1 si un montant avec une devise est présent"),
    FeatureSpec("urgency_hits", "mots d'urgence ou de menace distincts"),
    FeatureSpec("reward_hits", "mots de gain ou de cadeau distincts"),
    FeatureSpec("account_hits", "mots de compte, d'identifiant ou de livraison distincts"),
    FeatureSpec("upper_ratio", "part des lettres latines en majuscules"),
    FeatureSpec("digit_ratio", "part des caractères qui sont des chiffres"),
    FeatureSpec("n_exclamations", "points d'exclamation"),
    FeatureSpec("length", "caractères du message"),
)
FEATURE_NAMES: tuple[str, ...] = tuple(f.name for f in FEATURES)


def normalize(text: str) -> str:
    """Forme de recherche des mots-clés (voir le module)."""
    text = unicodedata.normalize("NFKC", text).translate(_DIGITS).casefold()
    # Les caractères de format invisibles (U+200B…, catégorie Cf) servent à couper les
    # mots-clés pour tromper les filtres : « bloqu\u200bé » doit rester « bloque ».
    text = "".join(c for c in text if unicodedata.category(c) != "Cf")
    text = _ARABIC_DIACRITICS_RE.sub("", text).translate(_ALIF_FORMS)
    # NFD sépare les accents (et la hamza portée par ؤ ou ئ) de leur lettre ; on les retire.
    return "".join(c for c in unicodedata.normalize("NFD", text) if not unicodedata.combining(c))


def _keyword_patterns(keywords: Iterable[str]) -> tuple[re.Pattern[str], ...]:
    patterns = []
    # Les mots-clés passent par la même normalisation que les messages.
    for keyword in dict.fromkeys(normalize(k) for k in keywords):
        if keyword.isascii():
            patterns.append(re.compile(rf"(?<![a-z0-9]){re.escape(keyword)}"))
        else:
            patterns.append(re.compile(re.escape(keyword)))
    return tuple(patterns)


_URGENCY = _keyword_patterns(URGENCY_KEYWORDS)
_REWARD = _keyword_patterns(REWARD_KEYWORDS)
_ACCOUNT = _keyword_patterns(ACCOUNT_KEYWORDS)


def _hits(patterns: tuple[re.Pattern[str], ...], text: str) -> int:
    return sum(1 for p in patterns if p.search(text))


def find_urls(text: str) -> list[str]:
    """Liens du message, dans l'ordre d'apparition (ponctuation finale retirée)."""
    return [m.group(0).rstrip(".,;:!?)»\"'") for m in _URL_RE.finditer(text)]


def _url_host(url: str) -> str:
    match = _HOST_RE.match(url)
    host = match.group(1).lower() if match else ""
    return host.removeprefix("www.")


class SmishingFeatureExtractor:
    """Calcule :data:`FEATURES` pour un message ou une série de messages."""

    def __init__(self, shorteners: frozenset[str] | None = None) -> None:
        self.shorteners = shorteners if shorteners is not None else load_shorteners()

    def extract(self, text: str) -> dict[str, float]:
        if not isinstance(text, str):
            raise TypeError("le message doit être une chaîne")
        folded = unicodedata.normalize("NFKC", text).translate(_DIGITS)
        normalized = normalize(text)
        urls = find_urls(folded)
        # Les chiffres des liens ne sont ni des numéros ni des montants, et les groupes d'un
        # numéro de téléphone (« +44 7700 900123 ») ne sont pas des numéros courts.
        without_urls = _URL_RE.sub(" ", folded)
        without_phones = _PHONE_RE.sub(" ", without_urls)
        latin_letters = [c for c in folded if c.isalpha() and c.isascii()]
        return {
            "has_url": float(bool(urls)),
            "n_urls": float(len(urls)),
            "has_shortener": float(any(_url_host(u) in self.shorteners for u in urls)),
            "has_short_code": float(bool(_SHORT_CODE_RE.search(without_phones))),
            "has_phone": float(bool(_PHONE_RE.search(without_urls))),
            "has_amount": float(bool(_AMOUNT_RE.search(without_urls))),
            "urgency_hits": float(_hits(_URGENCY, normalized)),
            "reward_hits": float(_hits(_REWARD, normalized)),
            "account_hits": float(_hits(_ACCOUNT, normalized)),
            "upper_ratio": (
                sum(c.isupper() for c in latin_letters) / len(latin_letters)
                if latin_letters
                else 0.0
            ),
            "digit_ratio": sum(c.isdigit() for c in folded) / len(folded) if folded else 0.0,
            "n_exclamations": float(folded.count("!")),
            "length": float(len(text)),
        }

    def transform(self, texts: Iterable[str]) -> pd.DataFrame:
        """Une ligne par message, une colonne par feature (``float64``)."""
        index = texts.index if isinstance(texts, pd.Series) else None
        rows = [self.extract(t) for t in texts]
        return pd.DataFrame(rows, columns=list(FEATURE_NAMES), index=index, dtype="float64")

    def to_array(self, texts: Iterable[str]) -> np.ndarray:
        return self.transform(texts).to_numpy()
