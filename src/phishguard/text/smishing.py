"""Features « smishing » faites à la main, lisibles et multilingues (anglais, français, arabe).

Ce sont des fonctions pures, sans accès réseau, pour pouvoir les porter à l'identique dans
l'extension (module 5) et expliquer un verdict : « contient un lien et un mot d'urgence ».
Elles complètent le TF-IDF, elles ne le remplacent pas.
"""

from __future__ import annotations

import re

import numpy as np
from sklearn.base import BaseEstimator, TransformerMixin

# Lien explicite (schéma ou www.) ou nom de domaine nu suivi d'un chemin ou d'un TLD courant.
_URL = re.compile(
    r"(?:https?://|www\.)\S+"
    r"|\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:com|net|org|info|co|uk|fr|ma|dz|tn|ly|me|io|xyz|top"
    r"|site|online|example)\b(?:/\S*)?",
    re.IGNORECASE,
)
# Numéro court surtaxé ou de réponse (« text WIN to 87121 »), 4 à 6 chiffres isolés.
_SHORT_CODE = re.compile(r"(?<![\d+])\b\d{4,6}\b(?![\d,.])")
# Numéro de téléphone : au moins 9 chiffres, avec espaces, points ou tirets possibles.
_PHONE = re.compile(r"(?:\+|00)?\d(?:[\s.-]?\d){8,}")
# Montant : symbole ou code monétaire collé ou séparé d'un nombre.
_MONEY = re.compile(
    r"(?:[£$€]\s?\d|\d[\d\s.,]*\s?(?:[£$€]|(?:eur|euros?|usd|gbp|dh|mad|dzd|da|dinars?"
    r"|دينار|درهم|دج)\b))",
    re.IGNORECASE,
)

URGENCY_WORDS: tuple[str, ...] = (
    # anglais
    "urgent", "now", "immediately", "today", "expire", "expires", "suspended", "verify",
    "confirm", "claim", "winner", "won", "prize", "free", "final notice", "act now",
    # français
    "immédiatement", "aujourd'hui", "dernier rappel", "suspendu", "suspendue", "bloqué",
    "bloquée", "vérifier", "vérifiez", "confirmer", "confirmez", "gagné", "gratuit",
    "remboursement", "amende", "majoration", "colis", "sous 24h", "sous 48h",
    # arabe
    "عاجل", "فورا", "فوراً", "الآن", "اليوم", "تعليق", "موقوف", "تأكيد", "تحقق", "ربحت",
    "جائزة", "مجانا", "مجاناً", "غرامة", "طرد", "حسابك",
)  # fmt: skip

# Ordre fixe : il définit les colonnes du modèle et ne doit pas changer sans réentraîner.
FEATURE_NAMES: tuple[str, ...] = (
    "has_url",
    "has_short_code",
    "has_phone",
    "has_money",
    "urgency_hits",
    "upper_ratio",
    "digit_ratio",
    "n_exclamations",
    "length",
)


def _urgency_hits(lower: str) -> int:
    hits = 0
    for word in URGENCY_WORDS:
        if " " in word or not word.isascii():
            hits += word in lower
        else:
            hits += bool(re.search(rf"\b{re.escape(word)}\b", lower))
    return hits


def smishing_features(text: str) -> dict[str, float]:
    """Calcule les features d'un message. Ne lève jamais d'exception sur une chaîne."""
    if not isinstance(text, str):
        raise TypeError("text doit être une chaîne")
    lower = text.lower()
    letters = [c for c in text if c.isalpha()]
    # Les majuscules n'ont de sens que pour les écritures qui en ont (pas l'arabe).
    cased = [c for c in letters if c.isupper() or c.islower()]
    phone = bool(_PHONE.search(text))
    return {
        "has_url": float(bool(_URL.search(text))),
        "has_short_code": float(bool(_SHORT_CODE.search(text)) and not phone),
        "has_phone": float(phone),
        "has_money": float(bool(_MONEY.search(text))),
        "urgency_hits": float(_urgency_hits(lower)),
        "upper_ratio": sum(c.isupper() for c in cased) / len(cased) if cased else 0.0,
        "digit_ratio": sum(c.isdigit() for c in text) / len(text) if text else 0.0,
        "n_exclamations": float(text.count("!")),
        "length": float(len(text)),
    }


class SmishingFeatures(BaseEstimator, TransformerMixin):
    """Transformeur scikit-learn : liste de textes -> matrice ``(n, len(FEATURE_NAMES))``.

    ``length`` et ``urgency_hits`` sont passés au log pour rester à l'échelle des autres
    colonnes (comprises entre 0 et 1) à côté d'un TF-IDF normalisé.
    """

    def fit(self, X, y=None):
        return self

    def transform(self, X):
        rows = []
        for text in X:
            f = smishing_features(text)
            f["length"] = np.log1p(f["length"]) / 6.0
            f["urgency_hits"] = np.log1p(f["urgency_hits"])
            f["n_exclamations"] = np.log1p(f["n_exclamations"])
            rows.append([f[name] for name in FEATURE_NAMES])
        return np.asarray(rows, dtype=float).reshape(-1, len(FEATURE_NAMES))

    def get_feature_names_out(self, input_features=None):
        return np.asarray(FEATURE_NAMES, dtype=object)
