"""Explications du modèle de texte (étape 3.3).

Le modèle SMS (étape 1.9) est linéaire sur un TF-IDF : son score est

    score = constante + somme sur les n-grammes j de (coefficient_j × tfidf_j)

La contribution d'un n-gramme est donc exactement ``coefficient × tfidf``, et elles
s'additionnent jusqu'au score (marge du SVM ou log-odds de la régression logistique).

Un n-gramme de caractères (« ``rif`` », « ``z i`` ») ne parle à personne. Chaque
contribution est donc **ramenée aux mots du message** : un n-gramme présent plusieurs
fois partage sa contribution entre ses occurrences, et une occurrence la donne au mot qui
la contient (``char_wb`` ne franchit jamais un espace) ou, pour un bigramme de mots, la
partage entre ses deux mots. La somme des contributions des mots reste exactement celle
des n-grammes : rien n'est perdu ni inventé.

À côté des mots, :func:`message_categories` repère les **catégories** de leurre que
l'utilisateur reconnaîtra : urgence, argent, lien, code, compte (features smishing de
l'étape 1.9).

**Vie privée.** Une explication contient des mots du message de l'utilisateur. Elle ne
doit jamais être journalisée ; elle n'est renvoyée qu'à celui qui a soumis le message.
"""

from __future__ import annotations

import math
import re
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from functools import lru_cache
from typing import TYPE_CHECKING, Any, Literal

import numpy as np

from phishguard.explain.shap_url import UnsupportedModelError
from phishguard.text.smishing import (
    ACCOUNT_KEYWORDS,
    REWARD_KEYWORDS,
    URGENCY_KEYWORDS,
    SmishingFeatureExtractor,
    find_urls,
    keyword_patterns,
    normalize,
)

if TYPE_CHECKING:
    from phishguard.text.models import TextModel

Category = Literal["urgency", "money", "link", "code", "account"]
# Espace du score : log-odds (régression logistique) ou marge (SVM linéaire).
Space = Literal["log_odds", "margin"]
CATEGORIES: tuple[Category, ...] = ("urgency", "money", "link", "code", "account")
Direction = Literal["phishing", "safe"]
DEFAULT_TOP = 5

# Demande d'un code ou d'un secret : le leurre le plus dangereux par SMS (vol de compte,
# validation d'un paiement). Mêmes règles de normalisation que les mots-clés smishing.
CODE_KEYWORDS = (
    "code",
    "otp",
    "pin",
    "password",
    "passcode",
    "mot de passe",
    "mdp",
    "verification",
    "رمز",
    "كود",
    "كلمة السر",
)
CURRENCY_WORDS = ("eur", "euro", "euros", "usd", "gbp", "dzd", "dinar", "dinars", "دج", "دينار")
_CURRENCY_RE = re.compile(r"[£$€]|\d")
_CURRENCY = r"(?:[£$€]|eur(?:os?)?\b|usd\b|gbp\b|dzd\b|dinars?\b|دج|دينار)"
# Nombre collé à une devise, avant ou après : « 500 € », « €1,99 », « 2,49 EUR ».
_AMOUNT_NUMBER_RE = re.compile(
    rf"(?:{_CURRENCY}\s?(\d[\d.,]*))|(?:(\d[\d.,]*)\s?{_CURRENCY})", re.IGNORECASE
)
_WHITE_SPACES_RE = re.compile(r"\s\s+")  # même règle que scikit-learn pour char_wb


@dataclass(frozen=True)
class TermContribution:
    """Un mot du message (forme prétraitée du modèle) et sa contribution au score."""

    term: str
    contribution: float

    def to_dict(self) -> dict[str, Any]:
        return {"term": self.term, "contribution": round(self.contribution, 6)}


@dataclass(frozen=True)
class TextExplanation:
    """Contribution de chaque mot au score du modèle de texte, et catégories du message.

    ``terms`` : un élément par mot distinct, dans l'ordre de première apparition.
    ``category_terms`` : pour chaque catégorie présente, les mots qui l'évoquent (une
    catégorie peut être présente sans mot dédié, par exemple un mot-clé de plusieurs mots).
    """

    intercept: float
    terms: tuple[TermContribution, ...]
    categories: tuple[Category, ...] = ()
    category_terms: Mapping[str, tuple[str, ...]] = field(default_factory=dict)
    analyzer: str = "char_wb"
    space: Space = "margin"

    @property
    def decision(self) -> float:
        """Score du modèle (marge ou log-odds), retrouvé à partir des contributions."""
        return self.intercept + math.fsum(t.contribution for t in self.terms)

    def top(
        self, n: int = DEFAULT_TOP, *, direction: Direction = "phishing"
    ) -> tuple[TermContribution, ...]:
        """Les ``n`` mots qui ont le plus poussé vers ``direction`` (ordre reproductible)."""
        if n < 0:
            raise ValueError("n doit être positif ou nul")
        sign = 1.0 if direction == "phishing" else -1.0
        pushing = [t for t in self.terms if sign * t.contribution > 0]
        pushing.sort(key=lambda t: (-sign * t.contribution, t.term))
        return tuple(pushing[:n])

    def contribution_of(self, term: str) -> float:
        return math.fsum(t.contribution for t in self.terms if t.term == term)

    def to_dict(self, top: int = 10) -> dict[str, Any]:
        """Vue analyste : constante, score, mots les plus influents dans chaque sens."""
        return {
            "analyzer": self.analyzer,
            "space": self.space,
            "intercept": round(self.intercept, 6),
            "decision": round(self.decision, 6),
            "top_phishing": [t.to_dict() for t in self.top(top)],
            "top_safe": [t.to_dict() for t in self.top(top, direction="safe")],
            "categories": list(self.categories),
        }


# --------------------------------------------------------------------------- #
# Catégories du message
# --------------------------------------------------------------------------- #


@lru_cache(maxsize=1)
def _patterns() -> dict[str, tuple[re.Pattern[str], ...]]:
    return {
        "urgency": keyword_patterns(URGENCY_KEYWORDS),
        "reward": keyword_patterns(REWARD_KEYWORDS),
        "account": keyword_patterns(ACCOUNT_KEYWORDS),
        "code": keyword_patterns(CODE_KEYWORDS),
        "currency": keyword_patterns(CURRENCY_WORDS),
    }


@lru_cache(maxsize=1)
def _extractor() -> SmishingFeatureExtractor:
    return SmishingFeatureExtractor()


def _matches(kind: str, normalized: str) -> bool:
    return any(p.search(normalized) for p in _patterns()[kind])


def _without_urls(text: str) -> str:
    for url in find_urls(text):
        text = text.replace(url, " ")
    return text


def message_categories(text: str) -> tuple[Category, ...]:
    """Catégories de leurre présentes dans le message, dans l'ordre de :data:`CATEGORIES`.

    Le texte d'un lien ne compte que comme lien : ``caf-verification.example`` ne demande
    pas de code.
    """
    features = _extractor().extract(text)
    normalized = normalize(_without_urls(text))
    present = {
        "urgency": features["urgency_hits"] > 0,
        "money": features["has_amount"] > 0 or features["reward_hits"] > 0,
        "link": features["has_url"] > 0,
        "code": _matches("code", normalized),
        "account": features["account_hits"] > 0,
    }
    return tuple(c for c in CATEGORIES if present[c])


def amount_numbers(text: str) -> frozenset[str]:
    """Nombres d'un montant (« 500 » dans « 500 € ») : ils évoquent l'argent."""
    return frozenset(
        (match.group(1) or match.group(2)).rstrip(".,")
        for match in _AMOUNT_NUMBER_RE.finditer(text)
    )


def word_categories(word: str) -> frozenset[Category]:
    """Catégories qu'un mot évoque à lui seul (« urgent », « 50€ », un lien…).

    Un lien n'évoque que la catégorie ``link``, quels que soient les mots de son adresse.
    """
    if find_urls(word):
        return frozenset({"link"})
    normalized = normalize(word)
    found: set[Category] = set()
    if _matches("urgency", normalized):
        found.add("urgency")
    if _matches("reward", normalized) or (
        _CURRENCY_RE.search(word) is not None and _matches("currency", normalized)
    ):
        found.add("money")
    if any(c in word for c in "£$€"):
        found.add("money")
    if _matches("code", normalized):
        found.add("code")
    if _matches("account", normalized):
        found.add("account")
    return frozenset(found)


# --------------------------------------------------------------------------- #
# Des n-grammes aux mots
# --------------------------------------------------------------------------- #


def char_wb_ngrams(word: str, ngram_range: tuple[int, int]) -> list[str]:
    """N-grammes ``char_wb`` d'un mot, comme scikit-learn (mot entouré d'espaces ; un mot
    plus court que ``n`` n'est compté qu'une fois)."""
    padded = f" {word} "
    length = len(padded)
    grams: list[str] = []
    low, high = ngram_range
    for n in range(low, high + 1):
        offset = 0
        grams.append(padded[offset : offset + n])
        while offset + n < length:
            offset += 1
            grams.append(padded[offset : offset + n])
        if offset == 0:
            break
    return grams


def _aggregate(words: Sequence[str], shares: Sequence[float]) -> tuple[TermContribution, ...]:
    totals: dict[str, float] = {}
    for word, share in zip(words, shares, strict=True):
        totals[word] = totals.get(word, 0.0) + share
    return tuple(TermContribution(word, value) for word, value in totals.items())


def _char_wb_terms(
    document: str, ngram_range: tuple[int, int], contributions: Mapping[str, float]
) -> tuple[TermContribution, ...]:
    words = _WHITE_SPACES_RE.sub(" ", document).split()
    per_word = [char_wb_ngrams(w, ngram_range) for w in words]
    occurrences = Counter(g for grams in per_word for g in grams)
    shares = [
        math.fsum(contributions.get(g, 0.0) / occurrences[g] for g in grams) for grams in per_word
    ]
    return _aggregate(words, shares)


def _word_terms(
    tokens: Sequence[str], ngram_range: tuple[int, int], contributions: Mapping[str, float]
) -> tuple[TermContribution, ...]:
    spans: list[tuple[str, int, int]] = []  # n-gramme, début, fin (exclue)
    low, high = ngram_range
    for n in range(low, high + 1):
        for start in range(len(tokens) - n + 1):
            spans.append((" ".join(tokens[start : start + n]), start, start + n))
    occurrences = Counter(gram for gram, _, _ in spans)
    shares = [0.0] * len(tokens)
    for gram, start, end in spans:
        value = contributions.get(gram, 0.0)
        if value:
            part = value / occurrences[gram] / (end - start)
            for position in range(start, end):
                shares[position] += part
    return _aggregate(tokens, shares)


class TextExplainer:
    """Contribution de chaque mot au score d'un :class:`~phishguard.text.models.TextModel`.

    Pris en charge : un pipeline ``TF-IDF → classifieur linéaire`` (régression
    logistique, SVM linéaire), sur des n-grammes de caractères (``char_wb``) ou de mots.
    Les autres approches (features smishing, embeddings) lèvent
    :class:`UnsupportedModelError` : leurs catégories restent disponibles par
    :func:`message_categories`.
    """

    def __init__(self, model: TextModel) -> None:
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.pipeline import Pipeline

        estimator = model.estimator
        if not isinstance(estimator, Pipeline) or len(estimator.steps) != 2:
            raise UnsupportedModelError("pipeline TF-IDF → classifieur linéaire attendu")
        vectorizer, classifier = estimator.steps[0][1], estimator.steps[-1][1]
        if not isinstance(vectorizer, TfidfVectorizer):
            raise UnsupportedModelError(f"{type(vectorizer).__name__} : TF-IDF attendu")
        if vectorizer.analyzer not in ("char_wb", "word"):
            raise UnsupportedModelError(f"analyseur {vectorizer.analyzer!r} non pris en charge")
        coef = getattr(classifier, "coef_", None)
        if coef is None or np.asarray(coef).shape[0] != 1:
            raise UnsupportedModelError("classifieur linéaire binaire attendu")
        self.model = model
        self.vectorizer = vectorizer
        self.analyzer: str = vectorizer.analyzer
        self.coef = np.asarray(coef, dtype=float).ravel()
        self.intercept = float(np.asarray(classifier.intercept_, dtype=float).ravel()[0])
        self.space: Space = "log_odds" if hasattr(classifier, "predict_proba") else "margin"
        self.vocabulary = vectorizer.get_feature_names_out()
        self._preprocess = vectorizer.build_preprocessor()
        self._tokenize = vectorizer.build_tokenizer()
        stop_words = vectorizer.get_stop_words()
        self._stop_words = frozenset(stop_words) if stop_words else frozenset()

    def _contributions(self, text: str) -> dict[str, float]:
        row = self.vectorizer.transform([text]).tocsr()
        return {
            str(self.vocabulary[j]): float(self.coef[j] * value)
            for j, value in zip(row.indices, row.data, strict=True)
        }

    def explain(self, text: str) -> TextExplanation:
        contributions = self._contributions(text)
        document = self._preprocess(text)
        ngram_range = tuple(self.vectorizer.ngram_range)
        if self.analyzer == "char_wb":
            terms = _char_wb_terms(document, ngram_range, contributions)
        else:
            tokens = [t for t in self._tokenize(document) if t not in self._stop_words]
            terms = _word_terms(tokens, ngram_range, contributions)
        categories = message_categories(text)
        amounts = amount_numbers(document)
        by_category: dict[str, list[str]] = defaultdict(list)
        for term in terms:
            evoked = set(word_categories(term.term))
            if term.term.strip(".,;:!?") in amounts:
                evoked.add("money")
            for category in evoked & set(categories):
                by_category[category].append(term.term)
        return TextExplanation(
            intercept=self.intercept,
            terms=terms,
            categories=categories,
            category_terms={c: tuple(words) for c, words in by_category.items()},
            analyzer=self.analyzer,
            space=self.space,
        )

    def explain_many(self, texts: Iterable[str]) -> list[TextExplanation]:
        return [self.explain(t) for t in texts]
