"""Augmentation adversariale de l'entraînement (étape 3.9).

L'entraînement adversarial ajoute au **seul bloc d'entraînement** des copies perturbées
de ses échantillons, avec la même étiquette, pour que le modèle apprenne que la forme
ajoutée par l'attaquant (sous-domaines, chemin, paramètre, mots de remplissage,
chiffres) ne change pas la nature d'un leurre.

**Un générateur distinct de celui du banc d'essai.** Si le modèle s'entraînait sur les
perturbations exactes du banc (étape 3.7), il apprendrait ses mots, ses labels et ses
graines, et le banc mesurerait sa mémoire plutôt que sa robustesse. Ce module réutilise
les *techniques* de :mod:`phishguard.adversarial.perturb`, mais avec :

- ses **propres vocabulaires**, disjoints de ceux du banc (mots de remplissage,
  sous-domaines, segments de chemin, noms de paramètres), ce que vérifient les tests ;
- ses **propres réglages**, tirés au hasard dans une plage pour chaque échantillon
  (nombre de mots, profondeur du chemin, longueur du paramètre, taux de remplacement) ;
- d'autres **séparateurs** et une autre **table leet** ;
- sa **propre graine** (:data:`TRAINING_SEED`), le banc utilisant la graine 0.

Les techniques de caractères (homoglyphes, largeur nulle, casse) ne sont pas utilisées :
la normalisation de l'étape 3.8 les annule avant le modèle, leurs copies seraient
identiques aux originaux. Les homographes d'hôte non plus : ils fabriquent un autre
domaine, et une URL légitime réécrite n'est plus légitime.

**Pas de fuite entre blocs.** Les perturbations d'URL gardent le domaine enregistré, et
le split de l'étape 1.4 est groupé par domaine : une copie reste dans le bloc de son
original. Le texte ne passe pas d'un bloc à l'autre non plus : seul l'entraînement est
augmenté, la validation (seuils) et le test restent intacts.

Déterministe : même entrée, même graine, même sortie (graine par échantillon tirée d'un
CRC32, comme le banc).
"""

from __future__ import annotations

import random
from collections import Counter
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Literal

import numpy as np

from phishguard.adversarial import perturb as P

AugmentedClasses = Literal["phishing", "both"]

GENERATOR_VERSION = "1.0.0"
# Graine de l'entraînement : jamais celle du banc d'essai (0 par défaut).
TRAINING_SEED = 3_009

LABEL_PHISHING = 1

# --------------------------------------------------------------------------- #
# Vocabulaires d'entraînement, disjoints de ceux du banc d'essai
# --------------------------------------------------------------------------- #

# Mots de messages personnels anodins (anglais, comme le corpus SMS), écrits à la main
# et sans regarder les coefficients du modèle. Aucun n'est dans P.BENIGN_WORDS.
TRAINING_BENIGN_WORDS: tuple[str, ...] = (
    "cheers", "call", "me", "when", "free", "after", "school", "kids", "game", "match",
    "coffee", "movie", "train", "station", "pick", "up", "dad", "sis", "bro", "birthday",
    "party", "cake", "gym", "shopping", "groceries", "milk", "bread", "rain", "cold",
    "sunny", "beach", "holiday", "friday", "saturday", "sunday", "meeting", "office",
    "boss", "exam", "homework", "library", "drive", "car", "parking", "text", "back",
    "great", "awesome", "cool", "sure", "maybe", "busy", "tired", "hungry", "pizza",
)  # fmt: skip
# Sous-domaines et segments de chemin d'allure légitime, aucun en commun avec le banc.
TRAINING_SUBDOMAINS: tuple[str, ...] = (
    "www3", "secure", "account", "my", "web", "m", "mobile", "de", "es", "it", "shop",
    "store", "news", "blog", "media", "img", "files", "go", "info", "service",
)  # fmt: skip
TRAINING_PATH_SEGMENTS: tuple[str, ...] = (
    "de", "es", "it", "home", "page", "pages", "content", "media", "images", "public",
    "site", "portal", "account", "user", "customer", "faq", "info", "about", "2025",
    "v2", "app", "includes", "resources", "files",
)  # fmt: skip
TRAINING_TRACKING_PARAMS: tuple[str, ...] = (
    "utm_medium", "utm_content", "utm_term", "fbclid", "gclid", "mc_eid", "session",
    "cid", "track", "_hsenc",
)  # fmt: skip
# Séparateurs de lettres : le banc utilise « . ».
TRAINING_SEPARATORS: tuple[str, ...] = ("-", "_", "*")
# Table leet différente de P.LEET : symboles en plus des chiffres.
TRAINING_LEET: dict[str, str] = {
    "a": "@", "b": "8", "e": "3", "g": "9", "i": "!", "o": "0", "s": "$", "t": "+",
}  # fmt: skip


# --------------------------------------------------------------------------- #
# Recettes
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Recipe:
    """Une technique d'évasion et la plage de ses réglages à l'entraînement.

    ``apply_one(sample, rnd)`` tire ses réglages dans ``rnd`` : deux échantillons ne
    reçoivent pas la même intensité, contrairement au banc où elle est fixe.
    """

    name: str
    vector: P.Vector
    technique: str
    description: str
    apply_one: Callable[[str, random.Random], str]


def _pad(text: str, rnd: random.Random) -> str:
    words = rnd.sample(TRAINING_BENIGN_WORDS, k=len(TRAINING_BENIGN_WORDS))
    return P.pad_benign(text, words, n=rnd.randint(8, 60))


def _leet(text: str, rnd: random.Random) -> str:
    return P.leetspeak(
        text, rate=rnd.uniform(0.2, 0.8), seed=rnd.getrandbits(32), table=TRAINING_LEET
    )


def _split(text: str, rnd: random.Random) -> str:
    return P.split_with_symbols(
        text,
        rnd.choice(TRAINING_SEPARATORS),
        min_length=4,
        rate=rnd.uniform(0.3, 0.8),
        seed=rnd.getrandbits(32),
    )


def _subdomains(url: str, rnd: random.Random) -> str:
    return P.add_subdomains(
        url, n=rnd.randint(1, 3), labels=TRAINING_SUBDOMAINS, seed=rnd.getrandbits(32)
    )


def _path(url: str, rnd: random.Random) -> str:
    return P.add_benign_path(
        url, depth=rnd.randint(1, 4), segments=TRAINING_PATH_SEGMENTS, seed=rnd.getrandbits(32)
    )


def _param(url: str, rnd: random.Random) -> str:
    return P.add_long_param(
        url, length=rnd.randint(40, 320), seed=rnd.getrandbits(32), names=TRAINING_TRACKING_PARAMS
    )


RECIPES: dict[str, Recipe] = {
    r.name: r
    for r in (
        Recipe("pad_words", "text", "TXT-05", "8 à 60 mots anodins ajoutés à la fin", _pad),
        Recipe("leet_symbols", "text", "TXT-04", "20 à 80 % des lettres en chiffres ou symboles", _leet),
        Recipe("split_dashes", "text", "TXT-03", "30 à 80 % des mots coupés par « - », « _ » ou « * »", _split),
        Recipe("subdomains", "url", "URL-03", "1 à 3 sous-domaines d'allure légitime", _subdomains),
        Recipe("benign_path", "url", "URL-04", "page déplacée sous 1 à 4 répertoires", _path),
        Recipe("long_param", "url", "URL-06", "paramètre de suivi de 40 à 320 caractères", _param),
    )
}  # fmt: skip


def recipes_for(vector: P.Vector) -> list[Recipe]:
    """Recettes d'un vecteur, dans l'ordre du registre."""
    return [r for r in RECIPES.values() if r.vector == vector]


# --------------------------------------------------------------------------- #
# Augmentation
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Augmentation:
    """Bloc d'entraînement augmenté : originaux d'abord, puis les copies perturbées.

    ``origin[i]`` est l'indice de l'original dont l'échantillon ``i`` est la copie
    (lui-même pour un original). ``recipe[i]`` est la recette appliquée, ``None`` pour
    un original.
    """

    samples: list[str]
    labels: np.ndarray
    origin: np.ndarray
    recipe: list[str | None]
    skipped: int = 0  # échantillons choisis qu'aucune recette n'a pu modifier
    by_recipe: dict[str, int] = field(default_factory=dict)

    @property
    def n_original(self) -> int:
        return sum(r is None for r in self.recipe)

    @property
    def n_added(self) -> int:
        return len(self.samples) - self.n_original

    @property
    def is_copy(self) -> np.ndarray:
        return np.array([r is not None for r in self.recipe], dtype=bool)

    def summary(self) -> dict[str, object]:
        """Comptes seulement, jamais d'échantillon (rapports versionnés)."""
        labels = self.labels[self.is_copy]
        return {
            "original": self.n_original,
            "added": self.n_added,
            "added_phishing": int((labels == LABEL_PHISHING).sum()),
            "added_legitimate": int((labels != LABEL_PHISHING).sum()),
            "skipped": self.skipped,
            "by_recipe": dict(self.by_recipe),
        }


def augment(
    samples: Sequence[str],
    labels: Sequence[int] | np.ndarray,
    vector: P.Vector,
    *,
    classes: AugmentedClasses = "phishing",
    copies: int = 1,
    seed: int = TRAINING_SEED,
    recipes: Sequence[Recipe] | None = None,
) -> Augmentation:
    """Ajoute ``copies`` versions perturbées de chaque échantillon choisi.

    ``classes`` : ``"phishing"`` (le plan de l'étape 3.9) ou ``"both"``, qui perturbe
    aussi le légitime. Le second apprend au modèle que la forme ajoutée n'est un indice
    ni dans un sens ni dans l'autre ; le premier peut au contraire lui apprendre qu'elle
    signale le phishing, et faire monter les faux positifs.

    Pour chaque copie, les recettes sont essayées dans un ordre tiré au hasard, jusqu'à
    la première qui modifie l'échantillon. S'il n'y en a aucune, l'échantillon n'est
    pas copié et compte dans ``skipped``.
    """
    if copies < 1:
        raise ValueError(f"copies doit être au moins 1 : {copies!r}")
    if classes not in ("phishing", "both"):
        raise ValueError(f"classes inconnues : {classes!r}")
    samples = list(samples)
    y = np.asarray(labels).astype(int)
    if y.shape != (len(samples),):
        raise ValueError("une étiquette par échantillon est attendue")
    pool = list(recipes) if recipes is not None else recipes_for(vector)
    if not pool:
        raise ValueError(f"aucune recette pour le vecteur {vector!r}")
    if any(r.vector != vector for r in pool):
        raise ValueError(f"recettes d'un autre vecteur que {vector!r}")

    out_samples, out_labels = list(samples), list(y)
    origin, applied = list(range(len(samples))), [None] * len(samples)
    counts: Counter[str] = Counter()
    skipped = 0
    for i, (sample, label) in enumerate(zip(samples, y, strict=True)):
        if classes == "phishing" and label != LABEL_PHISHING:
            continue
        for copy in range(copies):
            # Générateur non cryptographique voulu : augmentation reproductible.
            rnd = random.Random(P.sample_seed(seed + copy, sample))  # nosec B311
            order = rnd.sample(pool, k=len(pool))
            for recipe in order:
                perturbed = recipe.apply_one(sample, rnd)
                if perturbed and perturbed != sample:
                    out_samples.append(perturbed)
                    out_labels.append(int(label))
                    origin.append(i)
                    applied.append(recipe.name)
                    counts[recipe.name] += 1
                    break
            else:
                skipped += 1
    return Augmentation(
        samples=out_samples,
        labels=np.asarray(out_labels, dtype=int),
        origin=np.asarray(origin, dtype=int),
        recipe=applied,
        skipped=skipped,
        by_recipe={r.name: counts[r.name] for r in pool},
    )
