"""Bibliothèque de perturbations (étape 3.6).

Chaque fonction reproduit une technique d'évasion du catalogue
(``docs/evasion-catalog.md``) en modifiant la **forme** d'un échantillon sans en changer
le sens pour un lecteur : une URL perturbée mène toujours au même serveur, un message
perturbé se lit toujours de la même façon. C'est ce qui distingue une évasion d'un bruit.

Usage : **évaluer et renforcer les détecteurs** de PhishGuard, jamais produire des
leurres. Le banc d'essai (étape 3.7) applique ces perturbations aux échantillons du jeu
de test et mesure le rappel avant et après ; l'entraînement adversarial (étape 3.9) les
applique au seul jeu d'entraînement.

Garanties, vérifiées par ``tests/test_adversarial_perturb.py`` :

- **déterminisme** : même entrée, même graine, même sortie, sur toutes les machines
  (``random.Random`` et une graine par échantillon tirée d'un CRC32, jamais de
  ``hash()``, qui change d'un processus à l'autre) ;
- **modification** : une entrée où la technique s'applique ressort modifiée et non vide.
  Une technique à taux (``rate``) qui ne tire aucune position en modifie quand même une ;
- **sens préservé** : retirer la perturbation redonne l'entrée (largeur nulle,
  homoglyphes, casse), et une URL perturbée reste valide et garde son domaine enregistré.

Une entrée où la technique ne peut pas s'appliquer (aucune lettre remplaçable, URL sur
une adresse IP pour les sous-domaines) est rendue telle quelle : :func:`apply` le compte
à part, pour que le banc d'essai ne mesure pas une perturbation qui n'a pas eu lieu.
"""

from __future__ import annotations

import random
import string
import zlib
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Literal
from urllib.parse import urlsplit, urlunsplit

from phishguard.urls.features import is_ip_host, parse_host

Vector = Literal["url", "text"]

ZW = "\u200b"  # ZERO WIDTH SPACE : invisible, catégorie Unicode Cf
ZERO_WIDTH_CHARS = ("\u200b", "\u200c", "\u200d", "\u2060", "\ufeff")

# Lettres latines → lettre identique d'une autre écriture (cyrillique, sauf mention).
# Choisies pour être indiscernables dans les polices courantes : ce sont celles des
# attaques par homographe connues, et celles que l'étape 3.8 doit replier.
HOMOGLYPHS: dict[str, str] = {
    "a": "а", "c": "с", "e": "е", "i": "і", "j": "ј", "o": "о", "p": "р", "s": "ѕ",
    "x": "х", "y": "у",
    "A": "А", "B": "В", "C": "С", "E": "Е", "H": "Н", "I": "І", "K": "К", "M": "М",
    "O": "О", "P": "Р", "T": "Т", "X": "Х",
}  # fmt: skip
# Remplacements « leet » courants : un chiffre ou un symbole qui ressemble à la lettre.
LEET: dict[str, str] = {"a": "4", "e": "3", "i": "1", "o": "0", "s": "5", "t": "7", "l": "1"}

# Mots de messages personnels anodins (anglais, comme le corpus d'entraînement du modèle
# SMS). Écrits à la main, sans regarder les coefficients du modèle : la dilution reste
# une attaque en boîte noire (AML.T0043.003), pas une optimisation.
BENIGN_WORDS: tuple[str, ...] = (
    "hey", "thanks", "see", "you", "later", "tonight", "home", "dinner", "love", "mum",
    "sorry", "late", "ok", "lunch", "tomorrow", "morning", "sleep", "work", "soon",
    "miss", "hope", "fine", "good", "night", "weekend", "bus", "class", "yeah", "lol",
    "haha",
)  # fmt: skip
# Segments de chemin et sous-domaines d'allure légitime (pages d'aide, langues, CMS).
BENIGN_PATH_SEGMENTS: tuple[str, ...] = (
    "fr", "en", "help", "support", "aide", "docs", "index", "articles", "news", "blog",
    "wp-content", "uploads", "2026", "static", "assets",
)  # fmt: skip
BENIGN_SUBDOMAINS: tuple[str, ...] = (
    "www2", "fr", "en", "support", "help", "portal", "app", "mail", "cdn", "static",
)  # fmt: skip
# Noms de paramètres de suivi : ceux qu'ajoutent les outils d'emailing et d'analytics.
TRACKING_PARAMS: tuple[str, ...] = ("utm_source", "utm_campaign", "ref", "sid", "token", "trk")

_TOKEN_ALPHABET = string.ascii_letters + string.digits


# --------------------------------------------------------------------------- #
# Outils
# --------------------------------------------------------------------------- #


def sample_seed(seed: int, sample: str) -> int:
    """Graine propre à un échantillon, stable d'une machine et d'un processus à l'autre.

    Chaque échantillon reçoit ainsi ses propres positions perturbées, sans que le
    résultat dépende de l'ordre des échantillons ni de ``PYTHONHASHSEED``.
    """
    return zlib.crc32(sample.encode("utf-8", "surrogatepass"), seed & 0xFFFFFFFF)


def _pick(rnd: random.Random, positions: Sequence[int], rate: float) -> list[int]:
    """Positions tirées avec la probabilité ``rate``, au moins une si possible."""
    if not 0.0 < rate <= 1.0:
        raise ValueError(f"rate doit être dans ]0, 1] : {rate!r}")
    chosen = [p for p in positions if rnd.random() < rate]
    if not chosen and positions:
        chosen = [rnd.choice(positions)]
    return chosen


def _replace(text: str, table: dict[str, str], rate: float, seed: int) -> str:
    # Générateur non cryptographique voulu : perturbation déterministe (voir le module).
    rnd = random.Random(seed)  # nosec B311
    chosen = set(_pick(rnd, [i for i, c in enumerate(text) if c in table], rate))
    return "".join(table[c] if i in chosen else c for i, c in enumerate(text))


# --------------------------------------------------------------------------- #
# Texte (TXT-01 à TXT-05)
# --------------------------------------------------------------------------- #


def insert_zero_width(text: str, every: int = 3, char: str = ZW) -> str:
    """Glisse ``char`` après chaque ``every``-ième lettre d'un mot (TXT-02).

    Les caractères sont insérés **à l'intérieur des mots** seulement, là où ils coupent
    les n-grammes ; jamais après la dernière lettre d'un mot.
    """
    if every < 1:
        raise ValueError(f"every doit être au moins 1 : {every!r}")
    if char not in ZERO_WIDTH_CHARS:
        raise ValueError(f"{char!r} n'est pas un caractère de largeur nulle")
    out: list[str] = []
    run = 0
    for i, c in enumerate(text):
        out.append(c)
        if c.isalnum():
            run += 1
            following = text[i + 1] if i + 1 < len(text) else ""
            if run % every == 0 and following.isalnum():
                out.append(char)
        else:
            run = 0
    return "".join(out)


def swap_homoglyphs(text: str, rate: float = 0.3, seed: int = 0) -> str:
    """Remplace des lettres latines par une lettre identique d'une autre écriture (TXT-01)."""
    return _replace(text, HOMOGLYPHS, rate, seed)


def leetspeak(text: str, rate: float = 0.5, seed: int = 0, table: Mapping[str, str] = LEET) -> str:
    """Remplace des lettres par un chiffre qui leur ressemble : ``compte`` → ``c0mpt3`` (TXT-04).

    Seules les minuscules sont remplacées, comme dans les leurres réels.
    """
    return _replace(text, dict(table), rate, seed)


def split_with_symbols(
    text: str, separator: str = ".", min_length: int = 4, rate: float = 0.5, seed: int = 0
) -> str:
    """Sépare les lettres de mots choisis par ``separator`` : ``code`` → ``c.o.d.e`` (TXT-03).

    Seuls les mots entièrement alphabétiques d'au moins ``min_length`` lettres sont
    candidats : un nombre ou un lien coupé ne se lirait plus.
    """
    if not separator or separator.isalnum():
        raise ValueError(f"separator doit être un symbole : {separator!r}")
    words = text.split(" ")
    candidates = [i for i, w in enumerate(words) if w.isalpha() and len(w) >= min_length]
    # Générateur non cryptographique voulu : perturbation déterministe (voir le module).
    chosen = set(_pick(random.Random(seed), candidates, rate))  # nosec B311
    return " ".join(separator.join(w) if i in chosen else w for i, w in enumerate(words))


def pad_benign(text: str, benign_words: Sequence[str] = BENIGN_WORDS, n: int = 20) -> str:
    """Ajoute ``n`` mots anodins à la fin du message (TXT-05, dilution)."""
    if n < 1:
        raise ValueError(f"n doit être au moins 1 : {n!r}")
    words = [w for w in benign_words if w.strip()]
    if not words:
        raise ValueError("benign_words ne contient aucun mot")
    padding = [words[i % len(words)] for i in range(n)]
    return f"{text} {' '.join(padding)}"


# --------------------------------------------------------------------------- #
# URL (URL-02, URL-03, URL-04, URL-06, URL-07)
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class _Netloc:
    userinfo: str  # avec son « @ », ou vide
    host: str
    port: str  # avec son « : », ou vide

    @classmethod
    def parse(cls, netloc: str) -> _Netloc:
        userinfo, at, hostport = netloc.rpartition("@")
        if hostport.startswith("["):  # IPv6 littérale
            end = hostport.find("]") + 1
            host, port = hostport[:end], hostport[end:]
        else:
            host, colon, port = hostport.partition(":")
            port = colon + port
        return cls(userinfo + at, host, port)

    def __str__(self) -> str:
        return f"{self.userinfo}{self.host}{self.port}"


def _with_scheme(url: str) -> tuple[str, bool]:
    """URL avec un schéma (ajouté si absent, comme le fait la normalisation)."""
    if "://" in url.split("?", 1)[0]:
        return url, False
    return f"http://{url}", True


def _rebuild(parts, netloc: _Netloc | None = None, **changes: str) -> str:
    fields = parts._replace(netloc=parts.netloc if netloc is None else str(netloc), **changes)
    return urlunsplit(fields)


def _restore(url: str, added_scheme: bool) -> str:
    return url[len("http://") :] if added_scheme else url


def add_subdomains(
    url: str, n: int = 2, labels: Sequence[str] = BENIGN_SUBDOMAINS, seed: int = 0
) -> str:
    """Ajoute ``n`` sous-domaines d'allure légitime devant l'hôte (URL-03).

    Le domaine enregistré ne change pas : l'attaquant le contrôle et crée les
    sous-domaines qu'il veut. Une URL sur une adresse IP, ou dont l'hôte est lui-même un
    suffixe (``github.io``, où un sous-domaine appartient à quelqu'un d'autre), est rendue
    telle quelle.
    """
    if n < 1:
        raise ValueError(f"n doit être au moins 1 : {n!r}")
    url, added = _with_scheme(url)
    parts = urlsplit(url)
    netloc = _Netloc.parse(parts.netloc)
    if not netloc.host or is_ip_host(netloc.host.strip("[]").lower()):
        return _restore(url, added)
    # Générateur non cryptographique voulu : perturbation déterministe (voir le module).
    rnd = random.Random(seed)  # nosec B311
    prefix = ".".join(rnd.choice(labels) for _ in range(n))
    host = f"{prefix}.{netloc.host}"
    if (
        parse_host(host.lower()).registered_domain
        != parse_host(netloc.host.lower()).registered_domain
    ):
        return _restore(url, added)
    return _restore(_rebuild(parts, _Netloc(netloc.userinfo, host, netloc.port)), added)


def add_benign_path(
    url: str, depth: int = 3, segments: Sequence[str] = BENIGN_PATH_SEGMENTS, seed: int = 0
) -> str:
    """Place la page sous ``depth`` répertoires d'allure légitime (URL-04).

    ``/login.php`` devient ``/help/fr/docs/login.php`` : la page reste la même, déposée
    plus profond sur le serveur de l'attaquant.
    """
    if depth < 1:
        raise ValueError(f"depth doit être au moins 1 : {depth!r}")
    url, added = _with_scheme(url)
    parts = urlsplit(url)
    # Générateur non cryptographique voulu : perturbation déterministe (voir le module).
    rnd = random.Random(seed)  # nosec B311
    prefix = "/".join(rnd.choice(segments) for _ in range(depth))
    path = f"/{prefix}{parts.path if parts.path.startswith('/') else '/' + parts.path}"
    return _restore(_rebuild(parts, path=path), added)


def add_long_param(
    url: str, length: int = 200, seed: int = 0, names: Sequence[str] = TRACKING_PARAMS
) -> str:
    """Ajoute un paramètre de suivi de ``length`` caractères à la requête (URL-06)."""
    if length < 1:
        raise ValueError(f"length doit être au moins 1 : {length!r}")
    if not names:
        raise ValueError("names ne contient aucun nom de paramètre")
    url, added = _with_scheme(url)
    parts = urlsplit(url)
    # Générateur non cryptographique voulu : perturbation déterministe (voir le module).
    rnd = random.Random(seed)  # nosec B311
    value = "".join(rnd.choice(_TOKEN_ALPHABET) for _ in range(length))
    param = f"{rnd.choice(names)}={value}"
    query = f"{parts.query}&{param}" if parts.query else param
    return _restore(_rebuild(parts, query=query), added)


def partial_uppercase(url: str, rate: float = 0.5, seed: int = 0) -> str:
    """Met en majuscules une partie des lettres de l'hôte (URL-07).

    Seul l'hôte est touché : il est insensible à la casse (RFC 4343), alors que le chemin
    peut ne pas l'être côté serveur, et la page changerait.
    """
    url, added = _with_scheme(url)
    parts = urlsplit(url)
    netloc = _Netloc.parse(parts.netloc)
    host = netloc.host
    # Générateur non cryptographique voulu : perturbation déterministe (voir le module).
    rnd = random.Random(seed)  # nosec B311
    letters = [i for i, c in enumerate(host) if c.isascii() and c.islower()]
    chosen = set(_pick(rnd, letters, rate))
    host = "".join(c.upper() if i in chosen else c for i, c in enumerate(host))
    return _restore(_rebuild(parts, _Netloc(netloc.userinfo, host, netloc.port)), added)


def swap_host_homoglyphs(url: str, rate: float = 0.3, seed: int = 0) -> str:
    """Remplace des lettres de l'hôte par des homoglyphes cyrilliques (URL-02).

    Le résultat est un nom de domaine internationalisé, que le navigateur transmettra en
    Punycode. **Il désigne un autre domaine** : c'est celui que l'attaquant enregistre,
    et c'est ce que le détecteur doit reconnaître comme une imitation. Le suffixe public
    (``.com``, ``.co.uk``) n'est jamais touché : il doit rester un suffixe existant.
    """
    url, added = _with_scheme(url)
    parts = urlsplit(url)
    netloc = _Netloc.parse(parts.netloc)
    host = netloc.host
    if not host or is_ip_host(host.strip("[]").lower()):
        return _restore(url, added)
    registered = parse_host(host.lower()).registered_domain
    _, dot, suffix = registered.partition(".")
    if not dot or not host.lower().endswith(f".{suffix}"):
        return _restore(url, added)  # pas de suffixe public reconnu
    head = host[: -len(suffix) - 1]
    head = _replace(head, {k: v for k, v in HOMOGLYPHS.items() if k.islower()}, rate, seed)
    netloc = _Netloc(netloc.userinfo, f"{head}.{host[-len(suffix) :]}", netloc.port)
    return _restore(_rebuild(parts, netloc), added)


# --------------------------------------------------------------------------- #
# Registre
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Perturbation:
    """Perturbation nommée, avec ses réglages, prête pour le banc d'essai.

    ``technique`` renvoie à la fiche du catalogue (``docs/evasion-catalog.md``).
    ``apply_one(sample, seed)`` reçoit déjà la graine propre à l'échantillon.
    ``creates_lookalike`` : la perturbation fabrique une imitation (un autre domaine). Un
    échantillon légitime perturbé n'est alors plus légitime, et le signaler est juste :
    son « FPR » ne mesure pas une fausse alerte.
    """

    name: str
    vector: Vector
    technique: str
    description: str
    apply_one: Callable[[str, int], str]
    creates_lookalike: bool = False

    def __call__(self, sample: str, seed: int = 0) -> str:
        return self.apply_one(sample, sample_seed(seed, sample))


@dataclass(frozen=True)
class Applied:
    """Échantillons perturbés, et lesquels l'ont vraiment été."""

    samples: list[str]
    changed: list[bool]

    @property
    def n_changed(self) -> int:
        return sum(self.changed)


PERTURBATIONS: dict[str, Perturbation] = {
    p.name: p
    for p in (
        # --- texte --------------------------------------------------------------- #
        Perturbation(
            "zero_width",
            "text",
            "TXT-02",
            "U+200B après chaque troisième lettre d'un mot",
            lambda s, seed: insert_zero_width(s, every=3),
        ),
        Perturbation(
            "homoglyphs",
            "text",
            "TXT-01",
            "30 % des lettres remplaçables par leur homoglyphe cyrillique",
            lambda s, seed: swap_homoglyphs(s, rate=0.3, seed=seed),
        ),
        Perturbation(
            "leetspeak",
            "text",
            "TXT-04",
            "50 % des lettres a, e, i, l, o, s, t remplacées par un chiffre",
            lambda s, seed: leetspeak(s, rate=0.5, seed=seed),
        ),
        Perturbation(
            "split_symbols",
            "text",
            "TXT-03",
            "la moitié des mots de 4 lettres ou plus coupés par des points",
            lambda s, seed: split_with_symbols(s, ".", min_length=4, rate=0.5, seed=seed),
        ),
        Perturbation(
            "pad_benign",
            "text",
            "TXT-05",
            "20 mots de messages personnels ajoutés à la fin",
            lambda s, seed: pad_benign(s, BENIGN_WORDS, n=20),
        ),
        # Variantes à intensité maximale (étape 3.7) : le premier passage du banc a
        # montré que les n-grammes de caractères résistent aux réglages modérés. Un
        # attaquant n'a aucune raison de s'arrêter là, le lecteur ne voit pas la
        # différence.
        Perturbation(
            "homoglyphs_full",
            "text",
            "TXT-01",
            "toutes les lettres remplaçables par leur homoglyphe cyrillique",
            lambda s, seed: swap_homoglyphs(s, rate=1.0, seed=seed),
        ),
        Perturbation(
            "zero_width_dense",
            "text",
            "TXT-02",
            "U+200B entre toutes les lettres d'un mot",
            lambda s, seed: insert_zero_width(s, every=1),
        ),
        Perturbation(
            "pad_benign_long",
            "text",
            "TXT-05",
            "50 mots de messages personnels ajoutés à la fin",
            lambda s, seed: pad_benign(s, BENIGN_WORDS, n=50),
        ),
        # --- URL ----------------------------------------------------------------- #
        Perturbation(
            "url_subdomains",
            "url",
            "URL-03",
            "2 sous-domaines d'allure légitime devant l'hôte",
            lambda s, seed: add_subdomains(s, n=2, seed=seed),
        ),
        Perturbation(
            "url_benign_path",
            "url",
            "URL-04",
            "page déplacée sous 3 répertoires d'allure légitime",
            lambda s, seed: add_benign_path(s, depth=3, seed=seed),
        ),
        Perturbation(
            "url_long_param",
            "url",
            "URL-06",
            "paramètre de suivi de 200 caractères ajouté à la requête",
            lambda s, seed: add_long_param(s, length=200, seed=seed),
        ),
        Perturbation(
            "url_uppercase",
            "url",
            "URL-07",
            "la moitié des lettres de l'hôte en majuscules",
            lambda s, seed: partial_uppercase(s, rate=0.5, seed=seed),
        ),
        Perturbation(
            "url_homoglyphs",
            "url",
            "URL-02",
            "30 % des lettres remplaçables de l'hôte (hors TLD) en cyrillique",
            lambda s, seed: swap_host_homoglyphs(s, rate=0.3, seed=seed),
            creates_lookalike=True,
        ),
    )
}


def perturbations_for(vector: Vector) -> list[Perturbation]:
    """Perturbations d'un vecteur, dans l'ordre du registre."""
    return [p for p in PERTURBATIONS.values() if p.vector == vector]


def apply(name: str, samples: Iterable[str], seed: int = 0) -> Applied:
    """Applique la perturbation ``name`` à chaque échantillon, avec sa propre graine."""
    try:
        perturbation = PERTURBATIONS[name]
    except KeyError:
        raise ValueError(f"perturbation inconnue : {name!r}") from None
    originals = list(samples)
    perturbed = [perturbation(s, seed) for s in originals]
    return Applied(perturbed, [p != o for p, o in zip(perturbed, originals, strict=True)])
