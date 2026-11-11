"""Du jargon aux phrases : raisons lisibles et conseil d'action (étape 3.2).

Un analyste lit « ``is_typosquat`` = 1 (+1,9) » ; un utilisateur doit lire « L'adresse
ressemble à celle de paypal mais n'est pas la sienne. » Ce module fait la traduction :

1. **Raisons du modèle URL.** Seules les features *compréhensibles* deviennent des
   phrases (:data:`FEATURE_REASONS`). « Le chemin fait 4 caractères » reste dans la vue
   analyste (étape 3.1, ``docs/explain-url.md``). Chaque raison reçoit une part des
   points du modèle, proportionnelle à sa contribution SHAP, et les raisons sont rangées
   en trois niveaux :

   - les **indices** précis et vérifiables (une marque dans l'hôte, une adresse IP, un
     TLD à risque), par poids ;
   - puis les indices de **forme** (hôte long, chargé de tirets ou de chiffres) : ils
     reflètent en partie le biais de popularité des données (étape 3.1) et ne font que
     compléter la liste ;
   - enfin, pour un verdict suspect ou phishing, les **constats** précis qui n'ont pas
     fait monter le score (un raccourcisseur), cités avec 0 point.
2. **Raisons des sources** (âge du domaine, VirusTotal…) et **règles dures**, avec leurs
   points de la fusion (étape 2.10).
3. **Au plus trois raisons**, de la plus forte à la plus faible, et **toujours un
   conseil d'action**, selon le canal et le verdict.

Les phrases viennent de gabarits YAML, un par langue (``templates.fr.yml``, ``en``,
``ar``), qui ont tous les mêmes clés et les mêmes variables.

**Sécurité.** Une explication ne recopie jamais l'entrée telle quelle : un fragment issu
de l'URL ou du message (une extension, un mot) passe par :func:`safe_fragment`, qui retire
les caractères invisibles et de contrôle (dont les inversions de sens d'écriture), les
caractères de balisage, et rend les adresses non cliquables. Les messages restent du
**texte brut** : un client doit les insérer comme texte (``textContent``), jamais comme
HTML.
"""

from __future__ import annotations

import math
import re
import string
import unicodedata
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from functools import lru_cache
from importlib import resources
from typing import Any, Literal, cast
from urllib.parse import unquote

import yaml

from phishguard.enrichers.base import Signal, SignalStatus
from phishguard.explain.shap_url import UrlExplanation
from phishguard.explain.text import TextExplanation
from phishguard.fusion.mitre import Channel
from phishguard.fusion.score import MODEL, FusionResult, Verdict
from phishguard.urls.brands import BrandIndex, load_brands
from phishguard.urls.features import InvalidUrlError, parse_url
from phishguard.urls.idn import skeleton
from phishguard.urls.tld import top_level_domain

Language = Literal["fr", "en", "ar"]
LANGUAGES: tuple[Language, ...] = ("fr", "en", "ar")
DEFAULT_LANGUAGE: Language = "fr"
MAX_REASONS = 3
# Une contribution plus petite (en points de score) n'est pas citée comme raison.
MIN_REASON_POINTS = 0.5
FRAGMENT_MAX_LENGTH = 60

# Seuils au-delà desquels une feature numérique devient un indice lisible. Ils sont
# choisis pour être rares dans le légitime (voir docs/url-features.md) : la moyenne des
# hôtes Tranco fait 12,5 caractères, celle du phishing 29.
RISKY_TLD_RATE = 0.5  # plus d'une URL sur deux de ce TLD était du phishing à l'entraînement
MANY_SUBDOMAINS = 3
LONG_HOST = 30
MANY_HYPHENS = 3
MANY_DIGITS = 5

Params = Mapping[str, str | int]
ParamValue = str | int


class TemplateError(ValueError):
    """Fichier de gabarits invalide, ou gabarit appelé sans ses variables."""


# --------------------------------------------------------------------------- #
# Nettoyage des fragments issus de l'entrée
# --------------------------------------------------------------------------- #

# Contrôles, format (U+200B, U+202E…), surrogates, usage privé, non attribués, séparateurs
# de ligne et de paragraphe.
_DROPPED_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"})
_MARKUP = str.maketrans("", "", "<>&\"'`\\{}[]")
_SPACES_RE = re.compile(r"\s+")
_SCHEME_RE = re.compile(r"(?i)\b(h)tt(ps?)\b")
ELLIPSIS = "…"


def safe_fragment(text: object, max_length: int = FRAGMENT_MAX_LENGTH) -> str:
    """Fragment de l'entrée rendu inoffensif pour une phrase d'explication.

    - forme NFKC, espaces regroupés ;
    - caractères invisibles, de contrôle et d'inversion de sens retirés : ils
      permettraient de faire lire autre chose que ce qui est écrit ;
    - caractères de balisage retirés (``< > & " ' ` \\ { } [ ]``) : même inséré par
      erreur comme HTML, le fragment ne peut ni ouvrir une balise ni sortir d'un attribut ;
    - adresses désarmées (``hxxp``, ``[.]``, ``[@]``) : aucune messagerie ne les rend
      cliquables ;
    - au plus ``max_length`` caractères avant désarmement, ``…`` en cas de coupure.
    """
    if max_length < 1:
        raise ValueError("max_length doit être au moins 1")
    # NFKC écrit « … » en trois points, que le désarmement transformerait en « [.][.][.] » :
    # l'ellipse d'une coupure précédente est préservée.
    value = ELLIPSIS.join(unicodedata.normalize("NFKC", part) for part in str(text).split(ELLIPSIS))
    value = "".join(
        " " if c.isspace() else c
        for c in value
        if c.isspace() or unicodedata.category(c) not in _DROPPED_CATEGORIES
    )
    value = _SPACES_RE.sub(" ", value.translate(_MARKUP)).strip()
    if len(value) > max_length:
        value = value[: max_length - 1].rstrip() + ELLIPSIS
    value = _SCHEME_RE.sub(r"\1xx\2", value)
    return value.replace(".", "[.]").replace("@", "[@]")


def _clean_params(params: Mapping[str, Any]) -> dict[str, ParamValue]:
    cleaned: dict[str, ParamValue] = {}
    for key, value in params.items():
        if isinstance(value, bool) or not isinstance(value, int | str):
            raise TemplateError(f"variable {key!r} : entier ou texte attendu, pas {value!r}")
        cleaned[key] = value if isinstance(value, int) else safe_fragment(value)
    return cleaned


# --------------------------------------------------------------------------- #
# Gabarits
# --------------------------------------------------------------------------- #

_PLACEHOLDER_RE = re.compile(r"[a-z][a-z_]*")


def placeholders(template: str) -> frozenset[str]:
    """Variables d'un gabarit. Refuse les formats et les accès (``{x.y}``, ``{x[0]}``,
    ``{x!r}``, ``{x:>5}``) : un gabarit ne doit rien pouvoir lire d'autre qu'une valeur."""
    names = set()
    try:
        parsed = list(string.Formatter().parse(template))
    except ValueError as exc:
        raise TemplateError(f"gabarit mal formé : {template!r}") from exc
    for _literal, name, spec, conversion in parsed:
        if name is None:
            continue
        if not _PLACEHOLDER_RE.fullmatch(name) or spec or conversion:
            raise TemplateError(f"variable interdite {{{name}}} dans {template!r}")
        names.add(name)
    return frozenset(names)


@dataclass(frozen=True)
class Templates:
    """Gabarits d'une langue : raisons (par code) et conseils (par canal et verdict)."""

    language: Language
    version: int
    reasons: Mapping[str, str]
    advice: Mapping[str, str]

    def reason(self, code: str, params: Mapping[str, Any] | None = None) -> str:
        """Phrase de la raison ``code``, variables nettoyées par :func:`safe_fragment`."""
        try:
            template = self.reasons[code]
        except KeyError:
            raise TemplateError(f"{self.language} : aucun gabarit pour {code!r}") from None
        return _render(template, _clean_params(params or {}), code)

    def advice_for(self, channel: Channel, verdict: Verdict) -> str:
        key = f"{advice_channel(channel)}.{verdict}"
        try:
            return self.advice[key]
        except KeyError:
            raise TemplateError(f"{self.language} : aucun conseil pour {key!r}") from None


def _render(template: str, params: Mapping[str, ParamValue], code: str) -> str:
    missing = placeholders(template) - set(params)
    if missing:
        raise TemplateError(f"{code} : variables manquantes {sorted(missing)}")
    return template.format_map(params)


def advice_channel(channel: Channel) -> str:
    """Les SMS et les messageries partagent leurs conseils."""
    return "message" if channel in ("sms", "messaging") else channel


def _section(data: Mapping[str, Any], name: str, path: str) -> dict[str, str]:
    section = data.get(name)
    if not isinstance(section, dict) or not section:
        raise TemplateError(f"{path} : section {name!r} absente ou vide")
    for key, value in section.items():
        if not isinstance(key, str) or not isinstance(value, str) or not value.strip():
            raise TemplateError(f"{path} : {name}.{key} doit être un texte non vide")
        placeholders(value)
    return dict(section)


def parse_templates(text: str, language: Language, path: str = "<gabarits>") -> Templates:
    """Lit et valide un fichier de gabarits (YAML sûr : aucun objet Python construit)."""
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise TemplateError(f"{path} : YAML invalide") from exc
    if not isinstance(data, dict):
        raise TemplateError(f"{path} : un dictionnaire est attendu")
    if data.get("language") != language:
        raise TemplateError(f"{path} : langue {data.get('language')!r}, {language!r} attendue")
    version = data.get("version")
    if isinstance(version, bool) or not isinstance(version, int):
        raise TemplateError(f"{path} : version entière attendue")
    return Templates(
        language=language,
        version=version,
        reasons=_section(data, "reasons", path),
        advice=_section(data, "advice", path),
    )


def check_language(language: str) -> Language:
    if language not in LANGUAGES:
        raise ValueError(f"langue non prise en charge : {language!r} (connues : {LANGUAGES})")
    return cast(Language, language)


@lru_cache(maxsize=len(LANGUAGES))
def load_templates(language: str = DEFAULT_LANGUAGE) -> Templates:
    """Gabarits embarqués dans le paquet pour ``language``."""
    language = check_language(language)
    name = f"templates.{language}.yml"
    text = resources.files("phishguard.explain").joinpath(name).read_text("utf-8")
    return parse_templates(text, language, name)


# --------------------------------------------------------------------------- #
# Constats sur l'URL (marques, TLD)
# --------------------------------------------------------------------------- #

# Même découpage du chemin que phishguard.urls.features pour ``brand_in_path``.
_PATH_SEGMENT_SPLIT_RE = re.compile(r"[/?&=;#]")


@dataclass(frozen=True)
class UrlFacts:
    """Ce qu'une phrase peut citer d'une URL : marques imitées et extension."""

    tld: str = ""
    brand_in_host: str | None = None
    lookalike_brand: str | None = None
    homograph_brand: str | None = None
    brand_in_path: str | None = None


@lru_cache(maxsize=1)
def _default_brands() -> BrandIndex:
    return load_brands()


def url_facts(url: str, brands: BrandIndex | None = None) -> UrlFacts:
    """Marques et extension d'une URL, retrouvées comme les calculent les features.

    Une URL invalide donne des constats vides : l'explication ne doit jamais échouer.
    """
    try:
        parsed = parse_url(url)
    except InvalidUrlError:
        return UrlFacts()
    if parsed.is_ip:
        return UrlFacts()
    brands = brands or _default_brands()
    official = brands.official_for(parsed.registered_domain)
    labels = [*parsed.subdomains, parsed.domain_label]
    _distance, nearest = brands.nearest(parsed.domain_label, official)
    decoded = unquote(f"{parsed.path}?{parsed.query}" if parsed.query else parsed.path)
    return UrlFacts(
        tld=top_level_domain(parsed.host),
        brand_in_host=brands.find(labels, exclude=official),
        lookalike_brand=nearest,
        homograph_brand=brands.find(map(skeleton, labels), exclude=official),
        brand_in_path=brands.find(_PATH_SEGMENT_SPLIT_RE.split(decoded), exclude=official),
    )


# --------------------------------------------------------------------------- #
# Raisons tirées des features URL
# --------------------------------------------------------------------------- #

Features = Mapping[str, float]


def _on(name: str) -> Callable[[Features], bool]:
    return lambda f: f.get(name, 0.0) >= 1


def _at_least(name: str, threshold: float) -> Callable[[Features], bool]:
    return lambda f: f.get(name, 0.0) >= threshold


def _count(name: str) -> Callable[[UrlFacts, Features], Params | None]:
    return lambda _facts, f: {"n": int(f[name])}


def _brand(attribute: str) -> Callable[[UrlFacts, Features], Params | None]:
    def params(facts: UrlFacts, _f: Features) -> Params | None:
        brand = getattr(facts, attribute)
        return {"brand": brand} if brand else None

    return params


def _tld(facts: UrlFacts, _f: Features) -> Params | None:
    return {"tld": facts.tld} if facts.tld else None


def _no_params(_facts: UrlFacts, _f: Features) -> Params | None:
    return {}


Kind = Literal["cue", "shape"]


@dataclass(frozen=True)
class FeatureReason:
    """Une phrase possible pour un groupe de features du modèle URL.

    ``applies`` dit si la valeur est en elle-même un indice ; ``params`` donne les
    variables du gabarit (``None`` : la phrase ne peut pas être écrite, elle est omise).
    ``kind`` : indice précis (``cue``) ou de forme (``shape``). ``observation`` : constat
    assez net pour être cité même sans effet sur le score.
    """

    code: str
    features: tuple[str, ...]
    applies: Callable[[Features], bool]
    params: Callable[[UrlFacts, Features], Params | None] = _no_params
    kind: Kind = "cue"
    observation: bool = False


def _not_ip(condition: Callable[[Features], bool]) -> Callable[[Features], bool]:
    """Pour une adresse IP, la forme de l'hôte est déjà dite par ``url.ip_host``."""
    return lambda f: f.get("host_is_ip", 0.0) < 1 and condition(f)


FEATURE_REASONS: tuple[FeatureReason, ...] = (
    FeatureReason(
        "url.brand_lookalike",
        ("is_typosquat", "brand_min_distance"),
        _on("is_typosquat"),
        _brand("lookalike_brand"),
        observation=True,
    ),
    FeatureReason(
        "url.homograph",
        ("homograph_brand",),
        _on("homograph_brand"),
        _brand("homograph_brand"),
        observation=True,
    ),
    FeatureReason(
        "url.mixed_script", ("host_mixed_script",), _on("host_mixed_script"), observation=True
    ),
    FeatureReason(
        "url.brand_in_host",
        ("brand_in_host",),
        _on("brand_in_host"),
        _brand("brand_in_host"),
        observation=True,
    ),
    FeatureReason(
        "url.brand_in_path",
        ("brand_in_path",),
        _on("brand_in_path"),
        _brand("brand_in_path"),
        observation=True,
    ),
    FeatureReason("url.ip_host", ("host_is_ip",), _on("host_is_ip"), observation=True),
    FeatureReason("url.userinfo", ("has_userinfo",), _on("has_userinfo"), observation=True),
    FeatureReason("url.port", ("has_port",), _on("has_port")),
    FeatureReason("url.shortener", ("is_shortener",), _on("is_shortener"), observation=True),
    FeatureReason(
        "url.risky_tld", ("tld_phish_rate",), _at_least("tld_phish_rate", RISKY_TLD_RATE), _tld
    ),
    FeatureReason(
        "url.login_keywords",
        ("host_kw_hits", "path_kw_hits"),
        lambda f: f.get("host_kw_hits", 0.0) + f.get("path_kw_hits", 0.0) >= 1,
    ),
    FeatureReason("url.embedded_url", ("path_has_embedded_url",), _on("path_has_embedded_url")),
    FeatureReason(
        "url.many_subdomains",
        ("host_n_subdomains",),
        _at_least("host_n_subdomains", MANY_SUBDOMAINS),
        _count("host_n_subdomains"),
    ),
    FeatureReason(
        "url.long_host",
        ("host_len",),
        _not_ip(_at_least("host_len", LONG_HOST)),
        _count("host_len"),
        kind="shape",
    ),
    FeatureReason(
        "url.many_hyphens",
        ("host_n_hyphens",),
        _not_ip(_at_least("host_n_hyphens", MANY_HYPHENS)),
        _count("host_n_hyphens"),
        kind="shape",
    ),
    FeatureReason(
        "url.many_digits",
        ("host_n_digits",),
        _not_ip(_at_least("host_n_digits", MANY_DIGITS)),
        _count("host_n_digits"),
        kind="shape",
    ),
)
# Ordre d'affichage : indices et sources, puis forme, puis constats à 0 point.
TIER_CUE, TIER_SHAPE, TIER_OBSERVATION = 0, 1, 2


# --------------------------------------------------------------------------- #
# Explication
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class ReasonText:
    """Une raison prête à afficher : code stable, part du score, phrase, variables."""

    code: str
    source: str
    points: float
    message: str
    params: Params = field(default_factory=dict)


@dataclass(frozen=True)
class Explanation:
    """Ce que voit l'utilisateur : au plus trois raisons et un conseil d'action."""

    language: Language
    reasons: tuple[ReasonText, ...]
    advice: str


@dataclass(frozen=True)
class _Candidate:
    code: str
    source: str
    points: float
    params: Params
    tier: int = TIER_CUE


def _signal_candidate(source: str, points: float, signal: Signal | None) -> _Candidate:
    evidence = signal.evidence if signal is not None else {}
    if source == "rdap":
        age = evidence.get("age_days")
        if isinstance(age, int) and not isinstance(age, bool) and age >= 0:
            return _Candidate("signal.domain_age", source, points, {"n": age})
        return _Candidate("signal.rdap", source, points, {})
    if source == "virustotal":
        stats = evidence.get("stats")
        engines = 0
        if isinstance(stats, Mapping):
            engines = sum(
                v
                for k in ("malicious", "suspicious")
                if isinstance(v := stats.get(k), int) and not isinstance(v, bool)
            )
        if engines > 0:
            return _Candidate("signal.virustotal_engines", source, points, {"n": engines})
        return _Candidate("signal.virustotal", source, points, {})
    if source in ("urlscan", "dns", "certificate_transparency"):
        return _Candidate(f"signal.{source}", source, points, {})
    return _Candidate("signal.other", source, points, {"source": source})


def _strongest_ok(signals: Iterable[Signal]) -> dict[str, Signal]:
    """Le signal ``ok`` de plus fort risque par source, comme la fusion."""
    found: dict[str, Signal] = {}
    for signal in signals:
        if signal.status is not SignalStatus.OK:
            continue
        current = found.get(signal.source)
        if current is None or signal.risk > current.risk:
            found[signal.source] = signal
    return found


def feature_candidates(
    explanation: UrlExplanation,
    facts: UrlFacts,
    model_points: float,
    *,
    observations: bool = False,
) -> list[_Candidate]:
    """Raisons lisibles du modèle URL, avec leur part des points du modèle.

    Une raison est retenue si sa condition est remplie **et** que ses features ont poussé
    vers « phishing » (contribution SHAP positive). Sa part des points est
    ``model_points × contribution / somme des contributions positives`` : le reste
    revient à des features que l'utilisateur ne pourrait pas vérifier. Avec
    ``observations``, les constats précis sans effet sur le score sont ajoutés à 0 point.
    """
    attributions = explanation.by_name()
    values = {name: a.value for name, a in attributions.items()}
    positive_total = math.fsum(max(0.0, a.shap) for a in attributions.values())
    weighted: list[tuple[int, float, str, Params]] = []
    for rule in FEATURE_REASONS:
        if not any(name in attributions for name in rule.features) or not rule.applies(values):
            continue
        params = rule.params(facts, values)
        if params is None:
            continue
        weight = math.fsum(
            attributions[name].shap for name in rule.features if name in attributions
        )
        points = model_points * weight / positive_total if positive_total > 0 else 0.0
        if weight > 0 and points >= MIN_REASON_POINTS:
            tier = TIER_SHAPE if rule.kind == "shape" else TIER_CUE
            weighted.append((tier, points, rule.code, params))
        elif observations and rule.observation:
            weighted.append((TIER_OBSERVATION, 0.0, rule.code, params))

    found: list[_Candidate] = []
    seen_brands: set[str] = set()
    for tier, points, code, params in sorted(weighted, key=lambda t: (t[0], -t[1], t[2])):
        brand = params.get("brand")
        if isinstance(brand, str):
            if brand in seen_brands:
                continue  # une seule phrase par marque imitée
            seen_brands.add(brand)
        found.append(_Candidate(code, MODEL, points, params, tier))
    return found


# --------------------------------------------------------------------------- #
# Raisons tirées du modèle de texte (étape 3.3)
# --------------------------------------------------------------------------- #

TEXT_TERMS = 3  # mots cités dans la raison ``text.terms``
TERM_MAX_LENGTH = 16  # trois mots et leurs séparateurs tiennent dans un fragment
TERM_MIN_LENGTH = 3
_TERM_STRIP = string.punctuation + "«»“”‘’…؟،؛ "
# Mots-outils : le modèle de caractères leur donne parfois du poids, mais « votre » ou
# « est » n'expliquent rien à un utilisateur. Ils restent dans la vue analyste.
DISPLAY_STOP_WORDS = frozenset(
    [
        "les",
        "des",
        "une",
        "est",
        "son",
        "ses",
        "sur",
        "aux",
        "par",
        "pour",
        "avec",
        "dans",
        "vos",
        "votre",
        "nos",
        "notre",
        "vous",
        "nous",
        "leur",
        "leurs",
        "qui",
        "que",
        "quoi",
        "elle",
        "ils",
        "pas",
        "plus",
        "tout",
        "tous",
        "mais",
        "car",
        "donc",
        "cette",
        "ces",
        "the",
        "and",
        "for",
        "you",
        "your",
        "are",
        "was",
        "this",
        "that",
        "with",
        "from",
        "have",
        "has",
        "not",
        "our",
        "can",
        "will",
    ]
) | frozenset({"على", "إلى", "التي", "الذي", "هذا", "هذه", "عبر", "بعد", "قبل"})


def display_term(term: str) -> str | None:
    """Forme affichable d'un mot du message, ou ``None`` s'il ne doit pas être cité.

    Ne sont jamais recopiés : un lien (il serait cliquable dans certaines messageries),
    un mot sans lettre (un code reçu ou un numéro de téléphone peuvent être personnels),
    un mot-outil ou un mot de moins de trois caractères.
    """
    from phishguard.text.smishing import find_urls

    if find_urls(term):
        return None
    cleaned = term.strip(_TERM_STRIP)
    if len(cleaned) < TERM_MIN_LENGTH or cleaned.casefold() in DISPLAY_STOP_WORDS:
        return None
    if not any(c.isalpha() for c in cleaned):
        return None  # nombre, code reçu, numéro : rien à expliquer, peut-être personnel
    return safe_fragment(cleaned, TERM_MAX_LENGTH)


def text_candidates(
    explanation: TextExplanation, model_points: float, *, alarming: bool = False
) -> list[_Candidate]:
    """Raisons lisibles du modèle de texte, avec leur part des points du modèle.

    1. **Catégories** de leurre (urgence, argent, lien, code, compte) : le poids d'une
       catégorie est la somme des contributions positives des mots qui l'évoquent.
    2. **Mots** : pour un verdict suspect ou phishing (``alarming``) seulement, les
       trois mots restants qui ont le plus poussé vers « phishing », en une seule raison,
       après les catégories (niveau « forme »). Pour un message jugé sûr, dire que ses
       mots « reviennent dans les messages frauduleux » serait trompeur.
    3. Pour un verdict suspect ou phishing, une catégorie présente sans effet sur le
       score est citée à 0 point (« le message parle d'un code » reste utile).

    Les parts suivent la règle des URL : ``model_points × poids / somme des
    contributions positives``.
    """
    positive_total = math.fsum(max(0.0, t.contribution) for t in explanation.terms)
    share = (model_points / positive_total) if positive_total > 0 else 0.0
    positive = {t.term: t.contribution for t in explanation.terms if t.contribution > 0}

    found: list[_Candidate] = []
    cited_words: set[str] = set()
    for category in explanation.categories:
        words = explanation.category_terms.get(category, ())
        weight = math.fsum(positive.get(w, 0.0) for w in set(words))
        points = weight * share
        if points >= MIN_REASON_POINTS:
            found.append(_Candidate(f"text.{category}", MODEL, points, {}, TIER_CUE))
            cited_words.update(words)
        elif alarming:
            found.append(_Candidate(f"text.{category}", MODEL, 0.0, {}, TIER_OBSERVATION))

    if not alarming:
        return found
    shown: list[str] = []
    weight = 0.0
    for term in explanation.top(len(explanation.terms)):
        if term.term in cited_words:
            continue
        display = display_term(term.term)
        if display is None or display in shown:
            continue
        shown.append(display)
        weight += term.contribution
        if len(shown) == TEXT_TERMS:
            break
    if shown and weight * share >= MIN_REASON_POINTS:
        found.append(
            _Candidate("text.terms", MODEL, weight * share, {"terms": ", ".join(shown)}, TIER_SHAPE)
        )
    return found


class ReasonBuilder:
    """Construit l'explication destinée à l'utilisateur, dans une langue."""

    def __init__(
        self,
        language: str = DEFAULT_LANGUAGE,
        *,
        brands: BrandIndex | None = None,
        max_reasons: int = MAX_REASONS,
    ) -> None:
        self.templates = load_templates(language)
        self.language: Language = self.templates.language
        self.brands = brands
        if max_reasons < 1:
            raise ValueError("au moins une raison doit pouvoir être citée")
        self.max_reasons = max_reasons

    def for_fusion(
        self,
        fusion: FusionResult,
        *,
        channel: Channel = "url",
        signals: Iterable[Signal] = (),
        url: str | None = None,
        explanation: UrlExplanation | None = None,
        text_explanation: TextExplanation | None = None,
        model_code: str = MODEL,
    ) -> Explanation:
        """Explication d'un résultat de fusion.

        - règle dure : c'est l'unique raison ;
        - sinon, sources qui ont fait monter le score, et raisons du modèle : celles des
          features URL (``url`` et ``explanation``) ou du message (``text_explanation``,
          étape 3.3) ; à défaut, et seulement pour un verdict suspect ou phishing, une
          raison générale ``model_code``.
        """
        advice = self.templates.advice_for(channel, fusion.verdict)
        if fusion.hard_rule is not None:
            code = f"hard_rule.{fusion.hard_rule}"
            points = 100.0 if fusion.verdict == "phishing" else 0.0
            source = fusion.hard_rule
            if code not in self.templates.reasons:
                return self._explanation(
                    [_Candidate("signal.other", source, points, {"source": source})], advice
                )
            return self._explanation([_Candidate(code, source, points, {})], advice)

        by_source = _strongest_ok(signals)
        candidates: list[_Candidate] = []
        for c in fusion.contributions:  # déjà triées par points décroissants
            if c.points < MIN_REASON_POINTS:
                continue
            if c.source != MODEL:
                candidates.append(_signal_candidate(c.source, c.points, by_source.get(c.source)))
                continue
            alarming = fusion.verdict != "safe"
            from_model: Sequence[_Candidate] = ()
            if text_explanation is not None:
                from_model = text_candidates(text_explanation, c.points, alarming=alarming)
            elif explanation is not None and url is not None:
                facts = url_facts(url, self.brands)
                from_model = feature_candidates(explanation, facts, c.points, observations=alarming)
            candidates.extend(from_model)
            if alarming and not any(m.points >= MIN_REASON_POINTS for m in from_model):
                candidates.append(_Candidate(model_code, MODEL, c.points, {}))
        return self._explanation(candidates, advice)

    def _explanation(self, candidates: Sequence[_Candidate], advice: str) -> Explanation:
        ranked = sorted(candidates, key=lambda c: (c.tier, -c.points, c.code))
        ranked = ranked[: self.max_reasons]
        reasons = tuple(
            ReasonText(
                code=c.code,
                source=c.source,
                points=round(min(max(c.points, 0.0), 100.0), 1),
                message=self.templates.reason(c.code, c.params),
                params=_clean_params(c.params),
            )
            for c in ranked
        )
        return Explanation(language=self.language, reasons=reasons, advice=advice)

    def email_rules(self, triggered: Sequence[str], verdict: Verdict) -> Explanation:
        """Explication du score email par règles (étape 1.11) : les règles déclenchées
        les plus lourdes, traduites, avec leurs points."""
        from phishguard.email.score import RULE_BY_NAME

        candidates = [
            _Candidate(f"email.{name}", "email_rules", float(RULE_BY_NAME[name].points), {})
            for name in triggered
        ]
        return self._explanation(candidates, self.templates.advice_for("email", verdict))
