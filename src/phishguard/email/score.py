"""Score d'un email : règles transparentes, puis features pour un modèle (étape 1.11).

Deux usages des signaux du parseur (:mod:`phishguard.email.parser`) :

1. **Règles** (:data:`RULES`) : chaque règle déclenchée ajoute des points, le score est
   plafonné à 100 et chaque point a une raison lisible. Verdict : sûr sous 30, suspect
   de 30 à 70, phishing au-delà de 70, comme la fusion prévue à l'étape 2.10. Les
   poids sont fixés à la main, d'après la gravité du signal et sa rareté dans les
   emails légitimes, **avant** toute mesure : ils ne sont pas réglés sur le test.
2. **Features** (:func:`email_features`) : les mêmes signaux, en nombres, rangés par
   groupe (:data:`FEATURE_GROUPS`) pour entraîner un modèle et le comparer aux règles.

Le groupe ``auth`` mérite une attention particulière : DMARC date de 2012 et les
corpus publics d'emails légitimes (SpamAssassin, 2002-2003) n'ont aucun en-tête
d'authentification. Un modèle entraîné sur eux apprend « pas d'en-tête = légitime »,
un biais de collecte comme ``is_https`` pour les URLs (étape 1.5). L'étape 1.11 entraîne
donc aussi chaque modèle sans ce groupe.
"""

from __future__ import annotations

import math
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from functools import lru_cache
from typing import Any

from phishguard.data.urls import normalize_url
from phishguard.email.html import link_target
from phishguard.email.parser import ParsedEmail
from phishguard.text.smishing import SmishingFeatureExtractor
from phishguard.urls.brands import load_shorteners
from phishguard.urls.features import is_ip_host

SAFE_BELOW = 30
PHISHING_ABOVE = 70
VERDICTS = ("safe", "suspicious", "phishing")
# Familles de pièces jointes dangereuses à ouvrir (voir parser.RISKY_EXTENSIONS).
DANGEROUS_ATTACHMENTS = frozenset({"executable", "script", "macro_document", "html", "disk_image"})
HIDDEN_TEXT_MIN_CHARS = 50  # une ligne d'aperçu cachée de newsletter fait moins
ZERO_WIDTH_MIN = 3


# --------------------------------------------------------------------------- #
# Features
# --------------------------------------------------------------------------- #

FEATURE_GROUPS: dict[str, tuple[str, ...]] = {
    "auth": (
        "dmarc_fail",
        "dmarc_pass",
        "spf_fail",
        "spf_softfail",
        "dkim_fail",
        "dkim_pass",
        "auth_missing",
    ),
    "sender": ("reply_to_differs", "return_path_differs", "display_name_spoof"),
    "links": (
        "log_links",
        "mismatched_links",
        "link_domains",
        "ip_link",
        "shortener_link",
        "non_web_link",
        "forms",
    ),
    "attachments": (
        "attachments",
        "dangerous_attachment",
        "archive_attachment",
        "disguised_attachment",
    ),
    "content": (
        "log_hidden_chars",
        "zero_width_chars",
        "urgency_hits",
        "account_hits",
        "reward_hits",
        "log_text_length",
        "has_html",
    ),
}
FEATURE_NAMES: tuple[str, ...] = tuple(n for names in FEATURE_GROUPS.values() for n in names)


def feature_names(exclude_groups: Iterable[str] = ()) -> tuple[str, ...]:
    excluded = set(exclude_groups)
    unknown = excluded - set(FEATURE_GROUPS)
    if unknown:
        raise ValueError(f"groupes inconnus : {sorted(unknown)}")
    return tuple(n for g, names in FEATURE_GROUPS.items() if g not in excluded for n in names)


@lru_cache(maxsize=1)
def _shorteners() -> frozenset[str]:
    return load_shorteners()


@lru_cache(maxsize=1)
def _text_extractor() -> SmishingFeatureExtractor:
    return SmishingFeatureExtractor()


def _link_host(href: str) -> str | None:
    normalized = normalize_url(href)
    return None if normalized is None else normalized[1]


def email_features(email: ParsedEmail, *, max_text_chars: int = 20_000) -> dict[str, float]:
    """Features numériques d'un email analysé, dans l'ordre de :data:`FEATURE_NAMES`."""
    auth = email.auth
    # Lien réécrit par une passerelle de sécurité : on regarde la vraie cible.
    hosts = [
        _link_host(link_target(link))
        for link in email.links
        if link.scheme in ("http", "https") and link.href_domain is not None
    ]
    hosts = [h for h in hosts if h]
    text = f"{email.subject}\n{email.text[:max_text_chars]}"
    words = _text_extractor().extract(text)
    values: dict[str, float] = {
        "dmarc_fail": auth.dmarc == "fail",
        "dmarc_pass": auth.dmarc == "pass",
        "spf_fail": auth.spf == "fail",
        "spf_softfail": auth.spf == "softfail",
        "dkim_fail": auth.dkim == "fail",
        "dkim_pass": auth.dkim == "pass",
        "auth_missing": auth.source is None,
        # Une liste de diffusion renvoie les réponses à la liste : Reply-To différent est
        # alors normal (615 des 766 emails légitimes concernés de SpamAssassin).
        "reply_to_differs": email.reply_to_differs and not email.mailing_list,
        "return_path_differs": email.return_path_differs,
        "display_name_spoof": email.display_name_spoof,
        "log_links": math.log1p(len(email.links)),
        # Liens web seulement : un lien javascript: trompeur compte dans non_web_link.
        "mismatched_links": sum(
            1 for link in email.mismatched_links if link.scheme in ("http", "https", "")
        ),
        "link_domains": len({link.href_domain for link in email.links if link.href_domain}),
        "ip_link": any(is_ip_host(h) for h in hosts),
        "shortener_link": any(h.removeprefix("www.") in _shorteners() for h in hosts),
        "non_web_link": any(
            link.scheme in ("javascript", "data", "vbscript", "file") for link in email.links
        ),
        "forms": email.forms,
        "attachments": len(email.attachments),
        "dangerous_attachment": any(a.risk in DANGEROUS_ATTACHMENTS for a in email.attachments),
        "archive_attachment": any(a.risk == "archive" for a in email.attachments),
        "disguised_attachment": any(a.double_extension or a.rtlo for a in email.attachments),
        "log_hidden_chars": math.log1p(email.hidden_text.chars),
        "zero_width_chars": email.zero_width_chars,
        "urgency_hits": words["urgency_hits"],
        "account_hits": words["account_hits"],
        "reward_hits": words["reward_hits"],
        "log_text_length": math.log1p(len(email.text)),
        "has_html": email.has_html,
    }
    return {name: float(values[name]) for name in FEATURE_NAMES}


# Features facultatives : le modèle URL de l'étape 1.6 appliqué aux liens de l'email.
URL_MODEL_FEATURES = ("max_link_url_score", "link_flagged_by_url_model")
# Seuil à 0,1 % de faux positifs par lien, pas 1 % : la règle juge le lien le plus
# suspect d'un email qui en a souvent des dizaines, et le taux de faux positifs par email
# croît avec le nombre de liens (au seuil de 1 %, 17 % des emails légitimes SpamAssassin
# étaient signalés).
DEFAULT_URL_THRESHOLD = "fpr_0_1pct"


def url_model_features(
    email: ParsedEmail,
    url_model: Any,
    *,
    threshold_name: str = DEFAULT_URL_THRESHOLD,
    max_links: int = 50,
) -> dict[str, float]:
    """Score du lien le plus suspect selon un :class:`phishguard.urls.model.UrlModel`.

    Seuls les liens web absolus sont scorés (50 au plus, dans l'ordre du message), par
    leur vraie cible quand une passerelle de sécurité les a réécrits ; une
    URL que le modèle refuse (``InvalidUrlError``) est ignorée. Sans lien scorable, les
    deux features valent 0.
    """
    targets = (link_target(link) for link in email.links if link.scheme in ("http", "https"))
    urls = [url for url in targets if normalize_url(url) is not None][:max_links]
    scores = []
    for url in urls:
        try:
            scores.append(float(url_model.score([url])[0]))
        except ValueError:  # InvalidUrlError en hérite
            continue
    best = max(scores, default=0.0)
    flagged = bool(scores) and best > url_model.threshold(threshold_name)
    return {"max_link_url_score": best, "link_flagged_by_url_model": float(flagged)}


# --------------------------------------------------------------------------- #
# Règles
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Rule:
    name: str
    points: int
    reason: str  # phrase montrée à l'utilisateur
    applies: Callable[[Mapping[str, float]], bool]


RULES: tuple[Rule, ...] = (
    Rule(
        "dmarc_fail",
        30,
        "Le domaine de l'expéditeur n'a pas autorisé cet envoi (DMARC en échec).",
        lambda f: bool(f["dmarc_fail"]),
    ),
    Rule(
        "spf_fail",
        15,
        "Le serveur d'envoi n'est pas autorisé par le domaine (SPF en échec).",
        lambda f: bool(f["spf_fail"]),
    ),
    Rule(
        "spf_softfail",
        5,
        "Le serveur d'envoi n'est probablement pas autorisé (SPF « softfail »).",
        lambda f: bool(f["spf_softfail"]),
    ),
    Rule(
        "dkim_fail",
        10,
        "La signature DKIM de l'email est invalide.",
        lambda f: bool(f["dkim_fail"]),
    ),
    Rule(
        "reply_to_differs",
        20,
        "Votre réponse partirait vers un autre domaine que celui de l'expéditeur.",
        lambda f: bool(f["reply_to_differs"]),
    ),
    Rule(
        "display_name_spoof",
        25,
        "Le nom affiché imite une autre adresse que l'adresse réelle de l'expéditeur.",
        lambda f: bool(f["display_name_spoof"]),
    ),
    Rule(
        "return_path_differs",
        5,
        "L'adresse de retour est sur un autre domaine (fréquent pour les envois en masse).",
        lambda f: bool(f["return_path_differs"]),
    ),
    Rule(
        "mismatched_link",
        35,
        "Un lien affiche une adresse mais mène vers un autre site.",
        lambda f: f["mismatched_links"] > 0,
    ),
    Rule(
        "non_web_link",
        30,
        "Un lien exécute du code (javascript:, data:) au lieu d'ouvrir une page.",
        lambda f: bool(f["non_web_link"]),
    ),
    Rule(
        "form",
        20,
        "L'email contient un formulaire : un service légitime vous renvoie vers son site.",
        lambda f: f["forms"] > 0,
    ),
    Rule(
        "ip_link",
        15,
        "Un lien pointe vers une adresse IP plutôt qu'un nom de site.",
        lambda f: bool(f["ip_link"]),
    ),
    Rule(
        "url_model",
        35,
        "Un lien ressemble aux liens de phishing appris par le modèle URL.",
        lambda f: bool(f.get("link_flagged_by_url_model", 0.0)),
    ),
    Rule(
        "shortener_link",
        10,
        "Un lien passe par un raccourcisseur qui masque sa destination.",
        lambda f: bool(f["shortener_link"]),
    ),
    Rule(
        "dangerous_attachment",
        40,
        "Une pièce jointe peut exécuter du code ou ouvrir une fausse page de connexion.",
        lambda f: bool(f["dangerous_attachment"]),
    ),
    Rule(
        "disguised_attachment",
        40,
        "Le nom d'une pièce jointe cache sa vraie extension (facture.pdf.exe).",
        lambda f: bool(f["disguised_attachment"]),
    ),
    Rule(
        "archive_attachment",
        10,
        "Une archive est jointe : son contenu n'est pas vérifiable sans l'ouvrir.",
        lambda f: bool(f["archive_attachment"]),
    ),
    Rule(
        "hidden_text",
        10,
        "L'email contient du texte caché, souvent utilisé pour tromper les filtres.",
        lambda f: f["log_hidden_chars"] >= math.log1p(HIDDEN_TEXT_MIN_CHARS),
    ),
    Rule(
        "zero_width_chars",
        10,
        "Des caractères invisibles coupent les mots, souvent pour tromper les filtres.",
        lambda f: f["zero_width_chars"] >= ZERO_WIDTH_MIN,
    ),
    Rule(
        "urgent_account_request",
        10,
        "Le message presse d'agir sur un compte, une carte ou un colis.",
        lambda f: f["urgency_hits"] > 0 and f["account_hits"] > 0,
    ),
)
RULE_BY_NAME = {rule.name: rule for rule in RULES}


@dataclass(frozen=True)
class RuleScore:
    score: int  # 0 à 100
    verdict: str
    triggered: tuple[str, ...]

    @property
    def reasons(self) -> list[str]:
        return [RULE_BY_NAME[name].reason for name in self.triggered]

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "verdict": self.verdict,
            "triggered": list(self.triggered),
            "reasons": self.reasons,
        }


def verdict(score: float) -> str:
    """``safe`` sous 30, ``suspicious`` de 30 à 70, ``phishing`` au-delà de 70."""
    if score < SAFE_BELOW:
        return "safe"
    return "phishing" if score > PHISHING_ABOVE else "suspicious"


def rule_score(features: Mapping[str, float]) -> RuleScore:
    """Score des règles, plafonné à 100, avec les règles déclenchées par ordre de poids."""
    triggered = sorted(
        (rule for rule in RULES if rule.applies(features)), key=lambda r: (-r.points, r.name)
    )
    score = min(100, sum(rule.points for rule in triggered))
    return RuleScore(score, verdict(score), tuple(rule.name for rule in triggered))


def score_email(email: ParsedEmail, url_model: Any = None) -> RuleScore:
    """Score des règles ; avec ``url_model``, la règle ``url_model`` peut s'appliquer."""
    features = email_features(email)
    if url_model is not None:
        features.update(url_model_features(email, url_model))
    return rule_score(features)
