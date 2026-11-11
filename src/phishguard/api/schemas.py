"""Schémas d'entrée de l'API (étape 4.2) : toute entrée est hostile.

Les bornes sont posées **dans le schéma**, avant que la moindre ligne d'analyse ne
s'exécute :

- tailles minimales et maximales de chaque chaîne ;
- **mode strict** : ``"true"`` n'est pas un booléen, ``123`` n'est pas une chaîne ;
- **aucun champ inconnu** (``extra="forbid"``) : une faute de frappe dans
  ``use_threat_intel`` ne doit pas désactiver silencieusement une option ;
- **caractères refusés** : octet nul et autres caractères de contrôle C0 et C1, et
  demi-codets UTF-16 isolés (``"\\ud800"`` est un JSON valide, mais ne s'encode pas en
  UTF-8 et ferait échouer plus loin le journal ou le hachage). Le texte d'un message
  garde la tabulation et les fins de ligne ; une URL n'en contient jamais.

Les caractères **invisibles de format** (largeur nulle, inversion de sens U+202E) ne sont
pas refusés : ce sont des techniques d'évasion que la normalisation de l'étape 3.8 retire
et compte, et leur présence est un indice. Les refuser ici masquerait l'attaque.

Le contrat de la **réponse** est ``phishguard.schema.AnalysisResponse`` (étape 2.11 bis).
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Annotated, Literal

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    model_validator,
)

from phishguard.explain.reasons import DEFAULT_LANGUAGE, Language
from phishguard.fusion.score import Verdict

MAX_URL_CHARS = 2048
MAX_TEXT_CHARS = 5000  # même borne que phishguard.analysis.MAX_TEXT_CHARS
MAX_DOMAIN_CHARS = 253

# C0 (sauf tabulation et fins de ligne pour le texte), DEL, C1, demi-codets isolés.
_FORBIDDEN_IN_TEXT = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f\ud800-\udfff]")
_FORBIDDEN_IN_URL = re.compile(r"[\x00-\x1f\x7f-\x9f\ud800-\udfff]")
# Label d'un nom d'hôte après encodage IDNA : lettres, chiffres, tirets (RFC 1123).
_ASCII_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")


def _reject(pattern: re.Pattern[str], what: str):
    def check(value: str) -> str:
        found = pattern.search(value)
        if found is not None:
            # Position seulement : le caractère lui-même n'est pas recopié.
            raise ValueError(f"{what} : caractère de contrôle interdit (position {found.start()})")
        return value

    return check


def _domain(value: str) -> str:
    """Domaine ramené à sa forme ASCII (IDNA), en minuscules, sans point final.

    Au moins deux labels, chacun LDH après encodage ; le dernier (TLD) n'est pas numérique,
    ce qui écarte les adresses IP : un retour porte sur un nom, pas sur une machine.
    """
    domain = value.strip().rstrip(".").lower()
    try:
        ascii_domain = domain.encode("idna").decode("ascii")
    except UnicodeError:
        raise ValueError("domaine invalide : encodage IDNA impossible") from None
    labels = ascii_domain.split(".")
    if (
        len(labels) < 2
        or not all(_ASCII_LABEL.match(label) for label in labels)
        or labels[-1].isdigit()
    ):
        raise ValueError("domaine invalide : un nom de domaine est attendu, pas une URL")
    if len(ascii_domain) > MAX_DOMAIN_CHARS:
        raise ValueError("domaine trop long")
    return ascii_domain


def _not_blank(value: str) -> str:
    if not value.strip():
        raise ValueError("texte vide")
    return value


UrlStr = Annotated[
    str,
    StringConstraints(min_length=4, max_length=MAX_URL_CHARS),
    AfterValidator(_reject(_FORBIDDEN_IN_URL, "URL")),
]
MessageStr = Annotated[
    str,
    StringConstraints(min_length=1, max_length=MAX_TEXT_CHARS),
    AfterValidator(_reject(_FORBIDDEN_IN_TEXT, "texte")),
    AfterValidator(_not_blank),
]
DomainStr = Annotated[
    str,
    StringConstraints(min_length=3, max_length=MAX_DOMAIN_CHARS),
    AfterValidator(_reject(_FORBIDDEN_IN_URL, "domaine")),
    AfterValidator(_domain),
]


class _Request(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class _AnalysisOptions(_Request):
    language: Language = Field(
        default=DEFAULT_LANGUAGE, description="Langue des raisons et du conseil"
    )
    analyst: bool = Field(
        default=False, description="Inclure la vue analyste (« Détails techniques »)"
    )


class UrlRequest(_AnalysisOptions):
    url: UrlStr = Field(description="URL à analyser, http ou https")
    use_threat_intel: bool = Field(
        default=False,
        description=(
            "Interroger les sources de Threat Intelligence : l'URL est alors envoyée à des "
            "tiers. Sans effet si le serveur ne les a pas activées, et jamais pour une URL "
            "interne."
        ),
    )

    model_config = ConfigDict(
        json_schema_extra={"examples": [{"url": "https://example.com/login", "language": "fr"}]}
    )


class TextRequest(_AnalysisOptions):
    text: MessageStr = Field(description="Contenu du SMS ou du message, jamais conservé")
    channel: Literal["sms", "messaging"] = "sms"
    use_threat_intel: bool = Field(
        default=False,
        description="Réservé : l'analyse d'un message est entièrement locale (enrichment=skipped)",
    )

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [{"text": "Votre colis est bloqué, payez 1,99 € ici", "channel": "sms"}]
        }
    )


# --------------------------------------------------------------------------- #
# Retours des utilisateurs
# --------------------------------------------------------------------------- #

Judgement = Literal["false_positive", "false_negative"]


class FeedbackRequest(_Request):
    """Retour d'un utilisateur sur un verdict.

    **Le domaine seulement, jamais l'URL complète** : le chemin et les paramètres d'une URL
    portent souvent des jetons ou des identifiants personnels. Aucun horodatage n'est
    accepté du client : le serveur date lui-même la réception.
    """

    domain: DomainStr = Field(description="Domaine analysé, sans chemin ni paramètres")
    verdict: Verdict = Field(description="Verdict reçu de PhishGuard")
    judgement: Judgement = Field(description="Jugement de l'utilisateur")

    @model_validator(mode="after")
    def _coherent(self) -> FeedbackRequest:
        if self.judgement == "false_positive" and self.verdict == "safe":
            raise ValueError("un faux positif porte sur un verdict suspect ou phishing")
        if self.judgement == "false_negative" and self.verdict == "phishing":
            raise ValueError("un faux négatif porte sur un verdict sûr ou suspect")
        return self


class FeedbackAccepted(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    status: Literal["quarantined"] = "quarantined"
    received_at: datetime


# --------------------------------------------------------------------------- #
# Méta
# --------------------------------------------------------------------------- #


class Health(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    status: Literal["ok"] = "ok"


class ModelOut(BaseModel):
    """Un modèle déployé. ``sha256`` : empreinte du fichier chargé au démarrage."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    version: str
    kind: Literal["lightgbm", "text", "rules"]
    trained_at: str | None = None
    sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    calibrated: bool = False
    calibration_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")


class ModelsInfo(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: str
    fusion_version: str
    normalization_version: str | None = Field(
        default=None, description="Version de la normalisation des entrées (étape 3.8)"
    )
    models: dict[Literal["url", "text", "email"], ModelOut]
