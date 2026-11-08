"""Correspondance des détections avec MITRE ATT&CK (étape 2.11).

Chaque verdict ``suspicious`` ou ``phishing`` est relié aux techniques ATT&CK qu'il
illustre, pour qu'un analyste lise la détection dans le vocabulaire commun de la défense.
Un verdict ``safe`` n'en a aucune.

| Constat                                         | Technique                                  |
| ----------------------------------------------- | ------------------------------------------ |
| Lien malveillant dans un email                  | T1566.002 Phishing: Spearphishing Link     |
| Pièce jointe à risque dans un email             | T1566.001 Phishing: Spearphishing Attachment |
| Message via un service tiers (SMS, messagerie)  | T1566.003 Phishing: Spearphishing via Service |
| L'utilisateur est incité à cliquer              | T1204.001 User Execution: Malicious Link   |
| L'utilisateur est incité à ouvrir un fichier    | T1204.002 User Execution: Malicious File   |
| Le message demande des informations             | T1598 Phishing for Information (.001 à .003) |
| Domaine récent ou imitant une marque            | T1583.001 Acquire Infrastructure: Domains  |

Un verdict de phishing reçoit **toujours** au moins une technique : à défaut de constat
plus précis, T1566 Phishing.

Les identifiants et intitulés viennent de ``fusion/mitre_attack.json``, vérifié contre
les données officielles d'ATT&CK par ``scripts/verify_mitre.py`` (version indiquée dans
le fichier). Les intitulés restent en anglais : ce sont ceux de MITRE, que les analystes
recherchent tels quels. Les phrases pour l'utilisateur viendront du module 3.
"""

from __future__ import annotations

import json
import math
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from functools import lru_cache
from importlib import resources
from typing import Any, Literal

from phishguard.enrichers.base import Signal, SignalStatus
from phishguard.fusion.score import Verdict

Channel = Literal["url", "email", "sms", "messaging"]
CHANNELS: tuple[Channel, ...] = ("url", "email", "sms", "messaging")
RECENT_DAYS = 30  # un domaine ou un premier certificat de moins de 30 jours est « récent »
ATTACK_URL = "https://attack.mitre.org/techniques/"
# Features URL (étape 1.5) qui révèlent un domaine imitant une marque.
LOOKALIKE_FEATURES = ("is_typosquat", "homograph_brand", "host_mixed_script")


@dataclass(frozen=True)
class Technique:
    id: str  # T1566.002
    name: str  # Phishing: Spearphishing Link
    tactic: str  # Initial Access
    url: str
    reason: str  # constat qui justifie la technique

    def to_dict(self) -> dict[str, str]:
        return dict(self.__dict__)


@dataclass(frozen=True)
class Observations:
    """Ce que l'analyse a constaté, indépendamment du verdict."""

    channel: Channel
    has_link: bool = False
    risky_attachment: bool = False
    requests_information: bool = False  # identifiants, codes, données de paiement…
    recent_domain: bool = False
    lookalike_domain: bool = False

    def __post_init__(self) -> None:
        if self.channel not in CHANNELS:
            raise ValueError(f"canal inconnu : {self.channel!r} (connus : {CHANNELS})")


@lru_cache(maxsize=1)
def catalog() -> dict[str, Any]:
    """Catalogue versionné des techniques (``fusion/mitre_attack.json``)."""
    text = resources.files("phishguard.fusion").joinpath("mitre_attack.json").read_text("utf-8")
    return json.loads(text)


def technique(technique_id: str, reason: str) -> Technique:
    """Technique du catalogue, avec son intitulé complet (« Parent: Sous-technique »)."""
    data = catalog()
    try:
        entry = data["techniques"][technique_id]
    except KeyError:
        raise KeyError(f"technique absente du catalogue : {technique_id}") from None
    name = entry["name"]
    if "." in technique_id:
        name = f"{data['techniques'][technique_id.split('.')[0]]['name']}: {name}"
    return Technique(
        id=technique_id,
        name=name,
        tactic=data["tactics"][entry["tactic"]],
        url=ATTACK_URL + technique_id.replace(".", "/"),
        reason=reason,
    )


def map_techniques(verdict: Verdict, observations: Observations) -> tuple[Technique, ...]:
    """Techniques ATT&CK illustrées par une détection. Aucune pour un verdict ``safe``."""
    if verdict == "safe":
        return ()
    obs = observations
    link = obs.has_link or obs.channel == "url"
    found: list[tuple[str, str]] = []

    if obs.channel == "email":
        if obs.has_link:
            found.append(("T1566.002", "lien malveillant dans un email"))
        if obs.risky_attachment:
            found.append(("T1566.001", "pièce jointe à risque dans un email"))
    elif obs.channel in ("sms", "messaging"):
        found.append(("T1566.003", f"message reçu par un service tiers ({obs.channel})"))

    if link:
        found.append(("T1204.001", "l'utilisateur est incité à ouvrir un lien"))
    if obs.risky_attachment:
        found.append(("T1204.002", "l'utilisateur est incité à ouvrir un fichier"))

    if obs.requests_information:
        if link:
            found.append(("T1598.003", "lien vers une page qui demande des informations"))
        elif obs.risky_attachment:
            found.append(("T1598.002", "pièce jointe qui demande des informations"))
        elif obs.channel in ("sms", "messaging"):
            found.append(("T1598.001", f"informations demandées par {obs.channel}"))
        else:
            found.append(("T1598", "le message demande des informations"))

    if obs.recent_domain or obs.lookalike_domain:
        why = " et ".join(
            text
            for flag, text in (
                (obs.recent_domain, f"domaine de moins de {RECENT_DAYS} jours"),
                (obs.lookalike_domain, "domaine qui imite une marque"),
            )
            if flag
        )
        found.append(("T1583.001", why))

    if not any(tid.startswith(("T1566", "T1598")) for tid, _ in found):
        found.insert(0, ("T1566", "tentative de phishing"))  # aucun vecteur plus précis
    return tuple(technique(tid, reason) for tid, reason in found)


def domain_observations(
    signals: Iterable[Signal], url_features: Mapping[str, float] | None = None
) -> dict[str, bool]:
    """``recent_domain`` et ``lookalike_domain`` d'après les sources et les features URL.

    Récent : RDAP (âge) ou Certificate Transparency (premier certificat) sous 30 jours.
    Imitation : typosquatting, homographe ou mélange d'écritures (étape 1.5).
    """
    recent = False
    for signal in signals:
        if signal.status is not SignalStatus.OK:
            continue
        key = {"rdap": "age_days", "certificate_transparency": "first_seen_days"}.get(signal.source)
        days = signal.evidence.get(key) if key else None
        if isinstance(days, int) and not isinstance(days, bool) and 0 <= days < RECENT_DAYS:
            recent = True
    features = url_features or {}
    lookalike = any(_is_set(features.get(name)) for name in LOOKALIKE_FEATURES)
    return {"recent_domain": recent, "lookalike_domain": lookalike}


def _is_set(value: Any) -> bool:
    """Feature booléenne activée. Une valeur manquante ou NaN (``bool(nan)`` vaut ``True``) ne l'est pas."""
    if isinstance(value, float) and math.isnan(value):
        return False
    return bool(value)
