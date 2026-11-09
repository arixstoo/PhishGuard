"""Fusion du score : modèle local, Threat Intelligence et règles dures (étape 2.10).

:func:`fuse` est une **fonction pure** : même entrée, même sortie, aucun appel réseau,
aucune horloge. Ses paramètres (poids, seuils, règles) viennent d'un fichier versionné,
``fusion/fusion.json``, chargé et validé par :class:`FusionConfig`.

**1. Règles dures**, dans cet ordre :

- liste noire personnelle, correspondance Google Safe Browsing, ou hôte qui imite des
  lettres latines (``lookalike_host``, étape 3.12) : ``phishing`` (100) ;
- liste blanche personnelle : ``sûr`` (0).

Safe Browsing passe **avant** la liste blanche : une page confirmée comme dangereuse par
Google reste signalée, même si l'utilisateur a mis son domaine en liste blanche (domaine
légitime compromis, ou liste blanche obtenue par manipulation). L'alerte d'hôte de
l'étape 3.8 aussi : ``аpple.com`` n'est pas ``apple.com``, et une liste blanche obtenue
par confusion ne doit pas l'innocenter. Elle est calculée localement
(:func:`lookalike_host_signal`) et mesurée dans ``docs/robustness-report.md`` : sur le
test, elle signale 99,4 % des homographes et aucune URL légitime.

**2. Combinaison des signaux** : un « OU probabiliste » pondéré ::

    p = 1 − (1 − p_modèle) × Π (1 − poids_source × risque_source)

Chaque indice indépendant de phishing **augmente** la probabilité, sans jamais la faire
dépasser 1. Trois choix, à connaître :

- seuls les signaux ``ok`` comptent : une source en panne, hors délai ou désactivée
  n'apporte rien (un signal manquant n'est pas un risque) ;
- un signal **rassurant** (risque 0 : domaine ancien, VirusTotal sans détection) ne fait
  **pas** baisser le score. Une part importante du phishing est hébergée sur des sites
  anciens compromis (21 % des faux négatifs de l'étape 1.8) : l'âge d'un domaine ne
  prouve pas l'innocence d'une page ;
- le poids traduit la confiance accordée à la source, de 0 (ignorée) à 1 (crue telle
  quelle).

**3. Seuils** : score = probabilité × 100, arrondi. ``sûr`` sous 30, ``suspect`` de 30 à
70 compris, ``phishing`` au-delà de 70.

Le résultat détaille la contribution de chaque source (points du score, répartis en
proportion de leur effet sur la probabilité), pour expliquer le verdict (module 3).
"""

from __future__ import annotations

import json
import math
from collections.abc import Iterable
from dataclasses import dataclass, field
from functools import lru_cache
from importlib import resources
from numbers import Real
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from phishguard.enrichers.base import Signal, SignalStatus

Verdict = Literal["safe", "suspicious", "phishing"]
MODEL = "model"
# Règle dure locale de l'étape 3.12 : hôte qui imite des lettres latines (étape 3.8).
LOOKALIKE_HOST = "lookalike_host"
_MAX_EFFECT = 1 - 1e-9  # borne pour le calcul des contributions (log de 0)


class Thresholds(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    suspicious: int = Field(ge=1, le=99)
    phishing: int = Field(ge=1, le=99)

    @model_validator(mode="after")
    def _ordered(self) -> Thresholds:
        if not self.suspicious < self.phishing:
            raise ValueError("le seuil « suspect » doit être sous le seuil « phishing »")
        return self


class HardRules(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    phishing_sources: tuple[str, ...] = ()


class FusionConfig(BaseModel):
    """Paramètres de la fusion. Toute modification change ``version``."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    version: str = Field(pattern=r"^\d+\.\d+\.\d+$")
    thresholds: Thresholds
    hard_rules: HardRules
    weights: dict[str, float]
    rationale: dict[str, str] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _check(self) -> FusionConfig:
        if MODEL not in self.weights:
            raise ValueError("le poids du modèle est requis")
        for source, weight in self.weights.items():
            if not 0 <= weight <= 1:
                raise ValueError(f"poids de {source} hors de [0, 1] : {weight}")
        missing = set(self.weights) - set(self.rationale)
        if missing:
            raise ValueError(f"chaque poids doit être justifié ; manque : {sorted(missing)}")
        overlap = set(self.hard_rules.phishing_sources) & set(self.weights)
        if overlap:
            raise ValueError(f"une source ne peut être à la fois règle dure et poids : {overlap}")
        return self

    @classmethod
    def load(cls, path: Path) -> FusionConfig:
        return cls.model_validate(json.loads(Path(path).read_text(encoding="utf-8")))


@lru_cache(maxsize=1)
def default_config() -> FusionConfig:
    """Configuration versionnée livrée avec le paquet (``fusion/fusion.json``)."""
    text = resources.files("phishguard.fusion").joinpath("fusion.json").read_text("utf-8")
    return FusionConfig.model_validate(json.loads(text))


# --------------------------------------------------------------------------- #
# Résultat
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Contribution:
    source: str
    risk: float  # risque annoncé par la source (ou probabilité du modèle)
    weight: float
    effect: float  # poids × risque : part de probabilité apportée seule
    points: float  # part du score final attribuée à cette source


@dataclass(frozen=True)
class FusionResult:
    score: int  # 0 à 100
    verdict: Verdict
    probability: float
    hard_rule: str | None = None  # règle dure appliquée, sinon None
    contributions: tuple[Contribution, ...] = ()
    ignored: tuple[str, ...] = ()  # sources non utilisables (erreur, délai, désactivée)
    config_version: str = ""
    thresholds: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "verdict": self.verdict,
            "probability": self.probability,
            "hard_rule": self.hard_rule,
            "contributions": [c.__dict__ for c in self.contributions],
            "ignored": list(self.ignored),
            "config_version": self.config_version,
            "thresholds": dict(self.thresholds),
        }


def verdict_for(score: int, thresholds: Thresholds) -> Verdict:
    if score < thresholds.suspicious:
        return "safe"
    if score > thresholds.phishing:
        return "phishing"
    return "suspicious"


def to_score(probability: float) -> int:
    """Probabilité en score entier de 0 à 100, arrondi au plus proche (0,5 vers le haut)."""
    return min(100, max(0, math.floor(probability * 100 + 0.5)))


# --------------------------------------------------------------------------- #
# Fusion
# --------------------------------------------------------------------------- #


def fuse(
    model_probability: float,
    signals: Iterable[Signal] = (),
    *,
    allowlisted: bool = False,
    blocklisted: bool = False,
    config: FusionConfig | None = None,
) -> FusionResult:
    """Score final de 0 à 100 et verdict, à partir des signaux disponibles.

    ``model_probability`` est la probabilité **calibrée** du modèle local
    (:class:`~phishguard.fusion.calibration.ScoreCalibrator`). ``allowlisted`` et
    ``blocklisted`` viennent des listes personnelles de l'utilisateur.
    """
    config = config or default_config()
    # Real couvre float, int et les flottants numpy ; bool est exclu (True n'est pas 1,0).
    if (
        isinstance(model_probability, bool)
        or not isinstance(model_probability, Real)
        or not 0 <= model_probability <= 1  # faux aussi pour NaN
    ):
        raise ValueError(f"probabilité du modèle hors de [0, 1] : {model_probability!r}")
    signals = tuple(signals)
    usable = _usable_signals(signals)
    ignored = tuple(sorted({s.source for s in signals if s.source not in usable}))
    common = {
        "ignored": ignored,
        "config_version": config.version,
        "thresholds": config.thresholds.model_dump(),
    }

    if blocklisted:
        return FusionResult(100, "phishing", 1.0, hard_rule="blocklist", **common)
    for source in config.hard_rules.phishing_sources:
        signal = usable.get(source)
        if signal is not None and signal.risk >= 1.0:
            return FusionResult(100, "phishing", 1.0, hard_rule=source, **common)
    if allowlisted:
        return FusionResult(0, "safe", 0.0, hard_rule="allowlist", **common)

    effects: list[tuple[str, float, float]] = [
        (MODEL, float(model_probability), config.weights[MODEL])
    ]
    for source, signal in sorted(usable.items()):
        weight = config.weights.get(source, 0.0)
        if weight > 0 and signal.risk > 0:
            effects.append((source, signal.risk, weight))

    remaining = 1.0
    for _source, risk, weight in effects:
        remaining *= 1 - weight * risk
    probability = 1 - remaining
    score = to_score(probability)
    return FusionResult(
        score=score,
        verdict=verdict_for(score, config.thresholds),
        probability=probability,
        contributions=_contributions(effects, probability),
        **common,
    )


def _usable_signals(signals: tuple[Signal, ...]) -> dict[str, Signal]:
    """Un signal ``ok`` par source ; en cas de doublon, celui de plus fort risque.

    L'orchestrateur ne renvoie qu'un signal par source, mais :func:`fuse` ne doit pas
    dépendre de l'ordre de ses entrées : garder le dernier vu le ferait. Retenir le plus
    fort risque est déterministe et prudent.
    """
    usable: dict[str, Signal] = {}
    for signal in signals:
        if signal.status is not SignalStatus.OK:
            continue
        current = usable.get(signal.source)
        if current is None or signal.risk > current.risk:
            usable[signal.source] = signal
    return usable


def _contributions(
    effects: list[tuple[str, float, float]], probability: float
) -> tuple[Contribution, ...]:
    """Répartit le score entre les sources, au prorata de −log(1 − effet).

    Dans un OU probabiliste, les effets se combinent par produit : en passant au
    logarithme, ils s'additionnent, ce qui donne une répartition exacte et sans ordre.
    """
    logs = [-math.log(1 - min(weight * risk, _MAX_EFFECT)) for _, risk, weight in effects]
    total = sum(logs)
    contributions = [
        Contribution(
            source=source,
            risk=risk,
            weight=weight,
            effect=weight * risk,
            points=(log / total * probability * 100) if total > 0 else 0.0,
        )
        for (source, risk, weight), log in zip(effects, logs, strict=True)
    ]
    return tuple(sorted(contributions, key=lambda c: c.points, reverse=True))


def lookalike_host_signal(alert: str | None) -> Signal | None:
    """Signal local de la règle dure ``lookalike_host`` pour une alerte d'hôte.

    ``alert`` est le résultat de
    :func:`phishguard.security.normalize.host_script_alert`. Sans alerte, aucun signal :
    l'absence d'imitation n'est pas un indice de sûreté.
    """
    if alert is None:
        return None
    return Signal(
        source=LOOKALIKE_HOST, status=SignalStatus.OK, risk=1.0, evidence={"alert": alert}
    )
