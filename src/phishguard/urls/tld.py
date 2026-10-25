"""Risque associé au domaine de premier niveau (TLD), appris sur l'entraînement.

La feature est la part de phishing observée pour un TLD dans le bloc d'entraînement,
lissée vers la part globale (moyenne bayésienne) :

    taux(tld) = (phishing(tld) + m × a_priori) / (total(tld) + m)

Un TLD rare reste proche de la part globale au lieu de valoir 0 ou 1 ; un TLD jamais vu
reçoit la part globale.

**Biais de collecte.** Ce taux reflète nos sources autant que le phishing réel : le
légitime vient des domaines les plus visités (Tranco), très souvent en ``.com`` ou en
domaine national, et la part globale (20 %) est très supérieure à la prévalence réelle.
Le taux sert donc à ordonner les TLD entre eux, pas comme une probabilité. Il ne doit
jamais être calculé sur la validation ou le test (fuite d'étiquette).
"""

from __future__ import annotations

import ipaddress
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

DEFAULT_SMOOTHING = 20.0


def top_level_domain(host: str) -> str:
    """Dernier label de l'hôte (forme ASCII), ou ``""`` pour une adresse IP."""
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return host.rstrip(".").rsplit(".", 1)[-1].lower()
    return ""


@dataclass(frozen=True)
class TldRiskTable:
    """Taux de phishing lissé par TLD."""

    prior: float
    smoothing: float
    rates: Mapping[str, float] = field(default_factory=dict)
    support: Mapping[str, int] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not 0.0 <= self.prior <= 1.0:
            raise ValueError("prior doit être compris entre 0 et 1")
        if self.smoothing <= 0:
            raise ValueError("smoothing doit être strictement positif")

    @classmethod
    def fit(
        cls, tlds: Iterable[str], labels: Iterable[int], *, smoothing: float = DEFAULT_SMOOTHING
    ) -> TldRiskTable:
        """Apprend la table à partir des TLD et étiquettes (1 = phishing) d'entraînement."""
        counts: dict[str, list[int]] = {}
        total = positives = 0
        for tld, label in zip(tlds, labels, strict=True):
            if label not in (0, 1):
                raise ValueError(f"étiquette inattendue : {label!r}")
            entry = counts.setdefault(tld, [0, 0])
            entry[0] += 1
            entry[1] += int(label)
            total += 1
            positives += int(label)
        if total == 0:
            raise ValueError("aucune ligne d'entraînement")
        prior = positives / total
        rates = {
            tld: (pos + smoothing * prior) / (n + smoothing)
            for tld, (n, pos) in sorted(counts.items())
        }
        support = {tld: n for tld, (n, _) in sorted(counts.items())}
        return cls(prior=prior, smoothing=smoothing, rates=rates, support=support)

    def rate(self, tld: str) -> float:
        return self.rates.get(tld, self.prior)

    # ----------------------------------------------------------------------- #
    # Sérialisation (relue par l'extension, module 5)
    # ----------------------------------------------------------------------- #

    def to_dict(self) -> dict[str, Any]:
        return {
            "prior": round(self.prior, 6),
            "smoothing": self.smoothing,
            "rates": {tld: round(rate, 6) for tld, rate in self.rates.items()},
            "support": dict(self.support),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> TldRiskTable:
        return cls(
            prior=float(data["prior"]),
            smoothing=float(data["smoothing"]),
            rates={str(k): float(v) for k, v in data["rates"].items()},
            support={str(k): int(v) for k, v in data.get("support", {}).items()},
        )

    def save(self, path: Path) -> None:
        Path(path).write_text(json.dumps(self.to_dict(), indent=2) + "\n", encoding="utf-8")

    @classmethod
    def load(cls, path: Path) -> TldRiskTable:
        return cls.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))
