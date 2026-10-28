"""Contrat commun des enrichisseurs de Threat Intelligence (étape 2.2).

Un enrichisseur interroge **une** source (Safe Browsing, VirusTotal, RDAP…) au sujet
d'une URL et de son domaine, et renvoie un :class:`Signal`. La règle centrale :

    **un enrichisseur ne lève jamais d'exception vers l'appelant.**

Un service tiers en panne, lent ou qui répond n'importe quoi ne doit pas faire tomber
l'analyse : il devient un signal ``error`` ou ``timeout``, et le verdict se dégrade au
lieu d'échouer. Cette règle n'est pas laissée à la discipline de chaque source : elle
est appliquée par :meth:`Enricher.enrich`, une méthode modèle (*template method*) que
les sous-classes ne redéfinissent pas. Elles implémentent :meth:`Enricher._enrich`, qui
peut lever ce qu'elle veut.

Exemple minimal ::

    class Example(Enricher):
        name = "example"

        async def _enrich(self, url: str, domain: str) -> Signal:
            listed = await lookup(domain)
            return self.ok(risk=1.0 if listed else 0.0, evidence={"listed": listed})

Deux exceptions ne sont **pas** converties en signal :

- ``asyncio.CancelledError`` : c'est ainsi que l'orchestrateur (étape 2.9) arrête une
  source qui dépasse le budget de temps. L'avaler empêcherait l'annulation ;
- ``KeyboardInterrupt`` et ``SystemExit`` (comme toute ``BaseException`` hors
  ``Exception``).

Le message d'une exception n'est jamais recopié dans le signal, seul son type l'est :
les erreurs HTTP contiennent souvent l'URL de la requête, et certaines API (Safe
Browsing) y mettent la clé (``?key=…``). Le détail part dans le journal, au niveau
``DEBUG``.
"""

from __future__ import annotations

import inspect
import logging
import time
from abc import ABC, abstractmethod
from enum import StrEnum
from typing import Any, ClassVar

import httpx
from pydantic import BaseModel, ConfigDict, Field

logger = logging.getLogger(__name__)


class SignalStatus(StrEnum):
    OK = "ok"  # la source a répondu, ``risk`` est utilisable
    ERROR = "error"  # échec (réseau, quota, réponse invalide, bug) : ``risk`` vaut 0
    SKIPPED = "skipped"  # source non interrogée (désactivée, clé absente, hors périmètre)
    TIMEOUT = "timeout"  # la source n'a pas répondu à temps


class Signal(BaseModel):
    """Résultat d'une source, quel qu'il soit.

    ``risk`` est une contribution normalisée entre 0 et 1, que la fusion (étape 2.10)
    pondère. **Un signal absent n'est pas un signal de risque** : hors ``ok``, ``risk``
    vaut toujours 0.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    source: str = Field(min_length=1)  # 'virustotal', 'rdap', ...
    status: SignalStatus
    risk: float = Field(default=0.0, ge=0.0, le=1.0)
    evidence: dict[str, Any] = Field(default_factory=dict)  # données utiles à l'analyste
    latency_ms: int = Field(default=0, ge=0)

    @property
    def usable(self) -> bool:
        """``True`` si la source a répondu et que ``risk`` peut entrer dans la fusion."""
        return self.status is SignalStatus.OK


class Enricher(ABC):
    """Source de Threat Intelligence. Voir la docstring du module pour le contrat."""

    #: Identifiant stable de la source, recopié dans ``Signal.source``.
    name: ClassVar[str]

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        if "enrich" in cls.__dict__:
            raise TypeError(
                f"{cls.__name__} ne doit pas redéfinir enrich() : implémenter _enrich()"
            )
        # ABCMeta ne calcule __abstractmethods__ qu'après __init_subclass__ : on teste
        # directement si _enrich est encore abstraite (classe intermédiaire).
        if getattr(cls._enrich, "__isabstractmethod__", False):
            return
        if not inspect.iscoroutinefunction(cls._enrich):
            raise TypeError(f"{cls.__name__}._enrich doit être une coroutine (async def)")
        name = getattr(cls, "name", None)
        if not isinstance(name, str) or not name:
            raise TypeError(f"{cls.__name__} doit définir un attribut de classe `name` non vide")

    def is_enabled(self) -> bool:
        """Faux si la source ne doit pas être interrogée (par exemple clé absente)."""
        return True

    @abstractmethod
    async def _enrich(self, url: str, domain: str) -> Signal:
        """Interroge la source. Peut lever : :meth:`enrich` convertit l'exception."""

    async def enrich(self, url: str, domain: str) -> Signal:
        """Interroge la source et renvoie toujours un :class:`Signal`, sans jamais lever."""
        if not self.is_enabled():
            return self.skipped("disabled")
        start = time.perf_counter()
        try:
            signal = await self._enrich(url, domain)
            if not isinstance(signal, Signal):
                raise TypeError(f"_enrich() a renvoyé {type(signal).__name__}, pas un Signal")
        except (TimeoutError, httpx.TimeoutException) as exc:
            signal = self._failure(SignalStatus.TIMEOUT, exc)
        except Exception as exc:  # noqa: BLE001 : le contrat interdit de propager
            signal = self._failure(SignalStatus.ERROR, exc)
        return self._finalize(signal, start)

    # ------------------------------------------------------------------ #
    # Constructeurs de signaux pour les sous-classes
    # ------------------------------------------------------------------ #

    def ok(self, risk: float = 0.0, evidence: dict[str, Any] | None = None) -> Signal:
        return Signal(source=self.name, status=SignalStatus.OK, risk=risk, evidence=evidence or {})

    def skipped(self, reason: str) -> Signal:
        return Signal(source=self.name, status=SignalStatus.SKIPPED, evidence={"reason": reason})

    def error(self, reason: str) -> Signal:
        """Échec attendu et déjà compris (quota épuisé, réponse illisible…)."""
        return Signal(source=self.name, status=SignalStatus.ERROR, evidence={"reason": reason})

    # ------------------------------------------------------------------ #

    def _failure(self, status: SignalStatus, exc: Exception) -> Signal:
        logger.debug("enrichisseur %s : %s", self.name, status, exc_info=exc)
        return Signal(source=self.name, status=status, evidence={"error": type(exc).__name__})

    def _finalize(self, signal: Signal, start: float) -> Signal:
        """Impose la source, la latence et ``risk = 0`` hors ``ok``."""
        update: dict[str, Any] = {
            "source": self.name,
            "latency_ms": max(0, round((time.perf_counter() - start) * 1000)),
        }
        if signal.status is not SignalStatus.OK:
            update["risk"] = 0.0
        return signal.model_copy(update=update)
