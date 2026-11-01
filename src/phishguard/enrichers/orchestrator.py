"""Orchestrateur des enrichisseurs : parallèle, avec un budget de temps (étape 2.9).

Toutes les sources actives sont interrogées **en même temps**, sous un budget global
de 2,5 secondes. À l'échéance, les sources qui n'ont pas répondu sont **annulées** et
marquées ``timeout`` (``reason: budget_exceeded``), et les autres sont utilisées.
L'analyse ne lève jamais d'exception à cause d'une source : elle **se dégrade**.

Le budget de 2,5 s laisse de la marge sous l'objectif de 3 s avec enrichissement
(cahier des charges, exigences non fonctionnelles). Il borne le pire cas : sans lui, une
seule source lente (crt.sh) fixerait la latence de toute l'analyse.

**Vie privée.** L'enrichissement est un choix de l'utilisateur (opt-in). Avec
``enabled=False``, aucune source n'est appelée et le résultat l'indique
(``enrichment = "skipped"``).

Usage ::

    async with Orchestrator.from_settings() as orchestrator:
        result = await orchestrator.enrich("https://exemple.com/login")

Le contexte ``async with`` crée le client HTTP partagé par toutes les sources (étape 2.8)
et le ferme à la fin.

Limite : l'annulation ne peut interrompre qu'un code qui rend la main à la boucle
asyncio. Une source qui bloquerait la boucle (appel synchrone) retarderait tout ; les
enrichisseurs du projet sont tous asynchrones.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Collection, Sequence
from dataclasses import dataclass
from types import TracebackType
from typing import Literal, Self

import httpx

from phishguard.config import Settings, get_settings
from phishguard.enrichers.base import Enricher, Signal, SignalStatus
from phishguard.enrichers.http import create_shared_client
from phishguard.enrichers.registry import build_enrichers
from phishguard.urls.features import InvalidUrlError, parse_url

logger = logging.getLogger(__name__)

DEFAULT_BUDGET_S = 2.5
# Temps laissé aux sources annulées pour libérer leurs ressources (connexions…).
CANCEL_GRACE_S = 0.2

Enrichment = Literal["used", "skipped"]


@dataclass(frozen=True)
class EnrichmentResult:
    """Signaux de toutes les sources interrogées, dans l'ordre des sources."""

    signals: tuple[Signal, ...]
    enrichment: Enrichment
    latency_ms: int
    budget_ms: int

    @property
    def by_source(self) -> dict[str, Signal]:
        return {signal.source: signal for signal in self.signals}

    @property
    def usable(self) -> tuple[Signal, ...]:
        """Signaux exploitables par la fusion (statut ``ok``)."""
        return tuple(s for s in self.signals if s.usable)

    @property
    def timed_out(self) -> tuple[str, ...]:
        return tuple(s.source for s in self.signals if s.status is SignalStatus.TIMEOUT)


def registered_domain(url: str) -> str:
    """Domaine enregistré de ``url`` (``login.exemple.co.uk`` → ``exemple.co.uk``), ou ``""``."""
    try:
        return parse_url(url).registered_domain
    except (InvalidUrlError, ValueError):
        return ""


class Orchestrator:
    def __init__(
        self,
        enrichers: Sequence[Enricher],
        *,
        budget_s: float = DEFAULT_BUDGET_S,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        if budget_s <= 0:
            raise ValueError("le budget doit être positif")
        names = [e.name for e in enrichers]
        if len(names) != len(set(names)):
            raise ValueError(
                f"sources en double : {sorted({n for n in names if names.count(n) > 1})}"
            )
        self.enrichers = tuple(enrichers)
        self.budget_s = budget_s
        self._client = client  # client partagé dont l'orchestrateur est propriétaire

    @classmethod
    def from_settings(
        cls, settings: Settings | None = None, *, budget_s: float = DEFAULT_BUDGET_S
    ) -> Self:
        """Toutes les sources du registre, sur un client HTTP partagé (à fermer)."""
        client = create_shared_client()
        enrichers = build_enrichers(settings or get_settings(), client=client)
        return cls(enrichers, budget_s=budget_s, client=client)

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()

    @property
    def sources(self) -> tuple[str, ...]:
        return tuple(e.name for e in self.enrichers)

    async def enrich(
        self,
        url: str,
        domain: str | None = None,
        *,
        enabled: bool = True,
        sources: Collection[str] | None = None,
    ) -> EnrichmentResult:
        """Interroge les sources au sujet de ``url``. Ne lève jamais à cause d'une source.

        ``domain`` vaut par défaut le domaine enregistré de l'URL. ``sources`` limite
        l'analyse à certaines sources ; ``enabled=False`` n'en appelle aucune.
        """
        budget_ms = round(self.budget_s * 1000)
        if not enabled:
            return EnrichmentResult((), "skipped", 0, budget_ms)
        if sources is not None:
            unknown = set(sources) - set(self.sources)
            if unknown:
                raise ValueError(f"sources inconnues : {sorted(unknown)}")
        selected = [e for e in self.enrichers if sources is None or e.name in sources]
        domain = registered_domain(url) if domain is None else domain

        start = time.perf_counter()
        tasks = {
            enricher.name: asyncio.create_task(
                enricher.enrich(url, domain), name=f"enrich:{enricher.name}"
            )
            for enricher in selected
        }
        try:
            if tasks:
                await asyncio.wait(tasks.values(), timeout=self.budget_s)
        except asyncio.CancelledError:
            await _cancel(tasks.values())  # l'appelant abandonne : les sources aussi
            raise
        pending = [t for t in tasks.values() if not t.done()]
        if pending:
            await _cancel(pending)

        signals = tuple(self._collect(name, task, budget_ms) for name, task in tasks.items())
        latency_ms = round((time.perf_counter() - start) * 1000)
        return EnrichmentResult(signals, "used", latency_ms, budget_ms)

    @staticmethod
    def _collect(name: str, task: asyncio.Task[Signal], budget_ms: int) -> Signal:
        if task.cancelled() or not task.done():
            return Signal(
                source=name,
                status=SignalStatus.TIMEOUT,
                evidence={"reason": "budget_exceeded", "budget_ms": budget_ms},
                latency_ms=budget_ms,
            )
        exc = task.exception()
        if exc is not None:
            # enrich() ne lève pas, par contrat (étape 2.2) ; cette garde protège l'analyse
            # d'une source qui ne le respecterait pas.
            logger.error("source %s : exception hors contrat", name, exc_info=exc)
            return Signal(
                source=name, status=SignalStatus.ERROR, evidence={"error": type(exc).__name__}
            )
        return task.result()


async def _cancel(tasks: Collection[asyncio.Task[Signal]]) -> None:
    for task in tasks:
        task.cancel()
    _, still_running = await asyncio.wait(tasks, timeout=CANCEL_GRACE_S)
    for task in still_running:
        logger.warning("source %s : annulation ignorée", task.get_name())
