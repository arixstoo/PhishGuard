"""Résilience des appels aux sources : nouvelles tentatives et disjoncteur (étape 2.8).

Deux mécanismes complémentaires, appliqués à chaque requête HTTP d'un enrichisseur par
:class:`ResilientClient` :

**Nouvelles tentatives** (``tenacity``), seulement sur les erreurs **temporaires** :

- réponses 500, 502, 503 et 504 ;
- réponse 429, **seulement** si la source annonce un délai court (``Retry-After``, ou
  ``X-Rate-Limit-Reset-After`` chez urlscan). Sans délai annoncé, un 429 signale un
  quota épuisé (VirusTotal) : réessayer ne ferait que le consommer davantage ;
- échecs de connexion (``ConnectError``, ``ConnectTimeout``, ``RemoteProtocolError``).

Un délai de **lecture** dépassé n'est pas retenté : la source a reçu la requête et elle
est lente, recommencer doublerait l'attente. Le délai entre deux tentatives croît de
façon exponentielle (0,2 s puis 0,4 s, avec un peu d'aléa) et ne dépasse jamais
``max_delay`` : l'orchestrateur (étape 2.9) n'accorde que 2,5 s à l'ensemble des sources.

**Disjoncteur** (*circuit breaker*), un par source. Après 5 échecs consécutifs (erreur
réseau, délai dépassé, 5xx ou 429 après les nouvelles tentatives), la source est mise en
pause 60 s : on ne l'interroge plus, et l'enrichisseur renvoie ``skipped``
(``circuit_open``) immédiatement, au lieu d'attendre une panne de plus. Ensuite, **une
seule** requête d'essai est autorisée (état « semi-ouvert ») : si elle réussit, le
disjoncteur se referme ; sinon, il se rouvre pour 60 s. Une réponse 4xx autre que 429
(clé refusée, page absente) prouve que la source répond : ce n'est pas un échec.
"""

from __future__ import annotations

import asyncio
import logging
import random
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from email.utils import parsedate_to_datetime
from enum import StrEnum
from typing import Any

import httpx
from tenacity import AsyncRetrying, RetryCallState, stop_after_attempt

from phishguard.enrichers.base import SourceUnavailable

logger = logging.getLogger(__name__)

TRANSIENT_STATUSES = frozenset({429, 500, 502, 503, 504})
RETRYABLE_ERRORS: tuple[type[Exception], ...] = (
    httpx.ConnectError,
    httpx.ConnectTimeout,
    httpx.RemoteProtocolError,
)
RETRY_AFTER_HEADERS = ("Retry-After", "X-Rate-Limit-Reset-After")

Sleep = Callable[[float], Awaitable[None]]


async def _sleep(seconds: float) -> None:
    await asyncio.sleep(seconds)


# --------------------------------------------------------------------------- #
# Nouvelles tentatives
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class RetryPolicy:
    attempts: int = 3  # requête initiale comprise
    base_delay: float = 0.2
    max_delay: float = 1.0  # délai maximal entre deux tentatives, Retry-After compris
    jitter: float = 0.1

    def __post_init__(self) -> None:
        if self.attempts < 1:
            raise ValueError("attempts doit valoir au moins 1")
        if self.base_delay < 0 or self.max_delay < 0 or self.jitter < 0:
            raise ValueError("les délais doivent être positifs")

    def backoff(self, attempt: int) -> float:
        """Délai avant la tentative ``attempt + 1`` (``attempt`` commence à 1)."""
        delay = min(self.max_delay, self.base_delay * 2 ** (attempt - 1))
        return min(self.max_delay, delay + random.uniform(0, self.jitter))


DEFAULT_RETRY = RetryPolicy()
NO_RETRY = RetryPolicy(attempts=1)


def retry_after(response: httpx.Response) -> float | None:
    """Délai annoncé par la source, en secondes (nombre ou date HTTP), ou ``None``."""
    for header in RETRY_AFTER_HEADERS:
        value = response.headers.get(header)
        if value is None:
            continue
        value = value.strip()
        try:
            return max(0.0, float(value))
        except ValueError:
            pass
        try:
            when = parsedate_to_datetime(value)
        except (TypeError, ValueError):
            continue
        return max(0.0, when.timestamp() - time.time())
    return None


def should_retry(response: httpx.Response, policy: RetryPolicy) -> bool:
    if response.status_code not in TRANSIENT_STATUSES:
        return False
    delay = retry_after(response)
    if delay is not None:
        return delay <= policy.max_delay
    return response.status_code != 429  # 429 sans délai : quota épuisé


async def send_with_retry(
    send: Callable[[], Awaitable[httpx.Response]],
    policy: RetryPolicy = DEFAULT_RETRY,
    sleep: Sleep | None = None,
) -> httpx.Response:
    """Appelle ``send`` et le relance sur les erreurs temporaires, selon ``policy``.

    Renvoie la dernière réponse, même en erreur, ou relève la dernière exception.
    ``send`` doit être une fonction ``async`` (pas une ``lambda`` qui renvoie une
    coroutine : ``tenacity`` ne l'attendrait pas).
    """

    def retry(state: RetryCallState) -> bool:
        outcome = state.outcome
        assert outcome is not None
        if outcome.failed:
            return isinstance(outcome.exception(), RETRYABLE_ERRORS)
        return should_retry(outcome.result(), policy)

    def wait(state: RetryCallState) -> float:
        outcome = state.outcome
        if outcome is not None and not outcome.failed:
            announced = retry_after(outcome.result())
            if announced is not None:
                return announced
        return policy.backoff(state.attempt_number)

    async def before_sleep(state: RetryCallState) -> None:
        outcome = state.outcome
        if outcome is not None and not outcome.failed:
            await outcome.result().aclose()  # libère la connexion d'une réponse en flux
        logger.debug("nouvelle tentative %d", state.attempt_number + 1)

    def give_up(state: RetryCallState) -> Any:
        assert state.outcome is not None
        return state.outcome.result()  # dernière réponse, ou relève la dernière exception

    retrying = AsyncRetrying(
        stop=stop_after_attempt(policy.attempts),
        wait=wait,
        retry=retry,
        before_sleep=before_sleep,
        retry_error_callback=give_up,
        sleep=sleep or (lambda seconds: _sleep(seconds)),
    )
    return await retrying(send)


# --------------------------------------------------------------------------- #
# Disjoncteur
# --------------------------------------------------------------------------- #


class CircuitState(StrEnum):
    CLOSED = "closed"  # fonctionnement normal
    OPEN = "open"  # source en pause : aucune requête
    HALF_OPEN = "half_open"  # pause terminée : une requête d'essai autorisée


class CircuitOpen(SourceUnavailable):
    def __init__(self, source: str, retry_in_s: float | None) -> None:
        super().__init__("circuit_open", retry_in_s)
        self.source = source


class CircuitBreaker:
    """Disjoncteur d'une source. Utilisé depuis une seule boucle asyncio : pas de verrou."""

    def __init__(
        self,
        source: str,
        *,
        failure_threshold: int = 5,
        reset_timeout: float = 60.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if failure_threshold < 1 or reset_timeout <= 0:
            raise ValueError("failure_threshold >= 1 et reset_timeout > 0")
        self.source = source
        self.failure_threshold = failure_threshold
        self.reset_timeout = reset_timeout
        self._clock = clock
        self._state = CircuitState.CLOSED
        self._failures = 0
        self._opened_at = 0.0
        self._probe_in_flight = False

    @property
    def state(self) -> CircuitState:
        if self._state is CircuitState.OPEN and self._remaining() <= 0:
            self._state = CircuitState.HALF_OPEN
        return self._state

    @property
    def consecutive_failures(self) -> int:
        return self._failures

    def _remaining(self) -> float:
        return self._opened_at + self.reset_timeout - self._clock()

    def before_call(self) -> None:
        """Lève :class:`CircuitOpen` si la source ne doit pas être interrogée."""
        state = self.state
        if state is CircuitState.OPEN:
            raise CircuitOpen(self.source, self._remaining())
        if state is CircuitState.HALF_OPEN:
            if self._probe_in_flight:
                raise CircuitOpen(self.source, None)  # une requête d'essai est déjà en cours
            self._probe_in_flight = True

    def record_success(self) -> None:
        if self._state is not CircuitState.CLOSED:
            logger.info("source %s rétablie : disjoncteur refermé", self.source)
        self._state = CircuitState.CLOSED
        self._failures = 0
        self._probe_in_flight = False

    def record_failure(self) -> None:
        self._failures += 1
        self._probe_in_flight = False
        if self._state is CircuitState.HALF_OPEN or self._failures >= self.failure_threshold:
            if self._state is not CircuitState.OPEN:
                logger.warning(
                    "source %s en panne (%d échecs) : pause de %.0f s",
                    self.source,
                    self._failures,
                    self.reset_timeout,
                )
            self._state = CircuitState.OPEN
            self._opened_at = self._clock()

    def release(self) -> None:
        """Requête interrompue sans résultat (annulation) : ni succès ni échec."""
        self._probe_in_flight = False


# --------------------------------------------------------------------------- #
# Client
# --------------------------------------------------------------------------- #


class ResilientClient:
    """Enveloppe d'un ``httpx.AsyncClient`` : disjoncteur et nouvelles tentatives.

    Expose la partie de l'interface ``httpx`` utilisée par les enrichisseurs :
    ``get``, ``post``, ``request``, ``build_request`` et ``send``.
    """

    def __init__(
        self,
        client: httpx.AsyncClient,
        breaker: CircuitBreaker,
        retry: RetryPolicy = DEFAULT_RETRY,
        sleep: Sleep | None = None,
    ) -> None:
        self._client = client
        self.breaker = breaker
        self.retry = retry
        self._sleep = sleep

    @property
    def is_closed(self) -> bool:
        return self._client.is_closed

    def build_request(self, method: str, url: str | httpx.URL, **kwargs: Any) -> httpx.Request:
        return self._client.build_request(method, url, **kwargs)

    async def send(self, request: httpx.Request, *, stream: bool = False) -> httpx.Response:
        self.breaker.before_call()

        # Une vraie fonction async : tenacity n'attend pas le résultat d'une lambda.
        async def attempt() -> httpx.Response:
            return await self._client.send(request, stream=stream)

        try:
            response = await send_with_retry(attempt, self.retry, self._sleep)
        except httpx.HTTPError:
            self.breaker.record_failure()
            raise
        except BaseException:
            self.breaker.release()  # annulation (budget de l'orchestrateur) ou bug
            raise
        if response.status_code in TRANSIENT_STATUSES:
            self.breaker.record_failure()
        else:
            self.breaker.record_success()
        return response

    async def request(self, method: str, url: str | httpx.URL, **kwargs: Any) -> httpx.Response:
        return await self.send(self.build_request(method, url, **kwargs))

    async def get(self, url: str | httpx.URL, **kwargs: Any) -> httpx.Response:
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str | httpx.URL, **kwargs: Any) -> httpx.Response:
        return await self.request("POST", url, **kwargs)
