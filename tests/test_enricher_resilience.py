"""Tests des nouvelles tentatives et du disjoncteur des enrichisseurs (étape 2.8)."""

import asyncio
from datetime import UTC, datetime, timedelta
from email.utils import format_datetime

import httpx
import pytest
import respx

from phishguard.enrichers.http import (
    DEFAULT_TIMEOUT,
    USER_AGENT,
    HttpEnricher,
    create_shared_client,
)
from phishguard.enrichers.resilience import (
    NO_RETRY,
    CircuitBreaker,
    CircuitOpen,
    CircuitState,
    ResilientClient,
    RetryPolicy,
    retry_after,
    send_with_retry,
    should_retry,
)

API = "https://api.example.test/lookup"
POLICY = RetryPolicy(attempts=3, base_delay=0.2, max_delay=1.0, jitter=0.0)


def run(coro):
    return asyncio.run(coro)


class Clock:
    def __init__(self):
        self.now = 1_000.0

    def __call__(self):
        return self.now


class Sleeps:
    """Fonction d'attente simulée : enregistre les délais demandés."""

    def __init__(self):
        self.delays = []

    async def __call__(self, seconds):
        self.delays.append(seconds)


class Lookup(HttpEnricher):
    """Source minimale : une requête, un signal."""

    name = "lookup"

    async def _enrich(self, url, domain):
        async with self.http() as client:
            response = await client.get(API, params={"q": domain})
        if response.status_code != 200:
            return self.error("http", {"http_status": response.status_code})
        return self.ok(0.5, {"answer": response.json()})


async def fetch(policy=POLICY, sleep=None, stream=False):
    async with httpx.AsyncClient() as client:

        async def send():
            return await client.send(client.build_request("GET", API), stream=stream)

        return await send_with_retry(send, policy, sleep)


# --------------------------------------------------------------------------- #
# Politique de nouvelles tentatives
# --------------------------------------------------------------------------- #


def test_backoff_is_exponential_and_capped():
    policy = RetryPolicy(base_delay=0.2, max_delay=1.0, jitter=0.0)
    assert [policy.backoff(n) for n in (1, 2, 3, 4, 5)] == [0.2, 0.4, 0.8, 1.0, 1.0]
    jittered = RetryPolicy(base_delay=0.2, max_delay=1.0, jitter=0.1)
    assert all(0.2 <= jittered.backoff(1) <= 0.3 for _ in range(50))


@pytest.mark.parametrize(
    "kwargs", [{"attempts": 0}, {"base_delay": -1}, {"max_delay": -1}, {"jitter": -0.1}]
)
def test_invalid_policies_are_rejected(kwargs):
    with pytest.raises(ValueError):
        RetryPolicy(**kwargs)


def test_retry_after_header_forms():
    assert retry_after(httpx.Response(429, headers={"Retry-After": "2"})) == 2.0
    assert retry_after(httpx.Response(429, headers={"X-Rate-Limit-Reset-After": "0.5"})) == 0.5
    assert retry_after(httpx.Response(429, headers={"Retry-After": "soon"})) is None
    assert retry_after(httpx.Response(429)) is None
    soon = format_datetime(datetime.now(UTC) + timedelta(seconds=30), usegmt=True)
    assert 25 <= retry_after(httpx.Response(503, headers={"Retry-After": soon})) <= 31
    past = format_datetime(datetime.now(UTC) - timedelta(hours=1), usegmt=True)
    assert retry_after(httpx.Response(503, headers={"Retry-After": past})) == 0.0


@pytest.mark.parametrize(
    ("status", "headers", "expected"),
    [
        (500, {}, True),
        (502, {}, True),
        (503, {}, True),
        (504, {}, True),
        (503, {"Retry-After": "30"}, False),  # délai trop long pour le budget
        (429, {}, False),  # quota épuisé : réessayer le consommerait
        (429, {"Retry-After": "0.5"}, True),
        (429, {"Retry-After": "30"}, False),
        (400, {}, False),
        (401, {}, False),
        (404, {}, False),
        (200, {}, False),
    ],
)
def test_only_transient_responses_are_retried(status, headers, expected):
    assert should_retry(httpx.Response(status, headers=headers), POLICY) is expected


@respx.mock
def test_server_error_is_retried_with_exponential_backoff():
    route = respx.get(API).mock(
        side_effect=[httpx.Response(503), httpx.Response(502), httpx.Response(200, json=1)]
    )
    sleeps = Sleeps()
    response = run(fetch(sleep=sleeps))
    assert (response.status_code, route.call_count) == (200, 3)
    assert sleeps.delays == [0.2, 0.4]


@respx.mock
def test_last_response_is_returned_when_attempts_run_out():
    route = respx.get(API).mock(return_value=httpx.Response(503))
    response = run(fetch(sleep=Sleeps()))
    assert (response.status_code, route.call_count) == (503, 3)


@respx.mock
def test_short_retry_after_is_honoured():
    respx.get(API).mock(
        side_effect=[httpx.Response(429, headers={"Retry-After": "0.5"}), httpx.Response(200)]
    )
    sleeps = Sleeps()
    assert run(fetch(sleep=sleeps)).status_code == 200
    assert sleeps.delays == [0.5]


@respx.mock
def test_quota_exhausted_is_not_retried():
    route = respx.get(API).mock(return_value=httpx.Response(429))
    assert run(fetch(sleep=Sleeps())).status_code == 429
    assert route.call_count == 1


@respx.mock
def test_connection_errors_are_retried():
    route = respx.get(API).mock(
        side_effect=[
            httpx.ConnectError("refusée"),
            httpx.ConnectTimeout("lent"),
            httpx.Response(200),
        ]
    )
    assert run(fetch(sleep=Sleeps())).status_code == 200
    assert route.call_count == 3


@respx.mock
def test_persistent_connection_error_is_raised():
    respx.get(API).mock(side_effect=httpx.ConnectError("refusée"))
    with pytest.raises(httpx.ConnectError):
        run(fetch(sleep=Sleeps()))


@respx.mock
def test_read_timeout_is_not_retried():
    route = respx.get(API).mock(side_effect=httpx.ReadTimeout("lent"))
    with pytest.raises(httpx.ReadTimeout):
        run(fetch(sleep=Sleeps()))
    assert route.call_count == 1


@respx.mock
def test_streamed_response_is_closed_before_retrying():
    first = httpx.Response(503)
    respx.get(API).mock(side_effect=[first, httpx.Response(200)])
    assert run(fetch(sleep=Sleeps(), stream=True)).status_code == 200
    assert first.is_closed


@respx.mock
def test_no_retry_policy_sends_once():
    route = respx.get(API).mock(return_value=httpx.Response(503))
    run(fetch(policy=NO_RETRY, sleep=Sleeps()))
    assert route.call_count == 1


# --------------------------------------------------------------------------- #
# Disjoncteur
# --------------------------------------------------------------------------- #


def test_breaker_opens_after_five_consecutive_failures():
    clock = Clock()
    breaker = CircuitBreaker("src", clock=clock)
    for _ in range(4):
        breaker.before_call()
        breaker.record_failure()
    assert breaker.state is CircuitState.CLOSED
    breaker.before_call()
    breaker.record_failure()
    assert breaker.state is CircuitState.OPEN
    with pytest.raises(CircuitOpen) as info:
        breaker.before_call()
    assert info.value.reason == "circuit_open"
    assert info.value.retry_in_s == pytest.approx(60.0)


def test_a_success_resets_the_failure_count():
    breaker = CircuitBreaker("src")
    for _ in range(4):
        breaker.record_failure()
    breaker.record_success()
    for _ in range(4):
        breaker.record_failure()
    assert breaker.state is CircuitState.CLOSED and breaker.consecutive_failures == 4


def test_half_open_allows_a_single_probe():
    clock = Clock()
    breaker = CircuitBreaker("src", failure_threshold=1, clock=clock)
    breaker.record_failure()
    clock.now += 59.9
    assert breaker.state is CircuitState.OPEN
    clock.now += 0.1
    assert breaker.state is CircuitState.HALF_OPEN
    breaker.before_call()  # la requête d'essai
    with pytest.raises(CircuitOpen):
        breaker.before_call()  # une seconde requête attend le résultat de l'essai
    breaker.record_success()
    assert breaker.state is CircuitState.CLOSED
    breaker.before_call()


def test_failed_probe_reopens_for_a_full_period():
    clock = Clock()
    breaker = CircuitBreaker("src", clock=clock)
    for _ in range(5):
        breaker.record_failure()
    clock.now += 60
    breaker.before_call()
    breaker.record_failure()  # un seul échec suffit en semi-ouvert
    assert breaker.state is CircuitState.OPEN
    clock.now += 59
    assert breaker.state is CircuitState.OPEN


def test_cancelled_probe_frees_the_slot():
    clock = Clock()
    breaker = CircuitBreaker("src", failure_threshold=1, clock=clock)
    breaker.record_failure()
    clock.now += 60
    breaker.before_call()
    breaker.release()
    breaker.before_call()  # un nouvel essai est possible


@pytest.mark.parametrize("kwargs", [{"failure_threshold": 0}, {"reset_timeout": 0}])
def test_invalid_breaker_settings(kwargs):
    with pytest.raises(ValueError):
        CircuitBreaker("src", **kwargs)


# --------------------------------------------------------------------------- #
# Critère de l'étape : panne simulée, le disjoncteur s'ouvre puis se referme
# --------------------------------------------------------------------------- #


@respx.mock
def test_outage_opens_the_breaker_then_recovery_closes_it():
    clock = Clock()
    route = respx.get(API).mock(return_value=httpx.Response(503))
    source = Lookup(breaker=CircuitBreaker("lookup", clock=clock))

    async def call():
        return await source.enrich("https://example.test/", "example.test")

    async def outage_then_recovery():
        failures = [await call() for _ in range(5)]  # panne : 5 échecs consécutifs
        calls_during_outage = route.call_count
        paused = await call()  # disjoncteur ouvert : la source n'est plus interrogée
        calls_while_open = route.call_count - calls_during_outage
        clock.now += 60  # fin de la pause
        route.mock(return_value=httpx.Response(200, json="ok"))  # la source est rétablie
        probe = await call()
        after = await call()
        return failures, calls_during_outage, paused, calls_while_open, probe, after

    failures, calls_during_outage, paused, calls_while_open, probe, after = run(
        outage_then_recovery()
    )
    assert [s.status for s in failures] == ["error"] * 5
    assert calls_during_outage == 15  # 5 analyses × 3 tentatives
    assert source.breaker.state is CircuitState.CLOSED
    assert paused.status == "skipped" and paused.evidence["reason"] == "circuit_open"
    assert paused.evidence["retry_in_s"] == pytest.approx(60.0)
    assert paused.latency_ms < 50 and calls_while_open == 0
    assert (probe.status, probe.risk, after.status) == ("ok", 0.5, "ok")


@respx.mock
def test_client_errors_do_not_open_the_breaker():
    respx.get(API).mock(return_value=httpx.Response(401))
    source = Lookup()

    async def many():
        return [await source.enrich("https://example.test/", "example.test") for _ in range(8)]

    assert all(s.evidence["http_status"] == 401 for s in run(many()))
    assert source.breaker.state is CircuitState.CLOSED


@respx.mock
def test_network_errors_count_as_failures():
    clock = Clock()
    respx.get(API).mock(side_effect=httpx.ConnectError("refusée"))
    source = Lookup(breaker=CircuitBreaker("lookup", failure_threshold=2, clock=clock))

    async def three():
        return [await source.enrich("https://example.test/", "example.test") for _ in range(3)]

    signals = run(three())
    assert [s.status for s in signals] == ["error", "error", "skipped"]


@respx.mock
def test_each_source_has_its_own_breaker():
    class Other(Lookup):
        name = "other"

    respx.get(API).mock(return_value=httpx.Response(503))
    broken = Lookup(breaker=CircuitBreaker("lookup", failure_threshold=1))
    healthy = Other()
    run(broken.enrich("https://x.test/", "x.test"))
    assert broken.breaker.state is CircuitState.OPEN
    assert healthy.breaker.state is CircuitState.CLOSED
    assert healthy.breaker.source == "other"


# --------------------------------------------------------------------------- #
# Client partagé
# --------------------------------------------------------------------------- #


def test_shared_client_defaults():
    async def scenario():
        async with create_shared_client() as client:
            return client.timeout, client.headers["user-agent"], client.follow_redirects

    timeout, user_agent, follow = run(scenario())
    assert timeout == DEFAULT_TIMEOUT
    assert (timeout.connect, timeout.read) == (2.0, 3.0)
    assert user_agent == USER_AGENT and follow is False


@respx.mock
def test_sources_share_one_client_and_keep_it_open():
    class Other(Lookup):
        name = "other"

    respx.get(API).mock(return_value=httpx.Response(200, json="ok"))

    async def scenario():
        async with create_shared_client() as client:
            sources = [Lookup(client=client), Other(client=client)]
            signals = await asyncio.gather(
                *(s.enrich("https://x.test/", "x.test") for s in sources)
            )
            return signals, client.is_closed

    signals, closed = run(scenario())
    assert [s.status for s in signals] == ["ok", "ok"] and not closed


@respx.mock
def test_resilient_client_exposes_post_and_request():
    respx.post(API).mock(return_value=httpx.Response(201))

    async def scenario():
        async with httpx.AsyncClient() as raw:
            client = ResilientClient(raw, CircuitBreaker("x"), POLICY)
            return (await client.post(API, json={"a": 1})).status_code, client.is_closed

    assert run(scenario()) == (201, False)
