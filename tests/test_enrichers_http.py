"""Tests du socle HTTP des enrichisseurs."""

import asyncio

import httpx
import pytest
import respx

from phishguard.enrichers.http import (
    USER_AGENT,
    ExpiringCache,
    HttpEnricher,
    status_reason,
)


class Clock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now


class Echo(HttpEnricher):
    name = "echo"

    async def _enrich(self, url, domain):
        async with self.http() as client:
            response = await client.get("https://api.example.test/echo")
        return self.ok(evidence={"user_agent": response.request.headers["user-agent"]})


def test_cache_expires_entries():
    clock = Clock()
    cache = ExpiringCache(clock=clock)
    cache.set("a", 1, ttl=10)
    assert cache.get("a") == 1
    clock.now = 10
    assert cache.get("a") is None and len(cache) == 0


def test_cache_evicts_the_oldest_entry():
    cache = ExpiringCache(maxsize=2)
    for key in "abc":
        cache.set(key, key, ttl=60)
    assert cache.get("a") is None and cache.get("c") == "c"


def test_cache_ignores_non_positive_ttl_and_refreshes_on_set():
    clock = Clock()
    cache = ExpiringCache(maxsize=2, clock=clock)
    cache.set("a", 1, ttl=0)
    assert cache.get("a") is None
    cache.set("a", 1, ttl=5)
    cache.set("b", 2, ttl=5)
    cache.set("a", 3, ttl=5)  # a redevient le plus récent
    cache.set("c", 4, ttl=5)
    assert (cache.get("a"), cache.get("b")) == (3, None)
    with pytest.raises(ValueError):
        ExpiringCache(maxsize=0)


@pytest.mark.parametrize(
    ("status", "reason"),
    [
        (401, "unauthorized"),
        (403, "unauthorized"),
        (404, "not_found"),
        (429, "rate_limited"),
        (500, "server_error"),
        (502, "server_error"),
        (400, "http_400"),
        (302, "http_302"),
    ],
)
def test_status_reason(status, reason):
    assert status_reason(status) == reason


@respx.mock
def test_default_client_sends_an_identifiable_user_agent():
    respx.get("https://api.example.test/echo").mock(return_value=httpx.Response(200))
    signal = asyncio.run(Echo().enrich("https://x.test/", "x.test"))
    assert signal.evidence["user_agent"] == USER_AGENT


@respx.mock
def test_injected_client_is_used_and_left_open():
    respx.get("https://api.example.test/echo").mock(return_value=httpx.Response(200))

    async def scenario():
        async with httpx.AsyncClient(headers={"User-Agent": "shared"}) as client:
            enricher = Echo(client=client)
            first = await enricher.enrich("https://x.test/", "x.test")
            second = await enricher.enrich("https://x.test/", "x.test")
            return first, second, client.is_closed

    first, second, closed = asyncio.run(scenario())
    assert first.evidence["user_agent"] == "shared" and second.status == "ok"
    assert not closed


@respx.mock
def test_redirects_are_not_followed():
    respx.get("https://api.example.test/echo").mock(
        return_value=httpx.Response(302, headers={"location": "http://169.254.169.254/"})
    )
    route = respx.get("http://169.254.169.254/")

    class Status(HttpEnricher):
        name = "status"

        async def _enrich(self, url, domain):
            async with self.http() as client:
                response = await client.get("https://api.example.test/echo")
            return self.ok(evidence={"status": response.status_code})

    signal = asyncio.run(Status().enrich("https://x.test/", "x.test"))
    assert signal.evidence["status"] == 302 and not route.called


@pytest.mark.parametrize(
    ("domain", "expected"),
    [
        ("Example.COM.", "example.com"),
        ("bücher.de", "xn--bcher-kva.de"),
        ("xn--bcher-kva.de", "xn--bcher-kva.de"),
        ("127.0.0.1", None),
        ("[::1]", None),
        ("localhost", None),
        ("a..b", None),
        ("-x.com", None),
        ("ex_ample.com", None),
        ("", None),
    ],
)
def test_normalize_domain(domain, expected):
    from phishguard.enrichers.http import normalize_domain

    assert normalize_domain(domain) == expected
