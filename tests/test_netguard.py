"""Tests du garde-fou réseau anti-SSRF (étape 2.3).

Aucun test n'utilise le réseau : la résolution DNS est simulée (résolveur injecté ou
``socket.getaddrinfo`` remplacé) et les réponses HTTP passent par ``httpx.MockTransport``.
"""

import asyncio
import gzip
import ipaddress
import socket

import httpx
import pytest
from hypothesis import given
from hypothesis import strategies as st

from phishguard.security import netguard as ng
from phishguard.security.netguard import (
    BlockedDestination,
    NetPolicy,
    ResponseTooLarge,
    TooManyRedirects,
)

PUBLIC = "93.184.215.14"
PUBLIC_2 = "151.101.1.69"


def run(coro):
    return asyncio.run(coro)


def fake_resolver(table):
    """Résolveur simulé : ``{nom: [ip, ...]}``. Enregistre les appels."""

    async def resolve(host, port):
        resolve.calls.append((host, port))
        if host not in table:
            raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")
        answer = table[host]
        return answer() if callable(answer) else answer

    resolve.calls = []
    return resolve


PUBLIC_DNS = fake_resolver({"example.com": [PUBLIC], "cdn.example.net": [PUBLIC_2]})


def blocked_reason(url, resolver=PUBLIC_DNS, policy=ng.DEFAULT_POLICY):
    with pytest.raises(BlockedDestination) as info:
        run(ng.resolve_target(url, policy=policy, resolver=resolver))
    return info.value.reason


# --------------------------------------------------------------------------- #
# Critère « Terminé quand » de l'étape 2.3
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("url", "reason"),
    [
        ("http://127.0.0.1", "blocked_address"),
        ("http://localhost", "blocked_hostname"),
        ("http://169.254.169.254", "blocked_address"),
        ("http://[::1]", "blocked_address"),
        ("http://0x7f000001", "blocked_address"),
        ("http://2130706433", "blocked_address"),
        ("file:///etc/passwd", "scheme_not_allowed"),
    ],
)
def test_done_criteria_urls_are_refused(url, reason):
    assert blocked_reason(url) == reason


def test_domain_resolving_to_a_private_ip_is_refused():
    resolver = fake_resolver({"intranet.example.com": ["10.0.0.5"]})
    assert blocked_reason("https://intranet.example.com/admin", resolver) == "blocked_address"
    assert resolver.calls == [("intranet.example.com", 443)]


def test_localhost_through_the_system_resolver_is_refused(monkeypatch):
    # Même si le filtre de noms était contourné (/etc/hosts), l'adresse est refusée.
    def getaddrinfo(host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port))]

    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)
    monkeypatch.setattr(ng, "BLOCKED_NAME_SUFFIXES", ())
    assert blocked_reason("http://localhost/", resolver=ng.system_resolver) == "blocked_address"


# --------------------------------------------------------------------------- #
# Schéma, port, identifiants, nom d'hôte
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("url", "reason"),
    [
        ("ftp://example.com/", "scheme_not_allowed"),
        ("gopher://example.com:70/_SMTP", "scheme_not_allowed"),
        ("javascript:alert(1)", "scheme_not_allowed"),
        ("data:text/html,x", "scheme_not_allowed"),
        ("//example.com/", "scheme_not_allowed"),
        ("http://example.com:22/", "port_not_allowed"),
        ("http://example.com:6379/", "port_not_allowed"),
        ("https://example.com:8443/", "port_not_allowed"),
        ("http://user:pass@example.com/", "credentials_in_url"),
        ("http://example.com@127.0.0.1/", "credentials_in_url"),
        ("http:///path", "missing_host"),
        ("http://exa mple.com/", "invalid_host"),
        ("http://-bad-.example.com/", "invalid_host"),
        ("http://a..example.com/", "invalid_host"),
        ("http://[not-an-ip]/", "invalid_url"),
    ],
)
def test_malformed_or_forbidden_urls_are_refused(url, reason):
    assert blocked_reason(url) == reason


@pytest.mark.parametrize(
    "host",
    [
        "localhost.",
        "LOCALHOST",
        "app.localhost",
        "printer.local",
        "metadata.google.internal",
        "nas.home.arpa",
        "box.localdomain",
    ],
)
def test_local_names_are_refused_before_resolution(host):
    resolver = fake_resolver({host.lower(): [PUBLIC]})
    assert blocked_reason(f"http://{host}/", resolver) == "blocked_hostname"
    assert resolver.calls == []


def test_allowed_ports_are_configurable():
    policy = NetPolicy(allowed_ports=frozenset({443, 8443}))
    target = run(ng.resolve_target("https://example.com:8443/", policy=policy, resolver=PUBLIC_DNS))
    assert target.port == 8443
    assert blocked_reason("http://example.com/", policy=policy) == "port_not_allowed"


def test_public_domain_is_accepted():
    target = run(ng.resolve_target("https://Example.COM/login?x=1", resolver=PUBLIC_DNS))
    assert target.host == "example.com"
    assert target.port == 443
    assert target.addresses == (ipaddress.ip_address(PUBLIC),)
    assert not target.is_ip_literal


def test_internationalized_domain_is_resolved_in_punycode():
    resolver = fake_resolver({"xn--bcher-kva.de": [PUBLIC]})
    target = run(ng.resolve_target("http://bücher.de/", resolver=resolver))
    assert target.host == "xn--bcher-kva.de"


# --------------------------------------------------------------------------- #
# Adresses IP : formes ambiguës et plages interdites
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("0x7f000001", "127.0.0.1"),
        ("2130706433", "127.0.0.1"),
        ("0177.0.0.1", "127.0.0.1"),
        ("0x7f.0.0.1", "127.0.0.1"),
        ("127.1", "127.0.0.1"),
        ("127.0.1", "127.0.0.1"),
        ("10.1", "10.0.0.1"),
        ("0", "0.0.0.0"),
        ("0xa9fea9fe", "169.254.169.254"),
        ("127.0.0.1.", "127.0.0.1"),
        ("0x5db8d70e", PUBLIC),
    ],
)
def test_legacy_ipv4_forms_are_decoded(host, expected):
    assert ng.parse_legacy_ipv4(host) == ipaddress.IPv4Address(expected)


@pytest.mark.parametrize("host", ["example.com", "1.example.com", "0x7f.example.com", "xn--80a"])
def test_domain_names_are_not_ipv4(host):
    assert ng.parse_legacy_ipv4(host) is None


@pytest.mark.parametrize(
    "host", ["1.2.3.4.5", "256.0.0.1", "08.0.0.1", "1..2", "example.123", "4294967296"]
)
def test_invalid_numeric_hosts_are_refused_not_resolved(host):
    resolver = fake_resolver({host: [PUBLIC]})
    with pytest.raises(BlockedDestination) as info:
        run(ng.resolve_target(f"http://{host}/", resolver=resolver))
    assert info.value.reason in {"invalid_ip", "invalid_url"}
    assert resolver.calls == []


@pytest.mark.parametrize(
    "url",
    [
        "http://127.1/",
        "http://0/",
        "http://0.0.0.0/",
        "http://10.0.0.1/",
        "http://172.16.0.1/",
        "http://192.168.1.1/",
        "http://100.64.0.1/",  # espace partagé (CGNAT)
        "http://192.0.2.1/",  # documentation
        "http://198.18.0.1/",  # bancs de test
        "http://224.0.0.1/",  # multicast
        "http://255.255.255.255/",
        "http://[::]/",
        "http://[::ffff:127.0.0.1]/",
        "http://[::ffff:7f00:1]/",
        "http://[::ffff:169.254.169.254]/",
        "http://[fe80::1]/",
        "http://[fe80::1%25eth0]/",
        "http://[fc00::1]/",
        "http://[fd12:3456::1]/",
        "http://[ff02::1]/",
        "http://[2002:7f00:1::]/",  # 6to4 vers 127.0.0.1
        "http://[2001:0:4136:e378:8000:63bf:3fff:fdd2]/",  # Teredo
        "http://[64:ff9b::a9fe:a9fe]/",  # NAT64 vers 169.254.169.254
        "http://[fd00:ec2::254]/",  # métadonnées AWS en IPv6
    ],
)
def test_non_public_addresses_are_refused(url):
    assert blocked_reason(url) == "blocked_address"


def test_octal_ipv4_is_refused_even_before_the_guard():
    # httpx refuse déjà cette forme ; parse_legacy_ipv4 la décode pour les autres chemins.
    assert blocked_reason("http://0177.0.0.1/") in {"invalid_url", "blocked_address"}


@pytest.mark.parametrize("ip", [PUBLIC, "8.8.8.8", "2606:4700:4700::1111", "2001:4860:4860::8888"])
def test_public_addresses_are_accepted(ip):
    assert ng.is_public_ip(ipaddress.ip_address(ip))


@given(st.ip_addresses(v=4))
def test_every_ipv4_is_judged_the_same_in_any_notation(ip):
    """Une IP refusée l'est aussi écrite en entier, en hexadécimal ou en octal."""
    for host in (str(int(ip)), hex(int(ip)), ".".join(f"0{b:o}" for b in ip.packed)):
        assert ng.parse_legacy_ipv4(host) == ip


@given(st.ip_addresses(v=4).filter(lambda ip: not ip.is_global))
def test_non_global_ipv4_is_never_public(ip):
    assert not ng.is_public_ip(ip)
    assert not ng.is_public_ip(ipaddress.IPv6Address(f"::ffff:{ip}"))


# --------------------------------------------------------------------------- #
# Résolution DNS
# --------------------------------------------------------------------------- #


def test_one_private_address_among_public_ones_is_enough_to_refuse():
    resolver = fake_resolver({"mixed.example.com": [PUBLIC, "127.0.0.1", PUBLIC_2]})
    assert blocked_reason("http://mixed.example.com/", resolver) == "blocked_address"


def test_ipv6_answer_is_checked_too():
    resolver = fake_resolver({"dual.example.com": [PUBLIC, "::1"]})
    assert blocked_reason("http://dual.example.com/", resolver) == "blocked_address"


def test_dns_errors_are_refusals():
    assert blocked_reason("http://unknown.example.org/") == "dns_failure"
    assert blocked_reason("http://empty.example/", fake_resolver({"empty.example": []})) == (
        "dns_failure"
    )
    garbage = fake_resolver({"bad.example": ["not-an-ip"]})
    assert blocked_reason("http://bad.example/", garbage) == "dns_failure"


def test_slow_dns_is_a_refusal():
    async def slow(host, port):
        await asyncio.sleep(10)

    policy = NetPolicy(dns_timeout=0.05)
    assert blocked_reason("http://example.com/", slow, policy) == "dns_timeout"


def test_system_resolver_uses_getaddrinfo(monkeypatch):
    seen = []

    def getaddrinfo(host, port, *args, **kwargs):
        seen.append((host, port))
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", (PUBLIC, port)),
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2606:4700::1", port, 0, 0)),
        ]

    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)
    target = run(ng.resolve_target("https://example.com/", resolver=ng.system_resolver))
    assert seen == [("example.com", 443)]
    assert [str(a) for a in target.addresses] == [PUBLIC, "2606:4700::1"]


# --------------------------------------------------------------------------- #
# Requête protégée : connexion à l'IP validée, redirections, limites
# --------------------------------------------------------------------------- #


class Recorder:
    """Transport simulé : renvoie les réponses de ``routes`` et garde les requêtes."""

    def __init__(self, routes):
        self.routes = routes
        self.requests = []

    def __call__(self, request):
        self.requests.append(request)
        key = (request.headers["host"], request.url.path)
        return self.routes[key]() if callable(self.routes[key]) else self.routes[key]

    @property
    def transport(self):
        return httpx.MockTransport(self)


def fetch(url, recorder, resolver=PUBLIC_DNS, **kwargs):
    return run(ng.guarded_request(url, resolver=resolver, transport=recorder.transport, **kwargs))


def test_connects_to_the_validated_ip_with_the_original_host_and_sni():
    recorder = Recorder({("example.com", "/page"): httpx.Response(200, text="bonjour")})
    response = fetch("https://example.com/page?q=1", recorder)
    sent = recorder.requests[0]
    assert sent.url.host == PUBLIC  # connexion à l'IP, pas au nom
    assert sent.url.params["q"] == "1"
    assert sent.headers["host"] == "example.com"
    assert sent.extensions["sni_hostname"] == "example.com"  # certificat vérifié pour le nom
    assert (response.status_code, response.content, response.address) == (200, b"bonjour", PUBLIC)
    assert response.url == "https://example.com/page?q=1"


def test_dns_rebinding_cannot_redirect_the_connection():
    # 1re réponse publique (validée), 2e privée : on ne résout qu'une fois par saut,
    # et on se connecte à l'adresse validée.
    answers = iter([[PUBLIC], ["127.0.0.1"]])
    resolver = fake_resolver({"rebind.example.com": lambda: next(answers)})
    recorder = Recorder({("rebind.example.com", "/"): httpx.Response(200)})
    fetch("http://rebind.example.com/", recorder, resolver)
    assert len(resolver.calls) == 1
    assert recorder.requests[0].url.host == PUBLIC


def test_ip_literal_url_has_no_sni_and_keeps_the_port_in_host():
    policy = NetPolicy(allowed_ports=frozenset({443, 8443}))
    recorder = Recorder({(f"{PUBLIC}:8443", "/"): httpx.Response(204)})
    fetch(f"https://{PUBLIC}:8443/", recorder, policy=policy)
    assert "sni_hostname" not in recorder.requests[0].extensions


def test_ipv6_host_header_is_bracketed():
    recorder = Recorder({("[2606:4700:4700::1111]", "/"): httpx.Response(200)})
    fetch("http://[2606:4700:4700::1111]/", recorder)
    assert recorder.requests[0].url.host == "2606:4700:4700::1111"


def test_only_minimal_headers_are_sent():
    recorder = Recorder({("example.com", "/"): httpx.Response(200)})
    fetch("http://example.com/", recorder)
    sent = {k.lower() for k in recorder.requests[0].headers}
    assert "cookie" not in sent and "authorization" not in sent
    assert recorder.requests[0].headers["user-agent"].startswith("PhishGuard-netguard")


def test_redirects_are_followed_and_revalidated():
    recorder = Recorder(
        {
            ("example.com", "/short"): httpx.Response(301, headers={"location": "/step"}),
            ("example.com", "/step"): httpx.Response(
                302, headers={"location": "https://cdn.example.net/final"}
            ),
            ("cdn.example.net", "/final"): httpx.Response(200, text="ok"),
        }
    )
    response = fetch("http://example.com/short", recorder)
    assert response.url == "https://cdn.example.net/final"
    assert response.redirects == ("http://example.com/step", "https://cdn.example.net/final")
    assert [r.url.host for r in recorder.requests] == [PUBLIC, PUBLIC, PUBLIC_2]


@pytest.mark.parametrize(
    "location",
    [
        "http://169.254.169.254/latest/meta-data/",
        "http://localhost:80/admin",
        "http://0x7f000001/",
        "file:///etc/passwd",
        "http://example.com:6379/",
        "http://internal.example.com/",
    ],
)
def test_redirect_to_a_forbidden_destination_is_refused(location):
    resolver = fake_resolver({"example.com": [PUBLIC], "internal.example.com": ["10.1.2.3"]})
    recorder = Recorder(
        {("example.com", "/go"): httpx.Response(302, headers={"location": location})}
    )
    with pytest.raises(BlockedDestination):
        fetch("http://example.com/go", recorder, resolver)
    assert len(recorder.requests) == 1  # la destination interdite n'est jamais contactée


def test_redirect_loop_is_capped():
    recorder = Recorder(
        {("example.com", "/loop"): httpx.Response(302, headers={"location": "/loop"})}
    )
    with pytest.raises(TooManyRedirects):
        fetch("http://example.com/loop", recorder, policy=NetPolicy(max_redirects=2))
    assert len(recorder.requests) == 3  # la requête initiale et deux redirections


def test_redirect_without_location_is_returned_as_is():
    recorder = Recorder({("example.com", "/"): httpx.Response(302)})
    assert fetch("http://example.com/", recorder).status_code == 302


def test_declared_oversized_response_is_refused():
    big = httpx.Response(200, headers={"content-length": "5000000"}, content=b"")
    recorder = Recorder({("example.com", "/"): big})
    with pytest.raises(ResponseTooLarge) as info:
        fetch("http://example.com/", recorder)
    assert info.value.reason == "content_length"


def test_streamed_oversized_response_is_refused():
    def stream():
        async def chunks():
            for _ in range(100):
                yield b"x" * 1024

        return httpx.Response(200, content=chunks())

    recorder = Recorder({("example.com", "/"): stream})
    with pytest.raises(ResponseTooLarge) as info:
        fetch("http://example.com/", recorder, policy=NetPolicy(max_bytes=10_000))
    assert info.value.reason == "body"


def test_gzip_bomb_is_measured_after_decompression():
    bomb = gzip.compress(b"\0" * 2_000_000)  # environ 2 Ko compressés
    response = httpx.Response(200, headers={"content-encoding": "gzip"}, content=bomb)
    recorder = Recorder({("example.com", "/"): response})
    assert len(bomb) < 10_000
    with pytest.raises(ResponseTooLarge):
        fetch("http://example.com/", recorder, policy=NetPolicy(max_bytes=100_000))


def test_slow_response_hits_the_total_timeout():
    async def handler(request):
        await asyncio.sleep(10)
        return httpx.Response(200)

    with pytest.raises(TimeoutError):
        run(
            ng.guarded_request(
                "http://example.com/",
                resolver=PUBLIC_DNS,
                transport=httpx.MockTransport(handler),
                policy=NetPolicy(total_timeout=0.1),
            )
        )


def test_only_get_and_head_are_allowed():
    recorder = Recorder({("example.com", "/"): httpx.Response(200)})
    assert fetch("http://example.com/", recorder, method="head").status_code == 200
    assert recorder.requests[0].method == "HEAD"
    with pytest.raises(ng.NetGuardError) as info:
        fetch("http://example.com/", recorder, method="POST")
    assert info.value.reason == "method_not_allowed"


def test_client_ignores_proxy_environment(monkeypatch):
    # Un proxy implicite choisirait lui-même la destination : il est ignoré.
    monkeypatch.setenv("HTTP_PROXY", "http://10.0.0.1:3128")
    monkeypatch.setenv("HTTPS_PROXY", "http://10.0.0.1:3128")
    recorder = Recorder({("example.com", "/"): httpx.Response(200)})
    fetch("http://example.com/", recorder)
    assert recorder.requests[0].url.host == PUBLIC


def test_blocked_destination_is_never_contacted():
    recorder = Recorder({})
    for url in ("http://127.0.0.1/", "http://localhost/", "http://[::1]/", "file:///etc/passwd"):
        with pytest.raises(BlockedDestination):
            fetch(url, recorder)
    assert recorder.requests == []
