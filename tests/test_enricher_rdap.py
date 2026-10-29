"""Tests de l'enrichisseur RDAP (étape 2.7), réponses simulées par respx.

Les réponses suivent le format RFC 9083 et reprennent les dates d'enregistrement
publiques de cinq domaines connus. Elles ne sont pas capturées sur les serveurs réels :
``scripts/check_enrichers.py --source rdap`` le vérifie en local.
"""

import asyncio
from datetime import UTC, datetime

import httpx
import pytest
import respx

from phishguard.enrichers.rdap import (
    BOOTSTRAP_URL,
    RdapEnricher,
    parse_bootstrap,
    risk_from_age,
    server_for,
)

NOW = datetime(2026, 10, 29, 12, 0, tzinfo=UTC)
VERISIGN = "https://rdap.verisign.com/com/v1/"
PIR = "https://rdap.publicinterestregistry.org/rdap/"
BOOTSTRAP = {
    "version": "1.0",
    "publication": "2026-10-01T00:00:00Z",
    "services": [
        [["com", "net"], [VERISIGN]],
        [["org"], [PIR]],
        [["uk"], ["https://rdap.nominet.uk/uk/"]],
        [["co.uk"], ["https://rdap.example-cc.test/"]],
        [["de"], ["https://rdap.denic.de/"]],
        [["insecure"], ["http://rdap.insecure.test/"]],
    ],
}


def run(coro):
    return asyncio.run(coro)


def rdap_domain(name, registered=None, registrar="MarkMonitor Inc.", iana_id="292"):
    events = [{"eventAction": "expiration", "eventDate": "2028-09-14T04:00:00Z"}]
    if registered:
        events.insert(0, {"eventAction": "registration", "eventDate": registered})
    return {
        "objectClassName": "domain",
        "ldhName": name.upper(),
        "status": ["client delete prohibited", "client transfer prohibited"],
        "events": events,
        "entities": [
            {
                "objectClassName": "entity",
                "roles": ["registrar"],
                "publicIds": [{"type": "IANA Registrar ID", "identifier": iana_id}],
                "vcardArray": [
                    "vcard",
                    [["version", {}, "text", "4.0"], ["fn", {}, "text", registrar]],
                ],
            }
        ],
        "nameservers": [{"objectClassName": "nameserver", "ldhName": "NS1.EXAMPLE.NET"}],
    }


def enricher(**kwargs):
    return RdapEnricher(now=lambda: NOW, **kwargs)


def mock_bootstrap():
    return respx.get(BOOTSTRAP_URL).mock(return_value=httpx.Response(200, json=BOOTSTRAP))


# --------------------------------------------------------------------------- #
# Critère de l'étape : âge correct sur 5 domaines connus
# --------------------------------------------------------------------------- #

KNOWN_DOMAINS = [
    ("google.com", VERISIGN, "1997-09-15T04:00:00Z", 10_636),
    ("example.com", VERISIGN, "1995-08-14T04:00:00Z", 11_399),
    ("wikipedia.org", PIR, "2001-01-13T00:12:14Z", 9_420),
    ("github.com", VERISIGN, "2007-10-09T18:20:50Z", 6_959),
    ("python.org", PIR, "1995-03-27T05:00:00Z", 11_539),
]


@pytest.mark.parametrize(("domain", "server", "registered", "age_days"), KNOWN_DOMAINS)
@respx.mock
def test_age_of_known_domains(domain, server, registered, age_days):
    mock_bootstrap()
    route = respx.get(f"{server}domain/{domain}").mock(
        return_value=httpx.Response(200, json=rdap_domain(domain, registered))
    )
    signal = run(enricher().enrich(f"https://www.{domain}/", domain))
    assert route.called
    assert (signal.source, signal.status, signal.risk) == ("rdap", "ok", 0.0)
    assert signal.evidence["age_days"] == age_days
    assert signal.evidence["registration_date"].startswith(registered[:10])
    assert signal.evidence["registrar"] == {"name": "MarkMonitor Inc.", "iana_id": "292"}
    assert signal.evidence["server"] == server


@respx.mock
def test_three_day_old_domain_is_a_strong_signal():
    mock_bootstrap()
    respx.get(f"{VERISIGN}domain/secure-login-update.com").mock(
        return_value=httpx.Response(
            200, json=rdap_domain("secure-login-update.com", "2026-10-26T09:00:00Z", "NameCheap")
        )
    )
    signal = run(enricher().enrich("https://secure-login-update.com/", "secure-login-update.com"))
    assert (signal.evidence["age_days"], signal.risk) == (3, 1.0)


@pytest.mark.parametrize(
    ("age", "risk"),
    [
        (None, 0.0),
        (-1, 0.0),
        (0, 1.0),
        (6, 1.0),
        (7, 0.8),
        (29, 0.8),
        (30, 0.4),
        (89, 0.4),
        (90, 0.1),
        (364, 0.1),
        (365, 0.0),
        (10_000, 0.0),
    ],
)
def test_age_risk_scale(age, risk):
    assert risk_from_age(age) == risk


# --------------------------------------------------------------------------- #
# Signal manquant : jamais un risque (piège de l'étape)
# --------------------------------------------------------------------------- #


@respx.mock
def test_registry_without_registration_date_gives_no_risk():
    mock_bootstrap()
    respx.get("https://rdap.denic.de/domain/example.de").mock(
        return_value=httpx.Response(200, json=rdap_domain("example.de", registered=None))
    )
    signal = run(enricher().enrich("https://example.de/", "example.de"))
    assert (signal.status, signal.risk, signal.evidence["age_days"]) == ("ok", 0.0, None)
    assert signal.evidence["note"] == "registration_date_missing"


@respx.mock
def test_tld_without_rdap_server_is_skipped():
    mock_bootstrap()
    signal = run(enricher().enrich("https://example.zz/", "example.zz"))
    assert (signal.status, signal.risk, signal.evidence) == (
        "skipped",
        0.0,
        {"reason": "no_rdap_server"},
    )


@respx.mock
def test_unregistered_domain_gives_no_risk():
    mock_bootstrap()
    respx.get(f"{VERISIGN}domain/not-registered-xyz.com").mock(return_value=httpx.Response(404))
    signal = run(enricher().enrich("https://not-registered-xyz.com/", "not-registered-xyz.com"))
    assert (signal.status, signal.risk, signal.evidence["found"]) == ("ok", 0.0, False)


@pytest.mark.parametrize(("status", "reason"), [(429, "rate_limited"), (503, "server_error")])
@respx.mock
def test_registry_errors(status, reason):
    mock_bootstrap()
    respx.get(f"{VERISIGN}domain/example.com").mock(return_value=httpx.Response(status))
    signal = run(enricher().enrich("https://example.com/", "example.com"))
    assert (signal.status, signal.evidence["reason"], signal.risk) == ("error", reason, 0.0)


@respx.mock
def test_bootstrap_failure_is_an_error_signal():
    respx.get(BOOTSTRAP_URL).mock(return_value=httpx.Response(500))
    assert run(enricher().enrich("https://example.com/", "example.com")).status == "error"


@respx.mock
def test_malformed_rdap_answer_is_an_error():
    mock_bootstrap()
    respx.get(f"{VERISIGN}domain/example.com").mock(
        return_value=httpx.Response(200, json={"objectClassName": "entity"})
    )
    assert run(enricher().enrich("https://example.com/", "example.com")).status == "error"


@pytest.mark.parametrize("domain", ["", "192.0.2.1", "localhost"])
def test_invalid_domain_is_skipped(domain):
    assert run(enricher().enrich("https://x/", domain)).evidence == {"reason": "unsupported_input"}


# --------------------------------------------------------------------------- #
# Amorçage IANA et cache
# --------------------------------------------------------------------------- #


def test_bootstrap_keeps_only_https_servers():
    servers = parse_bootstrap(BOOTSTRAP)
    assert servers["com"] == servers["net"] == VERISIGN
    assert "insecure" not in servers


def test_longest_suffix_wins():
    servers = parse_bootstrap(BOOTSTRAP)
    assert server_for("example.co.uk", servers) == "https://rdap.example-cc.test/"
    assert server_for("example.uk", servers) == "https://rdap.nominet.uk/uk/"
    assert server_for("example.zz", servers) is None


@respx.mock
def test_bootstrap_and_results_are_cached():
    bootstrap = mock_bootstrap()
    route = respx.get(f"{VERISIGN}domain/example.com").mock(
        return_value=httpx.Response(200, json=rdap_domain("example.com", "1995-08-14T04:00:00Z"))
    )
    other = respx.get(f"{VERISIGN}domain/github.com").mock(
        return_value=httpx.Response(200, json=rdap_domain("github.com", "2007-10-09T18:20:50Z"))
    )
    source = enricher()

    async def scenario():
        await source.enrich("https://example.com/", "example.com")
        second = await source.enrich("https://example.com/a", "example.com")
        await source.enrich("https://github.com/", "github.com")
        return second

    second = run(scenario())
    assert (bootstrap.call_count, route.call_count, other.call_count) == (1, 1, 1)
    assert second.evidence["cached"] is True


@respx.mock
def test_rdap_request_asks_for_rdap_json():
    mock_bootstrap()
    route = respx.get(f"{VERISIGN}domain/example.com").mock(
        return_value=httpx.Response(200, json=rdap_domain("example.com", "1995-08-14T04:00:00Z"))
    )
    run(enricher().enrich("https://example.com/", "Example.COM"))
    assert "application/rdap+json" in route.calls.last.request.headers["accept"]
