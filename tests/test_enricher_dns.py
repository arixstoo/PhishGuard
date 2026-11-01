"""Tests de l'enrichisseur DNS (étape 2.7). La résolution est simulée, sans réseau."""

import asyncio
import types

import dns.exception
import dns.resolver
import pytest

from phishguard.enrichers import dns_records as D
from phishguard.enrichers.dns_records import DnsEnricher, DomainDoesNotExist


def run(coro):
    return asyncio.run(coro)


def fake_lookup(records, errors=None):
    """``records`` : ``{type: (ttl, [valeurs])}`` ; un type absent donne une réponse vide."""

    async def lookup(name, rdtype):
        lookup.calls.append((name, rdtype))
        if errors and rdtype in errors:
            raise errors[rdtype]
        return records.get(rdtype, (0, []))

    lookup.calls = []
    return lookup


def enrich(records, errors=None, domain="example.com"):
    lookup = fake_lookup(records, errors)
    return run(DnsEnricher(lookup=lookup).enrich(f"https://{domain}/", domain)), lookup


TYPICAL = {
    "A": (3600, ["93.184.215.14"]),
    "AAAA": (3600, ["2606:2800:21f:cb07:6820:80da:af6b:8b2c"]),
    "MX": (3600, ["10 mail.example.com."]),
    "NS": (86400, ["a.iana-servers.net.", "b.iana-servers.net."]),
}


def test_typical_domain_has_no_risk():
    signal, lookup = enrich(TYPICAL)
    assert (signal.source, signal.status, signal.risk) == ("dns", "ok", 0.0)
    assert signal.evidence["a"] == ["93.184.215.14"]
    assert signal.evidence["mx"] == ["mail.example.com"]
    assert signal.evidence["ns"] == ["a.iana-servers.net", "b.iana-servers.net"]
    assert signal.evidence["flags"] == []
    assert sorted(t for _, t in lookup.calls) == ["A", "AAAA", "MX", "NS"]


def test_free_dns_provider_is_flagged():
    records = {**TYPICAL, "NS": (3600, ["ns1.afraid.org.", "ns2.afraid.org."])}
    signal, _ = enrich(records)
    assert signal.risk == pytest.approx(0.3)
    assert signal.evidence["free_dns_provider"] == "afraid.org"
    assert "free_dns_provider" in signal.evidence["flags"]


def test_fast_flux_like_answer_is_flagged():
    ips = [f"198.51.100.{i}" for i in range(1, 9)]
    signal, _ = enrich({**TYPICAL, "A": (60, ips)})
    assert signal.risk == pytest.approx(0.3)
    assert "fast_flux_like" in signal.evidence["flags"]
    assert signal.evidence["a_ttl"] == 60


def test_low_ttl_alone_is_not_a_risk():
    # Les CDN légitimes utilisent des TTL courts : seul, ce n'est pas un signal.
    signal, _ = enrich({**TYPICAL, "A": (60, ["104.16.0.1", "104.16.0.2"])})
    assert signal.risk == 0.0


def test_risk_is_capped():
    records = {
        **TYPICAL,
        "A": (30, [f"198.51.100.{i}" for i in range(10)]),
        "NS": (300, ["ns1.duckdns.org."]),
    }
    signal, _ = enrich(records)
    assert signal.risk == D.MAX_RISK


def test_missing_mx_is_recorded_but_not_a_url_risk():
    records = {k: v for k, v in TYPICAL.items() if k != "MX"}
    signal, _ = enrich(records)
    assert signal.risk == 0.0 and "no_mx" in signal.evidence["flags"]


def test_null_mx_means_no_email():
    signal, _ = enrich({**TYPICAL, "MX": (3600, ["0 ."])})
    assert signal.evidence["null_mx"] is True and signal.evidence["mx"] == []
    assert "no_mx" in signal.evidence["flags"]


def test_nonexistent_domain_gives_no_risk():
    errors = {t: DomainDoesNotExist("x") for t in ("A", "AAAA", "MX", "NS")}
    signal, _ = enrich({}, errors)
    assert (signal.status, signal.risk, signal.evidence) == ("ok", 0.0, {"exists": False})


def test_partial_failures_are_reported():
    signal, _ = enrich(TYPICAL, {"AAAA": TimeoutError(), "MX": OSError()})
    assert signal.status == "ok"
    assert signal.evidence["errors"] == {"AAAA": "TimeoutError", "MX": "OSError"}
    assert "no_mx" not in signal.evidence["flags"]  # MX inconnu, pas absent


def test_total_failure_is_a_timeout_or_error_signal():
    timeouts = {t: TimeoutError() for t in ("A", "AAAA", "MX", "NS")}
    assert enrich({}, timeouts)[0].status == "timeout"
    failures = {t: OSError() for t in ("A", "AAAA", "MX", "NS")}
    assert enrich({}, failures)[0].status == "error"


@pytest.mark.parametrize("domain", ["", "10.0.0.1", "localhost"])
def test_invalid_domain_is_skipped_without_lookup(domain):
    signal, lookup = enrich(TYPICAL, domain=domain)
    assert signal.status == "skipped" and lookup.calls == []


# --------------------------------------------------------------------------- #
# Résolution réelle par dnspython (bibliothèque simulée)
# --------------------------------------------------------------------------- #


class FakeRecord:
    def __init__(self, text):
        self.text = text

    def to_text(self):
        return self.text


class FakeAnswer(list):
    def __init__(self, ttl, values):
        super().__init__(FakeRecord(v) for v in values)
        self.rrset = types.SimpleNamespace(ttl=ttl)


@pytest.mark.parametrize(
    ("raised", "expected"),
    [
        (dns.resolver.NXDOMAIN(), DomainDoesNotExist),
        (dns.exception.Timeout(), TimeoutError),
    ],
)
def test_dnspython_errors_are_translated(monkeypatch, raised, expected):
    async def resolve(self, *args, **kwargs):
        raise raised

    monkeypatch.setattr(D.dns.asyncresolver.Resolver, "__init__", lambda self, *a, **k: None)
    monkeypatch.setattr(D.dns.asyncresolver.Resolver, "resolve", resolve)
    with pytest.raises(expected):
        run(D.make_dnspython_lookup()("example.com", "A"))


def test_dnspython_answers_and_empty_answers(monkeypatch):
    seen = []

    async def resolve(self, name, rdtype, **kwargs):
        seen.append((name, rdtype, kwargs["search"]))
        if rdtype == "MX":
            raise dns.resolver.NoAnswer()
        return FakeAnswer(120, ["93.184.215.14"])

    monkeypatch.setattr(D.dns.asyncresolver.Resolver, "__init__", lambda self, *a, **k: None)
    monkeypatch.setattr(D.dns.asyncresolver.Resolver, "resolve", resolve)
    lookup = D.make_dnspython_lookup()

    async def scenario():
        return await lookup("example.com", "A"), await lookup("example.com", "MX")

    assert run(scenario()) == ((120, ["93.184.215.14"]), (0, []))
    assert seen[0] == ("example.com", "A", False)  # pas de domaine de recherche local
