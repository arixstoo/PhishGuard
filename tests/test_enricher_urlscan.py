"""Tests de l'enrichisseur urlscan.io (étape 2.6), réponses simulées par respx."""

import asyncio
import json

import httpx
import pytest
import respx

from phishguard.config import Settings
from phishguard.enrichers.urlscan import API, UrlscanEnricher

KEY = "test-key-not-a-real-secret"
URL = "https://login.phish.example.test/verify?user=alice@example.org#step2"
DOMAIN = "phish.example.test"
SEARCH = f"{API}/search/"


def run(coro):
    return asyncio.run(coro)


def hit(uuid, page_domain, time="2026-10-20T10:00:00.000Z", verdicts=None, **page):
    item = {
        "_id": uuid,
        "task": {"time": time, "url": f"https://{page_domain}/", "visibility": "public"},
        "page": {
            "domain": page_domain,
            "url": f"https://{page_domain}/",
            "ip": "203.0.113.7",
            "country": "NL",
            "asnname": "EXAMPLE-AS",
            "server": "nginx",
            "status": "200",
            **page,
        },
        "sort": [1, uuid],
        "result": f"{API}/result/{uuid}/",
        "screenshot": f"https://urlscan.io/screenshots/{uuid}.png",
    }
    if verdicts is not None:
        item["verdicts"] = verdicts
    return item


def search(*items):
    return {"results": list(items), "total": len(items), "has_more": False}


RESULT_MALICIOUS = {
    "verdicts": {
        "overall": {
            "score": 100,
            "malicious": True,
            "categories": ["phishing"],
            "brands": [{"key": "examplebank", "name": "Example Bank"}],
        }
    }
}


def enricher(**kwargs):
    return UrlscanEnricher(KEY, **kwargs)


# --------------------------------------------------------------------------- #
# Recherche
# --------------------------------------------------------------------------- #


@respx.mock
def test_search_sends_only_the_domain():
    route = respx.get(SEARCH).mock(return_value=httpx.Response(200, json=search()))
    run(enricher().enrich(URL, DOMAIN))
    request = route.calls.last.request
    assert request.url.params["q"] == f"domain:{DOMAIN}"
    assert request.headers["api-key"] == KEY
    assert "alice" not in str(request.url) and "verify" not in str(request.url)


@respx.mock
def test_existing_malicious_scan_from_the_full_report():
    respx.get(SEARCH).mock(
        return_value=httpx.Response(200, json=search(hit("uuid-1", "login.phish.example.test")))
    )
    report = respx.get(f"{API}/result/uuid-1/").mock(
        return_value=httpx.Response(200, json=RESULT_MALICIOUS)
    )
    signal = run(enricher().enrich(URL, DOMAIN))
    assert report.called
    assert (signal.source, signal.status, signal.risk) == ("urlscan", "ok", 1.0)
    scan = signal.evidence["scans"][0]
    assert scan["verdict"] == {
        "malicious": True,
        "score": 100,
        "brands": ["Example Bank"],
        "categories": ["phishing"],
    }
    assert (scan["ip"], scan["country"], scan["asn_name"]) == ("203.0.113.7", "NL", "EXAMPLE-AS")
    assert scan["screenshot"] == "https://urlscan.io/screenshots/uuid-1.png"


@respx.mock
def test_verdict_in_search_results_avoids_the_report_call():
    verdicts = {"malicious": False, "score": 40}
    respx.get(SEARCH).mock(
        return_value=httpx.Response(200, json=search(hit("u", DOMAIN, verdicts=verdicts)))
    )
    report = respx.get(f"{API}/result/u/")
    signal = run(enricher().enrich(URL, DOMAIN))
    assert not report.called
    assert signal.risk == pytest.approx(0.4)


@respx.mock
def test_legitimate_score_gives_no_risk():
    verdicts = {"overall": {"malicious": False, "score": -100}}
    respx.get(SEARCH).mock(
        return_value=httpx.Response(200, json=search(hit("u", DOMAIN, verdicts=verdicts)))
    )
    assert run(enricher().enrich(URL, DOMAIN)).risk == 0.0


@respx.mock
def test_pages_that_only_load_a_resource_from_the_domain_are_ignored():
    # Une page sur un autre site qui charge un script depuis le domaine cherché.
    respx.get(SEARCH).mock(
        return_value=httpx.Response(
            200, json=search(hit("other", "unrelated.test"), hit("look", "phish.example.test.evil"))
        )
    )
    signal = run(enricher().enrich(URL, DOMAIN))
    assert signal.evidence == {"found": False, "scans": [], "cached": False}
    assert signal.risk == 0.0


@respx.mock
def test_latest_scan_decides_and_evidence_is_capped():
    items = [hit(f"u{i}", DOMAIN, time=f"2026-10-{10 + i:02d}T00:00:00Z") for i in range(8)]
    respx.get(SEARCH).mock(return_value=httpx.Response(200, json=search(*items)))
    report = respx.get(f"{API}/result/u7/").mock(
        return_value=httpx.Response(200, json=RESULT_MALICIOUS)
    )
    signal = run(enricher().enrich(URL, DOMAIN))
    assert report.called  # le plus récent, pas le premier de la liste
    assert signal.evidence["total"] == 8 and len(signal.evidence["scans"]) == 5


@respx.mock
def test_unavailable_report_still_gives_a_signal():
    respx.get(SEARCH).mock(return_value=httpx.Response(200, json=search(hit("u", DOMAIN))))
    respx.get(f"{API}/result/u/").mock(return_value=httpx.Response(404))
    signal = run(enricher().enrich(URL, DOMAIN))
    assert (signal.status, signal.risk) == ("ok", 0.0)
    assert signal.evidence["scans"][0]["verdict"] is None


# --------------------------------------------------------------------------- #
# Cache : critère de l'étape
# --------------------------------------------------------------------------- #


@respx.mock
def test_search_results_are_cached():
    now = [0.0]
    route = respx.get(SEARCH).mock(
        return_value=httpx.Response(
            200, json=search(hit("u", DOMAIN, verdicts={"malicious": True, "score": 100}))
        )
    )
    source = enricher(clock=lambda: now[0])

    async def scenario():
        first = await source.enrich(URL, DOMAIN)
        second = await source.enrich("https://other.phish.example.test/", DOMAIN)
        now[0] = 3601
        third = await source.enrich(URL, DOMAIN)
        return first, second, third

    first, second, third = run(scenario())
    assert route.call_count == 2
    assert (first.evidence["cached"], second.evidence["cached"]) == (False, True)
    assert second.risk == 1.0 and third.evidence["cached"] is False


# --------------------------------------------------------------------------- #
# Soumission : derrière un drapeau, jamais publique
# --------------------------------------------------------------------------- #


@respx.mock
def test_submission_is_off_by_default():
    respx.get(SEARCH).mock(return_value=httpx.Response(200, json=search()))
    scan = respx.post(f"{API}/scan/")
    signal = run(enricher().enrich(URL, DOMAIN))
    assert not scan.called
    assert (signal.status, signal.evidence["found"]) == ("ok", False)


@respx.mock
def test_submission_when_enabled_is_unlisted_and_strips_private_parts():
    respx.get(SEARCH).mock(return_value=httpx.Response(200, json=search()))
    scan = respx.post(f"{API}/scan/").mock(
        return_value=httpx.Response(
            200, json={"uuid": "new-uuid", "visibility": "unlisted", "api": f"{API}/result/new/"}
        )
    )
    signal = run(enricher(submit=True).enrich(URL, DOMAIN))
    body = json.loads(scan.calls.last.request.content)
    assert body == {
        "url": "https://login.phish.example.test/verify?user=alice@example.org",
        "visibility": "unlisted",
    }
    assert signal.status == "skipped"
    assert signal.evidence == {
        "reason": "scan_submitted",
        "uuid": "new-uuid",
        "requested_visibility": "unlisted",
        "visibility": "unlisted",
    }


@respx.mock
def test_same_url_is_not_submitted_twice_while_pending():
    respx.get(SEARCH).mock(return_value=httpx.Response(200, json=search()))
    scan = respx.post(f"{API}/scan/").mock(
        return_value=httpx.Response(200, json={"uuid": "pending-uuid"})
    )
    source = enricher(submit=True, visibility="private")

    async def twice():
        return [await source.enrich(URL, DOMAIN) for _ in range(2)]

    first, second = run(twice())
    assert first.evidence["reason"] == "scan_submitted"
    assert scan.call_count == 1
    assert json.loads(scan.calls.last.request.content)["visibility"] == "private"
    assert second.evidence == {"reason": "scan_pending", "uuid": "pending-uuid"}


@respx.mock
def test_visibility_enforced_by_urlscan_is_reported():
    respx.get(SEARCH).mock(return_value=httpx.Response(200, json=search()))
    respx.post(f"{API}/scan/").mock(
        return_value=httpx.Response(200, json={"uuid": "u", "visibility": "private"})
    )
    signal = run(enricher(submit=True).enrich(URL, DOMAIN))
    assert signal.evidence["visibility"] == "private"


def test_public_visibility_is_refused():
    with pytest.raises(ValueError, match="visibilité"):
        UrlscanEnricher(KEY, visibility="public")


def test_from_settings_reads_the_submission_flag(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    for var in ("URLSCAN_API_KEY", "URLSCAN_SUBMIT", "URLSCAN_VISIBILITY"):
        monkeypatch.delenv(var, raising=False)
    assert not UrlscanEnricher.from_settings(Settings()).is_enabled()
    monkeypatch.setenv("URLSCAN_API_KEY", KEY)
    monkeypatch.setenv("URLSCAN_SUBMIT", "true")
    monkeypatch.setenv("URLSCAN_VISIBILITY", "private")
    source = UrlscanEnricher.from_settings(Settings())
    assert source.is_enabled() and source._submit and source._visibility == "private"


# --------------------------------------------------------------------------- #
# Erreurs
# --------------------------------------------------------------------------- #


@respx.mock
def test_rate_limit_reports_when_to_retry():
    respx.get(SEARCH).mock(
        return_value=httpx.Response(429, headers={"X-Rate-Limit-Reset-After": "42"})
    )
    signal = run(enricher().enrich(URL, DOMAIN))
    assert signal.evidence == {"reason": "rate_limited", "http_status": 429, "retry_after_s": 42.0}


@pytest.mark.parametrize(("status", "reason"), [(401, "unauthorized"), (500, "server_error")])
@respx.mock
def test_http_errors(status, reason):
    respx.get(SEARCH).mock(return_value=httpx.Response(status))
    signal = run(enricher().enrich(URL, DOMAIN))
    assert (signal.status, signal.evidence["reason"]) == ("error", reason)


@pytest.mark.parametrize("body", [{"results": "x"}, [1], {"total": 3}])
@respx.mock
def test_malformed_search_is_an_error(body):
    respx.get(SEARCH).mock(return_value=httpx.Response(200, json=body))
    assert run(enricher().enrich(URL, DOMAIN)).status == "error"


@pytest.mark.parametrize("domain", ["", "127.0.0.1", "not a domain"])
def test_invalid_domain_is_skipped(domain):
    signal = run(enricher().enrich(URL, domain))
    assert (signal.status, signal.evidence) == ("skipped", {"reason": "unsupported_input"})
