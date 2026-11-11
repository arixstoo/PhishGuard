"""Couche service et endpoints (étape 4.3).

Critère : les trois endpoints d'analyse renvoient le schéma figé de l'étape 2.11 bis.
Chaque réponse est relue par :class:`AnalysisResponse` (aucun champ inconnu, bornes et
cohérence vérifiées) et comparée à ce que le pipeline seul aurait produit.
"""

from __future__ import annotations

import asyncio
import hashlib
import threading

import pytest
from api_support import EMAILS, api_client, settings_for

from phishguard.analysis import EMAIL_RULES_VERSION
from phishguard.api.schemas import TextRequest, UrlRequest
from phishguard.api.service import (
    INVALID_URL_MESSAGE,
    AnalysisService,
    EmailUpload,
    InputTooLargeError,
    InvalidInputError,
)
from phishguard.deployment import load_analyzers
from phishguard.email.parser import EmailLimits
from phishguard.schema import SCHEMA_VERSION, AnalysisResponse

PHISHING_URL = "http://secure-login-verify.xyz/verify/account/123456"
LOOKALIKE_URL = "https://\u0430pple.com/login"  # « \u0430 » cyrillique


@pytest.fixture(scope="module")
def client(api_models_dir, tmp_path_factory):
    settings = settings_for(
        api_models_dir, tmp_path_factory.mktemp("api"), rate_limit_enabled=False
    )
    with api_client(settings) as client:
        yield client


def contract(response) -> AnalysisResponse:
    """La réponse respecte le contrat figé et se relit à l'identique."""
    assert response.status_code == 200, response.text
    parsed = AnalysisResponse.model_validate(response.json())
    assert parsed.schema_version == SCHEMA_VERSION
    assert AnalysisResponse.model_validate_json(parsed.to_json()) == parsed
    return parsed


# --------------------------------------------------------------------------- #
# Analyse
# --------------------------------------------------------------------------- #


def test_url_endpoint_returns_the_frozen_schema(client):
    response = contract(client.post("/v1/analyze/url", json={"url": PHISHING_URL}))
    assert response.channel == "url"
    assert response.model_version == "url_v2"
    assert response.enrichment == "skipped" and response.signals == {}
    assert response.analyst is None  # vue analyste à la demande seulement
    assert response.reasons and response.advice


def test_url_endpoint_applies_the_lookalike_hard_rule(client):
    response = contract(
        client.post("/v1/analyze/url", json={"url": LOOKALIKE_URL, "analyst": True})
    )
    assert response.verdict == "phishing" and response.score == 100
    assert [r.code for r in response.reasons] == ["hard_rule.lookalike_host"]
    assert response.analyst.normalization.host_alert == "mixed_script_label"
    assert response.mitre


@pytest.mark.parametrize("language", ["fr", "en", "ar"])
def test_text_endpoint_returns_the_frozen_schema(client, language):
    body = {"text": "urgent your account is locked verify now", "language": language}
    response = contract(client.post("/v1/analyze/text", json=body))
    assert response.channel == "sms" and response.language == language
    assert response.model_version == "text_v2"


def test_text_endpoint_channel_and_analyst_view(client):
    body = {"text": "see you at the station tonight", "channel": "messaging", "analyst": True}
    response = contract(client.post("/v1/analyze/text", json=body))
    assert response.channel == "messaging"
    assert response.analyst is not None and response.analyst.model.version == "text_v2"


@pytest.mark.parametrize("path", sorted(EMAILS.glob("*.eml"))[:4], ids=lambda p: p.name)
def test_email_endpoint_returns_the_frozen_schema(client, path):
    response = contract(
        client.post(
            "/v1/analyze/email",
            files={"file": (path.name, path.read_bytes(), "message/rfc822")},
            data={"language": "en", "analyst": "true"},
        )
    )
    assert response.channel == "email" and response.language == "en"
    assert response.model_version == EMAIL_RULES_VERSION
    assert response.analyst is not None


@pytest.mark.parametrize("media_type", ["application/octet-stream", "message/rfc822; x=1"])
def test_email_endpoint_accepts_the_usual_media_types(client, media_type):
    path = min(EMAILS.glob("*.eml"))
    contract(
        client.post("/v1/analyze/email", files={"file": (path.name, path.read_bytes(), media_type)})
    )


def test_api_answer_matches_the_pipeline(client, api_models_dir):
    """L'API ne change rien au verdict : même réponse que le pipeline appelé directement."""
    analyzers = load_analyzers(api_models_dir)
    direct = asyncio.run(analyzers.url.analyze(PHISHING_URL)).to_response("fr", analyst=False)
    via_api = contract(client.post("/v1/analyze/url", json={"url": PHISHING_URL}))
    assert via_api.model_dump(exclude={"latency_ms"}) == direct.model_dump(exclude={"latency_ms"})


@pytest.mark.parametrize(
    "url", ["ftp://example.com/file", "javascript:alert(1)", "https://", "http:///path"]
)
def test_unanalysable_url_is_a_400_that_does_not_echo_it(client, url):
    response = client.post("/v1/analyze/url", json={"url": url})
    assert response.status_code == 400
    assert response.json() == {"error": {"code": "invalid_input", "message": INVALID_URL_MESSAGE}}


def test_threat_intel_is_skipped_when_the_server_has_not_enabled_it(client):
    body = {"url": PHISHING_URL, "use_threat_intel": True}
    response = contract(client.post("/v1/analyze/url", json=body))
    assert response.enrichment == "skipped" and response.signals == {}


def test_email_parser_limit_is_the_api_limit(api_models_dir, tmp_path):
    settings = settings_for(api_models_dir, tmp_path, max_email_bytes=2048)
    with api_client(settings) as client:
        service = client.app.state.phishguard.service
        assert service.analyzers.email.limits == EmailLimits(max_bytes=2048)
        big = b"Subject: x\r\n\r\n" + b"a" * 4096
        response = client.post(
            "/v1/analyze/email", files={"file": ("big.eml", big, "message/rfc822")}
        )
    assert response.status_code == 413


# --------------------------------------------------------------------------- #
# Pool de threads
# --------------------------------------------------------------------------- #


def test_ml_runs_in_the_threadpool_not_on_the_event_loop(client):
    service = client.app.state.phishguard.service
    seen: dict[str, str] = {}
    text_analyze = service.analyzers.text.analyze
    url_score = service.analyzers.url._score_locally

    def record(name, function):
        def wrapper(*args, **kwargs):
            seen[name] = threading.current_thread().name
            try:
                asyncio.get_running_loop()
            except RuntimeError:
                pass
            else:  # pragma: no cover - serait un échec
                seen[name] = "event loop"
            return function(*args, **kwargs)

        return wrapper

    service.analyzers.text.analyze = record("text", text_analyze)
    service.analyzers.url._score_locally = record("url", url_score)
    try:
        assert client.post("/v1/analyze/text", json={"text": "hello"}).status_code == 200
        assert client.post("/v1/analyze/url", json={"url": PHISHING_URL}).status_code == 200
    finally:
        del service.analyzers.text.analyze, service.analyzers.url._score_locally
    assert seen.keys() == {"text", "url"}
    assert all(name.startswith("AnyIO worker thread") for name in seen.values()), seen


def test_service_translates_input_errors(api_models_dir):
    async def inline(function, *args, **kwargs):
        return function(*args, **kwargs)

    service = AnalysisService(
        load_analyzers(api_models_dir, email_limits=EmailLimits(max_bytes=1024)), run_sync=inline
    )
    with pytest.raises(InvalidInputError):
        asyncio.run(service.analyze_url(UrlRequest(url="ftp://example.com")))
    with pytest.raises(InputTooLargeError):
        asyncio.run(service.analyze_email(EmailUpload(b"Subject: x\r\n\r\n" + b"a" * 2048)))
    response = asyncio.run(service.analyze_text(TextRequest(text="hello", language="en")))
    assert response.language == "en"


# --------------------------------------------------------------------------- #
# GET /v1/model
# --------------------------------------------------------------------------- #


def test_model_endpoint_describes_the_served_models(client, api_models_dir):
    info = client.get("/v1/model").json()
    assert info["schema_version"] == SCHEMA_VERSION
    assert info["fusion_version"] == "1.1.0"
    url, text, email = (info["models"][k] for k in ("url", "text", "email"))
    assert url["version"] == "url_v2" and url["kind"] == "lightgbm"
    assert url["trained_at"] == "2026-11-01T00:00:00+00:00"
    assert (
        url["sha256"] == hashlib.sha256((api_models_dir / "url_v2.joblib").read_bytes()).hexdigest()
    )
    assert (
        text["sha256"]
        == hashlib.sha256((api_models_dir / "text_v2.joblib").read_bytes()).hexdigest()
    )
    assert url["calibrated"] is False and url["calibration_sha256"] is None
    assert email == {
        "version": EMAIL_RULES_VERSION,
        "kind": "rules",
        "trained_at": None,
        "sha256": None,
        "calibrated": False,
        "calibration_sha256": None,
    }


# --------------------------------------------------------------------------- #
# POST /v1/feedback
# --------------------------------------------------------------------------- #


def test_feedback_is_quarantined_with_a_server_timestamp(client):
    database = client.app.state.phishguard.database
    before = database.count_feedback()
    response = client.post(
        "/v1/feedback",
        json={"domain": "Bücher.Example", "verdict": "phishing", "judgement": "false_positive"},
    )
    assert response.status_code == 202
    assert response.json()["status"] == "quarantined"
    assert (
        response.json()["received_at"].endswith("Z") or "+00:00" in response.json()["received_at"]
    )
    assert database.count_feedback() == before + 1


def test_feedback_does_not_change_the_served_verdict(client):
    first = contract(client.post("/v1/analyze/url", json={"url": PHISHING_URL}))
    for _ in range(20):
        client.post(
            "/v1/feedback",
            json={
                "domain": "secure-login-verify.xyz",
                "verdict": first.verdict,
                "judgement": "false_positive" if first.verdict != "safe" else "false_negative",
            },
        )
    again = contract(client.post("/v1/analyze/url", json={"url": PHISHING_URL}))
    assert (again.verdict, again.score) == (first.verdict, first.score)
