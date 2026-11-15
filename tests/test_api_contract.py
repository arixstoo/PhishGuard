"""Matrice de contrat de l'API (étape 4.7) : un test par endpoint et par cas d'erreur.

Chaque ligne de :data:`CASES` est une requête et la réponse attendue (statut, ``code``
d'erreur). Pour **chaque** réponse, quelle qu'elle soit, la matrice vérifie aussi les
invariants transverses : enveloppe d'erreur commune, en-têtes de sécurité (étape 4.5),
identifiant de requête (étape 4.6), aucune recopie de l'entrée.

:func:`test_every_documented_status_is_exercised` relie la matrice au schéma OpenAPI :
un statut documenté pour une route sans ligne qui le provoque fait échouer la suite.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field
from typing import Any

import pytest
from api_support import EMAILS, api_client, settings_for

from phishguard.api.hardening import SECURITY_HEADERS
from phishguard.schema import AnalysisResponse

SENTINEL = "zq-sentinelle-9431"  # recopiée dans des entrées fautives : jamais renvoyée
JSON = {"Content-Type": "application/json"}
EML = (EMAILS / "02_phish_link_mismatch.eml").read_bytes()
MAX_EMAIL = 4096
BAD_KEY = {"X-API-Key": "pg_" + "A" * 43}
FEEDBACK = {"domain": "paypal-secure.example", "verdict": "phishing", "judgement": "false_positive"}


@dataclass(frozen=True)
class Case:
    id: str
    method: str
    path: str
    status: int
    code: str | None = None
    json: Any = None
    content: bytes | None = None
    files: dict | None = None
    headers: dict = field(default_factory=dict)


def _big_json(field_name: str) -> bytes:
    return json.dumps({field_name: "a" * 70_000}).encode()


CASES = [
    # --- GET /v1/health ----------------------------------------------------- #
    Case("health-ok", "GET", "/v1/health", 200),
    Case("health-head", "HEAD", "/v1/health", 200),
    Case("health-bad-key-ignored", "GET", "/v1/health", 200, headers=BAD_KEY),
    Case("health-post", "POST", "/v1/health", 405, "method_not_allowed"),
    # --- GET /v1/model ------------------------------------------------------ #
    Case("model-ok", "GET", "/v1/model", 200),
    Case("model-bad-key", "GET", "/v1/model", 401, "invalid_api_key", headers=BAD_KEY),
    Case("model-post", "POST", "/v1/model", 405, "method_not_allowed"),
    # --- POST /v1/analyze/url ----------------------------------------------- #
    Case("url-ok", "POST", "/v1/analyze/url", 200, json={"url": "https://example.com/"}),
    Case("url-ftp", "POST", "/v1/analyze/url", 400, "invalid_input",
         json={"url": f"ftp://{SENTINEL}.example/"}),
    Case("url-bad-key", "POST", "/v1/analyze/url", 401, "invalid_api_key",
         json={"url": "https://example.com/"}, headers=BAD_KEY),
    Case("url-get", "GET", "/v1/analyze/url", 405, "method_not_allowed"),
    Case("url-body-too-big", "POST", "/v1/analyze/url", 413, "payload_too_large",
         content=_big_json("url"), headers=JSON),
    Case("url-text-plain", "POST", "/v1/analyze/url", 415, "unsupported_media_type",
         content=b'{"url": "https://example.com/"}', headers={"Content-Type": "text/plain"}),
    Case("url-missing", "POST", "/v1/analyze/url", 422, "validation_error", json={}),
    Case("url-too-long", "POST", "/v1/analyze/url", 422, "validation_error",
         json={"url": f"https://{SENTINEL}.example/" + "a" * 3000}),
    Case("url-control-char", "POST", "/v1/analyze/url", 422, "validation_error",
         json={"url": f"https://{SENTINEL}.example/\x00"}),
    Case("url-wrong-type", "POST", "/v1/analyze/url", 422, "validation_error", json={"url": 42}),
    Case("url-unknown-field", "POST", "/v1/analyze/url", 422, "validation_error",
         json={"url": "https://example.com/", SENTINEL: True}),
    Case("url-malformed-json", "POST", "/v1/analyze/url", 422, "validation_error",
         content=b'{"url": ', headers=JSON),
    # --- POST /v1/analyze/text ---------------------------------------------- #
    Case("text-ok", "POST", "/v1/analyze/text", 200, json={"text": "see you tonight"}),
    Case("text-bad-key", "POST", "/v1/analyze/text", 401, "invalid_api_key",
         json={"text": "x"}, headers=BAD_KEY),
    Case("text-get", "GET", "/v1/analyze/text", 405, "method_not_allowed"),
    Case("text-body-too-big", "POST", "/v1/analyze/text", 413, "payload_too_large",
         content=_big_json("text"), headers=JSON),
    Case("text-no-content-type", "POST", "/v1/analyze/text", 415, "unsupported_media_type",
         content=b'{"text": "x"}'),
    Case("text-empty", "POST", "/v1/analyze/text", 422, "validation_error", json={"text": ""}),
    Case("text-blank", "POST", "/v1/analyze/text", 422, "validation_error", json={"text": " \n"}),
    Case("text-too-long", "POST", "/v1/analyze/text", 422, "validation_error",
         json={"text": SENTINEL * 400}),
    Case("text-nul", "POST", "/v1/analyze/text", 422, "validation_error",
         json={"text": f"{SENTINEL}\x00"}),
    Case("text-surrogate", "POST", "/v1/analyze/text", 422, "validation_error",
         content=b'{"text": "\\ud800"}', headers=JSON),
    Case("text-bad-language", "POST", "/v1/analyze/text", 422, "validation_error",
         json={"text": "x", "language": "klingon"}),
    # --- POST /v1/analyze/email --------------------------------------------- #
    Case("email-ok", "POST", "/v1/analyze/email", 200,
         files={"file": ("m.eml", EML, "message/rfc822")}),
    Case("email-bad-key", "POST", "/v1/analyze/email", 401, "invalid_api_key",
         files={"file": ("m.eml", EML, "message/rfc822")}, headers=BAD_KEY),
    Case("email-get", "GET", "/v1/analyze/email", 405, "method_not_allowed"),
    Case("email-too-big", "POST", "/v1/analyze/email", 413, "payload_too_large",
         files={"file": ("m.eml", EML + b"x" * MAX_EMAIL, "message/rfc822")}),
    Case("email-pdf", "POST", "/v1/analyze/email", 415, "unsupported_media_type",
         files={"file": ("m.pdf", EML, "application/pdf")}),
    Case("email-empty", "POST", "/v1/analyze/email", 422, "validation_error",
         files={"file": ("m.eml", b"  \r\n", "message/rfc822")}),
    Case("email-missing-file", "POST", "/v1/analyze/email", 422, "validation_error",
         files={"other": ("m.eml", EML, "message/rfc822")}),
    # --- POST /v1/feedback -------------------------------------------------- #
    Case("feedback-ok", "POST", "/v1/feedback", 202, json=FEEDBACK),
    Case("feedback-bad-key", "POST", "/v1/feedback", 401, "invalid_api_key",
         json=FEEDBACK, headers=BAD_KEY),
    Case("feedback-get", "GET", "/v1/feedback", 405, "method_not_allowed"),
    Case("feedback-body-too-big", "POST", "/v1/feedback", 413, "payload_too_large",
         content=_big_json("domain"), headers=JSON),
    Case("feedback-text-plain", "POST", "/v1/feedback", 415, "unsupported_media_type",
         content=b"{}", headers={"Content-Type": "text/plain"}),
    Case("feedback-url-not-domain", "POST", "/v1/feedback", 422, "validation_error",
         json={**FEEDBACK, "domain": f"https://{SENTINEL}.example/reset?t=1"}),
    Case("feedback-ip", "POST", "/v1/feedback", 422, "validation_error",
         json={**FEEDBACK, "domain": "192.0.2.1"}),
    Case("feedback-incoherent", "POST", "/v1/feedback", 422, "validation_error",
         json={**FEEDBACK, "verdict": "safe"}),
    Case("feedback-timestamp", "POST", "/v1/feedback", 422, "validation_error",
         json={**FEEDBACK, "received_at": "2020-01-01T00:00:00Z"}),
    # --- Ailleurs ----------------------------------------------------------- #
    Case("unknown-route", "GET", f"/v1/{SENTINEL}", 404, "not_found"),
    Case("root", "GET", "/", 404, "not_found"),
    Case("trace", "TRACE", "/v1/analyze/url", 405, "method_not_allowed"),
]  # fmt: skip


@pytest.fixture(scope="module")
def client(api_models_dir, tmp_path_factory):
    settings = settings_for(
        api_models_dir,
        tmp_path_factory.mktemp("contract"),
        rate_limit_enabled=False,
        max_email_bytes=MAX_EMAIL,
    )
    with api_client(settings) as test_client:
        yield test_client


def send(client, case: Case):
    return client.request(
        case.method,
        case.path,
        json=case.json,
        content=case.content,
        files=case.files,
        headers=case.headers,
    )


@pytest.mark.parametrize("case", CASES, ids=lambda c: c.id)
def test_endpoint_contract(client, case):
    response = send(client, case)
    assert response.status_code == case.status, response.text[:300]

    # Invariants de toute réponse.
    for name, value in SECURITY_HEADERS.items():
        assert response.headers.get(name) == value, name
    assert len(response.headers["x-request-id"]) == 32
    assert SENTINEL not in response.text  # l'entrée n'est jamais réfléchie
    if case.id == "url-unknown-field":  # nom choisi par le client : remplacé
        assert response.json()["error"]["details"][0]["loc"] == ["body", "<champ inconnu>"]
    if case.method == "HEAD":
        assert response.content == b""
        return
    assert response.headers["content-type"] == "application/json"
    body = response.json()

    if case.code is None:
        assert "error" not in body
        if case.path.startswith("/v1/analyze/"):
            AnalysisResponse.model_validate(body)
        return
    assert set(body) == {"error"}
    assert body["error"]["code"] == case.code
    assert isinstance(body["error"]["message"], str) and body["error"]["message"]
    for detail in body["error"].get("details", []):
        assert set(detail) == {"loc", "type", "msg"}  # jamais « input » ni « ctx »
    if case.status == 401:
        assert response.headers["www-authenticate"] == "X-API-Key"
    if case.status == 405:
        assert "allow" in response.headers


def test_every_documented_status_is_exercised(client):
    """Le schéma OpenAPI ne promet aucune réponse que la matrice ne provoque pas."""
    exercised = {(c.method.lower(), c.path, str(c.status)) for c in CASES}
    paths = client.get("/openapi.json").json()["paths"]
    missing = [
        (method, path, status)
        for path, operations in paths.items()
        for method, operation in operations.items()
        for status in operation["responses"]
        if status != "429"  # limite de débit : test_every_route_is_rate_limited
        and (method, path, status) not in exercised
    ]
    assert missing == []


# Toutes les routes, sauf la santé : sans limite (sondes de l'orchestrateur).
ROUTES = sorted(
    {(c.method, c.path) for c in CASES if c.status in {200, 202} and c.path != "/v1/health"}
)


@pytest.mark.parametrize(("method", "path"), ROUTES, ids=lambda v: str(v))
def test_every_route_is_rate_limited(api_models_dir, tmp_path, method, path):
    case = next(c for c in CASES if (c.method, c.path) == (method, path) and c.status < 300)
    settings = settings_for(
        api_models_dir, tmp_path, rate_limit_anonymous="1/minute", max_email_bytes=MAX_EMAIL
    )
    with api_client(settings) as fresh:
        assert send(fresh, case).status_code == case.status
        limited = send(fresh, case)
    assert limited.status_code == 429
    assert limited.json()["error"]["code"] == "rate_limited"
    assert int(limited.headers["retry-after"]) >= 1


def test_key_database_outage_gives_503_not_anonymous_access(api_models_dir, tmp_path):
    with api_client(settings_for(api_models_dir, tmp_path)) as c:
        database = c.app.state.phishguard.database

        def broken(_key):
            raise sqlite3.OperationalError("disk I/O error")

        database.verify_key = broken
        response = c.get("/v1/model", headers=BAD_KEY)
        anonymous = c.get("/v1/model")
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "service_unavailable"
    assert anonymous.status_code == 200  # sans clé, la base n'est pas consultée


def test_email_too_large_for_the_parser_is_413(api_models_dir, tmp_path):
    """Borne de l'analyseur (``EmailTooLargeError``), distincte de la lecture bornée."""
    from phishguard.email.parser import EmailTooLargeError

    with api_client(settings_for(api_models_dir, tmp_path)) as c:

        def too_large(_raw):
            raise EmailTooLargeError("x")

        c.app.state.phishguard.service.analyzers.email.analyze = too_large
        response = c.post("/v1/analyze/email", files={"file": ("m.eml", EML, "message/rfc822")})
    assert response.status_code == 413
    assert response.json()["error"]["code"] == "payload_too_large"
