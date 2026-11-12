"""Durcissement HTTP (étape 4.5) : en-têtes de sécurité sur toute réponse, CORS à liste
explicite, documentation fermée en production, délai par requête et filet d'erreurs."""

from __future__ import annotations

import asyncio
import json
import time

import pytest
from api_support import api_client, settings_for
from pydantic import ValidationError

from phishguard.api.hardening import (
    API_CSP,
    DOCS_CSP,
    SECURITY_HEADERS,
    RequestGuardMiddleware,
)
from phishguard.api.settings import ApiSettings

EXTENSION = "chrome-extension://abcdefghijklmnopabcdefghijklmnop"
SITE = "https://phishguard.example"
EVIL = "https://evil.example"


def assert_hardened(response, *, csp: str = API_CSP) -> None:
    for name, value in SECURITY_HEADERS.items():
        assert response.headers.get(name) == value, name
    assert response.headers["content-security-policy"] == csp
    assert "server" not in response.headers
    assert "x-powered-by" not in response.headers


# --------------------------------------------------------------------------- #
# En-têtes de sécurité
# --------------------------------------------------------------------------- #


def test_every_kind_of_response_carries_the_security_headers(api_models_dir, tmp_path):
    settings = settings_for(api_models_dir, tmp_path, rate_limit_anonymous="4/minute")
    with api_client(settings, raise_server_exceptions=False) as client:
        # Un compteur par route : les quatre premiers appels de /analyze/text passent.
        responses = {
            "200 santé": client.get("/v1/health"),
            "200 analyse": client.post("/v1/analyze/text", json={"text": "hello"}),
            "422": client.post("/v1/analyze/text", json={"text": ""}),
            "415": client.post("/v1/analyze/text", content=b"{}", headers={"Content-Type": "x"}),
            "413": client.post(
                "/v1/analyze/text",
                content=b"x" * (settings.max_json_bytes + 1),
                headers={"Content-Type": "application/json"},
            ),
            "429": client.post("/v1/analyze/text", json={"text": "hello"}),
            "401": client.get("/v1/model", headers={"X-API-Key": "pg_inconnue"}),
            "404": client.get("/v1/nope"),
        }
    assert responses["429"].status_code == 429
    for label, response in responses.items():
        assert str(response.status_code) == label.split()[0], label
        assert_hardened(response)


def test_an_internal_error_still_carries_the_security_headers(api_models_dir, tmp_path):
    """Le 500 de Starlette (ServerErrorMiddleware) contournerait les middlewares."""

    def broken(_text, *, channel):
        raise RuntimeError("détail interne /etc/phishguard")

    with api_client(settings_for(api_models_dir, tmp_path), raise_server_exceptions=False) as c:
        c.app.state.phishguard.service.analyzers.text.analyze = broken
        response = c.post("/v1/analyze/text", json={"text": "hello"})
    assert response.status_code == 500
    assert response.json() == {
        "error": {"code": "internal_error", "message": "Erreur interne du serveur."}
    }
    assert "interne /etc" not in response.text and "Traceback" not in response.text
    assert_hardened(response)


def test_analysis_results_are_never_cached(api_models_dir, tmp_path):
    with api_client(settings_for(api_models_dir, tmp_path)) as client:
        response = client.post("/v1/analyze/url", json={"url": "https://example.com/"})
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["content-type"] == "application/json"


def test_documentation_gets_its_own_content_policy_in_development(api_models_dir, tmp_path):
    with api_client(settings_for(api_models_dir, tmp_path)) as client:
        docs = client.get("/docs")
        schema = client.get("/openapi.json")
    assert docs.status_code == 200
    assert_hardened(docs, csp=DOCS_CSP)
    assert "frame-ancestors 'none'" in DOCS_CSP
    assert_hardened(schema)  # le schéma est du JSON : politique stricte


def test_curl_head_on_health_shows_the_headers(api_models_dir, tmp_path):
    """La vérification « curl -I » du cahier des charges."""
    with api_client(settings_for(api_models_dir, tmp_path)) as client:
        response = client.head("/v1/health")
    assert response.status_code == 200
    assert response.content == b""
    assert_hardened(response)


def test_hsts_is_sent_in_production_only(api_models_dir, tmp_path):
    with api_client(settings_for(api_models_dir, tmp_path)) as client:
        assert "strict-transport-security" not in client.get("/v1/health").headers
    production = settings_for(api_models_dir, tmp_path, environment="production")
    with api_client(production) as client:
        response = client.get("/v1/health")
    assert response.headers["strict-transport-security"] == "max-age=31536000"


# --------------------------------------------------------------------------- #
# Production : pas de route de débogage
# --------------------------------------------------------------------------- #


def test_production_serves_no_documentation_or_debug_page(api_models_dir, tmp_path):
    settings = settings_for(api_models_dir, tmp_path, environment="production")
    assert settings.docs_active is False
    with api_client(settings, raise_server_exceptions=False) as client:
        assert client.app.debug is False
        for path in ("/docs", "/docs/oauth2-redirect", "/redoc", "/openapi.json"):
            response = client.get(path)
            assert response.status_code == 404, path
            assert response.json()["error"]["code"] == "not_found"
        assert client.get("/v1/health").status_code == 200


def test_documentation_cannot_be_forced_on_in_production(tmp_path):
    with pytest.raises(ValidationError, match="documentation"):
        ApiSettings(_env_file=None, environment="production", docs_enabled=True)


def test_development_keeps_the_documentation_unless_disabled():
    assert ApiSettings(_env_file=None).docs_active is True
    assert ApiSettings(_env_file=None, docs_enabled=False).docs_active is False


def test_unknown_environment_prevents_startup():
    with pytest.raises(ValidationError):
        ApiSettings(_env_file=None, environment="staging")


# --------------------------------------------------------------------------- #
# CORS
# --------------------------------------------------------------------------- #


def preflight(client, origin: str, headers: str = "content-type,x-api-key"):
    return client.options(
        "/v1/analyze/url",
        headers={
            "Origin": origin,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": headers,
        },
    )


def test_without_configured_origins_no_cors_header_is_ever_sent(api_models_dir, tmp_path):
    with api_client(settings_for(api_models_dir, tmp_path)) as client:
        response = client.post(
            "/v1/analyze/url", json={"url": "https://example.com/"}, headers={"Origin": EVIL}
        )
        assert response.status_code == 200
        assert "access-control-allow-origin" not in response.headers
        refused = preflight(client, EVIL)
    assert refused.status_code == 405  # aucune pré-vérification acceptée
    assert "access-control-allow-origin" not in refused.headers


@pytest.fixture
def cors_client(api_models_dir, tmp_path):
    settings = settings_for(
        api_models_dir,
        tmp_path,
        cors_allowed_origins=f"{EXTENSION},{SITE}",
        rate_limit_anonymous="2/minute",
    )
    with api_client(settings) as client:
        yield client


def test_preflight_from_an_allowed_origin(cors_client):
    response = preflight(cors_client, EXTENSION)
    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == EXTENSION  # jamais « * »
    assert "access-control-allow-credentials" not in response.headers
    allowed = response.headers["access-control-allow-headers"].lower()
    assert "x-api-key" in allowed and "content-type" in allowed
    assert set(response.headers["access-control-allow-methods"].split(", ")) == {"GET", "POST"}
    assert response.headers["access-control-max-age"] == "600"
    assert_hardened(response)


def test_preflight_from_another_origin_is_refused(cors_client):
    for origin in (EVIL, "null", f"{SITE}.evil.example", "http://phishguard.example"):
        response = preflight(cors_client, origin)
        assert response.status_code == 400, origin
        assert "access-control-allow-origin" not in response.headers


def test_preflight_refuses_unexpected_request_headers(cors_client):
    response = preflight(cors_client, SITE, headers="content-type,x-admin")
    assert response.status_code == 400


def test_actual_request_exposes_the_rate_limit_headers(cors_client):
    response = cors_client.post(
        "/v1/analyze/url", json={"url": "https://example.com/"}, headers={"Origin": SITE}
    )
    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == SITE
    assert "origin" in response.headers["vary"].lower()
    exposed = response.headers["access-control-expose-headers"].lower()
    assert {"retry-after", "x-ratelimit-remaining"} <= set(exposed.split(", "))


def test_a_rate_limited_browser_client_can_read_why(cors_client):
    """Le 429 porte les en-têtes CORS : l'extension peut lire ``Retry-After``."""
    for _ in range(2):
        assert cors_client.get("/v1/model", headers={"Origin": SITE}).status_code == 200
    response = cors_client.get("/v1/model", headers={"Origin": SITE})
    assert response.status_code == 429
    assert response.headers["access-control-allow-origin"] == SITE
    assert "retry-after" in response.headers


def test_a_disallowed_origin_gets_no_cors_header_on_actual_requests(cors_client):
    response = cors_client.post(
        "/v1/analyze/url", json={"url": "https://example.com/"}, headers={"Origin": EVIL}
    )
    assert "access-control-allow-origin" not in response.headers


@pytest.mark.parametrize(
    "origin",
    [
        "*",
        "null",
        "https://*.example.com",
        "https://phishguard.example/",
        "https://phishguard.example/api",
        "https://phishguard.example?x=1",
        "https://user@phishguard.example",
        "ftp://phishguard.example",
        "javascript://phishguard.example",
        "phishguard.example",
        "",
    ],
)
def test_invalid_cors_origins_prevent_startup(origin):
    with pytest.raises(ValidationError):
        ApiSettings(_env_file=None, cors_allowed_origins=[origin] if origin else [""])


def test_cors_origins_from_the_environment(monkeypatch):
    monkeypatch.setenv(
        "PHISHGUARD_API_CORS_ALLOWED_ORIGINS", f" {EXTENSION} ,{SITE},{SITE},http://localhost:5173"
    )
    settings = ApiSettings(_env_file=None)
    assert settings.cors_allowed_origins == (EXTENSION, SITE, "http://localhost:5173")
    monkeypatch.setenv("PHISHGUARD_API_CORS_ALLOWED_ORIGINS", json.dumps([SITE]))
    assert ApiSettings(_env_file=None).cors_allowed_origins == (SITE,)


def test_production_refuses_plain_http_origins_except_loopback():
    with pytest.raises(ValidationError, match="http"):
        ApiSettings(
            _env_file=None, environment="production", cors_allowed_origins=["http://site.example"]
        )
    settings = ApiSettings(
        _env_file=None,
        environment="production",
        cors_allowed_origins=["http://localhost:5173", "http://127.0.0.1", EXTENSION],
    )
    assert len(settings.cors_allowed_origins) == 3


# --------------------------------------------------------------------------- #
# Délai par requête et filet d'erreurs (middleware seul, en ASGI)
# --------------------------------------------------------------------------- #


def run_asgi(app, *, body_chunks=(b"",), delay=0.0, headers=None):
    """Exécute une requête ASGI ; renvoie les messages envoyés par l'application."""
    sent: list[dict] = []
    chunks = list(body_chunks)

    async def receive():
        if delay:
            await asyncio.sleep(delay)
        if chunks:
            chunk = chunks.pop(0)
            return {"type": "http.request", "body": chunk, "more_body": bool(chunks)}
        await asyncio.sleep(3600)  # le client ne dit plus rien
        return {"type": "http.disconnect"}

    async def send(message):
        sent.append(message)

    scope = {
        "type": "http",
        "method": "POST",
        "path": "/v1/analyze/text",
        "headers": headers or [(b"content-length", b"3")],
    }
    asyncio.run(app(scope, receive, send))
    return sent


def status_and_body(sent) -> tuple[int, dict]:
    start = next(m for m in sent if m["type"] == "http.response.start")
    body = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
    return start["status"], json.loads(body)


async def read_whole_body(scope, receive, send):
    while (await receive()).get("more_body", False):
        pass
    await send({"type": "http.response.start", "status": 200, "headers": []})
    await send({"type": "http.response.body", "body": b"{}"})


def test_a_client_sending_its_body_too_slowly_gets_408():
    guard = RequestGuardMiddleware(read_whole_body, timeout_seconds=0.05)
    sent = run_asgi(guard, body_chunks=(b"a", b"b", b"c"), delay=0.03)
    status, body = status_and_body(sent)
    assert status == 408
    assert body["error"]["code"] == "request_timeout"


def test_a_slow_treatment_gets_503_with_retry_after():
    async def slow(scope, receive, send):
        await receive()
        await asyncio.sleep(1)

    sent = run_asgi(RequestGuardMiddleware(slow, timeout_seconds=0.05))
    status, body = status_and_body(sent)
    assert status == 503
    assert body["error"]["code"] == "timeout"
    start = sent[0]
    assert (b"retry-after", b"5") in start["headers"]


def test_a_fast_request_passes_through_untouched():
    sent = run_asgi(RequestGuardMiddleware(read_whole_body, timeout_seconds=1))
    assert status_and_body(sent) == (200, {})


def test_unexpected_exception_becomes_an_empty_500():
    async def broken(scope, receive, send):
        raise RuntimeError("chemin secret /srv/phishguard")

    sent = run_asgi(RequestGuardMiddleware(broken, timeout_seconds=1))
    status, body = status_and_body(sent)
    assert status == 500
    assert body == {"error": {"code": "internal_error", "message": "Erreur interne du serveur."}}


def test_an_error_after_the_response_started_sends_nothing_more():
    async def half(scope, receive, send):
        await send({"type": "http.response.start", "status": 200, "headers": []})
        raise RuntimeError("trop tard")

    sent = run_asgi(RequestGuardMiddleware(half, timeout_seconds=1))
    assert [m["type"] for m in sent] == ["http.response.start"]


def test_slow_analysis_through_the_api_times_out(api_models_dir, tmp_path):
    settings = settings_for(api_models_dir, tmp_path, request_timeout_seconds=0.05)
    with api_client(settings) as client:
        analyzer = client.app.state.phishguard.service.analyzers.text
        original = analyzer.analyze

        def slow(text, *, channel):
            time.sleep(0.3)  # dans le pool de threads : non interruptible
            return original(text, channel=channel)

        analyzer.analyze = slow
        response = client.post("/v1/analyze/text", json={"text": "hello"})
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "timeout"
    assert_hardened(response)


def test_timeout_settings_are_bounded():
    for value in (0, -1, 3600):
        with pytest.raises(ValidationError):
            ApiSettings(_env_file=None, request_timeout_seconds=value)


# --------------------------------------------------------------------------- #
# Lanceur
# --------------------------------------------------------------------------- #


def test_launcher_bounds_connections(monkeypatch):
    import uvicorn

    from phishguard.api import __main__ as launcher

    calls = []
    monkeypatch.setattr(uvicorn, "run", lambda *args, **kwargs: calls.append(kwargs))
    launcher.main([])
    (kwargs,) = calls
    assert kwargs["limit_concurrency"] == 100
    assert kwargs["timeout_keep_alive"] == 5
    assert kwargs["h11_max_incomplete_event_size"] == 16 * 1024
