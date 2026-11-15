"""Squelette de l'API (étape 4.1) : santé, documentation, chargement unique des modèles,
configuration."""

from __future__ import annotations

import pytest
from api_support import api_client, settings_for
from fastapi.testclient import TestClient
from pydantic import ValidationError

from phishguard.api import main
from phishguard.api.main import create_app
from phishguard.api.settings import ApiSettings
from phishguard.deployment import load_analyzers


def test_health_answers_without_key_or_rate_limit(api_models_dir, tmp_path):
    settings = settings_for(api_models_dir, tmp_path, rate_limit_anonymous="2/minute")
    with api_client(settings) as client:
        for _ in range(5):  # au-delà de la limite : la santé n'est jamais limitée
            response = client.get("/v1/health")
            assert response.status_code == 200
            assert response.json() == {"status": "ok"}
        # Une clé invalide ne gêne pas la sonde : la route est hors authentification.
        assert client.get("/v1/health", headers={"X-API-Key": "nope"}).status_code == 200


def test_interactive_documentation_lists_the_routes(api_models_dir, tmp_path):
    with api_client(settings_for(api_models_dir, tmp_path)) as client:
        assert client.get("/docs").status_code == 200
        paths = client.get("/openapi.json").json()["paths"]
    assert {
        "/v1/health",
        "/v1/model",
        "/v1/feedback",
        "/v1/analyze/url",
        "/v1/analyze/text",
        "/v1/analyze/email",
    } <= set(paths)


def test_documentation_can_be_disabled(api_models_dir, tmp_path):
    with api_client(settings_for(api_models_dir, tmp_path, docs_enabled=False)) as client:
        for path in ("/docs", "/redoc", "/openapi.json"):
            assert client.get(path).status_code == 404
        assert client.get("/v1/health").status_code == 200


def test_models_are_loaded_once_at_startup(api_models_dir, tmp_path):
    calls = []

    def factory(settings, orchestrator):
        calls.append(orchestrator)
        return load_analyzers(settings.models_dir)

    app = create_app(settings_for(api_models_dir, tmp_path), analyzers_factory=factory)
    assert calls == []  # rien n'est chargé à la construction de l'application
    with TestClient(app) as client:
        for text in ("hello", "see you tonight", "win a prize now"):
            assert client.post("/v1/analyze/text", json={"text": text}).status_code == 200
    assert calls == [None]  # une seule fois, sans Threat Intelligence par défaut


def test_startup_fails_when_a_deployed_model_is_missing(tmp_path):
    app = create_app(settings_for(tmp_path / "empty", tmp_path))
    with pytest.raises(FileNotFoundError, match="url_v2"), TestClient(app):
        pass


def test_importing_the_module_does_not_build_the_app():
    assert "app" not in vars(main)
    assert callable(main.create_app)


def test_unknown_route_uses_the_error_envelope(api_models_dir, tmp_path):
    with api_client(settings_for(api_models_dir, tmp_path)) as client:
        response = client.get("/v1/nope")
        assert response.status_code == 404
        assert response.json() == {"error": {"code": "not_found", "message": "Not Found"}}
        response = client.get("/v1/analyze/url")
        assert response.status_code == 405
        assert response.json()["error"]["code"] == "method_not_allowed"


def test_internal_errors_reveal_nothing(api_models_dir, tmp_path):
    def broken(_text, *, channel):
        raise RuntimeError("secret interne /etc/phishguard")

    with api_client(settings_for(api_models_dir, tmp_path), raise_server_exceptions=False) as c:
        c.app.state.phishguard.service.analyzers.text.analyze = broken
        response = c.post("/v1/analyze/text", json={"text": "hello"})
    assert response.status_code == 500
    assert response.json() == {
        "error": {"code": "internal_error", "message": "Erreur interne du serveur."}
    }
    assert "secret" not in response.text and "Traceback" not in response.text


# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #


def test_settings_are_read_from_prefixed_environment(monkeypatch, tmp_path):
    monkeypatch.setenv("PHISHGUARD_API_MODELS_DIR", str(tmp_path))
    monkeypatch.setenv("PHISHGUARD_API_TRUSTED_PROXIES", "10.0.0.0/8, 127.0.0.1,::1")
    monkeypatch.setenv("PHISHGUARD_API_RATE_LIMIT_ANONYMOUS", "5/second;100/hour")
    settings = ApiSettings(_env_file=None)
    assert settings.models_dir == tmp_path
    assert [str(n) for n in settings.trusted_proxies] == ["10.0.0.0/8", "127.0.0.1/32", "::1/128"]
    assert settings.rate_limit_anonymous == "5/second;100/hour"


def test_secure_defaults():
    settings = ApiSettings(_env_file=None)
    assert settings.trusted_proxies == ()  # X-Forwarded-For ignoré
    assert settings.threat_intel_enabled is False  # rien n'est envoyé à des tiers
    assert settings.rate_limit_enabled is True
    assert settings.max_email_bytes == 1024 * 1024


@pytest.mark.parametrize(
    "field, value",
    [
        ("rate_limit_anonymous", "beaucoup"),
        ("rate_limit_authenticated", ""),
        ("trusted_proxies", "10.0.0.1/8"),  # bits d'hôte : faute de frappe probable
        ("trusted_proxies", "pas-une-ip"),
        ("max_email_bytes", 100 * 1024 * 1024),
    ],
)
def test_invalid_settings_prevent_startup(field, value):
    with pytest.raises((ValidationError, ValueError)):
        ApiSettings(_env_file=None, **{field: value})


def test_launcher_disables_uvicorn_proxy_headers(monkeypatch):
    """L'IP du client n'est réécrite que par l'API, d'après les proxys déclarés."""
    import uvicorn

    from phishguard.api import __main__ as launcher

    calls = []
    monkeypatch.setattr(uvicorn, "run", lambda *args, **kwargs: calls.append((args, kwargs)))
    launcher.main([])
    ((args, kwargs),) = calls
    assert args == ("phishguard.api.main:app",)
    assert kwargs["host"] == "127.0.0.1"  # exposer l'API est un choix explicite
    assert kwargs["proxy_headers"] is False and kwargs["server_header"] is False
