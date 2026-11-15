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


def test_health_answers(api_models_dir, tmp_path):
    with api_client(settings_for(api_models_dir, tmp_path)) as client:
        for _ in range(5):
            response = client.get("/v1/health")
            assert response.status_code == 200
            assert response.json() == {"status": "ok"}


def test_interactive_documentation_lists_the_routes(api_models_dir, tmp_path):
    with api_client(settings_for(api_models_dir, tmp_path)) as client:
        assert client.get("/docs").status_code == 200
        paths = client.get("/openapi.json").json()["paths"]
    assert "/v1/health" in paths


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
        for _ in range(3):
            assert client.get("/v1/health").status_code == 200
        analyzers = client.app.state.phishguard.analyzers
        assert analyzers.url.model_version == "url_v2"
        assert analyzers.text.model_version == "text_v2"
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
        response = client.post("/v1/health")
        assert response.status_code == 405
        assert response.json()["error"]["code"] == "method_not_allowed"


def test_internal_errors_reveal_nothing(api_models_dir, tmp_path):
    app = create_app(settings_for(api_models_dir, tmp_path))

    @app.get("/v1/_broken")
    async def broken() -> None:
        raise RuntimeError("secret interne /etc/phishguard")

    with TestClient(app, raise_server_exceptions=False) as client:
        response = client.get("/v1/_broken")
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
    monkeypatch.setenv("PHISHGUARD_API_DOCS_ENABLED", "false")
    settings = ApiSettings(_env_file=None)
    assert settings.models_dir == tmp_path
    assert settings.docs_enabled is False


def test_secure_defaults():
    settings = ApiSettings(_env_file=None)
    assert settings.threat_intel_enabled is False  # rien n'est envoyé à des tiers


@pytest.mark.parametrize("field, value", [("docs_enabled", "peut-être"), ("models_dir", 3.5)])
def test_invalid_settings_prevent_startup(field, value):
    with pytest.raises((ValidationError, ValueError)):
        ApiSettings(_env_file=None, **{field: value})


def test_launcher_disables_uvicorn_proxy_headers(monkeypatch):
    """L'IP du client n'est jamais réécrite par uvicorn d'après X-Forwarded-For."""
    import uvicorn

    from phishguard.api import __main__ as launcher

    calls = []
    monkeypatch.setattr(uvicorn, "run", lambda *args, **kwargs: calls.append((args, kwargs)))
    launcher.main([])
    ((args, kwargs),) = calls
    assert args == ("phishguard.api.main:app",)
    assert kwargs["host"] == "127.0.0.1"  # exposer l'API est un choix explicite
    assert kwargs["proxy_headers"] is False and kwargs["server_header"] is False
