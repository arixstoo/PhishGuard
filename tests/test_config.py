"""Tests du chargement des clés d'API (étape 2.1)."""

from pathlib import Path

import pytest

from phishguard.config import KEYED_SOURCES, Settings, get_settings

ROOT = Path(__file__).resolve().parents[1]
FAKE_KEY = "test-key-not-a-real-secret"


@pytest.fixture(autouse=True)
def isolated_env(monkeypatch, tmp_path):
    """Ni l'environnement du développeur ni son .env ne doivent fuiter dans les tests."""
    for field in KEYED_SOURCES.values():
        monkeypatch.delenv(field.upper(), raising=False)
    monkeypatch.chdir(tmp_path)
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def test_starts_without_any_key():
    settings = Settings()
    assert settings.enabled_sources() == frozenset()
    assert all(settings.api_key(source) is None for source in KEYED_SOURCES)


def test_keys_from_environment_enable_their_source(monkeypatch):
    monkeypatch.setenv("VT_API_KEY", FAKE_KEY)
    monkeypatch.setenv("GSB_API_KEY", "other-key")
    settings = Settings()
    assert settings.enabled_sources() == {"virustotal", "google_safe_browsing"}
    assert settings.api_key("virustotal") == FAKE_KEY
    assert not settings.is_enabled("urlscan")


def test_keys_from_dotenv_file(tmp_path):
    (tmp_path / ".env").write_text(f"URLSCAN_API_KEY={FAKE_KEY}\nURLHAUS_AUTH_KEY=x\n")
    settings = Settings()
    assert settings.enabled_sources() == {"urlscan"}
    assert settings.api_key("urlscan") == FAKE_KEY


def test_environment_overrides_dotenv(monkeypatch, tmp_path):
    (tmp_path / ".env").write_text("VT_API_KEY=from-file\n")
    monkeypatch.setenv("VT_API_KEY", "from-env")
    assert Settings().api_key("virustotal") == "from-env"


@pytest.mark.parametrize("value", ["", "   ", "\t"])
def test_blank_key_keeps_the_source_disabled(monkeypatch, value):
    monkeypatch.setenv("VT_API_KEY", value)
    assert not Settings().is_enabled("virustotal")


def test_surrounding_whitespace_is_stripped(monkeypatch):
    monkeypatch.setenv("VT_API_KEY", f"  {FAKE_KEY}\n")
    assert Settings().api_key("virustotal") == FAKE_KEY


def test_copy_of_env_example_enables_nothing(tmp_path):
    (tmp_path / ".env").write_text((ROOT / ".env.example").read_text(encoding="utf-8"))
    assert Settings().enabled_sources() == frozenset()


def test_env_example_documents_every_key():
    lines = (ROOT / ".env.example").read_text(encoding="utf-8").splitlines()
    declared = {line.split("=", 1)[0] for line in lines if "=" in line and line[0] != "#"}
    assert {field.upper() for field in KEYED_SOURCES.values()} <= declared
    # Aucune valeur pré-remplie : le fichier modèle ne doit jamais porter de secret.
    assert all(line.split("=", 1)[1] == "" for line in lines if "=" in line and line[0] != "#")


def test_key_never_appears_in_repr_or_dump(monkeypatch):
    monkeypatch.setenv("VT_API_KEY", FAKE_KEY)
    settings = Settings()
    assert FAKE_KEY not in repr(settings)
    assert FAKE_KEY not in str(settings)
    assert FAKE_KEY not in settings.model_dump_json()


def test_unknown_source_is_rejected():
    with pytest.raises(ValueError, match="source inconnue"):
        Settings().api_key("shodan")


def test_settings_are_read_once_and_frozen(monkeypatch):
    first = get_settings()
    monkeypatch.setenv("VT_API_KEY", FAKE_KEY)
    assert get_settings() is first and not first.is_enabled("virustotal")
    get_settings.cache_clear()
    assert get_settings().is_enabled("virustotal")
    with pytest.raises(ValueError):
        first.vt_api_key = None


def test_cli_lists_sources_without_printing_keys(monkeypatch, capsys):
    from phishguard.config import main

    monkeypatch.setenv("VT_API_KEY", FAKE_KEY)
    main()
    out = capsys.readouterr().out
    assert FAKE_KEY not in out
    assert "virustotal" in out and "activée" in out
    assert "désactivée" in out
