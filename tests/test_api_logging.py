"""Journalisation sans données personnelles (étape 4.6).

Le test central : une URL qui contient un jeton secret est analysée, et ce jeton
n'apparaît dans **aucune** ligne du journal, à aucun niveau (DEBUG compris), ni dans
celles de PhishGuard, ni dans celles des bibliothèques. Les autres tests étendent la
règle au texte, aux emails, aux clés d'API, aux erreurs et aux chemins inconnus.
"""

from __future__ import annotations

import io
import json
import logging
import re
import secrets

import pytest
from api_support import EMAILS, api_client, settings_for

from phishguard.api import logs
from phishguard.api.logs import (
    REDACTED,
    annotate,
    configure_logging,
    describe_exception,
    scrub,
)
from phishguard.api.settings import ApiSettings

# Sentinelle tirée à chaque exécution : ne doit jamais être écrite dans le journal.
SECRET = "tok_" + secrets.token_hex(16)
SECRET_HOST = "secret-reset-portal.example"
SECRET_URL = f"https://user:{SECRET}@{SECRET_HOST}/reset/{SECRET}?token={SECRET}#{SECRET}"


@pytest.fixture
def log_stream():
    """Journal JSON de l'API au niveau DEBUG, dans un tampon."""
    stream = io.StringIO()
    configure_logging(
        ApiSettings(_env_file=None, log_level="DEBUG", log_format="json"), stream=stream
    )
    return stream


def lines(stream: io.StringIO) -> list[dict]:
    return [json.loads(line) for line in stream.getvalue().splitlines() if line.strip()]


def request_lines(stream: io.StringIO) -> list[dict]:
    return [line for line in lines(stream) if line["event"] == "request"]


def assert_never_logged(stream: io.StringIO, *needles: str) -> None:
    output = stream.getvalue()
    assert output, "aucun journal écrit : le test ne prouverait rien"
    for needle in needles:
        assert needle not in output, f"{needle!r} écrit dans le journal"


# --------------------------------------------------------------------------- #
# Le test du cahier des charges
# --------------------------------------------------------------------------- #


def test_a_secret_token_in_an_analysed_url_never_reaches_the_logs(
    api_models_dir, tmp_path, log_stream
):
    with api_client(settings_for(api_models_dir, tmp_path)) as client:
        response = client.post("/v1/analyze/url", json={"url": SECRET_URL, "analyst": True})
    assert response.status_code == 200

    assert_never_logged(log_stream, SECRET, SECRET_HOST, "/reset/")
    (line,) = request_lines(log_stream)
    body = response.json()
    assert line["route"] == "/v1/analyze/url"
    assert line["method"] == "POST"
    assert line["status"] == 200
    assert line["verdict"] == body["verdict"]
    assert line["score"] == body["score"]
    assert line["model_version"] == body["model_version"] == "url_v2"
    assert line["channel"] == "url"
    assert line["threat_intel"] is False
    assert line["client"] == "anonymous"
    assert isinstance(line["duration_ms"], float) and line["duration_ms"] >= 0
    assert re.fullmatch(r"[0-9a-f]{32}", line["request_id"])
    assert line["request_id"] == response.headers["x-request-id"]
    assert line["level"] == "info" and line["timestamp"].endswith("Z")


def test_request_lines_carry_only_whitelisted_fields(api_models_dir, tmp_path, log_stream):
    with api_client(settings_for(api_models_dir, tmp_path)) as client:
        client.post("/v1/analyze/url", json={"url": SECRET_URL})
    (line,) = request_lines(log_stream)
    allowed = {
        "event",
        "request_id",
        "method",
        "route",
        "status",
        "duration_ms",
        "client",
        "key_id",
        "level",
        "logger",
        "timestamp",
    } | logs.ANNOTATION_KEYS
    assert set(line) <= allowed
    # Ni IP, ni en-têtes, ni chaîne de requête.
    assert "testclient" not in log_stream.getvalue()


# --------------------------------------------------------------------------- #
# Autres entrées
# --------------------------------------------------------------------------- #


def test_message_content_is_never_logged(api_models_dir, tmp_path, log_stream):
    text = f"Votre colis est bloqué, code {SECRET}, payez sur {SECRET_URL}"
    with api_client(settings_for(api_models_dir, tmp_path)) as client:
        assert client.post("/v1/analyze/text", json={"text": text}).status_code == 200
    assert_never_logged(log_stream, SECRET, "colis", SECRET_HOST)
    (line,) = request_lines(log_stream)
    assert line["route"] == "/v1/analyze/text" and line["verdict"]


def test_email_content_is_never_logged(api_models_dir, tmp_path, log_stream):
    raw = (EMAILS / "02_phish_link_mismatch.eml").read_bytes()
    raw = raw.replace(b"\n\n", f"\n\nSecret {SECRET} {SECRET_URL}\n\n".encode(), 1)
    sender = re.search(rb"^From:.*$", raw, re.MULTILINE).group().decode()
    with api_client(settings_for(api_models_dir, tmp_path)) as client:
        response = client.post(
            "/v1/analyze/email", files={"file": ("m.eml", raw, "message/rfc822")}
        )
    assert response.status_code == 200
    assert_never_logged(log_stream, SECRET, SECRET_HOST, sender.removeprefix("From:").strip())
    assert request_lines(log_stream)[0]["channel"] == "email"


def test_api_keys_are_never_logged_valid_or_not(api_models_dir, tmp_path, log_stream):
    with api_client(settings_for(api_models_dir, tmp_path)) as client:
        record, key = client.app.state.phishguard.database.create_key("ci")
        assert client.get("/v1/model", headers={"X-API-Key": key}).status_code == 200
        forged = key[:-4] + "AAAA"
        assert client.get("/v1/model", headers={"X-API-Key": forged}).status_code == 401
    assert_never_logged(log_stream, key, forged, key[3:20])
    ok, refused = request_lines(log_stream)
    assert ok["client"] == "authenticated" and ok["key_id"] == record.key_id
    assert refused["client"] == "rejected" and refused["status"] == 401


def test_invalid_url_and_validation_errors_are_not_logged(api_models_dir, tmp_path, log_stream):
    with api_client(settings_for(api_models_dir, tmp_path)) as client:
        assert client.post("/v1/analyze/url", json={"url": f"ftp://{SECRET}"}).status_code == 400
        too_long = {"url": "https://a.example/" + SECRET * 100}
        assert client.post("/v1/analyze/url", json=too_long).status_code == 422
        unknown = {"url": "https://a.example/", SECRET: SECRET}
        assert client.post("/v1/analyze/url", json=unknown).status_code == 422
    assert_never_logged(log_stream, SECRET)
    assert [line["status"] for line in request_lines(log_stream)] == [400, 422, 422]


def test_unknown_paths_are_logged_as_unmatched(api_models_dir, tmp_path, log_stream):
    with api_client(settings_for(api_models_dir, tmp_path)) as client:
        assert client.get(f"/v1/{SECRET}?token={SECRET}").status_code == 404
    assert_never_logged(log_stream, SECRET)
    assert request_lines(log_stream)[0]["route"] == "_unmatched"


def test_internal_errors_log_types_and_places_but_no_message(api_models_dir, tmp_path, log_stream):
    def broken(_text, *, channel):
        raise RuntimeError(f"échec sur {SECRET_URL}") from ValueError(SECRET)

    with api_client(settings_for(api_models_dir, tmp_path), raise_server_exceptions=False) as c:
        c.app.state.phishguard.service.analyzers.text.analyze = broken
        assert c.post("/v1/analyze/text", json={"text": "hello"}).status_code == 500
    assert_never_logged(log_stream, SECRET, SECRET_HOST, "Traceback")
    (error,) = [line for line in lines(log_stream) if line["event"] == "erreur interne"]
    assert error["level"] == "error"
    types = [item["type"] for item in error["exc_summary"]]
    assert types == ["builtins.RuntimeError", "builtins.ValueError"]
    assert any("in broken" in frame for frame in error["exc_summary"][0]["frames"])
    (line,) = request_lines(log_stream)
    assert line["status"] == 500 and line["level"] == "error"


def test_library_debug_logs_with_exceptions_are_scrubbed(log_stream):
    """Une erreur httpx cite l'URL appelée (Safe Browsing : la clé dans la requête)."""
    try:
        raise ConnectionError(f"Server error for url '{SECRET_URL}&key=AIzaSyFAKE'")
    except ConnectionError:
        logging.getLogger("httpx").debug("échec de %s", SECRET_URL, exc_info=True)
    logging.getLogger("phishguard.enrichers").info("source %s", f"user@{SECRET_HOST}")
    assert_never_logged(log_stream, SECRET, SECRET_HOST, "AIzaSyFAKE")
    first, second = lines(log_stream)
    assert first["event"] == "échec de [url]"
    assert first["exc_summary"][0]["type"] == "builtins.ConnectionError"
    assert second["event"] == "source [email]"


def test_logs_written_from_worker_threads_carry_the_request_id(
    api_models_dir, tmp_path, log_stream
):
    """La normalisation journalise dans le pool de threads : même identifiant."""
    with api_client(settings_for(api_models_dir, tmp_path)) as client:
        response = client.post("/v1/analyze/text", json={"text": "vér\u200bifiez votre compte"})
    request_id = response.headers["x-request-id"]
    normalized = [line for line in lines(log_stream) if "normalisée" in line["event"]]
    assert normalized and all(line["request_id"] == request_id for line in normalized)
    assert "compte" not in log_stream.getvalue()


def test_every_response_gets_a_fresh_server_side_request_id(api_models_dir, tmp_path):
    with api_client(settings_for(api_models_dir, tmp_path)) as client:
        ids = {
            client.get("/v1/health", headers={"X-Request-ID": "forged\nline"}).headers[
                "x-request-id"
            ]
            for _ in range(5)
        }
        preflight = client.options("/v1/analyze/url")
    assert len(ids) == 5 and all(re.fullmatch(r"[0-9a-f]{32}", i) for i in ids)
    assert re.fullmatch(r"[0-9a-f]{32}", preflight.headers["x-request-id"])


def test_rate_limited_and_timed_out_requests_are_logged(api_models_dir, tmp_path, log_stream):
    settings = settings_for(api_models_dir, tmp_path, rate_limit_anonymous="1/minute")
    with api_client(settings) as client:
        client.get("/v1/model")
        assert client.get("/v1/model").status_code == 429
    assert [line["status"] for line in request_lines(log_stream)] == [200, 429]


# --------------------------------------------------------------------------- #
# Briques
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "text, expected",
    [
        (f"voir {SECRET_URL} svp", "voir [url] svp"),
        ("hxxps://evil.example/x et www.evil.example/a", "[url] et [url]"),
        ("écrire à alice.martin+test@mail.example.org", "écrire à [email]"),
        ("clé pg_" + "A" * 43, "clé [api-key]"),
        ("ligne\nfausse entrée\r\x1b[31m", "ligne�fausse entrée��[31m"),
        ("models/url_v2.joblib introuvable", "models/url_v2.joblib introuvable"),
    ],
)
def test_scrub(text, expected):
    assert scrub(text) == expected


def test_scrub_truncates_long_strings():
    assert len(scrub("a" * 10_000)) < 1100


def test_redact_masks_sensitive_keys_at_any_depth():
    event = {
        "event": "x",
        "url": "a",
        "Text": "b",
        "nested": {"headers": {"cookie": "c"}, "ok": [1, "d"], "domain": "e"},
        "path": object(),
    }
    out = logs.redact(None, "info", event)
    assert out["url"] == out["Text"] == REDACTED
    assert out["nested"] == {"headers": REDACTED, "ok": [1, "d"], "domain": REDACTED}
    assert out["path"] == "<object>"


def test_describe_exception_has_no_message():
    try:
        try:
            raise KeyError(SECRET)
        except KeyError:
            raise RuntimeError(SECRET_URL)  # contexte implicite (__context__) voulu
    except RuntimeError as exc:
        described = describe_exception(exc)
    assert SECRET not in json.dumps(described)
    assert [d["type"] for d in described] == ["builtins.RuntimeError", "builtins.KeyError"]


def test_annotate_accepts_only_whitelisted_fields():
    with pytest.raises(KeyError, match="url"):
        annotate(url=SECRET_URL)
    annotate(verdict="phishing")  # hors requête : ignoré sans erreur


def test_console_format_in_development_json_in_production():
    assert ApiSettings(_env_file=None).log_json is False
    assert ApiSettings(_env_file=None, environment="production").log_json is True
    assert ApiSettings(_env_file=None, log_format="json").log_json is True
    assert ApiSettings(_env_file=None, log_level="debug").log_level == "DEBUG"


def test_console_format_never_prints_a_traceback():
    stream = io.StringIO()
    configure_logging(ApiSettings(_env_file=None, log_format="console"), stream=stream)
    try:
        raise ValueError(SECRET)
    except ValueError:
        logging.getLogger("phishguard.test").exception("échec")
    output = stream.getvalue()
    assert "échec" in output and "Traceback" not in output and SECRET not in output


def test_configure_logging_is_idempotent():
    for _ in range(3):
        configure_logging(ApiSettings(_env_file=None), stream=io.StringIO())
    named = [h for h in logging.getLogger().handlers if h.get_name() == logs.HANDLER_NAME]
    assert len(named) == 1


def test_launcher_disables_uvicorn_access_log(monkeypatch):
    import uvicorn

    from phishguard.api import __main__ as launcher

    calls = []
    monkeypatch.setattr(uvicorn, "run", lambda *args, **kwargs: calls.append(kwargs))
    # Enregistre l'état d'origine : le lanceur écrit la variable, monkeypatch la restaure.
    monkeypatch.setenv("PHISHGUARD_API_LOG_LEVEL", "INFO")
    request_cleanup = launcher.get_api_settings.cache_clear
    try:
        launcher.main(["--log-level", "warning"])
    finally:
        request_cleanup()
    (kwargs,) = calls
    assert kwargs["access_log"] is False  # chemin brut, requête et IP du client
    assert kwargs["log_config"] is None
    assert kwargs["log_level"] == "warning"
    assert logging.getLogger().level == logging.WARNING
