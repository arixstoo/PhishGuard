"""Schémas d'entrée stricts (étape 4.2) : toute entrée hostile reçoit une erreur propre.

Une erreur propre : un code HTTP 4xx, l'enveloppe ``{"error": {...}}``, et **rien de
l'entrée** dans la réponse (ni la valeur fautive, ni un caractère de contrôle).
"""

from __future__ import annotations

import pytest
from api_support import api_client, settings_for

from phishguard.api.middleware import _content_length
from phishguard.api.schemas import FeedbackRequest, TextRequest, UrlRequest

SECRET = "MARQUEUR-ENTREE-A-NE-PAS-RENVOYER"  # ne doit jamais revenir dans une réponse


@pytest.fixture(scope="module")
def client(api_models_dir, tmp_path_factory):
    settings = settings_for(api_models_dir, tmp_path_factory.mktemp("api"))
    with api_client(settings) as client:
        yield client


def assert_clean_error(response, status: int, code: str) -> dict:
    assert response.status_code == status, response.text
    body = response.json()
    assert set(body) == {"error"} and body["error"]["code"] == code
    assert '"input"' not in response.text and SECRET not in response.text
    assert "Traceback" not in response.text
    return body["error"]


# --------------------------------------------------------------------------- #
# Critère de l'étape : URL géante, texte vide, JSON malformé, octet nul
# --------------------------------------------------------------------------- #


def test_url_of_100_000_characters_is_refused_before_parsing(client):
    response = client.post("/v1/analyze/url", json={"url": f"https://example.com/{SECRET}" * 4000})
    assert_clean_error(response, 413, "payload_too_large")


def test_url_over_2048_characters_is_a_validation_error(client):
    url = f"https://example.com/{SECRET}/" + "a" * 3000  # corps sous la limite de taille
    error = assert_clean_error(
        client.post("/v1/analyze/url", json={"url": url}), 422, "validation_error"
    )
    assert error["details"] == [
        {"loc": ["body", "url"], "type": "string_too_long", "msg": error["details"][0]["msg"]}
    ]


@pytest.mark.parametrize("text", ["", "   \n\t  "])
def test_empty_text_is_refused(client, text):
    error = assert_clean_error(
        client.post("/v1/analyze/text", json={"text": text}), 422, "validation_error"
    )
    assert error["details"][0]["loc"] == ["body", "text"]


@pytest.mark.parametrize(
    "body",
    [b"{bad", b'{"url": "https://example.com"', b"", b"[]", b"null", b'"https://example.com"'],
)
def test_malformed_json_is_refused(client, body):
    response = client.post(
        "/v1/analyze/url", content=body, headers={"content-type": "application/json"}
    )
    assert_clean_error(response, 422, "validation_error")


@pytest.mark.parametrize(
    "route, field",
    [("/v1/analyze/url", "url"), ("/v1/analyze/text", "text")],
)
def test_null_byte_is_refused(client, route, field):
    value = f"https://example.com/\x00{SECRET}" if field == "url" else f"bonjour\x00{SECRET}"
    error = assert_clean_error(client.post(route, json={field: value}), 422, "validation_error")
    assert "position" in error["details"][0]["msg"]


# --------------------------------------------------------------------------- #
# Autres entrées hostiles
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "value",
    [
        "https://example.com/\x1b[31m",  # séquence d'échappement de terminal
        "https://example.com/\u0085",  # C1 (NEL)
        "https://example.com/\x7f",
        "https://exa\nmple.com/",
    ],
)
def test_control_characters_are_refused_in_urls(client, value):
    assert_clean_error(client.post("/v1/analyze/url", json={"url": value}), 422, "validation_error")


@pytest.mark.parametrize("route, field", [("/v1/analyze/url", "url"), ("/v1/analyze/text", "text")])
def test_lone_surrogates_are_refused(client, route, field):
    # Demi-codet isolé, échappé : JSON valide, mais impossible à encoder en UTF-8.
    body = b'{"%s": "https://example.com/\\ud800"}' % field.encode()
    response = client.post(route, content=body, headers={"content-type": "application/json"})
    assert_clean_error(response, 422, "validation_error")


def test_text_keeps_tabs_newlines_and_invisible_evasion_characters(client):
    # Largeur nulle et inversion de sens : des évasions que la normalisation compte,
    # pas des erreurs de l'entrée.
    text = "Votre compte\test bloqué\r\nvérifiez\u200b ici \u202eexe.pdf"
    response = client.post("/v1/analyze/text", json={"text": text, "analyst": True})
    assert response.status_code == 200
    assert response.json()["analyst"]["normalization"]["changed"] is True


def test_text_over_5000_characters_is_refused(client):
    response = client.post("/v1/analyze/text", json={"text": "a" * 5001})
    assert_clean_error(response, 422, "validation_error")


def test_unknown_fields_are_refused(client):
    response = client.post(
        "/v1/analyze/url", json={"url": "https://example.com", "use_threat_intell": True}
    )
    error = assert_clean_error(response, 422, "validation_error")
    assert error["details"][0]["type"] == "extra_forbidden"


@pytest.mark.parametrize(
    "body",
    [
        {"url": "https://example.com", "use_threat_intel": "true"},
        {"url": "https://example.com", "analyst": 1},
        {"url": 12345},
        {"url": ["https://example.com"]},
        {"url": "https://example.com", "language": "de"},
    ],
)
def test_types_are_strict(client, body):
    assert_clean_error(client.post("/v1/analyze/url", json=body), 422, "validation_error")


@pytest.mark.parametrize("content_type", ["text/plain", "application/x-www-form-urlencoded", None])
def test_json_routes_require_the_json_media_type(client, content_type):
    headers = {"content-type": content_type} if content_type else {}
    response = client.post(
        "/v1/analyze/url", content=b'{"url": "https://example.com"}', headers=headers
    )
    assert_clean_error(response, 415, "unsupported_media_type")


def test_chunked_body_is_cut_at_the_limit(client):
    def chunks():
        yield b'{"url": "https://example.com/'
        for _ in range(100):
            yield b"a" * 1024  # 100 Ko sans Content-Length

    response = client.post(
        "/v1/analyze/url", content=chunks(), headers={"content-type": "application/json"}
    )
    assert_clean_error(response, 413, "payload_too_large")


def test_content_length_parsing():
    def scope(*values: bytes) -> dict:
        return {"headers": [(b"content-length", v) for v in values]}

    assert _content_length(scope()) is None
    assert _content_length(scope(b"42")) == 42
    assert _content_length(scope(b"42", b"42")) == 42
    for bad in ((b"-1",), (b"12abc",), (b"1e3",), (b"42", b"43"), (b"9" * 30,)):
        assert _content_length(scope(*bad)) == -1


# --------------------------------------------------------------------------- #
# Email
# --------------------------------------------------------------------------- #


def test_email_over_one_mebibyte_is_refused(client):
    big = b"Subject: x\r\n\r\n" + b"a" * (1024 * 1024 + 1)
    response = client.post("/v1/analyze/email", files={"file": ("big.eml", big, "message/rfc822")})
    assert_clean_error(response, 413, "payload_too_large")


def test_email_just_under_the_route_limit_but_over_the_file_limit_is_refused(client):
    # Le corps tient dans l'enveloppe multipart, mais le fichier dépasse 1 Mio.
    content = b"Subject: x\r\n\r\n" + b"a" * (1024 * 1024 + 100 - 14)
    response = client.post(
        "/v1/analyze/email", files={"file": ("big.eml", content, "message/rfc822")}
    )
    assert_clean_error(response, 413, "payload_too_large")


@pytest.mark.parametrize("media_type", ["image/png", "application/pdf", "text/html", ""])
def test_unexpected_email_content_types_are_refused(client, media_type):
    response = client.post(
        "/v1/analyze/email", files={"file": ("mail.eml", b"Subject: x\r\n\r\nhi", media_type)}
    )
    assert_clean_error(response, 415, "unsupported_media_type")


def test_empty_email_is_refused(client):
    response = client.post(
        "/v1/analyze/email", files={"file": ("mail.eml", b"  \r\n", "message/rfc822")}
    )
    assert_clean_error(response, 422, "validation_error")


def test_email_requires_a_file(client):
    response = client.post("/v1/analyze/email", data={"language": "fr"})
    assert_clean_error(response, 422, "validation_error")


def test_email_options_are_validated(client):
    response = client.post(
        "/v1/analyze/email",
        files={"file": ("mail.eml", b"Subject: x\r\n\r\nhi", "message/rfc822")},
        data={"language": "klingon"},
    )
    assert_clean_error(response, 422, "validation_error")


# --------------------------------------------------------------------------- #
# Schémas, sans HTTP
# --------------------------------------------------------------------------- #


def test_request_defaults_are_private():
    assert UrlRequest(url="https://example.com").use_threat_intel is False
    assert UrlRequest(url="https://example.com").analyst is False
    assert TextRequest(text="hello").channel == "sms"


@pytest.mark.parametrize(
    "domain, expected",
    [
        ("Example.COM.", "example.com"),
        ("bücher.example", "xn--bcher-kva.example"),
        ("sub.domain.co.uk", "sub.domain.co.uk"),
    ],
)
def test_feedback_domain_is_normalized(domain, expected):
    request = FeedbackRequest(domain=domain, verdict="phishing", judgement="false_positive")
    assert request.domain == expected


@pytest.mark.parametrize(
    "domain",
    [
        "https://example.com/login?token=abc",  # une URL : chemin et paramètres refusés
        "example.com/path",
        "user@example.com",
        "192.168.1.1",
        "localhost",
        "-bad.example",
        "ex ample.com",
        "<script>.com",
        "a" * 64 + ".com",
    ],
)
def test_feedback_refuses_anything_but_a_domain(domain):
    with pytest.raises(ValueError):
        FeedbackRequest(domain=domain, verdict="phishing", judgement="false_positive")


@pytest.mark.parametrize(
    "verdict, judgement", [("safe", "false_positive"), ("phishing", "false_negative")]
)
def test_feedback_judgement_must_match_the_verdict(client, verdict, judgement):
    response = client.post(
        "/v1/feedback", json={"domain": "example.com", "verdict": verdict, "judgement": judgement}
    )
    assert_clean_error(response, 422, "validation_error")


def test_feedback_refuses_a_client_timestamp(client):
    body = {
        "domain": "example.com",
        "verdict": "phishing",
        "judgement": "false_positive",
        "received_at": "1999-01-01T00:00:00Z",
    }
    assert_clean_error(client.post("/v1/feedback", json=body), 422, "validation_error")
