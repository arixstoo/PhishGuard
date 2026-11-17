"""Page « coller et analyser » (étape 5.12) : servie par l'API, sûre par construction.

Le rendu et le parcours dans un navigateur sont vérifiés par Playwright
(``extension/e2e/web-page.spec.ts``) ; ici, ce que le serveur sert et ce que le code de la
page s'interdit.
"""

from __future__ import annotations

import re
from html.parser import HTMLParser

import pytest
from api_support import api_client, settings_for

from phishguard.api.routers.web import ASSETS, WEB_CSP
from phishguard.api.schemas import MAX_TEXT_CHARS, MAX_URL_CHARS

PAGE_JS = ASSETS["paste.js"][0].decode("utf-8")
PAGE_CSS = ASSETS["paste.css"][0].decode("utf-8")


@pytest.fixture(scope="module")
def client(api_models_dir, tmp_path_factory):
    with api_client(settings_for(api_models_dir, tmp_path_factory.mktemp("web"))) as c:
        yield c


class _Page(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.tags: list[tuple[str, dict[str, str | None]]] = []
        self.inline_scripts = 0
        self._in_script = False

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))
        self._in_script = tag == "script"

    def handle_endtag(self, tag):
        self._in_script = False

    def handle_data(self, data):
        if self._in_script and data.strip():
            self.inline_scripts += 1


def parse(html: str) -> _Page:
    page = _Page()
    page.feed(html)
    return page


def test_page_is_served_with_its_own_strict_policy(client):
    response = client.get("/")
    assert response.status_code == 200
    assert response.headers["content-type"] == "text/html; charset=utf-8"
    assert response.headers["content-security-policy"] == WEB_CSP
    # Les en-têtes de sécurité de l'API s'appliquent aussi à la page.
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert "Ne collez pas de mot de passe ou de données personnelles." in response.text


def test_policy_allows_nothing_but_the_page_itself():
    directives = dict(d.strip().split(" ", 1) for d in WEB_CSP.split(";"))
    assert directives["default-src"] == "'none'"
    for name in ("script-src", "style-src", "img-src", "connect-src"):
        assert directives[name] == "'self'", name
    assert directives["form-action"] == "'none'"  # le texte n'est jamais envoyé par formulaire
    assert directives["require-trusted-types-for"] == "'script'"
    assert "unsafe" not in WEB_CSP


def test_html_has_no_inline_code_and_no_external_resource(client):
    page = parse(client.get("/").text)
    assert page.inline_scripts == 0
    for tag, attrs in page.tags:
        assert not any(name.startswith("on") for name in attrs), (tag, attrs)
        assert "style" not in attrs, tag
        if tag in ("script", "link", "img"):
            ref = attrs.get("src") or attrs.get("href") or ""
            assert ref.startswith("static/"), ref
    [textarea] = [attrs for tag, attrs in page.tags if tag == "textarea"]
    # Sans name, le texte ne peut pas finir dans une URL ; correcteur distant désactivé.
    assert "name" not in textarea
    assert textarea["spellcheck"] == "false"
    assert textarea["maxlength"] == str(MAX_TEXT_CHARS)


@pytest.mark.parametrize(
    ("pattern", "label"),
    [
        (
            r"\.innerHTML\b|\.outerHTML\b|insertAdjacentHTML|document\.write|createContextualFragment",
            "HTML",
        ),
        (r"\beval\s*\(|new\s+Function\s*\(|setTimeout\s*\(\s*[\"'`]", "code dynamique"),
        (r"localStorage|sessionStorage|indexedDB|document\.cookie", "stockage"),
        (
            r"XMLHttpRequest|WebSocket|EventSource|sendBeacon|navigator\.sendBeacon",
            "autre canal réseau",
        ),
    ],
)
def test_page_code_forbids(pattern, label):
    assert not re.search(pattern, PAGE_JS), label


def test_page_code_only_calls_the_two_analysis_routes():
    assert re.findall(r"post\(\"(/[^\"]+)\"", PAGE_JS) == ["/v1/analyze/text", "/v1/analyze/url"]
    assert PAGE_JS.count("fetch(") == 1


def test_page_limits_match_the_api_schemas():
    assert f"const MAX_CHARS = {MAX_TEXT_CHARS};" in PAGE_JS
    assert f"const MAX_URL_CHARS = {MAX_URL_CHARS};" in PAGE_JS


@pytest.mark.parametrize(
    ("name", "media_type"),
    [
        ("paste.js", "text/javascript; charset=utf-8"),
        ("paste.css", "text/css; charset=utf-8"),
        ("icon.svg", "image/svg+xml"),
    ],
)
def test_assets(client, name, media_type):
    response = client.get(f"/static/{name}")
    assert response.status_code == 200
    assert response.headers["content-type"] == media_type
    assert response.headers["x-content-type-options"] == "nosniff"
    # Un fichier ouvert seul (SVG) n'exécute rien : politique de l'API.
    assert response.headers["content-security-policy"].startswith("default-src 'none'")


@pytest.mark.parametrize(
    "path", ["/static/main.py", "/static/..%2Fmain.py", "/static/%2e%2e/settings.py", "/static/"]
)
def test_no_other_file_is_served(client, path):
    assert client.get(path).status_code == 404


def test_page_is_not_part_of_the_api_schema(client):
    paths = client.get("/openapi.json").json()["paths"]
    assert "/" not in paths and not any(p.startswith("/static") for p in paths)


def test_page_can_be_disabled(api_models_dir, tmp_path):
    with api_client(settings_for(api_models_dir, tmp_path, web_page_enabled=False)) as c:
        assert c.get("/").status_code == 404
        assert c.get("/static/paste.js").status_code == 404


# --------------------------------------------------------------------------- #
# Contrastes (WCAG AA), en clair et en sombre
# --------------------------------------------------------------------------- #


def _tokens(css: str) -> tuple[dict[str, str], dict[str, str]]:
    light_block = re.search(r":root\s*\{(.*?)\}", css, re.DOTALL).group(1)
    dark_block = re.search(
        r"prefers-color-scheme:\s*dark\)\s*\{\s*:root\s*\{(.*?)\}", css, re.DOTALL
    ).group(1)

    def parse_block(block: str) -> dict[str, str]:
        return dict(re.findall(r"--([\w-]+):\s*(#[0-9a-fA-F]{6})", block))

    light = parse_block(light_block)
    return light, {**light, **parse_block(dark_block)}


def _luminance(hex_color: str) -> float:
    def channel(value: int) -> float:
        c = value / 255
        return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4

    r, g, b = (int(hex_color[i : i + 2], 16) for i in (1, 3, 5))
    return 0.2126 * channel(r) + 0.7152 * channel(g) + 0.0722 * channel(b)


def contrast(a: str, b: str) -> float:
    la, lb = sorted((_luminance(a), _luminance(b)), reverse=True)
    return (la + 0.05) / (lb + 0.05)


TEXT_PAIRS = [
    ("fg", "bg"),
    ("muted", "bg"),
    ("fg", "surface"),
    ("muted", "surface"),
    ("accent", "bg"),
    ("accent-fg", "accent"),
    ("phishing", "bg"),
    ("warning-fg", "warning-bg"),
    ("safe", "safe-bg"),
    ("suspicious", "suspicious-bg"),
    ("phishing", "phishing-bg"),
    ("fg", "safe-bg"),
    ("fg", "suspicious-bg"),
    ("fg", "phishing-bg"),
    ("muted", "safe-bg"),
    ("muted", "suspicious-bg"),
    ("muted", "phishing-bg"),
]
NON_TEXT_PAIRS = [("line", "bg"), ("focus", "bg"), ("phishing", "bg"), ("suspicious", "warning-bg")]


@pytest.mark.parametrize("scheme", [0, 1], ids=["clair", "sombre"])
def test_contrast_wcag_aa(scheme):
    tokens = _tokens(PAGE_CSS)[scheme]
    for fg, bg in TEXT_PAIRS:
        assert contrast(tokens[fg], tokens[bg]) >= 4.5, (
            fg,
            bg,
            round(contrast(tokens[fg], tokens[bg]), 2),
        )
    for fg, bg in NON_TEXT_PAIRS:
        assert contrast(tokens[fg], tokens[bg]) >= 3, (fg, bg)
