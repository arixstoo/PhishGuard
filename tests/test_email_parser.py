"""Tests du parseur d'emails (étape 1.10).

Les emails de ``tests/fixtures/emails/`` sont rédigés à la main (domaines réservés
``example.*``). Les emails réels du corpus Phishing Pot, téléchargés par
``scripts/fetch_email_samples.py`` dans ``data/raw/emails/``, sont testés s'ils sont
présents (licence CC BY-NC : jamais versionnés).
"""

import importlib.util
import json
import time
from pathlib import Path

import httpx
import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from phishguard.email import EmailLimits, EmailTooLargeError, parse_eml
from phishguard.email import auth as A
from phishguard.email import html as H
from phishguard.email.parser import display_name_domain, make_address

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "emails"
PUBLIC_SAMPLES = ROOT / "data" / "raw" / "emails"


def load_script(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def parse(name, **kwargs):
    return parse_eml((FIXTURES / name).read_bytes(), **kwargs)


# --------------------------------------------------------------------------- #
# Les emails de test
# --------------------------------------------------------------------------- #


def test_all_fixtures_parse_without_failed_steps():
    files = sorted(FIXTURES.glob("*.eml"))
    assert len(files) >= 10
    for path in files:
        result = parse_eml(path.read_bytes())
        assert not [d for d in result.defects if "_failed:" in d], path.name
        json.dumps(result.to_dict())  # sérialisable


def test_legit_newsletter():
    r = parse("01_legit_newsletter.eml")
    assert (r.auth.spf, r.auth.dkim, r.auth.dmarc) == ("pass", "pass", "pass")
    assert r.subject == "Votre commande est expédiée"
    assert r.from_.address == "news@shop.example.com" and r.from_.registered_domain == "example.com"
    assert not (r.reply_to_differs or r.return_path_differs or r.display_name_spoof)
    assert len(r.links) == 2 and not r.mismatched_links
    # Une ligne d'aperçu cachée est courante dans un email légitime.
    assert r.hidden_text.reasons == {"display_none": 1}
    assert r.text.startswith("Bonjour, votre commande 1234")  # partie texte brut préférée


def test_link_whose_text_differs_from_its_target():
    r = parse("02_phish_link_mismatch.eml")
    assert r.auth.dmarc == "fail" and r.auth.spf == "fail" and r.auth.dkim == "none"
    (link,) = r.mismatched_links
    assert link.text_domain == "paypal.com" and link.href_domain == "example.net"


def test_reply_to_and_return_path_on_other_domains():
    r = parse("03_phish_reply_to.eml")
    assert r.reply_to_differs and r.return_path_differs
    assert r.reply_to[0].address == "ceo.company.urgent@example.net"
    assert r.auth.spf == "softfail" and r.auth.dmarc == "none"


def test_risky_attachments():
    r = parse("04_phish_double_extension.eml")
    exe, archive = r.attachments
    assert exe.filename == "Facture_2026.pdf.exe" and exe.risk == "executable"
    assert exe.double_extension and exe.size == 64
    assert archive.risk == "archive" and not archive.double_extension
    assert len(r.risky_attachments) == 2


def test_html_attachment_is_not_analyzed_as_the_body():
    r = parse("05_phish_html_attachment.eml")
    (attachment,) = r.attachments
    assert attachment.risk == "html" and attachment.content_type == "text/html"
    assert r.forms == 0 and not r.has_html  # le formulaire est dans la pièce jointe


def test_hidden_text_and_zero_width_characters():
    r = parse("06_phish_hidden_text.eml")
    assert r.hidden_text.reasons == {
        "tiny_font": 1,
        "same_color_as_background": 1,
        "visibility_hidden": 1,
    }
    assert "compte rendu" not in r.text and "texte blanc" not in r.text
    assert r.zero_width_chars == 1


def test_malformed_headers_and_unknown_charset():
    r = parse("07_malformed_headers.eml")
    assert r.from_ is None and r.auth.source is None
    assert r.defects  # anomalies notées, pas d'exception


def test_deep_nesting_is_cut():
    r = parse("08_nested.eml")
    assert "depth_truncated:10" in r.defects
    shallow = parse("08_nested.eml", limits=EmailLimits(max_depth=20))
    assert shallow.text.strip() == "fond"


def test_quoted_printable_latin1_and_text_links():
    r = parse("09_plain_french_qp.eml")
    assert r.subject == "Réunion publique" and r.from_.display_name == "Mairie de Château"
    assert "réunion publique" in r.text
    (link,) = r.links
    assert link.kind == "text" and link.href == "https://www.mairie.example.fr/reunion?id=5"


def test_only_the_top_authentication_results_header_is_trusted():
    r = parse("10_fake_auth_results.eml")
    assert r.auth.dmarc == "fail" and r.auth.authserv_id == "mx.example.org"
    assert r.auth.headers_seen == 2
    # Avec un serveur de confiance explicite, c'est son en-tête qui compte.
    trusted = parse("10_fake_auth_results.eml", trusted_authserv_ids=["mx.google.com"])
    assert trusted.auth.dmarc == "pass"
    nobody = parse("10_fake_auth_results.eml", trusted_authserv_ids=["mx.autre.example"])
    assert nobody.auth.source is None and nobody.auth.dmarc == "unknown"


def test_arabic_subject_homograph_link_and_rtlo_attachment():
    r = parse("11_arabic_idn.eml")
    assert r.subject == "تم تعليق حسابك"
    (link,) = r.mismatched_links
    assert link.text_domain == "apple.com" and link.href_domain == "xn--pple-43d.com"
    (attachment,) = r.attachments
    assert attachment.rtlo and attachment.extension == "exe" and attachment.risk == "executable"


def test_javascript_link_forms_mailto_and_relative_links():
    r = parse("12_javascript_form.eml")
    by_kind = {(link.kind, link.scheme): link for link in r.links}
    assert by_kind[("a", "javascript")].mismatch  # affiche une adresse web, exécute du code
    assert r.forms == 1 and by_kind[("form", "https")].href_domain == "example.net"
    assert not by_kind[("a", "mailto")].mismatch
    relative = by_kind[("a", "")]
    assert relative.href_domain is None and not relative.mismatch


def test_display_name_spoof_and_received_spf_fallback():
    r = parse("13_display_name_spoof.eml")
    assert r.display_name_spoof
    assert r.auth.spf == "fail" and r.auth.source == "received-spf"


# --------------------------------------------------------------------------- #
# Limites et robustesse
# --------------------------------------------------------------------------- #


def test_oversized_message_is_refused():
    with pytest.raises(EmailTooLargeError):
        parse_eml(b"x" * 101, EmailLimits(max_bytes=100))


def test_only_bytes_are_accepted():
    with pytest.raises(TypeError):
        parse_eml("From: a@example.com\n\nhello")


def test_part_link_and_text_limits():
    parts = "".join(
        f'--b\r\nContent-Type: text/html\r\n\r\n<a href="https://s{i}.example.com/">x</a>\r\n'
        for i in range(30)
    )
    raw = f'Content-Type: multipart/mixed; boundary="b"\r\n\r\n{parts}--b--\r\n'.encode()
    r = parse_eml(raw, EmailLimits(max_parts=10, max_links=5))
    assert "parts_truncated:10" in r.defects
    assert len(r.links) == 5 and any(d.startswith("links_truncated") for d in r.defects)
    long_text = b"Content-Type: text/plain\r\n\r\n" + b"a" * 500
    assert len(parse_eml(long_text, EmailLimits(max_text_chars=100)).text) == 100


def test_deeply_nested_html_stays_fast():
    # Remonter les ancêtres de chaque balise coûtait profondeur × balises : ce message de
    # 0,5 Mo bloquait l'analyse plus de dix minutes.
    html = '<div style="background:#fff">' + '<span style="color:#000">' * 20_000 + "x"
    raw = b"Content-Type: text/html\r\n\r\n" + html.encode()
    start = time.perf_counter()
    parse_eml(raw)
    assert time.perf_counter() - start < 10


def test_same_color_is_inherited_through_the_tree():
    analysis = H.analyze_html(
        '<table bgcolor="#ffffff"><tr><td><div><span style="color:white">caché</span></div>'
        "</td></tr></table><p>vu</p>",
        max_links=10,
    )
    assert analysis.hidden.reasons == {"same_color_as_background": 1}
    assert analysis.text == "vu"


def test_html_tag_budget_is_shared_by_all_parts():
    part = "--b\r\nContent-Type: text/html\r\n\r\n" + "<b>x</b>" * 30 + "\r\n"
    raw = f'Content-Type: multipart/alternative; boundary="b"\r\n\r\n{part * 5}--b--\r\n'
    r = parse_eml(raw.encode(), EmailLimits(max_html_tags=100))
    assert r.defects.count("html_tags_truncated:100") == 1
    assert r.text.count("x") == 50  # 100 balises : 50 « <b>x</b> » sur les 150


def test_thousands_of_tiny_parts_are_cut_before_parsing():
    # La bibliothèque standard lisait les 100 000 parties (une vingtaine de secondes)
    # avant que max_parts ne joue.
    part = b"--B\r\nContent-Type: application/octet-stream\r\n\r\nx\r\n"
    raw = b"From: a@b.example\r\nContent-Type: multipart/mixed; boundary=B\r\n\r\n"
    r = parse_eml(raw + part * 5_000 + b"--B--\r\n", EmailLimits(max_parts=20))
    assert "mime_truncated:20" in r.defects and r.parts == 20
    assert r.from_.address == "a@b.example"


@pytest.mark.parametrize(
    ("headers", "kept_from"),
    [
        (b"From: a@b.example\r\n" + b"X-A: b\r\n" * 2_000, "a@b.example"),  # trop de champs
        (b"From: a@b.example\r\nSubject: " + b"=?utf-8?q?a?= " * 10_000 + b"\r\n", "a@b.example"),
        (b"X-A: b\r\n" * 2_000 + b"From: a@b.example\r\n", None),  # From au-delà de la limite
    ],
    ids=["many_fields", "huge_subject", "from_beyond_limit"],
)
def test_headers_are_bounded_before_parsing(headers, kept_from):
    r = parse_eml(headers + b"\r\nbody", EmailLimits(max_headers=100))
    assert "headers_truncated" in r.defects
    assert (r.from_.address if r.from_ else None) == kept_from
    assert r.text.strip() == "body"
    assert not [d for d in r.defects if "_failed:" in d]


def test_auth_survives_a_trapped_from_header():
    raw = b"Authentication-Results: mx.example; spf=fail; dmarc=fail\r\nFrom: " + b"(" * 20_000
    r = parse_eml(raw + b"a@b.example\r\n\r\nx")
    assert (r.auth.spf, r.auth.dmarc) == ("fail", "fail")


def test_empty_and_garbage_inputs():
    for raw in (b"", b"\x00\xff" * 50, b"\r\n\r\n", b":::\r\n\r\n", b"From: <<<@@@>>>\r\n\r\nx"):
        result = parse_eml(raw)
        assert not [d for d in result.defects if "_failed:" in d]


@settings(max_examples=200, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(st.binary(max_size=2000))
def test_random_bytes_never_crash_the_parser(raw):
    result = parse_eml(raw)
    json.dumps(result.to_dict())


@settings(max_examples=150, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(
    st.sampled_from(sorted(p.name for p in FIXTURES.glob("*.eml"))),
    st.integers(min_value=0, max_value=4000),
    st.binary(min_size=1, max_size=40),
)
def test_corrupted_fixtures_never_crash_the_parser(name, position, garbage):
    raw = (FIXTURES / name).read_bytes()
    position %= len(raw)
    parse_eml(raw[:position] + garbage + raw[position + len(garbage) :])


@pytest.mark.skipif(not PUBLIC_SAMPLES.is_dir(), reason="emails publics non téléchargés")
def test_public_phishing_samples():
    files = sorted(PUBLIC_SAMPLES.rglob("*.eml"))
    assert files, "lancez scripts/fetch_email_samples.py"
    for path in files:
        result = parse_eml(path.read_bytes())
        assert not [d for d in result.defects if "_failed:" in d], path.name
        assert result.from_ is not None, path.name


# --------------------------------------------------------------------------- #
# Authentification
# --------------------------------------------------------------------------- #


def test_authentication_results_parsing():
    header = (
        "mx.example.org 1; spf=pass (sender IP is 192.0.2.1; ok) smtp.mailfrom=a.example; "
        "dkim=fail header.d=a.example; dkim=pass header.d=b.example; DMARC=Fail"
    )
    authserv, results = A.parse_authentication_results(header)
    assert authserv == "mx.example.org"
    assert results == {"spf": "pass", "dkim": "pass", "dmarc": "fail"}  # un DKIM valide suffit


def test_authentication_results_edge_cases():
    assert A.parse_authentication_results("") == (None, {})
    assert A.parse_authentication_results("mx.example.org; none") == ("mx.example.org", {})
    _, results = A.parse_authentication_results("mx; spf=bizarre; arc=pass")
    assert results == {"spf": "unknown"}
    assert A.strip_comments("a (b (c) d) e \\( f") == "a  e \\( f"


def test_exchange_online_header_without_authserv_id():
    # Forme vue dans 46 des 50 emails Phishing Pot : pas d'identifiant de serveur, et
    # « bestguesspass » quand le domaine n'a pas d'enregistrement DMARC.
    header = (
        "spf=pass (sender IP is 192.0.2.1) smtp.mailfrom=mg.a.example; dkim=pass "
        "(signature was verified) header.d=a.example;dmarc=bestguesspass action=none "
        "header.from=a.example;compauth=pass reason=109"
    )
    assert A.parse_authentication_results(header) == (
        None,
        {"spf": "pass", "dkim": "pass", "dmarc": "none"},
    )
    assert A.read_auth_results([header]).spf == "pass"


def test_received_spf_and_fallbacks():
    assert A.parse_received_spf("SoftFail (mx: transitioning) client-ip=192.0.2.1") == "softfail"
    assert A.parse_received_spf("") == "unknown"
    combined = A.read_auth_results(["mx.example.org; dmarc=pass"], ["fail (x)"])
    assert combined.spf == "fail" and combined.dmarc == "pass"
    assert A.read_auth_results([]) == A.AuthResults()


# --------------------------------------------------------------------------- #
# HTML et adresses
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("style", "reason"),
    [
        ("display: none", "display_none"),
        ("DISPLAY:NONE !important", "display_none"),
        ("visibility:hidden", "visibility_hidden"),
        ("opacity: 0", "opacity_zero"),
        ("opacity: 0.0", "opacity_zero"),
        ("font-size:0", "tiny_font"),
        ("font-size: 1px", "tiny_font"),
        ("font-size: 0.05em", "tiny_font"),
        ("max-height:0; overflow:hidden", "zero_height"),
        ("color:#fff; background-color:white", "same_color_as_background"),
        ("color: rgb(255, 255, 255); background: #FFFFFF url(x.png)", "same_color_as_background"),
        ("font-size: 14px; color: #333", None),
        ("max-height:0", None),  # sans overflow:hidden, le contenu reste visible
        ("opacity: 0.8", None),
    ],
)
def test_hiding_reasons(style, reason):
    soup = H.BeautifulSoup(f'<span style="{style}">x</span>', "html.parser")
    assert H.hiding_reason(soup.span) == reason


def test_hidden_attribute_and_nested_hidden_elements_counted_once():
    analysis = H.analyze_html(
        '<div hidden><span style="display:none">a</span> b</div><p>visible</p>', max_links=10
    )
    assert analysis.hidden.elements == 1 and analysis.hidden.reasons == {"hidden_attribute": 1}
    assert analysis.text == "visible"


def test_scripts_and_styles_are_ignored():
    analysis = H.analyze_html(
        "<style>.a{}</style><script>var u='https://x.example.com'</script><p>ok</p>", max_links=10
    )
    assert analysis.text == "ok" and not analysis.links


@pytest.mark.parametrize(
    ("value", "expected"),
    [("#FFF", "#ffffff"), ("white", "#ffffff"), ("rgb(0,0,0)", "#000000"), ("bleu", None)],
)
def test_normalize_color(value, expected):
    assert H.normalize_color(value) == expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("https://login.paypal.com/x", "paypal.com"),
        ("www.amazon.co.uk", "amazon.co.uk"),
        ("münchen.de", "xn--mnchen-3ya.de"),
        ("user.github.io", "user.github.io"),
        ("Bradesco.recompensas", None),  # pas de suffixe public connu
        ("www", None),
        ("", None),
        ("http://[::1", None),
    ],
)
def test_registered_domain(value, expected):
    assert H.registered_domain(value) == expected


def test_make_link():
    assert H.make_link("a", "https://evil.example.net/", "https://www.paypal.com").mismatch
    assert not H.make_link("a", "https://www.paypal.com/x", "paypal.com").mismatch
    assert not H.make_link("a", "https://evil.example.net/", "Cliquez ici").mismatch
    assert H.make_link("a", "data:text/html,x", "www.bank.example.com").mismatch


@pytest.mark.parametrize(
    ("href", "rewriter"),
    [
        ("https://clicktime.symantec.com/39e8?u=http%3A%2F%2Fwww.paypal.com%2F", "symantec"),
        (
            "https://eur01.safelinks.protection.outlook.com/?url=https%3A%2F%2Fwww.paypal.com",
            "safelinks",
        ),
        ("https://urldefense.proofpoint.com/v2/url?u=https-3A__www.paypal.com_x&d=1", "proofpoint"),
        ("https://urldefense.com/v3/__https://www.paypal.com/x__;!!ab$", "proofpoint"),
    ],
)
def test_links_rewritten_by_security_gateways_are_unwrapped(href, rewriter):
    # Vu sur Phishing Pot : un lien réécrit par la passerelle passait pour trompeur.
    link = H.make_link("a", href, "www.paypal.com")
    assert (link.href_domain, link.rewritten_by, link.mismatch) == ("paypal.com", rewriter, False)


def test_unwrapping_keeps_a_lure_behind_a_gateway():
    href = "https://eur01.safelinks.protection.outlook.com/?url=https%3A%2F%2Fevil.example.net%2F"
    assert H.make_link("a", href, "www.paypal.com").mismatch
    # Cible non web ou absente : le lien n'est pas déballé.
    assert (
        H.unwrap_rewritten("https://x.safelinks.protection.outlook.com/?url=javascript:x") is None
    )
    assert H.unwrap_rewritten("https://clicktime.symantec.com/x") is None


def test_text_links_strip_trailing_punctuation():
    links = H.text_links("Voir https://a.example.com/x. et (https://b.example.com/y)", limit=10)
    assert [link.href for link in links] == ["https://a.example.com/x", "https://b.example.com/y"]
    assert len(H.text_links("https://a.example.com " * 20, limit=3)) == 3


def test_addresses():
    address = make_address("Service", "<Service@Example.COM>")
    assert address.domain == "example.com" and address.registered_domain == "example.com"
    assert make_address("", "") is None
    assert make_address("Nom seul", "").domain is None
    assert display_name_domain("service@paypal.com") == "paypal.com"
    assert display_name_domain("PayPal.com Support") == "paypal.com"
    assert display_name_domain("Service client") is None


def test_from_with_unquoted_comma_keeps_the_real_sender():
    raw = b'From: "Microsoft account team", _ <no-reply@notice.example.net>\r\n\r\nx'
    result = parse_eml(raw)
    assert result.from_.address == "no-reply@notice.example.net"
    assert "multiple_from" not in result.defects


# --------------------------------------------------------------------------- #
# Scripts
# --------------------------------------------------------------------------- #


def test_parse_email_cli(capsys, tmp_path):
    cli = load_script("parse_email")
    assert cli.main([str(FIXTURES / "04_phish_double_extension.eml")]) == 0
    out = capsys.readouterr().out
    assert "Facture_2026.pdf.exe" in out and "double extension" in out
    assert cli.main([str(FIXTURES / "02_phish_link_mismatch.eml"), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["auth"]["dmarc"] == "fail"
    assert cli.main([str(tmp_path / "absent.eml")]) == 1


def test_fetch_email_samples_with_a_fake_network(tmp_path):
    script = load_script("fetch_email_samples")

    def handler(request):
        n = int(request.url.path.rsplit("-", 1)[1].split(".")[0])
        if n == 11:  # numéro absent du corpus
            return httpx.Response(404)
        return httpx.Response(200, content=f"From: a@example.com\r\n\r\n{n}".encode())

    args = script.parse_args(["--output-dir", str(tmp_path), "--count", "3", "--step", "10"])
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        entries = script.fetch(client, args)
    assert [e["file"] for e in entries] == ["sample-1.eml", "sample-21.eml", "sample-31.eml"]
    assert (tmp_path / "sample-21.eml").read_bytes().endswith(b"21")
    assert all(len(e["sha256"]) == 64 for e in entries)
    with pytest.raises(SystemExit):
        script.parse_args(["--count", "0"])
