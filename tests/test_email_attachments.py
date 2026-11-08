"""Tests de l'inspection du contenu des pièces jointes (étape 2.13).

Fichiers fabriqués et inoffensifs : voir ``tests/attachment_samples.py``.
"""

import time
from email.message import EmailMessage
from pathlib import Path

import attachment_samples as S
import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from phishguard.email.attachments import ContentFindings, detect_type, inspect_content
from phishguard.email.parser import EmailLimits, parse_eml
from phishguard.email.score import email_features, score_email

FIXTURES = Path(__file__).parent / "fixtures" / "emails"
NEW_RULES = {
    "type_mismatch",
    "remote_content_document",
    "hidden_archive_payload",
    "active_pdf",
    "credential_form_attachment",
}


def email_with(filename, data, maintype="application", subtype="octet-stream"):
    msg = EmailMessage()
    msg["From"] = "Service Client <client@shop.example.test>"
    msg["To"] = "alice@example.test"
    msg["Subject"] = "Votre facture"
    msg.set_content("Bonjour, veuillez trouver votre facture en pièce jointe.")
    msg.add_attachment(data, maintype=maintype, subtype=subtype, filename=filename)
    return parse_eml(msg.as_bytes())


# --------------------------------------------------------------------------- #
# Type réel par signature
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("data", "expected"),
    [
        (S.PE, "pe_executable"),
        (S.ELF, "elf_executable"),
        (b"\xcf\xfa\xed\xfe" + b"\x00" * 12, "macho_executable"),
        (S.ole_file(), "ole"),
        (S.zip_file({"a.txt": b"x"}), "zip"),
        (b"Rar!\x1a\x07\x01\x00", "rar"),
        (b"7z\xbc\xaf\x27\x1c\x00\x04", "7z"),
        (b"\x1f\x8b\x08\x00", "gzip"),
        (b"MSCF\x00\x00\x00\x00", "cab"),
        (S.RTF_PLAIN, "rtf"),
        (S.LNK, "lnk"),
        (S.PNG, "png"),
        (b"\xff\xd8\xff\xe0\x00\x10JFIF", "jpeg"),
        (b"GIF89a\x01\x00", "gif"),
        (S.PDF_PLAIN, "pdf"),
        (b"junk before header\n%PDF-1.5\n", "pdf"),
        (S.ISO, "iso"),
        (b"#!/bin/sh\nrm -rf /tmp/x\n", "shell_script"),
        (S.HTML_PLAIN, "html"),
        (b"\xef\xbb\xbf<!doctype html><title>x</title>", "html"),
        (b"Bonjour, ceci est un texte.", None),
        (b"", None),
    ],
    # Identifiants courts : pytest recopie l'identifiant dans PYTEST_CURRENT_TEST, et
    # Windows refuse une variable d'environnement de plus de 32 767 caractères (ISO).
    ids=lambda value: value if isinstance(value, str) or value is None else f"{len(value)}B",
)
def test_detect_type_by_signature(data, expected):
    assert detect_type(data) == expected


# --------------------------------------------------------------------------- #
# Critère de l'étape : les cinq formes d'attaque sont détectées
# --------------------------------------------------------------------------- #


def test_executable_renamed_as_pdf_is_detected():
    email = email_with("facture.pdf", S.PE, "application", "pdf")
    (attachment,) = email.attachments
    assert attachment.risk is None  # le nom seul ne voyait rien
    assert attachment.content.detected_type == "pe_executable"
    assert attachment.type_mismatch and attachment.effective_risk == "executable"
    rules = set(score_email(email).triggered)
    assert {"dangerous_attachment", "type_mismatch"} <= rules
    assert score_email(email).verdict == "phishing"


def test_old_word_document_with_macros_is_detected():
    email = email_with("contrat.doc", S.ole_file(["Macros"], nested="VBA"), "application", "msword")
    (attachment,) = email.attachments
    assert attachment.risk is None  # « .doc » n'est pas une extension à macros
    assert attachment.content.macros and attachment.effective_risk == "macro_document"
    assert "dangerous_attachment" in score_email(email).triggered


def test_excel_macro_storage_is_detected():
    data = S.ole_file(["Workbook", "_VBA_PROJECT_CUR"])
    assert inspect_content(data).macros


def test_docx_hiding_a_vba_project_is_detected():
    findings = inspect_content(S.docx(macros=True))
    assert (findings.detected_type, findings.macros, findings.family) == (
        "ooxml",
        True,
        "macro_document",
    )


def test_docx_loading_a_remote_template_is_detected():
    email = email_with("offre.docx", S.docx(remote_template=True))
    (attachment,) = email.attachments
    assert attachment.content.remote_template and not attachment.content.macros
    assert "remote_content_document" in score_email(email).triggered


def test_rtf_with_embedded_object_is_detected():
    assert inspect_content(S.RTF_OBJECT).rtf_objects
    assert not inspect_content(S.RTF_PLAIN).rtf_objects


def test_encrypted_archive_is_detected():
    data = S.zip_file({"facture.pdf.exe": S.PE}, encrypted=("facture.pdf.exe",))
    email = email_with("facture.zip", data, "application", "zip")
    (attachment,) = email.attachments
    assert attachment.content.archive_encrypted
    assert attachment.content.archive_dangerous_members == ("facture.pdf.exe",)
    assert "hidden_archive_payload" in score_email(email).triggered


def test_archive_listing_without_extraction():
    data = S.zip_file(
        {"docs/": b"", "docs/lisez-moi.txt": b"x", "run.js": b"x", "setup.EXE": b"x", "a.lnk": b"x"}
    )
    findings = inspect_content(data)
    assert findings.archive_entries == 5 and not findings.archive_encrypted
    assert findings.archive_dangerous_members == ("a.lnk", "run.js", "setup.EXE")


@pytest.mark.parametrize(
    ("data", "expected"),
    [
        (S.PDF_JAVASCRIPT, ("javascript", "open_action")),
        (S.PDF_OBFUSCATED, ("javascript", "launch")),
        (S.PDF_PLAIN, ("open_action",)),
    ],
)
def test_pdf_active_content(data, expected):
    assert inspect_content(data).pdf_active == expected


def test_only_dangerous_pdf_actions_trigger_the_rule():
    assert "active_pdf" in score_email(email_with("a.pdf", S.PDF_JAVASCRIPT)).triggered
    # /OpenAction seul (zoom à l'ouverture) est courant dans les PDF légitimes.
    assert "active_pdf" not in score_email(email_with("a.pdf", S.PDF_PLAIN)).triggered


def test_html_attachment_asking_for_a_password_is_detected():
    email = email_with("connexion.html", S.HTML_LOGIN, "text", "html")
    (attachment,) = email.attachments
    assert attachment.content.credential_form
    assert {"dangerous_attachment", "credential_form_attachment"} <= set(
        score_email(email).triggered
    )
    assert not inspect_content(S.HTML_PLAIN).credential_form


# --------------------------------------------------------------------------- #
# Pas de faux positif sur le contenu légitime
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("filename", "data"),
    [
        ("contrat.doc", S.ole_file()),
        ("rapport.docx", S.docx()),
        ("photo.png", S.PNG),
        ("plan.pdf", S.PDF_PLAIN),
        ("notes.rtf", S.RTF_PLAIN),
        ("archive.zip", S.zip_file({"a.txt": b"x", "b.pdf": S.PDF_PLAIN})),
    ],
)
def test_legitimate_attachments_trigger_no_new_rule(filename, data):
    email = email_with(filename, data)
    (attachment,) = email.attachments
    assert not attachment.type_mismatch
    assert not NEW_RULES & set(score_email(email).triggered)


@pytest.mark.parametrize(
    "data",
    [
        b"MZ,Mozambique,2024\nFR,France,2024\n" * 10,  # « MZ » : code pays en tête d'un CSV
        b"MZ" + b"\x00" * 200,  # en-tête DOS sans signature PE
        b"MZ" + b"\x00" * 58 + (0x40).to_bytes(4, "little") + b"XX\x00\x00",  # mauvaise signature
        b"MZ" + b"\x00" * 58 + (0xFFFFFFF0).to_bytes(4, "little"),  # adresse hors du fichier
    ],
)
def test_text_starting_with_mz_is_not_an_executable(data):
    assert detect_type(data) != "pe_executable"
    (attachment,) = email_with("pays.csv", data, "text", "csv").attachments
    assert not attachment.type_mismatch
    assert score_email(email_with("pays.csv", data, "text", "csv")).verdict == "safe"


@pytest.mark.parametrize(
    "relation",
    [
        # Guillemets simples et espaces autour de « = » : du XML valide, à détecter aussi.
        (
            b"<Relationship Id='rId1' Type='http://schemas.openxmlformats.org/officeDocument/"
            b"2006/relationships/attachedTemplate' Target='https://t.example.test/t.dotm' "
            b"TargetMode = 'External'/>"
        ),
        (
            b'<pr:Relationship TargetMode="External" Target="https://t.example.test/t.dotm" '
            b'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/'
            b'attachedTemplate" Id="rId1"/>'
        ),
    ],
)
def test_remote_template_is_detected_whatever_the_xml_quoting(relation):
    rels = b"<Relationships>" + relation + b"</Relationships>"
    data = S.zip_file(
        {"[Content_Types].xml": S.CONTENT_TYPES, "word/_rels/settings.xml.rels": rels}
    )
    assert inspect_content(data).remote_template


def test_local_template_and_other_external_links_are_not_remote_templates():
    rels = (
        b'<Relationships><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/'
        b'officeDocument/2006/relationships/attachedTemplate" Target="Normal.dotm"/>'
        b'<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/'
        b'2006/relationships/hyperlink" Target="https://example.test/" TargetMode="External"/>'
        b"</Relationships>"
    )
    data = S.zip_file(
        {"[Content_Types].xml": S.CONTENT_TYPES, "word/_rels/settings.xml.rels": rels}
    )
    assert not inspect_content(data).remote_template


def test_unreadable_ooxml_member_keeps_the_other_findings(monkeypatch):
    # Un .rels illisible (compression inconnue, membre corrompu) ne doit pas effacer les
    # macros déjà trouvées.
    import zipfile

    def broken_open(self, *args, **kwargs):
        raise NotImplementedError("compression inconnue")

    data = S.docx(macros=True, remote_template=True)  # construit avant de casser open()
    monkeypatch.setattr(zipfile.ZipFile, "open", broken_open)
    findings = inspect_content(data)
    assert findings.macros and findings.detected_type == "ooxml"
    assert "ooxml_rels_unreadable" in findings.errors


def test_executable_with_its_real_name_is_not_a_mismatch():
    (attachment,) = email_with("outil.exe", S.PE).attachments
    assert attachment.effective_risk == "executable" and not attachment.type_mismatch


@pytest.mark.parametrize("fixture", ["01_legit_newsletter.eml", "09_plain_french_qp.eml"])
def test_legitimate_fixtures_are_unchanged(fixture):
    email = parse_eml((FIXTURES / fixture).read_bytes())
    assert not NEW_RULES & set(score_email(email).triggered)
    features = email_features(email)
    assert all(features[name] == 0 for name in NEW_RULES)


# --------------------------------------------------------------------------- #
# Robustesse : fichiers hostiles, limites, garanties du parseur
# --------------------------------------------------------------------------- #


@settings(max_examples=300, deadline=None)
@given(
    st.sampled_from([b"", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", b"PK\x03\x04", b"%PDF-", b"{\\rtf"]),
    st.binary(max_size=4096),
)
def test_hostile_bytes_never_raise(prefix, tail):
    findings = inspect_content(prefix + tail)
    assert isinstance(findings, ContentFindings)


@pytest.mark.parametrize(
    ("data", "error"),
    [
        (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 100, "ole_unreadable"),
        (b"PK\x03\x04" + b"\xff" * 100, "zip_unreadable"),
    ],
)
def test_corrupted_containers_are_reported(data, error):
    assert error in inspect_content(data).errors


def test_zip_bomb_is_never_decompressed():
    bomb = S.zip_file({"zeros.bin": b"\x00" * 50_000_000})  # 50 Mo qui tiennent en ~50 Ko
    assert len(bomb) < 200_000
    start = time.perf_counter()
    findings = inspect_content(bomb)
    assert time.perf_counter() - start < 1.0
    assert findings.archive_entries == 1 and not findings.errors


def test_oversized_content_is_truncated_and_inspection_stays_fast():
    data = S.PDF_PLAIN + b"x" * 12_000_000
    start = time.perf_counter()
    findings = inspect_content(data)
    assert time.perf_counter() - start < 3.0
    assert "content_truncated" in findings.errors and findings.detected_type == "pdf"


def test_inspection_can_be_disabled():
    msg = EmailMessage()
    msg["From"] = "a@example.test"
    msg.set_content("x")
    msg.add_attachment(S.PE, maintype="application", subtype="pdf", filename="facture.pdf")
    email = parse_eml(msg.as_bytes(), limits=EmailLimits(inspect_attachments=False))
    (attachment,) = email.attachments
    assert attachment.content == ContentFindings() and not attachment.type_mismatch


def test_attachment_serialization_includes_the_findings():
    (attachment,) = email_with("facture.pdf", S.PE).attachments
    data = attachment.to_dict()
    assert data["content"]["detected_type"] == "pe_executable"
    assert data["content"]["family"] == "executable"
    assert data["type_mismatch"] is True and data["effective_risk"] == "executable"
