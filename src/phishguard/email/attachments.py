"""Inspection du contenu des pièces jointes (étape 2.13).

Le parseur (étape 1.10) juge une pièce jointe sur son **nom**. Un attaquant contourne
facilement ce contrôle : exécutable renommé ``facture.pdf``, document Word ancien
format (``.doc``, sans « m ») plein de macros, ``.docx`` renommé qui cache un projet
VBA, archive chiffrée dont le mot de passe est dans le corps du message. Ce module
regarde le **contenu** :

1. **vrai type** du fichier, par sa signature (ses premiers octets) ;
2. **macros VBA** : documents OLE (Office 97-2003, via ``olefile``) et OOXML
   (``vbaProject.bin``) ; **modèle distant** d'un document Word (injection de modèle) ;
   objets OLE embarqués dans un RTF ;
3. **archives ZIP** listées **sans extraction** : exécutable ou script à l'intérieur,
   archive chiffrée ;
4. **PDF** à contenu actif (``/JavaScript``, ``/Launch``, fichier embarqué), y compris
   avec des noms obfusqués (``/J#61vaScript``) ;
5. **page HTML** jointe qui demande un mot de passe.

Règles de sécurité, car le fichier est hostile et peut viser le parseur lui-même :

- rien n'est exécuté, ouvert dans une application, extrait sur disque ni envoyé à un
  tiers : tout se passe en mémoire, sur les octets déjà décodés du message ;
- aucun membre d'archive n'est décompressé (une bombe zip est donc sans effet), sauf
  les petits fichiers XML d'un document OOXML, bornés à 64 Ko ;
- chaque lecture est bornée (:class:`InspectionLimits`) ;
- :func:`inspect_content` ne lève jamais : un fichier illisible donne un constat vide
  et une erreur notée dans ``errors``.

Ce que le module ne fait pas : il ne décompresse pas les flux des PDF (un JavaScript
caché dans un flux compressé n'est pas vu), ne lit ni RAR ni 7z (signalés comme
archives, contenu inconnu), et ne détecte pas les macros Excel 4.0 (XLM), ni le VBA des
présentations PowerPoint 97-2003 (stocké dans un flux binaire propre à PowerPoint).
"""

from __future__ import annotations

import io
import re
import struct
import zipfile
import zlib
from dataclasses import asdict, dataclass, field

import olefile

# Types reconnus par signature, et famille de risque correspondante (mêmes noms que
# parser.RISKY_EXTENSIONS). None : type sans risque particulier.
TYPE_FAMILIES: dict[str, str | None] = {
    "pe_executable": "executable",
    "elf_executable": "executable",
    "macho_executable": "executable",
    "jar": "executable",
    "lnk": "script",
    "shell_script": "script",
    "html": "html",
    "iso": "disk_image",
    "zip": "archive",
    "rar": "archive",
    "7z": "archive",
    "gzip": "archive",
    "cab": "archive",
    "ole": None,  # document Office 97-2003 (ou MSI) : risque selon les macros
    "ooxml": None,
    "odf": None,
    "pdf": None,
    "rtf": None,
    "png": None,
    "jpeg": None,
    "gif": None,
}
# Types qu'aucune extension de document ou d'image ne devrait cacher.
DANGEROUS_TYPES = frozenset(
    {"pe_executable", "elf_executable", "macho_executable", "jar", "lnk", "shell_script",
     "html", "iso"}
)  # fmt: skip
# Extensions de membres d'archive dangereux (sous-ensemble de parser.RISKY_EXTENSIONS,
# dupliqué ici pour éviter une importation circulaire).
DANGEROUS_MEMBER_EXTENSIONS = frozenset(
    {"exe", "scr", "com", "pif", "bat", "cmd", "msi", "dll", "cpl", "jar", "js", "jse",
     "vbs", "vbe", "wsf", "wsh", "hta", "ps1", "lnk", "url", "iso", "img", "vhd", "vhdx",
     "docm", "xlsm", "pptm", "htm", "html", "svg"}
)  # fmt: skip
PDF_ACTIVE_NAMES = {
    b"javascript": "javascript",
    b"js": "javascript",
    b"launch": "launch",
    b"embeddedfile": "embedded_file",
    b"embeddedfiles": "embedded_file",
    b"submitform": "submit_form",
    b"openaction": "open_action",  # courant dans les PDF légitimes (zoom à l'ouverture)
}
# Noms de stockages OLE qui contiennent un projet VBA (Word : Macros/VBA, Excel :
# _VBA_PROJECT_CUR/VBA).
OLE_VBA_STORAGES = frozenset({"macros", "_vba_project_cur", "vba"})

_PDF_NAME = re.compile(rb"/([A-Za-z0-9#]{1,40})")
_HEX_ESCAPE = re.compile(rb"#([0-9A-Fa-f]{2})")
# Éléments <Relationship …> d'un fichier .rels. Les attributs XML acceptent les deux
# guillemets et des espaces autour de « = » : chercher une chaîne exacte se contourne.
_RELATIONSHIP = re.compile(rb"<\s*(?:\w+:)?relationship\b[^>]*>", re.IGNORECASE)
_EXTERNAL_MODE = re.compile(rb"\btargetmode\s*=\s*[\"']\s*external\s*[\"']", re.IGNORECASE)
_PASSWORD_INPUT = re.compile(rb"<input\b[^>]{0,500}?type\s*=\s*[\"']?password", re.IGNORECASE)
_HTML_START = re.compile(rb"^\s*(<!doctype\s+html|<html|<head|<body|<script|<form|<meta|<svg)",
                         re.IGNORECASE)  # fmt: skip


@dataclass(frozen=True)
class InspectionLimits:
    max_bytes: int = 10 * 1024 * 1024  # contenu inspecté par pièce jointe
    max_zip_entries: int = 1_000
    max_ole_entries: int = 2_000
    max_xml_member_bytes: int = 64 * 1024  # fichiers XML d'OOXML lus pour le modèle distant
    max_pdf_scan_bytes: int = 5 * 1024 * 1024
    max_html_scan_bytes: int = 2 * 1024 * 1024
    max_listed_members: int = 10  # membres dangereux gardés dans le constat


@dataclass(frozen=True)
class ContentFindings:
    detected_type: str | None = None
    macros: bool = False
    remote_template: bool = False  # document Word qui charge un modèle distant
    rtf_objects: bool = False  # objets OLE embarqués dans un RTF
    archive_entries: int = 0
    archive_encrypted: bool = False
    archive_dangerous_members: tuple[str, ...] = ()
    pdf_active: tuple[str, ...] = ()
    credential_form: bool = False  # page HTML qui demande un mot de passe
    errors: tuple[str, ...] = field(default=())

    @property
    def family(self) -> str | None:
        """Famille de risque du contenu réel (``executable``, ``archive``…), ou None."""
        if self.macros:
            return "macro_document"
        return TYPE_FAMILIES.get(self.detected_type or "")

    def to_dict(self) -> dict[str, object]:
        return {**asdict(self), "family": self.family}


# --------------------------------------------------------------------------- #
# Type par signature
# --------------------------------------------------------------------------- #


def detect_type(data: bytes) -> str | None:
    """Type du fichier d'après sa signature, ou None s'il n'est pas reconnu."""
    head = data[:16]
    if head.startswith(b"MZ") and _has_pe_header(data):
        return "pe_executable"
    if head.startswith(b"\x7fELF"):
        return "elf_executable"
    if head[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe",
                    b"\xcf\xfa\xed\xfe"):  # fmt: skip
        return "macho_executable"
    if head.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return "ole"
    if head.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
        return "zip"  # précisé en ooxml, odf ou jar par l'inspection de l'archive
    if head.startswith(b"Rar!\x1a\x07"):
        return "rar"
    if head.startswith(b"7z\xbc\xaf\x27\x1c"):
        return "7z"
    if head.startswith(b"\x1f\x8b"):
        return "gzip"
    if head.startswith(b"MSCF"):
        return "cab"
    if head.startswith(b"{\\rtf"):
        return "rtf"
    if head.startswith(b"L\x00\x00\x00\x01\x14\x02\x00"):
        return "lnk"
    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if head.startswith(b"\xff\xd8\xff"):
        return "jpeg"
    if head.startswith((b"GIF87a", b"GIF89a")):
        return "gif"
    if b"%PDF-" in data[:1024]:  # la norme tolère des octets avant l'en-tête
        return "pdf"
    if any(data[offset : offset + 5] == b"CD001" for offset in (0x8001, 0x8801, 0x9001)):
        return "iso"
    if head.startswith(b"#!"):
        return "shell_script"
    text = data[:1024].lstrip(b"\xef\xbb\xbf")  # BOM UTF-8
    if _HTML_START.match(text):
        return "html"
    return None


def _has_pe_header(data: bytes) -> bool:
    """Signature ``PE\\0\\0`` à l'adresse lue en 0x3C (``e_lfanew``), comme le chargeur Windows.

    « MZ » seul ne suffit pas : un texte peut commencer par ces deux lettres (code pays du
    Mozambique en tête d'un CSV). Un exécutable Windows a toujours son en-tête PE, dans les
    premiers kilo-octets du fichier.
    """
    if len(data) < 0x40:
        return False
    (offset,) = struct.unpack_from("<I", data, 0x3C)
    return 0x40 <= offset <= 0x10000 and data[offset : offset + 4] == b"PE\x00\x00"


# --------------------------------------------------------------------------- #
# Inspection
# --------------------------------------------------------------------------- #


def inspect_content(data: bytes, limits: InspectionLimits | None = None) -> ContentFindings:
    """Constats sur le contenu d'une pièce jointe. Ne lève jamais."""
    limits = limits or InspectionLimits()
    errors: list[str] = []
    if len(data) > limits.max_bytes:
        errors.append("content_truncated")
        data = data[: limits.max_bytes]
    try:
        detected = detect_type(data)
        findings: dict[str, object] = {"detected_type": detected}
        if detected == "ole":
            findings["macros"] = _ole_has_vba(data, limits, errors)
        elif detected == "zip":
            findings.update(_inspect_zip(data, limits, errors))
        elif detected == "pdf":
            findings["pdf_active"] = _pdf_active(data[: limits.max_pdf_scan_bytes])
        elif detected == "rtf":
            findings["rtf_objects"] = b"\\objdata" in data or b"\\objupdate" in data
        if detected == "html" or (detected is None and b"<" in data[:4096]):
            scan = data[: limits.max_html_scan_bytes]
            findings["credential_form"] = _PASSWORD_INPUT.search(scan) is not None
        return ContentFindings(**findings, errors=tuple(errors))  # type: ignore[arg-type]
    except Exception as exc:  # noqa: BLE001 : un fichier hostile ne doit rien casser
        return ContentFindings(errors=(*errors, f"inspection_failed:{type(exc).__name__}"))


def _ole_has_vba(data: bytes, limits: InspectionLimits, errors: list[str]) -> bool:
    try:
        ole = olefile.OleFileIO(io.BytesIO(data))
    except Exception:  # noqa: BLE001 : OLE corrompu ou volontairement malformé
        errors.append("ole_unreadable")
        return False
    try:
        entries = ole.listdir(streams=True, storages=True)
        if len(entries) > limits.max_ole_entries:
            errors.append("ole_entries_truncated")
            entries = entries[: limits.max_ole_entries]
        return any(part.lower() in OLE_VBA_STORAGES for path in entries for part in path)
    finally:
        ole.close()


def _inspect_zip(data: bytes, limits: InspectionLimits, errors: list[str]) -> dict[str, object]:
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except (zipfile.BadZipFile, ValueError, OSError, EOFError):
        errors.append("zip_unreadable")
        return {}
    with archive:
        infos = archive.infolist()
        if len(infos) > limits.max_zip_entries:
            errors.append("zip_entries_truncated")
            infos = infos[: limits.max_zip_entries]
        names = {info.filename for info in infos}
        lowered = {name.lower() for name in names}
        result: dict[str, object] = {
            "archive_entries": len(infos),
            "archive_encrypted": any(info.flag_bits & 0x1 for info in infos),
        }
        if "[content_types].xml" in lowered:
            result["detected_type"] = "ooxml"
            result["macros"] = any(name.endswith("vbaproject.bin") for name in lowered)
            result["remote_template"] = _remote_template(archive, infos, limits, errors)
            return result
        if "mimetype" in lowered and any(n.startswith("meta-inf/manifest.xml") for n in lowered):
            result["detected_type"] = "odf"
            result["macros"] = any(n.startswith("basic/") for n in lowered)
            return result
        if "meta-inf/manifest.mf" in lowered and any(n.endswith(".class") for n in lowered):
            result["detected_type"] = "jar"
            return result
        dangerous = sorted(
            name
            for name in names
            if not name.endswith("/") and _extension(name) in DANGEROUS_MEMBER_EXTENSIONS
        )
        result["archive_dangerous_members"] = tuple(dangerous[: limits.max_listed_members])
        return result


def _remote_template(
    archive: zipfile.ZipFile,
    infos: list[zipfile.ZipInfo],
    limits: InspectionLimits,
    errors: list[str],
) -> bool:
    """Document Word qui charge son modèle depuis le réseau (injection de modèle)."""
    for info in infos:
        name = info.filename.lower()
        if not (name.endswith(".rels") and "settings" in name):
            continue
        if info.file_size > limits.max_xml_member_bytes or info.flag_bits & 0x1:
            errors.append("ooxml_rels_skipped")
            continue
        try:
            with archive.open(info) as member:
                xml = member.read(limits.max_xml_member_bytes)
        except (zipfile.BadZipFile, NotImplementedError, RuntimeError, OSError, EOFError,
                zlib.error):  # fmt: skip
            # Membre corrompu ou compression inconnue : les autres constats sont gardés.
            errors.append("ooxml_rels_unreadable")
            continue
        for relation in _RELATIONSHIP.findall(xml):
            if b"attachedtemplate" in relation.lower() and _EXTERNAL_MODE.search(relation):
                return True
    return False


def _pdf_active(data: bytes) -> tuple[str, ...]:
    """Noms actifs d'un PDF, y compris obfusqués par échappement (``/J#61vaScript``)."""
    found = set()
    for match in _PDF_NAME.finditer(data):
        raw = match.group(1)
        name = _HEX_ESCAPE.sub(lambda m: bytes([int(m.group(1), 16)]), raw) if b"#" in raw else raw
        label = PDF_ACTIVE_NAMES.get(name.lower())
        if label:
            found.add(label)
    return tuple(sorted(found))


def _extension(name: str) -> str | None:
    base = name.rsplit("/", 1)[-1].lower().rstrip(". ")
    return base.rsplit(".", 1)[-1] if "." in base else None
