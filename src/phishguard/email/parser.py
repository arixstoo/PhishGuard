"""Parseur défensif d'emails bruts (``.eml``) (étape 1.10).

Un email est une **entrée hostile** : taille démesurée, imbrication profonde, en-têtes
malformés, jeux de caractères inconnus, HTML piégé. Règles :

1. Rien n'est rendu, exécuté, ouvert ni téléchargé : bibliothèque standard ``email``
   pour la structure, BeautifulSoup (``html.parser``) pour le HTML.
2. Tout est borné (:class:`EmailLimits`) : taille du message, nombre de parties,
   profondeur d'imbrication, liens, pièces jointes, texte conservé. Un message trop gros
   est refusé (:class:`EmailTooLargeError`) ; les autres dépassements tronquent et sont
   notés dans ``defects``.
3. Aucune autre exception ne sort de :func:`parse_eml` : une étape qui échoue sur un
   message malformé est notée dans ``defects`` et le reste de l'analyse continue. Le
   fuzzing du module 4 vérifiera cette garantie à grande échelle.

Signaux extraits (utilisés par le score de l'étape 1.11) : résultats SPF, DKIM et DMARC
(:mod:`phishguard.email.auth`), cohérence des domaines ``From`` / ``Reply-To`` /
``Return-Path``, nom affiché qui imite une autre adresse, liens dont le texte affiché
diffère de la cible, formulaires, pièces jointes à risque et texte masqué
(:mod:`phishguard.email.html`).
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import asdict, dataclass, field
from email import policy
from email.message import EmailMessage, Message
from email.parser import BytesParser
from email.utils import getaddresses, parseaddr
from typing import Any

from phishguard.email.auth import AuthResults, read_auth_results
from phishguard.email.html import (
    HiddenText,
    Link,
    analyze_html,
    count_zero_width,
    registered_domain,
    text_links,
)

# Extensions à risque, par famille. Comparées en minuscules à la dernière extension.
RISKY_EXTENSIONS: dict[str, frozenset[str]] = {
    "executable": frozenset(
        {"exe", "scr", "com", "pif", "bat", "cmd", "msi", "msix", "dll", "cpl", "jar", "app"}
    ),
    "script": frozenset(
        {"js", "jse", "vbs", "vbe", "wsf", "wsh", "hta", "ps1", "psm1", "sh", "py", "lnk", "url"}
    ),
    "macro_document": frozenset({"docm", "dotm", "xlsm", "xltm", "xlam", "pptm", "ppam", "sldm"}),
    "html": frozenset({"htm", "html", "shtml", "xhtml", "svg", "mht", "mhtml"}),
    "disk_image": frozenset({"iso", "img", "vhd", "vhdx"}),
    "archive": frozenset({"zip", "rar", "7z", "gz", "tgz", "ace", "arj", "cab", "xz", "bz2"}),
}
# Extensions qu'un attaquant met en avant dans « facture.pdf.exe ».
DECOY_EXTENSIONS = frozenset(
    {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "jpg", "jpeg", "png", "csv"}
)
# Caractère de contrôle U+202E : « facture<RTLO>fdp.exe » s'affiche « factureexe.pdf ».
RTLO = "\u202e"
_EMAIL_IN_TEXT_RE = re.compile(r"[\w.+-]+@([\w-]+(?:\.[\w-]+)+)")
_DOMAIN_IN_TEXT_RE = re.compile(r"\b((?:[\w-]+\.)+[a-z]{2,24})\b", re.IGNORECASE)


class EmailTooLargeError(ValueError):
    """Le message dépasse :attr:`EmailLimits.max_bytes` : il n'est pas analysé."""


@dataclass(frozen=True)
class EmailLimits:
    max_bytes: int = 10 * 1024 * 1024
    max_parts: int = 200
    max_depth: int = 10
    max_links: int = 500
    max_attachments: int = 100
    max_html_chars: int = 2_000_000
    # Pour tout le message. Le coût de html.parser croît plus vite que le nombre de
    # balises (200 000 : une vingtaine de secondes) ; une lettre d'information en compte
    # quelques milliers.
    max_html_tags: int = 50_000
    max_text_chars: int = 100_000
    # En-têtes du message principal. Sur 200 emails Phishing Pot : 37 Ko, 96 champs et
    # 21 Ko pour le plus long champ, au plus. Sans borne, la bibliothèque standard met
    # plusieurs minutes sur 10 Mio d'en-têtes « From » ou un « Subject » géant.
    max_header_bytes: int = 128 * 1024
    max_headers: int = 500
    max_header_field_bytes: int = 32 * 1024


@dataclass(frozen=True)
class Address:
    display_name: str
    address: str
    domain: str | None  # domaine de l'adresse, en minuscules
    registered_domain: str | None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class Attachment:
    filename: str | None
    content_type: str
    size: int
    extension: str | None
    risk: str | None  # famille de RISKY_EXTENSIONS, ou None
    double_extension: bool
    rtlo: bool

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass
class ParsedEmail:
    subject: str = ""
    from_: Address | None = None
    reply_to: list[Address] = field(default_factory=list)
    return_path: Address | None = None
    date: str | None = None
    message_id: str | None = None
    auth: AuthResults = field(default_factory=AuthResults)
    reply_to_differs: bool = False
    return_path_differs: bool = False
    display_name_spoof: bool = False
    mailing_list: bool = False  # en-tête List-Id ou List-Post (RFC 2919, RFC 2369)
    text: str = ""
    has_html: bool = False
    links: list[Link] = field(default_factory=list)
    forms: int = 0
    attachments: list[Attachment] = field(default_factory=list)
    hidden_text: HiddenText = field(default_factory=HiddenText)
    zero_width_chars: int = 0
    parts: int = 0
    defects: list[str] = field(default_factory=list)

    @property
    def mismatched_links(self) -> list[Link]:
        return [link for link in self.links if link.mismatch]

    @property
    def risky_attachments(self) -> list[Attachment]:
        return [a for a in self.attachments if a.risk or a.double_extension or a.rtlo]

    def to_dict(self) -> dict[str, Any]:
        """Forme sérialisable en JSON (pour la CLI, l'API et les tests)."""
        return {
            "subject": self.subject,
            "from": None if self.from_ is None else self.from_.to_dict(),
            "reply_to": [a.to_dict() for a in self.reply_to],
            "return_path": None if self.return_path is None else self.return_path.to_dict(),
            "date": self.date,
            "message_id": self.message_id,
            "auth": self.auth.to_dict(),
            "reply_to_differs": self.reply_to_differs,
            "return_path_differs": self.return_path_differs,
            "display_name_spoof": self.display_name_spoof,
            "mailing_list": self.mailing_list,
            "text": self.text,
            "has_html": self.has_html,
            "links": [link.to_dict() for link in self.links],
            "forms": self.forms,
            "attachments": [a.to_dict() for a in self.attachments],
            "hidden_text": self.hidden_text.to_dict(),
            "zero_width_chars": self.zero_width_chars,
            "parts": self.parts,
            "defects": list(self.defects),
        }


# --------------------------------------------------------------------------- #
# Adresses
# --------------------------------------------------------------------------- #


def make_address(display_name: str, address: str) -> Address | None:
    address = address.strip().strip("<>").strip()
    if not address and not display_name:
        return None
    domain = address.rsplit("@", 1)[1].lower().rstrip(".") if "@" in address else None
    return Address(
        display_name=display_name.strip(),
        address=address,
        domain=domain or None,
        registered_domain=registered_domain(domain) if domain else None,
    )


def _header(msg: Message, name: str) -> str | None:
    value = msg.get(name)
    return None if value is None else str(value)


def _addresses(msg: Message, name: str) -> list[Address]:
    values = msg.get_all(name) or []
    pairs = getaddresses([str(v) for v in values])
    return [a for a in (make_address(n, e) for n, e in pairs) if a is not None]


def display_name_domain(display_name: str) -> str | None:
    """Domaine enregistré d'une adresse ou d'un domaine écrit dans le nom affiché.

    ``"service@paypal.com" <x@evil.example>`` : le nom affiché imite une adresse PayPal.
    """
    match = _EMAIL_IN_TEXT_RE.search(display_name) or _DOMAIN_IN_TEXT_RE.search(display_name)
    return registered_domain(match.group(1)) if match else None


def _differs(a: Address | None, b: Address | None) -> bool:
    return (
        a is not None
        and b is not None
        and a.registered_domain is not None
        and b.registered_domain is not None
        and a.registered_domain != b.registered_domain
    )


# --------------------------------------------------------------------------- #
# Parties
# --------------------------------------------------------------------------- #


def _walk(msg: Message, limits: EmailLimits, defects: list[str]) -> Iterator[Message]:
    """Parties du message en profondeur, avec bornes de profondeur et de nombre."""
    stack: list[tuple[Message, int]] = [(msg, 0)]
    seen = 0
    while stack:
        part, depth = stack.pop()
        seen += 1
        if seen > limits.max_parts:
            defects.append(f"parts_truncated:{limits.max_parts}")
            return
        yield part
        if not part.is_multipart():
            continue
        if depth >= limits.max_depth:
            defects.append(f"depth_truncated:{limits.max_depth}")
            continue
        payload = part.get_payload()
        children = payload if isinstance(payload, list) else []
        stack.extend(
            (child, depth + 1) for child in reversed(children) if isinstance(child, Message)
        )


def _decoded_text(part: Message, defects: list[str]) -> str:
    """Contenu texte d'une partie, sans jamais lever (jeu de caractères inconnu, etc.)."""
    if isinstance(part, EmailMessage):
        try:
            content = part.get_content()
            if isinstance(content, str):
                return content
        except (LookupError, UnicodeError, ValueError, AssertionError, KeyError, TypeError):
            defects.append("content_decoding_fallback")
    payload = part.get_payload(decode=True)
    if not isinstance(payload, bytes):
        return ""
    charset = part.get_content_charset() or "utf-8"
    try:
        return payload.decode(charset, errors="replace")
    except LookupError:
        return payload.decode("utf-8", errors="replace")


def _filename(part: Message, defects: list[str]) -> str | None:
    try:
        name = part.get_filename()
    except (ValueError, LookupError, UnicodeError, TypeError, IndexError):
        defects.append("filename_unreadable")
        return None
    return str(name) if name else None


def make_attachment(part: Message, filename: str | None) -> Attachment:
    payload = part.get_payload(decode=True)
    size = len(payload) if isinstance(payload, bytes) else 0
    name = filename or ""
    rtlo = RTLO in name
    # Avec un RTLO, l'extension réelle est celle des caractères stockés, pas celle affichée.
    clean = name.replace(RTLO, "").strip().rstrip(".").lower()
    pieces = clean.rsplit("/", 1)[-1].split(".")
    extension = pieces[-1] if len(pieces) > 1 and pieces[-1] else None
    risk = next((family for family, exts in RISKY_EXTENSIONS.items() if extension in exts), None)
    double = (
        len(pieces) > 2
        and pieces[-2] in DECOY_EXTENSIONS
        and risk is not None
        and risk != "archive"
    )
    return Attachment(
        filename=filename,
        content_type=part.get_content_type(),
        size=size,
        extension=extension,
        risk=risk,
        double_extension=double,
        rtlo=rtlo,
    )


def _nth_offset(data: str | bytes, needle: Any, allowed: int) -> int | None:
    """Position de l'occurrence n° ``allowed + 1`` de ``needle``, ou ``None``."""
    position = -1
    for _ in range(max(allowed, 0) + 1):
        position = data.find(needle, position + 1)
        if position < 0:
            return None
    return position


_HEADER_END_RE = re.compile(rb"\r?\n\r?\n")
_FIELD_START_RE = re.compile(rb"\n(?![ \t])")  # une ligne qui ne continue pas la précédente


def _bound_headers(raw: bytes, limits: EmailLimits) -> tuple[bytes, bool]:
    """Borne les en-têtes du message principal avant l'analyse.

    Garde les ``max_headers`` premiers champs (les plus récents, dont celui du serveur de
    réception), coupe chaque champ à ``max_header_field_bytes`` et le bloc entier à
    ``max_header_bytes``. Le corps n'est pas touché.
    """
    end = _HEADER_END_RE.search(raw)
    split = end.start() if end else len(raw)
    header, body = raw[:split], raw[split:]
    if len(header) <= limits.max_header_field_bytes and header.count(b"\n") < limits.max_headers:
        return raw, False  # cas courant : rien à borner
    starts = [0]
    for match in _FIELD_START_RE.finditer(header):
        starts.append(match.end())
        if len(starts) > limits.max_headers:
            break
    ends = [s - 1 for s in starts[1:]] + [len(header)]
    fields = [
        header[start:stop][: limits.max_header_field_bytes]
        for start, stop in list(zip(starts, ends, strict=True))[: limits.max_headers]
    ]
    bounded = b"\n".join(fields)[: limits.max_header_bytes]
    if bounded == header:
        return raw, False
    return bounded.rstrip(b"\r") + body, True


def _tag_limit_offset(html: str, max_tags: int) -> int | None:
    """Position du « < » qui ouvre la balise n° ``max_tags + 1``, ou ``None``."""
    return _nth_offset(html, "<", max_tags)


def _is_attachment(part: Message, filename: str | None) -> bool:
    disposition = part.get_content_disposition()
    if disposition == "attachment":
        return True
    if part.is_multipart() or part.get_content_maintype() == "message":
        return False
    if part.get_content_type() in ("text/plain", "text/html") and disposition != "attachment":
        return False
    return filename is not None or part.get_content_maintype() in ("application", "audio", "video")


# --------------------------------------------------------------------------- #
# Point d'entrée
# --------------------------------------------------------------------------- #


def _step(result: ParsedEmail, name: str, func: Any, *args: Any) -> Any:
    """Exécute une étape ; sur une erreur inattendue, la note et continue."""
    try:
        return func(*args)
    except RecursionError:
        result.defects.append(f"{name}_failed:RecursionError")
    # Entrée hostile : aucune exception ne doit sortir du parseur (garantie documentée).
    except Exception as exc:  # noqa: BLE001
        result.defects.append(f"{name}_failed:{type(exc).__name__}")
    return None


def parse_eml(
    raw: bytes,
    limits: EmailLimits | None = None,
    *,
    trusted_authserv_ids: list[str] | None = None,
) -> ParsedEmail:
    """Analyse un email brut et retourne ses signaux.

    Lève :class:`EmailTooLargeError` si ``raw`` dépasse ``limits.max_bytes``, et
    ``TypeError`` si ``raw`` n'est pas de type ``bytes``. Ne lève rien d'autre.
    """
    if not isinstance(raw, bytes | bytearray):
        raise TypeError("parse_eml attend le message brut en bytes")
    limits = limits or EmailLimits()
    if len(raw) > limits.max_bytes:
        raise EmailTooLargeError(f"message de {len(raw)} octets (limite {limits.max_bytes})")

    result = ParsedEmail()
    raw = bytes(raw)
    # La bibliothèque standard analyse toutes les parties avant que max_parts ne joue :
    # 10 Mio découpés en 100 000 parties minuscules, c'est une vingtaine de secondes. On
    # coupe donc avant l'analyse quand les lignes de délimiteur (« --… ») sont bien plus
    # nombreuses que ce que max_parts laissera lire.
    cut = _nth_offset(raw, b"\n--", 4 * limits.max_parts)
    if cut is not None:
        result.defects.append(f"mime_truncated:{limits.max_parts}")
        raw = raw[:cut]
    raw, headers_cut = _bound_headers(raw, limits)
    if headers_cut:
        result.defects.append("headers_truncated")
    msg = _step(result, "structure", BytesParser(policy=policy.default).parsebytes, raw)
    if msg is None:
        return result
    result.defects.extend(type(d).__name__ for d in getattr(msg, "defects", []))

    # Étapes séparées : un « From » piégé qui fait échouer la lecture des expéditeurs ne
    # doit pas faire perdre l'authentification.
    _step(result, "headers", _read_headers, msg, result)
    _step(result, "auth", _read_auth, msg, result, trusted_authserv_ids)
    _step(result, "body", _read_body, msg, result, limits)
    return result


def _read_headers(msg: Message, result: ParsedEmail) -> None:
    result.subject = _header(msg, "Subject") or ""
    result.date = _header(msg, "Date")
    result.message_id = _header(msg, "Message-ID")
    # « "Service client", _ <x@y> » (virgule hors des guillemets) se découpe en deux
    # entrées dont la première n'a pas d'adresse : on garde la première vraie adresse.
    senders = _addresses(msg, "From")
    with_address = [a for a in senders if a.domain is not None]
    result.from_ = with_address[0] if with_address else (senders[0] if senders else None)
    if len(with_address) > 1:
        result.defects.append("multiple_from")
    result.reply_to = _addresses(msg, "Reply-To")
    return_path = _header(msg, "Return-Path")
    if return_path:
        result.return_path = make_address(*parseaddr(return_path))

    result.reply_to_differs = any(_differs(result.from_, r) for r in result.reply_to)
    result.mailing_list = msg.get("List-Id") is not None or msg.get("List-Post") is not None
    result.return_path_differs = _differs(result.from_, result.return_path)
    if result.from_ is not None and result.from_.registered_domain is not None:
        shown = display_name_domain(result.from_.display_name)
        result.display_name_spoof = shown is not None and shown != result.from_.registered_domain


def _read_auth(msg: Message, result: ParsedEmail, trusted: list[str] | None) -> None:
    result.auth = read_auth_results(
        [str(v) for v in msg.get_all("Authentication-Results") or []],
        [str(v) for v in msg.get_all("Received-SPF") or []],
        trusted,
    )


def _read_body(msg: Message, result: ParsedEmail, limits: EmailLimits) -> None:
    plain_parts: list[str] = []
    html_texts: list[str] = []
    tags_left = limits.max_html_tags
    for part in _walk(msg, limits, result.defects):
        result.parts += 1
        result.defects.extend(
            type(d).__name__ for d in getattr(part, "defects", []) if part is not msg
        )
        if part.is_multipart():
            continue
        filename = _filename(part, result.defects)
        if _is_attachment(part, filename):
            if len(result.attachments) >= limits.max_attachments:
                defect = f"attachments_truncated:{limits.max_attachments}"
                if defect not in result.defects:
                    result.defects.append(defect)
                continue
            result.attachments.append(make_attachment(part, filename))
            continue
        content_type = part.get_content_type()
        if content_type == "text/plain":
            plain_parts.append(_decoded_text(part, result.defects))
        elif content_type == "text/html":
            html = _decoded_text(part, result.defects)
            if len(html) > limits.max_html_chars:
                result.defects.append(f"html_truncated:{limits.max_html_chars}")
                html = html[: limits.max_html_chars]
            # Budget de balises commun à toutes les parties HTML du message.
            cut = _tag_limit_offset(html, tags_left)
            if cut is not None:
                defect = f"html_tags_truncated:{limits.max_html_tags}"
                if defect not in result.defects:
                    result.defects.append(defect)
                html = html[:cut]
            tags_left -= html.count("<")
            result.has_html = True
            remaining = max(0, limits.max_links - len(result.links))
            analysis = analyze_html(html, max_links=remaining)
            if analysis.truncated_links:
                result.defects.append(f"links_truncated:{limits.max_links}")
            result.links.extend(analysis.links)
            result.forms += analysis.forms
            result.hidden_text.elements += analysis.hidden.elements
            result.hidden_text.chars += analysis.hidden.chars
            result.hidden_text.reasons.update(analysis.hidden.reasons)
            html_texts.append(analysis.text)

    # Texte de référence : la partie texte brut si elle existe, sinon le HTML visible.
    text = "\n".join(plain_parts) if any(p.strip() for p in plain_parts) else "\n".join(html_texts)
    result.zero_width_chars = count_zero_width("\n".join(plain_parts)) + count_zero_width(
        "\n".join(html_texts)
    )
    if not result.has_html:
        remaining = max(0, limits.max_links - len(result.links))
        result.links.extend(text_links(text, remaining))
    if len(text) > limits.max_text_chars:
        result.defects.append(f"text_truncated:{limits.max_text_chars}")
        text = text[: limits.max_text_chars]
    result.text = text
