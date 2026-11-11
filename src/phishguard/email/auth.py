"""Résultats d'authentification SPF, DKIM et DMARC (étape 1.10).

Le serveur qui reçoit un email vérifie SPF (RFC 7208), DKIM (RFC 6376) et DMARC
(RFC 7489), puis **ajoute en tête** un en-tête ``Authentication-Results`` (RFC 8601) :

    Authentication-Results: mx.example.net;
        spf=pass smtp.mailfrom=sender.example; dkim=pass header.d=sender.example;
        dmarc=pass header.from=sender.example

**Seul l'en-tête du dernier serveur de réception est fiable.** Un attaquant peut écrire
lui-même des ``Authentication-Results: …; dmarc=pass`` dans son message : ils arrivent
plus bas dans l'en-tête, sous celui ajouté par le serveur de l'utilisateur. On lit donc
le **premier** en-tête ``Authentication-Results`` (le plus récent), ou, si
``trusted_authserv_ids`` est fourni, le premier dont l'identifiant de serveur en fait
partie. ``Received-SPF`` (RFC 7208, § 9.1) sert de repli pour SPF seulement, sauf s'il
est l'en-tête d'authentification le plus haut et qu'aucun serveur de confiance n'est
configuré : un échec SPF qu'il signale prime alors sur un ``Authentication-Results``
placé dessous (jamais l'inverse : un ``pass`` en tête n'efface pas un échec).
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from dataclasses import asdict, dataclass

METHODS = ("spf", "dkim", "dmarc")
RESULTS = frozenset(
    {"pass", "fail", "softfail", "neutral", "none", "temperror", "permerror", "policy"}
)
UNKNOWN = "unknown"  # aucun résultat lisible pour la méthode
_RESULT_RE = re.compile(r"^\s*([a-z][a-z0-9-]*)\s*=\s*([a-z]+)", re.IGNORECASE)
_PREFERENCE = ("pass", "fail", "softfail", "neutral", "policy", "temperror", "permerror", "none")
# Résultats propres à Microsoft (Exchange Online) : « bestguesspass » veut dire que le
# domaine n'a pas d'enregistrement DMARC (le message serait passé s'il en avait un).
_ALIASES = {"bestguesspass": "none"}
_SPF_FAILURES = frozenset({"fail", "softfail"})


@dataclass(frozen=True)
class AuthResults:
    spf: str = UNKNOWN
    dkim: str = UNKNOWN
    dmarc: str = UNKNOWN
    source: str | None = None  # "authentication-results", "received-spf" ou None
    authserv_id: str | None = None
    headers_seen: int = 0

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def strip_comments(value: str) -> str:
    """Retire les commentaires ``( … )`` (imbriqués et échappés compris, RFC 5322)."""
    out, depth, escaped = [], 0, False
    for char in value:
        if escaped:
            escaped = False
            if depth == 0:
                out.append(char)
            continue
        if char == "\\":
            escaped = True
            if depth == 0:
                out.append(char)
        elif char == "(":
            depth += 1
        elif char == ")" and depth:
            depth -= 1
        elif depth == 0:
            out.append(char)
    return "".join(out)


def _split_results(value: str) -> list[str]:
    """Commentaires retirés puis découpage sur ``;``, en une passe qui respecte les guillemets.

    Hors guillemets, le comportement est celui de ``strip_comments`` suivi de
    ``split(";")``. Entre guillemets (``smtp.mailfrom="x(;dmarc=pass"@evil.example``,
    recopié de l'expéditeur par le serveur), ni ``(`` ni ``;`` n'ont de sens : ils ne
    peuvent plus masquer ni inventer de résultat. Un guillemet jamais refermé fait
    revenir au découpage simple, pour qu'il ne masque pas tout ce qui le suit.
    """
    parts: list[str] = []
    current: list[str] = []
    depth, escaped, quoted = 0, False, False
    for char in value:
        if escaped:
            escaped = False
            if char == ";" and depth == 0 and not quoted:
                parts.append("".join(current).strip())  # « \; » coupait déjà avant
                current = []
            elif depth == 0:
                current.append(char)
            continue
        if char == "\\":
            escaped = True
            if depth == 0:
                current.append(char)
        elif quoted:
            current.append(char)
            if char == '"':
                quoted = False
        elif depth:
            if char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
        elif char == '"':
            quoted = True
            current.append(char)
        elif char == "(":
            depth = 1
        elif char == ";":
            parts.append("".join(current).strip())
            current = []
        else:
            current.append(char)
    if quoted:
        return [p.strip() for p in strip_comments(value).split(";")]
    parts.append("".join(current).strip())
    return parts


def parse_authentication_results(value: str) -> tuple[str | None, dict[str, str]]:
    """``(authserv-id, {méthode: résultat})`` d'un en-tête ``Authentication-Results``.

    Plusieurs signatures DKIM : ``pass`` si l'une passe (RFC 6376 : une seule signature
    valide suffit), sinon le premier résultat dans l'ordre de :data:`_PREFERENCE`.
    """
    parts = _split_results(value)
    if not parts or not parts[0]:
        return None, {}
    # Exchange Online omet l'identifiant de serveur, pourtant obligatoire (RFC 8601) :
    # « Authentication-Results: spf=pass … ; dkim=pass … ». Le premier élément est alors
    # déjà un résultat.
    if _RESULT_RE.match(parts[0]):
        authserv_id, results_parts = None, parts
    else:
        authserv_id = parts[0].split()[0].lower() if parts[0].split() else None
        results_parts = parts[1:]
    found: dict[str, list[str]] = {}
    for part in results_parts:
        match = _RESULT_RE.match(part)
        if not match:
            continue
        method, result = match.group(1).lower(), match.group(2).lower()
        result = _ALIASES.get(result, result)
        if method in METHODS:
            found.setdefault(method, []).append(result if result in RESULTS else UNKNOWN)
    results = {}
    for method, values in found.items():
        results[method] = next((r for r in _PREFERENCE if r in values), values[0])
    return authserv_id, results


def parse_received_spf(value: str) -> str:
    """Résultat d'un en-tête ``Received-SPF`` (premier mot)."""
    words = strip_comments(value).split()
    result = words[0].lower() if words else ""
    return result if result in RESULTS else UNKNOWN


def read_auth_results(
    authentication_results: Sequence[str],
    received_spf: Sequence[str] = (),
    trusted_authserv_ids: Iterable[str] | None = None,
    received_spf_on_top: bool = False,
) -> AuthResults:
    """Résultats à retenir, à partir des en-têtes dans l'ordre du message (haut en bas).

    ``received_spf_on_top`` : le premier en-tête d'authentification du message est un
    ``Received-SPF``. Sans ``trusted_authserv_ids``, un échec qu'il signale (``fail``,
    ``softfail``) prime alors sur le SPF d'un ``Authentication-Results`` placé plus bas,
    que l'expéditeur a pu écrire lui-même. Il ne peut qu'aggraver le verdict : un
    ``pass`` (celui d'un relais de transfert, par exemple) n'efface pas un échec plus bas.
    """
    trusted = None if trusted_authserv_ids is None else {t.lower() for t in trusted_authserv_ids}
    for header in authentication_results:
        authserv_id, results = parse_authentication_results(header)
        if trusted is not None and authserv_id not in trusted:
            continue
        spf = results.get("spf")
        source = "authentication-results"
        if received_spf and spf is None:
            spf = parse_received_spf(received_spf[0])
        elif received_spf and trusted is None and received_spf_on_top:
            top_spf = parse_received_spf(received_spf[0])
            if top_spf in _SPF_FAILURES:
                spf = top_spf
        return AuthResults(
            spf=spf or UNKNOWN,
            dkim=results.get("dkim", UNKNOWN),
            dmarc=results.get("dmarc", UNKNOWN),
            source=source,
            authserv_id=authserv_id,
            headers_seen=len(authentication_results),
        )
    if received_spf:
        return AuthResults(
            spf=parse_received_spf(received_spf[0]),
            source="received-spf",
            headers_seen=len(authentication_results),
        )
    return AuthResults(headers_seen=len(authentication_results))
