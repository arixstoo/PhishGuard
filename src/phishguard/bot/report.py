"""Analyse d'un message reçu par le bot et réponse à afficher (étape 5.11).

1. Les liens (``extract.py``) et le texte sont analysés **en parallèle** par l'API, sous
   un délai global (``analysis_timeout_seconds``, 2,5 s par défaut) : le critère de l'étape
   est un verdict en moins de 3 secondes.
2. Verdict global : le plus prudent de tous. Un lien de phishing dans un message anodin
   rend le message dangereux.
3. Réponse en **texte brut**, sans aperçu de lien, et adresses **désarmées** : seul l'hôte
   est cité (jamais le chemin, qui peut porter un jeton), en ASCII (un homographe
   ``аpple.com`` apparaît sous sa forme Punycode ``xn--pple-43d.com``), avec ``[.]`` à la
   place des points. Telegram ne peut alors ni en faire un lien cliquable ni le visiter.
   Le bot ne doit jamais devenir le relais d'un lien de phishing.
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from phishguard.bot.api_client import ApiError, PhishGuardApi
from phishguard.bot.extract import Extraction, FoundLink
from phishguard.bot.texts import text
from phishguard.explain.reasons import Language
from phishguard.schema import AnalysisResponse

RANK = {"safe": 0, "suspicious": 1, "phishing": 2}
MAX_SHOWN_CHARS = 60
MAX_REASONS_PER_ITEM = 2
# Isolation bidirectionnelle (FSI … PDI) : un hôte reste lisible de gauche à droite dans
# une phrase arabe, et un hôte piégé (U+202E) ne retourne pas le reste de la ligne.
FSI, PDI = "\u2068", "\u2069"
# Caractères de mise en forme invisibles : retirés de tout ce que le bot recopie.
_INVISIBLE = dict.fromkeys(
    map(
        ord,
        "\u200b\u200c\u200d\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069\ufeff",
    ),
    None,
)


# Ce qui ressemble à un nom de domaine dans un texte recopié (raison, conseil) : Telegram en
# ferait un lien. « 1.99 » ne l'est pas (le dernier label doit commencer par une lettre).
_DOMAIN_LIKE = re.compile(
    r"(?i)\b(?:[a-z0-9\u00a1-\uffff-]+\.)+[a-z\u00a1-\uffff][a-z0-9\u00a1-\uffff-]+\b"
)


@dataclass(frozen=True)
class LinkResult:
    link: FoundLink
    response: AnalysisResponse | None  # None : analyse échouée


@dataclass(frozen=True)
class Report:
    verdict: str | None  # None : rien n'a pu être analysé
    text_result: AnalysisResponse | None
    text_failed: bool
    links: tuple[LinkResult, ...]
    extraction: Extraction

    @property
    def partial(self) -> bool:
        return self.text_failed or any(r.response is None for r in self.links)


def _strictest(responses: list[AnalysisResponse]) -> AnalysisResponse | None:
    # À verdict égal, le score le plus haut ; le message passe avant un lien (son conseil
    # parle du message entier).
    return max(
        responses, key=lambda r: (RANK[r.verdict], r.score, r.channel != "url"), default=None
    )


async def analyze_message(
    message: str,
    extraction: Extraction,
    *,
    api: PhishGuardApi,
    language: Language,
    threat_intel: bool,
    timeout: float,
) -> Report:
    """Analyse le texte et chaque lien ; une partie échouée n'empêche pas le reste."""

    async def guarded(coro) -> AnalysisResponse | None:
        try:
            return await coro
        except ApiError:
            return None

    analyze_text = bool(message.strip())
    tasks = (
        [asyncio.ensure_future(guarded(api.analyze_text(message, language=language)))]
        if analyze_text
        else []
    )
    tasks += [
        asyncio.ensure_future(
            guarded(api.analyze_url(link.url, language=language, threat_intel=threat_intel))
        )
        for link in extraction.links
    ]
    if tasks:
        _, pending = await asyncio.wait(tasks, timeout=timeout)
        for task in pending:
            task.cancel()
    results = [t.result() if t.done() and not t.cancelled() else None for t in tasks]
    text_result = results.pop(0) if analyze_text else None
    links = tuple(LinkResult(link, r) for link, r in zip(extraction.links, results, strict=True))
    done = [r for r in (text_result, *[l.response for l in links]) if r is not None]
    worst = _strictest(done)
    return Report(
        verdict=worst.verdict if worst else None,
        text_result=text_result,
        text_failed=analyze_text and text_result is None,
        links=links,
        extraction=extraction,
    )


# --------------------------------------------------------------------------- #
# Réponse
# --------------------------------------------------------------------------- #


def clean(value: str) -> str:
    """Texte recopié : invisibles retirés, une seule ligne, noms de domaine désarmés."""
    one_line = " ".join(value.translate(_INVISIBLE).split())
    return _DOMAIN_LIKE.sub(lambda m: m.group().replace(".", "[.]"), one_line)


def defang_host(url: str) -> str:
    """Hôte d'une URL, en ASCII, désarmé : ``paypa1-login[.]example``."""
    try:
        host = urlsplit(url).hostname or ""
    except ValueError:
        host = ""
    host = " ".join(host.translate(_INVISIBLE).split()).rstrip(".")
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        host = host.encode("ascii", "backslashreplace").decode("ascii")
    host = host[:253] or "?"
    return f"{FSI}{host.replace('.', '[.]').replace(':', '[:]')}{PDI}"


def _shown(value: str) -> str:
    shown = " ".join(value.translate(_INVISIBLE).split())
    if len(shown) > MAX_SHOWN_CHARS:
        shown = shown[: MAX_SHOWN_CHARS - 1] + "…"
    # Un texte affiché qui ressemble à une adresse (« www.paypal.com ») est désarmé aussi.
    return f"{FSI}{shown.replace('.', '[.]')}{PDI}"


def _reasons(response: AnalysisResponse) -> list[str]:
    if response.verdict == "safe":
        return []
    return [f"   • {clean(r.message)}" for r in response.reasons[:MAX_REASONS_PER_ITEM]]


def render(report: Report, language: Language, *, max_urls: int) -> str:
    """Réponse du bot en texte brut (jamais interprétée comme HTML ou Markdown)."""
    if report.verdict is None:
        return text(language, "unavailable")
    lines = [text(language, f"verdict_{report.verdict}"), ""]
    if report.text_result is not None or report.text_failed:
        item = report.text_result.verdict if report.text_result else "failed"
        lines.append(text(language, "message_line", verdict=text(language, f"item_{item}")))
        if report.text_result is not None:
            lines += _reasons(report.text_result)
    for result in report.links:
        item = result.response.verdict if result.response else "failed"
        lines.append(
            text(
                language,
                "link_line",
                host=defang_host(result.link.url),
                verdict=text(language, f"item_{item}"),
            )
        )
        if result.link.shown_as:
            lines.append(text(language, "hidden_link", shown=_shown(result.link.shown_as)))
        if result.response is not None:
            lines += _reasons(result.response)
    if report.extraction.skipped:
        lines.append(text(language, "skipped", count=report.extraction.skipped, max_urls=max_urls))
    if report.extraction.not_web:
        lines.append(text(language, "not_web", count=report.extraction.not_web))
    if report.partial:
        lines += ["", text(language, "partial")]
    worst = _strictest(
        [r for r in (report.text_result, *[l.response for l in report.links]) if r is not None]
    )
    if worst is not None:
        lines += ["", text(language, "advice", advice=clean(worst.advice))]
    if report.links:
        lines += ["", text(language, "defanged_note")]
    return "\n".join(lines)


__all__ = ["LinkResult", "Report", "analyze_message", "clean", "defang_host", "render"]
