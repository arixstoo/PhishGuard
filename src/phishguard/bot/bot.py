"""Bot Telegram de PhishGuard (étape 5.11) : réception, commandes, limites, réponse.

- **Conversations privées seulement.** Dans un groupe, le bot ne lit rien et ne répond
  rien : il n'a pas à voir les messages de personnes qui ne lui ont rien demandé.
- **Rien n'est conservé.** Le message est analysé puis oublié. En mémoire seulement, et
  bornés : l'heure du dernier message de chaque utilisateur (limite de débit, quelques
  secondes) et la langue choisie par ``/langue`` (perdue au redémarrage).
- **Journal sans contenu** : nombre de liens, verdict, durée. Jamais le texte, les liens,
  l'identifiant de l'utilisateur ou de la conversation (étape 4.6).
- **Limites** : ``max_urls`` liens par message, ``max_text_chars`` caractères, un message
  toutes les ``min_interval_seconds`` par utilisateur, ``max_concurrent`` analyses en
  même temps. Un utilisateur trop rapide est prévenu **une fois** par fenêtre : répondre
  à chaque message ferait du bot un amplificateur.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable

from cachetools import TTLCache

from phishguard.bot.api_client import PhishGuardApi
from phishguard.bot.extract import extract_links
from phishguard.bot.report import analyze_message, render
from phishguard.bot.settings import BotSettings
from phishguard.bot.telegram import (
    Incoming,
    IncomingCallback,
    IncomingMessage,
    TelegramClient,
    TelegramError,
    parse_update,
)
from phishguard.bot.texts import LANGUAGE_NAMES, language_from_code, text
from phishguard.explain.reasons import LANGUAGES, Language

logger = logging.getLogger("phishguard.bot")

COMMANDS: dict[str, str] = {
    "start": "start",
    "aide": "help",
    "help": "help",
    "confidentialite": "privacy",
    "privacy": "privacy",
    "langue": "language",
    "language": "language",
}
MAX_TRACKED_USERS = 50_000
LANGUAGE_TTL_SECONDS = 30 * 24 * 3600


def command_of(message: str) -> tuple[str, str] | None:
    """``("language", "en")`` pour ``/langue@PhishGuardBot en`` ; ``None`` si ce n'est pas une commande connue."""
    if not message.startswith("/"):
        return None
    head, _, rest = message[1:].partition(" ")
    name = head.split("@", 1)[0].lower()
    return (COMMANDS[name], rest.strip()) if name in COMMANDS else None


class PhishGuardBot:
    def __init__(
        self,
        settings: BotSettings,
        *,
        telegram: TelegramClient,
        api: PhishGuardApi,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.settings = settings
        self.telegram = telegram
        self.api = api
        self._clock = clock
        self._semaphore = asyncio.Semaphore(settings.max_concurrent)
        ttl = max(settings.min_interval_seconds, 0.001)
        # Utilisateur → déjà prévenu d'aller moins vite. Expire avec la fenêtre.
        self._recent: TTLCache[int, bool] = TTLCache(MAX_TRACKED_USERS, ttl=ttl, timer=clock)
        self._languages: TTLCache[int, Language] = TTLCache(
            MAX_TRACKED_USERS, ttl=LANGUAGE_TTL_SECONDS, timer=clock
        )
        self._tasks: set[asyncio.Task[None]] = set()

    # ------------------------------------------------------------------ #

    def language_for(self, user_id: int | None, code: str | None) -> Language:
        if user_id is not None and (chosen := self._languages.get(user_id)) is not None:
            return chosen
        return language_from_code(code) or self.settings.default_language

    def _language_keyboard(self) -> list[list[tuple[str, str]]]:
        return [[(LANGUAGE_NAMES[lang], f"lang:{lang}") for lang in LANGUAGES]]

    async def handle(self, incoming: Incoming) -> None:
        if isinstance(incoming, IncomingCallback):
            await self._handle_callback(incoming)
        elif incoming.chat_type == "private":
            await self._handle_message(incoming)
        # Groupes, canaux : rien n'est lu, rien n'est répondu.

    async def _handle_callback(self, callback: IncomingCallback) -> None:
        chosen = callback.data.removeprefix("lang:")
        if (
            callback.chat_type != "private"
            or chosen not in LANGUAGES
            or not callback.data.startswith("lang:")
        ):
            await self.telegram.answer_callback(callback.callback_id)
            return
        language: Language = chosen  # type: ignore[assignment]
        self._languages[callback.user_id] = language
        await self.telegram.answer_callback(callback.callback_id, text(language, "language_set"))
        if callback.chat_id is not None:
            await self.telegram.send_message(callback.chat_id, text(language, "language_set"))

    async def _handle_message(self, message: IncomingMessage) -> None:
        language = self.language_for(message.user_id, message.language_code)
        say = self.telegram.send_message
        content = message.text or ""
        # Toute réponse coûte un message : commandes comprises, tout passe par la limite.
        if not self._admit(message.user_id):
            if message.user_id is not None and not self._recent.get(message.user_id):
                self._recent[message.user_id] = True
                await say(message.chat_id, text(language, "too_fast"))
            return
        command = command_of(content) if not message.forwarded else None
        if command is not None:
            name, argument = command
            if name == "language":
                if argument.lower() in LANGUAGES:
                    if message.user_id is not None:
                        self._languages[message.user_id] = argument.lower()  # type: ignore[assignment]
                    await say(message.chat_id, text(argument.lower(), "language_set"))  # type: ignore[arg-type]
                else:
                    await say(
                        message.chat_id,
                        text(language, "language_prompt"),
                        keyboard=self._language_keyboard(),
                    )
                return
            values = {
                "max_urls": self.settings.max_urls,
                "max_chars": self.settings.max_text_chars,
                "interval": f"{self.settings.min_interval_seconds:g}",
            }
            await say(message.chat_id, text(language, name, **values))
            return

        if not content.strip():
            await say(message.chat_id, text(language, "empty"))
            return
        if len(content) > self.settings.max_text_chars:
            await say(
                message.chat_id, text(language, "too_long", max_chars=self.settings.max_text_chars)
            )
            return

        start = self._clock()
        extraction = extract_links(content, message.entities, limit=self.settings.max_urls)
        async with self._semaphore:
            report = await analyze_message(
                content,
                extraction,
                api=self.api,
                language=language,
                threat_intel=self.settings.threat_intel,
                timeout=self.settings.analysis_timeout_seconds,
            )
        reply = render(report, language, max_urls=self.settings.max_urls)
        await say(message.chat_id, reply, reply_to=message.message_id)
        logger.info(
            "message analysé : %d lien(s), verdict %s, %s, %.0f ms",
            len(extraction.links),
            report.verdict or "aucun",
            "partiel" if report.partial else "complet",
            (self._clock() - start) * 1000,
        )

    def _admit(self, user_id: int | None) -> bool:
        """Vrai si l'utilisateur n'a pas envoyé de message depuis ``min_interval_seconds``."""
        if user_id is None or self.settings.min_interval_seconds == 0:
            return True
        if user_id in self._recent:
            return False
        self._recent[user_id] = False  # vu ; pas encore prévenu
        return True

    # ------------------------------------------------------------------ #
    # Réception (long polling)
    # ------------------------------------------------------------------ #

    def dispatch(self, raw_update: object) -> None:
        """Traite une mise à jour en tâche de fond : un message lent ne bloque pas les autres."""
        incoming = parse_update(raw_update)
        if incoming is None:
            return
        task = asyncio.create_task(self._safe_handle(incoming))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _safe_handle(self, incoming: Incoming) -> None:
        try:
            await self.handle(incoming)
        except TelegramError as exc:
            logger.warning("réponse non envoyée : %s", exc.code)
        except Exception as exc:  # noqa: BLE001 : un message ne doit jamais arrêter le bot
            logger.error("erreur inattendue : %s", type(exc).__name__)

    async def run(self, stop: asyncio.Event) -> None:
        """Boucle de réception jusqu'à ``stop`` ; reprend après une panne réseau."""
        offset: int | None = None
        backoff = 1.0
        while not stop.is_set():
            poll = asyncio.ensure_future(
                self.telegram.get_updates(offset, timeout=self.settings.poll_timeout_seconds)
            )
            stopper = asyncio.ensure_future(stop.wait())
            done, _ = await asyncio.wait({poll, stopper}, return_when=asyncio.FIRST_COMPLETED)
            if stopper in done:
                poll.cancel()
                break
            stopper.cancel()
            try:
                updates = poll.result()
            except TelegramError as exc:
                logger.warning("réception interrompue : %s", exc.code)
                await asyncio.sleep(exc.retry_after or backoff)
                backoff = min(backoff * 2, 60)
                continue
            backoff = 1.0
            for update in updates:
                update_id = update.get("update_id") if isinstance(update, dict) else None
                if isinstance(update_id, int):
                    # Accusé de réception au prochain appel : jamais traité deux fois.
                    offset = max(offset or 0, update_id + 1)
                self.dispatch(update)
        if self._tasks:
            await asyncio.wait(self._tasks, timeout=10)


__all__ = ["PhishGuardBot", "command_of"]
