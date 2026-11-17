"""Lance le bot : ``python -m phishguard.bot`` (``make bot``).

Réception par **long polling** : le bot va chercher les messages chez Telegram. Aucun
port n'est ouvert, rien n'est exposé à Internet ; c'est aussi le mode de production
retenu (docs/telegram-bot.md).

Le journal de ``httpx`` est coupé : il écrit l'URL de chaque requête, et l'URL de l'API
Bot contient le jeton (``/bot<jeton>/getUpdates``).
"""

from __future__ import annotations

import asyncio
import logging
import signal
import sys

import httpx
from pydantic import ValidationError

from phishguard.bot.api_client import PhishGuardApi
from phishguard.bot.bot import PhishGuardBot
from phishguard.bot.settings import BotSettings, get_bot_settings
from phishguard.bot.telegram import TelegramClient, TelegramError

logger = logging.getLogger("phishguard.bot")

# Journaux qui recopient des URLs (donc le jeton) ou des corps de requête.
SILENCED_LOGGERS = ("httpx", "httpcore")


def configure_logging(level: str) -> None:
    logging.basicConfig(
        level=level, format="%(asctime)s %(levelname)s %(name)s %(message)s", stream=sys.stderr
    )
    for name in SILENCED_LOGGERS:
        logging.getLogger(name).setLevel(logging.WARNING)
        logging.getLogger(name).propagate = False


async def main(settings: BotSettings) -> None:
    limits = httpx.Limits(max_connections=settings.max_concurrent * 6 + 4)
    timeout = httpx.Timeout(settings.analysis_timeout_seconds, connect=2.0)
    # Deux clients : l'un ne parle qu'à l'API PhishGuard, l'autre qu'à Telegram. Aucun ne
    # suit de redirection ni ne lit de variable d'environnement de proxy implicite.
    async with (
        httpx.AsyncClient(
            timeout=timeout, limits=limits, follow_redirects=False, trust_env=False
        ) as api_http,
        httpx.AsyncClient(timeout=60, follow_redirects=False, trust_env=False) as telegram_http,
    ):
        telegram = TelegramClient(
            telegram_http,
            token=settings.token.get_secret_value(),
            base_url=settings.telegram_api_url,
        )
        api = PhishGuardApi(
            api_http,
            base_url=settings.api_url,
            api_key=settings.api_key.get_secret_value() if settings.api_key else None,
        )
        name = await telegram.get_me()
        logger.info("bot @%s prêt (API %s)", name, settings.api_url)
        stop = asyncio.Event()
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, stop.set)
            except NotImplementedError:  # Windows : Ctrl+C lève KeyboardInterrupt
                pass
        await PhishGuardBot(settings, telegram=telegram, api=api).run(stop)
        logger.info("bot arrêté")


def run() -> int:
    try:
        settings = get_bot_settings()
    except ValidationError as exc:
        # Champs en cause seulement, jamais les valeurs (le jeton est un secret).
        fields = ", ".join(".".join(map(str, e["loc"])) or "?" for e in exc.errors())
        print(
            f"configuration du bot invalide : {fields} (voir docs/telegram-bot.md)", file=sys.stderr
        )
        return 2
    configure_logging(settings.log_level)
    try:
        asyncio.run(main(settings))
    except TelegramError as exc:
        logger.error("Telegram refuse la connexion (%s) : jeton révoqué ou réseau ?", exc.code)
        return 1
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
