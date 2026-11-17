"""Client minimal de l'API Bot de Telegram (étape 5.11).

Le cahier des charges proposait ``aiogram``. Il n'est pas employé : aiogram 3.31 (la
dernière version publiée depuis plus de deux semaines) impose ``pydantic<2.14`` et aurait
fait **rétrograder pydantic dans tout le projet**, API comprise, et ajouté neuf paquets
(aiohttp, yarl, multidict…). Le bot n'a besoin que de quatre méthodes de l'API Bot ;
``httpx``, déjà employé par le projet, suffit. Écart documenté dans docs/telegram-bot.md.

**Le jeton est dans l'URL** de chaque appel (``/bot<jeton>/sendMessage``) : c'est le
protocole de Telegram. Aucun message d'erreur de ce module ne contient donc d'URL ni de
message d'exception de ``httpx`` (qui recopie l'URL), et ``__main__`` coupe le journal de
``httpx``. Une erreur est réduite à un code.

Les mises à jour reçues sont des **entrées hostiles** : :func:`parse_update` ne garde que
les champs utiles, vérifie leur type et ignore tout le reste ; une forme inattendue donne
``None``, jamais une exception.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

import httpx

# Réponse de l'API Bot : bornée (un getUpdates de 100 messages de 4 096 caractères tient
# largement dans 4 Mio).
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
MAX_ENTITIES = 100
TELEGRAM_TEXT_LIMIT = 4096


class TelegramError(Exception):
    """Échec d'un appel à l'API Bot. ``code`` seulement : jamais l'URL (elle contient le jeton)."""

    def __init__(self, code: str, *, retry_after: float | None = None) -> None:
        super().__init__(code)
        self.code = code
        self.retry_after = retry_after


@dataclass(frozen=True)
class Entity:
    """Entité Telegram utile : un lien visible (``url``) ou caché derrière un texte (``text_link``)."""

    type: str
    offset: int  # en unités UTF-16, comme Telegram
    length: int
    url: str | None = None


@dataclass(frozen=True)
class IncomingMessage:
    update_id: int
    message_id: int | None
    chat_id: int
    chat_type: str
    user_id: int | None
    language_code: str | None
    text: str | None
    entities: tuple[Entity, ...] = field(default_factory=tuple)
    forwarded: bool = False
    has_media: bool = False


@dataclass(frozen=True)
class IncomingCallback:
    update_id: int
    callback_id: str
    chat_id: int | None
    chat_type: str | None
    user_id: int
    language_code: str | None
    data: str


Incoming = IncomingMessage | IncomingCallback


def _int(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _str(value: Any, max_chars: int) -> str | None:
    return value if isinstance(value, str) and len(value) <= max_chars else None


def _entities(value: Any) -> tuple[Entity, ...]:
    if not isinstance(value, list):
        return ()
    out: list[Entity] = []
    for raw in value[:MAX_ENTITIES]:
        if not isinstance(raw, dict) or raw.get("type") not in ("url", "text_link"):
            continue
        offset, length = _int(raw.get("offset")), _int(raw.get("length"))
        if offset is None or length is None or offset < 0 or length <= 0:
            continue
        url = _str(raw.get("url"), 8192) if raw["type"] == "text_link" else None
        if raw["type"] == "text_link" and url is None:
            continue
        out.append(Entity(type=raw["type"], offset=offset, length=length, url=url))
    return tuple(out)


def parse_update(update: Any) -> Incoming | None:
    """Un message ou un clic sur un bouton ; ``None`` pour tout le reste."""
    if not isinstance(update, dict) or (update_id := _int(update.get("update_id"))) is None:
        return None
    if isinstance(callback := update.get("callback_query"), dict):
        sender = callback.get("from") if isinstance(callback.get("from"), dict) else {}
        message = callback.get("message") if isinstance(callback.get("message"), dict) else {}
        chat = message.get("chat") if isinstance(message.get("chat"), dict) else {}
        callback_id = _str(callback.get("id"), 128)
        user_id = _int(sender.get("id"))
        data = _str(callback.get("data"), 64)
        if callback_id is None or user_id is None or data is None:
            return None
        return IncomingCallback(
            update_id=update_id,
            callback_id=callback_id,
            chat_id=_int(chat.get("id")),
            chat_type=_str(chat.get("type"), 32),
            user_id=user_id,
            language_code=_str(sender.get("language_code"), 16),
            data=data,
        )
    message = update.get("message")
    if not isinstance(message, dict):
        return None  # message modifié, canal, sondage… : ignorés
    chat = message.get("chat") if isinstance(message.get("chat"), dict) else {}
    chat_id, chat_type = _int(chat.get("id")), _str(chat.get("type"), 32)
    if chat_id is None or chat_type is None:
        return None
    sender = message.get("from") if isinstance(message.get("from"), dict) else {}
    # Un message transféré garde son texte ; la légende d'une photo en tient lieu.
    text_key = "text" if "text" in message else "caption"
    text = message.get(text_key)
    entities_key = "entities" if text_key == "text" else "caption_entities"
    return IncomingMessage(
        update_id=update_id,
        message_id=_int(message.get("message_id")),
        chat_id=chat_id,
        chat_type=chat_type,
        user_id=_int(sender.get("id")),
        language_code=_str(sender.get("language_code"), 16),
        text=text if isinstance(text, str) else None,
        entities=_entities(message.get(entities_key)),
        forwarded="forward_origin" in message or "forward_date" in message,
        has_media=any(
            k in message for k in ("photo", "document", "video", "voice", "audio", "sticker")
        ),
    )


class TelegramClient:
    """Les quatre méthodes de l'API Bot dont le bot a besoin."""

    def __init__(self, http: httpx.AsyncClient, *, token: str, base_url: str) -> None:
        self._http = http
        self._base = f"{base_url}/bot{token}"

    async def _call(self, method: str, payload: dict[str, Any], *, timeout: float) -> Any:
        try:
            response = await self._http.post(
                f"{self._base}/{method}",
                content=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                timeout=timeout,
            )
        except httpx.TimeoutException:
            raise TelegramError("timeout") from None
        except httpx.HTTPError:
            raise TelegramError("network") from None
        if len(response.content) > MAX_RESPONSE_BYTES:
            raise TelegramError("response_too_large")
        try:
            body = response.json()
        except ValueError:
            raise TelegramError(f"http_{response.status_code}") from None
        if not isinstance(body, dict) or body.get("ok") is not True:
            params = body.get("parameters") if isinstance(body, dict) else None
            retry = params.get("retry_after") if isinstance(params, dict) else None
            raise TelegramError(
                f"http_{response.status_code}",
                retry_after=float(retry) if isinstance(retry, int | float) else None,
            )
        return body.get("result")

    async def get_me(self) -> str:
        """Nom du bot (vérifie le jeton au démarrage)."""
        result = await self._call("getMe", {}, timeout=10)
        name = result.get("username") if isinstance(result, dict) else None
        if not isinstance(name, str):
            raise TelegramError("invalid_response")
        return name

    async def get_updates(self, offset: int | None, *, timeout: int) -> list[Any]:
        payload: dict[str, Any] = {
            "timeout": timeout,
            "allowed_updates": ["message", "callback_query"],
        }
        if offset is not None:
            payload["offset"] = offset
        result = await self._call("getUpdates", payload, timeout=timeout + 10)
        if not isinstance(result, list):
            raise TelegramError("invalid_response")
        return result

    async def send_message(
        self,
        chat_id: int,
        text: str,
        *,
        reply_to: int | None = None,
        keyboard: list[list[tuple[str, str]]] | None = None,
    ) -> None:
        """Texte brut (aucun ``parse_mode`` : rien n'est interprété comme HTML ou Markdown),
        sans aperçu de lien : Telegram ne visite jamais une adresse citée par le bot."""
        payload: dict[str, Any] = {
            "chat_id": chat_id,
            "text": text[:TELEGRAM_TEXT_LIMIT],
            "link_preview_options": {"is_disabled": True},
        }
        if reply_to is not None:
            payload["reply_parameters"] = {
                "message_id": reply_to,
                "allow_sending_without_reply": True,
            }
        if keyboard is not None:
            payload["reply_markup"] = {
                "inline_keyboard": [
                    [{"text": label, "callback_data": data} for label, data in row]
                    for row in keyboard
                ]
            }
        await self._call("sendMessage", payload, timeout=10)

    async def answer_callback(self, callback_id: str, text: str | None = None) -> None:
        payload: dict[str, Any] = {"callback_query_id": callback_id}
        if text:
            payload["text"] = text[:200]
        await self._call("answerCallbackQuery", payload, timeout=10)


__all__ = [
    "Entity",
    "Incoming",
    "IncomingCallback",
    "IncomingMessage",
    "TelegramClient",
    "TelegramError",
    "parse_update",
]
