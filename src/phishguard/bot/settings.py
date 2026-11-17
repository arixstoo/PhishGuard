"""Configuration du bot Telegram (étape 5.11), préfixe ``PHISHGUARD_BOT_``.

Seul le jeton est obligatoire. Les valeurs par défaut sont les plus prudentes : aucune
source de Threat Intelligence (l'URL resterait chez l'API), limites actives, API locale.

``PHISHGUARD_BOT_TOKEN`` vient de @BotFather. C'est un secret : il donne le contrôle
complet du bot. Il n'apparaît jamais dans un journal ni dans un message d'erreur
(``SecretStr``, et le journal de ``httpx``, qui écrit l'URL appelée, est coupé : l'URL de
l'API Bot contient le jeton, voir ``telegram.py``).
"""

from __future__ import annotations

import re
from functools import lru_cache
from typing import Literal
from urllib.parse import urlsplit

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from phishguard.explain.reasons import DEFAULT_LANGUAGE, Language

# Format des jetons de @BotFather : identifiant numérique du bot, « : », 35 caractères.
TOKEN_RE = re.compile(r"^\d{5,20}:[A-Za-z0-9_-]{30,64}$")
API_KEY_RE = re.compile(r"^pg_[A-Za-z0-9_-]{43}$")
LOOPBACK = frozenset({"localhost", "127.0.0.1", "::1"})


def _base_url(value: str, *, allow_plain_http: Literal["any", "loopback", "never"]) -> str:
    """Adresse de base canonique : schéma et hôte, chemin éventuel, rien d'autre."""
    parts = urlsplit(value.strip())
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError("adresse http(s) attendue")
    if parts.username or parts.password or parts.query or parts.fragment:
        raise ValueError("ni identifiants, ni paramètres, ni fragment dans l'adresse")
    if parts.scheme == "http":
        loopback = parts.hostname in LOOPBACK
        if allow_plain_http == "never" or (allow_plain_http == "loopback" and not loopback):
            raise ValueError("https obligatoire")
    return f"{parts.scheme}://{parts.netloc}{parts.path.rstrip('/')}"


class BotSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="PHISHGUARD_BOT_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        frozen=True,
        env_ignore_empty=True,
        # Une erreur de validation recopie par défaut la valeur refusée : ici, un jeton.
        hide_input_in_errors=True,
    )

    token: SecretStr
    # API PhishGuard (module 4). En http, seulement sur un réseau privé : boucle locale ou
    # réseau interne de docker compose (``http://api:8000``), jamais à travers Internet.
    api_url: str = "http://127.0.0.1:8000"
    # Clé de l'API (``make api-key NAME=telegram-bot``) : tous les utilisateurs du bot
    # passent par lui, le palier anonyme (30/min par IP) serait vite épuisé.
    api_key: SecretStr | None = None
    # Serveur de l'API Bot : celui de Telegram, ou un serveur local (telegram-bot-api).
    telegram_api_url: str = "https://api.telegram.org"
    # Sources de Threat Intelligence de l'API : l'URL partirait chez des tiers. Sans effet
    # si l'API ne les a pas activées.
    threat_intel: bool = False
    default_language: Language = DEFAULT_LANGUAGE

    # --- Limites (étape 5.11) ----------------------------------------------- #
    max_urls: int = Field(default=5, ge=1, le=10)
    # Un message Telegram fait 4 096 caractères au plus ; l'API en accepte 5 000.
    max_text_chars: int = Field(default=4096, ge=64, le=5000)
    # Délai minimal entre deux analyses d'un même utilisateur.
    min_interval_seconds: float = Field(default=3.0, ge=0, le=600)
    # Durée maximale d'une analyse complète (critère : verdict en moins de 3 s).
    analysis_timeout_seconds: float = Field(default=2.5, gt=0, le=30)
    # Analyses simultanées, tous utilisateurs confondus.
    max_concurrent: int = Field(default=16, ge=1, le=256)
    # Attente d'un nouveau message côté Telegram (long polling).
    poll_timeout_seconds: int = Field(default=30, ge=1, le=50)

    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"

    @field_validator("token")
    @classmethod
    def _valid_token(cls, value: SecretStr) -> SecretStr:
        if not TOKEN_RE.match(value.get_secret_value()):
            # Sans recopier la valeur : c'est un secret.
            raise ValueError("jeton Telegram mal formé (attendu : 123456:ABC…, de @BotFather)")
        return value

    @field_validator("api_key")
    @classmethod
    def _valid_api_key(cls, value: SecretStr | None) -> SecretStr | None:
        if value is not None and not API_KEY_RE.match(value.get_secret_value()):
            raise ValueError("clé d'API mal formée (attendu : pg_ suivi de 43 caractères)")
        return value

    @field_validator("api_url")
    @classmethod
    def _valid_api_url(cls, value: str) -> str:
        return _base_url(value, allow_plain_http="any")

    @field_validator("telegram_api_url")
    @classmethod
    def _valid_telegram_url(cls, value: str) -> str:
        return _base_url(value, allow_plain_http="loopback")


@lru_cache(maxsize=1)
def get_bot_settings() -> BotSettings:
    return BotSettings()  # type: ignore[call-arg]  # token lu dans l'environnement


__all__ = ["BotSettings", "get_bot_settings"]
