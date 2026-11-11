"""Configuration de l'API (étape 4.1), lue par ``pydantic-settings``.

Variables d'environnement préfixées par ``PHISHGUARD_API_`` (``PHISHGUARD_API_MODELS_DIR``,
``PHISHGUARD_API_TRUSTED_PROXIES``…), puis fichier ``.env`` du répertoire courant.
L'environnement est prioritaire. Les clés des sources de Threat Intelligence restent dans
:mod:`phishguard.config` (étape 2.1) : ce module ne porte aucun secret.

Les valeurs par défaut sont celles d'un poste de développement **sûr** : enrichissement
désactivé, aucun proxy de confiance (``X-Forwarded-For`` ignoré), limites de débit actives.
Une valeur invalide fait échouer le démarrage : mieux vaut ne pas démarrer que démarrer
sans protection.
"""

from __future__ import annotations

from functools import lru_cache
from ipaddress import IPv4Network, IPv6Network, ip_network
from pathlib import Path
from typing import Annotated

from limits import parse_many
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

MIB = 1024 * 1024

IPNetwork = IPv4Network | IPv6Network


class ApiSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="PHISHGUARD_API_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",  # .env contient aussi les clés des sources et des scripts
        frozen=True,
        env_ignore_empty=True,
    )

    # --- Modèles et données ------------------------------------------------- #
    models_dir: Path = Path("models")
    # Base SQLite des empreintes de clés d'API et des retours (jamais versionnée).
    database_path: Path = Path("data/api/phishguard.sqlite3")

    # --- Documentation interactive ----------------------------------------- #
    # /docs, /redoc et /openapi.json. L'étape 4.5 les désactive en production.
    docs_enabled: bool = True

    # --- Entrées (étape 4.2) ------------------------------------------------ #
    max_email_bytes: int = Field(default=1 * MIB, ge=1024, le=10 * MIB)
    # Corps des requêtes JSON : une URL de 2 048 caractères ou un texte de 5 000
    # caractères, même entièrement échappés en \\uXXXX, tiennent largement.
    max_json_bytes: int = Field(default=64 * 1024, ge=1024, le=1 * MIB)

    # --- Threat Intelligence (module 2) ------------------------------------ #
    # Le serveur n'interroge des sources externes que si ce drapeau est vrai **et** que
    # le client le demande pour l'analyse (``use_threat_intel``).
    threat_intel_enabled: bool = False

    # --- Limites de débit (étape 4.4) --------------------------------------- #
    rate_limit_enabled: bool = True
    # Syntaxe de la bibliothèque ``limits`` : « 30/minute », « 5/second;100/hour ».
    rate_limit_anonymous: str = "30/minute"
    rate_limit_authenticated: str = "300/minute"
    # Clé présentée mais inconnue ou révoquée : très bas, contre la recherche de clés.
    rate_limit_rejected: str = "10/minute"
    # URI de stockage de la bibliothèque ``limits`` (mode asynchrone, préfixe ``async+``
    # ajouté au besoin). ``memory://`` : un compteur par processus ; avec plusieurs
    # workers, un stockage partagé (``redis://…``), sinon chaque worker accorde le quota.
    rate_limit_storage_uri: str = "memory://"

    # --- Proxy inverse (étape 4.4) ------------------------------------------ #
    # Réseaux des proxys dont l'en-tête X-Forwarded-For est cru, en JSON ou séparés par
    # des virgules : PHISHGUARD_API_TRUSTED_PROXIES=10.0.0.0/8,127.0.0.1. Vide (défaut) :
    # l'en-tête est ignoré, l'IP du client est celle de la connexion.
    trusted_proxies: Annotated[tuple[IPNetwork, ...], NoDecode] = ()

    @field_validator("trusted_proxies", mode="before")
    @classmethod
    def _parse_networks(cls, value: object) -> object:
        if isinstance(value, str):
            text = value.strip()
            if text.startswith("["):
                import json

                value = json.loads(text)
            else:
                value = [part for part in (p.strip() for p in text.split(",")) if part]
        if isinstance(value, list | tuple):
            # strict : « 10.0.0.1/8 » (bits d'hôte non nuls) est une faute probable, refusée.
            return tuple(ip_network(str(item), strict=True) for item in value)
        return value

    @field_validator(
        "rate_limit_anonymous", "rate_limit_authenticated", "rate_limit_rejected", mode="after"
    )
    @classmethod
    def _valid_limit(cls, value: str) -> str:
        try:
            if not parse_many(value):
                raise ValueError
        except ValueError:
            raise ValueError(f"limite de débit invalide : {value!r} (ex. « 30/minute »)") from None
        return value


@lru_cache(maxsize=1)
def get_api_settings() -> ApiSettings:
    """Configuration du processus, lue une seule fois (``cache_clear()`` dans les tests)."""
    return ApiSettings()
