"""Configuration de l'API (étape 4.1), lue par ``pydantic-settings``.

Variables d'environnement préfixées par ``PHISHGUARD_API_`` (``PHISHGUARD_API_MODELS_DIR``,
``PHISHGUARD_API_TRUSTED_PROXIES``…), puis fichier ``.env`` du répertoire courant.
L'environnement est prioritaire. Les clés des sources de Threat Intelligence restent dans
:mod:`phishguard.config` (étape 2.1) : ce module ne porte aucun secret.

Les valeurs par défaut sont celles d'un poste de développement **sûr** : enrichissement
désactivé, aucun proxy de confiance (``X-Forwarded-For`` ignoré), limites de débit actives,
aucune origine CORS autorisée. Une valeur invalide fait échouer le démarrage : mieux vaut
ne pas démarrer que démarrer sans protection.

``PHISHGUARD_API_ENVIRONMENT=production`` (étape 4.5) désactive la documentation
interactive, ajoute ``Strict-Transport-Security`` et refuse les origines CORS en
``http://`` hors boucle locale : une configuration de développement oubliée en production
empêche le démarrage au lieu d'ouvrir une brèche.
"""

from __future__ import annotations

from functools import lru_cache
from ipaddress import IPv4Network, IPv6Network, ip_network
from pathlib import Path
from typing import Annotated, Literal
from urllib.parse import urlsplit

from limits import parse_many
from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

MIB = 1024 * 1024

IPNetwork = IPv4Network | IPv6Network
Environment = Literal["development", "production"]

# Schémas d'origine admis pour CORS : sites web et extensions de navigateur (module 5).
CORS_SCHEMES = frozenset({"http", "https", "chrome-extension", "moz-extension"})
LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "[::1]"})


def _comma_separated(value: object) -> object:
    """Liste lue dans l'environnement : JSON (``["a", "b"]``) ou ``a,b``."""
    if isinstance(value, str):
        text = value.strip()
        if text.startswith("["):
            import json

            return json.loads(text)
        return [part for part in (p.strip() for p in text.split(",")) if part]
    return value


def _validated_origin(origin: str) -> str:
    """Origine CORS exacte (``schéma://hôte[:port]``), sans joker ni chemin.

    ``*`` et ``null`` sont refusés : ``*`` ouvrirait les routes à clé à n'importe quel
    site, et ``null`` est l'origine des iframes isolées et des fichiers locaux, qu'un
    attaquant obtient à volonté.
    """
    if origin in {"*", "null"} or "*" in origin:
        raise ValueError(f"origine CORS refusée : {origin!r} (liste explicite attendue)")
    parts = urlsplit(origin)
    if (
        parts.scheme not in CORS_SCHEMES
        or not parts.netloc
        or parts.path
        or parts.query
        or parts.fragment
        or "@" in parts.netloc
        or origin != f"{parts.scheme}://{parts.netloc}"
    ):
        raise ValueError(
            f"origine CORS invalide : {origin!r} (forme attendue : https://exemple.org, "
            "chrome-extension://<identifiant>, sans chemin ni barre finale)"
        )
    return origin


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

    # --- Environnement (étape 4.5) ------------------------------------------ #
    environment: Environment = "development"

    # --- Documentation interactive ----------------------------------------- #
    # /docs, /redoc et /openapi.json. Non renseigné : actifs en développement seulement ;
    # les activer en production est refusé (voir ``_production_is_locked_down``).
    docs_enabled: bool | None = None

    # --- Entrées (étape 4.2) ------------------------------------------------ #
    max_email_bytes: int = Field(default=1 * MIB, ge=1024, le=10 * MIB)
    # Corps des requêtes JSON : une URL de 2 048 caractères ou un texte de 5 000
    # caractères, même entièrement échappés en \\uXXXX, tiennent largement.
    max_json_bytes: int = Field(default=64 * 1024, ge=1024, le=1 * MIB)

    # --- Durcissement HTTP (étape 4.5) -------------------------------------- #
    # Origines autorisées à appeler l'API depuis un navigateur, liste explicite :
    # PHISHGUARD_API_CORS_ALLOWED_ORIGINS=chrome-extension://abcdef…,https://phishguard.example
    # Vide (défaut) : aucune réponse CORS, les navigateurs bloquent tout appel d'un autre site.
    cors_allowed_origins: Annotated[tuple[str, ...], NoDecode] = ()
    # Durée maximale d'une requête, lecture du corps comprise (un client qui envoie son
    # corps octet par octet est coupé). Au-delà : 408 pendant la lecture, 503 ensuite.
    request_timeout_seconds: float = Field(default=30.0, gt=0, le=300)
    # Durée de mise en cache des pré-vérifications CORS par le navigateur.
    cors_max_age_seconds: int = Field(default=600, ge=0, le=86_400)

    # --- Journalisation (étape 4.6) ----------------------------------------- #
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    # json : une ligne JSON par événement ; console : texte lisible. Non renseigné :
    # json en production, console en développement.
    log_format: Literal["json", "console"] | None = None

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
        value = _comma_separated(value)
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

    @field_validator("log_level", mode="before")
    @classmethod
    def _upper_level(cls, value: object) -> object:
        return value.strip().upper() if isinstance(value, str) else value

    @field_validator("cors_allowed_origins", mode="before")
    @classmethod
    def _parse_origins(cls, value: object) -> object:
        value = _comma_separated(value)
        if isinstance(value, list | tuple):
            return tuple(dict.fromkeys(_validated_origin(str(item).strip()) for item in value))
        return value

    @model_validator(mode="after")
    def _production_is_locked_down(self) -> ApiSettings:
        if self.environment != "production":
            return self
        if self.docs_enabled:
            raise ValueError(
                "documentation interactive refusée en production "
                "(PHISHGUARD_API_DOCS_ENABLED) : elle publie toute la surface de l'API"
            )
        for origin in self.cors_allowed_origins:
            parts = urlsplit(origin)
            if parts.scheme == "http" and parts.netloc.rsplit(":", 1)[0] not in LOOPBACK_HOSTS:
                raise ValueError(f"origine CORS en http refusée en production : {origin!r}")
        return self

    @property
    def is_production(self) -> bool:
        return self.environment == "production"

    @property
    def log_json(self) -> bool:
        return self.log_format == "json" if self.log_format else self.is_production

    @property
    def docs_active(self) -> bool:
        """``/docs``, ``/redoc`` et ``/openapi.json`` servis."""
        return self.docs_enabled if self.docs_enabled is not None else not self.is_production


@lru_cache(maxsize=1)
def get_api_settings() -> ApiSettings:
    """Configuration du processus, lue une seule fois (``cache_clear()`` dans les tests)."""
    return ApiSettings()
