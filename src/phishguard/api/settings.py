"""Configuration de l'API (étape 4.1), lue par ``pydantic-settings``.

Variables d'environnement préfixées par ``PHISHGUARD_API_`` (``PHISHGUARD_API_MODELS_DIR``,
``PHISHGUARD_API_DOCS_ENABLED``…), puis fichier ``.env`` du répertoire courant.
L'environnement est prioritaire. Les clés des sources de Threat Intelligence restent dans
:mod:`phishguard.config` (étape 2.1) : ce module ne porte aucun secret.

Les valeurs par défaut sont celles d'un poste de développement **sûr** : enrichissement
désactivé. Une valeur invalide fait échouer le démarrage : mieux vaut ne pas démarrer que
démarrer mal configuré.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class ApiSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="PHISHGUARD_API_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",  # .env contient aussi les clés des sources et des scripts
        frozen=True,
        env_ignore_empty=True,
    )

    # --- Modèles ------------------------------------------------------------ #
    models_dir: Path = Path("models")

    # --- Documentation interactive ----------------------------------------- #
    # /docs, /redoc et /openapi.json. L'étape 4.5 les désactive en production.
    docs_enabled: bool = True

    # --- Threat Intelligence (module 2) ------------------------------------ #
    # Le serveur n'interroge des sources externes que si ce drapeau est vrai **et** que
    # le client le demande pour l'analyse (étape 4.3).
    threat_intel_enabled: bool = False


@lru_cache(maxsize=1)
def get_api_settings() -> ApiSettings:
    """Configuration du processus, lue une seule fois (``cache_clear()`` dans les tests)."""
    return ApiSettings()
