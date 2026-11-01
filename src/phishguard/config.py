"""Configuration et clés d'API des sources de Threat Intelligence (étape 2.1).

Les clés sont lues dans l'environnement, puis dans un fichier ``.env`` du répertoire
courant (jamais commité, voir ``.env.example``). L'environnement est prioritaire.

**Une clé absente désactive la source, elle ne fait pas échouer le démarrage.** Le
projet fonctionne sans aucune clé : l'analyse reste locale et les enrichisseurs qui en
ont besoin sont simplement ignorés. Une valeur vide ou faite d'espaces compte comme
absente, pour qu'une copie brute de ``.env.example`` ne change rien.

Les clés sont gardées en :class:`pydantic.SecretStr` : elles n'apparaissent ni dans
``repr``, ni dans les journaux, ni dans les messages d'erreur de validation. Seul
:meth:`Settings.api_key` renvoie la valeur en clair, au moment de l'appel à la source.

Vérifier la configuration sans afficher les clés ::

    python -m phishguard.config
"""

from __future__ import annotations

from functools import lru_cache
from typing import Final

from pydantic import SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Source d'enrichissement -> champ de Settings qui porte sa clé. Les noms des sources
# sont ceux du champ ``Signal.source`` des enrichisseurs (étape 2.2).
KEYED_SOURCES: Final[dict[str, str]] = {
    "google_safe_browsing": "gsb_api_key",
    "virustotal": "vt_api_key",
    "urlscan": "urlscan_api_key",
    "abuseipdb": "abuseipdb_api_key",
}


class Settings(BaseSettings):
    """Clés d'API, chacune facultative. Nom de variable = nom du champ en majuscules."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",  # .env contient aussi les clés des scripts de collecte
        frozen=True,
    )

    gsb_api_key: SecretStr | None = None
    vt_api_key: SecretStr | None = None
    urlscan_api_key: SecretStr | None = None
    abuseipdb_api_key: SecretStr | None = None

    @field_validator(*KEYED_SOURCES.values(), mode="before")
    @classmethod
    def _blank_is_missing(cls, value: object) -> object:
        if isinstance(value, SecretStr):
            value = value.get_secret_value()
        if isinstance(value, str):
            value = value.strip()
            return value or None
        return value

    def api_key(self, source: str) -> str | None:
        """Clé en clair de ``source``, ou ``None`` si elle n'est pas configurée."""
        secret: SecretStr | None = getattr(self, _field_for(source))
        return secret.get_secret_value() if secret is not None else None

    def is_enabled(self, source: str) -> bool:
        return self.api_key(source) is not None

    def enabled_sources(self) -> frozenset[str]:
        """Sources dont la clé est configurée."""
        return frozenset(s for s in KEYED_SOURCES if self.is_enabled(s))


def _field_for(source: str) -> str:
    try:
        return KEYED_SOURCES[source]
    except KeyError:
        known = ", ".join(sorted(KEYED_SOURCES))
        raise ValueError(f"source inconnue : {source!r} (connues : {known})") from None


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Configuration du processus, lue une seule fois.

    Les tests qui modifient l'environnement appellent ``get_settings.cache_clear()``.
    """
    return Settings()


def main() -> None:
    settings = get_settings()
    for source, field in KEYED_SOURCES.items():
        state = "activée" if settings.is_enabled(source) else "désactivée (clé absente)"
        print(f"{source:<22} {field.upper():<20} {state}")


if __name__ == "__main__":
    main()
