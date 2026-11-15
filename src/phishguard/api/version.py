"""Version de l'API : celle du paquet installé (``pyproject.toml``)."""

from __future__ import annotations

from functools import lru_cache
from importlib.metadata import PackageNotFoundError, version


@lru_cache(maxsize=1)
def api_version() -> str:
    try:
        return version("phishguard")
    except PackageNotFoundError:  # sources lues sans installation
        return "0.0.0"
