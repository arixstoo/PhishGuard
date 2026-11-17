"""Page « coller et analyser » (étape 5.12, docs/web-page.md).

Pour celles et ceux qui n'installeront jamais d'extension : une page statique, servie par
l'API elle-même. Même origine que ``/v1/analyze/*`` : ni CORS à ouvrir, ni clé d'API dans
la page (elle appelle l'API au palier anonyme, limité par IP).

- Quatre fichiers fixes, lus une fois au démarrage ; aucun chemin n'est construit depuis
  la requête (pas de traversée de répertoire possible).
- Politique de contenu propre à la page (:data:`WEB_CSP`) : ses seuls fichiers, ses seules
  requêtes vers cette origine, aucun envoi de formulaire, aucun cadre, et **Trusted
  Types** : le navigateur refuse toute insertion de HTML par chaîne (``innerHTML``…), en
  plus de la règle du code (``textContent`` seulement).
- Hors schéma OpenAPI : ce n'est pas une route de l'API. Désactivable
  (``PHISHGUARD_API_WEB_PAGE_ENABLED=false``).
"""

from __future__ import annotations

from importlib.resources import files
from typing import Final

from fastapi import APIRouter
from fastapi.responses import Response

from phishguard.api.errors import ApiError

WEB_CSP: Final = (
    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; "
    "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; "
    "require-trusted-types-for 'script'; trusted-types 'none'"
)

_STATIC = files("phishguard.api").joinpath("static")
_PAGE: Final = _STATIC.joinpath("index.html").read_bytes()
ASSETS: Final[dict[str, tuple[bytes, str]]] = {
    name: (_STATIC.joinpath(name).read_bytes(), media_type)
    for name, media_type in {
        "paste.js": "text/javascript; charset=utf-8",
        "paste.css": "text/css; charset=utf-8",
        "icon.svg": "image/svg+xml",
    }.items()
}

router = APIRouter(include_in_schema=False)


@router.get("/")
async def page() -> Response:
    return Response(
        _PAGE,
        media_type="text/html; charset=utf-8",
        headers={"Content-Security-Policy": WEB_CSP},
    )


@router.get("/static/{name}")
async def asset(name: str) -> Response:
    found = ASSETS.get(name)
    if found is None:
        raise ApiError(404, "not_found", "Ressource introuvable.")
    content, media_type = found
    return Response(content, media_type=media_type)


__all__ = ["ASSETS", "WEB_CSP", "router"]
