"""Erreurs de l'API : une seule enveloppe, jamais de trace de pile, jamais l'entrée.

Toute erreur a la forme ::

    {"error": {"code": "validation_error", "message": "…", "details": [...]}}

``code`` est stable (un client peut s'en servir), ``message`` est lisible et peut changer.

Deux règles de sécurité :

- **l'entrée n'est jamais renvoyée**. Pydantic recopie par défaut la valeur fautive
  (``input``) dans ses erreurs : une URL de 100 000 caractères reviendrait en entier, un
  jeton dans une URL serait réfléchi, des caractères de contrôle aussi. Seuls
  l'emplacement, le type et le message de chaque erreur sont gardés, et le nom d'un
  champ inconnu, choisi par le client, est remplacé par ``<champ inconnu>`` ;
- **une erreur interne ne dit rien** : 500, code ``internal_error``, la trace est dans le
  journal du serveur seulement.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from starlette.exceptions import HTTPException as StarletteHTTPException

logger = logging.getLogger(__name__)

MAX_ERROR_DETAILS = 20
# Emplacement d'une erreur : indices et noms de champs du schéma (identifiants) seulement.
_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}")
UNKNOWN_FIELD = "<champ inconnu>"

_STATUS_CODES: dict[int, str] = {
    400: "bad_request",
    401: "unauthorized",
    403: "forbidden",
    404: "not_found",
    405: "method_not_allowed",
    406: "not_acceptable",
    413: "payload_too_large",
    415: "unsupported_media_type",
    422: "validation_error",
    429: "rate_limited",
    500: "internal_error",
    503: "service_unavailable",
}


class ErrorDetail(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    loc: list[str | int] = Field(description="Emplacement du champ fautif")
    type: str
    msg: str


class ErrorBody(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    code: str = Field(pattern=r"^[a-z_]+$")
    message: str
    details: list[ErrorDetail] | None = None


class ErrorResponse(BaseModel):
    """Corps de toute réponse d'erreur (documenté dans l'OpenAPI)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    error: ErrorBody


class ApiError(Exception):
    """Erreur prévue, renvoyée telle quelle au client."""

    def __init__(
        self,
        status_code: int,
        code: str,
        message: str,
        *,
        headers: dict[str, str] | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message
        self.headers = headers


def error_response(
    status_code: int,
    code: str,
    message: str,
    *,
    details: list[ErrorDetail] | None = None,
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    body = ErrorResponse(error=ErrorBody(code=code, message=message, details=details))
    return JSONResponse(
        body.model_dump(mode="json", exclude_none=True), status_code=status_code, headers=headers
    )


def _safe_loc_part(part: Any, error_type: str, *, last: bool) -> str | int:
    """Élément d'emplacement renvoyable : un indice, ou un nom de champ **du schéma**.

    Le nom d'un champ inconnu (``extra_forbidden``) est choisi par le client : le
    renvoyer serait réfléchir son entrée. Il est remplacé, comme tout élément qui n'a pas
    la forme d'un identifiant (clé de dictionnaire arbitraire).
    """
    if isinstance(part, int):
        return part
    text = str(part)
    if (last and error_type == "extra_forbidden") or not _IDENTIFIER.fullmatch(text):
        return UNKNOWN_FIELD
    return text


def sanitized_details(errors: Any) -> list[ErrorDetail]:
    """Erreurs de validation sans ``input`` ni ``ctx`` : rien de l'entrée n'est renvoyé."""
    details: list[ErrorDetail] = []
    for error in list(errors)[:MAX_ERROR_DETAILS]:
        error_type = str(error.get("type", "value_error"))
        parts = list(error.get("loc", ()))
        loc = [
            _safe_loc_part(part, error_type, last=i == len(parts) - 1)
            for i, part in enumerate(parts)
        ]
        details.append(
            ErrorDetail(
                loc=loc,
                type=str(error.get("type", "value_error"))[:64],
                msg=str(error.get("msg", "valeur invalide"))[:200],
            )
        )
    return details


# --------------------------------------------------------------------------- #
# Gestionnaires
# --------------------------------------------------------------------------- #


# Chaque gestionnaire vérifie le type reçu par un ``if`` explicite : un ``assert`` serait
# retiré par ``python -O``. Un type inattendu est un défaut de câblage, pas de l'entrée.


def _miswired(handler: str, exc: Exception) -> TypeError:
    return TypeError(f"gestionnaire {handler} appelé pour {type(exc).__name__}")


async def _api_error(_request: Request, exc: Exception) -> JSONResponse:
    if not isinstance(exc, ApiError):
        raise _miswired("ApiError", exc)
    return error_response(exc.status_code, exc.code, exc.message, headers=exc.headers)


async def _validation_error(_request: Request, exc: Exception) -> JSONResponse:
    if not isinstance(exc, RequestValidationError):
        raise _miswired("RequestValidationError", exc)
    return error_response(
        422,
        "validation_error",
        "La requête est invalide : voir « details ».",
        details=sanitized_details(exc.errors()),
    )


async def _http_error(_request: Request, exc: Exception) -> JSONResponse:
    if not isinstance(exc, StarletteHTTPException):
        raise _miswired("HTTPException", exc)
    code = _STATUS_CODES.get(exc.status_code, "http_error")
    # Le détail des exceptions HTTP de Starlette et FastAPI est un texte fixe (« Not
    # Found ») ; une chaîne venue d'ailleurs serait tronquée.
    message = exc.detail if isinstance(exc.detail, str) else code
    return error_response(exc.status_code, code, message[:200], headers=exc.headers)


async def _unexpected(_request: Request, exc: Exception) -> JSONResponse:
    logger.exception("erreur interne", exc_info=exc)
    return error_response(500, "internal_error", "Erreur interne du serveur.")


def install_error_handlers(app: FastAPI) -> None:
    app.add_exception_handler(ApiError, _api_error)
    app.add_exception_handler(RequestValidationError, _validation_error)
    app.add_exception_handler(StarletteHTTPException, _http_error)
    app.add_exception_handler(Exception, _unexpected)


# Réponses d'erreur, pour la documentation OpenAPI des routes. Chaque route ne déclare que
# celles qu'elle peut produire : tests/test_api_contract.py provoque chaque statut documenté.
_ERROR_DESCRIPTIONS: dict[int, str] = {
    400: "Entrée bien formée mais inanalysable",
    401: "Clé d'API inconnue ou révoquée",
    413: "Corps de requête ou fichier trop gros",
    415: "Type de contenu refusé",
    422: "Entrée invalide (taille, format, caractère de contrôle)",
    429: "Limite de débit dépassée",
}


def error_responses(*statuses: int) -> dict[int | str, dict[str, Any]]:
    return {s: {"model": ErrorResponse, "description": _ERROR_DESCRIPTIONS[s]} for s in statuses}


# Toute route de /v1 : clé refusée, limite de débit.
ERROR_RESPONSES = error_responses(401, 429)
# Routes à corps JSON : en plus, taille, type de contenu, validation.
JSON_ERROR_RESPONSES = error_responses(401, 413, 415, 422, 429)
