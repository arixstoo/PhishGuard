"""Erreurs de l'API : une seule enveloppe, jamais de trace de pile, jamais l'entrée.

Toute erreur a la forme ::

    {"error": {"code": "validation_error", "message": "…", "details": [...]}}

``code`` est stable (un client peut s'en servir), ``message`` est lisible et peut changer.

Deux règles de sécurité :

- **l'entrée n'est jamais renvoyée**. Pydantic recopie par défaut la valeur fautive
  (``input``) dans ses erreurs : une URL de 100 000 caractères reviendrait en entier, un
  jeton dans une URL serait réfléchi, des caractères de contrôle aussi. Seuls
  l'emplacement, le type et le message de chaque erreur sont gardés ;
- **une erreur interne ne dit rien** : 500, code ``internal_error``, la trace est dans le
  journal du serveur seulement.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from starlette.exceptions import HTTPException as StarletteHTTPException

logger = logging.getLogger(__name__)

MAX_ERROR_DETAILS = 20

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


def sanitized_details(errors: Any) -> list[ErrorDetail]:
    """Erreurs de validation sans ``input`` ni ``ctx`` : rien de l'entrée n'est renvoyé."""
    details: list[ErrorDetail] = []
    for error in list(errors)[:MAX_ERROR_DETAILS]:
        loc = [part if isinstance(part, int) else str(part)[:64] for part in error.get("loc", ())]
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


async def _api_error(_request: Request, exc: Exception) -> JSONResponse:
    assert isinstance(exc, ApiError)
    return error_response(exc.status_code, exc.code, exc.message, headers=exc.headers)


async def _validation_error(_request: Request, exc: Exception) -> JSONResponse:
    assert isinstance(exc, RequestValidationError)
    return error_response(
        422,
        "validation_error",
        "La requête est invalide : voir « details ».",
        details=sanitized_details(exc.errors()),
    )


async def _http_error(_request: Request, exc: Exception) -> JSONResponse:
    assert isinstance(exc, StarletteHTTPException)
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


# Réponses d'erreur communes, pour la documentation OpenAPI des routes.
ERROR_RESPONSES: dict[int | str, dict[str, Any]] = {
    status: {"model": ErrorResponse, "description": description}
    for status, description in ((422, "Entrée invalide (taille, format, caractère de contrôle)"),)
}
