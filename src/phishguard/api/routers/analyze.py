"""Routes d'analyse (étape 4.3) : URL, message, email.

Toutes renvoient le contrat figé de l'étape 2.11 bis (:class:`AnalysisResponse`). Les
routes ne contiennent aucune logique d'analyse : elles valident, délèguent à la couche
service et traduisent ses erreurs en codes HTTP. Chaque analyse ajoute à la ligne de
journal de sa requête son verdict et la version du modèle, rien de l'entrée (étape 4.6).
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, File, Form, UploadFile

from phishguard.api.dependencies import AppState, analysis_service, app_state, require_json
from phishguard.api.errors import ERROR_RESPONSES, ApiError, ErrorResponse
from phishguard.api.logs import annotate_analysis
from phishguard.api.schemas import TextRequest, UrlRequest
from phishguard.api.service import (
    AnalysisService,
    EmailUpload,
    InputTooLargeError,
    InvalidInputError,
)
from phishguard.explain.reasons import DEFAULT_LANGUAGE, Language
from phishguard.schema import AnalysisResponse

router = APIRouter(prefix="/analyze", tags=["analyse"])

# Types déclarés par les clients pour un .eml : navigateurs (message/rfc822), curl -F
# et la plupart des bibliothèques (application/octet-stream), certains clients mail.
EMAIL_CONTENT_TYPES = frozenset({"message/rfc822", "application/octet-stream", "text/plain"})
READ_CHUNK = 64 * 1024

Service = Annotated[AnalysisService, Depends(analysis_service)]


def _input_error(exc: Exception) -> ApiError:
    if isinstance(exc, InputTooLargeError):
        return ApiError(413, "payload_too_large", str(exc))
    return ApiError(400, "invalid_input", str(exc))


@router.post(
    "/url",
    response_model=AnalysisResponse,
    dependencies=[Depends(require_json)],
    responses={400: {"model": ErrorResponse, "description": "URL inanalysable"}, **ERROR_RESPONSES},
    summary="Analyser une URL",
)
async def analyze_url(body: UrlRequest, service: Service) -> AnalysisResponse:
    try:
        response = await service.analyze_url(body)
    except InvalidInputError as exc:
        raise _input_error(exc) from None
    annotate_analysis(response, threat_intel=body.use_threat_intel)
    return response


@router.post(
    "/text",
    response_model=AnalysisResponse,
    dependencies=[Depends(require_json)],
    responses=ERROR_RESPONSES,
    summary="Analyser un SMS ou un message",
)
async def analyze_text(body: TextRequest, service: Service) -> AnalysisResponse:
    response = await service.analyze_text(body)
    annotate_analysis(response)
    return response


@router.post(
    "/email",
    response_model=AnalysisResponse,
    responses={
        413: {"model": ErrorResponse, "description": "Fichier trop volumineux"},
        415: {"model": ErrorResponse, "description": "Type de fichier refusé"},
        **ERROR_RESPONSES,
    },
    summary="Analyser un email (fichier .eml)",
)
async def analyze_email(
    file: Annotated[UploadFile, File(description="Email brut au format .eml (RFC 5322)")],
    service: Service,
    state: Annotated[AppState, Depends(app_state)],
    language: Annotated[Language, Form(description="Langue des raisons")] = DEFAULT_LANGUAGE,
    analyst: Annotated[bool, Form(description="Inclure la vue analyste")] = False,
) -> AnalysisResponse:
    media_type = (file.content_type or "").split(";", 1)[0].strip().lower()
    if media_type not in EMAIL_CONTENT_TYPES:
        raise ApiError(415, "unsupported_media_type", "Fichier .eml attendu (message/rfc822).")
    content = await _read_bounded(file, state.settings.max_email_bytes)
    if not content.strip():
        raise ApiError(422, "validation_error", "Fichier vide.")
    try:
        response = await service.analyze_email(
            EmailUpload(content, language=language, analyst=analyst)
        )
    except (InvalidInputError, InputTooLargeError) as exc:
        raise _input_error(exc) from None
    annotate_analysis(response)
    return response


async def _read_bounded(file: UploadFile, limit: int) -> bytes:
    """Contenu du fichier, ou 413 dès que ``limit`` est dépassée (lecture par blocs)."""
    chunks: list[bytes] = []
    size = 0
    while chunk := await file.read(READ_CHUNK):
        size += len(chunk)
        if size > limit:
            raise ApiError(
                413, "payload_too_large", f"Email trop volumineux (limite : {limit} octets)."
            )
        chunks.append(chunk)
    return b"".join(chunks)
