"""Retours des utilisateurs (``POST /v1/feedback``, étape 4.10).

Un retour signale un faux positif ou un faux négatif sur un **domaine**, jamais sur une
URL complète, avec le verdict reçu ; le serveur l'horodate lui-même. Il est rangé dans
une table de **quarantaine** que rien ne relit automatiquement : **aucun réentraînement
automatique**, sans quoi n'importe qui pourrait empoisonner le modèle en envoyant de faux
retours. Les signalements sont relus à la main, par lots
(``python -m phishguard.api.feedback``, docs/feedback.md).

Défenses, de l'extérieur vers l'intérieur :

1. limite de débit du niveau du client **et** quota propre aux retours
   (``rate_limit_feedback``, 20/heure par défaut), avant la lecture du corps ;
2. schéma strict : domaine ramené en ASCII, ni URL ni IP, jugement cohérent avec le
   verdict, aucun horodatage accepté du client ;
3. déduplication : un même rapporteur qui répète le même signalement n'ajoute rien, et
   reçoit la même réponse (rien à apprendre de l'état de la base) ;
4. plafond de la quarantaine (``feedback_max_pending``) : au-delà, 503, le disque ne se
   remplit pas ;
5. rapporteur désigné par un pseudonyme quotidien, jamais par son IP
   (:mod:`phishguard.api.pseudonym`), pour repérer un lot venu d'une seule source.
"""

from __future__ import annotations

import logging
from typing import Annotated

from fastapi import APIRouter, Depends
from starlette.concurrency import run_in_threadpool

from phishguard.api.dependencies import AppState, app_state, require_json
from phishguard.api.errors import JSON_ERROR_RESPONSES, ApiError
from phishguard.api.schemas import FeedbackAccepted, FeedbackRequest
from phishguard.api.security import Client, authenticated_client
from phishguard.api.storage import QuarantineFullError

logger = logging.getLogger(__name__)

router = APIRouter(tags=["retours"])

FEEDBACK_ROUTE = "/feedback"


@router.post(
    FEEDBACK_ROUTE,
    status_code=202,
    response_model=FeedbackAccepted,
    dependencies=[Depends(require_json)],
    responses=JSON_ERROR_RESPONSES,
    summary="Signaler un faux positif ou un faux négatif",
    description=(
        "Le retour est mis en **quarantaine** et relu à la main : il ne modifie ni le "
        "modèle ni les verdicts. Domaine seulement, jamais l'URL complète."
    ),
)
async def feedback(
    body: FeedbackRequest,
    state: Annotated[AppState, Depends(app_state)],
    client: Annotated[Client, Depends(authenticated_client)],
) -> FeedbackAccepted:
    settings = state.settings
    try:
        received_at = await run_in_threadpool(
            state.database.quarantine_feedback,
            domain=body.domain,
            verdict=body.verdict,
            judgement=body.judgement,
            key_id=client.key_id,  # pour écarter un lot abusif ; jamais l'adresse IP
            reporter=state.pseudonyms(client),
            client_tier="authenticated" if client.kind == "authenticated" else "anonymous",
            max_pending=settings.feedback_max_pending,
            dedup_seconds=settings.feedback_dedup_seconds,
        )
    except QuarantineFullError:
        logger.warning("quarantaine des retours pleine : retour refusé")
        raise ApiError(
            503,
            "feedback_unavailable",
            "Retours momentanément refusés : relecture en attente.",
            headers={"Retry-After": "3600"},
        ) from None
    return FeedbackAccepted(received_at=received_at)
