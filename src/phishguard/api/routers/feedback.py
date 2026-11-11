"""Retours des utilisateurs (``POST /v1/feedback``).

Un retour signale un faux positif ou un faux négatif sur un **domaine**, jamais sur une
URL complète. Il est rangé dans une table de quarantaine, relue à la main par lots :
**aucun réentraînement automatique**, sans quoi n'importe qui pourrait empoisonner le
modèle en envoyant de faux retours. L'étape 4.10 complète ce circuit (relecture, tests de
non-influence) ; la route est déjà validée comme les autres.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends
from starlette.concurrency import run_in_threadpool

from phishguard.api.dependencies import AppState, app_state, require_json
from phishguard.api.errors import ERROR_RESPONSES
from phishguard.api.schemas import FeedbackAccepted, FeedbackRequest

router = APIRouter(tags=["retours"])


@router.post(
    "/feedback",
    status_code=202,
    response_model=FeedbackAccepted,
    dependencies=[Depends(require_json)],
    responses=ERROR_RESPONSES,
    summary="Signaler un faux positif ou un faux négatif",
)
async def feedback(
    body: FeedbackRequest,
    state: Annotated[AppState, Depends(app_state)],
) -> FeedbackAccepted:
    received_at = await run_in_threadpool(
        state.database.quarantine_feedback,
        domain=body.domain,
        verdict=body.verdict,
        judgement=body.judgement,
        key_id=None,  # clé d'API du client à l'étape 4.4 ; jamais l'adresse IP
    )
    return FeedbackAccepted(received_at=received_at)
