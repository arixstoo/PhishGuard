"""Schémas de l'API.

Le contrat de la **réponse** d'analyse est ``phishguard.schema.AnalysisResponse``
(étape 2.11 bis). Les schémas d'entrée arrivent à l'étape 4.2.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict


class Health(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    status: Literal["ok"] = "ok"
