"""Routes d'analyse : URL, message, email (étape 4.3)."""

from __future__ import annotations

from fastapi import APIRouter

router = APIRouter(prefix="/analyze", tags=["analyse"])
