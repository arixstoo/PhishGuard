"""Client de l'API PhishGuard pour le bot (étape 5.11).

Le bot ne fait aucune analyse lui-même : il appelle ``POST /v1/analyze/url`` pour chaque
lien et ``POST /v1/analyze/text`` pour le texte du message, puis valide la réponse avec le
contrat figé (:class:`~phishguard.schema.AnalysisResponse`). Une réponse hors contrat est
une panne, pas un verdict.

- aucune redirection suivie : la clé d'API ne doit pas partir vers un autre hôte ;
- réponse bornée en taille ;
- les erreurs sont réduites à un code : un message d'exception de ``httpx`` recopie
  l'URL appelée, et le message de l'utilisateur ne doit jamais finir dans un journal.
"""

from __future__ import annotations

import re
from typing import Any

import httpx
from pydantic import ValidationError

from phishguard.explain.reasons import Language
from phishguard.schema import AnalysisResponse

MAX_RESPONSE_BYTES = 256 * 1024
# Caractères que l'API refuse dans un texte (étape 4.2) : contrôles C0 sauf tabulation et
# fins de ligne, DEL, C1, demi-codets isolés. Remplacés par une espace plutôt que de faire
# échouer l'analyse.
_FORBIDDEN_IN_TEXT = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f\ud800-\udfff]")


class ApiError(Exception):
    """Échec d'un appel à l'API : ``code`` seulement (jamais l'entrée, jamais l'URL)."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class PhishGuardApi:
    def __init__(self, http: httpx.AsyncClient, *, base_url: str, api_key: str | None) -> None:
        self._http = http
        self._base = base_url
        self._headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if api_key:
            self._headers["X-API-Key"] = api_key

    async def _post(self, path: str, body: dict[str, Any]) -> AnalysisResponse:
        try:
            response = await self._http.post(
                f"{self._base}{path}", json=body, headers=self._headers, follow_redirects=False
            )
        except httpx.TimeoutException:
            raise ApiError("timeout") from None
        except httpx.HTTPError:
            raise ApiError("network") from None
        if response.status_code == 429:
            raise ApiError("rate_limited")
        if response.status_code == 400:
            raise ApiError("invalid_input")  # URL que l'API ne sait pas découper
        if response.status_code != 200:
            raise ApiError(f"http_{response.status_code}")
        if len(response.content) > MAX_RESPONSE_BYTES:
            raise ApiError("invalid_response")
        try:
            return AnalysisResponse.model_validate_json(response.content)
        except ValidationError:
            raise ApiError("invalid_response") from None

    async def analyze_url(
        self, url: str, *, language: Language, threat_intel: bool
    ) -> AnalysisResponse:
        body = {
            "url": url,
            "language": language,
            "use_threat_intel": threat_intel,
            "analyst": False,
        }
        return await self._post("/v1/analyze/url", body)

    async def analyze_text(self, text: str, *, language: Language) -> AnalysisResponse:
        clean = _FORBIDDEN_IN_TEXT.sub(" ", text)
        body = {"text": clean, "channel": "messaging", "language": language, "analyst": False}
        return await self._post("/v1/analyze/text", body)


__all__ = ["ApiError", "PhishGuardApi"]
