"""Pseudonyme du rapporteur d'un retour (étape 4.10), sans donnée personnelle conservée.

À la relecture, il faut savoir si cent signalements d'un domaine viennent de cent
personnes ou d'une seule : c'est le premier indice d'une tentative d'empoisonnement. Mais
l'adresse IP d'un client anonyme ne doit pas être stockée (étape 4.6).

Le pseudonyme est un HMAC-SHA256 de la clé de limite de débit (IP, ou /64 en IPv6) sous
une **clé tirée au hasard, gardée en mémoire seulement et renouvelée chaque jour (UTC)** :

- deux retours d'une même source le même jour ont le même pseudonyme ;
- la clé n'est écrite nulle part : une fois renouvelée (ou le processus redémarré), plus
  personne, l'exploitant compris, ne peut relier un pseudonyme à une adresse, même en
  essayant les 2^32 adresses IPv4 ;
- d'un jour à l'autre, les pseudonymes d'une même source diffèrent : la base ne permet
  pas de suivre quelqu'un dans le temps.

Un client authentifié est désigné par l'identifiant public de sa clé (``key:<key_id>``),
déjà connu de l'exploitant, qui peut révoquer une clé abusive.

Limite assumée : avec plusieurs workers, chacun a sa clé, donc ses pseudonymes ; la
déduplication et le regroupement se font alors par worker.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
from collections.abc import Callable
from datetime import UTC, date, datetime

from phishguard.api.security import Client

PSEUDONYM_HEX_CHARS = 16  # 64 bits : assez pour regrouper, rien à inverser


def _today() -> date:
    return datetime.now(UTC).date()


class ReporterPseudonyms:
    """Pseudonymes du jour, sous une clé en mémoire renouvelée à chaque changement de date."""

    def __init__(self, *, today: Callable[[], date] = _today) -> None:
        self._today = today
        self._lock = threading.Lock()
        self._day: date | None = None
        self._key = b""

    def _current_key(self) -> bytes:
        day = self._today()
        with self._lock:
            if day != self._day:
                self._day, self._key = day, secrets.token_bytes(32)
            return self._key

    def __call__(self, client: Client) -> str:
        if client.kind == "authenticated" and client.key_id:
            return f"key:{client.key_id}"
        digest = hmac.new(self._current_key(), client.rate_key.encode(), hashlib.sha256)
        return f"anon:{digest.hexdigest()[:PSEUDONYM_HEX_CHARS]}"
