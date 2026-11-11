"""Base SQLite de l'API : empreintes des clés d'API (étape 4.4) et retours en quarantaine.

**Aucune clé n'est stockée en clair.** Une clé est un secret aléatoire de 256 bits
(``pg_`` suivi de 43 caractères base64url), montré une seule fois à sa création ; la base
n'en garde que l'empreinte SHA-256. Un hachage lent (bcrypt, Argon2) n'apporte rien ici :
il protège des mots de passe choisis par des humains, devinables par dictionnaire, pas
un secret de 256 bits tiré par ``secrets``. Il coûterait en revanche des dizaines de
millisecondes à **chaque** requête authentifiée.

Une fuite de la base ne donne donc aucune clé utilisable. Une clé se révoque sans être
supprimée (``revoked_at``) : l'historique reste, la clé ne passe plus.

Les **retours** des utilisateurs vont dans une table de quarantaine que rien ne relit
automatiquement : aucun réentraînement n'en dépend (empoisonnement, étape 4.10).

Une connexion par opération : SQLite l'ouvre en quelques dizaines de microsecondes, et
l'API l'appelle depuis plusieurs threads. Le mode WAL laisse lire pendant une écriture.
"""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import os
import re
import secrets
import sqlite3
import stat
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

KEY_PREFIX = "pg_"
KEY_TOKEN_BYTES = 32  # 256 bits
# Format exact d'une clé émise : toute autre valeur est refusée sans consulter la base.
KEY_PATTERN = re.compile(r"^pg_[A-Za-z0-9_-]{43}$")
KEY_ID_PATTERN = re.compile(r"^[0-9a-f]{12}$")
MAX_NAME_LENGTH = 64
SCHEMA_VERSION = 1

_SCHEMA = """
CREATE TABLE IF NOT EXISTS api_keys (
    key_id      TEXT PRIMARY KEY,
    key_hash    TEXT NOT NULL UNIQUE,
    name        TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    revoked_at  TEXT
);
CREATE TABLE IF NOT EXISTS feedback_quarantine (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    domain      TEXT NOT NULL,
    verdict     TEXT NOT NULL CHECK (verdict IN ('safe', 'suspicious', 'phishing')),
    judgement   TEXT NOT NULL CHECK (judgement IN ('false_positive', 'false_negative')),
    received_at TEXT NOT NULL,
    key_id      TEXT,
    reviewed    INTEGER NOT NULL DEFAULT 0
);
"""

ClientTier = Literal["anonymous", "authenticated"]


def hash_key(key: str) -> str:
    """Empreinte SHA-256 (hexadécimale) d'une clé d'API."""
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def generate_key() -> str:
    return KEY_PREFIX + secrets.token_urlsafe(KEY_TOKEN_BYTES)


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


@dataclass(frozen=True)
class ApiKey:
    """Clé enregistrée, sans le secret."""

    key_id: str
    name: str
    created_at: str
    revoked_at: str | None = None

    @property
    def active(self) -> bool:
        return self.revoked_at is None


class Database:
    """Accès à la base SQLite de l'API. Crée le fichier et son schéma au besoin."""

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        self._initialize()

    # ------------------------------------------------------------------ #

    def _initialize(self) -> None:
        # Un fichier, jamais « :memory: » : chaque connexion y verrait une base vide.
        if str(self.path) == ":memory:":
            raise ValueError("base SQLite en fichier attendue (une connexion par opération)")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            # Créé lisible par son seul propriétaire, avant qu'une ligne n'y soit écrite.
            fd = os.open(self.path, os.O_CREAT | os.O_WRONLY, 0o600)
            os.close(fd)
        db = sqlite3.connect(self.path, timeout=5.0)
        try:
            db.execute("PRAGMA journal_mode=WAL")
            db.executescript(_SCHEMA)
            db.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
            db.commit()
        finally:
            db.close()
        if os.name == "posix":
            mode = stat.S_IMODE(self.path.stat().st_mode)
            if mode & 0o077:
                os.chmod(self.path, 0o600)

    @contextlib.contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        db = sqlite3.connect(self.path, timeout=5.0, isolation_level=None)
        try:
            db.execute("PRAGMA foreign_keys=ON")
            db.execute("BEGIN")
            yield db
            db.execute("COMMIT")
        except BaseException:
            with contextlib.suppress(sqlite3.Error):
                db.execute("ROLLBACK")
            raise
        finally:
            db.close()

    # ------------------------------------------------------------------ #
    # Clés d'API
    # ------------------------------------------------------------------ #

    def create_key(self, name: str) -> tuple[ApiKey, str]:
        """Crée une clé ; renvoie sa fiche et le **secret, à montrer une seule fois**."""
        name = name.strip()
        if not name or len(name) > MAX_NAME_LENGTH or not name.isprintable():
            raise ValueError(f"nom de clé : 1 à {MAX_NAME_LENGTH} caractères imprimables")
        key = generate_key()
        record = ApiKey(key_id=secrets.token_hex(6), name=name, created_at=_now())
        with self._connect() as db:
            db.execute(
                "INSERT INTO api_keys (key_id, key_hash, name, created_at) VALUES (?, ?, ?, ?)",
                (record.key_id, hash_key(key), record.name, record.created_at),
            )
        return record, key

    def verify_key(self, key: str) -> ApiKey | None:
        """Fiche de la clé si elle est valide et active, sinon ``None``.

        Une valeur qui n'a pas le format d'une clé émise est refusée sans requête.
        """
        if not KEY_PATTERN.fullmatch(key):
            return None
        digest = hash_key(key)
        with self._connect() as db:
            row = db.execute(
                "SELECT key_id, key_hash, name, created_at, revoked_at FROM api_keys "
                "WHERE key_hash = ?",
                (digest,),
            ).fetchone()
        # La recherche se fait sur l'empreinte, que l'attaquant ne maîtrise pas : la
        # comparaison à temps constant est une ceinture de plus.
        if row is None or not hmac.compare_digest(row[1], digest) or row[4] is not None:
            return None
        return ApiKey(key_id=row[0], name=row[2], created_at=row[3])

    def revoke_key(self, key_id: str) -> bool:
        """Révoque ``key_id`` ; ``False`` si elle n'existe pas ou l'était déjà."""
        if not KEY_ID_PATTERN.fullmatch(key_id):
            return False
        with self._connect() as db:
            cursor = db.execute(
                "UPDATE api_keys SET revoked_at = ? WHERE key_id = ? AND revoked_at IS NULL",
                (_now(), key_id),
            )
        return cursor.rowcount == 1

    def list_keys(self) -> list[ApiKey]:
        with self._connect() as db:
            rows = db.execute(
                "SELECT key_id, name, created_at, revoked_at FROM api_keys ORDER BY created_at"
            ).fetchall()
        return [ApiKey(*row) for row in rows]

    # ------------------------------------------------------------------ #
    # Retours en quarantaine
    # ------------------------------------------------------------------ #

    def quarantine_feedback(
        self, *, domain: str, verdict: str, judgement: str, key_id: str | None
    ) -> datetime:
        """Range un retour en quarantaine ; renvoie l'heure de réception (serveur)."""
        received = datetime.now(UTC).replace(microsecond=0)
        with self._connect() as db:
            db.execute(
                "INSERT INTO feedback_quarantine (domain, verdict, judgement, received_at, key_id)"
                " VALUES (?, ?, ?, ?, ?)",
                (domain, verdict, judgement, received.isoformat(), key_id),
            )
        return received

    def count_feedback(self) -> int:
        with self._connect() as db:
            return int(db.execute("SELECT COUNT(*) FROM feedback_quarantine").fetchone()[0])
