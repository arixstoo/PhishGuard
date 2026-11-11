"""Base SQLite de l'API : retours des utilisateurs en quarantaine (étape 4.3).

Les **retours** des utilisateurs vont dans une table de quarantaine que rien ne relit
automatiquement : aucun réentraînement n'en dépend (empoisonnement, étape 4.10).

Une connexion par opération : SQLite l'ouvre en quelques dizaines de microsecondes, et
l'API l'appelle depuis plusieurs threads. Le mode WAL laisse lire pendant une écriture.
"""

from __future__ import annotations

import contextlib
import os
import sqlite3
import stat
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

SCHEMA_VERSION = 1

_SCHEMA = """
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
