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
automatiquement : aucun réentraînement n'en dépend (empoisonnement, étape 4.10). Ils sont
relus à la main, par lots (``python -m phishguard.api.feedback``), puis acceptés ou
rejetés ; la table est bornée et purgée (voir :meth:`Database.quarantine_feedback`).

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
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal

KEY_PREFIX = "pg_"
KEY_TOKEN_BYTES = 32  # 256 bits
# Format exact d'une clé émise : toute autre valeur est refusée sans consulter la base.
KEY_PATTERN = re.compile(r"^pg_[A-Za-z0-9_-]{43}$")
KEY_ID_PATTERN = re.compile(r"^[0-9a-f]{12}$")
MAX_NAME_LENGTH = 64
SCHEMA_VERSION = 2

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

# Version 2 (étape 4.10) : pseudonyme du rapporteur, niveau du client et décision de
# relecture. ALTER TABLE ajoute les colonnes sans toucher aux lignes existantes.
_MIGRATIONS: dict[int, str] = {
    2: """
ALTER TABLE feedback_quarantine ADD COLUMN reporter TEXT;
ALTER TABLE feedback_quarantine ADD COLUMN client_tier TEXT
    CHECK (client_tier IN ('anonymous', 'authenticated'));
ALTER TABLE feedback_quarantine ADD COLUMN decision TEXT
    CHECK (decision IN ('accepted', 'rejected'));
ALTER TABLE feedback_quarantine ADD COLUMN reviewed_at TEXT;
CREATE INDEX IF NOT EXISTS feedback_dedup
    ON feedback_quarantine (reporter, domain, judgement, received_at);
CREATE INDEX IF NOT EXISTS feedback_pending ON feedback_quarantine (decision, id);
""",
}

FeedbackDecision = Literal["accepted", "rejected"]


class QuarantineFullError(RuntimeError):
    """La quarantaine a atteint sa taille maximale de retours en attente."""


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
            found = int(db.execute("PRAGMA user_version").fetchone()[0])
            if found > SCHEMA_VERSION:
                raise RuntimeError(
                    f"{self.path} : schéma {found}, plus récent que ce code ({SCHEMA_VERSION})"
                )
            db.executescript(_SCHEMA)
            # Migrations dans l'ordre, chacune une seule fois. Une base neuve
            # (user_version 0) reçoit le schéma initial puis toutes les migrations.
            for version in range(max(found, 1) + 1, SCHEMA_VERSION + 1):
                db.executescript(_MIGRATIONS[version])
            db.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
            db.commit()
        finally:
            db.close()
        if os.name == "posix":
            mode = stat.S_IMODE(self.path.stat().st_mode)
            if mode & 0o077:
                os.chmod(self.path, 0o600)

    @contextlib.contextmanager
    def _connect(self, *, immediate: bool = False) -> Iterator[sqlite3.Connection]:
        """Une transaction. ``immediate`` : verrou d'écriture pris dès le début, pour une
        lecture suivie d'une écriture qui dépend de ce qui a été lu (plafond, doublon)."""
        db = sqlite3.connect(self.path, timeout=5.0, isolation_level=None)
        try:
            db.execute("PRAGMA foreign_keys=ON")
            db.execute("BEGIN IMMEDIATE" if immediate else "BEGIN")
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
        self,
        *,
        domain: str,
        verdict: str,
        judgement: str,
        key_id: str | None,
        reporter: str | None = None,
        client_tier: ClientTier | None = None,
        max_pending: int | None = None,
        dedup_seconds: int = 0,
    ) -> datetime:
        """Range un retour en quarantaine ; renvoie l'heure de réception (serveur).

        - ``reporter`` : pseudonyme du client (jamais son IP ni sa clé), qui permet de
          repérer, à la relecture, un lot venu d'une seule source ;
        - ``dedup_seconds`` : un même rapporteur qui signale le même domaine avec le même
          jugement dans ce délai n'ajoute rien. La réponse est la même : rien à apprendre ;
        - ``max_pending`` : au-delà de ce nombre de retours en attente de relecture,
          :class:`QuarantineFullError`. La quarantaine ne grossit pas sans limite.

        Lecture et écriture dans la même transaction (``BEGIN IMMEDIATE``) : deux requêtes
        simultanées ne peuvent pas dépasser le plafond ni contourner la déduplication.
        """
        received = datetime.now(UTC).replace(microsecond=0)
        with self._connect(immediate=True) as db:
            if reporter is not None and dedup_seconds > 0:
                since = (received - timedelta(seconds=dedup_seconds)).isoformat()
                duplicate = db.execute(
                    "SELECT 1 FROM feedback_quarantine WHERE reporter = ? AND domain = ? "
                    "AND judgement = ? AND received_at >= ? LIMIT 1",
                    (reporter, domain, judgement, since),
                ).fetchone()
                if duplicate is not None:
                    return received
            if max_pending is not None:
                pending = db.execute(
                    "SELECT COUNT(*) FROM feedback_quarantine WHERE decision IS NULL"
                ).fetchone()[0]
                if pending >= max_pending:
                    raise QuarantineFullError(f"{pending} retours en attente de relecture")
            db.execute(
                "INSERT INTO feedback_quarantine (domain, verdict, judgement, received_at, "
                "key_id, reporter, client_tier) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (domain, verdict, judgement, received.isoformat(), key_id, reporter, client_tier),
            )
        return received

    def count_feedback(self, *, pending_only: bool = False) -> int:
        query = "SELECT COUNT(*) FROM feedback_quarantine"
        if pending_only:
            query += " WHERE decision IS NULL"
        with self._connect() as db:
            return int(db.execute(query).fetchone()[0])

    def pending_feedback(self, limit: int = 100, after_id: int = 0) -> list[FeedbackRecord]:
        """Retours en attente de relecture, les plus anciens d'abord (un lot)."""
        if limit < 1:
            raise ValueError("limit doit être positif")
        with self._connect() as db:
            rows = db.execute(
                "SELECT id, domain, verdict, judgement, received_at, key_id, reporter, "
                "client_tier, decision FROM feedback_quarantine "
                "WHERE decision IS NULL AND id > ? ORDER BY id LIMIT ?",
                (after_id, limit),
            ).fetchall()
        return [FeedbackRecord(*row) for row in rows]

    def feedback_summary(self) -> list[DomainSummary]:
        """Retours en attente regroupés par domaine et jugement, du plus signalé au moins.

        ``reporters`` : nombre de sources distinctes. Cent signalements d'un seul
        rapporteur ne valent pas cent signalements de cent rapporteurs : c'est le premier
        indice d'une tentative d'empoisonnement.
        """
        with self._connect() as db:
            rows = db.execute(
                "SELECT domain, judgement, COUNT(*), "
                "COUNT(DISTINCT COALESCE(reporter, key_id, '')), "
                "MIN(received_at), MAX(received_at) FROM feedback_quarantine "
                "WHERE decision IS NULL GROUP BY domain, judgement "
                "ORDER BY COUNT(*) DESC, domain"
            ).fetchall()
        return [DomainSummary(*row) for row in rows]

    def decide_feedback(self, ids: Iterable[int], decision: FeedbackDecision) -> int:
        """Accepte ou rejette des retours en attente ; renvoie le nombre de lignes décidées.

        Un retour déjà décidé n'est pas modifié : la décision d'un relecteur ne s'écrase pas.
        """
        if decision not in ("accepted", "rejected"):
            raise ValueError(f"décision inconnue : {decision!r}")
        selected = sorted({int(i) for i in ids})
        if not selected:
            return 0
        now = _now()
        changed = 0
        with self._connect() as db:
            for feedback_id in selected:
                cursor = db.execute(
                    "UPDATE feedback_quarantine SET decision = ?, reviewed = 1, reviewed_at = ? "
                    "WHERE id = ? AND decision IS NULL",
                    (decision, now, feedback_id),
                )
                changed += cursor.rowcount
        return changed

    def purge_feedback(self, older_than_days: int, *, include_pending: bool = False) -> int:
        """Supprime les retours décidés (et, au besoin, en attente) plus vieux que le délai.

        Rétention bornée : un retour relu n'a plus de raison d'être gardé.
        """
        if older_than_days < 0:
            raise ValueError("older_than_days doit être positif ou nul")
        cutoff = (datetime.now(UTC) - timedelta(days=older_than_days)).isoformat()
        query = "DELETE FROM feedback_quarantine WHERE received_at < ?"
        if not include_pending:
            query += " AND decision IS NOT NULL"
        with self._connect() as db:
            cursor = db.execute(query, (cutoff,))
        return cursor.rowcount

    def enforce_feedback_retention(self, retention_days: int) -> int:
        """Rétention maximale (PRIVACY.md) : tout retour plus vieux est supprimé, relu ou non."""
        if retention_days < 1:
            raise ValueError("retention_days doit être au moins 1")
        return self.purge_feedback(retention_days, include_pending=True)


@dataclass(frozen=True)
class FeedbackRecord:
    """Un retour de la quarantaine, tel qu'il est relu."""

    id: int
    domain: str
    verdict: str
    judgement: str
    received_at: str
    key_id: str | None
    reporter: str | None
    client_tier: str | None
    decision: str | None


@dataclass(frozen=True)
class DomainSummary:
    """Retours en attente pour un domaine et un jugement."""

    domain: str
    judgement: str
    reports: int
    reporters: int
    first_at: str
    last_at: str
