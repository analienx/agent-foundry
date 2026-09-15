"""Durable, idempotent attempt records with no execution capability."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ACTIVE = {"claimed", "running"}
TERMINAL = {"succeeded", "failed", "cancelled", "interrupted"}


class AttemptConflict(ValueError):
    """An idempotency key was reused for a different request."""


class ActiveAttemptError(RuntimeError):
    """The workspace already owns a non-terminal attempt."""


@dataclass(frozen=True)
class Attempt:
    id: str
    workspace_id: str
    idempotency_key: str
    request_hash: str
    status: str
    exit_code: int | None


def canonical_hash(request: dict[str, Any]) -> str:
    encoded = json.dumps(request, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


class AttemptStore:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS attempts (
                id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, idempotency_key TEXT NOT NULL,
                request_hash TEXT NOT NULL, status TEXT NOT NULL, exit_code INTEGER,
                UNIQUE(workspace_id, idempotency_key))""")

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, isolation_level=None)
        db.row_factory = sqlite3.Row
        return db

    @staticmethod
    def _row(row: sqlite3.Row) -> Attempt:
        return Attempt(**dict(row))

    def claim(self, *, workspace_id: str, idempotency_key: str, request: dict[str, Any]) -> tuple[Attempt, bool]:
        if not workspace_id or not idempotency_key:
            raise ValueError("workspace_id and idempotency_key are required")
        digest = canonical_hash(request)
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            existing = db.execute("SELECT * FROM attempts WHERE workspace_id=? AND idempotency_key=?", (workspace_id, idempotency_key)).fetchone()
            if existing:
                attempt = self._row(existing)
                if attempt.request_hash != digest:
                    raise AttemptConflict("idempotency key belongs to a different request")
                db.execute("COMMIT")
                return attempt, True
            active = db.execute("SELECT id FROM attempts WHERE workspace_id=? AND status IN ('claimed','running')", (workspace_id,)).fetchone()
            if active:
                raise ActiveAttemptError(f"workspace already has active attempt {active['id']}")
            attempt = Attempt(str(uuid.uuid4()), workspace_id, idempotency_key, digest, "claimed", None)
            db.execute("INSERT INTO attempts VALUES (?, ?, ?, ?, ?, ?)", tuple(attempt.__dict__.values()))
            db.execute("COMMIT")
            return attempt, False

    def transition(self, attempt_id: str, status: str, *, exit_code: int | None = None) -> Attempt:
        if status not in ACTIVE | TERMINAL:
            raise ValueError(f"unsupported attempt status: {status}")
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM attempts WHERE id=?", (attempt_id,)).fetchone()
            if not row:
                raise KeyError(attempt_id)
            attempt = self._row(row)
            if attempt.status in TERMINAL:
                raise ValueError("terminal attempts cannot transition")
            db.execute("UPDATE attempts SET status=?, exit_code=? WHERE id=?", (status, exit_code, attempt_id))
            db.execute("COMMIT")
            return Attempt(attempt.id, attempt.workspace_id, attempt.idempotency_key, attempt.request_hash, status, exit_code)

    def recover_interrupted(self) -> list[Attempt]:
        """Terminalize in-flight records; deliberately never execute or retry them."""
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            rows = db.execute("SELECT * FROM attempts WHERE status IN ('claimed','running')").fetchall()
            db.execute("UPDATE attempts SET status='interrupted' WHERE status IN ('claimed','running')")
            db.execute("COMMIT")
            return [Attempt(a.id, a.workspace_id, a.idempotency_key, a.request_hash, "interrupted", a.exit_code) for a in map(self._row, rows)]
