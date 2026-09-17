"""Durable v3 job/attempt/event store: the minimal isolated-execution contract.

This module owns the state machine from :mod:`agent_foundry.state`, the
monotonic event log with cursors, generation fencing, idempotent mutating
calls, honest cancellation/recovery/``unknown_outcome``/quarantine semantics,
and immutable artifact attachment records built on
:mod:`agent_foundry.artifacts`.

It never executes anything: native launch/liveness/cancel evidence and
payload mounting belong to deployment adapters implementing
:mod:`agent_foundry.adapters`. There is no model routing, agent planning,
dependency fetching, transport, credentials, or UI here.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from .adapters import ArtifactVerifier, NativeLiveness
from .artifacts import (
    ArtifactManifest,
    ArtifactVerificationError,
    check_matches_job,
    validate_manifest,
    verify_payload_bytes,
)
from .attempts import AttemptConflict, canonical_hash
from .state import (
    ACCEPTED,
    CANCEL_REQUESTED,
    NON_TERMINAL,
    TERMINAL,
    can_transition,
    is_terminal,
)


class StaleGenerationError(ValueError):
    """A mutating call carried an outdated generation fencing token."""


class IllegalTransitionError(ValueError):
    """The requested state edge is not part of the v3 machine."""


class JobNotReadyError(ValueError):
    """``read_result`` was called before the job reached a terminal state."""


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass(frozen=True)
class Job:
    id: str
    project: str
    ref: str
    source_digest: str
    generation: int
    state: str
    policy_hash: str
    objective: str
    authority_ref: str
    command_profile: str
    native_identity: str | None
    result: dict | None
    quarantine_reason: str | None
    current_attempt_id: str
    attempt_count: int
    created_at: str
    updated_at: str


@dataclass(frozen=True)
class JobEvent:
    seq: int
    job_id: str
    attempt_id: str | None
    generation: int
    ts: str
    actor: str
    from_state: str
    to_state: str
    reason: str


@dataclass(frozen=True)
class AttachmentRecord:
    job_id: str
    artifact_digest: str
    manifest: dict
    actor: str
    attached_at: str


@dataclass(frozen=True)
class RecoveredJob:
    job: Job
    disposition: str  # "interrupted" | "unknown_outcome" | "cancelled" | "alive"


_SCHEMA = """
CREATE TABLE IF NOT EXISTS jobs (
    id TEXT PRIMARY KEY, project TEXT NOT NULL, ref TEXT NOT NULL,
    source_digest TEXT NOT NULL, generation INTEGER NOT NULL, state TEXT NOT NULL,
    policy_hash TEXT NOT NULL DEFAULT '', objective TEXT NOT NULL DEFAULT '',
    authority_ref TEXT NOT NULL DEFAULT '', command_profile TEXT NOT NULL DEFAULT '',
    native_identity TEXT, result_json TEXT, quarantine_reason TEXT,
    current_attempt_id TEXT NOT NULL, attempt_count INTEGER NOT NULL,
    created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS attempts (
    id TEXT PRIMARY KEY, job_id TEXT NOT NULL, attempt_no INTEGER NOT NULL,
    generation INTEGER NOT NULL, prior_attempt_id TEXT, actor TEXT NOT NULL,
    created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS events (
    seq INTEGER PRIMARY KEY AUTOINCREMENT, job_id TEXT NOT NULL,
    attempt_id TEXT, generation INTEGER NOT NULL, ts TEXT NOT NULL,
    actor TEXT NOT NULL, from_state TEXT NOT NULL, to_state TEXT NOT NULL,
    reason TEXT NOT NULL DEFAULT '', source_digest TEXT NOT NULL DEFAULT '',
    artifact_digests_json TEXT NOT NULL DEFAULT '[]', policy_hash TEXT NOT NULL DEFAULT '');
CREATE TABLE IF NOT EXISTS attachments (
    job_id TEXT NOT NULL, artifact_digest TEXT NOT NULL,
    manifest_json TEXT NOT NULL, actor TEXT NOT NULL, attached_at TEXT NOT NULL,
    PRIMARY KEY (job_id, artifact_digest));
CREATE TABLE IF NOT EXISTS idempotency (
    scope TEXT NOT NULL, key TEXT NOT NULL, request_hash TEXT NOT NULL,
    response_json TEXT NOT NULL, PRIMARY KEY (scope, key));
"""


class JobStore:
    """SQLite-backed durable store for the v3 execution contract."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as db:
            db.executescript(_SCHEMA)

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, isolation_level=None)
        db.row_factory = sqlite3.Row
        return db

    # -- row mapping ----------------------------------------------------

    @staticmethod
    def _job(row: sqlite3.Row) -> Job:
        data = dict(row)
        result_json = data.pop("result_json")
        return Job(
            **{k: data[k] for k in (
                "id", "project", "ref", "source_digest", "generation", "state",
                "policy_hash", "objective", "authority_ref", "command_profile",
                "native_identity", "quarantine_reason", "current_attempt_id",
                "attempt_count", "created_at", "updated_at")},
            result=json.loads(result_json) if result_json else None,
        )

    @staticmethod
    def _event(row: sqlite3.Row) -> JobEvent:
        data = dict(row)
        return JobEvent(
            seq=data["seq"], job_id=data["job_id"], attempt_id=data["attempt_id"],
            generation=data["generation"], ts=data["ts"], actor=data["actor"],
            from_state=data["from_state"], to_state=data["to_state"], reason=data["reason"],
        )

    def _get_job(self, db: sqlite3.Connection, job_id: str) -> Job:
        row = db.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
        if not row:
            raise KeyError(job_id)
        return self._job(row)

    # -- idempotency -----------------------------------------------------

    def _idem_begin(
        self, db: sqlite3.Connection, *, scope: str, key: str, payload: dict
    ) -> dict | None:
        """Return a stored response on replay; None when this call is new.

        Raises :class:`AttemptConflict` when the key is reused with a
        different payload.
        """
        if not key:
            raise ValueError("idempotency_key is required")
        digest = canonical_hash(payload)
        row = db.execute("SELECT request_hash, response_json FROM idempotency WHERE scope=? AND key=?", (scope, key)).fetchone()
        if row:
            if row["request_hash"] != digest:
                raise AttemptConflict("idempotency key belongs to a different request")
            return json.loads(row["response_json"])
        db.execute("INSERT INTO idempotency (scope, key, request_hash, response_json) VALUES (?, ?, ?, ?)", (scope, key, digest, "{}"))
        return None

    def _idem_store(self, db: sqlite3.Connection, *, scope: str, key: str, response: dict) -> None:
        db.execute("UPDATE idempotency SET response_json=? WHERE scope=? AND key=?", (json.dumps(response, sort_keys=True), scope, key))

    # -- events ----------------------------------------------------------

    def _record(
        self, db: sqlite3.Connection, job: Job, *, from_state: str, to_state: str,
        actor: str, reason: str, artifact_digests: list[str] | None = None,
    ) -> None:
        db.execute(
            "INSERT INTO events (job_id, attempt_id, generation, ts, actor, from_state, to_state, reason, source_digest, artifact_digests_json, policy_hash)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (job.id, job.current_attempt_id, job.generation, _utcnow(), actor,
             from_state, to_state, reason, job.source_digest,
             json.dumps(artifact_digests or []), job.policy_hash),
        )

    def _set_state(
        self, db: sqlite3.Connection, job: Job, *, to_state: str, actor: str,
        reason: str, check_generation: int | None = None, **fields: Any,
    ) -> Job:
        if check_generation is not None and job.generation != check_generation:
            raise StaleGenerationError(
                f"stale generation: have {job.generation}, call carried {check_generation}"
            )
        if job.state in TERMINAL:
            raise IllegalTransitionError(f"terminal job {job.id} in {job.state!r} is immutable")
        if not can_transition(job.state, to_state):
            raise IllegalTransitionError(f"illegal transition {job.state!r} -> {to_state!r}")
        from_state = job.state
        columns = {"state": to_state, "updated_at": _utcnow(), **fields}
        if "result" in columns:
            columns["result_json"] = json.dumps(columns.pop("result")) if columns["result"] is not None else None
        names = ", ".join(f"{name}=?" for name in columns)
        db.execute(f"UPDATE jobs SET {names} WHERE id=?", (*columns.values(), job.id))
        updated = self._get_job(db, job.id)
        self._record(db, updated, from_state=from_state, to_state=to_state, actor=actor, reason=reason)
        return updated

    def _attached_digests(self, db: sqlite3.Connection, job_id: str) -> list[str]:
        rows = db.execute("SELECT artifact_digest FROM attachments WHERE job_id=? ORDER BY attached_at", (job_id,)).fetchall()
        return [row["artifact_digest"] for row in rows]

    @staticmethod
    def _job_response(job: Job) -> dict:
        return {"job_id": job.id, "state": job.state, "generation": job.generation,
                "attempt_id": job.current_attempt_id}

    # -- minimal Foundry API --------------------------------------------

    def prepare_job(
        self, *, project: str, ref: str, source_digest: str, idempotency_key: str,
        actor: str = "supervisor", policy_hash: str = "", objective: str = "",
        authority_ref: str = "",
    ) -> tuple[Job, bool]:
        for name, value in (("project", project), ("ref", ref), ("source_digest", source_digest)):
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} must be a non-empty string")
        payload = {"op": "prepare_job", "project": project, "ref": ref,
                   "source_digest": source_digest, "policy_hash": policy_hash,
                   "objective": objective, "authority_ref": authority_ref}
        scope = f"prepare:{project}"
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            replay = self._idem_begin(db, scope=scope, key=idempotency_key, payload=payload)
            if replay is not None:
                job = self._get_job(db, replay["job_id"])
                db.execute("COMMIT")
                return job, True
            now = _utcnow()
            job_id = str(uuid.uuid4())
            attempt_id = str(uuid.uuid4())
            db.execute(
                "INSERT INTO jobs (id, project, ref, source_digest, generation, state, policy_hash, objective,"
                " authority_ref, command_profile, native_identity, result_json, quarantine_reason,"
                " current_attempt_id, attempt_count, created_at, updated_at)"
                " VALUES (?, ?, ?, ?, 1, 'accepted', ?, ?, ?, '', NULL, NULL, NULL, ?, 1, ?, ?)",
                (job_id, project, ref, source_digest, policy_hash, objective, authority_ref, attempt_id, now, now),
            )
            db.execute(
                "INSERT INTO attempts (id, job_id, attempt_no, generation, prior_attempt_id, actor, created_at)"
                " VALUES (?, ?, 1, 1, NULL, ?, ?)",
                (attempt_id, job_id, actor, now),
            )
            job = self._get_job(db, job_id)
            self._record(db, job, from_state="accepted", to_state="accepted",
                         actor=actor, reason="job accepted")
            self._idem_store(db, scope=scope, key=idempotency_key, response=self._job_response(job))
            db.execute("COMMIT")
            return job, False

    def mark_preparing(self, job_id: str, *, actor: str, expected_generation: int, idempotency_key: str) -> tuple[Job, bool]:
        return self._advance(job_id, ACCEPTED, "preparing", actor=actor,
                             expected_generation=expected_generation,
                             idempotency_key=idempotency_key, reason="preparing isolated workspace")

    def mark_ready(self, job_id: str, *, actor: str, expected_generation: int, idempotency_key: str) -> tuple[Job, bool]:
        return self._advance(job_id, "preparing", "ready", actor=actor,
                             expected_generation=expected_generation,
                             idempotency_key=idempotency_key, reason="workspace ready")

    def _advance(
        self, job_id: str, expect_state: str, to_state: str, *, actor: str,
        expected_generation: int, idempotency_key: str, reason: str,
    ) -> tuple[Job, bool]:
        payload = {"op": to_state, "job_id": job_id, "generation": expected_generation}
        scope = f"job:{job_id}"
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            replay = self._idem_begin(db, scope=scope, key=idempotency_key, payload=payload)
            if replay is not None:
                job = self._get_job(db, job_id)
                db.execute("COMMIT")
                return job, True
            job = self._get_job(db, job_id)
            if job.state != expect_state:
                raise IllegalTransitionError(f"expected {expect_state!r}, job is {job.state!r}")
            updated = self._set_state(db, job, to_state=to_state, actor=actor,
                                      reason=reason, check_generation=expected_generation)
            self._idem_store(db, scope=scope, key=idempotency_key, response=self._job_response(updated))
            db.execute("COMMIT")
            return updated, False

    def attach_artifact(
        self, *, job_id: str, manifest: dict, expected_generation: int,
        idempotency_key: str, actor: str = "supervisor",
        require_lock_digest: str | None = None, require_platform: str | None = None,
        payload: bytes | None = None, verifier: ArtifactVerifier | None = None,
    ) -> tuple[AttachmentRecord, bool]:
        """Validate ``manifest``, pin it to the job, and record attachment.

        On any validation, pinning, or verification failure the job is moved
        to ``quarantined`` (when non-terminal) and the mismatch is recorded;
        the original error is then re-raised.
        """
        raw_manifest = dict(manifest)
        payload_hash = canonical_hash(
            {"op": "attach_artifact", "job_id": job_id, "manifest": raw_manifest,
             "generation": expected_generation,
             "lock": require_lock_digest, "platform": require_platform}
        )
        scope = f"job:{job_id}"
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            replay = self._idem_begin(
                db, scope=scope, key=idempotency_key,
                payload={"op": "attach_artifact", "digest": payload_hash},
            )
            if replay is not None:
                row = db.execute(
                    "SELECT * FROM attachments WHERE job_id=? AND artifact_digest=?",
                    (job_id, replay["artifact_digest"])).fetchone()
                db.execute("COMMIT")
                record = AttachmentRecord(job_id, row["artifact_digest"],
                                          json.loads(row["manifest_json"]), row["actor"], row["attached_at"])
                return record, True
            job = self._get_job(db, job_id)

            def quarantine_and_raise(error: Exception) -> None:
                if job.state in NON_TERMINAL:
                    quarantined = self._set_state(
                        db, job, to_state="quarantined", actor=actor,
                        reason=f"artifact verification failed: {error}",
                        check_generation=expected_generation,
                        quarantine_reason=str(error))
                    self._idem_store(db, scope=scope, key=idempotency_key,
                                     response={**self._job_response(quarantined), "quarantined": True})
                db.execute("COMMIT")
                raise error

            try:
                parsed = validate_manifest(raw_manifest)
            except Exception as error:  # noqa: BLE001 - must quarantine on any failure
                quarantine_and_raise(error)
                raise AssertionError("unreachable")
            if job.generation != expected_generation:
                error = StaleGenerationError(
                    f"stale generation: have {job.generation}, call carried {expected_generation}")
                quarantine_and_raise(error)
                raise AssertionError("unreachable")
            if job.state in TERMINAL:
                db.execute("ROLLBACK")
                raise IllegalTransitionError(f"terminal job {job.id} in {job.state!r} cannot attach artifacts")
            try:
                check_matches_job(parsed, source_commit=job.source_digest,
                                  lock_digest=require_lock_digest, platform=require_platform)
                if payload is not None:
                    verify_payload_bytes(parsed, payload)
                if verifier is not None and not verifier.verify(parsed):
                    raise ArtifactVerificationError("deployment verifier rejected the payload")
            except Exception as error:  # noqa: BLE001 - must quarantine on any failure
                quarantine_and_raise(error)
                raise AssertionError("unreachable")
            now = _utcnow()
            db.execute(
                "INSERT OR IGNORE INTO attachments (job_id, artifact_digest, manifest_json, actor, attached_at)"
                " VALUES (?, ?, ?, ?, ?)",
                (job_id, parsed.payload_digest, json.dumps(parsed.to_dict(), sort_keys=True), actor, now),
            )
            row = db.execute(
                "SELECT * FROM attachments WHERE job_id=? AND artifact_digest=?",
                (job_id, parsed.payload_digest)).fetchone()
            self._record(db, job, from_state=job.state, to_state=job.state, actor=actor,
                         reason=f"artifact attached {parsed.payload_digest[:12]}",
                         artifact_digests=self._attached_digests(db, job_id))
            record = AttachmentRecord(job_id, row["artifact_digest"],
                                      json.loads(row["manifest_json"]), row["actor"], row["attached_at"])
            self._idem_store(db, scope=scope, key=idempotency_key,
                             response={**self._job_response(job), "artifact_digest": record.artifact_digest})
            db.execute("COMMIT")
            return record, False

    def execute(
        self, *, job_id: str, command_profile: str, objective: str, authority_ref: str,
        expected_generation: int, idempotency_key: str, actor: str = "supervisor",
        native_identity: str | None = None,
        launcher: Callable[..., str] | None = None,
    ) -> tuple[Job, bool]:
        """Move a ``ready`` job to ``running``.

        The native identity is stored *before* the job is reported as
        running, in a single transaction. Either ``native_identity`` or a
        ``launcher`` callable returning one must be supplied; Foundry never
        launches anything itself.
        """
        if not command_profile.strip() or not objective.strip() or not authority_ref.strip():
            raise ValueError("command_profile, objective, and authority_ref are required")
        payload = {"op": "execute", "job_id": job_id, "command_profile": command_profile,
                   "objective": objective, "authority_ref": authority_ref,
                   "generation": expected_generation}
        scope = f"job:{job_id}"
        identity = native_identity
        # Resolve the identity before touching durable state so the commit
        # below stores it atomically with the running transition.
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            replay = self._idem_begin(db, scope=scope, key=idempotency_key, payload=payload)
            if replay is not None:
                job = self._get_job(db, job_id)
                db.execute("COMMIT")
                return job, True
            job = self._get_job(db, job_id)
            if identity is None and launcher is not None:
                identity = launcher(job_id=job.id, attempt_id=job.current_attempt_id,
                                    command_profile=command_profile)
            if not identity or not str(identity).strip():
                db.execute("ROLLBACK")
                raise ValueError("a native identity is required before reporting running")
            updated = self._set_state(
                db, job, to_state="running", actor=actor,
                reason=f"executing {command_profile}",
                check_generation=expected_generation,
                native_identity=str(identity), command_profile=command_profile,
                objective=objective, authority_ref=authority_ref)
            self._idem_store(db, scope=scope, key=idempotency_key, response=self._job_response(updated))
            db.execute("COMMIT")
            return updated, False

    def record_result(
        self, *, job_id: str, outcome: str, result: dict | None = None,
        expected_generation: int, idempotency_key: str, actor: str = "supervisor",
    ) -> tuple[Job, bool]:
        if outcome not in ("succeeded", "failed"):
            raise ValueError("outcome must be 'succeeded' or 'failed'")
        payload = {"op": "record_result", "job_id": job_id, "outcome": outcome,
                   "result": result or {}, "generation": expected_generation}
        scope = f"job:{job_id}"
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            replay = self._idem_begin(db, scope=scope, key=idempotency_key, payload=payload)
            if replay is not None:
                job = self._get_job(db, job_id)
                db.execute("COMMIT")
                return job, True
            job = self._get_job(db, job_id)
            if job.state != "running":
                raise IllegalTransitionError(f"only a running job can record a result (job is {job.state!r})")
            updated = self._set_state(db, job, to_state=outcome, actor=actor,
                                      reason=f"native unit reported {outcome}",
                                      check_generation=expected_generation,
                                      result=result or {})
            self._idem_store(db, scope=scope, key=idempotency_key, response=self._job_response(updated))
            db.execute("COMMIT")
            return updated, False

    def fail_job(self, *, job_id: str, reason: str, expected_generation: int,
                 idempotency_key: str, actor: str = "supervisor") -> tuple[Job, bool]:
        if not reason.strip():
            raise ValueError("a failure reason is required")
        payload = {"op": "fail_job", "job_id": job_id, "reason": reason,
                   "generation": expected_generation}
        scope = f"job:{job_id}"
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            replay = self._idem_begin(db, scope=scope, key=idempotency_key, payload=payload)
            if replay is not None:
                job = self._get_job(db, job_id)
                db.execute("COMMIT")
                return job, True
            job = self._get_job(db, job_id)
            updated = self._set_state(db, job, to_state="failed", actor=actor,
                                      reason=reason, check_generation=expected_generation)
            self._idem_store(db, scope=scope, key=idempotency_key, response=self._job_response(updated))
            db.execute("COMMIT")
            return updated, False

    def cancel(self, *, job_id: str, reason: str, expected_generation: int,
               idempotency_key: str, actor: str = "supervisor") -> tuple[Job, bool]:
        """Request cancellation. The job settles via ``confirm_cancelled``."""
        if not reason.strip():
            raise ValueError("a cancellation reason is required")
        payload = {"op": "cancel", "job_id": job_id, "reason": reason,
                   "generation": expected_generation}
        scope = f"job:{job_id}"
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            replay = self._idem_begin(db, scope=scope, key=idempotency_key, payload=payload)
            if replay is not None:
                job = self._get_job(db, job_id)
                db.execute("COMMIT")
                return job, True
            job = self._get_job(db, job_id)
            updated = self._set_state(db, job, to_state="cancel_requested", actor=actor,
                                      reason=reason, check_generation=expected_generation)
            self._idem_store(db, scope=scope, key=idempotency_key, response=self._job_response(updated))
            db.execute("COMMIT")
            return updated, False

    def confirm_cancelled(self, *, job_id: str, expected_generation: int,
                          idempotency_key: str, actor: str = "supervisor",
                          native_dead: bool) -> tuple[Job, bool]:
        """Settle a ``cancel_requested`` job once the adapter proves death."""
        if not native_dead:
            raise ValueError("confirm_cancelled requires adapter evidence that the native unit is dead")
        payload = {"op": "confirm_cancelled", "job_id": job_id, "generation": expected_generation}
        scope = f"job:{job_id}"
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            replay = self._idem_begin(db, scope=scope, key=idempotency_key, payload=payload)
            if replay is not None:
                job = self._get_job(db, job_id)
                db.execute("COMMIT")
                return job, True
            job = self._get_job(db, job_id)
            if job.state != CANCEL_REQUESTED:
                raise IllegalTransitionError(f"only a cancel_requested job can be confirmed (job is {job.state!r})")
            updated = self._set_state(db, job, to_state="cancelled", actor=actor,
                                      reason="native unit confirmed dead",
                                      check_generation=expected_generation)
            self._idem_store(db, scope=scope, key=idempotency_key, response=self._job_response(updated))
            db.execute("COMMIT")
            return updated, False

    def mark_unknown_outcome(self, *, job_id: str, reason: str, expected_generation: int,
                             idempotency_key: str, actor: str = "supervisor") -> tuple[Job, bool]:
        """Record an honest ambiguous outcome. Never replayed automatically."""
        if not reason.strip():
            raise ValueError("an unknown-outcome reason is required")
        payload = {"op": "mark_unknown_outcome", "job_id": job_id, "reason": reason,
                   "generation": expected_generation}
        scope = f"job:{job_id}"
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            replay = self._idem_begin(db, scope=scope, key=idempotency_key, payload=payload)
            if replay is not None:
                job = self._get_job(db, job_id)
                db.execute("COMMIT")
                return job, True
            job = self._get_job(db, job_id)
            updated = self._set_state(db, job, to_state="unknown_outcome", actor=actor,
                                      reason=reason, check_generation=expected_generation)
            self._idem_store(db, scope=scope, key=idempotency_key, response=self._job_response(updated))
            db.execute("COMMIT")
            return updated, False

    def quarantine_job(self, *, job_id: str, reason: str, expected_generation: int,
                       idempotency_key: str, actor: str = "supervisor") -> tuple[Job, bool]:
        if not reason.strip():
            raise ValueError("a quarantine reason is required")
        payload = {"op": "quarantine_job", "job_id": job_id, "reason": reason,
                   "generation": expected_generation}
        scope = f"job:{job_id}"
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            replay = self._idem_begin(db, scope=scope, key=idempotency_key, payload=payload)
            if replay is not None:
                job = self._get_job(db, job_id)
                db.execute("COMMIT")
                return job, True
            job = self._get_job(db, job_id)
            updated = self._set_state(db, job, to_state="quarantined", actor=actor,
                                      reason=reason, check_generation=expected_generation,
                                      quarantine_reason=reason)
            self._idem_store(db, scope=scope, key=idempotency_key, response=self._job_response(updated))
            db.execute("COMMIT")
            return updated, False

    def retry_job(self, *, job_id: str, reason: str, expected_generation: int,
                  idempotency_key: str, actor: str = "supervisor") -> tuple[Job, bool]:
        """Open a new generation linked to the prior attempt.

        Legal from ``failed``, ``interrupted``, ``unknown_outcome``, and
        ``cancelled``. ``succeeded`` and ``quarantined`` are final.
        """
        if not reason.strip():
            raise ValueError("a retry reason is required")
        payload = {"op": "retry_job", "job_id": job_id, "reason": reason,
                   "generation": expected_generation}
        scope = f"job:{job_id}"
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            replay = self._idem_begin(db, scope=scope, key=idempotency_key, payload=payload)
            if replay is not None:
                job = self._get_job(db, job_id)
                db.execute("COMMIT")
                return job, True
            job = self._get_job(db, job_id)
            if job.state not in ("failed", "interrupted", "unknown_outcome", "cancelled"):
                raise IllegalTransitionError(f"job in {job.state!r} cannot be retried")
            if job.generation != expected_generation:
                raise StaleGenerationError(
                    f"stale generation: have {job.generation}, call carried {expected_generation}")
            now = _utcnow()
            new_generation = job.generation + 1
            attempt_id = str(uuid.uuid4())
            db.execute(
                "INSERT INTO attempts (id, job_id, attempt_no, generation, prior_attempt_id, actor, created_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?)",
                (attempt_id, job.id, job.attempt_count + 1, new_generation,
                 job.current_attempt_id, actor, now),
            )
            from_state = job.state
            db.execute(
                "UPDATE jobs SET state='accepted', generation=?, current_attempt_id=?,"
                " attempt_count=attempt_count+1, native_identity=NULL, result_json=NULL,"
                " quarantine_reason=NULL, updated_at=? WHERE id=?",
                (new_generation, attempt_id, now, job.id),
            )
            updated = self._get_job(db, job.id)
            self._record(db, updated, from_state=from_state, to_state="accepted",
                         actor=actor, reason=f"retry: {reason}")
            self._idem_store(db, scope=scope, key=idempotency_key, response=self._job_response(updated))
            db.execute("COMMIT")
            return updated, False

    # -- reads -----------------------------------------------------------

    def get_job(self, job_id: str) -> Job:
        with self._connect() as db:
            return self._get_job(db, job_id)

    def status(self, job_id: str, *, after_cursor: int = 0) -> tuple[Job, list[JobEvent], int]:
        """Return the job snapshot, events after ``after_cursor``, and cursor."""
        with self._connect() as db:
            job = self._get_job(db, job_id)
            rows = db.execute(
                "SELECT * FROM events WHERE job_id=? AND seq>? ORDER BY seq ASC", (job_id, after_cursor)).fetchall()
            events = [self._event(row) for row in rows]
            cursor = events[-1].seq if events else after_cursor
            return job, events, cursor

    def read_result(self, job_id: str) -> dict:
        with self._connect() as db:
            job = self._get_job(db, job_id)
            if job.state not in TERMINAL:
                raise JobNotReadyError(f"job {job_id} is {job.state!r}, not terminal")
            row = db.execute("SELECT MAX(seq) AS cursor FROM events WHERE job_id=?", (job_id,)).fetchone()
            return {
                "job_id": job.id,
                "state": job.state,
                "generation": job.generation,
                "attempt_id": job.current_attempt_id,
                "attempt_count": job.attempt_count,
                "result": job.result,
                "artifact_digests": self._attached_digests(db, job_id),
                "quarantine_reason": job.quarantine_reason,
                "cursor": row["cursor"] or 0,
            }

    def attachments(self, job_id: str) -> list[AttachmentRecord]:
        with self._connect() as db:
            rows = db.execute("SELECT * FROM attachments WHERE job_id=? ORDER BY attached_at", (job_id,)).fetchall()
            return [AttachmentRecord(job_id, row["artifact_digest"], json.loads(row["manifest_json"]),
                                     row["actor"], row["attached_at"]) for row in rows]

    # -- recovery --------------------------------------------------------

    def recover(
        self, *, liveness: NativeLiveness | None = None, actor: str = "reconciler",
    ) -> list[RecoveredJob]:
        """Reconcile non-terminal jobs after a restart without replaying work.

        - Jobs that never recorded a native identity (``accepted``,
          ``preparing``, ``ready``) certainly never started: ``interrupted``.
        - A ``cancel_requested`` job without an identity never launched:
          ``cancelled``.
        - A job with a native identity is ``alive`` when ``liveness``
          confirms it; otherwise its side effects are unconfirmed and it
          becomes ``unknown_outcome``. Without a liveness probe there is no
          evidence, so the outcome is likewise ``unknown_outcome``.
        """
        recovered: list[RecoveredJob] = []
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            rows = db.execute("SELECT * FROM jobs ORDER BY rowid").fetchall()
            for row in rows:
                job = self._job(row)
                if job.state not in NON_TERMINAL:
                    continue
                if job.native_identity is None:
                    if job.state == CANCEL_REQUESTED:
                        updated = self._set_state(db, job, to_state="cancelled", actor=actor,
                                                  reason="recover: cancel requested before launch")
                        recovered.append(RecoveredJob(updated, "cancelled"))
                    else:
                        updated = self._set_state(db, job, to_state="interrupted", actor=actor,
                                                  reason="recover: never started; no native identity recorded")
                        recovered.append(RecoveredJob(updated, "interrupted"))
                    continue
                alive = liveness(job.native_identity) if liveness is not None else False
                if alive:
                    recovered.append(RecoveredJob(job, "alive"))
                    continue
                reason = ("recover: native unit dead with unconfirmed side effects"
                          if liveness is not None else
                          "recover: no liveness evidence after restart; outcome unconfirmed")
                updated = self._set_state(db, job, to_state="unknown_outcome", actor=actor, reason=reason)
                recovered.append(RecoveredJob(updated, "unknown_outcome"))
            db.execute("COMMIT")
        return recovered
