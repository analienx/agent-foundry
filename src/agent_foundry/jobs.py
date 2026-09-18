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

Launch protocol (two-phase, crash-safe)
---------------------------------------
``execute`` with a deployment ``launcher`` runs in two phases:

1. **Reserve (durable).** Inside one transaction the store derives a
   deterministic launch token from the idempotency scope/key, records it on
   the job, and stores a ``launching`` reservation marker. Only then does it
   commit.
2. **Launch (outside the transaction) and confirm (durable).** The launcher
   is invoked *after* the reservation commits, receiving the token, and the
   resulting native identity is committed with the ``ready -> running``
   transition in a second transaction.

A crash between reservation and confirmation can therefore never duplicate
side effects: retrying with the same idempotency key reuses the same launch
token (adapters MUST be idempotent on it), and :meth:`recover` reconciles any
still-reserved job to ``unknown_outcome`` rather than declaring it never
started. The launcher is never invoked while holding the database write lock.
"""

from __future__ import annotations

import inspect
import json
import sqlite3
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from .adapters import ArtifactVerifier, NativeLiveness
from .artifacts import (
    ArtifactValidationError,
    ArtifactVerificationError,
    check_matches_policy,
    validate_artifact_policy,
    validate_manifest,
    verify_payload_bytes,
)
from .attachment import (
    ArtifactAttachmentRequest,
    AttachmentReceipt,
    AttachmentReceiptError,
    AttachmentReceiptVerifier,
    AttachmentReplayError,
    AttachmentRequestError,
    verify_attachment_receipt,
)
from .attempts import AttemptConflict, canonical_hash
from .state import (
    ACCEPTED,
    CANCEL_REQUESTED,
    NON_TERMINAL,
    TERMINAL,
    can_transition,
)


class StaleGenerationError(ValueError):
    """A mutating call carried an outdated generation fencing token."""


class IllegalTransitionError(ValueError):
    """The requested state edge is not part of the v3 machine."""


class JobNotReadyError(ValueError):
    """``read_result`` was called before the job reached a terminal state."""


class _ResumeLaunch(Exception):
    """Control flow: phase A committed a reservation earlier; resume at phase B."""


#: States in which artifact attachment is legal. Attachments freeze at
#: ``execute`` time; ``running``, ``cancel_requested``, and terminal states
#: reject attachment so execution evidence always binds the frozen set.
ATTACHABLE_STATES = frozenset({ACCEPTED, "preparing", "ready"})


class _SqlReplayGuard:
    """Durable single-use receipt guard running inside the attach transaction.

    Consumption is committed together with the attachment row (or with the
    durable failure response for a quarantined attachment), so a receipt is
    consumed by the *attempt* that presented it and never by an outcome: a
    failed or rejected attachment still burns the receipt and a fresh receipt
    is required for a new attempt or generation. That is the fail-closed
    direction -- byte-identical receipt reuse can never succeed.
    """

    def __init__(self, db: sqlite3.Connection):
        self._db = db

    def reserve(self, replay_key: str, *, job_id: str, generation: int,
                replay_domain: str, receipt_digest: str) -> None:
        row = self._db.execute(
            "SELECT * FROM receipt_replays WHERE replay_key=?", (replay_key,)).fetchone()
        if row is not None:
            raise AttachmentReplayError(
                f"attachment receipt {row['receipt_digest'][:12]} already authorized an "
                f"attachment for job {row['job_id']!r} generation {row['generation']}")
        self._db.execute(
            "INSERT INTO receipt_replays (replay_key, job_id, generation, replay_domain,"
            " receipt_digest, reserved_at) VALUES (?, ?, ?, ?, ?, ?)",
            (replay_key, job_id, int(generation), replay_domain, receipt_digest, _utcnow()))

_ERROR_TYPES: dict[str, type[Exception]] = {
    "StaleGenerationError": StaleGenerationError,
    "IllegalTransitionError": IllegalTransitionError,
    "ArtifactValidationError": ArtifactValidationError,
    "ArtifactVerificationError": ArtifactVerificationError,
    "AttachmentRequestError": AttachmentRequestError,
    "AttachmentReceiptError": AttachmentReceiptError,
    "AttachmentReplayError": AttachmentReplayError,
    "AttemptConflict": AttemptConflict,
    "ValueError": ValueError,
}


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
    artifact_policy: dict
    frozen_artifact_digests: list[str]
    launch_token: str | None
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
    source_digest: str
    artifact_digests: list[str]
    policy_hash: str


@dataclass(frozen=True)
class AttachmentRecord:
    job_id: str
    artifact_digest: str
    manifest: dict
    actor: str
    attached_at: str
    generation: int = 1
    mount_point: str = ""
    receipt_digest: str = ""
    replay_domain: str = ""
    evidence: dict | None = None


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
    artifact_policy_json TEXT NOT NULL DEFAULT '{}',
    frozen_artifacts_json TEXT NOT NULL DEFAULT '[]',
    launch_token TEXT,
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
    generation INTEGER NOT NULL DEFAULT 1, mount_point TEXT NOT NULL DEFAULT '',
    receipt_digest TEXT NOT NULL DEFAULT '', replay_domain TEXT NOT NULL DEFAULT '',
    receipt_evidence_json TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (job_id, artifact_digest));
CREATE TABLE IF NOT EXISTS receipt_replays (
    replay_key TEXT PRIMARY KEY, job_id TEXT NOT NULL, generation INTEGER NOT NULL,
    replay_domain TEXT NOT NULL, receipt_digest TEXT NOT NULL, reserved_at TEXT NOT NULL);
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
            self._migrate(db)

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, isolation_level=None)
        db.row_factory = sqlite3.Row
        return db

    @staticmethod
    def _migrate(db: sqlite3.Connection) -> None:
        """Add post-0.2.0 columns to databases created by older schemas."""
        job_cols = {row["name"] for row in db.execute("PRAGMA table_info(jobs)").fetchall()}
        for name, ddl in (
            ("artifact_policy_json", "TEXT NOT NULL DEFAULT '{}'"),
            ("frozen_artifacts_json", "TEXT NOT NULL DEFAULT '[]'"),
            ("launch_token", "TEXT"),
        ):
            if name not in job_cols:
                db.execute(f"ALTER TABLE jobs ADD COLUMN {name} {ddl}")
        attach_cols = {row["name"] for row in db.execute("PRAGMA table_info(attachments)").fetchall()}
        for name, ddl in (
            ("generation", "INTEGER NOT NULL DEFAULT 1"),
            ("mount_point", "TEXT NOT NULL DEFAULT ''"),
            ("receipt_digest", "TEXT NOT NULL DEFAULT ''"),
            ("replay_domain", "TEXT NOT NULL DEFAULT ''"),
            ("receipt_evidence_json", "TEXT NOT NULL DEFAULT ''"),
        ):
            if name not in attach_cols:
                db.execute(f"ALTER TABLE attachments ADD COLUMN {name} {ddl}")

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
                "attempt_count", "launch_token", "created_at", "updated_at")},
            result=json.loads(result_json) if result_json else None,
            artifact_policy=json.loads(data.get("artifact_policy_json") or "{}"),
            frozen_artifact_digests=json.loads(data.get("frozen_artifacts_json") or "[]"),
        )

    @staticmethod
    def _event(row: sqlite3.Row) -> JobEvent:
        data = dict(row)
        return JobEvent(
            seq=data["seq"], job_id=data["job_id"], attempt_id=data["attempt_id"],
            generation=data["generation"], ts=data["ts"], actor=data["actor"],
            from_state=data["from_state"], to_state=data["to_state"], reason=data["reason"],
            source_digest=data.get("source_digest") or "",
            artifact_digests=json.loads(data.get("artifact_digests_json") or "[]"),
            policy_hash=data.get("policy_hash") or "",
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
        different payload. A bare ``{}`` placeholder left by a pre-hardening
        crash is treated as "no durable outcome yet" so the call can proceed
        under the current protocol instead of being misreported as replayed.
        """
        if not key:
            raise ValueError("idempotency_key is required")
        digest = canonical_hash(payload)
        row = db.execute("SELECT request_hash, response_json FROM idempotency WHERE scope=? AND key=?", (scope, key)).fetchone()
        if row:
            if row["request_hash"] != digest:
                raise AttemptConflict("idempotency key belongs to a different request")
            stored = json.loads(row["response_json"])
            if stored == {}:
                return None
            return stored
        db.execute("INSERT INTO idempotency (scope, key, request_hash, response_json) VALUES (?, ?, ?, ?)", (scope, key, digest, "{}"))
        return None

    def _idem_store(self, db: sqlite3.Connection, *, scope: str, key: str, response: dict) -> None:
        db.execute("UPDATE idempotency SET response_json=? WHERE scope=? AND key=?", (json.dumps(response, sort_keys=True), scope, key))

    @staticmethod
    def _idem_failure(job: Job | None, error: Exception) -> dict:
        response: dict[str, Any] = {
            "failed": True,
            "error_type": type(error).__name__,
            "error": str(error),
        }
        if job is not None:
            response.update(JobStore._job_response(job))
        return response

    @staticmethod
    def _raise_stored_failure(response: dict) -> None:
        error_type = response.get("error_type", "ValueError")
        message = response.get("error", "durable request failed")
        raise _ERROR_TYPES.get(error_type, ValueError)(message)

    # -- events ----------------------------------------------------------

    def _record(
        self, db: sqlite3.Connection, job: Job, *, from_state: str, to_state: str,
        actor: str, reason: str, artifact_digests: list[str] | None = None,
    ) -> None:
        if artifact_digests is None:
            artifact_digests = self._attached_digests(db, job.id)
        db.execute(
            "INSERT INTO events (job_id, attempt_id, generation, ts, actor, from_state, to_state, reason, source_digest, artifact_digests_json, policy_hash)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (job.id, job.current_attempt_id, job.generation, _utcnow(), actor,
             from_state, to_state, reason, job.source_digest,
             json.dumps(artifact_digests), job.policy_hash),
        )

    def _set_state(
        self, db: sqlite3.Connection, job: Job, *, to_state: str, actor: str,
        reason: str, check_generation: int | None = None,
        artifact_digests: list[str] | None = None, **fields: Any,
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
        self._record(db, updated, from_state=from_state, to_state=to_state, actor=actor,
                     reason=reason, artifact_digests=artifact_digests)
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
        authority_ref: str = "", artifact_policy: dict | None = None,
    ) -> tuple[Job, bool]:
        """Accept a job and persist its job-bound artifact policy.

        When ``artifact_policy`` is given it is validated, persisted on the
        job, and bound to ``policy_hash`` (an explicitly passed
        ``policy_hash`` must equal the policy digest). Later
        :meth:`attach_artifact` calls enforce it: callers cannot omit or
        contradict declared constraints.
        """
        for name, value in (("project", project), ("ref", ref), ("source_digest", source_digest)):
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} must be a non-empty string")
        normalized_policy: dict = {}
        if artifact_policy is not None:
            normalized_policy = validate_artifact_policy(artifact_policy)
            computed = canonical_hash({"artifact_policy": normalized_policy})
            if policy_hash and policy_hash != computed:
                raise ValueError("policy_hash does not match the artifact_policy digest")
            policy_hash = computed
        payload = {"op": "prepare_job", "project": project, "ref": ref,
                   "source_digest": source_digest, "policy_hash": policy_hash,
                   "objective": objective, "authority_ref": authority_ref,
                   "artifact_policy": normalized_policy}
        scope = f"prepare:{project}"
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                replay = self._idem_begin(db, scope=scope, key=idempotency_key, payload=payload)
                if replay is not None:
                    if replay.get("failed"):
                        self._raise_stored_failure(replay)
                    job = self._get_job(db, replay["job_id"])
                    db.execute("COMMIT")
                    return job, True
                now = _utcnow()
                job_id = str(uuid.uuid4())
                attempt_id = str(uuid.uuid4())
                db.execute(
                    "INSERT INTO jobs (id, project, ref, source_digest, generation, state, policy_hash, objective,"
                    " authority_ref, command_profile, native_identity, result_json, quarantine_reason,"
                    " current_attempt_id, attempt_count, artifact_policy_json, frozen_artifacts_json,"
                    " launch_token, created_at, updated_at)"
                    " VALUES (?, ?, ?, ?, 1, 'accepted', ?, ?, ?, '', NULL, NULL, NULL, ?, 1, ?, '[]', NULL, ?, ?)",
                    (job_id, project, ref, source_digest, policy_hash, objective, authority_ref,
                     attempt_id, json.dumps(normalized_policy, sort_keys=True), now, now),
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
            except Exception:
                try:
                    db.execute("ROLLBACK")
                except Exception:
                    pass
                raise

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
            try:
                replay = self._idem_begin(db, scope=scope, key=idempotency_key, payload=payload)
                if replay is not None:
                    if replay.get("failed"):
                        self._raise_stored_failure(replay)
                    job = self._get_job(db, job_id)
                    db.execute("COMMIT")
                    return job, True
                job = self._get_job(db, job_id)
                if job.generation != expected_generation:
                    error = StaleGenerationError(
                        f"stale generation: have {job.generation}, call carried {expected_generation}")
                    self._idem_store(db, scope=scope, key=idempotency_key,
                                     response=self._idem_failure(job, error))
                    db.execute("COMMIT")
                    raise error
                if job.state != expect_state:
                    error = IllegalTransitionError(
                        f"expected {expect_state!r}, job is {job.state!r}")
                    self._idem_store(db, scope=scope, key=idempotency_key,
                                     response=self._idem_failure(job, error))
                    db.execute("COMMIT")
                    raise error
                updated = self._set_state(db, job, to_state=to_state, actor=actor,
                                          reason=reason, check_generation=expected_generation)
                self._idem_store(db, scope=scope, key=idempotency_key, response=self._job_response(updated))
                db.execute("COMMIT")
                return updated, False
            except Exception:
                try:
                    db.execute("ROLLBACK")
                except Exception:
                    pass
                raise

    def attach_artifact(
        self, *, job_id: str, manifest: dict, expected_generation: int,
        idempotency_key: str, actor: str = "supervisor",
        require_lock_digest: str | None = None, require_platform: str | None = None,
        require_source_repo: str | None = None, require_arch: str | None = None,
        require_toolchain: str | None = None, require_lifecycle_policy: str | None = None,
        require_provenance_ref: str | None = None,
        payload: bytes | None = None, verifier: ArtifactVerifier | None = None,
        attachment_request: ArtifactAttachmentRequest | dict | None = None,
        attachment_receipt: AttachmentReceipt | dict | None = None,
        receipt_verifier: AttachmentReceiptVerifier | None = None,
    ) -> tuple[AttachmentRecord, bool]:
        """Verify a payload and record an immutable attachment.

        The manifest is schema-validated, pinned to the job's source digest
        and job-bound artifact policy (callers cannot omit required
        constraints), checked byte-for-byte against ``payload``, confirmed by
        the deployment ``verifier``, and exposed through the adapter's
        read-only mount. Only then is the attachment recorded. ``payload``
        and ``verifier`` are both required: an unverified or unmounted
        attachment is never recorded.

        Generation fencing is checked before any mutation: a stale attach
        from generation N raises :class:`StaleGenerationError` without
        touching generation N+1 (no quarantine, no event, no record).
        Attachment is legal only in ``accepted``/``preparing``/``ready``;
        ``running``, ``cancel_requested``, and terminal states reject the
        call. A failed call stores its durable failure under the idempotency
        key so replays raise the same error instead of ``KeyError``.

        When the job's artifact policy sets ``require_attachment_receipt`` (or
        when any receipt argument is supplied), an Agent Interop authenticated
        receipt must be presented and verified before the attachment is
        recorded: the request is bound to the manifest, job, and current
        attempt, the receipt is authenticated by the deployment
        ``receipt_verifier``, its plan/step evidence is checked against the
        manifest verification plan, and the receipt is durably consumed so a
        byte-identical reply can never authorize a second attachment.
        """
        raw_manifest = dict(manifest)
        caller_constraints = {
            name: value for name, value in (
                ("source_repo", require_source_repo),
                ("lock_digest", require_lock_digest),
                ("platform", require_platform),
                ("arch", require_arch),
                ("toolchain", require_toolchain),
                ("lifecycle_policy", require_lifecycle_policy),
                ("provenance_ref", require_provenance_ref),
            ) if value is not None
        }
        payload_hash = canonical_hash(
            {"op": "attach_artifact", "job_id": job_id, "manifest": raw_manifest,
             "generation": expected_generation, "constraints": caller_constraints,
             "has_payload": payload is not None,
             "verifier": type(verifier).__name__ if verifier is not None else None,
             "attachment_request": (attachment_request.request_hash
                                    if isinstance(attachment_request, ArtifactAttachmentRequest)
                                    else attachment_request),
             "has_receipt": attachment_receipt is not None}
        )
        scope = f"job:{job_id}"
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                replay = self._idem_begin(
                    db, scope=scope, key=idempotency_key,
                    payload={"op": "attach_artifact", "digest": payload_hash},
                )
                if replay is not None:
                    if replay.get("failed"):
                        db.execute("COMMIT")
                        self._raise_stored_failure(replay)
                    row = db.execute(
                        "SELECT * FROM attachments WHERE job_id=? AND artifact_digest=?",
                        (job_id, replay["artifact_digest"])).fetchone()
                    db.execute("COMMIT")
                    if row is None:
                        # Row removed by a later retry: rebuild from the
                        # durable response instead of raising KeyError.
                        record = AttachmentRecord(
                            job_id, replay["artifact_digest"],
                            replay.get("manifest", {}), replay.get("actor", actor),
                            replay.get("attached_at", ""), replay.get("generation", 1),
                            replay.get("mount_point", ""),
                            replay.get("receipt_digest", ""),
                            replay.get("replay_domain", ""),
                            replay.get("receipt_evidence"))
                        return record, True
                    record = self._attachment(row)
                    return record, True
                job = self._get_job(db, job_id)

                # Fencing first: a stale attach must not mutate or quarantine
                # the current generation.
                if job.generation != expected_generation:
                    error = StaleGenerationError(
                        f"stale generation: have {job.generation}, call carried {expected_generation}")
                    self._idem_store(db, scope=scope, key=idempotency_key,
                                     response=self._idem_failure(job, error))
                    db.execute("COMMIT")
                    raise error
                # Attach window: frozen at execute; never in running,
                # cancel_requested, or terminal states. A rejection here is a
                # caller error, not payload evidence: no quarantine.
                if job.state not in ATTACHABLE_STATES:
                    error = IllegalTransitionError(
                        f"attachments freeze before execution; job is {job.state!r}")
                    self._idem_store(db, scope=scope, key=idempotency_key,
                                     response=self._idem_failure(job, error))
                    db.execute("COMMIT")
                    raise error

                def quarantine_and_raise(error: Exception) -> None:
                    if job.state in NON_TERMINAL:
                        quarantined = self._set_state(
                            db, job, to_state="quarantined", actor=actor,
                            reason=f"artifact verification failed: {error}",
                            check_generation=expected_generation,
                            quarantine_reason=str(error), launch_token=None)
                        self._idem_store(db, scope=scope, key=idempotency_key,
                                         response=self._idem_failure(quarantined, error))
                    else:
                        self._idem_store(db, scope=scope, key=idempotency_key,
                                         response=self._idem_failure(job, error))
                    db.execute("COMMIT")
                    raise error

                try:
                    parsed = validate_manifest(
                        raw_manifest,
                        allowed_binaries=(verifier.allowed_verifier_binaries
                                          if verifier is not None else None),
                        allowed_profiles=(verifier.allowed_verification_profiles
                                          if verifier is not None else None),
                    )
                except Exception as error:  # noqa: BLE001 - must quarantine on any failure
                    quarantine_and_raise(error)
                    raise AssertionError("unreachable")
                try:
                    check_matches_policy(parsed, source_commit=job.source_digest,
                                         policy=job.artifact_policy,
                                         caller_constraints=caller_constraints)
                    if payload is None:
                        raise ArtifactVerificationError(
                            "payload bytes are required: unverified attachments are never recorded")
                    if verifier is None:
                        raise ArtifactVerificationError(
                            "a deployment verifier is required: unmounted attachments are never recorded")
                    verify_payload_bytes(parsed, payload)
                    if not verifier.verify(parsed):
                        raise ArtifactVerificationError("deployment verifier rejected the payload")
                    evidence = self._verify_attachment_receipt(
                        db, job=job, manifest=parsed,
                        attachment_request=attachment_request,
                        attachment_receipt=attachment_receipt,
                        receipt_verifier=receipt_verifier)
                    mount_point = verifier.mount_readonly(job_id=job.id, manifest=parsed)
                    if not isinstance(mount_point, str) or not mount_point.strip():
                        raise ArtifactVerificationError(
                            "deployment verifier returned no read-only mount point")
                except Exception as error:  # noqa: BLE001 - must quarantine on any failure
                    quarantine_and_raise(error)
                    raise AssertionError("unreachable")
                now = _utcnow()
                db.execute(
                    "INSERT OR IGNORE INTO attachments (job_id, artifact_digest, manifest_json, actor, attached_at,"
                    " generation, mount_point, receipt_digest, replay_domain, receipt_evidence_json)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (job_id, parsed.payload_digest, json.dumps(parsed.to_dict(), sort_keys=True),
                     actor, now, job.generation, mount_point.strip(),
                     evidence.receipt_digest if evidence else "",
                     evidence.replay_domain if evidence else "",
                     json.dumps(evidence.to_dict(), sort_keys=True) if evidence else ""),
                )
                row = db.execute(
                    "SELECT * FROM attachments WHERE job_id=? AND artifact_digest=?",
                    (job_id, parsed.payload_digest)).fetchone()
                self._record(db, job, from_state=job.state, to_state=job.state, actor=actor,
                             reason=f"artifact attached {parsed.payload_digest[:12]}",
                             artifact_digests=self._attached_digests(db, job_id))
                assert row is not None
                record = self._attachment(row)
                self._idem_store(db, scope=scope, key=idempotency_key,
                                 response={**self._job_response(job),
                                           "artifact_digest": record.artifact_digest,
                                           "manifest": record.manifest, "actor": record.actor,
                                           "attached_at": record.attached_at,
                                           "generation": record.generation,
                                           "mount_point": record.mount_point,
                                           "receipt_digest": record.receipt_digest,
                                           "replay_domain": record.replay_domain,
                                           "receipt_evidence": record.evidence})
                db.execute("COMMIT")
                return record, False
            except Exception:
                try:
                    db.execute("ROLLBACK")
                except Exception:
                    pass
                raise

    @staticmethod
    def _attachment(row: sqlite3.Row) -> AttachmentRecord:
        keys = row.keys()
        evidence_json = row["receipt_evidence_json"] if "receipt_evidence_json" in keys else ""
        return AttachmentRecord(
            row["job_id"], row["artifact_digest"], json.loads(row["manifest_json"]),
            row["actor"], row["attached_at"], row["generation"], row["mount_point"],
            row["receipt_digest"] if "receipt_digest" in keys else "",
            row["replay_domain"] if "replay_domain" in keys else "",
            json.loads(evidence_json) if evidence_json else None)

    @staticmethod
    def _verify_attachment_receipt(
        db: sqlite3.Connection, *, job: Job, manifest, attachment_request,
        attachment_receipt, receipt_verifier,
    ):
        """Verify the Agent Interop receipt for an attachment, fail closed.

        Returns the :class:`AttachmentReceiptEvidence` for durable recording
        (or ``None`` when no receipt was required). When the job's artifact
        policy demands a receipt, all three receipt arguments are mandatory;
        supplying any of them always triggers verification so a caller can
        never downgrade an authenticated attachment to an unauthenticated one.
        """
        required = bool(job.artifact_policy.get("require_attachment_receipt"))
        supplied = (attachment_request is not None or attachment_receipt is not None
                    or receipt_verifier is not None)
        if not required and not supplied:
            return None
        if attachment_request is None or attachment_receipt is None or receipt_verifier is None:
            raise ArtifactVerificationError(
                "an authenticated Agent Interop attachment receipt is required: request, "
                "receipt, and deployment receipt verifier must all be supplied")
        request = (attachment_request if isinstance(attachment_request, ArtifactAttachmentRequest)
                   else ArtifactAttachmentRequest.from_dict(attachment_request))
        receipt = (attachment_receipt if isinstance(attachment_receipt, AttachmentReceipt)
                   else AttachmentReceipt.from_dict(attachment_receipt))
        expected = ArtifactAttachmentRequest.for_manifest(
            manifest, submitting_identity=request.submitting_identity,
            job_id=job.id, attempt_id=job.current_attempt_id,
            generation=job.generation)
        if request != expected:
            raise ArtifactVerificationError(
                "attachment request does not match the manifest, job, and current attempt")
        return verify_attachment_receipt(
            receipt, request, verifier=receipt_verifier,
            verify_plan=manifest.verify_commands,
            replay_guard=_SqlReplayGuard(db))

    @staticmethod
    def _launch_token(*, scope: str, key: str) -> str:
        """Derive the durable idempotent launch token for an execute call."""
        return canonical_hash({"launch_reservation": True, "scope": scope, "key": key})

    @staticmethod
    def _invoke_launcher(launcher: Callable[..., str], *, job: Job,
                         command_profile: str, launch_token: str) -> str:
        """Invoke the deployment launcher outside any database transaction."""
        try:
            signature = inspect.signature(launcher)
        except (TypeError, ValueError):
            signature = None
        if signature is not None:
            try:
                signature.bind(job_id=job.id, attempt_id=job.current_attempt_id,
                               command_profile=command_profile, launch_token=launch_token)
            except TypeError:
                return launcher(job_id=job.id, attempt_id=job.current_attempt_id,
                                command_profile=command_profile)
        return launcher(job_id=job.id, attempt_id=job.current_attempt_id,
                        command_profile=command_profile, launch_token=launch_token)

    def execute(
        self, *, job_id: str, command_profile: str, objective: str, authority_ref: str,
        expected_generation: int, idempotency_key: str, actor: str = "supervisor",
        native_identity: str | None = None,
        launcher: Callable[..., str] | None = None,
    ) -> tuple[Job, bool]:
        """Move a ``ready`` job to ``running`` under the two-phase protocol.

        With ``native_identity`` the transition commits atomically (no
        external side effect is possible inside the transaction). With a
        deployment ``launcher`` the call first commits a durable launch
        reservation carrying an idempotent launch token, invokes the launcher
        outside the transaction with that token, then commits the identity
        with the ``running`` transition. Attachments freeze at this point:
        the frozen digest set is persisted and bound to execution/result
        evidence.
        """
        if not command_profile.strip() or not objective.strip() or not authority_ref.strip():
            raise ValueError("command_profile, objective, and authority_ref are required")
        payload = {"op": "execute", "job_id": job_id, "command_profile": command_profile,
                   "objective": objective, "authority_ref": authority_ref,
                   "generation": expected_generation}
        scope = f"job:{job_id}"
        launch_token = self._launch_token(scope=scope, key=idempotency_key)

        def fail_in_txn(db: sqlite3.Connection, job: Job | None, error: Exception) -> None:
            self._idem_store(db, scope=scope, key=idempotency_key,
                             response=self._idem_failure(job, error))
            db.execute("COMMIT")
            raise error

        # -- phase A: durable reservation (launcher path) or atomic commit --
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                replay = self._idem_begin(db, scope=scope, key=idempotency_key, payload=payload)
                if replay is not None:
                    if replay.get("failed"):
                        db.execute("COMMIT")
                        self._raise_stored_failure(replay)
                    if replay.get("launching"):
                        # A reservation is already committed for this key.
                        reservation = self._get_job(db, job_id)
                        if (reservation.state == "running" and reservation.native_identity
                                and reservation.launch_token is None):
                            # Phase C committed but the marker update was
                            # lost: reconcile the marker, do not relaunch.
                            self._idem_store(db, scope=scope, key=idempotency_key,
                                             response=self._job_response(reservation))
                            db.execute("COMMIT")
                            return reservation, True
                        if (reservation.state == "ready"
                                and reservation.launch_token == replay.get("launch_token")):
                            # Reservation still pending: resume at phase B/C
                            # with the same idempotent token.
                            db.execute("COMMIT")
                            raise _ResumeLaunch(launch_token)
                        else:
                            error = IllegalTransitionError(
                                "launch reservation is no longer pending"
                                f" (job is {reservation.state!r})")
                            self._idem_store(db, scope=scope, key=idempotency_key,
                                             response=self._idem_failure(reservation, error))
                            db.execute("COMMIT")
                            raise error
                    else:
                        job = self._get_job(db, job_id)
                        db.execute("COMMIT")
                        return job, True
                job = self._get_job(db, job_id)
                if job.generation != expected_generation:
                    fail_in_txn(db, job, StaleGenerationError(
                        f"stale generation: have {job.generation}, call carried {expected_generation}"))
                    raise AssertionError("unreachable")
                if job.state != "ready":
                    fail_in_txn(db, job, IllegalTransitionError(
                        f"only a ready job can execute (job is {job.state!r})"))
                    raise AssertionError("unreachable")
                if launcher is not None:
                    if job.launch_token is not None and job.launch_token != launch_token:
                        fail_in_txn(db, job, AttemptConflict(
                            "a launch reservation is already pending for this job"))
                        raise AssertionError("unreachable")
                    if job.launch_token is None:
                        db.execute("UPDATE jobs SET launch_token=?, updated_at=? WHERE id=?",
                                   (launch_token, _utcnow(), job.id))
                        job = self._get_job(db, job_id)
                        self._record(db, job, from_state="ready", to_state="ready",
                                     actor=actor, reason=f"launch reserved {launch_token[:12]}")
                    self._idem_store(db, scope=scope, key=idempotency_key,
                                     response={**self._job_response(job), "launching": True,
                                               "launch_token": launch_token})
                    db.execute("COMMIT")
                else:
                    if not native_identity or not str(native_identity).strip():
                        db.execute("ROLLBACK")
                        raise ValueError("a native identity is required before reporting running")
                    if job.launch_token is not None:
                        fail_in_txn(db, job, AttemptConflict(
                            "a launch reservation is already pending for this job"))
                        raise AssertionError("unreachable")
                    frozen = self._attached_digests(db, job_id)
                    updated = self._set_state(
                        db, job, to_state="running", actor=actor,
                        reason=f"executing {command_profile}",
                        check_generation=expected_generation,
                        native_identity=str(native_identity), command_profile=command_profile,
                        objective=objective, authority_ref=authority_ref,
                        frozen_artifacts_json=json.dumps(frozen), launch_token=None,
                        artifact_digests=frozen)
                    self._idem_store(db, scope=scope, key=idempotency_key,
                                     response=self._job_response(updated))
                    db.execute("COMMIT")
                    return updated, False
            except _ResumeLaunch:
                pass
            except Exception:
                try:
                    db.execute("ROLLBACK")
                except Exception:
                    pass
                raise

        # -- phase B: invoke the deployment launcher with no lock held --
        if native_identity is not None and str(native_identity).strip():
            # A directly supplied identity confirms a pending reservation
            # without invoking the launcher again.
            identity = str(native_identity)
        elif launcher is None:
            raise ValueError(
                "a launch reservation is pending for this key: supply the launcher "
                "or a native identity to confirm it")
        else:
            with self._connect() as db:
                job = self._get_job(db, job_id)
            try:
                identity = self._invoke_launcher(launcher, job=job,
                                                 command_profile=command_profile,
                                                 launch_token=launch_token)
            except Exception as error:
                with self._connect() as db:
                    db.execute("BEGIN IMMEDIATE")
                    try:
                        current = self._get_job(db, job_id)
                        if current.launch_token == launch_token and current.state == "ready":
                            db.execute("UPDATE jobs SET launch_token=NULL, updated_at=? WHERE id=?",
                                       (_utcnow(), job_id))
                            current = self._get_job(db, job_id)
                        if not isinstance(error, (ValueError, AttemptConflict)):
                            wrapped: Exception = ValueError(f"launcher failed: {error}")
                        else:
                            wrapped = error
                        self._idem_store(db, scope=scope, key=idempotency_key,
                                         response=self._idem_failure(current, wrapped))
                        db.execute("COMMIT")
                    except Exception:
                        try:
                            db.execute("ROLLBACK")
                        except Exception:
                            pass
                        raise
                raise error
            if not identity or not str(identity).strip():
                error = ValueError("launcher returned no native identity")
                with self._connect() as db:
                    db.execute("BEGIN IMMEDIATE")
                    try:
                        current = self._get_job(db, job_id)
                        self._idem_store(db, scope=scope, key=idempotency_key,
                                         response=self._idem_failure(current, error))
                        db.execute("COMMIT")
                    except Exception:
                        try:
                            db.execute("ROLLBACK")
                        except Exception:
                            pass
                        raise
                raise error
            identity = str(identity)

        # -- phase C: commit the identity with the running transition --
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                stored_row = db.execute(
                    "SELECT response_json FROM idempotency WHERE scope=? AND key=?",
                    (scope, idempotency_key)).fetchone()
                stored = json.loads(stored_row["response_json"]) if stored_row else {}
                if stored and not stored.get("launching") and not stored.get("failed"):
                    job = self._get_job(db, job_id)
                    db.execute("COMMIT")
                    return job, True
                if stored.get("failed"):
                    db.execute("COMMIT")
                    self._raise_stored_failure(stored)
                job = self._get_job(db, job_id)
                if job.generation != expected_generation:
                    fail_in_txn(db, job, StaleGenerationError(
                        f"stale generation: have {job.generation}, call carried {expected_generation}"))
                    raise AssertionError("unreachable")
                if job.state != "ready" or job.launch_token != launch_token:
                    fail_in_txn(db, job, IllegalTransitionError(
                        f"launch reservation {launch_token[:12]} is no longer pending"
                        f" (job is {job.state!r})"))
                    raise AssertionError("unreachable")
                frozen = self._attached_digests(db, job_id)
                updated = self._set_state(
                    db, job, to_state="running", actor=actor,
                    reason=f"executing {command_profile}",
                    check_generation=expected_generation,
                    native_identity=identity, command_profile=command_profile,
                    objective=objective, authority_ref=authority_ref,
                    frozen_artifacts_json=json.dumps(frozen), launch_token=None,
                    artifact_digests=frozen)
                self._idem_store(db, scope=scope, key=idempotency_key,
                                 response=self._job_response(updated))
                db.execute("COMMIT")
                return updated, False
            except Exception:
                try:
                    db.execute("ROLLBACK")
                except Exception:
                    pass
                raise

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
            try:
                replay = self._idem_begin(db, scope=scope, key=idempotency_key, payload=payload)
                if replay is not None:
                    if replay.get("failed"):
                        db.execute("COMMIT")
                        self._raise_stored_failure(replay)
                    job = self._get_job(db, job_id)
                    db.execute("COMMIT")
                    return job, True
                job = self._get_job(db, job_id)
                if job.generation != expected_generation:
                    error = StaleGenerationError(
                        f"stale generation: have {job.generation}, call carried {expected_generation}")
                    self._idem_store(db, scope=scope, key=idempotency_key,
                                     response=self._idem_failure(job, error))
                    db.execute("COMMIT")
                    raise error
                if job.state != "running":
                    error = IllegalTransitionError(
                        f"only a running job can record a result (job is {job.state!r})")
                    self._idem_store(db, scope=scope, key=idempotency_key,
                                     response=self._idem_failure(job, error))
                    db.execute("COMMIT")
                    raise error
                frozen = job.frozen_artifact_digests or self._attached_digests(db, job_id)
                updated = self._set_state(db, job, to_state=outcome, actor=actor,
                                          reason=f"native unit reported {outcome}",
                                          check_generation=expected_generation,
                                          result=result or {}, launch_token=None,
                                          artifact_digests=frozen)
                self._idem_store(db, scope=scope, key=idempotency_key, response=self._job_response(updated))
                db.execute("COMMIT")
                return updated, False
            except Exception:
                try:
                    db.execute("ROLLBACK")
                except Exception:
                    pass
                raise

    def fail_job(self, *, job_id: str, reason: str, expected_generation: int,
                 idempotency_key: str, actor: str = "supervisor") -> tuple[Job, bool]:
        if not reason.strip():
            raise ValueError("a failure reason is required")
        payload = {"op": "fail_job", "job_id": job_id, "reason": reason,
                   "generation": expected_generation}
        scope = f"job:{job_id}"
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                replay = self._idem_begin(db, scope=scope, key=idempotency_key, payload=payload)
                if replay is not None:
                    if replay.get("failed"):
                        db.execute("COMMIT")
                        self._raise_stored_failure(replay)
                    job = self._get_job(db, job_id)
                    db.execute("COMMIT")
                    return job, True
                job = self._get_job(db, job_id)
                updated = self._set_state(db, job, to_state="failed", actor=actor,
                                          reason=reason, check_generation=expected_generation,
                                          launch_token=None)
                self._idem_store(db, scope=scope, key=idempotency_key, response=self._job_response(updated))
                db.execute("COMMIT")
                return updated, False
            except Exception:
                try:
                    db.execute("ROLLBACK")
                except Exception:
                    pass
                raise

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
            try:
                replay = self._idem_begin(db, scope=scope, key=idempotency_key, payload=payload)
                if replay is not None:
                    if replay.get("failed"):
                        db.execute("COMMIT")
                        self._raise_stored_failure(replay)
                    job = self._get_job(db, job_id)
                    db.execute("COMMIT")
                    return job, True
                job = self._get_job(db, job_id)
                updated = self._set_state(db, job, to_state="cancel_requested", actor=actor,
                                          reason=reason, check_generation=expected_generation,
                                          launch_token=None)
                self._idem_store(db, scope=scope, key=idempotency_key, response=self._job_response(updated))
                db.execute("COMMIT")
                return updated, False
            except Exception:
                try:
                    db.execute("ROLLBACK")
                except Exception:
                    pass
                raise

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
            try:
                replay = self._idem_begin(db, scope=scope, key=idempotency_key, payload=payload)
                if replay is not None:
                    if replay.get("failed"):
                        db.execute("COMMIT")
                        self._raise_stored_failure(replay)
                    job = self._get_job(db, job_id)
                    db.execute("COMMIT")
                    return job, True
                job = self._get_job(db, job_id)
                if job.state != CANCEL_REQUESTED:
                    error = IllegalTransitionError(
                        f"only a cancel_requested job can be confirmed (job is {job.state!r})")
                    self._idem_store(db, scope=scope, key=idempotency_key,
                                     response=self._idem_failure(job, error))
                    db.execute("COMMIT")
                    raise error
                updated = self._set_state(db, job, to_state="cancelled", actor=actor,
                                          reason="native unit confirmed dead",
                                          check_generation=expected_generation,
                                          launch_token=None)
                self._idem_store(db, scope=scope, key=idempotency_key, response=self._job_response(updated))
                db.execute("COMMIT")
                return updated, False
            except Exception:
                try:
                    db.execute("ROLLBACK")
                except Exception:
                    pass
                raise

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
            try:
                replay = self._idem_begin(db, scope=scope, key=idempotency_key, payload=payload)
                if replay is not None:
                    if replay.get("failed"):
                        db.execute("COMMIT")
                        self._raise_stored_failure(replay)
                    job = self._get_job(db, job_id)
                    db.execute("COMMIT")
                    return job, True
                job = self._get_job(db, job_id)
                updated = self._set_state(db, job, to_state="unknown_outcome", actor=actor,
                                          reason=reason, check_generation=expected_generation,
                                          launch_token=None)
                self._idem_store(db, scope=scope, key=idempotency_key, response=self._job_response(updated))
                db.execute("COMMIT")
                return updated, False
            except Exception:
                try:
                    db.execute("ROLLBACK")
                except Exception:
                    pass
                raise

    def quarantine_job(self, *, job_id: str, reason: str, expected_generation: int,
                       idempotency_key: str, actor: str = "supervisor") -> tuple[Job, bool]:
        if not reason.strip():
            raise ValueError("a quarantine reason is required")
        payload = {"op": "quarantine_job", "job_id": job_id, "reason": reason,
                   "generation": expected_generation}
        scope = f"job:{job_id}"
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                replay = self._idem_begin(db, scope=scope, key=idempotency_key, payload=payload)
                if replay is not None:
                    if replay.get("failed"):
                        db.execute("COMMIT")
                        self._raise_stored_failure(replay)
                    job = self._get_job(db, job_id)
                    db.execute("COMMIT")
                    return job, True
                job = self._get_job(db, job_id)
                updated = self._set_state(db, job, to_state="quarantined", actor=actor,
                                          reason=reason, check_generation=expected_generation,
                                          quarantine_reason=reason, launch_token=None)
                self._idem_store(db, scope=scope, key=idempotency_key, response=self._job_response(updated))
                db.execute("COMMIT")
                return updated, False
            except Exception:
                try:
                    db.execute("ROLLBACK")
                except Exception:
                    pass
                raise

    def retry_job(self, *, job_id: str, reason: str, expected_generation: int,
                  idempotency_key: str, actor: str = "supervisor") -> tuple[Job, bool]:
        """Open a new generation linked to the prior attempt.

        Legal from ``failed``, ``interrupted``, ``unknown_outcome``, and
        ``cancelled``. ``succeeded`` and ``quarantined`` are final. The new
        generation starts with no attachments, no frozen set, and no launch
        reservation: artifacts from the prior attempt never leak across the
        generation boundary.
        """
        if not reason.strip():
            raise ValueError("a retry reason is required")
        payload = {"op": "retry_job", "job_id": job_id, "reason": reason,
                   "generation": expected_generation}
        scope = f"job:{job_id}"
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                replay = self._idem_begin(db, scope=scope, key=idempotency_key, payload=payload)
                if replay is not None:
                    if replay.get("failed"):
                        db.execute("COMMIT")
                        self._raise_stored_failure(replay)
                    job = self._get_job(db, job_id)
                    db.execute("COMMIT")
                    return job, True
                job = self._get_job(db, job_id)
                if job.state not in ("failed", "interrupted", "unknown_outcome", "cancelled"):
                    error = IllegalTransitionError(f"job in {job.state!r} cannot be retried")
                    self._idem_store(db, scope=scope, key=idempotency_key,
                                     response=self._idem_failure(job, error))
                    db.execute("COMMIT")
                    raise error
                if job.generation != expected_generation:
                    error = StaleGenerationError(
                        f"stale generation: have {job.generation}, call carried {expected_generation}")
                    self._idem_store(db, scope=scope, key=idempotency_key,
                                     response=self._idem_failure(job, error))
                    db.execute("COMMIT")
                    raise error
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
                    " quarantine_reason=NULL, frozen_artifacts_json='[]', launch_token=NULL,"
                    " updated_at=? WHERE id=?",
                    (new_generation, attempt_id, now, job.id),
                )
                db.execute("DELETE FROM attachments WHERE job_id=?", (job.id,))
                updated = self._get_job(db, job.id)
                self._record(db, updated, from_state=from_state, to_state="accepted",
                             actor=actor, reason=f"retry: {reason}", artifact_digests=[])
                self._idem_store(db, scope=scope, key=idempotency_key, response=self._job_response(updated))
                db.execute("COMMIT")
                return updated, False
            except Exception:
                try:
                    db.execute("ROLLBACK")
                except Exception:
                    pass
                raise

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
            frozen = job.frozen_artifact_digests or self._attached_digests(db, job_id)
            return {
                "job_id": job.id,
                "state": job.state,
                "generation": job.generation,
                "attempt_id": job.current_attempt_id,
                "attempt_count": job.attempt_count,
                "result": job.result,
                "artifact_digests": frozen,
                "frozen_artifact_digests": frozen,
                "source_digest": job.source_digest,
                "policy_hash": job.policy_hash,
                "quarantine_reason": job.quarantine_reason,
                "cursor": row["cursor"] or 0,
            }

    def attachments(self, job_id: str) -> list[AttachmentRecord]:
        with self._connect() as db:
            rows = db.execute("SELECT * FROM attachments WHERE job_id=? ORDER BY attached_at", (job_id,)).fetchall()
            return [self._attachment(row) for row in rows]

    # -- recovery --------------------------------------------------------

    def recover(
        self, *, liveness: NativeLiveness | None = None, actor: str = "reconciler",
    ) -> list[RecoveredJob]:
        """Reconcile non-terminal jobs after a restart without replaying work.

        - A job with a durably reserved but unconfirmed launch (``launch_token``
          set) may already have native side effects even though no identity
          was committed: ``unknown_outcome``. It is never blindly replayed.
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
            try:
                rows = db.execute("SELECT * FROM jobs ORDER BY rowid").fetchall()
                for row in rows:
                    job = self._job(row)
                    if job.state not in NON_TERMINAL:
                        continue
                    if job.launch_token is not None:
                        updated = self._set_state(
                            db, job, to_state="unknown_outcome", actor=actor,
                            reason="recover: launch reserved but unconfirmed; side effects possible",
                            launch_token=None)
                        recovered.append(RecoveredJob(updated, "unknown_outcome"))
                        continue
                    if job.native_identity is None:
                        if job.state == CANCEL_REQUESTED:
                            updated = self._set_state(db, job, to_state="cancelled", actor=actor,
                                                      reason="recover: cancel requested before launch",
                                                      launch_token=None)
                            recovered.append(RecoveredJob(updated, "cancelled"))
                        else:
                            updated = self._set_state(db, job, to_state="interrupted", actor=actor,
                                                      reason="recover: never started; no native identity recorded",
                                                      launch_token=None)
                            recovered.append(RecoveredJob(updated, "interrupted"))
                        continue
                    alive = liveness(job.native_identity) if liveness is not None else False
                    if alive:
                        recovered.append(RecoveredJob(job, "alive"))
                        continue
                    reason = ("recover: native unit dead with unconfirmed side effects"
                              if liveness is not None else
                              "recover: no liveness evidence after restart; outcome unconfirmed")
                    updated = self._set_state(db, job, to_state="unknown_outcome", actor=actor,
                                              reason=reason, launch_token=None)
                    recovered.append(RecoveredJob(updated, "unknown_outcome"))
                db.execute("COMMIT")
            except Exception:
                try:
                    db.execute("ROLLBACK")
                except Exception:
                    pass
                raise
        return recovered
