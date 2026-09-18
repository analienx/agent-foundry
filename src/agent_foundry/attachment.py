"""Authenticated artifact attachment requests and Agent Interop receipts.

An attachment is not just "a payload whose digest matches a manifest". Before
a job may start, the deployment must be able to prove *who* asked for the
attachment, *what* repository/source revision/lock digest/artifact digest/
job/attempt it is bound to, and that the authorizing Agent Interop receipt is
authentic, single-use, and bound to the exact verification plan and read-only
mount that was actually produced.

This module owns the pure, offline half of that contract:

- :class:`ArtifactAttachmentRequest` binds repository, source SHA, lock
  digest, artifact digest, submitting identity, job, attempt, and generation
  into one canonical, hashable document.
- :class:`AttachmentReceipt` is the *Agent Interop* authenticated attachment
  receipt (``agent-interop-gateway/attachment-receipt/v1``). Its statement
  binds the job, generation, artifact digest, staged CAS reference, read-only
  mount handle, verifier identity, complete verification-plan hash, ordered
  per-step results, and the issuance/expiry/replay-domain triple.
- :func:`verify_attachment_receipt` authenticates the receipt through a
  deployment-injected :class:`AttachmentReceiptVerifier`, enforces statement
  equality, request binding, plan/step coverage, freshness, and single-use
  replay protection, and returns immutable evidence.

There is deliberately **no cryptography, key material, transport, credential,
or network surface** here: authentication is delegated to the deployment,
exactly like :class:`agent_foundry.adapters.ArtifactVerifier`. The library only
decides whether the evidence it was handed is well-formed, consistent, and
unused.
"""

from __future__ import annotations

import hashlib
import json
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Protocol

from .artifacts import ArtifactManifest

#: Canonical schema of the attachment request document.
REQUEST_SCHEMA = "foundry.artifact-attachment-request/v1"
#: Canonical schema/statement type of the Agent Interop attachment receipt.
RECEIPT_SCHEMA = "agent-interop-gateway/attachment-receipt/v1"
STATEMENT_TYPE = RECEIPT_SCHEMA

#: Receipts are short-lived deployment attestations, never durable grants.
MAX_RECEIPT_TTL_SECONDS = 24 * 3600

#: Request fields that must match the manifest, the job, and the attempt
#: (the receiver derives them; a caller can never default them).
BINDING_FIELDS = (
    "repository",
    "source_sha",
    "lock_digest",
    "artifact_digest",
    "submitting_identity",
    "job_id",
    "attempt_id",
)

#: Authentication material is not part of the signed statement.
_AUTH_FIELDS = ("mac", "receipt_ref")

#: Fields the authenticated statement must carry, exactly.
STATEMENT_FIELDS = (
    "issuer",
    "job_id",
    "generation",
    "artifact_digest",
    "staged_ref",
    "mount_handle",
    "verifier",
    "plan_hash",
    "steps",
    "issued_at",
    "expires_at",
    "replay_domain",
)

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_COMMIT_RE = re.compile(r"^[0-9a-f]{7,64}$")
_STAGED_REF_RE = re.compile(r"^(cas|staging):[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_RECEIPT_REF_RE = re.compile(r"^receipt:[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_NETWORK_SCHEMES = ("http://", "https://", "ftp://", "sftp://", "ssh://")
_SHELL_METACHARS = (";", "|", "&", "$", "`", "\n", "\r", "<", ">", "*", "?", "~", "!")


class AttachmentRequestError(ValueError):
    """An attachment request document is malformed or contradicts evidence."""


class AttachmentReceiptError(ValueError):
    """An attachment receipt is unauthentic, mismatched, stale, or unsupported."""


class AttachmentReplayError(AttachmentReceiptError):
    """The receipt was already used to authorize an earlier attachment."""


def canonical_json(document: dict) -> bytes:
    """Deterministic JSON bytes: sorted keys, no insignificant whitespace."""
    return json.dumps(document, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, default=str).encode("utf-8")


def canonical_hash(document: dict) -> str:
    return hashlib.sha256(canonical_json(document)).hexdigest()


def plan_hash_for_plan(normalized_plan) -> str:
    """Canonical hash of a complete normalized ``verify_commands`` plan."""
    plan = [list(c) if isinstance(c, (list, tuple)) else c for c in normalized_plan]
    return canonical_hash({"verify_commands": plan})


def step_commitment(index: int, step) -> str:
    """Canonical commitment proving that plan step ``index`` was executed."""
    normalized = list(step) if isinstance(step, (list, tuple)) else step
    return canonical_hash({"index": index, "step": normalized})


def attachment_replay_domain(job_id: str, generation: int, artifact_digest: str) -> str:
    """Anti-replay scope: one issuance binds to exactly this triple."""
    return canonical_hash({"replay_domain": "agent-interop-gateway/foundry.v3/attach",
                           "job_id": job_id, "generation": int(generation),
                           "artifact_digest": artifact_digest})


def _parse_ts(value: str, *, field_name: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError) as error:
        raise AttachmentReceiptError(f"{field_name} is not an ISO-8601 timestamp: {value!r}") from error
    if parsed.tzinfo is None:
        raise AttachmentReceiptError(f"{field_name} must be timezone-aware")
    return parsed.astimezone(timezone.utc)


def _require_text(raw: dict, name: str, errors: list[str]) -> str:
    value = raw.get(name)
    if not isinstance(value, str) or not value.strip():
        errors.append(f"{name} must be a non-empty string")
        return ""
    return value.strip()


def validate_staged_ref(ref: str) -> str:
    """Validate an immutable deployment-owned CAS/staging identifier."""
    if not isinstance(ref, str) or not _STAGED_REF_RE.match(ref):
        raise AttachmentReceiptError(
            "staged_ref must be an immutable deployment-owned staging/CAS "
            "identifier of the form 'cas:<id>' or 'staging:<id>' "
            "(no URLs, paths, or shell syntax)")
    lowered = ref.lower()
    if ("://" in ref or any(scheme in lowered for scheme in _NETWORK_SCHEMES)
            or any(meta in ref for meta in _SHELL_METACHARS)
            or "/" in ref.split(":", 1)[-1] or "\\" in ref or ".." in ref):
        raise AttachmentReceiptError(
            "staged_ref must be an immutable deployment-owned staging/CAS identifier")
    return ref


def validate_mount_handle(handle: str, *, staged_ref: str | None = None) -> str:
    """Validate a deployment mount handle: never a host filesystem path.

    A host path (absolute, relative, or drive-lettered) is not evidence of a
    read-only mount, so it is rejected outright -- this is the boundary
    attack the Phase 4 negative tests exercise.
    """
    if not isinstance(handle, str) or not handle.strip():
        raise AttachmentReceiptError("mount_handle must be a nonempty deployment mount handle")
    text = handle.strip()
    lowered = text.lower()
    if ("://" in text or any(scheme in lowered for scheme in _NETWORK_SCHEMES)
            or any(meta in text for meta in _SHELL_METACHARS)):
        raise AttachmentReceiptError("mount_handle must not contain URLs or shell syntax")
    if text.startswith(("/", "\\", ".")) or re.match(r"^[A-Za-z]:", text):
        raise AttachmentReceiptError(
            "mount_handle must be a deployment mount handle, not a host filesystem path")
    if lowered.startswith(("cas:", "staging:")):
        raise AttachmentReceiptError("mount_handle must not be derived from a CAS/staging ref")
    if staged_ref is not None and text == staged_ref:
        raise AttachmentReceiptError(
            "mount_handle must be a separate read-only mount handle, not the staged_payload ref")
    return text


@dataclass(frozen=True)
class ArtifactAttachmentRequest:
    """Everything a specific submission binds before Foundry will attach."""

    repository: str
    source_sha: str
    lock_digest: str
    artifact_digest: str
    submitting_identity: str
    job_id: str
    attempt_id: str
    generation: int = 1
    schema_version: str = REQUEST_SCHEMA

    def __post_init__(self) -> None:
        if self.schema_version != REQUEST_SCHEMA:
            raise AttachmentRequestError(f"schema_version must be {REQUEST_SCHEMA!r}")
        errors: list[str] = []
        for name in BINDING_FIELDS:
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                errors.append(f"{name} must be a non-empty string")
        if isinstance(self.source_sha, str) and not _COMMIT_RE.match(self.source_sha):
            errors.append("source_sha must be lowercase hex of length 7..64")
        for name in ("lock_digest", "artifact_digest"):
            value = getattr(self, name)
            if isinstance(value, str) and not _SHA256_RE.match(value):
                errors.append(f"{name} must be a 64-char lowercase hex sha256")
        if not isinstance(self.generation, int) or isinstance(self.generation, bool) \
                or self.generation < 1:
            errors.append("generation must be an integer >= 1")
        if errors:
            raise AttachmentRequestError("; ".join(errors))

    def to_dict(self) -> dict:
        return {"schema_version": self.schema_version, "generation": self.generation,
                **{name: getattr(self, name) for name in BINDING_FIELDS}}

    def canonical_bytes(self) -> bytes:
        return canonical_json(self.to_dict())

    @property
    def request_hash(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()

    @classmethod
    def from_dict(cls, raw: dict) -> ArtifactAttachmentRequest:
        if not isinstance(raw, dict):
            raise AttachmentRequestError("attachment request must be a mapping")
        if raw.get("schema_version") != REQUEST_SCHEMA:
            raise AttachmentRequestError(f"schema_version must be {REQUEST_SCHEMA!r}")
        errors: list[str] = []
        values = {name: _require_text(raw, name, errors) for name in BINDING_FIELDS}
        generation = raw.get("generation", 1)
        if not isinstance(generation, int) or isinstance(generation, bool) or generation < 1:
            errors.append("generation must be an integer >= 1")
        unknown = sorted(k for k in raw if k not in set(BINDING_FIELDS) | {"schema_version", "generation"})
        if unknown:
            errors.append(f"attachment request has unknown fields: {unknown}")
        if errors:
            raise AttachmentRequestError("; ".join(errors))
        return cls(**values, generation=generation, schema_version=REQUEST_SCHEMA)

    @classmethod
    def for_manifest(cls, manifest: ArtifactManifest, *, submitting_identity: str,
                     job_id: str, attempt_id: str, generation: int = 1,
                     ) -> ArtifactAttachmentRequest:
        """Derive the request a manifest-backed attachment must present."""
        return cls(
            repository=manifest.source_repo,
            source_sha=manifest.source_commit,
            lock_digest=manifest.lock_digest,
            artifact_digest=manifest.payload_digest,
            submitting_identity=submitting_identity,
            job_id=job_id,
            attempt_id=attempt_id,
            generation=generation,
        )


@dataclass(frozen=True)
class AttachmentReceipt:
    """An Agent Interop authenticated attachment receipt.

    Exactly one authentication channel is present: ``mac`` (issuer-signed
    statement) or ``receipt_ref`` (opaque server-side deployment receipt).
    Foundry never signs receipts and never holds issuer secrets.
    """

    issuer: str
    job_id: str
    generation: int
    artifact_digest: str
    staged_ref: str
    mount_handle: str
    verifier: str
    plan_hash: str
    steps: tuple
    issued_at: str
    expires_at: str
    replay_domain: str
    mac: str = ""
    receipt_ref: str = ""
    schema_version: str = RECEIPT_SCHEMA

    def __post_init__(self) -> None:
        if self.schema_version != RECEIPT_SCHEMA:
            raise AttachmentReceiptError(f"schema_version must be {RECEIPT_SCHEMA!r}")

    def to_dict(self) -> dict:
        """The Agent Interop wire form, byte-for-byte.

        Identical to Agent Interop's ``V3AttachmentReceipt.model_dump()``: the
        same statement fields plus ``mac``/``receipt_ref`` (``None`` when the
        other channel is used). There is no extra Foundry-only key, so a
        receipt issued by Agent Interop round-trips unchanged and the receipt
        digest is the digest of the actual wire document.
        """
        return {**{name: self._value(name) for name in STATEMENT_FIELDS},
                "mac": self.mac or None, "receipt_ref": self.receipt_ref or None}

    def _value(self, name: str):
        value = getattr(self, name)
        if name == "steps":
            return [dict(step) for step in value]
        return value

    def statement(self) -> dict:
        """Canonical statement covered by the receipt authentication."""
        return {**{name: self._value(name) for name in STATEMENT_FIELDS},
                "statement": STATEMENT_TYPE}

    @property
    def receipt_digest(self) -> str:
        """Stable identity of this exact receipt document."""
        return canonical_hash(self.to_dict())

    @classmethod
    def from_dict(cls, raw: dict) -> AttachmentReceipt:
        if not isinstance(raw, dict):
            raise AttachmentReceiptError("attachment receipt must be a mapping")
        declared = raw.get("schema_version", RECEIPT_SCHEMA)
        if declared != RECEIPT_SCHEMA:
            raise AttachmentReceiptError(f"schema_version must be {RECEIPT_SCHEMA!r}")
        errors: list[str] = []
        values = {name: _require_text(raw, name, errors) for name in STATEMENT_FIELDS
                  if name not in ("generation", "steps")}
        generation = raw.get("generation")
        if not isinstance(generation, int) or isinstance(generation, bool) or generation < 1:
            errors.append("generation must be an integer >= 1")
        steps_raw = raw.get("steps")
        steps: tuple = ()
        if not isinstance(steps_raw, list) or not steps_raw:
            errors.append("steps must be a non-empty list of verified-step evidence")
        else:
            normalized = []
            for index, step in enumerate(steps_raw):
                if not isinstance(step, dict) or step.get("index") != index:
                    errors.append("steps must be ordered verified-step evidence with matching index")
                    break
                evidence = step.get("evidence_digest")
                if not isinstance(evidence, str) or not evidence.strip():
                    errors.append("steps[].evidence_digest must be a non-empty string")
                    break
                normalized.append({"index": index, "step": step.get("step"),
                                   "evidence_digest": evidence})
            steps = tuple(normalized)
        if values.get("artifact_digest") and not _SHA256_RE.match(values["artifact_digest"]):
            errors.append("artifact_digest must be a 64-char lowercase hex sha256")
        mac = raw.get("mac")
        receipt_ref = raw.get("receipt_ref")
        if mac is not None and (not isinstance(mac, str) or not _SHA256_RE.match(mac)):
            errors.append("mac must be a 64-char lowercase hex MAC")
        if receipt_ref is not None and (not isinstance(receipt_ref, str)
                                        or not _RECEIPT_REF_RE.match(receipt_ref)):
            errors.append("receipt_ref must be an opaque server-side handle of the form 'receipt:<id>'")
        if (mac is None) == (receipt_ref is None):
            errors.append("receipt requires exactly one authentication channel: mac or receipt_ref")
        unknown = sorted(k for k in raw
                         if k not in set(STATEMENT_FIELDS) | set(_AUTH_FIELDS) | {"schema_version"})
        if unknown:
            errors.append(f"attachment receipt has unknown fields: {unknown}")
        if errors:
            raise AttachmentReceiptError("; ".join(errors))
        return cls(schema_version=RECEIPT_SCHEMA, steps=steps, generation=generation,
                   mac=mac or "", receipt_ref=receipt_ref or "", **values)


class AttachmentReceiptVerifier(ABC):
    """Deployment-owned authentication of Agent Interop attachment receipts.

    Implementations hold the issuer trust store (or the opaque server-side
    receipt directory) and run the actual authentication. The library never
    sees a key, never reaches the network, and never executes a process: it
    only demands the authenticated statement for the receipt it was handed.
    """

    @abstractmethod
    def verify_receipt(self, receipt: AttachmentReceipt, *,
                       request: ArtifactAttachmentRequest, now: str) -> dict:
        """Authenticate ``receipt`` and return its verified statement.

        Must raise (any exception) when the receipt is not from a trusted
        issuer, its authentication material does not verify, or it is
        expired/over-long-lived. Returning the statement asserts that the
        mounted payload, verifier identity, and plan results are real.
        """


class ReceiptReplayGuard(Protocol):
    """Durable single-use enforcement for authenticated receipts."""

    def reserve(self, replay_key: str, *, job_id: str, generation: int,
                replay_domain: str, receipt_digest: str) -> None:
        """Consume ``replay_key`` or raise :class:`AttachmentReplayError`."""


@dataclass
class InMemoryReplayGuard:
    """Non-durable guard: only for tests and single-process embedding."""

    seen: dict = field(default_factory=dict)

    def reserve(self, replay_key: str, *, job_id: str, generation: int,
                replay_domain: str, receipt_digest: str) -> None:
        if replay_key in self.seen:
            first = self.seen[replay_key]
            raise AttachmentReplayError(
                f"attachment receipt {first['receipt_digest'][:12]} was already "
                f"consumed for job {first['job_id']!r} generation {first['generation']}")
        self.seen[replay_key] = {"job_id": job_id, "generation": generation,
                                 "replay_domain": replay_domain,
                                 "receipt_digest": receipt_digest}


@dataclass(frozen=True)
class AttachmentReceiptEvidence:
    """Immutable, authenticated attachment evidence recorded with a mount."""

    issuer: str
    staged_ref: str
    mount_handle: str
    verifier: str
    plan_hash: str
    steps: tuple
    replay_domain: str
    receipt_digest: str
    issued_at: str
    expires_at: str
    job_id: str
    generation: int
    artifact_digest: str
    request_hash: str

    def to_dict(self) -> dict:
        return {"issuer": self.issuer, "staged_ref": self.staged_ref,
                "mount_handle": self.mount_handle, "verifier": self.verifier,
                "plan_hash": self.plan_hash,
                "steps": [dict(step) for step in self.steps],
                "replay_domain": self.replay_domain,
                "receipt_digest": self.receipt_digest,
                "issued_at": self.issued_at, "expires_at": self.expires_at,
                "job_id": self.job_id, "generation": self.generation,
                "artifact_digest": self.artifact_digest,
                "request_hash": self.request_hash}


def receipt_replay_key(receipt: AttachmentReceipt) -> str:
    """Single-use key: this exact receipt may authorize exactly one attach.

    ``receipt_ref`` is an opaque server-side handle and is single-use by
    construction, so it keys on the handle; a MAC-signed receipt keys on its
    full document digest. Either way a *fresh* receipt for the same artifact
    remains possible, while a byte-identical replay can never succeed.
    """
    if receipt.receipt_ref:
        return f"{receipt.replay_domain}:ref:{receipt.receipt_ref}"
    return f"{receipt.replay_domain}:mac:{receipt.receipt_digest}"


def _check_receipt_window(receipt: AttachmentReceipt, *, now: datetime,
                          clock_skew_seconds: int,
                          max_ttl_seconds: int) -> None:
    skew = timedelta(seconds=max(0, clock_skew_seconds))
    issued = _parse_ts(receipt.issued_at, field_name="issued_at")
    expires = _parse_ts(receipt.expires_at, field_name="expires_at")
    if expires <= issued:
        raise AttachmentReceiptError("receipt expires_at must be after issued_at")
    if expires - issued > timedelta(seconds=max_ttl_seconds):
        raise AttachmentReceiptError(
            f"receipt validity exceeds the {max_ttl_seconds}s maximum TTL")
    if issued > now + skew:
        raise AttachmentReceiptError("receipt issued_at is in the future")
    if expires <= now - skew:
        raise AttachmentReceiptError("receipt has expired")


def verify_attachment_receipt(
    receipt: AttachmentReceipt,
    request: ArtifactAttachmentRequest,
    *,
    verifier: AttachmentReceiptVerifier,
    verify_plan=None,
    replay_guard: ReceiptReplayGuard | None = None,
    now: datetime | None = None,
    clock_skew_seconds: int = 60,
    max_ttl_seconds: int = MAX_RECEIPT_TTL_SECONDS,
) -> AttachmentReceiptEvidence:
    """Authenticate and verify an Agent Interop receipt before any job start.

    Order matters. The receipt is authenticated first so a forged statement
    can never poison the durable replay table; then the authenticated
    statement must equal the receipt it claims to authenticate, then the
    request binding, then the verification-plan/step coverage, then freshness,
    and only then is the receipt consumed. Any failure raises
    :class:`AttachmentReceiptError` (:class:`AttachmentReplayError` for a
    replay) and the caller must fail closed.
    """
    if not isinstance(request, ArtifactAttachmentRequest):
        raise AttachmentRequestError("a validated attachment request is required")
    if not isinstance(receipt, AttachmentReceipt):
        raise AttachmentReceiptError("a parsed attachment receipt is required")
    if verifier is None:
        raise AttachmentReceiptError(
            "a deployment receipt verifier is required: unauthenticated attachments "
            "are never accepted")
    moment = now or datetime.now(timezone.utc)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    moment = moment.astimezone(timezone.utc)

    statement = verifier.verify_receipt(
        receipt, request=request, now=moment.strftime("%Y-%m-%dT%H:%M:%SZ"))
    if not isinstance(statement, dict):
        raise AttachmentReceiptError("the receipt verifier returned no authenticated statement")
    mismatches: list[str] = []
    claimed = receipt.statement()
    for name in STATEMENT_FIELDS:
        if name == "steps":
            continue
        if statement.get(name) != claimed[name]:
            mismatches.append(name)
    if mismatches:
        raise AttachmentReceiptError(
            "authenticated statement does not match the attachment receipt: "
            + ", ".join(sorted(mismatches)))
    statement_steps = statement.get("steps")
    if not isinstance(statement_steps, list) or \
            [dict(s) for s in statement_steps] != list(claimed["steps"]):
        raise AttachmentReceiptError(
            "authenticated statement verified-step evidence does not match the receipt")

    # Request binding: repository/source SHA/lock digest/artifact digest/
    # submitting identity/job/attempt are asserted by the request document.
    if receipt.job_id != request.job_id:
        raise AttachmentReceiptError("receipt job_id does not match the attachment request")
    if int(receipt.generation) != int(request.generation):
        raise AttachmentReceiptError("receipt generation does not match the attachment request")
    if receipt.artifact_digest != request.artifact_digest:
        raise AttachmentReceiptError(
            "receipt artifact_digest does not match the attachment request")
    expected_domain = attachment_replay_domain(request.job_id, request.generation,
                                               request.artifact_digest)
    if receipt.replay_domain != expected_domain:
        raise AttachmentReceiptError(
            "receipt replay_domain does not bind this job, generation, and artifact digest")

    # Mount evidence: a host path or a CAS ref is never proof of a read-only
    # mount, so the boundary attack fails closed here.
    validate_staged_ref(receipt.staged_ref)
    validate_mount_handle(receipt.mount_handle, staged_ref=receipt.staged_ref)
    if not receipt.verifier.strip() or not receipt.plan_hash.strip():
        raise AttachmentReceiptError(
            "receipt must carry a verifier identity and a verification plan hash")

    if verify_plan is not None:
        if receipt.plan_hash != plan_hash_for_plan(verify_plan):
            raise AttachmentReceiptError(
                "receipt plan_hash does not match the manifest verification plan")
        if len(receipt.steps) != len(verify_plan):
            raise AttachmentReceiptError(
                "receipt step evidence does not cover the manifest verification plan")
        for index, (evidence, step) in enumerate(zip(receipt.steps, verify_plan)):
            normalized = list(step) if isinstance(step, (list, tuple)) else step
            if evidence.get("step") != normalized:
                raise AttachmentReceiptError(
                    "receipt step evidence does not match the manifest verification plan")
            if evidence.get("evidence_digest") != step_commitment(index, step):
                raise AttachmentReceiptError(
                    "receipt step evidence is not a valid verified-step commitment")

    _check_receipt_window(receipt, now=moment, clock_skew_seconds=clock_skew_seconds,
                          max_ttl_seconds=max_ttl_seconds)
    if replay_guard is not None:
        replay_guard.reserve(receipt_replay_key(receipt), job_id=receipt.job_id,
                             generation=int(receipt.generation),
                             replay_domain=receipt.replay_domain,
                             receipt_digest=receipt.receipt_digest)
    return AttachmentReceiptEvidence(
        issuer=receipt.issuer, staged_ref=receipt.staged_ref,
        mount_handle=receipt.mount_handle, verifier=receipt.verifier,
        plan_hash=receipt.plan_hash, steps=receipt.steps,
        replay_domain=receipt.replay_domain, receipt_digest=receipt.receipt_digest,
        issued_at=receipt.issued_at, expires_at=receipt.expires_at,
        job_id=receipt.job_id, generation=int(receipt.generation),
        artifact_digest=receipt.artifact_digest, request_hash=request.request_hash)