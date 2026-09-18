"""Cross-repository conformance: Foundry consumes Agent Interop receipts.

This is the Phase 4 integration proof. It uses the *real* Agent Interop
implementation (``agent_interop_gateway.foundry``) to issue and authenticate
receipts, and the real Foundry ``JobStore`` to consume them, so neither side
is faked:

- Interop's ``HmacReceiptIssuer`` signs the canonical statement.
- Interop's ``HmacReceiptVerifier`` (issuer trust store) runs the
  authentication inside a Foundry ``AttachmentReceiptVerifier`` adapter.
- The receipt travels in Interop's exact wire form -- Foundry's
  ``AttachmentReceipt.to_dict()`` is byte-identical to Interop's
  ``V3AttachmentReceipt.model_dump()``.
- Foundry records the mount handle, verifier identity, plan hash, and step
  commitments as durable attachment evidence, and burns the receipt so it can
  never authorize a second attachment.

Point ``AGENT_INTEROP_SRC`` at an Agent Interop checkout to run this; it is
skipped (not silently passed) when Agent Interop is unavailable. The default
resolves the local Goal worktree, which is the environment this goal verifies.
"""

from __future__ import annotations

import hashlib
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

_INTEROP_SRC_ENV = "AGENT_INTEROP_SRC"


def _interop_source_candidates():
    """Locate an Agent Interop checkout without hardcoding a machine path."""
    override = os.environ.get(_INTEROP_SRC_ENV)
    if override:
        yield Path(override)
    root = Path(__file__).resolve().parents[1]
    for base in (root.parent, root.parent.parent):
        yield base / "agent-interop" / "src"
        if base.is_dir():
            for child in sorted(base.iterdir()):
                if child.is_dir() and "interop" in child.name.lower():
                    yield child / "src"


for _candidate in _interop_source_candidates():
    if (_candidate / "agent_interop_gateway" / "foundry.py").is_file():
        sys.path.insert(0, str(_candidate))
        break

interop = pytest.importorskip(
    "agent_interop_gateway.foundry",
    reason=f"set {_INTEROP_SRC_ENV} to an Agent Interop checkout to run conformance")

from agent_foundry import (
    ArtifactAttachmentRequest,
    ArtifactVerifier,
    AttachmentReceipt,
    AttachmentReceiptError,
    AttachmentReceiptVerifier,
    JobStore,
)

ISSUER = "analienx-shiftio-foundry"
KEY = b"conformance-issuer-key"
STAGED_REF = "cas:shiftio-foundry-20260918T135448-0b7485f0"
MOUNT_HANDLE = "mount:ro/shiftio-foundry-verifier"
VERIFIER_ID = "podman-readonly-no-egress/v1"
SOURCE = "a" * 40
LOCK = "b" * 64


class DeploymentVerifier(ArtifactVerifier):
    """The deployment adapter: verifies bytes and exposes the read-only mount."""

    def verify(self, manifest):
        return True

    def mount_readonly(self, *, job_id, manifest):
        return MOUNT_HANDLE


class InteropReceiptVerifier(AttachmentReceiptVerifier):
    """Foundry adapter over Agent Interop's issuer trust store."""

    def __init__(self, issuers):
        self._interop = interop.HmacReceiptVerifier(issuers=issuers)

    def verify_receipt(self, receipt, *, request, now):
        wire = interop.V3AttachmentReceipt(**receipt.to_dict())
        binding = interop.ReceiptBinding(
            job_id=request.job_id,
            generation=request.generation,
            artifact_digest=request.artifact_digest,
            replay_domain=interop.attachment_replay_domain(
                request.job_id, request.generation, request.artifact_digest))
        statement = self._interop.verify_receipt(wire, binding=binding, now=now)
        return statement


def make_manifest():
    payload = b"interop-conformance-payload"
    manifest = {
        "schema_version": "foundry.artifact/v1",
        "kind": "dir-archive",
        "producer": "local-foundry",
        "source_repo": "analienx/Shiftio",
        "source_commit": SOURCE,
        "lock_digest": LOCK,
        "platform": "linux",
        "arch": "x86_64",
        "toolchain": "node-24",
        "payload_digest": hashlib.sha256(payload).hexdigest(),
        "payload_bytes": len(payload),
        "built_at": "2026-09-18T00:00:00+00:00",
        "retention": "goal-evidence",
        "lifecycle_policy": "no-scripts",
        "provenance_ref": "conformance-provenance",
        "verify_commands": ["sha256-check", ["sha256sum", "--check", "manifest.sha256"],
                            "signature-check"],
    }
    return manifest, payload


def prepare(store):
    policy = {
        "source_repo": "analienx/Shiftio",
        "lock_digest": LOCK,
        "platform": "linux",
        "arch": "x86_64",
        "toolchain": "node-24",
        "lifecycle_policy": "no-scripts",
        "provenance_ref": "conformance-provenance",
        "require_attachment_receipt": True,
    }
    job, _ = store.prepare_job(project="Shiftio", ref="main", source_digest=SOURCE,
                               idempotency_key="prep", artifact_policy=policy)
    job, _ = store.mark_preparing(job.id, actor="t", expected_generation=1,
                                  idempotency_key="prep-2")
    job, _ = store.mark_ready(job.id, actor="t", expected_generation=1,
                              idempotency_key="prep-3")
    return job


def issue(manifest, job, *, issuer=ISSUER, key=KEY, **overrides):
    """Issue a real Agent Interop receipt for the given job and plan."""
    plan = manifest["verify_commands"]
    steps = [{"index": index, "step": step,
              "evidence_digest": interop.step_commitment(index, step)}
             for index, step in enumerate(plan)]
    params = {
        "job_id": job.id,
        "generation": job.generation,
        "artifact_digest": manifest["payload_digest"],
        "staged_ref": STAGED_REF,
        "mount_handle": MOUNT_HANDLE,
        "verifier": VERIFIER_ID,
        "plan_hash": interop.plan_hash_for_plan(plan),
        "steps": steps,
    }
    params.update(overrides)
    return interop.HmacReceiptIssuer(issuer=issuer, key=key).issue(**params)


def request_for(manifest, job, **overrides):
    fields = {
        "repository": "analienx/Shiftio",
        "source_sha": manifest["source_commit"],
        "lock_digest": manifest["lock_digest"],
        "artifact_digest": manifest["payload_digest"],
        "submitting_identity": "pi-5b18fdefe0f04807b34af9e62ac898f9",
        "job_id": job.id,
        "attempt_id": job.current_attempt_id,
        "generation": job.generation,
    }
    fields.update(overrides)
    return ArtifactAttachmentRequest(**fields)


def test_foundry_receipt_wire_form_is_byte_identical_to_interop(tmp_path):
    manifest, _ = make_manifest()
    store = JobStore(tmp_path / "wire.sqlite")
    job = prepare(store)
    wire = issue(manifest, job)
    # Interop's Pydantic model forbids extras, so any Foundry-only key would
    # make this raise: exact wire compatibility is asserted, not assumed.
    interop.V3AttachmentReceipt(**wire)
    parsed = AttachmentReceipt.from_dict(wire)
    assert parsed.to_dict() == interop.V3AttachmentReceipt(**wire).model_dump()
    assert parsed.receipt_digest == interop.canonical_hash(
        interop.V3AttachmentReceipt(**wire).model_dump())


def test_interop_issued_receipt_attaches_and_records_evidence(tmp_path):
    manifest, payload = make_manifest()
    store = JobStore(tmp_path / "conformance.sqlite")
    job = prepare(store)
    request = request_for(manifest, job)
    record, replay = store.attach_artifact(
        job_id=job.id, manifest=manifest, expected_generation=job.generation,
        idempotency_key="attach-1", payload=payload,
        verifier=DeploymentVerifier(), attachment_request=request,
        attachment_receipt=issue(manifest, job),
        receipt_verifier=InteropReceiptVerifier({ISSUER: KEY}))
    assert replay is False
    assert record.receipt_digest
    assert record.replay_domain == interop.attachment_replay_domain(
        job.id, job.generation, manifest["payload_digest"])
    assert record.evidence["mount_handle"] == MOUNT_HANDLE
    assert record.evidence["verifier"] == VERIFIER_ID
    assert record.evidence["plan_hash"] == interop.plan_hash_for_plan(
        manifest["verify_commands"])
    assert record.evidence["staged_ref"] == STAGED_REF


def test_replayed_interop_receipt_cannot_attach_twice(tmp_path):
    manifest, payload = make_manifest()
    store = JobStore(tmp_path / "replay.sqlite")
    job = prepare(store)
    receipt = issue(manifest, job)
    verifier = InteropReceiptVerifier({ISSUER: KEY})
    store.attach_artifact(
        job_id=job.id, manifest=manifest, expected_generation=job.generation,
        idempotency_key="attach-1", payload=payload,
        verifier=DeploymentVerifier(), attachment_request=request_for(manifest, job),
        attachment_receipt=receipt, receipt_verifier=verifier)
    fresh_job = store.attach_artifact.__self__.get_job(job.id)
    with pytest.raises(Exception, match="already authorized an attachment"):
        store.attach_artifact(
            job_id=job.id, manifest=manifest, expected_generation=job.generation,
            idempotency_key="attach-2", payload=payload,
            verifier=DeploymentVerifier(), attachment_request=request_for(manifest, fresh_job),
            attachment_receipt=receipt, receipt_verifier=verifier)


def test_receipt_from_untrusted_issuer_never_attaches(tmp_path):
    manifest, payload = make_manifest()
    store = JobStore(tmp_path / "untrusted.sqlite")
    job = prepare(store)
    with pytest.raises(Exception, match="not in the trusted issuer store"):
        store.attach_artifact(
            job_id=job.id, manifest=manifest, expected_generation=job.generation,
            idempotency_key="attach-1", payload=payload,
            verifier=DeploymentVerifier(), attachment_request=request_for(manifest, job),
            attachment_receipt=issue(manifest, job, issuer="attacker"),
            receipt_verifier=InteropReceiptVerifier({ISSUER: KEY}))


def test_receipt_bound_to_another_job_never_attaches(tmp_path):
    manifest, payload = make_manifest()
    store = JobStore(tmp_path / "wrong-job.sqlite")
    job = prepare(store)
    # The request is honest for *this* job, but the receipt was issued for a
    # different job, so its replay domain cannot bind this attach context.
    foreign = issue(manifest, job, job_id="other-job")
    with pytest.raises(Exception, match=r"replay_domain|does not bind"):
        store.attach_artifact(
            job_id=job.id, manifest=manifest, expected_generation=job.generation,
            idempotency_key="attach-1", payload=payload,
            verifier=DeploymentVerifier(), attachment_request=request_for(manifest, job),
            attachment_receipt=foreign,
            receipt_verifier=InteropReceiptVerifier({ISSUER: KEY}))


def test_request_for_another_job_never_attaches(tmp_path):
    manifest, payload = make_manifest()
    store = JobStore(tmp_path / "wrong-source.sqlite")
    job = prepare(store)
    # A request naming a different job/attempt contradicts the manifest, the
    # job, and the current attempt, so Foundry rejects it before verification.
    other = request_for(manifest, job, job_id="other-job", attempt_id="other-attempt")
    with pytest.raises(Exception, match="does not match the manifest, job, and current attempt"):
        store.attach_artifact(
            job_id=job.id, manifest=manifest, expected_generation=job.generation,
            idempotency_key="attach-1", payload=payload,
            verifier=DeploymentVerifier(), attachment_request=other,
            attachment_receipt=issue(manifest, job, job_id="other-job"),
            receipt_verifier=InteropReceiptVerifier({ISSUER: KEY}))


def test_unsigned_receipt_is_rejected_by_the_interop_verifier(tmp_path):
    manifest, _payload = make_manifest()
    store = JobStore(tmp_path / "unsigned.sqlite")
    job = prepare(store)
    wire = issue(manifest, job)
    wire.pop("mac")
    with pytest.raises(AttachmentReceiptError):
        AttachmentReceipt.from_dict(wire)
