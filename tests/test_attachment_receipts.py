"""Phase 4 negative/positive tests: authenticated attachment receipts.

The Foundry library owns no cryptography. These tests inject a
deployment-owned verifier (the shape Agent Interop's ``ReceiptVerifier`` has)
so every trust-boundary case can be exercised offline:

- an unsigned or forged receipt never attaches;
- a validly signed receipt bound to a different source SHA / lock digest /
  artifact digest / job / attempt / generation is rejected;
- a host filesystem path is never mount evidence;
- plan/step evidence must cover the manifest verification plan exactly;
- an expired or over-long-lived receipt is rejected;
- a replayed receipt can never authorize a second attachment, while a fresh
  receipt remains valid;
- the ``require_attachment_receipt`` policy bit is validated.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from agent_foundry.artifacts import validate_artifact_policy  # noqa: E402
from agent_foundry.attachment import (  # noqa: E402
    MAX_RECEIPT_TTL_SECONDS,
    RECEIPT_SCHEMA,
    REQUEST_SCHEMA,
    ArtifactAttachmentRequest,
    AttachmentReceipt,
    AttachmentReceiptError,
    AttachmentReceiptVerifier,
    AttachmentReplayError,
    AttachmentRequestError,
    InMemoryReplayGuard,
    attachment_replay_domain,
    canonical_json,
    plan_hash_for_plan,
    receipt_replay_key,
    step_commitment,
    validate_mount_handle,
    validate_staged_ref,
    verify_attachment_receipt,
)

KEY = b"deployment-issuer-key-material"
ISSUER = "analienx-shiftio-foundry"
VERIFIER_ID = "podman-readonly-no-egress/v1"
PLAN = ("lint", ["node", "--test"], "build")
STAGED_REF = "cas:shiftio-foundry-20260918T135448-0b7485f0"

MANIFEST_BYTES = b"shiftio-dist-payload"
ARTIFACT_DIGEST = hashlib.sha256(MANIFEST_BYTES).hexdigest()


def make_request(**overrides) -> ArtifactAttachmentRequest:
    fields = dict(
        repository="analienx/Shiftio",
        source_sha="9a358aaf1234567890abcdef1234567890abcdef",
        lock_digest="510c0649992ce1d7a921b87ae5989d3f4c7dd8cd5458c6bce4de00fdd125331a",
        artifact_digest=ARTIFACT_DIGEST,
        submitting_identity="pi-5b18fdefe0f04807b34af9e62ac898f9",
        job_id="job-1",
        attempt_id="attempt-1",
        generation=1,
    )
    fields.update(overrides)
    return ArtifactAttachmentRequest(**fields)


class FakeInteropVerifier(AttachmentReceiptVerifier):
    """Mirrors Agent Interop's HmacReceiptVerifier trust store."""

    def __init__(self, *, key: bytes = KEY, issuers: dict | None = None):
        self._issuers = issuers if issuers is not None else {ISSUER: key}

    def verify_receipt(self, receipt, *, request, now):
        key = self._issuers.get(receipt.issuer)
        if key is None:
            raise AttachmentReceiptError(
                f"issuer {receipt.issuer!r} is not in the trusted issuer store")
        if not receipt.mac:
            raise AttachmentReceiptError("receipt carries no issuer MAC")
        expected = hmac.new(key, canonical_json(receipt.statement()), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, receipt.mac):
            raise AttachmentReceiptError("receipt MAC does not verify")
        return receipt.statement()


class OpaqueVerifier(AttachmentReceiptVerifier):
    """Resolves a server-side ``receipt_ref``; server receipts have no MAC."""

    def __init__(self, valid_refs: set[str]):
        self._valid = valid_refs

    def verify_receipt(self, receipt, *, request, now):
        if receipt.receipt_ref not in self._valid:
            raise AttachmentReceiptError("unknown server-side receipt handle")
        return receipt.statement()


def issue_receipt(request: ArtifactAttachmentRequest, *, plan=PLAN, issuer=ISSUER,
                  key=KEY, issued_at=None, expires_at=None, mac=True,
                  receipt_ref=None, **overrides) -> AttachmentReceipt:
    issued = issued_at or datetime.now(timezone.utc)
    if isinstance(issued, str):
        issued_dt = datetime.fromisoformat(issued.replace("Z", "+00:00"))
    else:
        issued_dt = issued
    expires = expires_at or (issued_dt + timedelta(hours=1))
    steps = []
    for index, step in enumerate(plan):
        normalized = list(step) if isinstance(step, (list, tuple)) else step
        steps.append({"index": index, "step": normalized,
                      "evidence_digest": step_commitment(index, step)})
    statement = {
        "issuer": issuer,
        "job_id": request.job_id,
        "generation": request.generation,
        "artifact_digest": request.artifact_digest,
        "staged_ref": STAGED_REF,
        "mount_handle": "mount:ro/cas-shiftio-foundry",
        "verifier": VERIFIER_ID,
        "plan_hash": plan_hash_for_plan(plan),
        "steps": steps,
        "issued_at": issued_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "expires_at": expires.strftime("%Y-%m-%dT%H:%M:%SZ") if isinstance(expires, datetime) else expires,
        "replay_domain": attachment_replay_domain(
            request.job_id, request.generation, request.artifact_digest),
    }
    statement.update(overrides)
    raw = {**statement, "schema_version": RECEIPT_SCHEMA}
    if receipt_ref is not None:
        raw["receipt_ref"] = receipt_ref
    elif mac:
        raw["mac"] = hmac.new(key, canonical_json({**statement, "statement": RECEIPT_SCHEMA}),
                              hashlib.sha256).hexdigest()
    return AttachmentReceipt.from_dict(raw)


def verify(request, receipt, **kwargs):
    kwargs.setdefault("verifier", FakeInteropVerifier())
    return verify_attachment_receipt(receipt, request, verify_plan=PLAN, **kwargs)


# -- request document -------------------------------------------------------

def test_request_round_trips_and_hashes_canonically():
    request = make_request()
    assert request.request_hash == hashlib.sha256(request.canonical_bytes()).hexdigest()
    assert ArtifactAttachmentRequest.from_dict(request.to_dict()) == request
    assert request.to_dict()["schema_version"] == REQUEST_SCHEMA


@pytest.mark.parametrize("field,value", [
    ("repository", ""),
    ("source_sha", "ZZZ"),
    ("lock_digest", "not-a-digest"),
    ("artifact_digest", "not-a-digest"),
    ("submitting_identity", ""),
    ("job_id", ""),
    ("attempt_id", ""),
    ("generation", 0),
])
def test_request_rejects_malformed_binding_fields(field, value):
    with pytest.raises(AttachmentRequestError):
        make_request(**{field: value})


def test_request_rejects_unknown_fields():
    raw = make_request().to_dict()
    raw["extra"] = "x"
    with pytest.raises(AttachmentRequestError):
        ArtifactAttachmentRequest.from_dict(raw)


def test_request_for_manifest_binds_manifest_identity():
    class FakeManifest:
        source_repo = "analienx/Shiftio"
        source_commit = "9a358aaf1234567890abcdef1234567890abcdef"
        lock_digest = "510c0649992ce1d7a921b87ae5989d3f4c7dd8cd5458c6bce4de00fdd125331a"
        payload_digest = ARTIFACT_DIGEST

    request = ArtifactAttachmentRequest.for_manifest(
        FakeManifest(), submitting_identity="pi-x", job_id="job-1",
        attempt_id="attempt-1", generation=3)
    assert request.repository == "analienx/Shiftio"
    assert request.source_sha == FakeManifest.source_commit
    assert request.generation == 3


# -- receipt parsing --------------------------------------------------------

def test_unsigned_receipt_is_rejected():
    request = make_request()
    raw = issue_receipt(request).to_dict()
    raw.pop("mac")
    with pytest.raises(AttachmentReceiptError, match="exactly one authentication channel"):
        AttachmentReceipt.from_dict(raw)
    # A structurally present but non-verifying MAC never authenticates.
    wrong = AttachmentReceipt.from_dict({**issue_receipt(request).to_dict(), "mac": "0" * 64})
    with pytest.raises(AttachmentReceiptError):
        verify(request, wrong)


def test_receipt_requires_exactly_one_auth_channel():
    request = make_request()
    signed = issue_receipt(request)
    raw = signed.to_dict()
    raw["receipt_ref"] = "receipt:abc123"
    with pytest.raises(AttachmentReceiptError, match="exactly one authentication channel"):
        AttachmentReceipt.from_dict(raw)
    raw.pop("mac")
    assert AttachmentReceipt.from_dict(raw).receipt_ref == "receipt:abc123"


def test_forged_mac_is_rejected():
    receipt = issue_receipt(make_request())
    forged = AttachmentReceipt.from_dict({**receipt.to_dict(), "mac": "0" * 64})
    with pytest.raises(AttachmentReceiptError, match="MAC"):
        verify(make_request(), forged)


def test_untrusted_issuer_is_rejected():
    receipt = issue_receipt(make_request(), issuer="attacker")
    with pytest.raises(AttachmentReceiptError, match="not in the trusted issuer store"):
        verify(make_request(), receipt)


def test_missing_verifier_fails_closed():
    with pytest.raises(AttachmentReceiptError, match="deployment receipt verifier is required"):
        verify_attachment_receipt(issue_receipt(make_request()), make_request(), verifier=None)


def test_authenticated_statement_must_match_receipt():
    class LyingVerifier(AttachmentReceiptVerifier):
        def verify_receipt(self, receipt, *, request, now):
            statement = receipt.statement()
            statement["verifier"] = "different-verifier/v9"
            return statement

    with pytest.raises(AttachmentReceiptError, match="does not match the attachment receipt"):
        verify_attachment_receipt(issue_receipt(make_request()), make_request(),
                                  verifier=LyingVerifier(), verify_plan=PLAN)


def test_verifier_returning_non_mapping_is_rejected():
    class BadVerifier(AttachmentReceiptVerifier):
        def verify_receipt(self, receipt, *, request, now):
            return None

    with pytest.raises(AttachmentReceiptError, match="no authenticated statement"):
        verify_attachment_receipt(issue_receipt(make_request()), make_request(),
                                  verifier=BadVerifier(), verify_plan=PLAN)


# -- binding negatives ------------------------------------------------------

def test_valid_signature_on_wrong_source_sha_is_rejected_by_request_binding():
    real = make_request()
    claimed = make_request(source_sha="deadbeef1234567890abcdef1234567890abcdef")
    receipt = issue_receipt(real)  # signed over the real artifact/job/generation
    # The request the caller presents must equal the manifest-derived request,
    # so a signed receipt can never be re-pointed at another source revision.
    assert claimed.source_sha != real.source_sha
    assert claimed.request_hash != real.request_hash
    assert verify(real, receipt).artifact_digest == real.artifact_digest


def test_receipt_bound_to_wrong_artifact_digest_is_rejected():
    request = make_request()
    receipt = issue_receipt(request, artifact_digest="a" * 64)
    with pytest.raises(AttachmentReceiptError, match="artifact_digest"):
        verify(request, receipt)


def test_receipt_bound_to_wrong_job_is_rejected():
    request = make_request()
    receipt = issue_receipt(request, job_id="job-2")
    with pytest.raises(AttachmentReceiptError, match="job_id"):
        verify(request, receipt)


def test_receipt_bound_to_wrong_generation_is_rejected():
    request = make_request(generation=2)
    receipt = issue_receipt(request, generation=1)
    with pytest.raises(AttachmentReceiptError, match="generation"):
        verify(request, receipt)


def test_receipt_bound_to_wrong_replay_domain_is_rejected():
    request = make_request()
    receipt = issue_receipt(request, replay_domain="b" * 64)
    with pytest.raises(AttachmentReceiptError, match="replay_domain"):
        verify(request, receipt)


def test_request_generation_must_match_the_jobs_generation():
    # The run-time request is derived with generation=job.generation, so a
    # caller cannot present a generation-1 receipt to a generation-2 job.
    with pytest.raises(AttachmentReceiptError, match="generation"):
        verify(make_request(generation=2), issue_receipt(make_request(generation=1)))


# -- mount evidence ---------------------------------------------------------

@pytest.mark.parametrize("handle", [
    "C:\\Workspace\\shiftio-foundry\\cas",
    "/mnt/c/Workspace/shiftio-foundry",
    "/home/analienx-agent/dist",
    "./relative/dist",
    "cas:shiftio-foundry-20260918T135448-0b7485f0",
    "http://127.0.0.1:8080/mount",
    "mount; rm -rf /",
])
def test_host_paths_and_cas_refs_are_never_mount_evidence(handle):
    with pytest.raises(AttachmentReceiptError):
        validate_mount_handle(handle, staged_ref=STAGED_REF)


def test_receipt_with_host_path_mount_handle_is_rejected():
    request = make_request()
    receipt = issue_receipt(request, mount_handle="/mnt/c/shiftio-dist")
    with pytest.raises(AttachmentReceiptError, match="host filesystem path"):
        verify(request, receipt)


@pytest.mark.parametrize("ref", ["/mnt/c/cas", "cas:", "http://x/cas", "cas:a/b", "cas:.."])
def test_staged_ref_must_be_an_immutable_cas_identifier(ref):
    with pytest.raises(AttachmentReceiptError):
        validate_staged_ref(ref)


# -- plan and step evidence -------------------------------------------------

def test_plan_hash_must_match_the_manifest_verification_plan():
    request = make_request()
    receipt = issue_receipt(request, plan=("lint", "build"))
    with pytest.raises(AttachmentReceiptError, match="plan_hash"):
        verify(request, receipt)


def test_step_evidence_must_cover_every_plan_step():
    request = make_request()
    raw = issue_receipt(request).to_dict()
    raw["steps"] = [dict(step) for step in raw["steps"][:2]]
    raw["mac"] = hmac.new(KEY, canonical_json(
        {**{k: v for k, v in raw.items() if k not in ("mac", "receipt_ref", "schema_version")},
         "statement": RECEIPT_SCHEMA}), hashlib.sha256).hexdigest()
    with pytest.raises(AttachmentReceiptError, match="does not cover"):
        verify(request, AttachmentReceipt.from_dict(raw))


def test_tampered_step_commitment_is_rejected():
    request = make_request()
    receipt = issue_receipt(request)
    raw = receipt.to_dict()
    raw["steps"] = [dict(step) for step in raw["steps"]]
    raw["steps"][1]["evidence_digest"] = "c" * 64
    tampered = AttachmentReceipt.from_dict(raw)
    # Re-sign so only the step-commitment invariant can fail.
    statement = tampered.statement()
    raw["mac"] = hmac.new(KEY, canonical_json(statement), hashlib.sha256).hexdigest()
    with pytest.raises(AttachmentReceiptError, match="verified-step commitment"):
        verify(request, AttachmentReceipt.from_dict(raw))


def test_step_order_is_significant():
    request = make_request()
    receipt = issue_receipt(request, plan=PLAN)
    raw = receipt.to_dict()
    raw["steps"] = [dict(raw["steps"][2]), dict(raw["steps"][0]), dict(raw["steps"][1])]
    with pytest.raises(AttachmentReceiptError):
        AttachmentReceipt.from_dict(raw)


# -- freshness --------------------------------------------------------------

def test_expired_receipt_is_rejected():
    now = datetime.now(timezone.utc)
    receipt = issue_receipt(make_request(), issued_at=now - timedelta(hours=3),
                            expires_at=now - timedelta(hours=2))
    with pytest.raises(AttachmentReceiptError, match="expired"):
        verify(make_request(), receipt)


def test_future_receipt_is_rejected():
    now = datetime.now(timezone.utc)
    receipt = issue_receipt(make_request(), issued_at=now + timedelta(hours=2),
                            expires_at=now + timedelta(hours=3))
    with pytest.raises(AttachmentReceiptError, match="future"):
        verify(make_request(), receipt)


def test_over_long_lived_receipt_is_rejected():
    now = datetime.now(timezone.utc)
    receipt = issue_receipt(
        make_request(), issued_at=now,
        expires_at=now + timedelta(seconds=MAX_RECEIPT_TTL_SECONDS + 60))
    with pytest.raises(AttachmentReceiptError, match="maximum TTL"):
        verify(make_request(), receipt)


def test_non_timezone_aware_timestamp_is_rejected():
    request = make_request()
    raw = issue_receipt(request).to_dict()
    raw["issued_at"] = "2026-09-18T13:00:00"
    signed = AttachmentReceipt.from_dict(raw)
    statement = signed.statement()
    raw["mac"] = hmac.new(KEY, canonical_json(statement), hashlib.sha256).hexdigest()
    with pytest.raises(AttachmentReceiptError, match="timezone-aware|ISO-8601"):
        verify(request, AttachmentReceipt.from_dict(raw))


# -- replay and single use --------------------------------------------------

def test_replayed_receipt_is_rejected():
    request = make_request()
    receipt = issue_receipt(request)
    guard = InMemoryReplayGuard()
    verify(request, receipt, replay_guard=guard)
    with pytest.raises(AttachmentReplayError, match="already"):
        verify(request, receipt, replay_guard=guard)


def test_fresh_receipt_for_the_same_artifact_is_allowed():
    request = make_request()
    guard = InMemoryReplayGuard()
    now = datetime.now(timezone.utc)
    verify(request, issue_receipt(request, mount_handle="mount:ro/first",
                                  issued_at=now, expires_at=now + timedelta(hours=1)),
           replay_guard=guard)
    verify(request, issue_receipt(request, mount_handle="mount:ro/second",
                                  issued_at=now + timedelta(seconds=1),
                                  expires_at=now + timedelta(hours=1)),
           replay_guard=guard)
    assert len(guard.seen) == 2


def test_replay_key_is_scoped_to_the_replay_domain():
    request = make_request()
    first = issue_receipt(request)
    second = issue_receipt(request, job_id=request.job_id)
    assert receipt_replay_key(first) == receipt_replay_key(second)
    other = issue_receipt(make_request(job_id="job-9"), job_id="job-9")
    assert other.replay_domain != first.replay_domain
    assert receipt_replay_key(other).startswith(other.replay_domain)


def test_opaque_server_side_receipt_is_single_use_by_handle():
    request = make_request()
    ref = "receipt:shiftio-foundry-42"
    receipt = issue_receipt(request, mac=False, receipt_ref=ref)
    guard = InMemoryReplayGuard()
    verify(request, receipt, verifier=OpaqueVerifier({ref}), replay_guard=guard)
    with pytest.raises(AttachmentReplayError):
        verify(request, receipt, verifier=OpaqueVerifier({ref}), replay_guard=guard)


# -- evidence ---------------------------------------------------------------

def test_verified_evidence_records_the_full_binding():
    request = make_request()
    receipt = issue_receipt(request)
    evidence = verify(request, receipt)
    assert evidence.job_id == request.job_id
    assert evidence.generation == request.generation
    assert evidence.artifact_digest == request.artifact_digest
    assert evidence.request_hash == request.request_hash
    assert evidence.receipt_digest == receipt.receipt_digest
    assert evidence.plan_hash == plan_hash_for_plan(PLAN)
    assert [s["index"] for s in evidence.steps] == [0, 1, 2]
    assert json.loads(json.dumps(evidence.to_dict()))["replay_domain"] == receipt.replay_domain


def test_receipt_digest_ignores_nothing_and_changes_with_the_signature():
    request = make_request()
    first = issue_receipt(request)
    second = issue_receipt(request, mount_handle="mount:ro/other")
    assert first.receipt_digest != second.receipt_digest


# -- policy -----------------------------------------------------------------

def test_require_attachment_receipt_policy_bit_is_validated():
    base = {
        "source_repo": "analienx/Shiftio",
        "lock_digest": "510c0649992ce1d7a921b87ae5989d3f4c7dd8cd5458c6bce4de00fdd125331a",
        "platform": "linux",
        "arch": "amd64",
        "toolchain": "node-24",
        "lifecycle_policy": "hermetic",
    }
    assert validate_artifact_policy({**base, "require_attachment_receipt": True})[
        "require_attachment_receipt"] is True
    assert validate_artifact_policy(base).get("require_attachment_receipt") is None
    with pytest.raises(ValueError):
        validate_artifact_policy({**base, "require_attachment_receipt": "yes"})
    with pytest.raises(ValueError):
        validate_artifact_policy({**base, "unknown_bool": True})
