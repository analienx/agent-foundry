"""Regression tests for the merge-blocking hardening review (PR #2).

Each finding gets at least one failing-before/passing-after test:

1. Two-phase launch reservation with an idempotent adapter token: a crash
   between reservation and confirmation can never duplicate side effects.
2. A stale attach from generation N rejects without mutating generation N+1.
3. Attach requires payload verification AND the adapter read-only mount.
4. Job-bound artifact policy persisted at prepare time and enforced as
   declared; callers cannot omit required constraints.
5. Attachments freeze before execution; attach rejected in running /
   cancel_requested / terminal states; execution/result evidence binds the
   frozen digest set.
6. Failed-attachment idempotency replay returns the same durable failure.
7. Events expose source digest, artifact digests, and policy hash.
8. Named verification profiles / structured argv governed by the adapter
   (no substring checks).
"""

import hashlib

import pytest

from agent_foundry import (
    ArtifactValidationError,
    ArtifactVerificationError,
    ArtifactVerifier,
    AttemptConflict,
    IllegalTransitionError,
    JobStore,
    StaleGenerationError,
    validate_manifest,
)

SOURCE = "a" * 40
LOCK = "b" * 64
POLICY = {
    "source_repo": "example/synthetic",
    "lock_digest": LOCK,
    "platform": "linux",
    "arch": "x86_64",
    "toolchain": "node-22",
    "lifecycle_policy": "no-scripts",
    "provenance_ref": "synthetic-provenance",
}


class FakeVerifier(ArtifactVerifier):
    def __init__(self, accept=True):
        self.accept = accept
        self.verify_calls = 0
        self.mount_calls = []

    def verify(self, manifest):
        self.verify_calls += 1
        return self.accept

    def mount_readonly(self, *, job_id, manifest):
        self.mount_calls.append((job_id, manifest.payload_digest))
        return f"/mnt/ro/{manifest.payload_digest[:12]}"


class IdempotentAdapter:
    """Deployment launcher stand-in: idempotent on the launch token."""

    def __init__(self):
        self.calls = []  # launch tokens seen, in order
        self.by_token = {}

    def __call__(self, *, job_id, attempt_id, command_profile, launch_token=None):
        assert launch_token, "adapter requires the durable launch token"
        self.calls.append(launch_token)
        return self.by_token.setdefault(launch_token, f"native-{launch_token[:12]}")


def make_manifest(**overrides):
    payload = overrides.pop("payload_bytes_raw", b"hardening-payload")
    manifest = {
        "schema_version": "foundry.artifact/v1",
        "kind": "dir-archive",
        "producer": "synthetic-ci",
        "source_repo": "example/synthetic",
        "source_commit": SOURCE,
        "lock_digest": LOCK,
        "platform": "linux",
        "arch": "x86_64",
        "toolchain": "node-22",
        "payload_digest": hashlib.sha256(payload).hexdigest(),
        "payload_bytes": len(payload),
        "built_at": "2026-09-17T00:00:00+00:00",
        "retention": "test-only",
        "lifecycle_policy": "no-scripts",
        "provenance_ref": "synthetic-provenance",
        "verify_commands": ["sha256sum --check manifest.sha256"],
    }
    manifest.update(overrides)
    return manifest, payload


def make_job(store, key="prep-1", policy=POLICY):
    kwargs = {} if policy is None else {"artifact_policy": policy}
    job, _ = store.prepare_job(project="synthetic", ref="main",
                                source_digest=SOURCE, idempotency_key=key, **kwargs)
    return job


def drive_ready(store, job, gen=1, tag=""):
    job, _ = store.mark_preparing(job.id, actor="t", expected_generation=gen,
                                  idempotency_key=f"to-prep{tag}")
    job, _ = store.mark_ready(job.id, actor="t", expected_generation=gen,
                              idempotency_key=f"to-ready{tag}")
    return job


def attach(store, job, key, verifier=None, **manifest_overrides):
    manifest, payload = make_manifest(**manifest_overrides)
    return store.attach_artifact(
        job_id=job.id, manifest=manifest, expected_generation=job.generation,
        idempotency_key=key, payload=payload,
        verifier=FakeVerifier() if verifier is None else verifier,
    ), manifest, payload


# -- (1) two-phase launch -------------------------------------------------

def test_launcher_receives_idempotent_token_and_replay_does_not_relaunch(tmp_path):
    store = JobStore(tmp_path / "f.sqlite")
    job = drive_ready(store, make_job(store))
    adapter = IdempotentAdapter()
    job, dup = store.execute(job_id=job.id, command_profile="offline", objective="o",
                             authority_ref="a", expected_generation=1,
                             idempotency_key="exec-1", launcher=adapter)
    assert not dup and job.state == "running" and job.launch_token is None
    first_identity = job.native_identity
    assert len(adapter.calls) == 1
    # Same-key replay must not invoke the launcher again.
    job2, dup2 = store.execute(job_id=job.id, command_profile="offline", objective="o",
                               authority_ref="a", expected_generation=1,
                               idempotency_key="exec-1", launcher=adapter)
    assert dup2 and job2.native_identity == first_identity
    assert len(adapter.calls) == 1


def test_crash_between_reserve_and_confirm_never_duplicates(tmp_path):
    store = JobStore(tmp_path / "f.sqlite")
    job = drive_ready(store, make_job(store))

    def crashing_launcher(*, job_id, attempt_id, command_profile, launch_token=None):
        raise KeyboardInterrupt("simulated crash after reservation commit")

    with pytest.raises(KeyboardInterrupt):
        store.execute(job_id=job.id, command_profile="offline", objective="o",
                      authority_ref="a", expected_generation=1,
                      idempotency_key="exec-1", launcher=crashing_launcher)
    reserved = store.get_job(job.id)
    assert reserved.state == "ready" and reserved.launch_token is not None

    # Restart reconciles the pending reservation honestly: side effects are
    # possible, so the job is unknown_outcome, never silently replayed.
    recovered = store.recover()
    assert [(r.job.id, r.disposition) for r in recovered] == [(job.id, "unknown_outcome")]

    # And the same execute key now fails durably instead of relaunching.
    adapter = IdempotentAdapter()
    with pytest.raises(IllegalTransitionError):
        store.execute(job_id=job.id, command_profile="offline", objective="o",
                      authority_ref="a", expected_generation=1,
                      idempotency_key="exec-1", launcher=adapter)
    assert adapter.calls == []


def test_crash_retry_with_same_key_reuses_token_idempotently(tmp_path):
    store = JobStore(tmp_path / "f.sqlite")
    job = drive_ready(store, make_job(store))
    seen = []

    def flaky_launcher(*, job_id, attempt_id, command_profile, launch_token=None):
        seen.append(launch_token)
        if len(seen) == 1:
            raise KeyboardInterrupt("simulated crash inside launcher")
        return f"native-{launch_token[:12]}"

    with pytest.raises(KeyboardInterrupt):
        store.execute(job_id=job.id, command_profile="offline", objective="o",
                      authority_ref="a", expected_generation=1,
                      idempotency_key="exec-1", launcher=flaky_launcher)
    job, dup = store.execute(job_id=job.id, command_profile="offline", objective="o",
                             authority_ref="a", expected_generation=1,
                             idempotency_key="exec-1", launcher=flaky_launcher)
    assert job.state == "running" and not dup
    # Same durable token both times: an idempotent adapter starts one unit.
    assert len(seen) == 2 and seen[0] == seen[1]
    assert job.native_identity == f"native-{seen[0][:12]}"


# -- (2) stale attach -----------------------------------------------------

def test_stale_attach_rejects_without_touching_new_generation(tmp_path):
    store = JobStore(tmp_path / "f.sqlite")
    job = drive_ready(store, make_job(store))
    job, _ = store.fail_job(job_id=job.id, reason="boom", expected_generation=1,
                            idempotency_key="fail-1")
    job, _ = store.retry_job(job_id=job.id, reason="retry", expected_generation=1,
                             idempotency_key="retry-1")
    assert job.generation == 2 and job.state == "accepted"
    _, events_before, _ = store.status(job.id)
    manifest, payload = make_manifest()
    with pytest.raises(StaleGenerationError):
        store.attach_artifact(job_id=job.id, manifest=manifest, expected_generation=1,
                              idempotency_key="stale-art", payload=payload,
                              verifier=FakeVerifier())
    current = store.get_job(job.id)
    assert current.generation == 2 and current.state == "accepted"
    assert current.quarantine_reason is None
    assert store.attachments(job.id) == []
    _, events_after, _ = store.status(job.id)
    assert len(events_after) == len(events_before)


# -- (3) verification + read-only mount required --------------------------

def test_attach_without_payload_is_rejected_and_never_recorded(tmp_path):
    store = JobStore(tmp_path / "f.sqlite")
    job = drive_ready(store, make_job(store))
    manifest, _ = make_manifest()
    with pytest.raises(ArtifactVerificationError):
        store.attach_artifact(job_id=job.id, manifest=manifest, expected_generation=1,
                              idempotency_key="art-1", verifier=FakeVerifier())
    assert store.get_job(job.id).state == "quarantined"
    assert store.attachments(job.id) == []


def test_attach_without_verifier_is_rejected_and_never_recorded(tmp_path):
    store = JobStore(tmp_path / "f.sqlite")
    job = drive_ready(store, make_job(store))
    manifest, payload = make_manifest()
    with pytest.raises(ArtifactVerificationError):
        store.attach_artifact(job_id=job.id, manifest=manifest, expected_generation=1,
                              idempotency_key="art-1", payload=payload)
    assert store.attachments(job.id) == []


def test_attach_calls_verifier_and_mount_and_records_mount_point(tmp_path):
    store = JobStore(tmp_path / "f.sqlite")
    job = drive_ready(store, make_job(store))
    verifier = FakeVerifier()
    (record, dup), manifest, payload = attach(store, job, "art-1", verifier=verifier)
    assert not dup
    assert verifier.verify_calls == 1
    assert verifier.mount_calls == [(job.id, manifest["payload_digest"])]
    assert record.mount_point == f"/mnt/ro/{manifest['payload_digest'][:12]}"
    assert store.attachments(job.id)[0].mount_point == record.mount_point


def test_verifier_rejection_and_mount_failure_record_nothing(tmp_path):
    for verifier, key in ((FakeVerifier(accept=False), "art-no"),
                          (None, "art-mount")):
        store = JobStore(tmp_path / f"{key}.sqlite")
        job = drive_ready(store, make_job(store, key=key))
        manifest, payload = make_manifest()

        class BadMount(FakeVerifier):
            def mount_readonly(self, *, job_id, manifest):
                raise RuntimeError("mount unavailable")

        probe = verifier if verifier is not None else BadMount()
        with pytest.raises((ArtifactVerificationError, RuntimeError)):
            store.attach_artifact(job_id=job.id, manifest=manifest, expected_generation=1,
                                  idempotency_key="art-1", payload=payload, verifier=probe)
        assert store.attachments(job.id) == []


# -- (4) job-bound artifact policy ----------------------------------------

def test_policy_mismatch_quarantines_and_caller_cannot_weaken(tmp_path):
    store = JobStore(tmp_path / "f.sqlite")
    job = drive_ready(store, make_job(store))
    manifest, payload = make_manifest(arch="aarch64")
    with pytest.raises(ArtifactVerificationError):
        store.attach_artifact(job_id=job.id, manifest=manifest, expected_generation=1,
                              idempotency_key="art-1", payload=payload,
                              verifier=FakeVerifier())
    assert store.get_job(job.id).state == "quarantined"

    store2 = JobStore(tmp_path / "g.sqlite")
    job2 = drive_ready(store2, make_job(store2, key="prep-1"))
    manifest2, payload2 = make_manifest()
    # A caller constraint contradicting the stored policy is rejected.
    with pytest.raises(ArtifactVerificationError):
        store2.attach_artifact(job_id=job2.id, manifest=manifest2, expected_generation=1,
                               idempotency_key="art-1", payload=payload2,
                               verifier=FakeVerifier(), require_platform="windows")
    assert store2.get_job(job2.id).state == "quarantined"


def test_stored_policy_enforced_without_caller_constraints(tmp_path):
    store = JobStore(tmp_path / "f.sqlite")
    job = drive_ready(store, make_job(store))
    manifest, payload = make_manifest()
    # No require_* at all: the persisted policy still pins everything.
    record, dup = store.attach_artifact(job_id=job.id, manifest=manifest,
                                        expected_generation=1, idempotency_key="art-1",
                                        payload=payload, verifier=FakeVerifier())
    assert not dup and record.artifact_digest == manifest["payload_digest"]
    assert store.get_job(job.id).policy_hash
    assert store.get_job(job.id).artifact_policy["arch"] == "x86_64"


def test_prepare_rejects_policy_hash_mismatch_and_legacy_needs_constraints(tmp_path):
    store = JobStore(tmp_path / "f.sqlite")
    with pytest.raises(ValueError):
        store.prepare_job(project="s", ref="r", source_digest=SOURCE,
                          idempotency_key="k", artifact_policy=POLICY,
                          policy_hash="0" * 64)
    # Legacy job without a stored policy: omitted constraints are rejected.
    legacy = make_job(store, key="legacy", policy=None)
    legacy = drive_ready(store, legacy, tag="-legacy")
    manifest, payload = make_manifest()
    with pytest.raises(ArtifactVerificationError):
        store.attach_artifact(job_id=legacy.id, manifest=manifest, expected_generation=1,
                              idempotency_key="art-leg", payload=payload,
                              verifier=FakeVerifier(), require_lock_digest=LOCK)


# -- (5) freeze before execution ------------------------------------------

def test_attach_rejected_in_running_cancel_requested_and_terminal(tmp_path):
    store = JobStore(tmp_path / "f.sqlite")
    job = drive_ready(store, make_job(store))
    (record, _), manifest, payload = attach(store, job, "art-1")
    job, _ = store.execute(job_id=job.id, command_profile="offline", objective="o",
                           authority_ref="a", expected_generation=1,
                           idempotency_key="exec-1", native_identity="native-1")
    manifest2, payload2 = make_manifest(payload_bytes_raw=b"second-payload")
    with pytest.raises(IllegalTransitionError):
        store.attach_artifact(job_id=job.id, manifest=manifest2, expected_generation=1,
                              idempotency_key="art-2", payload=payload2,
                              verifier=FakeVerifier())
    assert store.get_job(job.id).state == "running"
    job, _ = store.cancel(job_id=job.id, reason="op", expected_generation=1,
                          idempotency_key="c1")
    with pytest.raises(IllegalTransitionError):
        store.attach_artifact(job_id=job.id, manifest=manifest2, expected_generation=1,
                              idempotency_key="art-3", payload=payload2,
                              verifier=FakeVerifier())
    job, _ = store.confirm_cancelled(job_id=job.id, expected_generation=1,
                                     idempotency_key="cc", native_dead=True)
    with pytest.raises(IllegalTransitionError):
        store.attach_artifact(job_id=job.id, manifest=manifest2, expected_generation=1,
                              idempotency_key="art-4", payload=payload2,
                              verifier=FakeVerifier())
    assert [a.artifact_digest for a in store.attachments(job.id)] == [record.artifact_digest]


def test_execute_freezes_digests_and_result_binds_them(tmp_path):
    store = JobStore(tmp_path / "f.sqlite")
    job = drive_ready(store, make_job(store))
    (record, _), _, _ = attach(store, job, "art-1")
    job, _ = store.execute(job_id=job.id, command_profile="offline", objective="o",
                           authority_ref="a", expected_generation=1,
                           idempotency_key="exec-1", native_identity="native-1")
    assert store.get_job(job.id).frozen_artifact_digests == [record.artifact_digest]
    job, events, _ = store.status(job.id)
    assert events[-1].to_state == "running"
    assert events[-1].artifact_digests == [record.artifact_digest]
    store.record_result(job_id=job.id, outcome="succeeded", result={},
                        expected_generation=1, idempotency_key="res-1")
    result = store.read_result(job.id)
    assert result["frozen_artifact_digests"] == [record.artifact_digest]
    assert result["artifact_digests"] == [record.artifact_digest]


def test_retry_starts_new_generation_with_no_attachments(tmp_path):
    store = JobStore(tmp_path / "f.sqlite")
    job = drive_ready(store, make_job(store))
    attach(store, job, "art-1")
    job, _ = store.execute(job_id=job.id, command_profile="offline", objective="o",
                           authority_ref="a", expected_generation=1,
                           idempotency_key="exec-1", native_identity="native-1")
    job, _ = store.record_result(job_id=job.id, outcome="failed", result={},
                                 expected_generation=1, idempotency_key="res-1")
    job, _ = store.retry_job(job_id=job.id, reason="again", expected_generation=1,
                             idempotency_key="retry-1")
    assert job.generation == 2 and job.frozen_artifact_digests == []
    assert store.attachments(job.id) == []
    # Replaying the generation-1 attach key still returns the durable
    # acknowledgement (rebuilt from the stored response) without KeyError
    # and without resurrecting the attachment in generation 2.
    manifest, payload = make_manifest()
    record_replay, dup = store.attach_artifact(
        job_id=job.id, manifest=manifest, expected_generation=1,
        idempotency_key="art-1", payload=payload, verifier=FakeVerifier())
    assert dup and record_replay.artifact_digest == manifest["payload_digest"]
    assert store.attachments(job.id) == []
    assert store.get_job(job.id).generation == 2


# -- (6) failed-attach replay ---------------------------------------------

def test_failed_attach_replay_returns_same_failure(tmp_path):
    store = JobStore(tmp_path / "f.sqlite")
    job = drive_ready(store, make_job(store))
    manifest, _ = make_manifest()
    with pytest.raises(ArtifactVerificationError, match="payload"):
        store.attach_artifact(job_id=job.id, manifest=manifest, expected_generation=1,
                              idempotency_key="art-1", payload=b"tampered",
                              verifier=FakeVerifier())
    # Replay with the same key/payload: same durable failure, not KeyError.
    with pytest.raises(ArtifactVerificationError, match="payload"):
        store.attach_artifact(job_id=job.id, manifest=manifest, expected_generation=1,
                              idempotency_key="art-1", payload=b"tampered",
                              verifier=FakeVerifier())
    assert store.get_job(job.id).state == "quarantined"


def test_conflicting_attach_key_rejected(tmp_path):
    store = JobStore(tmp_path / "f.sqlite")
    job = drive_ready(store, make_job(store))
    attach(store, job, "art-1")
    manifest, payload = make_manifest(payload_bytes_raw=b"other-payload")
    with pytest.raises(AttemptConflict):
        store.attach_artifact(job_id=job.id, manifest=manifest, expected_generation=1,
                              idempotency_key="art-1", payload=payload,
                              verifier=FakeVerifier())


# -- (7) event evidence ----------------------------------------------------

def test_events_expose_source_digest_artifact_digests_and_policy_hash(tmp_path):
    store = JobStore(tmp_path / "f.sqlite")
    job = drive_ready(store, make_job(store))
    (record, _), _, _ = attach(store, job, "art-1")
    _, events, _ = store.status(job.id, after_cursor=0)
    assert events, "expected a monotonic event log"
    for event in events:
        assert event.source_digest == SOURCE
        assert event.policy_hash == store.get_job(job.id).policy_hash
    attach_events = [e for e in events if e.artifact_digests]
    assert attach_events
    assert record.artifact_digest in attach_events[-1].artifact_digests


# -- (8) verification profiles / structured argv ---------------------------

def test_named_profiles_and_structured_argv_accepted(tmp_path):
    base, _ = make_manifest()
    named, _ = make_manifest(verify_commands=["sha256-check"])
    assert validate_manifest(named).verify_commands == ("sha256-check",)
    structured, _ = make_manifest(
        verify_commands=[["sha256sum", "--check", "manifest.sha256"]])
    parsed = validate_manifest(structured)
    assert parsed.verify_commands == (("sha256sum", "--check", "manifest.sha256"),)
    # Legacy single-string form still parses as structured argv.
    assert validate_manifest(base)


@pytest.mark.parametrize("commands", [
    ["curl https://example.invalid/check"],
    [["curl", "--check", "x"]],
    [["sha256sum", "--check", "https://example.invalid/manifest"]],
    ["sha256sum --check manifest.sha256; rm -rf /"],
    ["sha256sum --check $(evil)"],
    [["python", "-c", "print('hi')"]],
    [["sha256sum", "--upload-file", "manifest.sha256"]],
    [],
    [""],
    [["sha256sum", "", "x"]],
])
def test_ungoverned_verification_rejected(commands):
    manifest, _ = make_manifest(verify_commands=commands)
    with pytest.raises(ArtifactValidationError):
        validate_manifest(manifest)
