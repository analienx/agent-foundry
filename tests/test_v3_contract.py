"""Synthetic v3 contract tests: state machine, events, fencing, recovery, artifacts."""

import hashlib

import pytest

from agent_foundry import (
    ArtifactValidationError,
    ArtifactVerificationError,
    AttemptConflict,
    IllegalTransitionError,
    JobNotReadyError,
    JobStore,
    StaleGenerationError,
    validate_manifest,
)

SOURCE = "a" * 40
LOCK = "b" * 64


def make_manifest(**overrides):
    payload = overrides.pop("payload_bytes_raw", b"synthetic-payload")
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


def make_job(store, key="prep-1"):
    job, _ = store.prepare_job(project="synthetic", ref="main",
                                source_digest=SOURCE, idempotency_key=key)
    return job


def drive_ready(store, job):
    job, _ = store.mark_preparing(job.id, actor="t", expected_generation=1, idempotency_key="to-prep")
    job, _ = store.mark_ready(job.id, actor="t", expected_generation=1, idempotency_key="to-ready")
    return job


def drive_running(store, job):
    job = drive_ready(store, job)
    job, _ = store.execute(job_id=job.id, command_profile="offline-test", objective="synthetic",
                           authority_ref="synthetic-policy", expected_generation=1,
                           idempotency_key="exec-1", native_identity="native-1")
    return job


def test_state_machine_happy_path_and_terminal_immutability(tmp_path):
    store = JobStore(tmp_path / "f.sqlite")
    job = drive_running(store, make_job(store))
    job, _ = store.record_result(job_id=job.id, outcome="succeeded", result={"ok": True},
                                 expected_generation=1, idempotency_key="res-1")
    assert job.state == "succeeded"
    with pytest.raises(IllegalTransitionError):
        store.quarantine_job(job_id=job.id, reason="late", expected_generation=1, idempotency_key="q-late")
    # retry of succeeded is final
    with pytest.raises(IllegalTransitionError):
        store.retry_job(job_id=job.id, reason="no", expected_generation=1, idempotency_key="r-no")


def test_illegal_edges_rejected(tmp_path):
    store = JobStore(tmp_path / "f.sqlite")
    job = make_job(store)
    with pytest.raises(IllegalTransitionError):
        store.execute(job_id=job.id, command_profile="x", objective="y", authority_ref="z",
                      expected_generation=1, idempotency_key="e", native_identity="n")
    with pytest.raises(IllegalTransitionError):
        store.record_result(job_id=job.id, outcome="succeeded", expected_generation=1, idempotency_key="r")


def test_events_monotonic_and_cursor_pagination(tmp_path):
    store = JobStore(tmp_path / "f.sqlite")
    job = drive_running(store, make_job(store))
    _, events, cursor = store.status(job.id, after_cursor=0)
    assert [e.seq for e in events] == sorted(e.seq for e in events)
    assert cursor == events[-1].seq
    job, _ = store.record_result(job_id=job.id, outcome="failed", result={}, expected_generation=1, idempotency_key="res")
    _, later, cursor2 = store.status(job.id, after_cursor=cursor)
    assert len(later) == 1 and cursor2 > cursor
    _, empty, cursor3 = store.status(job.id, after_cursor=cursor2)
    assert empty == [] and cursor3 == cursor2


def test_generation_fencing_rejects_stale_writes(tmp_path):
    store = JobStore(tmp_path / "f.sqlite")
    job = drive_ready(store, make_job(store))
    with pytest.raises(StaleGenerationError):
        store.execute(job_id=job.id, command_profile="c", objective="o", authority_ref="a",
                      expected_generation=999, idempotency_key="stale", native_identity="n")


def test_idempotent_replay_and_conflict(tmp_path):
    store = JobStore(tmp_path / "f.sqlite")
    first, dup = store.prepare_job(project="s", ref="r", source_digest=SOURCE, idempotency_key="k")
    assert not dup
    second, dup2 = store.prepare_job(project="s", ref="r", source_digest=SOURCE, idempotency_key="k")
    assert dup2 and second.id == first.id
    with pytest.raises(AttemptConflict):
        store.prepare_job(project="s", ref="other", source_digest=SOURCE, idempotency_key="k")
    job = drive_running(store, first)
    replay, dup3 = store.execute(job_id=job.id, command_profile="offline-test", objective="synthetic",
                                 authority_ref="synthetic-policy", expected_generation=1,
                                 idempotency_key="exec-1", native_identity="native-OTHER")
    assert dup3 and replay.state == "running" and replay.native_identity == "native-1"


def test_execute_requires_native_identity_before_running(tmp_path):
    store = JobStore(tmp_path / "f.sqlite")
    job = drive_ready(store, make_job(store))
    with pytest.raises(ValueError):
        store.execute(job_id=job.id, command_profile="c", objective="o", authority_ref="a",
                      expected_generation=1, idempotency_key="no-ident")
    assert store.get_job(job.id).state == "ready"


def test_cancel_flow_requires_death_evidence(tmp_path):
    store = JobStore(tmp_path / "f.sqlite")
    job = drive_running(store, make_job(store))
    job, _ = store.cancel(job_id=job.id, reason="operator", expected_generation=1, idempotency_key="c1")
    assert job.state == "cancel_requested"
    with pytest.raises(ValueError):
        store.confirm_cancelled(job_id=job.id, expected_generation=1, idempotency_key="cc", native_dead=False)
    job, _ = store.confirm_cancelled(job_id=job.id, expected_generation=1, idempotency_key="cc", native_dead=True)
    assert job.state == "cancelled"


def test_recovery_never_started_is_interrupted(tmp_path):
    store = JobStore(tmp_path / "f.sqlite")
    job = make_job(store)
    recovered = store.recover()
    assert [(r.job.id, r.disposition) for r in recovered] == [(job.id, "interrupted")]
    assert store.get_job(job.id).state == "interrupted"


def test_recovery_without_liveness_is_unknown_outcome(tmp_path):
    store = JobStore(tmp_path / "f.sqlite")
    job = drive_running(store, make_job(store))
    recovered = store.recover()
    assert recovered[0].disposition == "unknown_outcome"
    assert store.get_job(job.id).state == "unknown_outcome"
    # unknown outcomes are never auto-replayed: explicit retry opens a new generation
    retried, _ = store.retry_job(job_id=job.id, reason="operator decision",
                                 expected_generation=1, idempotency_key="retry-1")
    assert retried.state == "accepted" and retried.generation == 2
    assert retried.current_attempt_id != job.current_attempt_id


def test_recovery_alive_native_stays_running(tmp_path):
    store = JobStore(tmp_path / "f.sqlite")
    job = drive_running(store, make_job(store))
    recovered = store.recover(liveness=lambda ident: True)
    assert recovered[0].disposition == "alive"
    assert store.get_job(job.id).state == "running"


def test_quarantine_from_any_non_terminal(tmp_path):
    store = JobStore(tmp_path / "f.sqlite")
    job = make_job(store)
    quarantined, _ = store.quarantine_job(job_id=job.id, reason="suspicious",
                                          expected_generation=1, idempotency_key="q1")
    assert quarantined.state == "quarantined"
    job2 = drive_running(store, make_job(store, key="prep-2"))
    quarantined2, _ = store.quarantine_job(job_id=job2.id, reason="suspicious",
                                           expected_generation=1, idempotency_key="q2")
    assert quarantined2.state == "quarantined"


def test_artifact_attach_and_tamper_quarantines(tmp_path):
    store = JobStore(tmp_path / "f.sqlite")
    job = drive_ready(store, make_job(store))
    manifest, payload = make_manifest()
    record, dup = store.attach_artifact(job_id=job.id, manifest=manifest, expected_generation=1,
                                        idempotency_key="art-1", payload=payload,
                                        require_lock_digest=LOCK, require_platform="linux")
    assert not dup and record.artifact_digest == manifest["payload_digest"]
    assert [a.artifact_digest for a in store.attachments(job.id)] == [manifest["payload_digest"]]
    # tampered payload quarantines the job and records the mismatch
    job2 = drive_ready(store, make_job(store, key="prep-2"))
    manifest2, _ = make_manifest()
    with pytest.raises(ArtifactVerificationError):
        store.attach_artifact(job_id=job2.id, manifest=manifest2, expected_generation=1,
                              idempotency_key="art-2", payload=b"tampered")
    assert store.get_job(job2.id).state == "quarantined"


def test_artifact_schema_rejects_network_verification_and_bad_kind(tmp_path):
    bad, _ = make_manifest(verify_commands=["curl https://example.invalid/check"])
    with pytest.raises(ArtifactValidationError):
        validate_manifest(bad)
    bad_kind, _ = make_manifest(kind="npm-cache")
    with pytest.raises(ArtifactValidationError):
        validate_manifest(bad_kind)


def test_artifact_source_pin_mismatch_quarantines(tmp_path):
    store = JobStore(tmp_path / "f.sqlite")
    job = drive_ready(store, make_job(store))
    manifest, payload = make_manifest(source_commit="c" * 40)
    with pytest.raises(ArtifactVerificationError):
        store.attach_artifact(job_id=job.id, manifest=manifest, expected_generation=1,
                              idempotency_key="art-x", payload=payload)
    assert store.get_job(job.id).state == "quarantined"


def test_read_result_terminal_only_and_reports_artifacts(tmp_path):
    store = JobStore(tmp_path / "f.sqlite")
    job = drive_ready(store, make_job(store))
    with pytest.raises(JobNotReadyError):
        store.read_result(job_id=job.id)
    manifest, payload = make_manifest()
    store.attach_artifact(job_id=job.id, manifest=manifest, expected_generation=1,
                          idempotency_key="art-1", payload=payload)
    job, _ = store.execute(job_id=job.id, command_profile="offline-test", objective="synthetic",
                           authority_ref="synthetic-policy", expected_generation=1,
                           idempotency_key="exec-1", native_identity="native-1")
    store.record_result(job_id=job.id, outcome="succeeded", result={"exit": 0},
                        expected_generation=1, idempotency_key="res-1")
    result = store.read_result(job_id=job.id)
    assert result["state"] == "succeeded"
    assert result["artifact_digests"] == [manifest["payload_digest"]]
