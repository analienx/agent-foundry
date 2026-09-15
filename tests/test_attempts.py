import pytest

from agent_foundry import ActiveAttemptError, AttemptConflict, AttemptStore


def test_same_key_replays_same_durable_attempt(tmp_path):
    store = AttemptStore(tmp_path / "attempts.sqlite")
    first, duplicate = store.claim(workspace_id="demo", idempotency_key="a", request={"argv": ["echo", "ok"]})
    replay, duplicate_replay = store.claim(workspace_id="demo", idempotency_key="a", request={"argv": ["echo", "ok"]})
    assert not duplicate
    assert duplicate_replay
    assert replay.id == first.id


def test_reusing_key_for_changed_request_is_rejected(tmp_path):
    store = AttemptStore(tmp_path / "attempts.sqlite")
    store.claim(workspace_id="demo", idempotency_key="a", request={"argv": ["echo", "one"]})
    with pytest.raises(AttemptConflict):
        store.claim(workspace_id="demo", idempotency_key="a", request={"argv": ["echo", "two"]})


def test_workspace_cannot_run_two_attempts(tmp_path):
    store = AttemptStore(tmp_path / "attempts.sqlite")
    store.claim(workspace_id="demo", idempotency_key="a", request={})
    with pytest.raises(ActiveAttemptError):
        store.claim(workspace_id="demo", idempotency_key="b", request={})


def test_recovery_marks_inflight_attempt_interrupted_without_retry(tmp_path):
    store = AttemptStore(tmp_path / "attempts.sqlite")
    attempt, _ = store.claim(workspace_id="demo", idempotency_key="a", request={})
    store.transition(attempt.id, "running")
    recovered = store.recover_interrupted()
    assert [(item.id, item.status) for item in recovered] == [(attempt.id, "interrupted")]
    with pytest.raises(ValueError):
        store.transition(attempt.id, "succeeded", exit_code=0)
