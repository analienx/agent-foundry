# Agent Foundry Core

A small public core for one hard part of agent orchestration: recording work attempts durably, making retries idempotent, and recovering honestly after a process restart.

It is intentionally not an agent framework. It has no model provider, shell execution, remote transport, credential handling, web server, or UI. Those belong in deployment-specific adapters outside this repository.

## Contract

- A caller supplies an idempotency key and canonical request payload.
- The first claim creates one durable attempt.
- A repeat with the same key and identical payload returns that same attempt.
- Reusing a key with different content is rejected.
- Only one active attempt is allowed per workspace.
- A restart never silently re-runs a non-terminal attempt. Recovery marks it `interrupted`, so an operator or higher-level policy must make the next decision explicitly.

## Example

```python
from agent_foundry import AttemptStore

store = AttemptStore("attempts.sqlite3")
attempt, duplicate = store.claim(
    workspace_id="demo",
    idempotency_key="request-2026-09-15-001",
    request={"argv": ["python", "-c", "print('hello')"]},
)
assert duplicate is False
store.transition(attempt.id, "running")
store.transition(attempt.id, "succeeded", exit_code=0)
```

## Run checks

```text
python -m pytest
```

## Security boundary

This package does not execute commands. A host integration must validate its own workspace boundary, identity, environment, command policy, cancellation, logs, and artifacts. Do not treat idempotency as authorization.

The repository contains synthetic data only. Keep deployment paths, credentials, project catalogs, local evidence, and provider configuration in a private overlay.
