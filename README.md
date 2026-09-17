# Agent Foundry Core

A small public core for one hard part of agent orchestration: durable,
idempotent execution records with honest recovery. It implements the public
minimal isolated-execution contract of Agent Foundry v3 (issue #1).

It is intentionally not an agent framework. It has no model provider, account
routing, agent planning, shell execution, remote transport, credential
handling, dependency fetching, package-manager caches, web server, or UI.
Those belong in deployment-specific adapters outside this repository.

## Contract

### Attempt ledger (compatible core)

- A caller supplies an idempotency key and canonical request payload.
- The first claim creates one durable attempt.
- A repeat with the same key and identical payload returns that same attempt.
- Reusing a key with different content is rejected.
- Only one active attempt is allowed per workspace.
- A restart never silently re-runs a non-terminal attempt. Recovery marks it
  `interrupted`, so an operator or higher-level policy must make the next
  decision explicitly.

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

### v3 job state machine (`JobStore`)

`prepare_job` / `attach_artifact` / `execute` / `status` / `cancel` /
`read_result` / `quarantine_job`, plus `mark_preparing`, `mark_ready`,
`record_result`, `fail_job`, `confirm_cancelled`, `mark_unknown_outcome`,
`retry_job`, and `recover`. Read helpers `status`, `get_job`, and
`attachments` never mutate state.

Durable machine:

```text
accepted -> preparing -> ready -> running -> succeeded
                      \          \-> failed
                       \-> failed  \-> cancel_requested -> cancelled
                                      \-> interrupted
                                      \-> unknown_outcome

ready -> unknown_outcome (launch reserved but unconfirmed at restart)
any non-terminal state -> quarantined
```

Rules enforced by the store:

- Every transition records attempt id, generation, timestamp, actor, source
  digest, attached artifact digests, policy hash, and a monotonic event
  cursor. `status(job_id, after_cursor=...)` replays events after a cursor.
- Every mutating call takes an `idempotency_key` and an `expected_generation`
  fencing token. Replays with the same key and payload return the stored
  acknowledgement; key reuse with different content is rejected; a stale
  generation is rejected with `StaleGenerationError`.
- `execute` uses a two-phase launch protocol for deployment launchers: it
  commits a durable launch reservation carrying an idempotent launch token,
  invokes the launcher *outside* the database transaction with that token,
  then commits the native identity with the `ready -> running` transition.
  Adapters MUST be idempotent on the token, so a crash between reservation
  and confirmation can never duplicate side effects; `recover` reconciles a
  still-reserved job to `unknown_outcome`. With `native_identity=` the
  transition commits atomically. Foundry never launches anything itself.
- `prepare_job` persists a job-bound artifact policy (`source_repo`,
  `lock_digest`, `platform`, `arch`, `toolchain`, `lifecycle_policy`,
  optional `provenance_ref`) bound to `policy_hash`. `attach_artifact`
  enforces it as declared plus the job source digest; callers cannot omit
  or contradict required constraints.
- `attach_artifact` requires payload bytes AND a deployment `ArtifactVerifier`
  (byte check, `verify`, and read-only `mount_readonly`); unverified or
  unmounted attachments are never recorded. Attachments freeze at `execute`:
  `running`, `cancel_requested`, and terminal states reject attachment, and
  execution/result evidence binds the frozen digest set. A stale attach from
  an older generation rejects with `StaleGenerationError` without mutating or
  quarantining the current generation; `retry_job` starts the new generation
  with no attachments. Failed calls store a durable failure under the
  idempotency key, so replays raise the same error.
- `cancel` moves a live job to `cancel_requested`; `confirm_cancelled`
  requires adapter evidence (`native_dead=True`) that the native unit is
  dead. Ambiguous outcomes become `unknown_outcome` via `mark_unknown_outcome`
  and are never replayed automatically.
- `recover` reconciles native liveness after a restart: jobs that never
  recorded an identity certainly never started (`interrupted`); jobs with an
  identity stay `running` only when a caller-supplied liveness probe confirms
  them alive, otherwise they become `unknown_outcome`.
- Terminal states are immutable. `retry_job` from `failed`, `interrupted`,
  `unknown_outcome`, or `cancelled` opens a new generation linked to the
  prior attempt id. `succeeded` and `quarantined` are final.
- `quarantine_job` is legal from any non-terminal state and records the reason.

### Artifact contract (`artifacts`)

An attached artifact is an immutable directory archive (`dir-archive`) or OCI
image (`oci-image`) identified by SHA-256 digest. `validate_manifest`
enforces the `foundry.artifact/v1` schema: allowlisted kind, producer,
source repo/commit, lockfile digest, platform/arch/toolchain, payload digest
and byte size, build timestamp, retention class, lifecycle-script policy
(`no-scripts` / `offline-only` / `hermetic` / `managed-postinstall`),
provenance reference, and verification steps expressed as named profiles
(`sha256-check`, `digest-check`, `signature-check`, `provenance-check`,
`reproducibility-check`) or structured argv governed by the deployment
adapter allowlist (offline binaries only; shell metacharacters and network
tokens rejected per-token, never executed here). `attach_artifact` additionally pins the manifest's
source commit (plus optional lock digest and platform) to the job, checks
payload bytes when provided, and may consult a deployment `ArtifactVerifier`.
Any validation, pinning, or verification failure quarantines the job and
records the mismatch. Attachments are immutable records; jobs cannot alter or
promote shared artifacts.

### Deployment adapters (`adapters`)

`ExecutionAdapter` (`launch` / `is_alive` / `cancel`) and `ArtifactVerifier`
(`verify` / `mount_readonly`) are abstract interfaces implemented outside this
package. Actual OS sandboxing, mounting, and execution live there — never a
privileged shell in this library.

## Run checks

```text
python -m pytest
```

## Security boundary

This package does not execute commands. A host integration must validate its
own workspace boundary, identity, environment, command policy, cancellation,
logs, and artifacts. Do not treat idempotency as authorization.

The repository contains synthetic data only. Keep deployment paths,
credentials, project catalogs, local evidence, and provider configuration in
a private overlay.
