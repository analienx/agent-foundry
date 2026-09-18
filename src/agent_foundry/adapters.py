"""Deployment-adapter interfaces for the v3 execution substrate.

Agent Foundry is a library: it owns durable job/attempt/event/artifact state
and the state-machine rules. It never touches the OS sandbox, host
filesystem, host interop, or network itself. Deployments implement these
small interfaces and inject them where the contracts require evidence:

- :class:`ExecutionAdapter` launches and cancels native units of work and
  reports liveness. Foundry reserves a durable launch token *before* the
  adapter is invoked and reports the job as running only after the native
  identity is committed. Adapter launches MUST be idempotent on the launch
  token: invoking ``launch`` twice with the same token must return the same
  native identity without duplicating side effects, so a crash between
  reservation and commit can never duplicate work.
- :class:`ArtifactVerifier` checks an immutable payload against its manifest
  and mounts it read-only for the job. Foundry only records the validated
  manifest, the verification outcome, and the mount point. The adapter
  governs which verification steps may run via ``allowed_verifier_binaries``
  and ``allowed_verification_profiles``.

There is intentionally no shell, transport, credential, model-routing, or UI
surface here.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Callable

from .artifacts import (
    ALLOWED_VERIFIER_BINARIES,
    VERIFICATION_PROFILES,
    ArtifactManifest,
)

# Callable returning True while a native unit is still alive.
NativeLiveness = Callable[[str], bool]


class ExecutionAdapter(ABC):
    """Deployment-owned sandbox/process control. Implemented outside Foundry."""

    @abstractmethod
    def launch(self, *, job_id: str, attempt_id: str, command_profile: str,
               launch_token: str | None = None) -> str:
        """Start the isolated unit and return its native identity.

        ``launch_token`` is a durable idempotency token committed by Foundry
        *before* this method is invoked. Implementations MUST treat it as an
        idempotency key: a repeat call carrying a previously seen token must
        return the originally created native identity without starting a
        second unit. ``None`` is passed only by legacy callers; new callers
        always supply a token.
        """

    @abstractmethod
    def is_alive(self, native_identity: str) -> bool:
        """Return True while the native unit is still alive."""

    @abstractmethod
    def cancel(self, native_identity: str) -> bool:
        """Request native termination. Return True when it is dead/absent."""


class ArtifactVerifier(ABC):
    """Deployment-owned immutable payload verification and read-only mount."""

    #: Structured-argv allowlist this deployment honors. Defaults to the
    #: library allowlist; deployments MUST only narrow it, never widen it
    #: with network- or shell-capable binaries.
    allowed_verifier_binaries: frozenset[str] = ALLOWED_VERIFIER_BINARIES
    #: Named verification profiles this deployment implements.
    allowed_verification_profiles: frozenset[str] = VERIFICATION_PROFILES

    @abstractmethod
    def verify(self, manifest: ArtifactManifest) -> bool:
        """Return True only when the stored payload matches the manifest."""

    @abstractmethod
    def mount_readonly(self, *, job_id: str, manifest: ArtifactManifest) -> str:
        """Expose the payload read-only to the job; return the mount point.

        Must return a non-empty mount-point string on success and raise on
        failure. Foundry records an attachment only after this returns.
        """
