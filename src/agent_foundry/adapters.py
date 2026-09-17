"""Deployment-adapter interfaces for the v3 execution substrate.

Agent Foundry is a library: it owns durable job/attempt/event/artifact state
and the state-machine rules. It never touches the OS sandbox, host
filesystem, host interop, or network itself. Deployments implement these
small interfaces and inject them where the contracts require evidence:

- :class:`ExecutionAdapter` launches and cancels native units of work and
  reports liveness. Foundry stores the native identity *before* reporting a
  job as running, and reconciles native liveness after a restart before
  changing state.
- :class:`ArtifactVerifier` checks an immutable payload against its manifest
  and mounts it read-only for the job. Foundry only records the validated
  manifest and the verification outcome.

There is intentionally no shell, transport, credential, model-routing, or UI
surface here.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Callable

from .artifacts import ArtifactManifest

# Callable returning True while a native unit is still alive.
NativeLiveness = Callable[[str], bool]


class ExecutionAdapter(ABC):
    """Deployment-owned sandbox/process control. Implemented outside Foundry."""

    @abstractmethod
    def launch(self, *, job_id: str, attempt_id: str, command_profile: str) -> str:
        """Start the isolated unit and return its native identity."""

    @abstractmethod
    def is_alive(self, native_identity: str) -> bool:
        """Return True while the native unit is still alive."""

    @abstractmethod
    def cancel(self, native_identity: str) -> bool:
        """Request native termination. Return True when it is dead/absent."""


class ArtifactVerifier(ABC):
    """Deployment-owned immutable payload verification and read-only mount."""

    @abstractmethod
    def verify(self, manifest: ArtifactManifest) -> bool:
        """Return True only when the stored payload matches the manifest."""

    @abstractmethod
    def mount_readonly(self, *, job_id: str, manifest: ArtifactManifest) -> str:
        """Expose the payload read-only to the job; return the mount point."""
