"""Immutable artifact manifest validation and attachment records.

An attached artifact is an immutable directory archive or OCI image identified
by SHA-256 digest. The manifest carries everything a deployment adapter needs
to verify, pin, and mount the payload read-only without network access.

This module performs pure validation only: schema/kind allowlist, digest
formats, size, provenance fields, lifecycle-script policy, and a syntactic
no-network check over the offline verification commands. Actual payload
fetching, mounting, and execution stay in deployment adapters.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field

SCHEMA_VERSION = "foundry.artifact/v1"
ALLOWED_KINDS = frozenset({"dir-archive", "oci-image"})

_HEX_RE = re.compile(r"^[0-9a-f]+$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
# Full git SHA or SHA-256 digest for source commits.
_COMMIT_RE = re.compile(r"^[0-9a-f]{7,64}$")
# Tokens that imply the verification step needs network access.
_NETWORK_TOKENS = ("http://", "https://", "curl ", "curl\t", "wget ", "ssh ", "scp ", "ftp://")


class ArtifactValidationError(ValueError):
    """A manifest failed schema, digest, policy, or offline-verification checks."""


class ArtifactVerificationError(ValueError):
    """A manifest was well-formed but payload verification failed."""


@dataclass(frozen=True)
class ArtifactManifest:
    schema_version: str
    kind: str
    producer: str
    source_repo: str
    source_commit: str
    lock_digest: str
    platform: str
    arch: str
    toolchain: str
    payload_digest: str
    payload_bytes: int
    built_at: str
    retention: str
    lifecycle_policy: str
    provenance_ref: str
    verify_commands: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict:
        return {
            "schema_version": self.schema_version,
            "kind": self.kind,
            "producer": self.producer,
            "source_repo": self.source_repo,
            "source_commit": self.source_commit,
            "lock_digest": self.lock_digest,
            "platform": self.platform,
            "arch": self.arch,
            "toolchain": self.toolchain,
            "payload_digest": self.payload_digest,
            "payload_bytes": self.payload_bytes,
            "built_at": self.built_at,
            "retention": self.retention,
            "lifecycle_policy": self.lifecycle_policy,
            "provenance_ref": self.provenance_ref,
            "verify_commands": list(self.verify_commands),
        }


_REQUIRED_TEXT_FIELDS = (
    "producer",
    "source_repo",
    "platform",
    "arch",
    "toolchain",
    "built_at",
    "retention",
    "lifecycle_policy",
    "provenance_ref",
)


def validate_manifest(raw: dict) -> ArtifactManifest:
    """Validate a raw manifest mapping and return an immutable record."""
    if not isinstance(raw, dict):
        raise ArtifactValidationError("manifest must be a mapping")
    errors: list[str] = []
    if raw.get("schema_version") != SCHEMA_VERSION:
        errors.append(f"schema_version must be {SCHEMA_VERSION!r}")
    kind = raw.get("kind")
    if kind not in ALLOWED_KINDS:
        errors.append(f"kind must be one of {sorted(ALLOWED_KINDS)}")
    for name in _REQUIRED_TEXT_FIELDS:
        value = raw.get(name)
        if not isinstance(value, str) or not value.strip():
            errors.append(f"{name} must be a non-empty string")
    source_commit = raw.get("source_commit", "")
    if not isinstance(source_commit, str) or not _COMMIT_RE.match(source_commit):
        errors.append("source_commit must be hex of length 7..64")
    for name in ("lock_digest", "payload_digest"):
        value = raw.get(name, "")
        if not isinstance(value, str) or not _SHA256_RE.match(value):
            errors.append(f"{name} must be a 64-char lowercase hex sha256")
    payload_bytes = raw.get("payload_bytes")
    if not isinstance(payload_bytes, int) or isinstance(payload_bytes, bool) or payload_bytes <= 0:
        errors.append("payload_bytes must be a positive integer")
    commands = raw.get("verify_commands")
    if not isinstance(commands, list) or not commands or not all(isinstance(c, str) and c.strip() for c in commands):
        errors.append("verify_commands must be a non-empty list of command strings")
    else:
        for command in commands:
            lowered = command.lower()
            if any(token in lowered for token in _NETWORK_TOKENS):
                errors.append(f"verify_commands must not need network access: {command!r}")
                break
    if errors:
        raise ArtifactValidationError("; ".join(errors))
    return ArtifactManifest(
        schema_version=raw["schema_version"],
        kind=raw["kind"],
        producer=raw["producer"],
        source_repo=raw["source_repo"],
        source_commit=raw["source_commit"],
        lock_digest=raw["lock_digest"],
        platform=raw["platform"],
        arch=raw["arch"],
        toolchain=raw["toolchain"],
        payload_digest=raw["payload_digest"],
        payload_bytes=raw["payload_bytes"],
        built_at=raw["built_at"],
        retention=raw["retention"],
        lifecycle_policy=raw["lifecycle_policy"],
        provenance_ref=raw["provenance_ref"],
        verify_commands=tuple(raw["verify_commands"]),
    )


def verify_payload_bytes(manifest: ArtifactManifest, payload: bytes) -> None:
    """Check opaque payload bytes against the manifest digest and size."""
    if len(payload) != manifest.payload_bytes:
        raise ArtifactVerificationError(
            f"payload size {len(payload)} != manifest payload_bytes {manifest.payload_bytes}"
        )
    digest = hashlib.sha256(payload).hexdigest()
    if digest != manifest.payload_digest:
        raise ArtifactVerificationError("payload digest mismatch: possible tampering")


def check_matches_job(
    manifest: ArtifactManifest,
    *,
    source_commit: str,
    lock_digest: str | None = None,
    platform: str | None = None,
) -> None:
    """Enforce digest/platform pinning between a job request and a manifest."""
    mismatches: list[str] = []
    if manifest.source_commit != source_commit:
        mismatches.append("source_commit does not match the job request")
    if lock_digest is not None and manifest.lock_digest != lock_digest:
        mismatches.append("lock_digest does not match the job request")
    if platform is not None and manifest.platform != platform:
        mismatches.append("platform does not match the job request")
    if mismatches:
        raise ArtifactVerificationError("; ".join(mismatches))
