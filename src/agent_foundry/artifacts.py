"""Immutable artifact manifest validation and attachment records.

An attached artifact is an immutable directory archive or OCI image identified
by SHA-256 digest. The manifest carries everything a deployment adapter needs
to verify, pin, and mount the payload read-only without network access.

This module performs pure validation only: schema/kind allowlist, digest
formats, size, provenance fields, lifecycle-script policy, and verification
steps expressed either as named verification profiles or as structured argv
governed by the deployment adapter (see :mod:`agent_foundry.adapters`).
Actual payload fetching, mounting, and execution stay in deployment adapters.

There is intentionally no shell, transport, credential, or network surface
here: verification commands are never executed by this library.
"""

from __future__ import annotations

import hashlib
import re
import shlex
from dataclasses import dataclass, field

SCHEMA_VERSION = "foundry.artifact/v1"
ALLOWED_KINDS = frozenset({"dir-archive", "oci-image"})

# Named verification profiles. A manifest may reference these instead of
# spelling out argv; the deployment adapter decides what each profile runs.
VERIFICATION_PROFILES = frozenset({
    "sha256-check",
    "digest-check",
    "signature-check",
    "provenance-check",
    "reproducibility-check",
})

# Structured-argv allowlist: argv[0] (basename) of an offline verification
# command. The deployment adapter governs this set; adapters may narrow it by
# overriding ``ArtifactVerifier.allowed_verifier_binaries``. Anything capable
# of egress or shell execution is absent by construction.
ALLOWED_VERIFIER_BINARIES = frozenset({
    "sha256sum",
    "shasum",
    "sha256",
    "cosign",
    "openssl",
    "tar",
    "digest",
})

# Lifecycle-script policy allowlist. Payloads must declare how much script
# execution they require; the job-bound policy pins the maximum tolerated.
LIFECYCLE_POLICIES = frozenset({
    "no-scripts",
    "offline-only",
    "hermetic",
    "managed-postinstall",
})

_HEX_RE = re.compile(r"^[0-9a-f]+$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
# Full git SHA or SHA-256 digest for source commits.
_COMMIT_RE = re.compile(r"^[0-9a-f]{7,64}$")
# Shell metacharacters: a verification step must be a single argv, never a
# shell pipeline. Any of these in a string-form command rejects it.
_SHELL_METACHARS = (";", "|", "&", "$", "`", "\n", "\r", "<", ">", "(", ")",
                    "{", "}", "*", "?", "~", "!")
# Discrete argv tokens/flags that imply network access or remote execution.
# Checked per-token after shlex parsing (not substring matching), plus a
# scheme-prefix check on the token value.
_NETWORK_TOKENS = frozenset({
    "curl", "wget", "ssh", "scp", "ftp", "sftp", "rsync", "git", "npm",
    "pip", "docker", "podman",
})
_NETWORK_SCHEMES = ("http://", "https://", "ftp://", "sftp://", "ssh://")
_NETWORK_FLAGS = ("--url", "--upload-file", "--remote")


class ArtifactValidationError(ValueError):
    """A manifest failed schema, digest, policy, or verification-step checks."""


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
    verify_commands: tuple = field(default_factory=tuple)

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
            "verify_commands": [list(c) if isinstance(c, tuple) else c
                                for c in self.verify_commands],
        }


_REQUIRED_TEXT_FIELDS = (
    "producer",
    "source_repo",
    "platform",
    "arch",
    "toolchain",
    "built_at",
    "retention",
    "provenance_ref",
)

# Constraints a job-bound artifact policy may declare. ``source_commit`` is
# always pinned to the job's source digest rather than the policy document.
POLICY_FIELDS = (
    "source_repo",
    "lock_digest",
    "platform",
    "arch",
    "toolchain",
    "lifecycle_policy",
    "provenance_ref",
)


def _validate_verify_step(step: object, *, allowed_binaries: frozenset[str],
                          allowed_profiles: frozenset[str]) -> list[str] | None:
    """Validate one verification step.

    Returns the normalized structured argv (a list of tokens), or ``None``
    when the step is a named profile. Raises :class:`ArtifactValidationError`
    on any violation.
    """
    if isinstance(step, str):
        text = step.strip()
        if not text:
            raise ArtifactValidationError("verify_commands entries must be non-empty")
        # A bare token matching a named profile is a profile reference.
        if re.fullmatch(r"[a-z0-9][a-z0-9_-]*", text) and text in allowed_profiles:
            return None
        if any(meta in text for meta in _SHELL_METACHARS):
            raise ArtifactValidationError(
                f"verify_commands must be a single argv without shell metacharacters: {step!r}")
        try:
            argv = shlex.split(text, posix=True)
        except ValueError as error:
            raise ArtifactValidationError(f"verify_commands entry does not parse: {error}") from error
        if not argv:
            raise ArtifactValidationError("verify_commands entries must be non-empty")
        step = argv
    if isinstance(step, (list, tuple)):
        argv = list(step)
        if not argv or not all(isinstance(t, str) and t.strip() for t in argv):
            raise ArtifactValidationError(
                "verify_commands argv entries must be non-empty token lists")
        if any(any(meta in token for meta in (";", "|", "&", "$", "`", "\n", "\r"))
               for token in argv):
            raise ArtifactValidationError(
                f"verify_commands argv must not contain shell metacharacters: {argv!r}")
        binary = argv[0].rsplit("/", 1)[-1]
        if binary not in allowed_binaries:
            raise ArtifactValidationError(
                f"verify_commands binary {binary!r} is not governed by the adapter allowlist")
        lowered = [token.lower() for token in argv]
        if lowered[0] in _NETWORK_TOKENS:
            raise ArtifactValidationError(
                f"verify_commands must not need network access: {argv!r}")
        for token in lowered[1:]:
            first = token.split("=", 1)[0]
            if (token in _NETWORK_TOKENS or first in _NETWORK_FLAGS
                    or token.startswith(_NETWORK_SCHEMES)):
                raise ArtifactValidationError(
                    f"verify_commands must not need network access: {argv!r}")
        return argv
    raise ArtifactValidationError(
        "verify_commands entries must be named profiles or argv token lists")


def validate_verify_commands(commands: object, *, allowed_binaries: frozenset[str] | None = None,
                             allowed_profiles: frozenset[str] | None = None) -> tuple:
    """Validate verification steps and return normalized argv/profile tuples."""
    binaries = allowed_binaries or ALLOWED_VERIFIER_BINARIES
    profiles = allowed_profiles or VERIFICATION_PROFILES
    if not isinstance(commands, list) or not commands:
        raise ArtifactValidationError("verify_commands must be a non-empty list")
    normalized: list = []
    for step in commands:
        argv = _validate_verify_step(step, allowed_binaries=binaries, allowed_profiles=profiles)
        normalized.append(tuple(argv) if argv is not None else step.strip())
    return tuple(normalized)


def validate_manifest(raw: dict, *, allowed_binaries: frozenset[str] | None = None,
                      allowed_profiles: frozenset[str] | None = None) -> ArtifactManifest:
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
    lifecycle = raw.get("lifecycle_policy", "")
    if isinstance(lifecycle, str) and lifecycle.strip() and lifecycle not in LIFECYCLE_POLICIES:
        errors.append(f"lifecycle_policy must be one of {sorted(LIFECYCLE_POLICIES)}")
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
    normalized_commands: tuple = ()
    try:
        normalized_commands = validate_verify_commands(
            raw.get("verify_commands"), allowed_binaries=allowed_binaries,
            allowed_profiles=allowed_profiles)
    except ArtifactValidationError as error:
        errors.append(str(error))
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
        verify_commands=normalized_commands,
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


def validate_artifact_policy(policy: dict) -> dict:
    """Validate a job-bound artifact policy document.

    Required keys: ``source_repo``, ``lock_digest``, ``platform``, ``arch``,
    ``toolchain``, ``lifecycle_policy``. ``provenance_ref`` is optional but,
    when declared, is enforced. Returns a normalized copy.
    """
    if not isinstance(policy, dict):
        raise ValueError("artifact_policy must be a mapping")
    errors: list[str] = []
    normalized: dict = {}
    for name in ("source_repo", "platform", "arch", "toolchain", "provenance_ref"):
        if name == "provenance_ref" and "provenance_ref" not in policy:
            continue
        value = policy.get(name)
        if not isinstance(value, str) or not value.strip():
            errors.append(f"artifact_policy[{name}] must be a non-empty string")
        else:
            normalized[name] = value
    lock = policy.get("lock_digest", "")
    if not isinstance(lock, str) or not _SHA256_RE.match(lock):
        errors.append("artifact_policy[lock_digest] must be a 64-char lowercase hex sha256")
    else:
        normalized["lock_digest"] = lock
    lifecycle = policy.get("lifecycle_policy", "")
    if lifecycle not in LIFECYCLE_POLICIES:
        errors.append(f"artifact_policy[lifecycle_policy] must be one of {sorted(LIFECYCLE_POLICIES)}")
    else:
        normalized["lifecycle_policy"] = lifecycle
    unknown = sorted(k for k in policy if k not in set(POLICY_FIELDS))
    if unknown:
        errors.append(f"artifact_policy has unknown fields: {unknown}")
    if errors:
        raise ValueError("; ".join(errors))
    return normalized


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


def check_matches_policy(
    manifest: ArtifactManifest,
    *,
    source_commit: str,
    policy: dict,
    caller_constraints: dict | None = None,
) -> None:
    """Enforce a job-bound artifact policy against a manifest.

    Every field declared in ``policy`` must equal the manifest value, and
    ``manifest.source_commit`` must equal the job's source digest. Caller
    constraints may narrow but never widen or contradict the stored policy:
    any caller value disagreeing with the stored policy is rejected, and any
    required field missing from both is rejected as omittable.
    """
    mismatches: list[str] = []
    if manifest.source_commit != source_commit:
        mismatches.append("source_commit does not match the job request")
    manifest_values = {
        "source_repo": manifest.source_repo,
        "lock_digest": manifest.lock_digest,
        "platform": manifest.platform,
        "arch": manifest.arch,
        "toolchain": manifest.toolchain,
        "lifecycle_policy": manifest.lifecycle_policy,
        "provenance_ref": manifest.provenance_ref,
    }
    caller_constraints = caller_constraints or {}
    for name in POLICY_FIELDS:
        declared = policy.get(name)
        caller_value = caller_constraints.get(name)
        actual = manifest_values[name]
        if declared is not None:
            if actual != declared:
                mismatches.append(f"{name} does not match the job artifact policy")
            if caller_value is not None and caller_value != declared:
                mismatches.append(f"caller constraint {name} contradicts the job artifact policy")
        elif caller_value is not None:
            if actual != caller_value:
                mismatches.append(f"{name} does not match the caller constraint")
        elif name != "provenance_ref":
            mismatches.append(f"no constraint declared for required field {name}")
    if mismatches:
        raise ArtifactVerificationError("; ".join(mismatches))
