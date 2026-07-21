"""Offline Sigstore verification through the official GitHub CLI."""

from __future__ import annotations

import json
from pathlib import Path
import re
import subprocess
from tempfile import TemporaryDirectory
from typing import Any, Callable

from github_sigstore_json import parse_rfc3339, sha256_bytes


OIDC_ISSUER = "https://token.actions.githubusercontent.com"
PREDICATE_TYPE = "https://slsa.dev/provenance/v1"
HEX_64 = re.compile(r"^[0-9a-f]{64}$")
COMMIT_SHA = re.compile(r"^[0-9a-f]{40}$")


class BackendUnavailableError(RuntimeError):
    """Raised when the approved GitHub CLI backend is unavailable."""


class GithubCLIBackend:
    def __init__(
        self, *, repository: str, repository_id: int, workflow_identity: str,
        signer_commit: str, source_commit: str, source_binding_sha256: str,
        trusted_root_set_sha256: str, executable: str = "gh",
        runner: Callable[..., Any] = subprocess.run,
    ) -> None:
        if not repository or not workflow_identity or not executable:
            raise ValueError("backend identity strings must not be empty")
        if type(repository_id) is not int or repository_id <= 0:
            raise ValueError("repository_id must be a positive integer")
        for field, value in (
            ("signer_commit", signer_commit), ("source_commit", source_commit),
        ):
            if not isinstance(value, str) or not COMMIT_SHA.fullmatch(value):
                raise ValueError(f"{field} must be a full lowercase Git SHA")
        for field, value in (
            ("source_binding_sha256", source_binding_sha256),
            ("trusted_root_set_sha256", trusted_root_set_sha256),
        ):
            if not isinstance(value, str) or not HEX_64.fullmatch(value):
                raise ValueError(f"{field} must be 64 lowercase hex characters")
        self.repository = repository
        self.repository_id = repository_id
        self.workflow_identity = workflow_identity
        self.signer_commit = signer_commit
        self.source_commit = source_commit
        self.source_binding_sha256 = source_binding_sha256
        self.trusted_root_set_sha256 = trusted_root_set_sha256
        self.executable = executable
        self.runner = runner

    def _command(
        self, artifact_path: Path, bundle_path: Path, root_path: Path,
    ) -> list[str]:
        return [
            self.executable, "attestation", "verify", str(artifact_path),
            "--bundle", str(bundle_path),
            "--custom-trusted-root", str(root_path),
            "--repo", self.repository,
            "--signer-workflow", self.workflow_identity,
            "--signer-digest", self.signer_commit,
            "--source-digest", self.signer_commit,
            "--source-ref", "refs/heads/main",
            "--cert-oidc-issuer", OIDC_ISSUER,
            "--predicate-type", PREDICATE_TYPE,
            "--deny-self-hosted-runners",
            "--format", "json",
        ]

    @staticmethod
    def _parse_result(stdout: str, artifact_sha256: str) -> str:
        try:
            values = json.loads(stdout)
        except json.JSONDecodeError as exc:
            raise ValueError("gh verification stdout must be valid JSON") from exc
        if not isinstance(values, list):
            raise ValueError("gh verification JSON root must be an array")
        if len(values) != 1:
            raise ValueError("gh verification must return exactly one attestation")
        value = values[0]
        if not isinstance(value, dict) or not isinstance(value.get("attestation"), dict):
            raise ValueError("gh verification result must contain an attestation")
        result = value.get("verificationResult")
        if not isinstance(result, dict):
            raise ValueError("gh verificationResult must be an object")
        signature = result.get("signature")
        certificate = signature.get("certificate") if isinstance(signature, dict) else None
        if not isinstance(certificate, dict) or not certificate:
            raise ValueError("verified certificate is missing")
        statement = result.get("statement")
        if not isinstance(statement, dict) or statement.get("predicateType") != PREDICATE_TYPE:
            raise ValueError("verified predicate type mismatch")
        subjects = statement.get("subject")
        digest = None
        if isinstance(subjects, list) and len(subjects) == 1:
            subject = subjects[0]
            if isinstance(subject, dict) and isinstance(subject.get("digest"), dict):
                digest = subject["digest"].get("sha256")
        if digest != artifact_sha256:
            raise ValueError("verified artifact digest mismatch")
        timestamps = result.get("verifiedTimestamps")
        if not isinstance(timestamps, list) or not timestamps:
            raise ValueError("verified result has no trusted timestamp")
        parsed = []
        for timestamp in timestamps:
            if not isinstance(timestamp, dict) or timestamp.get("type") not in {
                "Tlog", "TimestampAuthority",
            }:
                raise ValueError("unsupported trusted timestamp type")
            parsed.append(parse_rfc3339(timestamp.get("timestamp"), "timestamp"))
        return max(parsed).isoformat()

    def verify(
        self, *, predicate_bytes: bytes, bundle_bytes: bytes,
        trusted_root_bytes: bytes,
    ) -> dict[str, Any]:
        for label, value in (
            ("predicate", predicate_bytes), ("bundle", bundle_bytes),
            ("trusted root", trusted_root_bytes),
        ):
            if not isinstance(value, bytes) or not value:
                raise ValueError(f"{label} bytes must not be empty")
        root_digest = sha256_bytes(trusted_root_bytes)
        if root_digest != self.trusted_root_set_sha256:
            raise ValueError("trusted_root_set_sha256 mismatch")
        artifact_digest = sha256_bytes(predicate_bytes)
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifact_path = root / "predicate.json"
            bundle_path = root / "bundle.jsonl"
            trusted_root_path = root / "trusted_root.jsonl"
            artifact_path.write_bytes(predicate_bytes)
            bundle_path.write_bytes(bundle_bytes)
            trusted_root_path.write_bytes(trusted_root_bytes)
            try:
                completed = self.runner(
                    self._command(artifact_path, bundle_path, trusted_root_path),
                    capture_output=True, text=True, timeout=60, check=False,
                    shell=False,
                )
            except FileNotFoundError as exc:
                raise BackendUnavailableError("GitHub CLI executable is unavailable") from exc
            except (subprocess.TimeoutExpired, TimeoutError) as exc:
                raise ValueError("gh attestation verify timed out") from exc
        if completed.returncode != 0:
            raise ValueError("gh attestation verify failed")
        if completed.stderr:
            raise ValueError("gh attestation verify wrote to stderr")
        verified_at = self._parse_result(completed.stdout, artifact_digest)
        return {
            "artifact_sha256": artifact_digest,
            "repository": self.repository,
            "repository_id": self.repository_id,
            "workflow_identity": self.workflow_identity,
            "signer_commit": self.signer_commit,
            "source_commit": self.source_commit,
            "source_binding_sha256": self.source_binding_sha256,
            "oidc_issuer": OIDC_ISSUER,
            "runner_environment": "github-hosted",
            "sigstore_instance": "public-good",
            "verified_at": verified_at,
            "trusted_root_set_sha256": root_digest,
        }
