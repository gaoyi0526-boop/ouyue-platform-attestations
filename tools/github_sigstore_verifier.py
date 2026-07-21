"""Offline platform-attestation verification and durable replay state."""

from __future__ import annotations

from contextlib import closing
from datetime import datetime
from pathlib import Path
import sqlite3
from typing import Any

from github_sigstore_backend import BackendUnavailableError
from github_sigstore_provider import (
    canonical_json_bytes,
    load_json,
    parse_rfc3339,
    sha256_bytes,
    sha256_file,
    validate_pre_sign,
)


OIDC_ISSUER = "https://token.actions.githubusercontent.com"
STATE_SCHEMA_VERSION = 1
BACKEND_RECEIPT_FIELDS = (
    "artifact_sha256", "repository", "repository_id", "workflow_identity",
    "signer_commit", "source_commit", "source_binding_sha256", "oidc_issuer",
    "runner_environment", "sigstore_instance", "verified_at",
    "trusted_root_set_sha256",
)
VERIFIED_ATTESTATION_COLUMNS = (
    "replay_key", "predicate_raw_sha256", "freeze_record_raw_sha256",
    "repository_id", "trusted_root_epoch", "trusted_root_set_sha256",
    "verified_at", "verification_receipt_jcs_sha256",
)
STATE_CLAIM_FIELDS = VERIFIED_ATTESTATION_COLUMNS


class ReplayStateError(ValueError):
    """Raised when durable replay or trusted-root state rejects a claim."""


class BundleVerificationBackend:
    """Fail-closed placeholder for the separately approved crypto adapter."""

    def verify(
        self, *, predicate_bytes: bytes, bundle_bytes: bytes,
        trusted_root_bytes: bytes,
    ) -> dict[str, Any]:
        raise BackendUnavailableError(
            "approved offline bundle verification backend is unavailable"
        )


def _require_regular_nonempty(path: Path, label: str) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{label} must be a regular non-symlink file")
    value = path.read_bytes()
    if not value:
        raise ValueError(f"{label} must not be empty")
    return value


def _require_exact_fields(
    value: dict[str, Any], fields: tuple[str, ...], label: str,
) -> None:
    actual = set(value)
    expected = set(fields)
    if len(value) != len(fields) or actual != expected:
        raise ValueError(
            f"{label} fields mismatch: missing={sorted(expected - actual)}, "
            f"extra={sorted(actual - expected)}"
        )


def initialize_state_db(state_db_path: Path) -> None:
    if not state_db_path.is_absolute():
        raise ReplayStateError("state database path must be absolute")
    if state_db_path.is_symlink() or (
        state_db_path.exists() and not state_db_path.is_file()
    ):
        raise ReplayStateError("state database must be a regular non-symlink file")
    state_db_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with closing(sqlite3.connect(state_db_path)) as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute(
                """CREATE TABLE IF NOT EXISTS state_metadata (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    schema_version INTEGER NOT NULL,
                    trusted_root_epoch INTEGER,
                    trusted_root_set_sha256 TEXT
                )"""
            )
            connection.execute(
                """CREATE TABLE IF NOT EXISTS verified_attestations (
                    replay_key TEXT PRIMARY KEY,
                    predicate_raw_sha256 TEXT NOT NULL,
                    freeze_record_raw_sha256 TEXT NOT NULL,
                    repository_id INTEGER NOT NULL,
                    trusted_root_epoch INTEGER NOT NULL,
                    trusted_root_set_sha256 TEXT NOT NULL,
                    verified_at TEXT NOT NULL,
                    verification_receipt_jcs_sha256 TEXT NOT NULL
                )"""
            )
            connection.execute(
                "INSERT OR IGNORE INTO state_metadata "
                "(singleton, schema_version) VALUES (1, ?)",
                (STATE_SCHEMA_VERSION,),
            )
            row = connection.execute(
                "SELECT schema_version FROM state_metadata WHERE singleton = 1"
            ).fetchone()
            if row != (STATE_SCHEMA_VERSION,):
                raise ReplayStateError("unsupported state schema version")
            connection.commit()
    except sqlite3.Error as exc:
        raise ReplayStateError(f"state database initialization failed: {exc}") from exc


def claim_verified_attestation(
    state_db_path: Path, claim: dict[str, Any],
) -> None:
    _require_exact_fields(claim, STATE_CLAIM_FIELDS, "state claim")
    if type(claim["repository_id"]) is not int or claim["repository_id"] <= 0:
        raise ReplayStateError("repository_id must be a positive integer")
    epoch = claim["trusted_root_epoch"]
    if type(epoch) is not int:
        raise ReplayStateError("trusted_root_epoch must be an integer")
    for field in (
        "replay_key", "predicate_raw_sha256", "freeze_record_raw_sha256",
        "trusted_root_set_sha256", "verification_receipt_jcs_sha256",
    ):
        value = claim[field]
        if not isinstance(value, str) or len(value) != 64 or any(
            character not in "0123456789abcdef" for character in value
        ):
            raise ReplayStateError(f"{field} must be 64 lowercase hex characters")
    initialize_state_db(state_db_path)
    connection = sqlite3.connect(state_db_path, isolation_level=None)
    try:
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("BEGIN IMMEDIATE")
        if connection.execute(
            "SELECT 1 FROM verified_attestations WHERE replay_key = ?",
            (claim["replay_key"],),
        ).fetchone():
            raise ReplayStateError("attestation replay detected")
        current_epoch, current_digest = connection.execute(
            "SELECT trusted_root_epoch, trusted_root_set_sha256 "
            "FROM state_metadata WHERE singleton = 1"
        ).fetchone()
        if current_epoch is not None and epoch < current_epoch:
            raise ReplayStateError("trusted root epoch rollback detected")
        if current_epoch == epoch and current_digest != claim["trusted_root_set_sha256"]:
            raise ReplayStateError("trusted root epoch equivocation detected")
        if current_epoch is None or epoch > current_epoch:
            connection.execute(
                "UPDATE state_metadata SET trusted_root_epoch = ?, "
                "trusted_root_set_sha256 = ? WHERE singleton = 1",
                (epoch, claim["trusted_root_set_sha256"]),
            )
        placeholders = ", ".join("?" for _ in VERIFIED_ATTESTATION_COLUMNS)
        connection.execute(
            f"INSERT INTO verified_attestations "
            f"({', '.join(VERIFIED_ATTESTATION_COLUMNS)}) VALUES ({placeholders})",
            tuple(claim[field] for field in VERIFIED_ATTESTATION_COLUMNS),
        )
        connection.execute("COMMIT")
    except ReplayStateError:
        if connection.in_transaction:
            connection.execute("ROLLBACK")
        raise
    except sqlite3.Error as exc:
        if connection.in_transaction:
            connection.execute("ROLLBACK")
        raise ReplayStateError(f"state claim failed: {exc}") from exc
    finally:
        connection.close()


def _validate_backend_receipt(
    receipt: Any, *, predicate: dict[str, Any], freeze: dict[str, Any],
    predicate_raw_sha256: str, repository: str, repository_id: int,
    signer_commit: str, workflow_identity: str,
) -> datetime:
    if not isinstance(receipt, dict):
        raise ValueError("backend receipt must be an object")
    _require_exact_fields(receipt, BACKEND_RECEIPT_FIELDS, "backend receipt")
    expected = {
        "artifact_sha256": predicate_raw_sha256,
        "repository": repository,
        "repository_id": repository_id,
        "workflow_identity": workflow_identity,
        "signer_commit": signer_commit,
        "source_commit": freeze["source_commit"],
        "source_binding_sha256": predicate["source_binding_sha256"],
        "oidc_issuer": OIDC_ISSUER,
        "runner_environment": "github-hosted",
        "sigstore_instance": "public-good",
        "trusted_root_set_sha256": freeze["trusted_root_set_sha256"],
    }
    for field, expected_value in expected.items():
        if receipt[field] != expected_value:
            raise ValueError(f"{field} mismatch in backend receipt")
    return parse_rfc3339(receipt["verified_at"], "verified_at")


def claim_from_receipt(receipt: dict[str, Any]) -> dict[str, Any]:
    return {field: receipt[field] for field in STATE_CLAIM_FIELDS}


def verify_offline(
    *, repo_root: Path, predicate_path: Path, freeze_record_path: Path,
    bundle_path: Path, trusted_root_path: Path, state_db_path: Path,
    repository: str, repository_id: int, signer_commit: str,
    workflow_identity: str, backend: BundleVerificationBackend | None = None,
) -> dict[str, Any]:
    predicate_bytes = _require_regular_nonempty(predicate_path, "predicate")
    freeze_bytes = _require_regular_nonempty(freeze_record_path, "freeze record")
    bundle_bytes = _require_regular_nonempty(bundle_path, "bundle")
    trusted_root_bytes = _require_regular_nonempty(trusted_root_path, "trusted root")
    predicate = load_json(predicate_path)
    freeze = load_json(freeze_record_path)
    root_digest = sha256_bytes(trusted_root_bytes)
    if freeze.get("trusted_root_set_sha256") != root_digest:
        raise ValueError("trusted_root_set_sha256 mismatch")
    backend_receipt = (backend or BundleVerificationBackend()).verify(
        predicate_bytes=predicate_bytes, bundle_bytes=bundle_bytes,
        trusted_root_bytes=trusted_root_bytes,
    )
    predicate_raw = sha256_bytes(predicate_bytes)
    verified_at = _validate_backend_receipt(
        backend_receipt, predicate=predicate, freeze=freeze,
        predicate_raw_sha256=predicate_raw, repository=repository,
        repository_id=repository_id, signer_commit=signer_commit,
        workflow_identity=workflow_identity,
    )
    provider_receipt = validate_pre_sign(
        repo_root=repo_root, predicate_path=predicate_path,
        expected_predicate_sha256=predicate_raw,
        freeze_record_path=freeze_record_path,
        expected_freeze_sha256=sha256_bytes(freeze_bytes), repository=repository,
        repository_id=repository_id, signer_commit=signer_commit,
        workflow_identity=workflow_identity, now=verified_at,
    )
    result = {
        "status": "PLATFORM_ATTESTATION_VERIFIED", "schema_version": "2.1",
        "predicate_raw_sha256": predicate_raw,
        "predicate_jcs_sha256": provider_receipt["predicate_jcs_sha256"],
        "freeze_record_raw_sha256": sha256_bytes(freeze_bytes),
        "repository_id": repository_id,
        "platform_identity": provider_receipt["platform_identity"],
        "replay_key": provider_receipt["replay_key"],
        "trusted_root_epoch": freeze["trusted_root_epoch"],
        "trusted_root_set_sha256": root_digest,
        "verified_at": verified_at.isoformat(),
        "source_commit": freeze["source_commit"],
        "signer_commit": signer_commit,
        "capability_status": "PLATFORM_PROVIDER_CONFIGURED_AND_VERIFIED",
        "authority_granted": False,
        "formal_attestation_signing_authorized": True,
        "lease_creation_authorized": False, "state_advance_authorized": False,
    }
    result["verification_receipt_jcs_sha256"] = sha256_bytes(
        canonical_json_bytes(result)
    )
    claim_verified_attestation(state_db_path, claim_from_receipt(result))
    result["state_db"] = str(state_db_path)
    return result
