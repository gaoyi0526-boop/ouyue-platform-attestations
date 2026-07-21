"""Exact governance checks for V2.1 platform-attestation authorization."""

from __future__ import annotations

from datetime import datetime, timezone
import re
from typing import Any, Callable


HEX_64 = re.compile(r"^[0-9a-f]{64}$")
COMMIT_SHA = re.compile(r"^[0-9a-f]{40}$")
REPOSITORY = "gaoyi0526-boop/ouyue-platform-attestations"
GOVERNED_REPOSITORY = "gaoyi0526-boop/ouyue-skills"
GOVERNED_SOURCE_COMMIT = "39ea5ceaf46d8b7c28ca0dc9ebf211128eec8fd2"
PERMITTED_WRITE_ROOT = (
    "docs/superpowers/specs/g0-f03-through-g0-execution-01-20260719/"
    "01_authority_rebase"
)
OWNER_EVENT_ID = (
    "G0-FC01-FC06-OWNER-APPROVE-EXACT-CANDIDATE-EVENT-20260719-01"
)
OWNER_EVENT_SHA = (
    "1ef101befb6a6d5770beb318dd78a0baf35b2662b70bf9ee004245e524b022c6"
)
REQUEST_ID = (
    "G0-FC01-FC06-LEASE-ISSUER-ATTESTATION-REQUEST-20260719-01"
)
REQUEST_SHA = (
    "4df9bc29d6e200c1d8d92202984ca0336de4c4f6459952de728e399934d25096"
)
FINGERPRINT_EVENT_ID = (
    "G0-FC01-FC06-OWNER-APPROVE-PTO-LEASE-CONTROLLER-FINGERPRINT-20260719-01"
)
FINGERPRINT_EVENT_SHA = (
    "f6af77088620e63dd3261fd55abc639bcf6faebb5cdf585294819e6a754fbc5d"
)
EVIDENCE_EPOCH = "PTO_LEASE_CONTROLLER_CANDIDATE_KEY_EPOCH_20260719_01"

INPUTS_V21_FIELDS = (
    "artifact_type", "schema_version", "allowed_actions", "allowed_paths",
    "source_binding", "capability_envelope",
)
SOURCE_BINDING_FIELDS = (
    "repository", "source_commit",
    "governed_repository", "governed_source_commit",
    "causal_owner_decision_event_raw_sha256",
    "subject_attestation_request_raw_sha256",
    "fingerprint_approval_event_raw_sha256",
)
CAPABILITY_FIELDS = (
    "authorized_scope", "permitted_write_root",
    "formal_attestation_signing_authorized", "lease_creation_authorized",
    "authority_rebase_execution_authorized", "registry_activation_authorized",
    "f03_closed", "g0_execution_authorized", "runtime_authorization",
    "t01_authorized", "state_advance_authorized",
)
SIGNING_V21_FIELDS = (
    "artifact_type", "schema_version", "event_id", "issued_at", "valid_until",
    "decision_authority", "decision", "owner_source", "causal_owner_event",
    "fingerprint_approval_event", "subject_attestation_request",
    "approved_candidate_identity", "inputs_raw_sha256", "source_commit",
    "lease_binding", "platform_provider", "signature_count",
    "billing_plan_status", "formal_attestation_signing_authorized",
    "lease_creation_authorized", "state_advance_authorized",
)
OWNER_SOURCE_FIELDS = (
    "source_type", "thread_id", "source_text_projection",
    "source_projection_sha256", "cryptographic_signature_status",
)
LEASE_BINDING_FIELDS = (
    "lease_id", "lease_generation", "fence_token", "run_id", "operation_id",
    "idempotency_key", "authorized_scope", "permitted_write_root",
)
PLATFORM_PROVIDER_FIELDS = (
    "repository", "repository_id", "workflow_identity", "environment", "branch",
    "platform_identity", "sigstore_instance",
)
CANDIDATE_FIELDS = (
    "issuer_role", "thumbprint_sha1", "certificate_raw_sha256",
    "public_key_value_sha256",
)
CANDIDATE_IDENTITY = {
    "issuer_role": "PTO_LEASE_CONTROLLER",
    "thumbprint_sha1": "FF6249EBFF3B242E4F08AA1A7BCA1D3BA47D01CD",
    "certificate_raw_sha256":
        "4280e156fd6df78310dbe9844b79d56a2ec67310836f9f72dc9715d34b67a8a0",
    "public_key_value_sha256":
        "08f89a550dcaea726a212d80093bcd564f8b0543384f8be141e94b85ed469c07",
}


def _exact(value: Any, fields: tuple[str, ...], label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    actual, expected = set(value), set(fields)
    if len(value) != len(fields) or actual != expected:
        raise ValueError(
            f"{label} fields mismatch: missing={sorted(expected - actual)}, "
            f"extra={sorted(actual - expected)}"
        )
    return value


def _hex(value: Any, field: str) -> str:
    if not isinstance(value, str) or not HEX_64.fullmatch(value):
        raise ValueError(f"{field} must be 64 lowercase hex characters")
    return value


def _text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value or value.strip() != value:
        raise ValueError(f"{field} must be a non-empty trimmed string")
    return value


def _time(value: Any, field: str) -> datetime:
    text = _text(value, field)
    normalized = text[:-1] + "+00:00" if text.endswith("Z") else text
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ValueError(f"{field} must be RFC3339") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{field} must include a timezone")
    return parsed.astimezone(timezone.utc)


def _expect(value: dict[str, Any], field: str, expected: Any) -> None:
    if value[field] != expected:
        raise ValueError(f"{field} mismatch")


def validate_inputs_v21(
    inputs: dict[str, Any], *, source_commit: str,
    hash_value: Callable[[Any], str],
) -> dict[str, str]:
    _exact(inputs, INPUTS_V21_FIELDS, "inputs")
    _expect(
        inputs, "artifact_type",
        "PTO_LEASE_CONTROLLER_PLATFORM_ATTESTATION_INPUTS",
    )
    _expect(inputs, "schema_version", "2.1")
    _expect(
        inputs, "allowed_actions",
        ["CREATE_PLATFORM_ATTESTATION_FOR_PTO_LEASE_CONTROLLER_IDENTITY"],
    )
    _expect(inputs, "allowed_paths", [PERMITTED_WRITE_ROOT])
    if not isinstance(source_commit, str) or not COMMIT_SHA.fullmatch(source_commit):
        raise ValueError("source_commit must be a full lowercase Git SHA")

    source = _exact(
        inputs["source_binding"], SOURCE_BINDING_FIELDS, "source_binding"
    )
    expected_source = {
        "repository": REPOSITORY,
        "source_commit": source_commit,
        "governed_repository": GOVERNED_REPOSITORY,
        "governed_source_commit": GOVERNED_SOURCE_COMMIT,
        "causal_owner_decision_event_raw_sha256": OWNER_EVENT_SHA,
        "subject_attestation_request_raw_sha256": REQUEST_SHA,
        "fingerprint_approval_event_raw_sha256": FINGERPRINT_EVENT_SHA,
    }
    for field, expected in expected_source.items():
        _expect(source, field, expected)

    capability = _exact(
        inputs["capability_envelope"], CAPABILITY_FIELDS, "capability_envelope"
    )
    _expect(capability, "authorized_scope", "AUTHORITY_ONLY_REBASE")
    _expect(capability, "permitted_write_root", PERMITTED_WRITE_ROOT)
    _expect(capability, "formal_attestation_signing_authorized", True)
    for field in CAPABILITY_FIELDS[3:]:
        _expect(capability, field, False)

    names = (
        ("allowed_actions", "allowed_actions_sha256"),
        ("allowed_paths", "allowed_paths_sha256"),
        ("source_binding", "source_binding_sha256"),
        ("capability_envelope", "capability_envelope_sha256"),
    )
    result = {output: hash_value(inputs[source_name]) for source_name, output in names}
    for field, digest in result.items():
        _hex(digest, field)
    return result


def validate_signing_event_v21(
    signing: dict[str, Any], *, inputs_raw_sha256: str,
    predicate: dict[str, Any], source_commit: str, repository: str,
    repository_id: int, workflow_identity: str, platform_identity: str,
    now: datetime, hash_value: Callable[[Any], str] | None = None,
) -> None:
    _exact(signing, SIGNING_V21_FIELDS, "signing event")
    constants = {
        "artifact_type": "OWNER_AUTHORIZE_PLATFORM_ATTESTATION_SIGNING_EVENT",
        "schema_version": "1.0",
        "event_id": "OWNER-AUTHORIZE-PLATFORM-ATTESTATION-SIGNING-20260721-01",
        "decision_authority": "OWNER",
        "decision": "AUTHORIZE_EXACT_PLATFORM_ATTESTATION_SIGNING",
        "inputs_raw_sha256": _hex(inputs_raw_sha256, "inputs_raw_sha256"),
        "source_commit": source_commit,
        "billing_plan_status": "BILLING_PLAN_UNSUPPORTED",
        "formal_attestation_signing_authorized": True,
        "lease_creation_authorized": False,
        "state_advance_authorized": False,
    }
    for field, expected in constants.items():
        _expect(signing, field, expected)
    if not COMMIT_SHA.fullmatch(source_commit):
        raise ValueError("source_commit must be a full lowercase Git SHA")
    issued = _time(signing["issued_at"], "issued_at")
    expires = _time(signing["valid_until"], "valid_until")
    current = now.astimezone(timezone.utc)
    if issued > current:
        raise ValueError("signing event is not yet valid")
    if expires <= current:
        raise ValueError("signing event is expired")
    if expires > _time(predicate["valid_until"], "predicate valid_until"):
        raise ValueError("signing event exceeds predicate validity")
    if type(signing["signature_count"]) is not int or signing["signature_count"] != 1:
        raise ValueError("signature_count must be exact integer 1")

    owner = _exact(signing["owner_source"], OWNER_SOURCE_FIELDS, "owner_source")
    _expect(owner, "source_type", "CURRENT_THREAD_OWNER_DIRECTIVE")
    _expect(owner, "thread_id", "019f841c-3532-71f0-ad29-c7f043c108e3")
    _expect(owner, "cryptographic_signature_status", "NOT_AVAILABLE")
    projection = _text(owner["source_text_projection"], "source_text_projection")
    _hex(owner["source_projection_sha256"], "source_projection_sha256")
    if hash_value and owner["source_projection_sha256"] != hash_value(projection):
        raise ValueError("source_projection_sha256 mismatch")

    causal = _exact(
        signing["causal_owner_event"], ("decision_event_id", "raw_sha256"),
        "causal_owner_event",
    )
    _expect(causal, "decision_event_id", OWNER_EVENT_ID)
    _expect(causal, "raw_sha256", OWNER_EVENT_SHA)
    _expect(predicate, "decision_event_id", OWNER_EVENT_ID)
    _expect(predicate, "decision_event_raw_sha256", OWNER_EVENT_SHA)

    fingerprint = _exact(
        signing["fingerprint_approval_event"],
        ("decision_event_id", "raw_sha256", "evidence_epoch",
         "checkpoint_generation"), "fingerprint_approval_event",
    )
    _expect(fingerprint, "decision_event_id", FINGERPRINT_EVENT_ID)
    _expect(fingerprint, "raw_sha256", FINGERPRINT_EVENT_SHA)
    _expect(fingerprint, "evidence_epoch", EVIDENCE_EPOCH)
    _expect(fingerprint, "checkpoint_generation", 1)
    _expect(predicate, "evidence_epoch", EVIDENCE_EPOCH)
    _expect(predicate, "checkpoint_generation", 1)

    request = _exact(
        signing["subject_attestation_request"], ("request_id", "raw_sha256"),
        "subject_attestation_request",
    )
    _expect(request, "request_id", REQUEST_ID)
    _expect(request, "raw_sha256", REQUEST_SHA)
    _expect(predicate, "subject_attestation_request_raw_sha256", REQUEST_SHA)

    candidate = _exact(
        signing["approved_candidate_identity"], CANDIDATE_FIELDS,
        "approved_candidate_identity",
    )
    for field, expected in CANDIDATE_IDENTITY.items():
        _expect(candidate, field, expected)

    lease = _exact(signing["lease_binding"], LEASE_BINDING_FIELDS, "lease_binding")
    for field in LEASE_BINDING_FIELDS[:-1]:
        _expect(lease, field, predicate[field])
    _expect(lease, "permitted_write_root", PERMITTED_WRITE_ROOT)

    provider = _exact(
        signing["platform_provider"], PLATFORM_PROVIDER_FIELDS,
        "platform_provider",
    )
    expected_provider = {
        "repository": repository, "repository_id": repository_id,
        "workflow_identity": workflow_identity,
        "environment": "platform-attestation-signer",
        "branch": "refs/heads/main", "platform_identity": platform_identity,
        "sigstore_instance": "public-good",
    }
    for field, expected in expected_provider.items():
        _expect(provider, field, expected)
