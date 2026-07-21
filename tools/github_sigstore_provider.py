from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import re
from typing import Any

from github_sigstore_authorization import (
    validate_inputs_v21,
    validate_signing_event_v21,
)
from github_sigstore_json import (
    canonical_json_bytes,
    load_json,
    parse_rfc3339,
    sha256_bytes,
    sha256_file,
)

FROZEN_ROOT = Path("docs/superpowers/specs/platform-attestation-manifests")
HEX_64 = re.compile(r"^[0-9a-f]{64}$")
COMMIT_SHA = re.compile(r"^[0-9a-f]{40}$")

PREDICATE_V2_FIELDS = (
    'attestation_id', 'issuer_identity', 'identity_evidence_class',
    'decision_event_id', 'decision_event_raw_sha256',
    'subject_attestation_request_raw_sha256', 'project_id', 'thread_id',
    'stage_id', 'task_id', 'lease_id', 'lease_generation', 'fence_token',
    'run_id', 'operation_id', 'idempotency_key', 'authorized_scope',
    'allowed_actions_sha256', 'allowed_paths_sha256', 'source_binding_sha256',
    'capability_envelope_sha256', 'owner_gate_type', 'valid_until',
    'predecessor_event_payload_sha256', 'evidence_epoch',
    'checkpoint_generation', 'attestation_content_sha256',
)
FREEZE_V2_FIELDS = (
    'artifact_type', 'schema_version', 'freeze_status', 'predicate_path',
    'predicate_raw_sha256', 'predicate_jcs_sha256',
    'subject_attestation_request_raw_sha256', 'repository', 'repository_id',
    'workflow_identity', 'source_commit', 'nonce_sha256', 'platform_identity',
    'trusted_root_epoch', 'trusted_root_set_sha256', 'replay_key',
    'authorization_expires_at', 'formal_attestation_signing_authorized',
    'lease_creation_authorized', 'state_advance_authorized',
)
HASH_FIELDS = {
    'decision_event_raw_sha256', 'subject_attestation_request_raw_sha256',
    'idempotency_key', 'allowed_actions_sha256', 'allowed_paths_sha256',
    'source_binding_sha256', 'capability_envelope_sha256',
    'predecessor_event_payload_sha256', 'attestation_content_sha256',
}
PREDICATE_CONSTANTS = {
    'identity_evidence_class': 'PLATFORM_ATTESTED',
    'project_id': 'Governance-Repair-Lease-Issuer-Contract-01',
    'thread_id': 'T90',
    'stage_id': 'AUTHORITY_REBASE',
    'task_id': 'PREPARE_AUTHORITY_ONLY_REBASE_EXECUTION_CONTRACT_V1',
    'authorized_scope': 'AUTHORITY_ONLY_REBASE',
    'owner_gate_type': 'HIGH_IMPACT',
}

def _require_exact_fields(value: dict[str, Any], fields: tuple[str, ...],
                          label: str) -> None:
    actual = set(value)
    expected = set(fields)
    if len(value) != len(fields) or actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise ValueError(f'{label} fields mismatch: missing={missing}, extra={extra}')

def _require_hex(value: Any, field: str) -> str:
    if not isinstance(value, str) or not HEX_64.fullmatch(value):
        raise ValueError(f'{field} must be 64 lowercase hex characters')
    return value

def _require_non_empty(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value or value.strip() != value:
        raise ValueError(f'{field} must be a non-empty trimmed string')
    return value

def _require_relative_frozen_path(repo_root: Path, path: Path, suffix: str) -> str:
    root = repo_root.resolve()
    candidate = path if path.is_absolute() else root / path
    if candidate.is_symlink() or not candidate.is_file():
        raise ValueError('attestation input must be a regular non-symlink file')
    resolved = candidate.resolve()
    try:
        relative = resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError('attestation input is outside the repository') from exc
    if not relative.is_relative_to(FROZEN_ROOT) or not relative.name.endswith(suffix):
        raise ValueError(f'attestation input must be under {FROZEN_ROOT} and end in {suffix}')
    return relative.as_posix()

def validate_predicate_v2(predicate: dict[str, Any], *, now: datetime) -> datetime:
    _require_exact_fields(predicate, PREDICATE_V2_FIELDS, 'predicate')
    for field, expected in PREDICATE_CONSTANTS.items():
        if predicate[field] != expected:
            raise ValueError(f'{field} must equal {expected}')
    for field in PREDICATE_V2_FIELDS:
        if field not in HASH_FIELDS and field not in {
            'lease_generation', 'checkpoint_generation',
        }:
            _require_non_empty(predicate[field], field)
    for field in HASH_FIELDS:
        _require_hex(predicate[field], field)
    for field in ('lease_generation', 'checkpoint_generation'):
        value = predicate[field]
        if type(value) is not int or value < 0:
            raise ValueError(f'{field} must be a non-negative integer')
    expires = parse_rfc3339(predicate['valid_until'], 'valid_until')
    if expires <= now.astimezone(timezone.utc):
        raise ValueError('predicate is expired')
    content = dict(predicate)
    declared = content.pop('attestation_content_sha256')
    actual = sha256_bytes(canonical_json_bytes(content))
    if declared != actual:
        raise ValueError('attestation_content_sha256 mismatch')
    return expires

def _platform_identity(repository_id: int, workflow_identity: str) -> str:
    return f'github-actions:{repository_id}:{workflow_identity}@refs/heads/main'

def _derive_replay_key(freeze: dict[str, Any], predicate: dict[str, Any]) -> str:
    material = {
        'repository_id': freeze['repository_id'],
        'nonce_sha256': freeze['nonce_sha256'],
        'predicate_raw_sha256': freeze['predicate_raw_sha256'],
        'lease_id': predicate['lease_id'],
        'lease_generation': predicate['lease_generation'],
        'fence_token': predicate['fence_token'],
    }
    return sha256_bytes(canonical_json_bytes(material))

def validate_freeze_record_v2(
    freeze: dict[str, Any],
    *,
    predicate: dict[str, Any],
    predicate_path: str,
    predicate_raw_sha256: str,
    predicate_jcs_sha256: str,
    repository: str,
    repository_id: int,
    workflow_identity: str,
    now: datetime,
) -> datetime:
    _require_exact_fields(freeze, FREEZE_V2_FIELDS, 'freeze record')
    constants = {
        'artifact_type': 'PTO_LEASE_CONTROLLER_PLATFORM_ATTESTATION_FREEZE_RECORD',
        'schema_version': '2.1',
        'freeze_status': 'FROZEN',
        'predicate_path': predicate_path,
        'predicate_raw_sha256': predicate_raw_sha256,
        'predicate_jcs_sha256': predicate_jcs_sha256,
        'subject_attestation_request_raw_sha256':
            predicate['subject_attestation_request_raw_sha256'],
        'repository': repository,
        'repository_id': repository_id,
        'workflow_identity': workflow_identity,
        'platform_identity': _platform_identity(repository_id, workflow_identity),
    }
    for field, expected in constants.items():
        if freeze[field] != expected:
            raise ValueError(f'{field} mismatch in freeze record')
    if type(repository_id) is not int or repository_id <= 0:
        raise ValueError('repository_id must be a positive integer')
    source_commit = freeze['source_commit']
    if not isinstance(source_commit, str) or not COMMIT_SHA.fullmatch(source_commit):
        raise ValueError('source_commit must be a full lowercase Git SHA')
    for field in (
        'predicate_raw_sha256', 'predicate_jcs_sha256', 'nonce_sha256',
        'trusted_root_set_sha256', 'replay_key',
    ):
        _require_hex(freeze[field], field)
    epoch = freeze['trusted_root_epoch']
    if type(epoch) is not int or epoch <= 0:
        raise ValueError('trusted_root_epoch must be a positive integer')
    if freeze['formal_attestation_signing_authorized'] is not True:
        raise ValueError('formal_attestation_signing_authorized must be true')
    for field in ('lease_creation_authorized', 'state_advance_authorized'):
        if freeze[field] is not False:
            raise ValueError(f'{field} must remain false')
    if freeze['replay_key'] != _derive_replay_key(freeze, predicate):
        raise ValueError('replay_key mismatch')
    expires = parse_rfc3339(
        freeze['authorization_expires_at'], 'authorization_expires_at'
    )
    predicate_expires = parse_rfc3339(predicate['valid_until'], 'valid_until')
    current = now.astimezone(timezone.utc)
    if expires <= current:
        raise ValueError('freeze record is expired')
    if expires > predicate_expires:
        raise ValueError('freeze record exceeds predicate validity')
    return expires

def validate_pre_sign(
    *,
    repo_root: Path,
    predicate_path: Path,
    expected_predicate_sha256: str,
    freeze_record_path: Path,
    expected_freeze_sha256: str,
    repository: str,
    repository_id: int,
    signer_commit: str,
    workflow_identity: str,
    now: datetime,
) -> dict[str, Any]:
    if repo_root.is_symlink() or not repo_root.is_dir():
        raise ValueError('repo_root must be a regular directory')
    predicate_relative = _require_relative_frozen_path(
        repo_root, predicate_path, '.predicate.json'
    )
    freeze_relative = _require_relative_frozen_path(
        repo_root, freeze_record_path, '.freeze.json'
    )
    stem = predicate_relative.removesuffix('.predicate.json')
    if freeze_relative != f'{stem}.freeze.json':
        raise ValueError('predicate and freeze record must share the same stem')
    inputs_relative = _require_relative_frozen_path(
        repo_root, Path(f'{stem}.inputs.json'), '.inputs.json'
    )
    signing_relative = _require_relative_frozen_path(
        repo_root, Path(f'{stem}.signing.json'), '.signing.json'
    )
    predicate_file = repo_root.resolve() / predicate_relative
    freeze_file = repo_root.resolve() / freeze_relative
    inputs_file = repo_root.resolve() / inputs_relative
    signing_file = repo_root.resolve() / signing_relative
    predicate_raw = sha256_file(predicate_file)
    freeze_raw = sha256_file(freeze_file)
    if _require_hex(expected_predicate_sha256, 'predicate_sha256') != predicate_raw:
        raise ValueError('predicate SHA-256 mismatch')
    if _require_hex(expected_freeze_sha256, 'freeze_record_sha256') != freeze_raw:
        raise ValueError('freeze record SHA-256 mismatch')
    predicate = load_json(predicate_file)
    validate_predicate_v2(predicate, now=now)
    predicate_jcs = sha256_bytes(canonical_json_bytes(predicate))
    freeze = load_json(freeze_file)
    validate_freeze_record_v2(
        freeze, predicate=predicate, predicate_path=predicate_relative,
        predicate_raw_sha256=predicate_raw, predicate_jcs_sha256=predicate_jcs,
        repository=repository, repository_id=repository_id,
        workflow_identity=workflow_identity, now=now,
    )
    if not isinstance(signer_commit, str) or not COMMIT_SHA.fullmatch(signer_commit):
        raise ValueError('signer_commit must be a full lowercase Git SHA')
    inputs = load_json(inputs_file)
    input_hashes = validate_inputs_v21(
        inputs, source_commit=freeze['source_commit'],
        hash_value=lambda value: sha256_bytes(canonical_json_bytes(value)),
    )
    for field, expected in input_hashes.items():
        if predicate[field] != expected:
            raise ValueError(f'{field} mismatch with inputs')
    signing_raw = sha256_file(signing_file)
    if predicate['predecessor_event_payload_sha256'] != signing_raw:
        raise ValueError('predecessor_event_payload_sha256 mismatch with signing event')
    validate_signing_event_v21(
        load_json(signing_file), inputs_raw_sha256=sha256_file(inputs_file),
        predicate=predicate, source_commit=freeze['source_commit'],
        repository=repository, repository_id=repository_id,
        workflow_identity=workflow_identity, platform_identity=freeze['platform_identity'],
        now=now, hash_value=lambda value: sha256_bytes(canonical_json_bytes(value)),
    )
    return {
        'status': 'PRE_SIGN_VALIDATION_PASSED',
        'schema_version': '2.1',
        'predicate_path': predicate_relative,
        'predicate_raw_sha256': predicate_raw,
        'predicate_jcs_sha256': predicate_jcs,
        'freeze_record_path': freeze_relative,
        'freeze_record_raw_sha256': freeze_raw,
        'inputs_path': inputs_relative,
        'inputs_raw_sha256': sha256_file(inputs_file),
        'signing_event_path': signing_relative,
        'signing_event_raw_sha256': signing_raw,
        'repository_id': repository_id,
        'source_commit': freeze['source_commit'],
        'signer_commit': signer_commit,
        'platform_identity': freeze['platform_identity'],
        'replay_key': freeze['replay_key'],
        'capability_status': 'FORMAL_ATTESTATION_SIGNING_AUTHORIZED',
        'authority_granted': False,
    }
