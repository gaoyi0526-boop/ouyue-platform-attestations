"""Command-line surface for frozen V2 platform-attestation artifacts."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import sys

from github_sigstore_backend import BackendUnavailableError, GithubCLIBackend
from github_sigstore_provider import load_json, validate_pre_sign
from github_sigstore_verifier import (
    ReplayStateError,
    verify_offline,
)


EXIT_OK = 0
EXIT_VALIDATION_FAILED = 1
EXIT_BACKEND_UNAVAILABLE = 2
EXIT_REPLAY_STATE_FAILED = 3


def _add_identity_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--repository", required=True)
    parser.add_argument("--repository-id", required=True, type=int)
    parser.add_argument("--signer-commit", required=True)
    parser.add_argument("--workflow-identity", required=True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Validate or offline-verify frozen V2 attestation artifacts."
    )
    commands = parser.add_subparsers(dest="command", required=True)

    pre_sign = commands.add_parser("validate-pre-sign")
    for name in (
        "repo-root", "predicate", "predicate-sha256", "freeze-record",
        "freeze-record-sha256",
    ):
        pre_sign.add_argument(f"--{name}", required=True)
    _add_identity_arguments(pre_sign)

    offline = commands.add_parser("verify-offline")
    for name in (
        "repo-root", "predicate", "freeze-record", "bundle", "trusted-root",
        "state-db",
    ):
        offline.add_argument(f"--{name}", required=True)
    _add_identity_arguments(offline)
    return parser


def _build_offline_backend(args: argparse.Namespace) -> GithubCLIBackend:
    predicate = load_json(Path(args.predicate))
    freeze = load_json(Path(args.freeze_record))
    return GithubCLIBackend(
        repository=args.repository,
        repository_id=args.repository_id,
        workflow_identity=args.workflow_identity,
        signer_commit=args.signer_commit,
        source_commit=freeze["source_commit"],
        source_binding_sha256=predicate["source_binding_sha256"],
        trusted_root_set_sha256=freeze["trusted_root_set_sha256"],
    )


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "validate-pre-sign":
            result = validate_pre_sign(
                repo_root=Path(args.repo_root),
                predicate_path=Path(args.predicate),
                expected_predicate_sha256=args.predicate_sha256,
                freeze_record_path=Path(args.freeze_record),
                expected_freeze_sha256=args.freeze_record_sha256,
                repository=args.repository,
                repository_id=args.repository_id,
                signer_commit=args.signer_commit,
                workflow_identity=args.workflow_identity,
                now=datetime.now(timezone.utc),
            )
        else:
            result = verify_offline(
                repo_root=Path(args.repo_root),
                predicate_path=Path(args.predicate),
                freeze_record_path=Path(args.freeze_record),
                bundle_path=Path(args.bundle),
                trusted_root_path=Path(args.trusted_root),
                state_db_path=Path(args.state_db),
                repository=args.repository,
                repository_id=args.repository_id,
                signer_commit=args.signer_commit,
                workflow_identity=args.workflow_identity,
                backend=_build_offline_backend(args),
            )
    except BackendUnavailableError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return EXIT_BACKEND_UNAVAILABLE
    except ReplayStateError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return EXIT_REPLAY_STATE_FAILED
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return EXIT_VALIDATION_FAILED
    print(json.dumps(result, sort_keys=True))
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
