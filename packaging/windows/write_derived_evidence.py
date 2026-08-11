#!/usr/bin/env python3
"""Derive strict provenance/loader/cleanup/performance gates from the matrix."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from release_common import (
    ReleaseError,
    evidence_envelope,
    evidence_record,
    identity_sha256,
    json_bytes,
    load_identity,
    read_json,
    require_release_bootstrap,
    verify_evidence_file,
    verify_generator_runtime,
)


GATES = {
    "runtime-provenance": ("runtime_provenance",),
    "dll-denial": ("dll_denial", "helper_path_denial"),
    "process-cleanup": (
        "lingering_bundle_processes",
        "timeout_reap",
        "bundle_content_fingerprint_unchanged",
    ),
    "compatibility-performance": ("host", "cases", "behavior_fingerprint", "coverage", "profiles"),
}


def main() -> int:
    require_release_bootstrap("packaging/windows/write_derived_evidence.py")
    parser = argparse.ArgumentParser()
    parser.add_argument("--gate", choices=tuple(sorted(GATES)), required=True)
    parser.add_argument("--identity", required=True, type=Path)
    parser.add_argument("--matrix", required=True, type=Path)
    parser.add_argument("--json", required=True, type=Path)
    args = parser.parse_args()
    identity_path = args.identity.resolve(strict=True)
    identity = load_identity(identity_path)
    identity_hash = identity_sha256(identity_path)
    matrix_path = args.matrix.resolve(strict=True)
    matrix_record = evidence_record(identity, "fresh-extract-practical")
    verify_evidence_file(
        matrix_path,
        record=matrix_record,
        identity=identity,
        identity_hash=identity_hash,
    )
    matrix = read_json(matrix_path)
    payload = matrix["observations"]
    missing = [key for key in GATES[args.gate] if key not in payload]
    if missing:
        raise ReleaseError(f"practical matrix lacks derived observations: {missing}")
    observations = {key: payload[key] for key in GATES[args.gate]}
    observations["matrix_file"] = matrix_record["file"]
    logical_argv = [
        "<PYTHON>",
        "packaging/windows/write_derived_evidence.py",
        "--gate",
        args.gate,
        "--identity",
        "<RELEASE-IDENTITY>",
        "--matrix",
        "<PRACTICAL-EVIDENCE>",
        "--json",
        "<EVIDENCE-OUTPUT>",
    ]
    record = verify_generator_runtime(
        identity,
        gate=args.gate,
        logical_argv=logical_argv,
    )
    result = evidence_envelope(
        identity,
        identity_hash=identity_hash,
        record=record,
        observations=observations,
    )
    if args.json.exists() or args.json.is_symlink():
        raise ReleaseError(f"derived evidence output exists: {args.json}")
    args.json.parent.mkdir(parents=True, exist_ok=True)
    args.json.write_bytes(json_bytes(result))
    print(f"PASS: strict {args.gate} evidence derived from exact practical matrix")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ReleaseError, OSError, ValueError, json.JSONDecodeError) as exc:
        raise SystemExit(f"error: {exc}") from exc
