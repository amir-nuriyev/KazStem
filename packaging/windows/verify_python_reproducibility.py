#!/usr/bin/env python3
"""Verify two independent PyInstaller builds consuming one canonical v2 pair."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from release_common import (
    ReleaseError,
    artifact_record,
    evidence_envelope,
    files_equal,
    file_record,
    identity_sha256,
    json_bytes,
    load_identity,
    python_build_receipt_projection,
    read_json,
    require_release_bootstrap,
    tree_record,
    verify_artifact,
    verify_file,
    verify_generator_runtime,
    verify_python_build_receipt,
    verify_tree,
)


def main() -> int:
    require_release_bootstrap("packaging/windows/verify_python_reproducibility.py")
    parser = argparse.ArgumentParser()
    parser.add_argument("--identity", required=True, type=Path)
    parser.add_argument("--bootstrap-python", required=True, type=Path)
    parser.add_argument("--wheelhouse", required=True, type=Path)
    parser.add_argument("--optimization-config", required=True, type=Path)
    parser.add_argument("--python-build-identity", required=True, type=Path)
    parser.add_argument("--python-build-receipt", required=True, type=Path)
    for suffix in ("a", "b"):
        parser.add_argument(f"--build-root-{suffix}", required=True, type=Path)
        parser.add_argument(f"--receipt-{suffix}", required=True, type=Path)
        parser.add_argument(f"--frozen-{suffix}", required=True, type=Path)
        parser.add_argument(f"--wheel-{suffix}", required=True, type=Path)
        parser.add_argument(f"--sdist-{suffix}", required=True, type=Path)
        parser.add_argument(f"--ledger-{suffix}", required=True, type=Path)
    parser.add_argument("--json", required=True, type=Path)
    args = parser.parse_args()
    identity_path = args.identity.resolve(strict=True)
    identity = load_identity(identity_path)
    identity_hash = identity_sha256(identity_path)
    roots = [args.build_root_a.resolve(strict=True), args.build_root_b.resolve(strict=True)]
    if roots[0] == roots[1] or roots[0] in roots[1].parents or roots[1] in roots[0].parents or roots[0].samefile(roots[1]):
        raise ReleaseError("Python reproducibility roots are equal/nested/aliased")
    receipts = [args.receipt_a.resolve(strict=True), args.receipt_b.resolve(strict=True)]
    frozen = [args.frozen_a.resolve(strict=True), args.frozen_b.resolve(strict=True)]
    wheels = [args.wheel_a.resolve(strict=True), args.wheel_b.resolve(strict=True)]
    sdists = [args.sdist_a.resolve(strict=True), args.sdist_b.resolve(strict=True)]
    ledgers = [args.ledger_a.resolve(strict=True), args.ledger_b.resolve(strict=True)]
    values = []
    for index in range(2):
        label = chr(ord("a") + index)
        value = read_json(receipts[index])
        verify_python_build_receipt(
            value,
            identity,
            label=label,
            build_root=roots[index],
            bootstrap_python=args.bootstrap_python,
            wheelhouse=args.wheelhouse,
            optimization_config=args.optimization_config,
            python_build_identity=args.python_build_identity,
            python_build_receipt=args.python_build_receipt,
            frozen=frozen[index],
            wheel=wheels[index],
            sdist=sdists[index],
            base_ledger=ledgers[index],
        )
        verify_tree(frozen[index], identity["inputs"]["frozen_tree"], label=f"frozen {label}")
        verify_artifact(wheels[index], identity["artifacts"]["wheel"], label=f"wheel {label}")
        verify_artifact(sdists[index], identity["artifacts"]["sdist"], label=f"sdist {label}")
        verify_file(ledgers[index], identity["inputs"]["base_ledger"], label=f"ledger {label}")
        values.append(value)
    if (
        not files_equal(wheels[0], wheels[1])
        or not files_equal(sdists[0], sdists[1])
        or tree_record(frozen[0]) != tree_record(frozen[1])
        or not files_equal(ledgers[0], ledgers[1])
        or values[0]["root_identity"] == values[1]["root_identity"]
    ):
        raise ReleaseError("independent Python/freezer build products differ")
    logical_argv = [
        "<PYTHON>",
        "packaging/windows/verify_python_reproducibility.py",
        "--identity",
        "<RELEASE-IDENTITY>",
        "--bootstrap-python",
        "<BOOTSTRAP-PYTHON>",
        "--wheelhouse",
        "<WHEELHOUSE>",
        "--optimization-config",
        "<OPTIMIZATION-CONFIG>",
        "--python-build-identity",
        "<CANONICAL-PYTHON-BUILD-IDENTITY>",
        "--python-build-receipt",
        "<CANONICAL-PYTHON-BUILD-RECEIPT>",
        "--build-root-a",
        "<BUILD-ROOT-A>",
        "--receipt-a",
        "<BUILD-RECEIPT-A>",
        "--frozen-a",
        "<FROZEN-A>",
        "--wheel-a",
        "<WHEEL-A>",
        "--sdist-a",
        "<SDIST-A>",
        "--ledger-a",
        "<LEDGER-A>",
        "--build-root-b",
        "<BUILD-ROOT-B>",
        "--receipt-b",
        "<BUILD-RECEIPT-B>",
        "--frozen-b",
        "<FROZEN-B>",
        "--wheel-b",
        "<WHEEL-B>",
        "--sdist-b",
        "<SDIST-B>",
        "--ledger-b",
        "<LEDGER-B>",
        "--json",
        "<EVIDENCE-OUTPUT>",
    ]
    record = verify_generator_runtime(
        identity,
        gate="python-artifact-reproducibility",
        logical_argv=logical_argv,
    )
    observations = {
        "build_receipts": [python_build_receipt_projection(value) for value in values],
        "wheel": artifact_record(wheels[0], identity["artifacts"]["wheel"]["url"]),
        "sdist": artifact_record(sdists[0], identity["artifacts"]["sdist"]["url"]),
        "frozen_tree": tree_record(frozen[0]),
        "base_ledger": file_record(ledgers[0]),
        "root_proof": {
            "build_labels": ["a", "b"],
            "distinct_nonnested_nonaliased": True,
            "canonical_linux_roundtrip_receipt_validated": True,
        },
    }
    result = evidence_envelope(
        identity,
        identity_hash=identity_hash,
        record=record,
        observations=observations,
    )
    if args.json.exists() or args.json.is_symlink():
        raise ReleaseError(f"Python reproducibility evidence exists: {args.json}")
    args.json.parent.mkdir(parents=True, exist_ok=True)
    args.json.write_bytes(json_bytes(result))
    print("PASS: two independent Windows freezers consumed one validated v2 pair")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ReleaseError, OSError, ValueError, json.JSONDecodeError) as exc:
        raise SystemExit(f"error: {exc}") from exc
