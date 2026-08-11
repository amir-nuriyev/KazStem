#!/usr/bin/env python3
"""Prepare, but never activate, the exact bf1f Darwin validation candidate."""

from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
import subprocess
from typing import Any

from release_common import (
    ReleaseError,
    assert_relative_json,
    canonical_hash,
    ensure_distinct_nonaliased_paths,
    ensure_output_outside,
    file_record,
    json_bytes,
    read_json,
)


MATRIX_SCHEMA = "kazstem-macos-bf1f-native-validation-matrix-v1"
RECEIPT_SCHEMA = "kazstem-macos-bf1f-validation-preparation-v1"
AUDITED_COMMIT = "8d51f7334132ed2513f87b0ed21e08cbc206eb66"
AUDITED_TREE = "144a946cf989da13afc729ba4b80b04620f61df4"
F03_RESOURCE_ID = "f03e703d3e2a67044a7d91fd7d575b92cb4e61aa782fb67cff91b0a5ff0ebd5a"
BF1F_RESOURCE_ID = "bf1f31ff6e5860585b9e4134f12dcfb9d6df8030ee87b368e5a5f29eb45c1188"
DARWIN_RUNTIME_ID = "5341c48bfd1ef57e3976d0849d0ec6d61e2d45ff8d4643b07176fbc6eddf8e57"
DARWIN_RUNTIME_MANIFEST = {
    "bytes": 10679,
    "sha256": "bb84ef3fc227fd24c78e4b8f25caa26f365a5f9497aaa76a7ec2d5d49836ee72",
}
BF1F_MANIFEST = {
    "bytes": 18092,
    "sha256": "8d596011020b21a903244490cc7201d348d7bcc5442ef736ec7e4ac5435083e1",
}
MATRIX_PATH = "packaging/macos/bf1f-validation-matrix.json"
PLATFORM_LOCK_PATH = "src/qazmorph/platform_runtime_assets.lock.json"
REQUIRED_RESOURCE_FILES = {
    "kaz.automorf.hfstol",
    "kaz.autogen.hfstol",
    "kaz.guesser.automorf.hfstol",
    "kaz.guesser.autogen.hfstol",
    "kaz.rlx.bin",
}


def _exact(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        observed = set(value) if isinstance(value, dict) else set()
        raise ReleaseError(
            f"{label} fields differ: missing={sorted(fields - observed)}, "
            f"extra={sorted(observed - fields)}"
        )
    return value


def _git(repository: Path, *argv: str) -> str:
    process = subprocess.run(
        ["git", *argv],
        cwd=repository,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=60,
        check=False,
    )
    if process.returncode:
        raise ReleaseError(f"cannot verify audited bf1f source object: {argv!r}")
    return process.stdout.strip()


def _validate_matrix(value: Any) -> dict[str, Any]:
    matrix = _exact(
        value,
        {
            "activation",
            "audited_source",
            "behavior_cases",
            "candidate",
            "current_release",
            "platform",
            "required_gates",
            "schema",
            "status",
        },
        "bf1f validation matrix",
    )
    if (
        matrix["schema"] != MATRIX_SCHEMA
        or matrix["status"] != "blocked-pending-real-macos-native-validation"
        or matrix["audited_source"]
        != {"commit": AUDITED_COMMIT, "tree": AUDITED_TREE}
        or matrix["platform"]
        != {"system": "darwin", "machine": "arm64", "minimum_os": "15.0"}
        or matrix["current_release"]
        != {
            "darwin_runtime": {
                "bundle_id": DARWIN_RUNTIME_ID,
                "manifest": DARWIN_RUNTIME_MANIFEST,
            },
            "resource_bundle_ids": [F03_RESOURCE_ID],
        }
    ):
        raise ReleaseError("bf1f matrix audited source/current Darwin binding differs")
    candidate = _exact(
        matrix["candidate"], {"darwin_runtime", "resource"}, "bf1f candidate"
    )
    if candidate["darwin_runtime"] != {
        "bundle_id": DARWIN_RUNTIME_ID,
        "manifest": DARWIN_RUNTIME_MANIFEST,
    }:
        raise ReleaseError("bf1f candidate does not retain the audited Darwin runtime")
    resource = _exact(
        candidate["resource"],
        {"bundle_id", "manifest", "manifest_schema", "producer_snapshot"},
        "bf1f candidate resource",
    )
    expected_snapshot = f"packaging/resource-producer/{BF1F_RESOURCE_ID}"
    if resource != {
        "bundle_id": BF1F_RESOURCE_ID,
        "manifest": BF1F_MANIFEST,
        "manifest_schema": "qazmorph-resource-manifest-v4",
        "producer_snapshot": expected_snapshot,
    }:
        raise ReleaseError("bf1f candidate resource identity differs")
    activation = _exact(
        matrix["activation"],
        {
            "automatic",
            "candidate_lock_is_release_input",
            "required_reviewed_change",
            "source_lock_must_remain_f03_only",
        },
        "bf1f activation policy",
    )
    if (
        activation["automatic"] is not False
        or activation["candidate_lock_is_release_input"] is not False
        or activation["source_lock_must_remain_f03_only"] is not True
        or not isinstance(activation["required_reviewed_change"], str)
        or not activation["required_reviewed_change"]
    ):
        raise ReleaseError("bf1f activation policy is not fail closed")
    gates = matrix["required_gates"]
    cases = matrix["behavior_cases"]
    if (
        not isinstance(gates, list)
        or len(gates) < 8
        or not isinstance(cases, list)
        or len(cases) < 14
    ):
        raise ReleaseError("bf1f native matrix is incomplete")
    gate_names: list[str] = []
    for index, gate in enumerate(gates):
        item = _exact(
            gate, {"gate", "requirement", "tool"}, f"bf1f gate {index}"
        )
        if any(not isinstance(item[name], str) or not item[name] for name in item):
            raise ReleaseError("bf1f gate contains an empty field")
        gate_names.append(item["gate"])
    if gate_names != sorted(set(gate_names)):
        raise ReleaseError("bf1f gates must be sorted and unique")
    if cases != sorted(set(cases)):
        raise ReleaseError("bf1f behavior cases must be sorted and unique")
    return matrix


def _validate_resource_manifest(value: Any) -> dict[str, Any]:
    manifest = _exact(
        value,
        {"build", "bundle_id", "files", "schema", "source", "version"},
        "bf1f resource manifest",
    )
    if (
        manifest["schema"] != "qazmorph-resource-manifest-v4"
        or manifest["bundle_id"] != BF1F_RESOURCE_ID
        or set(manifest["files"]) != REQUIRED_RESOURCE_FILES
        or not isinstance(manifest["version"], str)
        or not manifest["version"].endswith(f"qazmorph-{BF1F_RESOURCE_ID[:16]}")
    ):
        raise ReleaseError("bf1f resource manifest identity/inventory differs")
    identity = {
        key: value
        for key, value in manifest.items()
        if key not in {"bundle_id", "version"}
    }
    if canonical_hash(identity) != BF1F_RESOURCE_ID:
        raise ReleaseError("bf1f resource manifest content identity differs")
    for name, record in manifest["files"].items():
        if (
            not isinstance(record, dict)
            or set(record) != {"bytes", "sha256"}
            or isinstance(record["bytes"], bool)
            or not isinstance(record["bytes"], int)
            or record["bytes"] <= 0
            or not isinstance(record["sha256"], str)
            or len(record["sha256"]) != 64
        ):
            raise ReleaseError(f"bf1f resource file identity is invalid: {name}")
    return manifest


def prepare(args: argparse.Namespace) -> dict[str, Any]:
    repository = args.repository.resolve(strict=True)
    if not (repository / ".git").exists():
        raise ReleaseError("bf1f preparation repository is not a Git checkout")
    matrix_path = args.matrix.resolve(strict=True)
    lock_path = args.platform_lock.resolve(strict=True)
    expected_matrix = (repository / MATRIX_PATH).resolve(strict=True)
    expected_lock = (repository / PLATFORM_LOCK_PATH).resolve(strict=True)
    if matrix_path != expected_matrix or lock_path != expected_lock:
        raise ReleaseError("bf1f preparation inputs are not the checked source files")
    for label, output in (
        ("candidate lock", args.candidate_lock_output),
        ("preparation receipt", args.output),
    ):
        if output.exists() or output.is_symlink():
            raise ReleaseError(f"bf1f {label} output already exists")
        ensure_output_outside(output, repository, label=f"bf1f {label}")
    ensure_distinct_nonaliased_paths(
        args.candidate_lock_output,
        args.output,
        labels=("bf1f candidate lock", "bf1f preparation receipt"),
    )
    if _git(repository, "rev-parse", f"{AUDITED_COMMIT}^{{tree}}") != AUDITED_TREE:
        raise ReleaseError("audited v4 source tree is unavailable or differs")

    matrix = _validate_matrix(read_json(matrix_path))
    snapshot = repository / matrix["candidate"]["resource"]["producer_snapshot"]
    resource_manifest_path = snapshot / "RESOURCE-MANIFEST.json"
    if resource_manifest_path.is_symlink():
        raise ReleaseError("bf1f producer manifest must not be a symlink")
    if file_record(resource_manifest_path) != BF1F_MANIFEST:
        raise ReleaseError("checked bf1f producer manifest bytes differ")
    resource_manifest = _validate_resource_manifest(read_json(resource_manifest_path))

    source_lock = _exact(
        read_json(lock_path), {"runtimes", "schema"}, "platform runtime lock"
    )
    if source_lock["schema"] != "kazstem-platform-runtime-lock-v1" or not isinstance(
        source_lock["runtimes"], list
    ):
        raise ReleaseError("platform runtime lock schema differs")
    darwin_indices = [
        index
        for index, record in enumerate(source_lock["runtimes"])
        if isinstance(record, dict)
        and record.get("platform") == {"system": "darwin", "machine": "arm64"}
    ]
    if len(darwin_indices) != 1:
        raise ReleaseError("platform lock lacks one exact Darwin arm64 entry")
    darwin_index = darwin_indices[0]
    expected_darwin = {
        "bundle_id": DARWIN_RUNTIME_ID,
        "manifest": DARWIN_RUNTIME_MANIFEST,
        "platform": {"system": "darwin", "machine": "arm64"},
        "resource_bundle_ids": [F03_RESOURCE_ID],
    }
    if source_lock["runtimes"][darwin_index] != expected_darwin:
        raise ReleaseError("tracked Darwin runtime lock is not exactly f03-only")
    if any(
        BF1F_RESOURCE_ID in record.get("resource_bundle_ids", [])
        for record in source_lock["runtimes"]
        if isinstance(record, dict)
        and record.get("platform") == {"system": "darwin", "machine": "arm64"}
    ):
        raise ReleaseError("tracked Darwin runtime lock already enables bf1f")

    candidate_lock = copy.deepcopy(source_lock)
    candidate_darwin = copy.deepcopy(expected_darwin)
    candidate_darwin["resource_bundle_ids"] = [BF1F_RESOURCE_ID]
    candidate_lock["runtimes"][darwin_index] = candidate_darwin
    for index, record in enumerate(source_lock["runtimes"]):
        if index != darwin_index and candidate_lock["runtimes"][index] != record:
            raise ReleaseError("bf1f candidate lock changed a non-Darwin entry")

    tools: list[dict[str, Any]] = []
    for gate in matrix["required_gates"]:
        tool_path = (repository / gate["tool"]).resolve(strict=True)
        try:
            tool_path.relative_to(repository)
        except ValueError as exc:
            raise ReleaseError("bf1f gate tool escapes the repository") from exc
        tools.append({"gate": gate["gate"], "path": gate["tool"], "file": file_record(tool_path)})

    args.candidate_lock_output.parent.mkdir(parents=True, exist_ok=True)
    args.candidate_lock_output.write_bytes(json_bytes(candidate_lock))
    candidate_record = file_record(args.candidate_lock_output)
    receipt = {
        "schema": RECEIPT_SCHEMA,
        "pass": True,
        "audited_source": matrix["audited_source"],
        "platform": matrix["platform"],
        "release_enabled": False,
        "native_validation_complete": False,
        "activation_status": matrix["status"],
        "activation_blockers": [
            "real-macos-15-arm64-native-runtime-validation",
            "complete-bf1f-behavior-matrix-without-skips",
            "independent-candidate-wheel-freezer-and-archive-reproduction",
            "reviewed-tracked-platform-lock-change",
        ],
        "matrix": {
            "path": MATRIX_PATH,
            "file": file_record(matrix_path),
            "required_gates": matrix["required_gates"],
            "behavior_cases": matrix["behavior_cases"],
        },
        "source_lock": {"path": PLATFORM_LOCK_PATH, "file": file_record(lock_path)},
        "candidate_lock": {
            "path": "candidate-platform-runtime-assets.lock.json",
            "file": candidate_record,
            "release_input": False,
        },
        "allowed_lock_change": {
            "platform": {"system": "darwin", "machine": "arm64"},
            "before_resource_bundle_ids": [F03_RESOURCE_ID],
            "after_resource_bundle_ids": [BF1F_RESOURCE_ID],
            "runtime_unchanged": {
                "bundle_id": DARWIN_RUNTIME_ID,
                "manifest": DARWIN_RUNTIME_MANIFEST,
            },
            "all_other_entries_byte_semantically_unchanged": True,
        },
        "candidate_resource": {
            "bundle_id": resource_manifest["bundle_id"],
            "version": resource_manifest["version"],
            "schema": resource_manifest["schema"],
            "manifest": file_record(resource_manifest_path),
            "required_files": sorted(REQUIRED_RESOURCE_FILES),
            "producer_snapshot": matrix["candidate"]["resource"][
                "producer_snapshot"
            ],
        },
        "checked_tools": tools,
    }
    assert_relative_json(receipt, label="bf1f validation preparation receipt")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(json_bytes(receipt))
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", required=True, type=Path)
    parser.add_argument("--matrix", required=True, type=Path)
    parser.add_argument("--platform-lock", required=True, type=Path)
    parser.add_argument("--candidate-lock-output", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    result = prepare(args)
    print(
        "PREPARED ONLY: bf1f remains disabled pending "
        f"{len(result['matrix']['required_gates'])} real macOS gates"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ReleaseError, OSError, ValueError, json.JSONDecodeError) as exc:
        raise SystemExit(f"error: {exc}") from exc
