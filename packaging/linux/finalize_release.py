#!/usr/bin/env python3
"""Fail closed over all Linux publication artifacts and evidence."""

from __future__ import annotations

import argparse
import json
from pathlib import Path, PurePosixPath
import re
from typing import Any

from release_common import (
    READY_AUDIT_SCHEMA,
    SOURCE_AUDIT_SCHEMA,
    ReleaseError,
    assert_relative_evidence,
    decode_json,
    ensure_output_outside,
    file_record,
    identity_sha256,
    inspect_tar,
    json_bytes,
    load_identity,
    read_json,
    ready_source_binding,
    verify_artifact,
    verify_file,
    archive_limits,
)


SUMS_NAME = "SHA256SUMS"
EVIDENCE_SCHEMAS = {
    "blackbox": "kazstem-linux-blackbox-v1",
    "compatibility-performance": "kazstem-linux-mystem-json-performance-v2",
    "compression-comparison": "kazstem-linux-compression-comparison-v1",
    "elf-closure": "kazstem-linux-elf-closure-v1",
    "optimization-ledger": "kazstem-linux-final-optimization-decision-ledger-v1",
    "practical": "kazstem-linux-practical-matrix-v1",
    "python-reproducibility": "kazstem-python-artifact-reproducibility-v1",
    "ready-archive-audit": READY_AUDIT_SCHEMA,
    "runtime-provenance": "kazstem-linux-runtime-provenance-v2",
    "source-archive-audit": SOURCE_AUDIT_SCHEMA,
}


def _read_tar_json(
    path: Path, member_name: str, *, max_bytes: int = 4 * 1024**2
) -> Any:
    import tarfile

    with tarfile.open(path, "r:*") as archive:
        try:
            member = archive.getmember(member_name)
        except KeyError as exc:
            raise ReleaseError(f"archive lacks required member: {member_name}") from exc
        if not member.isfile() or member.size > max_bytes:
            raise ReleaseError(f"invalid embedded JSON member: {member_name}")
        source = archive.extractfile(member)
        if source is None:
            raise ReleaseError(f"cannot read embedded JSON member: {member_name}")
        data = source.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise ReleaseError(f"embedded JSON exceeds cap: {member_name}")
    return decode_json(data, label=f"embedded {member_name}")


def _gate_evidence(
    path: Path, gate: str, kind: str, identity: dict[str, Any]
) -> dict[str, Any] | None:
    value: dict[str, Any] | None = None
    if kind in {"json", "json-pass"}:
        value = read_json(path)
        if not isinstance(value, dict):
            raise ReleaseError(f"evidence is not a JSON object: {path.name}")
        if value.get("schema") != EVIDENCE_SCHEMAS[gate]:
            raise ReleaseError(f"evidence has the wrong gate schema: {path.name}")
        if (
            value.get("release") != identity["release"]
            or value.get("source_commit") != identity["source_commit"]
        ):
            raise ReleaseError(
                f"evidence belongs to a different release/commit: {path.name}"
            )
        if kind == "json-pass" and not (
            value.get("pass") is True or value.get("result") == "pass"
        ):
            raise ReleaseError(f"evidence is not an explicit JSON pass: {path.name}")
    else:
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeError as exc:
            raise ReleaseError(f"text evidence is not UTF-8: {path.name}") from exc
        if gate == "source-suite" and (
            re.search(r"(?m)^OK(?:\s|$)", text) is None
            or "FAILED" in text
            or "Traceback" in text
        ):
            raise ReleaseError(
                "source-suite evidence does not record a clean unittest pass"
            )
        if gate == "network-trace" and re.search(
            r"\b(?:socket|connect|accept|bind|listen|send\w*|recv\w*|shutdown|setsockopt|getsockopt)\(",
            text,
        ):
            raise ReleaseError("network trace records a forbidden network syscall")
        return None

    if gate == "blackbox" and (
        not isinstance(value.get("tests"), int)
        or value["tests"] < 13
        or value.get("unsupported_special_entries") != []
        or value.get("neural_weight_files") != []
    ):
        raise ReleaseError("black-box evidence does not satisfy the release contract")
    if gate == "practical" and (
        not isinstance(value.get("cases"), int)
        or value["cases"] < 70
        or value.get("bundle_fingerprint_unchanged") is not True
        or value.get("read_only_resource_runtime_unchanged") is not True
        or value.get("network_tls_modules_absent") is not True
        or value.get("lingering_native_processes") != []
    ):
        raise ReleaseError("practical evidence does not satisfy the release contract")
    if gate == "compatibility-performance" and (
        value.get("output_identity") is not True
        or not isinstance(value.get("runs"), list)
        or len(value["runs"]) < 2
    ):
        raise ReleaseError("compatibility performance evidence is incomplete")
    if gate == "elf-closure" and any(
        value.get(field) != []
        for field in ("missing", "escaped", "banned_dependencies", "banned_modules")
    ):
        raise ReleaseError(
            "ELF closure evidence contains an unresolved/banned dependency"
        )
    if gate == "runtime-provenance" and (
        value.get("schema") != "kazstem-linux-runtime-provenance-v2"
        or value.get("official") is not True
        or value.get("verified") is not True
        or value.get("non_official_reasons") != []
    ):
        raise ReleaseError("runtime provenance is not official and fully verified")
    if gate == "python-reproducibility" and (
        not isinstance(value.get("wheel_direct_builds"), int)
        or isinstance(value.get("wheel_direct_builds"), bool)
        or value["wheel_direct_builds"] < 3
        or not isinstance(value.get("sdist_direct_builds"), int)
        or isinstance(value.get("sdist_direct_builds"), bool)
        or value["sdist_direct_builds"] < 3
        or value.get("sdist_to_wheel_identity") is not True
    ):
        raise ReleaseError("canonical Python artifact reproducibility is incomplete")
    if gate == "compression-comparison" and (
        not isinstance(value.get("candidates"), list)
        or len(value["candidates"]) < 2
        or not isinstance(value.get("selected"), str)
        or not value["selected"]
        or any(
            not isinstance(candidate, dict)
            or candidate.get("byte_identical") is not True
            for candidate in value["candidates"]
        )
    ):
        raise ReleaseError("compression comparison is incomplete or non-reproducible")
    if gate == "optimization-ledger" and (
        value.get("final_behavior_gate") != "pass"
        or not isinstance(value.get("accepted"), list)
        or not isinstance(value.get("rejected"), list)
    ):
        raise ReleaseError("optimization ledger lacks an explicit final behavior pass")
    return value


def finalize(args: argparse.Namespace) -> dict[str, Any]:
    ensure_output_outside(
        args.output, args.artifacts, label="finalization report output"
    )
    if args.output.exists() or args.output.is_symlink():
        raise ReleaseError(f"finalization output already exists: {args.output}")
    identity_path = args.identity.resolve(strict=True)
    identity = load_identity(identity_path)
    if args.artifacts.is_symlink() or args.evidence.is_symlink():
        raise ReleaseError("artifact/evidence roots must not be symlinks")
    artifacts_dir = args.artifacts.resolve(strict=True)
    evidence_dir = args.evidence.resolve(strict=True)
    artifacts = identity["artifacts"]
    expected_names = {record["filename"] for record in artifacts.values()}
    observed_names = {path.name for path in artifacts_dir.iterdir()}
    permitted = expected_names | {SUMS_NAME}
    if observed_names - permitted or not expected_names <= observed_names:
        raise ReleaseError(
            f"final artifact directory is not clean: missing={sorted(expected_names - observed_names)}, "
            f"extra={sorted(observed_names - permitted)}"
        )
    for name, expected in artifacts.items():
        verify_artifact(
            artifacts_dir / expected["filename"], expected, label=f"final {name}"
        )

    ready_path = artifacts_dir / artifacts["ready_run"]["filename"]
    source_path = artifacts_dir / artifacts["corresponding_source"]["filename"]
    inspect_tar(
        ready_path,
        limits=archive_limits(identity, "ready_run"),
        expected_top=identity["ready_run"]["top_level"],
    )
    inspect_tar(
        source_path,
        limits=archive_limits(identity, "corresponding_source"),
        expected_top=identity["corresponding_source"]["top_level"],
    )
    binding_member = f"{identity['ready_run']['top_level']}/CORRESPONDING-SOURCE.json"
    if _read_tar_json(ready_path, binding_member) != ready_source_binding(identity):
        raise ReleaseError(
            "final ready-run archive has the wrong source URL/checksum binding"
        )

    required_evidence = identity["verification"]["evidence"]
    required_evidence_paths = {record["path"] for record in required_evidence}
    observed_evidence_paths: set[str] = set()
    observed_evidence_directories: set[str] = set()
    for path in evidence_dir.rglob("*"):
        relative = path.relative_to(evidence_dir).as_posix()
        if path.is_symlink():
            raise ReleaseError(f"symlink is forbidden in final evidence: {relative}")
        if path.is_file():
            observed_evidence_paths.add(relative)
        elif path.is_dir():
            observed_evidence_directories.add(relative)
        else:
            raise ReleaseError(
                f"special entry is forbidden in final evidence: {relative}"
            )
    if observed_evidence_paths != required_evidence_paths:
        raise ReleaseError(
            "final evidence inventory differs from identity "
            f"(missing={sorted(required_evidence_paths - observed_evidence_paths)}, "
            f"extra={sorted(observed_evidence_paths - required_evidence_paths)})"
        )
    expected_directories = {
        parent.as_posix()
        for relative in required_evidence_paths
        for parent in PurePosixPath(relative).parents
        if parent.as_posix() != "."
    }
    if observed_evidence_directories != expected_directories:
        raise ReleaseError("final evidence has missing or extra directories")
    assert_relative_evidence(evidence_dir)
    for record in required_evidence:
        path = evidence_dir / record["path"]
        verify_file(path, record["file"], label=f"release evidence {record['path']}")
        _gate_evidence(path, record["gate"], record["kind"], identity)
    evidence_by_gate = {
        record["gate"]: read_json(evidence_dir / record["path"])
        for record in required_evidence
        if record["kind"] in {"json", "json-pass"}
    }
    ready_audit = evidence_by_gate["ready-archive-audit"]
    if not (
        isinstance(ready_audit, dict)
        and ready_audit.get("schema") == READY_AUDIT_SCHEMA
        and ready_audit.get("archive") == artifacts["ready_run"]
    ):
        raise ReleaseError("evidence lacks the exact ready-run archive audit")
    source_audit = evidence_by_gate["source-archive-audit"]
    if not (
        isinstance(source_audit, dict)
        and source_audit.get("schema") == SOURCE_AUDIT_SCHEMA
        and source_audit.get("archive") == artifacts["corresponding_source"]
        and source_audit.get("nested_archives_pass") is True
    ):
        raise ReleaseError("evidence lacks the exact corresponding-source nested audit")

    if any(path.is_symlink() for path in args.repro_root):
        raise ReleaseError("reproduction roots must not be symlinks")
    roots = [path.resolve(strict=True) for path in args.repro_root]
    if len(set(roots)) < identity["verification"]["minimum_distinct_roots"]:
        raise ReleaseError("insufficient distinct native reproduction roots")
    for index, root in enumerate(roots):
        for other in roots[index + 1 :]:
            if root in other.parents or other in root.parents:
                raise ReleaseError("reproduction roots must not contain one another")
        for name in ("ready_run", "corresponding_source"):
            expected = artifacts[name]
            verify_artifact(
                root / expected["filename"],
                expected,
                label=f"reproduction root {index} {name}",
            )

    sums_path = artifacts_dir / SUMS_NAME
    sums = "".join(
        f"{record['sha256']}  {record['filename']}\n"
        for record in sorted(artifacts.values(), key=lambda item: item["filename"])
    )
    if sums_path.exists():
        if sums_path.is_symlink() or sums_path.read_text(encoding="utf-8") != sums:
            raise ReleaseError(
                "existing global SHA256SUMS differs from exact release identity"
            )
    else:
        sums_path.write_text(sums, encoding="utf-8")
    final_names = {path.name for path in artifacts_dir.iterdir()}
    if final_names != permitted:
        raise ReleaseError(
            f"final artifact directory has unexpected entries: {sorted(final_names ^ permitted)}"
        )

    report = {
        "schema": "kazstem-linux-release-finalization-v2",
        "pass": True,
        "release": identity["release"],
        "source_commit": identity["source_commit"],
        "release_url": identity["release_url"],
        "identity_contract_sha256": identity_sha256(identity_path),
        "artifacts": artifacts,
        "sha256sums": {"filename": SUMS_NAME, **file_record(sums_path)},
        "required_evidence": [record["path"] for record in required_evidence],
        "distinct_reproduction_roots": len(set(roots)),
        "reproducible_artifacts": [
            artifacts["ready_run"]["filename"],
            artifacts["corresponding_source"]["filename"],
        ],
        "publication_requirement": "Publish the corresponding-source archive before or together with the ready-run archive at the exact recorded URLs.",
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(json_bytes(report))
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--identity", required=True, type=Path)
    parser.add_argument("--artifacts", required=True, type=Path)
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--repro-root", required=True, action="append", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    result = finalize(args)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ReleaseError, OSError, ValueError, json.JSONDecodeError) as exc:
        raise SystemExit(f"error: {exc}") from exc
