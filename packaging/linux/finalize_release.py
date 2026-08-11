#!/usr/bin/env python3
"""Fail closed over all Linux publication artifacts and evidence."""

from __future__ import annotations

import argparse
import atexit
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import sys
import tempfile
import types
from typing import Any

def _source_module(name: str, path: Path) -> types.ModuleType:
    module = types.ModuleType(name)
    module.__file__ = str(path)
    sys.modules[name] = module
    source = path.read_bytes()
    exec(compile(source, str(path), "exec", dont_inherit=True), module.__dict__)
    return module


_tool_directory = Path(__file__).resolve().parent
_common = _source_module(
    "_kazstem_finalizer_release_common", _tool_directory / "release_common.py"
)
python_reproducibility = _source_module(
    "_kazstem_finalizer_python_reproducibility",
    _tool_directory / "verify_python_reproducibility.py",
)
READY_AUDIT_SCHEMA = _common.READY_AUDIT_SCHEMA
SOURCE_AUDIT_SCHEMA = _common.SOURCE_AUDIT_SCHEMA
EVIDENCE_PAYLOAD_SCHEMAS = _common.EVIDENCE_PAYLOAD_SCHEMAS
ReleaseError = _common.ReleaseError
archive_limits = _common.archive_limits
assert_relative_evidence = _common.assert_relative_evidence
decode_json = _common.decode_json
ensure_distinct_nonaliased_paths = _common.ensure_distinct_nonaliased_paths
ensure_output_outside = _common.ensure_output_outside
file_record = _common.file_record
identity_sha256 = _common.identity_sha256
inspect_tar = _common.inspect_tar
json_bytes = _common.json_bytes
load_identity = _common.load_identity
read_json = _common.read_json
ready_source_binding = _common.ready_source_binding
validate_compression_comparison = _common.validate_compression_comparison
validate_gate_envelope = _common.validate_gate_envelope
validate_source_authority_payload = _common.validate_source_authority_payload
verify_artifact = _common.verify_artifact
verify_file = _common.verify_file


SUMS_NAME = "SHA256SUMS"
IDENTITY_NAME = "RELEASE-IDENTITY.json"
EVIDENCE_SUMS_NAME = "EVIDENCE-SHA256SUMS"


def _snapshot_file(
    source: Path,
    destination: Path,
    *,
    expected: dict[str, Any] | None,
    max_bytes: int,
    label: str,
) -> dict[str, Any]:
    metadata = source.lstat()
    if source.is_symlink() or not stat.S_ISREG(metadata.st_mode):
        raise ReleaseError(f"{label} is not a regular non-symlink file")
    if metadata.st_nlink != 1 or metadata.st_size > max_bytes:
        raise ReleaseError(f"{label} is aliased or exceeds its snapshot cap")
    destination.parent.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256()
    copied = 0
    with source.open("rb") as input_file, destination.open("xb") as output_file:
        opened = os.fstat(input_file.fileno())
        if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
            raise ReleaseError(f"{label} changed before snapshot open")
        while chunk := input_file.read(1024 * 1024):
            copied += len(chunk)
            if copied > max_bytes:
                raise ReleaseError(f"{label} grew beyond its snapshot cap")
            digest.update(chunk)
            output_file.write(chunk)
        closed = os.fstat(input_file.fileno())
    current = source.lstat()
    if (
        (closed.st_dev, closed.st_ino, closed.st_size)
        != (opened.st_dev, opened.st_ino, opened.st_size)
        or (current.st_dev, current.st_ino, current.st_size)
        != (opened.st_dev, opened.st_ino, opened.st_size)
    ):
        raise ReleaseError(f"{label} changed during snapshot")
    record = {"bytes": copied, "sha256": digest.hexdigest()}
    if expected is not None and record != {
        "bytes": expected["bytes"],
        "sha256": expected["sha256"],
    }:
        raise ReleaseError(f"{label} snapshot differs from identity")
    destination.chmod(0o400)
    return record
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
    path: Path,
    gate: str,
    kind: str,
    subjects: list[str],
    identity: dict[str, Any],
    identity_digest: str,
    canonical_artifacts: Path,
) -> dict[str, Any]:
    if kind != "envelope":
        raise ReleaseError(f"evidence is not a structured envelope: {path.name}")
    envelope = read_json(path)
    value = validate_gate_envelope(
        envelope,
        identity=identity,
        identity_contract_sha256=identity_digest,
        gate=gate,
        subjects=subjects,
    )
    if value.get("schema") != EVIDENCE_PAYLOAD_SCHEMAS[gate]:
        raise ReleaseError(f"evidence has the wrong payload schema: {path.name}")
    if (
        value.get("release") != identity["release"]
        or value.get("source_commit") != identity["source_commit"]
    ):
        raise ReleaseError(
            f"evidence payload belongs to a different release/commit: {path.name}"
        )
    if not (value.get("pass") is True or value.get("result") == "pass"):
        raise ReleaseError(f"evidence payload is not an explicit pass: {path.name}")

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
    if gate == "source-authority":
        value = validate_source_authority_payload(value, identity=identity)
    if gate == "python-reproducibility":
        try:
            value = python_reproducibility.validate_reproducibility_payload(
                value,
                identity=identity,
                identity_contract_sha256=identity_digest,
                canonical_artifacts=canonical_artifacts,
            )
        except python_reproducibility.ReleaseError as exc:
            raise ReleaseError(f"Python reproducibility payload is invalid: {exc}") from exc
    if gate == "compression-comparison":
        value = validate_compression_comparison(
            value,
            identity=identity,
            identity_contract_sha256=identity_digest,
        )
    if gate == "optimization-ledger" and (
        value.get("final_behavior_gate") != "pass"
        or not isinstance(value.get("accepted"), list)
        or not isinstance(value.get("rejected"), list)
    ):
        raise ReleaseError("optimization ledger lacks an explicit final behavior pass")
    if gate == "source-suite" and (
        not isinstance(value.get("tests_run"), int)
        or isinstance(value.get("tests_run"), bool)
        or value["tests_run"] <= 0
        or value.get("tests_run") != value.get("tests_discovered")
        or value.get("failures") != 0
        or value.get("errors") != 0
        or value.get("unexpected_successes") != 0
        or not isinstance(value.get("skipped"), int)
        or not isinstance(value.get("expected_failures"), int)
    ):
        raise ReleaseError("source-suite structured counts are not a clean pass")
    if gate == "network-trace" and (
        value.get("forbidden_syscalls") != []
        or value.get("full_descendant_coverage") is not False
        or value.get("trace_truncated") is not False
    ):
        raise ReleaseError("network trace payload is incomplete")
    return value


def finalize(args: argparse.Namespace) -> dict[str, Any]:
    report_checksum_path = args.output.with_name(args.output.name + ".sha256")
    if report_checksum_path.exists() or report_checksum_path.is_symlink():
        raise ReleaseError("final report checksum sidecar already exists")
    ensure_output_outside(
        args.output, args.artifacts, label="finalization report output"
    )
    ensure_output_outside(
        args.output, args.evidence, label="finalization report output"
    )
    ensure_output_outside(
        report_checksum_path,
        args.artifacts,
        label="finalization report checksum output",
    )
    ensure_output_outside(
        report_checksum_path,
        args.evidence,
        label="finalization report checksum output",
    )
    if args.output.exists() or args.output.is_symlink():
        raise ReleaseError(f"finalization output already exists: {args.output}")
    if args.artifacts.is_symlink() or args.evidence.is_symlink():
        raise ReleaseError("artifact/evidence roots must not be symlinks")
    artifacts_dir = args.artifacts.resolve(strict=True)
    evidence_dir = args.evidence.resolve(strict=True)
    if any(path.is_symlink() for path in args.repro_root):
        raise ReleaseError("reproduction roots must not be symlinks")
    roots = [path.resolve(strict=True) for path in args.repro_root]
    identity_input = args.identity.resolve(strict=True)
    distinct_paths = [
        ("final report", args.output),
        ("final report checksum", report_checksum_path),
        ("release identity", identity_input),
        ("artifact root", artifacts_dir),
        ("evidence root", evidence_dir),
        *[(f"reproduction root {index}", root) for index, root in enumerate(roots)],
    ]
    for index, (first_label, first_path) in enumerate(distinct_paths):
        for second_label, second_path in distinct_paths[index + 1 :]:
            ensure_distinct_nonaliased_paths(
                first_path,
                second_path,
                labels=(first_label, second_label),
            )
    snapshot_root = Path(tempfile.mkdtemp(prefix="kazstem-finalizer-snapshot-"))
    def cleanup_snapshot() -> None:
        shutil.rmtree(snapshot_root, ignore_errors=True)
    atexit.register(cleanup_snapshot)
    identity_path = snapshot_root / "RELEASE-IDENTITY.json"
    identity_full_record = _snapshot_file(
        identity_input,
        identity_path,
        expected=None,
        max_bytes=64 * 1024**2,
        label="release identity",
    )
    identity = load_identity(identity_path)
    identity_digest = identity_sha256(identity_path)
    verify_file(
        Path(__file__).resolve(strict=True),
        identity["verification"]["finalizer"]["file"],
        label="running finalizer",
    )
    helper_records = {
        item["path"]: item["file"]
        for item in identity["verification"]["reproducibility"]["helpers"]
    }
    verify_file(
        Path(_common.__file__).resolve(strict=True),
        helper_records["packaging/linux/release_common.py"],
        label="loaded finalizer release_common",
    )
    python_gate = next(
        record
        for record in identity["verification"]["evidence"]
        if record["gate"] == "python-reproducibility"
    )
    verify_file(
        Path(python_reproducibility.__file__).resolve(strict=True),
        python_gate["execution"]["script"]["file"],
        label="loaded Python reproducibility validator",
    )
    artifacts = identity["artifacts"]
    expected_names = {record["filename"] for record in artifacts.values()}
    observed_names = {path.name for path in artifacts_dir.iterdir()}
    if observed_names != expected_names:
        raise ReleaseError(
            f"final artifact directory is not clean: missing={sorted(expected_names - observed_names)}, "
            f"extra={sorted(observed_names - expected_names)}"
        )
    snapshot_artifacts = snapshot_root / "artifacts"
    for name, expected in artifacts.items():
        _snapshot_file(
            artifacts_dir / expected["filename"],
            snapshot_artifacts / expected["filename"],
            expected=expected,
            max_bytes=expected["bytes"],
            label=f"final {name}",
        )

    ready_path = snapshot_artifacts / artifacts["ready_run"]["filename"]
    source_path = snapshot_artifacts / artifacts["corresponding_source"]["filename"]
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
    snapshot_evidence = snapshot_root / "evidence"
    for record in required_evidence:
        _snapshot_file(
            evidence_dir / record["path"],
            snapshot_evidence / record["path"],
            expected=record["file"],
            max_bytes=record["file"]["bytes"],
            label=f"release evidence {record['path']}",
        )
    evidence_by_gate = {
        record["gate"]: _gate_evidence(
            snapshot_evidence / record["path"],
            record["gate"],
            record["kind"],
            record["subjects"],
            identity,
            identity_digest,
            snapshot_artifacts,
        )
        for record in required_evidence
    }
    ready_audit = evidence_by_gate["ready-archive-audit"]
    if not (
        isinstance(ready_audit, dict)
        and ready_audit.get("schema") == READY_AUDIT_SCHEMA
        and ready_audit.get("archive") == artifacts["ready_run"]
        and ready_audit.get("identity_contract_sha256") == identity_digest
    ):
        raise ReleaseError("evidence lacks the exact ready-run archive audit")
    source_audit = evidence_by_gate["source-archive-audit"]
    if not (
        isinstance(source_audit, dict)
        and source_audit.get("schema") == SOURCE_AUDIT_SCHEMA
        and source_audit.get("archive") == artifacts["corresponding_source"]
        and source_audit.get("nested_archives_pass") is True
        and source_audit.get("identity_contract_sha256") == identity_digest
    ):
        raise ReleaseError("evidence lacks the exact corresponding-source nested audit")

    compression = evidence_by_gate["compression-comparison"]
    optimization = evidence_by_gate["optimization-ledger"]
    expected_optimization_fields = {
        "schema",
        "pass",
        "release",
        "source_commit",
        "source_tree",
        "identity_contract_sha256",
        "compression_evidence",
        "behavior_evidence",
        "selection_rule",
        "candidate_bindings",
        "selected_outputs",
        "accepted",
        "rejected",
        "behavior_gates",
        "final_behavior_gate",
    }
    if not isinstance(optimization, dict) or set(optimization) != expected_optimization_fields:
        raise ReleaseError("optimization ledger structure differs")
    evidence_record_by_gate = {
        record["gate"]: record for record in required_evidence
    }
    compression_record = evidence_record_by_gate["compression-comparison"]
    expected_compression_evidence = {
        "path": compression_record["path"],
        **file_record(evidence_dir / compression_record["path"]),
    }
    expected_behavior = {
        gate: {
            "path": evidence_record_by_gate[gate]["path"],
            **file_record(evidence_dir / evidence_record_by_gate[gate]["path"]),
        }
        for gate in ("blackbox", "practical")
    }
    expected_accepted = []
    expected_rejected = []
    expected_selected_outputs = {}
    for target in compression["targets"]:
        selected_candidate = next(
            candidate
            for candidate in target["candidates"]
            if candidate["name"] == target["selected"]
        )
        expected_selected_outputs[target["artifact"]] = target["selected_output"]
        expected_accepted.append(
            {
                "artifact": target["artifact"],
                "name": selected_candidate["name"],
                "filename": selected_candidate["filename"],
                "bytes": selected_candidate["bytes"],
                "sha256": selected_candidate["sha256"],
                "tradeoff": selected_candidate["tradeoff"],
                "reason": "exact minimum eligible compressed size and all behavior gates passed",
            }
        )
        expected_rejected.extend(
            {"artifact": target["artifact"], **item}
            for item in target["rejected"]
        )
    if (
        optimization["schema"]
        != EVIDENCE_PAYLOAD_SCHEMAS["optimization-ledger"]
        or optimization["pass"] is not True
        or optimization["release"] != identity["release"]
        or optimization["source_commit"] != identity["source_commit"]
        or optimization["source_tree"] != identity["source_tree"]
        or optimization["identity_contract_sha256"] != identity_digest
        or optimization["compression_evidence"] != expected_compression_evidence
        or optimization["behavior_evidence"] != expected_behavior
        or optimization["selection_rule"] != compression["selection_rule"]
        or optimization["candidate_bindings"] != compression["targets"]
        or optimization["selected_outputs"] != expected_selected_outputs
        or optimization["accepted"] != expected_accepted
        or optimization["rejected"] != expected_rejected
        or optimization["behavior_gates"] != ["blackbox", "practical"]
        or optimization["final_behavior_gate"] != "pass"
    ):
        raise ReleaseError("optimization ledger is not the exact checked decision")

    python_reproduction = evidence_by_gate["python-reproducibility"]
    build_receipts = {
        build.get("root"): build
        for build in python_reproduction["builds"]
        if isinstance(build, dict) and isinstance(build.get("root"), str)
    }
    if len(build_receipts) != len(python_reproduction["builds"]):
        raise ReleaseError("Python reproduction evidence has duplicate/invalid roots")
    if any(path.is_symlink() for path in args.repro_root):
        raise ReleaseError("reproduction roots must not be symlinks")
    roots = [path.resolve(strict=True) for path in args.repro_root]
    if (
        len(set(roots)) < identity["verification"]["minimum_distinct_roots"]
        or len(roots) != len(build_receipts)
    ):
        raise ReleaseError(
            "native reproduction roots do not match fresh-build evidence receipts"
        )
    observed_receipt_labels: set[str] = set()
    observed_inodes: set[tuple[int, int]] = set()
    root_expectations: list[tuple[Path, str, dict[str, Any]]] = []
    for index, root in enumerate(roots):
        for other in roots[index + 1 :]:
            if root in other.parents or other in root.parents:
                raise ReleaseError("reproduction roots must not contain one another")
        observed_names = {path.name for path in root.iterdir()}
        expected_root_names = {
            artifacts["ready_run"]["filename"],
            artifacts["corresponding_source"]["filename"],
            "REPRODUCTION-RECEIPT.json",
        }
        if observed_names != expected_root_names:
            raise ReleaseError("reproduction root is not a sealed receipt directory")
        receipt_path = root / "REPRODUCTION-RECEIPT.json"
        receipt_snapshot_path = (
            snapshot_root / "reproduction-receipts" / f"root-{index:02d}.json"
        )
        receipt_snapshot_record = _snapshot_file(
            receipt_path,
            receipt_snapshot_path,
            expected=None,
            max_bytes=64 * 1024**2,
            label=f"reproduction receipt {index}",
        )
        receipt = read_json(receipt_snapshot_path)
        if not isinstance(receipt, dict):
            raise ReleaseError("reproduction receipt is not a JSON object")
        label = receipt.get("root")
        build = build_receipts.get(label)
        if build is None or label in observed_receipt_labels:
            raise ReleaseError("reproduction receipt label is missing or duplicated")
        observed_receipt_labels.add(label)
        expected_receipt = build.get("receipt")
        if not isinstance(expected_receipt, dict) or expected_receipt.get(
            "path"
        ) != f"{label}/native/REPRODUCTION-RECEIPT.json":
            raise ReleaseError("reproduction envelope receipt path differs")
        if receipt_snapshot_record != {
            "bytes": expected_receipt.get("bytes"),
            "sha256": expected_receipt.get("sha256"),
        }:
            raise ReleaseError(f"reproduction receipt {label} file identity differs")
        root_expectations.append((root, label, expected_receipt))
        expected_receipt_payload = {
            "schema": "kazstem-reproduction-root-receipt-v1",
            "release": identity["release"],
            "source_commit": identity["source_commit"],
            "source_tree": identity["source_tree"],
            "source_ref": identity["source_ref"],
            "source_tag_object": identity["source_tag_object"],
            "identity_contract_sha256": identity_digest,
            "root": label,
            "checkout": build["checkout"],
            "python_build": build["canonical_python_build"],
            "frozen_build": build["frozen_build"],
            "assembly": build["native_assembly"],
            "bound_inputs": {
                name: identity["inputs"][name]
                for name in (
                    "frozen_tree",
                    "resource_tree",
                    "runtime_tree",
                    "source_payload_tree",
                    "git_archive",
                )
            },
            "artifacts": artifacts,
            "commands_succeeded": True,
            "filesystem_aliases": [],
        }
        if receipt != expected_receipt_payload:
            raise ReleaseError(
                "reproduction root receipt is not the exact fresh-build projection"
            )
        if (
            receipt.get("schema") != "kazstem-reproduction-root-receipt-v1"
            or receipt.get("release") != identity["release"]
            or receipt.get("source_commit") != identity["source_commit"]
            or receipt.get("source_tree") != identity["source_tree"]
            or receipt.get("identity_contract_sha256") != identity_digest
            or receipt.get("artifacts") != artifacts
            or receipt.get("commands_succeeded") is not True
            or receipt.get("filesystem_aliases") != []
        ):
            raise ReleaseError("reproduction receipt does not bind this release")
        for name in ("ready_run", "corresponding_source"):
            expected = artifacts[name]
            artifact_path = root / expected["filename"]
            verify_artifact(
                artifact_path,
                expected,
                label=f"reproduction root {index} {name}",
            )
            metadata = artifact_path.stat()
            inode = (metadata.st_dev, metadata.st_ino)
            if metadata.st_nlink != 1 or inode in observed_inodes:
                raise ReleaseError("reproduction root artifacts are hard-linked/aliased")
            observed_inodes.add(inode)
    if observed_receipt_labels != set(build_receipts):
        raise ReleaseError("not every fresh-build receipt has a reproduction root")

    # Recheck every mutable input immediately before creating publication
    # sidecars.  All semantic parsing above used the private immutable snapshot.
    if file_record(identity_input) != identity_full_record:
        raise ReleaseError("release identity changed during finalization")
    for relative, expected_record in (
        (record["path"], record["file"]) for record in required_evidence
    ):
        if file_record(evidence_dir / relative) != expected_record:
            raise ReleaseError(f"evidence changed during finalization: {relative}")
    for name, expected in artifacts.items():
        verify_artifact(
            artifacts_dir / expected["filename"],
            expected,
            label=f"pre-sidecar artifact {name}",
        )

    evidence_full_records = {
        record["path"]: record["file"]
        for record in required_evidence
    }
    identity_sidecar = artifacts_dir / IDENTITY_NAME
    evidence_sums_path = artifacts_dir / EVIDENCE_SUMS_NAME
    sums_path = artifacts_dir / SUMS_NAME
    for sidecar in (identity_sidecar, evidence_sums_path, sums_path):
        if sidecar.exists() or sidecar.is_symlink():
            raise ReleaseError(f"finalization sidecar already exists: {sidecar.name}")
    shutil.copyfile(identity_path, identity_sidecar)
    evidence_rows = "".join(
        f"{record['sha256']}  {record['bytes']}  {relative}\n"
        for relative, record in sorted(evidence_full_records.items())
    )
    evidence_sums_path.write_text(evidence_rows, encoding="utf-8")
    sidecar_records = {
        IDENTITY_NAME: file_record(identity_sidecar),
        EVIDENCE_SUMS_NAME: file_record(evidence_sums_path),
    }
    sums = "".join(
        f"{record['sha256']}  {filename}\n"
        for filename, record in sorted(
            {
                **{record["filename"]: record for record in artifacts.values()},
                **sidecar_records,
            }.items()
        )
    )
    sums_path.write_text(sums, encoding="utf-8")
    if file_record(identity_input) != identity_full_record:
        raise ReleaseError("release identity changed during finalization")
    if file_record(identity_sidecar) != identity_full_record:
        raise ReleaseError("finalized identity sidecar differs from its input")
    for relative, expected_record in evidence_full_records.items():
        if file_record(evidence_dir / relative) != expected_record:
            raise ReleaseError(f"evidence changed during finalization: {relative}")
    for name, expected in artifacts.items():
        verify_artifact(
            artifacts_dir / expected["filename"],
            expected,
            label=f"final rehash {name}",
        )
    permitted = expected_names | {SUMS_NAME, IDENTITY_NAME, EVIDENCE_SUMS_NAME}
    final_names = {path.name for path in artifacts_dir.iterdir()}
    if final_names != permitted:
        raise ReleaseError(
            f"final artifact directory has unexpected entries: {sorted(final_names ^ permitted)}"
        )
    for root, label, receipt_record in root_expectations:
        expected_root_names = {
            artifacts["ready_run"]["filename"],
            artifacts["corresponding_source"]["filename"],
            "REPRODUCTION-RECEIPT.json",
        }
        if {path.name for path in root.iterdir()} != expected_root_names:
            raise ReleaseError(f"reproduction root mutated: {label}")
        verify_file(
            root / "REPRODUCTION-RECEIPT.json",
            {"bytes": receipt_record["bytes"], "sha256": receipt_record["sha256"]},
            label=f"final reproduction receipt {label}",
        )
        for name in ("ready_run", "corresponding_source"):
            verify_artifact(
                root / artifacts[name]["filename"],
                artifacts[name],
                label=f"final reproduction root {label} {name}",
            )

    report = {
        "schema": "kazstem-linux-release-finalization-v3",
        "pass": True,
        "release": identity["release"],
        "source_commit": identity["source_commit"],
        "source_tree": identity["source_tree"],
        "source_origin": identity["source_origin"],
        "source_ref": identity["source_ref"],
        "release_url": identity["release_url"],
        "identity_contract_sha256": identity_digest,
        "artifacts": artifacts,
        "finalized_identity": {"filename": IDENTITY_NAME, **identity_full_record},
        "evidence_files": evidence_full_records,
        "evidence_ledger": {
            "filename": EVIDENCE_SUMS_NAME,
            **file_record(evidence_sums_path),
        },
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
    report_record = file_record(args.output)
    report_checksum_path.write_text(
        f"{report_record['sha256']}  {args.output.name}\n", encoding="utf-8"
    )
    if file_record(args.output) != report_record:
        raise ReleaseError("final platform report changed while writing its checksum")
    if file_record(identity_input) != identity_full_record:
        raise ReleaseError("release identity changed before final success")
    for relative, expected_record in evidence_full_records.items():
        if file_record(evidence_dir / relative) != expected_record:
            raise ReleaseError(f"evidence changed before final success: {relative}")
    for name, expected in artifacts.items():
        verify_artifact(
            artifacts_dir / expected["filename"],
            expected,
            label=f"pre-success artifact {name}",
        )
    for root, label, receipt_record in root_expectations:
        if {path.name for path in root.iterdir()} != {
            artifacts["ready_run"]["filename"],
            artifacts["corresponding_source"]["filename"],
            "REPRODUCTION-RECEIPT.json",
        }:
            raise ReleaseError(f"reproduction root changed before success: {label}")
        verify_file(
            root / "REPRODUCTION-RECEIPT.json",
            {"bytes": receipt_record["bytes"], "sha256": receipt_record["sha256"]},
            label=f"pre-success reproduction receipt {label}",
        )
    cleanup_snapshot()
    atexit.unregister(cleanup_snapshot)
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
