#!/usr/bin/env python3
"""Fail closed over all macOS publication artifacts and evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
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
    verify_darwin_loader_provenance,
    verify_file,
    validate_gate_envelope,
    archive_limits,
)


SUMS_NAME = "SHA256SUMS"
EVIDENCE_SCHEMAS = {
    "blackbox": "kazstem-macos-blackbox-v1",
    "compatibility-performance": "kazstem-macos-mystem-json-performance-v2",
    "compression-comparison": "kazstem-macos-compression-comparison-v2",
    "macho-closure": "kazstem-macos-macho-closure-v1",
    "module-native-inclusion": "kazstem-macos-module-native-inclusion-v1",
    "optimization-ledger": "kazstem-macos-final-optimization-decision-ledger-v1",
    "practical": "kazstem-macos-practical-matrix-v1",
    "python-reproducibility": "kazstem-python-artifact-reproducibility-v2",
    "ready-archive-audit": READY_AUDIT_SCHEMA,
    "runtime-provenance": "kazstem-macos-runtime-provenance-v2",
    "source-archive-audit": SOURCE_AUDIT_SCHEMA,
    "network-trace": "kazstem-macos-network-trace-v1",
    "source-suite": "kazstem-macos-source-suite-v1",
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
    path: Path,
    gate: str,
    kind: str,
    subjects: list[str],
    identity: dict[str, Any],
    identity_digest: str,
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
    if value.get("schema") != EVIDENCE_SCHEMAS[gate]:
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
        or value.get("resource_bundle_id")
        != identity["inputs"]["resource_tree"]["bundle_id"]
        or not isinstance(value.get("resource_version"), str)
        or not value["resource_version"]
        or value.get("unsupported_special_entries") != []
        or value.get("neural_weight_files") != []
    ):
        raise ReleaseError("black-box evidence does not satisfy the release contract")
    if gate == "practical":
        coverage = value.get("coverage")
        loader = (
            coverage.get("loader_environment")
            if isinstance(coverage, dict)
            else None
        )
        productive = (
            coverage.get("bf1f_productive_generation")
            if isinstance(coverage, dict)
            else None
        )
        if (
            not isinstance(value.get("cases"), int)
            or value["cases"] < 70
            or value.get("bundle_fingerprint_unchanged") is not True
            or value.get("read_only_resource_runtime_unchanged") is not True
            or value.get("network_tls_modules_absent") is not True
            or value.get("lingering_native_processes") != []
            or value.get("resource_bundle_id")
            != identity["inputs"]["resource_tree"]["bundle_id"]
            or not isinstance(value.get("resource_schema"), str)
            or not value["resource_schema"]
            or loader
            != {
                "clean_parent_official_gate": True,
                "hostile_parent_non_official_probe": (
                    "kazstem-hostile-loader-scrub-probe-v1"
                ),
                "captured_names": [
                    "DYLD_FUTURE_INJECTOR",
                    "DYLD_INSERT_LIBRARIES",
                    "DYLD_LIBRARY_PATH",
                    "LD_FUTURE_INJECTOR",
                ],
                "glibc_tunables_captured": True,
                "helper_environment_scrubbed": True,
            }
            or not isinstance(productive, dict)
            or productive.get("probe_schema")
            != "kazstem-bf1f-productive-generation-probe-v1"
        ):
            raise ReleaseError(
                "practical evidence does not satisfy the release contract"
            )
        requires_productive = (
            value["resource_schema"] == "qazmorph-resource-manifest-v4"
        )
        if productive != {
            "required": requires_productive,
            "executed_cases": 14 if requires_productive else 0,
            "probe_schema": "kazstem-bf1f-productive-generation-probe-v1",
        }:
            raise ReleaseError("bf1f practical generation evidence is incomplete")
    if gate == "compatibility-performance" and (
        value.get("output_identity") is not True
        or not isinstance(value.get("runs"), list)
        or len(value["runs"]) < 2
    ):
        raise ReleaseError("compatibility performance evidence is incomplete")
    if gate == "macho-closure" and any(
        value.get(field) != []
        for field in ("missing", "escaped", "banned_dependencies", "banned_modules")
    ):
        raise ReleaseError(
            "Mach-O closure evidence contains an unresolved/banned dependency"
        )
    if gate == "macho-closure" and (
        value.get("architectures") != ["arm64"]
        or value.get("fat_files") != []
        or value.get("non_system_absolute_dependencies") != []
        or value.get("codesign_strict_failures") != []
        or value.get("container_signature_failures") != []
        or not isinstance(value.get("signed_containers"), list)
        or not value["signed_containers"]
        or any(
            container.get("strict_deep") is not True
            or container.get("signature") != "adhoc"
            or container.get("team_identifier") is not None
            or container.get("authorities") != []
            for container in value["signed_containers"]
        )
        or value.get("signature_kind") != "adhoc"
        or value.get("team_identifiers") != []
        or value.get("developer_id_signed") is not False
        or value.get("notarized") is not False
        or value.get("stapled") is not False
        or value.get("maximum_minimum_os") != identity["platform"]["minimum_os"]
        or value.get("runtime_manifest_verified") is not True
        or value.get("runtime_bundle_id")
        != identity["inputs"]["runtime_tree"]["bundle_id"]
    ):
        raise ReleaseError("Mach-O architecture/signature/runtime policy is incomplete")
    if gate == "runtime-provenance":
        if (
            value.get("schema") != "kazstem-macos-runtime-provenance-v2"
            or value.get("official") is not True
            or value.get("verified") is not True
            or value.get("non_official_reasons") != []
            or value.get("runtime_bundle_id")
            != identity["inputs"]["runtime_tree"]["bundle_id"]
            or value.get("resource_bundle_id")
            != identity["inputs"]["resource_tree"]["bundle_id"]
            or value.get("force_rehash") is not True
        ):
            raise ReleaseError(
                "runtime provenance is not official and fully verified"
            )
        loader_environment = verify_darwin_loader_provenance(
            value.get("provenance")
        )
        if value.get("loader_environment") != loader_environment:
            raise ReleaseError(
                "runtime provenance loader summary is not independently reproduced"
            )
    if gate == "python-reproducibility" and (
        not isinstance(value.get("wheel_direct_builds"), int)
        or isinstance(value.get("wheel_direct_builds"), bool)
        or value["wheel_direct_builds"] < 2
        or not isinstance(value.get("sdist_direct_builds"), int)
        or isinstance(value.get("sdist_direct_builds"), bool)
        or value["sdist_direct_builds"] < 2
        or value.get("sdist_to_wheel_identity") is not True
        or value.get("native_direct_assemblies", 0) < 2
        or value.get("fresh_frozen_builds", 0) < 2
        or value.get("frozen_tree_identity") is not True
        or value.get("filesystem_aliases") != []
    ):
        raise ReleaseError("canonical Python artifact reproducibility is incomplete")
    if gate == "python-reproducibility":
        builds = value.get("builds")
        if not isinstance(builds, list) or len(builds) < 2:
            raise ReleaseError("reproducibility lacks distinct fresh builds")
        root_ids = [build.get("root") for build in builds if isinstance(build, dict)]
        if len(root_ids) != len(builds) or len(set(root_ids)) != len(root_ids):
            raise ReleaseError("reproducibility root identities are missing/aliased")
        expected_tree = identity["inputs"]["frozen_tree"]
        for build in builds:
            frozen = build.get("frozen_build")
            native = build.get("native_assembly")
            if (
                not isinstance(frozen, dict)
                or frozen.get("output_tree") != expected_tree
                or frozen.get("fresh_environment") is not True
                or not isinstance(frozen.get("commands"), list)
                or len(frozen["commands"]) < 3
                or any(
                    command.get("exit_status") != 0 for command in frozen["commands"]
                )
                or any(
                    command.get("capture", {}).get("process_group_reaped") is not True
                    or command.get("capture", {}).get("stream_cap_bytes")
                    != 16 * 1024 * 1024
                    or not isinstance(
                        command.get("capture", {}).get("timeout_seconds"), int
                    )
                    for command in frozen["commands"]
                )
                or not isinstance(native, dict)
                or native.get("used_frozen_tree") != expected_tree
            ):
                raise ReleaseError(
                    "a native reproduction reused or failed to build its freezer tree"
                )
            for asset_name, receipt_schema in (
                ("corresponding_source", "kazstem-macos-source-assembly-receipt-v1"),
                ("ready_run", "kazstem-macos-ready-assembly-receipt-v1"),
            ):
                assembly = native.get(asset_name)
                receipt = (
                    assembly.get("receipt") if isinstance(assembly, dict) else None
                )
                payload = receipt.get("payload") if isinstance(receipt, dict) else None
                expected_tar = identity["compression"][asset_name]["canonical_tar"]
                if (
                    not isinstance(receipt, dict)
                    or set(receipt) != {"path", "file", "payload"}
                    or not isinstance(receipt["path"], str)
                    or not isinstance(receipt["file"], dict)
                    or not isinstance(payload, dict)
                    or payload.get("schema") != receipt_schema
                    or payload.get("result") != "pass"
                    or payload.get("archive") != identity["artifacts"][asset_name]
                    or payload.get("canonical_tar")
                    != {
                        "filename": expected_tar["filename"],
                        "bytes": expected_tar["bytes"],
                        "sha256": expected_tar["sha256"],
                    }
                    or assembly.get("canonical_tar") != payload.get("canonical_tar")
                    or receipt["file"]
                    != {
                        "bytes": len(json_bytes(payload)),
                        "sha256": hashlib.sha256(json_bytes(payload)).hexdigest(),
                    }
                ):
                    raise ReleaseError(
                        f"native reproduction lacks exact raw-tar receipt: {asset_name}"
                    )
    if gate == "compression-comparison":
        assets = value.get("assets")
        if not isinstance(assets, dict) or set(assets) != {
            "ready_run",
            "corresponding_source",
        }:
            raise ReleaseError("compression comparison lacks both release assets")
        for asset_name, comparison in assets.items():
            if not isinstance(comparison, dict):
                raise ReleaseError("compression comparison asset is malformed")
            candidates = comparison.get("candidates")
            selected = comparison.get("selected")
            canonical_tar = comparison.get("canonical_tar")
            producer_receipts = (
                canonical_tar.get("producer_receipts")
                if isinstance(canonical_tar, dict)
                else None
            )
            if (
                not isinstance(candidates, list)
                or {candidate.get("format") for candidate in candidates}
                != {"gzip", "xz", "zstd"}
                or not isinstance(canonical_tar, dict)
                or canonical_tar.get("sha256")
                != identity["compression"][asset_name]["canonical_tar"]["sha256"]
                or canonical_tar.get("bytes")
                != identity["compression"][asset_name]["canonical_tar"]["bytes"]
                or canonical_tar.get("producer")
                != identity["compression"][asset_name]["canonical_tar"]["producer"]
                or not isinstance(producer_receipts, list)
                or len(producer_receipts) < 2
                or len({receipt.get("root") for receipt in producer_receipts})
                != len(producer_receipts)
                or any(
                    not isinstance(receipt, dict)
                    or set(receipt) != {"root", "path", "file", "canonical_tar"}
                    or receipt.get("canonical_tar")
                    != {
                        "filename": identity["compression"][asset_name][
                            "canonical_tar"
                        ]["filename"],
                        "bytes": identity["compression"][asset_name]["canonical_tar"][
                            "bytes"
                        ],
                        "sha256": identity["compression"][asset_name]["canonical_tar"][
                            "sha256"
                        ],
                    }
                    or not isinstance(receipt.get("file"), dict)
                    for receipt in producer_receipts
                )
                or any(
                    not isinstance(candidate, dict)
                    or candidate.get("byte_identical") is not True
                    or candidate.get("builds_identical") is not True
                    or candidate.get("roundtrip_tar_sha256")
                    != canonical_tar.get("sha256")
                    or candidate.get("roundtrip_tree_sha256")
                    != canonical_tar.get("tree_sha256")
                    or not isinstance(candidate.get("bytes"), int)
                    or candidate["bytes"] <= 0
                    or not isinstance(candidate.get("sha256"), str)
                    or len(candidate["sha256"]) != 64
                    or not isinstance(candidate.get("argv"), list)
                    or not isinstance(candidate.get("builds"), list)
                    or len(candidate["builds"]) != 2
                    for candidate in candidates
                )
                or not isinstance(selected, dict)
            ):
                raise ReleaseError(
                    "compression comparison is incomplete or non-reproducible"
                )
            eligible = [
                candidate
                for candidate in candidates
                if candidate.get("eligible") is True
            ]
            if not eligible:
                raise ReleaseError("compression comparison has no eligible candidate")
            measured = min(
                eligible,
                key=lambda candidate: (candidate["bytes"], candidate["format"]),
            )
            if (
                selected.get("format") != measured["format"]
                or selected.get("bytes") != measured["bytes"]
                or selected.get("sha256") != measured["sha256"]
                or selected.get("format")
                != identity["compression"][asset_name]["selected_format"]
                or selected.get("filename")
                != identity["artifacts"][asset_name]["filename"]
                or comparison.get("published") != identity["artifacts"][asset_name]
            ):
                raise ReleaseError(
                    "published asset is not the measured eligible minimum"
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
        or value.get("failures") != 0
        or value.get("errors") != 0
    ):
        raise ReleaseError("source-suite structured counts are not a clean pass")
    if gate == "network-trace" and (
        value.get("allowed_network_operations") != 0
        or value.get("sandbox_negative_control_denied") is not True
        or value.get("full_descendant_coverage") is not True
        or value.get("trace_truncated") is not False
        or not isinstance(value.get("events"), list)
        or not value["events"]
    ):
        raise ReleaseError("network trace payload is incomplete")
    if gate == "module-native-inclusion" and (
        value.get("banned_module_matches") != []
        or value.get("banned_native_matches") != []
        or value.get("sha2_provider") != "_sha2"
        or value.get("sha256_positive_control") is not True
        or value.get("zlib_negative_control") is not True
        or value.get("neural_weights") != []
    ):
        raise ReleaseError("module/native inclusion evidence is incomplete")
    return value


def finalize(args: argparse.Namespace) -> dict[str, Any]:
    ensure_output_outside(
        args.output, args.artifacts, label="finalization report output"
    )
    if args.output.exists() or args.output.is_symlink():
        raise ReleaseError(f"finalization output already exists: {args.output}")
    identity_path = args.identity.resolve(strict=True)
    identity = load_identity(identity_path)
    identity_digest = identity_sha256(identity_path)
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
        _gate_evidence(
            path,
            record["gate"],
            record["kind"],
            record["subjects"],
            identity,
            identity_digest,
        )
    evidence_by_gate = {
        record["gate"]: _gate_evidence(
            evidence_dir / record["path"],
            record["gate"],
            record["kind"],
            record["subjects"],
            identity,
            identity_digest,
        )
        for record in required_evidence
    }
    reproducibility_builds = evidence_by_gate["python-reproducibility"].get("builds")
    compression_assets = evidence_by_gate["compression-comparison"].get("assets")
    if not isinstance(reproducibility_builds, list) or not isinstance(
        compression_assets, dict
    ):
        raise ReleaseError("raw-tar producer cross-gate evidence is missing")
    for asset_name in ("ready_run", "corresponding_source"):
        expected_receipts: list[dict[str, Any]] = []
        for build in reproducibility_builds:
            root = build.get("root") if isinstance(build, dict) else None
            native = build.get("native_assembly") if isinstance(build, dict) else None
            assembly = native.get(asset_name) if isinstance(native, dict) else None
            receipt = assembly.get("receipt") if isinstance(assembly, dict) else None
            if not isinstance(root, str) or not isinstance(receipt, dict):
                raise ReleaseError("raw-tar producer receipt cross-link is malformed")
            expected_receipts.append(
                {
                    "root": root,
                    "path": receipt["path"],
                    "file": receipt["file"],
                    "canonical_tar": assembly["canonical_tar"],
                }
            )
        observed_receipts = compression_assets[asset_name]["canonical_tar"].get(
            "producer_receipts"
        )
        if observed_receipts != expected_receipts:
            raise ReleaseError(
                f"compression comparison is not bound to raw-tar roots: {asset_name}"
            )
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

    if any(path.is_symlink() for path in args.repro_root):
        raise ReleaseError("reproduction roots must not be symlinks")
    roots = [path.resolve(strict=True) for path in args.repro_root]
    if len(set(roots)) < identity["verification"]["minimum_distinct_roots"]:
        raise ReleaseError("insufficient distinct native reproduction roots")
    reproducibility_payload = evidence_by_gate["python-reproducibility"]
    receipts = reproducibility_payload.get("root_receipts")
    if not isinstance(receipts, list) or len(receipts) != len(roots):
        raise ReleaseError("reproducibility envelope does not bind every supplied root")
    receipts_by_logical: dict[str, dict[str, Any]] = {}
    for receipt in receipts:
        if (
            not isinstance(receipt, dict)
            or set(receipt) != {"logical_root", "path", "file"}
            or not isinstance(receipt["logical_root"], str)
            or receipt["logical_root"] in receipts_by_logical
            or receipt["path"]
            != f"{receipt['logical_root']}/reproduction/ROOT-REPRODUCTION.json"
        ):
            raise ReleaseError("reproduction receipt inventory is malformed")
        receipts_by_logical[receipt["logical_root"]] = receipt
    seen_inodes: set[tuple[int, int]] = set()
    for record in artifacts.values():
        metadata = (artifacts_dir / record["filename"]).stat()
        if metadata.st_nlink != 1:
            raise ReleaseError("canonical artifact is hard-linked")
        seen_inodes.add((metadata.st_dev, metadata.st_ino))
    logical_repro_roots: set[str] = set()
    for index, root in enumerate(roots):
        for other in roots[index + 1 :]:
            if root in other.parents or other in root.parents:
                raise ReleaseError("reproduction roots must not contain one another")
        expected_root_names = {
            artifacts["ready_run"]["filename"],
            artifacts["corresponding_source"]["filename"],
            "ROOT-REPRODUCTION.json",
        }
        observed_root_names = {path.name for path in root.iterdir()}
        if observed_root_names != expected_root_names:
            raise ReleaseError(
                f"reproduction root contains missing/extra files: {sorted(observed_root_names ^ expected_root_names)}"
            )
        for child in root.iterdir():
            if child.is_symlink() or not child.is_file():
                raise ReleaseError("reproduction root contains a non-regular entry")
            metadata = child.stat()
            inode = (metadata.st_dev, metadata.st_ino)
            if metadata.st_nlink != 1 or inode in seen_inodes:
                raise ReleaseError("reproduction root file is hard-linked/aliased")
            seen_inodes.add(inode)
        for name in ("ready_run", "corresponding_source"):
            expected = artifacts[name]
            verify_artifact(
                root / expected["filename"],
                expected,
                label=f"reproduction root {index} {name}",
            )
        root_report_path = root / "ROOT-REPRODUCTION.json"
        if not root_report_path.is_file() or root_report_path.is_symlink():
            raise ReleaseError("reproduction root lacks generated root evidence")
        root_report = read_json(root_report_path)
        if not isinstance(root_report, dict) or set(root_report) != {
            "schema",
            "logical_root",
            "source_commit",
            "source_tree",
            "source_ref",
            "fresh_frozen_tree",
            "artifacts",
            "commands",
        }:
            raise ReleaseError("reproduction root evidence schema is not exact")
        if (
            root_report["schema"] != "kazstem-macos-root-reproduction-v1"
            or root_report["source_commit"] != identity["source_commit"]
            or root_report["source_tree"] != identity["source_tree"]
            or root_report["source_ref"] != identity["source_ref"]
            or root_report["fresh_frozen_tree"] != identity["inputs"]["frozen_tree"]
            or root_report["artifacts"]
            != {
                "ready_run": artifacts["ready_run"],
                "corresponding_source": artifacts["corresponding_source"],
            }
            or not isinstance(root_report["commands"], list)
            or len(root_report["commands"]) < 3
            or any(
                command.get("exit_status") != 0 for command in root_report["commands"]
            )
            or any(
                command.get("capture", {}).get("process_group_reaped") is not True
                or command.get("capture", {}).get("stream_cap_bytes")
                != 16 * 1024 * 1024
                or not isinstance(
                    command.get("capture", {}).get("timeout_seconds"), int
                )
                for command in root_report["commands"]
            )
            or not isinstance(root_report["logical_root"], str)
            or not root_report["logical_root"]
        ):
            raise ReleaseError("reproduction root did not record a fresh exact build")
        if root_report["logical_root"] in logical_repro_roots:
            raise ReleaseError("reproduction roots share a logical identity")
        logical_repro_roots.add(root_report["logical_root"])
        receipt = receipts_by_logical.get(root_report["logical_root"])
        if receipt is None or file_record(root_report_path) != receipt["file"]:
            raise ReleaseError(
                "reproduction root receipt is not hash-bound to evidence"
            )
        from release_common import assert_relative_json

        assert_relative_json(root_report, label="root reproduction evidence")
    if logical_repro_roots != set(receipts_by_logical):
        raise ReleaseError(
            "supplied roots do not exactly match reproducibility receipts"
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
        "schema": "kazstem-macos-release-finalization-v2",
        "pass": True,
        "release": identity["release"],
        "source_commit": identity["source_commit"],
        "source_ref": identity["source_ref"],
        "release_url": identity["release_url"],
        "identity_contract_sha256": identity_digest,
        "identity": identity,
        "artifacts": artifacts,
        "sha256sums": {"filename": SUMS_NAME, **file_record(sums_path)},
        "required_evidence": required_evidence,
        "evidence_files": {
            record["path"]: file_record(evidence_dir / record["path"])
            for record in required_evidence
        },
        "distinct_reproduction_roots": len(set(roots)),
        "reproducible_artifacts": [
            artifacts["ready_run"]["filename"],
            artifacts["corresponding_source"]["filename"],
        ],
        "publication_requirement": "Publish the corresponding-source archive before or together with the ready-run archive at the exact recorded URLs.",
    }
    from release_common import assert_relative_json

    assert_relative_json(report, label="final release ledger")
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
