#!/usr/bin/env python3
"""Safely extract and completely audit one Linux ready-run archive."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import tempfile
from typing import Any

from release_common import (
    READY_AUDIT_SCHEMA,
    ReleaseError,
    archive_limits,
    assert_relative_evidence,
    compression_target,
    ensure_output_outside,
    ensure_distinct_nonaliased_paths,
    extract_validated_tar,
    identity_sha256,
    inspect_tar,
    materialize_uncompressed_tar,
    json_bytes,
    load_identity,
    parse_checksums,
    portable_path,
    read_json,
    ready_source_binding,
    selected_compression,
    regular_files,
    sha256_file,
    verify_artifact,
    verify_declared_archive_inventory,
    verify_file,
    verify_manifest_completeness,
    verify_outer_archive_completeness,
    verify_required_paths,
    verify_sealed_archive_modes,
)


def _verify_checksums(root: Path, relative: str) -> int:
    checksum_path = root / relative
    rows = parse_checksums(checksum_path.read_bytes())
    observed = {
        path.relative_to(root).as_posix()
        for path in regular_files(root)
        if path != checksum_path
    }
    if set(rows) != observed:
        raise ReleaseError(
            "ready-run checksum inventory is incomplete "
            f"(missing={sorted(observed - set(rows))}, extra={sorted(set(rows) - observed)})"
        )
    for name, expected in rows.items():
        actual = sha256_file(root / name)
        if actual != expected:
            raise ReleaseError(f"ready-run internal checksum mismatch: {name}")
    return len(rows)


def _manifest_bundle(
    path: Path, expected_id: str, expected_file: dict[str, Any], label: str
) -> None:
    verify_file(path, expected_file, label=f"{label} manifest")
    value = read_json(path)
    if not isinstance(value, dict) or value.get("bundle_id") != expected_id:
        raise ReleaseError(f"{label} manifest bundle id mismatch")


def audit(args: argparse.Namespace) -> dict[str, Any]:
    ensure_distinct_nonaliased_paths(
        args.output,
        args.fresh_root,
        labels=("ready audit output", "fresh extraction root"),
    )
    ensure_output_outside(args.output, args.fresh_root, label="ready-run audit output")
    if args.output.exists() or args.output.is_symlink():
        raise ReleaseError(f"audit output already exists: {args.output}")
    identity_path = args.identity.resolve(strict=True)
    identity = load_identity(identity_path)
    ready = identity["ready_run"]
    expected_inputs = identity["inputs"]
    archive = args.archive.resolve(strict=True)
    verify_artifact(
        archive, identity["artifacts"]["ready_run"], label="ready-run archive"
    )
    members = inspect_tar(
        archive,
        limits=archive_limits(identity, "ready_run"),
        expected_top=ready["top_level"],
    )
    compression = compression_target(identity, "ready_run")
    with tempfile.TemporaryDirectory(prefix="kazstem-ready-raw-audit-") as temporary:
        raw_tar = Path(temporary) / compression["input"]["filename"]
        materialize_uncompressed_tar(
            archive,
            raw_tar,
            compression=selected_compression(identity, "ready_run"),
            expected=compression["input"],
        )
        if inspect_tar(
            raw_tar,
            limits=archive_limits(identity, "ready_run"),
            expected_top=ready["top_level"],
        ) != members:
            raise ReleaseError("ready container differs from canonical raw tar")
    root = extract_validated_tar(
        archive,
        args.fresh_root.absolute(),
        members=members,
        limits=archive_limits(identity, "ready_run"),
    )
    verify_outer_archive_completeness(members, root, top_level=ready["top_level"])
    checksum_entries = _verify_checksums(root, "verification/BUNDLED-FILES.sha256")

    manifest_path = root / "verification/BUNDLE-MANIFEST.json"
    manifest = read_json(manifest_path)
    if not isinstance(manifest, dict) or set(manifest) != {
        "schema",
        "release",
        "source_commit",
        "executable_paths",
        "files",
        "symlinks",
        "directories",
    }:
        raise ReleaseError("invalid ready-run bundle manifest structure")
    if (
        manifest["schema"] != "kazstem-linux-ready-run-manifest-v2"
        or manifest["release"] != identity["release"]
        or manifest["source_commit"] != identity["source_commit"]
    ):
        raise ReleaseError("ready-run bundle manifest identity mismatch")
    verify_manifest_completeness(
        root,
        manifest,
        excluded_files={
            "verification/BUNDLE-MANIFEST.json",
            "verification/BUNDLED-FILES.sha256",
        },
    )
    raw_executable_paths = manifest["executable_paths"]
    if not isinstance(raw_executable_paths, list):
        raise ReleaseError("ready-run executable path inventory is not a list")
    executable_paths = [
        portable_path(value, label="ready-run executable path")
        for value in raw_executable_paths
    ]
    if executable_paths != sorted(set(executable_paths)):
        raise ReleaseError(
            "ready-run executable paths must be sorted and unique"
        )
    for relative in executable_paths:
        path = root / relative
        if not path.is_file() or path.is_symlink():
            raise ReleaseError(
                f"ready-run executable path does not name a file: {relative}"
            )
    verify_sealed_archive_modes(
        members,
        executable_paths={
            f"{ready['top_level']}/{relative}" for relative in executable_paths
        },
    )
    binding = read_json(root / "CORRESPONDING-SOURCE.json")
    if binding != ready_source_binding(identity):
        raise ReleaseError(
            "ready-run corresponding-source binding differs from release identity"
        )
    verify_required_paths(root, ready["required_paths"])
    verify_file(
        root / ready["platform_lock"]["path"],
        ready["platform_lock"]["file"],
        label="embedded unified platform lock",
    )
    _manifest_bundle(
        root / ready["resource_destination"] / "manifest.json",
        expected_inputs["resource_tree"]["bundle_id"],
        expected_inputs["resource_tree"]["manifest"],
        "embedded resource",
    )
    _manifest_bundle(
        root
        / ready["runtime_parent"]
        / expected_inputs["runtime_tree"]["bundle_id"]
        / "manifest.json",
        expected_inputs["runtime_tree"]["bundle_id"],
        expected_inputs["runtime_tree"]["manifest"],
        "embedded runtime",
    )
    for alias in ready["aliases"]:
        path = root / alias
        if (
            not path.is_symlink()
            or path.readlink().as_posix() != ready["launcher"]["path"]
        ):
            raise ReleaseError(f"ready-run alias differs from identity: {alias}")
    banned: list[str] = []
    for path in root.rglob("*"):
        relative = path.relative_to(root).as_posix()
        basename = path.name.casefold()
        if any(fragment in basename for fragment in ready["banned_name_fragments"]):
            banned.append(relative)
    if banned:
        raise ReleaseError(f"banned ready-run entries: {sorted(banned)}")
    for item in ready["nested_archives"]:
        verify_file(
            root / item["path"],
            {"bytes": item["bytes"], "sha256": item["sha256"]},
            label="ready-run embedded canonical wheel",
        )
    verify_declared_archive_inventory(
        root,
        {item["path"]: item["format"] for item in ready["nested_archives"]},
    )
    assert_relative_evidence(root / "verification")

    result = {
        "schema": READY_AUDIT_SCHEMA,
        "pass": True,
        "release": identity["release"],
        "source_commit": identity["source_commit"],
        "identity_contract_sha256": identity_sha256(identity_path),
        "archive": identity["artifacts"]["ready_run"],
        "top_level": ready["top_level"],
        "members": len(members),
        "checksum_entries": checksum_entries,
        "manifest_files": len(manifest["files"]),
        "manifest_symlinks": len(manifest["symlinks"]),
        "manifest_directories": len(manifest["directories"]),
        "safe_member_paths": True,
        "duplicate_case_ads_special_checks": "pass",
        "completeness": "pass",
        "relative_evidence": True,
        "canonical_uncompressed_tar": compression["input"],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(json_bytes(result))
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("archive", type=Path)
    parser.add_argument("--identity", required=True, type=Path)
    parser.add_argument("--fresh-root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    result = audit(args)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ReleaseError, OSError, ValueError, json.JSONDecodeError) as exc:
        raise SystemExit(f"error: {exc}") from exc
