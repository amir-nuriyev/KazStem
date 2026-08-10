#!/usr/bin/env python3
"""Safely extract and completely audit one Linux ready-run archive."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from release_common import (
    READY_AUDIT_SCHEMA,
    ReleaseError,
    archive_limits,
    assert_relative_evidence,
    ensure_output_outside,
    extract_validated_tar,
    identity_sha256,
    inspect_tar,
    json_bytes,
    load_identity,
    parse_checksums,
    read_json,
    ready_source_binding,
    regular_files,
    sha256_file,
    verify_artifact,
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
    root = extract_validated_tar(archive, args.fresh_root.absolute(), members=members)
    verify_sealed_archive_modes(members)
    verify_outer_archive_completeness(members, root, top_level=ready["top_level"])
    checksum_entries = _verify_checksums(root, "verification/BUNDLED-FILES.sha256")

    manifest_path = root / "verification/BUNDLE-MANIFEST.json"
    manifest = read_json(manifest_path)
    if not isinstance(manifest, dict) or set(manifest) != {
        "schema",
        "release",
        "source_commit",
        "files",
        "symlinks",
        "directories",
    }:
        raise ReleaseError("invalid ready-run bundle manifest structure")
    if (
        manifest["schema"] != "kazstem-linux-ready-run-manifest-v1"
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
    nested: list[str] = []
    for path in root.rglob("*"):
        relative = path.relative_to(root).as_posix()
        basename = path.name.casefold()
        if any(fragment in basename for fragment in ready["banned_name_fragments"]):
            banned.append(relative)
        if path.is_file() and basename.endswith(
            (
                ".tar",
                ".tar.gz",
                ".tar.bz2",
                ".tar.xz",
                ".tgz",
                ".tbz2",
                ".whl",
                ".zip",
                ".deb",
            )
        ):
            nested.append(relative)
    if banned:
        raise ReleaseError(f"banned ready-run entries: {sorted(banned)}")
    if nested:
        raise ReleaseError(
            f"source/build archives are forbidden in ready-run: {sorted(nested)}"
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
