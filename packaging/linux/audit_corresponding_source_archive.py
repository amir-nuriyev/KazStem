#!/usr/bin/env python3
"""Safely extract and completely audit the Linux source companion."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
from typing import Any
import unicodedata

from release_common import (
    SOURCE_AUDIT_SCHEMA,
    ReleaseError,
    archive_limits,
    assert_relative_evidence,
    canonical_hash,
    ensure_output_outside,
    extract_validated_tar,
    identity_sha256,
    inspect_nested,
    inspect_tar,
    json_bytes,
    load_identity,
    parse_checksums,
    portable_path,
    read_json,
    regular_files,
    sha256_file,
    source_identity_projection,
    tree_inventory,
    verify_artifact,
    verify_file,
    verify_manifest_completeness,
    verify_outer_archive_completeness,
    verify_required_paths,
    verify_sealed_archive_modes,
    verify_source_contract,
)


ARCHIVE_SUFFIXES = (
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


def _verify_checksums(root: Path) -> int:
    checksum = root / "SHA256SUMS"
    rows = parse_checksums(checksum.read_bytes())
    observed = {
        path.relative_to(root).as_posix()
        for path in regular_files(root)
        if path != checksum
    }
    if set(rows) != observed:
        raise ReleaseError(
            "source checksum inventory is incomplete "
            f"(missing={sorted(observed - set(rows))}, extra={sorted(set(rows) - observed)})"
        )
    for name, expected in rows.items():
        if sha256_file(root / name) != expected:
            raise ReleaseError(f"source internal checksum mismatch: {name}")
    return len(rows)


def _verify_payload_inventory(
    identity: dict[str, Any], manifest: dict[str, Any], root: Path
) -> None:
    inventory = manifest.get("payload_inventory")
    if not isinstance(inventory, list):
        raise ReleaseError("source manifest lacks the original payload inventory")
    inventory_paths: list[str] = []
    for index, item in enumerate(inventory):
        if not isinstance(item, dict):
            raise ReleaseError(f"invalid source payload inventory row {index}")
        kind = item.get("kind")
        fields = {
            "file": {"path", "kind", "mode", "bytes", "sha256"},
            "directory": {"path", "kind", "mode"},
            "symlink": {"path", "kind", "mode", "target"},
        }.get(kind)
        if fields is None or set(item) != fields:
            raise ReleaseError(f"invalid source payload inventory row {index}")
        inventory_paths.append(
            portable_path(item["path"], label=f"payload inventory row {index}")
        )
        if (
            not isinstance(item["mode"], str)
            or re.fullmatch(r"[0-7]{4}", item["mode"]) is None
        ):
            raise ReleaseError(f"invalid source payload mode at row {index}")
        if kind == "file" and (
            not isinstance(item["bytes"], int)
            or isinstance(item["bytes"], bool)
            or item["bytes"] < 0
            or not isinstance(item["sha256"], str)
            or re.fullmatch(r"[0-9a-f]{64}", item["sha256"]) is None
        ):
            raise ReleaseError(f"invalid source payload file identity at row {index}")
        if kind == "symlink" and (
            not isinstance(item["target"], str) or not item["target"]
        ):
            raise ReleaseError(f"invalid source payload symlink target at row {index}")
    if inventory_paths != sorted(set(inventory_paths)) or len(
        {unicodedata.normalize("NFC", value).casefold() for value in inventory_paths}
    ) != len(inventory_paths):
        raise ReleaseError("source payload inventory paths are not sorted and unique")
    expected_tree = identity["inputs"]["source_payload_tree"]
    record = {
        "entries": len(inventory),
        "regular_file_bytes": sum(
            item.get("bytes", 0) for item in inventory if isinstance(item, dict)
        ),
        "sha256": canonical_hash(inventory),
    }
    if record != expected_tree:
        raise ReleaseError(
            "source manifest payload inventory differs from release identity"
        )
    reserved = {
        "README.md",
        "SOURCE-IDENTITY.json",
        "SOURCE-MANIFEST.json",
        "SHA256SUMS",
        "python-artifacts",
    }
    declared_paths = {item["path"] for item in inventory}
    observed_paths = {
        item["path"]
        for item in tree_inventory(root)
        if item["path"].split("/", 1)[0] not in reserved
    }
    if declared_paths != observed_paths:
        raise ReleaseError(
            "source payload path inventory is incomplete "
            f"(missing={sorted(observed_paths - declared_paths)}, extra={sorted(declared_paths - observed_paths)})"
        )
    for item in inventory:
        if item["path"].split("/", 1)[0] in reserved:
            raise ReleaseError(
                "source payload inventory uses a generated/reserved path"
            )
        path = root / item["path"]
        kind = item.get("kind")
        if kind == "file":
            verify_file(
                path,
                {"bytes": item.get("bytes"), "sha256": item.get("sha256")},
                label=f"source payload {item['path']}",
            )
        elif kind == "symlink":
            if not path.is_symlink() or path.readlink().as_posix() != item.get(
                "target"
            ):
                raise ReleaseError(f"source payload symlink mismatch: {item['path']}")
        elif kind == "directory":
            if not path.is_dir() or path.is_symlink():
                raise ReleaseError(f"source payload directory mismatch: {item['path']}")
        else:
            raise ReleaseError("invalid source payload inventory kind")


def audit(args: argparse.Namespace) -> dict[str, Any]:
    ensure_output_outside(args.output, args.fresh_root, label="source audit output")
    if args.output.exists() or args.output.is_symlink():
        raise ReleaseError(f"audit output already exists: {args.output}")
    identity_path = args.identity.resolve(strict=True)
    identity = load_identity(identity_path)
    source = identity["corresponding_source"]
    archive = args.archive.resolve(strict=True)
    verify_artifact(
        archive,
        identity["artifacts"]["corresponding_source"],
        label="corresponding-source archive",
    )
    members = inspect_tar(
        archive,
        limits=archive_limits(identity, "corresponding_source"),
        expected_top=source["top_level"],
    )
    root = extract_validated_tar(archive, args.fresh_root.absolute(), members=members)
    verify_sealed_archive_modes(members)
    verify_outer_archive_completeness(members, root, top_level=source["top_level"])
    checksum_entries = _verify_checksums(root)
    projection = read_json(root / "SOURCE-IDENTITY.json")
    if projection != source_identity_projection(identity):
        raise ReleaseError(
            "embedded source identity projection differs from release identity"
        )
    manifest = read_json(root / "SOURCE-MANIFEST.json")
    expected_fields = {
        "schema",
        "release",
        "source_commit",
        "source_date_epoch",
        "source_identity_sha256",
        "payload_tree",
        "payload_inventory",
        "nested_archives",
        "files",
        "symlinks",
        "directories",
    }
    if not isinstance(manifest, dict) or set(manifest) != expected_fields:
        raise ReleaseError("invalid corresponding-source manifest structure")
    if (
        manifest["schema"] != "kazstem-linux-corresponding-source-manifest-v2"
        or manifest["release"] != identity["release"]
        or manifest["source_commit"] != identity["source_commit"]
        or manifest["source_date_epoch"] != identity["source_date_epoch"]
        or manifest["payload_tree"] != identity["inputs"]["source_payload_tree"]
        or manifest["nested_archives"] != source["nested_archives"]
        or manifest["source_identity_sha256"]
        != sha256_file(root / "SOURCE-IDENTITY.json")
    ):
        raise ReleaseError("corresponding-source manifest identity mismatch")
    verify_manifest_completeness(
        root,
        manifest,
        excluded_files={"SOURCE-MANIFEST.json", "SHA256SUMS"},
    )
    _verify_payload_inventory(identity, manifest, root)
    verify_required_paths(root, source["required_paths"])
    verify_source_contract(root, identity)
    assert_relative_evidence(root / source["evidence_root"])

    wheel_path = f"python-artifacts/{identity['artifacts']['wheel']['filename']}"
    sdist_path = f"python-artifacts/{identity['artifacts']['sdist']['filename']}"
    nested_by_path = {record["path"]: record for record in source["nested_archives"]}
    if nested_by_path.get(wheel_path, {}).get("format") != "zip":
        raise ReleaseError(
            "nested source inventory must bind the canonical wheel as zip"
        )
    if nested_by_path.get(sdist_path, {}).get("format") != "tar":
        raise ReleaseError(
            "nested source inventory must bind the canonical sdist as tar"
        )
    verify_artifact(
        root / wheel_path,
        identity["artifacts"]["wheel"],
        label="embedded canonical wheel",
    )
    verify_artifact(
        root / sdist_path,
        identity["artifacts"]["sdist"],
        label="embedded canonical sdist",
    )

    detected = {
        path.relative_to(root).as_posix()
        for path in regular_files(root)
        if path.name.casefold().endswith((*ARCHIVE_SUFFIXES, ".gz"))
    }
    declared = set(nested_by_path)
    if detected != declared:
        raise ReleaseError(
            "nested archive inventory is incomplete "
            f"(undeclared={sorted(detected - declared)}, missing={sorted(declared - detected)})"
        )
    nested_results: list[dict[str, Any]] = []
    limits = archive_limits(identity, "nested")
    if len(declared) > limits.max_members:
        raise ReleaseError("nested archive count exceeds the identity cap")
    total_expanded = 0
    for relative in sorted(declared):
        record = nested_by_path[relative]
        verify_file(
            root / relative,
            {"bytes": record["bytes"], "sha256": record["sha256"]},
            label=f"nested archive {relative}",
        )
        details = inspect_nested(root / relative, record["format"], limits=limits)
        expanded = details.get("expanded_bytes")
        if not isinstance(expanded, int) or expanded < 0:
            raise ReleaseError(
                f"nested archive audit lacks an expanded-byte count: {relative}"
            )
        total_expanded += expanded
        if total_expanded > limits.max_total_bytes:
            raise ReleaseError(
                "aggregate nested-source expansion exceeds the identity cap"
            )
        nested_results.append(
            {"path": relative, "format": record["format"], **details, "pass": True}
        )

    result = {
        "schema": SOURCE_AUDIT_SCHEMA,
        "pass": True,
        "release": identity["release"],
        "source_commit": identity["source_commit"],
        "identity_contract_sha256": identity_sha256(identity_path),
        "archive": identity["artifacts"]["corresponding_source"],
        "top_level": source["top_level"],
        "members": len(members),
        "checksum_entries": checksum_entries,
        "manifest_files": len(manifest["files"]),
        "manifest_symlinks": len(manifest["symlinks"]),
        "manifest_directories": len(manifest["directories"]),
        "nested_archives": nested_results,
        "nested_expanded_bytes": total_expanded,
        "nested_archives_pass": True,
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
