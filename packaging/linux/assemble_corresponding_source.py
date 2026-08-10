#!/usr/bin/env python3
"""Assemble the deterministic corresponding-source companion."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import shutil
from typing import Any

from release_common import (
    ReleaseError,
    archive_limits,
    assert_relative_evidence,
    checksum_rows,
    ensure_output_outside,
    file_record,
    json_bytes,
    load_identity,
    manifest_entry_records,
    normalize_tree,
    render_template,
    source_identity_projection,
    tree_inventory,
    verify_artifact,
    verify_file,
    verify_or_observe_output,
    verify_required_paths,
    verify_source_contract,
    verify_tree,
    write_deterministic_tar_xz,
)


RESERVED = {
    "README.md",
    "SOURCE-IDENTITY.json",
    "SOURCE-MANIFEST.json",
    "SHA256SUMS",
    "python-artifacts",
}


def _verify_nested(root: Path, records: list[dict[str, Any]]) -> None:
    for record in records:
        path = root / record["path"]
        verify_file(
            path,
            {"bytes": record["bytes"], "sha256": record["sha256"]},
            label=f"nested source archive {record['path']}",
        )


def assemble(args: argparse.Namespace) -> dict[str, Any]:
    ensure_output_outside(
        args.output, args.work_root, label="corresponding-source archive output"
    )
    if args.observation:
        ensure_output_outside(
            args.observation,
            args.work_root,
            label="corresponding-source observation",
        )
    if args.output.exists() or args.output.is_symlink():
        raise ReleaseError(f"corresponding-source output already exists: {args.output}")
    if args.observation and (
        args.observation.exists() or args.observation.is_symlink()
    ):
        raise ReleaseError(f"observation output already exists: {args.observation}")
    identity = load_identity(args.identity.resolve(strict=True))
    expected = identity["inputs"]
    source = identity["corresponding_source"]
    artifacts = identity["artifacts"]
    payload = args.payload.resolve(strict=True)
    template = args.source_readme_template.resolve(strict=True)
    wheel = args.wheel.resolve(strict=True)
    sdist = args.sdist.resolve(strict=True)
    verify_tree(
        payload, expected["source_payload_tree"], label="corresponding-source payload"
    )
    verify_source_contract(payload, identity)
    payload_inventory = tree_inventory(payload)
    verify_file(
        template, expected["source_readme_template"], label="source README template"
    )
    verify_artifact(wheel, artifacts["wheel"], label="canonical wheel")
    verify_artifact(sdist, artifacts["sdist"], label="canonical sdist")
    conflicts = sorted(
        name
        for name in RESERVED
        if (payload / name).exists() or (payload / name).is_symlink()
    )
    if conflicts:
        raise ReleaseError(f"source payload uses reserved generated paths: {conflicts}")
    assert_relative_evidence(payload / source["evidence_root"])

    work_root = args.work_root.absolute()
    if work_root.exists() or work_root.is_symlink():
        raise ReleaseError(f"work root already exists: {work_root}")
    work_root.mkdir(parents=True)
    root = work_root / source["top_level"]
    shutil.copytree(payload, root, symlinks=True)
    python_artifacts = root / "python-artifacts"
    python_artifacts.mkdir()
    shutil.copyfile(wheel, python_artifacts / wheel.name)
    shutil.copyfile(sdist, python_artifacts / sdist.name)

    readme = render_template(
        template,
        {
            "VERSION": identity["release"],
            "BINARY_ARCHIVE": artifacts["ready_run"]["filename"],
            "BINARY_URL": artifacts["ready_run"]["url"],
            "SOURCE_COMMIT": identity["source_commit"],
            "SOURCE_DATE_EPOCH": str(identity["source_date_epoch"]),
            "WHEEL_FILENAME": artifacts["wheel"]["filename"],
            "WHEEL_SHA256": artifacts["wheel"]["sha256"],
            "SDIST_FILENAME": artifacts["sdist"]["filename"],
            "SDIST_SHA256": artifacts["sdist"]["sha256"],
            "RESOURCE_BUNDLE_ID": expected["resource_tree"]["bundle_id"],
            "RUNTIME_BUNDLE_ID": expected["runtime_tree"]["bundle_id"],
            "RELEASE_URL": identity["release_url"],
        },
    )
    (root / "README.md").write_bytes(readme)
    projection = source_identity_projection(identity)
    (root / "SOURCE-IDENTITY.json").write_bytes(json_bytes(projection))
    _verify_nested(root, source["nested_archives"])

    manifest_path = root / "SOURCE-MANIFEST.json"
    files, links, directories = manifest_entry_records(
        root, excluded={"SOURCE-MANIFEST.json", "SHA256SUMS"}
    )
    manifest = {
        "schema": "kazstem-linux-corresponding-source-manifest-v2",
        "release": identity["release"],
        "source_commit": identity["source_commit"],
        "source_date_epoch": identity["source_date_epoch"],
        "source_identity_sha256": file_record(root / "SOURCE-IDENTITY.json")["sha256"],
        "payload_tree": expected["source_payload_tree"],
        "payload_inventory": payload_inventory,
        "nested_archives": source["nested_archives"],
        "files": files,
        "symlinks": links,
        "directories": directories,
    }
    manifest_path.write_bytes(json_bytes(manifest))
    (root / "SHA256SUMS").write_text(
        "\n".join(checksum_rows(root, excluded={"SHA256SUMS"})) + "\n",
        encoding="utf-8",
    )
    verify_required_paths(root, source["required_paths"])
    assert_relative_evidence(root / source["evidence_root"])

    executable_paths = {
        item["path"]
        for item in tree_inventory(payload)
        if item["kind"] == "file" and int(item["mode"], 8) & 0o111
    }
    normalize_tree(
        root, epoch=identity["source_date_epoch"], executable_paths=executable_paths
    )
    output = args.output.absolute()
    if output.name != artifacts["corresponding_source"]["filename"]:
        raise ReleaseError(
            "corresponding-source output path does not use the identity filename"
        )
    write_deterministic_tar_xz(
        root,
        output,
        epoch=identity["source_date_epoch"],
        limits=archive_limits(identity, "corresponding_source"),
    )
    verify_or_observe_output(
        output,
        artifacts["corresponding_source"],
        observation=args.observation.absolute() if args.observation else None,
        label="corresponding-source",
    )
    return {
        "result": "pass",
        "archive": artifacts["corresponding_source"],
        "top_level": source["top_level"],
        "files": len(files) + 2,
        "nested_archives": len(source["nested_archives"]),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--identity", required=True, type=Path)
    parser.add_argument("--payload", required=True, type=Path)
    parser.add_argument("--source-readme-template", required=True, type=Path)
    parser.add_argument("--wheel", required=True, type=Path)
    parser.add_argument("--sdist", required=True, type=Path)
    parser.add_argument("--work-root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--observation", type=Path)
    args = parser.parse_args()
    result = assemble(args)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ReleaseError, OSError, ValueError, json.JSONDecodeError) as exc:
        raise SystemExit(f"error: {exc}") from exc
