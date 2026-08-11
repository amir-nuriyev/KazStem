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
    ensure_distinct_nonaliased_paths,
    extract_validated_tar,
    ensure_output_outside,
    file_record,
    json_bytes,
    load_identity,
    manifest_entry_records,
    materialize_git_archive,
    normalize_tree,
    produce_canonical_tar_with_receipt,
    render_template,
    source_identity_projection,
    tar_producer_logical_argv,
    selected_compression,
    tree_inventory,
    inspect_tar,
    verify_artifact,
    verify_file,
    verify_or_observe_output,
    verify_required_paths,
    verify_source_contract,
    verify_tree,
    write_deterministic_tar_archive,
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
        ensure_distinct_nonaliased_paths(
            args.output,
            args.observation,
            labels=("corresponding-source archive output", "observation output"),
        )
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
    repository = args.repository.resolve(strict=True)
    template = args.source_readme_template.resolve(strict=True)
    wheel = args.wheel.resolve(strict=True)
    sdist = args.sdist.resolve(strict=True)
    verify_tree(
        payload, expected["source_payload_tree"], label="corresponding-source payload"
    )
    payload_inventory = tree_inventory(payload)
    verify_file(
        template, expected["source_readme_template"], label="source README template"
    )
    verify_artifact(wheel, artifacts["wheel"], label="canonical wheel")
    verify_artifact(sdist, artifacts["sdist"], label="canonical sdist")
    generated_application = source["source_categories"]["application_source"]
    conflicts = sorted(
        name
        for name in RESERVED | {generated_application}
        if (payload / name).exists() or (payload / name).is_symlink()
    )
    if conflicts:
        raise ReleaseError(f"source payload uses reserved generated paths: {conflicts}")
    assert_relative_evidence(payload / source["evidence_root"])
    for name, relative in source["source_categories"].items():
        if name == "application_source":
            continue
        category = payload / relative
        if not category.is_dir() or category.is_symlink():
            raise ReleaseError(
                f"supplemental source category is missing or invalid: {name}={relative}"
            )

    work_root = args.work_root.absolute()
    if work_root.exists() or work_root.is_symlink():
        raise ReleaseError(f"work root already exists: {work_root}")
    work_root.mkdir(parents=True)
    root = work_root / source["top_level"]
    shutil.copytree(payload, root, symlinks=True)
    application_root = root / generated_application
    application_root.mkdir(parents=True)
    git_archive = root / source["git_archive_file"]
    materialization = materialize_git_archive(repository, identity, git_archive)
    git_members = inspect_tar(
        git_archive,
        limits=archive_limits(identity, "nested"),
        expected_top="tree",
    )
    git_extract_parent = work_root / "git-archive-extract"
    extracted_tree = extract_validated_tar(
        git_archive,
        git_extract_parent,
        members=git_members,
        limits=archive_limits(identity, "nested"),
    )
    shutil.move(str(extracted_tree), str(application_root / "tree"))
    git_extract_parent.rmdir()
    for relative, data in (
        (source["source_commit_file"], f"{identity['source_commit']}\n".encode("ascii")),
        (source["source_tree_file"], f"{identity['source_tree']}\n".encode("ascii")),
        (source["source_origin_file"], f"{identity['source_origin']}\n".encode("utf-8")),
        (
            source["source_date_epoch_file"],
            f"{identity['source_date_epoch']}\n".encode("ascii"),
        ),
    ):
        marker = root / relative
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_bytes(data)
    git_metadata = application_root / "GIT-SOURCE.json"
    git_metadata.write_bytes(json_bytes(materialization))
    python_artifacts = root / "python-artifacts"
    python_artifacts.mkdir()
    shutil.copyfile(wheel, python_artifacts / wheel.name)
    shutil.copyfile(sdist, python_artifacts / sdist.name)

    readme = render_template(
        template,
        {
            "VERSION": identity["release"],
            "BINARY_TOP_LEVEL": identity["ready_run"]["top_level"],
            "SOURCE_COMMIT": identity["source_commit"],
            "SOURCE_TREE": identity["source_tree"],
            "SOURCE_ORIGIN": identity["source_origin"],
            "SOURCE_REF": identity["source_ref"],
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
        "schema": "kazstem-linux-corresponding-source-manifest-v3",
        "release": identity["release"],
        "source_commit": identity["source_commit"],
        "source_tree": identity["source_tree"],
        "source_origin": identity["source_origin"],
        "source_ref": identity["source_ref"],
        "source_date_epoch": identity["source_date_epoch"],
        "git_source_materialization": materialization,
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
    verify_source_contract(root, identity)
    assert_relative_evidence(root / source["evidence_root"])

    executable_paths = {
        item["path"]
        for item in tree_inventory(root)
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
    raw_tar_output = getattr(args, "raw_tar_output", None)
    producer_receipt = getattr(args, "producer_receipt", None)
    if (raw_tar_output is None) is not (producer_receipt is None):
        raise ReleaseError("raw tar output and producer receipt must be requested together")
    if raw_tar_output is not None:
        produce_canonical_tar_with_receipt(
            root,
            output,
            raw_tar_output,
            producer_receipt,
            identity_path=args.identity.resolve(strict=True),
            identity=identity,
            artifact="corresponding_source",
            producer_argv=tar_producer_logical_argv(
                identity, "corresponding_source", raw_tar_output.name
            ),
        )
    else:
        write_deterministic_tar_archive(
            root,
            output,
            epoch=identity["source_date_epoch"],
            limits=archive_limits(identity, "corresponding_source"),
            compression=selected_compression(identity, "corresponding_source"),
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
    parser.add_argument("--repository", required=True, type=Path)
    parser.add_argument("--source-readme-template", required=True, type=Path)
    parser.add_argument("--wheel", required=True, type=Path)
    parser.add_argument("--sdist", required=True, type=Path)
    parser.add_argument("--work-root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--observation", type=Path)
    parser.add_argument("--raw-tar-output", type=Path)
    parser.add_argument("--producer-receipt", type=Path)
    args = parser.parse_args()
    result = assemble(args)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ReleaseError, OSError, ValueError, json.JSONDecodeError) as exc:
        raise SystemExit(f"error: {exc}") from exc
