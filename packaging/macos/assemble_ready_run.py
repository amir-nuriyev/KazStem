#!/usr/bin/env python3
"""Assemble one checksum-bound, deterministic macOS ready-run archive."""

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
    compress_canonical_tar,
    ensure_output_outside,
    ensure_distinct_nonaliased_paths,
    file_record,
    json_bytes,
    load_identity,
    manifest_entry_records,
    normalize_tree,
    read_json,
    ready_source_binding,
    render_template,
    tree_inventory,
    verify_artifact,
    verify_file,
    verify_or_observe_output,
    verify_required_paths,
    verify_tree,
    write_deterministic_tar,
)


def _bundle_manifest(
    path: Path, expected_bundle_id: str, expected_file: dict[str, Any], label: str
) -> None:
    verify_file(path, expected_file, label=f"{label} manifest")
    value = read_json(path)
    if not isinstance(value, dict) or value.get("bundle_id") != expected_bundle_id:
        raise ReleaseError(f"{label} manifest has the wrong bundle_id")


def _copy_document(
    root: Path, source: Path, destination: str, expected: dict[str, Any]
) -> None:
    verify_file(source, expected, label=f"document {source.name}")
    target = root / destination
    if target.exists() or target.is_symlink():
        raise ReleaseError(f"document destination already exists: {destination}")
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, target)


def assemble(args: argparse.Namespace) -> dict[str, Any]:
    ensure_output_outside(args.output, args.work_root, label="ready-run archive output")
    if args.observation:
        ensure_distinct_nonaliased_paths(
            args.output,
            args.observation,
            labels=("ready-run archive output", "observation output"),
        )
        ensure_output_outside(
            args.observation, args.work_root, label="ready-run observation"
        )
    if args.output.exists() or args.output.is_symlink():
        raise ReleaseError(f"ready-run output already exists: {args.output}")
    if args.observation and (
        args.observation.exists() or args.observation.is_symlink()
    ):
        raise ReleaseError(f"observation output already exists: {args.observation}")
    identity_path = args.identity.resolve(strict=True)
    identity = load_identity(identity_path)
    expected = identity["inputs"]
    ready = identity["ready_run"]
    artifacts = identity["artifacts"]

    frozen = args.frozen.resolve(strict=True)
    resources = args.resources.resolve(strict=True)
    runtime = args.runtime.resolve(strict=True)
    documents = args.documents.resolve(strict=True)
    verify_tree(frozen, expected["frozen_tree"], label="frozen launcher")
    verify_tree(resources, expected["resource_tree"]["tree"], label="resource")
    verify_tree(runtime, expected["runtime_tree"]["tree"], label="runtime")
    _bundle_manifest(
        resources / "manifest.json",
        expected["resource_tree"]["bundle_id"],
        expected["resource_tree"]["manifest"],
        "resource",
    )
    _bundle_manifest(
        runtime / "manifest.json",
        expected["runtime_tree"]["bundle_id"],
        expected["runtime_tree"]["manifest"],
        "runtime",
    )
    verify_file(
        args.base_ledger.resolve(strict=True),
        expected["base_ledger"],
        label="base freezer ledger",
    )
    verify_file(
        args.binary_readme_template.resolve(strict=True),
        expected["binary_readme_template"],
        label="binary README template",
    )
    verify_artifact(
        args.wheel.resolve(strict=True), artifacts["wheel"], label="canonical wheel"
    )
    verify_artifact(
        args.sdist.resolve(strict=True), artifacts["sdist"], label="canonical sdist"
    )
    verify_artifact(
        args.corresponding_source.resolve(strict=True),
        artifacts["corresponding_source"],
        label="corresponding source",
    )
    launcher = frozen / ready["launcher"]["path"]
    verify_file(launcher, ready["launcher"]["file"], label="frozen launcher executable")
    verify_file(
        frozen / ready["platform_lock"]["path"],
        ready["platform_lock"]["file"],
        label="checked-in unified platform lock",
    )

    work_root = args.work_root.absolute()
    if work_root.exists() or work_root.is_symlink():
        raise ReleaseError(f"work root already exists: {work_root}")
    work_root.mkdir(parents=True)
    root = work_root / ready["top_level"]
    shutil.copytree(frozen, root, symlinks=True)

    removed: list[dict[str, Any]] = []
    for item in ready["remove_frozen_files"]:
        path = root / item["path"]
        verify_file(path, item["file"], label=f"declared frozen removal {item['path']}")
        removed.append({"path": item["path"], **file_record(path)})
        path.unlink()

    resource_destination = root / ready["resource_destination"]
    runtime_destination = (
        root / ready["runtime_parent"] / expected["runtime_tree"]["bundle_id"]
    )
    for destination, source, label in (
        (resource_destination, resources, "resource"),
        (runtime_destination, runtime, "runtime"),
    ):
        if destination.exists() or destination.is_symlink():
            raise ReleaseError(f"{label} destination already exists: {destination}")
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(source, destination, symlinks=True)

    launcher_relative = ready["launcher"]["path"]
    for alias in ready["aliases"]:
        target = root / alias
        if target.exists() or target.is_symlink():
            raise ReleaseError(f"alias destination already exists: {alias}")
        target.symlink_to(launcher_relative)

    for item in expected["documents"]:
        _copy_document(
            root,
            documents / item["source"],
            item["destination"],
            item["file"],
        )

    source_artifact = artifacts["corresponding_source"]
    readme = render_template(
        args.binary_readme_template.resolve(strict=True),
        {
            "VERSION": identity["release"],
            "TARGET": identity["platform"]["advertised_target"],
            "SOURCE_FILENAME": source_artifact["filename"],
            "SOURCE_SHA256": source_artifact["sha256"],
            "SOURCE_URL": source_artifact["url"],
            "RESOURCE_BUNDLE_ID": expected["resource_tree"]["bundle_id"],
            "RUNTIME_BUNDLE_ID": expected["runtime_tree"]["bundle_id"],
        },
    )
    readme_path = root / "README.md"
    if readme_path.exists() or readme_path.is_symlink():
        raise ReleaseError(
            "README.md destination is reserved for the rendered binary README"
        )
    readme_path.write_bytes(readme)
    (root / "CORRESPONDING-SOURCE.json").write_bytes(
        json_bytes(ready_source_binding(identity))
    )

    verification = root / "verification"
    if verification.exists() or verification.is_symlink():
        raise ReleaseError("verification/ is reserved for generated release evidence")
    verification.mkdir()
    build_identity = {
        "schema": "kazstem-macos-build-identity-v2",
        "release": identity["release"],
        "source_commit": identity["source_commit"],
        "source_ref": identity["source_ref"],
        "source_date_epoch": identity["source_date_epoch"],
        "ready_run": {
            "filename": artifacts["ready_run"]["filename"],
            "url": artifacts["ready_run"]["url"],
        },
        "canonical_python_artifacts": {
            "wheel": artifacts["wheel"],
            "sdist": artifacts["sdist"],
        },
        "corresponding_source": source_artifact,
        "frozen_launcher": ready["launcher"],
        "resource_bundle_id": expected["resource_tree"]["bundle_id"],
        "resource_manifest": expected["resource_tree"]["manifest"],
        "platform_runtime_bundle_id": expected["runtime_tree"]["bundle_id"],
        "platform_runtime_manifest": expected["runtime_tree"]["manifest"],
        "platform_lock": ready["platform_lock"],
    }
    (verification / "BUILD-IDENTITY.json").write_bytes(json_bytes(build_identity))
    (verification / "PLATFORM-TARGET.json").write_bytes(
        json_bytes(
            {
                "schema": "kazstem-macos-platform-target-v2",
                **identity["platform"],
            }
        )
    )
    base_ledger = read_json(args.base_ledger.resolve(strict=True))
    if (
        not isinstance(base_ledger, dict)
        or base_ledger.get("schema") != "kazstem-macos-frozen-build-v1"
        or base_ledger.get("pass") is not True
        or base_ledger.get("release") != identity["release"]
        or base_ledger.get("source_commit") != identity["source_commit"]
        or base_ledger.get("source_tree") != identity["source_tree"]
        or base_ledger.get("output_tree") != expected["frozen_tree"]
        or not isinstance(base_ledger.get("module_inventory", {}).get("modules"), list)
        or base_ledger.get("negative_controls", {})
        .get("pyinstaller-zlib-bootstrap", {})
        .get("failed_as_required")
        is not True
    ):
        raise ReleaseError(
            "base freezer ledger is not an exact generated frozen-build pass"
        )
    ledger = {
        "schema": "kazstem-macos-module-native-inclusion-ledger-v2",
        "release": identity["release"],
        "source_commit": identity["source_commit"],
        "base_ledger": base_ledger,
        "removed_frozen_files": removed,
        "added_bundles": {
            "resource": expected["resource_tree"],
            "runtime": expected["runtime_tree"],
        },
        "minimization_contract": identity["minimization"],
    }
    (verification / "MODULE-NATIVE-INCLUSION-LEDGER.json").write_bytes(
        json_bytes(ledger)
    )

    banned_matches: list[str] = []
    for path in root.rglob("*"):
        relative = path.relative_to(root).as_posix()
        basename = path.name.casefold()
        if any(fragment in basename for fragment in ready["banned_name_fragments"]):
            banned_matches.append(relative)
    if banned_matches:
        raise ReleaseError(f"banned ready-run entries: {sorted(banned_matches)}")

    executable_paths: set[str] = {launcher_relative}
    for source_root, destination in (
        (frozen, ""),
        (runtime, f"{ready['runtime_parent']}/{expected['runtime_tree']['bundle_id']}"),
        (resources, ready["resource_destination"]),
    ):
        for item in tree_inventory(source_root):
            if item["kind"] == "file" and int(item["mode"], 8) & 0o111:
                executable_paths.add(f"{destination}/{item['path']}".lstrip("/"))

    manifest_path = verification / "BUNDLE-MANIFEST.json"
    files, links, directories = manifest_entry_records(
        root,
        excluded={
            "verification/BUNDLE-MANIFEST.json",
            "verification/BUNDLED-FILES.sha256",
        },
    )
    manifest_path.write_bytes(
        json_bytes(
            {
                "schema": "kazstem-macos-ready-run-manifest-v2",
                "release": identity["release"],
                "source_commit": identity["source_commit"],
                "executable_paths": sorted(executable_paths),
                "files": files,
                "symlinks": links,
                "directories": directories,
            }
        )
    )
    checksum_path = verification / "BUNDLED-FILES.sha256"
    checksum_path.write_text(
        "\n".join(checksum_rows(root, excluded={"verification/BUNDLED-FILES.sha256"}))
        + "\n",
        encoding="utf-8",
    )
    verify_required_paths(root, ready["required_paths"])
    assert_relative_evidence(verification)

    normalize_tree(
        root, epoch=identity["source_date_epoch"], executable_paths=executable_paths
    )

    output = args.output.absolute()
    if output.name != artifacts["ready_run"]["filename"]:
        raise ReleaseError("ready-run output path does not use the identity filename")
    canonical_tar = (
        work_root / identity["compression"]["ready_run"]["canonical_tar"]["filename"]
    )
    tar_record = write_deterministic_tar(
        root,
        canonical_tar,
        epoch=identity["source_date_epoch"],
        limits=archive_limits(identity, "ready_run"),
    )
    if getattr(args, "canonical_tar_only", False):
        return {
            "schema": "kazstem-macos-ready-assembly-receipt-v1",
            "result": "candidate-only",
            "release": identity["release"],
            "source_commit": identity["source_commit"],
            "source_tree": identity["source_tree"],
            "top_level": ready["top_level"],
            "regular_files": len(
                [
                    path
                    for path in root.rglob("*")
                    if path.is_file() and not path.is_symlink()
                ]
            ),
            "canonical_tar": tar_record,
        }
    compression_receipt = compress_canonical_tar(
        canonical_tar,
        output,
        policy=identity["compression"]["ready_run"],
    )
    verify_or_observe_output(
        output,
        artifacts["ready_run"],
        observation=args.observation.absolute() if args.observation else None,
        label="ready-run",
    )
    return {
        "schema": "kazstem-macos-ready-assembly-receipt-v1",
        "result": "pass",
        "release": identity["release"],
        "source_commit": identity["source_commit"],
        "source_tree": identity["source_tree"],
        "archive": artifacts["ready_run"],
        "top_level": ready["top_level"],
        "regular_files": len(
            list(
                path
                for path in root.rglob("*")
                if path.is_file() and not path.is_symlink()
            )
        ),
        "removed_frozen_files": removed,
        "canonical_tar": tar_record,
        "compression": compression_receipt,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--identity", required=True, type=Path)
    parser.add_argument("--frozen", required=True, type=Path)
    parser.add_argument("--resources", required=True, type=Path)
    parser.add_argument("--runtime", required=True, type=Path)
    parser.add_argument("--documents", required=True, type=Path)
    parser.add_argument("--binary-readme-template", required=True, type=Path)
    parser.add_argument("--base-ledger", required=True, type=Path)
    parser.add_argument("--wheel", required=True, type=Path)
    parser.add_argument("--sdist", required=True, type=Path)
    parser.add_argument("--corresponding-source", required=True, type=Path)
    parser.add_argument("--work-root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--observation", type=Path)
    parser.add_argument("--receipt", required=True, type=Path)
    args = parser.parse_args()
    if args.receipt.exists() or args.receipt.is_symlink():
        raise ReleaseError("ready assembly receipt already exists")
    result = assemble(args)
    args.receipt.parent.mkdir(parents=True, exist_ok=True)
    args.receipt.write_bytes(json_bytes(result))
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ReleaseError, OSError, ValueError, json.JSONDecodeError) as exc:
        raise SystemExit(f"error: {exc}") from exc
