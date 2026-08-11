#!/usr/bin/env python3
"""Assemble one deterministic, identity-bound Windows ready-run ZIP."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import shutil
from typing import Any
import zipfile

from release_common import (
    ReleaseError,
    archive_limits,
    artifact_record,
    assert_relative_evidence,
    checksum_rows,
    copy_tree_exact,
    ensure_output_outside,
    file_record,
    files_equal,
    json_bytes,
    load_identity,
    manifest_records,
    pe_identity,
    read_json,
    require_release_bootstrap,
    normalize_tree,
    sha256_file,
    verify_artifact,
    verify_file,
    verify_or_observe_output,
    verify_required_paths,
    verify_tree,
    write_deterministic_zip,
)


def render_template(path: Path, replacements: dict[str, str]) -> bytes:
    try:
        text = path.read_text(encoding="utf-8", errors="strict")
    except (OSError, UnicodeError) as exc:
        raise ReleaseError(f"cannot read template {path}: {exc}") from exc
    for key, value in replacements.items():
        marker = "{{" + key + "}}"
        if text.count(marker) != 1:
            raise ReleaseError(f"template marker must occur exactly once: {marker}")
        text = text.replace(marker, value)
    if "{{" in text or "}}" in text:
        raise ReleaseError(f"unresolved template marker in {path.name}")
    return text.encode("utf-8")


def bundle_manifest(path: Path, expected_bundle_id: str, expected_file: dict[str, Any], label: str) -> dict[str, Any]:
    verify_file(path, expected_file, label=f"{label} manifest")
    value = read_json(path)
    if not isinstance(value, dict) or value.get("bundle_id") != expected_bundle_id:
        raise ReleaseError(f"{label} manifest has the wrong bundle_id")
    return value


def wheel_platform_lock(wheel: Path) -> bytes:
    try:
        with zipfile.ZipFile(wheel) as archive:
            candidates = [
                info for info in archive.infolist()
                if info.filename == "qazmorph/platform_runtime_assets.lock.json"
            ]
            if len(candidates) != 1 or candidates[0].file_size > 1024 * 1024:
                raise ReleaseError("canonical wheel has no unique bounded platform lock")
            return archive.read(candidates[0])
    except (OSError, zipfile.BadZipFile) as exc:
        raise ReleaseError(f"cannot inspect canonical wheel: {exc}") from exc


def copy_document(root: Path, source: Path, destination: str, expected: dict[str, Any]) -> None:
    verify_file(source, expected, label=f"document {source.name}")
    target = root / destination
    if target.exists() or target.is_symlink():
        raise ReleaseError(f"document destination already exists: {destination}")
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, target)


def assemble(args: argparse.Namespace) -> dict[str, Any]:
    ensure_output_outside(args.output, args.work_root, label="ready-run output")
    if args.observation:
        ensure_output_outside(args.observation, args.work_root, label="ready-run observation")
    if args.output.exists() or args.output.is_symlink():
        raise ReleaseError(f"ready-run output already exists: {args.output}")
    identity = load_identity(args.identity.resolve(strict=True))
    expected = identity["inputs"]
    ready = identity["ready_run"]
    artifacts = identity["artifacts"]

    frozen = args.frozen.resolve(strict=True)
    resources = args.resources.resolve(strict=True)
    runtime = args.runtime.resolve(strict=True)
    documents = args.documents.resolve(strict=True)
    platform_lock = args.platform_lock.resolve(strict=True)
    verify_tree(frozen, expected["frozen_tree"], label="frozen launcher")
    verify_tree(resources, expected["resource_tree"]["tree"], label="resource")
    verify_tree(runtime, expected["runtime_tree"]["tree"], label="Windows runtime")
    resource_manifest = bundle_manifest(
        resources / "manifest.json",
        expected["resource_tree"]["bundle_id"],
        expected["resource_tree"]["manifest"],
        "resource",
    )
    runtime_manifest = bundle_manifest(
        runtime / "manifest.json",
        expected["runtime_tree"]["bundle_id"],
        expected["runtime_tree"]["manifest"],
        "runtime",
    )
    verify_file(platform_lock, expected["platform_lock"], label="unified platform lock")
    platform_lock_value = read_json(platform_lock)
    matching = [
        value
        for value in platform_lock_value.get("runtimes", [])
        if value.get("platform") == {"system": "windows", "machine": "x86_64"}
    ] if isinstance(platform_lock_value, dict) else []
    if matching != [
        {
            "platform": {"system": "windows", "machine": "x86_64"},
            "resource_bundle_ids": [expected["resource_tree"]["bundle_id"]],
            "bundle_id": expected["runtime_tree"]["bundle_id"],
            "manifest": expected["runtime_tree"]["manifest"],
        }
    ]:
        raise ReleaseError("unified platform lock does not bind resource and Windows runtime")
    verify_file(args.base_ledger.resolve(strict=True), expected["base_ledger"], label="freezer ledger")
    verify_file(args.binary_readme_template.resolve(strict=True), expected["binary_readme_template"], label="binary README template")
    verify_artifact(args.wheel.resolve(strict=True), artifacts["wheel"], label="canonical wheel")
    verify_artifact(args.sdist.resolve(strict=True), artifacts["sdist"], label="canonical sdist")
    verify_artifact(args.corresponding_source.resolve(strict=True), artifacts["corresponding_source"], label="corresponding source")
    if wheel_platform_lock(args.wheel.resolve(strict=True)) != platform_lock.read_bytes():
        raise ReleaseError("wheel platform lock differs from the checked unified lock")
    frozen_lock = frozen / ready["platform_lock_path"]
    verify_file(frozen_lock, expected["platform_lock"], label="frozen platform lock")
    launcher = frozen / ready["launcher"]["path"]
    verify_file(launcher, ready["launcher"]["file"], label="frozen kazstem.exe")

    work_root = args.work_root.absolute()
    if work_root.exists() or work_root.is_symlink():
        raise ReleaseError(f"work root already exists: {work_root}")
    work_root.mkdir(parents=True)
    root = work_root / ready["top_level"]
    copy_tree_exact(frozen, root)

    removals: list[dict[str, Any]] = []
    for value in ready["remove_frozen_files"]:
        path = root / value["path"]
        verify_file(path, value["file"], label=f"declared removal {value['path']}")
        removals.append({"path": value["path"], **file_record(path)})
        path.unlink()

    resource_destination = root / ready["resource_destination"]
    runtime_destination = root / ready["runtime_parent"] / expected["runtime_tree"]["bundle_id"]
    copy_tree_exact(resources, resource_destination)
    copy_tree_exact(runtime, runtime_destination)

    launcher_output = root / ready["launcher"]["path"]
    for alias in ready["aliases"]:
        target = root / alias
        if target.exists() or target.is_symlink():
            raise ReleaseError(f"alias destination already exists: {alias}")
        shutil.copyfile(launcher_output, target)
        if not files_equal(target, launcher_output):
            raise ReleaseError(f"alias bytes differ from kazstem.exe: {alias}")

    for value in expected["documents"]:
        copy_document(
            root,
            documents / value["source"],
            value["destination"],
            value["file"],
        )

    source_artifact = artifacts["corresponding_source"]
    readme = render_template(
        args.binary_readme_template.resolve(strict=True),
        {
            "VERSION": identity["release"],
            "TARGET": identity["platform"]["label"],
            "SOURCE_FILENAME": source_artifact["filename"],
            "SOURCE_SHA256": source_artifact["sha256"],
            "SOURCE_URL": source_artifact["url"],
            "RESOURCE_BUNDLE_ID": expected["resource_tree"]["bundle_id"],
            "RUNTIME_BUNDLE_ID": expected["runtime_tree"]["bundle_id"],
        },
    )
    readme_path = root / "README-WINDOWS.md"
    if readme_path.exists():
        raise ReleaseError("README-WINDOWS.md is reserved for release generation")
    readme_path.write_bytes(readme)
    (root / "CORRESPONDING-SOURCE.json").write_bytes(
        json_bytes(
            {
                "schema": "kazstem-windows-source-binding-v1",
                "release": identity["release"],
                "source_commit": identity["source_commit"],
                "artifact": source_artifact,
            }
        )
    )

    verification = root / "verification"
    if verification.exists():
        raise ReleaseError("verification directory is reserved")
    verification.mkdir()
    (verification / "BUILD-IDENTITY.json").write_bytes(
        json_bytes(
            {
                "schema": "kazstem-windows-build-identity-v2",
                "release": identity["release"],
                "source_commit": identity["source_commit"],
                "source_date_epoch": identity["source_date_epoch"],
                "platform": identity["platform"],
                "canonical_python_artifacts": {
                    "wheel": artifacts["wheel"],
                    "sdist": artifacts["sdist"],
                },
                "canonical_python_builder": expected["canonical_python_builder"],
                "canonical_python_build_identity": expected[
                    "canonical_python_build_identity"
                ],
                "canonical_python_build_receipt": expected[
                    "canonical_python_build_receipt"
                ],
                "resource_bundle": expected["resource_tree"],
                "runtime_bundle": expected["runtime_tree"],
                "platform_lock": expected["platform_lock"],
                "corresponding_source": source_artifact,
            }
        )
    )
    ledger = read_json(args.base_ledger.resolve(strict=True))
    if not isinstance(ledger, dict):
        raise ReleaseError("base freezer ledger must be a JSON object")
    (verification / "MODULE-NATIVE-INCLUSION-LEDGER.json").write_bytes(
        json_bytes(
            {
                "schema": "kazstem-windows-module-native-inclusion-ledger-v1",
                "release": identity["release"],
                "source_commit": identity["source_commit"],
                "base_ledger": ledger,
                "removed_frozen_files": removals,
                "added_resource_bundle": expected["resource_tree"],
                "added_runtime_bundle": expected["runtime_tree"],
            }
        )
    )

    pe_files = sorted(
        [path for path in root.rglob("*") if path.is_file() and path.suffix.casefold() in {".exe", ".dll", ".pyd"}],
        key=lambda path: path.relative_to(root).as_posix(),
    )
    pe_records = []
    for path in pe_files:
        record = pe_identity(path)
        record["path"] = path.relative_to(root).as_posix()
        pe_records.append(record)
    if not pe_records or any(record["authenticode_embedded"] for record in pe_records):
        raise ReleaseError("ready-run must be explicitly and completely unsigned")
    (verification / "UNSIGNED-AUTHENTICODE.json").write_bytes(
        json_bytes(
            {
                "schema": "kazstem-windows-unsigned-inventory-v1",
                "result": "pass",
                "release": identity["release"],
                "source_commit": identity["source_commit"],
                "unsigned": True,
                "smartscreen_warning_possible": True,
                "files": pe_records,
            }
        )
    )

    banned_matches: list[str] = []
    for path in root.rglob("*"):
        name = path.name.casefold()
        relative = path.relative_to(root).as_posix()
        if any(fragment in name for fragment in ready["banned_name_fragments"]):
            banned_matches.append(relative)
    if banned_matches:
        raise ReleaseError(f"banned ready-run entries: {sorted(banned_matches)}")

    manifest_path = verification / "BUNDLE-MANIFEST.json"
    files, directories = manifest_records(root, excluded={"verification/BUNDLE-MANIFEST.json", "verification/BUNDLED-FILES.sha256"})
    manifest_path.write_bytes(
        json_bytes(
            {
                "schema": "kazstem-windows-ready-run-manifest-v1",
                "release": identity["release"],
                "source_commit": identity["source_commit"],
                "files": files,
                "directories": directories,
            }
        )
    )
    checksum_path = verification / "BUNDLED-FILES.sha256"
    checksum_path.write_text(
        "\n".join(checksum_rows(root, excluded={"verification/BUNDLED-FILES.sha256"})) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    verify_required_paths(root, ready["required_paths"])
    assert_relative_evidence(verification)

    executable_paths = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file() and path.suffix.casefold() in {".exe", ".dll", ".pyd"}
    }
    normalize_tree(root, epoch=identity["source_date_epoch"], executable_paths=executable_paths)
    output = args.output.absolute()
    if output.name != artifacts["ready_run"]["filename"]:
        raise ReleaseError("ready-run output filename differs from identity")
    write_deterministic_zip(root, output, epoch=identity["source_date_epoch"], limits=archive_limits(identity, "ready_run"))
    verify_or_observe_output(
        output,
        artifacts["ready_run"],
        observation=args.observation.absolute() if args.observation else None,
        label="ready-run",
    )
    return {
        "result": "pass",
        "archive": artifact_record(output, artifacts["ready_run"]["url"]),
        "top_level": ready["top_level"],
        "pe_files": len(pe_records),
        "unsigned": True,
    }


def main() -> int:
    require_release_bootstrap("packaging/windows/assemble_ready_run.py")
    parser = argparse.ArgumentParser()
    parser.add_argument("--identity", required=True, type=Path)
    parser.add_argument("--frozen", required=True, type=Path)
    parser.add_argument("--resources", required=True, type=Path)
    parser.add_argument("--runtime", required=True, type=Path)
    parser.add_argument("--platform-lock", required=True, type=Path)
    parser.add_argument("--documents", required=True, type=Path)
    parser.add_argument("--binary-readme-template", required=True, type=Path)
    parser.add_argument("--base-ledger", required=True, type=Path)
    parser.add_argument("--wheel", required=True, type=Path)
    parser.add_argument("--sdist", required=True, type=Path)
    parser.add_argument("--corresponding-source", required=True, type=Path)
    parser.add_argument("--work-root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--observation", type=Path)
    args = parser.parse_args()
    print(json.dumps(assemble(args), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ReleaseError, OSError, ValueError, json.JSONDecodeError) as exc:
        raise SystemExit(f"error: {exc}") from exc
