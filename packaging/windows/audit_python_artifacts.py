#!/usr/bin/env python3
"""Prove wheel/sdist payloads originate in the exact materialized Git tree."""

from __future__ import annotations

import argparse
import email.parser
import json
from pathlib import Path, PurePosixPath
import tarfile
import zipfile

from audit_corresponding_source_archive import inspect_tar
from release_common import (
    ArchiveLimits,
    ReleaseError,
    file_record,
    inspect_zip,
    json_bytes,
    portable_path,
    require_release_bootstrap,
    tree_record,
)


def main() -> int:
    require_release_bootstrap("packaging/windows/audit_python_artifacts.py")
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--wheel", required=True, type=Path)
    parser.add_argument("--sdist", required=True, type=Path)
    parser.add_argument("--version", required=True)
    parser.add_argument("--json", required=True, type=Path)
    args = parser.parse_args()
    source = args.source.resolve(strict=True)
    wheel = args.wheel.resolve(strict=True)
    sdist = args.sdist.resolve(strict=True)
    if not source.is_dir() or source.is_symlink():
        raise ReleaseError("materialized source root is invalid")
    limits = ArchiveLimits(200_000, 1024**3, 4 * 1024**3, 4096)
    inspect_zip(wheel, limits=limits)
    expected_python = {
        path.relative_to(source / "src/qazmorph").as_posix(): path.read_bytes()
        for path in sorted((source / "src/qazmorph").rglob("*.py"))
    }
    if not expected_python:
        raise ReleaseError("materialized source has no qazmorph Python package")
    with zipfile.ZipFile(wheel) as archive:
        wheel_names = [info.filename for info in archive.infolist() if not info.is_dir()]
        package_python = {
            name.removeprefix("qazmorph/"): archive.read(name)
            for name in wheel_names
            if name.startswith("qazmorph/") and name.endswith(".py")
        }
        if package_python != expected_python:
            raise ReleaseError("wheel Python sources differ from exact Git materialization")
        lock_name = "qazmorph/platform_runtime_assets.lock.json"
        if wheel_names.count(lock_name) != 1 or archive.read(lock_name) != (source / "src/qazmorph/platform_runtime_assets.lock.json").read_bytes():
            raise ReleaseError("wheel platform runtime lock differs from exact Git source")
        metadata_names = [name for name in wheel_names if name.endswith(".dist-info/METADATA")]
        if len(metadata_names) != 1:
            raise ReleaseError("wheel has no unique METADATA")
        metadata = email.parser.BytesParser().parsebytes(archive.read(metadata_names[0]))
        if metadata.get("Name") != "kazstem" or metadata.get("Version") != args.version:
            raise ReleaseError("wheel metadata name/version differs")

    tar_summary = inspect_tar(sdist, limits=limits)
    expected_top = f"kazstem-{args.version}"
    source_matches = 0
    generated: list[str] = []
    tar_regular: list[str] = []
    sources_manifest: list[str] | None = None
    with tarfile.open(sdist, "r:gz") as archive:
        for member in archive.getmembers():
            name = portable_path(member.name.rstrip("/"), label="sdist member")
            parts = PurePosixPath(name).parts
            if not parts or parts[0] != expected_top:
                raise ReleaseError(f"sdist member has wrong top-level root: {name}")
            if not member.isreg():
                continue
            relative = PurePosixPath(*parts[1:]).as_posix()
            stream = archive.extractfile(member)
            if stream is None:
                raise ReleaseError(f"cannot read sdist member: {relative}")
            payload = stream.read()
            tar_regular.append(relative)
            source_path = source / relative
            if source_path.is_file() and not source_path.is_symlink():
                if payload != source_path.read_bytes():
                    raise ReleaseError(f"sdist member differs from exact Git source: {relative}")
                source_matches += 1
            else:
                generated.append(relative)
            if relative.endswith(".egg-info/SOURCES.txt"):
                sources_manifest = payload.decode("utf-8", "strict").splitlines()
    required = {
        "pyproject.toml",
        "LICENSE",
        "THIRD_PARTY.md",
        "src/qazmorph/platform_runtime_assets.lock.json",
        "scripts/platform_runtime_sources.windows-x86_64.lock.json",
        "packaging/windows/release_common.py",
        "packaging/windows/finalize_release.py",
        "tests/test_windows_final_release_tooling.py",
    }
    if not required <= set(tar_regular):
        raise ReleaseError(f"sdist omits critical exact source: {sorted(required - set(tar_regular))}")
    if sources_manifest is None or sorted(sources_manifest) != sorted(tar_regular):
        raise ReleaseError("sdist SOURCES.txt is absent or not a complete regular-file inventory")
    permitted_generated_suffixes = ("PKG-INFO", ".egg-info/PKG-INFO", ".egg-info/SOURCES.txt", ".egg-info/dependency_links.txt", ".egg-info/entry_points.txt", ".egg-info/top_level.txt")
    if any(not relative.endswith(permitted_generated_suffixes) for relative in generated):
        raise ReleaseError(f"sdist has unexplained generated files: {generated}")
    result = {
        "schema": "kazstem-python-artifact-source-audit-v1",
        "result": "pass",
        "source_tree": tree_record(source),
        "wheel": file_record(wheel),
        "sdist": file_record(sdist),
        "wheel_python_files": len(expected_python),
        "sdist_regular_files": len(tar_regular),
        "sdist_exact_source_files": source_matches,
        "sdist_generated_metadata": sorted(generated),
        "sdist_physical_audit": tar_summary,
    }
    if args.json.exists() or args.json.is_symlink():
        raise ReleaseError(f"Python artifact audit output exists: {args.json}")
    args.json.parent.mkdir(parents=True, exist_ok=True)
    args.json.write_bytes(json_bytes(result))
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ReleaseError, OSError, ValueError, json.JSONDecodeError, tarfile.TarError, zipfile.BadZipFile) as exc:
        raise SystemExit(f"error: {exc}") from exc
