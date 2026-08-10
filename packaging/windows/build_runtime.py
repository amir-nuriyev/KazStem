#!/usr/bin/env python3
"""Build the minimized, manifest-bound Windows x86-64 native runtime."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import shutil
import stat
import sys
from typing import Any
from zipfile import BadZipFile, ZipFile, ZipInfo


PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))

from write_platform_runtime_manifest import (  # noqa: E402
    ManifestError,
    atomic_write,
    build_manifest,
    file_record,
    load_source_lock,
    read_canonical_lf_json,
)


RESOURCE_BUNDLE_ID = (
    "f03e703d3e2a67044a7d91fd7d575b92cb4e61aa782fb67cff91b0a5ff0ebd5a"
)
HFST_ARCHIVE = "hfst-3.17.2+g4028~e16268eb.x86_64.zip"
CG3_ARCHIVE = "cg3-1.6.8+g2347~8d5fa4dd.x86_64.zip"
COMMANDS = {
    "hfst-proc.exe": (HFST_ARCHIVE, "hfst/bin/hfst-proc.exe"),
    "hfst-optimized-lookup.exe": (
        HFST_ARCHIVE,
        "hfst/bin/hfst-optimized-lookup.exe",
    ),
    "cg-proc.exe": (CG3_ARCHIVE, "cg3/bin/cg-proc.exe"),
}
HFST_DLLS = (
    "libhfst-57.dll",
    "icuuc74.dll",
    "libgcc_s_seh-1.dll",
    "libstdc++-6.dll",
    "libwinpthread-1.dll",
    "icudt74.dll",
    "libreadline8.dll",
    "libtermcap.dll",
    "libfoma.dll",
    "zlib1.dll",
    "libfst-27.dll",
    "libdl.dll",
)
CG3_DLLS = (
    "libcg3.dll",
    "libsqlite3-0.dll",
    "icuin74.dll",
    "icuio74.dll",
)
IDENTICAL_SHARED_DLLS = (
    "icudt74.dll",
    "icuuc74.dll",
    "libgcc_s_seh-1.dll",
    "libstdc++-6.dll",
    "libwinpthread-1.dll",
)
MAX_ARCHIVE_UNCOMPRESSED_BYTES = 256 * 1024 * 1024


class BuildError(RuntimeError):
    pass


def portable_zip_name(name: str) -> str:
    if not name or "\x00" in name or "\\" in name:
        raise BuildError(f"unsafe ZIP member path: {name!r}")
    posix = PurePosixPath(name)
    windows = PureWindowsPath(name)
    if (
        posix.is_absolute()
        or windows.is_absolute()
        or windows.drive
        or name != posix.as_posix()
        or any(part in {"", ".", ".."} for part in posix.parts)
    ):
        raise BuildError(f"unsafe ZIP member path: {name!r}")
    return name


def zip_inventory(archive: Path) -> dict[str, ZipInfo]:
    try:
        with ZipFile(archive) as value:
            infos = value.infolist()
            bad = value.testzip()
    except (OSError, BadZipFile) as exc:
        raise BuildError(f"invalid ZIP archive {archive}: {exc}") from exc
    if bad is not None:
        raise BuildError(f"ZIP CRC verification failed: {archive}: {bad}")
    result: dict[str, ZipInfo] = {}
    folded: set[str] = set()
    total = 0
    for info in infos:
        name = portable_zip_name(info.filename.rstrip("/"))
        folded_name = name.casefold()
        if folded_name in folded:
            raise BuildError(f"case-insensitive duplicate ZIP member: {name}")
        folded.add(folded_name)
        mode = (info.external_attr >> 16) & 0xFFFF
        kind = stat.S_IFMT(mode)
        if kind not in {0, stat.S_IFREG, stat.S_IFDIR}:
            raise BuildError(f"unsupported ZIP member type: {name}")
        if info.flag_bits & 1:
            raise BuildError(f"encrypted ZIP member is forbidden: {name}")
        if info.file_size < 0 or info.compress_size < 0:
            raise BuildError(f"invalid ZIP member size: {name}")
        total += info.file_size
        if total > MAX_ARCHIVE_UNCOMPRESSED_BYTES:
            raise BuildError(f"ZIP uncompressed-size cap exceeded: {archive}")
        if not info.is_dir():
            result[name] = info
    return result


def archive_payload(
    archive: Path, inventory: dict[str, ZipInfo], member: str
) -> bytes:
    info = inventory.get(member)
    if info is None:
        raise BuildError(f"required ZIP member is missing: {archive}: {member}")
    with ZipFile(archive) as value:
        payload = value.read(info)
    if len(payload) != info.file_size:
        raise BuildError(f"ZIP member length changed during read: {archive}: {member}")
    return payload


def load_base_lock(path: Path) -> dict[str, Any]:
    try:
        lock = read_canonical_lf_json(
            path, label="base platform runtime lock"
        )
    except ManifestError as exc:
        raise BuildError(f"invalid base platform runtime lock {path}: {exc}") from exc
    if (
        not isinstance(lock, dict)
        or lock.get("schema") != "kazstem-platform-runtime-lock-v1"
        or set(lock) != {"schema", "runtimes"}
        or not isinstance(lock.get("runtimes"), list)
    ):
        raise BuildError(f"invalid base platform runtime lock: {path}")
    return lock


def build(args: argparse.Namespace) -> dict[str, Any]:
    source_lock_path = args.source_lock.resolve(strict=True)
    source_lock = load_source_lock(source_lock_path)
    if source_lock["platform"] != {
        "system": "windows",
        "machine": "x86_64",
        "minimum_os": "10.0.20348",
    }:
        raise BuildError("source lock is not the Windows x86-64 lock")
    archive_dir = args.archives.resolve(strict=True)
    source_dir = args.sources.resolve(strict=True)
    expected_archives = {record["filename"]: record for record in source_lock["archives"]}
    if set(expected_archives) != {HFST_ARCHIVE, CG3_ARCHIVE}:
        raise BuildError("Windows source lock has an unexpected binary archive set")
    observed_archive_names = {path.name for path in archive_dir.iterdir() if path.is_file()}
    if observed_archive_names != set(expected_archives):
        raise BuildError("Windows binary archive directory differs from source lock")
    for name, record in expected_archives.items():
        if file_record(archive_dir / name) != {
            "bytes": record["bytes"],
            "sha256": record["sha256"],
        }:
            raise BuildError(f"Windows binary archive identity mismatch: {name}")

    archive_paths = {name: archive_dir / name for name in expected_archives}
    inventories = {
        name: zip_inventory(path) for name, path in archive_paths.items()
    }
    for name in IDENTICAL_SHARED_DLLS:
        hfst = archive_payload(
            archive_paths[HFST_ARCHIVE], inventories[HFST_ARCHIVE], f"hfst/bin/{name}"
        )
        cg3 = archive_payload(
            archive_paths[CG3_ARCHIVE], inventories[CG3_ARCHIVE], f"cg3/bin/{name}"
        )
        if hfst != cg3:
            raise BuildError(f"supposedly shared DLL bytes differ: {name}")

    output_parent = args.output_parent.resolve()
    output_parent.mkdir(parents=True, exist_ok=True)
    staging = output_parent / "runtime-staging"
    if staging.exists():
        raise BuildError(f"refusing to overwrite runtime staging directory: {staging}")
    binary_dir = staging / "usr" / "bin"
    binary_dir.mkdir(parents=True)
    selected: dict[str, tuple[str, str]] = dict(COMMANDS)
    selected.update(
        {
            name: (HFST_ARCHIVE, f"hfst/bin/{name}")
            for name in HFST_DLLS
        }
    )
    selected.update(
        {
            name: (CG3_ARCHIVE, f"cg3/bin/{name}")
            for name in CG3_DLLS
        }
    )
    for output_name, (archive_name, member) in sorted(selected.items()):
        destination = binary_dir / output_name
        destination.write_bytes(
            archive_payload(
                archive_paths[archive_name], inventories[archive_name], member
            )
        )
        destination.chmod(0o555 if output_name.casefold().endswith(".exe") else 0o444)

    manifest_path = staging / "manifest.json"
    manifest = build_manifest(
        staging,
        archive_dir,
        source_dir,
        manifest_path,
        source_lock,
        source_lock_path,
    )
    atomic_write(manifest_path, manifest)
    bundle_id = manifest["bundle_id"]
    final = output_parent / bundle_id
    if final.exists():
        raise BuildError(f"refusing to overwrite content-addressed runtime: {final}")
    staging.rename(final)

    base_lock = load_base_lock(args.base_lock.resolve(strict=True))
    runtimes = [
        entry
        for entry in base_lock["runtimes"]
        if entry.get("platform") != {"system": "windows", "machine": "x86_64"}
    ]
    manifest_identity = file_record(final / "manifest.json")
    windows_entry = {
        "platform": {"system": "windows", "machine": "x86_64"},
        "resource_bundle_ids": [RESOURCE_BUNDLE_ID],
        "bundle_id": bundle_id,
        "manifest": manifest_identity,
    }
    runtimes.append(windows_entry)
    runtimes.sort(
        key=lambda entry: (
            entry["platform"]["system"], entry["platform"]["machine"]
        )
    )
    proposed_lock = {"schema": base_lock["schema"], "runtimes": runtimes}
    atomic_write(args.lock_output.resolve(), proposed_lock)

    final_binary_dir = final / "usr" / "bin"
    executable_access = {
        name: os.access(final_binary_dir / name, os.X_OK)
        for name in sorted(COMMANDS)
    }
    executable_availability = {
        name: {
            "regular_exe": (
                (final_binary_dir / name).is_file()
                and not (final_binary_dir / name).is_symlink()
                and (final_binary_dir / name).suffix.casefold() == ".exe"
            ),
            "manifest_hash_bound": manifest["commands"][name.removesuffix(".exe")][
                "sha256"
            ]
            == file_record(final_binary_dir / name)["sha256"],
            "version_execution_succeeded": bool(
                manifest["commands"][name.removesuffix(".exe")]["version_output"]
            ),
            "os_access_x_ok": executable_access[name],
        }
        for name in sorted(COMMANDS)
    }
    if not all(
        record["regular_exe"]
        and record["manifest_hash_bound"]
        and record["version_execution_succeeded"]
        for record in executable_availability.values()
    ):
        raise BuildError(
            f"Windows executable availability proof failed: {executable_availability}"
        )
    return {
        "schema": "kazstem-windows-runtime-build-v1",
        "platform": {"system": "windows", "machine": "x86_64"},
        "resource_bundle_id": RESOURCE_BUNDLE_ID,
        "runtime_bundle_id": bundle_id,
        "runtime_manifest": manifest_identity,
        "regular_files": len(manifest["files"]),
        "runtime_bytes": sum(
            record.get("bytes", 0) for record in manifest["files"].values()
        ),
        "pe_dependency_closure": manifest["dependency_closure"],
        "executable_access": executable_access,
        "executable_availability": executable_availability,
        "availability_contract": (
            "regular-exe-manifest-hash-successful-version-execution"
        ),
        "dll_layout": "all non-system imports adjacent to the three helper executables",
        "symlinks": 0,
        "admin_privileges_required": False,
        "windows_lock_entry": windows_entry,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--archives", required=True, type=Path)
    parser.add_argument("--sources", required=True, type=Path)
    parser.add_argument("--source-lock", required=True, type=Path)
    parser.add_argument("--output-parent", required=True, type=Path)
    parser.add_argument("--base-lock", required=True, type=Path)
    parser.add_argument("--lock-output", required=True, type=Path)
    parser.add_argument("--json", type=Path)
    args = parser.parse_args()
    result = build(args)
    encoded = json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if args.json is None:
        print(encoded, end="")
    else:
        args.json.write_text(encoded, encoding="utf-8", newline="\n")
        print(result["runtime_bundle_id"])
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (BuildError, ManifestError, OSError, ValueError) as error:
        raise SystemExit(f"error: {error}") from error
