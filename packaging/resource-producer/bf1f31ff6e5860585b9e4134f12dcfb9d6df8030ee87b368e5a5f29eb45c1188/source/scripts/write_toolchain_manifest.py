#!/usr/bin/env python3
"""Create or verify the extracted, unprivileged HFST/CG toolchain manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
from typing import Any


SCHEMA = "qazmorph-toolchain-manifest-v2"
LOCK_SCHEMA = "qazmorph-toolchain-archive-lock-v1"
ARCHIVE_FIELDS = frozenset(
    {"filename", "package", "version", "architecture", "bytes", "sha256"}
)


class ManifestError(RuntimeError):
    """Raised when a toolchain cannot be described or verified exactly."""


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def file_record(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise ManifestError(f"required file is missing: {path}")
    return {"bytes": path.stat().st_size, "sha256": sha256(path)}


def canonical_hash(value: Any) -> str:
    encoded = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def command_output(
    command: list[str], *, environment: dict[str, str], require_success: bool = True
) -> str:
    completed = subprocess.run(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
        env=environment,
    )
    output = "\n".join(line.rstrip() for line in completed.stdout.splitlines()).strip()
    # HFST prints argv[0] in its version banner. Staged extraction paths are
    # intentionally random, so canonicalize that one path before hashing.
    output = output.replace(command[0], Path(command[0]).name)
    if completed.returncode and require_success:
        raise ManifestError(
            f"version command failed ({completed.returncode}): {' '.join(command)}: {output}"
        )
    if not output:
        raise ManifestError(f"command produced no identifying output: {' '.join(command)}")
    return output


def extracted_files(root: Path, *, output: Path) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    output_resolved = output.resolve(strict=False)
    for path in sorted(root.rglob("*"), key=lambda candidate: candidate.as_posix()):
        if path.resolve(strict=False) == output_resolved:
            continue
        relative = path.relative_to(root).as_posix()
        metadata = path.lstat()
        mode = stat.S_IMODE(metadata.st_mode)
        if path.is_symlink():
            result[relative] = {
                "kind": "symlink",
                "mode": f"{mode:04o}",
                "target": os.readlink(path),
            }
        elif path.is_file():
            result[relative] = {
                "kind": "file",
                "mode": f"{mode:04o}",
                "bytes": metadata.st_size,
                "sha256": sha256(path),
            }
    if not result:
        raise ManifestError(f"toolchain directory has no files: {root}")
    return result


def deb_metadata(path: Path) -> dict[str, Any]:
    fields = command_output(
        ["dpkg-deb", "--field", str(path), "Package", "Version", "Architecture"],
        environment=os.environ.copy(),
    ).splitlines()
    parsed: dict[str, str] = {}
    for line in fields:
        key, separator, value = line.partition(":")
        if separator:
            parsed[key.strip().lower()] = value.strip()
    missing = {"package", "version", "architecture"} - parsed.keys()
    if missing:
        raise ManifestError(f"missing {sorted(missing)} in dpkg metadata for {path}")
    return {
        "filename": path.name,
        "package": parsed["package"],
        "version": parsed["version"],
        "architecture": parsed["architecture"],
        "bytes": path.stat().st_size,
        "sha256": sha256(path),
    }


def load_archive_lock(path: Path) -> dict[str, Any]:
    try:
        lock = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ManifestError(f"cannot read toolchain archive lock {path}: {exc}") from exc
    if not isinstance(lock, dict) or lock.get("schema") != LOCK_SCHEMA:
        raise ManifestError(f"unsupported toolchain archive lock schema: {path}")
    if set(lock) != {
        "schema",
        "distribution",
        "architecture",
        "required_commands",
        "packages",
    }:
        raise ManifestError(f"unexpected fields in toolchain archive lock: {path}")
    if not isinstance(lock["distribution"], str) or not lock["distribution"]:
        raise ManifestError(f"invalid distribution in toolchain archive lock: {path}")
    if not isinstance(lock["architecture"], str) or not lock["architecture"]:
        raise ManifestError(f"invalid architecture in toolchain archive lock: {path}")
    commands = lock.get("required_commands")
    if (
        not isinstance(commands, list)
        or not commands
        or any(not isinstance(command, str) or not command for command in commands)
        or len(set(commands)) != len(commands)
    ):
        raise ManifestError(f"invalid required command set in toolchain archive lock: {path}")
    packages = lock.get("packages")
    if not isinstance(packages, list) or not packages:
        raise ManifestError(f"toolchain archive lock has no packages: {path}")
    filenames: set[str] = set()
    package_names: set[str] = set()
    for index, record in enumerate(packages):
        if not isinstance(record, dict) or set(record) != ARCHIVE_FIELDS:
            raise ManifestError(f"invalid package record {index} in toolchain archive lock")
        for field in ("filename", "package", "version", "architecture", "sha256"):
            if not isinstance(record[field], str) or not record[field]:
                raise ManifestError(f"invalid {field} in toolchain archive record {index}")
        if not record["filename"].endswith(".deb") or Path(record["filename"]).name != record["filename"]:
            raise ManifestError(f"unsafe archive filename in toolchain lock: {record['filename']!r}")
        if record["architecture"] != lock["architecture"]:
            raise ManifestError(f"architecture mismatch in toolchain archive record {index}")
        if not isinstance(record["bytes"], int) or record["bytes"] <= 0:
            raise ManifestError(f"invalid byte size in toolchain archive record {index}")
        digest = record["sha256"]
        if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
            raise ManifestError(f"invalid SHA-256 in toolchain archive record {index}")
        if record["filename"] in filenames or record["package"] in package_names:
            raise ManifestError("duplicate archive filename or package in toolchain lock")
        filenames.add(record["filename"])
        package_names.add(record["package"])
    return lock


def verify_archive_records(
    expected: list[dict[str, Any]], actual: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    expected_by_name = {record["filename"]: record for record in expected}
    actual_by_name = {record["filename"]: record for record in actual}
    missing = sorted(set(expected_by_name) - set(actual_by_name))
    extra = sorted(set(actual_by_name) - set(expected_by_name))
    changed: dict[str, dict[str, dict[str, Any]]] = {}
    for filename in sorted(set(expected_by_name) & set(actual_by_name)):
        expected_record = expected_by_name[filename]
        actual_record = actual_by_name[filename]
        differences = {
            field: {"expected": expected_record[field], "actual": actual_record[field]}
            for field in sorted(ARCHIVE_FIELDS)
            if expected_record[field] != actual_record[field]
        }
        if differences:
            changed[filename] = differences
    if missing or extra or changed:
        raise ManifestError(
            "downloaded Debian archives differ from the checked-in lock: "
            f"missing={missing}, extra={extra}, changed={changed}"
        )
    return sorted(actual, key=lambda record: record["filename"])


def verify_archives(lock: dict[str, Any], deb_dir: Path) -> list[dict[str, Any]]:
    if not deb_dir.is_dir():
        raise ManifestError(f"Debian archive directory does not exist: {deb_dir}")
    unexpected = sorted(
        path.name for path in deb_dir.iterdir() if not path.is_file() or path.suffix != ".deb"
    )
    if unexpected:
        raise ManifestError(f"unexpected entries in Debian archive directory: {unexpected}")
    actual = [deb_metadata(path) for path in sorted(deb_dir.glob("*.deb"))]
    return verify_archive_records(lock["packages"], actual)


def build_manifest(
    toolchain_dir: Path,
    deb_dir: Path,
    output: Path,
    archive_lock: dict[str, Any],
    archive_lock_path: Path,
) -> dict[str, Any]:
    if not toolchain_dir.is_dir():
        raise ManifestError(f"toolchain directory does not exist: {toolchain_dir}")
    packages = verify_archives(archive_lock, deb_dir)

    library_paths = (
        toolchain_dir / "usr/lib/x86_64-linux-gnu",
        toolchain_dir / "usr/lib",
    )
    environment = os.environ.copy()
    environment["LC_ALL"] = "C.UTF-8"
    environment["LANG"] = "C.UTF-8"
    environment["TZ"] = "UTC"
    environment["LD_LIBRARY_PATH"] = os.pathsep.join(
        str(path) for path in library_paths if path.is_dir()
    )

    commands: dict[str, dict[str, Any]] = {}
    for name in archive_lock["required_commands"]:
        executable = toolchain_dir / "usr/bin" / name
        if not executable.is_file() or not os.access(executable, os.X_OK):
            raise ManifestError(f"required toolchain executable is missing: {executable}")
        commands[name] = {
            "path": f"usr/bin/{name}",
            "sha256": sha256(executable),
            "version_output": command_output(
                [str(executable), "--version"],
                environment=environment,
                require_success=False,
            ),
        }

    identity: dict[str, Any] = {
        "schema": SCHEMA,
        "distribution": archive_lock["distribution"],
        "architecture": archive_lock["architecture"],
        "archive_lock": {
            "schema": archive_lock["schema"],
            "file": file_record(archive_lock_path),
        },
        "packages": packages,
        "commands": commands,
        "files": extracted_files(toolchain_dir, output=output),
    }
    bundle_id = canonical_hash(identity)
    return {
        **identity,
        "bundle_id": bundle_id,
        "version": f"ubuntu-noble-hfst-cg3-{bundle_id[:16]}",
    }


def atomic_write(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(value, stream, ensure_ascii=False, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o644)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--toolchain-dir", type=Path)
    parser.add_argument("--deb-dir", type=Path)
    parser.add_argument("--lock", required=True, type=Path)
    parser.add_argument("--output", type=Path)
    action = parser.add_mutually_exclusive_group()
    action.add_argument("--verify", action="store_true")
    action.add_argument("--verify-archives-only", action="store_true")
    action.add_argument("--print-package-specs", action="store_true")
    args = parser.parse_args()

    archive_lock_path = args.lock.resolve()
    archive_lock = load_archive_lock(archive_lock_path)
    if args.print_package_specs:
        for package in archive_lock["packages"]:
            print(f"{package['package']}={package['version']}")
        return 0
    if args.deb_dir is None:
        parser.error("--deb-dir is required unless --print-package-specs is used")
    deb_dir = args.deb_dir.resolve()
    if args.verify_archives_only:
        packages = verify_archives(archive_lock, deb_dir)
        print(
            canonical_hash(
                {"lock": file_record(archive_lock_path), "packages": packages}
            )
        )
        return 0
    if args.toolchain_dir is None:
        parser.error("--toolchain-dir is required unless --verify-archives-only is used")
    output = args.output or args.toolchain_dir / "manifest.json"

    expected = build_manifest(
        args.toolchain_dir.resolve(),
        deb_dir,
        output.resolve(),
        archive_lock,
        archive_lock_path,
    )
    if args.verify:
        try:
            actual = json.loads(output.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ManifestError(f"cannot read toolchain manifest {output}: {exc}") from exc
        if actual != expected:
            raise ManifestError(f"toolchain manifest verification failed: {output}")
        print(expected["bundle_id"])
        return 0

    atomic_write(output, expected)
    print(expected["bundle_id"])
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ManifestError as error:
        raise SystemExit(f"error: {error}") from error
