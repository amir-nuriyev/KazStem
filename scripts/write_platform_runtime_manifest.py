#!/usr/bin/env python3
"""Create or verify a detached, content-addressed native runtime manifest."""

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


SCHEMA = "kazstem-platform-runtime-manifest-v1"
LOCK_SCHEMA = "kazstem-platform-runtime-source-lock-v1"


class ManifestError(RuntimeError):
    pass


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def file_record(path: Path) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink():
        raise ManifestError(f"required regular file is missing: {path}")
    return {"bytes": path.stat().st_size, "sha256": sha256(path)}


def canonical_hash(value: Any) -> str:
    encoded = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _is_sha256(value: object) -> bool:
    return bool(
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def load_source_lock(path: Path) -> dict[str, Any]:
    try:
        lock = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ManifestError(f"cannot read platform runtime source lock {path}: {exc}") from exc
    if not isinstance(lock, dict) or lock.get("schema") != LOCK_SCHEMA:
        raise ManifestError(f"unsupported platform runtime source lock schema: {path}")
    if set(lock) != {
        "schema",
        "distribution",
        "platform",
        "required_commands",
        "archives",
        "corresponding_sources",
        "components",
    }:
        raise ManifestError(f"unexpected fields in platform runtime source lock: {path}")
    selected_platform = lock.get("platform")
    if (
        not isinstance(selected_platform, dict)
        or set(selected_platform) != {"system", "machine", "minimum_os"}
        or any(
            not isinstance(selected_platform.get(name), str)
            or not selected_platform[name]
            for name in ("system", "machine", "minimum_os")
        )
    ):
        raise ManifestError(f"invalid platform in source lock: {path}")
    commands = lock.get("required_commands")
    if not isinstance(commands, list) or not commands:
        raise ManifestError(f"source lock has no required commands: {path}")
    command_names: set[str] = set()
    for index, command in enumerate(commands):
        if not isinstance(command, dict) or set(command) != {
            "name",
            "path",
            "version_args",
        }:
            raise ManifestError(f"invalid required command record {index}")
        name = command.get("name")
        relative = command.get("path")
        version_args = command.get("version_args")
        if (
            not isinstance(name, str)
            or not name
            or name in command_names
            or not isinstance(relative, str)
            or Path(relative).is_absolute()
            or ".." in Path(relative).parts
            or not isinstance(version_args, list)
            or not version_args
            or any(not isinstance(value, str) or not value for value in version_args)
        ):
            raise ManifestError(f"invalid required command record {index}")
        command_names.add(name)
    for field in ("archives", "corresponding_sources"):
        records = lock.get(field)
        if not isinstance(records, list) or not records:
            raise ManifestError(f"source lock has no {field}: {path}")
        filenames: set[str] = set()
        for index, record in enumerate(records):
            expected_fields = (
                {"component", "filename", "url", "bytes", "sha256"}
                if field == "archives"
                else {
                    "component",
                    "revision",
                    "filename",
                    "url",
                    "bytes",
                    "sha256",
                }
            )
            if not isinstance(record, dict) or set(record) != expected_fields:
                raise ManifestError(f"invalid {field} record {index}")
            filename = record.get("filename")
            if (
                not isinstance(filename, str)
                or Path(filename).name != filename
                or filename in filenames
                or not isinstance(record.get("bytes"), int)
                or record["bytes"] <= 0
                or not _is_sha256(record.get("sha256"))
            ):
                raise ManifestError(f"invalid {field} record {index}")
            filenames.add(filename)
    components = lock.get("components")
    if not isinstance(components, list) or not components:
        raise ManifestError(f"source lock has no component license inventory: {path}")
    for index, component in enumerate(components):
        if (
            not isinstance(component, dict)
            or set(component) != {"name", "version", "license"}
            or any(
                not isinstance(component.get(field), str) or not component[field]
                for field in ("name", "version", "license")
            )
        ):
            raise ManifestError(f"invalid component record {index}")
    return lock


def verify_record_directory(
    records: list[dict[str, Any]], root: Path, *, label: str
) -> list[dict[str, Any]]:
    expected = {record["filename"] for record in records}
    try:
        observed = {path.name for path in root.iterdir() if path.is_file()}
        invalid = sorted(path.name for path in root.iterdir() if not path.is_file())
    except OSError as exc:
        raise ManifestError(f"cannot read {label} directory {root}: {exc}") from exc
    if observed != expected or invalid:
        raise ManifestError(
            f"{label} directory differs from lock "
            f"(missing={sorted(expected - observed)}, extra={sorted(observed - expected)}, "
            f"invalid={invalid})"
        )
    verified: list[dict[str, Any]] = []
    for record in records:
        candidate = root / record["filename"]
        actual = file_record(candidate)
        if actual != {"bytes": record["bytes"], "sha256": record["sha256"]}:
            raise ManifestError(f"{label} identity mismatch: {candidate}")
        verified.append(dict(record))
    return verified


def command_output(command: list[str]) -> str:
    environment = os.environ.copy()
    environment.update({"LC_ALL": "C", "LANG": "C", "TZ": "UTC"})
    completed = subprocess.run(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=environment,
        check=False,
    )
    output = "\n".join(line.rstrip() for line in completed.stdout.splitlines()).strip()
    output = output.replace(command[0], Path(command[0]).name)
    if completed.returncode or not output:
        raise ManifestError(
            f"version command failed ({completed.returncode}): {' '.join(command)}: {output}"
        )
    return output


def extracted_files(root: Path, *, output: Path) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    output_lexical = output.absolute()
    for path in sorted(root.rglob("*"), key=lambda value: value.as_posix()):
        if path.absolute() == output_lexical:
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
        elif not path.is_dir():
            raise ManifestError(
                f"unsupported platform runtime entry type: {path}"
            )
    if not result:
        raise ManifestError(f"platform runtime directory has no files: {root}")
    return result


def build_manifest(
    runtime_dir: Path,
    archive_dir: Path,
    source_dir: Path,
    output: Path,
    source_lock: dict[str, Any],
    source_lock_path: Path,
) -> dict[str, Any]:
    archives = verify_record_directory(source_lock["archives"], archive_dir, label="archive")
    corresponding_sources = verify_record_directory(
        source_lock["corresponding_sources"], source_dir, label="source"
    )
    commands: dict[str, dict[str, Any]] = {}
    files = extracted_files(runtime_dir, output=output)
    for command in source_lock["required_commands"]:
        executable = runtime_dir / command["path"]
        if not executable.is_file() or not os.access(executable, os.X_OK):
            raise ManifestError(f"required runtime executable is missing: {executable}")
        resolved = executable.resolve(strict=True)
        try:
            resolved_relative = resolved.relative_to(runtime_dir).as_posix()
        except ValueError as exc:
            raise ManifestError(f"runtime executable escapes bundle: {executable}") from exc
        file_metadata = files.get(resolved_relative)
        if not isinstance(file_metadata, dict) or file_metadata.get("kind") != "file":
            raise ManifestError(f"runtime executable is absent from inventory: {executable}")
        commands[command["name"]] = {
            "path": command["path"],
            "sha256": file_metadata["sha256"],
            "version_output": command_output(
                [str(executable), *command["version_args"]]
            ),
        }
    selected_platform = source_lock["platform"]
    identity: dict[str, Any] = {
        "schema": SCHEMA,
        "distribution": source_lock["distribution"],
        "platform": {
            "system": selected_platform["system"],
            "machine": selected_platform["machine"],
        },
        "minimum_os": selected_platform["minimum_os"],
        "source_lock": {
            "schema": source_lock["schema"],
            "file": file_record(source_lock_path),
        },
        "archives": archives,
        "corresponding_sources": corresponding_sources,
        "components": source_lock["components"],
        "commands": commands,
        "files": files,
    }
    bundle_id = canonical_hash(identity)
    return {
        **identity,
        "bundle_id": bundle_id,
        "version": f"macos-arm64-hfst3.17.2-cg3-1.6.8-{bundle_id[:16]}",
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
        os.chmod(temporary, 0o444)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime-dir", required=True, type=Path)
    parser.add_argument("--archive-dir", required=True, type=Path)
    parser.add_argument("--source-dir", required=True, type=Path)
    parser.add_argument("--lock", required=True, type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--verify", action="store_true")
    args = parser.parse_args()

    runtime_dir = args.runtime_dir.resolve()
    output = (args.output or runtime_dir / "manifest.json").resolve()
    source_lock_path = args.lock.resolve()
    source_lock = load_source_lock(source_lock_path)
    expected = build_manifest(
        runtime_dir,
        args.archive_dir.resolve(),
        args.source_dir.resolve(),
        output,
        source_lock,
        source_lock_path,
    )
    if args.verify:
        try:
            actual = json.loads(output.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise ManifestError(f"cannot read platform runtime manifest {output}: {exc}") from exc
        if actual != expected:
            raise ManifestError(f"platform runtime manifest verification failed: {output}")
    else:
        atomic_write(output, expected)
    print(expected["bundle_id"])
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ManifestError as error:
        raise SystemExit(f"error: {error}") from error
