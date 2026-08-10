#!/usr/bin/env python3
"""Create or verify a detached, content-addressed native runtime manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
from pathlib import PurePosixPath, PureWindowsPath
import re
import stat
import struct
import subprocess
import tempfile
from typing import Any
from urllib.parse import urlsplit


SCHEMA = "kazstem-platform-runtime-manifest-v1"
LOCK_SCHEMA = "kazstem-platform-runtime-source-lock-v1"
SOURCE_LOCK_REQUIRED_FIELDS = {
    "schema",
    "distribution",
    "platform",
    "required_commands",
    "archives",
    "corresponding_sources",
    "components",
}
SOURCE_LOCK_OPTIONAL_FIELDS = {"runtime_version_label", "dependency_policy"}
PE_IMPORT_CLOSURE_SCHEMA = "kazstem-pe-import-closure-v1"
PE_MACHINE_X86_64 = 0x8664


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


def safe_relative_path(value: object) -> str | None:
    """Return a canonical slash-separated relative path, or ``None``.

    Source locks are checked on more than one host OS.  Checking with only the
    host's ``Path`` class would, for example, accept a Windows drive path while
    running the verifier on Linux.  Require one portable spelling instead.
    """

    if not isinstance(value, str) or not value or "\x00" in value or "\\" in value:
        return None
    posix = PurePosixPath(value)
    windows = PureWindowsPath(value)
    if (
        posix.is_absolute()
        or windows.is_absolute()
        or windows.drive
        or value != posix.as_posix()
        or any(part in {"", ".", ".."} for part in posix.parts)
    ):
        return None
    return value


def load_source_lock(path: Path) -> dict[str, Any]:
    try:
        lock = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ManifestError(f"cannot read platform runtime source lock {path}: {exc}") from exc
    if not isinstance(lock, dict) or lock.get("schema") != LOCK_SCHEMA:
        raise ManifestError(f"unsupported platform runtime source lock schema: {path}")
    fields = set(lock)
    if not SOURCE_LOCK_REQUIRED_FIELDS <= fields or not fields <= (
        SOURCE_LOCK_REQUIRED_FIELDS | SOURCE_LOCK_OPTIONAL_FIELDS
    ):
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
            or safe_relative_path(relative) is None
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
            url = record.get("url")
            parsed_url = urlsplit(url) if isinstance(url, str) else None
            if (
                not isinstance(filename, str)
                or safe_file_name(filename) is None
                or filename in filenames
                or not isinstance(record.get("bytes"), int)
                or isinstance(record.get("bytes"), bool)
                or record["bytes"] <= 0
                or not _is_sha256(record.get("sha256"))
                or not isinstance(record.get("component"), str)
                or not record["component"]
                or parsed_url is None
                or parsed_url.scheme != "https"
                or not parsed_url.netloc
                or parsed_url.username is not None
                or parsed_url.password is not None
                or bool(parsed_url.fragment)
                or (
                    field == "corresponding_sources"
                    and (
                        not isinstance(record.get("revision"), str)
                        or not record["revision"]
                    )
                )
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
    version_label = lock.get("runtime_version_label")
    if version_label is not None and (
        not isinstance(version_label, str)
        or re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,126}[a-z0-9]", version_label)
        is None
    ):
        raise ManifestError(f"invalid runtime version label in source lock: {path}")
    dependency_policy = lock.get("dependency_policy")
    if dependency_policy is not None:
        if (
            not isinstance(dependency_policy, dict)
            or set(dependency_policy)
            != {"format", "allowed_system_libraries"}
            or dependency_policy.get("format") != "pe-import-closure-v1"
            or not isinstance(
                dependency_policy.get("allowed_system_libraries"), list
            )
            or not dependency_policy["allowed_system_libraries"]
            or any(
                not isinstance(name, str)
                or name != name.casefold()
                or safe_file_name(name) is None
                or not name.endswith(".dll")
                for name in dependency_policy["allowed_system_libraries"]
            )
            or dependency_policy["allowed_system_libraries"]
            != sorted(set(dependency_policy["allowed_system_libraries"]))
        ):
            raise ManifestError(f"invalid dependency policy in source lock: {path}")
    return lock


def safe_file_name(value: str) -> str | None:
    """Validate a single portable filename used by a dependency allowlist."""

    if (
        not value
        or "\x00" in value
        or "/" in value
        or "\\" in value
        or PureWindowsPath(value).drive
        or value in {".", ".."}
    ):
        return None
    return value


def runtime_version_label(source_lock: dict[str, Any]) -> str:
    label = source_lock.get("runtime_version_label")
    if isinstance(label, str):
        return label
    # Compatibility path for the already-sealed legacy macOS runtime. New
    # platform locks must supply an explicit truthful label.
    if source_lock.get("platform") != {
        "system": "darwin",
        "machine": "arm64",
        "minimum_os": "14.0",
    }:
        raise ManifestError(
            "non-legacy platform source lock requires runtime_version_label"
        )
    return "macos-arm64-hfst3.17.2-cg3-1.6.8"


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
    # Resolve the directory entry itself before walking it.  macOS exposes
    # /var as a symlink to /private/var, and a TemporaryDirectory can therefore
    # give us lexical children below /var whose resolved targets are below
    # /private/var.  Comparing either form to an unresolved root falsely looks
    # like a bundle escape.  Resolve ancestors of the output as well, but keep
    # its final path component lexical so that an output symlink elsewhere in
    # the inventory is still recorded as a symlink rather than skipped.
    root = root.resolve(strict=True)
    output_lexical = output.parent.resolve(strict=True) / output.name
    result: dict[str, dict[str, Any]] = {}
    for path in sorted(root.rglob("*"), key=lambda value: value.as_posix()):
        if path == output_lexical:
            continue
        relative = path.relative_to(root).as_posix()
        metadata = path.lstat()
        mode = stat.S_IMODE(metadata.st_mode)
        if path.is_symlink():
            try:
                path.resolve(strict=True).relative_to(root)
            except (OSError, ValueError) as exc:
                raise ManifestError(
                    f"platform runtime symlink escapes bundle: {path}"
                ) from exc
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


def _pe_imports(path: Path) -> tuple[int, tuple[str, ...]]:
    """Read regular and delay-load imports without executing a PE file."""

    try:
        data = path.read_bytes()
    except OSError as exc:
        raise ManifestError(f"cannot read PE file {path}: {exc}") from exc

    def unpack(fmt: str, offset: int) -> tuple[Any, ...]:
        size = struct.calcsize(fmt)
        if offset < 0 or offset + size > len(data):
            raise ManifestError(f"truncated PE structure: {path}")
        return struct.unpack_from(fmt, data, offset)

    if len(data) < 0x40 or data[:2] != b"MZ":
        raise ManifestError(f"runtime entry is not a PE file: {path}")
    (pe_offset,) = unpack("<I", 0x3C)
    if pe_offset < 0x40 or pe_offset + 24 > len(data):
        raise ManifestError(f"invalid PE header offset: {path}")
    if data[pe_offset : pe_offset + 4] != b"PE\x00\x00":
        raise ManifestError(f"runtime entry has no PE signature: {path}")
    machine, section_count, _timestamp, _symbols, _symbol_count, optional_size, _flags = unpack(
        "<HHIIIHH", pe_offset + 4
    )
    optional_offset = pe_offset + 24
    if optional_size < 2 or optional_offset + optional_size > len(data):
        raise ManifestError(f"invalid PE optional header: {path}")
    (magic,) = unpack("<H", optional_offset)
    if magic == 0x20B:  # PE32+
        image_base = unpack("<Q", optional_offset + 24)[0]
        directory_count_offset = optional_offset + 108
        directory_offset = optional_offset + 112
    elif magic == 0x10B:  # PE32
        image_base = unpack("<I", optional_offset + 28)[0]
        directory_count_offset = optional_offset + 92
        directory_offset = optional_offset + 96
    else:
        raise ManifestError(f"unsupported PE optional-header magic: {path}")
    (directory_count,) = unpack("<I", directory_count_offset)
    section_offset = optional_offset + optional_size
    sections: list[tuple[int, int, int, int]] = []
    for index in range(section_count):
        offset = section_offset + index * 40
        _name, virtual_size, virtual_address, raw_size, raw_offset = unpack(
            "<8sIIII", offset
        )
        if raw_offset + raw_size > len(data):
            raise ManifestError(f"PE section exceeds file bounds: {path}")
        sections.append((virtual_address, virtual_size, raw_offset, raw_size))

    def rva_to_offset(rva: int) -> int:
        if rva == 0:
            raise ManifestError(f"invalid zero PE RVA: {path}")
        for virtual_address, virtual_size, raw_offset, raw_size in sections:
            span = max(virtual_size, raw_size)
            if virtual_address <= rva < virtual_address + span:
                delta = rva - virtual_address
                if delta >= raw_size or raw_offset + delta >= len(data):
                    break
                return raw_offset + delta
        raise ManifestError(f"PE RVA is outside backed sections: {path}")

    def c_string(rva: int) -> str:
        offset = rva_to_offset(rva)
        end = data.find(b"\x00", offset, min(len(data), offset + 4096))
        if end < 0:
            raise ManifestError(f"unterminated PE import name: {path}")
        try:
            value = data[offset:end].decode("ascii")
        except UnicodeDecodeError as exc:
            raise ManifestError(f"non-ASCII PE import name: {path}") from exc
        normalized = value.casefold()
        if safe_file_name(normalized) is None or not normalized.endswith(".dll"):
            raise ManifestError(f"unsafe PE import name {value!r}: {path}")
        return normalized

    def directory(index: int) -> tuple[int, int]:
        if directory_count <= index or directory_offset + (index + 1) * 8 > optional_offset + optional_size:
            return (0, 0)
        return unpack("<II", directory_offset + index * 8)

    imports: set[str] = set()
    import_rva, import_size = directory(1)
    if import_rva:
        offset = rva_to_offset(import_rva)
        limit = min(len(data), offset + max(import_size, 20))
        descriptors = 0
        while offset + 20 <= limit:
            descriptor = unpack("<IIIII", offset)
            if descriptor == (0, 0, 0, 0, 0):
                break
            imports.add(c_string(descriptor[3]))
            descriptors += 1
            if descriptors > 4096:
                raise ManifestError(f"excessive PE import descriptors: {path}")
            offset += 20
        else:
            raise ManifestError(f"unterminated PE import directory: {path}")

    delay_rva, delay_size = directory(13)
    if delay_rva:
        offset = rva_to_offset(delay_rva)
        limit = min(len(data), offset + max(delay_size, 32))
        descriptors = 0
        while offset + 32 <= limit:
            descriptor = unpack("<IIIIIIII", offset)
            if descriptor == (0, 0, 0, 0, 0, 0, 0, 0):
                break
            attributes, name_address = descriptor[:2]
            name_rva = (
                name_address
                if attributes & 1
                else name_address - image_base
            )
            if name_rva <= 0 or name_rva > 0xFFFFFFFF:
                raise ManifestError(f"invalid PE delay-import name address: {path}")
            imports.add(c_string(name_rva))
            descriptors += 1
            if descriptors > 4096:
                raise ManifestError(f"excessive PE delay imports: {path}")
            offset += 32
        else:
            raise ManifestError(f"unterminated PE delay-import directory: {path}")
    return machine, tuple(sorted(imports))


def audit_pe_dependency_closure(
    runtime_dir: Path,
    source_lock: dict[str, Any],
    files: dict[str, dict[str, Any]],
) -> dict[str, Any] | None:
    """Prove a minimal x86-64 PE closure from the locked command roots."""

    policy = source_lock.get("dependency_policy")
    if policy is None:
        return None
    if policy.get("format") != "pe-import-closure-v1":
        raise ManifestError("unsupported native dependency policy")
    allowed_system = set(policy["allowed_system_libraries"])
    paths = sorted(files)
    if len({path.casefold() for path in paths}) != len(paths):
        raise ManifestError("platform runtime has case-insensitive path collisions")
    if any(not path.casefold().endswith((".exe", ".dll")) for path in paths):
        raise ManifestError(
            "PE runtime inventory must contain only reachable executables and DLLs"
        )

    by_name: dict[str, str] = {}
    for relative in paths:
        name = PurePosixPath(relative).name.casefold()
        if name in by_name:
            raise ManifestError(
                f"PE runtime has ambiguous dependency basename: {name}"
            )
        by_name[name] = relative
    roots = sorted(command["path"] for command in source_lock["required_commands"])
    if any(root not in files for root in roots):
        raise ManifestError("PE dependency root is absent from runtime inventory")

    queue = list(roots)
    reached: set[str] = set()
    records: dict[str, dict[str, Any]] = {}
    observed_system: set[str] = set()
    while queue:
        relative = queue.pop(0)
        if relative in reached:
            continue
        reached.add(relative)
        machine, imports = _pe_imports(runtime_dir / relative)
        if machine != PE_MACHINE_X86_64:
            raise ManifestError(
                f"PE runtime file has non-x86_64 machine 0x{machine:04x}: {relative}"
            )
        bundled: list[str] = []
        system: list[str] = []
        for dependency in imports:
            bundled_path = by_name.get(dependency)
            if bundled_path is not None:
                bundled.append(bundled_path)
                if bundled_path not in reached:
                    queue.append(bundled_path)
            elif dependency in allowed_system:
                system.append(dependency)
                observed_system.add(dependency)
            else:
                raise ManifestError(
                    f"PE dependency is neither bundled nor allowlisted: "
                    f"{relative} -> {dependency}"
                )
        records[relative] = {
            "imports": list(imports),
            "bundled_dependencies": sorted(bundled),
            "system_dependencies": sorted(system),
        }
    if reached != set(paths):
        raise ManifestError(
            "PE runtime contains unreachable files: " + ", ".join(sorted(set(paths) - reached))
        )
    return {
        "schema": PE_IMPORT_CLOSURE_SCHEMA,
        "machine": "x86_64",
        "roots": roots,
        "files": {name: records[name] for name in sorted(records)},
        "system_libraries": sorted(observed_system),
    }


def build_manifest(
    runtime_dir: Path,
    archive_dir: Path,
    source_dir: Path,
    output: Path,
    source_lock: dict[str, Any],
    source_lock_path: Path,
) -> dict[str, Any]:
    runtime_dir = runtime_dir.resolve(strict=True)
    archive_dir = archive_dir.resolve(strict=True)
    source_dir = source_dir.resolve(strict=True)
    output = output.parent.resolve(strict=True) / output.name
    source_lock_path = source_lock_path.resolve(strict=True)
    archives = verify_record_directory(source_lock["archives"], archive_dir, label="archive")
    corresponding_sources = verify_record_directory(
        source_lock["corresponding_sources"], source_dir, label="source"
    )
    commands: dict[str, dict[str, Any]] = {}
    files = extracted_files(runtime_dir, output=output)
    windows_runtime = source_lock["platform"]["system"] == "windows"
    for command in source_lock["required_commands"]:
        executable = runtime_dir / command["path"]
        if (
            not executable.is_file()
            or executable.is_symlink()
            or (not windows_runtime and not os.access(executable, os.X_OK))
            or (
                windows_runtime
                and executable.suffix.casefold() != ".exe"
            )
        ):
            raise ManifestError(f"required runtime executable is missing: {executable}")
        resolved = executable.resolve(strict=True)
        try:
            resolved_relative = resolved.relative_to(runtime_dir).as_posix()
        except ValueError as exc:
            raise ManifestError(f"runtime executable escapes bundle: {executable}") from exc
        file_metadata = files.get(resolved_relative)
        if not isinstance(file_metadata, dict) or file_metadata.get("kind") != "file":
            raise ManifestError(f"runtime executable is absent from inventory: {executable}")
        command_record: dict[str, Any] = {
            "path": command["path"],
            "sha256": file_metadata["sha256"],
            "version_output": command_output(
                [str(executable), *command["version_args"]]
            ),
        }
        if windows_runtime:
            command_record["version_args"] = list(command["version_args"])
            command_record["os_access_x_ok"] = os.access(executable, os.X_OK)
            command_record["availability_contract"] = (
                "regular-exe-manifest-hash-successful-version-execution"
            )
        commands[command["name"]] = command_record
    dependency_closure = audit_pe_dependency_closure(
        runtime_dir, source_lock, files
    )
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
    if dependency_closure is not None:
        identity["dependency_closure"] = dependency_closure
    bundle_id = canonical_hash(identity)
    return {
        **identity,
        "bundle_id": bundle_id,
        "version": f"{runtime_version_label(source_lock)}-{bundle_id[:16]}",
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
