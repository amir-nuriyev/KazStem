#!/usr/bin/env python3
"""Build a sealed three-command Linux runtime from the historical r4 bundle.

The script deliberately copies only the files reached by KazStem analysis,
productive guessing/generation, and Constraint Grammar.  It does not claim
generic Linux portability: host-library closure is audited separately against
Ubuntu 24.04 x86_64.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
from typing import Any


SCHEMA = "kazstem-platform-runtime-manifest-v1"
LOCK_SCHEMA = "kazstem-linux-runtime-source-lock-v1"
REQUIRED_FILES = (
    "usr/bin/hfst-apertium-proc",
    "usr/bin/hfst-optimized-lookup",
    "usr/bin/cg-proc",
    "usr/lib/x86_64-linux-gnu/libhfst.so.55.0.0",
    "usr/lib/x86_64-linux-gnu/libfst.so.22.0.0",
    "usr/lib/x86_64-linux-gnu/libfoma.so.0.10.0",
    "usr/lib/x86_64-linux-gnu/libcg3.so.1",
)
REQUIRED_SYMLINKS = {
    "usr/bin/hfst-proc": "hfst-apertium-proc",
    "usr/lib/x86_64-linux-gnu/libhfst.so.55": "libhfst.so.55.0.0",
    "usr/lib/x86_64-linux-gnu/libfst.so.22": "libfst.so.22.0.0",
    "usr/lib/x86_64-linux-gnu/libfoma.so.0": "libfoma.so.0.10.0",
}
COMMANDS = {
    "hfst-proc": ("usr/bin/hfst-proc", ("--version",)),
    "hfst-optimized-lookup": (
        "usr/bin/hfst-optimized-lookup",
        ("--version",),
    ),
    "cg-proc": ("usr/bin/cg-proc", ("-v",)),
}


class BuildError(RuntimeError):
    pass


def runtime_sort_key(item: dict[str, Any]) -> tuple[str, str]:
    platform = item.get("platform")
    if not isinstance(platform, dict):
        raise BuildError("invalid platform runtime entry")
    system = platform.get("system")
    machine = platform.get("machine")
    if (
        not isinstance(system, str)
        or not system
        or not isinstance(machine, str)
        or not machine
    ):
        raise BuildError("invalid platform runtime entry")
    return system, machine


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def record(path: Path) -> dict[str, Any]:
    return {"bytes": path.stat().st_size, "sha256": sha256(path)}


def canonical_hash(value: Any) -> str:
    encoded = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def read_canonical_lf_json(path: Path, *, label: str) -> Any:
    try:
        payload = path.read_bytes()
    except OSError as exc:
        raise BuildError(f"cannot read {label} {path}: {exc}") from exc
    if (
        b"\r" in payload
        or payload != payload.rstrip(b" \t\r\n") + b"\n"
    ):
        raise BuildError(
            f"{label} must use UTF-8, LF-only lines, and one final LF: {path}"
        )
    try:
        return json.loads(payload.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise BuildError(f"cannot read {label} {path}: {exc}") from exc


def verify_record_set(
    root: Path, expected: list[dict[str, Any]], *, label: str
) -> list[dict[str, Any]]:
    expected_names = {item["filename"] for item in expected}
    observed = {path.name for path in root.iterdir() if path.is_file()}
    invalid = sorted(path.name for path in root.iterdir() if not path.is_file())
    if observed != expected_names or invalid:
        raise BuildError(
            f"{label} inventory mismatch: missing={sorted(expected_names-observed)}, "
            f"extra={sorted(observed-expected_names)}, invalid={invalid}"
        )
    for item in expected:
        path = root / item["filename"]
        if record(path) != {"bytes": item["bytes"], "sha256": item["sha256"]}:
            raise BuildError(f"{label} identity mismatch: {path}")
    return [dict(item) for item in expected]


def load_source_lock(path: Path) -> dict[str, Any]:
    value = read_canonical_lf_json(path, label="Linux runtime source lock")
    if not isinstance(value, dict) or value.get("schema") != LOCK_SCHEMA:
        raise BuildError(f"invalid Linux runtime source lock: {path}")
    required = {
        "schema",
        "distribution",
        "platform",
        "archives",
        "corresponding_sources",
        "components",
        "transform",
    }
    if set(value) != required:
        raise BuildError(f"unexpected source-lock fields: {sorted(set(value)^required)}")
    if value["platform"] != {
        "system": "linux",
        "machine": "x86_64",
        "minimum_os": "Ubuntu 24.04 x86_64 (glibc 2.39)",
    }:
        raise BuildError("source lock platform is not the sealed Ubuntu target")
    if value["transform"] not in (
        "exact-r4-subset",
        "exact-r4-subset-remove-unresolved-debug-links",
    ):
        raise BuildError("unsupported runtime transform")
    for field in ("archives", "corresponding_sources"):
        records = value[field]
        if not isinstance(records, list) or not records:
            raise BuildError(f"empty source-lock field: {field}")
        for item in records:
            if (
                not isinstance(item, dict)
                or Path(item.get("filename", "")).name != item.get("filename")
                or not isinstance(item.get("bytes"), int)
                or not isinstance(item.get("sha256"), str)
                or len(item["sha256"]) != 64
            ):
                raise BuildError(f"invalid {field} record: {item!r}")
    return value


def output(command: list[str], *, env: dict[str, str]) -> str:
    completed = subprocess.run(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
        check=False,
    )
    text = "\n".join(line.rstrip() for line in completed.stdout.splitlines()).strip()
    if completed.returncode or not text:
        raise BuildError(
            f"version command failed ({completed.returncode}): {command!r}: {text}"
        )
    return text.replace(command[0], Path(command[0]).name)


def files(root: Path, *, skip: Path | None = None) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
        if skip is not None and path.absolute() == skip.absolute():
            continue
        relative = path.relative_to(root).as_posix()
        mode = stat.S_IMODE(path.lstat().st_mode)
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
                **record(path),
            }
        elif not path.is_dir():
            raise BuildError(f"unsupported runtime member: {path}")
    return result


def remove_debug_links(path: Path) -> None:
    path.chmod(0o755)
    completed = subprocess.run(
        [
            "objcopy",
            "--remove-section=.gnu_debuglink",
            "--remove-section=.gnu_debugaltlink",
            str(path),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if completed.returncode:
        raise BuildError(f"objcopy failed for {path}: {completed.stderr.strip()}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--full-toolchain", required=True, type=Path)
    parser.add_argument("--archives", required=True, type=Path)
    parser.add_argument("--sources", required=True, type=Path)
    parser.add_argument("--source-lock", required=True, type=Path)
    parser.add_argument("--output-parent", required=True, type=Path)
    parser.add_argument("--lock-output", required=True, type=Path)
    parser.add_argument("--base-lock", required=True, type=Path)
    args = parser.parse_args()

    full = args.full_toolchain.resolve(strict=True)
    source_lock_path = args.source_lock.resolve(strict=True)
    source_lock = load_source_lock(source_lock_path)
    archives = verify_record_set(
        args.archives.resolve(strict=True), source_lock["archives"], label="archive"
    )
    sources = verify_record_set(
        args.sources.resolve(strict=True),
        source_lock["corresponding_sources"],
        label="corresponding source",
    )
    staging = args.output_parent.resolve() / "runtime-staging"
    if staging.exists():
        shutil.rmtree(staging)
    staging.mkdir(parents=True)

    for relative in REQUIRED_FILES:
        source = full / relative
        if not source.is_file() or source.is_symlink():
            raise BuildError(f"r4 source file is invalid: {source}")
        destination = staging / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination, follow_symlinks=False)
        if source_lock["transform"].endswith("remove-unresolved-debug-links"):
            remove_debug_links(destination)
    for relative, target in REQUIRED_SYMLINKS.items():
        source = full / relative
        if not source.is_symlink() or os.readlink(source) != target:
            raise BuildError(f"r4 source symlink is invalid: {source}")
        destination = staging / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.symlink_to(target)

    for relative in REQUIRED_FILES:
        path = staging / relative
        path.chmod(0o555 if relative.startswith("usr/bin/") else 0o444)
    for directory in sorted(
        (path for path in staging.rglob("*") if path.is_dir()),
        key=lambda item: len(item.parts),
        reverse=True,
    ):
        directory.chmod(0o555)

    manifest_path = staging / "manifest.json"
    inventory = files(staging, skip=manifest_path)
    libdir = staging / "usr/lib/x86_64-linux-gnu"
    environment = os.environ.copy()
    environment.update(
        {
            "LC_ALL": "C",
            "LANG": "C",
            "TZ": "UTC",
            "LD_LIBRARY_PATH": str(libdir),
        }
    )
    commands: dict[str, dict[str, Any]] = {}
    for name, (relative, version_args) in COMMANDS.items():
        executable = staging / relative
        resolved = executable.resolve(strict=True)
        resolved_relative = resolved.relative_to(staging).as_posix()
        metadata = inventory[resolved_relative]
        commands[name] = {
            "path": relative,
            "sha256": metadata["sha256"],
            "version_output": output([str(executable), *version_args], env=environment),
        }

    identity: dict[str, Any] = {
        "schema": SCHEMA,
        "distribution": source_lock["distribution"],
        "platform": {"system": "linux", "machine": "x86_64"},
        "minimum_os": source_lock["platform"]["minimum_os"],
        "source_lock": {"schema": LOCK_SCHEMA, "file": record(source_lock_path)},
        "archives": archives,
        "corresponding_sources": sources,
        "components": source_lock["components"],
        "commands": commands,
        "files": inventory,
    }
    bundle_id = canonical_hash(identity)
    manifest = {
        **identity,
        "bundle_id": bundle_id,
        "version": f"ubuntu24.04-x86_64-hfst3.16.0-cg3-1.4.6-{bundle_id[:16]}",
    }
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    manifest_path.chmod(0o444)
    staging.chmod(0o555)

    final = args.output_parent.resolve() / bundle_id
    if final.exists():
        shutil.rmtree(final)
    staging.rename(final)

    base_lock = read_canonical_lf_json(
        args.base_lock.resolve(strict=True),
        label="base platform runtime lock",
    )
    if base_lock.get("schema") != "kazstem-platform-runtime-lock-v1":
        raise BuildError("invalid base platform runtime lock")
    runtimes = [
        item
        for item in base_lock.get("runtimes", [])
        if item.get("platform") != {"system": "linux", "machine": "x86_64"}
    ]
    runtimes.append(
        {
            "platform": {"system": "linux", "machine": "x86_64"},
            "resource_bundle_ids": [
                "f03e703d3e2a67044a7d91fd7d575b92cb4e61aa782fb67cff91b0a5ff0ebd5a"
            ],
            "bundle_id": bundle_id,
            "manifest": record(final / "manifest.json"),
        }
    )
    runtimes.sort(key=runtime_sort_key)
    lock = {"schema": base_lock["schema"], "runtimes": runtimes}
    args.lock_output.parent.mkdir(parents=True, exist_ok=True)
    args.lock_output.write_text(
        json.dumps(lock, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(bundle_id)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (BuildError, OSError, ValueError, json.JSONDecodeError) as error:
        raise SystemExit(f"error: {error}") from error
