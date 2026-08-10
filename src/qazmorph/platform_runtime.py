"""Select content-addressed native runtimes shipped beside KazStem resources."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import platform as host_platform
import sys
from typing import Any


PLATFORM_RUNTIME_LOCK_SCHEMA = "kazstem-platform-runtime-lock-v1"
PLATFORM_RUNTIME_MANIFEST_SCHEMA = "kazstem-platform-runtime-manifest-v1"
PLATFORM_RUNTIME_LOCK_PATH = Path(__file__).with_name(
    "platform_runtime_assets.lock.json"
)


class PlatformRuntimeError(RuntimeError):
    """Raised when a checked-in native-runtime binding cannot be honored."""


@dataclass(frozen=True)
class PlatformRuntimeBinding:
    directory: Path
    binding: dict[str, Any]
    lock_entry: dict[str, Any]
    manifest: dict[str, Any]
    origin: str = "platform-runtime-lock"


def _is_sha256(value: object) -> bool:
    return bool(
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def normalized_runtime_platform(
    system: str | None = None, machine: str | None = None
) -> tuple[str, str]:
    """Return the stable platform key used by the checked-in runtime lock."""

    observed_system = (system if system is not None else sys.platform).lower()
    observed_machine = (
        machine if machine is not None else host_platform.machine()
    ).lower()
    system_aliases = {
        "darwin": "darwin",
        "linux": "linux",
        "win32": "windows",
        "cygwin": "windows",
        "msys": "windows",
        "windows": "windows",
    }
    machine_aliases = {
        "aarch64": "arm64",
        "arm64": "arm64",
        "amd64": "x86_64",
        "x64": "x86_64",
        "x86_64": "x86_64",
    }
    return (
        system_aliases.get(observed_system, observed_system),
        machine_aliases.get(observed_machine, observed_machine),
    )


def _validate_lock(lock: object, *, source: str) -> dict[str, Any]:
    if not isinstance(lock, dict) or lock.get("schema") != PLATFORM_RUNTIME_LOCK_SCHEMA:
        raise PlatformRuntimeError(f"unsupported platform runtime lock schema: {source}")
    if set(lock) != {"schema", "runtimes"}:
        raise PlatformRuntimeError(f"unexpected fields in platform runtime lock: {source}")
    runtimes = lock.get("runtimes")
    if not isinstance(runtimes, list) or not runtimes:
        raise PlatformRuntimeError(f"platform runtime lock has no runtimes: {source}")

    seen: set[tuple[str, str, str]] = set()
    for index, entry in enumerate(runtimes):
        if not isinstance(entry, dict) or set(entry) != {
            "platform",
            "resource_bundle_ids",
            "bundle_id",
            "manifest",
        }:
            raise PlatformRuntimeError(
                f"invalid platform runtime record {index} in {source}"
            )
        selected_platform = entry.get("platform")
        if not isinstance(selected_platform, dict) or set(selected_platform) != {
            "system",
            "machine",
        }:
            raise PlatformRuntimeError(
                f"invalid platform key in runtime record {index}"
            )
        system = selected_platform.get("system")
        machine = selected_platform.get("machine")
        if (
            not isinstance(system, str)
            or not isinstance(machine, str)
            or normalized_runtime_platform(system, machine) != (system, machine)
        ):
            raise PlatformRuntimeError(
                f"non-canonical platform key in runtime record {index}"
            )
        resource_ids = entry.get("resource_bundle_ids")
        if (
            not isinstance(resource_ids, list)
            or not resource_ids
            or any(not _is_sha256(value) for value in resource_ids)
            or len(set(resource_ids)) != len(resource_ids)
        ):
            raise PlatformRuntimeError(
                f"invalid resource binding in runtime record {index}"
            )
        bundle_id = entry.get("bundle_id")
        manifest = entry.get("manifest")
        if not _is_sha256(bundle_id):
            raise PlatformRuntimeError(
                f"invalid bundle identity in runtime record {index}"
            )
        if (
            not isinstance(manifest, dict)
            or set(manifest) != {"bytes", "sha256"}
            or not isinstance(manifest.get("bytes"), int)
            or manifest["bytes"] <= 0
            or not _is_sha256(manifest.get("sha256"))
        ):
            raise PlatformRuntimeError(
                f"invalid manifest binding in runtime record {index}"
            )
        for resource_id in resource_ids:
            key = (system, machine, resource_id)
            if key in seen:
                raise PlatformRuntimeError(
                    f"duplicate platform/resource binding in runtime record {index}"
                )
            seen.add(key)
    return lock


def load_platform_runtime_lock(
    path: str | Path | None = None,
) -> dict[str, Any]:
    selected = Path(path) if path is not None else PLATFORM_RUNTIME_LOCK_PATH
    try:
        value = json.loads(selected.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PlatformRuntimeError(
            f"cannot read platform runtime lock {selected}: {exc}"
        ) from exc
    return _validate_lock(value, source=str(selected))


def resolve_platform_runtime(
    resource_dir: Path,
    resource_bundle_id: str,
    *,
    lock: dict[str, Any] | None = None,
    platform: tuple[str, str] | None = None,
) -> PlatformRuntimeBinding | None:
    """Resolve an exact native runtime from the resource bundle's own root.

    An unlocked platform or resource returns ``None`` so the historical
    resource-bound toolchain path remains unchanged. Once the public lock has
    a matching record, the content-addressed runtime is mandatory and every
    manifest identity check fails closed.
    """

    selected_lock = (
        load_platform_runtime_lock()
        if lock is None
        else _validate_lock(lock, source="supplied lock")
    )
    selected_platform = normalized_runtime_platform(
        *(platform if platform is not None else normalized_runtime_platform())
    )
    matching = [
        entry
        for entry in selected_lock["runtimes"]
        if (
            entry["platform"]["system"],
            entry["platform"]["machine"],
        )
        == selected_platform
        and resource_bundle_id in entry["resource_bundle_ids"]
    ]
    if not matching:
        return None
    if len(matching) != 1:
        raise PlatformRuntimeError(
            "platform runtime lock has ambiguous matching records"
        )
    entry = matching[0]
    runtime_root = resource_dir.resolve(strict=True).parent
    immutable_root = runtime_root / "platform-runtimes"
    candidate = immutable_root / entry["bundle_id"]
    manifest_path = candidate / "manifest.json"
    try:
        if immutable_root.is_symlink() or candidate.is_symlink():
            raise OSError("content-addressed runtime path is a symlink")
        resolved_root = immutable_root.resolve(strict=True)
        resolved = candidate.resolve(strict=True)
        if resolved.parent != resolved_root:
            raise OSError("content-addressed runtime escapes bundled root")
        if not resolved.is_dir():
            raise OSError("content-addressed runtime is not a directory")
        if manifest_path.is_symlink() or not manifest_path.is_file():
            raise OSError("runtime manifest is not a regular file")
        data = manifest_path.read_bytes()
        stat = manifest_path.stat()
    except OSError as exc:
        raise PlatformRuntimeError(
            f"locked platform runtime is unavailable: {manifest_path}: {exc}"
        ) from exc

    expected = entry["manifest"]
    digest = hashlib.sha256(data).hexdigest()
    if stat.st_size != expected["bytes"] or digest != expected["sha256"]:
        raise PlatformRuntimeError(
            f"locked platform runtime is unavailable: manifest identity mismatch: {manifest_path}"
        )
    try:
        described = json.loads(data.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise PlatformRuntimeError(
            f"locked platform runtime is unavailable: invalid manifest: {manifest_path}"
        ) from exc
    if (
        not isinstance(described, dict)
        or described.get("schema") != PLATFORM_RUNTIME_MANIFEST_SCHEMA
        or described.get("bundle_id") != entry["bundle_id"]
        or described.get("platform") != entry["platform"]
        or not isinstance(described.get("commands"), dict)
        or not isinstance(described.get("files"), dict)
    ):
        raise PlatformRuntimeError(
            f"locked platform runtime is unavailable: manifest contents mismatch: {manifest_path}"
        )
    identity = {
        key: value
        for key, value in described.items()
        if key not in {"bundle_id", "version"}
    }
    encoded_identity = json.dumps(
        identity, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    if hashlib.sha256(encoded_identity).hexdigest() != entry["bundle_id"]:
        raise PlatformRuntimeError(
            f"locked platform runtime is unavailable: bundle identity checksum failed: {manifest_path}"
        )
    binding = {
        "bundle_id": entry["bundle_id"],
        "manifest": dict(expected),
    }
    return PlatformRuntimeBinding(
        directory=resolved,
        binding=binding,
        lock_entry=dict(entry),
        manifest=described,
    )
