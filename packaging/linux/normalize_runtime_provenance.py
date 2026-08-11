#!/usr/bin/env python3
"""Convert verified runtime provenance to bundle-relative release evidence."""

from __future__ import annotations

import argparse
import json
from pathlib import Path, PureWindowsPath
from typing import Any
from urllib.parse import urlsplit

from release_common import (
    ReleaseError,
    assert_relative_json,
    ensure_output_outside,
    json_bytes,
    load_identity,
    portable_path,
    read_json,
)


LOADER_OVERRIDE_VARIABLES = (
    "LD_LIBRARY_PATH",
    "LD_PRELOAD",
    "LD_AUDIT",
    "DYLD_LIBRARY_PATH",
    "DYLD_INSERT_LIBRARIES",
    "DYLD_FRAMEWORK_PATH",
    "DYLD_FALLBACK_FRAMEWORK_PATH",
    "DYLD_FALLBACK_LIBRARY_PATH",
    "DYLD_IMAGE_SUFFIX",
    "DYLD_ROOT_PATH",
    "DYLD_SHARED_REGION",
    "DYLD_PRINT_TO_FILE",
)
ABSENT_LOADER_RECORD = {
    "ambient_present": False,
    "removed_from_helper_environment": True,
    "sha256": None,
}


def _is_absolute(value: str) -> bool:
    return (
        Path(value).is_absolute()
        or PureWindowsPath(value).is_absolute()
        or bool(PureWindowsPath(value).drive)
    )


def _relative_path(value: str, bundle_root: Path) -> str:
    try:
        relative = Path(value).resolve(strict=True).relative_to(bundle_root)
    except (OSError, ValueError) as exc:
        raise ReleaseError(
            f"runtime provenance path is outside the extracted bundle: {value!r}"
        ) from exc
    return f"bundle/{relative.as_posix()}"


def _normalize(value: Any, bundle_root: Path) -> Any:
    if isinstance(value, list):
        return [_normalize(item, bundle_root) for item in value]
    if isinstance(value, dict):
        return {key: _normalize(item, bundle_root) for key, item in value.items()}
    if not isinstance(value, str):
        return value
    parsed = urlsplit(value)
    if parsed.scheme in {"https", "http"} and parsed.netloc:
        return value
    pieces = value.split(":")
    if len(pieces) > 1 and all(_is_absolute(piece) for piece in pieces):
        return ":".join(_relative_path(piece, bundle_root) for piece in pieces)
    if _is_absolute(value):
        return _relative_path(value, bundle_root)
    return value


def _validate_clean_loader_policy(raw: dict[str, Any]) -> None:
    environment = raw.get("environment")
    if not isinstance(environment, dict):
        raise ReleaseError("runtime provenance has no environment record")
    policy = environment.get("loader_policy")
    if not isinstance(policy, dict) or set(policy) != {
        "all_ambient_values_removed_from_helper_environment",
        "ambient_records",
        "captured_name_policy",
        "clean_parent_startup",
        "glibc_tunables",
        "linux_helper_ld_library_path",
        "schema",
    }:
        raise ReleaseError("runtime provenance loader policy shape differs")
    if (
        policy["schema"] != "qazmorph-native-helper-loader-environment-v2"
        or policy["captured_name_policy"]
        != {
            "exact_uppercase_prefixes": ["LD_", "DYLD_"],
            "exact_names": ["GLIBC_TUNABLES"],
        }
        or policy["ambient_records"] != {}
        or policy["glibc_tunables"] != ABSENT_LOADER_RECORD
        or policy["clean_parent_startup"] is not True
        or policy["all_ambient_values_removed_from_helper_environment"] is not True
    ):
        raise ReleaseError("runtime provenance does not prove a clean parent/helper environment")
    linux_library_path = policy["linux_helper_ld_library_path"]
    if not isinstance(linux_library_path, dict) or set(linux_library_path) != {
        "relative_paths",
        "source",
    }:
        raise ReleaseError("runtime provenance has no bound Linux helper library path")
    relative_paths = linux_library_path["relative_paths"]
    if (
        linux_library_path["source"] != "manifest-bound-runtime"
        or not isinstance(relative_paths, list)
        or len(relative_paths) != len(set(relative_paths))
    ):
        raise ReleaseError("Linux helper library-path binding differs")
    for index, value in enumerate(relative_paths):
        portable_path(value, label=f"Linux helper library path[{index}]")
    for name in LOADER_OVERRIDE_VARIABLES:
        expected = dict(ABSENT_LOADER_RECORD)
        if name == "LD_LIBRARY_PATH":
            expected.update(
                {
                    "helper_relative_paths": relative_paths,
                    "helper_value_source": "manifest-bound-runtime",
                }
            )
        if environment.get(name) != expected:
            raise ReleaseError(
                f"runtime provenance does not prove a clean helper environment for {name}"
            )
    if environment.get("GLIBC_TUNABLES") != ABSENT_LOADER_RECORD:
        raise ReleaseError("runtime provenance does not prove clean GLIBC_TUNABLES")


def normalize(args: argparse.Namespace) -> dict[str, Any]:
    ensure_output_outside(
        args.output, args.bundle_root, label="normalized provenance output"
    )
    if args.output.exists() or args.output.is_symlink():
        raise ReleaseError(
            f"normalized provenance output already exists: {args.output}"
        )
    identity = load_identity(args.identity.resolve(strict=True))
    bundle_root = args.bundle_root.resolve(strict=True)
    if not bundle_root.is_dir() or args.bundle_root.is_symlink():
        raise ReleaseError("bundle root must be a real extracted ready-run directory")
    if bundle_root.name != identity["ready_run"]["top_level"]:
        raise ReleaseError("runtime-provenance root name differs from release identity")
    raw = read_json(args.input.resolve(strict=True))
    if not isinstance(raw, dict):
        raise ReleaseError("runtime provenance input must be a JSON object")
    if (
        raw.get("official") is not True
        or raw.get("verified") is not True
        or raw.get("non_official_reasons") != []
    ):
        raise ReleaseError(
            "runtime provenance input is not official and fully verified"
        )
    _validate_clean_loader_policy(raw)
    runtime_expected = identity["inputs"]["runtime_tree"]
    resource_expected = identity["inputs"]["resource_tree"]
    active = raw.get("active_runtime")
    toolchain_manifest = raw.get("toolchain_manifest")
    if (
        not isinstance(active, dict)
        or active.get("bundle_id") != runtime_expected["bundle_id"]
    ):
        raise ReleaseError("runtime provenance selects the wrong runtime bundle")
    binding = active.get("platform_lock")
    if (
        not isinstance(binding, dict)
        or binding.get("bundle_id") != runtime_expected["bundle_id"]
        or binding.get("manifest") != runtime_expected["manifest"]
        or resource_expected["bundle_id"] not in binding.get("resource_bundle_ids", [])
    ):
        raise ReleaseError(
            "runtime provenance differs from the checked unified platform lock"
        )
    if (
        not isinstance(toolchain_manifest, dict)
        or toolchain_manifest.get("bundle_id") != runtime_expected["bundle_id"]
        or {
            "bytes": toolchain_manifest.get("bytes"),
            "sha256": toolchain_manifest.get("sha256"),
        }
        != runtime_expected["manifest"]
        or toolchain_manifest.get("verified") is not True
    ):
        raise ReleaseError(
            "runtime provenance manifest identity is unverified or incorrect"
        )
    executables = raw.get("executables")
    if not isinstance(executables, dict):
        raise ReleaseError("runtime provenance has no executable inventory")
    active_executables = [item for item in executables.values() if item is not None]
    if not active_executables or any(
        not isinstance(item, dict)
        or item.get("verified") is not True
        or not isinstance(item.get("path"), str)
        for item in active_executables
    ):
        raise ReleaseError("runtime provenance executable inventory is incomplete")

    normalized = _normalize(raw, bundle_root)
    assert_relative_json(normalized, label="normalized runtime provenance")
    result = {
        "schema": "kazstem-linux-runtime-provenance-v2",
        "pass": True,
        "release": identity["release"],
        "source_commit": identity["source_commit"],
        "official": True,
        "verified": True,
        "non_official_reasons": [],
        "path_namespace": {
            "bundle": "paths beginning bundle/ are relative to the extracted ready-run root"
        },
        "provenance": normalized,
    }
    assert_relative_json(result, label="normalized runtime provenance")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(json_bytes(result))
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--identity", required=True, type=Path)
    parser.add_argument("--bundle-root", required=True, type=Path)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    result = normalize(args)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ReleaseError, OSError, ValueError, json.JSONDecodeError) as exc:
        raise SystemExit(f"error: {exc}") from exc
