#!/usr/bin/env python3
"""Strict, location-independent primitives for macOS release tooling."""

from __future__ import annotations

import bz2
from dataclasses import dataclass
import gzip
import hashlib
import io
import json
import lzma
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
from typing import Any, BinaryIO, Iterable
import unicodedata
from urllib.parse import unquote, urlsplit
import zipfile


IDENTITY_SCHEMA = "kazstem-macos-release-identity-v2"
READY_AUDIT_SCHEMA = "kazstem-macos-ready-run-archive-audit-v2"
SOURCE_AUDIT_SCHEMA = "kazstem-macos-corresponding-source-audit-v2"
HEX_256 = re.compile(r"[0-9a-f]{64}\Z")
COMMIT = re.compile(r"[0-9a-f]{40}\Z")
VERSION = re.compile(r"[0-9]+(?:\.[0-9]+){2}(?:[a-z0-9.-]*[a-z0-9])?\Z")
SAFE_LABEL = re.compile(r"[a-z0-9][a-z0-9._-]{0,126}\Z")
MAX_HARD_MEMBERS = 1_000_000
MAX_HARD_FILE_BYTES = 16 * 1024**3
MAX_HARD_TOTAL_BYTES = 64 * 1024**3
MAX_HARD_PATH_BYTES = 4096
TAR_BLOCK_BYTES = 512
TAR_RECORD_BYTES = 20 * TAR_BLOCK_BYTES
MAX_TAR_EXTENSION_BYTES = 64 * 1024**2
SUPPORTED_NESTED_ARCHIVE_FORMATS = frozenset({"tar", "zip", "deb", "gzip"})
REQUIRED_EVIDENCE_GATES = {
    gate: "envelope"
    for gate in (
        "blackbox",
        "compatibility-performance",
        "compression-comparison",
        "macho-closure",
        "module-native-inclusion",
        "network-trace",
        "optimization-ledger",
        "practical",
        "python-reproducibility",
        "ready-archive-audit",
        "runtime-provenance",
        "source-archive-audit",
        "source-suite",
    )
}
LOADER_POLICY_SCHEMA = "qazmorph-native-helper-loader-environment-v2"
LOADER_OVERRIDE_PREFIXES = ("LD_", "DYLD_")
GLIBC_TUNABLES_VARIABLE = "GLIBC_TUNABLES"
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


class ReleaseError(RuntimeError):
    """A release input or gate violated the public release contract."""


def verify_darwin_loader_provenance(provenance: Any) -> dict[str, Any]:
    """Require a clean-parent, fully scrubbed Darwin helper environment."""

    if not isinstance(provenance, dict):
        raise ReleaseError("runtime provenance is not an object")
    environment = provenance.get("environment")
    expected_environment_fields = {
        "LANG",
        "LC_ALL",
        "PATH",
        GLIBC_TUNABLES_VARIABLE,
        "loader_policy",
        *LOADER_OVERRIDE_VARIABLES,
    }
    if not isinstance(environment, dict) or set(environment) != (
        expected_environment_fields
    ):
        raise ReleaseError("Darwin runtime loader environment schema is not exact")
    if environment["LANG"] != "C" or environment["LC_ALL"] != "C":
        raise ReleaseError("Darwin runtime loader probe locale is not canonical")

    clean_record = {
        "ambient_present": False,
        "removed_from_helper_environment": True,
        "sha256": None,
    }
    for name in (*LOADER_OVERRIDE_VARIABLES, GLIBC_TUNABLES_VARIABLE):
        if environment[name] != clean_record:
            raise ReleaseError(
                f"Darwin runtime loader variable is not clean and scrubbed: {name}"
            )

    path_record = environment["PATH"]
    if path_record != {
        "ambient_present": False,
        "ambient_untrusted": False,
        "removed_from_helper_environment": False,
    }:
        raise ReleaseError("Darwin runtime provenance leaked Windows PATH policy")

    policy = environment["loader_policy"]
    if not isinstance(policy, dict) or set(policy) != {
        "schema",
        "captured_name_policy",
        "ambient_records",
        "glibc_tunables",
        "clean_parent_startup",
        "all_ambient_values_removed_from_helper_environment",
        "linux_helper_ld_library_path",
    }:
        raise ReleaseError("Darwin runtime loader policy schema is not exact")
    if (
        policy["schema"] != LOADER_POLICY_SCHEMA
        or policy["captured_name_policy"]
        != {
            "exact_uppercase_prefixes": list(LOADER_OVERRIDE_PREFIXES),
            "exact_names": [GLIBC_TUNABLES_VARIABLE],
        }
        or policy["ambient_records"] != {}
        or policy["glibc_tunables"] != clean_record
        or policy["clean_parent_startup"] is not True
        or policy["all_ambient_values_removed_from_helper_environment"] is not True
        or policy["linux_helper_ld_library_path"] is not None
    ):
        raise ReleaseError("Darwin runtime loader policy is not clean and complete")
    return {
        "schema": LOADER_POLICY_SCHEMA,
        "captured_name_policy": policy["captured_name_policy"],
        "captured_ambient_names": [],
        "legacy_loader_records": len(LOADER_OVERRIDE_VARIABLES),
        "glibc_tunables_recorded": True,
        "clean_parent_startup": True,
        "all_ambient_values_removed_from_helper_environment": True,
        "linux_helper_ld_library_path": None,
        "windows_path_policy_applied": False,
    }


@dataclass(frozen=True)
class ArchiveLimits:
    max_members: int
    max_file_bytes: int
    max_total_bytes: int
    max_path_bytes: int


@dataclass(frozen=True)
class ArchiveMember:
    name: str
    kind: str
    size: int
    mode: int
    linkname: str | None = None
    sha256: str | None = None


@dataclass(frozen=True)
class GateExecution:
    """A locally verified, timeout-enforced execution of one locked gate."""

    gate: str
    started_monotonic: float
    timeout_seconds: int
    original_alarm_seconds: int


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ReleaseError(f"duplicate JSON key: {key!r}")
        value[key] = item
    return value


def decode_json(data: bytes, *, label: str) -> Any:
    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=_pairs)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ReleaseError(f"cannot read strict JSON {label}: {exc}") from exc


def read_json(path: Path) -> Any:
    try:
        if path.stat().st_size > 64 * 1024**2:
            raise ReleaseError(f"JSON file exceeds the 64 MiB safety cap: {path}")
        return decode_json(path.read_bytes(), label=str(path))
    except OSError as exc:
        raise ReleaseError(f"cannot read strict JSON {path}: {exc}") from exc


def json_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")


def canonical_hash(value: Any) -> str:
    encoded = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_stream(source: BinaryIO, *, limit: int) -> tuple[int, str]:
    digest = hashlib.sha256()
    size = 0
    while True:
        chunk = source.read(min(1024 * 1024, limit - size + 1))
        if not chunk:
            break
        size += len(chunk)
        if size > limit:
            raise ReleaseError(f"stream exceeds safety cap of {limit} bytes")
        digest.update(chunk)
    return size, digest.hexdigest()


def file_record(path: Path) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink():
        raise ReleaseError(f"not a regular file: {path}")
    return {"bytes": path.stat().st_size, "sha256": sha256_file(path)}


def artifact_record(path: Path, url: str) -> dict[str, Any]:
    return {"filename": path.name, **file_record(path), "url": url}


def ensure_output_outside(output: Path, protected_root: Path, *, label: str) -> None:
    output_resolved = output.resolve(strict=False)
    root_resolved = protected_root.resolve(strict=False)
    if output_resolved == root_resolved or root_resolved in output_resolved.parents:
        raise ReleaseError(f"{label} must be outside protected root {protected_root}")


def ensure_distinct_nonaliased_paths(
    first: Path, second: Path, *, labels: tuple[str, str]
) -> None:
    """Reject equal, nested, symlink-aliased, or hard-linked path endpoints.

    This check is intentionally usable before either endpoint exists.  Existing
    ancestors are resolved so that a symlinked parent cannot make two lexical
    output names alias after work has begun.
    """

    first_resolved = first.resolve(strict=False)
    second_resolved = second.resolve(strict=False)
    if (
        first_resolved == second_resolved
        or first_resolved in second_resolved.parents
        or second_resolved in first_resolved.parents
    ):
        raise ReleaseError(
            f"{labels[0]} and {labels[1]} must be distinct, non-nested paths"
        )
    if first.exists() and second.exists():
        try:
            aliased = os.path.samefile(first, second)
        except OSError as exc:
            raise ReleaseError(
                f"cannot prove {labels[0]}/{labels[1]} path independence: {exc}"
            ) from exc
        if aliased:
            raise ReleaseError(
                f"{labels[0]} and {labels[1]} must not be filesystem aliases"
            )


def _exact_fields(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        observed = set(value) if isinstance(value, dict) else set()
        raise ReleaseError(
            f"{label} fields differ: missing={sorted(fields - observed)}, "
            f"extra={sorted(observed - fields)}"
        )
    return value


def _positive_int(value: Any, label: str, *, ceiling: int | None = None) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ReleaseError(f"{label} must be a positive integer")
    if ceiling is not None and value > ceiling:
        raise ReleaseError(f"{label} exceeds hard ceiling {ceiling}")
    return value


def _sha(value: Any, label: str) -> str:
    if not isinstance(value, str) or HEX_256.fullmatch(value) is None:
        raise ReleaseError(f"{label} must be a lowercase SHA-256")
    return value


def portable_path(value: Any, *, label: str, single: bool = False) -> str:
    if not isinstance(value, str) or not value or "\x00" in value or "\\" in value:
        raise ReleaseError(f"{label} is not a portable relative path")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ReleaseError(f"{label} contains a control character")
    posix = PurePosixPath(value)
    windows = PureWindowsPath(value)
    parts = posix.parts
    windows_devices = {
        "con",
        "prn",
        "aux",
        "nul",
        *(f"com{number}" for number in range(1, 10)),
        *(f"lpt{number}" for number in range(1, 10)),
    }
    if (
        posix.is_absolute()
        or windows.is_absolute()
        or bool(windows.drive)
        or value != posix.as_posix()
        or any(part in {"", ".", ".."} for part in parts)
        or any(":" in part for part in parts)
        or any(part != part.rstrip(" .") for part in parts)
        or any(part.split(".", 1)[0].casefold() in windows_devices for part in parts)
        or value != unicodedata.normalize("NFC", value)
        or (single and len(parts) != 1)
    ):
        raise ReleaseError(f"{label} is not a portable relative path: {value!r}")
    if len(value.encode("utf-8")) > MAX_HARD_PATH_BYTES:
        raise ReleaseError(f"{label} exceeds the hard path cap")
    return value


def _file_identity(value: Any, label: str) -> dict[str, Any]:
    item = _exact_fields(value, {"bytes", "sha256"}, label)
    _positive_int(item["bytes"], f"{label}.bytes", ceiling=MAX_HARD_FILE_BYTES)
    _sha(item["sha256"], f"{label}.sha256")
    return item


def _url(value: Any, label: str, *, filename: str | None = None) -> str:
    if not isinstance(value, str):
        raise ReleaseError(f"{label} must be an HTTPS URL")
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or parsed.query
    ):
        raise ReleaseError(
            f"{label} must be an uncredentialed HTTPS URL without a fragment"
        )
    if filename is not None and unquote(parsed.path.rsplit("/", 1)[-1]) != filename:
        raise ReleaseError(f"{label} does not end in the exact artifact filename")
    return value


def _artifact(value: Any, label: str) -> dict[str, Any]:
    item = _exact_fields(value, {"filename", "bytes", "sha256", "url"}, label)
    portable_path(item["filename"], label=f"{label}.filename", single=True)
    _positive_int(item["bytes"], f"{label}.bytes", ceiling=MAX_HARD_FILE_BYTES)
    _sha(item["sha256"], f"{label}.sha256")
    _url(item["url"], f"{label}.url", filename=item["filename"])
    return item


def _tree(value: Any, label: str) -> dict[str, Any]:
    item = _exact_fields(value, {"entries", "regular_file_bytes", "sha256"}, label)
    _positive_int(item["entries"], f"{label}.entries", ceiling=MAX_HARD_MEMBERS)
    _positive_int(
        item["regular_file_bytes"],
        f"{label}.regular_file_bytes",
        ceiling=MAX_HARD_TOTAL_BYTES,
    )
    _sha(item["sha256"], f"{label}.sha256")
    return item


def _limits(value: Any, label: str) -> ArchiveLimits:
    item = _exact_fields(
        value,
        {"max_members", "max_file_bytes", "max_total_bytes", "max_path_bytes"},
        label,
    )
    limits = ArchiveLimits(
        _positive_int(
            item["max_members"], f"{label}.max_members", ceiling=MAX_HARD_MEMBERS
        ),
        _positive_int(
            item["max_file_bytes"],
            f"{label}.max_file_bytes",
            ceiling=MAX_HARD_FILE_BYTES,
        ),
        _positive_int(
            item["max_total_bytes"],
            f"{label}.max_total_bytes",
            ceiling=MAX_HARD_TOTAL_BYTES,
        ),
        _positive_int(
            item["max_path_bytes"],
            f"{label}.max_path_bytes",
            ceiling=MAX_HARD_PATH_BYTES,
        ),
    )
    if limits.max_file_bytes > limits.max_total_bytes:
        raise ReleaseError(f"{label}.max_file_bytes exceeds max_total_bytes")
    return limits


def _unique_paths(values: Any, label: str) -> list[str]:
    if not isinstance(values, list) or not values:
        raise ReleaseError(f"{label} must be a non-empty list")
    result = [
        portable_path(value, label=f"{label}[{index}]")
        for index, value in enumerate(values)
    ]
    if result != sorted(set(result)):
        raise ReleaseError(f"{label} must be sorted and unique")
    folded = [unicodedata.normalize("NFC", value).casefold() for value in result]
    if len(folded) != len(set(folded)):
        raise ReleaseError(f"{label} contains a case-insensitive collision")
    return result


def load_identity(path: Path) -> dict[str, Any]:
    value = read_json(path)
    identity = _exact_fields(
        value,
        {
            "schema",
            "release",
            "source_commit",
            "source_tree",
            "source_origin",
            "source_ref",
            "source_date_epoch",
            "release_url",
            "platform",
            "artifacts",
            "inputs",
            "ready_run",
            "corresponding_source",
            "archive_limits",
            "compression",
            "mach_o",
            "minimization",
            "verification",
        },
        "release identity",
    )
    if identity["schema"] != IDENTITY_SCHEMA:
        raise ReleaseError(
            f"unsupported release identity schema: {identity['schema']!r}"
        )
    if (
        not isinstance(identity["release"], str)
        or VERSION.fullmatch(identity["release"]) is None
    ):
        raise ReleaseError("release is not a canonical semantic version")
    if (
        not isinstance(identity["source_commit"], str)
        or COMMIT.fullmatch(identity["source_commit"]) is None
    ):
        raise ReleaseError("source_commit must be a lowercase 40-character Git id")
    if (
        not isinstance(identity["source_tree"], str)
        or COMMIT.fullmatch(identity["source_tree"]) is None
    ):
        raise ReleaseError("source_tree must be a lowercase 40-character Git id")
    _positive_int(identity["source_date_epoch"], "source_date_epoch")
    release_url = _url(identity["release_url"], "release_url")
    release_parts = [part for part in urlsplit(release_url).path.split("/") if part]
    if (
        urlsplit(release_url).netloc.casefold() != "github.com"
        or len(release_parts) != 5
        or release_parts[2:4] != ["releases", "tag"]
        or release_parts[4] != f"v{identity['release']}"
    ):
        raise ReleaseError(
            "release_url must name the exact public GitHub v<release> tag"
        )
    expected_origin = f"https://github.com/{release_parts[0]}/{release_parts[1]}.git"
    if identity["source_origin"] != expected_origin:
        raise ReleaseError(
            "source_origin must be the exact HTTPS Git origin corresponding to release_url"
        )
    if identity["source_ref"] != f"refs/tags/v{identity['release']}":
        raise ReleaseError("source_ref must be the exact immutable release tag")

    platform = _exact_fields(
        identity["platform"],
        {
            "system",
            "machine",
            "label",
            "advertised_target",
            "minimum_os",
            "unsigned",
            "notarized",
        },
        "platform",
    )
    if platform["system"] != "darwin" or platform["machine"] != "arm64":
        raise ReleaseError("macOS release tooling only accepts darwin/arm64")
    if (
        not isinstance(platform["label"], str)
        or SAFE_LABEL.fullmatch(platform["label"]) is None
    ):
        raise ReleaseError("platform.label is invalid")
    if (
        not isinstance(platform["advertised_target"], str)
        or not platform["advertised_target"]
    ):
        raise ReleaseError("platform.advertised_target is empty")
    if platform["minimum_os"] != "15.0":
        raise ReleaseError("the public filename contract requires macOS 15.0")
    if platform["unsigned"] is not True or platform["notarized"] is not False:
        raise ReleaseError("this recipe is explicitly unsigned and not notarized")

    artifacts = _exact_fields(
        identity["artifacts"],
        {"wheel", "sdist", "ready_run", "corresponding_source"},
        "artifacts",
    )
    for name in sorted(artifacts):
        _artifact(artifacts[name], f"artifacts.{name}")
    prefix = f"kazstem-{identity['release']}-{platform['label']}"
    if (
        artifacts["wheel"]["filename"]
        != f"kazstem-{identity['release']}-py3-none-any.whl"
    ):
        raise ReleaseError(
            "wheel filename does not match the canonical pure-Python artifact"
        )
    if artifacts["sdist"]["filename"] != f"kazstem-{identity['release']}.tar.gz":
        raise ReleaseError(
            "sdist filename does not match the canonical source artifact"
        )
    download_base = (
        release_url.rsplit("/tag/", 1)[0] + f"/download/v{identity['release']}/"
    )
    for name, record in artifacts.items():
        if record["url"] != download_base + record["filename"]:
            raise ReleaseError(
                f"artifacts.{name}.url is not the exact release download URL"
            )

    compression = _exact_fields(
        identity["compression"],
        {"ready_run", "corresponding_source"},
        "compression",
    )
    suffixes = {"gzip": ".tar.gz", "xz": ".tar.xz", "zstd": ".tar.zst"}
    tops = {
        "ready_run": f"{prefix}-ready-run-unsigned",
        "corresponding_source": f"{prefix}-corresponding-source",
    }
    for asset_name in ("ready_run", "corresponding_source"):
        policy = _exact_fields(
            compression[asset_name],
            {
                "canonical_tar",
                "compressors",
                "eligibility",
                "selected_format",
                "selection_rule",
            },
            f"compression.{asset_name}",
        )
        selected = policy["selected_format"]
        if selected not in suffixes:
            raise ReleaseError(f"unsupported selected compression: {selected!r}")
        if policy["selection_rule"] != "smallest-eligible-byte-identical":
            raise ReleaseError("compression selection rule is not exact")
        canonical_tar = _exact_fields(
            policy["canonical_tar"],
            {"filename", "bytes", "sha256", "producer"},
            f"compression.{asset_name}.canonical_tar",
        )
        if canonical_tar["filename"] != tops[asset_name] + ".tar":
            raise ReleaseError("canonical tar filename differs from its stable root")
        _positive_int(
            canonical_tar["bytes"],
            f"compression.{asset_name}.canonical_tar.bytes",
            ceiling=MAX_HARD_TOTAL_BYTES,
        )
        _sha(canonical_tar["sha256"], f"compression.{asset_name}.canonical_tar.sha256")
        producer = _exact_fields(
            canonical_tar["producer"],
            {"argv", "script", "source_commit", "source_tree"},
            f"compression.{asset_name}.canonical_tar.producer",
        )
        producer_script = _exact_fields(
            producer["script"],
            {"path", "file"},
            f"compression.{asset_name}.canonical_tar.producer.script",
        )
        portable_path(producer_script["path"], label="canonical tar producer script")
        _file_identity(producer_script["file"], "canonical tar producer script")
        if (
            producer["source_commit"] != identity["source_commit"]
            or producer["source_tree"] != identity["source_tree"]
            or not isinstance(producer["argv"], list)
            or len(producer["argv"]) < 2
            or producer["argv"][1] != producer_script["path"]
        ):
            raise ReleaseError("canonical tar producer is not source-bound")
        compressors = _exact_fields(
            policy["compressors"],
            {"gzip", "xz", "zstd"},
            f"compression.{asset_name}.compressors",
        )
        expected_argv = {
            "gzip": [
                "python3.14",
                "stdlib:gzip",
                "compresslevel=9",
                "mtime=0",
                "filename=",
            ],
            "xz": [
                "python3.14",
                "stdlib:lzma",
                "format=xz",
                "check=crc64",
                "preset=9e",
            ],
            "zstd": [
                "zstd",
                "-19",
                "--ultra",
                "--threads=1",
                "--no-progress",
                "--stdout",
                "canonical.tar",
            ],
        }
        for format_name, compressor in compressors.items():
            record = _exact_fields(
                compressor,
                {"argv", "executable", "name", "version", "version_argv"},
                f"compression.{asset_name}.compressors.{format_name}",
            )
            if record["argv"] != expected_argv[format_name]:
                raise ReleaseError(f"{format_name} compressor argv is not exact")
            if record["name"] != record["argv"][0]:
                raise ReleaseError("compressor name/argv disagree")
            _file_identity(record["executable"], f"{format_name} compressor executable")
            if (
                not isinstance(record["version"], str)
                or not record["version"]
                or not isinstance(record["version_argv"], list)
                or not record["version_argv"]
                or record["version_argv"][0] != record["name"]
            ):
                raise ReleaseError("compressor version binding is invalid")
        eligibility = policy["eligibility"]
        if not isinstance(eligibility, list) or len(eligibility) != 3:
            raise ReleaseError(
                "all three compression formats need eligibility decisions"
            )
        eligibility_by_format: dict[str, dict[str, Any]] = {}
        for record in eligibility:
            item = _exact_fields(
                record, {"eligible", "format", "reason"}, "compression eligibility"
            )
            if (
                item["format"] not in suffixes
                or item["format"] in eligibility_by_format
                or not isinstance(item["eligible"], bool)
                or not isinstance(item["reason"], str)
                or not item["reason"]
            ):
                raise ReleaseError("compression eligibility record is invalid")
            eligibility_by_format[item["format"]] = item
        if [item["format"] for item in eligibility] != sorted(suffixes):
            raise ReleaseError("compression eligibility must be sorted")
        if not eligibility_by_format[selected]["eligible"]:
            raise ReleaseError("selected compression is marked ineligible")
        if artifacts[asset_name]["filename"] != tops[asset_name] + suffixes[selected]:
            raise ReleaseError(
                "artifact suffix does not match measured selected format"
            )

    inputs = _exact_fields(
        identity["inputs"],
        {
            "frozen_tree",
            "resource_tree",
            "runtime_tree",
            "source_payload_tree",
            "git_archive",
            "base_ledger",
            "binary_readme_template",
            "source_readme_template",
            "runtime_source_lock",
            "platform_asset_lock",
            "build_stack",
            "freezer_wheelhouse",
            "freezer_requirements",
            "freezer_spec",
            "staging_receipt",
            "python_runtimes",
            "documents",
        },
        "inputs",
    )
    _tree(inputs["frozen_tree"], "inputs.frozen_tree")
    _tree(inputs["source_payload_tree"], "inputs.source_payload_tree")
    _tree(inputs["freezer_wheelhouse"], "inputs.freezer_wheelhouse")
    git_archive = _exact_fields(
        inputs["git_archive"],
        {"argv", "file", "prefix", "tool_version"},
        "inputs.git_archive",
    )
    _file_identity(git_archive["file"], "inputs.git_archive.file")
    expected_git_argv = [
        "git",
        "archive",
        "--format=tar",
        "--prefix=tree/",
        identity["source_commit"],
    ]
    if git_archive["argv"] != expected_git_argv:
        raise ReleaseError("inputs.git_archive.argv is not the exact canonical command")
    if git_archive["prefix"] != "tree/":
        raise ReleaseError("inputs.git_archive.prefix must be exactly 'tree/'")
    if (
        not isinstance(git_archive["tool_version"], str)
        or not git_archive["tool_version"].startswith("git version ")
        or len(git_archive["tool_version"]) > 128
    ):
        raise ReleaseError("inputs.git_archive.tool_version is invalid")
    for name in ("resource_tree", "runtime_tree"):
        item = _exact_fields(
            inputs[name], {"bundle_id", "manifest", "tree"}, f"inputs.{name}"
        )
        _sha(item["bundle_id"], f"inputs.{name}.bundle_id")
        _file_identity(item["manifest"], f"inputs.{name}.manifest")
        _tree(item["tree"], f"inputs.{name}.tree")
    for name in (
        "base_ledger",
        "binary_readme_template",
        "source_readme_template",
        "runtime_source_lock",
        "platform_asset_lock",
        "freezer_requirements",
        "freezer_spec",
    ):
        _file_identity(inputs[name], f"inputs.{name}")
    staging = _exact_fields(
        inputs["staging_receipt"], {"file", "generator"}, "inputs.staging_receipt"
    )
    _file_identity(staging["file"], "inputs.staging_receipt.file")
    staging_generator = _exact_fields(
        staging["generator"],
        {"path", "file", "schema"},
        "inputs.staging_receipt.generator",
    )
    if (
        staging_generator["path"] != "packaging/macos/stage_release_candidates.py"
        or staging_generator["schema"] != "kazstem-macos-release-staging-v1"
    ):
        raise ReleaseError(
            "staging receipt generator is not the checked fixed-point tool"
        )
    _file_identity(staging_generator["file"], "inputs.staging_receipt.generator.file")
    build_stack = _exact_fields(
        inputs["build_stack"], {"canonical", "freezer"}, "inputs.build_stack"
    )
    required_stack = {
        "canonical": {"build", "packaging", "pyproject-hooks", "setuptools", "wheel"},
        "freezer": {
            "altgraph",
            "macholib",
            "pip",
            "pyinstaller",
            "pyinstaller-hooks-contrib",
            "setuptools",
            "wheel",
        },
    }
    for role in ("canonical", "freezer"):
        records = build_stack[role]
        if not isinstance(records, list) or not records:
            raise ReleaseError(f"inputs.build_stack.{role} must be non-empty")
        names: list[str] = []
        for index, record in enumerate(records):
            item = _exact_fields(
                record,
                {"name", "version", "wheel", "source"},
                f"inputs.build_stack.{role}[{index}]",
            )
            name = item["name"]
            if not isinstance(name, str) or SAFE_LABEL.fullmatch(name) is None:
                raise ReleaseError(f"invalid build-stack name: {name!r}")
            if not isinstance(item["version"], str) or not item["version"]:
                raise ReleaseError(f"invalid build-stack version for {name}")
            names.append(name)
            _artifact(item["wheel"], f"inputs.build_stack.{role}[{index}].wheel")
            _artifact(item["source"], f"inputs.build_stack.{role}[{index}].source")
        if names != sorted(set(names)) or not required_stack[role] <= set(names):
            raise ReleaseError(
                f"inputs.build_stack.{role} is unsorted, duplicated, or incomplete"
            )
    python_runtimes = _exact_fields(
        inputs["python_runtimes"], {"canonical", "freezer"}, "inputs.python_runtimes"
    )
    for role, expected_version in (("canonical", "3.12.3"), ("freezer", "3.14.3")):
        runtime = _exact_fields(
            python_runtimes[role],
            {"implementation", "version", "executable"},
            f"inputs.python_runtimes.{role}",
        )
        if (
            runtime["implementation"] != "CPython"
            or runtime["version"] != expected_version
        ):
            raise ReleaseError(
                f"inputs.python_runtimes.{role} is not the sealed CPython"
            )
        _file_identity(
            runtime["executable"], f"inputs.python_runtimes.{role}.executable"
        )
    documents = inputs["documents"]
    if not isinstance(documents, list) or not documents:
        raise ReleaseError("inputs.documents must be a non-empty list")
    document_destinations: list[str] = []
    for index, document in enumerate(documents):
        item = _exact_fields(
            document, {"source", "destination", "file"}, f"inputs.documents[{index}]"
        )
        portable_path(item["source"], label=f"inputs.documents[{index}].source")
        document_destinations.append(
            portable_path(
                item["destination"], label=f"inputs.documents[{index}].destination"
            )
        )
        _file_identity(item["file"], f"inputs.documents[{index}].file")
    if document_destinations != sorted(set(document_destinations)) or len(
        {
            unicodedata.normalize("NFC", value).casefold()
            for value in document_destinations
        }
    ) != len(document_destinations):
        raise ReleaseError("document destinations must be sorted and unique")

    ready = _exact_fields(
        identity["ready_run"],
        {
            "top_level",
            "launcher",
            "platform_lock",
            "resource_destination",
            "runtime_parent",
            "aliases",
            "remove_frozen_files",
            "required_paths",
            "banned_name_fragments",
        },
        "ready_run",
    )
    expected_ready_top = tops["ready_run"]
    if ready["top_level"] != expected_ready_top:
        raise ReleaseError("ready_run.top_level does not match its artifact filename")
    launcher = _exact_fields(ready["launcher"], {"path", "file"}, "ready_run.launcher")
    portable_path(launcher["path"], label="ready_run.launcher.path")
    _file_identity(launcher["file"], "ready_run.launcher.file")
    lock = _exact_fields(
        ready["platform_lock"], {"path", "file"}, "ready_run.platform_lock"
    )
    portable_path(lock["path"], label="ready_run.platform_lock.path")
    _file_identity(lock["file"], "ready_run.platform_lock.file")
    portable_path(ready["resource_destination"], label="ready_run.resource_destination")
    portable_path(ready["runtime_parent"], label="ready_run.runtime_parent")
    aliases = ready["aliases"]
    if not isinstance(aliases, list) or not aliases:
        raise ReleaseError("ready_run.aliases must be non-empty")
    for index, alias in enumerate(aliases):
        portable_path(alias, label=f"ready_run.aliases[{index}]", single=True)
    if aliases != sorted(set(aliases)) or len(
        {unicodedata.normalize("NFC", value).casefold() for value in aliases}
    ) != len(aliases):
        raise ReleaseError("ready_run.aliases must be sorted and unique")
    removals = ready["remove_frozen_files"]
    if not isinstance(removals, list):
        raise ReleaseError("ready_run.remove_frozen_files must be a list")
    removal_paths: list[str] = []
    for index, removal in enumerate(removals):
        item = _exact_fields(
            removal, {"path", "file"}, f"ready_run.remove_frozen_files[{index}]"
        )
        removal_paths.append(
            portable_path(
                item["path"], label=f"ready_run.remove_frozen_files[{index}].path"
            )
        )
        _file_identity(item["file"], f"ready_run.remove_frozen_files[{index}].file")
    if removal_paths != sorted(set(removal_paths)) or len(
        {unicodedata.normalize("NFC", value).casefold() for value in removal_paths}
    ) != len(removal_paths):
        raise ReleaseError("ready-run removals must be sorted and unique")
    _unique_paths(ready["required_paths"], "ready_run.required_paths")
    banned = ready["banned_name_fragments"]
    if (
        not isinstance(banned, list)
        or not banned
        or any(
            not isinstance(item, str) or not item or item != item.casefold()
            for item in banned
        )
        or banned != sorted(set(banned))
    ):
        raise ReleaseError(
            "ready_run.banned_name_fragments must be sorted unique casefolded strings"
        )

    source = _exact_fields(
        identity["corresponding_source"],
        {
            "top_level",
            "evidence_root",
            "source_categories",
            "source_commit_file",
            "source_tree_file",
            "source_origin_file",
            "git_archive_file",
            "source_date_epoch_file",
            "required_paths",
            "nested_archives",
        },
        "corresponding_source",
    )
    expected_source_top = tops["corresponding_source"]
    if source["top_level"] != expected_source_top:
        raise ReleaseError(
            "corresponding_source.top_level does not match its artifact filename"
        )
    evidence_root = portable_path(
        source["evidence_root"], label="corresponding_source.evidence_root"
    )
    categories = _exact_fields(
        source["source_categories"],
        {
            "application_source",
            "build_inputs",
            "evidence",
            "freezer_source",
            "licenses",
            "resource_source",
            "runtime_source",
        },
        "corresponding_source.source_categories",
    )
    category_paths = [
        portable_path(value, label=f"corresponding_source.source_categories.{name}")
        for name, value in sorted(categories.items())
    ]
    if len(category_paths) != len(
        {unicodedata.normalize("NFC", value).casefold() for value in category_paths}
    ):
        raise ReleaseError("corresponding-source category paths must be unique")
    if categories["evidence"] != evidence_root:
        raise ReleaseError("source evidence root must match the evidence category")
    commit_file = portable_path(
        source["source_commit_file"], label="corresponding_source.source_commit_file"
    )
    tree_file = portable_path(
        source["source_tree_file"], label="corresponding_source.source_tree_file"
    )
    origin_file = portable_path(
        source["source_origin_file"], label="corresponding_source.source_origin_file"
    )
    git_archive_file = portable_path(
        source["git_archive_file"], label="corresponding_source.git_archive_file"
    )
    epoch_file = portable_path(
        source["source_date_epoch_file"],
        label="corresponding_source.source_date_epoch_file",
    )
    application_prefix = categories["application_source"] + "/"
    if any(
        not marker.startswith(application_prefix)
        for marker in (
            commit_file,
            tree_file,
            origin_file,
            git_archive_file,
            epoch_file,
        )
    ):
        raise ReleaseError(
            "source identity marker files must be inside application_source"
        )
    required_source_paths = _unique_paths(
        source["required_paths"], "corresponding_source.required_paths"
    )
    if not set(
        category_paths
        + [commit_file, tree_file, origin_file, git_archive_file, epoch_file]
        + [f"{categories['application_source']}/GIT-SOURCE.json"]
        + [f"{categories['application_source']}/tree"]
    ) <= set(required_source_paths):
        raise ReleaseError(
            "source categories and identity marker files must all be required paths"
        )
    nested = source["nested_archives"]
    if not isinstance(nested, list) or not nested:
        raise ReleaseError("corresponding_source.nested_archives must be non-empty")
    nested_paths: list[str] = []
    for index, record in enumerate(nested):
        item = _exact_fields(
            record, {"path", "format", "bytes", "sha256"}, f"nested_archives[{index}]"
        )
        nested_paths.append(
            portable_path(item["path"], label=f"nested_archives[{index}].path")
        )
        if item["format"] not in {"tar", "zip", "deb", "gzip"}:
            raise ReleaseError(f"unsupported nested archive format: {item['format']!r}")
        _positive_int(
            item["bytes"],
            f"nested_archives[{index}].bytes",
            ceiling=MAX_HARD_FILE_BYTES,
        )
        _sha(item["sha256"], f"nested_archives[{index}].sha256")
    if nested_paths != sorted(set(nested_paths)) or len(
        {unicodedata.normalize("NFC", value).casefold() for value in nested_paths}
    ) != len(nested_paths):
        raise ReleaseError("nested archive paths must be sorted and unique")
    nested_by_path = {record["path"]: record for record in nested}
    expected_git_nested = {
        "path": git_archive_file,
        "format": "tar",
        **git_archive["file"],
    }
    if nested_by_path.get(git_archive_file) != expected_git_nested:
        raise ReleaseError(
            "nested archive inventory must bind the exact canonical Git archive"
        )

    macho = _exact_fields(
        identity["mach_o"],
        {
            "architecture",
            "format",
            "system_boundaries",
            "runtime_bundle_id",
            "runtime_manifest",
            "signature",
            "rpath_policy",
        },
        "mach_o",
    )
    if macho["architecture"] != "arm64" or macho["format"] != "thin":
        raise ReleaseError("Mach-O policy requires thin arm64 files")
    if macho["system_boundaries"] != ["/System/Library/", "/usr/lib/"]:
        raise ReleaseError("Mach-O system boundary allowlist is not exact")
    _sha(macho["runtime_bundle_id"], "mach_o.runtime_bundle_id")
    if macho["runtime_bundle_id"] != inputs["runtime_tree"]["bundle_id"]:
        raise ReleaseError("Mach-O runtime bundle differs from the runtime input")
    _file_identity(macho["runtime_manifest"], "mach_o.runtime_manifest")
    if macho["runtime_manifest"] != inputs["runtime_tree"]["manifest"]:
        raise ReleaseError("Mach-O runtime manifest differs from the runtime input")
    signature = _exact_fields(
        macho["signature"],
        {"kind", "team_identifier", "developer_id", "notarized", "stapled"},
        "mach_o.signature",
    )
    if signature != {
        "kind": "adhoc",
        "team_identifier": None,
        "developer_id": False,
        "notarized": False,
        "stapled": False,
    }:
        raise ReleaseError("Mach-O signature policy must describe the unsigned asset")
    if macho["rpath_policy"] != {
        "bind_exact_observed_rpaths": True,
        "bundle_relative_precedes_inherited": True,
        "external_resolution_forbidden": True,
    }:
        raise ReleaseError("Mach-O rpath policy is not the strict release policy")

    minimization = _exact_fields(
        identity["minimization"],
        {
            "banned_modules",
            "banned_native_fragments",
            "required_modules",
            "negative_controls",
            "compression_candidates",
            "compression_selection",
            "strip_selection",
            "claim_scope",
        },
        "minimization",
    )
    for field in (
        "banned_modules",
        "banned_native_fragments",
        "required_modules",
        "negative_controls",
        "compression_candidates",
    ):
        values = minimization[field]
        if (
            not isinstance(values, list)
            or not values
            or values != sorted(set(values))
            or any(not isinstance(item, str) or not item for item in values)
        ):
            raise ReleaseError(f"minimization.{field} must be sorted and unique")
    if not {"_hashlib", "_ssl", "ssl", "socket", "urllib"} <= set(
        minimization["banned_modules"]
    ):
        raise ReleaseError("minimization banned-module coverage is incomplete")
    if not {"libcrypto", "libssl", "openssl"} <= set(
        minimization["banned_native_fragments"]
    ):
        raise ReleaseError("OpenSSL native negatives are incomplete")
    if "_sha2" not in minimization["required_modules"]:
        raise ReleaseError("_sha2 is required as the positive SHA-256 provider")
    if "pyinstaller-zlib-bootstrap" not in minimization["negative_controls"]:
        raise ReleaseError("the PyInstaller zlib negative control is required")
    if minimization["compression_candidates"] != ["gzip", "xz", "zstd"]:
        raise ReleaseError("gzip/xz/zstd must all be measured")
    if minimization["compression_selection"] != "smallest-byte-identical-passing":
        raise ReleaseError("compression selection rule is not fail closed")
    if minimization["strip_selection"] != "smaller-with-full-parity-and-resign":
        raise ReleaseError("strip selection rule is not fail closed")
    if minimization["claim_scope"] != "measured-candidates-component-floor":
        raise ReleaseError("the tooling must not claim an unverifiable global minimum")

    limits = _exact_fields(
        identity["archive_limits"],
        {"ready_run", "corresponding_source", "nested"},
        "archive_limits",
    )
    for name in ("ready_run", "corresponding_source", "nested"):
        _limits(limits[name], f"archive_limits.{name}")

    verification = _exact_fields(
        identity["verification"],
        {"minimum_distinct_roots", "reproducibility", "tracing", "evidence"},
        "verification",
    )
    if (
        _positive_int(
            verification["minimum_distinct_roots"],
            "verification.minimum_distinct_roots",
        )
        < 2
    ):
        raise ReleaseError("at least two distinct native build roots are required")
    reproducibility = _exact_fields(
        verification["reproducibility"],
        {
            "build_roots",
            "direct_build_argv",
            "sdist_build_argv",
            "freezer_install_argv",
            "frozen_build_argv",
            "environment",
            "tools",
        },
        "verification.reproducibility",
    )
    if (
        _positive_int(
            reproducibility["build_roots"],
            "verification.reproducibility.build_roots",
            ceiling=32,
        )
        < 2
    ):
        raise ReleaseError("reproducibility requires at least two distinct roots")
    environment = _exact_fields(
        reproducibility["environment"],
        {"LANG", "LC_ALL", "PYTHONHASHSEED", "SOURCE_DATE_EPOCH", "TZ"},
        "verification.reproducibility.environment",
    )
    expected_environment = {
        "LANG": "C",
        "LC_ALL": "C",
        "PYTHONHASHSEED": "0",
        "SOURCE_DATE_EPOCH": str(identity["source_date_epoch"]),
        "TZ": "UTC",
    }
    if environment != expected_environment:
        raise ReleaseError(
            "verification reproducibility environment is not the canonical environment"
        )
    tools = reproducibility["tools"]
    if not isinstance(tools, list) or not tools:
        raise ReleaseError("verification.reproducibility.tools must be non-empty")
    tool_names: list[str] = []
    for index, record in enumerate(tools):
        tool = _exact_fields(
            record,
            {"name", "version_argv", "version", "executable"},
            f"verification.reproducibility.tools[{index}]",
        )
        name = tool["name"]
        if not isinstance(name, str) or SAFE_LABEL.fullmatch(name) is None:
            raise ReleaseError("reproducibility tool name is invalid")
        tool_names.append(name)
        version_argv = tool["version_argv"]
        if (
            not isinstance(version_argv, list)
            or not version_argv
            or version_argv[0] != name
            or any(not isinstance(item, str) or not item for item in version_argv)
        ):
            raise ReleaseError("reproducibility tool version argv is invalid")
        if (
            not isinstance(tool["version"], str)
            or not tool["version"]
            or len(tool["version"]) > 4096
        ):
            raise ReleaseError("reproducibility tool version is invalid")
        _file_identity(
            tool["executable"],
            f"verification.reproducibility.tools[{index}].executable",
        )
    if tool_names != sorted(set(tool_names)):
        raise ReleaseError("reproducibility tools must be sorted and unique")
    reproducibility_tools = {tool["name"]: tool for tool in tools}
    for asset_name, policy in compression.items():
        for format_name, compressor in policy["compressors"].items():
            bound = reproducibility_tools.get(compressor["name"])
            projection = {
                key: compressor[key]
                for key in ("name", "version_argv", "version", "executable")
            }
            if bound != projection:
                raise ReleaseError(
                    f"compression.{asset_name}.{format_name} tool is not reproducibility-bound"
                )
    build_placeholders = {
        "direct_build_argv": {"{dist}"},
        "sdist_build_argv": {"{dist}"},
        "freezer_install_argv": {
            "{freezer_python}",
            "{freezer_requirements}",
            "{freezer_wheelhouse}",
            "{wheel}",
        },
        "frozen_build_argv": {
            "{freezer_evidence}",
            "{freezer_python}",
            "{freezer_work}",
            "{frozen_dist}",
            "{identity}",
            "{spec}",
            "{wheel}",
        },
    }
    for command_name, required_placeholders in build_placeholders.items():
        argv = reproducibility[command_name]
        if (
            not isinstance(argv, list)
            or len(argv) < 2
            or any(
                not isinstance(item, str)
                or not item
                or len(item) > 4096
                or absolute_reference(item) is not None
                for item in argv
            )
            or (
                command_name in {"direct_build_argv", "sdist_build_argv"}
                and argv[0] not in tool_names
            )
            or {token for item in argv for token in re.findall(r"\{[a-z_]+\}", item)}
            != required_placeholders
            or any(
                "{" in re.sub(r"\{[a-z_]+\}", "", item)
                or "}" in re.sub(r"\{[a-z_]+\}", "", item)
                for item in argv
            )
        ):
            raise ReleaseError(
                f"verification reproducibility {command_name} is invalid"
            )
    if reproducibility["freezer_install_argv"] != [
        "{freezer_python}",
        "-m",
        "pip",
        "install",
        "--disable-pip-version-check",
        "--no-index",
        "--no-deps",
        "--require-hashes",
        "--find-links",
        "{freezer_wheelhouse}",
        "-r",
        "{freezer_requirements}",
        "{wheel}",
    ]:
        raise ReleaseError("freezer install command is not offline/hash-locked")
    if reproducibility["frozen_build_argv"] != [
        "{freezer_python}",
        "packaging/macos/build_frozen_runtime.py",
        "--identity",
        "{identity}",
        "--wheel",
        "{wheel}",
        "--spec",
        "{spec}",
        "--work-root",
        "{freezer_work}",
        "--output",
        "{frozen_dist}",
        "--evidence",
        "{freezer_evidence}",
    ]:
        raise ReleaseError("frozen build command must use the checked orchestrator")
    tracing = _exact_fields(
        verification["tracing"],
        {
            "argv_prefix",
            "negative_control_argv",
            "process_observer_argv",
            "profile",
            "tool",
        },
        "verification.tracing",
    )
    tracing_tool = _exact_fields(
        tracing["tool"],
        {"name", "version_argv", "version", "executable"},
        "verification.tracing.tool",
    )
    if (
        tracing_tool["name"] != "sandbox-exec"
        or tracing_tool["version_argv"] != ["sandbox-exec", "-h"]
        or not isinstance(tracing_tool["version"], str)
        or not tracing_tool["version"]
    ):
        raise ReleaseError("verification tracing tool must bind sandbox-exec -h")
    _file_identity(tracing_tool["executable"], "verification.tracing.tool.executable")
    if tracing["argv_prefix"] != [
        "sandbox-exec",
        "-D",
        "WRITE_ROOT={write_root}",
        "-f",
        "{profile}",
        "--",
    ]:
        raise ReleaseError("verification sandbox argv prefix is not the strict form")
    profile = _exact_fields(
        tracing["profile"], {"path", "file"}, "verification.tracing.profile"
    )
    portable_path(profile["path"], label="verification.tracing.profile.path")
    _file_identity(profile["file"], "verification.tracing.profile.file")
    if tracing["negative_control_argv"] != [
        "python",
        "-c",
        "import socket; s=socket.socket(); s.bind(('127.0.0.1', 0))",
    ]:
        raise ReleaseError("network sandbox negative control is not exact")
    if tracing["process_observer_argv"] != ["ps", "-axo", "pid=,ppid=,comm="]:
        raise ReleaseError("process observer command is not exact")
    evidence = verification["evidence"]
    if not isinstance(evidence, list) or not evidence:
        raise ReleaseError("verification.evidence must be non-empty")
    evidence_paths: list[str] = []
    for index, record in enumerate(evidence):
        item = _exact_fields(
            record,
            {"path", "gate", "kind", "subjects", "file", "generator"},
            f"verification.evidence[{index}]",
        )
        evidence_paths.append(
            portable_path(item["path"], label=f"verification.evidence[{index}].path")
        )
        if item["kind"] != "envelope":
            raise ReleaseError("verification evidence kind must be envelope")
        if REQUIRED_EVIDENCE_GATES.get(item["gate"]) != item["kind"]:
            raise ReleaseError(
                f"invalid or wrongly typed verification gate: {item['gate']!r}"
            )
        _file_identity(item["file"], f"verification.evidence[{index}].file")
        generator = _exact_fields(
            item["generator"],
            {
                "argv",
                "cwd",
                "environment",
                "script",
                "source_commit",
                "source_tree",
                "timeout_seconds",
                "tool",
            },
            f"verification.evidence[{index}].generator",
        )
        script = _exact_fields(
            generator["script"],
            {"path", "file"},
            f"verification.evidence[{index}].generator.script",
        )
        portable_path(
            script["path"],
            label=f"verification.evidence[{index}].generator.script.path",
        )
        _file_identity(
            script["file"],
            f"verification.evidence[{index}].generator.script.file",
        )
        if (
            not isinstance(generator["argv"], list)
            or len(generator["argv"]) < 3
            or generator["argv"][1:3] != ["-S", script["path"]]
            or any(
                not isinstance(token, str) or not token for token in generator["argv"]
            )
            or generator["cwd"] != "release-workspace"
            or generator["source_commit"] != identity["source_commit"]
            or generator["source_tree"] != identity["source_tree"]
            or isinstance(generator["timeout_seconds"], bool)
            or not isinstance(generator["timeout_seconds"], int)
            or not 1 <= generator["timeout_seconds"] <= 86_400
            or generator["tool"] not in tool_names
            or generator["argv"][0] != generator["tool"]
        ):
            raise ReleaseError("verification evidence generator is not exact")
        generator_environment = generator["environment"]
        if (
            not isinstance(generator_environment, dict)
            or not generator_environment
            or any(
                not isinstance(key, str)
                or not isinstance(value, str)
                or absolute_reference(key) is not None
                or absolute_reference(value) is not None
                for key, value in generator_environment.items()
            )
        ):
            raise ReleaseError("verification evidence generator environment is invalid")
        subjects = item["subjects"]
        if (
            not isinstance(subjects, list)
            or not subjects
            or subjects != sorted(set(subjects))
            or any(subject not in artifacts for subject in subjects)
        ):
            raise ReleaseError("verification evidence subjects are invalid")
    if evidence_paths != sorted(set(evidence_paths)) or len(
        {unicodedata.normalize("NFC", value).casefold() for value in evidence_paths}
    ) != len(evidence_paths):
        raise ReleaseError("verification evidence paths must be sorted and unique")
    gates = [record["gate"] for record in evidence]
    if len(gates) != len(set(gates)) or set(gates) != set(REQUIRED_EVIDENCE_GATES):
        raise ReleaseError(
            "verification evidence gates differ from the required macOS release matrix "
            f"(missing={sorted(set(REQUIRED_EVIDENCE_GATES) - set(gates))}, "
            f"extra={sorted(set(gates) - set(REQUIRED_EVIDENCE_GATES))})"
        )
    return identity


def archive_limits(identity: dict[str, Any], name: str) -> ArchiveLimits:
    return _limits(identity["archive_limits"][name], f"archive_limits.{name}")


def verify_file(path: Path, expected: dict[str, Any], *, label: str) -> None:
    actual = file_record(path)
    if actual != expected:
        raise ReleaseError(
            f"{label} identity mismatch: expected={expected}, observed={actual}"
        )


def verify_artifact(path: Path, expected: dict[str, Any], *, label: str) -> None:
    if path.name != expected["filename"]:
        raise ReleaseError(
            f"{label} filename mismatch: expected {expected['filename']!r}, observed {path.name!r}"
        )
    verify_file(
        path, {"bytes": expected["bytes"], "sha256": expected["sha256"]}, label=label
    )


def _git_output(repository: Path, argv: list[str], *, label: str) -> str:
    process = subprocess.run(
        argv,
        cwd=repository,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=60,
        check=False,
    )
    if process.returncode != 0:
        detail = process.stderr[:4096].decode("utf-8", "replace").strip()
        raise ReleaseError(f"{label} failed with exit {process.returncode}: {detail}")
    try:
        return process.stdout.decode("utf-8").strip()
    except UnicodeError as exc:
        raise ReleaseError(f"{label} returned non-UTF-8 output") from exc


def materialize_git_archive(
    repository: Path, identity: dict[str, Any], destination: Path
) -> dict[str, Any]:
    """Resolve and archive the exact identity commit from its bound origin."""

    if repository.is_symlink() or not repository.is_dir():
        raise ReleaseError(
            f"Git source repository is not a real directory: {repository}"
        )
    repository = repository.resolve(strict=True)
    if destination.exists() or destination.is_symlink():
        raise ReleaseError(f"Git archive output already exists: {destination}")
    ensure_output_outside(destination, repository, label="Git archive output")
    commit = identity.get("source_commit")
    tree = identity.get("source_tree")
    origin = identity.get("source_origin")
    source_ref = identity.get("source_ref")
    if not isinstance(commit, str) or COMMIT.fullmatch(commit) is None:
        raise ReleaseError("source_commit is not a full lowercase Git object id")
    if not isinstance(tree, str) or COMMIT.fullmatch(tree) is None:
        raise ReleaseError("source_tree is not a full lowercase Git tree id")
    if not isinstance(origin, str):
        raise ReleaseError("source_origin is missing")
    if source_ref != f"refs/tags/v{identity['release']}":
        raise ReleaseError("source_ref is not the exact immutable release tag")
    git_input = identity.get("inputs", {}).get("git_archive")
    if not isinstance(git_input, dict):
        raise ReleaseError("inputs.git_archive is missing")
    expected_argv = [
        "git",
        "archive",
        "--format=tar",
        "--prefix=tree/",
        commit,
    ]
    if git_input.get("argv") != expected_argv or git_input.get("prefix") != "tree/":
        raise ReleaseError("inputs.git_archive command is not the canonical command")
    version = _git_output(repository, ["git", "--version"], label="git version")
    if git_input.get("tool_version") != version:
        raise ReleaseError(f"git version differs from identity: {version!r}")
    object_type = _git_output(
        repository, ["git", "cat-file", "-t", commit], label="Git commit lookup"
    )
    if object_type != "commit":
        raise ReleaseError(f"source_commit does not resolve to a commit: {commit}")
    observed_tree = _git_output(
        repository,
        ["git", "rev-parse", f"{commit}^{{tree}}"],
        label="Git tree lookup",
    )
    if observed_tree != tree:
        raise ReleaseError(
            f"source tree differs from identity: expected={tree}, observed={observed_tree}"
        )
    observed_ref = _git_output(
        repository,
        ["git", "rev-parse", f"{source_ref}^{{commit}}"],
        label="Git release-tag lookup",
    )
    if observed_ref != commit:
        raise ReleaseError("release tag does not resolve to source_commit")
    observed_origin = _git_output(
        repository,
        ["git", "remote", "get-url", "origin"],
        label="Git origin lookup",
    )
    if observed_origin != origin:
        raise ReleaseError(
            f"Git origin differs from identity: expected={origin!r}, observed={observed_origin!r}"
        )
    destination.parent.mkdir(parents=True, exist_ok=True)
    try:
        with destination.open("xb") as output:
            process = subprocess.run(
                expected_argv,
                cwd=repository,
                stdin=subprocess.DEVNULL,
                stdout=output,
                stderr=subprocess.PIPE,
                timeout=300,
                check=False,
            )
        if process.returncode != 0:
            detail = process.stderr[:4096].decode("utf-8", "replace").strip()
            raise ReleaseError(
                f"canonical git archive failed with exit {process.returncode}: {detail}"
            )
        expected_file = git_input.get("file")
        if not isinstance(expected_file, dict):
            raise ReleaseError("inputs.git_archive.file is missing")
        verify_file(destination, expected_file, label="canonical Git archive")
    except BaseException:
        destination.unlink(missing_ok=True)
        raise
    return {
        "schema": "kazstem-git-source-materialization-v1",
        "source_commit": commit,
        "source_tree": tree,
        "source_origin": origin,
        "source_ref": source_ref,
        "archive": {"filename": destination.name, **git_input["file"]},
        "argv": expected_argv,
        "tool_version": version,
    }


def _resolved_symlink(root: Path, path: Path) -> None:
    try:
        path.resolve(strict=True).relative_to(root)
    except (OSError, ValueError) as exc:
        raise ReleaseError(f"symlink escapes or is dangling: {path}") from exc


def _list_xattrs(path: Path) -> list[str]:
    """List attributes without following links, including CPython builds
    configured without the optional ``os.listxattr`` wrappers on macOS.
    """

    listxattr = getattr(os, "listxattr", None)
    if listxattr is not None:
        try:
            return sorted(listxattr(path, follow_symlinks=False))
        except OSError as exc:
            raise ReleaseError(
                f"cannot inspect extended attributes: {path}: {exc}"
            ) from exc
    xattr = Path("/usr/bin/xattr")
    if sys.platform != "darwin" or not xattr.is_file():
        raise ReleaseError(
            "no supported extended-attribute inspection API is available"
        )
    argv = [str(xattr)]
    if path.is_symlink():
        argv.append("-s")
    argv.extend(["--", str(path)])
    process = subprocess.run(
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
        check=False,
    )
    if process.returncode:
        raise ReleaseError(
            f"cannot inspect extended attributes: {path}: "
            f"{process.stderr[:1024].decode('utf-8', 'replace')}"
        )
    try:
        names = process.stdout.decode("utf-8", "strict").splitlines()
    except UnicodeError as exc:
        raise ReleaseError(f"extended-attribute names are not UTF-8: {path}") from exc
    if any(not name or "\x00" in name for name in names):
        raise ReleaseError(f"invalid extended-attribute name on {path}")
    return sorted(names)


def tree_inventory(
    root: Path, *, allow_os_provenance: bool = True
) -> list[dict[str, Any]]:
    if not root.is_dir() or root.is_symlink():
        raise ReleaseError(f"tree root is not a real directory: {root}")
    root = root.resolve(strict=True)
    result: list[dict[str, Any]] = []
    folded: dict[str, str] = {}
    regular_inodes: dict[tuple[int, int], str] = {}
    for path in sorted(
        root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()
    ):
        relative = portable_path(path.relative_to(root).as_posix(), label="tree entry")
        case = unicodedata.normalize("NFC", relative).casefold()
        if case in folded:
            raise ReleaseError(
                f"case-insensitive tree collision: {folded[case]!r}, {relative!r}"
            )
        folded[case] = relative
        metadata = path.lstat()
        if not (
            stat.S_ISREG(metadata.st_mode)
            or stat.S_ISDIR(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
        ):
            raise ReleaseError(f"unsupported special filesystem entry: {path}")
        regular_inode: tuple[int, int] | None = None
        if stat.S_ISREG(metadata.st_mode):
            regular_inode = (metadata.st_dev, metadata.st_ino)
            if metadata.st_nlink != 1 or regular_inode in regular_inodes:
                previous = regular_inodes.get(regular_inode, "outside-tree")
                raise ReleaseError(
                    f"hard-linked regular file is forbidden: {previous!r}, {relative!r}"
                )
        extended = _list_xattrs(path)
        if extended and not (
            allow_os_provenance and set(extended) == {"com.apple.provenance"}
        ):
            raise ReleaseError(
                f"extended attributes are forbidden in build input trees: {relative}: {sorted(extended)!r}"
            )
        mode = f"{stat.S_IMODE(metadata.st_mode):04o}"
        if stat.S_IMODE(metadata.st_mode) & 0o7000:
            raise ReleaseError(
                f"special permission bits are forbidden in release trees: {path}"
            )
        if path.is_symlink():
            target = os.readlink(path)
            _link_stays_within(f"root/{relative}", target, "root")
            _resolved_symlink(root, path)
            result.append(
                {"path": relative, "kind": "symlink", "mode": mode, "target": target}
            )
        elif path.is_dir():
            result.append({"path": relative, "kind": "directory", "mode": mode})
        elif path.is_file():
            if regular_inode is None:
                raise ReleaseError(f"regular file classification changed: {path}")
            regular_inodes[regular_inode] = relative
            result.append(
                {"path": relative, "kind": "file", "mode": mode, **file_record(path)}
            )
        else:
            raise ReleaseError(f"unsupported special filesystem entry: {path}")
    return result


def tree_record(root: Path) -> dict[str, Any]:
    inventory = tree_inventory(root)
    return {
        "entries": len(inventory),
        "regular_file_bytes": sum(item.get("bytes", 0) for item in inventory),
        "sha256": canonical_hash(inventory),
    }


def verify_tree(root: Path, expected: dict[str, Any], *, label: str) -> None:
    actual = tree_record(root)
    if actual != expected:
        raise ReleaseError(
            f"{label} tree mismatch: expected={expected}, observed={actual}"
        )


def regular_files(root: Path) -> list[Path]:
    return sorted(
        (path for path in root.rglob("*") if path.is_file() and not path.is_symlink()),
        key=lambda path: path.relative_to(root).as_posix(),
    )


def fresh_extract_xattr_observation(root: Path) -> dict[str, Any]:
    """Record only OS-managed provenance; reject every archived/user xattr."""

    provenance: list[str] = []
    for path in [root, *sorted(root.rglob("*"))]:
        names = _list_xattrs(path)
        unexpected = sorted(set(names) - {"com.apple.provenance"})
        if unexpected:
            raise ReleaseError(
                f"unexpected fresh-extract extended attributes: {path.name}: {unexpected}"
            )
        if "com.apple.provenance" in names:
            provenance.append(
                "." if path == root else path.relative_to(root).as_posix()
            )
    return {
        "allowed_name": "com.apple.provenance",
        "paths": provenance,
        "count": len(provenance),
        "archive_serialized": False,
    }


def symlinks(root: Path) -> list[Path]:
    return sorted(
        (path for path in root.rglob("*") if path.is_symlink()),
        key=lambda path: path.relative_to(root).as_posix(),
    )


def normalize_tree(
    root: Path, *, epoch: int, executable_paths: Iterable[str] = ()
) -> None:
    executable = set(executable_paths)
    root = root.resolve(strict=True)
    for path in sorted(root.rglob("*"), key=lambda item: len(item.parts), reverse=True):
        relative = path.relative_to(root).as_posix()
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            os.utime(path, (epoch, epoch), follow_symlinks=False)
        elif stat.S_ISDIR(metadata.st_mode):
            path.chmod(0o555)
            os.utime(path, (epoch, epoch))
        elif stat.S_ISREG(metadata.st_mode):
            path.chmod(0o555 if relative in executable else 0o444)
            os.utime(path, (epoch, epoch))
        else:
            raise ReleaseError(f"cannot normalize special entry: {path}")
    root.chmod(0o555)
    os.utime(root, (epoch, epoch))


def write_deterministic_tar_xz(
    root: Path, destination: Path, *, epoch: int, limits: ArchiveLimits
) -> None:
    if destination.exists():
        raise ReleaseError(f"archive output already exists: {destination}")
    root = root.resolve(strict=True)
    inventory = [
        root,
        *sorted(root.rglob("*"), key=lambda path: path.relative_to(root).as_posix()),
    ]
    if len(inventory) > limits.max_members:
        raise ReleaseError("output tree exceeds archive member cap")
    total = sum(
        path.lstat().st_size
        for path in inventory
        if path.is_file() and not path.is_symlink()
    )
    if total > limits.max_total_bytes:
        raise ReleaseError("output tree exceeds archive total-byte cap")
    destination.parent.mkdir(parents=True, exist_ok=True)
    try:
        with lzma.open(
            destination,
            "wb",
            format=lzma.FORMAT_XZ,
            check=lzma.CHECK_CRC64,
            preset=9 | lzma.PRESET_EXTREME,
        ) as compressed:
            with tarfile.open(
                fileobj=compressed, mode="w|", format=tarfile.GNU_FORMAT
            ) as archive:
                for path in inventory:
                    name = (
                        root.name
                        if path == root
                        else f"{root.name}/{path.relative_to(root).as_posix()}"
                    )
                    portable_path(name, label="archive output member")
                    metadata = path.lstat()
                    info = tarfile.TarInfo(name)
                    info.uid = info.gid = 0
                    info.uname = info.gname = "root"
                    info.mtime = epoch
                    if path.is_symlink():
                        info.type = tarfile.SYMTYPE
                        info.mode = 0o777
                        info.linkname = os.readlink(path)
                        info.size = 0
                        archive.addfile(info)
                    elif path.is_dir():
                        info.type = tarfile.DIRTYPE
                        info.mode = 0o555
                        info.size = 0
                        archive.addfile(info)
                    elif path.is_file():
                        if metadata.st_size > limits.max_file_bytes:
                            raise ReleaseError(f"file exceeds archive cap: {path}")
                        info.type = tarfile.REGTYPE
                        info.mode = stat.S_IMODE(metadata.st_mode)
                        info.size = metadata.st_size
                        with path.open("rb") as source:
                            archive.addfile(info, source)
                    else:
                        raise ReleaseError(f"unsupported output member: {path}")
    except BaseException:
        destination.unlink(missing_ok=True)
        raise


def write_deterministic_tar(
    root: Path, destination: Path, *, epoch: int, limits: ArchiveLimits
) -> dict[str, Any]:
    """Write the canonical normalized uncompressed tar payload."""

    if destination.exists() or destination.is_symlink():
        raise ReleaseError(f"canonical tar output already exists: {destination}")
    root = root.resolve(strict=True)
    inventory = [
        root,
        *sorted(root.rglob("*"), key=lambda path: path.relative_to(root).as_posix()),
    ]
    if len(inventory) > limits.max_members:
        raise ReleaseError("output tree exceeds archive member cap")
    total = sum(
        path.lstat().st_size
        for path in inventory
        if path.is_file() and not path.is_symlink()
    )
    if total > limits.max_total_bytes:
        raise ReleaseError("output tree exceeds archive total-byte cap")
    destination.parent.mkdir(parents=True, exist_ok=True)
    try:
        with destination.open("xb") as raw:
            with tarfile.open(
                fileobj=raw, mode="w|", format=tarfile.GNU_FORMAT
            ) as archive:
                for path in inventory:
                    name = (
                        root.name
                        if path == root
                        else f"{root.name}/{path.relative_to(root).as_posix()}"
                    )
                    portable_path(name, label="canonical tar member")
                    metadata = path.lstat()
                    info = tarfile.TarInfo(name)
                    info.uid = info.gid = 0
                    info.uname = info.gname = "root"
                    info.mtime = epoch
                    if path.is_symlink():
                        info.type = tarfile.SYMTYPE
                        info.mode = 0o777
                        info.linkname = os.readlink(path)
                        info.size = 0
                        archive.addfile(info)
                    elif path.is_dir():
                        info.type = tarfile.DIRTYPE
                        info.mode = 0o555
                        info.size = 0
                        archive.addfile(info)
                    elif path.is_file():
                        if metadata.st_size > limits.max_file_bytes:
                            raise ReleaseError(f"file exceeds archive cap: {path}")
                        info.type = tarfile.REGTYPE
                        info.mode = stat.S_IMODE(metadata.st_mode)
                        info.size = metadata.st_size
                        with path.open("rb") as source:
                            archive.addfile(info, source)
                    else:
                        raise ReleaseError(f"unsupported canonical tar member: {path}")
    except BaseException:
        destination.unlink(missing_ok=True)
        raise
    return {"filename": destination.name, **file_record(destination)}


def _verify_compressor(record: dict[str, Any]) -> Path:
    name = record["name"]
    if name.startswith("python"):
        executable = Path(sys.executable).resolve(strict=True)
    else:
        located = shutil.which(name)
        if located is None:
            raise ReleaseError(f"compressor is unavailable: {name}")
        executable = Path(located).resolve(strict=True)
    verify_file(executable, record["executable"], label=f"compressor {name}")
    version_argv = [str(executable), *record["version_argv"][1:]]
    process = subprocess.run(
        version_argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=60,
        check=False,
    )
    observed = process.stdout.decode("utf-8", "replace").strip()
    if process.returncode or observed != record["version"]:
        raise ReleaseError(f"compressor version differs: {name}: {observed!r}")
    return executable


def compress_canonical_tar(
    canonical_tar: Path,
    destination: Path,
    *,
    policy: dict[str, Any],
) -> dict[str, Any]:
    """Compress one exact tar with the identity-selected audited format."""

    if destination.exists() or destination.is_symlink():
        raise ReleaseError(f"compressed output already exists: {destination}")
    expected_tar = policy["canonical_tar"]
    verify_file(
        canonical_tar,
        {"bytes": expected_tar["bytes"], "sha256": expected_tar["sha256"]},
        label="canonical uncompressed tar",
    )
    selected = policy["selected_format"]
    compressor = policy["compressors"][selected]
    executable = _verify_compressor(compressor)
    destination.parent.mkdir(parents=True, exist_ok=True)
    try:
        if selected == "gzip":
            with canonical_tar.open("rb") as source, destination.open("xb") as raw:
                with gzip.GzipFile(
                    filename="", mode="wb", fileobj=raw, compresslevel=9, mtime=0
                ) as output:
                    shutil.copyfileobj(source, output, length=1024 * 1024)
        elif selected == "xz":
            with (
                canonical_tar.open("rb") as source,
                lzma.open(
                    destination,
                    "xb",
                    format=lzma.FORMAT_XZ,
                    check=lzma.CHECK_CRC64,
                    preset=9 | lzma.PRESET_EXTREME,
                ) as output,
            ):
                shutil.copyfileobj(source, output, length=1024 * 1024)
        elif selected == "zstd":
            with destination.open("xb") as output:
                process = subprocess.run(
                    [
                        str(executable),
                        "-19",
                        "--ultra",
                        "--threads=1",
                        "--no-progress",
                        "--stdout",
                        str(canonical_tar),
                    ],
                    stdin=subprocess.DEVNULL,
                    stdout=output,
                    stderr=subprocess.PIPE,
                    timeout=1800,
                    check=False,
                )
            if process.returncode:
                raise ReleaseError(
                    "zstd compressor failed: "
                    + process.stderr[:4096].decode("utf-8", "replace")
                )
        else:
            raise ReleaseError(f"unsupported selected compression: {selected!r}")
    except BaseException:
        destination.unlink(missing_ok=True)
        raise

    expected_suffix = {"gzip": ".tar.gz", "xz": ".tar.xz", "zstd": ".tar.zst"}[selected]
    if not destination.name.endswith(expected_suffix):
        destination.unlink(missing_ok=True)
        raise ReleaseError("compressed output suffix differs from selected format")
    return {
        "format": selected,
        "compressor": compressor,
        "canonical_tar": {
            "filename": canonical_tar.name,
            **file_record(canonical_tar),
        },
        "output": {"filename": destination.name, **file_record(destination)},
    }


def verify_or_observe_output(
    path: Path,
    expected: dict[str, Any],
    *,
    observation: Path | None,
    label: str,
) -> None:
    actual = artifact_record(path, expected["url"])
    if observation is not None:
        observation.parent.mkdir(parents=True, exist_ok=True)
        observation.write_bytes(json_bytes(actual))
    if actual != expected:
        quarantine = path.with_name(f"{path.name}.unsealed-{actual['sha256'][:12]}")
        if quarantine.exists() or quarantine.is_symlink():
            raise ReleaseError(
                f"{label} output mismatch and quarantine already exists: {quarantine}"
            )
        path.rename(quarantine)
        raise ReleaseError(
            f"{label} output identity mismatch: expected={expected}, observed={actual}; "
            f"candidate quarantined as {quarantine.name}"
        )


def source_identity_projection(identity: dict[str, Any]) -> dict[str, Any]:
    artifacts = identity["artifacts"]
    return {
        "schema": "kazstem-macos-source-identity-projection-v2",
        "release": identity["release"],
        "source_commit": identity["source_commit"],
        "source_tree": identity["source_tree"],
        "source_origin": identity["source_origin"],
        "source_ref": identity["source_ref"],
        "source_date_epoch": identity["source_date_epoch"],
        "release_url": identity["release_url"],
        "platform": identity["platform"],
        # Deliberately one-way: source records the stable ready-run location,
        # while the ready-run records the source archive's exact bytes.  The
        # source archive must not contain its own compression-dependent name or
        # hash, which would make final compression selection circular.
        "ready_run": {
            "filename": artifacts["ready_run"]["filename"],
            "url": artifacts["ready_run"]["url"],
        },
        "canonical_python_artifacts": {
            "wheel": artifacts["wheel"],
            "sdist": artifacts["sdist"],
        },
        "source_payload_tree": identity["inputs"]["source_payload_tree"],
        "git_archive": identity["inputs"]["git_archive"],
        "resource_bundle_id": identity["inputs"]["resource_tree"]["bundle_id"],
        "runtime_bundle_id": identity["inputs"]["runtime_tree"]["bundle_id"],
        "source_contract": {
            "categories": identity["corresponding_source"]["source_categories"],
            "source_commit_file": identity["corresponding_source"][
                "source_commit_file"
            ],
            "source_tree_file": identity["corresponding_source"]["source_tree_file"],
            "source_origin_file": identity["corresponding_source"][
                "source_origin_file"
            ],
            "git_archive_file": identity["corresponding_source"]["git_archive_file"],
            "source_date_epoch_file": identity["corresponding_source"][
                "source_date_epoch_file"
            ],
        },
    }


def ready_source_binding(identity: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": "kazstem-corresponding-source-binding-v2",
        "release": identity["release"],
        "source_commit": identity["source_commit"],
        "source_tree": identity["source_tree"],
        "source_origin": identity["source_origin"],
        "source_ref": identity["source_ref"],
        "ready_run_filename": identity["artifacts"]["ready_run"]["filename"],
        "corresponding_source": identity["artifacts"]["corresponding_source"],
        "canonical_python_artifacts": {
            "wheel": identity["artifacts"]["wheel"],
            "sdist": identity["artifacts"]["sdist"],
        },
        "publication_requirement": "Publish the exact corresponding-source asset at the recorded HTTPS URL beside this binary asset.",
    }


def render_template(path: Path, values: dict[str, str]) -> bytes:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise ReleaseError(f"cannot read template {path}: {exc}") from exc
    for key, value in values.items():
        text = text.replace(f"@{key}@", value)
    leftovers = sorted(set(re.findall(r"@[A-Z0-9_]+@", text)))
    if leftovers:
        raise ReleaseError(f"unrendered template placeholders: {leftovers}")
    return text.encode("utf-8")


def checksum_rows(root: Path, *, excluded: set[str]) -> list[str]:
    rows: list[str] = []
    for path in regular_files(root):
        relative = path.relative_to(root).as_posix()
        if relative not in excluded:
            rows.append(f"{sha256_file(path)}  {relative}")
    return rows


def parse_checksums(data: bytes) -> dict[str, str]:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ReleaseError("checksum file is not UTF-8") from exc
    result: dict[str, str] = {}
    folded: set[str] = set()
    for number, line in enumerate(text.splitlines(), 1):
        match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
        if match is None:
            raise ReleaseError(f"malformed checksum row {number}")
        digest, relative = match.groups()
        portable_path(relative, label=f"checksum row {number}")
        if relative in result or relative.casefold() in folded:
            raise ReleaseError(f"duplicate/case-colliding checksum path: {relative!r}")
        result[relative] = digest
        folded.add(relative.casefold())
    if not result:
        raise ReleaseError("checksum file is empty")
    if list(result) != sorted(result):
        raise ReleaseError("checksum rows are not sorted by portable path")
    return result


def _archive_member_name(name: str, *, limits: ArchiveLimits) -> str:
    try:
        encoded = name.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ReleaseError("archive path is not valid UTF-8") from exc
    if len(encoded) > limits.max_path_bytes:
        raise ReleaseError(f"archive path exceeds cap: {name!r}")
    cleaned = name.rstrip("/")
    while cleaned.startswith("./"):
        cleaned = cleaned[2:]
    relative = portable_path(cleaned, label="archive member")
    if any(
        part == "__MACOSX" or part.startswith("._")
        for part in PurePosixPath(relative).parts
    ):
        raise ReleaseError(
            f"AppleDouble/macOS metadata member is forbidden: {relative!r}"
        )
    return relative


def _link_stays_within(member: str, target: str, top: str) -> None:
    if not isinstance(target, str) or not target or "\x00" in target or "\\" in target:
        raise ReleaseError(f"invalid symlink target: {member!r} -> {target!r}")
    try:
        target.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ReleaseError(f"symlink target is not valid UTF-8: {member!r}") from exc
    if (
        PurePosixPath(target).is_absolute()
        or PureWindowsPath(target).is_absolute()
        or PureWindowsPath(target).drive
    ):
        raise ReleaseError(f"absolute symlink target: {member!r} -> {target!r}")
    stack = list(PurePosixPath(member).parent.parts)
    for part in PurePosixPath(target).parts:
        if part in {"", "."}:
            continue
        if part == "..":
            if not stack:
                raise ReleaseError(f"escaping symlink: {member!r} -> {target!r}")
            stack.pop()
        elif ":" in part or any(ord(character) < 32 for character in part):
            raise ReleaseError(f"non-portable symlink target: {member!r} -> {target!r}")
        else:
            stack.append(part)
    if not stack or (top and stack[0] != top):
        raise ReleaseError(f"symlink leaves top-level root: {member!r} -> {target!r}")


def _tar_stream_caps(limits: ArchiveLimits) -> tuple[int, int, int, int]:
    """Return raw, expanded, header-record, and extension-byte hard caps."""

    header_records = limits.max_members * 3 + 8
    extension_bytes = min(
        MAX_TAR_EXTENSION_BYTES,
        max(
            64 * 1024,
            limits.max_path_bytes * min(limits.max_members, 16_384) * 4,
        ),
    )
    expanded_bytes = min(
        MAX_HARD_TOTAL_BYTES,
        limits.max_total_bytes
        + header_records * TAR_BLOCK_BYTES
        + extension_bytes
        + limits.max_members * (TAR_BLOCK_BYTES - 1)
        + TAR_RECORD_BYTES,
    )
    # A compressed representation may be very slightly larger than its input.
    raw_bytes = min(MAX_HARD_TOTAL_BYTES, expanded_bytes + 1024**2)
    return raw_bytes, expanded_bytes, header_records, extension_bytes


def _copy_capped(
    source: BinaryIO, destination: BinaryIO, *, limit: int, label: str
) -> int:
    written = 0
    while True:
        chunk = source.read(min(1024 * 1024, limit - written + 1))
        if not chunk:
            return written
        if not isinstance(chunk, bytes):
            raise ReleaseError(f"{label} did not produce bytes")
        written += len(chunk)
        if written > limit:
            raise ReleaseError(f"{label} exceeds safety cap of {limit} bytes")
        destination.write(chunk)


def _materialize_tar_stream(
    path: Path | None,
    fileobj: BinaryIO | None,
    *,
    limits: ArchiveLimits,
) -> tuple[BinaryIO, int, int]:
    """Bound both compressed and expanded streams before tarfile sees them."""

    if (path is None) == (fileobj is None):
        raise ReleaseError("inspect_tar requires exactly one archive input")
    raw_cap, expanded_cap, _header_cap, _extension_cap = _tar_stream_caps(limits)
    raw = tempfile.SpooledTemporaryFile(max_size=min(raw_cap, 16 * 1024**2))
    expanded: BinaryIO | None = None
    try:
        if path is not None:
            if not path.is_file() or path.is_symlink():
                raise ReleaseError(f"tar input is not a regular file: {path}")
            if path.stat().st_size > raw_cap:
                raise ReleaseError(
                    f"raw tar stream exceeds safety cap of {raw_cap} bytes"
                )
            with path.open("rb") as source:
                raw_size = _copy_capped(
                    source, raw, limit=raw_cap, label="raw tar stream"
                )
        else:
            assert fileobj is not None
            raw_size = _copy_capped(fileobj, raw, limit=raw_cap, label="raw tar stream")
        raw.seek(0)
        magic = raw.read(8)
        raw.seek(0)
        compression: str | None
        if magic.startswith(b"\x1f\x8b"):
            compression = "gzip"
        elif magic.startswith(b"\xfd7zXZ\x00"):
            compression = "xz"
        elif magic.startswith(b"BZh"):
            compression = "bzip2"
        elif magic.startswith(b"\x28\xb5\x2f\xfd"):
            compression = "zstd"
        elif magic.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
            raise ReleaseError("zip input is not a tar stream")
        elif magic.startswith(b"!<arch>\n"):
            raise ReleaseError("ar input is not a tar stream")
        else:
            compression = None

        if compression is None:
            if raw_size > expanded_cap:
                raise ReleaseError(
                    f"expanded tar stream exceeds safety cap of {expanded_cap} bytes"
                )
            raw.seek(0)
            return raw, raw_size, raw_size

        expanded = tempfile.SpooledTemporaryFile(
            max_size=min(expanded_cap, 16 * 1024**2)
        )
        if compression == "zstd":
            zstd = shutil.which("zstd")
            if zstd is None:
                raise ReleaseError("zstd is required to inspect a zstd tar stream")
            process = subprocess.Popen(
                [zstd, "--decompress", "--no-progress", "--stdout"],
                stdin=raw,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            assert process.stdout is not None
            try:
                expanded_size = _copy_capped(
                    process.stdout,
                    expanded,
                    limit=expanded_cap,
                    label="expanded tar stream",
                )
            except BaseException:
                process.kill()
                process.wait()
                raise
            stderr = process.stderr.read(4097) if process.stderr is not None else b""
            returncode = process.wait(timeout=60)
            if returncode:
                raise ReleaseError(
                    "cannot materialize zstd tar stream: "
                    + stderr[:4096].decode("utf-8", "replace")
                )
            raw.close()
            expanded.seek(0)
            return expanded, raw_size, expanded_size
        if compression == "gzip":
            reader: BinaryIO = gzip.GzipFile(fileobj=raw, mode="rb")
        elif compression == "xz":
            reader = lzma.LZMAFile(raw, mode="rb")
        else:
            reader = bz2.BZ2File(raw, mode="rb")
        try:
            expanded_size = _copy_capped(
                reader,
                expanded,
                limit=expanded_cap,
                label="expanded tar stream",
            )
        finally:
            reader.close()
        raw.close()
        expanded.seek(0)
        return expanded, raw_size, expanded_size
    except (OSError, EOFError, lzma.LZMAError) as exc:
        if expanded is not None:
            expanded.close()
        raw.close()
        if isinstance(exc, ReleaseError):
            raise
        raise ReleaseError(f"cannot materialize bounded tar stream: {exc}") from exc
    except BaseException:
        if expanded is not None:
            expanded.close()
        raw.close()
        raise


def _tar_integer(field: bytes, *, label: str) -> int:
    if not field:
        raise ReleaseError(f"empty tar numeric field: {label}")
    if field[0] & 0x80:
        if field[0] & 0x40:
            raise ReleaseError(f"negative tar numeric field: {label}")
        encoded = bytes([field[0] & 0x7F]) + field[1:]
        return int.from_bytes(encoded, "big")
    stripped = field.strip(b" \x00")
    if not stripped:
        return 0
    if any(byte < ord("0") or byte > ord("7") for byte in stripped):
        raise ReleaseError(f"invalid tar octal field: {label}")
    return int(stripped, 8)


def _verify_tar_header(block: bytes) -> None:
    if len(block) != TAR_BLOCK_BYTES:
        raise ReleaseError("truncated tar header")
    stored = _tar_integer(block[148:156], label="checksum")
    checksum_block = block[:148] + b" " * 8 + block[156:]
    unsigned = sum(checksum_block)
    signed = sum(byte if byte < 128 else byte - 256 for byte in checksum_block)
    if stored not in {unsigned, signed}:
        raise ReleaseError("invalid tar header checksum")


def _parse_pax_records(data: bytes, *, path_cap: int) -> None:
    offset = 0
    keys: set[bytes] = set()
    while offset < len(data):
        separator = data.find(b" ", offset)
        if separator < 0:
            raise ReleaseError("malformed PAX metadata length")
        raw_length = data[offset:separator]
        if (
            not raw_length.isdigit()
            or raw_length.startswith(b"0")
            or len(raw_length) > 20
        ):
            raise ReleaseError("malformed PAX metadata length")
        length = int(raw_length)
        end = offset + length
        if end > len(data) or end <= separator + 1 or data[end - 1 : end] != b"\n":
            raise ReleaseError("truncated PAX metadata record")
        record = data[separator + 1 : end - 1]
        key, equals, value = record.partition(b"=")
        if not equals or not key or key in keys:
            raise ReleaseError("invalid or duplicate PAX metadata key")
        keys.add(key)
        try:
            decoded_key = key.decode("utf-8")
            decoded_value = value.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ReleaseError("PAX metadata is not UTF-8") from exc
        if "\x00" in decoded_key or "\x00" in decoded_value:
            raise ReleaseError("PAX metadata contains NUL")
        if any(
            ord(character) < 33 or ord(character) == 127 for character in decoded_key
        ):
            raise ReleaseError("PAX metadata key contains a control character")
        if decoded_key == "size":
            raise ReleaseError("PAX size overrides are forbidden")
        lowered_key = decoded_key.casefold()
        if (
            "xattr" in lowered_key
            or lowered_key.startswith("com.apple.")
            or lowered_key.startswith("schily.acl.")
        ):
            raise ReleaseError("PAX xattr/ACL metadata is forbidden")
        if decoded_key in {"path", "linkpath"} and len(value) > path_cap:
            raise ReleaseError("PAX path metadata exceeds archive path cap")
        offset = end
    if offset != len(data):
        raise ReleaseError("malformed PAX metadata body")


def _scan_physical_tar(stream: BinaryIO, *, limits: ArchiveLimits) -> None:
    """Validate every physical header, metadata record, body, and padding byte."""

    _raw_cap, _expanded_cap, header_cap, extension_cap = _tar_stream_caps(limits)
    headers = 0
    logical_members = 0
    logical_bytes = 0
    extension_records = 0
    extension_bytes = 0
    pending_extension = False
    saw_end = False
    while True:
        block = stream.read(TAR_BLOCK_BYTES)
        if not block:
            break
        if len(block) != TAR_BLOCK_BYTES:
            raise ReleaseError("truncated tar header block")
        if block == b"\x00" * TAR_BLOCK_BYTES:
            second = stream.read(TAR_BLOCK_BYTES)
            if second != b"\x00" * TAR_BLOCK_BYTES:
                raise ReleaseError("tar end marker is missing its second zero block")
            while True:
                padding = stream.read(1024 * 1024)
                if not padding:
                    break
                if any(padding):
                    raise ReleaseError("non-zero bytes follow the tar end marker")
            saw_end = True
            break

        headers += 1
        if headers > header_cap:
            raise ReleaseError("tar physical header count exceeds safety cap")
        _verify_tar_header(block)
        declared_size = _tar_integer(block[124:136], label="size")
        typeflag = block[156:157]
        extension = typeflag in {b"x", b"g", b"L", b"K"}
        regular = typeflag in {b"", b"\x00", b"0"}
        directory = typeflag == b"5"
        symlink = typeflag == b"2"
        if extension:
            extension_records += 1
            extension_bytes += declared_size
            if extension_records > limits.max_members * 2 + 8:
                raise ReleaseError("tar extension record count exceeds safety cap")
            if declared_size > extension_cap or extension_bytes > extension_cap:
                raise ReleaseError("tar PAX/extension metadata exceeds safety cap")
        elif regular:
            logical_members += 1
            if declared_size > limits.max_file_bytes:
                raise ReleaseError("tar physical member exceeds file cap")
            logical_bytes += declared_size
            if logical_bytes > limits.max_total_bytes:
                raise ReleaseError("tar physical bodies exceed total-byte cap")
        elif directory or symlink:
            logical_members += 1
            if declared_size != 0:
                raise ReleaseError("non-file tar member has a body")
        else:
            if declared_size != 0:
                raise ReleaseError("unsupported non-file tar member has a body")
            raise ReleaseError(f"unsupported tar typeflag: {typeflag!r}")
        if logical_members > limits.max_members:
            raise ReleaseError("tar member count exceeds safety cap")

        body_digest = hashlib.sha256()
        metadata = bytearray() if extension else None
        remaining = declared_size
        while remaining:
            chunk = stream.read(min(1024 * 1024, remaining))
            if not chunk:
                raise ReleaseError("truncated tar member body")
            remaining -= len(chunk)
            body_digest.update(chunk)
            if metadata is not None:
                metadata.extend(chunk)
        padding_size = (-declared_size) % TAR_BLOCK_BYTES
        if padding_size:
            padding = stream.read(padding_size)
            if len(padding) != padding_size:
                raise ReleaseError("truncated tar member padding")
            if any(padding):
                raise ReleaseError("non-zero tar member padding")

        if extension:
            assert metadata is not None
            if typeflag in {b"x", b"g"}:
                _parse_pax_records(bytes(metadata), path_cap=limits.max_path_bytes)
            else:
                try:
                    stripped_metadata = bytes(metadata).rstrip(b"\x00")
                    if b"\x00" in stripped_metadata:
                        raise ReleaseError("GNU tar extension contains embedded NUL")
                    long_value = stripped_metadata.decode("utf-8")
                except UnicodeDecodeError as exc:
                    raise ReleaseError("GNU tar extension is not UTF-8") from exc
                if (
                    not long_value
                    or len(long_value.encode("utf-8")) > limits.max_path_bytes
                ):
                    raise ReleaseError("GNU tar extension exceeds archive path cap")
            if typeflag != b"g":
                pending_extension = True
        else:
            pending_extension = False
    if not saw_end:
        raise ReleaseError("tar stream lacks a two-block end marker")
    if pending_extension:
        raise ReleaseError("tar extension metadata lacks a following member")


def _validate_archive_member_layout(members: Iterable[ArchiveMember]) -> None:
    """Reject full-path and ancestor collisions before filesystem work begins."""

    prefix_spellings: dict[tuple[str, ...], str] = {}
    entry_kinds: dict[tuple[str, ...], tuple[str, str]] = {}
    materialized = list(members)
    for member in materialized:
        parts = PurePosixPath(member.name).parts
        for length in range(1, len(parts) + 1):
            spelling = "/".join(parts[:length])
            folded = tuple(
                unicodedata.normalize("NFC", part).casefold() for part in parts[:length]
            )
            previous = prefix_spellings.get(folded)
            if previous is not None and previous != spelling:
                raise ReleaseError(
                    f"case/Unicode-colliding archive path prefixes: {previous!r}, {spelling!r}"
                )
            prefix_spellings[folded] = spelling
        folded_full = tuple(
            unicodedata.normalize("NFC", part).casefold() for part in parts
        )
        if folded_full in entry_kinds:
            raise ReleaseError(f"duplicate archive entry: {member.name!r}")
        entry_kinds[folded_full] = (member.name, member.kind)

    for member in materialized:
        parts = PurePosixPath(member.name).parts
        for length in range(1, len(parts)):
            folded = tuple(
                unicodedata.normalize("NFC", part).casefold() for part in parts[:length]
            )
            ancestor = entry_kinds.get(folded)
            if ancestor is not None and ancestor[1] != "directory":
                raise ReleaseError(
                    f"archive path descends through {ancestor[1]} member {ancestor[0]!r}"
                )


def inspect_tar(
    path: Path | None,
    *,
    fileobj: BinaryIO | None = None,
    limits: ArchiveLimits,
    expected_top: str | None = None,
) -> list[ArchiveMember]:
    names: set[str] = set()
    folded: set[str] = set()
    members: list[ArchiveMember] = []
    total = 0
    stream: BinaryIO | None = None
    try:
        stream, _raw_bytes, _expanded_bytes = _materialize_tar_stream(
            path, fileobj, limits=limits
        )
        _scan_physical_tar(stream, limits=limits)
        stream.seek(0)
        with tarfile.open(fileobj=stream, mode="r:") as archive:
            for member in archive:
                if len(members) >= limits.max_members:
                    raise ReleaseError("tar member count exceeds safety cap")
                stripped = member.name.rstrip("/")
                if stripped in {"", ".", "./"} and member.isdir():
                    continue
                name = _archive_member_name(member.name, limits=limits)
                folded_name = unicodedata.normalize("NFC", name).casefold()
                if name in names or folded_name in folded:
                    raise ReleaseError(f"duplicate/case-colliding tar member: {name!r}")
                names.add(name)
                folded.add(folded_name)
                if member.isfile():
                    kind = "file"
                    size = member.size
                    if size > limits.max_file_bytes:
                        raise ReleaseError(f"tar member exceeds file cap: {name!r}")
                    total += size
                    if total > limits.max_total_bytes:
                        raise ReleaseError("tar declared bytes exceed total cap")
                    source = archive.extractfile(member)
                    if source is None:
                        raise ReleaseError(f"cannot read tar member body: {name!r}")
                    with source:
                        observed_size, digest = sha256_stream(source, limit=size)
                    if observed_size != size:
                        raise ReleaseError(f"tar member body size mismatch: {name!r}")
                elif member.isdir():
                    kind = "directory"
                    size = 0
                    digest = None
                elif member.issym():
                    kind = "symlink"
                    size = 0
                    digest = None
                else:
                    raise ReleaseError(f"unsupported tar special member: {name!r}")
                if not member.isfile() and member.size != 0:
                    raise ReleaseError(f"non-file tar member has a body: {name!r}")
                mode = stat.S_IMODE(member.mode)
                if mode & 0o7000:
                    raise ReleaseError(
                        f"tar member has forbidden special permission bits: {name!r}"
                    )
                members.append(
                    ArchiveMember(
                        name,
                        kind,
                        size,
                        mode,
                        member.linkname if member.issym() else None,
                        digest,
                    )
                )
    except (tarfile.TarError, OSError, EOFError, lzma.LZMAError) as exc:
        if isinstance(exc, ReleaseError):
            raise
        raise ReleaseError(f"cannot inspect tar archive: {exc}") from exc
    finally:
        if stream is not None:
            stream.close()
    if not members:
        raise ReleaseError("tar archive has no auditable members")
    _validate_archive_member_layout(members)
    tops = sorted({PurePosixPath(member.name).parts[0] for member in members})
    if expected_top is not None and tops != [expected_top]:
        raise ReleaseError(
            f"unexpected archive roots: {tops!r}; expected {[expected_top]!r}"
        )
    top = expected_top or (tops[0] if len(tops) == 1 else "")
    for member in members:
        if member.kind == "symlink":
            if member.linkname is None:
                raise ReleaseError(f"symlink member lacks a target: {member.name!r}")
            _link_stays_within(member.name, member.linkname, top)
    return members


def extract_validated_tar(
    archive_path: Path,
    destination_parent: Path,
    *,
    members: list[ArchiveMember],
    limits: ArchiveLimits | None = None,
) -> Path:
    destination_parent = (
        destination_parent.parent.resolve(strict=True) / destination_parent.name
    )
    if destination_parent.exists():
        raise ReleaseError(
            f"fresh extraction parent already exists: {destination_parent}"
        )
    _validate_archive_member_layout(members)
    expected = {member.name: member for member in members}
    if limits is None:
        limits = ArchiveLimits(
            max_members=max(1, len(members)),
            max_file_bytes=max(1, *(member.size for member in members)),
            max_total_bytes=max(1, sum(member.size for member in members)),
            max_path_bytes=max(
                1, *(len(member.name.encode("utf-8")) for member in members)
            ),
        )
    stream: BinaryIO | None = None
    try:
        stream, _raw_bytes, _expanded_bytes = _materialize_tar_stream(
            archive_path, None, limits=limits
        )
        _scan_physical_tar(stream, limits=limits)
        stream.seek(0)
        with tarfile.open(fileobj=stream, mode="r:") as archive:
            max_path_bytes = max(len(member.name.encode("utf-8")) for member in members)
            extraction_limits = ArchiveLimits(
                max_members=len(members),
                max_file_bytes=max(member.size for member in members),
                max_total_bytes=sum(member.size for member in members),
                max_path_bytes=max_path_bytes,
            )
            actual: dict[str, tarfile.TarInfo] = {}
            actual_records: list[ArchiveMember] = []
            for member in archive:
                if len(actual) >= len(expected):
                    raise ReleaseError(
                        "archive gained members between inspection and extraction"
                    )
                name = _archive_member_name(member.name, limits=extraction_limits)
                if name in actual:
                    raise ReleaseError(
                        "archive gained duplicate members before extraction"
                    )
                if member.isfile():
                    kind = "file"
                    linkname = None
                elif member.isdir():
                    kind = "directory"
                    linkname = None
                elif member.issym():
                    kind = "symlink"
                    linkname = member.linkname
                else:
                    raise ReleaseError(
                        f"archive gained a special member before extraction: {name!r}"
                    )
                actual[name] = member
                actual_records.append(
                    ArchiveMember(
                        name=name,
                        kind=kind,
                        size=member.size,
                        mode=stat.S_IMODE(member.mode),
                        linkname=linkname,
                    )
                )
            _validate_archive_member_layout(actual_records)
            if set(actual) != set(expected):
                raise ReleaseError("archive changed between inspection and extraction")
            for record in actual_records:
                wanted = expected[record.name]
                if (
                    record.kind != wanted.kind
                    or record.size != wanted.size
                    or record.mode != wanted.mode
                    or record.linkname != wanted.linkname
                ):
                    raise ReleaseError(
                        f"archive member metadata changed before extraction: {record.name!r}"
                    )
            destination_parent.mkdir(parents=True)
            for record in members:
                if record.kind != "directory":
                    continue
                target = destination_parent / record.name
                target.mkdir(parents=True, exist_ok=True)
            for record in members:
                if record.kind != "file":
                    continue
                target = destination_parent / record.name
                target.parent.mkdir(parents=True, exist_ok=True)
                for parent in target.parents:
                    if parent == destination_parent:
                        break
                    if parent.is_symlink():
                        raise ReleaseError(
                            f"symlink parent during extraction: {record.name!r}"
                        )
                source = archive.extractfile(actual[record.name])
                if source is None:
                    raise ReleaseError(f"cannot read archive member: {record.name!r}")
                digest = hashlib.sha256()
                written = 0
                with target.open("xb") as output:
                    while True:
                        chunk = source.read(1024 * 1024)
                        if not chunk:
                            break
                        written += len(chunk)
                        if written > record.size:
                            raise ReleaseError(
                                f"member expanded beyond declared size: {record.name!r}"
                            )
                        digest.update(chunk)
                        output.write(chunk)
                if written != record.size:
                    raise ReleaseError(
                        f"member size changed during extraction: {record.name!r}"
                    )
                if record.sha256 is not None and digest.hexdigest() != record.sha256:
                    raise ReleaseError(
                        f"member content changed during extraction: {record.name!r}"
                    )
                target.chmod(record.mode)
            for record in members:
                if record.kind != "symlink":
                    continue
                target = destination_parent / record.name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.symlink_to(record.linkname)
            resolved_root = destination_parent.resolve(strict=True)
            for record in members:
                if record.kind != "symlink":
                    continue
                target = destination_parent / record.name
                _resolved_symlink(resolved_root, target)
            for record in sorted(
                (item for item in members if item.kind == "directory"),
                key=lambda item: len(PurePosixPath(item.name).parts),
                reverse=True,
            ):
                (destination_parent / record.name).chmod(record.mode)
    except BaseException:
        # Leave the fresh root for forensics; callers never reuse it.
        raise
    finally:
        if stream is not None:
            stream.close()
    tops = sorted({PurePosixPath(member.name).parts[0] for member in members})
    if len(tops) != 1:
        raise ReleaseError("archive must contain exactly one top-level root")
    return destination_parent / tops[0]


def inspect_zip(path: Path, *, limits: ArchiveLimits) -> dict[str, Any]:
    raw_bytes = path.stat().st_size
    if raw_bytes <= 0 or raw_bytes > limits.max_total_bytes:
        raise ReleaseError("raw zip stream exceeds safety cap")
    with path.open("rb") as source:
        tail_bytes = min(raw_bytes, 22 + 65535)
        source.seek(raw_bytes - tail_bytes)
        tail = source.read(tail_bytes)
    exact_eocd = False
    position = len(tail)
    while True:
        position = tail.rfind(b"PK\x05\x06", 0, position)
        if position < 0:
            break
        if position + 22 <= len(tail):
            comment_bytes = int.from_bytes(
                tail[position + 20 : position + 22], "little"
            )
            if position + 22 + comment_bytes == len(tail):
                exact_eocd = True
                break
        if position == 0:
            break
    if not exact_eocd:
        raise ReleaseError("zip has trailing/unreferenced bytes or no exact end record")
    names: set[str] = set()
    folded: set[str] = set()
    total = 0
    compressed_total = 0
    metadata_total = 0
    members = 0
    try:
        with zipfile.ZipFile(path) as archive:
            metadata_total += len(archive.comment)
            for info in archive.infolist():
                members += 1
                if members > limits.max_members:
                    raise ReleaseError("zip member count exceeds safety cap")
                name = _archive_member_name(info.filename, limits=limits)
                folded_name = unicodedata.normalize("NFC", name).casefold()
                if name in names or folded_name in folded:
                    raise ReleaseError(f"duplicate/case-colliding zip member: {name!r}")
                names.add(name)
                folded.add(folded_name)
                metadata_total += (
                    46
                    + len(info.filename.encode("utf-8"))
                    + len(info.extra)
                    + len(info.comment)
                )
                if metadata_total > min(
                    limits.max_total_bytes, MAX_TAR_EXTENSION_BYTES
                ):
                    raise ReleaseError("zip central/header metadata exceeds safety cap")
                if info.flag_bits & 0x1:
                    raise ReleaseError(f"encrypted zip member is forbidden: {name!r}")
                mode = (info.external_attr >> 16) & 0xFFFF
                kind = stat.S_IFMT(mode)
                if kind not in {0, stat.S_IFREG, stat.S_IFDIR}:
                    raise ReleaseError(f"zip special member is forbidden: {name!r}")
                if info.file_size > limits.max_file_bytes:
                    raise ReleaseError(f"zip member exceeds file cap: {name!r}")
                total += info.file_size
                compressed_total += info.compress_size
                if total > limits.max_total_bytes:
                    raise ReleaseError("zip declared bytes exceed total cap")
                if compressed_total > raw_bytes:
                    raise ReleaseError("zip compressed extents exceed raw stream")
                with archive.open(info) as source:
                    size, _digest = sha256_stream(
                        source, limit=min(limits.max_file_bytes, info.file_size)
                    )
                if size != info.file_size:
                    raise ReleaseError(f"zip member size mismatch: {name!r}")
    except (OSError, zipfile.BadZipFile, RuntimeError, NotImplementedError) as exc:
        if isinstance(exc, ReleaseError):
            raise
        raise ReleaseError(f"cannot inspect zip archive {path.name}: {exc}") from exc
    if not members:
        raise ReleaseError(f"zip archive has no members: {path.name}")
    return {
        "members": members,
        "raw_bytes": raw_bytes,
        "metadata_bytes": metadata_total,
        "compressed_bytes": compressed_total,
        "declared_bytes": total,
        "expanded_bytes": total,
    }


def _read_ar_members(path: Path, *, limits: ArchiveLimits) -> list[tuple[str, bytes]]:
    result: list[tuple[str, bytes]] = []
    names: set[str] = set()
    folded: set[str] = set()
    total = 0
    with path.open("rb") as source:
        if source.read(8) != b"!<arch>\n":
            raise ReleaseError(f"invalid ar/deb magic: {path.name}")
        while True:
            header = source.read(60)
            if not header:
                break
            if len(header) != 60 or header[58:] != b"`\n":
                raise ReleaseError(f"invalid ar member header: {path.name}")
            try:
                raw_name = header[:16].decode("ascii").strip()
                size = int(header[48:58].decode("ascii").strip())
            except (UnicodeDecodeError, ValueError) as exc:
                raise ReleaseError(f"invalid ar member metadata: {path.name}") from exc
            if size < 0:
                raise ReleaseError(f"negative ar member size: {path.name}")
            if raw_name.startswith(("/", "#1/")):
                raise ReleaseError(
                    "GNU/BSD extended ar names are not accepted in .deb gates"
                )
            name = raw_name.rstrip("/")
            portable_path(name, label="deb member", single=True)
            folded_name = unicodedata.normalize("NFC", name).casefold()
            if name in names or folded_name in folded:
                raise ReleaseError(f"duplicate/case-colliding deb member: {name!r}")
            if len(result) >= limits.max_members or size > limits.max_file_bytes:
                raise ReleaseError("deb member cap exceeded")
            total += size
            if total > limits.max_total_bytes:
                raise ReleaseError("deb total-byte cap exceeded")
            data = source.read(size)
            if len(data) != size:
                raise ReleaseError(f"truncated deb member: {name!r}")
            if size & 1 and source.read(1) != b"\n":
                raise ReleaseError(f"invalid deb alignment byte: {name!r}")
            names.add(name)
            folded.add(folded_name)
            result.append((name, data))
    return result


def inspect_deb(path: Path, *, limits: ArchiveLimits) -> dict[str, Any]:
    members = _read_ar_members(path, limits=limits)
    names = [name for name, _data in members]
    control = [name for name in names if name.startswith("control.tar")]
    payload = [name for name in names if name.startswith("data.tar")]
    if names.count("debian-binary") != 1 or len(control) != 1 or len(payload) != 1:
        raise ReleaseError(f"incomplete Debian binary archive: {path.name}")
    if dict(members)["debian-binary"] != b"2.0\n":
        raise ReleaseError(f"unsupported Debian binary format marker: {path.name}")
    permitted = {"debian-binary", control[0], payload[0], "_gpgorigin"}
    if set(names) - permitted:
        raise ReleaseError(
            f"unexpected Debian archive members: {sorted(set(names) - permitted)}"
        )
    nested_members = 0
    expanded_bytes = 0
    for name, data in members:
        if name.startswith(("control.tar", "data.tar")):
            if name.endswith(".zst"):
                records = _inspect_zstd_tar(data, limits=limits)
            else:
                records = inspect_tar(None, fileobj=io.BytesIO(data), limits=limits)
            nested_members += len(records)
            expanded_bytes += sum(record.size for record in records)
    return {
        "members": len(members),
        "embedded_tar_members": nested_members,
        "expanded_bytes": expanded_bytes,
    }


def _inspect_zstd_tar(data: bytes, *, limits: ArchiveLimits) -> list[ArchiveMember]:
    expansion_cap = min(
        MAX_HARD_TOTAL_BYTES,
        limits.max_total_bytes + limits.max_members * 2048 + 10 * 1024**2,
    )
    with tempfile.TemporaryDirectory(prefix="kazstem-zstd-audit-") as temporary:
        root = Path(temporary)
        compressed = root / "member.tar.zst"
        expanded = root / "member.tar"
        compressed.write_bytes(data)
        try:
            zstd = Path("/usr/bin/zstd")
            if not zstd.is_file():
                raise ReleaseError(
                    "zstd is required to inspect zstd-compressed .deb members"
                )
            process = subprocess.Popen(
                [str(zstd), "-q", "-d", "-c", str(compressed)],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            )
        except OSError as exc:
            raise ReleaseError(
                "zstd is required to inspect zstd-compressed Debian members"
            ) from exc
        if process.stdout is None:
            process.kill()
            raise ReleaseError("cannot capture zstd output")
        written = 0
        try:
            with process.stdout, expanded.open("xb") as destination:
                while True:
                    chunk = process.stdout.read(1024 * 1024)
                    if not chunk:
                        break
                    written += len(chunk)
                    if written > expansion_cap:
                        process.kill()
                        raise ReleaseError(
                            "zstd-compressed Debian member exceeds expansion cap"
                        )
                    destination.write(chunk)
            returncode = process.wait(timeout=30)
        except subprocess.TimeoutExpired as exc:
            process.kill()
            process.wait()
            raise ReleaseError("zstd decompression exceeded 30 seconds") from exc
        except BaseException:
            process.kill()
            process.wait()
            raise
        if returncode:
            raise ReleaseError("cannot decompress zstd-compressed Debian member")
        return inspect_tar(expanded, limits=limits)


def inspect_gzip(path: Path, *, limits: ArchiveLimits) -> dict[str, Any]:
    try:
        with gzip.open(path, "rb") as source:
            size, digest = sha256_stream(source, limit=limits.max_file_bytes)
    except (OSError, EOFError) as exc:
        raise ReleaseError(f"cannot inspect gzip stream {path.name}: {exc}") from exc
    if size == 0:
        raise ReleaseError(f"gzip stream is empty: {path.name}")
    return {"members": 1, "expanded_bytes": size, "expanded_sha256": digest}


def _looks_like_tar_prefix(prefix: bytes) -> bool:
    if len(prefix) >= 2 * TAR_BLOCK_BYTES and prefix[: 2 * TAR_BLOCK_BYTES] == (
        b"\x00" * (2 * TAR_BLOCK_BYTES)
    ):
        return True
    if len(prefix) < TAR_BLOCK_BYTES or not prefix[:100].rstrip(b"\x00"):
        return False
    try:
        _verify_tar_header(prefix[:TAR_BLOCK_BYTES])
    except ReleaseError:
        return False
    return True


def _compressed_prefix(path: Path, compression: str) -> bytes | None:
    try:
        with path.open("rb") as raw:
            if compression == "gzip":
                reader: BinaryIO = gzip.GzipFile(fileobj=raw, mode="rb")
            elif compression == "xz":
                reader = lzma.LZMAFile(raw, mode="rb")
            else:
                reader = bz2.BZ2File(raw, mode="rb")
            with reader:
                return reader.read(2 * TAR_BLOCK_BYTES)
    except (OSError, EOFError, lzma.LZMAError):
        # The compression magic is still recognized.  The format-specific
        # inspector will produce the corruption failure for a declared file.
        return None


def detect_archive_format(path: Path) -> str | None:
    """Recognize archive containers by bytes, never by their filename suffix."""

    if not path.is_file() or path.is_symlink():
        return None
    with path.open("rb") as source:
        prefix = source.read(2 * TAR_BLOCK_BYTES)
    if prefix.startswith(
        (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")
    ) or zipfile.is_zipfile(path):
        return "zip"
    if prefix.startswith(b"!<arch>\n"):
        return "deb"
    if prefix.startswith(b"\x1f\x8b"):
        expanded = _compressed_prefix(path, "gzip")
        return (
            "tar"
            if expanded is not None and _looks_like_tar_prefix(expanded)
            else "gzip"
        )
    if prefix.startswith(b"\xfd7zXZ\x00"):
        expanded = _compressed_prefix(path, "xz")
        return (
            "tar" if expanded is not None and _looks_like_tar_prefix(expanded) else "xz"
        )
    if prefix.startswith(b"BZh"):
        expanded = _compressed_prefix(path, "bzip2")
        return (
            "tar"
            if expanded is not None and _looks_like_tar_prefix(expanded)
            else "bzip2"
        )
    if prefix.startswith(b"\x28\xb5\x2f\xfd"):
        return "zstd"
    if prefix.startswith(b"7z\xbc\xaf\x27\x1c"):
        return "7z"
    if prefix.startswith((b"Rar!\x1a\x07\x00", b"Rar!\x1a\x07\x01\x00")):
        return "rar"
    if prefix.startswith(b"MSCF"):
        return "cab"
    if _looks_like_tar_prefix(prefix):
        return "tar"
    return None


def verify_declared_archive_inventory(
    root: Path, declared: dict[str, str]
) -> dict[str, str]:
    """Require every magic-recognized archive to be supported and declared."""

    if not root.is_dir() or root.is_symlink():
        raise ReleaseError(f"archive inventory root is invalid: {root}")
    for relative, kind in declared.items():
        portable_path(relative, label="declared nested archive path")
        if kind not in SUPPORTED_NESTED_ARCHIVE_FORMATS:
            raise ReleaseError(f"unsupported declared nested archive format: {kind!r}")
    observed: dict[str, str] = {}
    for path in regular_files(root):
        kind = detect_archive_format(path)
        if kind is None:
            continue
        relative = path.relative_to(root).as_posix()
        if kind not in SUPPORTED_NESTED_ARCHIVE_FORMATS:
            raise ReleaseError(
                f"recognized unsupported nested archive {relative!r}: {kind}"
            )
        observed[relative] = kind
    missing = sorted(set(declared) - set(observed))
    undeclared = sorted(set(observed) - set(declared))
    if missing or undeclared:
        raise ReleaseError(
            "nested archive inventory is incomplete "
            f"(undeclared={undeclared}, missing={missing})"
        )
    mismatched = sorted(
        relative for relative in declared if declared[relative] != observed[relative]
    )
    if mismatched:
        details = [
            f"{relative}:{declared[relative]}!={observed[relative]}"
            for relative in mismatched
        ]
        raise ReleaseError(f"nested archive format mismatch: {details}")
    return observed


def inspect_nested(path: Path, kind: str, *, limits: ArchiveLimits) -> dict[str, Any]:
    observed = detect_archive_format(path)
    if observed is None:
        raise ReleaseError(f"unrecognized nested archive bytes: {path.name}")
    if observed not in SUPPORTED_NESTED_ARCHIVE_FORMATS:
        raise ReleaseError(
            f"recognized unsupported nested archive format: {observed!r}"
        )
    if kind != observed:
        raise ReleaseError(
            f"nested archive format mismatch: declared={kind!r}, observed={observed!r}"
        )
    if kind == "tar":
        members = inspect_tar(path, limits=limits)
        expanded = sum(item.size for item in members)
        return {
            "members": len(members),
            "declared_bytes": expanded,
            "expanded_bytes": expanded,
        }
    if kind == "zip":
        return inspect_zip(path, limits=limits)
    if kind == "deb":
        return inspect_deb(path, limits=limits)
    if kind == "gzip":
        return inspect_gzip(path, limits=limits)
    raise ReleaseError(f"unsupported nested archive kind: {kind!r}")


_WEB_URL = re.compile(r"(?i)\bhttps?://[^\s<>\"']+")
_MACOS_SYSTEM_BOUNDARY = re.compile(r"/(?:usr/lib|System/Library)(?:/[^\s<>\"']*)?")
_PATH_BOUNDARY = r"(?:^|[\s=,:;()\[\]{}<>\"'])"
_ABSOLUTE_PATH_PATTERNS = (
    re.compile(rf"(?i){_PATH_BOUNDARY}file:(?://)?[^\s<>\"']*"),
    re.compile(rf"{_PATH_BOUNDARY}(?:~/|\.\.[\\/])[^\s<>\"']*"),
    re.compile(rf"{_PATH_BOUNDARY}[A-Za-z]:[\\/][^\s<>\"']*"),
    # UNC and Win32 device namespaces (\\server, \\?\, \\.\).
    re.compile(rf"{_PATH_BOUNDARY}\\{{2,}}[^\s<>\"']+"),
    # A rooted Windows path has no drive but is still machine-specific.
    re.compile(rf"{_PATH_BOUNDARY}\\[A-Za-z0-9?.][^\s<>\"']*"),
    # Remove web URLs before applying this POSIX-root detector so URL paths do
    # not become false positives.  Label-adjacent forms such as root=/tmp are
    # intentionally matched.
    re.compile(rf"{_PATH_BOUNDARY}/[^/\s<>\"'][^\s<>\"']*"),
)


def absolute_reference(value: str) -> str | None:
    """Return the first machine-absolute reference in arbitrary evidence text."""

    without_urls = _WEB_URL.sub("<url>", value)
    without_urls = _MACOS_SYSTEM_BOUNDARY.sub("<macos-system-boundary>", without_urls)
    for pattern in _ABSOLUTE_PATH_PATTERNS:
        match = pattern.search(without_urls)
        if match is not None:
            return match.group(0).lstrip(" \t\r\n=,:;()[]{}<>\"'")
    return None


def _absolute_reference(value: str) -> bool:
    """Compatibility wrapper for callers that only need a predicate."""

    return absolute_reference(value) is not None


def assert_relative_json(value: Any, *, label: str = "JSON evidence") -> None:
    def walk(item: Any, path: str) -> None:
        if isinstance(item, str):
            token = absolute_reference(item)
            if token is not None:
                raise ReleaseError(f"absolute path in {label} {path}: {token!r}")
        if isinstance(item, list):
            for index, child in enumerate(item):
                walk(child, f"{path}[{index}]")
        elif isinstance(item, dict):
            for key, child in item.items():
                walk(key, f"{path}.<key>")
                walk(child, f"{path}.{key}")

    walk(value, "$")


def assert_relative_evidence(root: Path) -> None:
    if not root.is_dir() or root.is_symlink():
        raise ReleaseError(f"evidence root is missing or invalid: {root}")
    for entry in root.rglob("*"):
        if entry.is_symlink():
            raise ReleaseError(f"symlink is forbidden in evidence: {entry}")
        mode = entry.lstat().st_mode
        if not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
            raise ReleaseError(f"special entry is forbidden in evidence: {entry}")
    for path in regular_files(root):
        if path.stat().st_size > 64 * 1024**2:
            raise ReleaseError(f"evidence text exceeds 64 MiB audit cap: {path}")
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeError as exc:
            raise ReleaseError(f"evidence must be UTF-8 text: {path}") from exc
        relative = path.relative_to(root).as_posix()
        if path.suffix.casefold() == ".json":
            assert_relative_json(
                decode_json(text.encode("utf-8"), label=relative),
                label=f"evidence JSON {relative}",
            )
        else:
            token = absolute_reference(text)
            if token is not None:
                raise ReleaseError(
                    f"absolute path token in evidence {relative}: {token!r}"
                )


def manifest_entry_records(
    root: Path, *, excluded: set[str]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[str]]:
    files: list[dict[str, Any]] = []
    links: list[dict[str, Any]] = []
    directories: list[str] = []
    for path in regular_files(root):
        relative = path.relative_to(root).as_posix()
        if relative not in excluded:
            files.append({"path": relative, **file_record(path)})
    for path in symlinks(root):
        links.append(
            {"path": path.relative_to(root).as_posix(), "target": os.readlink(path)}
        )
    for path in sorted(
        (path for path in root.rglob("*") if path.is_dir() and not path.is_symlink()),
        key=lambda path: path.relative_to(root).as_posix(),
    ):
        directories.append(path.relative_to(root).as_posix())
    return files, links, directories


def verify_manifest_completeness(
    root: Path,
    manifest: dict[str, Any],
    *,
    excluded_files: set[str],
) -> None:
    if (
        not isinstance(manifest.get("files"), list)
        or not isinstance(manifest.get("symlinks"), list)
        or not isinstance(manifest.get("directories"), list)
    ):
        raise ReleaseError("archive manifest lacks file/symlink/directory inventories")
    observed_files, observed_links, observed_directories = manifest_entry_records(
        root, excluded=excluded_files
    )
    if manifest["files"] != observed_files:
        raise ReleaseError("archive manifest file inventory is incomplete or incorrect")
    if manifest["symlinks"] != observed_links:
        raise ReleaseError(
            "archive manifest symlink inventory is incomplete or incorrect"
        )
    if manifest["directories"] != observed_directories:
        raise ReleaseError(
            "archive manifest directory inventory is incomplete or incorrect"
        )


def verify_outer_archive_completeness(
    members: list[ArchiveMember], root: Path, *, top_level: str
) -> None:
    expected: dict[str, str] = {top_level: "directory"}
    for path in root.rglob("*"):
        relative = path.relative_to(root).as_posix()
        name = f"{top_level}/{relative}"
        if path.is_symlink():
            kind = "symlink"
        elif path.is_dir():
            kind = "directory"
        elif path.is_file():
            kind = "file"
        else:
            raise ReleaseError(f"unsupported extracted entry: {relative}")
        expected[name] = kind
    observed = {member.name: member.kind for member in members}
    if observed != expected:
        raise ReleaseError(
            "outer archive member inventory is incomplete "
            f"(missing={sorted(set(expected) - set(observed))}, "
            f"extra={sorted(set(observed) - set(expected))})"
        )


def verify_sealed_archive_modes(
    members: list[ArchiveMember], *, executable_paths: Iterable[str] | None = None
) -> None:
    executable = None if executable_paths is None else set(executable_paths)
    if executable is not None:
        observed_files = {member.name for member in members if member.kind == "file"}
        unknown = executable - observed_files
        if unknown:
            raise ReleaseError(
                f"normalized executable inventory names non-files: {sorted(unknown)[:20]}"
            )
    failures: list[str] = []
    for member in members:
        if member.kind == "file":
            expected = (
                (0o555 if member.name in executable else 0o444)
                if executable is not None
                else None
            )
            allowed = {0o444, 0o555} if expected is None else {expected}
        elif member.kind == "directory":
            allowed = {0o555}
        else:
            allowed = {0o777}
        if member.mode not in allowed:
            wanted = "/".join(f"{mode:04o}" for mode in sorted(allowed))
            failures.append(f"{member.name}:{member.mode:04o}!={wanted}")
    if failures:
        raise ReleaseError(
            f"outer archive modes are not exactly normalized: {failures[:20]}"
        )


def verify_required_paths(root: Path, required: Iterable[str]) -> None:
    for relative in required:
        path = root / relative
        if not path.exists() and not path.is_symlink():
            raise ReleaseError(f"required release path is missing: {relative}")


def verify_source_contract(root: Path, identity: dict[str, Any]) -> None:
    source = identity["corresponding_source"]
    for name, relative in source["source_categories"].items():
        path = root / relative
        if not path.is_dir() or path.is_symlink():
            raise ReleaseError(
                f"corresponding-source category is missing or invalid: {name}={relative}"
            )
    markers = (
        (
            source["source_commit_file"],
            f"{identity['source_commit']}\n".encode("ascii"),
        ),
        (
            source["source_tree_file"],
            f"{identity['source_tree']}\n".encode("ascii"),
        ),
        (
            source["source_origin_file"],
            f"{identity['source_origin']}\n".encode("utf-8"),
        ),
        (
            source["source_date_epoch_file"],
            f"{identity['source_date_epoch']}\n".encode("ascii"),
        ),
    )
    for relative, expected in markers:
        path = root / relative
        if not path.is_file() or path.is_symlink() or path.read_bytes() != expected:
            raise ReleaseError(
                f"source identity marker differs from release identity: {relative}"
            )


def verify_ready_root_identity(root: Path, identity: dict[str, Any]) -> dict[str, int]:
    """Bind a fresh ready-run tree to its complete checked internal receipts.

    Behavior, Mach-O, network and performance gates operate on an extracted
    tree.  They must not accept an arbitrary directory merely because the
    envelope names the ready-run artifact.  The checks below cover every file,
    link and directory and independently bind the public source companion.
    """

    if root.is_symlink():
        raise ReleaseError("ready-run gate root must not be a symlink")
    root = root.resolve(strict=True)
    if not root.is_dir():
        raise ReleaseError("ready-run gate root is not a real directory")
    ready = identity["ready_run"]
    inputs = identity["inputs"]
    artifacts = identity["artifacts"]
    expected_build_identity = {
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
        "corresponding_source": artifacts["corresponding_source"],
        "frozen_launcher": ready["launcher"],
        "resource_bundle_id": inputs["resource_tree"]["bundle_id"],
        "resource_manifest": inputs["resource_tree"]["manifest"],
        "platform_runtime_bundle_id": inputs["runtime_tree"]["bundle_id"],
        "platform_runtime_manifest": inputs["runtime_tree"]["manifest"],
        "platform_lock": ready["platform_lock"],
    }
    if read_json(root / "verification/BUILD-IDENTITY.json") != expected_build_identity:
        raise ReleaseError("ready-run BUILD-IDENTITY differs from the release identity")
    if read_json(root / "CORRESPONDING-SOURCE.json") != ready_source_binding(identity):
        raise ReleaseError("ready-run source-companion binding differs")
    verify_file(
        root / ready["launcher"]["path"],
        ready["launcher"]["file"],
        label="identity-bound ready-run launcher",
    )
    verify_file(
        root / ready["platform_lock"]["path"],
        ready["platform_lock"]["file"],
        label="identity-bound ready-run platform lock",
    )
    verify_required_paths(root, ready["required_paths"])

    checksum_path = root / "verification/BUNDLED-FILES.sha256"
    checksums = parse_checksums(checksum_path.read_bytes())
    observed_files = {
        path.relative_to(root).as_posix()
        for path in regular_files(root)
        if path != checksum_path
    }
    if set(checksums) != observed_files:
        raise ReleaseError("ready-run checksum inventory is incomplete")
    for relative, expected in checksums.items():
        if sha256_file(root / relative) != expected:
            raise ReleaseError(f"ready-run checksum differs: {relative}")

    manifest = read_json(root / "verification/BUNDLE-MANIFEST.json")
    if (
        not isinstance(manifest, dict)
        or set(manifest)
        != {
            "schema",
            "release",
            "source_commit",
            "executable_paths",
            "files",
            "symlinks",
            "directories",
        }
        or manifest["schema"] != "kazstem-macos-ready-run-manifest-v2"
        or manifest["release"] != identity["release"]
        or manifest["source_commit"] != identity["source_commit"]
    ):
        raise ReleaseError("ready-run manifest identity differs")
    verify_manifest_completeness(
        root,
        manifest,
        excluded_files={
            "verification/BUNDLE-MANIFEST.json",
            "verification/BUNDLED-FILES.sha256",
        },
    )
    executable = set(_unique_paths(manifest["executable_paths"], "executable paths"))
    for path in root.rglob("*"):
        relative = path.relative_to(root).as_posix()
        mode = stat.S_IMODE(path.lstat().st_mode)
        expected_mode = (
            0o777
            if path.is_symlink()
            else 0o555
            if path.is_dir() or relative in executable
            else 0o444
        )
        if mode != expected_mode:
            raise ReleaseError(
                f"ready-run extracted mode differs: {relative}:{mode:04o}"
            )
    return {
        "checksummed_files": len(checksums),
        "manifest_directories": len(manifest["directories"]),
        "manifest_files": len(manifest["files"]),
        "manifest_symlinks": len(manifest["symlinks"]),
    }


def identity_sha256(path: Path) -> str:
    identity = load_identity(path)
    projection = dict(identity)
    projection["verification"] = {
        "minimum_distinct_roots": identity["verification"]["minimum_distinct_roots"],
        "reproducibility": identity["verification"]["reproducibility"],
        "tracing": identity["verification"]["tracing"],
        "evidence": [
            {
                "path": record["path"],
                "gate": record["gate"],
                "kind": record["kind"],
                "subjects": record["subjects"],
                "generator": record["generator"],
            }
            for record in identity["verification"]["evidence"]
        ],
    }
    return canonical_hash(projection)


def stream_evidence_record(data: bytes) -> dict[str, Any]:
    return {
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "lines": len(data.splitlines()),
        "truncated": False,
    }


def tool_output_identity(data: bytes, *, exit_status: int) -> str:
    """Bind arbitrary tool output without publishing host-specific text."""

    return (
        f"sha256={hashlib.sha256(data).hexdigest()};"
        f"bytes={len(data)};exit={exit_status}"
    )


def _validate_stream_evidence(value: Any, label: str) -> dict[str, Any]:
    record = _exact_fields(value, {"bytes", "sha256", "lines", "truncated"}, label)
    for field in ("bytes", "lines"):
        if (
            isinstance(record[field], bool)
            or not isinstance(record[field], int)
            or record[field] < 0
            or record[field] > MAX_HARD_TOTAL_BYTES
        ):
            raise ReleaseError(f"{label}.{field} is invalid")
    _sha(record["sha256"], f"{label}.sha256")
    if record["truncated"] is not False:
        raise ReleaseError(f"{label} must explicitly be nontruncated")
    return record


def validate_gate_envelope(
    value: Any,
    *,
    identity: dict[str, Any],
    identity_contract_sha256: str,
    gate: str,
    subjects: list[str],
) -> dict[str, Any]:
    envelope = _exact_fields(
        value,
        {
            "schema",
            "gate",
            "pass",
            "release",
            "source_commit",
            "source_tree",
            "identity_contract_sha256",
            "subjects",
            "invocation",
            "coverage",
            "payload",
        },
        f"{gate} evidence envelope",
    )
    if (
        envelope["schema"] != "kazstem-release-gate-envelope-v1"
        or envelope["gate"] != gate
        or envelope["pass"] is not True
        or envelope["release"] != identity["release"]
        or envelope["source_commit"] != identity["source_commit"]
        or envelope["source_tree"] != identity["source_tree"]
        or envelope["identity_contract_sha256"] != identity_contract_sha256
    ):
        raise ReleaseError(f"{gate} evidence envelope identity differs")
    expected_subjects = {
        subject: identity["artifacts"][subject] for subject in subjects
    }
    if envelope["subjects"] != expected_subjects:
        raise ReleaseError(f"{gate} evidence subjects differ from the identity")
    invocation = _exact_fields(
        envelope["invocation"],
        {
            "argv",
            "cwd",
            "environment",
            "exit_status",
            "script",
            "source_commit",
            "source_tree",
            "stderr",
            "stdout",
            "timeout_seconds",
            "tool",
        },
        f"{gate}.invocation",
    )
    generator_records = {
        record["gate"]: record["generator"]
        for record in identity["verification"]["evidence"]
    }
    generator = generator_records.get(gate)
    if generator is None:
        raise ReleaseError(f"{gate} has no identity-bound generator")
    argv = invocation["argv"]
    if (
        not isinstance(argv, list)
        or not argv
        or any(not isinstance(item, str) or not item for item in argv)
        or invocation["exit_status"] != 0
        or invocation["argv"] != generator["argv"]
        or invocation["cwd"] != generator["cwd"]
        or invocation["environment"] != generator["environment"]
        or invocation["script"] != generator["script"]
        or invocation["source_commit"] != generator["source_commit"]
        or invocation["source_tree"] != generator["source_tree"]
        or invocation["timeout_seconds"] != generator["timeout_seconds"]
    ):
        raise ReleaseError(
            f"{gate} evidence invocation differs from its locked generator"
        )
    environment = invocation["environment"]
    if not isinstance(environment, dict) or any(
        not isinstance(key, str) or not isinstance(item, str)
        for key, item in environment.items()
    ):
        raise ReleaseError(f"{gate} evidence environment is invalid")
    configured_tools = {
        tool["name"]: tool
        for tool in identity["verification"]["reproducibility"]["tools"]
    }
    tool = invocation["tool"]
    if (
        not isinstance(tool, dict)
        or tool.get("name") not in configured_tools
        or tool != configured_tools[tool["name"]]
        or argv[0] != tool["name"]
        or tool["name"] != generator["tool"]
    ):
        raise ReleaseError(f"{gate} evidence tool is not identity-bound")
    _validate_stream_evidence(invocation["stdout"], f"{gate}.stdout")
    _validate_stream_evidence(invocation["stderr"], f"{gate}.stderr")

    coverage = _exact_fields(
        envelope["coverage"],
        {
            "descendant_processes",
            "full_descendant_coverage",
            "network_trace",
            "observations",
            "trace_complete",
            "trace_truncated",
        },
        f"{gate}.coverage",
    )
    _positive_int(
        coverage["descendant_processes"],
        f"{gate}.coverage.descendant_processes",
        ceiling=MAX_HARD_MEMBERS,
    )
    if (
        not isinstance(coverage["full_descendant_coverage"], bool)
        or coverage["trace_complete"] is not True
        or coverage["trace_truncated"] is not False
        or not isinstance(coverage["observations"], dict)
        or any(
            isinstance(item, bool) or not isinstance(item, int) or item < 0
            for item in coverage["observations"].values()
        )
    ):
        raise ReleaseError(f"{gate} evidence coverage is incomplete")
    network = coverage["network_trace"]
    if gate == "network-trace":
        network = _exact_fields(
            network,
            {
                "cases_sandboxed",
                "events",
                "negative_control",
                "observed_descendants",
                "policy_argv_prefix",
                "policy_denials",
                "policy_tool",
                "process_observer_argv",
                "process_samples",
                "profile",
                "trace",
            },
            "network-trace.coverage.network_trace",
        )
        tracing = identity["verification"]["tracing"]
        if (
            network["policy_argv_prefix"] != tracing["argv_prefix"]
            or network["policy_tool"] != tracing["tool"]
            or network["profile"] != tracing["profile"]
            or network["process_observer_argv"] != tracing["process_observer_argv"]
            or coverage["full_descendant_coverage"] is not True
        ):
            raise ReleaseError("network evidence lacks full sandbox/process coverage")
        for field in (
            "cases_sandboxed",
            "observed_descendants",
            "policy_denials",
            "process_samples",
        ):
            _positive_int(
                network[field], f"network-trace.{field}", ceiling=MAX_HARD_MEMBERS
            )
        negative = _exact_fields(
            network["negative_control"],
            {"argv", "denied", "exit_status", "stderr", "stdout"},
            "network-trace.negative_control",
        )
        if (
            negative["argv"] != tracing["negative_control_argv"]
            or negative["denied"] is not True
            or isinstance(negative["exit_status"], bool)
            or not isinstance(negative["exit_status"], int)
            or negative["exit_status"] == 0
        ):
            raise ReleaseError("network sandbox negative control did not prove denial")
        _validate_stream_evidence(negative["stdout"], "network-trace.negative.stdout")
        _validate_stream_evidence(negative["stderr"], "network-trace.negative.stderr")
        trace_record = _validate_stream_evidence(
            network["trace"], "network-trace.trace"
        )
        if trace_record["bytes"] == 0 or trace_record["lines"] == 0:
            raise ReleaseError("network/process trace evidence must not be empty")
        events = network["events"]
        if (
            not isinstance(events, list)
            or not events
            or any(
                not isinstance(event, dict)
                or set(event) != {"kind", "process", "result", "sequence"}
                or not isinstance(event["kind"], str)
                or not isinstance(event["process"], str)
                or not isinstance(event["result"], str)
                or isinstance(event["sequence"], bool)
                or not isinstance(event["sequence"], int)
                for event in events
            )
            or [event["sequence"] for event in events] != list(range(len(events)))
        ):
            raise ReleaseError(
                "network/process normalized event evidence is incomplete"
            )
    elif network is not None:
        raise ReleaseError(f"{gate} unexpectedly contains network trace evidence")
    if gate == "source-suite" and coverage["full_descendant_coverage"] is not True:
        raise ReleaseError("source-suite lacks full descendant coverage")
    payload = envelope["payload"]
    if not isinstance(payload, dict):
        raise ReleaseError(f"{gate} evidence payload is not a JSON object")
    assert_relative_json(envelope, label=f"{gate} evidence envelope")
    return payload


def gate_envelope(
    *,
    identity: dict[str, Any],
    identity_contract_sha256: str,
    gate: str,
    subjects: list[str],
    invocation: dict[str, Any],
    coverage: dict[str, Any],
    payload: dict[str, Any],
) -> dict[str, Any]:
    value = {
        "schema": "kazstem-release-gate-envelope-v1",
        "gate": gate,
        "pass": True,
        "release": identity["release"],
        "source_commit": identity["source_commit"],
        "source_tree": identity["source_tree"],
        "identity_contract_sha256": identity_contract_sha256,
        "subjects": {subject: identity["artifacts"][subject] for subject in subjects},
        "invocation": invocation,
        "coverage": coverage,
        "payload": payload,
    }
    validate_gate_envelope(
        value,
        identity=identity,
        identity_contract_sha256=identity_contract_sha256,
        gate=gate,
        subjects=subjects,
    )
    return value


def _gate_generator(identity: dict[str, Any], gate: str) -> dict[str, Any]:
    matches = [
        record["generator"]
        for record in identity["verification"]["evidence"]
        if record["gate"] == gate
    ]
    if len(matches) != 1:
        raise ReleaseError(f"gate does not have exactly one generator: {gate}")
    return matches[0]


def _git_text(repository: Path, *arguments: str) -> str:
    process = subprocess.run(
        ["git", *arguments],
        cwd=repository,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=60,
        check=False,
    )
    if process.returncode:
        raise ReleaseError(
            f"gate source Git query failed: {arguments!r}: "
            f"{process.stderr[:1024].decode('utf-8', 'replace')}"
        )
    return process.stdout.decode("utf-8", "strict").strip()


def begin_gate_execution(
    identity: dict[str, Any], gate: str, *, caller_file: str
) -> GateExecution:
    """Fail closed unless this process is the exact checked gate invocation.

    Gate envelopes are evidence about a process, so their invocation cannot be
    populated by copying a record from the identity.  This check binds the live
    interpreter, original argv (including ``-S``), environment, working source
    checkout, and executing script bytes before installing a real wall-clock
    timeout.  The release workspace itself remains location-independent.
    """

    generator = _gate_generator(identity, gate)
    tools = {
        record["name"]: record
        for record in identity["verification"]["reproducibility"]["tools"]
    }
    tool = tools.get(generator["tool"])
    if tool is None:
        raise ReleaseError(f"gate generator tool is not bound: {gate}")
    verify_file(
        Path(sys.executable).resolve(strict=True),
        tool["executable"],
        label=f"{gate} live Python executable",
    )
    original = getattr(sys, "orig_argv", None)
    if not isinstance(original, list) or not original:
        raise ReleaseError(f"{gate} cannot recover the original interpreter argv")
    observed_argv = [generator["tool"], *original[1:]]
    if observed_argv != generator["argv"]:
        raise ReleaseError(
            f"{gate} live argv differs from the identity-bound generator"
        )
    if sys.flags.no_site != 1 or "-S" not in original[1:]:
        raise ReleaseError(f"{gate} must run with Python -S (site disabled)")
    for name in ("PYTHONHOME", "PYTHONPATH", "PYTHONSTARTUP", "PYTHONINSPECT"):
        if os.environ.get(name):
            raise ReleaseError(f"{gate} rejects ambient {name}")
    for name, expected in generator["environment"].items():
        if os.environ.get(name) != expected:
            raise ReleaseError(f"{gate} live environment differs for {name}")

    workspace = Path.cwd().resolve(strict=True)
    repository = workspace / "source-tree"
    if not repository.is_dir() or repository.is_symlink():
        raise ReleaseError(f"{gate} release workspace lacks a real source-tree")
    if _git_text(repository, "rev-parse", "HEAD") != identity["source_commit"]:
        raise ReleaseError(f"{gate} source checkout commit differs")
    if _git_text(repository, "rev-parse", "HEAD^{tree}") != identity["source_tree"]:
        raise ReleaseError(f"{gate} source checkout tree differs")
    if (
        _git_text(repository, "remote", "get-url", "origin")
        != identity["source_origin"]
    ):
        raise ReleaseError(f"{gate} source checkout origin differs")
    if (
        _git_text(repository, "rev-parse", f"{identity['source_ref']}^{{commit}}")
        != identity["source_commit"]
    ):
        raise ReleaseError(f"{gate} release tag differs from source_commit")
    if _git_text(repository, "status", "--porcelain=v1", "--untracked-files=no"):
        raise ReleaseError(f"{gate} source checkout has tracked modifications")

    script = (workspace / generator["script"]["path"]).resolve(strict=True)
    verify_file(script, generator["script"]["file"], label=f"{gate} generator script")
    live_script = Path(caller_file).resolve(strict=True)
    if not os.path.samefile(script, live_script):
        raise ReleaseError(f"{gate} executing script is not the identity-bound file")

    timeout = generator["timeout_seconds"]
    if not hasattr(signal, "SIGALRM"):
        raise ReleaseError(f"{gate} requires POSIX SIGALRM timeout enforcement")

    def timed_out(_signum: int, _frame: Any) -> None:
        raise ReleaseError(f"{gate} exceeded its locked {timeout}-second timeout")

    signal.signal(signal.SIGALRM, timed_out)
    previous = signal.alarm(timeout)
    if previous:
        signal.alarm(previous)
        raise ReleaseError(f"{gate} refuses to replace a pre-existing process alarm")
    return GateExecution(
        gate=gate,
        started_monotonic=time.monotonic(),
        timeout_seconds=timeout,
        original_alarm_seconds=previous,
    )


def locked_gate_invocation(
    identity: dict[str, Any],
    gate: str,
    *,
    stdout: bytes,
    execution: GateExecution,
) -> dict[str, Any]:
    """Finish a verified live gate run and materialize its exact receipt."""

    generator = _gate_generator(identity, gate)
    if (
        execution.gate != gate
        or execution.timeout_seconds != generator["timeout_seconds"]
        or execution.original_alarm_seconds != 0
        or time.monotonic() < execution.started_monotonic
    ):
        raise ReleaseError(f"{gate} execution receipt is invalid")
    signal.alarm(0)
    tools = {
        record["name"]: record
        for record in identity["verification"]["reproducibility"]["tools"]
    }
    tool = tools.get(generator["tool"])
    if tool is None:
        raise ReleaseError(f"gate generator tool is not bound: {gate}")
    return {
        "argv": generator["argv"],
        "cwd": generator["cwd"],
        "environment": generator["environment"],
        "exit_status": 0,
        "script": generator["script"],
        "source_commit": generator["source_commit"],
        "source_tree": generator["source_tree"],
        "timeout_seconds": generator["timeout_seconds"],
        "tool": tool,
        "stdout": stream_evidence_record(stdout),
        "stderr": stream_evidence_record(b""),
    }
