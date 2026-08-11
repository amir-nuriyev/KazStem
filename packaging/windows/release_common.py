#!/usr/bin/env python3
"""Fail-closed primitives shared by the Windows release tooling.

The release scripts deliberately avoid ``extractall`` and location-dependent
metadata.  A single checked release identity binds every input and output; an
observation run may report a differing candidate, but it quarantines it rather
than silently blessing new bytes.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
import shutil
import stat
import struct
import subprocess
import sys
import time
from typing import Any, BinaryIO, Iterable
import unicodedata
from urllib.parse import unquote, urlsplit
import zipfile
import zlib


if not __debug__:
    raise RuntimeError("Windows release gates must not run with Python -O")


IDENTITY_SCHEMA = "kazstem-windows-release-identity-v1"
READY_AUDIT_SCHEMA = "kazstem-windows-ready-run-archive-audit-v1"
SOURCE_AUDIT_SCHEMA = "kazstem-windows-corresponding-source-audit-v1"
HEX_256 = re.compile(r"[0-9a-f]{64}\Z")
COMMIT = re.compile(r"[0-9a-f]{40}\Z")
GIT_OBJECT = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
VERSION = re.compile(r"[0-9]+(?:\.[0-9]+){2}(?:[a-z0-9.-]*[a-z0-9])?\Z")
SAFE_LABEL = re.compile(r"[a-z0-9][a-z0-9._-]{0,126}\Z")
FORBIDDEN_LOADER_ENVIRONMENT = (
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
FORBIDDEN_LOADER_PREFIXES = ("LD_", "DYLD_")
GLIBC_TUNABLES_VARIABLE = "GLIBC_TUNABLES"
GIT_READ_ONLY_CONFIG_ARGUMENTS = (
    "-c",
    "core.fsmonitor=false",
    "-c",
    "core.untrackedCache=false",
)


def forbidden_loader_environment_name(name: str) -> bool:
    return name.startswith(FORBIDDEN_LOADER_PREFIXES) or name == GLIBC_TUNABLES_VARIABLE
WINDOWS_RUNTIME_COMMANDS = (
    "usr/bin/cg-proc.exe",
    "usr/bin/hfst-optimized-lookup.exe",
    "usr/bin/hfst-proc.exe",
)
WINDOWS_RUNTIME_DLLS = (
    "usr/bin/icudt74.dll",
    "usr/bin/icuin74.dll",
    "usr/bin/icuio74.dll",
    "usr/bin/icuuc74.dll",
    "usr/bin/libcg3.dll",
    "usr/bin/libdl.dll",
    "usr/bin/libfoma.dll",
    "usr/bin/libfst-27.dll",
    "usr/bin/libgcc_s_seh-1.dll",
    "usr/bin/libhfst-57.dll",
    "usr/bin/libreadline8.dll",
    "usr/bin/libsqlite3-0.dll",
    "usr/bin/libstdc++-6.dll",
    "usr/bin/libtermcap.dll",
    "usr/bin/libwinpthread-1.dll",
    "usr/bin/zlib1.dll",
)
WINDOWS_BEHAVIOR_EQUIVALENCE_CASES = (
    "version",
    "help",
    "alias-mystem-kz.exe",
    "alias-qazmorph.exe",
    "format-text",
    "format-json",
    "format-jsonl",
    "format-xml",
    "format-conllu",
    "productive-oov",
    "constraint-grammar",
    "generation",
    "generation-roundtrip",
    "unicode-crlf-reserved-nul",
    "xml-nul-controlled",
    "malformed-utf8",
    "cp1251",
    "invalid-encoding-base64_codec",
    "invalid-encoding-not-a-real-codec",
    "hostile-offline-file-paths",
    "parity-frozen",
    "parity-python-module",
    "parity-python-api",
)
MAX_HARD_MEMBERS = 1_000_000
MAX_HARD_FILE_BYTES = 16 * 1024**3
MAX_HARD_TOTAL_BYTES = 64 * 1024**3
MAX_HARD_PATH_BYTES = 4096
WINDOWS_DEVICES = {
    "con",
    "prn",
    "aux",
    "nul",
    *(f"com{number}" for number in range(1, 10)),
    *(f"lpt{number}" for number in range(1, 10)),
}
REQUIRED_EVIDENCE_GATES = {
    "archive-reproducibility": "kazstem-windows-archive-reproducibility-v1",
    "authenticode": "kazstem-windows-authenticode-inventory-v1",
    "binary-archive-audit": READY_AUDIT_SCHEMA,
    "compatibility-performance": "kazstem-windows-compatibility-performance-v1",
    "dll-denial": "kazstem-windows-dll-denial-gate-v1",
    "fresh-extract-practical": "kazstem-windows-practical-matrix-v1",
    "host-identity": "kazstem-windows-final-host-v1",
    "optimization": "kazstem-windows-optimization-selection-v1",
    "process-cleanup": "kazstem-windows-process-cleanup-gate-v1",
    "python-artifact-reproducibility": "kazstem-windows-python-artifact-reproducibility-v1",
    "runtime-provenance": "kazstem-windows-runtime-provenance-gate-v1",
    "source-archive-audit": SOURCE_AUDIT_SCHEMA,
    "source-suite": "kazstem-windows-source-suite-v1",
}
EVIDENCE_FIELDS = {
    "schema",
    "result",
    "release_identity_sha256",
    "subject",
    "execution",
    "coverage",
    "observations",
}
GENERATOR_SCRIPTS = {
    "archive-reproducibility": "packaging/windows/verify_archive_reproducibility.py",
    "authenticode": "packaging/windows/authenticode_inventory.py",
    "binary-archive-audit": "packaging/windows/audit_ready_run_archive.py",
    "compatibility-performance": "packaging/windows/write_derived_evidence.py",
    "dll-denial": "packaging/windows/write_derived_evidence.py",
    "fresh-extract-practical": "packaging/windows/practical_matrix_windows.py",
    "host-identity": "packaging/windows/write_final_host_evidence.py",
    "optimization": "packaging/windows/select_optimization_candidate.py",
    "process-cleanup": "packaging/windows/write_derived_evidence.py",
    "python-artifact-reproducibility": "packaging/windows/verify_python_reproducibility.py",
    "runtime-provenance": "packaging/windows/write_derived_evidence.py",
    "source-archive-audit": "packaging/windows/audit_corresponding_source_archive.py",
    "source-suite": "packaging/windows/run_source_suite.py",
}
RELEASE_SUPPORT_PATHS = (
    "packaging/windows/assemble_corresponding_source.py",
    "packaging/windows/assemble_ready_run.py",
    "packaging/windows/audit_corresponding_source_archive.py",
    "packaging/windows/audit_evidence_paths.py",
    "packaging/windows/audit_ready_run_archive.py",
    "packaging/windows/bounded_windows_process.py",
    "packaging/windows/release_bootstrap.py",
    "packaging/windows/release_common.py",
    "packaging/windows/source_suite_runner.py",
    "scripts/write_platform_runtime_manifest.py",
)
MINIMUM_GATE_CHECKS = {
    "archive-reproducibility": {"distinct-roots", "ready-byte-identity", "source-byte-identity"},
    "authenticode": {"all-pe-files", "embedded-certificate-table", "native-signature-status", "smartscreen-disclosure"},
    "binary-archive-audit": {"archive-byte-closure", "manifest-checksums", "pe-import-closure", "source-binding"},
    "compatibility-performance": {"deterministic-large-output", "five-formats", "peak-working-set", "startup-profile"},
    "dll-denial": {
        "adjacent-closure-success", "cwd-dll-denial", "cwd-helper-denial",
        "missing-dll", "path-dll-denial", "path-helper-denial", "renamed-helper",
    },
    "fresh-extract-practical": {
        "api-parity", "clean-loader-environment", "encodings", "generation",
        "hostile-paths", "oov-cg", "read-only-offline",
    },
    "host-identity": {"exact-os-build", "python-architecture", "runner-image"},
    "optimization": {"behavior-equivalence", "final-zip-bytes", "selected-full-rerun", "two-builds-per-candidate"},
    "process-cleanup": {"live-tree-observed", "no-descendants", "timeout-reap"},
    "python-artifact-reproducibility": {
        "fresh-build-roots", "frozen-tree-identity", "sdist-byte-or-semantic-parity",
        "sdist-roundtrip", "wheel-byte-or-semantic-parity",
    },
    "runtime-provenance": {
        "clean-loader-environment", "complete-inventory", "forced-rehash",
        "official-status", "platform-lock",
    },
    "source-archive-audit": {"git-source-receipt", "magic-nested-inventory", "source-closure", "source-manifest"},
    "source-suite": {
        "current-child-import-proof", "exact-test-id-ledger", "full-unittest-suite",
        "offline-canonical-wheel-install", "optimized-python-forbidden",
        "source-commit-tree",
    },
}


def canonical_generator_entrypoint_argv(
    identity: dict[str, Any], gate: str
) -> list[str] | None:
    script = GENERATOR_SCRIPTS[gate]
    common = ["<PYTHON>", script]
    static: dict[str, list[str]] = {
        "archive-reproducibility": [
            *common, "--identity", "<RELEASE-IDENTITY>",
            "--assembly-root-a", "<ASSEMBLY-ROOT-A>",
            "--assembly-root-b", "<ASSEMBLY-ROOT-B>",
            "--ready-a", "<READY-A>", "--ready-b", "<READY-B>",
            "--source-a", "<SOURCE-A>", "--source-b", "<SOURCE-B>",
            "--json", "<EVIDENCE-OUTPUT>",
        ],
        "authenticode": [
            *common, "--identity", "<RELEASE-IDENTITY>", "--archive",
            "<READY-RUN>", "--json", "<EVIDENCE-OUTPUT>",
        ],
        "binary-archive-audit": [
            *common, "--identity", "<RELEASE-IDENTITY>",
            "--release-identity-sha256", "<IDENTITY-SHA256>",
            "--archive", "<READY-RUN>", "--json", "<EVIDENCE-OUTPUT>",
        ],
        "fresh-extract-practical": [
            *common, "--identity", "<RELEASE-IDENTITY>", "--archive",
            "<READY-RUN>", "--wheel", "<WHEEL>", "--python", "<PYTHON>",
            "--json", "<EVIDENCE-OUTPUT>",
        ],
        "python-artifact-reproducibility": [
            *common, "--identity", "<RELEASE-IDENTITY>",
            "--bootstrap-python", "<BOOTSTRAP-PYTHON>",
            "--wheelhouse", "<WHEELHOUSE>",
            "--optimization-config", "<OPTIMIZATION-CONFIG>",
            "--python-build-identity", "<CANONICAL-PYTHON-BUILD-IDENTITY>",
            "--build-root-a", "<BUILD-ROOT-A>", "--receipt-a", "<BUILD-RECEIPT-A>",
            "--roundtrip-root-a", "<ROUNDTRIP-ROOT-A>",
            "--frozen-a", "<FROZEN-A>", "--wheel-a", "<WHEEL-A>",
            "--sdist-a", "<SDIST-A>", "--ledger-a", "<LEDGER-A>",
            "--build-root-b", "<BUILD-ROOT-B>", "--receipt-b", "<BUILD-RECEIPT-B>",
            "--roundtrip-root-b", "<ROUNDTRIP-ROOT-B>",
            "--frozen-b", "<FROZEN-B>", "--wheel-b", "<WHEEL-B>",
            "--sdist-b", "<SDIST-B>", "--ledger-b", "<LEDGER-B>",
            "--json", "<EVIDENCE-OUTPUT>",
        ],
        "source-archive-audit": [
            *common, "--identity", "<RELEASE-IDENTITY>",
            "--release-identity-sha256", "<IDENTITY-SHA256>",
            "--archive", "<CORRESPONDING-SOURCE>", "--json", "<EVIDENCE-OUTPUT>",
        ],
        "source-suite": [
            *common, "--identity", "<RELEASE-IDENTITY>",
            "--source-root-a", "<SOURCE-ROOT-A>",
            "--source-payload-a", "<SOURCE-PAYLOAD-A>",
            "--source-receipt-a", "<SOURCE-RECEIPT-A>",
            "--source-execution-receipt-a", "<SOURCE-EXECUTION-RECEIPT-A>",
            "--source-root-b", "<SOURCE-ROOT-B>",
            "--source-payload-b", "<SOURCE-PAYLOAD-B>",
            "--source-receipt-b", "<SOURCE-RECEIPT-B>",
            "--source-execution-receipt-b", "<SOURCE-EXECUTION-RECEIPT-B>",
            "--wheel", "<WHEEL>",
            "--install-root", "<SOURCE-SUITE-INSTALL-ROOT>",
            "--json", "<EVIDENCE-OUTPUT>",
        ],
    }
    if gate in static:
        return static[gate]
    if gate in {"compatibility-performance", "dll-denial", "process-cleanup", "runtime-provenance"}:
        return [
            *common, "--gate", gate, "--identity", "<RELEASE-IDENTITY>",
            "--matrix", "<PRACTICAL-EVIDENCE>", "--json", "<EVIDENCE-OUTPUT>",
        ]
    if gate == "optimization":
        result = [*common, "--identity", "<RELEASE-IDENTITY>"]
        for option, marker in (
            ("--candidate", "TREE"),
            ("--candidate-identity", "IDENTITY"),
            ("--assembly-root-a", "ASSEMBLY-A"),
            ("--assembly-root-b", "ASSEMBLY-B"),
            ("--archive-a", "ZIP-A"),
            ("--archive-b", "ZIP-B"),
            ("--receipt-a", "RECEIPT-A"),
            ("--receipt-b", "RECEIPT-B"),
            ("--behavior", "BEHAVIOR"),
            ("--config", "CONFIG"),
        ):
            for candidate in identity["optimization"]["candidates"]:
                name = candidate["name"]
                result.extend([option, f"{name}=<CANDIDATE-{marker}-{name}>"])
        result.extend(
            [
                "--selected-full-regression",
                "<SELECTED-FULL-REGRESSION>",
                "--json",
                "<EVIDENCE-OUTPUT>",
            ]
        )
        return result
    if gate == "host-identity":
        return None
    raise ReleaseError(f"no canonical evidence argv for gate {gate!r}")


def release_bootstrap_prefix_for_tree(
    tree: dict[str, Any], entrypoint: str
) -> list[str]:
    return [
        "<PYTHON>",
        "-I",
        "-B",
        "-X",
        "pycache_prefix=<FRESH-PYCACHE-ROOT>",
        "<MATERIALIZED-SOURCE>/packaging/windows/release_bootstrap.py",
        "--source-root",
        "<MATERIALIZED-SOURCE>",
        "--release-identity",
        "<RELEASE-IDENTITY>",
        "--materialization-root",
        "<SOURCE-MATERIALIZATION-ROOT>",
        "--materialization-receipt",
        "<SOURCE-MATERIALIZATION-RECEIPT>",
        "--materialization-execution-receipt",
        "<SOURCE-MATERIALIZATION-EXECUTION-RECEIPT>",
        "--cache-root",
        "<FRESH-PYCACHE-ROOT>",
        "--expected-tree-entries",
        str(tree["entries"]),
        "--expected-tree-bytes",
        str(tree["regular_file_bytes"]),
        "--expected-tree-sha256",
        tree["sha256"],
        "--entrypoint",
        entrypoint,
        "--",
    ]


def release_bootstrap_prefix(
    identity: dict[str, Any], entrypoint: str
) -> list[str]:
    return release_bootstrap_prefix_for_tree(
        identity["inputs"]["source_payload_tree"], entrypoint
    )


def wrap_release_tool_argv(
    identity: dict[str, Any], entrypoint_argv: list[str]
) -> list[str]:
    if (
        len(entrypoint_argv) < 2
        or entrypoint_argv[0] != "<PYTHON>"
        or entrypoint_argv[1] not in GENERATOR_SCRIPTS.values()
    ):
        raise ReleaseError("release entrypoint argv has a noncanonical prefix")
    return [
        *release_bootstrap_prefix(identity, entrypoint_argv[1]),
        *entrypoint_argv[2:],
    ]


def canonical_generator_argv(identity: dict[str, Any], gate: str) -> list[str] | None:
    entrypoint = canonical_generator_entrypoint_argv(identity, gate)
    return None if entrypoint is None else wrap_release_tool_argv(identity, entrypoint)


def source_boundary_contract(
    identity: dict[str, Any], entrypoint: str
) -> dict[str, Any]:
    support = {
        record["path"]: record
        for record in identity["inputs"]["release_support_files"]
    }
    bootstrap_path = "packaging/windows/release_bootstrap.py"
    if bootstrap_path not in support:
        raise ReleaseError("release support bundle has no source bootstrap")
    return {
        "schema": "kazstem-release-source-bootstrap-v1",
        "bootstrap": support[bootstrap_path],
        "source_root": "<MATERIALIZED-SOURCE>",
        "source_tree": identity["inputs"]["source_payload_tree"],
        "release_identity": "<RELEASE-IDENTITY>",
        "release_identity_verified": True,
        "materialization_root": "<SOURCE-MATERIALIZATION-ROOT>",
        "materialization_receipt": {
            "path": "<SOURCE-MATERIALIZATION-RECEIPT>",
            "file": identity["inputs"]["source_receipt"],
        },
        "materialization_execution_receipt":
        "<SOURCE-MATERIALIZATION-EXECUTION-RECEIPT>",
        "materialization_source": {
            "commit": identity["source_commit"],
            "tree": identity["source_tree"],
            "origin": identity["source_origin"],
            "ref": identity["source_ref"],
        },
        "fresh_materialization_objects_verified": True,
        "entrypoint": entrypoint,
        "cache_root": "<FRESH-PYCACHE-ROOT>",
        "cache_absent_before_execution": True,
        "cache_outside_source": True,
        "interpreter_flags": [
            "-I",
            "-B",
            "-X",
            "pycache_prefix=<FRESH-PYCACHE-ROOT>",
        ],
        "adjacent_bytecode_rejected_before_local_imports": True,
        "complete_source_inventory_verified_before_local_imports": True,
    }


def validate_generator_argv(identity: dict[str, Any], gate: str, argv: Any) -> list[str]:
    if not isinstance(argv, list) or any(not isinstance(value, str) or not value for value in argv):
        raise ReleaseError(f"evidence generator argv is invalid: {gate}")
    expected = canonical_generator_argv(identity, gate)
    if expected is not None:
        if argv != expected:
            raise ReleaseError(f"evidence generator argv differs from the exact {gate} contract")
        return argv
    script = GENERATOR_SCRIPTS[gate]
    if gate == "host-identity":
        prefix = release_bootstrap_prefix(identity, script)
        if argv[: len(prefix)] != prefix:
            raise ReleaseError("host generator bootstrap argv differs")
        entrypoint_argv = ["<PYTHON>", script, *argv[len(prefix) :]]
        if len(entrypoint_argv) != 16 or entrypoint_argv[:4] != ["<PYTHON>", script, "--identity", "<RELEASE-IDENTITY>"]:
            raise ReleaseError("host generator argv has a noncanonical prefix")
        values = entrypoint_argv[5::2]
        expected_options = [
            "--runner-os", "--runner-arch", "--image-os", "--image-version",
            "--run-id", "--json",
        ]
        if entrypoint_argv[4::2] != expected_options or len(values) != 6:
            raise ReleaseError("host generator argv option order differs")
        runner_os, runner_arch, image_os, image_version, run_id, output = values
        if (
            runner_os != "Windows"
            or runner_arch != "X64"
            or not image_os
            or not image_version
            or not run_id.isdecimal()
            or output != "<EVIDENCE-OUTPUT>"
        ):
            raise ReleaseError("host generator argv values differ from the Windows runner contract")
        return argv
    raise ReleaseError(f"cannot validate generator argv for gate {gate!r}")


class ReleaseError(RuntimeError):
    """A release input or gate violated the public release contract."""


@dataclass(frozen=True)
class ArchiveLimits:
    max_members: int
    max_file_bytes: int
    max_total_bytes: int
    max_path_bytes: int


@dataclass(frozen=True)
class ZipMember:
    name: str
    kind: str
    size: int
    mode: int
    crc32: int
    sha256: str | None


@dataclass(frozen=True)
class ZipOutputContract:
    epoch: int
    executable_suffixes: tuple[str, ...] = ()

    def mode_for(self, name: str, kind: str) -> int:
        if kind == "directory":
            return 0o555
        return 0o555 if name.casefold().endswith(self.executable_suffixes) else 0o444


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
        if not path.is_file() or path.is_symlink():
            raise ReleaseError(f"JSON input is not a regular file: {path}")
        if path.stat().st_size > 64 * 1024**2:
            raise ReleaseError(f"JSON input exceeds 64 MiB: {path}")
        return decode_json(path.read_bytes(), label=str(path))
    except OSError as exc:
        raise ReleaseError(f"cannot read JSON {path}: {exc}") from exc


def json_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")


def canonical_hash(value: Any) -> str:
    payload = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def sha256_stream(source: BinaryIO, *, limit: int) -> tuple[int, str]:
    digest = hashlib.sha256()
    size = 0
    while True:
        block = source.read(min(1024 * 1024, limit - size + 1))
        if not block:
            break
        size += len(block)
        if size > limit:
            raise ReleaseError(f"stream exceeds safety cap of {limit} bytes")
        digest.update(block)
    return size, digest.hexdigest()


def file_record(path: Path) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink():
        raise ReleaseError(f"not a regular file: {path}")
    metadata = path.stat()
    if metadata.st_nlink != 1:
        raise ReleaseError(f"hard-linked release input is forbidden: {path}")
    return {"bytes": metadata.st_size, "sha256": sha256_file(path)}


def artifact_record(path: Path, url: str) -> dict[str, Any]:
    return {"filename": path.name, **file_record(path), "url": url}


def files_equal(first: Path, second: Path) -> bool:
    """Compare regular files exactly and detect concurrent replacement."""

    def metadata(path: Path) -> tuple[int, int, int, int, int]:
        if not path.is_file() or path.is_symlink():
            raise ReleaseError(f"not a regular file: {path}")
        value = path.stat()
        if value.st_nlink != 1:
            raise ReleaseError(f"hard-linked release input is forbidden: {path}")
        return (
            value.st_dev,
            value.st_ino,
            value.st_size,
            value.st_mtime_ns,
            value.st_ctime_ns,
        )

    before_first = metadata(first)
    before_second = metadata(second)
    if before_first[2] != before_second[2]:
        return False
    with first.open("rb") as left, second.open("rb") as right:
        while True:
            left_block = left.read(1024 * 1024)
            right_block = right.read(1024 * 1024)
            if left_block != right_block:
                return False
            if not left_block:
                break
    return metadata(first) == before_first and metadata(second) == before_second


def _exact(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        observed = set(value) if isinstance(value, dict) else set()
        raise ReleaseError(
            f"{label} fields differ: missing={sorted(fields - observed)}, "
            f"extra={sorted(observed - fields)}"
        )
    return value


def _positive(value: Any, label: str, *, ceiling: int | None = None) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ReleaseError(f"{label} must be a positive integer")
    if ceiling is not None and value > ceiling:
        raise ReleaseError(f"{label} exceeds hard ceiling {ceiling}")
    return value


def _sha(value: Any, label: str) -> str:
    if not isinstance(value, str) or HEX_256.fullmatch(value) is None:
        raise ReleaseError(f"{label} must be a lowercase SHA-256")
    return value


def _pe_record(value: Any, label: str, *, expected_name: str | None = None) -> dict[str, Any]:
    record = _exact(
        value,
        {
            "path",
            "machine",
            "format",
            "sections",
            "coff_timestamp",
            "optional_header_bytes",
            "characteristics",
            "authenticode_embedded",
            "authenticode_file_offset",
            "authenticode_bytes",
            "bytes",
            "sha256",
        },
        label,
    )
    portable_path(record["path"], label=f"{label}.path", single=True)
    if expected_name is not None and record["path"].casefold() != expected_name.casefold():
        raise ReleaseError(f"{label}.path differs from {expected_name!r}")
    if record["machine"] != "AMD64" or record["format"] != "PE32+":
        raise ReleaseError(f"{label} is not AMD64 PE32+")
    for field in (
        "sections",
        "coff_timestamp",
        "optional_header_bytes",
        "characteristics",
        "authenticode_file_offset",
        "authenticode_bytes",
    ):
        item = record[field]
        if isinstance(item, bool) or not isinstance(item, int) or item < 0:
            raise ReleaseError(f"{label}.{field} must be a non-negative integer")
    if record["sections"] <= 0 or record["optional_header_bytes"] < 152:
        raise ReleaseError(f"{label} PE structure is incomplete")
    if not isinstance(record["authenticode_embedded"], bool):
        raise ReleaseError(f"{label}.authenticode_embedded must be boolean")
    embedded = bool(record["authenticode_file_offset"] and record["authenticode_bytes"])
    if record["authenticode_embedded"] != embedded:
        raise ReleaseError(f"{label} Authenticode fields disagree")
    _file({"bytes": record["bytes"], "sha256": record["sha256"]}, label)
    return record


def portable_path(value: Any, *, label: str, single: bool = False) -> str:
    """Validate one NFC, case-portable, ADS-safe Windows archive path."""

    if not isinstance(value, str) or not value or "\x00" in value or "\\" in value:
        raise ReleaseError(f"{label} is not a portable relative path")
    if unicodedata.normalize("NFC", value) != value:
        raise ReleaseError(f"{label} must already be NFC-normalized")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ReleaseError(f"{label} contains a control character")
    posix = PurePosixPath(value)
    windows = PureWindowsPath(value)
    parts = posix.parts
    invalid = (
        posix.is_absolute()
        or windows.is_absolute()
        or bool(windows.drive)
        or value != posix.as_posix()
        or any(part in {"", ".", ".."} for part in parts)
        or any(":" in part for part in parts)  # NTFS alternate data streams
        or any(part != part.rstrip(" .") for part in parts)
        or any(part.split(".", 1)[0].casefold() in WINDOWS_DEVICES for part in parts)
        or (single and len(parts) != 1)
    )
    if invalid:
        raise ReleaseError(f"{label} is not a portable relative path: {value!r}")
    if len(value.encode("utf-8")) > MAX_HARD_PATH_BYTES:
        raise ReleaseError(f"{label} exceeds the hard path cap")
    return value


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
        raise ReleaseError(f"{label} must be an uncredentialed HTTPS URL")
    if filename is not None and unquote(parsed.path.rsplit("/", 1)[-1]) != filename:
        raise ReleaseError(f"{label} does not end in {filename!r}")
    return value


def _file(value: Any, label: str) -> dict[str, Any]:
    item = _exact(value, {"bytes", "sha256"}, label)
    _positive(item["bytes"], f"{label}.bytes", ceiling=MAX_HARD_FILE_BYTES)
    _sha(item["sha256"], f"{label}.sha256")
    return item


def _artifact(value: Any, label: str) -> dict[str, Any]:
    item = _exact(value, {"filename", "bytes", "sha256", "url"}, label)
    portable_path(item["filename"], label=f"{label}.filename", single=True)
    _positive(item["bytes"], f"{label}.bytes", ceiling=MAX_HARD_FILE_BYTES)
    _sha(item["sha256"], f"{label}.sha256")
    _url(item["url"], f"{label}.url", filename=item["filename"])
    return item


def _tree(value: Any, label: str) -> dict[str, Any]:
    item = _exact(value, {"entries", "regular_file_bytes", "sha256"}, label)
    _positive(item["entries"], f"{label}.entries", ceiling=MAX_HARD_MEMBERS)
    _positive(
        item["regular_file_bytes"],
        f"{label}.regular_file_bytes",
        ceiling=MAX_HARD_TOTAL_BYTES,
    )
    _sha(item["sha256"], f"{label}.sha256")
    return item


def _limits(value: Any, label: str) -> ArchiveLimits:
    item = _exact(
        value,
        {"max_members", "max_file_bytes", "max_total_bytes", "max_path_bytes"},
        label,
    )
    limits = ArchiveLimits(
        _positive(item["max_members"], f"{label}.max_members", ceiling=MAX_HARD_MEMBERS),
        _positive(item["max_file_bytes"], f"{label}.max_file_bytes", ceiling=MAX_HARD_FILE_BYTES),
        _positive(item["max_total_bytes"], f"{label}.max_total_bytes", ceiling=MAX_HARD_TOTAL_BYTES),
        _positive(item["max_path_bytes"], f"{label}.max_path_bytes", ceiling=MAX_HARD_PATH_BYTES),
    )
    if limits.max_file_bytes > limits.max_total_bytes:
        raise ReleaseError(f"{label}.max_file_bytes exceeds max_total_bytes")
    return limits


def _unique_paths(values: Any, label: str) -> list[str]:
    if not isinstance(values, list) or not values:
        raise ReleaseError(f"{label} must be a non-empty list")
    paths = [portable_path(item, label=f"{label}[{index}]") for index, item in enumerate(values)]
    folded = [item.casefold() for item in paths]
    if paths != sorted(paths) or len(paths) != len(set(paths)) or len(folded) != len(set(folded)):
        raise ReleaseError(f"{label} must be sorted and collision-free")
    return paths


def load_identity(path: Path) -> dict[str, Any]:
    identity = _exact(
        read_json(path),
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
            "optimization",
            "performance",
            "archive_limits",
            "verification",
        },
        "release identity",
    )
    if identity["schema"] != IDENTITY_SCHEMA:
        raise ReleaseError(f"unsupported identity schema: {identity['schema']!r}")
    if not isinstance(identity["release"], str) or VERSION.fullmatch(identity["release"]) is None:
        raise ReleaseError("release must be a canonical semantic version")
    if not isinstance(identity["source_commit"], str) or COMMIT.fullmatch(identity["source_commit"]) is None:
        raise ReleaseError("source_commit must be a full lowercase Git id")
    if not isinstance(identity["source_tree"], str) or GIT_OBJECT.fullmatch(identity["source_tree"]) is None:
        raise ReleaseError("source_tree must be the full lowercase Git tree id")
    if identity["source_origin"] != "https://github.com/amir-nuriyev/KazStem.git":
        raise ReleaseError("source_origin must be the exact public KazStem Git origin")
    if identity["source_ref"] != f"refs/tags/v{identity['release']}":
        raise ReleaseError("source_ref must be the exact immutable release tag")
    _positive(identity["source_date_epoch"], "source_date_epoch")
    release_url = _url(identity["release_url"], "release_url")
    expected_release_url = (
        f"https://github.com/amir-nuriyev/KazStem/releases/tag/v{identity['release']}"
    )
    if release_url != expected_release_url:
        raise ReleaseError("release_url must name the exact KazStem version tag")

    platform = _exact(
        identity["platform"],
        {
            "system",
            "machine",
            "label",
            "runner",
            "minimum_os_build",
            "python",
            "pyinstaller",
            "archive_writer",
            "unsigned",
        },
        "platform",
    )
    if (
        platform["system"] != "windows"
        or platform["machine"] != "x86_64"
        or platform["label"] != "windows-server-2022-x86_64"
        or platform["runner"] != "windows-2022"
        or platform["minimum_os_build"] != "10.0.20348"
        or platform["python"] != "3.14.3"
        or platform["pyinstaller"] != "6.22.0"
        or platform["unsigned"] is not True
    ):
        raise ReleaseError("platform does not match the audited Windows contract")
    writer = _exact(platform["archive_writer"], {"implementation", "compression"}, "platform.archive_writer")
    if writer != {"implementation": "cpython-zipfile-3.14.3", "compression": "deflate-9"}:
        raise ReleaseError("archive writer contract changed")

    artifacts = _exact(identity["artifacts"], {"wheel", "sdist", "ready_run", "corresponding_source"}, "artifacts")
    for name, artifact in artifacts.items():
        _artifact(artifact, f"artifacts.{name}")
    prefix = f"kazstem-{identity['release']}-{platform['label']}"
    if artifacts["ready_run"]["filename"] != f"{prefix}-ready-run.zip":
        raise ReleaseError("ready-run filename differs from release identity")
    if artifacts["corresponding_source"]["filename"] != f"{prefix}-corresponding-source.zip":
        raise ReleaseError("corresponding-source filename differs from release identity")
    if artifacts["wheel"]["filename"] != f"kazstem-{identity['release']}-py3-none-any.whl":
        raise ReleaseError("wheel filename is not the canonical pure-Python wheel")
    if artifacts["sdist"]["filename"] != f"kazstem-{identity['release']}.tar.gz":
        raise ReleaseError("sdist filename is not canonical")
    download = f"https://github.com/amir-nuriyev/KazStem/releases/download/v{identity['release']}/"
    for name, artifact in artifacts.items():
        if artifact["url"] != download + artifact["filename"]:
            raise ReleaseError(f"artifacts.{name}.url is not the exact download URL")

    inputs = _exact(
        identity["inputs"],
        {
            "frozen_tree",
            "resource_tree",
            "runtime_tree",
            "source_payload_tree",
            "source_receipt",
            "bootstrap_python",
            "build_wheelhouse_tree",
            "canonical_python_build_identity",
            "optimization_config",
            "platform_lock",
            "base_ledger",
            "binary_readme_template",
            "source_readme_template",
            "release_support_files",
            "documents",
        },
        "inputs",
    )
    _tree(inputs["frozen_tree"], "inputs.frozen_tree")
    _tree(inputs["source_payload_tree"], "inputs.source_payload_tree")
    _file(inputs["source_receipt"], "inputs.source_receipt")
    _pe_record(
        inputs["bootstrap_python"],
        "inputs.bootstrap_python",
        expected_name="python.exe",
    )
    _tree(inputs["build_wheelhouse_tree"], "inputs.build_wheelhouse_tree")
    _file(
        inputs["canonical_python_build_identity"],
        "inputs.canonical_python_build_identity",
    )
    _file(inputs["optimization_config"], "inputs.optimization_config")
    support_files = inputs["release_support_files"]
    if not isinstance(support_files, list) or len(support_files) != len(
        RELEASE_SUPPORT_PATHS
    ):
        raise ReleaseError("release support-file inventory is incomplete")
    for index, (value, expected_path) in enumerate(
        zip(support_files, RELEASE_SUPPORT_PATHS)
    ):
        support = _exact(
            value,
            {"path", "file"},
            f"inputs.release_support_files[{index}]",
        )
        if support["path"] != expected_path:
            raise ReleaseError("release support-file paths differ")
        portable_path(support["path"], label="release support file")
        _file(support["file"], "release support file")
    for name in ("resource_tree", "runtime_tree"):
        bundle = _exact(inputs[name], {"bundle_id", "manifest", "tree"}, f"inputs.{name}")
        _sha(bundle["bundle_id"], f"inputs.{name}.bundle_id")
        _file(bundle["manifest"], f"inputs.{name}.manifest")
        _tree(bundle["tree"], f"inputs.{name}.tree")
    if inputs["resource_tree"]["bundle_id"] != (
        "f03e703d3e2a67044a7d91fd7d575b92cb4e61aa782fb67cff91b0a5ff0ebd5a"
    ):
        raise ReleaseError(
            "Windows final-release identity remains f03e-only until a real "
            "native bf1f acceptance gate is frozen"
        )
    if inputs["runtime_tree"]["bundle_id"] != "17a69ae11ff3fd92a555e8c95571223cbe8b217ec409a0b9b368f0aed90ee465":
        raise ReleaseError("identity is not bound to the audited Windows runtime")
    if inputs["runtime_tree"]["manifest"] != {
        "bytes": 20697,
        "sha256": "554a776a942e2db65ca34bb6e05e0c258976848203cbece38ababc0067d1ee46",
    }:
        raise ReleaseError("Windows runtime manifest identity changed")
    for name in ("platform_lock", "base_ledger", "binary_readme_template", "source_readme_template"):
        _file(inputs[name], f"inputs.{name}")
    documents = inputs["documents"]
    if not isinstance(documents, list) or not documents:
        raise ReleaseError("inputs.documents must be non-empty")
    destinations: list[str] = []
    for index, value in enumerate(documents):
        item = _exact(value, {"source", "destination", "file"}, f"inputs.documents[{index}]")
        portable_path(item["source"], label=f"inputs.documents[{index}].source")
        destinations.append(portable_path(item["destination"], label=f"inputs.documents[{index}].destination"))
        _file(item["file"], f"inputs.documents[{index}].file")
    if destinations != sorted(set(destinations)) or len({value.casefold() for value in destinations}) != len(destinations):
        raise ReleaseError("document destinations must be sorted and collision-free")

    ready = _exact(
        identity["ready_run"],
        {
            "top_level",
            "launcher",
            "aliases",
            "platform_lock_path",
            "resource_destination",
            "runtime_parent",
            "remove_frozen_files",
            "required_paths",
            "banned_name_fragments",
        },
        "ready_run",
    )
    if ready["top_level"] != artifacts["ready_run"]["filename"][:-4]:
        raise ReleaseError("ready_run.top_level differs from artifact filename")
    launcher = _exact(ready["launcher"], {"path", "file"}, "ready_run.launcher")
    if portable_path(launcher["path"], label="ready_run.launcher.path", single=True) != "kazstem.exe":
        raise ReleaseError("the public launcher must be kazstem.exe")
    _file(launcher["file"], "ready_run.launcher.file")
    aliases = _unique_paths(ready["aliases"], "ready_run.aliases")
    if aliases != ["mystem-kz.exe", "qazmorph.exe"]:
        raise ReleaseError("the two documented Windows aliases are required")
    portable_path(ready["platform_lock_path"], label="ready_run.platform_lock_path")
    portable_path(ready["resource_destination"], label="ready_run.resource_destination")
    portable_path(ready["runtime_parent"], label="ready_run.runtime_parent")
    removals = ready["remove_frozen_files"]
    if not isinstance(removals, list):
        raise ReleaseError("ready_run.remove_frozen_files must be a list")
    removal_paths: list[str] = []
    for index, value in enumerate(removals):
        item = _exact(value, {"path", "file"}, f"ready_run.remove_frozen_files[{index}]")
        removal_paths.append(portable_path(item["path"], label=f"ready_run.remove_frozen_files[{index}].path"))
        _file(item["file"], f"ready_run.remove_frozen_files[{index}].file")
    if removal_paths != sorted(set(removal_paths)):
        raise ReleaseError("ready-run removals must be sorted and unique")
    _unique_paths(ready["required_paths"], "ready_run.required_paths")
    banned = ready["banned_name_fragments"]
    if not isinstance(banned, list) or not banned or banned != sorted(set(banned)) or any(not isinstance(item, str) or not item or item != item.casefold() for item in banned):
        raise ReleaseError("ready-run banned fragments must be sorted casefolded strings")

    source = _exact(
        identity["corresponding_source"],
        {
            "top_level",
            "categories",
            "source_commit_file",
            "source_date_epoch_file",
            "components",
            "nested_archives",
            "wheelhouse_destination",
            "required_paths",
        },
        "corresponding_source",
    )
    if source["top_level"] != artifacts["corresponding_source"]["filename"][:-4]:
        raise ReleaseError("corresponding_source.top_level differs from artifact")
    categories = _exact(source["categories"], {"application", "build", "native", "evidence", "licenses"}, "corresponding_source.categories")
    for name, value in categories.items():
        portable_path(value, label=f"corresponding_source.categories.{name}")
    portable_path(source["source_commit_file"], label="corresponding_source.source_commit_file")
    portable_path(source["source_date_epoch_file"], label="corresponding_source.source_date_epoch_file")
    if portable_path(
        source["wheelhouse_destination"],
        label="corresponding_source.wheelhouse_destination",
    ) != "build/freezer-wheelhouse":
        raise ReleaseError("wheelhouse destination must be build/freezer-wheelhouse")
    components = source["components"]
    if not isinstance(components, list) or not components:
        raise ReleaseError("corresponding_source.components must be non-empty")
    component_destinations: list[str] = []
    for index, value in enumerate(components):
        item = _exact(value, {"name", "version", "license", "category", "source", "destination", "artifact"}, f"corresponding_source.components[{index}]")
        if not all(isinstance(item[key], str) and item[key] for key in ("name", "version", "license")):
            raise ReleaseError(f"corresponding source component {index} has empty metadata")
        if item["category"] not in categories:
            raise ReleaseError(f"corresponding source component {index} has unknown category")
        portable_path(item["source"], label=f"corresponding_source.components[{index}].source")
        component_destinations.append(portable_path(item["destination"], label=f"corresponding_source.components[{index}].destination"))
        _artifact(item["artifact"], f"corresponding_source.components[{index}].artifact")
        if Path(item["destination"]).name != item["artifact"]["filename"]:
            raise ReleaseError(f"corresponding source component {index} destination differs from artifact")
    if component_destinations != sorted(set(component_destinations)) or len({item.casefold() for item in component_destinations}) != len(component_destinations):
        raise ReleaseError("source component destinations must be sorted and collision-free")
    nested = source["nested_archives"]
    if not isinstance(nested, list) or not nested:
        raise ReleaseError("corresponding_source.nested_archives must be non-empty")
    nested_paths: list[str] = []
    for index, value in enumerate(nested):
        item = _exact(value, {"path", "kind"}, f"corresponding_source.nested_archives[{index}]")
        nested_paths.append(portable_path(item["path"], label=f"corresponding_source.nested_archives[{index}].path"))
        if item["kind"] not in {
            "zip",
            "tar-raw",
            "tar-gzip",
            "tar-xz",
            "tar-bzip2",
            "gzip",
            "xz",
            "bzip2",
        }:
            raise ReleaseError(f"unsupported nested archive kind: {item['kind']!r}")
    if nested_paths != sorted(set(nested_paths)):
        raise ReleaseError("nested archive paths must be sorted and unique")
    _unique_paths(source["required_paths"], "corresponding_source.required_paths")

    optimization = _exact(
        identity["optimization"],
        {"selected", "candidates", "selected_full_regression"},
        "optimization",
    )
    if not isinstance(optimization["selected"], str) or SAFE_LABEL.fullmatch(optimization["selected"]) is None:
        raise ReleaseError("optimization.selected is not a safe candidate label")
    candidates = optimization["candidates"]
    if not isinstance(candidates, list) or len(candidates) < 2:
        raise ReleaseError("optimization requires at least two candidates")
    candidate_names: list[str] = []
    selected_config: dict[str, Any] | None = None
    for index, candidate_value in enumerate(candidates):
        candidate = _exact(
            candidate_value,
            {"name", "config", "behavior"},
            f"optimization.candidates[{index}]",
        )
        name = candidate["name"]
        if not isinstance(name, str) or SAFE_LABEL.fullmatch(name) is None:
            raise ReleaseError(f"optimization candidate {index} has an unsafe name")
        candidate_names.append(name)
        _file(candidate["config"], f"optimization.candidates[{index}].config")
        _file(candidate["behavior"], f"optimization.candidates[{index}].behavior")
        if name == optimization["selected"]:
            selected_config = candidate["config"]
    if candidate_names != sorted(set(candidate_names)):
        raise ReleaseError("optimization candidates must be sorted and unique")
    if selected_config is None:
        raise ReleaseError("optimization.selected is not one of the candidates")
    if selected_config != inputs["optimization_config"]:
        raise ReleaseError("selected optimization config differs from inputs.optimization_config")
    _file(optimization["selected_full_regression"], "optimization.selected_full_regression")

    performance = _exact(
        identity["performance"],
        {
            "startup_runs",
            "startup_median_seconds_max",
            "large_input_characters",
            "large_runs",
            "large_timeout_seconds",
            "minimum_characters_per_second",
            "maximum_peak_working_set_bytes",
        },
        "performance",
    )
    integer_fields = {
        "startup_runs": (3, 100),
        "large_input_characters": (10_000, 10_000_000),
        "large_runs": (2, 10),
        "large_timeout_seconds": (30, 3600),
        "minimum_characters_per_second": (1, 10_000_000),
        "maximum_peak_working_set_bytes": (16 * 1024**2, 4 * 1024**3),
    }
    for field, (minimum, maximum) in integer_fields.items():
        value = performance[field]
        if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
            raise ReleaseError(f"performance.{field} is outside the audited range")
    startup_limit = performance["startup_median_seconds_max"]
    if isinstance(startup_limit, bool) or not isinstance(startup_limit, (int, float)) or not 0 < startup_limit <= 60:
        raise ReleaseError("performance.startup_median_seconds_max is invalid")

    archive_limits_value = _exact(identity["archive_limits"], {"ready_run", "corresponding_source", "nested"}, "archive_limits")
    for name in archive_limits_value:
        _limits(archive_limits_value[name], f"archive_limits.{name}")

    verification = _exact(identity["verification"], {"minimum_distinct_roots", "evidence"}, "verification")
    if verification["minimum_distinct_roots"] != 2:
        raise ReleaseError("exactly two or more distinct build roots are required")
    evidence = verification["evidence"]
    if not isinstance(evidence, list):
        raise ReleaseError("verification.evidence must be a list")
    subject_hash = release_subject_sha256(identity)
    observed: dict[str, str] = {}
    evidence_paths: list[str] = []
    for index, value in enumerate(evidence):
        item = _exact(
            value,
            {"gate", "schema", "subject_sha256", "path", "file", "generator"},
            f"verification.evidence[{index}]",
        )
        if item["gate"] in observed:
            raise ReleaseError(f"duplicate evidence gate: {item['gate']}")
        if item["schema"] != REQUIRED_EVIDENCE_GATES.get(item["gate"]):
            raise ReleaseError(f"wrong evidence schema for gate {item['gate']!r}")
        if item["subject_sha256"] != subject_hash:
            raise ReleaseError(f"wrong evidence subject for gate {item['gate']!r}")
        _file(item["file"], f"verification.evidence[{index}].file")
        generator = _exact(
            item["generator"],
            {
                "script",
                "argv",
                "cwd",
                "environment",
                "timeout_seconds",
                "tool",
                "source_boundary",
                "dependencies",
                "payload_schema",
                "required_coverage",
            },
            f"verification.evidence[{index}].generator",
        )
        script = _exact(
            generator["script"],
            {"path", "file"},
            f"verification.evidence[{index}].generator.script",
        )
        if script["path"] != GENERATOR_SCRIPTS[item["gate"]]:
            raise ReleaseError(f"wrong checked generator script for gate {item['gate']!r}")
        portable_path(script["path"], label="evidence generator script")
        _file(script["file"], "evidence generator script file")
        argv = validate_generator_argv(identity, item["gate"], generator["argv"])
        if generator["cwd"] != "<MATERIALIZED-SOURCE>":
            raise ReleaseError("evidence generator cwd must be the exact materialized source")
        if generator["environment"] != {
            "LC_ALL": "C",
            "PYTHONHASHSEED": "0",
            "TZ": "UTC",
        }:
            raise ReleaseError("evidence generator environment is not exact/minimal")
        if generator["timeout_seconds"] != 3600:
            raise ReleaseError("evidence generator timeout must be exactly 3600 seconds")
        tool = _exact(generator["tool"], {"name", "executable", "version", "file"}, "evidence generator tool")
        if (
            tool["name"] != "CPython"
            or tool["executable"] != "<PYTHON>"
            or tool["version"] != identity["platform"]["python"]
        ):
            raise ReleaseError("evidence generator tool is not the pinned CPython")
        _file(tool["file"], "evidence generator CPython executable")
        if tool["file"] != {
            "bytes": inputs["bootstrap_python"]["bytes"],
            "sha256": inputs["bootstrap_python"]["sha256"],
        }:
            raise ReleaseError("evidence generator is not the bound bootstrap CPython executable")
        boundary = generator["source_boundary"]
        if boundary != source_boundary_contract(identity, script["path"]):
            raise ReleaseError("evidence generator source execution boundary differs")
        if generator["dependencies"] != support_files:
            raise ReleaseError("evidence generator transitive dependencies differ")
        if generator["payload_schema"] != item["schema"] + "-observations-v1":
            raise ReleaseError("evidence observation payload schema is not canonical")
        coverage = _exact(
            generator["required_coverage"],
            {"assertions", "cases", "checks"},
            "evidence generator required coverage",
        )
        expected_checks = sorted(MINIMUM_GATE_CHECKS[item["gate"]])
        if coverage != {
            "assertions": len(expected_checks),
            "cases": 1,
            "checks": expected_checks,
        }:
            raise ReleaseError(f"evidence generator coverage is incomplete: {item['gate']}")
        observed[item["gate"]] = item["schema"]
        evidence_paths.append(portable_path(item["path"], label=f"verification.evidence[{index}].path"))
    if observed != REQUIRED_EVIDENCE_GATES:
        raise ReleaseError(f"verification gates differ: expected={REQUIRED_EVIDENCE_GATES}, observed={observed}")
    if evidence_paths != sorted(evidence_paths) or len({item.casefold() for item in evidence_paths}) != len(evidence_paths):
        raise ReleaseError("evidence paths must be sorted and collision-free")
    verify_release_support_files(
        identity,
        Path(__file__).resolve(strict=True).parents[2],
    )
    return identity


def archive_limits(identity: dict[str, Any], name: str) -> ArchiveLimits:
    return _limits(identity["archive_limits"][name], f"archive_limits.{name}")


def source_ready_location(identity: dict[str, Any]) -> dict[str, str]:
    """Return the one-way, hash-free ready-run reference embedded in source."""

    ready = identity["artifacts"]["ready_run"]
    return {"filename": ready["filename"], "url": ready["url"]}


def release_subject(identity: dict[str, Any]) -> dict[str, Any]:
    """Exact artifact/source subject every final evidence envelope proves."""

    return {
        "schema": "kazstem-windows-release-subject-v1",
        "release": identity["release"],
        "source": {
            "commit": identity["source_commit"],
            "tree": identity["source_tree"],
            "origin": identity["source_origin"],
            "ref": identity["source_ref"],
            "date_epoch": identity["source_date_epoch"],
            "materialized_tree": identity["inputs"]["source_payload_tree"],
            "materialization_receipt": identity["inputs"]["source_receipt"],
        },
        "platform": identity["platform"],
        "artifacts": identity["artifacts"],
        "resource_bundle": identity["inputs"]["resource_tree"],
        "runtime_bundle": identity["inputs"]["runtime_tree"],
        "platform_lock": identity["inputs"]["platform_lock"],
        "bootstrap_python": identity["inputs"]["bootstrap_python"],
        "build_wheelhouse_tree": identity["inputs"]["build_wheelhouse_tree"],
        "canonical_python_build_identity": identity["inputs"]["canonical_python_build_identity"],
        "optimization_config": identity["inputs"]["optimization_config"],
        "release_support_files": identity["inputs"]["release_support_files"],
        "optimization": identity["optimization"],
        "performance": identity["performance"],
    }


def release_subject_sha256(identity: dict[str, Any]) -> str:
    return canonical_hash(release_subject(identity))


def evidence_record(identity: dict[str, Any], gate: str) -> dict[str, Any]:
    matches = [
        record
        for record in identity["verification"]["evidence"]
        if record["gate"] == gate
    ]
    if len(matches) != 1:
        raise ReleaseError(f"release identity has no unique evidence gate {gate!r}")
    return matches[0]


def verify_release_support_files(
    identity: dict[str, Any], source_root: Path
) -> None:
    root = source_root.resolve(strict=True)
    records = identity["inputs"]["release_support_files"]
    for record in records:
        expected = root / record["path"]
        verify_file(
            expected,
            record["file"],
            label=f"release support file {record['path']}",
        )
        module_name = Path(record["path"]).stem
        loaded = sys.modules.get(module_name)
        if loaded is not None:
            loaded_name = getattr(loaded, "__file__", None)
            if loaded_name is None or Path(loaded_name).resolve(strict=True) != expected:
                raise ReleaseError(
                    f"loaded release helper {module_name} is not the exact adjacent source file"
                )


def require_release_bootstrap(entrypoint: str) -> dict[str, Any]:
    """Require the top-level isolated source launcher before any tool action."""

    expected_entrypoint = portable_path(entrypoint, label="release entrypoint")
    bootstrap_module = sys.modules.get("release_bootstrap")
    if bootstrap_module is None or not hasattr(bootstrap_module, "attestation"):
        raise ReleaseError(
            f"{expected_entrypoint} must run through release_bootstrap.py"
        )
    try:
        value = bootstrap_module.attestation()
        bootstrap_path = Path(bootstrap_module.__file__).resolve(strict=True)
    except (AttributeError, OSError, RuntimeError, ValueError) as exc:
        raise ReleaseError("release source bootstrap attestation is unavailable") from exc
    source_root = bootstrap_path.parents[2]
    if (
        not isinstance(value, dict)
        or value.get("schema") != "kazstem-release-source-bootstrap-v1"
        or value.get("entrypoint") != expected_entrypoint
        or value.get("source_root") != "<MATERIALIZED-SOURCE>"
        or value.get("release_identity") != "<RELEASE-IDENTITY>"
        or value.get("release_identity_verified") is not True
        or value.get("cache_root") != "<FRESH-PYCACHE-ROOT>"
        or value.get("cache_absent_before_execution") is not True
        or value.get("cache_outside_source") is not True
        or value.get("adjacent_bytecode_rejected_before_local_imports") is not True
        or value.get("complete_source_inventory_verified_before_local_imports")
        is not True
        or value.get("fresh_materialization_objects_verified") is not True
        or value.get("interpreter_flags")
        != ["-I", "-B", "-X", "pycache_prefix=<FRESH-PYCACHE-ROOT>"]
        or Path.cwd().resolve(strict=True) != source_root
        or not sys.dont_write_bytecode
        or sys.flags.isolated != 1
    ):
        raise ReleaseError("release source bootstrap attestation is not exact")
    return value


def verify_generator_runtime(
    identity: dict[str, Any],
    *,
    gate: str,
    logical_argv: list[str],
) -> dict[str, Any]:
    """Bind an evidence process to its exact checked source/tool/argv/context."""

    ambient_git = sorted(name for name in os.environ if name.startswith("GIT_"))
    if ambient_git:
        raise ReleaseError(
            f"{gate} generator inherited forbidden Git variables: {ambient_git}"
        )
    forbidden_environment = sorted(
        key
        for key in os.environ
        if key.upper().startswith("QAZMORPH_")
        or key.upper().endswith("_PROXY")
        or key in {"PYTHONPATH", "PYTHONHOME"}
        or forbidden_loader_environment_name(key)
    )
    if forbidden_environment:
        raise ReleaseError(
            f"{gate} generator inherited forbidden environment keys: {forbidden_environment}"
        )
    record = evidence_record(identity, gate)
    generator = record["generator"]
    require_release_bootstrap(GENERATOR_SCRIPTS[gate])
    expected_entrypoint_argv = canonical_generator_entrypoint_argv(identity, gate)
    if expected_entrypoint_argv is None:
        prefix = release_bootstrap_prefix(identity, GENERATOR_SCRIPTS[gate])
        expected_entrypoint_argv = [
            "<PYTHON>",
            GENERATOR_SCRIPTS[gate],
            *generator["argv"][len(prefix) :],
        ]
    if logical_argv != expected_entrypoint_argv:
        raise ReleaseError(
            f"actual entrypoint argv differs from frozen generator contract for {gate}"
        )
    source_root = Path.cwd().resolve(strict=True)
    verify_release_support_files(identity, source_root)
    script_path = source_root / generator["script"]["path"]
    verify_file(script_path, generator["script"]["file"], label=f"{gate} generator script")
    python_path = Path(sys.executable).resolve(strict=True)
    verify_file(python_path, generator["tool"]["file"], label=f"{gate} generator CPython")
    if __import__("platform").python_version() != generator["tool"]["version"]:
        raise ReleaseError(f"{gate} generator Python version differs")
    controlled_environment = {
        key: os.environ.get(key)
        for key in generator["environment"]
    }
    if controlled_environment != generator["environment"]:
        raise ReleaseError(f"{gate} generator controlled environment differs")
    bootstrap_module = sys.modules.get("release_bootstrap")
    if bootstrap_module is None or not hasattr(bootstrap_module, "attestation"):
        raise ReleaseError(f"{gate} generator bypassed the checked source bootstrap")
    attestation = bootstrap_module.attestation()
    boundary = dict(generator["source_boundary"])
    boundary.pop("bootstrap")
    expected_attestation = {"schema": boundary.pop("schema"), **boundary}
    if attestation != expected_attestation:
        raise ReleaseError(f"{gate} generator source bootstrap attestation differs")
    if source_root != Path(generator["script"]["path"]).resolve(strict=True).parents[2]:
        raise ReleaseError(f"{gate} generator cwd is not its materialized source root")
    verify_tree(
        source_root,
        identity["inputs"]["source_payload_tree"],
        label=f"{gate} generator materialized source",
    )
    return record


def identity_sha256(path: Path) -> str:
    """Hash the stable identity projection used by sidecar evidence.

    Output bytes and evidence contents are deliberately not embedded in their
    own prerequisites.  Locations remain bound, while the checked identity
    still binds the final artifact bytes at the finalizer boundary.
    """

    identity = load_identity(path)
    projection = dict(identity)
    projection["verification"] = {
        "minimum_distinct_roots": identity["verification"]["minimum_distinct_roots"],
        "evidence": [
            {key: value for key, value in record.items() if key != "file"}
            for record in identity["verification"]["evidence"]
        ],
    }
    return canonical_hash(projection)


def ensure_output_outside(output: Path, protected: Path, *, label: str) -> None:
    target = output.resolve(strict=False)
    root = protected.resolve(strict=False)
    if target == root or root in target.parents:
        raise ReleaseError(f"{label} must be outside protected root {protected}")


def _collision_key(relative: str) -> str:
    return unicodedata.normalize("NFC", relative).casefold()


def tree_inventory(root: Path) -> list[dict[str, Any]]:
    root = root.resolve(strict=True)
    if not root.is_dir() or root.is_symlink():
        raise ReleaseError(f"tree root is invalid: {root}")
    records: list[dict[str, Any]] = []
    folded: set[str] = set()
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        relative = portable_path(path.relative_to(root).as_posix(), label="tree entry")
        key = _collision_key(relative)
        if key in folded:
            raise ReleaseError(f"case/NFC-colliding tree path: {relative}")
        folded.add(key)
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            raise ReleaseError(f"symlink is forbidden in Windows release trees: {relative}")
        if stat.S_ISDIR(metadata.st_mode):
            records.append({"path": relative, "kind": "directory"})
        elif stat.S_ISREG(metadata.st_mode):
            if metadata.st_nlink != 1:
                raise ReleaseError(f"hard link is forbidden in release tree: {relative}")
            records.append({"path": relative, "kind": "file", **file_record(path)})
        else:
            raise ReleaseError(f"special entry is forbidden in release tree: {relative}")
    if not records:
        raise ReleaseError(f"release tree is empty: {root}")
    return records


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
        raise ReleaseError(f"{label} tree identity mismatch: expected={expected}, observed={actual}")


def verify_file(path: Path, expected: dict[str, Any], *, label: str) -> None:
    actual = file_record(path)
    if actual != expected:
        raise ReleaseError(f"{label} identity mismatch: expected={expected}, observed={actual}")


def verify_artifact(path: Path, expected: dict[str, Any], *, label: str) -> None:
    actual = artifact_record(path, expected["url"])
    if actual != expected:
        raise ReleaseError(f"{label} artifact mismatch: expected={expected}, observed={actual}")


def verify_source_receipt(value: Any, identity: dict[str, Any]) -> None:
    receipt = _exact(
        value,
        {"schema", "result", "source", "payload_tree", "git_archive", "execution", "coverage"},
        "source materialization receipt",
    )
    if receipt["schema"] != "kazstem-git-source-materialization-v2" or receipt["result"] != "pass":
        raise ReleaseError("source receipt schema/result is invalid")
    if receipt["source"] != {
        "commit": identity["source_commit"],
        "tree": identity["source_tree"],
        "origin": identity["source_origin"],
        "ref": identity["source_ref"],
    }:
        raise ReleaseError("source receipt Git identity differs from release identity")
    if receipt["payload_tree"] != identity["inputs"]["source_payload_tree"]:
        raise ReleaseError("source receipt payload tree differs from release identity")
    _file(receipt["git_archive"], "source receipt git_archive")
    execution = _exact(
        receipt["execution"],
        {"argv", "cwd", "environment", "tools", "dependencies", "exit_code"},
        "source receipt execution",
    )
    expected_argv = [
        "git",
        *GIT_READ_ONLY_CONFIG_ARGUMENTS,
        "archive",
        "--format=tar",
        "--prefix=KazStem/",
        identity["source_commit"],
    ]
    if execution["argv"] != expected_argv or execution["exit_code"] != 0:
        raise ReleaseError("source receipt does not record the exact Git archive command")
    if execution["cwd"] != "<SOURCE-REPOSITORY>":
        raise ReleaseError("source receipt cwd is not logically path-independent")
    if execution["environment"] != {
        "GIT_CONFIG_GLOBAL": "<NULL-DEVICE>",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "LC_ALL": "C",
        "PATH": "<BOUND-GIT-DIR>",
        "TZ": "UTC",
    }:
        raise ReleaseError("source receipt environment is not exact/minimal")
    if (
        not isinstance(execution["tools"], dict)
        or set(execution["tools"]) != {"git"}
    ):
        raise ReleaseError("source receipt lacks the exact Git version")
    git_tool = _exact(execution["tools"]["git"], {"version", "executable"}, "source receipt Git tool")
    if not isinstance(git_tool["version"], str) or not git_tool["version"].startswith("git version "):
        raise ReleaseError("source receipt Git version is invalid")
    _file(git_tool["executable"], "source receipt Git executable")
    expected_dependencies = [
        value
        for value in identity["inputs"]["release_support_files"]
        if value["path"]
        in {
            "packaging/windows/release_bootstrap.py",
            "packaging/windows/release_common.py",
        }
    ]
    if execution["dependencies"] != expected_dependencies:
        raise ReleaseError("source receipt bootstrap dependency bundle differs")
    coverage = _exact(receipt["coverage"], {"assertions", "cases", "checks"}, "source receipt coverage")
    if coverage != {
        "assertions": 14,
        "cases": 1,
        "checks": [
            "archive-content-matches-git-tree",
            "archive-sha256",
            "bootstrap-source-tree-equals-payload",
            "checked-source-bootstrap",
            "clean-worktree",
            "exact-commit",
            "exact-origin",
            "exact-ref",
            "exact-tree",
            "fsmonitor-disabled",
            "no-submodules",
            "payload-tree-record",
            "replacement-objects-disabled",
            "untracked-cache-disabled",
        ],
    }:
        raise ReleaseError("source receipt coverage is incomplete")


def verify_source_execution_receipt(
    value: Any,
    identity: dict[str, Any],
    *,
    label: str,
    materialization_root: Path,
    payload: Path,
    canonical_receipt: Path,
) -> None:
    receipt = _exact(
        value,
        {
            "schema",
            "result",
            "label",
            "source",
            "root_identity",
            "payload_identity",
            "canonical_receipt",
            "git_archive",
            "execution",
            "freshness",
            "coverage",
        },
        "source materialization execution receipt",
    )
    if (
        receipt["schema"] != "kazstem-git-source-materialization-execution-v2"
        or receipt["result"] != "pass"
        or receipt["label"] != label
    ):
        raise ReleaseError("source execution receipt schema/result/label differs")
    if receipt["source"] != {
        "commit": identity["source_commit"],
        "tree": identity["source_tree"],
        "origin": identity["source_origin"],
        "ref": identity["source_ref"],
    }:
        raise ReleaseError("source execution receipt Git identity differs")
    root = materialization_root.resolve(strict=True)
    payload_path = payload.resolve(strict=True)
    canonical_path = canonical_receipt.resolve(strict=True)
    expected_root = {
        "logical_label": label,
        "st_dev": root.stat().st_dev,
        "st_ino": root.stat().st_ino,
        "st_ctime_ns": root.stat().st_ctime_ns,
    }
    if receipt["root_identity"] != expected_root:
        raise ReleaseError("source execution receipt does not bind the actual root object")
    logical_root = f"<SOURCE-ROOT-{label.upper()}>"
    expected_payload = {
        "logical_path": f"{logical_root}/KazStem",
        "st_dev": payload_path.stat().st_dev,
        "st_ino": payload_path.stat().st_ino,
        "st_ctime_ns": payload_path.stat().st_ctime_ns,
        "tree": identity["inputs"]["source_payload_tree"],
    }
    if receipt["payload_identity"] != expected_payload:
        raise ReleaseError("source execution receipt does not bind the payload object/tree")
    for path, expected_name in (
        (payload_path, "KazStem"),
        (canonical_path, "GIT-SOURCE-MATERIALIZATION.json"),
    ):
        try:
            path.relative_to(root)
        except ValueError as exc:
            raise ReleaseError("source execution output escapes its fresh root") from exc
        if path.name != expected_name:
            raise ReleaseError("source execution output has a noncanonical name")
    if receipt["canonical_receipt"] != identity["inputs"]["source_receipt"]:
        raise ReleaseError("source execution receipt does not bind the canonical receipt")
    if file_record(canonical_path) != receipt["canonical_receipt"]:
        raise ReleaseError("canonical source receipt bytes changed after materialization")
    _file(receipt["git_archive"], "source execution git archive")
    execution = _exact(
        receipt["execution"],
        {
            "script", "argv", "cwd", "environment", "tools",
            "dependencies", "source_boundary", "exit_code",
        },
        "source execution command",
    )
    script = _exact(execution["script"], {"path", "file"}, "source execution script")
    if script["path"] != "packaging/windows/materialize_git_source.py":
        raise ReleaseError("source execution used an unexpected script")
    verify_file(
        payload_path / script["path"],
        script["file"],
        label="materialized source execution script",
    )
    inner_argv = [
        "<PYTHON>",
        script["path"],
        "--label",
        label,
        "--repo",
        "<SOURCE-REPOSITORY>",
        "--source-commit",
        identity["source_commit"],
        "--source-tree",
        identity["source_tree"],
        "--source-origin",
        identity["source_origin"],
        "--source-ref",
        identity["source_ref"],
        "--materialization-root",
        logical_root,
        "--archive",
        f"{logical_root}/SOURCE.tar",
        "--payload",
        f"{logical_root}/KazStem",
        "--receipt",
        f"{logical_root}/GIT-SOURCE-MATERIALIZATION.json",
        "--execution-receipt",
        f"{logical_root}/MATERIALIZATION-EXECUTION.json",
    ]
    expected_argv = [
        *release_bootstrap_prefix(identity, script["path"]),
        *inner_argv[2:],
    ]
    expected_environment = {
        "GIT_CONFIG_GLOBAL": "<NULL-DEVICE>",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "LC_ALL": "C",
        "PATH": "<BOUND-GIT-DIR>",
        "TZ": "UTC",
    }
    if (
        execution["argv"] != expected_argv
        or execution["cwd"] != "<BOOTSTRAP-MATERIALIZED-SOURCE>"
        or execution["environment"] != expected_environment
        or execution["exit_code"] != 0
    ):
        raise ReleaseError("source materialization command/environment is not exact")
    expected_dependencies = [
        value
        for value in identity["inputs"]["release_support_files"]
        if value["path"]
        in {
            "packaging/windows/release_bootstrap.py",
            "packaging/windows/release_common.py",
        }
    ]
    if execution["dependencies"] != expected_dependencies:
        raise ReleaseError("source materialization bootstrap dependency bundle differs")
    expected_boundary = source_boundary_contract(identity, script["path"])
    expected_boundary.pop("bootstrap")
    if execution["source_boundary"] != expected_boundary:
        raise ReleaseError("source materialization bootstrap boundary differs")
    tools = _exact(execution["tools"], {"git", "python"}, "source execution tools")
    git_tool = _exact(tools["git"], {"version", "executable"}, "source execution Git")
    if not isinstance(git_tool["version"], str) or not git_tool["version"].startswith("git version "):
        raise ReleaseError("source materialization Git version is invalid")
    _file(git_tool["executable"], "source execution Git executable")
    canonical_value = read_json(canonical_path)
    if canonical_value.get("execution", {}).get("tools", {}).get("git") != git_tool:
        raise ReleaseError("canonical and per-root receipts name different Git tools")
    python = _exact(tools["python"], {"version", "executable"}, "source execution Python")
    expected_python_file = {
        "bytes": identity["inputs"]["bootstrap_python"]["bytes"],
        "sha256": identity["inputs"]["bootstrap_python"]["sha256"],
    }
    if (
        python["version"] != identity["platform"]["python"]
        or python["executable"] != expected_python_file
    ):
        raise ReleaseError("source materialization Python differs from the bound bootstrap")
    if receipt["freshness"] != {
        "root_absent_before_execution": True,
        "root_created_by_process": True,
        "payload_created_by_process": True,
    }:
        raise ReleaseError("source execution receipt lacks fresh-root proof")
    expected_checks = [
        "canonical-receipt",
        "checked-bootstrap-invocation",
        "complete-bootstrap-source-inventory",
        "exact-command-and-tools",
        "external-fresh-pycache-root",
        "fresh-root-object",
        "git-archive-object",
        "nonaliased-output-layout",
        "payload-root-object",
        "source-commit-tree-origin-ref",
    ]
    if receipt["coverage"] != {
        "assertions": len(expected_checks),
        "cases": 1,
        "checks": expected_checks,
    }:
        raise ReleaseError("source execution receipt coverage is incomplete")


def python_build_commands(identity: dict[str, Any], *, noarchive: bool) -> list[dict[str, Any]]:
    def command(
        argv: list[str],
        cwd: str,
        overrides: dict[str, str] | None = None,
        timeout_seconds: int = 900,
    ) -> dict[str, Any]:
        return {
            "argv": argv,
            "cwd": cwd,
            "environment_overrides": overrides or {},
            "timeout_seconds": timeout_seconds,
            "exit_code": 0,
        }

    def source_tool(entrypoint: str, arguments: list[str]) -> list[str]:
        prefix = release_bootstrap_prefix(identity, entrypoint)
        prefix[0] = "<BUILD-PYTHON>"
        return [*prefix, *arguments]

    return [
        command(["<BOOTSTRAP-PYTHON>", "-m", "venv", "<FRESH-BUILD-ROOT>/venv"], "<FRESH-BUILD-ROOT>"),
        command(
            [
                "<BUILD-PYTHON>", "-m", "pip", "install", "--no-index",
                "--find-links", "<WHEELHOUSE>", "--require-hashes",
                "--only-binary=:all:", "--no-deps", "-r",
                "packaging/windows/build-requirements.lock.txt",
            ],
            "<MATERIALIZED-SOURCE>",
        ),
        command(
            [
                "<BUILD-PYTHON>", "packaging/build_canonical_python_artifacts.py",
                "--identity", "<CANONICAL-PYTHON-BUILD-IDENTITY>",
                "--source-checkout", "<MATERIALIZED-SOURCE>",
                "--wheelhouse", "<WHEELHOUSE>",
                "--requirements", "packaging/windows/build-requirements.lock.txt",
                "--workspace", "<FRESH-BUILD-ROOT>/canonical-python-workspace",
                "--roundtrip-workspace", "<SDIST-ROUNDTRIP-ROOT>",
                "--output-dir", "<FRESH-BUILD-ROOT>/artifacts",
                "--receipt", "<FRESH-BUILD-ROOT>/canonical-python-build-receipt.json",
            ],
            "<FRESH-BUILD-ROOT>",
        ),
        command(
            source_tool(
                "packaging/windows/audit_python_artifacts.py",
                ["--source", "<MATERIALIZED-SOURCE>",
                "--wheel", "<WHEEL>", "--sdist", "<SDIST>", "--version",
                identity["release"], "--json",
                "<FRESH-BUILD-ROOT>/python-artifact-source-audit.json"],
            ),
            "<MATERIALIZED-SOURCE>",
        ),
        command(
            ["<BUILD-PYTHON>", "-m", "pip", "install", "--no-index", "--no-deps", "<WHEEL>"],
            "<FRESH-BUILD-ROOT>",
        ),
        command(
            [
                "<BUILD-PYTHON>", "-m", "PyInstaller", "--clean", "--noconfirm",
                "--distpath", "<FRESH-BUILD-ROOT>/dist", "--workpath",
                "<FRESH-BUILD-ROOT>/pyinstaller-work", "packaging/windows/kazstem-minimal.spec",
            ],
            "<FRESH-BUILD-ROOT>",
            {
                "KAZSTEM_ENTRYPOINT": "<MATERIALIZED-SOURCE>/packaging/windows/entrypoint.py",
                "KAZSTEM_NOARCHIVE": "1" if noarchive else "0",
            },
            1200,
        ),
        command(
            source_tool(
                "packaging/windows/write_freezer_ledger.py",
                ["--frozen", "<FROZEN>", "--spec",
                "packaging/windows/kazstem-minimal.spec", "--source-commit",
                identity["source_commit"], "--config", "<OPTIMIZATION-CONFIG>",
                "--json", "<BASE-LEDGER>"],
            ),
            "<MATERIALIZED-SOURCE>",
        ),
    ]


def verify_python_build_receipt(
    value: Any,
    identity: dict[str, Any],
    *,
    label: str,
    build_root: Path,
    roundtrip_root: Path,
    bootstrap_python: Path,
    wheelhouse: Path,
    optimization_config: Path,
    python_build_identity: Path,
    frozen: Path,
    wheel: Path,
    sdist: Path,
    base_ledger: Path,
) -> None:
    receipt = _exact(
        value,
        {
            "schema",
            "result",
            "label",
            "source",
            "source_receipt",
            "source_boundary",
            "root_identity",
            "roundtrip_root_identity",
            "build_inputs",
            "source_tree_snapshots",
            "execution",
            "outputs",
            "coverage",
        },
        "Python/freezer build receipt",
    )
    if (
        receipt["schema"] != "kazstem-windows-python-freezer-build-v1"
        or receipt["result"] != "pass"
        or receipt["label"] != label
    ):
        raise ReleaseError("Python/freezer build receipt schema/label/result differs")
    if receipt["source"] != {
        "commit": identity["source_commit"],
        "tree": identity["source_tree"],
        "origin": identity["source_origin"],
        "ref": identity["source_ref"],
        "payload_tree": identity["inputs"]["source_payload_tree"],
    }:
        raise ReleaseError("build receipt source identity differs")
    if receipt["source_receipt"] != identity["inputs"]["source_receipt"]:
        raise ReleaseError("build receipt source materialization differs")
    expected_boundary = source_boundary_contract(
        identity, "packaging/windows/build_python_freezer.py"
    )
    expected_boundary.pop("bootstrap")
    if receipt["source_boundary"] != expected_boundary:
        raise ReleaseError("build receipt source bootstrap differs")
    resolved_root = build_root.resolve(strict=True)
    root_stat = resolved_root.stat()
    if receipt["root_identity"] != {
        "logical_label": label,
        "st_dev": root_stat.st_dev,
        "st_ino": root_stat.st_ino,
    }:
        raise ReleaseError("build receipt does not bind the actual fresh root object")
    resolved_roundtrip = roundtrip_root.resolve(strict=True)
    roundtrip_stat = resolved_roundtrip.stat()
    if (
        resolved_roundtrip == resolved_root
        or resolved_roundtrip in resolved_root.parents
        or resolved_root in resolved_roundtrip.parents
        or resolved_roundtrip.samefile(resolved_root)
        or receipt["roundtrip_root_identity"]
        != {
            "logical_label": f"{label}-sdist-roundtrip",
            "st_dev": roundtrip_stat.st_dev,
            "st_ino": roundtrip_stat.st_ino,
        }
    ):
        raise ReleaseError("sdist roundtrip root is not distinct/exactly receipted")
    bootstrap_path = bootstrap_python.resolve(strict=True)
    wheelhouse_path = wheelhouse.resolve(strict=True)
    config_path = optimization_config.resolve(strict=True)
    python_identity_path = python_build_identity.resolve(strict=True)
    if pe_identity(bootstrap_path) != identity["inputs"]["bootstrap_python"]:
        raise ReleaseError("build receipt bootstrap Python bytes/architecture differ")
    verify_tree(
        wheelhouse_path,
        identity["inputs"]["build_wheelhouse_tree"],
        label="build receipt wheelhouse",
    )
    verify_file(
        config_path,
        identity["inputs"]["optimization_config"],
        label="build receipt optimization config",
    )
    config_value = read_json(config_path)
    if (
        not isinstance(config_value, dict)
        or config_value.get("schema") != "kazstem-windows-optimization-config-v1"
        or not isinstance(config_value.get("switches"), dict)
        or not isinstance(config_value["switches"].get("noarchive"), bool)
    ):
        raise ReleaseError("build receipt optimization config semantics are invalid")
    verify_file(
        python_identity_path,
        identity["inputs"]["canonical_python_build_identity"],
        label="build receipt canonical Python identity",
    )
    requirements_path = resolved_root / "source/packaging/windows/build-requirements.lock.txt"
    canonical_builder_path = resolved_root / "source/packaging/build_canonical_python_artifacts.py"
    if receipt["build_inputs"] != {
        "bootstrap_python": identity["inputs"]["bootstrap_python"],
        "wheelhouse_tree": identity["inputs"]["build_wheelhouse_tree"],
        "canonical_python_build_identity": identity["inputs"]["canonical_python_build_identity"],
        "optimization_config": identity["inputs"]["optimization_config"],
        "requirements": file_record(requirements_path),
        "canonical_builder": file_record(canonical_builder_path),
        "release_support_files": identity["inputs"]["release_support_files"],
    }:
        raise ReleaseError("build receipt inputs differ from strict release identity")
    for support in identity["inputs"]["release_support_files"]:
        verify_file(
            resolved_root / "source" / support["path"],
            support["file"],
            label=f"build source support file {support['path']}",
        )
    source_snapshot = tree_record(resolved_root / "source")
    if receipt["source_tree_snapshots"] != {
        "before": identity["inputs"]["source_payload_tree"],
        "after": identity["inputs"]["source_payload_tree"],
    } or source_snapshot != identity["inputs"]["source_payload_tree"]:
        raise ReleaseError("build receipt source copy was modified during the build")
    for path, name in (
        (frozen, "frozen"),
        (wheel, "wheel"),
        (sdist, "sdist"),
        (base_ledger, "base ledger"),
    ):
        resolved = path.resolve(strict=True)
        try:
            resolved.relative_to(resolved_root)
        except ValueError as exc:
            raise ReleaseError(f"{name} output is not inside its receipt build root") from exc
    outputs = _exact(
        receipt["outputs"],
        {"frozen_tree", "wheel", "sdist", "base_ledger", "canonical_build_receipt"},
        "build receipt outputs",
    )
    if outputs != {
        "frozen_tree": tree_record(frozen),
        "wheel": artifact_record(wheel, identity["artifacts"]["wheel"]["url"]),
        "sdist": artifact_record(sdist, identity["artifacts"]["sdist"]["url"]),
        "base_ledger": file_record(base_ledger),
        "canonical_build_receipt": file_record(
            resolved_root / "canonical-python-build-receipt.json"
        ),
    }:
        raise ReleaseError("build receipt output identities differ from actual bytes")
    execution = _exact(
        receipt["execution"],
        {"commands", "environment", "tool_versions", "process_contract"},
        "build receipt execution",
    )
    if execution["commands"] != python_build_commands(
        identity, noarchive=config_value["switches"]["noarchive"]
    ):
        raise ReleaseError("build receipt commands differ from the exact offline build contract")
    if execution["process_contract"] != {
        "implementation": "windows-job-object-kill-on-close",
        "captures_direct_child_and_descendants": True,
        "combined_output_limit_bytes": 16 * 1024 * 1024,
        "timeout_reaps_process_tree": True,
        "launch_order": "create-suspended-assign-job-start-reader-resume",
        "active_processes_zero_before_return": True,
        "descendants_after_direct_exit_fail": True,
    }:
        raise ReleaseError("build receipt process-tree/output-bound contract differs")
    expected_environment = {
        "COMSPEC": "<SYSTEM32>/cmd.exe",
        "HOME": "<FRESH-BUILD-ROOT>/home",
        "LC_ALL": "C",
        "PATH": "<BOOTSTRAP-PYTHON-DIR>;<SYSTEM32>;<WINDOWS>",
        "PATHEXT": ".COM;.EXE;.BAT;.CMD",
        "PIP_DISABLE_PIP_VERSION_CHECK": "1",
        "PIP_FIND_LINKS": "<WHEELHOUSE>",
        "PIP_NO_INDEX": "1",
        "PIP_NO_INPUT": "1",
        "PYINSTALLER_CONFIG_DIR": "<FRESH-BUILD-ROOT>/pyinstaller-cache",
        "PYTHONHASHSEED": "0",
        "PYTHONNOUSERSITE": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "SOURCE_DATE_EPOCH": str(identity["source_date_epoch"]),
        "SYSTEMROOT": "<WINDOWS>",
        "TEMP": "<FRESH-BUILD-ROOT>/tmp",
        "TMP": "<FRESH-BUILD-ROOT>/tmp",
        "TZ": "UTC",
        "USERPROFILE": "<FRESH-BUILD-ROOT>/home",
        "WINDIR": "<WINDOWS>",
    }
    if execution["environment"] != expected_environment:
        raise ReleaseError("build receipt environment differs from deterministic contract")
    tools = execution["tool_versions"]
    required_tools = {"python", "pip", "build", "setuptools", "wheel", "pyinstaller", "zlib"}
    if (
        not isinstance(tools, dict)
        or set(tools) != required_tools
        or any(not isinstance(item, str) or not item for item in tools.values())
        or tools["python"] != identity["platform"]["python"]
        or tools["pyinstaller"] != identity["platform"]["pyinstaller"]
    ):
        raise ReleaseError("build receipt tool versions differ from the pinned contract")
    coverage = _exact(receipt["coverage"], {"assertions", "cases", "checks"}, "build receipt coverage")
    required_checks = [
        "base-ledger",
        "canonical-sdist",
        "fresh-root",
        "frozen-tree",
        "hash-locked-build-environment",
        "no-network-runtime-modules",
        "python-artifact-source-parity",
        "sdist-to-wheel-roundtrip",
        "sdist-byte-identity",
        "source-tree-unchanged",
        "wheel-byte-identity",
    ]
    if (
        coverage.get("assertions") != len(required_checks)
        or coverage.get("cases") != 1
        or coverage.get("checks") != required_checks
    ):
        raise ReleaseError("build receipt coverage is incomplete")


def source_execution_receipt_projection(value: dict[str, Any]) -> dict[str, Any]:
    """Return the published, host-independent source execution proof."""

    return {
        "schema": value["schema"],
        "result": value["result"],
        "label": value["label"],
        "source": value["source"],
        "root_identity": {
            "logical_label": value["root_identity"]["logical_label"],
            "distinct_nonnested_nonaliased": True,
        },
        "payload_identity": {
            "logical_path": value["payload_identity"]["logical_path"],
            "tree": value["payload_identity"]["tree"],
        },
        "canonical_receipt": value["canonical_receipt"],
        "git_archive": value["git_archive"],
        "execution": value["execution"],
        "freshness": value["freshness"],
        "coverage": value["coverage"],
    }


def python_build_receipt_projection(value: dict[str, Any]) -> dict[str, Any]:
    """Return the published build receipt without host/run inode identities."""

    return {
        key: item
        for key, item in value.items()
        if key not in {"root_identity", "roundtrip_root_identity"}
    } | {
        "root_identity": {
            "logical_label": value["root_identity"]["logical_label"],
            "distinct_nonnested_nonaliased": True,
        },
        "roundtrip_root_identity": {
            "logical_label": value["roundtrip_root_identity"]["logical_label"],
            "distinct_nonnested_nonaliased": True,
        },
    }


def verify_or_observe_output(path: Path, expected: dict[str, Any], *, observation: Path | None, label: str) -> None:
    actual = artifact_record(path, expected["url"])
    if observation is not None:
        if observation.exists() or observation.is_symlink():
            raise ReleaseError(f"observation path already exists: {observation}")
        observation.parent.mkdir(parents=True, exist_ok=True)
        observation.write_bytes(json_bytes(actual))
    if actual != expected:
        quarantine = path.with_name(f"{path.name}.unsealed-{actual['sha256'][:12]}")
        if quarantine.exists() or quarantine.is_symlink():
            raise ReleaseError(f"quarantine path already exists: {quarantine}")
        path.rename(quarantine)
        raise ReleaseError(
            f"{label} output mismatch; observed={actual}; candidate quarantined as {quarantine.name}"
        )


def copy_tree_exact(source: Path, destination: Path) -> None:
    """Copy a validated tree without preserving hard links or machine times."""

    tree_inventory(source)
    if destination.exists() or destination.is_symlink():
        raise ReleaseError(f"copy destination already exists: {destination}")
    destination.mkdir(parents=True)
    for item in tree_inventory(source):
        src = source / item["path"]
        dst = destination / item["path"]
        if item["kind"] == "directory":
            dst.mkdir()
        else:
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(src, dst)


def normalize_tree(root: Path, *, epoch: int, executable_paths: Iterable[str]) -> None:
    executable = set(executable_paths)
    for relative in executable:
        portable_path(relative, label="executable release path")
    for path in sorted(root.rglob("*"), key=lambda item: len(item.parts), reverse=True):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            raise ReleaseError(f"symlink survived Windows normalization: {relative}")
        mode = 0o555 if path.is_dir() or relative in executable else 0o444
        path.chmod(mode)
        os.utime(path, (epoch, epoch), follow_symlinks=False)
    root.chmod(0o555)
    os.utime(root, (epoch, epoch), follow_symlinks=False)


def checksum_rows(root: Path, *, excluded: set[str]) -> list[str]:
    rows: list[str] = []
    for item in tree_inventory(root):
        if item["kind"] == "file" and item["path"] not in excluded:
            rows.append(f"{item['sha256']}  {item['path']}")
    return rows


def manifest_records(root: Path, *, excluded: set[str]) -> tuple[list[dict[str, Any]], list[str]]:
    files: list[dict[str, Any]] = []
    directories: list[str] = []
    for item in tree_inventory(root):
        if item["kind"] == "directory":
            directories.append(item["path"])
        elif item["path"] not in excluded:
            files.append({"path": item["path"], "bytes": item["bytes"], "sha256": item["sha256"]})
    return files, directories


def verify_manifest(root: Path, manifest: dict[str, Any], *, excluded: set[str]) -> None:
    files, directories = manifest_records(root, excluded=excluded)
    if manifest.get("files") != files or manifest.get("directories") != directories:
        raise ReleaseError("generated archive manifest is incomplete or incorrect")


def verify_checksums(root: Path, path: Path) -> None:
    expected = checksum_rows(root, excluded={path.relative_to(root).as_posix()})
    try:
        observed = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        raise ReleaseError(f"cannot read checksum inventory: {exc}") from exc
    if observed != expected:
        raise ReleaseError("checksum inventory differs from extracted archive")


def verify_required_paths(root: Path, values: Iterable[str]) -> None:
    for relative in values:
        if not (root / relative).exists():
            raise ReleaseError(f"required release path is missing: {relative}")


def assert_relative_evidence(root: Path) -> None:
    try:
        from audit_evidence_paths import EvidenceError, scan_evidence

        scan_evidence(root, forbidden_values=[])
    except (EvidenceError, OSError, ValueError) as exc:
        raise ReleaseError(f"logical evidence path audit failed: {exc}") from exc


def _zip_datetime(epoch: int) -> tuple[int, int, int, int, int, int]:
    value = time.gmtime(epoch)
    if value.tm_year < 1980 or value.tm_year > 2107:
        raise ReleaseError("SOURCE_DATE_EPOCH is outside the ZIP timestamp range")
    return (value.tm_year, value.tm_mon, value.tm_mday, value.tm_hour, value.tm_min, value.tm_sec - value.tm_sec % 2)


def write_deterministic_zip(root: Path, destination: Path, *, epoch: int, limits: ArchiveLimits) -> None:
    inventory = tree_inventory(root)
    if len(inventory) + 1 > limits.max_members:
        raise ReleaseError("output ZIP exceeds member cap")
    total = sum(item.get("bytes", 0) for item in inventory)
    if total > limits.max_total_bytes:
        raise ReleaseError("output ZIP exceeds total-byte cap")
    if destination.exists() or destination.is_symlink():
        raise ReleaseError(f"ZIP output already exists: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    timestamp = _zip_datetime(epoch)
    try:
        with zipfile.ZipFile(destination, "x", compression=zipfile.ZIP_DEFLATED, compresslevel=9, strict_timestamps=True) as archive:
            entries = [{"path": root.name, "kind": "directory"}, *inventory]
            for item in entries:
                relative = item["path"]
                member = relative if relative == root.name else f"{root.name}/{relative}"
                portable_path(member, label="ZIP output member")
                if item["kind"] == "directory":
                    info = zipfile.ZipInfo(member + "/", timestamp)
                    info.create_system = 3
                    info.external_attr = ((stat.S_IFDIR | 0o555) << 16) | 0x10
                    info.compress_type = zipfile.ZIP_STORED
                    archive.writestr(info, b"")
                else:
                    if item["bytes"] > limits.max_file_bytes:
                        raise ReleaseError(f"output file exceeds ZIP cap: {relative}")
                    info = zipfile.ZipInfo(member, timestamp)
                    info.create_system = 3
                    info.external_attr = (stat.S_IFREG | (0o555 if relative.casefold().endswith((".exe", ".dll", ".pyd")) else 0o444)) << 16
                    info.compress_type = zipfile.ZIP_DEFLATED
                    info._compresslevel = 9
                    with (root / relative).open("rb") as source, archive.open(info, "w", force_zip64=True) as target:
                        shutil.copyfileobj(source, target, length=1024 * 1024)
    except BaseException:
        destination.unlink(missing_ok=True)
        raise


def _member_name(value: str, *, limits: ArchiveLimits) -> str:
    name = value[:-1] if value.endswith("/") else value
    portable_path(name, label="ZIP member")
    if len(name.encode("utf-8")) > limits.max_path_bytes:
        raise ReleaseError(f"ZIP path exceeds cap: {name!r}")
    return name


def _zip_extra_fields(data: bytes, *, label: str) -> dict[int, bytes]:
    fields: dict[int, bytes] = {}
    cursor = 0
    while cursor < len(data):
        if len(data) - cursor < 4:
            raise ReleaseError(f"truncated ZIP extra field in {label}")
        field_id, size = struct.unpack_from("<HH", data, cursor)
        cursor += 4
        if size > len(data) - cursor:
            raise ReleaseError(f"ZIP extra field exceeds header in {label}")
        if field_id in fields:
            raise ReleaseError(f"duplicate ZIP extra field 0x{field_id:04x} in {label}")
        if field_id != 0x0001:
            raise ReleaseError(f"unapproved ZIP extra field 0x{field_id:04x} in {label}")
        fields[field_id] = data[cursor : cursor + size]
        cursor += size
    return fields


def _decode_zip_name(data: bytes, flags: int, *, label: str) -> str:
    try:
        return data.decode("utf-8" if flags & 0x800 else "cp437", errors="strict")
    except UnicodeError as exc:
        raise ReleaseError(f"cannot decode ZIP filename in {label}") from exc


def _physical_zip_audit(
    path: Path,
    *,
    limits: ArchiveLimits,
    contract: ZipOutputContract | None = None,
) -> dict[str, Any]:
    """Validate EOCD, central directory, every local header, and byte closure."""

    size = path.stat().st_size
    if size < 22 or size > limits.max_total_bytes + limits.max_members * (limits.max_path_bytes + 512):
        raise ReleaseError("ZIP physical size is outside the declared safety caps")
    tail_size = min(size, 22 + 65535)
    with path.open("rb") as stream:
        stream.seek(size - tail_size)
        tail = stream.read(tail_size)
    signature = b"PK\x05\x06"
    candidates: list[int] = []
    offset = 0
    while True:
        index = tail.find(signature, offset)
        if index < 0:
            break
        absolute = size - tail_size + index
        if index + 22 <= len(tail):
            comment_length = struct.unpack_from("<H", tail, index + 20)[0]
            if absolute + 22 + comment_length == size:
                candidates.append(absolute)
        offset = index + 1
    if len(candidates) != 1:
        raise ReleaseError("ZIP must have one terminal EOCD and no trailing bytes")
    eocd_offset = candidates[0]
    with path.open("rb") as stream:
        stream.seek(eocd_offset)
        eocd = stream.read(22)
    (
        eocd_signature,
        disk,
        central_disk,
        disk_entries,
        total_entries,
        central_size,
        central_offset,
        comment_length,
    ) = struct.unpack("<I4H2IH", eocd)
    if (
        eocd_signature != 0x06054B50
        or disk != 0
        or central_disk != 0
        or disk_entries != total_entries
        or total_entries <= 0
        or total_entries > limits.max_members
        or comment_length != 0
        or central_offset + central_size != eocd_offset
    ):
        raise ReleaseError("ZIP EOCD/central-directory closure is invalid")
    if central_offset <= 0 or central_size <= 0:
        raise ReleaseError("ZIP central directory is empty or ZIP64-only")
    with path.open("rb") as stream:
        stream.seek(central_offset)
        central = stream.read(central_size)
    if len(central) != central_size:
        raise ReleaseError("ZIP central directory is truncated")
    records: list[dict[str, Any]] = []
    cursor = 0
    for index in range(total_entries):
        if len(central) - cursor < 46:
            raise ReleaseError("truncated ZIP central header")
        values = struct.unpack_from("<I6H3I5H2I", central, cursor)
        (
            header_signature,
            version_made,
            version_needed,
            flags,
            compression,
            mod_time,
            mod_date,
            crc,
            compressed_size,
            uncompressed_size,
            name_length,
            extra_length,
            member_comment_length,
            disk_start,
            internal_attributes,
            external_attributes,
            local_offset,
        ) = values
        if header_signature != 0x02014B50:
            raise ReleaseError("invalid ZIP central-header signature")
        end = cursor + 46 + name_length + extra_length + member_comment_length
        if end > len(central) or not name_length:
            raise ReleaseError("ZIP central variable fields are truncated")
        raw_name = central[cursor + 46 : cursor + 46 + name_length]
        extra = central[cursor + 46 + name_length : cursor + 46 + name_length + extra_length]
        if member_comment_length or disk_start or flags & ~0x800:
            raise ReleaseError("ZIP members may not use comments, multiple disks, encryption, or descriptors")
        extra_fields = _zip_extra_fields(extra, label=f"central member {index}")
        zip64 = extra_fields.get(0x0001, b"")
        zip64_cursor = 0
        if uncompressed_size == 0xFFFFFFFF:
            if len(zip64) - zip64_cursor < 8:
                raise ReleaseError("missing ZIP64 uncompressed size")
            uncompressed_size = struct.unpack_from("<Q", zip64, zip64_cursor)[0]
            zip64_cursor += 8
        if compressed_size == 0xFFFFFFFF:
            if len(zip64) - zip64_cursor < 8:
                raise ReleaseError("missing ZIP64 compressed size")
            compressed_size = struct.unpack_from("<Q", zip64, zip64_cursor)[0]
            zip64_cursor += 8
        if local_offset == 0xFFFFFFFF:
            if len(zip64) - zip64_cursor < 8:
                raise ReleaseError("missing ZIP64 local-header offset")
            local_offset = struct.unpack_from("<Q", zip64, zip64_cursor)[0]
            zip64_cursor += 8
        if zip64_cursor != len(zip64):
            raise ReleaseError("unexpected ZIP64 central metadata")
        name = _decode_zip_name(raw_name, flags, label=f"central member {index}")
        normalized_name = _member_name(name, limits=limits)
        directory = name.endswith("/")
        if contract is not None:
            stamp = _zip_datetime(contract.epoch)
            expected_time = (stamp[3] << 11) | (stamp[4] << 5) | (stamp[5] // 2)
            expected_date = ((stamp[0] - 1980) << 9) | (stamp[1] << 5) | stamp[2]
            expected_version = 20 if directory else 45
            expected_mode = contract.mode_for(normalized_name, "directory" if directory else "file")
            expected_attributes = (
                ((stat.S_IFDIR | expected_mode) << 16) | 0x10
                if directory
                else (stat.S_IFREG | expected_mode) << 16
            )
            expected_flags = 0 if name.isascii() else 0x800
            if (
                flags != expected_flags
                or compression != (zipfile.ZIP_STORED if directory else zipfile.ZIP_DEFLATED)
                or version_made != (3 << 8) | expected_version
                or version_needed != expected_version
                or mod_time != expected_time
                or mod_date != expected_date
                or internal_attributes != 0
                or external_attributes != expected_attributes
                or (directory and (crc != 0 or compressed_size != 0 or uncompressed_size != 0))
            ):
                raise ReleaseError(f"ZIP output metadata is not canonical: {name}")
        if compressed_size > size or uncompressed_size > limits.max_file_bytes:
            raise ReleaseError(f"ZIP physical member size exceeds cap: {name}")
        records.append(
            {
                "name": name,
                "raw_name": raw_name,
                "flags": flags,
                "version_needed": version_needed,
                "mod_time": mod_time,
                "mod_date": mod_date,
                "compression": compression,
                "crc": crc,
                "compressed_size": compressed_size,
                "uncompressed_size": uncompressed_size,
                "external_attributes": external_attributes,
                "local_offset": local_offset,
            }
        )
        cursor = end
    if cursor != len(central):
        raise ReleaseError("unreferenced bytes exist in the ZIP central directory")
    offsets = [record["local_offset"] for record in records]
    if offsets != sorted(set(offsets)) or offsets[0] != 0:
        raise ReleaseError("ZIP local headers are duplicated, reordered, or prefixed")
    with path.open("rb") as stream:
        for index, record in enumerate(records):
            local_offset = record["local_offset"]
            next_offset = offsets[index + 1] if index + 1 < len(offsets) else central_offset
            if local_offset + 30 > next_offset:
                raise ReleaseError("overlapping/truncated ZIP local header")
            stream.seek(local_offset)
            fixed = stream.read(30)
            values = struct.unpack("<I5H3I2H", fixed)
            (
                local_signature,
                version_needed,
                flags,
                compression,
                mod_time,
                mod_date,
                crc,
                compressed_size,
                uncompressed_size,
                name_length,
                extra_length,
            ) = values
            if (
                local_signature != 0x04034B50
                or version_needed != record["version_needed"]
                or flags != record["flags"]
                or compression != record["compression"]
                or mod_time != record["mod_time"]
                or mod_date != record["mod_date"]
            ):
                raise ReleaseError("ZIP local header differs from central directory")
            raw_name = stream.read(name_length)
            extra = stream.read(extra_length)
            if raw_name != record["raw_name"] or _decode_zip_name(raw_name, flags, label="local header") != record["name"]:
                raise ReleaseError("ZIP local filename differs from central directory")
            fields = _zip_extra_fields(extra, label=f"local member {index}")
            zip64 = fields.get(0x0001, b"")
            if uncompressed_size == 0xFFFFFFFF or compressed_size == 0xFFFFFFFF:
                if len(zip64) != 16:
                    raise ReleaseError("local ZIP64 size field must contain exactly two sizes")
                local_uncompressed, local_compressed = struct.unpack("<QQ", zip64)
            else:
                if zip64:
                    raise ReleaseError("unnecessary local ZIP64 metadata")
                local_uncompressed, local_compressed = uncompressed_size, compressed_size
            if (
                crc != record["crc"]
                or local_uncompressed != record["uncompressed_size"]
                or local_compressed != record["compressed_size"]
            ):
                raise ReleaseError("ZIP local CRC/size differs from central directory")
            data_end = local_offset + 30 + name_length + extra_length + record["compressed_size"]
            if data_end != next_offset:
                raise ReleaseError("ZIP has gaps, descriptors, overlaps, or unreferenced local bytes")
    return {
        "physical_bytes": size,
        "central_offset": central_offset,
        "central_bytes": central_size,
        "members": len(records),
        "archive_comment_bytes": 0,
        "trailing_bytes": 0,
        "unreferenced_bytes": 0,
    }


def inspect_zip(
    path: Path,
    *,
    limits: ArchiveLimits,
    contract: ZipOutputContract | None = None,
) -> list[ZipMember]:
    before = file_record(path)
    physical = _physical_zip_audit(path, limits=limits, contract=contract)
    members: list[ZipMember] = []
    names: set[str] = set()
    folded: set[str] = set()
    total = 0
    try:
        with zipfile.ZipFile(path) as archive:
            if archive.comment:
                raise ReleaseError("ZIP archive comments are forbidden")
            if archive.testzip() is not None:
                raise ReleaseError("ZIP CRC test failed")
            for info in archive.infolist():
                if len(members) >= limits.max_members:
                    raise ReleaseError("ZIP member count exceeds cap")
                name = _member_name(info.filename, limits=limits)
                key = _collision_key(name)
                if name in names or key in folded:
                    raise ReleaseError(f"duplicate/case/NFC-colliding ZIP member: {name!r}")
                names.add(name)
                folded.add(key)
                if info.flag_bits & 0x1:
                    raise ReleaseError(f"encrypted ZIP member is forbidden: {name!r}")
                if info.comment:
                    raise ReleaseError(f"ZIP member comment is forbidden: {name!r}")
                _zip_extra_fields(info.extra, label=f"logical member {name}")
                mode = (info.external_attr >> 16) & 0xFFFF
                kind_bits = stat.S_IFMT(mode)
                directory = info.is_dir()
                if directory:
                    if kind_bits not in {0, stat.S_IFDIR} or info.file_size != 0:
                        raise ReleaseError(f"invalid ZIP directory: {name!r}")
                    kind = "directory"
                    permissions = stat.S_IMODE(mode) or 0o555
                else:
                    if kind_bits not in {0, stat.S_IFREG}:
                        raise ReleaseError(f"symlink/special ZIP member is forbidden: {name!r}")
                    kind = "file"
                    permissions = stat.S_IMODE(mode) or 0o444
                if info.file_size < 0 or info.compress_size < 0 or info.file_size > limits.max_file_bytes:
                    raise ReleaseError(f"ZIP member size is invalid: {name!r}")
                total += info.file_size
                if total > limits.max_total_bytes:
                    raise ReleaseError("ZIP declared bytes exceed cap")
                member_sha256: str | None = None
                if not directory:
                    with archive.open(info) as stream:
                        size, member_sha256 = sha256_stream(stream, limit=info.file_size)
                    if size != info.file_size:
                        raise ReleaseError(f"ZIP member size changed while reading: {name!r}")
                if contract is not None:
                    expected_mode = contract.mode_for(name, kind)
                    expected_version = 20 if directory else 45
                    expected_attributes = (
                        ((stat.S_IFDIR | expected_mode) << 16) | 0x10
                        if directory
                        else (stat.S_IFREG | expected_mode) << 16
                    )
                    if (
                        info.date_time != _zip_datetime(contract.epoch)
                        or info.flag_bits != (0 if name.isascii() else 0x800)
                        or info.create_system != 3
                        or info.create_version != expected_version
                        or info.extract_version != expected_version
                        or info.compress_type
                        != (zipfile.ZIP_STORED if directory else zipfile.ZIP_DEFLATED)
                        or info.external_attr != expected_attributes
                    ):
                        raise ReleaseError(f"logical ZIP metadata is not canonical: {name}")
                members.append(
                    ZipMember(
                        name,
                        kind,
                        info.file_size,
                        permissions,
                        info.CRC,
                        member_sha256,
                    )
                )
    except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
        if isinstance(exc, ReleaseError):
            raise
        raise ReleaseError(f"cannot inspect ZIP {path}: {exc}") from exc
    if not members:
        raise ReleaseError("ZIP archive is empty")
    if physical["members"] != len(members) or file_record(path) != before:
        raise ReleaseError("ZIP changed during physical/logical audit")
    return members


def safe_extract_zip(
    path: Path,
    destination_parent: Path,
    *,
    limits: ArchiveLimits,
    contract: ZipOutputContract | None = None,
) -> Path:
    archive_before = file_record(path)
    members = inspect_zip(path, limits=limits, contract=contract)
    tops = sorted({PurePosixPath(item.name).parts[0] for item in members})
    if len(tops) != 1:
        raise ReleaseError("ZIP must contain exactly one top-level root")
    if destination_parent.exists() or destination_parent.is_symlink():
        raise ReleaseError(f"fresh extraction parent already exists: {destination_parent}")
    destination_parent.mkdir(parents=True)
    with zipfile.ZipFile(path) as archive:
        actual = {(_member_name(info.filename, limits=limits)): info for info in archive.infolist()}
        if set(actual) != {item.name for item in members}:
            raise ReleaseError("ZIP changed between inspection and extraction")
        for item in members:
            target = destination_parent / item.name
            if item.kind == "directory":
                target.mkdir(parents=True, exist_ok=False)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            for parent in target.parents:
                if parent == destination_parent:
                    break
                if parent.is_symlink():
                    raise ReleaseError(f"symlink parent during extraction: {item.name}")
            with archive.open(actual[item.name]) as source, target.open("xb") as output:
                size = 0
                while True:
                    block = source.read(1024 * 1024)
                    if not block:
                        break
                    size += len(block)
                    if size > item.size:
                        raise ReleaseError(f"ZIP member expanded beyond declaration: {item.name}")
                    output.write(block)
                if size != item.size:
                    raise ReleaseError(f"ZIP member truncated during extraction: {item.name}")
            target.chmod(item.mode)
    for item in sorted(
        (member for member in members if member.kind == "directory"),
        key=lambda member: len(PurePosixPath(member.name).parts),
        reverse=True,
    ):
        (destination_parent / item.name).chmod(item.mode)
    second_members = inspect_zip(path, limits=limits, contract=contract)
    if file_record(path) != archive_before or second_members != members:
        raise ReleaseError("ZIP archive/member metadata changed during extraction")
    for item in members:
        target = destination_parent / item.name
        if item.kind == "directory":
            if not target.is_dir() or target.is_symlink():
                raise ReleaseError(f"extracted ZIP directory metadata differs: {item.name}")
            continue
        if not target.is_file() or target.is_symlink():
            raise ReleaseError(f"extracted ZIP file metadata differs: {item.name}")
        data_record = file_record(target)
        with target.open("rb") as stream:
            crc = 0
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                crc = zlib.crc32(block, crc)
        if (
            data_record["bytes"] != item.size
            or data_record["sha256"] != item.sha256
            or crc & 0xFFFFFFFF != item.crc32
        ):
            raise ReleaseError(f"extracted ZIP content snapshot differs: {item.name}")
    return destination_parent / tops[0]


def pe_identity(path: Path) -> dict[str, Any]:
    """Read enough PE metadata to reject non-AMD64/non-PE32+ payloads."""

    try:
        with path.open("rb") as stream:
            if stream.read(2) != b"MZ":
                raise ReleaseError(f"not a PE file: {path.name}")
            stream.seek(0x3C)
            offset_data = stream.read(4)
            if len(offset_data) != 4:
                raise ReleaseError(f"truncated DOS header: {path.name}")
            offset = struct.unpack("<I", offset_data)[0]
            if offset < 64 or offset > min(path.stat().st_size - 26, 16 * 1024**2):
                raise ReleaseError(f"invalid PE header offset: {path.name}")
            stream.seek(offset)
            if stream.read(4) != b"PE\0\0":
                raise ReleaseError(f"missing PE signature: {path.name}")
            coff = stream.read(20)
            if len(coff) != 20:
                raise ReleaseError(f"truncated COFF header: {path.name}")
            machine, sections, timestamp, _, _, optional_size, characteristics = struct.unpack("<HHIIIHH", coff)
            optional = stream.read(optional_size)
            if len(optional) != optional_size or optional_size < 152:
                raise ReleaseError(f"truncated PE optional header: {path.name}")
            magic = struct.unpack_from("<H", optional, 0)[0]
            security_offset, security_size = struct.unpack_from("<II", optional, 144)
    except OSError as exc:
        raise ReleaseError(f"cannot inspect PE file {path}: {exc}") from exc
    if machine != 0x8664 or magic != 0x20B:
        raise ReleaseError(f"PE is not AMD64 PE32+: {path.name}")
    return {
        "path": path.name,
        "machine": "AMD64",
        "format": "PE32+",
        "sections": sections,
        "coff_timestamp": timestamp,
        "optional_header_bytes": optional_size,
        "characteristics": characteristics,
        "authenticode_embedded": bool(security_offset and security_size),
        "authenticode_file_offset": security_offset,
        "authenticode_bytes": security_size,
        **file_record(path),
    }


def evidence_envelope(
    identity: dict[str, Any],
    *,
    identity_hash: str,
    record: dict[str, Any],
    observations: dict[str, Any],
) -> dict[str, Any]:
    if not isinstance(identity_hash, str) or HEX_256.fullmatch(identity_hash) is None:
        raise ReleaseError("evidence identity hash is invalid")
    if not isinstance(observations, dict) or not observations:
        raise ReleaseError("evidence observations must be a non-empty mapping")
    if record.get("schema") not in REQUIRED_EVIDENCE_GATES.values():
        raise ReleaseError("evidence record has an unregistered schema")
    generator = record.get("generator")
    if not isinstance(generator, dict):
        raise ReleaseError("evidence record has no checked generator contract")
    payload = {
        "schema": generator["payload_schema"],
        "result": "pass",
        **observations,
    }
    validate_evidence_observations(record["gate"], payload, identity)
    return {
        "schema": record["schema"],
        "result": "pass",
        "release_identity_sha256": identity_hash,
        "subject": release_subject(identity),
        "execution": {
            "script": generator["script"],
            "argv": generator["argv"],
            "cwd": generator["cwd"],
            "environment": generator["environment"],
            "timeout_seconds": generator["timeout_seconds"],
            "tool": generator["tool"],
            "source_boundary": generator["source_boundary"],
            "dependencies": generator["dependencies"],
            "source": {
                "commit": identity["source_commit"],
                "tree": identity["source_tree"],
                "origin": identity["source_origin"],
                "ref": identity["source_ref"],
            },
            "exit_code": 0,
        },
        "coverage": generator["required_coverage"],
        "observations": payload,
    }


def _validate_clean_windows_runtime_provenance(value: Any) -> None:
    if not isinstance(value, dict):
        raise ReleaseError("runtime provenance observation must be an object")
    if (
        value.get("official") is not True
        or value.get("verified") is not True
        or value.get("non_official_reasons") != []
    ):
        raise ReleaseError("runtime provenance is not a clean official run")
    environment = value.get("environment")
    if not isinstance(environment, dict):
        raise ReleaseError("runtime provenance has no environment record")
    if environment.get("PATH") != {
        "ambient_present": True,
        "ambient_untrusted": False,
        "removed_from_helper_environment": True,
    }:
        raise ReleaseError("runtime provenance does not prove a trusted startup PATH")
    for name in FORBIDDEN_LOADER_ENVIRONMENT:
        if environment.get(name) != {
            "ambient_present": False,
            "removed_from_helper_environment": True,
            "sha256": None,
        }:
            raise ReleaseError(
                f"runtime provenance does not prove a clean helper environment for {name}"
            )
    if environment.get(GLIBC_TUNABLES_VARIABLE) != {
        "ambient_present": False,
        "removed_from_helper_environment": True,
        "sha256": None,
    }:
        raise ReleaseError("runtime provenance does not prove clean GLIBC_TUNABLES")
    if environment.get("loader_policy") != {
        "schema": "qazmorph-native-helper-loader-environment-v2",
        "captured_name_policy": {
            "exact_uppercase_prefixes": ["LD_", "DYLD_"],
            "exact_names": ["GLIBC_TUNABLES"],
        },
        "ambient_records": {},
        "glibc_tunables": {
            "ambient_present": False,
            "removed_from_helper_environment": True,
            "sha256": None,
        },
        "clean_parent_startup": True,
        "all_ambient_values_removed_from_helper_environment": True,
        "linux_helper_ld_library_path": None,
    }:
        raise ReleaseError("runtime provenance loader policy is not the clean Windows schema")


def _validate_windows_dll_denial(dll_value: Any, helper_value: Any) -> None:
    if not isinstance(dll_value, dict) or not isinstance(helper_value, dict):
        raise ReleaseError("DLL/helper denial observations must be objects")
    expected_normal = [
        {"command": command, "returncode": 0}
        for command in WINDOWS_RUNTIME_COMMANDS
    ]
    if (
        dll_value.get("result") != "pass"
        or dll_value.get("normal_adjacent_closure_success") is not True
        or dll_value.get("normal_adjacent_commands") != expected_normal
    ):
        raise ReleaseError("normal adjacent runtime closure was not executed exactly")
    records = dll_value.get("dlls")
    if not isinstance(records, list) or len(records) != len(WINDOWS_RUNTIME_DLLS):
        raise ReleaseError("DLL denial did not cover the exact bound runtime closure")
    seen: set[str] = set()
    for record in records:
        if not isinstance(record, dict) or set(record) != {
            "dll",
            "command",
            "missing_returncode",
            "path_injection_returncode",
            "cwd_injection_returncode",
        }:
            raise ReleaseError("DLL denial record fields differ")
        if record["dll"] not in WINDOWS_RUNTIME_DLLS or record["dll"] in seen:
            raise ReleaseError("DLL denial inventory differs or contains duplicates")
        seen.add(record["dll"])
        if record["command"] not in WINDOWS_RUNTIME_COMMANDS:
            raise ReleaseError("DLL denial used an unbound helper command")
        for field in (
            "missing_returncode",
            "path_injection_returncode",
            "cwd_injection_returncode",
        ):
            if type(record[field]) is not int or record[field] == 0:
                raise ReleaseError("DLL denial accepted a missing/fallback dependency")
    if seen != set(WINDOWS_RUNTIME_DLLS):
        raise ReleaseError("DLL denial omitted a bound runtime DLL")
    if set(helper_value) != {
        "result",
        "helper",
        "path_substitution_used",
        "cwd_substitution_used",
        "path_denial_returncode",
        "cwd_denial_returncode",
        "normal_adjacent_returncode",
    }:
        raise ReleaseError("helper denial record fields differ")
    if (
        helper_value["result"] != "pass"
        or helper_value["helper"] != "usr/bin/hfst-proc.exe"
        or helper_value["path_substitution_used"] is not False
        or helper_value["cwd_substitution_used"] is not False
        or type(helper_value["path_denial_returncode"]) is not int
        or helper_value["path_denial_returncode"] == 0
        or type(helper_value["cwd_denial_returncode"]) is not int
        or helper_value["cwd_denial_returncode"] == 0
        or type(helper_value["normal_adjacent_returncode"]) is not int
        or helper_value["normal_adjacent_returncode"] != 0
    ):
        raise ReleaseError("helper PATH/cwd denial did not pass")


def _validate_windows_timeout_reap(value: Any) -> None:
    if not isinstance(value, dict) or set(value) != {
        "result",
        "root_pid",
        "observed_bundle_processes_before_kill",
        "returncode_after_taskkill_tree",
        "lingering_bundle_processes",
    }:
        raise ReleaseError("timeout process-tree receipt fields differ")
    if (
        value["result"] != "pass"
        or type(value["root_pid"]) is not int
        or value["root_pid"] <= 0
        or type(value["observed_bundle_processes_before_kill"]) is not int
        or value["observed_bundle_processes_before_kill"] <= 0
        or type(value["returncode_after_taskkill_tree"]) is not int
        or value["returncode_after_taskkill_tree"] == 0
        or value["lingering_bundle_processes"] != []
    ):
        raise ReleaseError("timeout process tree was not observed and fully reaped")


def _validate_source_suite_ledger(value: Any) -> None:
    if not isinstance(value, dict) or set(value) != {
        "schema", "result", "import", "discovery", "run", "successes",
        "skips", "expected_failures", "unexpected", "tests_run",
        "runner_output", "discovery_order_equals_run_order",
    }:
        raise ReleaseError("source-suite ledger fields differ")
    if (
        value["schema"] != "kazstem-source-suite-test-ledger-v1"
        or value["result"] != "pass"
        or value["discovery_order_equals_run_order"] is not True
        or type(value["tests_run"]) is not int
        or value["tests_run"] <= 0
    ):
        raise ReleaseError("source-suite ledger did not pass")

    def count(record: Any, label: str) -> int:
        if (
            not isinstance(record, dict)
            or set(record) != {"count", "sha256", "values"}
            or type(record["count"]) is not int
            or record["count"] < 0
            or not isinstance(record["values"], list)
            or record["count"] != len(record["values"])
            or not isinstance(record["sha256"], str)
            or HEX_256.fullmatch(record["sha256"]) is None
            or record["sha256"] != canonical_hash(record["values"])
        ):
            raise ReleaseError(f"source-suite {label} record is invalid")
        return record["count"]

    discovered = count(value["discovery"], "discovery")
    run = count(value["run"], "run")
    successes = count(value["successes"], "successes")
    skips = count(value["skips"], "skips")
    expected_failures = count(value["expected_failures"], "expected failures")
    if (
        discovered != run
        or run != value["tests_run"]
        or value["discovery"]["sha256"] != value["run"]["sha256"]
        or successes + skips + expected_failures != run
    ):
        raise ReleaseError("source-suite discovery/run/result partition differs")
    unexpected = value["unexpected"]
    if not isinstance(unexpected, dict) or set(unexpected) != {
        "failures", "errors", "unexpected_successes"
    }:
        raise ReleaseError("source-suite unexpected-result fields differ")
    if any(count(unexpected[name], name) for name in sorted(unexpected)):
        raise ReleaseError("source-suite has unexpected test outcomes")
    output = value["runner_output"]
    if output != {
        "published": False,
        "reason": "raw unittest text omitted because it contains a nondeterministic duration",
    }:
        raise ReleaseError("source-suite runner output record is invalid")


def validate_evidence_observations(
    gate: str, observations: dict[str, Any], identity: dict[str, Any]
) -> None:
    fields: dict[str, set[str]] = {
        "archive-reproducibility": {
            "ready_run", "corresponding_source", "assembly_root_proof",
            "ready_run_byte_identical", "corresponding_source_byte_identical",
        },
        "authenticode": {"host", "all_unsigned", "smartscreen_warning_possible", "files"},
        "binary-archive-audit": {
            "archive", "top_level", "members", "pe_files", "runtime_files",
            "runtime_system_libraries", "authenticode", "smartscreen_warning_possible",
            "forbidden_runtime_files", "embedded_source_archives",
            "extracted_tree_before", "extracted_tree_after",
        },
        "compatibility-performance": {
            "host", "cases", "behavior_fingerprint", "coverage", "profiles", "matrix_file",
        },
        "dll-denial": {"dll_denial", "helper_path_denial", "matrix_file"},
        "fresh-extract-practical": {
            "root", "host", "cases", "results", "profiles", "behavior_fingerprint",
            "coverage", "runtime_provenance", "dll_denial", "helper_path_denial",
            "bundle_content_fingerprint_unchanged", "lingering_bundle_processes",
            "timeout_reap", "network_tls_neural_assets_absent",
            "network_tls_neural_absence_inventory",
        },
        "host-identity": {"runner", "host"},
        "optimization": {
            "selection_rule", "behavior_sha256", "selected", "selected_raw_tree",
            "selected_final_zip", "selected_full_regression", "candidates",
            "two_independent_assemblies_per_candidate", "python_optimization", "upx",
        },
        "process-cleanup": {
            "lingering_bundle_processes", "timeout_reap",
            "bundle_content_fingerprint_unchanged", "matrix_file",
        },
        "python-artifact-reproducibility": {
            "build_receipts", "wheel", "sdist", "frozen_tree", "base_ledger", "root_proof",
        },
        "runtime-provenance": {"runtime_provenance", "matrix_file"},
        "source-archive-audit": {
            "archive", "top_level", "outer_members", "application_tree", "components",
            "windows_locked_inputs", "nested_archives", "cpython_source_present",
            "pyinstaller_source_present", "openssl_source_component_present",
            "outer_symlinks", "outer_hardlinks", "outer_special_entries",
            "extracted_tree_before", "extracted_tree_after",
        },
        "source-suite": {
            "source", "payload_tree", "canonical_receipt",
            "materialization_execution_receipts", "process_supervisor",
            "wheel_install", "import_proofs",
            "unit_suite", "optimized_python_denial",
        },
    }
    expected = {"schema", "result", *fields[gate]}
    _exact(observations, expected, f"{gate} observations")
    if observations["result"] != "pass":
        raise ReleaseError(f"{gate} observations did not pass")
    if gate == "archive-reproducibility":
        if (
            observations["ready_run"] != identity["artifacts"]["ready_run"]
            or observations["corresponding_source"] != identity["artifacts"]["corresponding_source"]
            or observations["ready_run_byte_identical"] is not True
            or observations["corresponding_source_byte_identical"] is not True
            or observations["assembly_root_proof"] != {
                "logical_labels": ["a", "b"],
                "distinct_nonnested_nonaliased": True,
            }
        ):
            raise ReleaseError("archive reproducibility observations differ from the release")
    elif gate == "authenticode":
        if (
            observations["all_unsigned"] is not True
            or observations["smartscreen_warning_possible"] is not True
            or not isinstance(observations["files"], list)
            or not observations["files"]
            or any(value.get("status") != "NotSigned" or value.get("embedded_certificate_table") is not False for value in observations["files"])
        ):
            raise ReleaseError("Authenticode observations do not prove every PE is unsigned")
    elif gate == "binary-archive-audit":
        if (
            observations["archive"] != identity["artifacts"]["ready_run"]
            or observations["forbidden_runtime_files"] != []
            or observations["embedded_source_archives"] != []
            or observations["smartscreen_warning_possible"] is not True
            or observations["extracted_tree_before"] != observations["extracted_tree_after"]
        ):
            raise ReleaseError("binary archive observations are incomplete")
    elif gate == "source-archive-audit":
        if (
            observations["archive"] != identity["artifacts"]["corresponding_source"]
            or observations["cpython_source_present"] is not True
            or observations["pyinstaller_source_present"] is not True
            or observations["openssl_source_component_present"] is not False
            or any(observations[field] != 0 for field in ("outer_symlinks", "outer_hardlinks", "outer_special_entries"))
            or observations["extracted_tree_before"] != observations["extracted_tree_after"]
        ):
            raise ReleaseError("source archive observations are incomplete")
    elif gate == "fresh-extract-practical":
        _validate_clean_windows_runtime_provenance(
            observations["runtime_provenance"]
        )
        _validate_windows_dll_denial(
            observations["dll_denial"], observations["helper_path_denial"]
        )
        _validate_windows_timeout_reap(observations["timeout_reap"])
        if (
            observations["cases"] != len(observations["results"])
            or observations["bundle_content_fingerprint_unchanged"] is not True
            or observations["lingering_bundle_processes"] != []
            or observations["network_tls_neural_assets_absent"] is not True
        ):
            raise ReleaseError("fresh-extract practical observations are incomplete")
    elif gate == "host-identity":
        if (
            observations["runner"].get("label") != identity["platform"]["runner"]
            or observations["runner"].get("runner_os") != "Windows"
            or observations["runner"].get("runner_arch") != "X64"
            or observations["host"].get("python") != identity["platform"]["python"]
            or observations["host"].get("pointer_bits") != 64
            or observations["host"].get("machine", "").casefold() not in {"amd64", "x86_64"}
        ):
            raise ReleaseError("host identity observations differ from the Windows contract")
    elif gate in {"compatibility-performance", "dll-denial", "process-cleanup", "runtime-provenance"}:
        matrix_file = evidence_record(identity, "fresh-extract-practical")["file"]
        if observations["matrix_file"] != matrix_file:
            raise ReleaseError(f"{gate} is not derived from the exact practical matrix")
        if gate == "dll-denial":
            _validate_windows_dll_denial(
                observations["dll_denial"], observations["helper_path_denial"]
            )
        if gate == "process-cleanup" and (
            observations["lingering_bundle_processes"] != []
            or observations["bundle_content_fingerprint_unchanged"] is not True
        ):
            raise ReleaseError("process cleanup observations did not pass")
        if gate == "process-cleanup":
            _validate_windows_timeout_reap(observations["timeout_reap"])
        if gate == "runtime-provenance":
            _validate_clean_windows_runtime_provenance(
                observations["runtime_provenance"]
            )
        if gate == "compatibility-performance":
            profiles = observations["profiles"]
            startup = profiles.get("startup", {}) if isinstance(profiles, dict) else {}
            large = profiles.get("large_workload", []) if isinstance(profiles, dict) else []
            if (
                startup.get("runs") != identity["performance"]["startup_runs"]
                or startup.get("median_seconds", float("inf"))
                > identity["performance"]["startup_median_seconds_max"]
                or len(large) != identity["performance"]["large_runs"]
                or len({value.get("output_sha256") for value in large}) != 1
                or any(
                    value.get("characters_per_second", 0)
                    < identity["performance"]["minimum_characters_per_second"]
                    or value.get("process_tree_peak_working_set_bytes") is None
                    or value["process_tree_peak_working_set_bytes"]
                    > identity["performance"]["maximum_peak_working_set_bytes"]
                    for value in large
                )
            ):
                raise ReleaseError("performance observations exceed the release contract")
    elif gate == "python-artifact-reproducibility":
        if (
            observations["wheel"] != identity["artifacts"]["wheel"]
            or observations["sdist"] != identity["artifacts"]["sdist"]
            or observations["frozen_tree"] != identity["inputs"]["frozen_tree"]
            or observations["base_ledger"] != identity["inputs"]["base_ledger"]
            or observations["root_proof"].get("distinct_nonnested_nonaliased") is not True
            or len(observations["build_receipts"]) != 2
        ):
            raise ReleaseError("Python artifact reproducibility observations differ")
    elif gate == "optimization":
        if (
            observations["selected"] != identity["optimization"]["selected"]
            or observations["selected_final_zip"] != identity["artifacts"]["ready_run"]
            or observations["selected_full_regression"] != identity["optimization"]["selected_full_regression"]
            or observations["two_independent_assemblies_per_candidate"] is not True
            or len(observations["candidates"]) != len(identity["optimization"]["candidates"])
        ):
            raise ReleaseError("optimization observations differ from the selected final ZIP")
    elif gate == "source-suite":
        wheel_install = observations["wheel_install"]
        import_proofs = observations["import_proofs"]
        unit_suite = observations["unit_suite"]
        if isinstance(unit_suite, dict):
            _validate_source_suite_ledger(unit_suite.get("ledger"))
        if (
            observations["source"] != {
                "commit": identity["source_commit"], "tree": identity["source_tree"],
                "origin": identity["source_origin"], "ref": identity["source_ref"],
            }
            or observations["payload_tree"] != identity["inputs"]["source_payload_tree"]
            or observations["canonical_receipt"] != identity["inputs"]["source_receipt"]
            or len(observations["materialization_execution_receipts"]) != 2
            or observations["process_supervisor"] != {
                "implementation": "windows-job-object-kill-on-close",
                "source": next(
                    value["file"]
                    for value in identity["inputs"]["release_support_files"]
                    if value["path"] == "packaging/windows/bounded_windows_process.py"
                ),
                "launch_order": "create-suspended-assign-job-start-reader-resume",
                "active_processes_zero_before_return": True,
                "descendants_after_direct_exit_fail": True,
                "timeout_and_overflow_reap_job": True,
            }
            or not isinstance(wheel_install, dict)
            or wheel_install.get("wheel") != identity["artifacts"]["wheel"]
            or wheel_install.get("exit_code") != 0
            or wheel_install.get("installed_tree_unchanged_after_tests") is not True
            or wheel_install.get("argv") != [
                "<PYTHON>", "-m", "pip", "install", "--no-index",
                "--no-deps", "--no-compile", "--disable-pip-version-check",
                "--target", "<SOURCE-SUITE-INSTALL-ROOT>/site", "<WHEEL>",
            ]
            or not isinstance(import_proofs, dict)
            or import_proofs.get("identical") is not True
            or import_proofs.get("current_process") != import_proofs.get("isolated_child")
            or import_proofs.get("current_process", {}).get("distribution_version") != identity["release"]
            or import_proofs.get("current_process", {}).get("public_version") != identity["release"]
            or import_proofs.get("child_exit_code") != 0
            or not isinstance(unit_suite, dict)
            or unit_suite.get("exit_code") != 0
            or unit_suite.get("tests") != unit_suite.get("ledger", {}).get("tests_run")
            or unit_suite.get("argv") != [
                *release_bootstrap_prefix(
                    identity, "packaging/windows/source_suite_runner.py"
                ),
                "--source", "<MATERIALIZED-SOURCE>",
                "--site", "<SOURCE-SUITE-INSTALL-ROOT>/site",
                "--json", "<SOURCE-SUITE-INSTALL-ROOT>/TEST-LEDGER.json",
            ]
            or unit_suite.get("cwd") != "<MATERIALIZED-SOURCE>"
            or unit_suite.get("bootstrap") != next(
                value["file"]
                for value in identity["inputs"]["release_support_files"]
                if value["path"] == "packaging/windows/release_bootstrap.py"
            )
            or unit_suite.get("fresh_external_pycache_empty_after_exit") is not True
            or observations["optimized_python_denial"].get("exit_code_nonzero") is not True
        ):
            raise ReleaseError("source-suite observations are incomplete")
def verify_evidence_file(
    path: Path,
    *,
    record: dict[str, Any],
    identity: dict[str, Any],
    identity_hash: str,
) -> None:
    verify_file(path, record["file"], label=f"evidence {record['gate']}")
    value = read_json(path)
    if not isinstance(value, dict) or set(value) != EVIDENCE_FIELDS:
        raise ReleaseError(f"evidence envelope fields differ: {path}")
    if (
        value["schema"] != record["schema"]
        or value["result"] != "pass"
        or value["release_identity_sha256"] != identity_hash
        or value["subject"] != release_subject(identity)
        or canonical_hash(value["subject"]) != record["subject_sha256"]
    ):
        raise ReleaseError(f"evidence subject/schema/result differs: {path}")
    generator = record["generator"]
    expected_execution = {
        "script": generator["script"],
        "argv": generator["argv"],
        "cwd": generator["cwd"],
        "environment": generator["environment"],
        "timeout_seconds": generator["timeout_seconds"],
        "tool": generator["tool"],
        "source_boundary": generator["source_boundary"],
        "dependencies": generator["dependencies"],
        "source": {
            "commit": identity["source_commit"],
            "tree": identity["source_tree"],
            "origin": identity["source_origin"],
            "ref": identity["source_ref"],
        },
        "exit_code": 0,
    }
    if value["execution"] != expected_execution:
        raise ReleaseError(f"evidence execution receipt is incomplete: {path}")
    if value["coverage"] != generator["required_coverage"]:
        raise ReleaseError(f"evidence coverage is incomplete: {path}")
    observations = value["observations"]
    if (
        not isinstance(observations, dict)
        or observations.get("schema") != generator["payload_schema"]
        or observations.get("result") != "pass"
        or len(observations) <= 2
    ):
        raise ReleaseError(f"evidence observations are empty: {path}")
    validate_evidence_observations(record["gate"], observations, identity)


def compare_distinct_roots(first: Path, second: Path) -> dict[str, Any]:
    a = first.resolve(strict=True)
    b = second.resolve(strict=True)
    if a == b or a in b.parents or b in a.parents:
        raise ReleaseError("build roots are equal or nested")
    try:
        if a.samefile(b):
            raise ReleaseError("build roots alias the same filesystem object")
    except OSError as exc:
        raise ReleaseError(f"cannot compare build roots: {exc}") from exc
    first_record = tree_record(a)
    second_record = tree_record(b)
    if first_record != second_record:
        raise ReleaseError("distinct build roots are not byte-identical")
    return {"first": a.name, "second": b.name, "tree": first_record}
