#!/usr/bin/env python3
"""Strict, location-independent primitives for Linux release tooling."""

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
import platform
import re
import shutil
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import types
from typing import Any, BinaryIO, Iterable
import unicodedata
from urllib.parse import unquote, urlsplit
import zipfile


def _source_shared_module(name: str, path: Path) -> types.ModuleType:
    module = types.ModuleType(name)
    module.__file__ = str(path)
    sys.modules[name] = module
    source = path.read_bytes()
    exec(compile(source, str(path), "exec", dont_inherit=True), module.__dict__)
    return module


_process_supervisor = _source_shared_module(
    "_kazstem_release_common_process_supervisor",
    Path(__file__).resolve().parent.parent / "process_supervisor.py",
)
SupervisionError = _process_supervisor.SupervisionError
PaxFormatError = _process_supervisor.PaxFormatError
parse_pax_records = _process_supervisor.parse_pax_records
run_bounded = _process_supervisor.run_bounded


IDENTITY_SCHEMA = "kazstem-linux-release-identity-v2"
READY_AUDIT_SCHEMA = "kazstem-linux-ready-run-archive-audit-v2"
SOURCE_AUDIT_SCHEMA = "kazstem-linux-corresponding-source-audit-v2"
SOURCE_AUTHORITY_SCHEMA = "kazstem-linux-remote-tag-authority-v1"
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
UNNEEDED_OPENSSL_FRAGMENTS = frozenset(
    {"_hashlib", "_ssl", "libcrypto", "libssl", "openssl"}
)
TAR_CONTAINER_SUFFIXES = {"gzip": ".tar.gz", "xz": ".tar.xz"}
TAR_CANDIDATE_SUFFIXES = {**TAR_CONTAINER_SUFFIXES, "zstd": ".tar.zst"}
REQUIRED_EVIDENCE_GATES = {
    gate: "envelope"
    for gate in (
        "blackbox",
        "compatibility-performance",
        "compression-comparison",
        "elf-closure",
        "network-trace",
        "optimization-ledger",
        "practical",
        "python-reproducibility",
        "ready-archive-audit",
        "runtime-provenance",
        "source-archive-audit",
        "source-authority",
        "source-suite",
    )
}
GATE_SUBJECTS = {
    "blackbox": ["ready_run"],
    "compatibility-performance": ["ready_run"],
    "compression-comparison": ["corresponding_source", "ready_run"],
    "elf-closure": ["ready_run"],
    "network-trace": ["ready_run"],
    "optimization-ledger": ["corresponding_source", "ready_run"],
    "practical": ["ready_run"],
    "python-reproducibility": [
        "corresponding_source",
        "ready_run",
        "sdist",
        "wheel",
    ],
    "ready-archive-audit": ["ready_run"],
    "runtime-provenance": ["ready_run"],
    "source-archive-audit": ["corresponding_source"],
    "source-authority": [],
    "source-suite": ["sdist", "wheel"],
}
GATE_SCRIPT_PATHS = {
    "blackbox": "packaging/linux/blackbox_linux_bundle.py",
    "compatibility-performance": "packaging/linux/benchmark_compat_linux.py",
    "compression-comparison": "packaging/linux/generate_compression_comparison.py",
    "elf-closure": "packaging/linux/audit_elf_closure.py",
    "network-trace": "packaging/linux/run_network_workload.py",
    "optimization-ledger": "packaging/linux/generate_optimization_ledger.py",
    "practical": "packaging/linux/practical_matrix_linux.py",
    "python-reproducibility": "packaging/linux/verify_python_reproducibility.py",
    "ready-archive-audit": "packaging/linux/audit_ready_run_archive.py",
    "runtime-provenance": "packaging/linux/normalize_runtime_provenance.py",
    "source-archive-audit": "packaging/linux/audit_corresponding_source_archive.py",
    "source-authority": "packaging/linux/verify_remote_tag.py",
    "source-suite": "packaging/linux/run_source_suite.py",
}
GATE_EXECUTION_ARGV = {
    "blackbox": [
        "python3", GATE_SCRIPT_PATHS["blackbox"], "{ready_root}",
        "--identity", "{identity}", "--json", "{payload}",
    ],
    "compatibility-performance": [
        "python3", GATE_SCRIPT_PATHS["compatibility-performance"], "{ready_root}",
        "--identity", "{identity}", "--output", "{payload}",
        "--characters", "220000", "--runs", "2", "--timeout", "300",
    ],
    "compression-comparison": [
        "python3", GATE_SCRIPT_PATHS["compression-comparison"],
        "--identity", "{identity}", "--repository", "{source_checkout}",
        "--artifact-dir", "{artifact_dir}", "--producer-dir", "{producer_dir}",
        "--output", "{payload}", "--timeout", "1800",
    ],
    "elf-closure": [
        "python3", GATE_SCRIPT_PATHS["elf-closure"], "{ready_root}",
        "--identity", "{identity}", "--output", "{payload}",
    ],
    "network-trace": [
        "python3", GATE_SCRIPT_PATHS["network-trace"],
        "--identity", "{identity}", "--ready-run", "{ready_run}",
        "--output", "{payload}", "--timeout", "120",
    ],
    "optimization-ledger": [
        "python3", GATE_SCRIPT_PATHS["optimization-ledger"],
        "--identity", "{identity}",
        "--compression-evidence", "{compression_evidence}",
        "--blackbox-evidence", "{blackbox_evidence}",
        "--practical-evidence", "{practical_evidence}",
        "--output", "{payload}",
    ],
    "practical": [
        "python3", GATE_SCRIPT_PATHS["practical"], "{ready_root}",
        "--identity", "{identity}", "--wheel", "{wheel}",
        "--json", "{payload}",
    ],
    "python-reproducibility": [
        "python3", GATE_SCRIPT_PATHS["python-reproducibility"],
        "--identity", "{identity}", "--repository", "{source_checkout}",
        "--canonical-artifacts", "{artifact_dir}",
        "--python-build-identity", "{python_build_identity}",
        "--python-wheelhouse", "{python_wheelhouse}",
        "--python-freezer-wheelhouse", "{python_freezer_wheelhouse}",
        "--python-interpreter-source", "{python_interpreter_source}",
        "--payload", "{source_payload}", "--resources", "{resources}",
        "--runtime", "{runtime}", "--documents", "{documents}",
        "--binary-readme-template", "{binary_readme_template}",
        "--source-readme-template", "{source_readme_template}",
        "--base-ledger", "{base_ledger}", "--workspace", "{work}",
        "--output", "{payload}",
    ],
    "ready-archive-audit": [
        "python3", GATE_SCRIPT_PATHS["ready-archive-audit"], "{ready_run}",
        "--identity", "{identity}", "--fresh-root", "{fresh_root}",
        "--output", "{payload}",
    ],
    "runtime-provenance": [
        "python3", GATE_SCRIPT_PATHS["runtime-provenance"],
        "--identity", "{identity}", "--bundle-root", "{ready_root}",
        "--input", "{runtime_provenance_raw}", "--output", "{payload}",
    ],
    "source-archive-audit": [
        "python3", GATE_SCRIPT_PATHS["source-archive-audit"],
        "{corresponding_source}", "--identity", "{identity}",
        "--fresh-root", "{fresh_root}", "--output", "{payload}",
    ],
    "source-authority": [
        "python3", GATE_SCRIPT_PATHS["source-authority"],
        "--identity", "{identity}", "--output", "{payload}",
    ],
    "source-suite": [
        "python3", GATE_SCRIPT_PATHS["source-suite"],
        "--identity", "{identity}", "--wheel", "{wheel}",
        "--sdist", "{sdist}",
        "--pip-wheelhouse", "{python_freezer_wheelhouse}",
        "--output", "{payload}",
    ],
}
GATE_LOGICAL_INPUTS = {
    "{artifact_dir}": "inputs/artifact-dir",
    "{base_ledger}": "inputs/base-ledger",
    "{binary_readme_template}": "inputs/binary-readme-template",
    "{blackbox_evidence}": "inputs/blackbox-evidence",
    "{compression_evidence}": "inputs/compression-evidence",
    "{documents}": "inputs/documents",
    "{fresh_root}": "gate-work/auditor-fresh-root",
    "{practical_evidence}": "inputs/practical-evidence",
    "{producer_dir}": "inputs/producer-dir",
    "{python_build_identity}": "inputs/python-build-identity",
    "{python_freezer_wheelhouse}": "inputs/python-freezer-wheelhouse",
    "{python_interpreter_source}": "inputs/python-interpreter-source",
    "{python_wheelhouse}": "inputs/python-wheelhouse",
    "{ready_root}": "prepared/ready-run-root",
    "{resources}": "inputs/resources",
    "{runtime}": "inputs/runtime",
    "{runtime_provenance_raw}": "inputs/runtime-provenance-raw",
    "{source_checkout}": "source-checkout",
    "{source_payload}": "inputs/source-payload",
    "{source_readme_template}": "inputs/source-readme-template",
    "{work}": "gate-work/python-reproducibility",
}
NETWORK_BOUNDARY_DENIED_SYSCALLS = sorted(
    {
        "accept",
        "accept4",
        "bind",
        "connect",
        "getpeername",
        "getsockname",
        "getsockopt",
        "io_uring_enter",
        "io_uring_register",
        "io_uring_setup",
        "listen",
        "ptrace",
        "recvfrom",
        "recvmmsg",
        "recvmsg",
        "sendmmsg",
        "sendmsg",
        "sendto",
        "setns",
        "setsockopt",
        "shutdown",
        "socket",
        "socketpair",
        "unshare",
    }
)


def logical_gate_argv(identity: dict[str, Any], gate: str) -> list[str]:
    """Return the one location-independent argv accepted for a release gate."""
    subjects = GATE_SUBJECTS[gate]
    result: list[str] = []
    for configured in GATE_EXECUTION_ARGV[gate]:
        value = configured.replace("{payload}", "gate-output/payload.json").replace(
            "{identity}", "release-identity.json"
        )
        for subject in subjects:
            value = value.replace(
                "{" + subject + "}",
                "artifacts/" + identity["artifacts"][subject]["filename"],
            )
        for token, replacement in GATE_LOGICAL_INPUTS.items():
            value = value.replace(token, replacement)
        result.append(value)
    return result


def logical_network_boundary(identity: dict[str, Any]) -> dict[str, Any]:
    boundary = identity["verification"]["network_boundary"]
    library_file = boundary["library"]["file"]
    wrapper_file = boundary["wrapper"]["file"]
    arguments = [
        "--library-bytes", str(library_file["bytes"]),
        "--library-sha256", library_file["sha256"],
        "--wrapper-bytes", str(wrapper_file["bytes"]),
        "--wrapper-sha256", wrapper_file["sha256"],
        "--receipt-fd", "supervisor-pipe/network-boundary",
    ]
    for name in boundary["denied_syscalls"]:
        arguments.extend(["--deny-syscall", name])
    return {
        "argv_prefix": [
            "python3",
            boundary["wrapper"]["path"],
            "--library",
            "system/libseccomp.so.2",
            *arguments,
            "--",
        ],
        "library": boundary["library"],
        "policy": {
            key: boundary[key]
            for key in (
                "clone3_action",
                "clone_untraced_mask",
                "default_action",
                "denied_syscalls",
                "deny_action",
                "no_new_privs",
                "schema",
            )
        },
        "wrapper": boundary["wrapper"],
    }
EVIDENCE_PAYLOAD_SCHEMAS = {
    "blackbox": "kazstem-linux-blackbox-v1",
    "compatibility-performance": "kazstem-linux-mystem-json-performance-v2",
    "compression-comparison": "kazstem-linux-compression-comparison-v2",
    "elf-closure": "kazstem-linux-elf-closure-v1",
    "network-trace": "kazstem-linux-network-trace-v1",
    "optimization-ledger": "kazstem-linux-final-optimization-decision-ledger-v2",
    "practical": "kazstem-linux-practical-matrix-v1",
    "python-reproducibility": "kazstem-python-artifact-reproducibility-v2",
    "ready-archive-audit": READY_AUDIT_SCHEMA,
    "runtime-provenance": "kazstem-linux-runtime-provenance-v2",
    "source-archive-audit": SOURCE_AUDIT_SCHEMA,
    "source-authority": SOURCE_AUTHORITY_SCHEMA,
    "source-suite": "kazstem-linux-source-suite-v1",
}


class ReleaseError(RuntimeError):
    """A release input or gate violated the public release contract."""


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


def _remove_placeholders(value: str, placeholders: set[str]) -> str:
    result = value
    for placeholder in sorted(placeholders):
        result = result.replace(placeholder, "")
    return result


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


def tar_container_top(filename: str, *, label: str) -> str:
    for suffix in TAR_CONTAINER_SUFFIXES.values():
        if filename.endswith(suffix):
            return filename[: -len(suffix)]
    raise ReleaseError(f"{label} must use an audited tar container suffix")


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
            "source_tag_object",
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
        not isinstance(identity["source_tag_object"], str)
        or COMMIT.fullmatch(identity["source_tag_object"]) is None
        or identity["source_tag_object"] == identity["source_commit"]
    ):
        raise ReleaseError(
            "source_tag_object must be the distinct lowercase annotated-tag object id"
        )
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
    expected_origin = (
        f"https://github.com/{release_parts[0]}/{release_parts[1]}.git"
    )
    if identity["source_origin"] != expected_origin:
        raise ReleaseError(
            "source_origin must be the exact HTTPS Git origin corresponding to release_url"
        )
    if identity["source_ref"] != f"refs/tags/v{identity['release']}":
        raise ReleaseError("source_ref must be the immutable exact release tag")

    platform = _exact_fields(
        identity["platform"],
        {"system", "machine", "label", "advertised_target", "generic_linux"},
        "platform",
    )
    if platform["system"] != "linux" or platform["machine"] != "x86_64":
        raise ReleaseError("Linux release tooling only accepts linux/x86_64")
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
    if platform["generic_linux"] is not False:
        raise ReleaseError(
            "this recipe must not advertise the Ubuntu-bound asset as generic Linux"
        )

    artifacts = _exact_fields(
        identity["artifacts"],
        {"wheel", "sdist", "ready_run", "corresponding_source"},
        "artifacts",
    )
    for name in sorted(artifacts):
        _artifact(artifacts[name], f"artifacts.{name}")
    prefix = f"kazstem-{identity['release']}-{platform['label']}"
    if tar_container_top(
        artifacts["ready_run"]["filename"], label="ready-run filename"
    ) != f"{prefix}-ready-run":
        raise ReleaseError("ready-run filename does not match release/platform")
    if tar_container_top(
        artifacts["corresponding_source"]["filename"],
        label="corresponding-source filename",
    ) != f"{prefix}-corresponding-source":
        raise ReleaseError(
            "corresponding-source filename does not match release/platform"
        )
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
            "documents",
        },
        "inputs",
    )
    _tree(inputs["frozen_tree"], "inputs.frozen_tree")
    _tree(inputs["source_payload_tree"], "inputs.source_payload_tree")
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
    for name in ("base_ledger", "binary_readme_template", "source_readme_template"):
        _file_identity(inputs[name], f"inputs.{name}")
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
            "nested_archives",
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
    expected_ready_top = tar_container_top(
        artifacts["ready_run"]["filename"], label="ready-run filename"
    )
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
    nested_ready = ready["nested_archives"]
    expected_embedded_wheel = {
        "path": f"_internal/{artifacts['wheel']['filename']}",
        "format": "zip",
        "bytes": artifacts["wheel"]["bytes"],
        "sha256": artifacts["wheel"]["sha256"],
    }
    if nested_ready != [expected_embedded_wheel]:
        raise ReleaseError("ready-run nested archive must be the exact canonical wheel")
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
    if not {"_hashlib.", "_ssl.", "libcrypto", "libssl", "openssl"} <= set(
        banned
    ):
        raise ReleaseError("ready-run must explicitly ban OpenSSL runtime/module names")

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
            "bound_source_materials",
        },
        "corresponding_source",
    )
    expected_source_top = tar_container_top(
        artifacts["corresponding_source"]["filename"],
        label="corresponding-source filename",
    )
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
    if any(
        any(fragment in path.casefold() for fragment in UNNEEDED_OPENSSL_FRAGMENTS)
        for path in required_source_paths
    ):
        raise ReleaseError("unneeded OpenSSL source is forbidden from required paths")
    if not set(
        category_paths
        + [commit_file, tree_file, origin_file, git_archive_file, epoch_file]
        + [f"{categories['application_source']}/GIT-SOURCE.json"]
        + [f"{categories['application_source']}/tree"]
    ) <= set(
        required_source_paths
    ):
        raise ReleaseError(
            "source categories and identity marker files must all be required paths"
        )
    materials = source["bound_source_materials"]
    if not isinstance(materials, list) or not materials:
        raise ReleaseError("corresponding-source bound material inventory is empty")
    material_paths: list[str] = []
    material_keys: list[tuple[str, str]] = []
    for index, value in enumerate(materials):
        material = _exact_fields(
            value,
            {"file", "path", "role", "subject"},
            f"corresponding_source.bound_source_materials[{index}]",
        )
        material_paths.append(
            portable_path(
                material["path"],
                label=f"corresponding_source.bound_source_materials[{index}].path",
            )
        )
        if material["role"] not in {"license", "source"} or (
            not isinstance(material["subject"], str) or not material["subject"]
        ):
            raise ReleaseError("corresponding-source bound material metadata is invalid")
        _file_identity(
            material["file"],
            f"corresponding_source.bound_source_materials[{index}].file",
        )
        material_keys.append((material["subject"], material["role"]))
    expected_material_subjects = {
        "freezer",
        inputs["resource_tree"]["bundle_id"],
        inputs["runtime_tree"]["bundle_id"],
    }
    if (
        material_paths != sorted(set(material_paths))
        or len(material_keys) != len(set(material_keys))
        or set(material_keys)
        != {
            (subject, role)
            for subject in expected_material_subjects
            for role in ("license", "source")
        }
        or not set(material_paths) <= set(required_source_paths)
    ):
        raise ReleaseError(
            "corresponding-source materials do not cover freezer/resource/runtime source+license pairs"
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

    limits = _exact_fields(
        identity["archive_limits"],
        {"ready_run", "corresponding_source", "nested"},
        "archive_limits",
    )
    for name in ("ready_run", "corresponding_source", "nested"):
        _limits(limits[name], f"archive_limits.{name}")

    verification = _exact_fields(
        identity["verification"],
        {
            "minimum_distinct_roots",
            "network_boundary",
            "reproducibility",
            "compression",
            "tracing",
            "evidence",
            "finalizer",
        },
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
    finalizer = _exact_fields(
        verification["finalizer"], {"file", "path"}, "verification.finalizer"
    )
    if finalizer["path"] != "packaging/linux/finalize_release.py":
        raise ReleaseError("finalizer path differs")
    _file_identity(finalizer["file"], "verification.finalizer.file")
    reproducibility = _exact_fields(
        verification["reproducibility"],
        {
            "build_roots",
            "frozen_build_argv",
            "frozen_builder",
            "native_assemblers",
            "canonical_python",
            "environment",
            "helpers",
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
        < 3
    ):
        raise ReleaseError("Python reproducibility requires at least three roots")
    environment = _exact_fields(
        reproducibility["environment"],
        {
            "LANG",
            "LC_ALL",
            "PYTHONDONTWRITEBYTECODE",
            "PYTHONPYCACHEPREFIX",
            "PYTHONHASHSEED",
            "SOURCE_DATE_EPOCH",
            "TZ",
        },
        "verification.reproducibility.environment",
    )
    expected_environment = {
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONPYCACHEPREFIX": "workspace/pycache",
        "PYTHONHASHSEED": "0",
        "SOURCE_DATE_EPOCH": str(identity["source_date_epoch"]),
        "TZ": "UTC",
    }
    if environment != expected_environment:
        raise ReleaseError(
            "verification reproducibility environment is not the canonical environment"
        )
    helpers = reproducibility["helpers"]
    if not isinstance(helpers, list) or not helpers:
        raise ReleaseError("verification.reproducibility.helpers must be non-empty")
    helper_paths: list[str] = []
    for index, value in enumerate(helpers):
        helper = _exact_fields(
            value,
            {"file", "path"},
            f"verification.reproducibility.helpers[{index}]",
        )
        helper_paths.append(
            portable_path(
                helper["path"],
                label=f"verification.reproducibility.helpers[{index}].path",
            )
        )
        _file_identity(
            helper["file"],
            f"verification.reproducibility.helpers[{index}].file",
        )
    expected_helpers = [
        "packaging/linux/release_common.py",
        "packaging/process_supervisor.py",
    ]
    if helper_paths != expected_helpers:
        raise ReleaseError("release helper bundle paths differ")
    canonical_python = _exact_fields(
        reproducibility["canonical_python"],
        {
            "builder",
            "identity",
            "interpreter_source",
            "interpreter_build_recipe",
            "interpreter_license",
            "requirements_file",
            "requirements_path",
            "runtime_packages",
            "runtime_source_packages",
            "source_companions",
            "wheelhouse_files",
            "wheelhouse_manifest_sha256",
        },
        "verification.reproducibility.canonical_python",
    )
    builder = _exact_fields(
        canonical_python["builder"],
        {"file", "path", "receipt_schema"},
        "verification.reproducibility.canonical_python.builder",
    )
    if (
        portable_path(
            builder["path"],
            label="verification.reproducibility.canonical_python.builder.path",
        )
        != "packaging/build_canonical_python_artifacts.py"
        or builder["receipt_schema"] != "kazstem-canonical-python-build-receipt-v2"
    ):
        raise ReleaseError("canonical Python builder identity differs")
    _file_identity(
        builder["file"],
        "verification.reproducibility.canonical_python.builder.file",
    )
    native_assemblers = _exact_fields(
        reproducibility["native_assemblers"],
        {"ready_run", "release_common", "source"},
        "verification.reproducibility.native_assemblers",
    )
    expected_native_paths = {
        "ready_run": "packaging/linux/assemble_ready_run.py",
        "release_common": "packaging/linux/release_common.py",
        "source": "packaging/linux/assemble_corresponding_source.py",
    }
    for name, expected_path in expected_native_paths.items():
        record = _exact_fields(
            native_assemblers[name],
            {"file", "path"},
            f"verification.reproducibility.native_assemblers.{name}",
        )
        if record["path"] != expected_path:
            raise ReleaseError("native assembler path differs")
        _file_identity(
            record["file"],
            f"verification.reproducibility.native_assemblers.{name}.file",
        )
    python_identity = _exact_fields(
        canonical_python["identity"],
        {"file", "schema"},
        "verification.reproducibility.canonical_python.identity",
    )
    if python_identity["schema"] != "kazstem-canonical-python-build-identity-v2":
        raise ReleaseError("canonical Python build identity schema differs")
    _file_identity(
        python_identity["file"],
        "verification.reproducibility.canonical_python.identity.file",
    )
    portable_path(
        canonical_python["requirements_path"],
        label="verification.reproducibility.canonical_python.requirements_path",
    )
    _sha(
        canonical_python["wheelhouse_manifest_sha256"],
        "verification.reproducibility.canonical_python.wheelhouse_manifest_sha256",
    )
    interpreter_source = _exact_fields(
        canonical_python["interpreter_source"],
        {"file", "path"},
        "verification.reproducibility.canonical_python.interpreter_source",
    )
    portable_path(
        interpreter_source["path"],
        label="verification.reproducibility.canonical_python.interpreter_source.path",
    )
    _file_identity(
        interpreter_source["file"],
        "verification.reproducibility.canonical_python.interpreter_source.file",
    )
    if interpreter_source["path"] not in identity["corresponding_source"][
        "required_paths"
    ]:
        raise ReleaseError(
            "canonical interpreter source path is not required in corresponding source"
        )
    for name in (
        "interpreter_build_recipe",
        "interpreter_license",
        "requirements_file",
    ):
        record = _exact_fields(
            canonical_python[name],
            {"file", "path"},
            f"verification.reproducibility.canonical_python.{name}",
        )
        portable_path(
            record["path"],
            label=f"verification.reproducibility.canonical_python.{name}.path",
        )
        _file_identity(
            record["file"],
            f"verification.reproducibility.canonical_python.{name}.file",
        )
    if canonical_python["requirements_file"]["path"] != canonical_python[
        "requirements_path"
    ]:
        raise ReleaseError("canonical Python requirements path/file differ")
    wheelhouse_files = canonical_python["wheelhouse_files"]
    if not isinstance(wheelhouse_files, list) or not wheelhouse_files:
        raise ReleaseError("canonical Python wheelhouse file inventory is empty")
    wheelhouse_names: list[str] = []
    for index, value in enumerate(wheelhouse_files):
        wheel_record = _exact_fields(
            value,
            {"bytes", "filename", "sha256"},
            f"canonical Python wheelhouse_files[{index}]",
        )
        wheelhouse_names.append(
            portable_path(
                wheel_record["filename"],
                label=f"canonical Python wheelhouse_files[{index}].filename",
                single=True,
            )
        )
        if not wheel_record["filename"].endswith(".whl"):
            raise ReleaseError("canonical Python wheelhouse contains a non-wheel")
        _file_identity(
            {"bytes": wheel_record["bytes"], "sha256": wheel_record["sha256"]},
            f"canonical Python wheelhouse_files[{index}]",
        )
    if wheelhouse_names != sorted(set(wheelhouse_names)) or canonical_hash(
        wheelhouse_files
    ) != canonical_python["wheelhouse_manifest_sha256"]:
        raise ReleaseError("canonical Python wheelhouse inventory/digest differs")
    for collection_name in ("runtime_packages", "runtime_source_packages"):
        collection = canonical_python[collection_name]
        if not isinstance(collection, list):
            raise ReleaseError(f"canonical Python {collection_name} is not a list")
        filenames: list[str] = []
        for index, value in enumerate(collection):
            package = _exact_fields(
                value,
                {"architecture", "file", "filename", "name", "url", "version"},
                f"canonical Python {collection_name}[{index}]",
            )
            filenames.append(
                portable_path(
                    package["filename"],
                    label=f"canonical Python {collection_name}[{index}].filename",
                    single=True,
                )
            )
            if any(
                not isinstance(package[field], str) or not package[field]
                for field in ("architecture", "name", "url", "version")
            ) or not package["url"].startswith("https://"):
                raise ReleaseError("canonical Python runtime package metadata is invalid")
            package_spelling = (
                package["name"] + " " + package["filename"]
            ).casefold()
            if any(
                fragment in package_spelling
                for fragment in UNNEEDED_OPENSSL_FRAGMENTS
            ):
                raise ReleaseError(
                    "unneeded OpenSSL package/source is forbidden from canonical inputs"
                )
            _file_identity(
                package["file"],
                f"canonical Python {collection_name}[{index}].file",
            )
        if filenames != sorted(set(filenames)):
            raise ReleaseError(f"canonical Python {collection_name} is not sorted/unique")
    companions = canonical_python["source_companions"]
    if not isinstance(companions, list) or not companions:
        raise ReleaseError("canonical Python source companion inventory is empty")
    companion_paths: list[str] = []
    companion_keys: list[tuple[str, str, str]] = []
    for index, value in enumerate(companions):
        companion = _exact_fields(
            value,
            {"file", "path", "role", "source_member", "subject"},
            f"canonical Python source_companions[{index}]",
        )
        companion_paths.append(
            portable_path(
                companion["path"],
                label=f"canonical Python source_companions[{index}].path",
            )
        )
        if (
            not isinstance(companion["role"], str)
            or SAFE_LABEL.fullmatch(companion["role"]) is None
            or not isinstance(companion["subject"], str)
            or not companion["subject"]
            or (
                companion["source_member"] is not None
                and not isinstance(companion["source_member"], str)
            )
        ):
            raise ReleaseError("canonical Python source companion metadata is invalid")
        if companion["source_member"] is not None:
            portable_path(
                companion["source_member"],
                label=f"canonical Python source_companions[{index}].source_member",
            )
        _file_identity(
            companion["file"],
            f"canonical Python source_companions[{index}].file",
        )
        companion_keys.append(
            (companion["role"], companion["subject"], companion["path"])
        )
    if (
        companion_paths != sorted(set(companion_paths))
        or len(companion_keys) != len(set(companion_keys))
    ):
        raise ReleaseError("canonical Python source companions must be sorted/unique")
    companion_by_role_subject = {
        (item["role"], item["subject"]): item
        for item in companions
        if item["role"] != "build-wheel-license"
    }
    if len(companion_by_role_subject) != len(
        [item for item in companions if item["role"] != "build-wheel-license"]
    ):
        raise ReleaseError("canonical non-license source companion is duplicated")
    mandatory = {
        ("canonical-python-identity", "identity"): canonical_python["identity"]["file"],
        ("canonical-python-requirements", "requirements"): canonical_python[
            "requirements_file"
        ]["file"],
        ("cpython-build-recipe", "cpython"): canonical_python[
            "interpreter_build_recipe"
        ]["file"],
        ("cpython-license", "cpython"): canonical_python["interpreter_license"][
            "file"
        ],
        ("cpython-source", "cpython"): canonical_python["interpreter_source"][
            "file"
        ],
    }
    for key, expected_file in mandatory.items():
        if companion_by_role_subject.get(key, {}).get("file") != expected_file:
            raise ReleaseError(f"canonical Python source companion is missing: {key}")
    for wheel_record in wheelhouse_files:
        filename = wheel_record["filename"]
        wheel_companion = companion_by_role_subject.get(
            ("build-wheel", filename)
        )
        if wheel_companion is None or wheel_companion["file"] != {
            "bytes": wheel_record["bytes"],
            "sha256": wheel_record["sha256"],
        }:
            raise ReleaseError(f"canonical wheelhouse source companion is missing: {filename}")
        if not any(
            item["role"] == "build-wheel-license" and item["subject"] == filename
            for item in companions
        ):
            raise ReleaseError(f"canonical wheelhouse license companion is missing: {filename}")
    expected_role_subjects = set(mandatory) | {
        (role, wheel_record["filename"])
        for wheel_record in wheelhouse_files
        for role in ("build-wheel", "build-wheel-license")
    }
    upstream_filename = canonical_python["interpreter_source"]["path"].rsplit("/", 1)[-1]
    for package in canonical_python["runtime_packages"]:
        expected_role_subjects.add(("interpreter-package", package["filename"]))
        item = companion_by_role_subject.get(
            ("interpreter-package", package["filename"])
        )
        if item is None or item["file"] != package["file"]:
            raise ReleaseError("interpreter binary package companion is missing")
    for package in canonical_python["runtime_source_packages"]:
        if package["filename"] == upstream_filename:
            continue
        expected_role_subjects.add(
            ("interpreter-package-source", package["filename"])
        )
        item = companion_by_role_subject.get(
            ("interpreter-package-source", package["filename"])
        )
        if item is None or item["file"] != package["file"]:
            raise ReleaseError("interpreter source package companion is missing")
    if {
        (item["role"], item["subject"]) for item in companions
    } != expected_role_subjects:
        raise ReleaseError("canonical Python source companion role inventory differs")
    for item in companions:
        if (item["role"] == "build-wheel-license") is not (
            item["source_member"] is not None
        ):
            raise ReleaseError("canonical Python companion source-member binding differs")
    if not set(companion_paths) <= set(
        identity["corresponding_source"]["required_paths"]
    ):
        raise ReleaseError("canonical Python source companions are not all required paths")
    for companion in companions:
        format_by_role = {
            "build-wheel": "zip",
            "cpython-source": "tar",
            "interpreter-package": "deb",
            "interpreter-package-source": "tar",
        }
        if (
            companion["role"] == "interpreter-package-source"
            and companion["path"].endswith(".dsc")
        ):
            continue
        if companion["role"] not in format_by_role:
            continue
        expected_format = format_by_role[companion["role"]]
        if nested_by_path.get(companion["path"]) != {
            "path": companion["path"],
            "format": expected_format,
            **companion["file"],
        }:
            raise ReleaseError(
                f"nested archive inventory omits canonical source companion: {companion['path']}"
            )
    frozen_builder = _exact_fields(
        reproducibility["frozen_builder"],
        {
            "bootstrap",
            "bootstrap_pip",
            "build_argv",
            "environment",
            "file",
            "packages",
            "path",
            "process_supervisor",
            "provision_argv",
            "python_optimize",
            "receipt_schema",
            "release_common",
            "requirements",
            "source_companions",
            "source_packages",
            "spec",
            "timeout_seconds",
            "wheelhouse",
        },
        "verification.reproducibility.frozen_builder",
    )
    portable_path(
        frozen_builder["path"],
        label="verification.reproducibility.frozen_builder.path",
    )
    _file_identity(
        frozen_builder["file"],
        "verification.reproducibility.frozen_builder.file",
    )
    if (
        frozen_builder["path"] != "packaging/linux/build_frozen_from_wheel.py"
        or frozen_builder["receipt_schema"]
        != "kazstem-frozen-wheel-consumption-receipt-v2"
    ):
        raise ReleaseError("frozen builder receipt schema differs")
    for name, expected_path in {
        "bootstrap": "packaging/linux/frozen_wheel_entrypoint.py",
        "process_supervisor": "packaging/process_supervisor.py",
        "release_common": "packaging/linux/release_common.py",
        "requirements": "packaging/linux/python-freezer-requirements.lock",
        "spec": "packaging/linux/kazstem-minimal.spec",
    }.items():
        item = _exact_fields(
            frozen_builder[name],
            {"file", "path"},
            f"verification.reproducibility.frozen_builder.{name}",
        )
        if item["path"] != expected_path:
            raise ReleaseError(f"frozen builder {name} path differs")
        _file_identity(
            item["file"],
            f"verification.reproducibility.frozen_builder.{name}.file",
        )
    freezer_wheelhouse = _exact_fields(
        frozen_builder["wheelhouse"],
        {"files", "manifest_sha256"},
        "verification.reproducibility.frozen_builder.wheelhouse",
    )
    freezer_wheels = freezer_wheelhouse["files"]
    if not isinstance(freezer_wheels, list) or not freezer_wheels:
        raise ReleaseError("freezer wheelhouse is empty")
    freezer_names: list[str] = []
    for index, value in enumerate(freezer_wheels):
        wheel_record = _exact_fields(
            value,
            {"bytes", "filename", "sha256"},
            f"frozen builder wheelhouse[{index}]",
        )
        freezer_names.append(
            portable_path(
                wheel_record["filename"],
                label=f"frozen builder wheelhouse[{index}].filename",
                single=True,
            )
        )
        if not wheel_record["filename"].endswith(".whl"):
            raise ReleaseError("freezer wheelhouse contains a non-wheel")
        _file_identity(
            {"bytes": wheel_record["bytes"], "sha256": wheel_record["sha256"]},
            f"frozen builder wheelhouse[{index}]",
        )
    if freezer_names != sorted(set(freezer_names)) or canonical_hash(
        freezer_wheels
    ) != freezer_wheelhouse["manifest_sha256"]:
        raise ReleaseError("freezer wheelhouse inventory/digest differs")
    bootstrap_pip = _exact_fields(
        frozen_builder["bootstrap_pip"],
        {"file", "filename", "version"},
        "verification.reproducibility.frozen_builder.bootstrap_pip",
    )
    if (
        bootstrap_pip["filename"] not in freezer_names
        or not bootstrap_pip["filename"].casefold().startswith("pip-")
        or not isinstance(bootstrap_pip["version"], str)
        or not bootstrap_pip["version"]
    ):
        raise ReleaseError("freezer bootstrap pip identity differs")
    _file_identity(
        bootstrap_pip["file"],
        "verification.reproducibility.frozen_builder.bootstrap_pip.file",
    )
    matching_bootstrap = next(
        item for item in freezer_wheels if item["filename"] == bootstrap_pip["filename"]
    )
    if matching_bootstrap != {"filename": bootstrap_pip["filename"], **bootstrap_pip["file"]}:
        raise ReleaseError("freezer bootstrap pip differs from wheelhouse")
    packages = frozen_builder["packages"]
    if not isinstance(packages, list):
        raise ReleaseError("freezer package inventory is not a list")
    package_names: list[str] = []
    for index, value in enumerate(packages):
        package = _exact_fields(
            value, {"name", "version"}, f"frozen builder packages[{index}]"
        )
        if any(not isinstance(package[field], str) or not package[field] for field in package):
            raise ReleaseError("freezer package identity is invalid")
        package_names.append(package["name"].casefold().replace("_", "-"))
    if package_names != sorted(set(package_names)) or not {
        "altgraph",
        "packaging",
        "pip",
        "pyinstaller",
        "pyinstaller-hooks-contrib",
        "setuptools",
    } <= set(package_names):
        raise ReleaseError("freezer package inventory is incomplete")
    if {"name": "pip", "version": bootstrap_pip["version"]} not in packages:
        raise ReleaseError("freezer bootstrap pip version differs")
    expected_freezer_provision = [
        "{python}", "-S", "-m", "pip", "install", "--no-index",
        "--require-hashes", "--no-deps", "--only-binary=:all:",
        "--target", "{build_env}", "--find-links", "{wheelhouse}",
        "-r", "{requirements}",
    ]
    if frozen_builder["provision_argv"] != expected_freezer_provision:
        raise ReleaseError("freezer offline provision command differs")
    if frozen_builder["build_argv"] != [
        "{python}", "-S", "-m", "PyInstaller", "--clean", "--noconfirm",
        "--distpath", "{dist}", "--workpath", "{work}", "{spec}",
    ]:
        raise ReleaseError("freezer PyInstaller command differs")
    expected_freezer_environment = {
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PYTHONHASHSEED": "0",
        "SOURCE_DATE_EPOCH": str(identity["source_date_epoch"]),
        "TZ": "UTC",
    }
    if frozen_builder["environment"] != expected_freezer_environment:
        raise ReleaseError("freezer controlled environment differs")
    if frozen_builder["python_optimize"] not in {"0", "1", "2"}:
        raise ReleaseError("freezer Python optimization level differs")
    _positive_int(
        frozen_builder["timeout_seconds"],
        "verification.reproducibility.frozen_builder.timeout_seconds",
        ceiling=24 * 60 * 60,
    )
    source_packages = frozen_builder["source_packages"]
    if not isinstance(source_packages, list) or not source_packages:
        raise ReleaseError("freezer corresponding-source packages are empty")
    source_distributions: list[str] = []
    for index, value in enumerate(source_packages):
        source_package = _exact_fields(
            value,
            {"distribution", "file", "filename", "url", "version"},
            f"frozen builder source_packages[{index}]",
        )
        source_distributions.append(source_package["distribution"])
        portable_path(
            source_package["filename"],
            label=f"frozen builder source_packages[{index}].filename",
            single=True,
        )
        if (
            not isinstance(source_package["distribution"], str)
            or SAFE_LABEL.fullmatch(source_package["distribution"]) is None
            or not isinstance(source_package["version"], str)
            or not source_package["version"]
            or not isinstance(source_package["url"], str)
            or not source_package["url"].startswith("https://files.pythonhosted.org/")
        ):
            raise ReleaseError("freezer source-package provenance is invalid")
        _file_identity(
            source_package["file"],
            f"frozen builder source_packages[{index}].file",
        )
    package_versions = {item["name"]: item["version"] for item in packages}
    if source_distributions != sorted(set(source_distributions)) or {
        item["distribution"]: item["version"] for item in source_packages
    } != package_versions:
        raise ReleaseError("freezer source-package inventory differs from installed stack")
    freezer_companions = frozen_builder["source_companions"]
    if not isinstance(freezer_companions, list) or not freezer_companions:
        raise ReleaseError("freezer source companion inventory is empty")
    freezer_companion_paths: list[str] = []
    freezer_companion_keys: list[tuple[str, str, str | None]] = []
    for index, value in enumerate(freezer_companions):
        companion = _exact_fields(
            value,
            {"file", "path", "role", "source_member", "subject"},
            f"frozen builder source_companions[{index}]",
        )
        freezer_companion_paths.append(
            portable_path(
                companion["path"],
                label=f"frozen builder source_companions[{index}].path",
            )
        )
        if (
            companion["role"]
            not in {
                "freezer-build-wheel",
                "freezer-build-wheel-license",
                "freezer-requirements",
                "freezer-source-archive",
            }
            or not isinstance(companion["subject"], str)
            or not companion["subject"]
            or (
                companion["source_member"] is not None
                and not isinstance(companion["source_member"], str)
            )
        ):
            raise ReleaseError("freezer source companion metadata is invalid")
        _file_identity(
            companion["file"],
            f"frozen builder source_companions[{index}].file",
        )
        if (
            companion["role"] == "freezer-build-wheel-license"
        ) is not (companion["source_member"] is not None):
            raise ReleaseError("freezer companion source-member binding differs")
        freezer_companion_keys.append(
            (companion["role"], companion["subject"], companion["source_member"])
        )
    if freezer_companion_paths != sorted(set(freezer_companion_paths)) or len(
        freezer_companion_keys
    ) != len(set(freezer_companion_keys)):
        raise ReleaseError("freezer source companions are not sorted/unique")
    freezer_by_key = {
        (item["role"], item["subject"]): item
        for item in freezer_companions
        if item["role"] != "freezer-build-wheel-license"
    }
    if len(freezer_by_key) != len(
        [
            item
            for item in freezer_companions
            if item["role"] != "freezer-build-wheel-license"
        ]
    ):
        raise ReleaseError("freezer non-license source companion is duplicated")
    required_freezer_keys = {
        ("freezer-requirements", "requirements"),
        *(("freezer-build-wheel", item["filename"]) for item in freezer_wheels),
        *(("freezer-build-wheel-license", item["filename"]) for item in freezer_wheels),
        *(("freezer-source-archive", item["distribution"]) for item in source_packages),
    }
    if {
        (item["role"], item["subject"]) for item in freezer_companions
    } != required_freezer_keys:
        raise ReleaseError("freezer source companion role inventory differs")
    if freezer_by_key[("freezer-requirements", "requirements")]["file"] != frozen_builder[
        "requirements"
    ]["file"]:
        raise ReleaseError("freezer requirements source companion differs")
    for wheel_record in freezer_wheels:
        if freezer_by_key[("freezer-build-wheel", wheel_record["filename"])]["file"] != {
            "bytes": wheel_record["bytes"],
            "sha256": wheel_record["sha256"],
        }:
            raise ReleaseError("freezer build-wheel companion differs")
        license_companions = [
            item
            for item in freezer_companions
            if item["role"] == "freezer-build-wheel-license"
            and item["subject"] == wheel_record["filename"]
        ]
        if not license_companions or any(
            item["source_member"] is None for item in license_companions
        ):
            raise ReleaseError("freezer build-wheel license member is missing")
    for source_package in source_packages:
        if freezer_by_key[
            ("freezer-source-archive", source_package["distribution"])
        ]["file"] != source_package["file"]:
            raise ReleaseError("freezer source-package companion differs")
    for companion in freezer_companions:
        if companion["role"] not in {
            "freezer-build-wheel",
            "freezer-source-archive",
        }:
            continue
        expected_format = (
            "zip" if companion["role"] == "freezer-build-wheel" else "tar"
        )
        if nested_by_path.get(companion["path"]) != {
            "path": companion["path"],
            "format": expected_format,
            **companion["file"],
        }:
            raise ReleaseError("nested archive inventory omits freezer source companion")
    if not set(freezer_companion_paths) <= set(
        identity["corresponding_source"]["required_paths"]
    ):
        raise ReleaseError("freezer source companions are not all required paths")
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
    frozen_argv = reproducibility["frozen_build_argv"]
    expected_frozen_argv = [
        "python3",
        "-S",
        frozen_builder["path"],
        "--identity",
        "release-identity.json",
        "--source-checkout",
        "{source_checkout}",
        "--wheel",
        "{wheel}",
        "--wheelhouse",
        "{freezer_wheelhouse}",
        "--requirements",
        frozen_builder["requirements"]["path"],
        "--workspace",
        "{freezer_workspace}",
        "--frozen",
        "{frozen}",
        "--receipt",
        "{frozen_receipt}",
    ]
    if frozen_argv != expected_frozen_argv or frozen_argv[0] not in tool_names:
        raise ReleaseError("verification reproducibility frozen_build_argv is invalid")
    tracing = _exact_fields(
        verification["tracing"],
        {"argv_prefix", "forbidden_syscalls", "tool"},
        "verification.tracing",
    )
    tracing_tool = _exact_fields(
        tracing["tool"],
        {"name", "version_argv", "version", "executable"},
        "verification.tracing.tool",
    )
    if (
        tracing_tool["name"] != "strace"
        or tracing_tool["version_argv"] != ["strace", "--version"]
        or not isinstance(tracing_tool["version"], str)
        or not tracing_tool["version"]
    ):
        raise ReleaseError("verification tracing tool must bind strace --version")
    _file_identity(tracing_tool["executable"], "verification.tracing.tool.executable")
    if tracing["argv_prefix"] != [
        "strace",
        "-f",
        "-qq",
        "-e",
        "trace=network",
        "-o",
        "{trace}",
    ]:
        raise ReleaseError("verification tracing argv prefix is not the strict form")
    required_network_calls = sorted(
        {
            "accept",
            "accept4",
            "bind",
            "connect",
            "getpeername",
            "getsockname",
            "getsockopt",
            "listen",
            "recvfrom",
            "recvmmsg",
            "recvmsg",
            "sendmmsg",
            "sendmsg",
            "sendto",
            "setsockopt",
            "shutdown",
            "socket",
            "socketpair",
        }
    )
    if tracing["forbidden_syscalls"] != required_network_calls:
        raise ReleaseError("verification tracing syscall set is incomplete")
    boundary = _exact_fields(
        verification["network_boundary"],
        {
            "clone3_action",
            "clone_untraced_mask",
            "default_action",
            "denied_syscalls",
            "deny_action",
            "library",
            "no_new_privs",
            "schema",
            "wrapper",
        },
        "verification.network_boundary",
    )
    if (
        boundary["schema"] != "kazstem-linux-seccomp-network-boundary-v1"
        or boundary["default_action"] != "allow"
        or boundary["deny_action"] != "errno-EPERM"
        or boundary["clone3_action"] != "errno-ENOSYS"
        or boundary["clone_untraced_mask"] != 0x00800000
        or boundary["no_new_privs"] is not True
        or boundary["denied_syscalls"] != NETWORK_BOUNDARY_DENIED_SYSCALLS
    ):
        raise ReleaseError("verification network boundary policy differs")
    wrapper = _exact_fields(
        boundary["wrapper"], {"file", "path"}, "verification.network_boundary.wrapper"
    )
    if wrapper["path"] != "packaging/linux/run_no_network.py":
        raise ReleaseError("network boundary wrapper path differs")
    _file_identity(wrapper["file"], "verification.network_boundary.wrapper.file")
    library = _exact_fields(
        boundary["library"],
        {"file", "soname"},
        "verification.network_boundary.library",
    )
    if library["soname"] != "libseccomp.so.2":
        raise ReleaseError("network boundary library soname differs")
    _file_identity(library["file"], "verification.network_boundary.library.file")
    compression = _exact_fields(
        verification["compression"],
        {"selection_rule", "targets"},
        "verification.compression",
    )
    if compression["selection_rule"] != "minimum-bytes-then-name":
        raise ReleaseError("compression selection rule is not deterministic")
    targets = compression["targets"]
    if not isinstance(targets, list) or len(targets) != 2:
        raise ReleaseError("compression must cover both native release assets")
    target_names: list[str] = []
    for target_index, target_value in enumerate(targets):
        target = _exact_fields(
            target_value,
            {"artifact", "candidates", "input", "selected"},
            f"verification.compression.targets[{target_index}]",
        )
        artifact_name = target["artifact"]
        target_names.append(artifact_name)
        if artifact_name not in {"corresponding_source", "ready_run"}:
            raise ReleaseError("compression target is not a native release asset")
        artifact = artifacts[artifact_name]
        top_level = tar_container_top(
            artifact["filename"], label=f"artifacts.{artifact_name}.filename"
        )
        input_record = _exact_fields(
            target["input"],
            {"bytes", "filename", "producer", "sha256"},
            f"verification.compression.targets[{target_index}].input",
        )
        if input_record["filename"] != f"{top_level}.tar" or input_record[
            "producer"
        ] != "deterministic-gnu-tar-v1":
            raise ReleaseError("compression input is not the canonical raw tar")
        _file_identity(
            {"bytes": input_record["bytes"], "sha256": input_record["sha256"]},
            f"verification.compression.targets[{target_index}].input",
        )
        candidates = target["candidates"]
        if not isinstance(candidates, list) or len(candidates) < 2:
            raise ReleaseError("compression target requires at least two candidates")
        candidate_names: list[str] = []
        candidate_filenames: list[str] = []
        selected_candidate: dict[str, Any] | None = None
        for index, candidate_value in enumerate(candidates):
            candidate = _exact_fields(
                candidate_value,
                {
                    "argv",
                    "eligible",
                    "filename",
                    "format",
                    "ineligible_reason",
                    "name",
                    "tool",
                    "tradeoff",
                },
                f"verification.compression.targets[{target_index}].candidates[{index}]",
            )
            name = candidate["name"]
            if not isinstance(name, str) or SAFE_LABEL.fullmatch(name) is None:
                raise ReleaseError("compression candidate name is invalid")
            if candidate["format"] not in TAR_CANDIDATE_SUFFIXES:
                raise ReleaseError("compression candidate format is unsupported")
            expected_filename = top_level + TAR_CANDIDATE_SUFFIXES[candidate["format"]]
            if candidate["filename"] != expected_filename:
                raise ReleaseError("compression candidate filename/format differs")
            candidate_names.append(name)
            candidate_filenames.append(candidate["filename"])
            if name == target["selected"]:
                selected_candidate = candidate
            if (
                not isinstance(candidate["eligible"], bool)
                or (
                    candidate["eligible"] is True
                    and candidate["ineligible_reason"] is not None
                )
                or (
                    candidate["eligible"] is False
                    and (
                        not isinstance(candidate["ineligible_reason"], str)
                        or not candidate["ineligible_reason"]
                    )
                )
            ):
                raise ReleaseError("compression candidate eligibility is invalid")
            if candidate["tool"] not in tool_names:
                raise ReleaseError("compression candidate tool is not identity-bound")
            argv = candidate["argv"]
            if (
                not isinstance(argv, list)
                or len(argv) < 3
                or argv[0] != candidate["tool"]
                or sum(item.count("{input}") for item in argv) != 1
                or sum(item.count("{output}") for item in argv) != 1
                or any(
                    not isinstance(item, str)
                    or not item
                    or absolute_reference(item) is not None
                    or "{" in item.replace("{input}", "").replace("{output}", "")
                    for item in argv
                )
            ):
                raise ReleaseError("compression candidate argv is invalid")
            if not isinstance(candidate["tradeoff"], str) or not candidate["tradeoff"]:
                raise ReleaseError("compression candidate tradeoff is empty")
            expected_eligibility = {
                "gzip": ("gzip", True, None),
                "xz": ("xz", True, None),
                "zstd": (
                    "zstd",
                    False,
                    "no-install extraction cannot assume an external zstd decoder",
                ),
            }.get(name)
            if expected_eligibility is None or (
                candidate["format"],
                candidate["eligible"],
                candidate["ineligible_reason"],
            ) != expected_eligibility:
                raise ReleaseError(
                    "compression eligibility must follow the fixed no-install decoder matrix"
                )
        if (
            candidate_names != ["gzip", "xz", "zstd"]
            or len(candidate_filenames) != len(set(candidate_filenames))
            or selected_candidate is None
            or selected_candidate["eligible"] is not True
            or selected_candidate["format"] not in TAR_CONTAINER_SUFFIXES
            or selected_candidate["filename"] != artifact["filename"]
        ):
            raise ReleaseError("compression selection/candidate inventory differs")
    if target_names != ["corresponding_source", "ready_run"]:
        raise ReleaseError("compression targets must be sorted and complete")
    evidence = verification["evidence"]
    if not isinstance(evidence, list) or not evidence:
        raise ReleaseError("verification.evidence must be non-empty")
    evidence_paths: list[str] = []
    for index, record in enumerate(evidence):
        item = _exact_fields(
            record,
            {"path", "gate", "kind", "subjects", "execution", "file"},
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
        subjects = item["subjects"]
        if (
            not isinstance(subjects, list)
            or (not subjects and GATE_SUBJECTS[item["gate"]])
            or subjects != sorted(set(subjects))
            or any(subject not in artifacts for subject in subjects)
        ):
            raise ReleaseError("verification evidence subjects are invalid")
        if subjects != GATE_SUBJECTS[item["gate"]]:
            raise ReleaseError("verification gate subjects differ from fixed matrix")
        execution = _exact_fields(
            item["execution"],
            {
                "argv",
                "cwd",
                "environment",
                "generator",
                "network_syscall_ledger",
                "payload_expectations",
                "payload_schema",
                "script",
                "source_tree",
                "timeout_seconds",
            },
            f"verification.evidence[{index}].execution",
        )
        if execution["cwd"] != "source-checkout" or execution["source_tree"] != identity[
            "source_tree"
        ]:
            raise ReleaseError("evidence execution cwd/tree is not the release source")
        if execution["environment"] != reproducibility["environment"]:
            raise ReleaseError("evidence execution environment differs")
        for name in ("generator", "script"):
            executable_file = _exact_fields(
                execution[name],
                {"file", "path"},
                f"verification.evidence[{index}].execution.{name}",
            )
            portable_path(
                executable_file["path"],
                label=f"verification.evidence[{index}].execution.{name}.path",
            )
            _file_identity(
                executable_file["file"],
                f"verification.evidence[{index}].execution.{name}.file",
            )
        if execution["script"]["path"] != GATE_SCRIPT_PATHS[item["gate"]]:
            raise ReleaseError("verification gate script path differs from fixed matrix")
        execution_argv = execution["argv"]
        if execution_argv != GATE_EXECUTION_ARGV[item["gate"]]:
            raise ReleaseError("evidence execution argv differs from fixed gate matrix")
        if (
            execution["payload_schema"] != EVIDENCE_PAYLOAD_SCHEMAS[item["gate"]]
            or _positive_int(
                execution["timeout_seconds"],
                f"verification.evidence[{index}].execution.timeout_seconds",
                ceiling=24 * 60 * 60,
            )
            <= 0
            or execution["network_syscall_ledger"]
            is not (
                item["gate"]
                in {"network-trace", "python-reproducibility", "source-suite"}
            )
        ):
            raise ReleaseError("evidence execution schema/timeout/tracing is invalid")
        expectations = execution["payload_expectations"]
        expected_fields = (
            {
                "expected_failure_test_ids_sha256",
                "expected_failures",
                "skipped",
                "skipped_test_ids_sha256",
                "test_ids_sha256",
                "tests_discovered",
            }
            if item["gate"] == "source-suite"
            else (
                {"workload_bytes", "workload_lines", "workload_sha256"}
                if item["gate"] == "network-trace"
                else set()
            )
        )
        if not isinstance(expectations, dict) or set(expectations) != expected_fields:
            raise ReleaseError("evidence payload expectations differ")
        for key, expected_value in expectations.items():
            if key.endswith("sha256"):
                _sha(expected_value, f"{item['gate']}.payload_expectations.{key}")
            elif (
                isinstance(expected_value, bool)
                or not isinstance(expected_value, int)
                or expected_value < 0
                or (
                    key in {"tests_discovered", "workload_bytes", "workload_lines"}
                    and expected_value == 0
                )
            ):
                raise ReleaseError("evidence numeric payload expectation is invalid")
    if evidence_paths != sorted(set(evidence_paths)) or len(
        {unicodedata.normalize("NFC", value).casefold() for value in evidence_paths}
    ) != len(evidence_paths):
        raise ReleaseError("verification evidence paths must be sorted and unique")
    gates = [record["gate"] for record in evidence]
    if len(gates) != len(set(gates)) or set(gates) != set(REQUIRED_EVIDENCE_GATES):
        raise ReleaseError(
            "verification evidence gates differ from the required Linux release matrix "
            f"(missing={sorted(set(REQUIRED_EVIDENCE_GATES) - set(gates))}, "
            f"extra={sorted(set(gates) - set(REQUIRED_EVIDENCE_GATES))})"
        )
    return identity


def archive_limits(identity: dict[str, Any], name: str) -> ArchiveLimits:
    return _limits(identity["archive_limits"][name], f"archive_limits.{name}")


def compression_target(identity: dict[str, Any], artifact: str) -> dict[str, Any]:
    try:
        return next(
            target
            for target in identity["verification"]["compression"]["targets"]
            if target["artifact"] == artifact
        )
    except StopIteration as exc:
        raise ReleaseError(f"identity lacks compression target: {artifact}") from exc


def selected_compression(identity: dict[str, Any], artifact: str) -> str:
    target = compression_target(identity, artifact)
    candidate = next(
        item for item in target["candidates"] if item["name"] == target["selected"]
    )
    return candidate["format"]


def materialize_uncompressed_tar(
    archive: Path,
    destination: Path,
    *,
    compression: str,
    expected: dict[str, Any],
) -> dict[str, Any]:
    if destination.exists() or destination.is_symlink():
        raise ReleaseError(f"raw tar output already exists: {destination}")
    if compression not in TAR_CONTAINER_SUFFIXES:
        raise ReleaseError("cannot expand unsupported tar compression")
    destination.parent.mkdir(parents=True, exist_ok=True)
    opener = lzma.open if compression == "xz" else gzip.open
    digest = hashlib.sha256()
    written = 0
    try:
        with opener(archive, "rb") as source, destination.open("xb") as output:
            while True:
                chunk = source.read(1024 * 1024)
                if not chunk:
                    break
                written += len(chunk)
                if written > expected["bytes"]:
                    raise ReleaseError("selected archive expands beyond canonical tar")
                digest.update(chunk)
                output.write(chunk)
        observed = {"bytes": written, "sha256": digest.hexdigest()}
        if observed != {"bytes": expected["bytes"], "sha256": expected["sha256"]}:
            raise ReleaseError("selected archive does not contain the canonical raw tar")
        return observed
    except BaseException:
        destination.unlink(missing_ok=True)
        raise


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
        raise ReleaseError(f"Git source repository is not a real directory: {repository}")
    repository = repository.resolve(strict=True)
    if destination.exists() or destination.is_symlink():
        raise ReleaseError(f"Git archive output already exists: {destination}")
    ensure_output_outside(destination, repository, label="Git archive output")
    commit = identity.get("source_commit")
    tree = identity.get("source_tree")
    origin = identity.get("source_origin")
    if not isinstance(commit, str) or COMMIT.fullmatch(commit) is None:
        raise ReleaseError("source_commit is not a full lowercase Git object id")
    if not isinstance(tree, str) or COMMIT.fullmatch(tree) is None:
        raise ReleaseError("source_tree is not a full lowercase Git tree id")
    if not isinstance(origin, str):
        raise ReleaseError("source_origin is missing")
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
        raise ReleaseError(
            f"git version differs from identity: {version!r}"
        )
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
    observed_origin = _git_output(
        repository,
        ["git", "remote", "get-url", "origin"],
        label="Git origin lookup",
    )
    if observed_origin != origin:
        raise ReleaseError(
            f"Git origin differs from identity: expected={origin!r}, observed={observed_origin!r}"
        )
    observed_ref = _git_output(
        repository,
        ["git", "rev-parse", f"{identity['source_ref']}^{{commit}}"],
        label="Git release tag lookup",
    )
    if observed_ref != commit:
        raise ReleaseError(
            "source_commit is not the exact commit at the identity origin ref"
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
        "source_ref": identity["source_ref"],
        "archive": {"filename": destination.name, **git_input["file"]},
        "argv": expected_argv,
        "tool_version": version,
    }


def _resolved_symlink(root: Path, path: Path) -> None:
    try:
        path.resolve(strict=True).relative_to(root)
    except (OSError, ValueError) as exc:
        raise ReleaseError(f"symlink escapes or is dangling: {path}") from exc


def tree_inventory(root: Path) -> list[dict[str, Any]]:
    if not root.is_dir() or root.is_symlink():
        raise ReleaseError(f"tree root is not a real directory: {root}")
    root = root.resolve(strict=True)
    result: list[dict[str, Any]] = []
    folded: dict[str, str] = {}
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


def write_deterministic_raw_tar(
    root: Path, destination: Path, *, epoch: int, limits: ArchiveLimits
) -> dict[str, Any]:
    if destination.exists():
        raise ReleaseError(f"raw tar output already exists: {destination}")
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
        with tarfile.open(destination, mode="x", format=tarfile.GNU_FORMAT) as archive:
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
        return {"filename": destination.name, **file_record(destination)}
    except BaseException:
        destination.unlink(missing_ok=True)
        raise


def compress_deterministic_raw_tar(
    source: Path, destination: Path, *, compression: str
) -> None:
    if source.is_symlink() or not source.is_file():
        raise ReleaseError("canonical raw tar input is not a regular file")
    if destination.exists() or destination.is_symlink():
        raise ReleaseError(f"archive output already exists: {destination}")
    if compression not in TAR_CONTAINER_SUFFIXES:
        raise ReleaseError(f"unsupported deterministic tar compression: {compression}")
    if not destination.name.endswith(TAR_CONTAINER_SUFFIXES[compression]):
        raise ReleaseError("archive filename suffix differs from selected compression")
    destination.parent.mkdir(parents=True, exist_ok=True)
    try:
        if compression == "xz":
            with source.open("rb") as raw_input, lzma.open(
                destination,
                "wb",
                format=lzma.FORMAT_XZ,
                check=lzma.CHECK_CRC64,
                preset=9 | lzma.PRESET_EXTREME,
            ) as compressed:
                shutil.copyfileobj(raw_input, compressed, length=1024 * 1024)
        else:
            with source.open("rb") as raw_input, destination.open("xb") as raw_output:
                with gzip.GzipFile(
                    filename="",
                    mode="wb",
                    fileobj=raw_output,
                    compresslevel=9,
                    mtime=0,
                ) as compressed:
                    shutil.copyfileobj(raw_input, compressed, length=1024 * 1024)
    except BaseException:
        destination.unlink(missing_ok=True)
        raise


def write_deterministic_tar_archive(
    root: Path,
    destination: Path,
    *,
    epoch: int,
    limits: ArchiveLimits,
    compression: str,
) -> None:
    with tempfile.TemporaryDirectory(
        prefix=".kazstem-tar-", dir=destination.parent
    ) as temporary:
        raw_path = Path(temporary) / "payload.tar"
        write_deterministic_raw_tar(root, raw_path, epoch=epoch, limits=limits)
        compress_deterministic_raw_tar(
            raw_path, destination, compression=compression
        )


def produce_canonical_tar_with_receipt(
    root: Path,
    destination: Path,
    raw_tar_output: Path,
    receipt_output: Path,
    *,
    identity_path: Path,
    identity: dict[str, Any],
    artifact: str,
    producer_argv: list[str],
) -> dict[str, Any]:
    for label, path in (
        ("canonical raw tar", raw_tar_output),
        ("canonical tar producer receipt", receipt_output),
    ):
        if path.exists() or path.is_symlink():
            raise ReleaseError(f"{label} output already exists: {path}")
        ensure_output_outside(path, root, label=label)
    ensure_distinct_nonaliased_paths(
        raw_tar_output,
        receipt_output,
        labels=("canonical raw tar", "canonical tar producer receipt"),
    )
    target = compression_target(identity, artifact)
    script_name = "source" if artifact == "corresponding_source" else "ready_run"
    producer = identity["verification"]["reproducibility"]["native_assemblers"]
    running_script = Path(__file__).with_name(producer[script_name]["path"].rsplit("/", 1)[-1])
    verify_file(
        running_script,
        producer[script_name]["file"],
        label=f"{artifact} raw-tar producer script",
    )
    verify_file(
        Path(__file__).resolve(strict=True),
        producer["release_common"]["file"],
        label="raw-tar producer release_common",
    )
    configured_environment = identity["verification"]["reproducibility"]["environment"]
    if any(
        os.environ.get(key) != value
        for key, value in configured_environment.items()
        if key != "PYTHONPYCACHEPREFIX"
    ):
        raise ReleaseError("raw-tar producer environment differs from identity")
    actual_pycache = os.environ.get("PYTHONPYCACHEPREFIX")
    if actual_pycache != configured_environment["PYTHONPYCACHEPREFIX"]:
        if actual_pycache is None:
            raise ReleaseError("raw-tar producer lacks an isolated pycache prefix")
        pycache_path = Path(actual_pycache)
        if (
            not pycache_path.is_absolute()
            or not pycache_path.is_dir()
            or pycache_path.is_symlink()
            or root.resolve(strict=True) in pycache_path.resolve(strict=True).parents
            or pycache_path.resolve(strict=True) in root.resolve(strict=True).parents
        ):
            raise ReleaseError("raw-tar producer pycache prefix is not isolated")
    python_record = next(
        (
            record
            for record in identity["verification"]["reproducibility"]["tools"]
            if file_record(Path(sys.executable).resolve(strict=True)) == record["executable"]
        ),
        None,
    )
    if python_record is None:
        raise ReleaseError("raw-tar producer Python is not identity-bound")
    limits = archive_limits(identity, artifact)
    raw_tar_output.parent.mkdir(parents=True, exist_ok=True)
    first = write_deterministic_raw_tar(
        root, raw_tar_output, epoch=identity["source_date_epoch"], limits=limits
    )
    with tempfile.TemporaryDirectory(prefix="kazstem-tar-ab-") as temporary:
        second_path = Path(temporary) / raw_tar_output.name
        second = write_deterministic_raw_tar(
            root, second_path, epoch=identity["source_date_epoch"], limits=limits
        )
    expected_raw = target["input"]
    observed = {"filename": first["filename"], "bytes": first["bytes"], "sha256": first["sha256"]}
    if observed != {
        "filename": expected_raw["filename"],
        "bytes": expected_raw["bytes"],
        "sha256": expected_raw["sha256"],
    } or {"bytes": second["bytes"], "sha256": second["sha256"]} != {
        "bytes": first["bytes"], "sha256": first["sha256"]
    }:
        raise ReleaseError("canonical raw tar A/B/identity differs")
    compress_deterministic_raw_tar(
        raw_tar_output,
        destination,
        compression=selected_compression(identity, artifact),
    )
    receipt = {
        "schema": "kazstem-deterministic-tar-producer-receipt-v2",
        "pass": True,
        "release": identity["release"],
        "source_commit": identity["source_commit"],
        "source_tree": identity["source_tree"],
        "identity_contract_sha256": identity_sha256(identity_path),
        "artifact": artifact,
        "producer": {
            "script": producer[script_name],
            "release_common": producer["release_common"],
            "argv": producer_argv,
            "environment": configured_environment,
            "python": python_record,
        },
        "normalized_tree": tree_record(root),
        "canonical_tar": expected_raw,
        "runs": [
            {"run": "a", "output": expected_raw},
            {"run": "b", "output": expected_raw},
        ],
        "format": "gnu-tar-normalized-metadata-v1",
        "selected_compression": selected_compression(identity, artifact),
        "selected_container": identity["artifacts"][artifact],
    }
    assert_relative_json(receipt, label=f"{artifact} canonical tar producer receipt")
    receipt_output.parent.mkdir(parents=True, exist_ok=True)
    receipt_output.write_bytes(json_bytes(receipt))
    return receipt


def tar_producer_logical_argv(
    identity: dict[str, Any], artifact: str, raw_tar_filename: str
) -> list[str]:
    artifacts = identity["artifacts"]
    if artifact == "corresponding_source":
        return [
            "python3",
            "packaging/linux/assemble_corresponding_source.py",
            "--identity", "release-identity.json",
            "--payload", "inputs/source-payload",
            "--repository", "source-checkout",
            "--source-readme-template", "inputs/CORRESPONDING-SOURCE-README.template.md",
            "--wheel", f"artifacts/{artifacts['wheel']['filename']}",
            "--sdist", f"artifacts/{artifacts['sdist']['filename']}",
            "--work-root", "work/source",
            "--output", f"artifacts/{artifacts['corresponding_source']['filename']}",
            "--raw-tar-output", f"canonical/{raw_tar_filename}",
            "--producer-receipt", "evidence/corresponding-source-tar-producer.json",
        ]
    if artifact == "ready_run":
        return [
            "python3",
            "packaging/linux/assemble_ready_run.py",
            "--identity", "release-identity.json",
            "--frozen", "inputs/frozen",
            "--resources", "inputs/resources",
            "--runtime", "inputs/runtime",
            "--documents", "inputs/documents",
            "--binary-readme-template", "inputs/BINARY-README.template.md",
            "--base-ledger", "inputs/base-ledger.json",
            "--wheel", f"artifacts/{artifacts['wheel']['filename']}",
            "--sdist", f"artifacts/{artifacts['sdist']['filename']}",
            "--corresponding-source", f"artifacts/{artifacts['corresponding_source']['filename']}",
            "--work-root", "work/ready",
            "--output", f"artifacts/{artifacts['ready_run']['filename']}",
            "--raw-tar-output", f"canonical/{raw_tar_filename}",
            "--producer-receipt", "evidence/ready-run-tar-producer.json",
        ]
    raise ReleaseError("unknown canonical tar producer artifact")


def validate_tar_producer_receipt(
    value: Any,
    *,
    identity: dict[str, Any],
    identity_contract_sha256: str,
    artifact: str,
    raw_tar: Path | None,
) -> dict[str, Any]:
    receipt = _exact_fields(
        value,
        {
            "artifact",
            "canonical_tar",
            "format",
            "identity_contract_sha256",
            "normalized_tree",
            "pass",
            "producer",
            "release",
            "runs",
            "schema",
            "selected_compression",
            "selected_container",
            "source_commit",
            "source_tree",
        },
        f"{artifact} canonical tar producer receipt",
    )
    target = compression_target(identity, artifact)
    if (
        receipt["schema"] != "kazstem-deterministic-tar-producer-receipt-v2"
        or receipt["pass"] is not True
        or receipt["artifact"] != artifact
        or receipt["release"] != identity["release"]
        or receipt["source_commit"] != identity["source_commit"]
        or receipt["source_tree"] != identity["source_tree"]
        or receipt["identity_contract_sha256"] != identity_contract_sha256
        or receipt["canonical_tar"] != target["input"]
        or receipt["format"] != "gnu-tar-normalized-metadata-v1"
        or receipt["selected_compression"] != selected_compression(identity, artifact)
        or receipt["selected_container"] != identity["artifacts"][artifact]
        or receipt["runs"]
        != [
            {"run": "a", "output": target["input"]},
            {"run": "b", "output": target["input"]},
        ]
    ):
        raise ReleaseError("canonical tar producer receipt identity/A-B differs")
    if raw_tar is not None:
        verify_file(
            raw_tar,
            {"bytes": target["input"]["bytes"], "sha256": target["input"]["sha256"]},
            label=f"{artifact} canonical producer raw tar",
        )
    producer = _exact_fields(
        receipt["producer"],
        {"argv", "environment", "python", "release_common", "script"},
        f"{artifact} canonical tar producer",
    )
    script_name = "source" if artifact == "corresponding_source" else "ready_run"
    expected_producer = identity["verification"]["reproducibility"]["native_assemblers"]
    if (
        producer["script"] != expected_producer[script_name]
        or producer["release_common"] != expected_producer["release_common"]
        or producer["environment"]
        != identity["verification"]["reproducibility"]["environment"]
        or producer["argv"]
        != tar_producer_logical_argv(identity, artifact, target["input"]["filename"])
        or producer["python"]
        not in identity["verification"]["reproducibility"]["tools"]
        or producer["python"].get("name") != "python3"
    ):
        raise ReleaseError("canonical tar producer command/tool/tree binding differs")
    tree = receipt["normalized_tree"]
    if not isinstance(tree, dict) or tree.get("entries", 0) <= 0 or not isinstance(
        tree.get("sha256"), str
    ):
        raise ReleaseError("canonical tar producer normalized tree proof is invalid")
    assert_relative_json(receipt, label=f"{artifact} canonical tar producer receipt")
    return receipt


def write_deterministic_tar_xz(
    root: Path, destination: Path, *, epoch: int, limits: ArchiveLimits
) -> None:
    write_deterministic_tar_archive(
        root, destination, epoch=epoch, limits=limits, compression="xz"
    )


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
        "schema": "kazstem-linux-source-identity-projection-v1",
        "release": identity["release"],
        "source_commit": identity["source_commit"],
        "source_tree": identity["source_tree"],
        "source_origin": identity["source_origin"],
        "source_ref": identity["source_ref"],
        "source_date_epoch": identity["source_date_epoch"],
        "release_url": identity["release_url"],
        "platform": identity["platform"],
        "native_publication": {
            "release_url": identity["release_url"],
            "ready_run_top_level": identity["ready_run"]["top_level"],
            "corresponding_source_top_level": identity["corresponding_source"][
                "top_level"
            ],
        },
        "canonical_python_artifacts": {
            "wheel": artifacts["wheel"],
            "sdist": artifacts["sdist"],
        },
        "canonical_python_source_companions": identity["verification"][
            "reproducibility"
        ]["canonical_python"]["source_companions"],
        "source_payload_tree": identity["inputs"]["source_payload_tree"],
        "git_archive": identity["inputs"]["git_archive"],
        "resource_bundle_id": identity["inputs"]["resource_tree"]["bundle_id"],
        "runtime_bundle_id": identity["inputs"]["runtime_tree"]["bundle_id"],
        "source_contract": {
            "categories": identity["corresponding_source"]["source_categories"],
            "bound_source_materials": identity["corresponding_source"][
                "bound_source_materials"
            ],
            "source_commit_file": identity["corresponding_source"][
                "source_commit_file"
            ],
            "source_tree_file": identity["corresponding_source"][
                "source_tree_file"
            ],
            "source_origin_file": identity["corresponding_source"][
                "source_origin_file"
            ],
            "git_archive_file": identity["corresponding_source"][
                "git_archive_file"
            ],
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
        "ready_run_top_level": identity["ready_run"]["top_level"],
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
    return portable_path(cleaned, label="archive member")


def _link_stays_within(member: str, target: str, top: str) -> None:
    if not isinstance(target, str) or not target or "\x00" in target or "\\" in target:
        raise ReleaseError(f"invalid symlink target: {member!r} -> {target!r}")
    try:
        target.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ReleaseError(
            f"symlink target is not valid UTF-8: {member!r}"
        ) from exc
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
            if fileobj is None:
                raise ReleaseError("tar inspection requires path or file object")
            raw_size = _copy_capped(
                fileobj, raw, limit=raw_cap, label="raw tar stream"
            )
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
            raise ReleaseError("zstd-compressed tar streams are unsupported here")
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


def _parse_pax_records(data: bytes, *, path_cap: int) -> dict[str, str]:
    try:
        return parse_pax_records(
            data,
            path_cap=path_cap,
            allowed_keys=frozenset(
                {
                    "atime",
                    "charset",
                    "comment",
                    "ctime",
                    "gid",
                    "gname",
                    "linkpath",
                    "mtime",
                    "path",
                    "uid",
                    "uname",
                }
            ),
        )
    except PaxFormatError as exc:
        raise ReleaseError(f"invalid strict PAX metadata: {exc}") from exc


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
            if metadata is None:
                raise ReleaseError("tar extension metadata capture is unavailable")
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
                if not long_value or len(long_value.encode("utf-8")) > limits.max_path_bytes:
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
                unicodedata.normalize("NFC", part).casefold()
                for part in parts[:length]
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
                unicodedata.normalize("NFC", part).casefold()
                for part in parts[:length]
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
            max_path_bytes = max(
                len(member.name.encode("utf-8")) for member in members
            )
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


def _inspect_zip_physical(path: Path, *, limits: ArchiveLimits) -> tuple[int, int]:
    raw_bytes = path.stat().st_size
    with path.open("rb") as source:
        tail_bytes = min(raw_bytes, 22 + 65535)
        source.seek(raw_bytes - tail_bytes)
        tail = source.read(tail_bytes)
        position = tail.rfind(b"PK\x05\x06")
        if position < 0 or position + 22 > len(tail):
            raise ReleaseError("zip lacks a complete physical end record")
        eocd_offset = raw_bytes - tail_bytes + position
        (
            disk,
            central_disk,
            disk_entries,
            entries,
            central_size,
            central_offset,
            comment_length,
        ) = struct.unpack_from("<HHHHIIH", tail, position + 4)
        if (
            disk
            or central_disk
            or disk_entries != entries
            or entries in {0, 0xFFFF}
            or central_size == 0xFFFFFFFF
            or central_offset == 0xFFFFFFFF
            or comment_length
            or eocd_offset + 22 != raw_bytes
            or central_offset + central_size != eocd_offset
            or entries > limits.max_members
        ):
            raise ReleaseError("zip physical disk/count/comment/offset contract differs")
        cursor = central_offset
        local_records: list[tuple[int, int, int, int, int, int, bytes]] = []
        metadata_bytes = 22
        for _index in range(entries):
            source.seek(cursor)
            header = source.read(46)
            if len(header) != 46 or header[:4] != b"PK\x01\x02":
                raise ReleaseError("zip central directory is malformed")
            flags = struct.unpack_from("<H", header, 8)[0]
            compression = struct.unpack_from("<H", header, 10)[0]
            crc = struct.unpack_from("<I", header, 16)[0]
            compressed_size = struct.unpack_from("<I", header, 20)[0]
            expanded_size = struct.unpack_from("<I", header, 24)[0]
            name_length = struct.unpack_from("<H", header, 28)[0]
            extra_length = struct.unpack_from("<H", header, 30)[0]
            member_comment_length = struct.unpack_from("<H", header, 32)[0]
            start_disk = struct.unpack_from("<H", header, 34)[0]
            local_offset = struct.unpack_from("<I", header, 42)[0]
            variable = source.read(name_length + extra_length + member_comment_length)
            if (
                len(variable) != name_length + extra_length + member_comment_length
                or start_disk
                or flags & ~0x800
                or compression not in {0, 8}
                or compressed_size == 0xFFFFFFFF
                or expanded_size == 0xFFFFFFFF
                or local_offset == 0xFFFFFFFF
            ):
                raise ReleaseError("zip central member metadata is unsupported")
            name = variable[:name_length]
            local_records.append(
                (
                    local_offset,
                    compressed_size,
                    expanded_size,
                    crc,
                    compression,
                    flags,
                    name,
                )
            )
            cursor += 46 + len(variable)
            metadata_bytes += 46 + len(variable)
            if metadata_bytes > min(limits.max_total_bytes, MAX_TAR_EXTENSION_BYTES):
                raise ReleaseError("zip physical metadata exceeds safety cap")
        if cursor != eocd_offset:
            raise ReleaseError("zip central directory has gaps/unreferenced bytes")
        expected_offset = 0
        for (
            local_offset,
            compressed_size,
            expanded_size,
            crc,
            compression,
            flags,
            name,
        ) in sorted(local_records):
            if local_offset != expected_offset:
                raise ReleaseError("zip has prepended/gapped/overlapping local records")
            source.seek(local_offset)
            local = source.read(30)
            if len(local) != 30 or local[:4] != b"PK\x03\x04":
                raise ReleaseError("zip local header is malformed")
            local_flags = struct.unpack_from("<H", local, 6)[0]
            local_compression = struct.unpack_from("<H", local, 8)[0]
            local_crc = struct.unpack_from("<I", local, 14)[0]
            local_compressed = struct.unpack_from("<I", local, 18)[0]
            local_expanded = struct.unpack_from("<I", local, 22)[0]
            local_name_length = struct.unpack_from("<H", local, 26)[0]
            local_extra_length = struct.unpack_from("<H", local, 28)[0]
            variable = source.read(local_name_length + local_extra_length)
            if (
                len(variable) != local_name_length + local_extra_length
                or local_flags != flags
                or local_compression != compression
                or local_crc != crc
                or local_compressed != compressed_size
                or local_expanded != expanded_size
                or variable[:local_name_length] != name
            ):
                raise ReleaseError("zip local/central records differ")
            expected_offset = (
                local_offset
                + 30
                + local_name_length
                + local_extra_length
                + compressed_size
            )
            metadata_bytes += 30 + local_name_length + local_extra_length
            if expected_offset > central_offset:
                raise ReleaseError("zip compressed extent crosses central directory")
        if expected_offset != central_offset:
            raise ReleaseError("zip has unreferenced bytes before central directory")
    return entries, metadata_bytes


def inspect_zip(path: Path, *, limits: ArchiveLimits) -> dict[str, Any]:
    raw_bytes = path.stat().st_size
    if raw_bytes <= 0 or raw_bytes > limits.max_total_bytes:
        raise ReleaseError("raw zip stream exceeds safety cap")
    physical_members, metadata_total = _inspect_zip_physical(path, limits=limits)
    names: set[str] = set()
    folded: set[str] = set()
    total = 0
    compressed_total = 0
    members = 0
    layout: list[ArchiveMember] = []
    try:
        with zipfile.ZipFile(path) as archive:
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
                layout.append(
                    ArchiveMember(
                        name=name,
                        kind="directory" if info.is_dir() else "file",
                        size=info.file_size,
                        mode=stat.S_IMODE(mode) or (0o755 if info.is_dir() else 0o644),
                    )
                )
    except (OSError, zipfile.BadZipFile, RuntimeError, NotImplementedError) as exc:
        if isinstance(exc, ReleaseError):
            raise
        raise ReleaseError(f"cannot inspect zip archive {path.name}: {exc}") from exc
    if not members:
        raise ReleaseError(f"zip archive has no members: {path.name}")
    if members != physical_members:
        raise ReleaseError("zip physical/logical member counts differ")
    _validate_archive_member_layout(layout)
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


def inspect_deb(
    path: Path,
    *,
    limits: ArchiveLimits,
    zstd_tool: dict[str, Any] | None = None,
) -> dict[str, Any]:
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
                records = _inspect_zstd_tar(
                    data, limits=limits, zstd_tool=zstd_tool
                )
            else:
                records = inspect_tar(None, fileobj=io.BytesIO(data), limits=limits)
            nested_members += len(records)
            expanded_bytes += sum(record.size for record in records)
    return {
        "members": len(members),
        "embedded_tar_members": nested_members,
        "expanded_bytes": expanded_bytes,
    }


def _inspect_zstd_tar(
    data: bytes,
    *,
    limits: ArchiveLimits,
    zstd_tool: dict[str, Any] | None,
) -> list[ArchiveMember]:
    expansion_cap = min(
        MAX_HARD_TOTAL_BYTES,
        limits.max_total_bytes + limits.max_members * 2048 + 10 * 1024**2,
    )
    if zstd_tool is None:
        raise ReleaseError(
            "zstd-compressed Debian members require an identity-bound zstd tool"
        )
    tool = _exact_fields(
        zstd_tool,
        {"executable", "name", "version", "version_argv"},
        "zstd audit tool",
    )
    if tool["name"] != "zstd" or tool["version_argv"] != ["zstd", "--version"]:
        raise ReleaseError("zstd audit tool command differs")
    located = shutil.which("zstd")
    if located is None:
        raise ReleaseError("identity-bound zstd audit tool is unavailable")
    executable = Path(located).resolve(strict=True)
    verify_file(executable, tool["executable"], label="zstd audit executable")
    environment = {
        "HOME": os.devnull,
        "LANG": "C",
        "LC_ALL": "C",
        "TZ": "UTC",
    }
    try:
        version = run_bounded(
            [str(executable), "--version"],
            cwd=Path.cwd(),
            environment=environment,
            timeout=30,
            max_stdout=1024 * 1024,
            max_stderr=1024 * 1024,
        )
        expanded = run_bounded(
            [str(executable), "-q", "-d", "-c"],
            cwd=Path.cwd(),
            environment=environment,
            timeout=30,
            max_stdout=expansion_cap,
            max_stderr=1024 * 1024,
            input_data=data,
        )
    except SupervisionError as exc:
        raise ReleaseError(f"zstd Debian decompression was not contained: {exc}") from exc
    observed_version = (version.stdout + version.stderr).decode(
        "utf-8", "replace"
    ).strip()
    if version.returncode or observed_version != tool["version"]:
        raise ReleaseError("zstd audit tool version differs from identity")
    if expanded.returncode or expanded.stderr:
        raise ReleaseError("cannot decompress zstd-compressed Debian member")
    return inspect_tar(None, fileobj=io.BytesIO(expanded.stdout), limits=limits)


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
            "tar"
            if expanded is not None and _looks_like_tar_prefix(expanded)
            else "xz"
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
        relative
        for relative in declared
        if declared[relative] != observed[relative]
    )
    if mismatched:
        details = [
            f"{relative}:{declared[relative]}!={observed[relative]}"
            for relative in mismatched
        ]
        raise ReleaseError(f"nested archive format mismatch: {details}")
    return observed


def inspect_nested(
    path: Path,
    kind: str,
    *,
    limits: ArchiveLimits,
    zstd_tool: dict[str, Any] | None = None,
) -> dict[str, Any]:
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
        return inspect_deb(path, limits=limits, zstd_tool=zstd_tool)
    if kind == "gzip":
        return inspect_gzip(path, limits=limits)
    raise ReleaseError(f"unsupported nested archive kind: {kind!r}")


_WEB_URL = re.compile(r"(?i)\bhttps?://[^\s<>\"']+")
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
                raise ReleaseError(
                    f"absolute path in {label} {path}: {token!r}"
                )
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


def verify_canonical_source_companions(
    root: Path, identity: dict[str, Any]
) -> None:
    configuration = identity["verification"]["reproducibility"]
    groups = (
        (
            "canonical Python",
            configuration["canonical_python"]["source_companions"],
            "build-wheel",
            "build-wheel-license",
        ),
        (
            "freezer",
            configuration["frozen_builder"]["source_companions"],
            "freezer-build-wheel",
            "freezer-build-wheel-license",
        ),
    )
    for label, companions, wheel_role, license_role in groups:
        wheel_companions = {
            item["subject"]: root / item["path"]
            for item in companions
            if item["role"] == wheel_role
        }
        for item in companions:
            path = root / item["path"]
            verify_file(
                path,
                item["file"],
                label=f"{label} source companion {item['path']}",
            )
        for subject, wheel in wheel_companions.items():
            declared = [
                item
                for item in companions
                if item["role"] == license_role and item["subject"] == subject
            ]
            declared_members = [item["source_member"] for item in declared]
            if any(member is None for member in declared_members) or len(
                declared_members
            ) != len(set(declared_members)):
                raise ReleaseError("build-wheel license member inventory is duplicated")
            try:
                with zipfile.ZipFile(wheel) as archive:
                    actual_members = sorted(
                        name
                        for name in archive.namelist()
                        if not name.endswith("/")
                        and (
                            ".dist-info/licenses/" in name.casefold()
                            or (
                                ".dist-info/" in name.casefold()
                                and PurePosixPath(name).name.casefold().split(".", 1)[0]
                                in {"authors", "copying", "license", "notice"}
                            )
                        )
                    )
                    if sorted(declared_members) != actual_members:
                        raise ReleaseError(
                            "build-wheel license companion inventory is incomplete"
                        )
                    for item in declared:
                        license_bytes = archive.read(item["source_member"])
                        if {
                            "bytes": len(license_bytes),
                            "sha256": hashlib.sha256(license_bytes).hexdigest(),
                        } != item["file"]:
                            raise ReleaseError(
                                "build-wheel license companion differs from wheel member"
                            )
            except (KeyError, OSError, zipfile.BadZipFile) as exc:
                raise ReleaseError("cannot read the bound build-wheel license member") from exc


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
    verify_canonical_source_companions(root, identity)
    for item in source["bound_source_materials"]:
        verify_file(
            root / item["path"],
            item["file"],
            label=f"bound {item['subject']} {item['role']} material",
        )


def identity_sha256(path: Path) -> str:
    identity = load_identity(path)
    projection = dict(identity)
    # Evidence file hashes are the only intentionally excluded values: the
    # evidence envelopes bind this digest, so including their finalized bytes
    # would create a cycle.  Every other identity field, including the
    # finalizer and the network boundary, is part of the stable contract.
    projection["verification"] = {
        **identity["verification"],
        "evidence": [
            {
                "path": record["path"],
                "gate": record["gate"],
                "kind": record["kind"],
                "subjects": record["subjects"],
                "execution": record["execution"],
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


def remote_tag_argv(identity: dict[str, Any]) -> list[str]:
    """Return the one authoritative remote-ref query bound by the identity."""

    return [
        "git",
        "ls-remote",
        "--exit-code",
        "--tags",
        identity["source_origin"],
        identity["source_ref"],
        f"{identity['source_ref']}^{{}}",
    ]


def validate_source_authority_payload(
    value: Any, *, identity: dict[str, Any]
) -> dict[str, Any]:
    """Validate proof that the public origin exposes the exact annotated tag."""

    payload = _exact_fields(
        value,
        {
            "annotated_tag",
            "authoritative_remote",
            "pass",
            "release",
            "remote",
            "schema",
            "source_commit",
            "source_origin",
            "source_ref",
            "source_tag_object",
            "source_tree",
        },
        "source authority payload",
    )
    if (
        payload["schema"] != SOURCE_AUTHORITY_SCHEMA
        or payload["pass"] is not True
        or payload["annotated_tag"] is not True
        or payload["authoritative_remote"] is not True
        or payload["release"] != identity["release"]
        or payload["source_commit"] != identity["source_commit"]
        or payload["source_tree"] != identity["source_tree"]
        or payload["source_origin"] != identity["source_origin"]
        or payload["source_ref"] != identity["source_ref"]
        or payload["source_tag_object"] != identity["source_tag_object"]
    ):
        raise ReleaseError("source authority payload identity/tag differs")
    remote = _exact_fields(
        payload["remote"],
        {"argv", "exit_status", "records", "stderr", "stdout", "tool"},
        "source authority remote query",
    )
    expected_records = [
        {"object": identity["source_tag_object"], "ref": identity["source_ref"]},
        {
            "object": identity["source_commit"],
            "ref": f"{identity['source_ref']}^{{}}",
        },
    ]
    tools = {
        item["name"]: item
        for item in identity["verification"]["reproducibility"]["tools"]
    }
    if (
        remote["argv"] != remote_tag_argv(identity)
        or remote["exit_status"] != 0
        or remote["records"] != expected_records
        or remote["tool"] != tools.get("git")
    ):
        raise ReleaseError("source authority remote query is not exact")
    canonical_stdout = "".join(
        f"{record['object']}\t{record['ref']}\n" for record in expected_records
    ).encode("ascii")
    if remote["stdout"] != stream_evidence_record(canonical_stdout):
        raise ReleaseError("source authority remote stdout differs")
    if remote["stderr"] != stream_evidence_record(b""):
        raise ReleaseError("source authority remote stderr is not empty")
    _validate_stream_evidence(remote["stdout"], "source authority stdout")
    _validate_stream_evidence(remote["stderr"], "source authority stderr")
    return payload


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
    evidence_record = next(
        record
        for record in identity["verification"]["evidence"]
        if record["gate"] == gate
    )
    if evidence_record["subjects"] != subjects:
        raise ReleaseError(f"{gate} evidence subject declaration differs")
    execution = evidence_record["execution"]
    invocation = _exact_fields(
        envelope["invocation"],
        {
            "argv",
            "cwd",
            "environment",
            "exit_status",
            "generator",
            "script",
            "source_tree",
            "timeout_seconds",
            "tool",
            "stdout",
            "stderr",
        },
        f"{gate}.invocation",
    )
    argv = invocation["argv"]
    expected_argv = logical_gate_argv(identity, gate)
    if (
        not isinstance(argv, list)
        or not argv
        or any(not isinstance(item, str) or not item for item in argv)
        or invocation["exit_status"] != 0
        or argv != expected_argv
        or invocation["cwd"] != execution["cwd"]
        or invocation["source_tree"] != execution["source_tree"]
        or invocation["timeout_seconds"] != execution["timeout_seconds"]
        or invocation["generator"] != execution["generator"]
        or invocation["script"] != execution["script"]
    ):
        raise ReleaseError(f"{gate} evidence command did not record a clean exit")
    environment = invocation["environment"]
    if environment != execution["environment"]:
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
    ):
        raise ReleaseError(f"{gate} evidence tool is not identity-bound")
    _validate_stream_evidence(invocation["stdout"], f"{gate}.stdout")
    _validate_stream_evidence(invocation["stderr"], f"{gate}.stderr")

    coverage = _exact_fields(
        envelope["coverage"],
        {
            "descendant_processes",
            "full_descendant_coverage",
            "network_boundary",
            "network_trace",
            "observations",
            "process_containment",
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
    containment = _exact_fields(
        coverage["process_containment"],
        {
            "cgroup_kill_written",
            "cgroup_populated_zero",
            "descendant_peak",
            "final_descendants",
            "mechanism",
            "observed_descendants",
            "tasks_max",
        },
        f"{gate}.coverage.process_containment",
    )
    if (
        containment["mechanism"]
        not in {
            "linux-systemd-user-slice-cgroup-v2+prctl-subreaper-proc-starttime-pidfd",
            "posix-process-group-source-test-only",
        }
        or any(
            isinstance(containment[name], bool)
            or not isinstance(containment[name], int)
            or containment[name] < 0
            for name in (
                "descendant_peak",
                "final_descendants",
                "observed_descendants",
            )
        )
        or containment["final_descendants"] != 0
        or containment["descendant_peak"] > containment["observed_descendants"]
        or coverage["full_descendant_coverage"] is not False
    ):
        raise ReleaseError(f"{gate} process containment record is invalid")
    if containment["mechanism"].startswith("linux-systemd-"):
        if (
            isinstance(containment["tasks_max"], bool)
            or not isinstance(containment["tasks_max"], int)
            or containment["tasks_max"] <= 1
            or containment["cgroup_kill_written"] is not True
            or containment["cgroup_populated_zero"] is not True
        ):
            raise ReleaseError(f"{gate} kernel cgroup containment proof is invalid")
    elif (
        containment["tasks_max"] is not None
        or containment["cgroup_kill_written"] is not False
        or containment["cgroup_populated_zero"] is not False
    ):
        raise ReleaseError(f"{gate} source-test containment proof is invalid")
    if (
        platform.system() == "Linux"
        and containment["mechanism"]
        != "linux-systemd-user-slice-cgroup-v2+prctl-subreaper-proc-starttime-pidfd"
    ):
        raise ReleaseError(f"{gate} Linux evidence lacks kernel cgroup containment")
    network = coverage["network_trace"]
    network_boundary = coverage["network_boundary"]
    if gate in {"network-trace", "python-reproducibility", "source-suite"}:
        network = _exact_fields(
            network,
            {
                "argv_prefix",
                "denied_attempt_counts",
                "follow_descendants",
                "forbidden_syscalls",
                "processes",
                "syscall_counts",
                "syscalls",
                "trace",
                "tracer",
            },
            "network-trace.coverage.network_trace",
        )
        tracing = identity["verification"]["tracing"]
        if (
            network["argv_prefix"] != tracing["argv_prefix"]
            or network["tracer"] != tracing["tool"]
            or network["follow_descendants"] is not True
            or network["forbidden_syscalls"] != []
        ):
            raise ReleaseError("network trace evidence differs")
        boundary_expected = identity["verification"]["network_boundary"]
        boundary_evidence = _exact_fields(
            network_boundary,
            {"argv_prefix", "library", "policy", "receipt", "wrapper"},
            f"{gate}.coverage.network_boundary",
        )
        logical_boundary = logical_network_boundary(identity)
        if any(
            boundary_evidence[name] != logical_boundary[name]
            for name in ("argv_prefix", "library", "policy", "wrapper")
        ):
            raise ReleaseError("network boundary command/policy differs")
        boundary_receipt = _exact_fields(
            boundary_evidence["receipt"],
            {
                "clone3_action",
                "clone_untraced_denied",
                "clone_untraced_mask",
                "default_action",
                "denied_syscalls",
                "deny_action",
                "library",
                "no_new_privs",
                "pass",
                "resolved_syscalls",
                "schema",
                "unavailable_syscalls",
                "wrapper",
            },
            f"{gate}.coverage.network_boundary.receipt",
        )
        if (
            boundary_receipt["schema"]
            != "kazstem-linux-seccomp-network-boundary-receipt-v1"
            or boundary_receipt["pass"] is not True
            or boundary_receipt["default_action"] != boundary_expected["default_action"]
            or boundary_receipt["deny_action"] != boundary_expected["deny_action"]
            or boundary_receipt["no_new_privs"] is not True
            or boundary_receipt["clone_untraced_mask"]
            != boundary_expected["clone_untraced_mask"]
            or boundary_receipt["clone_untraced_denied"] is not True
            or boundary_receipt["clone3_action"] != boundary_expected["clone3_action"]
            or boundary_receipt["denied_syscalls"]
            != boundary_expected["denied_syscalls"]
            or boundary_receipt["resolved_syscalls"]
            != boundary_expected["denied_syscalls"]
            or boundary_receipt["unavailable_syscalls"] != []
            or boundary_receipt["library"] != boundary_expected["library"]["file"]
            or boundary_receipt["wrapper"] != boundary_expected["wrapper"]["file"]
        ):
            raise ReleaseError("network boundary receipt differs")
        _positive_int(
            network["processes"], "network-trace.processes", ceiling=MAX_HARD_MEMBERS
        )
        if (
            isinstance(network["syscalls"], bool)
            or not isinstance(network["syscalls"], int)
            or network["syscalls"] < 0
        ):
            raise ReleaseError("network trace syscall count is invalid")
        syscall_counts = network["syscall_counts"]
        if (
            not isinstance(syscall_counts, dict)
            or list(syscall_counts) != sorted(syscall_counts)
            or any(
                not isinstance(name, str)
                or not name
                or isinstance(count, bool)
                or not isinstance(count, int)
                or count <= 0
                for name, count in syscall_counts.items()
            )
            or sum(syscall_counts.values()) != network["syscalls"]
        ):
            raise ReleaseError("network syscall ledger is invalid")
        denied_attempt_counts = network["denied_attempt_counts"]
        if (
            not isinstance(denied_attempt_counts, dict)
            or list(denied_attempt_counts) != sorted(denied_attempt_counts)
            or any(
                name not in boundary_expected["denied_syscalls"]
                or isinstance(count, bool)
                or not isinstance(count, int)
                or count <= 0
                for name, count in denied_attempt_counts.items()
            )
        ):
            raise ReleaseError("network denied-attempt ledger is invalid")
        _validate_stream_evidence(network["trace"], "network-trace.trace")
    elif network is not None or network_boundary is not None:
        raise ReleaseError(f"{gate} unexpectedly contains network evidence")
    payload = envelope["payload"]
    if not isinstance(payload, dict):
        raise ReleaseError(f"{gate} evidence payload is not a JSON object")
    if payload.get("schema") != execution["payload_schema"]:
        raise ReleaseError(f"{gate} evidence payload schema differs from identity")
    if any(
        payload.get(field) != expected
        for field, expected in execution["payload_expectations"].items()
    ):
        raise ReleaseError(f"{gate} evidence payload inventory/config differs")
    if gate == "source-suite":
        expected_count = execution["payload_expectations"]["tests_discovered"]
        if (
            payload.get("tests_discovered") != expected_count
            or payload.get("tests_run") != expected_count
            or payload.get("failures") != 0
            or payload.get("errors") != 0
            or payload.get("unexpected_successes") != 0
            or payload.get("skipped")
            != execution["payload_expectations"]["skipped"]
            or payload.get("expected_failures")
            != execution["payload_expectations"]["expected_failures"]
            or any(
                isinstance(payload.get(field), bool)
                or not isinstance(payload.get(field), int)
                or payload.get(field) < 0
                for field in ("skipped", "expected_failures")
            )
        ):
            raise ReleaseError("source-suite exact inventory/count/result differs")
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
        "subjects": {
            subject: identity["artifacts"][subject] for subject in subjects
        },
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


def validate_compression_comparison(
    value: Any,
    *,
    identity: dict[str, Any],
    identity_contract_sha256: str,
) -> dict[str, Any]:
    report = _exact_fields(
        value,
        {
            "schema",
            "pass",
            "release",
            "source_commit",
            "source_tree",
            "identity_contract_sha256",
            "selection_rule",
            "targets",
        },
        "compression comparison",
    )
    configuration = identity["verification"]["compression"]
    if (
        report["schema"] != EVIDENCE_PAYLOAD_SCHEMAS["compression-comparison"]
        or report["pass"] is not True
        or report["release"] != identity["release"]
        or report["source_commit"] != identity["source_commit"]
        or report["source_tree"] != identity["source_tree"]
        or report["identity_contract_sha256"] != identity_contract_sha256
        or report["selection_rule"] != configuration["selection_rule"]
    ):
        raise ReleaseError("compression comparison identity/configuration differs")
    targets = report["targets"]
    configured_targets = configuration["targets"]
    if not isinstance(targets, list) or len(targets) != len(configured_targets):
        raise ReleaseError("compression target inventory differs")
    tools = {
        record["name"]: record
        for record in identity["verification"]["reproducibility"]["tools"]
    }
    for target, expected_target in zip(targets, configured_targets, strict=True):
        target_item = _exact_fields(
            target,
            {
                "artifact",
                "input",
                "producer_receipt",
                "candidates",
                "selected",
                "selected_output",
                "rejected",
            },
            "compression target",
        )
        artifact = identity["artifacts"][expected_target["artifact"]]
        if (
            target_item["artifact"] != expected_target["artifact"]
            or target_item["input"] != expected_target["input"]
        ):
            raise ReleaseError("compression target raw-tar producer binding differs")
        validate_tar_producer_receipt(
            target_item["producer_receipt"],
            identity=identity,
            identity_contract_sha256=identity_contract_sha256,
            artifact=expected_target["artifact"],
            raw_tar=None,
        )
        candidates = target_item["candidates"]
        configured = expected_target["candidates"]
        if not isinstance(candidates, list) or len(candidates) != len(configured):
            raise ReleaseError("compression candidate inventory differs")
        validated: list[dict[str, Any]] = []
        for candidate, expected in zip(candidates, configured, strict=True):
            item = _exact_fields(
                candidate,
                {
                    "argv",
                    "byte_identical",
                    "bytes",
                    "eligible",
                    "filename",
                    "format",
                    "ineligible_reason",
                    "name",
                    "runs",
                    "sha256",
                    "tool",
                    "tradeoff",
                },
                "compression candidate",
            )
            expected_binding = {
                key: expected[key]
                for key in (
                    "argv",
                    "eligible",
                    "filename",
                    "format",
                    "ineligible_reason",
                    "name",
                    "tradeoff",
                )
            }
            if (
                any(item[key] != expected_binding[key] for key in expected_binding)
                or item["tool"] != tools[expected["tool"]]
                or item["byte_identical"] is not True
            ):
                raise ReleaseError("compression candidate binding differs")
            _positive_int(item["bytes"], "compression candidate bytes")
            _sha(item["sha256"], "compression candidate sha256")
            if item["eligible"] is False and not item["ineligible_reason"]:
                raise ReleaseError("ineligible compression candidate lacks a reason")
            runs = item["runs"]
            if not isinstance(runs, list) or len(runs) != 2:
                raise ReleaseError("compression candidate lacks A/B runs")
            for run, run_name in zip(runs, ("a", "b"), strict=True):
                run_item = _exact_fields(
                    run, {"run", "command", "output"}, "compression run"
                )
                command = _exact_fields(
                    run_item["command"],
                    {"argv", "environment", "exit_status", "stderr", "stdout"},
                    "compression run command",
                )
                expected_argv = [
                    token.replace(
                        "{input}", f"canonical/{expected_target['input']['filename']}"
                    ).replace(
                        "{output}",
                        f"candidates/{target_item['artifact']}/{item['name']}/{run_name}/{item['filename']}",
                    )
                    for token in expected["argv"]
                ]
                output = _exact_fields(
                    run_item["output"],
                    {"bytes", "filename", "sha256"},
                    "compression run output",
                )
                if (
                    run_item["run"] != run_name
                    or command["argv"] != expected_argv
                    or command["environment"]
                    != identity["verification"]["reproducibility"]["environment"]
                    or command["exit_status"] != 0
                    or output
                    != {
                        "filename": item["filename"],
                        "bytes": item["bytes"],
                        "sha256": item["sha256"],
                    }
                ):
                    raise ReleaseError("compression A/B run differs from candidate summary")
                _validate_stream_evidence(command["stdout"], "compression stdout")
                _validate_stream_evidence(command["stderr"], "compression stderr")
            validated.append(item)
        eligible = [item for item in validated if item["eligible"] is True]
        if not eligible:
            raise ReleaseError("compression target has no eligible candidates")
        selected = min(eligible, key=lambda item: (item["bytes"], item["name"]))
        expected_output = {
            "filename": selected["filename"],
            "bytes": selected["bytes"],
            "sha256": selected["sha256"],
        }
        if (
            target_item["selected"] != selected["name"]
            or expected_target["selected"] != selected["name"]
            or target_item["selected_output"] != expected_output
            or expected_output
            != {
                "filename": artifact["filename"],
                "bytes": artifact["bytes"],
                "sha256": artifact["sha256"],
            }
        ):
            raise ReleaseError(
                "compression selection is not the exact eligible minimum/published asset"
            )
        expected_rejected = []
        for item in validated:
            if item["name"] == selected["name"]:
                continue
            if item["eligible"] is False:
                reason = f"ineligible: {item['ineligible_reason']}"
            elif item["bytes"] != selected["bytes"]:
                reason = f"larger by {item['bytes'] - selected['bytes']} bytes"
            else:
                reason = (
                    f"equal size; {selected['name']} wins deterministic name tie-break"
                )
            expected_rejected.append(
                {
                    "name": item["name"],
                    "filename": item["filename"],
                    "bytes": item["bytes"],
                    "sha256": item["sha256"],
                    "eligible": item["eligible"],
                    "ineligible_reason": item["ineligible_reason"],
                    "tradeoff": item["tradeoff"],
                    "reason": reason,
                }
            )
        if target_item["rejected"] != expected_rejected:
            raise ReleaseError("compression rejected tradeoffs are incomplete")
    return report
