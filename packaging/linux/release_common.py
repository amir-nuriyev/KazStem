#!/usr/bin/env python3
"""Strict, location-independent primitives for Linux release tooling."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import io
import json
import lzma
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
import stat
import subprocess
import tarfile
import tempfile
from typing import Any, BinaryIO, Iterable
import unicodedata
from urllib.parse import unquote, urlsplit
import zipfile


IDENTITY_SCHEMA = "kazstem-linux-release-identity-v1"
READY_AUDIT_SCHEMA = "kazstem-linux-ready-run-archive-audit-v2"
SOURCE_AUDIT_SCHEMA = "kazstem-linux-corresponding-source-audit-v2"
HEX_256 = re.compile(r"[0-9a-f]{64}\Z")
COMMIT = re.compile(r"[0-9a-f]{40}\Z")
VERSION = re.compile(r"[0-9]+(?:\.[0-9]+){2}(?:[a-z0-9.-]*[a-z0-9])?\Z")
SAFE_LABEL = re.compile(r"[a-z0-9][a-z0-9._-]{0,126}\Z")
MAX_HARD_MEMBERS = 1_000_000
MAX_HARD_FILE_BYTES = 16 * 1024**3
MAX_HARD_TOTAL_BYTES = 64 * 1024**3
MAX_HARD_PATH_BYTES = 4096
REQUIRED_EVIDENCE_GATES = {
    "blackbox": "json",
    "compatibility-performance": "json-pass",
    "compression-comparison": "json",
    "elf-closure": "json-pass",
    "network-trace": "text",
    "optimization-ledger": "json",
    "practical": "json-pass",
    "python-reproducibility": "json-pass",
    "ready-archive-audit": "json-pass",
    "runtime-provenance": "json",
    "source-archive-audit": "json-pass",
    "source-suite": "text",
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
    if artifacts["ready_run"]["filename"] != f"{prefix}-ready-run.tar.xz":
        raise ReleaseError("ready-run filename does not match release/platform")
    if (
        artifacts["corresponding_source"]["filename"]
        != f"{prefix}-corresponding-source.tar.xz"
    ):
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
            "base_ledger",
            "binary_readme_template",
            "source_readme_template",
            "documents",
        },
        "inputs",
    )
    _tree(inputs["frozen_tree"], "inputs.frozen_tree")
    _tree(inputs["source_payload_tree"], "inputs.source_payload_tree")
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
    expected_ready_top = artifacts["ready_run"]["filename"][:-7]
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
            "source_date_epoch_file",
            "required_paths",
            "nested_archives",
        },
        "corresponding_source",
    )
    expected_source_top = artifacts["corresponding_source"]["filename"][:-7]
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
    epoch_file = portable_path(
        source["source_date_epoch_file"],
        label="corresponding_source.source_date_epoch_file",
    )
    application_prefix = categories["application_source"] + "/"
    if not commit_file.startswith(application_prefix) or not epoch_file.startswith(
        application_prefix
    ):
        raise ReleaseError(
            "source identity marker files must be inside application_source"
        )
    required_source_paths = _unique_paths(
        source["required_paths"], "corresponding_source.required_paths"
    )
    if not set(category_paths + [commit_file, epoch_file]) <= set(
        required_source_paths
    ):
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

    limits = _exact_fields(
        identity["archive_limits"],
        {"ready_run", "corresponding_source", "nested"},
        "archive_limits",
    )
    for name in ("ready_run", "corresponding_source", "nested"):
        _limits(limits[name], f"archive_limits.{name}")

    verification = _exact_fields(
        identity["verification"], {"minimum_distinct_roots", "evidence"}, "verification"
    )
    if (
        _positive_int(
            verification["minimum_distinct_roots"],
            "verification.minimum_distinct_roots",
        )
        < 2
    ):
        raise ReleaseError("at least two distinct native build roots are required")
    evidence = verification["evidence"]
    if not isinstance(evidence, list) or not evidence:
        raise ReleaseError("verification.evidence must be non-empty")
    evidence_paths: list[str] = []
    for index, record in enumerate(evidence):
        item = _exact_fields(
            record,
            {"path", "gate", "kind", "file"},
            f"verification.evidence[{index}]",
        )
        evidence_paths.append(
            portable_path(item["path"], label=f"verification.evidence[{index}].path")
        )
        if item["kind"] not in {"json", "json-pass", "text"}:
            raise ReleaseError(
                "verification evidence kind must be json, json-pass, or text"
            )
        if REQUIRED_EVIDENCE_GATES.get(item["gate"]) != item["kind"]:
            raise ReleaseError(
                f"invalid or wrongly typed verification gate: {item['gate']!r}"
            )
        _file_identity(item["file"], f"verification.evidence[{index}].file")
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
        "source_date_epoch": identity["source_date_epoch"],
        "release_url": identity["release_url"],
        "platform": identity["platform"],
        "artifact_locations": {
            name: {
                "filename": artifacts[name]["filename"],
                "url": artifacts[name]["url"],
            }
            for name in ("ready_run", "corresponding_source")
        },
        "canonical_python_artifacts": {
            "wheel": artifacts["wheel"],
            "sdist": artifacts["sdist"],
        },
        "source_payload_tree": identity["inputs"]["source_payload_tree"],
        "resource_bundle_id": identity["inputs"]["resource_tree"]["bundle_id"],
        "runtime_bundle_id": identity["inputs"]["runtime_tree"]["bundle_id"],
        "source_contract": {
            "categories": identity["corresponding_source"]["source_categories"],
            "source_commit_file": identity["corresponding_source"][
                "source_commit_file"
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
    if len(name.encode("utf-8")) > limits.max_path_bytes:
        raise ReleaseError(f"archive path exceeds cap: {name!r}")
    cleaned = name.rstrip("/")
    while cleaned.startswith("./"):
        cleaned = cleaned[2:]
    return portable_path(cleaned, label="archive member")


def _link_stays_within(member: str, target: str, top: str) -> None:
    if not isinstance(target, str) or not target or "\x00" in target or "\\" in target:
        raise ReleaseError(f"invalid symlink target: {member!r} -> {target!r}")
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
    try:
        with (
            tarfile.open(path, "r:*")
            if path is not None
            else tarfile.open(fileobj=fileobj, mode="r:*") as archive
        ):
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
                elif member.isdir():
                    kind = "directory"
                    size = 0
                elif member.issym():
                    kind = "symlink"
                    size = 0
                else:
                    raise ReleaseError(f"unsupported tar special member: {name!r}")
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
                    )
                )
    except (tarfile.TarError, OSError, EOFError, lzma.LZMAError) as exc:
        if isinstance(exc, ReleaseError):
            raise
        raise ReleaseError(f"cannot inspect tar archive: {exc}") from exc
    if not members:
        raise ReleaseError("tar archive has no auditable members")
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
    archive_path: Path, destination_parent: Path, *, members: list[ArchiveMember]
) -> Path:
    destination_parent = (
        destination_parent.parent.resolve(strict=True) / destination_parent.name
    )
    if destination_parent.exists():
        raise ReleaseError(
            f"fresh extraction parent already exists: {destination_parent}"
        )
    destination_parent.mkdir(parents=True)
    expected = {member.name: member for member in members}
    try:
        with tarfile.open(archive_path, "r:*") as archive:
            actual = {member.name.rstrip("/"): member for member in archive}
            if set(actual) != set(expected):
                raise ReleaseError("archive changed between inspection and extraction")
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
                target.chmod(record.mode)
            for record in members:
                if record.kind != "symlink":
                    continue
                target = destination_parent / record.name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.symlink_to(record.linkname)
                _resolved_symlink(destination_parent.resolve(strict=True), target)
            for record in sorted(
                (item for item in members if item.kind == "directory"),
                key=lambda item: len(PurePosixPath(item.name).parts),
                reverse=True,
            ):
                (destination_parent / record.name).chmod(record.mode)
    except BaseException:
        # Leave the fresh root for forensics; callers never reuse it.
        raise
    tops = sorted({PurePosixPath(member.name).parts[0] for member in members})
    if len(tops) != 1:
        raise ReleaseError("archive must contain exactly one top-level root")
    return destination_parent / tops[0]


def inspect_zip(path: Path, *, limits: ArchiveLimits) -> dict[str, Any]:
    names: set[str] = set()
    folded: set[str] = set()
    total = 0
    members = 0
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
                if total > limits.max_total_bytes:
                    raise ReleaseError("zip declared bytes exceed total cap")
                with archive.open(info) as source:
                    size, _digest = sha256_stream(
                        source, limit=min(limits.max_file_bytes, info.file_size)
                    )
                if size != info.file_size:
                    raise ReleaseError(f"zip member size mismatch: {name!r}")
    except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
        if isinstance(exc, ReleaseError):
            raise
        raise ReleaseError(f"cannot inspect zip archive {path.name}: {exc}") from exc
    if not members:
        raise ReleaseError(f"zip archive has no members: {path.name}")
    return {"members": members, "declared_bytes": total, "expanded_bytes": total}


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
                    "/usr/bin/zstd is required to inspect Ubuntu .deb members"
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
    import gzip

    try:
        with gzip.open(path, "rb") as source:
            size, digest = sha256_stream(source, limit=limits.max_file_bytes)
    except (OSError, EOFError) as exc:
        raise ReleaseError(f"cannot inspect gzip stream {path.name}: {exc}") from exc
    if size == 0:
        raise ReleaseError(f"gzip stream is empty: {path.name}")
    return {"members": 1, "expanded_bytes": size, "expanded_sha256": digest}


def inspect_nested(path: Path, kind: str, *, limits: ArchiveLimits) -> dict[str, Any]:
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


def _absolute_reference(value: str) -> bool:
    if value.startswith(("https://", "http://")):
        return False
    if value.startswith(("/", "~/", "../", "..\\", "file://", "\\\\")):
        return True
    unix_token = re.compile(r"(?<![:/A-Za-z0-9_.-])/(?:[^\s\"']+)")
    return bool(
        re.match(r"^[A-Za-z]:[\\/]", value)
        or re.search(r"(?<![A-Za-z0-9])[A-Za-z]:[\\/][^\s\"']+", value)
        or "file://" in value
        or "~/" in value
        or unix_token.search(value)
    )


def assert_relative_json(value: Any, *, label: str = "JSON evidence") -> None:
    def walk(item: Any, path: str) -> None:
        if isinstance(item, str) and _absolute_reference(item):
            raise ReleaseError(f"absolute path in {label} {path}: {item!r}")
        if isinstance(item, list):
            for index, child in enumerate(item):
                walk(child, f"{path}[{index}]")
        elif isinstance(item, dict):
            for key, child in item.items():
                walk(child, f"{path}.{key}")

    walk(value, "$")


def assert_relative_evidence(root: Path) -> None:
    if not root.is_dir() or root.is_symlink():
        raise ReleaseError(f"evidence root is missing or invalid: {root}")
    unix_token = re.compile(r"(?<![:/A-Za-z0-9_.-])/(?:[^\s\"']+)")
    drive_token = re.compile(r"(?<![A-Za-z0-9])[A-Za-z]:[\\/][^\s\"']+")

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
            try:
                assert_relative_json(
                    json.loads(text, object_pairs_hook=_pairs),
                    label=f"evidence JSON {relative}",
                )
            except json.JSONDecodeError as exc:
                raise ReleaseError(f"invalid evidence JSON {relative}: {exc}") from exc
        else:
            match = (
                unix_token.search(text)
                or drive_token.search(text)
                or re.search(r"(?:file://|~/|\.\.[\\/])[^\s\"']+", text)
            )
            if match:
                raise ReleaseError(
                    f"absolute path token in evidence {relative}: {match.group(0)!r}"
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


def verify_sealed_archive_modes(members: list[ArchiveMember]) -> None:
    failures: list[str] = []
    for member in members:
        allowed = (
            {0o444, 0o555}
            if member.kind == "file"
            else ({0o555} if member.kind == "directory" else {0o777})
        )
        if member.mode not in allowed:
            failures.append(f"{member.name}:{member.mode:04o}")
    if failures:
        raise ReleaseError(f"outer archive is not read-only sealed: {failures[:20]}")


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


def identity_sha256(path: Path) -> str:
    identity = load_identity(path)
    projection = dict(identity)
    projection["verification"] = {
        "minimum_distinct_roots": identity["verification"]["minimum_distinct_roots"],
        "evidence": [
            {
                "path": record["path"],
                "gate": record["gate"],
                "kind": record["kind"],
            }
            for record in identity["verification"]["evidence"]
        ],
    }
    return canonical_hash(projection)
