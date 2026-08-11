#!/usr/bin/env python3
"""Build and normalize one cross-platform canonical KazStem wheel/sdist pair."""

from __future__ import annotations

import argparse
import base64
import csv
from email.parser import BytesParser
from email.policy import default as email_policy
import gzip
import hashlib
import importlib.metadata
import io
import json
import os
import platform
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
import shutil
import stat
import struct
import subprocess
import sys
import sysconfig
import tarfile
import tempfile
import time
import types
from typing import Any, BinaryIO
import unicodedata
import zipfile
import zlib

_supervisor_path = Path(__file__).resolve().with_name("process_supervisor.py")
_process_supervisor = types.ModuleType("_kazstem_source_process_supervisor")
_process_supervisor.__file__ = str(_supervisor_path)
sys.modules[_process_supervisor.__name__] = _process_supervisor
try:
    _supervisor_source = _supervisor_path.read_bytes()
    exec(
        compile(_supervisor_source, str(_supervisor_path), "exec", dont_inherit=True),
        _process_supervisor.__dict__,
    )
finally:
    _supervisor_source = b""

SupervisionError = _process_supervisor.SupervisionError
PaxFormatError = _process_supervisor.PaxFormatError
parse_pax_records = _process_supervisor.parse_pax_records
run_bounded = _process_supervisor.run_bounded


IDENTITY_SCHEMA = "kazstem-canonical-python-build-identity-v2"
RECEIPT_SCHEMA = "kazstem-canonical-python-build-receipt-v2"
HEX256 = re.compile(r"[0-9a-f]{64}\Z")
GIT_ID = re.compile(r"[0-9a-f]{40}\Z")
VERSION = re.compile(r"[0-9]+(?:\.[0-9]+){2}(?:[a-z0-9.-]*[a-z0-9])?\Z")
MAX_JSON_BYTES = 16 * 1024**2
WINDOWS_RESERVED = {
    "con",
    "prn",
    "aux",
    "nul",
    *(f"com{index}" for index in range(1, 10)),
    *(f"lpt{index}" for index in range(1, 10)),
}
REQUIRED_BUILD_DISTRIBUTIONS = {
    "build",
    "packaging",
    "pip",
    "pyproject-hooks",
    "setuptools",
    "twine",
    "wheel",
}
UNNEEDED_OPENSSL_FRAGMENTS = frozenset(
    {"_hashlib", "_ssl", "libcrypto", "libssl", "openssl"}
)
_RUNTIME_OBSERVATION_CACHE: dict[str, Any] | None = None


class BuildError(RuntimeError):
    """The canonical Python build contract was violated."""


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise BuildError(f"duplicate JSON key: {key!r}")
        result[key] = value
    return result


def _read_json(path: Path) -> Any:
    if path.stat().st_size > MAX_JSON_BYTES:
        raise BuildError(f"JSON exceeds cap: {path.name}")
    try:
        return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_pairs)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise BuildError(f"invalid strict JSON {path.name}: {exc}") from exc


def _json_bytes(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode(
        "utf-8"
    )


def _hash_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _file_record(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise BuildError(f"not a regular file: {path}")
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            size += len(chunk)
            digest.update(chunk)
    return {"bytes": size, "sha256": digest.hexdigest()}


def _exact(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        observed = set(value) if isinstance(value, dict) else set()
        raise BuildError(
            f"{label} fields differ: missing={sorted(fields - observed)}, "
            f"extra={sorted(observed - fields)}"
        )
    return value


def _positive(value: Any, label: str, ceiling: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 < value <= ceiling:
        raise BuildError(f"{label} must be a bounded positive integer")
    return value


def _sha(value: Any, label: str) -> str:
    if not isinstance(value, str) or HEX256.fullmatch(value) is None:
        raise BuildError(f"{label} is not a lowercase SHA-256")
    return value


def _portable(value: Any, label: str, *, single: bool = False) -> str:
    if (
        not isinstance(value, str)
        or not value
        or "\\" in value
        or unicodedata.normalize("NFC", value) != value
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise BuildError(f"{label} is not a portable relative path")
    posix = PurePosixPath(value)
    windows = PureWindowsPath(value)
    if (
        posix.is_absolute()
        or windows.is_absolute()
        or windows.drive
        or any(part in {"", ".", ".."} or ":" in part for part in posix.parts)
        or any(
            part.endswith((".", " "))
            or part.split(".", 1)[0].casefold() in WINDOWS_RESERVED
            for part in posix.parts
        )
        or value != posix.as_posix()
        or (single and len(posix.parts) != 1)
    ):
        raise BuildError(f"{label} is not a portable relative path: {value!r}")
    return value


def _identity_file(value: Any, label: str, *, max_bytes: int) -> dict[str, Any]:
    record = _exact(value, {"bytes", "sha256"}, label)
    _positive(record["bytes"], f"{label}.bytes", max_bytes)
    _sha(record["sha256"], f"{label}.sha256")
    return record


def _canonical_hash(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
    ).hexdigest()


def _stdlib_tree_record() -> dict[str, Any]:
    stdlib = Path(sysconfig.get_path("stdlib")).resolve(strict=True)
    inventory: list[dict[str, Any]] = []
    excluded = {"__pycache__", "site-packages", "dist-packages"}
    for path in sorted(stdlib.rglob("*"), key=lambda item: item.relative_to(stdlib).as_posix()):
        relative_path = path.relative_to(stdlib)
        if any(part in excluded for part in relative_path.parts):
            continue
        relative = relative_path.as_posix()
        if path.is_dir() and not path.is_symlink():
            inventory.append({"kind": "directory", "path": relative})
        elif path.is_file():
            # Symlink location/target spellings vary across roots.  The closure
            # binds the resolved bytes under the import-visible logical name.
            inventory.append(
                {"kind": "file", "path": relative, **_file_record(path.resolve(strict=True))}
            )
        else:
            raise BuildError("standard-library byte-input tree has a special/broken entry")
    return {
        "entries": len(inventory),
        "regular_file_bytes": sum(item.get("bytes", 0) for item in inventory),
        "sha256": _canonical_hash(inventory),
    }


def _loaded_libz_record() -> dict[str, Any] | None:
    if platform.system() != "Linux":
        return None
    candidates: set[Path] = set()
    try:
        for line in Path("/proc/self/maps").read_text(encoding="utf-8").splitlines():
            fields = line.split()
            if fields and fields[-1].startswith("/") and re.search(
                r"/libz\.so(?:\.|$)", fields[-1]
            ):
                candidates.add(Path(fields[-1]).resolve(strict=True))
    except (OSError, UnicodeError) as exc:
        raise BuildError("cannot inventory the loaded zlib shared object") from exc
    if len(candidates) != 1:
        raise BuildError("loaded zlib shared-object closure is ambiguous/missing")
    return _file_record(next(iter(candidates)))


def interpreter_runtime_observation() -> dict[str, Any]:
    """Return the exact interpreter inputs that can affect artifact bytes."""

    global _RUNTIME_OBSERVATION_CACHE
    if _RUNTIME_OBSERVATION_CACHE is None:
        zlib_extension = getattr(zlib, "__file__", None)
        zlib_builtin = "zlib" in sys.builtin_module_names
        if zlib_builtin is not (zlib_extension is None):
            raise BuildError("zlib built-in/extension identity is ambiguous")
        _RUNTIME_OBSERVATION_CACHE = {
            "python_executable": _file_record(Path(sys.executable).resolve(strict=True)),
            "stdlib": {
                "excluded_names": ["__pycache__", "dist-packages", "site-packages"],
                "tree": _stdlib_tree_record(),
            },
            "zlib_builtin": zlib_builtin,
            "zlib_extension": (
                None
                if zlib_extension is None
                else _file_record(Path(zlib_extension).resolve(strict=True))
            ),
            "loaded_libz": _loaded_libz_record(),
        }
    return json.loads(json.dumps(_RUNTIME_OBSERVATION_CACHE))


def _tool_identity(value: Any, label: str, *, max_bytes: int) -> dict[str, Any]:
    tool = _exact(
        value,
        {"executable", "name", "version", "version_argv"},
        label,
    )
    if (
        not isinstance(tool["name"], str)
        or not tool["name"]
        or not isinstance(tool["version"], str)
        or not tool["version"]
        or not isinstance(tool["version_argv"], list)
        or not tool["version_argv"]
        or tool["version_argv"][0] != tool["name"]
        or any(not isinstance(item, str) or not item for item in tool["version_argv"])
    ):
        raise BuildError(f"{label} is invalid")
    _identity_file(tool["executable"], f"{label}.executable", max_bytes=max_bytes)
    return tool


def load_identity(path: Path) -> dict[str, Any]:
    identity = _exact(
        _read_json(path),
        {
            "schema",
            "release",
            "source_commit",
            "source_tree",
            "source_origin",
            "source_ref",
            "source_date_epoch",
            "distribution",
            "execution_platform",
            "interpreter_provenance",
            "artifacts",
            "build",
            "roundtrip",
            "git",
            "helpers",
            "build_stack",
            "metadata",
            "compression",
            "source_inputs",
            "canonicalizer",
            "limits",
        },
        "canonical Python build identity",
    )
    if identity["schema"] != IDENTITY_SCHEMA:
        raise BuildError("unsupported canonical Python build identity schema")
    if not isinstance(identity["release"], str) or VERSION.fullmatch(identity["release"]) is None:
        raise BuildError("release is not canonical")
    for field in ("source_commit", "source_tree"):
        if not isinstance(identity[field], str) or GIT_ID.fullmatch(identity[field]) is None:
            raise BuildError(f"{field} is not a full lowercase Git id")
    if (
        not isinstance(identity["source_origin"], str)
        or not identity["source_origin"].startswith("https://github.com/")
        or not identity["source_origin"].endswith(".git")
    ):
        raise BuildError("source_origin must be an exact GitHub HTTPS origin")
    if identity["source_ref"] != f"refs/tags/v{identity['release']}":
        raise BuildError("source_ref must be the immutable exact release tag")
    _positive(identity["source_date_epoch"], "source_date_epoch", 2**63 - 1)
    if identity["distribution"] != "kazstem":
        raise BuildError("distribution must be exactly kazstem")
    limits = _exact(
        identity["limits"],
        {"max_artifact_bytes", "max_members", "max_total_uncompressed_bytes"},
        "limits",
    )
    max_artifact = _positive(
        limits["max_artifact_bytes"], "limits.max_artifact_bytes", 16 * 1024**3
    )
    _positive(limits["max_members"], "limits.max_members", 1_000_000)
    _positive(
        limits["max_total_uncompressed_bytes"],
        "limits.max_total_uncompressed_bytes",
        64 * 1024**3,
    )
    execution_platform = _exact(
        identity["execution_platform"],
        {"machine", "python_implementation", "system"},
        "execution_platform",
    )
    if any(
        not isinstance(execution_platform[field], str) or not execution_platform[field]
        for field in execution_platform
    ):
        raise BuildError("execution_platform fields must be non-empty")
    interpreter_provenance = _exact(
        identity["interpreter_provenance"],
        {
            "build_recipe",
            "corresponding_source_path",
            "implementation",
            "license",
            "runtime_closure",
            "source_archive",
        },
        "interpreter_provenance",
    )
    if interpreter_provenance["implementation"] != "CPython":
        raise BuildError("canonical interpreter provenance must identify CPython")
    _portable(
        interpreter_provenance["corresponding_source_path"],
        "interpreter_provenance.corresponding_source_path",
    )
    source_archive = _exact(
        interpreter_provenance["source_archive"],
        {"bytes", "filename", "sha256", "url"},
        "interpreter_provenance.source_archive",
    )
    _portable(source_archive["filename"], "interpreter source filename", single=True)
    _identity_file(
        {"bytes": source_archive["bytes"], "sha256": source_archive["sha256"]},
        "interpreter_provenance.source_archive",
        max_bytes=max_artifact,
    )
    if (
        not isinstance(source_archive["url"], str)
        or not source_archive["url"].startswith("https://www.python.org/ftp/python/")
    ):
        raise BuildError("interpreter source URL must be an exact python.org source URL")
    for name in ("build_recipe", "license"):
        source_file = _exact(
            interpreter_provenance[name],
            {"file", "path"},
            f"interpreter_provenance.{name}",
        )
        _portable(source_file["path"], f"interpreter_provenance.{name}.path")
        _identity_file(
            source_file["file"],
            f"interpreter_provenance.{name}.file",
            max_bytes=max_artifact,
        )
    runtime_closure = _exact(
        interpreter_provenance["runtime_closure"],
        {
            "evidence_scope",
            "loaded_libz",
            "packages",
            "provider",
            "python_executable",
            "schema",
            "source_packages",
            "stdlib",
            "zlib_extension",
            "zlib_builtin",
        },
        "interpreter_provenance.runtime_closure",
    )
    if runtime_closure["schema"] != "kazstem-python-builder-byte-inputs-v1":
        raise BuildError("interpreter byte-input schema differs")
    evidence_scope = _exact(
        runtime_closure["evidence_scope"],
        {"bound_components", "not_claimed", "statement"},
        "interpreter byte-input evidence scope",
    )
    if evidence_scope != {
        "statement": "canonical-artifact-byte-inputs-not-complete-system-runtime-v1",
        "bound_components": [
            "declared-provider-binary-and-source-package-records",
            "interpreter-executable",
            "loaded-libz",
            "standard-library-tree-with-declared-exclusions",
            "zlib-extension-or-built-in-module",
        ],
        "not_claimed": [
            "ambient-system-dso-closure",
            "compiler-toolchain-derivation",
            "interpreter-binary-rebuild-from-declared-source",
        ],
    }:
        raise BuildError("interpreter byte-input evidence scope differs")
    provider = _exact(
        runtime_closure["provider"],
        {
            "architecture",
            "build_id",
            "kind",
            "name",
            "upstream_version",
            "version",
        },
        "interpreter runtime provider",
    )
    if (
        provider["kind"] not in {"source-build", "ubuntu-deb"}
        or any(
            not isinstance(provider[field], str) or not provider[field]
            for field in ("architecture", "name", "upstream_version", "version")
        )
        or (
            provider["build_id"] is not None
            and (
                not isinstance(provider["build_id"], str)
                or re.fullmatch(r"[0-9a-f]{40}", provider["build_id"]) is None
            )
        )
    ):
        raise BuildError("interpreter runtime provider identity is invalid")
    for name in ("python_executable",):
        _identity_file(
            runtime_closure[name],
            f"interpreter runtime {name}",
            max_bytes=max_artifact,
        )
    if runtime_closure["zlib_builtin"] is True:
        if runtime_closure["zlib_extension"] is not None:
            raise BuildError("built-in zlib closure unexpectedly binds an extension")
    elif runtime_closure["zlib_builtin"] is False:
        _identity_file(
            runtime_closure["zlib_extension"],
            "interpreter runtime zlib_extension",
            max_bytes=max_artifact,
        )
    else:
        raise BuildError("interpreter runtime zlib_builtin must be boolean")
    if runtime_closure["loaded_libz"] is not None:
        _identity_file(
            runtime_closure["loaded_libz"],
            "interpreter runtime loaded_libz",
            max_bytes=max_artifact,
        )
    if (
        execution_platform["system"].casefold() == "linux"
        and runtime_closure["loaded_libz"] is None
    ):
        raise BuildError("Linux interpreter closure must bind loaded libz bytes")
    stdlib = _exact(
        runtime_closure["stdlib"],
        {"excluded_names", "tree"},
        "interpreter runtime stdlib",
    )
    if stdlib["excluded_names"] != [
        "__pycache__",
        "dist-packages",
        "site-packages",
    ]:
        raise BuildError("interpreter stdlib exclusion policy differs")
    stdlib_tree = _exact(
        stdlib["tree"],
        {"entries", "regular_file_bytes", "sha256"},
        "interpreter runtime stdlib tree",
    )
    for field in ("entries", "regular_file_bytes"):
        _positive(stdlib_tree[field], f"interpreter stdlib tree {field}", 64 * 1024**3)
    _sha(stdlib_tree["sha256"], "interpreter stdlib tree sha256")
    for collection_name in ("packages", "source_packages"):
        collection = runtime_closure[collection_name]
        if not isinstance(collection, list):
            raise BuildError(f"interpreter runtime {collection_name} is not a list")
        names: list[str] = []
        for index, package_value in enumerate(collection):
            package = _exact(
                package_value,
                {"architecture", "file", "filename", "name", "url", "version"},
                f"interpreter runtime {collection_name}[{index}]",
            )
            filename = _portable(
                package["filename"],
                f"interpreter runtime {collection_name}[{index}].filename",
                single=True,
            )
            names.append(filename)
            if any(
                not isinstance(package[field], str) or not package[field]
                for field in ("architecture", "name", "url", "version")
            ) or not package["url"].startswith("https://"):
                raise BuildError("interpreter package provenance metadata is invalid")
            package_spelling = (
                package["name"] + " " + package["filename"]
            ).casefold()
            if any(
                fragment in package_spelling
                for fragment in UNNEEDED_OPENSSL_FRAGMENTS
            ):
                raise BuildError(
                    "unneeded OpenSSL package/source is forbidden from canonical inputs"
                )
            _identity_file(
                package["file"],
                f"interpreter runtime {collection_name}[{index}].file",
                max_bytes=max_artifact,
            )
        if names != sorted(set(names)):
            raise BuildError(f"interpreter runtime {collection_name} is not sorted/unique")
    if not runtime_closure["source_packages"]:
        raise BuildError("interpreter runtime has no corresponding source package")
    if provider["kind"] == "ubuntu-deb" and (
        not runtime_closure["packages"]
        or provider["build_id"] is None
        or provider["name"] != "ubuntu"
    ):
        raise BuildError("Ubuntu interpreter byte-input provenance is incomplete")
    artifacts = _exact(identity["artifacts"], {"sdist", "wheel"}, "artifacts")
    expected_names = {
        "wheel": f"kazstem-{identity['release']}-py3-none-any.whl",
        "sdist": f"kazstem-{identity['release']}.tar.gz",
    }
    for name, expected_name in expected_names.items():
        record = _exact(
            artifacts[name], {"bytes", "filename", "sha256"}, f"artifacts.{name}"
        )
        if _portable(record["filename"], f"artifacts.{name}.filename", single=True) != expected_name:
            raise BuildError(f"artifacts.{name}.filename differs")
        _identity_file(
            {"bytes": record["bytes"], "sha256": record["sha256"]},
            f"artifacts.{name}",
            max_bytes=max_artifact,
        )
    git = _tool_identity(identity["git"], "git", max_bytes=max_artifact)
    if git["name"] != "git" or git["version_argv"] != ["git", "--version"]:
        raise BuildError("git tool must be exactly git --version")
    compression = _exact(
        identity["compression"],
        {"implementation", "zlib_compile_version", "zlib_runtime_version"},
        "compression",
    )
    if compression["implementation"] != "python-stdlib-zlib-deflate-9":
        raise BuildError("unsupported canonical compression implementation")
    for field in ("zlib_compile_version", "zlib_runtime_version"):
        if not isinstance(compression[field], str) or not compression[field]:
            raise BuildError(f"compression.{field} is empty")
    metadata = _exact(
        identity["metadata"],
        {
            "license_expression",
            "metadata_version",
            "required_classifiers",
            "wheel_version",
        },
        "metadata",
    )
    if metadata["metadata_version"] not in {"2.1", "2.2", "2.3", "2.4"}:
        raise BuildError("metadata.metadata_version is unsupported")
    if metadata["wheel_version"] != "1.0":
        raise BuildError("metadata.wheel_version must be exactly 1.0")
    if metadata["license_expression"] is not None and (
        not isinstance(metadata["license_expression"], str)
        or not metadata["license_expression"]
    ):
        raise BuildError("metadata.license_expression is invalid")
    classifiers = metadata["required_classifiers"]
    if (
        not isinstance(classifiers, list)
        or any(not isinstance(item, str) or not item for item in classifiers)
        or classifiers != sorted(set(classifiers))
    ):
        raise BuildError("metadata.required_classifiers must be sorted and unique")
    canonicalizer = _exact(identity["canonicalizer"], {"file", "path"}, "canonicalizer")
    if canonicalizer["path"] != "packaging/build_canonical_python_artifacts.py":
        raise BuildError("canonicalizer path is not the shared builder")
    _identity_file(canonicalizer["file"], "canonicalizer.file", max_bytes=max_artifact)
    helpers = _exact(identity["helpers"], {"process_supervisor"}, "helpers")
    supervisor = _exact(
        helpers["process_supervisor"], {"file", "path"}, "helpers.process_supervisor"
    )
    if supervisor["path"] != "packaging/process_supervisor.py":
        raise BuildError("process supervisor path differs")
    _identity_file(
        supervisor["file"], "helpers.process_supervisor.file", max_bytes=max_artifact
    )
    adjacent_supervisor = Path(__file__).resolve().with_name("process_supervisor.py")
    imported_supervisor = Path(_process_supervisor.__file__).resolve(strict=True)
    if imported_supervisor != adjacent_supervisor:
        raise BuildError("process supervisor import is not exact and adjacent")
    if _file_record(imported_supervisor) != supervisor["file"]:
        raise BuildError("loaded process supervisor bytes differ from identity")
    source_inputs = identity["source_inputs"]
    if not isinstance(source_inputs, list) or not source_inputs:
        raise BuildError("source_inputs must be non-empty")
    input_paths: list[str] = []
    for index, item_value in enumerate(source_inputs):
        item = _exact(item_value, {"file", "path"}, f"source_inputs[{index}]")
        input_paths.append(_portable(item["path"], f"source_inputs[{index}].path"))
        _identity_file(item["file"], f"source_inputs[{index}].file", max_bytes=max_artifact)
    if input_paths != sorted(set(input_paths)):
        raise BuildError("source_inputs must be sorted and unique")
    stack = _exact(
        identity["build_stack"],
        {
            "bootstrap_pip",
            "metadata_check_argv",
            "packages",
            "provision_argv",
            "requirements",
            "wheelhouse",
        },
        "build_stack",
    )
    requirements = _exact(
        stack["requirements"], {"file", "path"}, "build_stack.requirements"
    )
    _portable(requirements["path"], "build_stack.requirements.path")
    _identity_file(
        requirements["file"],
        "build_stack.requirements.file",
        max_bytes=max_artifact,
    )
    wheelhouse = _exact(
        stack["wheelhouse"], {"files", "manifest_sha256"}, "build_stack.wheelhouse"
    )
    wheels = wheelhouse["files"]
    if not isinstance(wheels, list) or not wheels:
        raise BuildError("build_stack.wheelhouse.files must be non-empty")
    wheel_names: list[str] = []
    for index, wheel_value in enumerate(wheels):
        wheel_record = _exact(
            wheel_value,
            {"bytes", "filename", "sha256"},
            f"build_stack.wheelhouse.files[{index}]",
        )
        wheel_names.append(
            _portable(
                wheel_record["filename"],
                f"build_stack.wheelhouse.files[{index}].filename",
                single=True,
            )
        )
        if not wheel_record["filename"].endswith(".whl"):
            raise BuildError("wheelhouse contains a non-wheel file")
        _identity_file(
            {"bytes": wheel_record["bytes"], "sha256": wheel_record["sha256"]},
            f"build_stack.wheelhouse.files[{index}]",
            max_bytes=max_artifact,
        )
    if wheel_names != sorted(set(wheel_names)):
        raise BuildError("wheelhouse filenames must be sorted and unique")
    _sha(wheelhouse["manifest_sha256"], "build_stack.wheelhouse.manifest_sha256")
    bootstrap_pip = _exact(
        stack["bootstrap_pip"],
        {"file", "filename", "version"},
        "build_stack.bootstrap_pip",
    )
    _identity_file(
        bootstrap_pip["file"],
        "build_stack.bootstrap_pip.file",
        max_bytes=max_artifact,
    )
    if (
        bootstrap_pip["filename"] not in wheel_names
        or not bootstrap_pip["filename"].casefold().startswith("pip-")
        or not isinstance(bootstrap_pip["version"], str)
        or not bootstrap_pip["version"]
        or next(
            item for item in wheels if item["filename"] == bootstrap_pip["filename"]
        )
        != {"filename": bootstrap_pip["filename"], **bootstrap_pip["file"]}
    ):
        raise BuildError("bootstrap pip wheel differs from locked wheelhouse")
    if wheelhouse["manifest_sha256"] != _canonical_hash(wheels):
        raise BuildError("wheelhouse manifest digest differs")
    packages = stack["packages"]
    if not isinstance(packages, list):
        raise BuildError("build_stack.packages must be a list")
    package_names: list[str] = []
    for index, package_value in enumerate(packages):
        package = _exact(
            package_value, {"name", "version"}, f"build_stack.packages[{index}]"
        )
        if (
            not isinstance(package["name"], str)
            or not package["name"]
            or not isinstance(package["version"], str)
            or not package["version"]
        ):
            raise BuildError("build stack package identity is invalid")
        package_names.append(package["name"].casefold().replace("_", "-"))
    if package_names != sorted(set(package_names)):
        raise BuildError("build stack packages must be normalized, sorted, and unique")
    if not REQUIRED_BUILD_DISTRIBUTIONS <= set(package_names):
        raise BuildError("build stack omits required build/metadata distributions")
    if {"name": "pip", "version": bootstrap_pip["version"]} not in packages:
        raise BuildError("bootstrap pip version differs from provisioned package set")
    expected_provision = [
        "{python}",
        "-S",
        "-m",
        "pip",
        "install",
        "--no-index",
        "--require-hashes",
        "--no-deps",
        "--only-binary=:all:",
        "--target",
        "{build_env}",
        "--find-links",
        "{wheelhouse}",
        "-r",
        "{requirements}",
    ]
    if stack["provision_argv"] != expected_provision:
        raise BuildError("build_stack.provision_argv is not the offline locked command")
    if stack["metadata_check_argv"] != [
        "{python}",
        "-S",
        "-m",
        "twine",
        "check",
        "--strict",
        "{wheel}",
        "{sdist}",
    ]:
        raise BuildError("build_stack.metadata_check_argv must be twine check --strict")
    input_by_path = {item["path"]: item["file"] for item in source_inputs}
    if input_by_path.get(supervisor["path"]) != supervisor["file"]:
        raise BuildError("process supervisor must be an exact declared source input")
    if input_by_path.get(requirements["path"]) != requirements["file"]:
        raise BuildError("offline requirements must be an exact declared source input")
    for name in ("build_recipe", "license"):
        provenance_file = interpreter_provenance[name]
        if input_by_path.get(provenance_file["path"]) != provenance_file["file"]:
            raise BuildError(f"interpreter {name} must be an exact source input")
    for section_name in ("build", "roundtrip"):
        section = _exact(
            identity[section_name],
            {"argv", "environment", "tool", "timeout_seconds"},
            section_name,
        )
        argv = section["argv"]
        if (
            not isinstance(argv, list)
            or len(argv) < 3
            or any(not isinstance(item, str) or not item for item in argv)
            or argv[0] != "{python}"
            or argv[1] != "-S"
            or sum(item.count("{raw_dist}") for item in argv) != 1
            or any(
                "{" in item.replace("{raw_dist}", "").replace("{python}", "")
                for item in argv
            )
        ):
            raise BuildError(f"{section_name}.argv is invalid")
        environment = _exact(
            section["environment"],
            {"LANG", "LC_ALL", "PYTHONHASHSEED", "SOURCE_DATE_EPOCH", "TZ"},
            f"{section_name}.environment",
        )
        expected_environment = {
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "PYTHONHASHSEED": "0",
            "SOURCE_DATE_EPOCH": str(identity["source_date_epoch"]),
            "TZ": "UTC",
        }
        if environment != expected_environment:
            raise BuildError(f"{section_name}.environment differs")
        tool = _tool_identity(
            section["tool"], f"{section_name}.tool", max_bytes=max_artifact
        )
        if tool["version_argv"][0] != tool["name"]:
            raise BuildError(f"{section_name}.tool/argv differs")
        _positive(section["timeout_seconds"], f"{section_name}.timeout_seconds", 24 * 60 * 60)
    if identity["build"]["tool"] != identity["roundtrip"]["tool"]:
        raise BuildError("primary and roundtrip Python tool identities differ")
    if runtime_closure["python_executable"] != identity["build"]["tool"][
        "executable"
    ]:
        raise BuildError("interpreter runtime executable differs from build tool")
    version_match = re.search(
        r"\bPython ([0-9]+\.[0-9]+\.[0-9]+)\b",
        identity["build"]["tool"]["version"],
    )
    if version_match is None:
        raise BuildError("canonical Python tool version is not CPython X.Y.Z")
    interpreter_version = version_match.group(1)
    if provider["upstream_version"] != interpreter_version:
        raise BuildError("interpreter runtime upstream version differs")
    if provider["kind"] == "source-build" and provider["version"] != interpreter_version:
        raise BuildError("source-built interpreter provider version differs")
    if provider["kind"] == "ubuntu-deb" and not provider["version"].startswith(
        interpreter_version + "-"
    ):
        raise BuildError("Ubuntu interpreter package version differs from CPython")
    if provider["kind"] == "ubuntu-deb":
        minor = ".".join(interpreter_version.split(".")[:2])
        required_binary_packages = {
            f"libpython{minor}-minimal",
            f"libpython{minor}-stdlib",
            f"python{minor}",
            f"python{minor}-minimal",
        }
        package_by_name = {
            item["name"]: item for item in runtime_closure["packages"]
        }
        for package_name in required_binary_packages:
            package = package_by_name.get(package_name)
            if (
                package is None
                or package["version"] != provider["version"]
                or package["architecture"] != provider["architecture"]
            ):
                raise BuildError(
                    "Ubuntu interpreter binary-package input set is incomplete"
                )
        if "zlib1g" not in package_by_name:
            raise BuildError("Ubuntu interpreter inputs omit the loaded zlib package")
        source_names = {
            item["name"] for item in runtime_closure["source_packages"]
        }
        if f"python{minor}" not in source_names or "zlib" not in source_names:
            raise BuildError(
                "Ubuntu interpreter corresponding-source input set is incomplete"
            )
    expected_source_filename = f"Python-{interpreter_version}.tgz"
    if (
        source_archive["filename"] != expected_source_filename
        or source_archive["url"]
        != f"https://www.python.org/ftp/python/{interpreter_version}/{expected_source_filename}"
    ):
        raise BuildError("CPython source archive does not match interpreter version")
    if not any(
        item["filename"] == source_archive["filename"]
        and item["url"] == source_archive["url"]
        and item["file"]
        == {"bytes": source_archive["bytes"], "sha256": source_archive["sha256"]}
        for item in runtime_closure["source_packages"]
    ):
        raise BuildError("interpreter runtime sources omit the upstream CPython archive")
    return identity


def _same_or_nested(first: Path, second: Path) -> bool:
    one = first.resolve(strict=False)
    two = second.resolve(strict=False)
    return one == two or one in two.parents or two in one.parents


def _verify_distinct(paths: list[tuple[str, Path]]) -> None:
    for index, (first_label, first) in enumerate(paths):
        for second_label, second in paths[index + 1 :]:
            if _same_or_nested(first, second):
                raise BuildError(f"{first_label} and {second_label} are equal/nested")
            if first.exists() and second.exists() and os.path.samefile(first, second):
                raise BuildError(f"{first_label} and {second_label} are filesystem aliases")


def _git_output(
    git: str, checkout: Path, *args: str, environment: dict[str, str]
) -> str:
    result = subprocess.run(
        [git, *args],
        cwd=checkout,
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=60,
    )
    if result.returncode:
        raise BuildError(f"git {' '.join(args)} failed")
    return result.stdout.strip()


def _verify_source(checkout: Path, identity: dict[str, Any]) -> dict[str, Any]:
    if checkout.is_symlink() or not checkout.is_dir():
        raise BuildError("source checkout is not a real directory")
    git_path, git_record = _resolved_tool(identity["git"])
    git = str(git_path)
    with tempfile.TemporaryDirectory(prefix="kazstem-git-home-") as temporary:
        environment = {
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_TERMINAL_PROMPT": "0",
            "HOME": temporary,
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "PATH": os.environ.get("PATH", os.defpath),
            "TZ": "UTC",
        }
        checks = (
            (_git_output(git, checkout, "rev-parse", "HEAD", environment=environment), identity["source_commit"]),
            (_git_output(git, checkout, "rev-parse", "HEAD^{tree}", environment=environment), identity["source_tree"]),
            (_git_output(git, checkout, "remote", "get-url", "origin", environment=environment), identity["source_origin"]),
            (
                _git_output(
                    git,
                    checkout,
                    "rev-parse",
                    f"{identity['source_ref']}^{{commit}}",
                    environment=environment,
                ),
                identity["source_commit"],
            ),
        )
        if any(observed != expected for observed, expected in checks):
            raise BuildError("source checkout commit/tree/origin/ref differs")
        if _git_output(
            git,
            checkout,
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
            "--ignored=matching",
            environment=environment,
        ):
            raise BuildError("source checkout is dirty")
    for item in [
        *identity["source_inputs"],
        identity["canonicalizer"],
        identity["helpers"]["process_supervisor"],
    ]:
        path = checkout / item["path"]
        if _file_record(path) != item["file"]:
            raise BuildError(f"source input differs: {item['path']}")
    return git_record


def _resolved_tool(expected: dict[str, Any]) -> tuple[Path, dict[str, Any]]:
    found = shutil.which(expected["name"])
    if found is None:
        raise BuildError(f"build tool unavailable: {expected['name']}")
    executable = Path(found).resolve(strict=True)
    if _file_record(executable) != expected["executable"]:
        raise BuildError("build tool executable differs")
    result = subprocess.run(
        [str(executable), *expected["version_argv"][1:]],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
        timeout=60,
    )
    if result.returncode or result.stdout.decode("utf-8", "replace").strip() != expected["version"]:
        raise BuildError("build tool version differs")
    return executable, expected


def _tool(identity_section: dict[str, Any]) -> tuple[Path, dict[str, Any]]:
    return _resolved_tool(identity_section["tool"])


def _stream_record(path: Path, cap: int) -> dict[str, Any]:
    if path.stat().st_size > cap:
        raise BuildError("build output stream exceeds capture cap")
    data = path.read_bytes()
    return {
        "bytes": len(data),
        "sha256": _hash_bytes(data),
        "lines": len(data.splitlines()),
        "truncated": False,
    }


def _verified_wheelhouse(path: Path, identity: dict[str, Any]) -> dict[str, Any]:
    if path.is_symlink() or not path.is_dir():
        raise BuildError("wheelhouse is not a real directory")
    observed: list[dict[str, Any]] = []
    for item in sorted(path.iterdir(), key=lambda candidate: candidate.name):
        if item.is_symlink() or not item.is_file():
            raise BuildError("wheelhouse contains a directory/link/special entry")
        _portable(item.name, "wheelhouse filename", single=True)
        observed.append({"filename": item.name, **_file_record(item)})
    expected = identity["build_stack"]["wheelhouse"]
    if observed != expected["files"] or _canonical_hash(observed) != expected["manifest_sha256"]:
        raise BuildError("wheelhouse inventory differs from identity")
    return {"files": observed, "manifest_sha256": expected["manifest_sha256"]}


def _controlled_environment(
    section: dict[str, Any],
    *,
    home: Path,
    build_env: Path | None,
    bootstrap_pythonpath: tuple[Path, str] | None = None,
) -> tuple[dict[str, str], dict[str, str]]:
    home.mkdir()
    temporary = home.parent / (home.name + "-tmp")
    cache = home.parent / (home.name + "-cache")
    pycache = home.parent / (home.name + "-pycache")
    temporary.mkdir()
    cache.mkdir()
    pycache.mkdir()
    logical = {
        **section["environment"],
        "GIT_CONFIG_GLOBAL": "disabled",
        "GIT_CONFIG_NOSYSTEM": "1",
        "HOME": "workspace/home",
        "PIP_CONFIG_FILE": "disabled",
        "PIP_DISABLE_PIP_VERSION_CHECK": "1",
        "PIP_NO_INDEX": "1",
        "PYTHONNOUSERSITE": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONPYCACHEPREFIX": "workspace/pycache",
        "TEMP": "workspace/tmp",
        "TMP": "workspace/tmp",
        "TMPDIR": "workspace/tmp",
        "XDG_CACHE_HOME": "workspace/cache",
    }
    actual = {
        **section["environment"],
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "HOME": str(home),
        "PIP_CONFIG_FILE": os.devnull,
        "PIP_DISABLE_PIP_VERSION_CHECK": "1",
        "PIP_NO_INDEX": "1",
        "PYTHONNOUSERSITE": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONPYCACHEPREFIX": str(pycache),
        "TEMP": str(temporary),
        "TMP": str(temporary),
        "TMPDIR": str(temporary),
        "XDG_CACHE_HOME": str(cache),
    }
    if build_env is not None:
        actual["PYTHONPATH"] = str(build_env)
        logical["PYTHONPATH"] = "workspace/build-env"
    elif bootstrap_pythonpath is not None:
        actual["PYTHONPATH"] = str(bootstrap_pythonpath[0])
        logical["PYTHONPATH"] = bootstrap_pythonpath[1]
    return actual, logical


def _normalized_stream(
    data: bytes, replacements: list[tuple[str, str]], *, label: str
) -> bytes:
    try:
        text = data.decode("utf-8")
    except UnicodeError as exc:
        raise BuildError(f"{label} is not UTF-8 and cannot be path-normalized") from exc
    text = text.replace("\r\n", "\n")
    for actual, logical in sorted(replacements, key=lambda item: len(item[0]), reverse=True):
        if actual:
            text = text.replace(actual, logical)
            text = text.replace(actual.replace("/", "\\"), logical)
    return text.encode("utf-8")


def _run_captured(
    actual: list[str],
    logical: list[str],
    *,
    cwd: Path,
    environment: dict[str, str],
    logical_environment: dict[str, str],
    capture_root: Path,
    timeout: int,
) -> dict[str, Any]:
    if capture_root.exists() or capture_root.is_symlink():
        raise BuildError("capture root existed before command")
    capture_root.mkdir()
    stdout_path = capture_root / "stdout.bin"
    stderr_path = capture_root / "stderr.bin"
    try:
        completed = run_bounded(
            actual,
            cwd=cwd,
            environment=environment,
            timeout=timeout,
            max_stdout=MAX_JSON_BYTES,
            max_stderr=MAX_JSON_BYTES,
        )
    except SupervisionError as exc:
        raise BuildError(f"command failed supervision: {logical!r}: {exc}") from exc
    replacements = [
        (actual_item, logical_item)
        for actual_item, logical_item in zip(actual, logical, strict=True)
        if actual_item != logical_item
    ]
    replacements.extend(
        (actual_value, logical_environment[key])
        for key, actual_value in environment.items()
        if key in logical_environment and actual_value != logical_environment[key]
    )
    replacements.append((str(cwd), "source-checkout"))
    stdout_data = _normalized_stream(
        completed.stdout, replacements, label="command stdout"
    )
    stderr_data = _normalized_stream(
        completed.stderr, replacements, label="command stderr"
    )
    stdout_path.write_bytes(stdout_data)
    stderr_path.write_bytes(stderr_data)
    record = {
        "argv": logical,
        "environment": logical_environment,
        "timeout_seconds": timeout,
        "exit_status": completed.returncode,
        "stdout": _stream_record(stdout_path, MAX_JSON_BYTES),
        "stderr": _stream_record(stderr_path, MAX_JSON_BYTES),
    }
    if completed.returncode:
        detail = stderr_data[:4096].decode("utf-8", "replace")
        raise BuildError(
            f"command failed with exit {completed.returncode}: {logical!r}: {detail}"
        )
    return record


def _installed_packages(build_env: Path) -> list[dict[str, str]]:
    packages: list[dict[str, str]] = []
    seen: set[str] = set()
    for distribution in importlib.metadata.distributions(path=[str(build_env)]):
        raw_name = distribution.metadata.get("Name", "")
        name = raw_name.casefold().replace("_", "-")
        version = distribution.version
        if not name or name in seen or not version:
            raise BuildError("provisioned build environment has invalid/duplicate metadata")
        seen.add(name)
        packages.append({"name": name, "version": version})
    return sorted(packages, key=lambda item: item["name"])


def _source_snapshot(root: Path) -> dict[str, Any]:
    entries: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        relative_path = path.relative_to(root)
        if ".git" in relative_path.parts:
            continue
        relative = relative_path.as_posix()
        _portable(relative, "source snapshot path")
        metadata = path.lstat()
        if stat.S_ISDIR(metadata.st_mode):
            entries.append({"kind": "directory", "path": relative})
        elif stat.S_ISREG(metadata.st_mode):
            entries.append({"kind": "file", "path": relative, **_file_record(path)})
        else:
            raise BuildError("source snapshot contains a link/special entry")
    return {"entries": len(entries), "sha256": _canonical_hash(entries)}


def _provision_build_env(
    identity: dict[str, Any],
    *,
    section: dict[str, Any],
    checkout: Path,
    wheelhouse: Path,
    requirements_relative: str,
    build_env: Path,
    capture_root: Path,
) -> dict[str, Any]:
    if build_env.exists() or build_env.is_symlink():
        raise BuildError("build environment existed before offline provisioning")
    requirements = checkout.joinpath(*PurePosixPath(requirements_relative).parts)
    if _file_record(requirements) != identity["build_stack"]["requirements"]["file"]:
        raise BuildError("offline requirements file differs")
    executable, tool = _tool(section)
    configured = identity["build_stack"]["provision_argv"]
    actual = [
        str(executable),
        *[
            item.replace("{build_env}", str(build_env))
            .replace("{wheelhouse}", str(wheelhouse))
            .replace("{requirements}", str(requirements))
            for item in configured[1:]
        ],
    ]
    logical = [
        item.replace("{build_env}", "workspace/build-env")
        .replace("{wheelhouse}", "inputs/wheelhouse")
        .replace("{requirements}", requirements_relative)
        for item in configured
    ]
    actual_environment, logical_environment = _controlled_environment(
        section,
        home=capture_root.parent / "provision-home",
        build_env=None,
        bootstrap_pythonpath=(
            wheelhouse / identity["build_stack"]["bootstrap_pip"]["filename"],
            "inputs/wheelhouse/"
            + identity["build_stack"]["bootstrap_pip"]["filename"],
        ),
    )
    invocation = _run_captured(
        actual,
        logical,
        cwd=checkout,
        environment=actual_environment,
        logical_environment=logical_environment,
        capture_root=capture_root,
        timeout=section["timeout_seconds"],
    )
    observed = _installed_packages(build_env)
    if observed != identity["build_stack"]["packages"]:
        raise BuildError(
            f"provisioned build package set differs: expected={identity['build_stack']['packages']!r}, "
            f"observed={observed!r}"
        )
    return {"invocation": invocation, "packages": observed, "tool": tool}


def _run_build(
    section: dict[str, Any],
    *,
    checkout: Path,
    raw_dist: Path,
    capture_root: Path,
    build_env: Path,
) -> dict[str, Any]:
    executable, tool = _tool(section)
    if raw_dist.exists() or raw_dist.is_symlink():
        raise BuildError("raw build output existed before command")
    actual = [
        str(executable),
        *[
            item.replace("{raw_dist}", str(raw_dist))
            for item in section["argv"][1:]
        ],
    ]
    logical = [
        item.replace("{raw_dist}", "workspace/raw-dist") for item in section["argv"]
    ]
    environment, logical_environment = _controlled_environment(
        section, home=capture_root.parent / "build-home", build_env=build_env
    )
    return {
        **_run_captured(
            actual,
            logical,
            cwd=checkout,
            environment=environment,
            logical_environment=logical_environment,
            capture_root=capture_root,
            timeout=section["timeout_seconds"],
        ),
        "tool": tool,
    }


def _metadata_identity(
    data: bytes, *, distribution: str, release: str, identity: dict[str, Any], label: str
) -> None:
    message = BytesParser(policy=email_policy).parsebytes(data)
    required_singletons = ("Metadata-Version", "Name", "Version")
    if any(len(message.get_all(field, [])) != 1 for field in required_singletons):
        raise BuildError(f"{label} lacks exact singleton identity headers")
    if (
        message["Name"].casefold().replace("_", "-") != distribution
        or message["Version"] != release
        or message["Metadata-Version"] != identity["metadata"]["metadata_version"]
    ):
        raise BuildError(f"{label} Name/Version differs")
    classifiers = sorted(message.get_all("Classifier", []))
    if classifiers != identity["metadata"]["required_classifiers"]:
        raise BuildError(f"{label} classifiers differ")
    licenses = message.get_all("License-Expression", [])
    expected_license = identity["metadata"]["license_expression"]
    if (licenses[0] if len(licenses) == 1 else None) != expected_license or (
        expected_license is None and licenses
    ):
        raise BuildError(f"{label} License-Expression differs")


def _safe_name(name: str, label: str) -> str:
    cleaned = name.rstrip("/")
    _portable(cleaned, label)
    return cleaned


def _reject_file_ancestor_collisions(names: set[str], label: str) -> None:
    folded = {unicodedata.normalize("NFC", name).casefold(): name for name in names}
    for name in names:
        parts = PurePosixPath(name).parts
        for index in range(1, len(parts)):
            parent = PurePosixPath(*parts[:index]).as_posix()
            if parent.casefold() in folded:
                raise BuildError(f"{label} has a file/descendant collision")


def _wheel_record_hash(data: bytes) -> str:
    return "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode(
        "ascii"
    )


def _inspect_zip_physical(source: Path, cap: int) -> None:
    data = source.read_bytes()
    if len(data) > cap:
        raise BuildError("raw wheel exceeds cap")
    eocd = data.rfind(b"PK\x05\x06")
    if eocd < 0 or eocd + 22 > len(data):
        raise BuildError("wheel lacks a complete ZIP end record")
    (
        disk,
        central_disk,
        disk_entries,
        entries,
        central_size,
        central_offset,
        comment_length,
    ) = struct.unpack_from("<HHHHIIH", data, eocd + 4)
    if (
        disk
        or central_disk
        or disk_entries != entries
        or eocd + 22 + comment_length != len(data)
        or comment_length
        or central_offset + central_size != eocd
        or entries == 0xFFFF
        or central_offset == 0xFFFFFFFF
        or central_size == 0xFFFFFFFF
    ):
        raise BuildError("wheel ZIP disk/count/comment/offset contract differs")
    position = central_offset
    locals_: list[tuple[int, int, int, int, int, int, bytes]] = []
    for _ in range(entries):
        if position + 46 > eocd or data[position : position + 4] != b"PK\x01\x02":
            raise BuildError("wheel central directory is malformed")
        (
            flags,
            compression,
            crc,
            compressed_size,
            expanded_size,
            name_length,
            extra_length,
            member_comment_length,
            local_offset,
        ) = (
            struct.unpack_from("<H", data, position + 8)[0],
            struct.unpack_from("<H", data, position + 10)[0],
            struct.unpack_from("<I", data, position + 16)[0],
            struct.unpack_from("<I", data, position + 20)[0],
            struct.unpack_from("<I", data, position + 24)[0],
            struct.unpack_from("<H", data, position + 28)[0],
            struct.unpack_from("<H", data, position + 30)[0],
            struct.unpack_from("<H", data, position + 32)[0],
            struct.unpack_from("<I", data, position + 42)[0],
        )
        end = position + 46 + name_length + extra_length + member_comment_length
        if end > eocd or flags & ~0x800 or compression not in {0, 8}:
            raise BuildError("wheel uses unsupported ZIP flags/compression/metadata")
        name = data[position + 46 : position + 46 + name_length]
        locals_.append(
            (local_offset, compressed_size, expanded_size, crc, compression, flags, name)
        )
        position = end
    if position != eocd:
        raise BuildError("wheel has unreferenced central-directory bytes")
    expected_offset = 0
    for (
        local_offset,
        compressed_size,
        expanded_size,
        crc,
        compression,
        flags,
        name,
    ) in sorted(locals_):
        if local_offset != expected_offset or local_offset + 30 > central_offset:
            raise BuildError("wheel has prepended/unreferenced local bytes")
        if data[local_offset : local_offset + 4] != b"PK\x03\x04":
            raise BuildError("wheel local header signature differs")
        local_flags = struct.unpack_from("<H", data, local_offset + 6)[0]
        local_compression = struct.unpack_from("<H", data, local_offset + 8)[0]
        local_crc = struct.unpack_from("<I", data, local_offset + 14)[0]
        local_compressed = struct.unpack_from("<I", data, local_offset + 18)[0]
        local_expanded = struct.unpack_from("<I", data, local_offset + 22)[0]
        local_name_length = struct.unpack_from("<H", data, local_offset + 26)[0]
        local_extra_length = struct.unpack_from("<H", data, local_offset + 28)[0]
        local_name = data[
            local_offset + 30 : local_offset + 30 + local_name_length
        ]
        if (
            local_flags != flags
            or local_compression != compression
            or local_crc != crc
            or local_compressed != compressed_size
            or local_expanded != expanded_size
            or local_name != name
        ):
            raise BuildError("wheel local/central metadata differs")
        expected_offset = (
            local_offset + 30 + local_name_length + local_extra_length + compressed_size
        )
        if expected_offset > central_offset:
            raise BuildError("wheel compressed body crosses central directory")
    if expected_offset != central_offset:
        raise BuildError("wheel contains trailing/unreferenced local bytes")


def _repack_wheel(
    source: Path, destination: Path, identity: dict[str, Any]
) -> dict[str, Any]:
    limits = identity["limits"]
    if source.stat().st_size > limits["max_artifact_bytes"]:
        raise BuildError("raw wheel exceeds cap")
    _inspect_zip_physical(source, limits["max_artifact_bytes"])
    files: dict[str, tuple[bytes, bool]] = {}
    folded: set[str] = set()
    with zipfile.ZipFile(source) as archive:
        if archive.comment:
            raise BuildError("raw wheel archive comment is forbidden")
        infos = archive.infolist()
        if len(infos) > limits["max_members"]:
            raise BuildError("wheel member count exceeds cap")
        total = 0
        for info in infos:
            name = _safe_name(info.filename, "wheel member")
            folded_name = unicodedata.normalize("NFC", name).casefold()
            if name in files or folded_name in folded:
                raise BuildError("wheel has duplicate/case-colliding members")
            folded.add(folded_name)
            if info.flag_bits & 1:
                raise BuildError("encrypted wheel member is forbidden")
            mode = (info.external_attr >> 16) & 0xFFFF
            kind = stat.S_IFMT(mode)
            if info.is_dir():
                continue
            if kind not in {0, stat.S_IFREG}:
                raise BuildError("wheel special entry is forbidden")
            if info.file_size > limits["max_artifact_bytes"]:
                raise BuildError("wheel member exceeds cap")
            data = archive.read(info)
            if len(data) != info.file_size:
                raise BuildError("wheel member size differs")
            total += len(data)
            if total > limits["max_total_uncompressed_bytes"]:
                raise BuildError("wheel expansion exceeds cap")
            files[name] = (data, bool(mode & 0o111))
    _reject_file_ancestor_collisions(set(files), "wheel")
    dist_info = sorted(
        {PurePosixPath(name).parts[0] for name in files if ".dist-info/" in name}
    )
    if len(dist_info) != 1:
        raise BuildError("wheel must contain exactly one dist-info directory")
    record_name = f"{dist_info[0]}/RECORD"
    metadata_name = f"{dist_info[0]}/METADATA"
    wheel_name = f"{dist_info[0]}/WHEEL"
    if not {record_name, metadata_name, wheel_name} <= set(files):
        raise BuildError("wheel lacks RECORD/METADATA/WHEEL")
    _metadata_identity(
        files[metadata_name][0],
        distribution=identity["distribution"],
        release=identity["release"],
        identity=identity,
        label="wheel METADATA",
    )
    wheel_metadata = BytesParser(policy=email_policy).parsebytes(files[wheel_name][0])
    if (
        wheel_metadata.get_all("Wheel-Version", [])
        != [identity["metadata"]["wheel_version"]]
        or wheel_metadata.get_all("Root-Is-Purelib", []) != ["true"]
        or wheel_metadata.get_all("Tag", []) != ["py3-none-any"]
    ):
        raise BuildError("wheel WHEEL metadata/version/tag differs")
    if wheel_metadata.get("Root-Is-Purelib", "").casefold() != "true":
        raise BuildError("wheel is not purelib")
    record_rows = list(csv.reader(io.StringIO(files[record_name][0].decode("utf-8"))))
    if len(record_rows) != len(files):
        raise BuildError("wheel RECORD is not complete")
    seen: set[str] = set()
    for row in record_rows:
        if len(row) != 3 or row[0] in seen or row[0] not in files:
            raise BuildError("wheel RECORD row is invalid")
        seen.add(row[0])
        if row[0] == record_name:
            if row[1:] != ["", ""]:
                raise BuildError("wheel RECORD self row must be unhashed")
        else:
            data = files[row[0]][0]
            if row[1] != _wheel_record_hash(data) or row[2] != str(len(data)):
                raise BuildError(f"wheel RECORD mismatch: {row[0]}")
    epoch = time.gmtime(max(identity["source_date_epoch"], 315532800))
    zip_time = (epoch.tm_year, epoch.tm_mon, epoch.tm_mday, epoch.tm_hour, epoch.tm_min, epoch.tm_sec // 2 * 2)
    with zipfile.ZipFile(
        destination, "x", compression=zipfile.ZIP_DEFLATED, compresslevel=9
    ) as output:
        for name in sorted(files):
            data, executable = files[name]
            info = zipfile.ZipInfo(name, zip_time)
            info.create_system = 3
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            info.extra = b""
            info.comment = b""
            output.writestr(info, data)
    return {
        "members": len(files),
        "uncompressed_bytes": sum(len(item[0]) for item in files.values()),
        "record_entries": len(record_rows),
        "metadata": metadata_name,
        "record": record_name,
        "metadata_sha256": _hash_bytes(files[metadata_name][0]),
        "mode_policy": "all-files-0644-v1",
        "normalized": True,
    }


def _tar_octal(field: bytes, label: str) -> int:
    stripped = field.rstrip(b"\0 ").lstrip(b" ")
    if not stripped:
        return 0
    if any(byte not in b"01234567" for byte in stripped):
        raise BuildError(f"sdist {label} is not portable octal")
    return int(stripped, 8)


def _tar_header_text(field: bytes, *, label: str) -> str:
    raw, separator, padding = field.partition(b"\0")
    if separator and any(padding):
        raise BuildError(f"raw sdist {label} has nonzero bytes after NUL")
    try:
        value = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise BuildError(f"raw sdist {label} is not UTF-8") from exc
    if unicodedata.normalize("NFC", value) != value or any(
        ord(character) < 32 or ord(character) == 127 for character in value
    ):
        raise BuildError(f"raw sdist {label} is not canonical UTF-8")
    return value


def _read_raw_sdist_stream(
    source: Path, identity: dict[str, Any]
) -> tuple[bytes, list[tuple[str, str, int]]]:
    limits = identity["limits"]
    physical_cap = (
        limits["max_total_uncompressed_bytes"]
        + limits["max_members"] * 1024
        + 20 * 512
    )
    if source.is_symlink() or not source.is_file():
        raise BuildError("raw sdist is not a regular file")
    if source.stat().st_size > limits["max_artifact_bytes"]:
        raise BuildError("raw sdist exceeds cap")
    with source.open("rb") as raw:
        if raw.read(2) != b"\x1f\x8b":
            raise BuildError("raw sdist is not gzip")
        raw.seek(0)
        expanded = bytearray()
        try:
            with gzip.GzipFile(fileobj=raw, mode="rb") as archive:
                while True:
                    chunk = archive.read(min(1024 * 1024, physical_cap + 1 - len(expanded)))
                    if not chunk:
                        break
                    expanded.extend(chunk)
                    if len(expanded) > physical_cap:
                        raise BuildError("raw sdist physical tar stream exceeds cap")
        except (EOFError, gzip.BadGzipFile) as exc:
            raise BuildError("raw sdist gzip stream is malformed") from exc
        if raw.tell() != source.stat().st_size:
            raise BuildError("raw sdist has trailing compressed bytes")
    data = bytes(expanded)
    position = 0
    physical_members = 0
    zero_blocks = 0
    pending_pax: dict[str, str] | None = None
    logical_members: list[tuple[str, str, int]] = []
    while position + 512 <= len(data):
        header = data[position : position + 512]
        position += 512
        if header == b"\0" * 512:
            zero_blocks += 1
            if zero_blocks == 2:
                if any(data[position:]):
                    raise BuildError("raw sdist has nonzero trailing tar bytes")
                if pending_pax is not None:
                    raise BuildError("raw sdist PAX metadata lacks a following member")
                return data, logical_members
            continue
        if zero_blocks:
            raise BuildError("raw sdist has an isolated zero header")
        physical_members += 1
        if physical_members > limits["max_members"]:
            raise BuildError("raw sdist physical member count exceeds cap")
        expected_checksum = _tar_octal(header[148:156], "header checksum")
        observed_checksum = sum(header[:148]) + 8 * ord(" ") + sum(header[156:])
        if expected_checksum != observed_checksum:
            raise BuildError("raw sdist tar header checksum differs")
        size = _tar_octal(header[124:136], "member size")
        entry_type = header[156:157]
        if entry_type in {b"L", b"K", b"g"}:
            raise BuildError("raw sdist GNU/global extension entries are forbidden")
        if entry_type not in {b"\0", b"0", b"5", b"x"}:
            raise BuildError("raw sdist link/special entry is forbidden")
        if entry_type == b"x" and pending_pax is not None:
            raise BuildError("raw sdist has chained PAX metadata")
        if entry_type == b"5" and size:
            raise BuildError("raw sdist non-file entry has a body")
        if size > limits["max_artifact_bytes"]:
            raise BuildError("raw sdist physical member body exceeds cap")
        padded = (size + 511) // 512 * 512
        if position + padded > len(data):
            raise BuildError("raw sdist member body is truncated")
        body = data[position : position + size]
        if any(data[position + size : position + padded]):
            raise BuildError("raw sdist member padding is nonzero")
        position += padded
        if entry_type == b"x":
            try:
                pending_pax = parse_pax_records(
                    body,
                    path_cap=4096,
                    allowed_keys=frozenset({"path"}),
                )
            except PaxFormatError as exc:
                raise BuildError(f"raw sdist PAX metadata is invalid: {exc}") from exc
            continue
        raw_name = _tar_header_text(header[:100], label="member name")
        prefix = _tar_header_text(header[345:500], label="member prefix")
        header_name = f"{prefix}/{raw_name}" if prefix else raw_name
        effective_name = (
            pending_pax.get("path", header_name)
            if pending_pax is not None
            else header_name
        )
        pending_pax = None
        logical_members.append(
            (effective_name, "directory" if entry_type == b"5" else "file", size)
        )
    raise BuildError("raw sdist lacks two terminating zero blocks")


def _read_sdist(source: Path, identity: dict[str, Any]) -> dict[str, tuple[bytes, bool]]:
    limits = identity["limits"]
    raw_tar, physical_members = _read_raw_sdist_stream(source, identity)
    files: dict[str, tuple[bytes, bool]] = {}
    folded: set[str] = set()
    total = 0
    with tarfile.open(fileobj=io.BytesIO(raw_tar), mode="r:") as archive:
        members = archive.getmembers()
        tarfile_members = [
            (
                member.name,
                "directory" if member.isdir() else "file" if member.isfile() else "other",
                member.size,
            )
            for member in members
        ]
        if tarfile_members != physical_members:
            raise BuildError("sdist PAX/header interpretation differs from physical scan")
        if len(members) > limits["max_members"]:
            raise BuildError("sdist member count exceeds cap")
        for member in members:
            name = _safe_name(member.name, "sdist member")
            folded_name = unicodedata.normalize("NFC", name).casefold()
            if name in files or folded_name in folded:
                raise BuildError("sdist has duplicate/case-colliding members")
            folded.add(folded_name)
            if member.isdir():
                continue
            if not member.isfile():
                raise BuildError("sdist links/special entries are forbidden")
            if member.size > limits["max_artifact_bytes"]:
                raise BuildError("sdist member exceeds cap")
            stream = archive.extractfile(member)
            if stream is None:
                raise BuildError("cannot read sdist member")
            data = stream.read(limits["max_artifact_bytes"] + 1)
            if len(data) != member.size:
                raise BuildError("sdist member size differs")
            total += len(data)
            if total > limits["max_total_uncompressed_bytes"]:
                raise BuildError("sdist expansion exceeds cap")
            files[name] = (data, bool(member.mode & 0o111))
    _reject_file_ancestor_collisions(set(files), "sdist")
    return files


def _repack_sdist(
    source: Path, destination: Path, identity: dict[str, Any]
) -> dict[str, Any]:
    files = _read_sdist(source, identity)
    tops = {PurePosixPath(name).parts[0] for name in files}
    expected_top = f"kazstem-{identity['release']}"
    if tops != {expected_top}:
        raise BuildError("sdist has an unexpected top-level directory")
    pkg_info = f"{expected_top}/PKG-INFO"
    pyproject = f"{expected_top}/pyproject.toml"
    canonicalizer = f"{expected_top}/{identity['canonicalizer']['path']}"
    if not {pkg_info, pyproject, canonicalizer} <= set(files):
        raise BuildError("sdist lacks PKG-INFO/pyproject/shared canonicalizer")
    _metadata_identity(
        files[pkg_info][0],
        distribution=identity["distribution"],
        release=identity["release"],
        identity=identity,
        label="sdist PKG-INFO",
    )
    if _hash_bytes(files[canonicalizer][0]) != identity["canonicalizer"]["file"]["sha256"]:
        raise BuildError("sdist contains a different canonicalizer")
    for item in identity["source_inputs"]:
        name = f"{expected_top}/{item['path']}"
        if name not in files or _hash_bytes(files[name][0]) != item["file"]["sha256"]:
            raise BuildError(f"sdist omits/differs source input: {item['path']}")
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name in sorted(files):
            data, _executable = files[name]
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = 0o644
            info.mtime = identity["source_date_epoch"]
            info.uid = info.gid = 0
            info.uname = info.gname = "root"
            archive.addfile(info, io.BytesIO(data))
    with destination.open("xb") as output:
        with gzip.GzipFile(
            filename="", mode="wb", fileobj=output, compresslevel=9, mtime=0
        ) as compressed:
            compressed.write(raw.getvalue())
    return {
        "members": len(files),
        "uncompressed_bytes": sum(len(item[0]) for item in files.values()),
        "pkg_info": pkg_info,
        "metadata_sha256": _hash_bytes(files[pkg_info][0]),
        "mode_policy": "all-files-0644-v1",
        "tar_format": "ustar",
        "source_inputs": len(identity["source_inputs"]),
        "normalized": True,
    }


def _canonicalize_pair(
    raw_dist: Path, output_dir: Path, identity: dict[str, Any]
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    if raw_dist.is_symlink() or not raw_dist.is_dir():
        raise BuildError("raw build output is not a real directory")
    if output_dir.exists() or output_dir.is_symlink():
        raise BuildError("canonical output directory already exists")
    expected_names = {
        identity["artifacts"]["wheel"]["filename"],
        identity["artifacts"]["sdist"]["filename"],
    }
    raw_children = list(raw_dist.iterdir())
    if any(path.is_symlink() or not path.is_file() for path in raw_children):
        raise BuildError("raw build output contains a link/directory/special entry")
    observed = {path.name for path in raw_children}
    if observed != expected_names:
        raise BuildError(
            f"raw build inventory differs: missing={sorted(expected_names - observed)}, "
            f"extra={sorted(observed - expected_names)}"
        )
    output_dir.mkdir()
    wheel_name = identity["artifacts"]["wheel"]["filename"]
    sdist_name = identity["artifacts"]["sdist"]["filename"]
    wheel_audit = _repack_wheel(raw_dist / wheel_name, output_dir / wheel_name, identity)
    sdist_audit = _repack_sdist(raw_dist / sdist_name, output_dir / sdist_name, identity)
    if wheel_audit["metadata_sha256"] != sdist_audit["metadata_sha256"]:
        raise BuildError("wheel METADATA and sdist PKG-INFO differ byte-for-byte")
    records = {
        "wheel": {"filename": wheel_name, **_file_record(output_dir / wheel_name)},
        "sdist": {"filename": sdist_name, **_file_record(output_dir / sdist_name)},
    }
    return records, wheel_audit, sdist_audit


def _run_metadata_check(
    identity: dict[str, Any],
    *,
    section: dict[str, Any],
    checkout: Path,
    build_env: Path,
    output_dir: Path,
    capture_root: Path,
) -> dict[str, Any]:
    executable, tool = _tool(section)
    wheel = output_dir / identity["artifacts"]["wheel"]["filename"]
    sdist = output_dir / identity["artifacts"]["sdist"]["filename"]
    configured = identity["build_stack"]["metadata_check_argv"]
    actual = [
        str(executable),
        *[
            item.replace("{wheel}", str(wheel)).replace("{sdist}", str(sdist))
            for item in configured[1:]
        ],
    ]
    logical = [
        item.replace("{wheel}", "dist/" + wheel.name).replace(
            "{sdist}", "dist/" + sdist.name
        )
        for item in configured
    ]
    environment, logical_environment = _controlled_environment(
        section, home=capture_root.parent / "twine-home", build_env=build_env
    )
    return {
        **_run_captured(
            actual,
            logical,
            cwd=checkout,
            environment=environment,
            logical_environment=logical_environment,
            capture_root=capture_root,
            timeout=section["timeout_seconds"],
        ),
        "tool": tool,
        "strict": True,
    }


def _extract_sdist(source: Path, destination: Path, identity: dict[str, Any]) -> Path:
    files = _read_sdist(source, identity)
    destination.mkdir()
    top = f"kazstem-{identity['release']}"
    for name, (data, executable) in files.items():
        relative = PurePosixPath(name).relative_to(top)
        target = destination.joinpath(*relative.parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        target.chmod(0o755 if executable else 0o644)
    return destination


def _adversarial_retime(root: Path, epoch: int) -> dict[str, Any]:
    paths = sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix())
    base = epoch + 7 * 24 * 60 * 60
    values: list[int] = []
    for index, path in enumerate(paths):
        stamp = base + index * 37
        os.utime(path, (stamp, stamp), follow_symlinks=False)
        values.append(stamp)
    os.utime(root, (base - 37, base - 37))
    values.append(base - 37)
    return {
        "entries": len(values),
        "minimum_epoch": min(values),
        "maximum_epoch": max(values),
        "all_differ_from_source_date_epoch": all(value != epoch for value in values),
    }


def _validate_stream(value: Any, label: str) -> None:
    stream = _exact(value, {"bytes", "lines", "sha256", "truncated"}, label)
    if (
        isinstance(stream["bytes"], bool)
        or not isinstance(stream["bytes"], int)
        or not 0 <= stream["bytes"] <= MAX_JSON_BYTES
        or isinstance(stream["lines"], bool)
        or not isinstance(stream["lines"], int)
        or stream["lines"] < 0
        or stream["truncated"] is not False
    ):
        raise BuildError(f"{label} is invalid")
    _sha(stream["sha256"], f"{label}.sha256")


def _validate_invocation(value: Any, label: str) -> dict[str, Any]:
    invocation = _exact(
        value,
        {
            "argv",
            "environment",
            "exit_status",
            "stderr",
            "stdout",
            "timeout_seconds",
        },
        label,
    )
    if (
        not isinstance(invocation["argv"], list)
        or not invocation["argv"]
        or any(not isinstance(item, str) or not item for item in invocation["argv"])
        or not isinstance(invocation["environment"], dict)
        or invocation["exit_status"] != 0
    ):
        raise BuildError(f"{label} command identity differs")
    _positive(invocation["timeout_seconds"], f"{label}.timeout_seconds", 24 * 60 * 60)
    _validate_stream(invocation["stdout"], f"{label}.stdout")
    _validate_stream(invocation["stderr"], f"{label}.stderr")
    return invocation


def _logical_environment(
    section: dict[str, Any], *, build_env: bool, bootstrap_pip: str | None = None
) -> dict[str, str]:
    value = {
        **section["environment"],
        "GIT_CONFIG_GLOBAL": "disabled",
        "GIT_CONFIG_NOSYSTEM": "1",
        "HOME": "workspace/home",
        "PIP_CONFIG_FILE": "disabled",
        "PIP_DISABLE_PIP_VERSION_CHECK": "1",
        "PIP_NO_INDEX": "1",
        "PYTHONNOUSERSITE": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONPYCACHEPREFIX": "workspace/pycache",
        "TEMP": "workspace/tmp",
        "TMP": "workspace/tmp",
        "TMPDIR": "workspace/tmp",
        "XDG_CACHE_HOME": "workspace/cache",
    }
    if build_env:
        value["PYTHONPATH"] = "workspace/build-env"
    elif bootstrap_pip is not None:
        value["PYTHONPATH"] = "inputs/wheelhouse/" + bootstrap_pip
    return value


def _expected_provision_argv(identity: dict[str, Any]) -> list[str]:
    requirements = identity["build_stack"]["requirements"]["path"]
    return [
        item.replace("{build_env}", "workspace/build-env")
        .replace("{wheelhouse}", "inputs/wheelhouse")
        .replace("{requirements}", requirements)
        for item in identity["build_stack"]["provision_argv"]
    ]


def _expected_metadata_argv(identity: dict[str, Any]) -> list[str]:
    return [
        item.replace(
            "{wheel}", "dist/" + identity["artifacts"]["wheel"]["filename"]
        ).replace(
            "{sdist}", "dist/" + identity["artifacts"]["sdist"]["filename"]
        )
        for item in identity["build_stack"]["metadata_check_argv"]
    ]


def validate_receipt(
    value: Any, *, identity: dict[str, Any], output_dir: Path
) -> dict[str, Any]:
    receipt = _exact(
        value,
        {
            "audits",
            "build",
            "build_stack",
            "canonical_artifacts",
            "canonicalizer",
            "compression",
            "execution_platform",
            "git",
            "helpers",
            "identity_sha256",
            "interpreter_provenance",
            "metadata_check",
            "pass",
            "provision",
            "raw_artifacts",
            "release",
            "roots",
            "roundtrip",
            "schema",
            "source_commit",
            "source_inputs",
            "source_snapshot",
            "source_tree",
            "wheelhouse",
        },
        "canonical Python build receipt",
    )
    if (
        receipt["schema"] != RECEIPT_SCHEMA
        or receipt["pass"] is not True
        or receipt["release"] != identity["release"]
        or receipt["execution_platform"] != identity["execution_platform"]
        or receipt["interpreter_provenance"] != identity["interpreter_provenance"]
        or receipt["source_commit"] != identity["source_commit"]
        or receipt["source_tree"] != identity["source_tree"]
        or receipt["identity_sha256"] != _canonical_hash(identity)
        or receipt["canonicalizer"] != identity["canonicalizer"]
        or receipt["compression"] != identity["compression"]
        or receipt["git"] != identity["git"]
        or receipt["source_inputs"] != identity["source_inputs"]
        or receipt["helpers"] != identity["helpers"]
        or receipt["build_stack"] != identity["build_stack"]
        or receipt["wheelhouse"] != identity["build_stack"]["wheelhouse"]
        or receipt["canonical_artifacts"] != identity["artifacts"]
    ):
        raise BuildError("canonical Python build receipt identity differs")
    if receipt["roots"] != {
        "primary": {"logical_root": "primary-workspace", "fresh": True},
        "roundtrip": {"logical_root": "roundtrip-workspace", "fresh": True},
        "distinct_nonnested_nonaliased": True,
    }:
        raise BuildError("canonical Python receipt root proof differs")
    for name, expected in identity["artifacts"].items():
        if _file_record(output_dir / expected["filename"]) != {
            "bytes": expected["bytes"],
            "sha256": expected["sha256"],
        }:
            raise BuildError(f"canonical receipt output differs: {name}")
    for phase, section_name in (("provision", "build"),):
        provision = _exact(receipt[phase], {"invocation", "packages", "tool"}, phase)
        if (
            provision["packages"] != identity["build_stack"]["packages"]
            or provision["tool"] != identity[section_name]["tool"]
        ):
            raise BuildError(f"{phase} build-stack identity differs")
        _validate_invocation(provision["invocation"], f"{phase}.invocation")
        if (
            provision["invocation"]["argv"] != _expected_provision_argv(identity)
            or provision["invocation"]["environment"]
            != _logical_environment(
                identity[section_name],
                build_env=False,
                bootstrap_pip=identity["build_stack"]["bootstrap_pip"]["filename"],
            )
            or provision["invocation"]["timeout_seconds"]
            != identity[section_name]["timeout_seconds"]
        ):
            raise BuildError(f"{phase} exact command/environment differs")
    build_invocation = _exact(
        receipt["build"],
        {
            "argv",
            "environment",
            "exit_status",
            "stderr",
            "stdout",
            "timeout_seconds",
            "tool",
        },
        "build",
    )
    if build_invocation["tool"] != identity["build"]["tool"]:
        raise BuildError("primary build tool differs")
    _validate_invocation(
        {key: value for key, value in build_invocation.items() if key != "tool"},
        "build",
    )
    if (
        build_invocation["argv"]
        != [
            item.replace("{raw_dist}", "workspace/raw-dist")
            for item in identity["build"]["argv"]
        ]
        or build_invocation["environment"]
        != _logical_environment(identity["build"], build_env=True)
        or build_invocation["timeout_seconds"] != identity["build"]["timeout_seconds"]
    ):
        raise BuildError("primary exact build command/environment differs")
    metadata_check = _exact(
        receipt["metadata_check"],
        {
            "argv",
            "environment",
            "exit_status",
            "stderr",
            "stdout",
            "strict",
            "timeout_seconds",
            "tool",
        },
        "metadata_check",
    )
    if metadata_check["strict"] is not True or metadata_check["tool"] != identity["build"]["tool"]:
        raise BuildError("primary twine strict receipt differs")
    _validate_invocation(
        {
            key: item
            for key, item in metadata_check.items()
            if key not in {"strict", "tool"}
        },
        "metadata_check",
    )
    if (
        metadata_check["argv"] != _expected_metadata_argv(identity)
        or metadata_check["environment"]
        != _logical_environment(identity["build"], build_env=True)
        or metadata_check["timeout_seconds"] != identity["build"]["timeout_seconds"]
    ):
        raise BuildError("primary exact twine command/environment differs")
    audits = _exact(receipt["audits"], {"sdist", "wheel"}, "audits")
    if (
        audits["wheel"].get("normalized") is not True
        or audits["wheel"].get("mode_policy") != "all-files-0644-v1"
        or audits["sdist"].get("normalized") is not True
        or audits["sdist"].get("mode_policy") != "all-files-0644-v1"
        or audits["sdist"].get("tar_format") != "ustar"
        or audits["wheel"].get("metadata_sha256")
        != audits["sdist"].get("metadata_sha256")
    ):
        raise BuildError("canonical Python artifact audit contract differs")
    roundtrip = _exact(
        receipt["roundtrip"],
        {
            "adversarial_retime",
            "audits",
            "canonical_artifacts",
            "invocation",
            "metadata_check",
            "provision",
            "source_snapshot",
            "wheel_and_sdist_identical",
        },
        "roundtrip",
    )
    if (
        roundtrip["canonical_artifacts"] != identity["artifacts"]
        or roundtrip["audits"] != audits
        or roundtrip["wheel_and_sdist_identical"] is not True
        or roundtrip["adversarial_retime"].get("all_differ_from_source_date_epoch")
        is not True
        or receipt["source_snapshot"].get("unchanged") is not True
        or roundtrip["source_snapshot"].get("unchanged") is not True
    ):
        raise BuildError("adversarial sdist roundtrip receipt differs")
    roundtrip_provision = _exact(
        roundtrip["provision"], {"invocation", "packages", "tool"}, "roundtrip.provision"
    )
    if (
        roundtrip_provision["packages"] != identity["build_stack"]["packages"]
        or roundtrip_provision["tool"] != identity["roundtrip"]["tool"]
    ):
        raise BuildError("roundtrip provision identity differs")
    _validate_invocation(
        roundtrip_provision["invocation"], "roundtrip.provision.invocation"
    )
    if (
        roundtrip_provision["invocation"]["argv"] != _expected_provision_argv(identity)
        or roundtrip_provision["invocation"]["environment"]
        != _logical_environment(
            identity["roundtrip"],
            build_env=False,
            bootstrap_pip=identity["build_stack"]["bootstrap_pip"]["filename"],
        )
        or roundtrip_provision["invocation"]["timeout_seconds"]
        != identity["roundtrip"]["timeout_seconds"]
    ):
        raise BuildError("roundtrip exact provision command/environment differs")
    roundtrip_invocation = dict(roundtrip["invocation"])
    if roundtrip_invocation.pop("tool", None) != identity["roundtrip"]["tool"]:
        raise BuildError("roundtrip build tool differs")
    _validate_invocation(roundtrip_invocation, "roundtrip.invocation")
    if (
        roundtrip_invocation["argv"]
        != [
            item.replace("{raw_dist}", "workspace/raw-dist")
            for item in identity["roundtrip"]["argv"]
        ]
        or roundtrip_invocation["environment"]
        != _logical_environment(identity["roundtrip"], build_env=True)
        or roundtrip_invocation["timeout_seconds"]
        != identity["roundtrip"]["timeout_seconds"]
    ):
        raise BuildError("roundtrip exact build command/environment differs")
    roundtrip_check = dict(roundtrip["metadata_check"])
    if (
        roundtrip_check.pop("tool", None) != identity["roundtrip"]["tool"]
        or roundtrip_check.pop("strict", None) is not True
    ):
        raise BuildError("roundtrip twine strict receipt differs")
    _validate_invocation(roundtrip_check, "roundtrip.metadata_check")
    if (
        roundtrip_check["argv"] != _expected_metadata_argv(identity)
        or roundtrip_check["environment"]
        != _logical_environment(identity["roundtrip"], build_env=True)
        or roundtrip_check["timeout_seconds"]
        != identity["roundtrip"]["timeout_seconds"]
    ):
        raise BuildError("roundtrip exact twine command/environment differs")
    return receipt


def build(args: argparse.Namespace) -> dict[str, Any]:
    for label, path in (
        ("workspace", args.workspace),
        ("roundtrip workspace", args.roundtrip_workspace),
        ("output directory", args.output_dir),
        ("receipt", args.receipt),
    ):
        if path.exists() or path.is_symlink():
            raise BuildError(f"{label} must not exist")
    if args.observation and (args.observation.exists() or args.observation.is_symlink()):
        raise BuildError("observation must not exist")
    if args.identity.is_symlink() or not args.identity.is_file():
        raise BuildError("identity must be a regular non-symlink file")
    if args.source_checkout.is_symlink() or not args.source_checkout.is_dir():
        raise BuildError("source checkout must be a real non-symlink directory")
    if args.wheelhouse.is_symlink() or not args.wheelhouse.is_dir():
        raise BuildError("wheelhouse must be a real non-symlink directory")
    if args.interpreter_source.is_symlink() or not args.interpreter_source.is_file():
        raise BuildError("interpreter source must be a regular non-symlink file")
    source = args.source_checkout.resolve(strict=True)
    distinct = [
        ("source", source),
        ("identity", args.identity.resolve(strict=True)),
        ("workspace", args.workspace),
        ("roundtrip workspace", args.roundtrip_workspace),
        ("output directory", args.output_dir),
        ("receipt", args.receipt),
    ]
    if args.observation:
        distinct.append(("observation", args.observation))
    distinct.append(("wheelhouse", args.wheelhouse.resolve(strict=True)))
    distinct.append(("interpreter source", args.interpreter_source.resolve(strict=True)))
    _verify_distinct(distinct)
    identity_path = args.identity.resolve(strict=True)
    identity = load_identity(identity_path)
    observed_platform = {
        "system": platform.system().casefold(),
        "machine": platform.machine().casefold(),
        "python_implementation": platform.python_implementation(),
    }
    if observed_platform != identity["execution_platform"]:
        raise BuildError("canonical build execution platform differs")
    canonicalizer_path = Path(__file__).resolve(strict=True)
    if _file_record(canonicalizer_path) != identity["canonicalizer"]["file"]:
        raise BuildError("running canonicalizer differs from identity")
    requirements_relative = _portable(
        args.requirements, "--requirements"
    )
    if requirements_relative != identity["build_stack"]["requirements"]["path"]:
        raise BuildError("--requirements differs from build identity")
    compression = {
        "implementation": "python-stdlib-zlib-deflate-9",
        "zlib_compile_version": zlib.ZLIB_VERSION,
        "zlib_runtime_version": zlib.ZLIB_RUNTIME_VERSION,
    }
    if compression != identity["compression"]:
        raise BuildError("zlib compile/runtime identity differs")
    runtime_observation = interpreter_runtime_observation()
    runtime_expected = identity["interpreter_provenance"]["runtime_closure"]
    if any(
        runtime_observation[name] != runtime_expected[name]
        for name in (
            "loaded_libz",
            "python_executable",
            "stdlib",
            "zlib_extension",
            "zlib_builtin",
        )
    ):
        raise BuildError("running interpreter byte inputs differ from identity")
    git_record = _verify_source(source, identity)
    source_snapshot = _source_snapshot(source)
    wheelhouse = args.wheelhouse.resolve(strict=True)
    wheelhouse_record = _verified_wheelhouse(wheelhouse, identity)
    interpreter_source = args.interpreter_source.resolve(strict=True)
    expected_interpreter_source = identity["interpreter_provenance"]["source_archive"]
    if (
        interpreter_source.name != expected_interpreter_source["filename"]
        or _file_record(interpreter_source)
        != {
            "bytes": expected_interpreter_source["bytes"],
            "sha256": expected_interpreter_source["sha256"],
        }
    ):
        raise BuildError("canonical interpreter corresponding source differs")

    workspace = args.workspace.absolute()
    workspace.mkdir(parents=True)
    source_build = workspace / "source-materialization"
    shutil.copytree(
        source,
        source_build,
        symlinks=True,
        ignore=shutil.ignore_patterns(".git"),
    )
    if _source_snapshot(source_build) != source_snapshot:
        raise BuildError("disposable source materialization differs from exact checkout")
    build_env = workspace / "build-env"
    provision = _provision_build_env(
        identity,
        section=identity["build"],
        checkout=source_build,
        wheelhouse=wheelhouse,
        requirements_relative=requirements_relative,
        build_env=build_env,
        capture_root=workspace / "provision-capture",
    )
    raw_dist = workspace / "raw-dist"
    invocation = _run_build(
        identity["build"],
        checkout=source_build,
        raw_dist=raw_dist,
        capture_root=workspace / "build-capture",
        build_env=build_env,
    )
    raw_records = {
        name: {"filename": record["filename"], **_file_record(raw_dist / record["filename"])}
        for name, record in identity["artifacts"].items()
    }
    output_dir = args.output_dir.absolute()
    records, wheel_audit, sdist_audit = _canonicalize_pair(raw_dist, output_dir, identity)
    metadata_check = _run_metadata_check(
        identity,
        section=identity["build"],
        checkout=source_build,
        build_env=build_env,
        output_dir=output_dir,
        capture_root=workspace / "twine-capture",
    )
    if _source_snapshot(source) != source_snapshot:
        raise BuildError("primary source tree changed during canonical build")
    _verify_source(source, identity)

    roundtrip = args.roundtrip_workspace.absolute()
    roundtrip.mkdir(parents=True)
    extracted = _extract_sdist(
        output_dir / identity["artifacts"]["sdist"]["filename"],
        roundtrip / "source",
        identity,
    )
    retime = _adversarial_retime(extracted, identity["source_date_epoch"])
    roundtrip_source_snapshot = _source_snapshot(extracted)
    roundtrip_build_source = roundtrip / "source-materialization"
    shutil.copytree(extracted, roundtrip_build_source, symlinks=True)
    if _source_snapshot(roundtrip_build_source) != roundtrip_source_snapshot:
        raise BuildError("roundtrip disposable materialization differs from sdist")
    roundtrip_build_env = roundtrip / "build-env"
    roundtrip_provision = _provision_build_env(
        identity,
        section=identity["roundtrip"],
        checkout=roundtrip_build_source,
        wheelhouse=wheelhouse,
        requirements_relative=requirements_relative,
        build_env=roundtrip_build_env,
        capture_root=roundtrip / "provision-capture",
    )
    roundtrip_raw = roundtrip / "raw-dist"
    roundtrip_invocation = _run_build(
        identity["roundtrip"],
        checkout=roundtrip_build_source,
        raw_dist=roundtrip_raw,
        capture_root=roundtrip / "build-capture",
        build_env=roundtrip_build_env,
    )
    roundtrip_canonical = roundtrip / "canonical"
    rebuilt_records, rebuilt_wheel_audit, rebuilt_sdist_audit = _canonicalize_pair(
        roundtrip_raw, roundtrip_canonical, identity
    )
    roundtrip_metadata_check = _run_metadata_check(
        identity,
        section=identity["roundtrip"],
        checkout=roundtrip_build_source,
        build_env=roundtrip_build_env,
        output_dir=roundtrip_canonical,
        capture_root=roundtrip / "twine-capture",
    )
    if _source_snapshot(extracted) != roundtrip_source_snapshot:
        raise BuildError("roundtrip source tree changed during canonical build")
    if rebuilt_records != records:
        raise BuildError("adversarially retimed sdist rebuild differs from canonical pair")

    expected_records = identity["artifacts"]
    if args.observation:
        args.observation.parent.mkdir(parents=True, exist_ok=True)
        args.observation.write_bytes(
            _json_bytes(
                {
                    "schema": "kazstem-canonical-python-build-observation-v1",
                    "source_commit": identity["source_commit"],
                    "source_tree": identity["source_tree"],
                    "canonicalizer": identity["canonicalizer"],
                    "compression": compression,
                    "canonical_artifacts": records,
                }
            )
        )
    if records != expected_records:
        for record in records.values():
            path = output_dir / record["filename"]
            path.rename(path.with_name(f"{path.name}.unsealed-{record['sha256'][:12]}"))
        raise BuildError("canonical artifact identity mismatch; outputs quarantined")

    root_identities = {
        (workspace.stat().st_dev, workspace.stat().st_ino),
        (roundtrip.stat().st_dev, roundtrip.stat().st_ino),
    }
    if len(root_identities) != 2:
        raise BuildError("primary and roundtrip roots alias")
    root_records = {
        "primary": {"logical_root": "primary-workspace", "fresh": True},
        "roundtrip": {"logical_root": "roundtrip-workspace", "fresh": True},
        "distinct_nonnested_nonaliased": True,
    }
    receipt = {
        "schema": RECEIPT_SCHEMA,
        "pass": True,
        "release": identity["release"],
        "execution_platform": observed_platform,
        "interpreter_provenance": identity["interpreter_provenance"],
        "source_commit": identity["source_commit"],
        "source_tree": identity["source_tree"],
        "identity_sha256": _canonical_hash(identity),
        "canonicalizer": identity["canonicalizer"],
        "helpers": identity["helpers"],
        "git": git_record,
        "compression": compression,
        "wheelhouse": wheelhouse_record,
        "build_stack": identity["build_stack"],
        "source_inputs": identity["source_inputs"],
        "source_snapshot": {**source_snapshot, "unchanged": True},
        "provision": provision,
        "build": invocation,
        "raw_artifacts": raw_records,
        "canonical_artifacts": records,
        "audits": {"wheel": wheel_audit, "sdist": sdist_audit},
        "metadata_check": metadata_check,
        "roots": root_records,
        "roundtrip": {
            "provision": roundtrip_provision,
            "invocation": roundtrip_invocation,
            "adversarial_retime": retime,
            "canonical_artifacts": rebuilt_records,
            "audits": {"wheel": rebuilt_wheel_audit, "sdist": rebuilt_sdist_audit},
            "metadata_check": roundtrip_metadata_check,
            "source_snapshot": {**roundtrip_source_snapshot, "unchanged": True},
            "wheel_and_sdist_identical": True,
        },
    }
    args.receipt.parent.mkdir(parents=True, exist_ok=True)
    args.receipt.write_bytes(_json_bytes(receipt))
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--identity", required=True, type=Path)
    parser.add_argument("--source-checkout", required=True, type=Path)
    parser.add_argument("--wheelhouse", required=True, type=Path)
    parser.add_argument("--requirements", required=True)
    parser.add_argument("--interpreter-source", required=True, type=Path)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--roundtrip-workspace", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--receipt", required=True, type=Path)
    parser.add_argument("--observation", type=Path)
    args = parser.parse_args()
    result = build(args)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (BuildError, OSError, ValueError, zipfile.BadZipFile, tarfile.TarError) as exc:
        raise SystemExit(f"error: {exc}") from exc
