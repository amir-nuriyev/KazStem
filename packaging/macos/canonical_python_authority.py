#!/usr/bin/env python3
"""Bind Linux-owned canonical Python artifacts into the macOS release."""

from __future__ import annotations

import hashlib
from pathlib import Path
import sys
import types
from typing import Any

from release_common import (
    ReleaseError,
    assert_relative_json,
    file_record,
    portable_path,
    read_json,
    verify_artifact,
    verify_file,
)


CONTRACT_SCHEMA = "kazstem-macos-canonical-python-authority-v1"
PYTHON_IDENTITY_SCHEMA = "kazstem-canonical-python-build-identity-v2"
PYTHON_RECEIPT_SCHEMA = "kazstem-canonical-python-build-receipt-v2"
LINUX_IDENTITY_SCHEMA = "kazstem-linux-release-identity-v2"
LINUX_REPRODUCIBILITY_SCHEMA = "kazstem-python-artifact-reproducibility-v2"
MINIMUM_LINUX_ROOTS = 3

BUILDER_PATH = "packaging/build_canonical_python_artifacts.py"
ADAPTER_PATH = "packaging/macos/canonical_python_authority.py"
SUPERVISOR_PATH = "packaging/process_supervisor.py"
LINUX_COMMON_PATH = "packaging/linux/release_common.py"
LINUX_VALIDATOR_PATH = "packaging/linux/verify_python_reproducibility.py"
PYTHON_IDENTITY_LOGICAL_PATH = "inputs/PYTHON-BUILD-IDENTITY.json"
LINUX_IDENTITY_LOGICAL_PATH = "inputs/LINUX-RELEASE-IDENTITY.json"
LINUX_REPRODUCIBILITY_LOGICAL_PATH = (
    "inputs/linux-python-reproducibility.json"
)
INTERPRETER_SOURCE_LOGICAL_PREFIX = "inputs/interpreter-source/"
LINUX_IDENTITY_SOURCE_PATH = "evidence/linux/RELEASE-IDENTITY.json"
LINUX_REPRODUCIBILITY_SOURCE_PATH = (
    "evidence/linux/python-reproducibility.json"
)


def _source_module(name: str, path: Path) -> types.ModuleType:
    module_name = f"{name}_{hashlib.sha256(path.read_bytes()).hexdigest()[:16]}"
    module = types.ModuleType(module_name)
    module.__file__ = str(path)
    sys.modules[module_name] = module
    source = path.read_bytes()
    exec(compile(source, str(path), "exec", dont_inherit=True), module.__dict__)
    return module


def _verify_checked_sources(repository: Path) -> dict[str, dict[str, Any]]:
    records: dict[str, dict[str, Any]] = {}
    for relative in (
        ADAPTER_PATH,
        BUILDER_PATH,
        SUPERVISOR_PATH,
        LINUX_COMMON_PATH,
        LINUX_VALIDATOR_PATH,
    ):
        path = repository / relative
        if path.is_symlink() or not path.is_file():
            raise ReleaseError(f"canonical authority source is invalid: {relative}")
        records[relative] = {"path": relative, "file": file_record(path)}
    return records


def _require_distinct_regular_files(paths: list[Path]) -> None:
    seen: set[tuple[int, int]] = set()
    for path in paths:
        metadata = path.stat()
        key = (metadata.st_dev, metadata.st_ino)
        if metadata.st_nlink != 1 or key in seen:
            raise ReleaseError(
                f"canonical authority input is hard-linked or aliased: {path.name}"
            )
        seen.add(key)


def _source_companions(
    payload: Path,
    linux_identity: dict[str, Any],
    *,
    linux_identity_path: Path,
    linux_reproducibility_path: Path,
) -> list[dict[str, Any]]:
    companions = list(
        linux_identity["verification"]["reproducibility"]["canonical_python"][
            "source_companions"
        ]
    )
    companions.extend(
        [
            {
                "path": LINUX_IDENTITY_SOURCE_PATH,
                "role": "linux-release-identity",
                "subject": "linux-canonical-authority",
                "source_member": None,
                "file": file_record(linux_identity_path),
            },
            {
                "path": LINUX_REPRODUCIBILITY_SOURCE_PATH,
                "role": "linux-reproducibility-evidence",
                "subject": "linux-canonical-authority",
                "source_member": None,
                "file": file_record(linux_reproducibility_path),
            },
        ]
    )
    companions.sort(key=lambda item: item["path"])
    paths: list[str] = []
    for index, item in enumerate(companions):
        if not isinstance(item, dict) or set(item) != {
            "file",
            "path",
            "role",
            "source_member",
            "subject",
        }:
            raise ReleaseError(
                f"canonical authority source companion {index} is malformed"
            )
        relative = portable_path(
            item["path"], label=f"canonical authority source companion {index}"
        )
        paths.append(relative)
        verify_file(
            payload / relative,
            item["file"],
            label=f"canonical authority source companion {relative}",
        )
    if paths != sorted(set(paths)):
        raise ReleaseError("canonical authority source companions collide")
    return companions


def bind_authority(
    *,
    repository: Path,
    payload: Path,
    python_build_identity_path: Path,
    linux_release_identity_path: Path,
    linux_reproducibility_path: Path,
    interpreter_source_path: Path,
    canonical_artifacts: Path,
    release_identity: dict[str, Any],
) -> dict[str, Any]:
    """Validate and project the immutable Linux canonical-artifact authority."""
    repository = repository.resolve(strict=True)
    payload = payload.resolve(strict=True)
    canonical_artifacts = canonical_artifacts.resolve(strict=True)
    checked = _verify_checked_sources(repository)
    verify_file(
        Path(__file__).resolve(strict=True),
        checked[ADAPTER_PATH]["file"],
        label="loaded canonical Python authority adapter",
    )
    for path in (
        python_build_identity_path,
        linux_release_identity_path,
        linux_reproducibility_path,
        interpreter_source_path,
    ):
        if path.is_symlink() or not path.is_file():
            raise ReleaseError(f"canonical authority input is invalid: {path.name}")
    python_build_identity_path = python_build_identity_path.resolve(strict=True)
    linux_release_identity_path = linux_release_identity_path.resolve(strict=True)
    linux_reproducibility_path = linux_reproducibility_path.resolve(strict=True)
    interpreter_source_path = interpreter_source_path.resolve(strict=True)
    _require_distinct_regular_files(
        [
            python_build_identity_path,
            linux_release_identity_path,
            linux_reproducibility_path,
            interpreter_source_path,
            *[
                canonical_artifacts / release_identity["artifacts"][name]["filename"]
                for name in ("wheel", "sdist")
            ],
        ]
    )

    try:
        builder = _source_module(
            "_kazstem_macos_authority_builder", repository / BUILDER_PATH
        )
        linux_validator = _source_module(
            "_kazstem_macos_authority_linux_validator",
            repository / LINUX_VALIDATOR_PATH,
        )
        python_identity = builder.load_identity(python_build_identity_path)
        linux_identity = linux_validator.load_identity(linux_release_identity_path)
    except Exception as exc:
        raise ReleaseError(f"canonical Python authority identity is invalid: {exc}") from exc

    linux_identity_digest = linux_validator.identity_sha256(
        linux_release_identity_path
    )
    linux_payload = read_json(linux_reproducibility_path)
    try:
        validated_linux_payload = linux_validator.validate_reproducibility_payload(
            linux_payload,
            identity=linux_identity,
            identity_contract_sha256=linux_identity_digest,
            canonical_artifacts=canonical_artifacts,
        )
    except Exception as exc:
        raise ReleaseError(
            f"Linux canonical Python reproducibility authority is invalid: {exc}"
        ) from exc

    expected_source = {
        name: release_identity[name]
        for name in (
            "release",
            "source_commit",
            "source_tree",
            "source_origin",
            "source_ref",
            "source_date_epoch",
        )
    }
    for label, value in (
        ("canonical Python build identity", python_identity),
        ("Linux release identity", linux_identity),
    ):
        if any(value.get(name) != expected for name, expected in expected_source.items()):
            raise ReleaseError(f"{label} differs from the macOS source identity")
    if linux_identity.get("release_url") != release_identity["release_url"]:
        raise ReleaseError("Linux authority release URL differs from macOS")
    tag_object = linux_identity.get("source_tag_object")
    if not isinstance(tag_object, str) or len(tag_object) != 40:
        raise ReleaseError("Linux authority lacks the exact release tag object")

    expected_artifacts = {
        name: release_identity["artifacts"][name] for name in ("wheel", "sdist")
    }
    if {
        name: {
            "filename": linux_identity["artifacts"][name]["filename"],
            "bytes": linux_identity["artifacts"][name]["bytes"],
            "sha256": linux_identity["artifacts"][name]["sha256"],
        }
        for name in ("wheel", "sdist")
    } != {
        name: {
            "filename": record["filename"],
            "bytes": record["bytes"],
            "sha256": record["sha256"],
        }
        for name, record in expected_artifacts.items()
    }:
        raise ReleaseError("Linux authority canonical artifacts differ from macOS")
    if python_identity["artifacts"] != {
        name: {
            "filename": record["filename"],
            "bytes": record["bytes"],
            "sha256": record["sha256"],
        }
        for name, record in expected_artifacts.items()
    }:
        raise ReleaseError("shared Python identity artifacts differ from macOS")
    for name, record in expected_artifacts.items():
        verify_artifact(
            canonical_artifacts / record["filename"],
            record,
            label=f"Linux-authoritative canonical {name}",
        )
    if validated_linux_payload.get("canonical_python_identity") != python_identity:
        raise ReleaseError("Linux authority embeds a different Python build identity")
    linux_roots = linux_identity["verification"]["reproducibility"]["build_roots"]
    if (
        isinstance(linux_roots, bool)
        or not isinstance(linux_roots, int)
        or linux_roots < MINIMUM_LINUX_ROOTS
        or len(validated_linux_payload.get("builds", [])) != linux_roots
    ):
        raise ReleaseError("Linux canonical authority lacks three fresh roots")

    interpreter_record = python_identity["interpreter_provenance"]["source_archive"]
    verify_file(
        interpreter_source_path,
        interpreter_record,
        label="canonical Python interpreter source",
    )
    companions = _source_companions(
        payload,
        linux_identity,
        linux_identity_path=linux_release_identity_path,
        linux_reproducibility_path=linux_reproducibility_path,
    )
    contract = {
        "schema": CONTRACT_SCHEMA,
        "adapter": {**checked[ADAPTER_PATH], "schema": CONTRACT_SCHEMA},
        "builder": {
            **checked[BUILDER_PATH],
            "identity_schema": PYTHON_IDENTITY_SCHEMA,
            "receipt_schema": PYTHON_RECEIPT_SCHEMA,
        },
        "process_supervisor": checked[SUPERVISOR_PATH],
        "linux_release_common": {
            **checked[LINUX_COMMON_PATH],
            "identity_schema": LINUX_IDENTITY_SCHEMA,
        },
        "linux_validator": {
            **checked[LINUX_VALIDATOR_PATH],
            "payload_schema": LINUX_REPRODUCIBILITY_SCHEMA,
            "entrypoint": "validate_reproducibility_payload",
        },
        "python_build_identity": {
            "path": PYTHON_IDENTITY_LOGICAL_PATH,
            "schema": PYTHON_IDENTITY_SCHEMA,
            "file": file_record(python_build_identity_path),
        },
        "linux_release_identity": {
            "path": LINUX_IDENTITY_LOGICAL_PATH,
            "schema": LINUX_IDENTITY_SCHEMA,
            "identity_contract_sha256": linux_identity_digest,
            "file": file_record(linux_release_identity_path),
        },
        "linux_reproducibility": {
            "path": LINUX_REPRODUCIBILITY_LOGICAL_PATH,
            "schema": LINUX_REPRODUCIBILITY_SCHEMA,
            "minimum_distinct_roots": MINIMUM_LINUX_ROOTS,
            "validated_distinct_roots": linux_roots,
            "file": file_record(linux_reproducibility_path),
        },
        "interpreter_source": {
            "path": INTERPRETER_SOURCE_LOGICAL_PREFIX + interpreter_source_path.name,
            "corresponding_source_path": python_identity["interpreter_provenance"][
                "corresponding_source_path"
            ],
            "file": file_record(interpreter_source_path),
        },
        "source_tag_object": tag_object,
        "canonical_artifacts": expected_artifacts,
        "source_companions": companions,
    }
    assert_relative_json(contract, label="canonical Python authority contract")
    return contract


def verify_bound_authority(
    *,
    identity: dict[str, Any],
    repository: Path,
    payload: Path,
    python_build_identity_path: Path,
    linux_release_identity_path: Path,
    linux_reproducibility_path: Path,
    interpreter_source_path: Path,
    canonical_artifacts: Path,
) -> dict[str, Any]:
    observed = bind_authority(
        repository=repository,
        payload=payload,
        python_build_identity_path=python_build_identity_path,
        linux_release_identity_path=linux_release_identity_path,
        linux_reproducibility_path=linux_reproducibility_path,
        interpreter_source_path=interpreter_source_path,
        canonical_artifacts=canonical_artifacts,
        release_identity=identity,
    )
    expected = identity["verification"]["reproducibility"][
        "canonical_python_authority"
    ]
    if observed != expected:
        raise ReleaseError("canonical Python authority differs from release identity")
    return observed
