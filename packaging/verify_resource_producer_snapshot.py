#!/usr/bin/env python3
"""Fail-closed verifier for the sealed bf1f producer and release closure."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import stat
import subprocess
from typing import Any, Sequence


SCHEMA = "qazmorph-resource-producer-source-snapshot-v1"
SNAPSHOT_SCOPE = (
    "manifest-bound-producer-inputs-with-separate-release-closure-v1"
)
BUNDLE_ID = "bf1f31ff6e5860585b9e4134f12dcfb9d6df8030ee87b368e5a5f29eb45c1188"
RESOURCE_MANIFEST_SCHEMA = "qazmorph-resource-manifest-v4"
RESOURCE_MANIFEST_BINDING_SCHEMA = (
    "qazmorph-resource-producer-manifest-binding-v1"
)
APERTIUM_BINDING_SCHEMA = "qazmorph-resource-producer-apertium-binding-v1"
TOOLCHAIN_BINDING_SCHEMA = "qazmorph-resource-producer-toolchain-binding-v1"
TOOLCHAIN_MANIFEST_SCHEMA = "qazmorph-toolchain-manifest-v2"
TOOLCHAIN_ARCHIVE_LOCK_SCHEMA = "qazmorph-toolchain-archive-lock-v1"
RELEASE_CLOSURE_BINDING_SCHEMA = (
    "qazmorph-resource-producer-release-closure-binding-v1"
)
RELEASE_CLOSURE_RECEIPT_SCHEMA = (
    "qazmorph-resource-producer-release-closure-receipt-v1"
)
LINUX_CLOSURE_LOCK_SCHEMA = "kazstem-linux-runtime-source-lock-v1"
RESOURCE_MANIFEST_RECORD = {
    "bytes": 18092,
    "sha256": "8d596011020b21a903244490cc7201d348d7bcc5442ef736ec7e4ac5435083e1",
}
CLOSURE_LOCK_PATH = "scripts/platform_runtime_sources.linux-x86_64.lock.json"
CLOSURE_LOCK_RECORD = {
    "bytes": 6948,
    "sha256": "bededc4a7522fb610c9c1ea87b3b44b31e1abd85cd160beea6262c3407857581",
}
EXPECTED_INPUTS = frozenset(
    {
        "scripts/bootstrap_h100.sh",
        "scripts/build_resources.sh",
        "scripts/generator_regression_probes.json",
        "scripts/guesser_regression_probes.json",
        "scripts/toolchain_assets.lock.json",
        "scripts/verify_generator_fst.py",
        "scripts/verify_guesser_fst.py",
        "scripts/write_manifest.py",
        "scripts/write_toolchain_manifest.py",
        "src/qazmorph/generator.py",
        "src/qazmorph/guesser.py",
    }
)
DISTINCT_RUNTIME_INPUTS = frozenset(
    {"src/qazmorph/generator.py", "src/qazmorph/guesser.py"}
)
RESOURCE_FILES = frozenset(
    {
        "kaz.automorf.hfstol",
        "kaz.autogen.hfstol",
        "kaz.guesser.automorf.hfstol",
        "kaz.guesser.autogen.hfstol",
        "kaz.rlx.bin",
    }
)


class SnapshotError(RuntimeError):
    pass


def _is_sha256(value: object) -> bool:
    return bool(
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _canonical_hash(value: Any) -> str:
    encoded = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _read_regular(path: Path) -> tuple[bytes, dict[str, int | str]]:
    try:
        before = path.lstat()
    except OSError as exc:
        raise SnapshotError(f"cannot stat required file {path}: {exc}") from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise SnapshotError(f"required entry is not a regular non-link file: {path}")
    try:
        with path.open("rb") as stream:
            data = stream.read()
            opened = os.fstat(stream.fileno())
        after = path.lstat()
    except OSError as exc:
        raise SnapshotError(f"cannot read required file {path}: {exc}") from exc
    stable_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
    if (
        len(data) != opened.st_size
        or any(getattr(before, name) != getattr(opened, name) for name in stable_fields)
        or any(getattr(opened, name) != getattr(after, name) for name in stable_fields)
    ):
        raise SnapshotError(f"required file changed while being verified: {path}")
    return data, {
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def _file_record(path: Path) -> dict[str, int | str]:
    return _read_regular(path)[1]


def _read_json_with_record(path: Path) -> tuple[Any, dict[str, int | str]]:
    data, record = _read_regular(path)
    try:
        return json.loads(data.decode("utf-8")), record
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise SnapshotError(f"cannot decode exact JSON file {path}: {exc}") from exc


def _read_json(path: Path) -> Any:
    return _read_json_with_record(path)[0]


def _safe_relative(value: object, *, label: str) -> PurePosixPath:
    if not isinstance(value, str) or not value or "\\" in value:
        raise SnapshotError(f"{label} must be a portable relative path")
    posix = PurePosixPath(value)
    windows = PureWindowsPath(value)
    if (
        posix.is_absolute()
        or windows.is_absolute()
        or windows.drive
        or not posix.parts
        or any(part in {"", ".", ".."} for part in posix.parts)
    ):
        raise SnapshotError(f"unsafe {label}: {value!r}")
    return posix


def _validate_file_record(value: object, *, label: str) -> dict[str, int | str]:
    if (
        not isinstance(value, dict)
        or set(value) != {"bytes", "sha256"}
        or not isinstance(value.get("bytes"), int)
        or isinstance(value.get("bytes"), bool)
        or value["bytes"] < 0
        or not _is_sha256(value.get("sha256"))
    ):
        raise SnapshotError(f"invalid exact file record for {label}")
    return {"bytes": value["bytes"], "sha256": value["sha256"]}


def _snapshot_metadata(payload: object) -> dict[str, Any]:
    expected_top = {
        "schema",
        "bundle_id",
        "snapshot_scope",
        "consumer_source_contract",
        "producer_build_inputs",
        "resource_manifest",
        "external_resource_source",
        "external_toolchain",
    }
    if not isinstance(payload, dict) or set(payload) != expected_top:
        raise SnapshotError("snapshot lock has an incomplete or unexpected schema")
    if (
        payload.get("schema") != SCHEMA
        or payload.get("bundle_id") != BUNDLE_ID
        or payload.get("snapshot_scope") != SNAPSHOT_SCOPE
    ):
        raise SnapshotError("snapshot schema, scope, or bundle identity changed")
    if payload.get("consumer_source_contract") != {
        "resource_producer_snapshot_is_separate": True,
        "runtime_consumer_source_may_differ": True,
        "runtime_consumer_source_must_not_replace_producer_snapshot": True,
    }:
        raise SnapshotError("producer/consumer source-separation contract is invalid")

    manifest_binding = payload.get("resource_manifest")
    if manifest_binding != {
        "schema": RESOURCE_MANIFEST_BINDING_SCHEMA,
        "snapshot_path": "RESOURCE-MANIFEST.json",
        **RESOURCE_MANIFEST_RECORD,
    }:
        raise SnapshotError("sealed resource-manifest binding changed")

    source = payload.get("external_resource_source")
    if not isinstance(source, dict) or set(source) != {
        "schema",
        "name",
        "url",
        "commit",
        "tree",
        "commit_timestamp",
        "license",
        "inputs",
    }:
        raise SnapshotError("Apertium external binding has an invalid schema")
    if source.get("schema") != APERTIUM_BINDING_SCHEMA:
        raise SnapshotError("Apertium external binding schema changed")
    if (
        source.get("name") != "apertium-kaz"
        or source.get("url") != "https://github.com/apertium/apertium-kaz"
        or source.get("commit") != "95c6dd0d8536ee69a7058634b03a3e82100b6b6e"
        or source.get("tree") != "8f8996c85a4081263a4eaf190f20bf4735d15291"
        or source.get("commit_timestamp") != "2023-11-01T19:52:09+00:00"
        or source.get("license") != "GPL-3.0"
    ):
        raise SnapshotError("Apertium source, revision, tree, or license changed")
    source_inputs = source.get("inputs")
    if not isinstance(source_inputs, dict) or set(source_inputs) != {
        "apertium-kaz.kaz.lexc",
        "apertium-kaz.kaz.rlx",
        "apertium-kaz.kaz.twol",
    }:
        raise SnapshotError("Apertium input inventory changed")
    for name, record in source_inputs.items():
        _validate_file_record(record, label=f"Apertium input {name}")

    toolchain = payload.get("external_toolchain")
    if not isinstance(toolchain, dict) or set(toolchain) != {
        "schema",
        "version",
        "bundle_id",
        "manifest",
        "archive_lock",
        "release_closure",
    }:
        raise SnapshotError("toolchain external binding has an invalid schema")
    if (
        toolchain.get("schema") != TOOLCHAIN_BINDING_SCHEMA
        or toolchain.get("version")
        != "ubuntu-noble-hfst-cg3-6cbd944616faf0bd"
        or toolchain.get("bundle_id")
        != "6cbd944616faf0bdef8e742eb57cc61ba55a8d643bc3df00f2cc66b542129899"
        or toolchain.get("manifest")
        != {
            "bytes": 48887,
            "sha256": "d39a1c6af7e6abd866cfa386c67c256c95b089cf67f5ffd5bb66c7b0cf2d9791",
        }
    ):
        raise SnapshotError("toolchain version, bundle, or manifest binding changed")
    archive_lock = toolchain.get("archive_lock")
    if archive_lock != {
        "schema": TOOLCHAIN_ARCHIVE_LOCK_SCHEMA,
        "snapshot_path": "source/scripts/toolchain_assets.lock.json",
        "bytes": 2120,
        "sha256": "73284682e37b367606d31ccf6307bd298435ea0ab4d37906eeb677cfb9ec7744",
    }:
        raise SnapshotError("toolchain archive-lock binding changed")
    release_closure = toolchain.get("release_closure")
    if release_closure != {
        "schema": RELEASE_CLOSURE_BINDING_SCHEMA,
        "lock_schema": LINUX_CLOSURE_LOCK_SCHEMA,
        "lock_path": CLOSURE_LOCK_PATH,
        "lock": CLOSURE_LOCK_RECORD,
        "physical_binary_archives_required": True,
        "physical_corresponding_sources_required": True,
        "canonical_release_builder_must_consume_receipt": True,
    }:
        raise SnapshotError("release-closure contract changed")
    return payload


def _producer_inputs(
    snapshot_root: Path, payload: dict[str, Any]
) -> tuple[dict[str, dict[str, int | str]], dict[str, Path]]:
    inputs = payload.get("producer_build_inputs")
    if not isinstance(inputs, dict) or set(inputs) != EXPECTED_INPUTS:
        raise SnapshotError("producer build-input set is incomplete or unexpected")

    expected_snapshot_files: set[str] = set()
    build_inputs: dict[str, dict[str, int | str]] = {}
    producer_paths: dict[str, Path] = {}
    for source_name in sorted(EXPECTED_INPUTS):
        record = inputs.get(source_name)
        if not isinstance(record, dict) or set(record) != {
            "snapshot_path",
            "bytes",
            "sha256",
        }:
            raise SnapshotError(f"invalid producer record: {source_name}")
        relative = _safe_relative(record["snapshot_path"], label="snapshot_path")
        if relative.parts[0] != "source":
            raise SnapshotError(f"producer input is outside source/: {relative}")
        if relative.as_posix() in expected_snapshot_files:
            raise SnapshotError(f"duplicate snapshot path: {relative}")
        expected_snapshot_files.add(relative.as_posix())
        candidate = snapshot_root.joinpath(*relative.parts)
        observed = _file_record(candidate)
        expected = _validate_file_record(
            {"bytes": record["bytes"], "sha256": record["sha256"]},
            label=source_name,
        )
        if observed != expected:
            raise SnapshotError(f"producer source identity changed: {source_name}")
        build_inputs[source_name] = observed
        producer_paths[source_name] = candidate.resolve()

    source_root = snapshot_root / "source"
    try:
        entries = list(source_root.rglob("*"))
    except OSError as exc:
        raise SnapshotError(f"cannot inventory producer snapshot: {exc}") from exc
    observed_files: set[str] = set()
    for entry in entries:
        try:
            entry_stat = entry.lstat()
        except OSError as exc:
            raise SnapshotError(f"cannot stat producer snapshot entry: {entry}") from exc
        if stat.S_ISLNK(entry_stat.st_mode):
            raise SnapshotError(f"producer snapshot contains a symlink: {entry}")
        if stat.S_ISREG(entry_stat.st_mode):
            observed_files.add(entry.relative_to(snapshot_root).as_posix())
        elif not stat.S_ISDIR(entry_stat.st_mode):
            raise SnapshotError(f"producer snapshot contains a special entry: {entry}")
    if observed_files != expected_snapshot_files:
        raise SnapshotError(
            "producer snapshot physical inventory differs from the locked input set"
        )
    return build_inputs, producer_paths


def _manifest_source_binding(payload: dict[str, Any]) -> dict[str, Any]:
    source = dict(payload["external_resource_source"])
    source.pop("schema")
    return source


def _manifest_toolchain_binding(payload: dict[str, Any]) -> dict[str, Any]:
    toolchain = payload["external_toolchain"]
    return {
        "bundle_id": toolchain["bundle_id"],
        "version": toolchain["version"],
        "manifest": toolchain["manifest"],
    }


def _validate_resource_manifest(
    manifest: object,
    payload: dict[str, Any],
    build_inputs: dict[str, dict[str, int | str]],
) -> dict[str, Any]:
    if not isinstance(manifest, dict) or set(manifest) != {
        "schema",
        "source",
        "build",
        "files",
        "bundle_id",
        "version",
    }:
        raise SnapshotError("resource manifest has an invalid exact schema")
    if manifest.get("schema") != RESOURCE_MANIFEST_SCHEMA:
        raise SnapshotError("resource manifest schema changed")
    if manifest.get("bundle_id") != BUNDLE_ID:
        raise SnapshotError("resource manifest bundle identity changed")
    identity = {
        key: value
        for key, value in manifest.items()
        if key not in {"bundle_id", "version"}
    }
    if _canonical_hash(identity) != BUNDLE_ID:
        raise SnapshotError("resource manifest canonical bundle identity is invalid")
    expected_version = (
        "apertium-kaz-"
        + payload["external_resource_source"]["commit"][:12]
        + "+qazmorph-"
        + BUNDLE_ID[:16]
    )
    if manifest.get("version") != expected_version:
        raise SnapshotError("resource manifest version label changed")
    if manifest.get("source") != _manifest_source_binding(payload):
        raise SnapshotError(
            "resource manifest does not bind the exact Apertium source, inputs, "
            "revision, tree, timestamp, and license"
        )
    build = manifest.get("build")
    if not isinstance(build, dict):
        raise SnapshotError("resource manifest build section is invalid")
    if build.get("inputs") != build_inputs:
        raise SnapshotError("resource manifest does not bind this producer snapshot")
    if build.get("toolchain") != _manifest_toolchain_binding(payload):
        raise SnapshotError(
            "resource manifest does not bind the exact toolchain bundle and manifest"
        )
    files = manifest.get("files")
    if not isinstance(files, dict) or set(files) != RESOURCE_FILES:
        raise SnapshotError("resource artifact inventory changed")
    for name, record in files.items():
        _validate_file_record(record, label=f"resource artifact {name}")
    return manifest


def _snapshot_resource_manifest(
    snapshot_root: Path,
    payload: dict[str, Any],
    build_inputs: dict[str, dict[str, int | str]],
) -> tuple[dict[str, Any], dict[str, int | str]]:
    binding = payload["resource_manifest"]
    relative = _safe_relative(binding["snapshot_path"], label="resource manifest path")
    path = snapshot_root.joinpath(*relative.parts)
    manifest, record = _read_json_with_record(path)
    expected = {"bytes": binding["bytes"], "sha256": binding["sha256"]}
    if record != expected:
        raise SnapshotError("sealed resource-manifest snapshot identity changed")
    return _validate_resource_manifest(manifest, payload, build_inputs), record


def _git_output(root: Path, *arguments: str) -> str:
    try:
        return subprocess.check_output(
            ["git", "-C", str(root), *arguments],
            text=True,
            encoding="utf-8",
            stderr=subprocess.STDOUT,
        ).strip()
    except (OSError, subprocess.CalledProcessError) as exc:
        detail = getattr(exc, "output", "")
        raise SnapshotError(
            f"cannot verify clean Apertium source with git: {detail}"
        ) from exc


def _verify_apertium_source(
    source_root: Path, binding: dict[str, Any]
) -> dict[str, Any]:
    if source_root.is_symlink():
        raise SnapshotError("Apertium source root must not be a symlink")
    try:
        root = source_root.resolve(strict=True)
    except OSError as exc:
        raise SnapshotError(f"cannot resolve Apertium source: {exc}") from exc
    if not root.is_dir():
        raise SnapshotError("Apertium source is not a directory")
    if _git_output(root, "status", "--porcelain=v1", "--untracked-files=all"):
        raise SnapshotError("Apertium source tree is not clean")
    if _git_output(root, "rev-parse", "HEAD") != binding["commit"]:
        raise SnapshotError("Apertium source commit changed")
    if _git_output(root, "rev-parse", "HEAD^{tree}") != binding["tree"]:
        raise SnapshotError("Apertium source tree identity changed")
    observed_inputs = {
        name: _file_record(root / name)
        for name in sorted(binding["inputs"])
    }
    if observed_inputs != binding["inputs"]:
        raise SnapshotError("Apertium physical source inputs changed")
    return {
        "commit": binding["commit"],
        "tree": binding["tree"],
        "license": binding["license"],
        "inputs": observed_inputs,
    }


def _validate_toolchain_manifest(
    manifest: object, binding: dict[str, Any]
) -> dict[str, Any]:
    if not isinstance(manifest, dict) or set(manifest) != {
        "schema",
        "distribution",
        "architecture",
        "packages",
        "archive_lock",
        "commands",
        "files",
        "bundle_id",
        "version",
    }:
        raise SnapshotError("toolchain manifest has an invalid exact schema")
    if (
        manifest.get("schema") != TOOLCHAIN_MANIFEST_SCHEMA
        or manifest.get("bundle_id") != binding["bundle_id"]
        or manifest.get("version") != binding["version"]
    ):
        raise SnapshotError("toolchain manifest identity changed")
    identity = {
        key: value
        for key, value in manifest.items()
        if key not in {"bundle_id", "version"}
    }
    if _canonical_hash(identity) != binding["bundle_id"]:
        raise SnapshotError("toolchain canonical bundle identity is invalid")
    archive = binding["archive_lock"]
    if manifest.get("archive_lock") != {
        "schema": archive["schema"],
        "file": {"bytes": archive["bytes"], "sha256": archive["sha256"]},
    }:
        raise SnapshotError("toolchain manifest archive-lock binding changed")
    packages = manifest.get("packages")
    if not isinstance(packages, list) or not packages:
        raise SnapshotError("toolchain manifest package inventory is empty")
    for index, package in enumerate(packages):
        if not isinstance(package, dict) or set(package) != {
            "package",
            "version",
            "architecture",
            "filename",
            "bytes",
            "sha256",
        }:
            raise SnapshotError(f"invalid toolchain package record {index}")
        _safe_relative(package["filename"], label="toolchain package filename")
        _validate_file_record(
            {"bytes": package["bytes"], "sha256": package["sha256"]},
            label=f"toolchain package {package['filename']}",
        )
    if not isinstance(manifest.get("commands"), dict):
        raise SnapshotError("toolchain command inventory is invalid")
    files = manifest.get("files")
    if not isinstance(files, dict) or not files:
        raise SnapshotError("toolchain file inventory is invalid")
    return manifest


def _verify_toolchain_inventory(
    toolchain_root: Path, binding: dict[str, Any]
) -> tuple[dict[str, Any], int]:
    if toolchain_root.is_symlink():
        raise SnapshotError("toolchain root must not be a symlink")
    try:
        root = toolchain_root.resolve(strict=True)
    except OSError as exc:
        raise SnapshotError(f"cannot resolve toolchain root: {exc}") from exc
    manifest_path = root / "manifest.json"
    manifest, record = _read_json_with_record(manifest_path)
    if record != binding["manifest"]:
        raise SnapshotError("toolchain manifest bytes changed")
    manifest = _validate_toolchain_manifest(manifest, binding)

    expected_files = manifest["files"]
    observed_paths: set[str] = set()
    for entry in root.rglob("*"):
        relative = entry.relative_to(root).as_posix()
        entry_stat = entry.lstat()
        if stat.S_ISDIR(entry_stat.st_mode):
            continue
        if relative == "manifest.json":
            continue
        if not (stat.S_ISREG(entry_stat.st_mode) or stat.S_ISLNK(entry_stat.st_mode)):
            raise SnapshotError(f"toolchain contains a special entry: {relative}")
        observed_paths.add(relative)
    if observed_paths != set(expected_files):
        raise SnapshotError("toolchain physical inventory differs from its manifest")

    for relative_name, expected in expected_files.items():
        relative = _safe_relative(relative_name, label="toolchain inventory path")
        path = root.joinpath(*relative.parts)
        observed_stat = path.lstat()
        if not isinstance(expected, dict):
            raise SnapshotError(f"invalid toolchain inventory record: {relative_name}")
        kind = expected.get("kind")
        expected_mode = expected.get("mode")
        observed_mode = f"{stat.S_IMODE(observed_stat.st_mode):04o}"
        if expected_mode != observed_mode:
            raise SnapshotError(f"toolchain mode changed: {relative_name}")
        if kind == "file":
            if set(expected) != {"kind", "mode", "bytes", "sha256"}:
                raise SnapshotError(f"invalid toolchain file record: {relative_name}")
            observed = _file_record(path)
            if observed != {
                "bytes": expected["bytes"],
                "sha256": expected["sha256"],
            }:
                raise SnapshotError(f"toolchain file identity changed: {relative_name}")
        elif kind == "symlink":
            if set(expected) != {"kind", "mode", "target"}:
                raise SnapshotError(f"invalid toolchain symlink record: {relative_name}")
            if not stat.S_ISLNK(observed_stat.st_mode):
                raise SnapshotError(f"toolchain symlink changed kind: {relative_name}")
            if os.readlink(path) != expected["target"]:
                raise SnapshotError(f"toolchain symlink target changed: {relative_name}")
        else:
            raise SnapshotError(f"unsupported toolchain inventory kind: {relative_name}")
    return manifest, len(expected_files)


def _validate_closure_lock(
    lock: object,
    binding: dict[str, Any],
    toolchain_manifest: dict[str, Any],
) -> dict[str, Any]:
    if not isinstance(lock, dict) or set(lock) != {
        "schema",
        "distribution",
        "platform",
        "transform",
        "archives",
        "corresponding_sources",
        "components",
    }:
        raise SnapshotError("release-closure lock has an invalid exact schema")
    if lock.get("schema") != binding["lock_schema"]:
        raise SnapshotError("release-closure lock schema changed")
    platform = lock.get("platform")
    if not isinstance(platform, dict) or set(platform) != {
        "system",
        "machine",
        "minimum_os",
    }:
        raise SnapshotError("release-closure platform schema changed")
    expected_record_sets = (
        (
            "archives",
            {"component", "filename", "url", "bytes", "sha256"},
        ),
        (
            "corresponding_sources",
            {"component", "revision", "filename", "url", "bytes", "sha256"},
        ),
    )
    for section, fields in expected_record_sets:
        records = lock.get(section)
        if not isinstance(records, list) or not records:
            raise SnapshotError(f"release-closure {section} inventory is empty")
        names: set[str] = set()
        for index, record in enumerate(records):
            if not isinstance(record, dict) or set(record) != fields:
                raise SnapshotError(
                    f"invalid release-closure {section} record {index}"
                )
            relative = _safe_relative(
                record["filename"], label=f"{section} filename"
            )
            if len(relative.parts) != 1 or relative.name in names:
                raise SnapshotError(
                    f"unsafe or duplicate release-closure filename: {relative}"
                )
            names.add(relative.name)
            _validate_file_record(
                {"bytes": record["bytes"], "sha256": record["sha256"]},
                label=f"{section} {relative.name}",
            )
    components = lock.get("components")
    if not isinstance(components, list) or not components:
        raise SnapshotError("release-closure component/license inventory is empty")
    for index, component in enumerate(components):
        if (
            not isinstance(component, dict)
            or set(component) != {"name", "version", "license"}
            or not all(
                isinstance(component.get(name), str) and component[name]
                for name in ("name", "version", "license")
            )
        ):
            raise SnapshotError(
                f"invalid release-closure component/license record {index}"
            )

    locked_archives = {
        (item["filename"], item["bytes"], item["sha256"])
        for item in lock["archives"]
    }
    toolchain_archives = {
        (item["filename"], item["bytes"], item["sha256"])
        for item in toolchain_manifest["packages"]
    }
    if locked_archives != toolchain_archives:
        raise SnapshotError(
            "release-closure binary archives differ from the toolchain packages"
        )
    return lock


def _verify_closure_lock(
    path: Path,
    binding: dict[str, Any],
    toolchain_manifest: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, int | str]]:
    lock, record = _read_json_with_record(path)
    if record != binding["lock"]:
        raise SnapshotError("release-closure lock bytes changed")
    return _validate_closure_lock(lock, binding, toolchain_manifest), record


def _verify_locked_directory(
    root_path: Path,
    records: Sequence[dict[str, Any]],
    *,
    label: str,
) -> dict[str, dict[str, int | str]]:
    if root_path.is_symlink():
        raise SnapshotError(f"{label} root must not be a symlink")
    try:
        root = root_path.resolve(strict=True)
    except OSError as exc:
        raise SnapshotError(f"cannot resolve {label} root: {exc}") from exc
    if not root.is_dir():
        raise SnapshotError(f"{label} root is not a directory")
    expected = {record["filename"]: record for record in records}
    observed_names: set[str] = set()
    for entry in root.iterdir():
        entry_stat = entry.lstat()
        if not stat.S_ISREG(entry_stat.st_mode) or stat.S_ISLNK(entry_stat.st_mode):
            raise SnapshotError(f"{label} contains a non-regular entry: {entry.name}")
        observed_names.add(entry.name)
    if observed_names != set(expected):
        raise SnapshotError(f"{label} physical inventory differs from its lock")
    result: dict[str, dict[str, int | str]] = {}
    for name, expected_record in expected.items():
        observed = _file_record(root / name)
        expected_identity = {
            "bytes": expected_record["bytes"],
            "sha256": expected_record["sha256"],
        }
        if observed != expected_identity:
            raise SnapshotError(f"{label} file identity changed: {name}")
        result[name] = observed
    return result


def _verify_resource_files(
    manifest_path: Path, manifest: dict[str, Any]
) -> int:
    if manifest_path.is_symlink():
        raise SnapshotError("resource manifest must not be a symlink")
    root_path = manifest_path.parent
    if root_path.is_symlink():
        raise SnapshotError("resource bundle root must not be a symlink")
    root = root_path.resolve(strict=True)
    expected_names = set(manifest["files"]) | {"manifest.json"}
    observed_names: set[str] = set()
    for entry in root.iterdir():
        entry_stat = entry.lstat()
        if not stat.S_ISREG(entry_stat.st_mode) or stat.S_ISLNK(entry_stat.st_mode):
            raise SnapshotError(
                f"resource bundle contains a non-regular entry: {entry.name}"
            )
        observed_names.add(entry.name)
    if observed_names != expected_names:
        raise SnapshotError("resource bundle physical inventory changed")
    for name, expected in manifest["files"].items():
        if _file_record(root / name) != expected:
            raise SnapshotError(f"resource artifact identity changed: {name}")
    return len(manifest["files"])


def _release_closure_identity(
    payload: dict[str, Any],
    resource_manifest_record: dict[str, int | str],
    closure_lock_record: dict[str, int | str],
    archives: dict[str, dict[str, int | str]],
    sources: dict[str, dict[str, int | str]],
) -> str:
    value = {
        "schema": RELEASE_CLOSURE_RECEIPT_SCHEMA,
        "resource_bundle_id": BUNDLE_ID,
        "resource_manifest": resource_manifest_record,
        "apertium_source": _manifest_source_binding(payload),
        "toolchain": _manifest_toolchain_binding(payload),
        "release_closure_lock": {
            "path": CLOSURE_LOCK_PATH,
            **closure_lock_record,
        },
        "binary_archives": archives,
        "corresponding_sources": sources,
    }
    return _canonical_hash(value)


def verify_snapshot(
    snapshot_root: Path,
    *,
    consumer_root: Path | None,
    resource_manifest: Path | None,
    apertium_source: Path | None = None,
    toolchain_dir: Path | None = None,
    closure_lock: Path | None = None,
    binary_archives_dir: Path | None = None,
    corresponding_sources_dir: Path | None = None,
) -> dict[str, Any]:
    if snapshot_root.is_symlink():
        raise SnapshotError("snapshot root must not be a symlink")
    snapshot_root = snapshot_root.resolve(strict=True)
    payload = _snapshot_metadata(_read_json(snapshot_root / "SNAPSHOT.json"))
    build_inputs, producer_paths = _producer_inputs(snapshot_root, payload)
    sealed_manifest, sealed_manifest_record = _snapshot_resource_manifest(
        snapshot_root, payload, build_inputs
    )

    consumer_records: dict[str, dict[str, int | str]] | None = None
    checked_closure_lock: Path | None = closure_lock
    if consumer_root is not None:
        consumer_root = consumer_root.resolve(strict=True)
        consumer_records = {}
        for source_name in sorted(DISTINCT_RUNTIME_INPUTS):
            consumer = consumer_root / source_name
            if consumer.resolve() == producer_paths[source_name]:
                raise SnapshotError(
                    f"runtime consumer source aliases producer source: {source_name}"
                )
            observed = _file_record(consumer)
            if observed == build_inputs[source_name]:
                raise SnapshotError(
                    "bf1f consumer hardening is missing; producer bytes were "
                    f"substituted as current runtime source: {source_name}"
                )
            consumer_records[source_name] = observed
        default_closure_lock = consumer_root / CLOSURE_LOCK_PATH
        if checked_closure_lock is None:
            checked_closure_lock = default_closure_lock
        elif checked_closure_lock.resolve(strict=True) != default_closure_lock.resolve(
            strict=True
        ):
            raise SnapshotError(
                "release-closure lock is not the canonical checked-in lock"
            )

    closure_contract = payload["external_toolchain"]["release_closure"]
    closure_lock_payload: dict[str, Any] | None = None
    closure_lock_record: dict[str, int | str] | None = None
    if checked_closure_lock is not None:
        # Full validation against the toolchain package set follows below when
        # the physical toolchain is supplied. Here the exact lock bytes and
        # external schema are already mandatory.
        provisional, record = _read_json_with_record(
            checked_closure_lock
        )
        if record != closure_contract["lock"]:
            raise SnapshotError("release-closure lock bytes changed")
        if (
            not isinstance(provisional, dict)
            or provisional.get("schema") != closure_contract["lock_schema"]
        ):
            raise SnapshotError("release-closure lock schema changed")
        closure_lock_payload = provisional
        closure_lock_record = record

    external_paths = {
        "resource manifest": resource_manifest,
        "Apertium source": apertium_source,
        "toolchain directory": toolchain_dir,
        "closure lock": checked_closure_lock,
        "binary archives": binary_archives_dir,
        "corresponding sources": corresponding_sources_dir,
    }
    release_requested = resource_manifest is not None or any(
        value is not None
        for name, value in external_paths.items()
        if name not in {"resource manifest", "closure lock"}
    )
    if release_requested:
        missing = [name for name, value in external_paths.items() if value is None]
        if missing:
            raise SnapshotError(
                "full release-closure verification requires: "
                + ", ".join(missing)
            )

    release_identity: str | None = None
    resource_artifacts_verified = 0
    toolchain_files_verified = 0
    archives_verified: dict[str, dict[str, int | str]] | None = None
    sources_verified: dict[str, dict[str, int | str]] | None = None
    apertium_verified: dict[str, Any] | None = None
    external_manifest_verified = False
    if release_requested:
        assert resource_manifest is not None
        assert apertium_source is not None
        assert toolchain_dir is not None
        assert checked_closure_lock is not None
        assert binary_archives_dir is not None
        assert corresponding_sources_dir is not None

        external_manifest, external_record = _read_json_with_record(resource_manifest)
        if external_record != sealed_manifest_record:
            raise SnapshotError("external resource manifest bytes differ from bf1f")
        external_manifest = _validate_resource_manifest(
            external_manifest, payload, build_inputs
        )
        if external_manifest != sealed_manifest:
            raise SnapshotError("external resource manifest payload differs from bf1f")
        resource_artifacts_verified = _verify_resource_files(
            resource_manifest, external_manifest
        )
        external_manifest_verified = True

        apertium_verified = _verify_apertium_source(
            apertium_source, payload["external_resource_source"]
        )
        toolchain_manifest, toolchain_files_verified = _verify_toolchain_inventory(
            toolchain_dir, payload["external_toolchain"]
        )
        closure_lock_payload, closure_lock_record = _verify_closure_lock(
            checked_closure_lock,
            closure_contract,
            toolchain_manifest,
        )
        archives_verified = _verify_locked_directory(
            binary_archives_dir,
            closure_lock_payload["archives"],
            label="binary archive closure",
        )
        sources_verified = _verify_locked_directory(
            corresponding_sources_dir,
            closure_lock_payload["corresponding_sources"],
            label="corresponding-source closure",
        )
        release_identity = _release_closure_identity(
            payload,
            sealed_manifest_record,
            closure_lock_record,
            archives_verified,
            sources_verified,
        )

    return {
        "schema": "qazmorph-resource-producer-source-verification-v2",
        "bundle_id": BUNDLE_ID,
        "snapshot_scope": SNAPSHOT_SCOPE,
        "snapshot_verified": True,
        "sealed_manifest_snapshot_verified": True,
        "canonical_bundle_identity_verified": True,
        "producer_inputs": len(build_inputs),
        "consumer_source_separate": consumer_records is not None,
        "consumer_records": consumer_records,
        "closure_lock_verified": closure_lock_record is not None,
        "external_resource_manifest_verified": external_manifest_verified,
        "resource_artifacts_verified": resource_artifacts_verified,
        "apertium_source_verified": apertium_verified is not None,
        "toolchain_binary_inventory_verified": toolchain_files_verified > 0,
        "toolchain_files_verified": toolchain_files_verified,
        "binary_archives_verified": (
            0 if archives_verified is None else len(archives_verified)
        ),
        "corresponding_sources_verified": (
            0 if sources_verified is None else len(sources_verified)
        ),
        "release_closure_complete": release_identity is not None,
        "release_closure_identity": release_identity,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--snapshot-root", required=True, type=Path)
    parser.add_argument("--consumer-root", type=Path)
    parser.add_argument("--resource-manifest", type=Path)
    parser.add_argument("--apertium-source", type=Path)
    parser.add_argument("--toolchain-dir", type=Path)
    parser.add_argument("--closure-lock", type=Path)
    parser.add_argument("--binary-archives-dir", type=Path)
    parser.add_argument("--corresponding-sources-dir", type=Path)
    args = parser.parse_args()
    try:
        receipt = verify_snapshot(
            args.snapshot_root,
            consumer_root=args.consumer_root,
            resource_manifest=args.resource_manifest,
            apertium_source=args.apertium_source,
            toolchain_dir=args.toolchain_dir,
            closure_lock=args.closure_lock,
            binary_archives_dir=args.binary_archives_dir,
            corresponding_sources_dir=args.corresponding_sources_dir,
        )
    except SnapshotError as exc:
        parser.error(str(exc))
    print(json.dumps(receipt, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
