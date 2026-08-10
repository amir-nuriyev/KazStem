#!/usr/bin/env python3
"""Fail-closed verifier for a manifest-bound resource-producer source snapshot."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
from typing import Any


SCHEMA = "qazmorph-resource-producer-source-snapshot-v1"
BUNDLE_ID = "bf1f31ff6e5860585b9e4134f12dcfb9d6df8030ee87b368e5a5f29eb45c1188"
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


class SnapshotError(RuntimeError):
    pass


def _file_record(path: Path) -> dict[str, int | str]:
    try:
        candidate_stat = path.lstat()
    except OSError as exc:
        raise SnapshotError(f"cannot stat snapshot file {path}: {exc}") from exc
    if stat.S_ISLNK(candidate_stat.st_mode) or not stat.S_ISREG(candidate_stat.st_mode):
        raise SnapshotError(f"snapshot entry is not a regular non-link file: {path}")
    digest = hashlib.sha256()
    size = 0
    try:
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                size += len(block)
                digest.update(block)
            opened_stat = os.fstat(stream.fileno())
    except OSError as exc:
        raise SnapshotError(f"cannot read snapshot file {path}: {exc}") from exc
    if (
        size != opened_stat.st_size
        or candidate_stat.st_dev != opened_stat.st_dev
        or candidate_stat.st_ino != opened_stat.st_ino
    ):
        raise SnapshotError(f"snapshot file changed while being verified: {path}")
    return {"bytes": size, "sha256": digest.hexdigest()}


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise SnapshotError(f"cannot read JSON {path}: {exc}") from exc


def _safe_relative(value: object) -> PurePosixPath:
    if not isinstance(value, str):
        raise SnapshotError("snapshot_path must be a string")
    relative = PurePosixPath(value)
    if relative.is_absolute() or not relative.parts or ".." in relative.parts:
        raise SnapshotError(f"unsafe snapshot_path: {value!r}")
    if relative.parts[0] != "source":
        raise SnapshotError(f"producer input is outside source/: {value!r}")
    return relative


def verify_snapshot(
    snapshot_root: Path,
    *,
    consumer_root: Path | None,
    resource_manifest: Path | None,
) -> dict[str, Any]:
    snapshot_root = snapshot_root.resolve()
    lock_path = snapshot_root / "SNAPSHOT.json"
    payload = _read_json(lock_path)
    if not isinstance(payload, dict):
        raise SnapshotError("snapshot lock must be an object")
    if payload.get("schema") != SCHEMA or payload.get("bundle_id") != BUNDLE_ID:
        raise SnapshotError("snapshot schema or bundle identity changed")
    contract = payload.get("consumer_source_contract")
    if contract != {
        "resource_producer_snapshot_is_separate": True,
        "runtime_consumer_source_may_differ": True,
        "runtime_consumer_source_must_not_replace_producer_snapshot": True,
    }:
        raise SnapshotError("producer/consumer source-separation contract is invalid")
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
        relative = _safe_relative(record["snapshot_path"])
        if relative.as_posix() in expected_snapshot_files:
            raise SnapshotError(f"duplicate snapshot path: {relative}")
        expected_snapshot_files.add(relative.as_posix())
        candidate = snapshot_root.joinpath(*relative.parts)
        observed = _file_record(candidate)
        expected = {"bytes": record["bytes"], "sha256": record["sha256"]}
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

    consumer_records: dict[str, dict[str, int | str]] | None = None
    if consumer_root is not None:
        consumer_root = consumer_root.resolve()
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

    manifest_verified = False
    if resource_manifest is not None:
        manifest = _read_json(resource_manifest.resolve())
        try:
            manifest_inputs = manifest["build"]["inputs"]
        except (KeyError, TypeError) as exc:
            raise SnapshotError("resource manifest has no build-input inventory") from exc
        if (
            not isinstance(manifest, dict)
            or manifest.get("schema") != "qazmorph-resource-manifest-v4"
            or manifest.get("bundle_id") != BUNDLE_ID
            or manifest_inputs != build_inputs
        ):
            raise SnapshotError("resource manifest does not bind this producer snapshot")
        manifest_verified = True

    return {
        "schema": "qazmorph-resource-producer-source-verification-v1",
        "bundle_id": BUNDLE_ID,
        "snapshot_verified": True,
        "producer_inputs": len(build_inputs),
        "consumer_source_separate": consumer_records is not None,
        "consumer_records": consumer_records,
        "resource_manifest_verified": manifest_verified,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--snapshot-root", required=True, type=Path)
    parser.add_argument("--consumer-root", type=Path)
    parser.add_argument("--resource-manifest", type=Path)
    args = parser.parse_args()
    try:
        receipt = verify_snapshot(
            args.snapshot_root,
            consumer_root=args.consumer_root,
            resource_manifest=args.resource_manifest,
        )
    except SnapshotError as exc:
        parser.error(str(exc))
    print(json.dumps(receipt, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
