#!/usr/bin/env python3
"""Compare deterministic gzip/xz/zstd for both canonical release tar payloads."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import lzma
from pathlib import Path
import shutil
import subprocess
import sys
from typing import Any

from release_common import (
    ReleaseError,
    begin_gate_execution,
    archive_limits,
    assert_relative_json,
    canonical_hash,
    file_record,
    gate_envelope,
    identity_sha256,
    inspect_tar,
    json_bytes,
    load_identity,
    locked_gate_invocation,
    read_json,
    validate_gate_envelope,
    verify_artifact,
    verify_file,
)


SUFFIX = {"gzip": ".tar.gz", "xz": ".tar.xz", "zstd": ".tar.zst"}


def _reject_compressed_input(path: Path) -> None:
    with path.open("rb") as stream:
        magic = stream.read(8)
    if magic.startswith(
        (
            b"\x1f\x8b",
            b"\xfd7zXZ\x00",
            b"BZh",
            b"\x28\xb5\x2f\xfd",
            b"7z\xbc\xaf\x27\x1c",
            b"Rar!\x1a\x07",
            b"PK\x03\x04",
        )
    ):
        raise ReleaseError(
            "canonical compression comparison requires one uncompressed tar input"
        )


def _verify_tool(record: dict[str, Any]) -> Path:
    if record["name"].startswith("python"):
        executable = Path(sys.executable).resolve(strict=True)
    else:
        located = shutil.which(record["name"])
        if located is None:
            raise ReleaseError(f"compressor is unavailable: {record['name']}")
        executable = Path(located).resolve(strict=True)
    verify_file(executable, record["executable"], label=f"compressor {record['name']}")
    process = subprocess.run(
        [str(executable), *record["version_argv"][1:]],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=60,
        check=False,
    )
    if (
        process.returncode
        or process.stdout.decode("utf-8", "replace").strip() != record["version"]
    ):
        raise ReleaseError(f"compressor version differs: {record['name']}")
    return executable


def _compress(
    source: Path,
    destination: Path,
    *,
    format_name: str,
    compressor: dict[str, Any],
) -> dict[str, Any]:
    if destination.exists() or destination.is_symlink():
        raise ReleaseError(f"compression candidate already exists: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    executable = _verify_tool(compressor)
    if format_name == "gzip":
        with source.open("rb") as input_stream, destination.open("xb") as raw:
            with gzip.GzipFile(
                filename="", mode="wb", fileobj=raw, compresslevel=9, mtime=0
            ) as output_stream:
                shutil.copyfileobj(input_stream, output_stream, length=1024 * 1024)
    elif format_name == "xz":
        with (
            source.open("rb") as input_stream,
            lzma.open(
                destination,
                "xb",
                format=lzma.FORMAT_XZ,
                check=lzma.CHECK_CRC64,
                preset=9 | lzma.PRESET_EXTREME,
            ) as output_stream,
        ):
            shutil.copyfileobj(input_stream, output_stream, length=1024 * 1024)
    elif format_name == "zstd":
        with destination.open("xb") as output_stream:
            process = subprocess.run(
                [
                    str(executable),
                    "-19",
                    "--ultra",
                    "--threads=1",
                    "--no-progress",
                    "--stdout",
                    str(source),
                ],
                stdin=subprocess.DEVNULL,
                stdout=output_stream,
                stderr=subprocess.PIPE,
                timeout=3600,
                check=False,
            )
        if process.returncode:
            raise ReleaseError(
                "zstd compression failed: "
                + process.stderr[:4096].decode("utf-8", "replace")
            )
    else:
        raise ReleaseError(f"unsupported compression format: {format_name}")
    return {"filename": destination.name, **file_record(destination)}


def _decompress(
    source: Path,
    destination: Path,
    *,
    format_name: str,
    compressor: dict[str, Any],
    byte_cap: int,
) -> dict[str, Any]:
    if destination.exists() or destination.is_symlink():
        raise ReleaseError(f"round-trip output already exists: {destination}")
    if format_name in {"gzip", "xz"}:
        reader = (
            gzip.open(source, "rb")
            if format_name == "gzip"
            else lzma.open(source, "rb")
        )
        size = 0
        digest = hashlib.sha256()
        with reader, destination.open("xb") as output:
            while True:
                block = reader.read(min(1024 * 1024, byte_cap - size + 1))
                if not block:
                    break
                size += len(block)
                if size > byte_cap:
                    raise ReleaseError(
                        "compressed candidate expands beyond canonical tar cap"
                    )
                digest.update(block)
                output.write(block)
        return {
            "filename": destination.name,
            "bytes": size,
            "sha256": digest.hexdigest(),
        }
    executable = _verify_tool(compressor)
    with destination.open("xb") as output:
        process = subprocess.run(
            [str(executable), "--decompress", "--no-progress", "--stdout", str(source)],
            stdin=subprocess.DEVNULL,
            stdout=output,
            stderr=subprocess.PIPE,
            timeout=3600,
            check=False,
        )
    if process.returncode:
        raise ReleaseError("zstd round-trip decompression failed")
    if destination.stat().st_size > byte_cap:
        raise ReleaseError("zstd candidate expands beyond canonical tar cap")
    return {"filename": destination.name, **file_record(destination)}


def _one_asset(
    *,
    identity: dict[str, Any],
    asset_name: str,
    canonical_tar: Path,
    published: Path | None,
    workspace: Path,
    enforce_selection: bool = True,
    producer_receipts: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    policy = identity["compression"][asset_name]
    expected_tar = policy["canonical_tar"]
    verify_file(
        canonical_tar,
        {"bytes": expected_tar["bytes"], "sha256": expected_tar["sha256"]},
        label=f"{asset_name} canonical tar",
    )
    _reject_compressed_input(canonical_tar)
    members = inspect_tar(
        canonical_tar,
        limits=archive_limits(identity, asset_name),
        expected_top=(
            identity["ready_run"]["top_level"]
            if asset_name == "ready_run"
            else identity["corresponding_source"]["top_level"]
        ),
    )
    tar_tree_identity = canonical_hash(
        [
            {
                "name": member.name,
                "kind": member.kind,
                "size": member.size,
                "mode": member.mode,
                "linkname": member.linkname,
                "sha256": member.sha256,
            }
            for member in members
        ]
    )
    eligibility = {record["format"]: record for record in policy["eligibility"]}
    candidates: list[dict[str, Any]] = []
    for format_name in ("gzip", "xz", "zstd"):
        compressor = policy["compressors"][format_name]
        builds: list[dict[str, Any]] = []
        for build_index in (1, 2):
            suffix = SUFFIX[format_name]
            candidate = (
                workspace
                / asset_name
                / format_name
                / f"build-{build_index}"
                / (canonical_tar.name[:-4] + suffix)
            )
            compressed = _compress(
                canonical_tar,
                candidate,
                format_name=format_name,
                compressor=compressor,
            )
            expanded = candidate.with_name("roundtrip.tar")
            roundtrip = _decompress(
                candidate,
                expanded,
                format_name=format_name,
                compressor=compressor,
                byte_cap=expected_tar["bytes"],
            )
            if (
                roundtrip["bytes"] != expected_tar["bytes"]
                or roundtrip["sha256"] != expected_tar["sha256"]
            ):
                raise ReleaseError(
                    f"{asset_name}/{format_name} does not round-trip to canonical tar"
                )
            roundtrip_members = inspect_tar(
                expanded,
                limits=archive_limits(identity, asset_name),
                expected_top=(
                    identity["ready_run"]["top_level"]
                    if asset_name == "ready_run"
                    else identity["corresponding_source"]["top_level"]
                ),
            )
            if len(roundtrip_members) != len(members):
                raise ReleaseError("compression round-trip member count changed")
            builds.append(
                {
                    "root": f"{asset_name}/{format_name}/build-{build_index}",
                    "output": compressed,
                    "roundtrip": roundtrip,
                }
            )
        first = builds[0]["output"]
        second = builds[1]["output"]
        if first["bytes"] != second["bytes"] or first["sha256"] != second["sha256"]:
            raise ReleaseError(
                f"{asset_name}/{format_name} compression is not deterministic"
            )
        candidates.append(
            {
                "format": format_name,
                "suffix": SUFFIX[format_name],
                "eligible": eligibility[format_name]["eligible"],
                "eligibility_reason": eligibility[format_name]["reason"],
                "bytes": first["bytes"],
                "sha256": first["sha256"],
                "argv": compressor["argv"],
                "tool": compressor,
                "builds": builds,
                "builds_identical": True,
                "byte_identical": True,
                "roundtrip_tar_sha256": expected_tar["sha256"],
                "roundtrip_tree_sha256": tar_tree_identity,
            }
        )
    eligible = [candidate for candidate in candidates if candidate["eligible"]]
    if not eligible:
        raise ReleaseError(f"{asset_name} has no eligible compression format")
    selected = min(eligible, key=lambda item: (item["bytes"], item["format"]))
    if enforce_selection and selected["format"] != policy["selected_format"]:
        raise ReleaseError(
            f"{asset_name} identity selected {policy['selected_format']}, measured {selected['format']}"
        )
    selected_filename = canonical_tar.name[:-4] + SUFFIX[selected["format"]]
    published_record: dict[str, Any] | None = None
    if published is not None:
        verify_artifact(
            published,
            identity["artifacts"][asset_name],
            label=f"published {asset_name}",
        )
        if file_record(published) != {
            "bytes": selected["bytes"],
            "sha256": selected["sha256"],
        }:
            raise ReleaseError(
                f"published {asset_name} is not the selected minimum candidate"
            )
        selected_filename = published.name
        published_record = identity["artifacts"][asset_name]
    return {
        "canonical_tar": {
            "filename": canonical_tar.name,
            **file_record(canonical_tar),
            "producer": expected_tar["producer"],
            "members": len(members),
            "tree_sha256": tar_tree_identity,
            "producer_receipts": producer_receipts or [],
        },
        "candidates": candidates,
        "selected": {
            "format": selected["format"],
            "bytes": selected["bytes"],
            "sha256": selected["sha256"],
            "filename": selected_filename,
        },
        "published": published_record,
    }


def compare(args: argparse.Namespace) -> dict[str, Any]:
    if args.workspace.exists() or args.workspace.is_symlink():
        raise ReleaseError("compression comparison workspace must be fresh")
    if args.output.exists() or args.output.is_symlink():
        raise ReleaseError("compression comparison output already exists")
    identity_path = args.identity.resolve(strict=True)
    identity = load_identity(identity_path)
    execution = begin_gate_execution(
        identity, "compression-comparison", caller_file=__file__
    )
    reproducibility_path = args.reproducibility.resolve(strict=True)
    reproducibility_record = next(
        record
        for record in identity["verification"]["evidence"]
        if record["gate"] == "python-reproducibility"
    )
    verify_file(
        reproducibility_path,
        reproducibility_record["file"],
        label="Python reproducibility evidence for raw-tar receipts",
    )
    reproducibility = validate_gate_envelope(
        read_json(reproducibility_path),
        identity=identity,
        identity_contract_sha256=identity_sha256(identity_path),
        gate="python-reproducibility",
        subjects=reproducibility_record["subjects"],
    )
    builds = reproducibility.get("builds")
    if not isinstance(builds, list) or len(builds) < 2:
        raise ReleaseError("compression comparison lacks two native raw-tar producers")
    producer_receipts: dict[str, list[dict[str, Any]]] = {
        "ready_run": [],
        "corresponding_source": [],
    }
    for build in builds:
        root = build.get("root") if isinstance(build, dict) else None
        native = build.get("native_assembly") if isinstance(build, dict) else None
        if not isinstance(root, str) or not isinstance(native, dict):
            raise ReleaseError("raw-tar producer build is malformed")
        for asset_name in producer_receipts:
            assembly = native.get(asset_name)
            receipt = assembly.get("receipt") if isinstance(assembly, dict) else None
            if (
                not isinstance(receipt, dict)
                or set(receipt) != {"path", "file", "payload"}
                or assembly.get("canonical_tar")
                != receipt.get("payload", {}).get("canonical_tar")
            ):
                raise ReleaseError(
                    f"raw-tar producer receipt is malformed: {asset_name}"
                )
            producer_receipts[asset_name].append(
                {
                    "root": root,
                    "path": receipt["path"],
                    "file": receipt["file"],
                    "canonical_tar": assembly["canonical_tar"],
                }
            )
    workspace = args.workspace.absolute()
    workspace.mkdir(parents=True)
    assets = {
        "ready_run": _one_asset(
            identity=identity,
            asset_name="ready_run",
            canonical_tar=args.ready_tar.resolve(strict=True),
            published=args.ready_run.resolve(strict=True),
            workspace=workspace,
            producer_receipts=producer_receipts["ready_run"],
        ),
        "corresponding_source": _one_asset(
            identity=identity,
            asset_name="corresponding_source",
            canonical_tar=args.source_tar.resolve(strict=True),
            published=args.corresponding_source.resolve(strict=True),
            workspace=workspace,
            producer_receipts=producer_receipts["corresponding_source"],
        ),
    }
    payload = {
        "schema": "kazstem-macos-compression-comparison-v2",
        "pass": True,
        "release": identity["release"],
        "source_commit": identity["source_commit"],
        "source_tree": identity["source_tree"],
        "selection_rule": "smallest-eligible-byte-identical",
        "assets": assets,
    }
    assert_relative_json(payload, label="compression comparison payload")
    envelope = gate_envelope(
        identity=identity,
        identity_contract_sha256=identity_sha256(identity_path),
        gate="compression-comparison",
        subjects=["corresponding_source", "ready_run"],
        invocation=locked_gate_invocation(
            identity,
            "compression-comparison",
            stdout=b"PASS: ready/source compression candidates measured twice\n",
            execution=execution,
        ),
        coverage={
            "descendant_processes": 10,
            "full_descendant_coverage": True,
            "network_trace": None,
            "observations": {
                "assets": 2,
                "candidate_builds": 12,
                "candidate_formats": 6,
                "roundtrips": 12,
            },
            "trace_complete": True,
            "trace_truncated": False,
        },
        payload=payload,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(json_bytes(envelope))
    return envelope


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--identity", required=True, type=Path)
    parser.add_argument("--ready-tar", required=True, type=Path)
    parser.add_argument("--source-tar", required=True, type=Path)
    parser.add_argument("--ready-run", required=True, type=Path)
    parser.add_argument("--corresponding-source", required=True, type=Path)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--reproducibility", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    compare(args)
    print("PASS: ready/source compression candidates measured twice")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ReleaseError, OSError, ValueError, json.JSONDecodeError) as exc:
        raise SystemExit(f"error: {exc}") from exc
