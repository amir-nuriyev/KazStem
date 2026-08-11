#!/usr/bin/env python3
"""Audit the complete, paired Windows corresponding-source ZIP."""

from __future__ import annotations

import argparse
import bz2
import gzip
import io
import json
import lzma
from pathlib import Path, PurePosixPath
import stat
import tarfile
import tempfile
from typing import Any, BinaryIO
import unicodedata
import zlib

from release_common import (
    SOURCE_AUDIT_SCHEMA,
    ArchiveLimits,
    ReleaseError,
    ZipOutputContract,
    archive_limits,
    artifact_record,
    assert_relative_evidence,
    evidence_envelope,
    file_record,
    inspect_zip,
    json_bytes,
    load_identity,
    identity_sha256,
    portable_path,
    read_json,
    require_release_bootstrap,
    safe_extract_zip,
    sha256_stream,
    source_ready_location,
    tree_record,
    tree_inventory,
    verify_artifact,
    verify_canonical_python_release,
    verify_checksums,
    verify_file,
    verify_generator_runtime,
    verify_manifest,
    verify_required_paths,
    verify_source_receipt,
    verify_tree,
)


def safe_link(name: str, target: str, *, hardlink: bool) -> None:
    if not target or "\x00" in target or "\\" in target:
        raise ReleaseError(f"unsafe nested archive link target: {name!r} -> {target!r}")
    raw = PurePosixPath(target) if hardlink else PurePosixPath(name).parent / target
    if raw.is_absolute():
        raise ReleaseError(f"absolute nested archive link: {name!r} -> {target!r}")
    collapsed: list[str] = []
    for part in raw.parts:
        if part in {"", "."}:
            continue
        if part == "..":
            if not collapsed:
                raise ReleaseError(f"escaping nested archive link: {name!r} -> {target!r}")
            collapsed.pop()
        else:
            collapsed.append(part)
    if not collapsed:
        raise ReleaseError(f"empty nested archive link target: {name!r}")
    portable_path("/".join(collapsed), label="nested archive link target")


def _tar_number(value: bytes, *, label: str) -> int:
    if value and value[0] & 0x80:
        result = int.from_bytes(value, "big", signed=True)
    else:
        stripped = value.rstrip(b"\0 ").lstrip(b" ") or b"0"
        try:
            result = int(stripped, 8)
        except ValueError as exc:
            raise ReleaseError(f"invalid tar numeric field: {label}") from exc
    if result < 0:
        raise ReleaseError(f"negative tar numeric field: {label}")
    return result


def _physical_tar_audit(path: Path, *, limits: ArchiveLimits) -> dict[str, Any]:
    physical_bytes = path.stat().st_size
    physical_cap = limits.max_total_bytes + limits.max_members * (limits.max_path_bytes + 2048) + 20 * 512
    if physical_bytes < 1024 or physical_bytes % 512 or physical_bytes > physical_cap:
        raise ReleaseError("tar physical size/alignment exceeds safety contract")
    headers = 0
    payload_bytes = 0
    zero_started = False
    zero_blocks = 0
    with path.open("rb") as stream:
        cursor = 0
        while cursor < physical_bytes:
            block = stream.read(512)
            if len(block) != 512:
                raise ReleaseError("truncated tar physical block")
            cursor += 512
            if block == b"\0" * 512:
                zero_started = True
                zero_blocks += 1
                continue
            if zero_started:
                raise ReleaseError("tar has nonzero bytes after end-of-archive markers")
            headers += 1
            if headers > limits.max_members:
                raise ReleaseError("tar physical header count exceeds cap")
            stored_checksum = _tar_number(block[148:156], label="checksum")
            calculated_checksum = sum(block[:148]) + 8 * ord(" ") + sum(block[156:])
            if stored_checksum != calculated_checksum:
                raise ReleaseError("tar header checksum mismatch")
            magic = block[257:263]
            if magic not in {b"ustar\0", b"ustar "}:
                raise ReleaseError("tar header is not POSIX/GNU ustar")
            kind = block[156:157]
            if kind not in {b"\0", b"0", b"1", b"2", b"5", b"x", b"g", b"L", b"K"}:
                raise ReleaseError(f"tar physical special member is forbidden: {kind!r}")
            member_size = _tar_number(block[124:136], label="size")
            if member_size > limits.max_file_bytes:
                raise ReleaseError("tar physical member exceeds file cap")
            payload_bytes += member_size
            if payload_bytes > limits.max_total_bytes:
                raise ReleaseError("tar physical payload exceeds total cap")
            padded = (member_size + 511) // 512 * 512
            if cursor + padded > physical_bytes:
                raise ReleaseError("tar physical member exceeds archive")
            stream.seek(padded, 1)
            cursor += padded
    if zero_blocks < 2:
        raise ReleaseError("tar lacks two end-of-archive zero blocks")
    return {
        "physical_bytes": physical_bytes,
        "physical_headers": headers,
        "physical_payload_bytes": payload_bytes,
        "terminal_zero_blocks": zero_blocks,
        "trailing_nonzero_bytes": 0,
    }


def _decompress_strict(path: Path, destination: Path, *, kind: str, cap: int) -> None:
    compression_kind = kind.removeprefix("tar-")
    if compression_kind == "gzip":
        decoder: Any = zlib.decompressobj(16 + zlib.MAX_WBITS)
    elif compression_kind == "xz":
        decoder = lzma.LZMADecompressor(format=lzma.FORMAT_AUTO)
    elif compression_kind == "bzip2":
        decoder = bz2.BZ2Decompressor()
    else:
        raise ReleaseError(f"unsupported compressed tar kind: {kind}")
    written = 0
    with path.open("rb") as source, destination.open("xb") as output:
        while True:
            block = source.read(1024 * 1024)
            if not block:
                break
            try:
                expanded = decoder.decompress(block)
            except (zlib.error, lzma.LZMAError, OSError) as exc:
                raise ReleaseError(f"cannot decompress {kind} stream") from exc
            written += len(expanded)
            if written > cap:
                raise ReleaseError(f"{kind} expanded bytes exceed cap")
            output.write(expanded)
            if getattr(decoder, "unused_data", b""):
                raise ReleaseError(f"{kind} has concatenated/trailing compressed data")
        if not getattr(decoder, "eof", False):
            raise ReleaseError(f"{kind} compressed stream is truncated")
        if getattr(decoder, "unused_data", b""):
            raise ReleaseError(f"{kind} has trailing bytes")


def _tar_header(data: bytes) -> bool:
    if len(data) < 512 or data[257:263] not in {b"ustar\0", b"ustar "}:
        return False
    try:
        stored = _tar_number(data[148:156], label="probe checksum")
    except ReleaseError:
        return False
    calculated = sum(data[:148]) + 8 * ord(" ") + sum(data[156:512])
    return stored == calculated


def _compressed_prefix(path: Path, kind: str) -> bytes:
    if kind == "gzip":
        decoder: Any = zlib.decompressobj(16 + zlib.MAX_WBITS)
    elif kind == "xz":
        decoder = lzma.LZMADecompressor(format=lzma.FORMAT_AUTO)
    else:
        decoder = bz2.BZ2Decompressor()
    output = bytearray()
    try:
        with path.open("rb") as stream:
            while len(output) < 512:
                block = stream.read(65536)
                if not block:
                    break
                output.extend(decoder.decompress(block, max_length=512 - len(output)))
    except (OSError, zlib.error, lzma.LZMAError) as exc:
        raise ReleaseError(f"cannot probe compressed archive magic: {path.name}") from exc
    return bytes(output)


def detected_archive_kind(path: Path) -> str | None:
    with path.open("rb") as stream:
        prefix = stream.read(512)
    if prefix.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
        return "zip"
    if prefix.startswith(b"7z\xbc\xaf'\x1c"):
        return "unsupported-7z"
    if prefix.startswith((b"Rar!\x1a\x07\x00", b"Rar!\x1a\x07\x01\x00")):
        return "unsupported-rar"
    if prefix.startswith(b"\x1f\x8b"):
        base = "gzip"
        return "tar-gzip" if _tar_header(_compressed_prefix(path, base)) else base
    if prefix.startswith(b"\xfd7zXZ\x00"):
        base = "xz"
        return "tar-xz" if _tar_header(_compressed_prefix(path, base)) else base
    if prefix.startswith(b"BZh"):
        base = "bzip2"
        return "tar-bzip2" if _tar_header(_compressed_prefix(path, base)) else base
    return "tar-raw" if _tar_header(prefix) else None


def inspect_tar(path: Path, *, limits: ArchiveLimits) -> dict[str, Any]:
    before = file_record(path)
    detected = detected_archive_kind(path)
    if detected is None:
        raise ReleaseError("input has no supported tar/archive magic")
    if detected == "zip":
        raise ReleaseError("ZIP input was mislabeled as tar")
    temporary: tempfile.TemporaryDirectory[str] | None = None
    tar_path = path
    if detected != "tar-raw":
        temporary = tempfile.TemporaryDirectory(prefix="kazstem-nested-tar-")
        tar_path = Path(temporary.name) / "expanded.tar"
        _decompress_strict(
            path,
            tar_path,
            kind=detected,
            cap=limits.max_total_bytes + limits.max_members * (limits.max_path_bytes + 2048) + 20 * 512,
        )
    physical = _physical_tar_audit(tar_path, limits=limits)
    names: set[str] = set()
    folded: set[str] = set()
    total = 0
    regular = 0
    symlinks = 0
    hardlinks = 0
    try:
        with tarfile.open(tar_path, "r:") as archive:
            members = archive.getmembers()
            effective_names = [portable_path(member.name.rstrip("/"), label="nested tar member") for member in members]
            link_paths = {
                name
                for name, member in zip(effective_names, members)
                if member.issym() or member.islnk()
            }
            for name in effective_names:
                ancestors = PurePosixPath(name).parents
                if any(parent.as_posix() in link_paths for parent in ancestors if parent.as_posix() != "."):
                    raise ReleaseError(f"tar member descends through a link entry: {name}")
            prior_regular: set[str] = set()
            for index, (member, name) in enumerate(zip(members, effective_names)):
                if index >= limits.max_members:
                    raise ReleaseError(f"nested tar member cap exceeded: {path.name}")
                key = unicodedata.normalize("NFC", name).casefold()
                if name in names or key in folded:
                    raise ReleaseError(f"duplicate/colliding nested tar member: {name!r}")
                names.add(name)
                folded.add(key)
                if member.isreg():
                    if member.size < 0 or member.size > limits.max_file_bytes:
                        raise ReleaseError(f"nested tar file cap exceeded: {name}")
                    total += member.size
                    if total > limits.max_total_bytes:
                        raise ReleaseError(f"nested tar total cap exceeded: {path.name}")
                    stream = archive.extractfile(member)
                    if stream is None:
                        raise ReleaseError(f"cannot read nested tar member: {name}")
                    with stream:
                        observed, _ = sha256_stream(stream, limit=member.size)
                    if observed != member.size:
                        raise ReleaseError(f"nested tar member size changed: {name}")
                    regular += 1
                    prior_regular.add(name)
                elif member.isdir():
                    pass
                elif member.issym():
                    safe_link(name, member.linkname, hardlink=False)
                    symlinks += 1
                elif member.islnk():
                    safe_link(name, member.linkname, hardlink=True)
                    if member.linkname not in prior_regular:
                        raise ReleaseError(f"tar hardlink target is absent/not prior: {name}")
                    hardlinks += 1
                else:
                    raise ReleaseError(f"special nested tar member is forbidden: {name}")
    except (OSError, tarfile.TarError) as exc:
        if isinstance(exc, ReleaseError):
            raise
        raise ReleaseError(f"cannot inspect nested tar {path.name}: {exc}") from exc
    if not names:
        raise ReleaseError(f"nested tar is empty: {path.name}")
    if file_record(path) != before:
        raise ReleaseError("nested tar changed during physical/logical audit")
    if temporary is not None:
        temporary.cleanup()
    return {
        "kind": detected,
        "members": len(names),
        "regular_files": regular,
        "expanded_bytes": total,
        "contained_symlinks": symlinks,
        "contained_hardlinks": hardlinks,
        "special_entries": 0,
        **physical,
    }


def inspect_single_stream(path: Path, *, kind: str, limits: ArchiveLimits) -> dict[str, Any]:
    before = file_record(path)
    with tempfile.TemporaryDirectory(prefix="kazstem-nested-stream-") as temporary:
        expanded = Path(temporary) / "expanded"
        _decompress_strict(path, expanded, kind=kind, cap=limits.max_file_bytes)
        size = expanded.stat().st_size
        digest = file_record(expanded)["sha256"]
    if not size:
        raise ReleaseError(f"nested {kind} stream is empty: {path.name}")
    if file_record(path) != before:
        raise ReleaseError(f"nested {kind} stream changed during audit")
    return {"kind": kind, "members": 1, "expanded_bytes": size, "expanded_sha256": digest}


def inspect_nested(path: Path, kind: str, *, limits: ArchiveLimits) -> dict[str, Any]:
    detected = detected_archive_kind(path)
    if detected in {"unsupported-7z", "unsupported-rar"}:
        raise ReleaseError(f"recognized unsupported nested archive format: {detected}")
    if detected != kind:
        raise ReleaseError(
            f"nested archive magic differs from identity: {path.name}: expected {kind}, observed {detected}"
        )
    if kind.startswith("tar-"):
        return inspect_tar(path, limits=limits)
    if kind == "zip":
        members = inspect_zip(path, limits=limits)
        return {
            "kind": "zip",
            "members": len(members),
            "expanded_bytes": sum(member.size for member in members),
            "symlinks": 0,
            "hardlinks": 0,
            "special_entries": 0,
        }
    if kind in {"gzip", "xz", "bzip2"}:
        return inspect_single_stream(path, kind=kind, limits=limits)
    raise ReleaseError(f"unsupported nested source archive kind: {kind}")


def artifact_key(value: dict[str, Any]) -> tuple[str, int, str, str]:
    return (value["filename"], value["bytes"], value["sha256"], value["url"])


def magic_archive_inventory(root: Path) -> dict[str, str]:
    detected_nested: dict[str, str] = {}
    unsupported: list[dict[str, str]] = []
    for item in tree_inventory(root):
        if item["kind"] != "file":
            continue
        path = root / item["path"]
        kind = detected_archive_kind(path)
        if kind in {"unsupported-7z", "unsupported-rar"}:
            unsupported.append({"path": item["path"], "kind": kind})
        elif kind is not None:
            detected_nested[item["path"]] = kind
    if unsupported:
        raise ReleaseError(
            f"recognized unsupported nested source archives: {unsupported}"
        )
    return detected_nested


def audit(args: argparse.Namespace) -> dict[str, Any]:
    identity = load_identity(args.identity.resolve(strict=True))
    archive = args.archive.resolve(strict=True)
    artifact = identity["artifacts"]["corresponding_source"]
    verify_artifact(archive, artifact, label="corresponding source")
    zip_contract = ZipOutputContract(identity["source_date_epoch"])
    outer = inspect_zip(
        archive,
        limits=archive_limits(identity, "corresponding_source"),
        contract=zip_contract,
    )
    if {PurePosixPath(member.name).parts[0] for member in outer} != {identity["corresponding_source"]["top_level"]}:
        raise ReleaseError("corresponding-source ZIP has the wrong top-level root")
    for member in outer:
        expected_mode = 0o555 if member.kind == "directory" else 0o444
        if member.mode != expected_mode:
            raise ReleaseError(
                f"source ZIP mode is not normalized: {member.name}:{member.mode:04o}"
            )

    with tempfile.TemporaryDirectory(prefix="kazstem-windows-source-audit-") as temporary:
        root = safe_extract_zip(
            archive,
            Path(temporary) / "fresh",
            limits=archive_limits(identity, "corresponding_source"),
            contract=zip_contract,
        )
        extracted_before = tree_record(root)
        source_contract = identity["corresponding_source"]
        categories = source_contract["categories"]
        verify_required_paths(root, source_contract["required_paths"])
        for name, relative in categories.items():
            path = root / relative
            if not path.is_dir() or path.is_symlink():
                raise ReleaseError(f"source category is missing: {name}={relative}")
        manifest = read_json(root / "SOURCE-MANIFEST.json")
        if not isinstance(manifest, dict) or manifest.get("schema") != "kazstem-windows-corresponding-source-manifest-v1" or manifest.get("source_commit") != identity["source_commit"]:
            raise ReleaseError("source manifest identity is invalid")
        verify_manifest(root, manifest, excluded={"SOURCE-MANIFEST.json", "SOURCE-FILES.sha256"})
        verify_checksums(root, root / "SOURCE-FILES.sha256")
        if (root / source_contract["source_commit_file"]).read_bytes() != (identity["source_commit"] + "\n").encode("ascii"):
            raise ReleaseError("source commit marker differs from identity")
        if (root / source_contract["source_date_epoch_file"]).read_bytes() != (str(identity["source_date_epoch"]) + "\n").encode("ascii"):
            raise ReleaseError("source epoch marker differs from identity")

        application = root / categories["application"] / "KazStem"
        verify_tree(application, identity["inputs"]["source_payload_tree"], label="extracted application source")
        for relative in ("LICENSE", "THIRD_PARTY.md", "pyproject.toml"):
            if not (application / relative).is_file():
                raise ReleaseError(f"application source license/build metadata is missing: {relative}")
        license_files = [
            path
            for path in (root / categories["licenses"]).rglob("*")
            if path.is_file() and not path.is_symlink()
        ]
        if not license_files:
            raise ReleaseError("corresponding-source license category is empty")
        for relative in ("LICENSE", "NOTICE", "THIRD_PARTY.md"):
            copied_license = root / categories["licenses"] / "KazStem" / relative
            if copied_license.read_bytes() != (application / relative).read_bytes():
                raise ReleaseError(f"copied application license differs: {relative}")
        closure = read_json(root / "SOURCE-CLOSURE.json")
        canonical = root / categories["build"] / "canonical-python-artifacts"
        embedded_python_identity = (
            root / categories["build"] / "canonical-python-build-identity.json"
        )
        embedded_python_receipt = (
            root / categories["build"] / "canonical-python-build-receipt.json"
        )
        canonical_contract = verify_canonical_python_release(
            identity,
            source_root=application,
            python_build_identity=embedded_python_identity,
            python_build_receipt=embedded_python_receipt,
            wheel=canonical / identity["artifacts"]["wheel"]["filename"],
            sdist=canonical / identity["artifacts"]["sdist"]["filename"],
        )
        expected_components = [
            {
                "name": value["name"],
                "version": value["version"],
                "license": value["license"],
                "category": value["category"],
                "path": value["destination"],
                "artifact": value["artifact"],
            }
            for value in source_contract["components"]
        ]
        expected_closure = {
            "schema": "kazstem-windows-source-closure-v1",
            "release": identity["release"],
            "source_commit": identity["source_commit"],
            "source_ref": identity["source_ref"],
            "paired_ready_run": source_ready_location(identity),
            "canonical_python_artifacts": {
                "wheel": identity["artifacts"]["wheel"],
                "sdist": identity["artifacts"]["sdist"],
            },
            "canonical_python_build_identity": {
                "path": f"{categories['build']}/canonical-python-build-identity.json",
                "file": identity["inputs"]["canonical_python_build_identity"],
            },
            "canonical_python_build_receipt": {
                "path": f"{categories['build']}/canonical-python-build-receipt.json",
                "file": identity["inputs"]["canonical_python_build_receipt"],
                "schema": "kazstem-canonical-python-build-receipt-v2",
                "execution_platform": canonical_contract["receipt"]["execution_platform"],
                "linux_roundtrip_wheel_and_sdist_identical": canonical_contract[
                    "receipt"
                ]["roundtrip"]["wheel_and_sdist_identical"],
            },
            "components": expected_components,
            "offline_freezer_wheelhouse": {
                "path": source_contract["wheelhouse_destination"],
                "tree": identity["inputs"]["build_wheelhouse_tree"],
            },
            "native_runtime_bundle": identity["inputs"]["runtime_tree"],
            "source_materialization": {
                "source": {
                    "commit": identity["source_commit"],
                    "tree": identity["source_tree"],
                    "origin": identity["source_origin"],
                    "ref": identity["source_ref"],
                },
                "payload_tree": identity["inputs"]["source_payload_tree"],
                "receipt": identity["inputs"]["source_receipt"],
            },
        }
        if closure != expected_closure:
            raise ReleaseError("SOURCE-CLOSURE.json is incomplete or differs from identity")
        embedded_receipt = root / categories["evidence"] / "GIT-SOURCE-MATERIALIZATION.json"
        verify_file(embedded_receipt, identity["inputs"]["source_receipt"], label="embedded source receipt")
        verify_source_receipt(read_json(embedded_receipt), identity)
        for value in source_contract["components"]:
            verify_artifact(root / value["destination"], value["artifact"], label=f"extracted source {value['name']}")
        verify_tree(
            root / source_contract["wheelhouse_destination"],
            identity["inputs"]["build_wheelhouse_tree"],
            label="extracted offline freezer wheelhouse",
        )

        verify_file(
            embedded_python_identity,
            identity["inputs"]["canonical_python_build_identity"],
            label="source canonical Python build identity",
        )
        verify_file(
            embedded_python_receipt,
            identity["inputs"]["canonical_python_build_receipt"],
            label="source canonical Python build receipt",
        )
        for name in ("wheel", "sdist"):
            verify_artifact(canonical / identity["artifacts"][name]["filename"], identity["artifacts"][name], label=f"source {name}")

        windows_lock = read_json(application / "scripts/platform_runtime_sources.windows-x86_64.lock.json")
        if not isinstance(windows_lock, dict) or windows_lock.get("schema") != "kazstem-platform-runtime-source-lock-v1":
            raise ReleaseError("application source lacks the exact Windows runtime source lock")
        locked_artifacts = {
            (value["filename"], value["bytes"], value["sha256"], value["url"])
            for field in ("archives", "corresponding_sources")
            for value in windows_lock[field]
        }
        closure_artifacts = {artifact_key(value["artifact"]) for value in source_contract["components"]}
        missing_locked = sorted(locked_artifacts - closure_artifacts)
        if missing_locked:
            raise ReleaseError(f"Windows native binary/source closure is incomplete: {missing_locked}")
        component_names = {value["name"].casefold() for value in source_contract["components"]}
        normalized_names = {
            name.replace("_", "-").replace(" ", "-") for name in component_names
        }
        required_build_sources = {
            "altgraph",
            "build",
            "cpython",
            "packaging",
            "pefile",
            "pyinstaller",
            "pyinstaller-hooks-contrib",
            "pyproject-hooks",
            "pywin32-ctypes",
            "setuptools",
            "wheel",
        }
        missing_build_sources = sorted(required_build_sources - normalized_names)
        if missing_build_sources:
            raise ReleaseError(
                f"hash-locked Python/freezer source closure is incomplete: {missing_build_sources}"
            )
        required_resource_sources = {
            "kazstem-resource-build-inputs",
            "kazstem-resource-build-evidence",
        }
        missing_resource_sources = sorted(required_resource_sources - normalized_names)
        if missing_resource_sources:
            raise ReleaseError(
                f"resource corresponding-source closure is incomplete: {missing_resource_sources}"
            )
        if any(name == "openssl" or name.startswith("openssl ") for name in component_names):
            raise ReleaseError("OpenSSL source is not part of the Windows source closure")
        if not isinstance(windows_lock.get("components"), list) or not windows_lock["components"]:
            raise ReleaseError("Windows lock lacks its complete component/license inventory")
        closure_licenses = {
            (value["name"], value["version"], value["license"])
            for value in source_contract["components"]
        }
        locked_licenses = {
            (value["name"], value["version"], value["license"])
            for value in windows_lock["components"]
        }
        if locked_licenses - closure_licenses:
            raise ReleaseError(
                "native component/license inventory is incomplete: "
                + repr(sorted(locked_licenses - closure_licenses))
            )

        nested_results: list[dict[str, Any]] = []
        declared_nested = {
            value["path"]: value["kind"]
            for value in source_contract["nested_archives"]
        }
        detected_nested = magic_archive_inventory(root)
        if detected_nested != declared_nested:
            raise ReleaseError(
                "magic-driven nested source archive inventory differs "
                f"(missing={sorted(set(detected_nested) - set(declared_nested))}, "
                f"extra={sorted(set(declared_nested) - set(detected_nested))}, "
                f"kind_mismatches={sorted(path for path in set(detected_nested) & set(declared_nested) if detected_nested[path] != declared_nested[path])})"
            )
        for value in source_contract["nested_archives"]:
            nested = root / value["path"]
            nested_results.append(
                {
                    "path": value["path"],
                    **inspect_nested(nested, value["kind"], limits=archive_limits(identity, "nested")),
                }
            )
        evidence = root / categories["evidence"]
        assert_relative_evidence(evidence)
        result = {
            "schema": SOURCE_AUDIT_SCHEMA,
            "result": "pass",
            "release_identity_sha256": args.release_identity_sha256,
            "archive": artifact_record(archive, artifact["url"]),
            "top_level": root.name,
            "outer_members": len(outer),
            "application_tree": tree_record(application),
            "components": len(expected_components),
            "windows_locked_inputs": len(locked_artifacts),
            "nested_archives": nested_results,
            "cpython_source_present": True,
            "pyinstaller_source_present": True,
            "openssl_source_component_present": False,
            "outer_symlinks": 0,
            "outer_hardlinks": 0,
            "outer_special_entries": 0,
            "extracted_tree_before": extracted_before,
            "extracted_tree_after": tree_record(root),
        }
        if result["extracted_tree_before"] != result["extracted_tree_after"]:
            raise ReleaseError("corresponding-source extracted content changed during audit")
    return result


def main() -> int:
    require_release_bootstrap("packaging/windows/audit_corresponding_source_archive.py")
    parser = argparse.ArgumentParser()
    parser.add_argument("--identity", required=True, type=Path)
    parser.add_argument("--release-identity-sha256", required=True)
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--json", required=True, type=Path)
    args = parser.parse_args()
    if len(args.release_identity_sha256) != 64:
        parser.error("--release-identity-sha256 must be a SHA-256")
    identity = load_identity(args.identity.resolve(strict=True))
    expected_identity_hash = identity_sha256(args.identity.resolve(strict=True))
    if args.release_identity_sha256 != expected_identity_hash:
        raise ReleaseError("passed release identity hash differs from stable identity projection")
    logical_argv = [
        "<PYTHON>",
        "packaging/windows/audit_corresponding_source_archive.py",
        "--identity",
        "<RELEASE-IDENTITY>",
        "--release-identity-sha256",
        "<IDENTITY-SHA256>",
        "--archive",
        "<CORRESPONDING-SOURCE>",
        "--json",
        "<EVIDENCE-OUTPUT>",
    ]
    record = verify_generator_runtime(
        identity,
        gate="source-archive-audit",
        logical_argv=logical_argv,
    )
    result = audit(args)
    if args.json.exists() or args.json.is_symlink():
        raise ReleaseError(f"source audit output exists: {args.json}")
    args.json.parent.mkdir(parents=True, exist_ok=True)
    observations = {
        key: value
        for key, value in result.items()
        if key not in {"schema", "result", "release_identity_sha256"}
    }
    args.json.write_bytes(
        json_bytes(
            evidence_envelope(
                identity,
                identity_hash=expected_identity_hash,
                record=record,
                observations=observations,
            )
        )
    )
    print(f"PASS: {result['outer_members']} source ZIP members; {result['components']} closure components")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ReleaseError, OSError, ValueError, json.JSONDecodeError) as exc:
        raise SystemExit(f"error: {exc}") from exc
