#!/usr/bin/env python3
"""Statically audit a final Windows ready-run ZIP before execution."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import tempfile
from typing import Any
import zipfile

from release_common import (
    READY_AUDIT_SCHEMA,
    ReleaseError,
    ZipOutputContract,
    archive_limits,
    artifact_record,
    evidence_envelope,
    identity_sha256,
    file_record,
    files_equal,
    inspect_zip,
    json_bytes,
    load_identity,
    require_release_bootstrap,
    pe_identity,
    read_json,
    safe_extract_zip,
    tree_record,
    verify_generator_runtime,
    verify_artifact,
    verify_checksums,
    verify_file,
    verify_manifest,
    verify_required_paths,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))

from write_platform_runtime_manifest import ManifestError, _pe_imports  # noqa: E402


FORBIDDEN_SUFFIXES = {".pt", ".pth", ".ckpt", ".safetensors", ".onnx"}
FORBIDDEN_NAMES = {
    "pytorch_model.bin",
    "libssl.dll",
    "libcrypto.dll",
    "_ssl.pyd",
    "_hashlib.pyd",
}
FORBIDDEN_FRAGMENTS = ("openssl", "libssl", "libcrypto", "neural", "torch", "stanza")


def verify_runtime_manifest(runtime: Path, expected: dict[str, Any]) -> dict[str, Any]:
    manifest_path = runtime / "manifest.json"
    verify_file(manifest_path, expected["manifest"], label="runtime manifest")
    manifest = read_json(manifest_path)
    if not isinstance(manifest, dict) or manifest.get("bundle_id") != expected["bundle_id"]:
        raise ReleaseError("runtime bundle identity differs from release identity")
    files = manifest.get("files")
    closure = manifest.get("dependency_closure")
    if not isinstance(files, dict) or not isinstance(closure, dict):
        raise ReleaseError("runtime manifest lacks file inventory/dependency closure")
    observed_paths = {
        path.relative_to(runtime).as_posix()
        for path in runtime.rglob("*")
        if path.is_file() and path != manifest_path
    }
    if observed_paths != set(files):
        raise ReleaseError("runtime manifest file inventory is incomplete")
    for relative, record in files.items():
        if not isinstance(record, dict) or record.get("kind") != "file":
            raise ReleaseError(f"Windows runtime entry is not a regular file: {relative}")
        actual = file_record(runtime / relative)
        if actual != {"bytes": record.get("bytes"), "sha256": record.get("sha256")}:
            raise ReleaseError(f"runtime file differs from manifest: {relative}")
    closure_files = closure.get("files")
    if closure.get("schema") != "kazstem-pe-import-closure-v1" or closure.get("machine") != "x86_64" or not isinstance(closure_files, dict):
        raise ReleaseError("runtime PE closure schema/machine is invalid")
    if set(closure_files) != set(files):
        raise ReleaseError("runtime PE closure is not complete")
    names = {Path(relative).name.casefold(): relative for relative in files}
    if len(names) != len(files):
        raise ReleaseError("runtime has ambiguous PE basenames")
    reached_system: set[str] = set()
    for relative in sorted(files):
        try:
            machine, imports = _pe_imports(runtime / relative)
        except ManifestError as exc:
            raise ReleaseError(f"cannot parse runtime PE {relative}: {exc}") from exc
        if machine != 0x8664:
            raise ReleaseError(f"runtime PE is not AMD64: {relative}")
        bundled = sorted(names[name] for name in imports if name in names)
        system = sorted(name for name in imports if name not in names)
        reached_system.update(system)
        expected_record = {
            "imports": list(imports),
            "bundled_dependencies": bundled,
            "system_dependencies": system,
        }
        if closure_files[relative] != expected_record:
            raise ReleaseError(f"runtime PE closure changed: {relative}")
    if sorted(reached_system) != closure.get("system_libraries"):
        raise ReleaseError("runtime system-library boundary changed")
    if sorted(reached_system) != ["advapi32.dll", "kernel32.dll", "msvcrt.dll", "user32.dll"]:
        raise ReleaseError("runtime system-library boundary is not the audited set")
    return manifest


def audit(args: argparse.Namespace) -> dict[str, Any]:
    identity = load_identity(args.identity.resolve(strict=True))
    archive = args.archive.resolve(strict=True)
    artifact = identity["artifacts"]["ready_run"]
    verify_artifact(archive, artifact, label="ready-run")
    zip_contract = ZipOutputContract(
        identity["source_date_epoch"], (".exe", ".dll", ".pyd")
    )
    members = inspect_zip(
        archive,
        limits=archive_limits(identity, "ready_run"),
        contract=zip_contract,
    )
    if {Path(member.name).parts[0] for member in members} != {identity["ready_run"]["top_level"]}:
        raise ReleaseError("ready-run ZIP has the wrong top-level root")
    for member in members:
        expected_mode = (
            0o555
            if member.kind == "directory"
            or member.name.casefold().endswith((".exe", ".dll", ".pyd"))
            else 0o444
        )
        if member.mode != expected_mode:
            raise ReleaseError(
                f"ready-run ZIP mode is not normalized: {member.name}:{member.mode:04o}"
            )
    expected_stamp = __import__("time").gmtime(identity["source_date_epoch"])
    expected_time = (expected_stamp.tm_year, expected_stamp.tm_mon, expected_stamp.tm_mday, expected_stamp.tm_hour, expected_stamp.tm_min, expected_stamp.tm_sec - expected_stamp.tm_sec % 2)
    with zipfile.ZipFile(archive) as value:
        for info in value.infolist():
            if info.date_time != expected_time:
                raise ReleaseError(f"non-normalized ZIP timestamp: {info.filename}")
            if not info.is_dir() and info.compress_type != zipfile.ZIP_DEFLATED:
                raise ReleaseError(f"ready-run file is not deflate-compressed: {info.filename}")

    with tempfile.TemporaryDirectory(prefix="kazstem-windows-ready-audit-") as temporary:
        extraction = Path(temporary) / "fresh"
        root = safe_extract_zip(
            archive,
            extraction,
            limits=archive_limits(identity, "ready_run"),
            contract=zip_contract,
        )
        extracted_before = tree_record(root)
        verify_required_paths(root, identity["ready_run"]["required_paths"])
        manifest_path = root / "verification/BUNDLE-MANIFEST.json"
        manifest = read_json(manifest_path)
        if not isinstance(manifest, dict) or manifest.get("schema") != "kazstem-windows-ready-run-manifest-v1" or manifest.get("release") != identity["release"] or manifest.get("source_commit") != identity["source_commit"]:
            raise ReleaseError("ready-run manifest identity is invalid")
        verify_manifest(root, manifest, excluded={"verification/BUNDLE-MANIFEST.json", "verification/BUNDLED-FILES.sha256"})
        verify_checksums(root, root / "verification/BUNDLED-FILES.sha256")

        build_identity = read_json(root / "verification/BUILD-IDENTITY.json")
        if (
            not isinstance(build_identity, dict)
            or build_identity.get("schema") != "kazstem-windows-build-identity-v2"
            or build_identity.get("source_commit") != identity["source_commit"]
            or build_identity.get("canonical_python_artifacts")
            != {"wheel": identity["artifacts"]["wheel"], "sdist": identity["artifacts"]["sdist"]}
            or build_identity.get("canonical_python_builder")
            != identity["inputs"]["canonical_python_builder"]
            or build_identity.get("canonical_python_build_identity")
            != identity["inputs"]["canonical_python_build_identity"]
            or build_identity.get("canonical_python_build_receipt")
            != identity["inputs"]["canonical_python_build_receipt"]
        ):
            raise ReleaseError("embedded build identity differs from release identity")
        binding = read_json(root / "CORRESPONDING-SOURCE.json")
        if not isinstance(binding, dict) or binding.get("artifact") != identity["artifacts"]["corresponding_source"]:
            raise ReleaseError("ready-run corresponding-source binding differs")

        launcher = root / identity["ready_run"]["launcher"]["path"]
        verify_file(launcher, identity["ready_run"]["launcher"]["file"], label="kazstem.exe")
        for alias in identity["ready_run"]["aliases"]:
            if not files_equal(root / alias, launcher):
                raise ReleaseError(f"Windows alias differs from kazstem.exe: {alias}")
        platform_lock = root / identity["ready_run"]["platform_lock_path"]
        verify_file(platform_lock, identity["inputs"]["platform_lock"], label="frozen unified platform lock")
        platform_lock_value = read_json(platform_lock)
        windows_entries = [
            value for value in platform_lock_value.get("runtimes", [])
            if value.get("platform") == {"system": "windows", "machine": "x86_64"}
        ] if isinstance(platform_lock_value, dict) else []
        if windows_entries != [
            {
                "platform": {"system": "windows", "machine": "x86_64"},
                "resource_bundle_ids": [identity["inputs"]["resource_tree"]["bundle_id"]],
                "bundle_id": identity["inputs"]["runtime_tree"]["bundle_id"],
                "manifest": identity["inputs"]["runtime_tree"]["manifest"],
            }
        ]:
            raise ReleaseError("embedded platform lock does not bind resource/runtime")

        resource = root / identity["ready_run"]["resource_destination"]
        resource_manifest = resource / "manifest.json"
        verify_file(resource_manifest, identity["inputs"]["resource_tree"]["manifest"], label="resource manifest")
        if read_json(resource_manifest).get("bundle_id") != identity["inputs"]["resource_tree"]["bundle_id"]:
            raise ReleaseError("resource bundle identity changed")
        runtime = root / identity["ready_run"]["runtime_parent"] / identity["inputs"]["runtime_tree"]["bundle_id"]
        runtime_manifest = verify_runtime_manifest(runtime, identity["inputs"]["runtime_tree"])

        pe_records: list[dict[str, Any]] = []
        forbidden: list[str] = []
        source_archives: list[str] = []
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            relative = path.relative_to(root).as_posix()
            lowered = path.name.casefold()
            if lowered in FORBIDDEN_NAMES or path.suffix.casefold() in FORBIDDEN_SUFFIXES or any(fragment in lowered for fragment in FORBIDDEN_FRAGMENTS):
                forbidden.append(relative)
            if lowered.endswith((".tar", ".tar.gz", ".tar.xz", ".tar.bz2", ".tgz", ".tbz2")):
                source_archives.append(relative)
            if path.suffix.casefold() in {".exe", ".dll", ".pyd"}:
                record = pe_identity(path)
                record["path"] = relative
                pe_records.append(record)
        if forbidden:
            raise ReleaseError(f"OpenSSL/neural/network-forbidden files are present: {forbidden}")
        if source_archives:
            raise ReleaseError(f"source archives leaked into ready-run: {source_archives}")
        unsigned = read_json(root / "verification/UNSIGNED-AUTHENTICODE.json")
        expected_unsigned = sorted(pe_records, key=lambda item: item["path"])
        if not isinstance(unsigned, dict) or unsigned.get("unsigned") is not True or unsigned.get("smartscreen_warning_possible") is not True or unsigned.get("files") != expected_unsigned or any(item["authenticode_embedded"] for item in expected_unsigned):
            raise ReleaseError("unsigned/AuthentiCode inventory is incomplete")
        readme = (root / "README-WINDOWS.md").read_text(encoding="utf-8", errors="strict")
        if "unsigned" not in readme.casefold() or "SmartScreen" not in readme:
            raise ReleaseError("binary README omits unsigned/SmartScreen disclosure")

        result = {
            "schema": READY_AUDIT_SCHEMA,
            "result": "pass",
            "release_identity_sha256": args.release_identity_sha256,
            "archive": artifact_record(archive, artifact["url"]),
            "top_level": root.name,
            "members": len(members),
            "pe_files": len(pe_records),
            "runtime_files": len(runtime_manifest["files"]),
            "runtime_system_libraries": runtime_manifest["dependency_closure"]["system_libraries"],
            "authenticode": "all PE files have no embedded signature",
            "smartscreen_warning_possible": True,
            "forbidden_runtime_files": [],
            "embedded_source_archives": [],
            "extracted_tree_before": extracted_before,
            "extracted_tree_after": tree_record(root),
        }
        if result["extracted_tree_before"] != result["extracted_tree_after"]:
            raise ReleaseError("ready-run extracted content changed during audit")
    return result


def main() -> int:
    require_release_bootstrap("packaging/windows/audit_ready_run_archive.py")
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
        "packaging/windows/audit_ready_run_archive.py",
        "--identity",
        "<RELEASE-IDENTITY>",
        "--release-identity-sha256",
        "<IDENTITY-SHA256>",
        "--archive",
        "<READY-RUN>",
        "--json",
        "<EVIDENCE-OUTPUT>",
    ]
    record = verify_generator_runtime(
        identity,
        gate="binary-archive-audit",
        logical_argv=logical_argv,
    )
    result = audit(args)
    if args.json.exists() or args.json.is_symlink():
        raise ReleaseError(f"audit output already exists: {args.json}")
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
    print(f"PASS: {result['members']} ready-run ZIP members")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ReleaseError, OSError, ValueError, json.JSONDecodeError) as exc:
        raise SystemExit(f"error: {exc}") from exc
