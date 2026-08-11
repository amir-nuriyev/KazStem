#!/usr/bin/env python3
"""Derive the strict macOS release identity from exact checked inputs."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
from typing import Any

from release_common import (
    IDENTITY_SCHEMA,
    REQUIRED_EVIDENCE_GATES,
    ReleaseError,
    artifact_record,
    assert_relative_json,
    detect_archive_format,
    file_record,
    inspect_tar,
    inspect_zip,
    json_bytes,
    load_identity,
    portable_path,
    read_json,
    tree_record,
    tool_output_identity,
    verify_declared_archive_inventory,
    verify_file,
)
from canonical_python_authority import bind_authority


CONFIG_SCHEMA = "kazstem-macos-release-config-v1"
BUILD_STACK_SCHEMA = "kazstem-macos-build-stack-v1"
STAGING_SCHEMA = "kazstem-macos-release-staging-v1"
GATE_SCRIPTS = {
    "blackbox": "packaging/macos/blackbox_macos_bundle.py",
    "compatibility-performance": "packaging/macos/derive_compatibility_performance.py",
    "compression-comparison": "packaging/macos/compare_compression.py",
    "macho-closure": "packaging/macos/audit_macho_closure.py",
    "module-native-inclusion": "packaging/macos/audit_module_native_inclusion.py",
    "network-trace": "packaging/macos/verify_offline_processes.py",
    "optimization-ledger": "packaging/macos/write_optimization_ledger.py",
    "practical": "packaging/macos/practical_matrix_macos.py",
    "python-reproducibility": "packaging/macos/verify_python_reproducibility.py",
    "ready-archive-audit": "packaging/macos/audit_ready_run_archive.py",
    "runtime-provenance": "packaging/macos/normalize_runtime_provenance.py",
    "source-archive-audit": "packaging/macos/audit_corresponding_source_archive.py",
    "source-suite": "packaging/macos/run_source_suite.py",
}
GATE_SUBJECTS = {
    "blackbox": ["ready_run"],
    "compatibility-performance": ["ready_run", "wheel"],
    "compression-comparison": ["corresponding_source", "ready_run"],
    "macho-closure": ["ready_run"],
    "module-native-inclusion": ["ready_run"],
    "network-trace": ["ready_run"],
    "optimization-ledger": ["corresponding_source", "ready_run"],
    "practical": ["ready_run", "wheel"],
    "python-reproducibility": [
        "corresponding_source",
        "ready_run",
        "sdist",
        "wheel",
    ],
    "ready-archive-audit": ["ready_run"],
    "runtime-provenance": ["ready_run", "wheel"],
    "source-archive-audit": ["corresponding_source"],
    "source-suite": ["sdist", "wheel"],
}
GATE_TIMEOUTS = {
    "blackbox": 900,
    "compatibility-performance": 120,
    "compression-comparison": 14_400,
    "macho-closure": 1800,
    "module-native-inclusion": 900,
    "network-trace": 900,
    "optimization-ledger": 120,
    "practical": 7200,
    "python-reproducibility": 21_600,
    "ready-archive-audit": 1800,
    "runtime-provenance": 900,
    "source-archive-audit": 7200,
    "source-suite": 7200,
}
GATE_ARGUMENTS = {
    "blackbox": ["--identity", "release-identity.json", "--root", "fresh/ready"],
    "compatibility-performance": [
        "--identity",
        "release-identity.json",
        "--practical",
        "evidence/gates/practical.json",
    ],
    "compression-comparison": [
        "--identity",
        "release-identity.json",
        "--ready-tar",
        "canonical/ready.tar",
        "--source-tar",
        "canonical/source.tar",
        "--ready-run",
        "artifacts/ready-run",
        "--corresponding-source",
        "artifacts/corresponding-source",
        "--workspace",
        "work/compression",
        "--reproducibility",
        "evidence/gates/python-reproducibility.json",
    ],
    "macho-closure": [
        "--identity",
        "release-identity.json",
        "--bundle",
        "fresh/ready",
        "--runtime-archives",
        "inputs/runtime-archives",
        "--runtime-sources",
        "inputs/runtime-sources",
        "--runtime-source-lock",
        "source-tree/scripts/platform_runtime_sources.lock.json",
        "--python",
        "python3.14",
    ],
    "module-native-inclusion": [
        "--identity",
        "release-identity.json",
        "--bundle",
        "fresh/ready",
    ],
    "network-trace": [
        "--identity",
        "release-identity.json",
        "--bundle",
        "fresh/ready",
        "--profile",
        "source-tree/packaging/macos/network-deny.sb",
        "--python",
        "python3.14",
        "--workspace",
        "work/network",
    ],
    "optimization-ledger": [
        "--identity",
        "release-identity.json",
        "--practical",
        "evidence/gates/practical.json",
        "--compression",
        "evidence/gates/compression-comparison.json",
        "--macho",
        "evidence/gates/macho-closure.json",
        "--modules",
        "evidence/gates/module-native-inclusion.json",
    ],
    "practical": [
        "--identity",
        "release-identity.json",
        "--root",
        "fresh/ready",
        "--wheel",
        "artifacts/wheel",
        "--bootstrap-python",
        "python3.14",
    ],
    "python-reproducibility": [
        "--identity",
        "release-identity.json",
        "--repository",
        "source-tree",
        "--canonical-artifacts",
        "artifacts",
        "--python-build-identity",
        "inputs/PYTHON-BUILD-IDENTITY.json",
        "--linux-release-identity",
        "inputs/LINUX-RELEASE-IDENTITY.json",
        "--linux-reproducibility",
        "inputs/linux-python-reproducibility.json",
        "--python-interpreter-source",
        "inputs/interpreter-source-file",
        "--payload",
        "inputs/source-payload",
        "--resources",
        "inputs/resources",
        "--runtime",
        "inputs/runtime",
        "--documents",
        "inputs/documents",
        "--binary-readme-template",
        "source-tree/packaging/macos/BINARY-README.template.md",
        "--source-readme-template",
        "source-tree/packaging/macos/CORRESPONDING-SOURCE-README.template.md",
        "--base-ledger",
        "inputs/base-ledger.json",
        "--freezer-wheelhouse",
        "inputs/freezer-wheelhouse",
        "--freezer-requirements",
        "inputs/freezer-requirements.lock",
        "--freezer-spec",
        "source-tree/packaging/macos/kazstem-minimal.spec",
        "--workspace",
        "work/reproduction",
    ],
    "ready-archive-audit": [
        "artifacts/ready-run",
        "--identity",
        "release-identity.json",
        "--fresh-root",
        "fresh/ready-audit",
    ],
    "runtime-provenance": [
        "--identity",
        "release-identity.json",
        "--bundle",
        "fresh/ready",
        "--wheel",
        "artifacts/wheel",
        "--python",
        "python3.14",
    ],
    "source-archive-audit": [
        "artifacts/corresponding-source",
        "--identity",
        "release-identity.json",
        "--fresh-root",
        "fresh/source-audit",
    ],
    "source-suite": [
        "--identity",
        "release-identity.json",
        "--repository",
        "source-tree",
        "--python",
        "python3.14",
    ],
}


def _exact(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise ReleaseError(f"{label} fields are not exact")
    return value


def _git(repository: Path, *argv: str) -> str:
    process = subprocess.run(
        ["git", *argv],
        cwd=repository,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=60,
        check=False,
    )
    if process.returncode:
        raise ReleaseError(f"Git command failed: {argv!r}")
    return process.stdout.decode("utf-8", "strict").strip()


def _record_at_commit(repository: Path, commit: str, relative: str) -> dict[str, Any]:
    portable_path(relative, label="identity-bound source path")
    working = repository / relative
    verify = subprocess.run(
        ["git", "show", "--no-textconv", f"{commit}:{relative}"],
        cwd=repository,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=60,
        check=False,
    )
    if verify.returncode or not working.is_file() or working.is_symlink():
        raise ReleaseError(f"identity source file is absent from commit: {relative}")
    if verify.stdout != working.read_bytes():
        raise ReleaseError(f"working source bytes differ from commit: {relative}")
    return file_record(working)


def _tool(spec: Any) -> dict[str, Any]:
    value = _exact(spec, {"name", "path", "version_argv"}, "tool specification")
    if not isinstance(value["path"], str) or not value["path"]:
        raise ReleaseError("tool specification path is empty")
    path = Path(value["path"]).resolve(strict=True)
    argv = value["version_argv"]
    if (
        not isinstance(value["name"], str)
        or not value["name"]
        or not isinstance(argv, list)
        or not argv
        or argv[0] != value["name"]
    ):
        raise ReleaseError("tool specification name/argv is invalid")
    process = subprocess.run(
        [str(path), *argv[1:]],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=60,
        check=False,
    )
    if process.returncode:
        raise ReleaseError(f"tool version command failed: {value['name']}")
    return {
        "name": value["name"],
        "version_argv": argv,
        "version": process.stdout.decode("utf-8", "replace").strip(),
        "executable": file_record(path),
    }


def _verify_staging_receipt(
    args: argparse.Namespace,
    *,
    release: str,
    commit: str,
    tree: str,
    source_ref: str,
    artifacts: dict[str, dict[str, Any]],
    tar_paths: dict[str, Path],
) -> dict[str, Any]:
    receipt_path = args.staging_receipt.resolve(strict=True)
    receipt = read_json(receipt_path)
    assert_relative_json(receipt, label="staging receipt")
    if (
        not isinstance(receipt, dict)
        or set(receipt)
        != {
            "schema",
            "pass",
            "release",
            "source_commit",
            "source_tree",
            "source_ref",
            "bootstrap_identity_contract_sha256",
            "hypotheses",
            "unique_fixed_point",
            "selected",
            "independent_recheck",
        }
        or receipt["schema"] != STAGING_SCHEMA
        or receipt["pass"] is not True
        or receipt["release"] != release
        or receipt["source_commit"] != commit
        or receipt["source_tree"] != tree
        or receipt["source_ref"] != source_ref
    ):
        raise ReleaseError("staging receipt identity differs")
    hypotheses = receipt["hypotheses"]
    if not isinstance(hypotheses, list) or [
        item.get("hypothesis") for item in hypotheses
    ] != ["gzip", "xz", "zstd"]:
        raise ReleaseError("staging receipt lacks all ordered filename hypotheses")
    fixed = [item for item in hypotheses if item.get("fixed_point") is True]
    if len(fixed) != 1 or receipt["unique_fixed_point"] != fixed[0]["hypothesis"]:
        raise ReleaseError("staging receipt lacks one unique fixed point")
    for hypothesis in hypotheses:
        for asset_name in ("corresponding_source", "ready_run"):
            comparison = hypothesis.get(asset_name)
            candidates = (
                comparison.get("candidates") if isinstance(comparison, dict) else None
            )
            if (
                not isinstance(candidates, list)
                or {candidate.get("format") for candidate in candidates}
                != {"gzip", "xz", "zstd"}
                or any(
                    candidate.get("builds_identical") is not True
                    or candidate.get("byte_identical") is not True
                    or not isinstance(candidate.get("builds"), list)
                    or len(candidate["builds"]) != 2
                    or candidate.get("roundtrip_tar_sha256")
                    != comparison.get("canonical_tar", {}).get("sha256")
                    for candidate in candidates
                )
            ):
                raise ReleaseError("staging compression comparison is incomplete")
    selected = receipt["selected"]
    if (
        not isinstance(selected, dict)
        or selected.get("ready_run") != artifacts["ready_run"]
        or selected.get("corresponding_source") != artifacts["corresponding_source"]
    ):
        raise ReleaseError("staging selected artifact records differ")
    canonical = selected.get("canonical_tars")
    if not isinstance(canonical, dict) or set(canonical) != {
        "ready_run",
        "corresponding_source",
    }:
        raise ReleaseError("staging selected canonical tars are incomplete")
    for asset_name, path in tar_paths.items():
        expected = {"filename": path.name, **file_record(path)}
        if canonical[asset_name] != expected:
            raise ReleaseError(f"staging canonical tar differs: {asset_name}")
    staged_identity = selected.get("staged_identity")
    if not isinstance(staged_identity, dict) or set(staged_identity) != {
        "path",
        "file",
    }:
        raise ReleaseError("staging receipt lacks its staged identity")
    staged_path = portable_path(staged_identity["path"], label="staged identity path")
    verify_file(
        args.staging_workspace.resolve(strict=True) / staged_path,
        staged_identity["file"],
        label="staged fixed-point identity",
    )
    recheck = receipt["independent_recheck"]
    if (
        not isinstance(recheck, dict)
        or recheck.get("distinct_nonaliased_roots") is not True
    ):
        raise ReleaseError("staging receipt lacks an independent nonaliased recheck")
    for asset_name in ("ready_run", "corresponding_source"):
        record = recheck.get(asset_name)
        if (
            not isinstance(record, dict)
            or set(record) != {"path", "file"}
            or record["file"]
            != {
                "bytes": artifacts[asset_name]["bytes"],
                "sha256": artifacts[asset_name]["sha256"],
            }
        ):
            raise ReleaseError(f"staging recheck differs: {asset_name}")
    return {
        "file": file_record(receipt_path),
        "generator": {
            "path": "packaging/macos/stage_release_candidates.py",
            "file": _record_at_commit(
                args.repository.resolve(strict=True),
                commit,
                "packaging/macos/stage_release_candidates.py",
            ),
            "schema": STAGING_SCHEMA,
        },
    }


def _artifact(path: Path, *, release_url: str) -> dict[str, Any]:
    return artifact_record(
        path.resolve(strict=True),
        release_url.replace("/tag/", "/download/") + "/" + path.name,
    )


def _manifest_bundle(path: Path, *, label: str) -> tuple[str, dict[str, Any]]:
    manifest = path / "manifest.json"
    value = read_json(manifest)
    bundle_id = value.get("bundle_id") if isinstance(value, dict) else None
    if not isinstance(bundle_id, str) or len(bundle_id) != 64:
        raise ReleaseError(f"{label} manifest lacks a content-addressed bundle id")
    return bundle_id, file_record(manifest)


def _validate_python_artifacts(
    wheel: Path, sdist: Path, *, release: str, limits: dict[str, Any]
) -> None:
    if wheel.name != f"kazstem-{release}-py3-none-any.whl":
        raise ReleaseError("canonical wheel filename is wrong")
    if sdist.name != f"kazstem-{release}.tar.gz":
        raise ReleaseError("canonical sdist filename is wrong")
    from release_common import ArchiveLimits

    nested_limits = ArchiveLimits(**limits)
    inspect_zip(wheel, limits=nested_limits)
    inspect_tar(
        sdist,
        limits=nested_limits,
        expected_top=f"kazstem-{release}",
    )
    import zipfile

    with zipfile.ZipFile(wheel) as archive:
        metadata_names = [
            name for name in archive.namelist() if name.endswith(".dist-info/METADATA")
        ]
        if len(metadata_names) != 1:
            raise ReleaseError("canonical wheel has no unique METADATA")
        metadata = archive.read(metadata_names[0]).decode("utf-8", "strict")
    if f"\nVersion: {release}\n" not in "\n" + metadata:
        raise ReleaseError("canonical wheel metadata version differs")


def _source_nested(
    payload: Path,
    *,
    application_source: str,
    git_archive_file: str,
    git_archive: Path,
    wheel: Path,
    sdist: Path,
) -> list[dict[str, Any]]:
    observed: dict[str, str] = {}
    for path in sorted(payload.rglob("*")):
        if path.is_file() and not path.is_symlink():
            kind = detect_archive_format(path)
            if kind is not None:
                if kind not in {"tar", "zip", "deb", "gzip"}:
                    raise ReleaseError(
                        f"unsupported source payload archive: {path.relative_to(payload)}={kind}"
                    )
                observed[path.relative_to(payload).as_posix()] = kind
    verify_declared_archive_inventory(payload, observed)
    records = [
        {"path": relative, "format": kind, **file_record(payload / relative)}
        for relative, kind in observed.items()
    ]
    records.extend(
        [
            {"path": git_archive_file, "format": "tar", **file_record(git_archive)},
            {
                "path": f"python-artifacts/{wheel.name}",
                "format": "zip",
                **file_record(wheel),
            },
            {
                "path": f"python-artifacts/{sdist.name}",
                "format": "tar",
                **file_record(sdist),
            },
        ]
    )
    records.sort(key=lambda item: item["path"])
    paths = [record["path"] for record in records]
    if len(paths) != len(set(paths)):
        raise ReleaseError("nested source archive paths collide")
    return records


def _prove_runtime_source_closure(
    payload: Path,
    lock_path: Path,
    *,
    runtime_id: str,
    runtime_manifest: dict[str, Any],
    platform_lock_path: Path,
    resource_id: str,
) -> None:
    lock = read_json(lock_path)
    if (
        not isinstance(lock, dict)
        or lock.get("schema") != "kazstem-platform-runtime-source-lock-v1"
        or lock.get("platform")
        != {"system": "darwin", "machine": "arm64", "minimum_os": "14.0"}
    ):
        raise ReleaseError("Darwin runtime source lock is not exact")
    files_by_name: dict[str, list[Path]] = {}
    for path in payload.rglob("*"):
        if path.is_file() and not path.is_symlink():
            files_by_name.setdefault(path.name, []).append(path)
    for field in ("archives", "corresponding_sources"):
        for record in lock[field]:
            matches = files_by_name.get(record["filename"], [])
            if len(matches) != 1:
                raise ReleaseError(f"runtime closure lacks unique {record['filename']}")
            verify_file(
                matches[0],
                {"bytes": record["bytes"], "sha256": record["sha256"]},
                label=f"runtime closure {record['filename']}",
            )
    suspicious = sorted(
        path.relative_to(payload).as_posix()
        for path in payload.rglob("*")
        if path.is_file()
        and any(
            token in path.name.casefold()
            for token in ("openssl", "libssl", "libcrypto")
        )
    )
    if suspicious:
        raise ReleaseError(
            f"OpenSSL source/binaries are forbidden in closure: {suspicious}"
        )
    asset_lock = read_json(platform_lock_path)
    selected = [
        record
        for record in asset_lock.get("runtimes", [])
        if record.get("platform") == {"system": "darwin", "machine": "arm64"}
    ]
    expected = {
        "bundle_id": runtime_id,
        "manifest": runtime_manifest,
        "platform": {"system": "darwin", "machine": "arm64"},
        "resource_bundle_ids": [resource_id],
    }
    if selected != [expected]:
        raise ReleaseError(
            "unified platform lock does not bind the exact Darwin runtime"
        )


def _evidence(
    *,
    repository: Path,
    commit: str,
    tree: str,
    release: str,
    epoch: int,
    evidence_root: Path,
    bootstrap: bool,
    python_tool: str,
    artifact_filenames: dict[str, str],
    tar_filenames: dict[str, str],
    interpreter_source_path: str,
) -> list[dict[str, Any]]:
    environment = {
        "LANG": "C",
        "LC_ALL": "C",
        "PYTHONHASHSEED": "0",
        "SOURCE_DATE_EPOCH": str(epoch),
        "TZ": "UTC",
    }
    result: list[dict[str, Any]] = []
    for gate in sorted(REQUIRED_EVIDENCE_GATES):
        source_script = GATE_SCRIPTS[gate]
        script = f"source-tree/{source_script}"
        record_path = f"gates/{gate}.json"
        evidence_path = evidence_root / record_path
        if evidence_path.is_file() and not evidence_path.is_symlink():
            evidence_file = file_record(evidence_path)
        elif bootstrap:
            evidence_file = {"bytes": 1, "sha256": "0" * 64}
        else:
            raise ReleaseError(f"final evidence is missing: {record_path}")
        replacements = {
            "artifacts/ready-run": f"artifacts/{artifact_filenames['ready_run']}",
            "artifacts/corresponding-source": f"artifacts/{artifact_filenames['corresponding_source']}",
            "artifacts/wheel": f"artifacts/{artifact_filenames['wheel']}",
            "canonical/ready.tar": f"canonical/{tar_filenames['ready_run']}",
            "canonical/source.tar": f"canonical/{tar_filenames['corresponding_source']}",
            "inputs/interpreter-source-file": interpreter_source_path,
        }
        arguments = [replacements.get(token, token) for token in GATE_ARGUMENTS[gate]]
        argv = [
            python_tool,
            "-S",
            script,
            *arguments,
            "--output",
            f"evidence/{record_path}",
        ]
        result.append(
            {
                "path": record_path,
                "gate": gate,
                "kind": "envelope",
                "subjects": GATE_SUBJECTS[gate],
                "file": evidence_file,
                "generator": {
                    "argv": argv,
                    "cwd": "release-workspace",
                    "environment": environment,
                    "script": {
                        "path": script,
                        "file": _record_at_commit(repository, commit, source_script),
                    },
                    "source_commit": commit,
                    "source_tree": tree,
                    "timeout_seconds": GATE_TIMEOUTS[gate],
                    "tool": python_tool,
                },
            }
        )
    return result


def generate(args: argparse.Namespace) -> dict[str, Any]:
    if args.output.exists() or args.output.is_symlink():
        raise ReleaseError("release identity output already exists")
    repository = args.repository.resolve(strict=True)
    config = read_json(args.config.resolve(strict=True))
    required_config = {
        "schema",
        "release",
        "source_date_epoch",
        "release_url",
        "platform",
        "archive_limits",
        "ready_run",
        "corresponding_source",
        "minimization",
        "compression",
        "reproducibility",
        "tool_specs",
        "python_runtimes",
        "documents",
    }
    _exact(config, required_config, "release config")
    if config["schema"] != CONFIG_SCHEMA:
        raise ReleaseError("unsupported release config schema")
    commit = _git(repository, "rev-parse", "HEAD")
    tree = _git(repository, "rev-parse", "HEAD^{tree}")
    origin = _git(repository, "remote", "get-url", "origin")
    status = _git(repository, "status", "--porcelain=v1", "--untracked-files=all")
    if status and not args.allow_dirty_bootstrap:
        raise ReleaseError("identity must be generated from a clean source checkout")
    if origin != "https://github.com/amir-nuriyev/KazStem.git":
        raise ReleaseError(
            "release origin is not the canonical public HTTPS repository"
        )
    release = config["release"]
    release_url = config["release_url"]
    source_ref = f"refs/tags/v{release}"
    if _git(repository, "rev-parse", f"{source_ref}^{{commit}}") != commit:
        raise ReleaseError("the exact release tag does not resolve to HEAD")
    wheel = args.wheel.resolve(strict=True)
    sdist = args.sdist.resolve(strict=True)
    _validate_python_artifacts(
        wheel,
        sdist,
        release=release,
        limits=config["archive_limits"]["nested"],
    )
    native_placeholders = args.bootstrap
    artifacts = {
        "wheel": _artifact(wheel, release_url=release_url),
        "sdist": _artifact(sdist, release_url=release_url),
    }
    for asset_name, path in (
        ("ready_run", args.ready_run),
        ("corresponding_source", args.corresponding_source),
    ):
        if native_placeholders:
            artifacts[asset_name] = {
                "filename": path.name,
                "bytes": 1,
                "sha256": "0" * 64,
                "url": release_url.replace("/tag/", "/download/") + "/" + path.name,
            }
        else:
            artifacts[asset_name] = _artifact(
                path.resolve(strict=True), release_url=release_url
            )
    git_archive = args.git_archive.absolute()
    if git_archive.exists() or git_archive.is_symlink():
        raise ReleaseError("canonical Git archive output must be fresh")
    git_archive.parent.mkdir(parents=True, exist_ok=True)
    with git_archive.open("xb") as output:
        process = subprocess.run(
            [
                "git",
                "archive",
                "--format=tar",
                "--prefix=tree/",
                commit,
            ],
            cwd=repository,
            stdin=subprocess.DEVNULL,
            stdout=output,
            stderr=subprocess.PIPE,
            timeout=300,
            check=False,
        )
    if process.returncode:
        git_archive.unlink(missing_ok=True)
        raise ReleaseError("canonical Git archive generation failed")
    resources = args.resources.resolve(strict=True)
    runtime = args.runtime.resolve(strict=True)
    resource_id, resource_manifest = _manifest_bundle(resources, label="resource")
    runtime_id, runtime_manifest = _manifest_bundle(runtime, label="runtime")
    payload = args.source_payload.resolve(strict=True)
    platform_lock = args.platform_asset_lock.resolve(strict=True)
    runtime_source_lock = args.runtime_source_lock.resolve(strict=True)
    _prove_runtime_source_closure(
        payload,
        runtime_source_lock,
        runtime_id=runtime_id,
        runtime_manifest=runtime_manifest,
        platform_lock_path=platform_lock,
        resource_id=resource_id,
    )
    source_config = config["corresponding_source"]
    if wheel.parent.resolve() != sdist.parent.resolve():
        raise ReleaseError("canonical wheel and sdist must share one input directory")
    authority = bind_authority(
        repository=repository,
        payload=payload,
        python_build_identity_path=args.python_build_identity,
        linux_release_identity_path=args.linux_release_identity,
        linux_reproducibility_path=args.linux_reproducibility,
        interpreter_source_path=args.python_interpreter_source,
        canonical_artifacts=wheel.parent,
        release_identity={
            "release": release,
            "source_commit": commit,
            "source_tree": tree,
            "source_origin": origin,
            "source_ref": source_ref,
            "source_date_epoch": config["source_date_epoch"],
            "release_url": release_url,
            "artifacts": artifacts,
        },
    )
    missing_authority_paths = sorted(
        {item["path"] for item in authority["source_companions"]}
        - set(source_config["required_paths"])
    )
    if missing_authority_paths:
        raise ReleaseError(
            "corresponding-source required paths omit canonical authority inputs: "
            f"{missing_authority_paths}"
        )
    nested = _source_nested(
        payload,
        application_source=source_config["source_categories"]["application_source"],
        git_archive_file=source_config["git_archive_file"],
        git_archive=git_archive,
        wheel=wheel,
        sdist=sdist,
    )
    documents: list[dict[str, Any]] = []
    documents_root = args.documents.resolve(strict=True)
    for record in config["documents"]:
        source = portable_path(record["source"], label="document source")
        destination = portable_path(record["destination"], label="document destination")
        documents.append(
            {
                "source": source,
                "destination": destination,
                "file": file_record(documents_root / source),
            }
        )
    documents.sort(key=lambda item: item["destination"])
    ready_config = config["ready_run"]
    frozen = args.frozen.resolve(strict=True)
    removals = [
        {"path": relative, "file": file_record(frozen / relative)}
        for relative in ready_config["remove_frozen_paths"]
    ]
    build_stack = read_json(args.build_stack.resolve(strict=True))
    if (
        not isinstance(build_stack, dict)
        or set(build_stack) != {"schema", "canonical", "freezer"}
        or build_stack["schema"] != BUILD_STACK_SCHEMA
    ):
        raise ReleaseError("build-stack input schema is invalid")
    payload_records = {
        (path.name, file_record(path)["sha256"])
        for path in payload.rglob("*")
        if path.is_file() and not path.is_symlink()
    }
    for role in ("canonical", "freezer"):
        for record in build_stack[role]:
            for artifact_name in ("wheel", "source"):
                artifact = record[artifact_name]
                if (artifact["filename"], artifact["sha256"]) not in payload_records:
                    raise ReleaseError(
                        f"build-stack closure lacks {artifact['filename']}"
                    )
    tools = sorted(
        (_tool(spec) for spec in config["tool_specs"]), key=lambda item: item["name"]
    )
    tool_names = [tool["name"] for tool in tools]
    if tool_names != sorted(set(tool_names)):
        raise ReleaseError("tool specifications are duplicated")
    python_tool = config["python_runtimes"]["freezer"]["tool"]
    if python_tool not in tool_names:
        raise ReleaseError("freezer Python is not a bound tool")
    tool_by_name = {tool["name"]: tool for tool in tools}
    runtime_config = _exact(
        config["python_runtimes"], {"freezer"}, "Python runtimes"
    )["freezer"]
    runtime_config = _exact(runtime_config, {"tool"}, "freezer Python runtime")
    record = tool_by_name[runtime_config["tool"]]
    version = record["version"].removeprefix("Python ").strip()
    if version != "3.14.3":
        raise ReleaseError(
            f"freezer Python version must be 3.14.3, observed {version}"
        )
    python_runtimes = {
        "freezer": {
            "implementation": "CPython",
            "version": version,
            "executable": record["executable"],
        }
    }
    compressor_tools = config["compression"]["tools"]
    compressors = {
        "gzip": {
            **tool_by_name[compressor_tools["python"]],
            "argv": [
                python_tool,
                "stdlib:gzip",
                "compresslevel=9",
                "mtime=0",
                "filename=",
            ],
        },
        "xz": {
            **tool_by_name[compressor_tools["python"]],
            "argv": [
                python_tool,
                "stdlib:lzma",
                "format=xz",
                "check=crc64",
                "preset=9e",
            ],
        },
        "zstd": {
            **tool_by_name[compressor_tools["zstd"]],
            "argv": [
                "zstd",
                "-19",
                "--ultra",
                "--threads=1",
                "--no-progress",
                "--stdout",
                "canonical.tar",
            ],
        },
    }
    compression: dict[str, Any] = {}
    tar_paths = {
        "ready_run": (
            args.ready_tar.absolute()
            if args.bootstrap
            else args.ready_tar.resolve(strict=True)
        ),
        "corresponding_source": (
            args.source_tar.absolute()
            if args.bootstrap
            else args.source_tar.resolve(strict=True)
        ),
    }
    producer_scripts = {
        "ready_run": "packaging/macos/assemble_ready_run.py",
        "corresponding_source": "packaging/macos/assemble_corresponding_source.py",
    }
    for asset_name in ("ready_run", "corresponding_source"):
        tar_path = tar_paths[asset_name]
        policy = config["compression"][asset_name]
        tar_identity = (
            {"bytes": 1, "sha256": "0" * 64}
            if args.bootstrap
            else file_record(tar_path)
        )
        compression[asset_name] = {
            "canonical_tar": {
                "filename": tar_path.name,
                **tar_identity,
                "producer": {
                    "argv": [
                        python_tool,
                        producer_scripts[asset_name],
                        "--identity",
                        "release-identity.json",
                    ],
                    "script": {
                        "path": producer_scripts[asset_name],
                        "file": _record_at_commit(
                            repository, commit, producer_scripts[asset_name]
                        ),
                    },
                    "source_commit": commit,
                    "source_tree": tree,
                },
            },
            "compressors": compressors,
            "eligibility": policy["eligibility"],
            "selected_format": policy["selected_format"],
            "selection_rule": "smallest-eligible-byte-identical",
        }
    tracing_tool = _exact(
        config["reproducibility"]["tracing_tool"],
        {"name", "path", "version_argv"},
        "sandbox tracing tool",
    )
    sandbox_path = Path(tracing_tool["path"]).resolve(strict=True)
    sandbox_process = subprocess.run(
        [str(sandbox_path), *tracing_tool["version_argv"][1:]],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=60,
        check=False,
    )
    sandbox_record = {
        "name": tracing_tool["name"],
        "version_argv": tracing_tool["version_argv"],
        "version": tool_output_identity(
            sandbox_process.stdout, exit_status=sandbox_process.returncode
        ),
        "executable": file_record(sandbox_path),
    }
    if args.bootstrap:
        staging_receipt = {
            "file": {"bytes": 1, "sha256": "0" * 64},
            "generator": {
                "path": "packaging/macos/stage_release_candidates.py",
                "file": _record_at_commit(
                    repository, commit, "packaging/macos/stage_release_candidates.py"
                ),
                "schema": STAGING_SCHEMA,
            },
        }
    else:
        if args.staging_receipt is None or args.staging_workspace is None:
            raise ReleaseError(
                "final identity requires --staging-receipt and --staging-workspace"
            )
        staging_receipt = _verify_staging_receipt(
            args,
            release=release,
            commit=commit,
            tree=tree,
            source_ref=source_ref,
            artifacts=artifacts,
            tar_paths=tar_paths,
        )
    identity = {
        "schema": IDENTITY_SCHEMA,
        "release": release,
        "source_commit": commit,
        "source_tree": tree,
        "source_origin": origin,
        "source_ref": source_ref,
        "source_date_epoch": config["source_date_epoch"],
        "release_url": release_url,
        "platform": config["platform"],
        "artifacts": artifacts,
        "inputs": {
            "frozen_tree": tree_record(frozen),
            "resource_tree": {
                "bundle_id": resource_id,
                "manifest": resource_manifest,
                "tree": tree_record(resources),
            },
            "runtime_tree": {
                "bundle_id": runtime_id,
                "manifest": runtime_manifest,
                "tree": tree_record(runtime),
            },
            "source_payload_tree": tree_record(payload),
            "git_archive": {
                "argv": [
                    "git",
                    "archive",
                    "--format=tar",
                    "--prefix=tree/",
                    commit,
                ],
                "file": file_record(git_archive),
                "prefix": "tree/",
                "tool_version": _git(repository, "--version"),
            },
            "base_ledger": file_record(args.base_ledger.resolve(strict=True)),
            "binary_readme_template": _record_at_commit(
                repository, commit, "packaging/macos/BINARY-README.template.md"
            ),
            "source_readme_template": _record_at_commit(
                repository,
                commit,
                "packaging/macos/CORRESPONDING-SOURCE-README.template.md",
            ),
            "runtime_source_lock": file_record(runtime_source_lock),
            "platform_asset_lock": file_record(platform_lock),
            "build_stack": {
                "canonical": build_stack["canonical"],
                "freezer": build_stack["freezer"],
            },
            "freezer_wheelhouse": tree_record(
                args.freezer_wheelhouse.resolve(strict=True)
            ),
            "freezer_requirements": file_record(
                args.freezer_requirements.resolve(strict=True)
            ),
            "freezer_spec": _record_at_commit(
                repository, commit, "packaging/macos/kazstem-minimal.spec"
            ),
            "staging_receipt": staging_receipt,
            "python_runtimes": python_runtimes,
            "documents": documents,
        },
        "ready_run": {
            "top_level": ready_config["top_level"],
            "launcher": {
                "path": ready_config["launcher_path"],
                "file": file_record(frozen / ready_config["launcher_path"]),
            },
            "platform_lock": {
                "path": ready_config["platform_lock_path"],
                "file": file_record(frozen / ready_config["platform_lock_path"]),
            },
            "resource_destination": ready_config["resource_destination"],
            "runtime_parent": ready_config["runtime_parent"],
            "aliases": ready_config["aliases"],
            "remove_frozen_files": removals,
            "required_paths": ready_config["required_paths"],
            "banned_name_fragments": ready_config["banned_name_fragments"],
        },
        "corresponding_source": {
            **source_config,
            "nested_archives": nested,
        },
        "archive_limits": config["archive_limits"],
        "compression": compression,
        "mach_o": {
            "architecture": "arm64",
            "format": "thin",
            "system_boundaries": ["/System/Library/", "/usr/lib/"],
            "runtime_bundle_id": runtime_id,
            "runtime_manifest": runtime_manifest,
            "signature": {
                "kind": "adhoc",
                "team_identifier": None,
                "developer_id": False,
                "notarized": False,
                "stapled": False,
            },
            "rpath_policy": {
                "bind_exact_observed_rpaths": True,
                "bundle_relative_precedes_inherited": True,
                "external_resolution_forbidden": True,
            },
        },
        "minimization": config["minimization"],
        "verification": {
            "minimum_distinct_roots": config["reproducibility"]["build_roots"],
            "reproducibility": {
                "build_roots": config["reproducibility"]["build_roots"],
                "canonical_python_authority": authority,
                "freezer_install_argv": config["reproducibility"][
                    "freezer_install_argv"
                ],
                "frozen_build_argv": config["reproducibility"]["frozen_build_argv"],
                "environment": config["reproducibility"]["environment"],
                "tools": tools,
            },
            "tracing": {
                "argv_prefix": [
                    "sandbox-exec",
                    "-D",
                    "WRITE_ROOT={write_root}",
                    "-f",
                    "{profile}",
                    "--",
                ],
                "negative_control_argv": [
                    "python",
                    "-c",
                    "import socket; s=socket.socket(); s.bind(('127.0.0.1', 0))",
                ],
                "process_observer_argv": ["ps", "-axo", "pid=,ppid=,comm="],
                "profile": {
                    "path": "packaging/macos/network-deny.sb",
                    "file": _record_at_commit(
                        repository, commit, "packaging/macos/network-deny.sb"
                    ),
                },
                "tool": sandbox_record,
            },
            "evidence": _evidence(
                repository=repository,
                commit=commit,
                tree=tree,
                release=release,
                epoch=config["source_date_epoch"],
                evidence_root=args.evidence_root.resolve(strict=True),
                bootstrap=args.bootstrap,
                python_tool=python_tool,
                artifact_filenames={
                    name: record["filename"] for name, record in artifacts.items()
                },
                tar_filenames={
                    name: policy["canonical_tar"]["filename"]
                    for name, policy in compression.items()
                },
                interpreter_source_path=authority["interpreter_source"]["path"],
            ),
        },
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(json_bytes(identity))
    try:
        loaded = load_identity(args.output)
    except BaseException:
        args.output.unlink(missing_ok=True)
        raise
    if loaded != identity:
        args.output.unlink(missing_ok=True)
        raise ReleaseError("identity changed during strict round-trip validation")
    return identity


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--repository", required=True, type=Path)
    parser.add_argument("--wheel", required=True, type=Path)
    parser.add_argument("--sdist", required=True, type=Path)
    parser.add_argument("--ready-run", required=True, type=Path)
    parser.add_argument("--corresponding-source", required=True, type=Path)
    parser.add_argument("--ready-tar", required=True, type=Path)
    parser.add_argument("--source-tar", required=True, type=Path)
    parser.add_argument("--frozen", required=True, type=Path)
    parser.add_argument("--resources", required=True, type=Path)
    parser.add_argument("--runtime", required=True, type=Path)
    parser.add_argument("--source-payload", required=True, type=Path)
    parser.add_argument("--documents", required=True, type=Path)
    parser.add_argument("--base-ledger", required=True, type=Path)
    parser.add_argument("--freezer-wheelhouse", required=True, type=Path)
    parser.add_argument("--freezer-requirements", required=True, type=Path)
    parser.add_argument("--build-stack", required=True, type=Path)
    parser.add_argument("--python-build-identity", required=True, type=Path)
    parser.add_argument("--linux-release-identity", required=True, type=Path)
    parser.add_argument("--linux-reproducibility", required=True, type=Path)
    parser.add_argument("--python-interpreter-source", required=True, type=Path)
    parser.add_argument("--runtime-source-lock", required=True, type=Path)
    parser.add_argument("--platform-asset-lock", required=True, type=Path)
    parser.add_argument("--staging-receipt", type=Path)
    parser.add_argument("--staging-workspace", type=Path)
    parser.add_argument("--git-archive", required=True, type=Path)
    parser.add_argument("--evidence-root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--bootstrap", action="store_true")
    parser.add_argument("--allow-dirty-bootstrap", action="store_true")
    args = parser.parse_args()
    if args.allow_dirty_bootstrap and not args.bootstrap:
        raise SystemExit("error: --allow-dirty-bootstrap requires --bootstrap")
    generate(args)
    print("PASS: strict macOS release identity generated")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ReleaseError, OSError, ValueError, json.JSONDecodeError) as exc:
        raise SystemExit(f"error: {exc}") from exc
