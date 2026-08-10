#!/usr/bin/env python3
"""Lock, describe, and verify the optional Stanza candidate-ranker runtime."""

from __future__ import annotations

import argparse
import hashlib
from importlib import metadata
from importlib.util import find_spec
import json
import os
from pathlib import Path
import platform
import sys
import tempfile
from typing import Any


MODEL_SCHEMA = "qazmorph-neural-model-manifest-v1"
ENVIRONMENT_SCHEMA = "qazmorph-neural-environment-manifest-v2"
MODEL_MANIFEST = "manifest.json"
ENVIRONMENT_MANIFEST = "qazmorph-neural-environment.json"


class ManifestError(RuntimeError):
    """Raised when a neural lock or runtime fails exact verification."""


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def file_record(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise ManifestError(f"required file is missing: {path}")
    return {"bytes": path.stat().st_size, "sha256": sha256(path)}


def canonical_hash(value: Any) -> str:
    encoded = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def load_lock(path: Path) -> dict[str, Any]:
    try:
        lock = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ManifestError(f"cannot read neural asset lock {path}: {exc}") from exc
    if lock.get("schema") != "qazmorph-neural-lock-v1":
        raise ManifestError(f"unsupported neural asset lock schema: {path}")
    for key in ("python", "installer", "stanza", "venv_packages", "host_packages", "host_runtime", "model_files"):
        if key not in lock:
            raise ManifestError(f"neural asset lock lacks {key!r}: {path}")
    return lock


def normalized_name(name: str) -> str:
    return name.lower().replace("_", "-").replace(".", "-")


def distribution_version(name: str) -> str:
    try:
        return metadata.version(name)
    except metadata.PackageNotFoundError as exc:
        raise ManifestError(f"required Python distribution is unavailable: {name}") from exc


def verify_package_versions(lock: dict[str, Any]) -> dict[str, str]:
    observed: dict[str, str] = {}
    for group in ("venv_packages", "host_packages"):
        packages = lock[group]
        if not isinstance(packages, dict):
            raise ManifestError(f"lock {group} must be an object")
        for name, expected in sorted(packages.items(), key=lambda item: normalized_name(item[0])):
            actual = distribution_version(name)
            if actual != expected:
                raise ManifestError(
                    f"Python distribution {name} is {actual}, expected exactly {expected}"
                )
            observed[name] = actual
    return observed


def observed_distribution_closure() -> dict[str, str | list[str]]:
    """Snapshot every Python distribution visible to the neural interpreter."""

    observed: dict[str, set[str]] = {}
    for distribution in metadata.distributions():
        raw_name = distribution.metadata.get("Name")
        if not raw_name:
            continue
        name = normalized_name(raw_name)
        version = distribution.version
        observed.setdefault(name, set()).add(version)
    return {
        name: next(iter(versions)) if len(versions) == 1 else sorted(versions)
        for name, versions in sorted(observed.items())
    }


def observed_model_files(model_dir: Path) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for path in sorted(model_dir.rglob("*"), key=lambda candidate: candidate.as_posix()):
        if path.is_file() and path.name != MODEL_MANIFEST:
            result[path.relative_to(model_dir).as_posix()] = file_record(path)
    return result


def expected_model_files(lock: dict[str, Any]) -> dict[str, dict[str, Any]]:
    files = lock["model_files"]
    if not isinstance(files, dict):
        raise ManifestError("lock model_files must be an object")
    return files


def verify_model_files(lock: dict[str, Any], model_dir: Path) -> dict[str, dict[str, Any]]:
    observed = observed_model_files(model_dir)
    expected = expected_model_files(lock)
    if observed != expected:
        missing = sorted(set(expected) - set(observed))
        extra = sorted(set(observed) - set(expected))
        changed = sorted(
            path for path in set(expected) & set(observed) if expected[path] != observed[path]
        )
        raise ManifestError(
            "Stanza model bundle differs from lock: "
            f"missing={missing}, extra={extra}, changed={changed}"
        )
    return observed


def model_manifest(lock: dict[str, Any], lock_path: Path, model_dir: Path) -> dict[str, Any]:
    files = verify_model_files(lock, model_dir)
    identity: dict[str, Any] = {
        "schema": MODEL_SCHEMA,
        "lock": file_record(lock_path),
        "stanza": lock["stanza"],
        "source": {
            "name": "Stanza Kazakh KTB model distribution",
            "url": "https://stanfordnlp.github.io/stanza/available_models.html",
            "redistributed": False,
        },
        "files": files,
    }
    bundle_id = canonical_hash(identity)
    return {
        **identity,
        "bundle_id": bundle_id,
        "version": f"stanza-kk-{lock['stanza']['version']}-{bundle_id[:16]}",
    }


def source_files(project_root: Path) -> dict[str, dict[str, Any]]:
    relative_paths: set[Path] = {
        Path("LICENSE"),
        Path("README.md"),
        Path("THIRD_PARTY.md"),
        Path("pyproject.toml"),
        Path("scripts/bootstrap_neural_h100.sh"),
        Path("scripts/neural_assets.lock.json"),
        Path("scripts/write_neural_manifest.py"),
    }
    relative_paths.update(path.relative_to(project_root) for path in (project_root / "src").rglob("*.py"))
    return {
        path.as_posix(): file_record(project_root / path)
        for path in sorted(relative_paths, key=lambda item: item.as_posix())
    }


def installed_qazmorph_files() -> dict[str, dict[str, Any]]:
    specification = find_spec("qazmorph")
    if specification is None or not specification.submodule_search_locations:
        raise ManifestError("installed qazmorph package cannot be located")
    package_dir = Path(next(iter(specification.submodule_search_locations))).resolve()
    files = {
        path.relative_to(package_dir).as_posix(): file_record(path)
        for path in sorted(package_dir.rglob("*.py"), key=lambda candidate: candidate.as_posix())
    }
    if not files:
        raise ManifestError(f"installed qazmorph package has no Python sources: {package_dir}")
    return files


def load_verified_model_manifest(lock: dict[str, Any], lock_path: Path, model_dir: Path) -> dict[str, Any]:
    expected = model_manifest(lock, lock_path, model_dir)
    path = model_dir / MODEL_MANIFEST
    try:
        actual = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ManifestError(f"cannot read neural model manifest {path}: {exc}") from exc
    if actual != expected:
        raise ManifestError(f"neural model manifest verification failed: {path}")
    return expected


def environment_manifest(
    lock: dict[str, Any], lock_path: Path, model_dir: Path, project_root: Path
) -> dict[str, Any]:
    expected_python = str(lock["python"])
    actual_python = f"{sys.version_info.major}.{sys.version_info.minor}"
    if actual_python != expected_python:
        raise ManifestError(f"Python is {actual_python}, expected exactly {expected_python}")
    packages = verify_package_versions(lock)
    model = load_verified_model_manifest(lock, lock_path, model_dir)

    try:
        import torch
    except ImportError as exc:
        raise ManifestError("the H100 system torch package is unavailable") from exc
    observed_runtime = {
        "torch": torch.__version__,
        "cuda": torch.version.cuda,
        "cuda_available": torch.cuda.is_available(),
        "gpu": torch.cuda.get_device_name(0) if torch.cuda.is_available() else None,
    }
    for key, expected in lock["host_runtime"].items():
        if observed_runtime.get(key) != expected:
            raise ManifestError(
                f"host runtime {key} is {observed_runtime.get(key)!r}, expected {expected!r}"
            )
    if not observed_runtime["cuda_available"]:
        raise ManifestError("CUDA is not available to the neural environment")

    project_records = source_files(project_root)
    installed_records = installed_qazmorph_files()
    expected_installed = {
        relative.removeprefix("src/qazmorph/"): record
        for relative, record in project_records.items()
        if relative.startswith("src/qazmorph/")
    }
    if installed_records != expected_installed:
        raise ManifestError(
            "installed qazmorph Python sources do not match the project source snapshot"
        )

    identity: dict[str, Any] = {
        "schema": ENVIRONMENT_SCHEMA,
        "lock": file_record(lock_path),
        "python": {
            "implementation": platform.python_implementation(),
            "version": platform.python_version(),
            "abi": sys.implementation.cache_tag,
        },
        "platform": {
            "machine": platform.machine(),
            "system": platform.system(),
        },
        "packages": packages,
        "visible_distribution_versions": observed_distribution_closure(),
        "host_runtime": observed_runtime,
        "model_bundle_id": model["bundle_id"],
        "project_sources": project_records,
        "installed_qazmorph": installed_records,
    }
    bundle_id = canonical_hash(identity)
    return {
        **identity,
        "bundle_id": bundle_id,
        "version": f"qazmorph-neural-{bundle_id[:16]}",
    }


def atomic_write(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(value, stream, ensure_ascii=False, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o644)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def print_requirements(lock: dict[str, Any]) -> None:
    for name, version in sorted(
        lock["venv_packages"].items(), key=lambda item: normalized_name(item[0])
    ):
        print(f"{name}=={version}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lock", required=True, type=Path)
    parser.add_argument("--model-dir", type=Path)
    parser.add_argument("--project-root", type=Path)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--print-requirements", action="store_true")
    action.add_argument("--verify-model-files", action="store_true")
    action.add_argument("--write-model-manifest", action="store_true")
    action.add_argument("--verify-model-manifest", action="store_true")
    action.add_argument("--write-environment-manifest", action="store_true")
    action.add_argument("--verify-environment-manifest", action="store_true")
    args = parser.parse_args()

    lock_path = args.lock.resolve()
    lock = load_lock(lock_path)
    if args.print_requirements:
        print_requirements(lock)
        return 0
    if args.model_dir is None:
        parser.error("--model-dir is required for this action")
    model_dir = args.model_dir.resolve()

    if args.verify_model_files:
        verify_model_files(lock, model_dir)
        return 0
    if args.write_model_manifest:
        manifest = model_manifest(lock, lock_path, model_dir)
        atomic_write(model_dir / MODEL_MANIFEST, manifest)
        print(manifest["bundle_id"])
        return 0
    if args.verify_model_manifest:
        manifest = load_verified_model_manifest(lock, lock_path, model_dir)
        print(manifest["bundle_id"])
        return 0

    if args.project_root is None:
        parser.error("--project-root is required for environment manifests")
    project_root = args.project_root.resolve()
    manifest = environment_manifest(lock, lock_path, model_dir, project_root)
    output = Path(sys.prefix) / ENVIRONMENT_MANIFEST
    if args.verify_environment_manifest:
        try:
            actual = json.loads(output.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ManifestError(f"cannot read neural environment manifest {output}: {exc}") from exc
        if actual != manifest:
            raise ManifestError(f"neural environment manifest verification failed: {output}")
        print(manifest["bundle_id"])
        return 0
    atomic_write(output, manifest)
    print(manifest["bundle_id"])
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ManifestError as error:
        raise SystemExit(f"error: {error}") from error
