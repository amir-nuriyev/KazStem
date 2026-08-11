#!/usr/bin/env python3
"""Build every release artifact in fresh roots and rebuild from the sdist."""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import sys
import tempfile
import time
import types
from typing import Any
import zipfile

def _source_module(name: str, path: Path) -> types.ModuleType:
    module = types.ModuleType(name)
    module.__file__ = str(path)
    sys.modules[name] = module
    source = path.read_bytes()
    exec(compile(source, str(path), "exec", dont_inherit=True), module.__dict__)
    return module


_tool_directory = Path(__file__).resolve().parent
_common = _source_module(
    "_kazstem_repro_release_common", _tool_directory / "release_common.py"
)
canonical_python_builder = _source_module(
    "_kazstem_repro_canonical_builder",
    _tool_directory.parent / "build_canonical_python_artifacts.py",
)
ReleaseError = _common.ReleaseError
archive_limits = _common.archive_limits
assert_relative_json = _common.assert_relative_json
ensure_distinct_nonaliased_paths = _common.ensure_distinct_nonaliased_paths
ensure_output_outside = _common.ensure_output_outside
extract_validated_tar = _common.extract_validated_tar
file_record = _common.file_record
canonical_hash = _common.canonical_hash
identity_sha256 = _common.identity_sha256
inspect_tar = _common.inspect_tar
inspect_zip = _common.inspect_zip
json_bytes = _common.json_bytes
load_identity = _common.load_identity
read_json = _common.read_json
sha256_file = _common.sha256_file
tree_record = _common.tree_record
tree_inventory = _common.tree_inventory
validate_tar_producer_receipt = _common.validate_tar_producer_receipt
verify_artifact = _common.verify_artifact
verify_canonical_source_companions = _common.verify_canonical_source_companions
verify_file = _common.verify_file
verify_tree = _common.verify_tree
SupervisionError = canonical_python_builder.SupervisionError
run_bounded = canonical_python_builder.run_bounded


def _resolved_tool(name: str, expected: dict[str, Any]) -> Path:
    observed = shutil.which(name)
    if observed is None:
        raise ReleaseError(f"required reproducibility tool is unavailable: {name}")
    path = Path(observed).resolve(strict=True)
    verify_file(path, expected["executable"], label=f"reproducibility tool {name}")
    argv = [str(path), *expected["version_argv"][1:]]
    process = subprocess.run(
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=60,
        check=False,
    )
    try:
        version = process.stdout.decode("utf-8").strip()
    except UnicodeError as exc:
        raise ReleaseError(f"{name} version output is not UTF-8") from exc
    if process.returncode != 0 or version != expected["version"]:
        raise ReleaseError(
            f"{name} version differs from identity: exit={process.returncode}, "
            f"observed={version!r}"
        )
    return path


def _stream_record(data: bytes) -> dict[str, Any]:
    return {
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "truncated": False,
        "lines": len(data.splitlines()),
    }


def _normalize_command_stream(
    data: bytes,
    *,
    actual_argv: list[str],
    logical_argv: list[str],
    environment: dict[str, str],
) -> bytes:
    try:
        text = data.decode("utf-8")
    except UnicodeError as exc:
        raise ReleaseError("reproducibility command output is not UTF-8") from exc
    text = text.replace("\r\n", "\n")
    replacements = [
        (actual, logical)
        for actual, logical in zip(actual_argv, logical_argv, strict=True)
        if actual != logical
    ]
    if "HOME" in environment:
        replacements.append((environment["HOME"], "workspace/controlled-home"))
    if "PYTHONPYCACHEPREFIX" in environment:
        replacements.append(
            (environment["PYTHONPYCACHEPREFIX"], "workspace/pycache")
        )
    for actual, logical in sorted(replacements, key=lambda item: len(item[0]), reverse=True):
        if actual:
            text = text.replace(actual, logical)
            text = text.replace(actual.replace("/", "\\"), logical)
    return text.encode("utf-8")


def _run(
    argv: list[str],
    *,
    logical_argv: list[str],
    cwd: Path,
    environment: dict[str, str],
    timeout: int = 600,
) -> dict[str, Any]:
    capture_cap = 16 * 1024**2
    try:
        completed = run_bounded(
            argv,
            cwd=cwd,
            environment=environment,
            timeout=timeout,
            max_stdout=capture_cap,
            max_stderr=capture_cap,
        )
    except SupervisionError as exc:
        raise ReleaseError(f"reproducibility command supervision failed: {exc}") from exc
    stdout_data = _normalize_command_stream(
        completed.stdout,
        actual_argv=argv,
        logical_argv=logical_argv,
        environment=environment,
    )
    stderr_data = _normalize_command_stream(
        completed.stderr,
        actual_argv=argv,
        logical_argv=logical_argv,
        environment=environment,
    )
    result = {
        "argv": logical_argv,
        "exit_status": completed.returncode,
        "stdout": _stream_record(stdout_data),
        "stderr": _stream_record(stderr_data),
    }
    if completed.returncode != 0:
        detail = stderr_data[:4096].decode("utf-8", "replace")
        raise ReleaseError(
            f"reproducibility command failed with exit {completed.returncode}: "
            f"{logical_argv!r}: {detail}"
        )
    return result


def _command(
    configured: list[str],
    *,
    tools: dict[str, Path],
    actual_output: Path,
    logical_output: str,
    placeholder: str,
) -> tuple[list[str], list[str]]:
    actual = [item.replace(placeholder, str(actual_output)) for item in configured]
    logical = [item.replace(placeholder, logical_output) for item in configured]
    actual[0] = str(tools[configured[0]])
    return actual, logical


def _assert_unique_regular_files(root: Path, inodes: set[tuple[int, int]]) -> int:
    count = 0
    for path in sorted(root.rglob("*")):
        if path.is_symlink() or not path.is_file():
            continue
        metadata = path.stat()
        if metadata.st_nlink != 1:
            raise ReleaseError(f"hard-linked reproduction input/output: {path.name}")
        key = (metadata.st_dev, metadata.st_ino)
        if key in inodes:
            raise ReleaseError(
                f"filesystem alias crosses independent reproduction roots: {path.name}"
            )
        inodes.add(key)
        count += 1
    return count


def _artifact_freshness(
    path: Path, *, start_ns: int, inodes: set[tuple[int, int]]
) -> dict[str, Any]:
    metadata = path.stat()
    if metadata.st_nlink != 1:
        raise ReleaseError(f"built artifact is hard-linked: {path.name}")
    key = (metadata.st_dev, metadata.st_ino)
    if key in inodes:
        raise ReleaseError(f"built artifact aliases an earlier output: {path.name}")
    inodes.add(key)
    if metadata.st_ctime_ns < start_ns:
        raise ReleaseError(f"built artifact predates its build command: {path.name}")
    return {
        "link_count": metadata.st_nlink,
        "created_by_command": True,
        **file_record(path),
    }


def _record_digest(data: bytes) -> str:
    return "sha256=" + base64.urlsafe_b64encode(
        hashlib.sha256(data).digest()
    ).rstrip(b"=").decode("ascii")


def _wheel_package_inventory(
    wheel: Path, *, identity: dict[str, Any]
) -> dict[str, Any]:
    """Independently validate RECORD and inventory the wheel's qazmorph package."""

    verify_artifact(wheel, identity["artifacts"]["wheel"], label="frozen-build wheel")
    inspect_zip(wheel, limits=archive_limits(identity, "nested"))
    files: dict[str, bytes] = {}
    with zipfile.ZipFile(wheel) as archive:
        for info in archive.infolist():
            if info.is_dir():
                continue
            data = archive.read(info)
            if len(data) != info.file_size:
                raise ReleaseError("wheel member length differs during frozen audit")
            files[info.filename] = data
    dist_info = sorted(
        {
            PurePosixPath(name).parts[0]
            for name in files
            if len(PurePosixPath(name).parts) > 1
            and PurePosixPath(name).parts[0].endswith(".dist-info")
        }
    )
    if len(dist_info) != 1:
        raise ReleaseError("frozen-build wheel lacks one dist-info directory")
    record_path = f"{dist_info[0]}/RECORD"
    if record_path not in files:
        raise ReleaseError("frozen-build wheel lacks RECORD")
    try:
        rows = list(csv.reader(io.StringIO(files[record_path].decode("utf-8"))))
    except (UnicodeError, csv.Error) as exc:
        raise ReleaseError("frozen-build wheel RECORD is malformed") from exc
    if len(rows) != len(files):
        raise ReleaseError("frozen-build wheel RECORD is incomplete")
    seen: set[str] = set()
    for row in rows:
        if len(row) != 3 or row[0] in seen or row[0] not in files:
            raise ReleaseError("frozen-build wheel RECORD row differs")
        seen.add(row[0])
        if row[0] == record_path:
            if row[1:] != ["", ""]:
                raise ReleaseError("frozen-build wheel RECORD self row differs")
        else:
            data = files[row[0]]
            if row[1] != _record_digest(data) or row[2] != str(len(data)):
                raise ReleaseError("frozen-build wheel RECORD hash/size differs")
    package_files = [
        {"path": name, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
        for name, data in sorted(files.items())
        if name.startswith("qazmorph/")
    ]
    if not package_files or not any(
        item["path"].endswith(".py") for item in package_files
    ):
        raise ReleaseError("frozen-build wheel lacks the qazmorph Python package")
    modules: list[dict[str, Any]] = []
    for item in package_files:
        path = item["path"]
        if not path.endswith(".py"):
            continue
        parts = list(PurePosixPath(path).with_suffix("").parts)
        if parts[-1] == "__init__":
            parts.pop()
        modules.append(
            {
                "module": ".".join(parts),
                "path": path,
                "file": {"bytes": item["bytes"], "sha256": item["sha256"]},
            }
        )
    return {
        "record": {"path": record_path, **file_record_from_bytes(files[record_path])},
        "package": {
            "root": "qazmorph",
            "files": package_files,
            "inventory_sha256": canonical_hash(package_files),
        },
        "modules": modules,
    }


def file_record_from_bytes(data: bytes) -> dict[str, Any]:
    return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def validate_frozen_wheel_receipt(
    value: Any,
    *,
    identity: dict[str, Any],
    wheel: Path,
    frozen_tree: dict[str, Any],
    frozen_inventory: list[dict[str, Any]],
    configuration: dict[str, Any],
) -> dict[str, Any]:
    """Bind a checked freezer's complete wheel read and package lineage audit."""

    receipt = _exact_object(
        value,
        {
            "build",
            "embedded_package",
            "frozen_tree",
            "input_consumption",
            "package",
            "pass",
            "provision",
            "record",
            "schema",
            "wheel",
        },
        "frozen wheel consumption receipt",
    )
    inventory = _wheel_package_inventory(wheel, identity=identity)
    consumption = _exact_object(
        receipt["input_consumption"],
        {
            "bytes_hashed_per_pass",
            "complete_sha256_passes",
            "record_verified",
            "source_fallbacks_disabled",
        },
        "frozen wheel input consumption",
    )
    embedded = _exact_object(
        receipt["embedded_package"],
        {
            "analysis_complete",
            "mechanism",
            "modules",
            "package_inventory_sha256",
            "source",
            "wheel",
            "wheel_path",
        },
        "frozen embedded package audit",
    )
    embedded_path = f"_internal/{identity['artifacts']['wheel']['filename']}"
    embedded_inventory = [
        item
        for item in frozen_inventory
        if item.get("path") == embedded_path and item.get("kind") == "file"
    ]
    if len(embedded_inventory) != 1:
        raise ReleaseError("frozen tree lacks one exact embedded canonical wheel")
    embedded_file = {
        key: embedded_inventory[0][key] for key in ("bytes", "sha256")
    }
    provision = _exact_object(
        receipt["provision"],
        {"invocation", "packages", "wheelhouse"},
        "frozen provision receipt",
    )
    build = _exact_object(
        receipt["build"],
        {"bootstrap", "invocation", "spec"},
        "frozen build receipt",
    )

    def validate_internal_invocation(
        candidate: Any,
        *,
        expected_argv: list[str],
        expected_environment: dict[str, str],
        label: str,
    ) -> None:
        invocation = _exact_object(
            candidate,
            {
                "argv",
                "containment",
                "environment",
                "exit_status",
                "observed_descendants",
                "stderr",
                "stdout",
                "timeout_seconds",
            },
            label,
        )
        if (
            invocation["argv"] != expected_argv
            or invocation["environment"] != expected_environment
            or invocation["exit_status"] != 0
            or invocation["timeout_seconds"] != configuration["timeout_seconds"]
            or invocation["containment"]
            not in {
                "linux-inherited-systemd-user-service-cgroup-v2+prctl-subreaper-proc-starttime-pidfd",
                "linux-systemd-user-slice-cgroup-v2+prctl-subreaper-proc-starttime-pidfd",
                "linux-prctl-subreaper-proc-starttime-pidfd",
                "posix-process-group-source-test-only",
            }
            or isinstance(invocation["observed_descendants"], bool)
            or not isinstance(invocation["observed_descendants"], int)
            or invocation["observed_descendants"] < 0
        ):
            raise ReleaseError(f"{label} command/environment differs")
        if sys.platform.startswith("linux") and not invocation[
            "containment"
        ].startswith(("linux-systemd-", "linux-inherited-systemd-")):
            raise ReleaseError(f"{label} lacks Linux kernel cgroup containment")
        _validate_stream(invocation["stdout"], f"{label}.stdout")
        _validate_stream(invocation["stderr"], f"{label}.stderr")

    base_environment = {
        **configuration["environment"],
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
    provision_environment = {
        **base_environment,
        "PYTHONPATH": "inputs/freezer-wheelhouse/"
        + configuration["bootstrap_pip"]["filename"],
    }
    provision_argv = [
        item.replace("{build_env}", "workspace/build-env")
        .replace("{wheelhouse}", "inputs/freezer-wheelhouse")
        .replace("{requirements}", configuration["requirements"]["path"])
        for item in configuration["provision_argv"]
    ]
    validate_internal_invocation(
        provision["invocation"],
        expected_argv=provision_argv,
        expected_environment=provision_environment,
        label="frozen provision invocation",
    )
    build_environment = {
        **base_environment,
        "PYTHONPATH": "workspace/build-env",
        "KAZSTEM_CANONICAL_WHEEL": "artifacts/"
        + identity["artifacts"]["wheel"]["filename"],
        "KAZSTEM_FROZEN_BOOTSTRAP": configuration["bootstrap"]["path"],
        "KAZSTEM_PYTHON_OPTIMIZE": configuration["python_optimize"],
    }
    build_argv = [
        item.replace("{dist}", "workspace/dist")
        .replace("{work}", "workspace/pyinstaller-work")
        .replace("{spec}", configuration["spec"]["path"])
        for item in configuration["build_argv"]
    ]
    validate_internal_invocation(
        build["invocation"],
        expected_argv=build_argv,
        expected_environment=build_environment,
        label="frozen PyInstaller invocation",
    )
    if (
        receipt["schema"] != "kazstem-frozen-wheel-consumption-receipt-v2"
        or receipt["pass"] is not True
        or receipt["wheel"]
        != {
            key: identity["artifacts"]["wheel"][key]
            for key in ("filename", "bytes", "sha256")
        }
        or receipt["record"] != inventory["record"]
        or receipt["package"] != inventory["package"]
        or receipt["frozen_tree"] != frozen_tree
        or consumption
        != {
            "bytes_hashed_per_pass": identity["artifacts"]["wheel"]["bytes"],
            "complete_sha256_passes": 2,
            "record_verified": True,
            "source_fallbacks_disabled": True,
        }
        or embedded
        != {
            "analysis_complete": True,
            "mechanism": "exact-canonical-wheel-data-import-v1",
            "modules": inventory["modules"],
            "package_inventory_sha256": inventory["package"]["inventory_sha256"],
            "source": "canonical-wheel-only",
            "wheel_path": embedded_path,
            "wheel": embedded_file,
        }
        or provision["packages"] != configuration["packages"]
        or provision["wheelhouse"] != configuration["wheelhouse"]
        or build["bootstrap"] != configuration["bootstrap"]
        or build["spec"] != configuration["spec"]
    ):
        raise ReleaseError("frozen wheel consumption/package audit differs")
    return receipt


def _clone_exact(
    *,
    repository: Path,
    checkout: Path,
    identity: dict[str, Any],
    git: Path,
    environment: dict[str, str],
    logical_root: str,
) -> dict[str, Any]:
    if checkout.exists() or checkout.is_symlink():
        raise ReleaseError(f"fresh checkout already exists: {logical_root}")
    clone = _run(
        [
            str(git),
            "clone",
            "--no-local",
            "--no-hardlinks",
            "--no-checkout",
            str(repository),
            str(checkout),
        ],
        logical_argv=[
            "git",
            "clone",
            "--no-local",
            "--no-hardlinks",
            "--no-checkout",
            "source-origin-cache",
            logical_root,
        ],
        cwd=checkout.parent,
        environment=environment,
    )
    commands = [clone]
    commands.append(
        _run(
            [str(git), "remote", "set-url", "origin", identity["source_origin"]],
            logical_argv=["git", "remote", "set-url", "origin", "source-origin"],
            cwd=checkout,
            environment=environment,
        )
    )
    commands.append(
        _run(
            [str(git), "checkout", "--detach", identity["source_commit"]],
            logical_argv=["git", "checkout", "--detach", identity["source_commit"]],
            cwd=checkout,
            environment=environment,
        )
    )
    observed_commit = subprocess.run(
        [str(git), "rev-parse", "HEAD"],
        cwd=checkout,
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        check=True,
    ).stdout.strip()
    observed_tree = subprocess.run(
        [str(git), "rev-parse", "HEAD^{tree}"],
        cwd=checkout,
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        check=True,
    ).stdout.strip()
    if (
        observed_commit != identity["source_commit"]
        or observed_tree != identity["source_tree"]
    ):
        raise ReleaseError("fresh checkout differs from the identity commit/tree")
    observed_ref = subprocess.run(
        [str(git), "rev-parse", f"{identity['source_ref']}^{{commit}}"],
        cwd=checkout,
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        check=True,
    ).stdout.strip()
    if observed_ref != identity["source_commit"]:
        raise ReleaseError("fresh checkout origin ref differs from source_commit")
    observed_tag_object = subprocess.run(
        [str(git), "rev-parse", identity["source_ref"]],
        cwd=checkout,
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        check=True,
    ).stdout.strip()
    observed_tag_type = subprocess.run(
        [str(git), "cat-file", "-t", identity["source_ref"]],
        cwd=checkout,
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        check=True,
    ).stdout.strip()
    if (
        observed_tag_object != identity["source_tag_object"]
        or observed_tag_type != "tag"
    ):
        raise ReleaseError("fresh checkout annotated tag object differs")
    status = subprocess.run(
        [
            str(git),
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
            "--ignored=matching",
        ],
        cwd=checkout,
        env=environment,
        stdout=subprocess.PIPE,
        check=True,
    ).stdout
    if status:
        raise ReleaseError("fresh checkout is unexpectedly dirty")
    return {
        "source_commit": observed_commit,
        "source_tree": observed_tree,
        "source_origin": identity["source_origin"],
        "source_ref": identity["source_ref"],
        "source_tag_object": observed_tag_object,
        "commands": commands,
    }


def _git_value(
    git: Path, repository: Path, environment: dict[str, str], arguments: list[str]
) -> str:
    try:
        completed = run_bounded(
            [str(git), *arguments],
            cwd=repository,
            environment=environment,
            timeout=60,
            max_stdout=64 * 1024,
            max_stderr=64 * 1024,
        )
    except SupervisionError as exc:
        raise ReleaseError(f"seed Git command supervision failed: {arguments}") from exc
    if completed.returncode != 0:
        raise ReleaseError(f"seed Git command failed: {arguments}")
    try:
        return completed.stdout.decode("utf-8").strip()
    except UnicodeError as exc:
        raise ReleaseError("seed Git command output is not UTF-8") from exc


def _verify_seed_repository(
    repository: Path,
    *,
    identity: dict[str, Any],
    git: Path,
    environment: dict[str, str],
) -> None:
    checks = (
        (["rev-parse", "HEAD"], identity["source_commit"]),
        (["rev-parse", "HEAD^{tree}"], identity["source_tree"]),
        (["remote", "get-url", "origin"], identity["source_origin"]),
        (["rev-parse", identity["source_ref"]], identity["source_tag_object"]),
        (["rev-parse", f"{identity['source_ref']}^{{commit}}"], identity["source_commit"]),
        (["cat-file", "-t", identity["source_ref"]], "tag"),
    )
    if any(
        _git_value(git, repository, environment, arguments) != expected
        for arguments, expected in checks
    ):
        raise ReleaseError("seed repository commit/tree/origin/tag differs")
    if _git_value(
        git,
        repository,
        environment,
        [
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
            "--ignored=matching",
        ],
    ):
        raise ReleaseError("seed repository is dirty")


def _exact_object(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise ReleaseError(f"{label} fields differ")
    return value


def _validate_stream(value: Any, label: str) -> None:
    stream = _exact_object(
        value, {"bytes", "lines", "sha256", "truncated"}, label
    )
    if (
        isinstance(stream["bytes"], bool)
        or not isinstance(stream["bytes"], int)
        or stream["bytes"] < 0
        or isinstance(stream["lines"], bool)
        or not isinstance(stream["lines"], int)
        or stream["lines"] < 0
        or not isinstance(stream["sha256"], str)
        or len(stream["sha256"]) != 64
        or stream["truncated"] is not False
    ):
        raise ReleaseError(f"{label} stream record is invalid")


def _validate_command_record(value: Any, expected_argv: list[str], label: str) -> None:
    command = _exact_object(
        value, {"argv", "exit_status", "stderr", "stdout"}, label
    )
    if command["argv"] != expected_argv or command["exit_status"] != 0:
        raise ReleaseError(f"{label} argv/exit differs")
    _validate_stream(command["stdout"], f"{label}.stdout")
    _validate_stream(command["stderr"], f"{label}.stderr")


def _validate_fresh_file(
    value: Any, *, expected: dict[str, Any] | None, label: str
) -> None:
    record = _exact_object(
        value,
        {"bytes", "created_by_command", "link_count", "sha256"},
        label,
    )
    if (
        record["created_by_command"] is not True
        or record["link_count"] != 1
        or isinstance(record["bytes"], bool)
        or not isinstance(record["bytes"], int)
        or record["bytes"] <= 0
        or not isinstance(record["sha256"], str)
        or len(record["sha256"]) != 64
        or (
            expected is not None
            and {"bytes": record["bytes"], "sha256": record["sha256"]}
            != {"bytes": expected["bytes"], "sha256": expected["sha256"]}
        )
    ):
        raise ReleaseError(f"{label} freshness/file identity differs")


def validate_reproducibility_payload(
    value: Any,
    *,
    identity: dict[str, Any],
    identity_contract_sha256: str,
    canonical_artifacts: Path,
) -> dict[str, Any]:
    """Strictly validate the full fresh-build payload and each receipt projection."""
    payload = _exact_object(
        value,
        {
            "adversarial_sdist_roundtrips",
            "builds",
            "canonical_artifacts",
            "canonical_python_identity",
            "configuration",
            "controlled_environment",
            "filesystem_aliases",
            "frozen_direct_builds",
            "identity_contract_sha256",
            "native_direct_assemblies",
            "native_reproduction_roots",
            "pass",
            "release",
            "schema",
            "sdist_direct_builds",
            "sdist_to_sdist_identity",
            "sdist_to_wheel_identity",
            "source_commit",
            "source_origin",
            "source_ref",
            "source_tag_object",
            "source_tree",
            "wheel_direct_builds",
        },
        "Python reproducibility payload",
    )
    configuration = identity["verification"]["reproducibility"]
    expected_count = configuration["build_roots"]
    if (
        payload["schema"] != "kazstem-python-artifact-reproducibility-v2"
        or payload["pass"] is not True
        or payload["release"] != identity["release"]
        or payload["source_commit"] != identity["source_commit"]
        or payload["source_tree"] != identity["source_tree"]
        or payload["source_origin"] != identity["source_origin"]
        or payload["source_ref"] != identity["source_ref"]
        or payload["source_tag_object"] != identity["source_tag_object"]
        or payload["identity_contract_sha256"] != identity_contract_sha256
        or payload["configuration"] != configuration
        or payload["canonical_artifacts"]
        != {
            "wheel": identity["artifacts"]["wheel"],
            "sdist": identity["artifacts"]["sdist"],
        }
        or payload["filesystem_aliases"] != []
        or payload["sdist_to_wheel_identity"] is not True
        or payload["sdist_to_sdist_identity"] is not True
        or any(
            payload[name] != expected_count
            for name in (
                "adversarial_sdist_roundtrips",
                "frozen_direct_builds",
                "native_direct_assemblies",
                "sdist_direct_builds",
                "wheel_direct_builds",
            )
        )
        or not isinstance(payload["builds"], list)
        or len(payload["builds"]) != expected_count
    ):
        raise ReleaseError("Python reproducibility top-level contract differs")
    expected_controlled = {
        **configuration["environment"],
        "HOME": "workspace/controlled-home",
        "GIT_CONFIG_GLOBAL": "disabled",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "PATH": "search-only; every selected executable is hash-bound",
    }
    if payload["controlled_environment"] != expected_controlled:
        raise ReleaseError("Python reproducibility controlled environment differs")
    with tempfile.TemporaryDirectory(prefix="kazstem-python-identity-validate-") as temporary:
        python_identity_path = Path(temporary) / "identity.json"
        python_identity_path.write_bytes(
            canonical_python_builder._json_bytes(payload["canonical_python_identity"])
        )
        try:
            python_identity = canonical_python_builder.load_identity(
                python_identity_path
            )
        except canonical_python_builder.BuildError as exc:
            raise ReleaseError(f"embedded canonical Python identity is invalid: {exc}") from exc
    if (
        python_identity["release"] != identity["release"]
        or python_identity["source_commit"] != identity["source_commit"]
        or python_identity["source_tree"] != identity["source_tree"]
        or python_identity["source_origin"] != identity["source_origin"]
        or python_identity["source_ref"] != identity["source_ref"]
        or python_identity["artifacts"]
        != {
            name: {
                "filename": identity["artifacts"][name]["filename"],
                "bytes": identity["artifacts"][name]["bytes"],
                "sha256": identity["artifacts"][name]["sha256"],
            }
            for name in ("wheel", "sdist")
        }
    ):
        raise ReleaseError("embedded canonical Python identity differs from release")

    expected_roots = [f"build-{index:02d}" for index in range(expected_count)]
    if payload["native_reproduction_roots"] != [
        f"{label}/native" for label in expected_roots
    ]:
        raise ReleaseError("native reproduction root labels differ")
    assembler_records = configuration["native_assemblers"]
    wheel = identity["artifacts"]["wheel"]
    sdist = identity["artifacts"]["sdist"]
    for index, build_value in enumerate(payload["builds"]):
        label = expected_roots[index]
        build = _exact_object(
            build_value,
            {
                "canonical_python_build",
                "checkout",
                "checkout_regular_files",
                "frozen_build",
                "native_assembly",
                "receipt",
                "root",
                "sdist",
                "wheel",
            },
            f"{label} build",
        )
        if build["root"] != label or (
            isinstance(build["checkout_regular_files"], bool)
            or not isinstance(build["checkout_regular_files"], int)
            or build["checkout_regular_files"] <= 0
        ):
            raise ReleaseError(f"{label} root/file inventory differs")
        checkout = _exact_object(
            build["checkout"],
            {
                "commands",
                "source_commit",
                "source_origin",
                "source_ref",
                "source_tag_object",
                "source_tree",
            },
            f"{label}.checkout",
        )
        if (
            checkout["source_commit"] != identity["source_commit"]
            or checkout["source_tree"] != identity["source_tree"]
            or checkout["source_origin"] != identity["source_origin"]
            or checkout["source_ref"] != identity["source_ref"]
            or checkout["source_tag_object"] != identity["source_tag_object"]
            or not isinstance(checkout["commands"], list)
            or len(checkout["commands"]) != 3
        ):
            raise ReleaseError(f"{label} checkout identity differs")
        expected_checkout_commands = [
            [
                "git", "clone", "--no-local", "--no-hardlinks", "--no-checkout",
                "source-origin-cache", f"{label}/checkout",
            ],
            ["git", "remote", "set-url", "origin", "source-origin"],
            ["git", "checkout", "--detach", identity["source_commit"]],
        ]
        for command_index, expected_argv in enumerate(expected_checkout_commands):
            _validate_command_record(
                checkout["commands"][command_index],
                expected_argv,
                f"{label}.checkout.commands[{command_index}]",
            )
        canonical_build = _exact_object(
            build["canonical_python_build"],
            {"command", "receipt", "receipt_payload"},
            f"{label}.canonical_python_build",
        )
        builder = configuration["canonical_python"]["builder"]
        expected_build_argv = [
            python_identity["build"]["tool"]["name"], "-I", "-S", builder["path"],
            "--identity", "inputs/PYTHON-BUILD-IDENTITY.json",
            "--source-checkout", f"{label}/checkout",
            "--wheelhouse", "inputs/python-wheelhouse",
            "--requirements", configuration["canonical_python"]["requirements_path"],
            "--interpreter-source",
            "inputs/interpreter-source/"
            + python_identity["interpreter_provenance"]["source_archive"]["filename"],
            "--workspace", f"{label}/python-primary",
            "--roundtrip-workspace", f"{label}/python-roundtrip",
            "--output-dir", f"{label}/python-dist",
            "--receipt", f"{label}/CANONICAL-PYTHON-BUILD-RECEIPT.json",
        ]
        _validate_command_record(
            canonical_build["command"], expected_build_argv, f"{label}.canonical command"
        )
        receipt_record = _exact_object(
            canonical_build["receipt"],
            {"bytes", "created_by_command", "link_count", "schema", "sha256"},
            f"{label}.canonical receipt file",
        )
        if receipt_record["schema"] != builder["receipt_schema"]:
            raise ReleaseError(f"{label} canonical receipt schema differs")
        _validate_fresh_file(
            {key: receipt_record[key] for key in ("bytes", "created_by_command", "link_count", "sha256")},
            expected=None,
            label=f"{label}.canonical receipt file",
        )
        try:
            canonical_python_builder.validate_receipt(
                canonical_build["receipt_payload"],
                identity=python_identity,
                output_dir=canonical_artifacts,
            )
        except canonical_python_builder.BuildError as exc:
            raise ReleaseError(f"{label} canonical receipt payload is invalid: {exc}") from exc
        _validate_fresh_file(build["wheel"], expected=wheel, label=f"{label}.wheel")
        _validate_fresh_file(build["sdist"], expected=sdist, label=f"{label}.sdist")
        frozen = _exact_object(
            build["frozen_build"],
            {
                "command",
                "created_by_command",
                "inventory",
                "receipt",
                "receipt_payload",
                "regular_files",
                "tree",
            },
            f"{label}.frozen_build",
        )
        expected_frozen_argv = [
            item
            for item in configuration["frozen_build_argv"]
        ]
        logical_frozen_replacements = {
            "{source_checkout}": f"{label}/checkout",
            "{wheel}": f"{label}/python-dist/{wheel['filename']}",
            "{freezer_wheelhouse}": "inputs/python-freezer-wheelhouse",
            "{freezer_workspace}": f"{label}/freezer-work",
            "{frozen}": f"{label}/frozen",
            "{frozen_receipt}": f"{label}/FROZEN-WHEEL-CONSUMPTION.json",
        }
        for index, item in enumerate(expected_frozen_argv):
            for marker, replacement in logical_frozen_replacements.items():
                item = item.replace(marker, replacement)
            expected_frozen_argv[index] = item
        _validate_command_record(
            frozen["command"], expected_frozen_argv, f"{label}.frozen command"
        )
        if (
            frozen["created_by_command"] is not True
            or frozen["tree"] != identity["inputs"]["frozen_tree"]
            or not isinstance(frozen["inventory"], list)
            or canonical_hash(frozen["inventory"]) != frozen["tree"]["sha256"]
            or len(frozen["inventory"]) != frozen["tree"]["entries"]
            or sum(item.get("bytes", 0) for item in frozen["inventory"])
            != frozen["tree"]["regular_file_bytes"]
            or isinstance(frozen["regular_files"], bool)
            or not isinstance(frozen["regular_files"], int)
            or frozen["regular_files"] <= 0
        ):
            raise ReleaseError(f"{label} frozen output proof differs")
        frozen_receipt_record = _exact_object(
            frozen["receipt"],
            {"bytes", "created_by_command", "link_count", "schema", "sha256"},
            f"{label}.frozen receipt file",
        )
        if (
            frozen_receipt_record["schema"]
            != configuration["frozen_builder"]["receipt_schema"]
        ):
            raise ReleaseError(f"{label} frozen receipt schema differs")
        _validate_fresh_file(
            {
                key: frozen_receipt_record[key]
                for key in ("bytes", "created_by_command", "link_count", "sha256")
            },
            expected=None,
            label=f"{label}.frozen receipt file",
        )
        validate_frozen_wheel_receipt(
            frozen["receipt_payload"],
            identity=identity,
            wheel=canonical_artifacts / wheel["filename"],
            frozen_tree=frozen["tree"],
            frozen_inventory=frozen["inventory"],
            configuration=configuration["frozen_builder"],
        )
        assembly = _exact_object(
            build["native_assembly"], {"ready_run", "source"}, f"{label}.assembly"
        )
        for assembly_name, artifact_name in (
            ("source", "corresponding_source"),
            ("ready_run", "ready_run"),
        ):
            section = _exact_object(
                assembly[assembly_name],
                {"artifact", "canonical_tar_producer", "command", "release_common", "tool"},
                f"{label}.assembly.{assembly_name}",
            )
            if (
                section["tool"] != assembler_records[assembly_name]
                or section["release_common"] != assembler_records["release_common"]
            ):
                raise ReleaseError(f"{label} assembler tool identity differs")
            expected_assembly_argv = (
                [
                    "python3", assembler_records["source"]["path"],
                    "--identity", "release-identity.json",
                    "--repository", f"{label}/checkout",
                    "--payload", "inputs/source-payload",
                    "--source-readme-template", "inputs/CORRESPONDING-SOURCE-README.template.md",
                    "--wheel", f"{label}/python-dist/{wheel['filename']}",
                    "--sdist", f"{label}/python-dist/{sdist['filename']}",
                    "--work-root", f"{label}/native-work/source-work",
                    "--output", f"{label}/native/{identity['artifacts']['corresponding_source']['filename']}",
                    "--raw-tar-output", f"{label}/canonical/{identity['verification']['compression']['targets'][0 if identity['verification']['compression']['targets'][0]['artifact'] == 'corresponding_source' else 1]['input']['filename']}",
                    "--producer-receipt", f"{label}/producer-receipts/corresponding-source-tar-producer.json",
                ]
                if assembly_name == "source"
                else [
                    "python3", assembler_records["ready_run"]["path"],
                    "--identity", "release-identity.json",
                    "--frozen", f"{label}/frozen",
                    "--resources", "inputs/resources",
                    "--runtime", "inputs/runtime",
                    "--documents", "inputs/documents",
                    "--binary-readme-template", "inputs/BINARY-README.template.md",
                    "--base-ledger", "inputs/base-ledger.json",
                    "--wheel", f"{label}/python-dist/{wheel['filename']}",
                    "--sdist", f"{label}/python-dist/{sdist['filename']}",
                    "--corresponding-source", f"{label}/native/{identity['artifacts']['corresponding_source']['filename']}",
                    "--work-root", f"{label}/native-work/ready-work",
                    "--output", f"{label}/native/{identity['artifacts']['ready_run']['filename']}",
                    "--raw-tar-output", f"{label}/canonical/{identity['verification']['compression']['targets'][0 if identity['verification']['compression']['targets'][0]['artifact'] == 'ready_run' else 1]['input']['filename']}",
                    "--producer-receipt", f"{label}/producer-receipts/ready-run-tar-producer.json",
                ]
            )
            _validate_command_record(
                section["command"],
                expected_assembly_argv,
                f"{label}.assembly.{assembly_name}.command",
            )
            _validate_fresh_file(
                section["artifact"],
                expected=identity["artifacts"][artifact_name],
                label=f"{label}.assembly.{assembly_name}.artifact",
            )
            producer = _exact_object(
                section["canonical_tar_producer"],
                {"raw_tar", "receipt", "receipt_file"},
                f"{label}.assembly.{assembly_name}.producer",
            )
            validated_producer = validate_tar_producer_receipt(
                producer["receipt"],
                identity=identity,
                identity_contract_sha256=identity_contract_sha256,
                artifact=artifact_name,
                raw_tar=None,
            )
            if validated_producer != producer["receipt"]:
                raise ReleaseError(f"{label} producer receipt normalization differs")
            target = next(
                item
                for item in identity["verification"]["compression"]["targets"]
                if item["artifact"] == artifact_name
            )
            _validate_fresh_file(
                producer["raw_tar"], expected=target["input"], label=f"{label}.raw tar"
            )
            _validate_fresh_file(
                producer["receipt_file"], expected=None, label=f"{label}.producer receipt"
            )
        root_receipt_record = _exact_object(
            build["receipt"],
            {"bytes", "created_by_command", "link_count", "path", "sha256"},
            f"{label}.root receipt record",
        )
        if root_receipt_record["path"] != f"{label}/native/REPRODUCTION-RECEIPT.json":
            raise ReleaseError(f"{label} root receipt path differs")
        _validate_fresh_file(
            {key: root_receipt_record[key] for key in ("bytes", "created_by_command", "link_count", "sha256")},
            expected=None,
            label=f"{label}.root receipt record",
        )
    assert_relative_json(payload, label="validated Python reproducibility payload")
    return payload


def verify(args: argparse.Namespace) -> dict[str, Any]:
    if args.output.exists() or args.output.is_symlink():
        raise ReleaseError(
            f"reproducibility output already exists: {args.output}"
        )
    if args.workspace.exists() or args.workspace.is_symlink():
        raise ReleaseError(f"reproducibility workspace must be fresh: {args.workspace}")
    output_paths = [
        ("reproducibility workspace", args.workspace),
        ("reproducibility report", args.output),
    ]
    input_paths = [
        ("release identity", args.identity),
        ("seed repository", args.repository),
        ("canonical artifacts", args.canonical_artifacts),
        ("canonical Python identity", args.python_build_identity),
        ("canonical Python wheelhouse", args.python_wheelhouse),
        ("Python freezer wheelhouse", args.python_freezer_wheelhouse),
        ("canonical interpreter source", args.python_interpreter_source),
        ("source payload", args.payload),
        ("resources", args.resources),
        ("runtime", args.runtime),
        ("documents", args.documents),
        ("binary README template", args.binary_readme_template),
        ("source README template", args.source_readme_template),
        ("base ledger", args.base_ledger),
    ]
    for output_label, output_path in output_paths:
        for input_label, input_path in input_paths:
            ensure_distinct_nonaliased_paths(
                output_path,
                input_path,
                labels=(output_label, input_label),
            )
    ensure_distinct_nonaliased_paths(
        args.workspace,
        args.output,
        labels=("reproducibility workspace", "reproducibility report"),
    )
    ensure_output_outside(
        args.output, args.workspace, label="reproducibility report output"
    )
    identity_path = args.identity.resolve(strict=True)
    identity = load_identity(identity_path)
    identity_digest = identity_sha256(identity_path)
    helper_records = {
        item["path"]: item["file"]
        for item in identity["verification"]["reproducibility"]["helpers"]
    }
    verify_file(
        Path(_common.__file__).resolve(strict=True),
        helper_records["packaging/linux/release_common.py"],
        label="loaded reproducibility release_common",
    )
    verify_file(
        Path(canonical_python_builder.__file__).resolve(strict=True),
        identity["verification"]["reproducibility"]["canonical_python"]["builder"]["file"],
        label="loaded canonical Python builder",
    )
    repository = args.repository.resolve(strict=True)
    canonical = args.canonical_artifacts.resolve(strict=True)
    for name in (
        "payload",
        "resources",
        "runtime",
        "documents",
    ):
        path = getattr(args, name)
        if path.is_symlink() or not path.is_dir():
            raise ReleaseError(f"reproducibility input root is invalid: {name}")
    for name in (
        "binary_readme_template",
        "source_readme_template",
        "base_ledger",
    ):
        path = getattr(args, name)
        if path.is_symlink() or not path.is_file():
            raise ReleaseError(f"reproducibility input file is invalid: {name}")
    wheel = identity["artifacts"]["wheel"]
    sdist = identity["artifacts"]["sdist"]
    canonical_wheel = canonical / wheel["filename"]
    canonical_sdist = canonical / sdist["filename"]
    verify_artifact(canonical_wheel, wheel, label="canonical wheel")
    verify_artifact(canonical_sdist, sdist, label="canonical sdist")

    configuration = identity["verification"]["reproducibility"]
    canonical_configuration = configuration["canonical_python"]
    if args.python_build_identity.is_symlink() or not args.python_build_identity.is_file():
        raise ReleaseError("canonical Python build identity is not a regular file")
    verify_file(
        args.python_build_identity,
        canonical_configuration["identity"]["file"],
        label="canonical Python build identity",
    )
    if args.python_wheelhouse.is_symlink() or not args.python_wheelhouse.is_dir():
        raise ReleaseError("canonical Python wheelhouse is not a real directory")
    if (
        args.python_freezer_wheelhouse.is_symlink()
        or not args.python_freezer_wheelhouse.is_dir()
    ):
        raise ReleaseError("Python freezer wheelhouse is not a real directory")
    if (
        args.python_interpreter_source.is_symlink()
        or not args.python_interpreter_source.is_file()
    ):
        raise ReleaseError("canonical interpreter source is not a regular file")
    verify_file(
        args.python_interpreter_source,
        canonical_configuration["interpreter_source"]["file"],
        label="canonical interpreter corresponding source",
    )
    payload_interpreter_source = args.payload.joinpath(
        *Path(canonical_configuration["interpreter_source"]["path"]).parts
    )
    verify_file(
        payload_interpreter_source,
        canonical_configuration["interpreter_source"]["file"],
        label="corresponding-source payload interpreter source",
    )
    verify_canonical_source_companions(args.payload.resolve(strict=True), identity)
    try:
        python_identity = canonical_python_builder.load_identity(
            args.python_build_identity
        )
    except canonical_python_builder.BuildError as exc:
        raise ReleaseError(f"canonical Python build identity is invalid: {exc}") from exc
    if (
        python_identity["schema"] != canonical_configuration["identity"]["schema"]
        or python_identity["release"] != identity["release"]
        or python_identity["source_commit"] != identity["source_commit"]
        or python_identity["source_tree"] != identity["source_tree"]
        or python_identity["source_origin"] != identity["source_origin"]
        or python_identity["source_ref"] != identity["source_ref"]
        or python_identity["source_date_epoch"] != identity["source_date_epoch"]
        or python_identity["artifacts"]
        != {
            name: {
                "filename": record["filename"],
                "bytes": record["bytes"],
                "sha256": record["sha256"],
            }
            for name, record in (("wheel", wheel), ("sdist", sdist))
        }
        or python_identity["canonicalizer"]
        != {
            "path": canonical_configuration["builder"]["path"],
            "file": canonical_configuration["builder"]["file"],
        }
        or python_identity["interpreter_provenance"]["corresponding_source_path"]
        != canonical_configuration["interpreter_source"]["path"]
        or python_identity["interpreter_provenance"]["source_archive"]["filename"]
        != args.python_interpreter_source.name
        or python_identity["interpreter_provenance"]["build_recipe"]
        != canonical_configuration["interpreter_build_recipe"]
        or python_identity["interpreter_provenance"]["license"]
        != canonical_configuration["interpreter_license"]
    ):
        raise ReleaseError("canonical Python identity differs from Linux release identity")
    if (
        python_identity["build_stack"]["requirements"]["path"]
        != canonical_configuration["requirements_path"]
        or python_identity["build_stack"]["requirements"]
        != canonical_configuration["requirements_file"]
        or python_identity["build_stack"]["wheelhouse"]["files"]
        != canonical_configuration["wheelhouse_files"]
        or python_identity["interpreter_provenance"]["runtime_closure"]["packages"]
        != canonical_configuration["runtime_packages"]
        or python_identity["interpreter_provenance"]["runtime_closure"][
            "source_packages"
        ]
        != canonical_configuration["runtime_source_packages"]
        or python_identity["build_stack"]["wheelhouse"]["manifest_sha256"]
        != canonical_configuration["wheelhouse_manifest_sha256"]
    ):
        raise ReleaseError("canonical Python build-stack binding differs")
    tool_records = {record["name"]: record for record in configuration["tools"]}
    tools = {
        name: _resolved_tool(name, record)
        for name, record in sorted(tool_records.items())
    }
    git = tools.get("git")
    if git is None:
        raise ReleaseError("reproducibility tool set must include git")
    python_tool_record = python_identity["build"]["tool"]
    if (
        python_identity["roundtrip"]["tool"] != python_tool_record
        or tool_records.get(python_tool_record["name"]) != python_tool_record
        or python_tool_record["name"] not in tools
    ):
        raise ReleaseError("canonical Python interpreter is not release-tool bound")
    python_tool = tools[python_tool_record["name"]]
    environment = {
        key: value for key, value in configuration["environment"].items()
    }
    workspace = args.workspace.absolute()
    workspace.mkdir(parents=True)
    home = workspace / "controlled-home"
    home.mkdir()
    pycache = workspace / "pycache"
    pycache.mkdir()
    environment.update(
        {
            "HOME": str(home),
            "PYTHONPYCACHEPREFIX": str(pycache),
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_TERMINAL_PROMPT": "0",
            "PATH": os.environ.get("PATH", os.defpath),
        }
    )
    _verify_seed_repository(
        repository, identity=identity, git=git, environment=environment
    )

    all_inodes: set[tuple[int, int]] = set()
    builds: list[dict[str, Any]] = []
    native_roots: list[str] = []
    for index in range(configuration["build_roots"]):
        _verify_seed_repository(
            repository, identity=identity, git=git, environment=environment
        )
        label = f"build-{index:02d}"
        build_root = workspace / label
        checkout = build_root / "checkout"
        build_root.mkdir()
        checkout_record = _clone_exact(
            repository=repository,
            checkout=checkout,
            identity=identity,
            git=git,
            environment=environment,
            logical_root=f"{label}/checkout",
        )
        checkout_files = _assert_unique_regular_files(checkout, all_inodes)
        dist = build_root / "python-dist"
        canonical_workspace = build_root / "python-primary"
        canonical_roundtrip = build_root / "python-roundtrip"
        canonical_receipt = build_root / "CANONICAL-PYTHON-BUILD-RECEIPT.json"
        builder_path = checkout.joinpath(
            *Path(canonical_configuration["builder"]["path"]).parts
        )
        verify_file(
            builder_path,
            canonical_configuration["builder"]["file"],
            label=f"{label} canonical Python builder",
        )
        actual_argv = [
            str(python_tool),
            "-I",
            "-S",
            str(builder_path),
            "--identity",
            str(args.python_build_identity.resolve(strict=True)),
            "--source-checkout",
            str(checkout),
            "--wheelhouse",
            str(args.python_wheelhouse.resolve(strict=True)),
            "--requirements",
            canonical_configuration["requirements_path"],
            "--interpreter-source",
            str(args.python_interpreter_source.resolve(strict=True)),
            "--workspace",
            str(canonical_workspace),
            "--roundtrip-workspace",
            str(canonical_roundtrip),
            "--output-dir",
            str(dist),
            "--receipt",
            str(canonical_receipt),
        ]
        logical_argv = [
            python_tool_record["name"],
            "-I",
            "-S",
            canonical_configuration["builder"]["path"],
            "--identity",
            "inputs/PYTHON-BUILD-IDENTITY.json",
            "--source-checkout",
            f"{label}/checkout",
            "--wheelhouse",
            "inputs/python-wheelhouse",
            "--requirements",
            canonical_configuration["requirements_path"],
            "--interpreter-source",
            "inputs/interpreter-source/" + args.python_interpreter_source.name,
            "--workspace",
            f"{label}/python-primary",
            "--roundtrip-workspace",
            f"{label}/python-roundtrip",
            "--output-dir",
            f"{label}/python-dist",
            "--receipt",
            f"{label}/CANONICAL-PYTHON-BUILD-RECEIPT.json",
        ]
        start_ns = time.time_ns()
        build_command = _run(
            actual_argv,
            logical_argv=logical_argv,
            cwd=checkout,
            environment=environment,
        )
        built_wheel = dist / wheel["filename"]
        built_sdist = dist / sdist["filename"]
        verify_artifact(built_wheel, wheel, label=f"{label} wheel")
        verify_artifact(built_sdist, sdist, label=f"{label} sdist")
        canonical_receipt_value = read_json(canonical_receipt)
        try:
            canonical_python_builder.validate_receipt(
                canonical_receipt_value,
                identity=python_identity,
                output_dir=dist,
            )
        except canonical_python_builder.BuildError as exc:
            raise ReleaseError(
                f"{label} canonical Python receipt is invalid: {exc}"
            ) from exc
        canonical_receipt_record = _artifact_freshness(
            canonical_receipt, start_ns=start_ns, inodes=all_inodes
        )
        wheel_freshness = _artifact_freshness(
            built_wheel, start_ns=start_ns, inodes=all_inodes
        )
        sdist_freshness = _artifact_freshness(
            built_sdist, start_ns=start_ns, inodes=all_inodes
        )

        frozen = build_root / "frozen"
        frozen_receipt = build_root / "FROZEN-WHEEL-CONSUMPTION.json"
        freezer_workspace = build_root / "freezer-work"
        frozen_builder = checkout.joinpath(
            *Path(configuration["frozen_builder"]["path"]).parts
        )
        verify_file(
            frozen_builder,
            configuration["frozen_builder"]["file"],
            label=f"{label} frozen builder",
        )
        frozen_configured = configuration["frozen_build_argv"]
        frozen_actual_replacements = {
            "release-identity.json": str(identity_path),
            "{source_checkout}": str(checkout),
            "{wheel}": str(built_wheel),
            "{freezer_wheelhouse}": str(
                args.python_freezer_wheelhouse.resolve(strict=True)
            ),
            "{freezer_workspace}": str(freezer_workspace),
            "{frozen}": str(frozen),
            "{frozen_receipt}": str(frozen_receipt),
        }
        frozen_argv = []
        for configured_item in frozen_configured:
            actual_item = configured_item
            for marker, replacement in frozen_actual_replacements.items():
                actual_item = actual_item.replace(marker, replacement)
            frozen_argv.append(actual_item)
        frozen_argv[0] = str(tools[frozen_configured[0]])
        frozen_logical_replacements = {
            "{source_checkout}": f"{label}/checkout",
            "{wheel}": f"{label}/python-dist/{wheel['filename']}",
            "{freezer_wheelhouse}": "inputs/python-freezer-wheelhouse",
            "{freezer_workspace}": f"{label}/freezer-work",
            "{frozen}": f"{label}/frozen",
            "{frozen_receipt}": f"{label}/FROZEN-WHEEL-CONSUMPTION.json",
        }
        frozen_logical_argv = []
        for configured_item in frozen_configured:
            logical_item = configured_item
            for marker, replacement in frozen_logical_replacements.items():
                logical_item = logical_item.replace(marker, replacement)
            frozen_logical_argv.append(logical_item)
        if (
            frozen.exists()
            or frozen.is_symlink()
            or frozen_receipt.exists()
            or frozen_receipt.is_symlink()
            or freezer_workspace.exists()
            or freezer_workspace.is_symlink()
        ):
            raise ReleaseError("frozen-build output/receipt existed before command execution")
        frozen_start_ns = time.time_ns()
        frozen_command = _run(
            frozen_argv,
            logical_argv=frozen_logical_argv,
            cwd=checkout,
            environment=environment,
        )
        verify_tree(
            frozen,
            identity["inputs"]["frozen_tree"],
            label=f"{label} independently built frozen launcher",
        )
        frozen_tree_record = tree_record(frozen)
        frozen_inventory_record = tree_inventory(frozen)
        frozen_receipt_value = read_json(frozen_receipt)
        validate_frozen_wheel_receipt(
            frozen_receipt_value,
            identity=identity,
            wheel=built_wheel,
            frozen_tree=frozen_tree_record,
            frozen_inventory=frozen_inventory_record,
            configuration=configuration["frozen_builder"],
        )
        frozen_receipt_freshness = _artifact_freshness(
            frozen_receipt, start_ns=frozen_start_ns, inodes=all_inodes
        )
        frozen_files = _assert_unique_regular_files(frozen, all_inodes)
        if any(
            path.stat().st_ctime_ns < frozen_start_ns
            for path in frozen.rglob("*")
            if path.is_file() and not path.is_symlink()
        ):
            raise ReleaseError("frozen launcher contains a file predating its build")

        native = build_root / "native"
        native.mkdir()
        native_work = build_root / "native-work"
        assembler_records = configuration["native_assemblers"]
        checked_assemblers: dict[str, Path] = {}
        for assembler_name in ("release_common", "source", "ready_run"):
            assembler_record = assembler_records[assembler_name]
            assembler_path = checkout.joinpath(*Path(assembler_record["path"]).parts)
            verify_file(
                assembler_path,
                assembler_record["file"],
                label=f"{label} {assembler_name} assembler input",
            )
            checked_assemblers[assembler_name] = assembler_path
        source_path = native / identity["artifacts"]["corresponding_source"]["filename"]
        source_target = next(
            item
            for item in identity["verification"]["compression"]["targets"]
            if item["artifact"] == "corresponding_source"
        )
        source_raw_tar = build_root / "canonical" / source_target["input"]["filename"]
        source_producer_receipt = (
            build_root / "producer-receipts/corresponding-source-tar-producer.json"
        )
        source_actual_argv = [
            str(python_tool),
            str(checked_assemblers["source"]),
            "--identity", str(identity_path),
            "--repository", str(checkout),
            "--payload", str(args.payload.resolve(strict=True)),
            "--source-readme-template", str(args.source_readme_template.resolve(strict=True)),
            "--wheel", str(built_wheel),
            "--sdist", str(built_sdist),
            "--work-root", str(native_work / "source-work"),
            "--output", str(source_path),
            "--raw-tar-output", str(source_raw_tar),
            "--producer-receipt", str(source_producer_receipt),
        ]
        source_logical_argv = [
            python_tool_record["name"],
            assembler_records["source"]["path"],
            "--identity", "release-identity.json",
            "--repository", f"{label}/checkout",
            "--payload", "inputs/source-payload",
            "--source-readme-template", "inputs/CORRESPONDING-SOURCE-README.template.md",
            "--wheel", f"{label}/python-dist/{wheel['filename']}",
            "--sdist", f"{label}/python-dist/{sdist['filename']}",
            "--work-root", f"{label}/native-work/source-work",
            "--output", f"{label}/native/{source_path.name}",
            "--raw-tar-output", f"{label}/canonical/{source_raw_tar.name}",
            "--producer-receipt", f"{label}/producer-receipts/corresponding-source-tar-producer.json",
        ]
        source_assembly_command = _run(
            source_actual_argv,
            logical_argv=source_logical_argv,
            cwd=checkout,
            environment=environment,
        )
        ready_path = native / identity["artifacts"]["ready_run"]["filename"]
        ready_target = next(
            item
            for item in identity["verification"]["compression"]["targets"]
            if item["artifact"] == "ready_run"
        )
        ready_raw_tar = build_root / "canonical" / ready_target["input"]["filename"]
        ready_producer_receipt = build_root / "producer-receipts/ready-run-tar-producer.json"
        ready_actual_argv = [
            str(python_tool),
            str(checked_assemblers["ready_run"]),
            "--identity", str(identity_path),
            "--frozen", str(frozen),
            "--resources", str(args.resources.resolve(strict=True)),
            "--runtime", str(args.runtime.resolve(strict=True)),
            "--documents", str(args.documents.resolve(strict=True)),
            "--binary-readme-template", str(args.binary_readme_template.resolve(strict=True)),
            "--base-ledger", str(args.base_ledger.resolve(strict=True)),
            "--wheel", str(built_wheel),
            "--sdist", str(built_sdist),
            "--corresponding-source", str(source_path),
            "--work-root", str(native_work / "ready-work"),
            "--output", str(ready_path),
            "--raw-tar-output", str(ready_raw_tar),
            "--producer-receipt", str(ready_producer_receipt),
        ]
        ready_logical_argv = [
            python_tool_record["name"],
            assembler_records["ready_run"]["path"],
            "--identity", "release-identity.json",
            "--frozen", f"{label}/frozen",
            "--resources", "inputs/resources",
            "--runtime", "inputs/runtime",
            "--documents", "inputs/documents",
            "--binary-readme-template", "inputs/BINARY-README.template.md",
            "--base-ledger", "inputs/base-ledger.json",
            "--wheel", f"{label}/python-dist/{wheel['filename']}",
            "--sdist", f"{label}/python-dist/{sdist['filename']}",
            "--corresponding-source", f"{label}/native/{source_path.name}",
            "--work-root", f"{label}/native-work/ready-work",
            "--output", f"{label}/native/{ready_path.name}",
            "--raw-tar-output", f"{label}/canonical/{ready_raw_tar.name}",
            "--producer-receipt", f"{label}/producer-receipts/ready-run-tar-producer.json",
        ]
        ready_assembly_command = _run(
            ready_actual_argv,
            logical_argv=ready_logical_argv,
            cwd=checkout,
            environment=environment,
        )
        source_producer_value = validate_tar_producer_receipt(
            read_json(source_producer_receipt),
            identity=identity,
            identity_contract_sha256=identity_digest,
            artifact="corresponding_source",
            raw_tar=source_raw_tar,
        )
        ready_producer_value = validate_tar_producer_receipt(
            read_json(ready_producer_receipt),
            identity=identity,
            identity_contract_sha256=identity_digest,
            artifact="ready_run",
            raw_tar=ready_raw_tar,
        )
        source_raw_freshness = _artifact_freshness(
            source_raw_tar, start_ns=start_ns, inodes=all_inodes
        )
        ready_raw_freshness = _artifact_freshness(
            ready_raw_tar, start_ns=start_ns, inodes=all_inodes
        )
        source_producer_freshness = _artifact_freshness(
            source_producer_receipt, start_ns=start_ns, inodes=all_inodes
        )
        ready_producer_freshness = _artifact_freshness(
            ready_producer_receipt, start_ns=start_ns, inodes=all_inodes
        )
        source_freshness = _artifact_freshness(
            source_path, start_ns=start_ns, inodes=all_inodes
        )
        ready_freshness = _artifact_freshness(
            ready_path, start_ns=start_ns, inodes=all_inodes
        )
        native_roots.append(f"{label}/native")
        build_entry = {
            "root": label,
            "checkout": checkout_record,
            "checkout_regular_files": checkout_files,
            "canonical_python_build": {
                "command": build_command,
                "receipt": {
                    "schema": canonical_configuration["builder"]["receipt_schema"],
                    **canonical_receipt_record,
                },
                "receipt_payload": canonical_receipt_value,
            },
            "frozen_build": {
                "command": frozen_command,
                "tree": frozen_tree_record,
                "inventory": frozen_inventory_record,
                "regular_files": frozen_files,
                "created_by_command": True,
                "receipt": {
                    "schema": configuration["frozen_builder"]["receipt_schema"],
                    **frozen_receipt_freshness,
                },
                "receipt_payload": frozen_receipt_value,
            },
            "wheel": wheel_freshness,
            "sdist": sdist_freshness,
            "native_assembly": {
                "source": {
                    "command": source_assembly_command,
                    "tool": assembler_records["source"],
                    "release_common": assembler_records["release_common"],
                    "artifact": source_freshness,
                    "canonical_tar_producer": {
                        "receipt": source_producer_value,
                        "receipt_file": source_producer_freshness,
                        "raw_tar": source_raw_freshness,
                    },
                },
                "ready_run": {
                    "command": ready_assembly_command,
                    "tool": assembler_records["ready_run"],
                    "release_common": assembler_records["release_common"],
                    "artifact": ready_freshness,
                    "canonical_tar_producer": {
                        "receipt": ready_producer_value,
                        "receipt_file": ready_producer_freshness,
                        "raw_tar": ready_raw_freshness,
                    },
                },
            },
        }
        receipt = {
            "schema": "kazstem-reproduction-root-receipt-v1",
            "release": identity["release"],
            "source_commit": identity["source_commit"],
            "source_tree": identity["source_tree"],
            "source_ref": identity["source_ref"],
            "source_tag_object": identity["source_tag_object"],
            "identity_contract_sha256": identity_digest,
            "root": label,
            "checkout": checkout_record,
            "python_build": build_entry["canonical_python_build"],
            "frozen_build": build_entry["frozen_build"],
            "assembly": build_entry["native_assembly"],
            "bound_inputs": {
                name: identity["inputs"][name]
                for name in (
                    "frozen_tree",
                    "resource_tree",
                    "runtime_tree",
                    "source_payload_tree",
                    "git_archive",
                )
            },
            "artifacts": {
                "corresponding_source": identity["artifacts"][
                    "corresponding_source"
                ],
                "ready_run": identity["artifacts"]["ready_run"],
                "sdist": identity["artifacts"]["sdist"],
                "wheel": identity["artifacts"]["wheel"],
            },
            "commands_succeeded": True,
            "filesystem_aliases": [],
        }
        assert_relative_json(receipt, label=f"{label} reproduction receipt")
        receipt_path = native / "REPRODUCTION-RECEIPT.json"
        receipt_path.write_bytes(json_bytes(receipt))
        build_entry["receipt"] = {
            "path": f"{label}/native/REPRODUCTION-RECEIPT.json",
            **_artifact_freshness(
                receipt_path, start_ns=start_ns, inodes=all_inodes
            ),
        }
        builds.append(build_entry)

    _verify_seed_repository(
        repository, identity=identity, git=git, environment=environment
    )

    result = {
        "schema": "kazstem-python-artifact-reproducibility-v2",
        "pass": True,
        "release": identity["release"],
        "source_commit": identity["source_commit"],
        "source_tree": identity["source_tree"],
        "source_origin": identity["source_origin"],
        "source_ref": identity["source_ref"],
        "source_tag_object": identity["source_tag_object"],
        "identity_contract_sha256": identity_digest,
        "configuration": configuration,
        "controlled_environment": {
            **configuration["environment"],
            "HOME": "workspace/controlled-home",
            "GIT_CONFIG_GLOBAL": "disabled",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_TERMINAL_PROMPT": "0",
            "PATH": "search-only; every selected executable is hash-bound",
        },
        "wheel_direct_builds": len(builds),
        "sdist_direct_builds": len(builds),
        "frozen_direct_builds": len(builds),
        "native_direct_assemblies": len(builds),
        "sdist_to_wheel_identity": True,
        "sdist_to_sdist_identity": True,
        "adversarial_sdist_roundtrips": len(builds),
        "canonical_artifacts": {"wheel": wheel, "sdist": sdist},
        "canonical_python_identity": python_identity,
        "builds": builds,
        "native_reproduction_roots": native_roots,
        "filesystem_aliases": [],
    }
    validate_reproducibility_payload(
        result,
        identity=identity,
        identity_contract_sha256=identity_digest,
        canonical_artifacts=canonical,
    )
    assert_relative_json(result, label="Python reproducibility report")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(json_bytes(result))
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--identity", required=True, type=Path)
    parser.add_argument("--repository", required=True, type=Path)
    parser.add_argument("--canonical-artifacts", required=True, type=Path)
    parser.add_argument("--python-build-identity", required=True, type=Path)
    parser.add_argument("--python-wheelhouse", required=True, type=Path)
    parser.add_argument("--python-freezer-wheelhouse", required=True, type=Path)
    parser.add_argument("--python-interpreter-source", required=True, type=Path)
    parser.add_argument("--payload", required=True, type=Path)
    parser.add_argument("--resources", required=True, type=Path)
    parser.add_argument("--runtime", required=True, type=Path)
    parser.add_argument("--documents", required=True, type=Path)
    parser.add_argument("--binary-readme-template", required=True, type=Path)
    parser.add_argument("--source-readme-template", required=True, type=Path)
    parser.add_argument("--base-ledger", required=True, type=Path)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    result = verify(args)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ReleaseError, OSError, ValueError, json.JSONDecodeError) as exc:
        raise SystemExit(f"error: {exc}") from exc
