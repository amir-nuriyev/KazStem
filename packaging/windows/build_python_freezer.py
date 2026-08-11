#!/usr/bin/env python3
"""Build wheel, sdist, and PyInstaller tree in one fresh Windows root."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import platform
import shutil
import sys
from typing import Any

from bounded_windows_process import BoundedProcessError, run_bounded

from release_common import (
    ReleaseError,
    artifact_record,
    copy_tree_exact,
    file_record,
    files_equal,
    json_bytes,
    load_identity,
    pe_identity,
    read_json,
    release_bootstrap_prefix,
    require_release_bootstrap,
    tree_record,
    verify_artifact,
    verify_canonical_python_release,
    verify_file,
    verify_python_build_receipt,
    verify_source_receipt,
    verify_source_execution_receipt,
    verify_release_support_files,
    verify_tree,
)


CREATE_NO_WINDOW = 0x08000000


def logical_environment(identity: dict[str, Any]) -> dict[str, str]:
    return {
        "COMSPEC": "<SYSTEM32>/cmd.exe",
        "HOME": "<FRESH-BUILD-ROOT>/home",
        "LC_ALL": "C",
        "PATH": "<BOOTSTRAP-PYTHON-DIR>;<SYSTEM32>;<WINDOWS>",
        "PATHEXT": ".COM;.EXE;.BAT;.CMD",
        "PIP_DISABLE_PIP_VERSION_CHECK": "1",
        "PIP_FIND_LINKS": "<WHEELHOUSE>",
        "PIP_NO_INDEX": "1",
        "PIP_NO_INPUT": "1",
        "PYINSTALLER_CONFIG_DIR": "<FRESH-BUILD-ROOT>/pyinstaller-cache",
        "PYTHONHASHSEED": "0",
        "PYTHONNOUSERSITE": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "SOURCE_DATE_EPOCH": str(identity["source_date_epoch"]),
        "SYSTEMROOT": "<WINDOWS>",
        "TEMP": "<FRESH-BUILD-ROOT>/tmp",
        "TMP": "<FRESH-BUILD-ROOT>/tmp",
        "TZ": "UTC",
        "USERPROFILE": "<FRESH-BUILD-ROOT>/home",
        "WINDIR": "<WINDOWS>",
    }


def actual_environment(
    identity: dict[str, Any], root: Path, bootstrap: Path, wheelhouse: Path
) -> dict[str, str]:
    windows = Path(os.environ.get("SystemRoot", r"C:\Windows")).resolve(strict=True)
    system32 = windows / "System32"
    temporary = root / "tmp"
    home = root / "home"
    for path in (temporary, home, root / "pyinstaller-cache"):
        path.mkdir(parents=True, exist_ok=True)
    return {
        "ComSpec": str(system32 / "cmd.exe"),
        "HOME": str(home),
        "LC_ALL": "C",
        "PATH": os.pathsep.join([str(bootstrap.parent), str(system32), str(windows)]),
        "PATHEXT": ".COM;.EXE;.BAT;.CMD",
        "PIP_DISABLE_PIP_VERSION_CHECK": "1",
        "PIP_FIND_LINKS": str(wheelhouse),
        "PIP_NO_INDEX": "1",
        "PIP_NO_INPUT": "1",
        "PYINSTALLER_CONFIG_DIR": str(root / "pyinstaller-cache"),
        "PYTHONHASHSEED": "0",
        "PYTHONNOUSERSITE": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "SOURCE_DATE_EPOCH": str(identity["source_date_epoch"]),
        "SystemRoot": str(windows),
        "TEMP": str(temporary),
        "TMP": str(temporary),
        "TZ": "UTC",
        "USERPROFILE": str(home),
        "WINDIR": str(windows),
    }


def run(command: list[str], *, cwd: Path, environment: dict[str, str], timeout: float = 900) -> None:
    completed = run_bounded(
        command,
        cwd=cwd,
        environment=environment,
        timeout_seconds=timeout,
    )
    if completed.returncode:
        raise ReleaseError(
            f"build command failed ({completed.returncode}): {completed.stdout.decode('utf-8', 'replace')[-8000:]}"
        )


def query_tools(python: Path, *, cwd: Path, environment: dict[str, str]) -> dict[str, str]:
    code = (
        "import json,platform,zlib,pip,build,setuptools,wheel,PyInstaller;"
        "print(json.dumps({'python':platform.python_version(),'pip':pip.__version__,"
        "'build':build.__version__,'setuptools':setuptools.__version__,'wheel':wheel.__version__,"
        "'pyinstaller':PyInstaller.__version__,'zlib':zlib.ZLIB_RUNTIME_VERSION},sort_keys=True))"
    )
    completed = run_bounded(
        [str(python), "-c", code],
        cwd=cwd,
        environment=environment,
        timeout_seconds=60,
        output_limit_bytes=1024 * 1024,
    )
    if completed.returncode:
        raise ReleaseError(f"cannot query pinned build tools: {completed.stdout.decode('utf-8', 'replace')}")
    value = json.loads(completed.stdout.decode("utf-8", "strict"))
    if not isinstance(value, dict):
        raise ReleaseError("build tool query returned no object")
    return value


def main() -> int:
    boundary = require_release_bootstrap(
        "packaging/windows/build_python_freezer.py"
    )
    parser = argparse.ArgumentParser()
    parser.add_argument("--identity", required=True, type=Path)
    parser.add_argument("--label", choices=("a", "b"), required=True)
    parser.add_argument("--mode", choices=("observe", "verify"), required=True)
    parser.add_argument("--bootstrap-python", required=True, type=Path)
    parser.add_argument("--source-payload", required=True, type=Path)
    parser.add_argument("--source-receipt", required=True, type=Path)
    parser.add_argument("--wheelhouse", required=True, type=Path)
    parser.add_argument("--requirements", required=True, type=Path)
    parser.add_argument("--python-build-identity", required=True, type=Path)
    parser.add_argument("--python-build-receipt", required=True, type=Path)
    parser.add_argument("--canonical-wheel", required=True, type=Path)
    parser.add_argument("--canonical-sdist", required=True, type=Path)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--build-root", required=True, type=Path)
    parser.add_argument("--receipt", required=True, type=Path)
    args = parser.parse_args()
    if sys.platform != "win32" or platform.machine().casefold() not in {"amd64", "x86_64"}:
        raise ReleaseError("Python/freezer builds require native Windows x86-64")
    identity_path = args.identity.resolve(strict=True)
    identity = load_identity(identity_path)
    running_source_root = Path(__file__).resolve(strict=True).parents[2]
    verify_release_support_files(identity, running_source_root)
    bootstrap = args.bootstrap_python.resolve(strict=True)
    if not Path(sys.executable).resolve(strict=True).samefile(bootstrap):
        raise ReleaseError("builder must itself run under the bound bootstrap Python")
    if pe_identity(bootstrap) != identity["inputs"]["bootstrap_python"]:
        raise ReleaseError("bootstrap Python bytes/AMD64 PE identity differ from release identity")
    if platform.python_version() != identity["platform"]["python"]:
        raise ReleaseError("bootstrap Python version differs from release identity")
    payload = args.source_payload.resolve(strict=True)
    verify_tree(payload, identity["inputs"]["source_payload_tree"], label="materialized Git source")
    source_receipt = args.source_receipt.resolve(strict=True)
    verify_file(source_receipt, identity["inputs"]["source_receipt"], label="source receipt")
    verify_source_receipt(read_json(source_receipt), identity)
    source_materialization_root = payload.parent
    source_execution_receipt = (
        source_materialization_root / "MATERIALIZATION-EXECUTION.json"
    ).resolve(strict=True)
    verify_source_execution_receipt(
        read_json(source_execution_receipt),
        identity,
        label=args.label,
        materialization_root=source_materialization_root,
        payload=payload,
        canonical_receipt=source_receipt,
    )
    requirements = args.requirements.resolve(strict=True)
    if not files_equal(requirements, payload / "packaging/windows/build-requirements.lock.txt"):
        raise ReleaseError("build requirements differ from exact materialized Git source")
    wheelhouse = args.wheelhouse.resolve(strict=True)
    verify_tree(
        wheelhouse,
        identity["inputs"]["build_wheelhouse_tree"],
        label="offline freezer wheelhouse",
    )
    python_build_identity = args.python_build_identity.resolve(strict=True)
    verify_file(
        python_build_identity,
        identity["inputs"]["canonical_python_build_identity"],
        label="canonical Python build identity",
    )
    python_build_receipt = args.python_build_receipt.resolve(strict=True)
    canonical_wheel = args.canonical_wheel.resolve(strict=True)
    canonical_sdist = args.canonical_sdist.resolve(strict=True)
    canonical_contract = verify_canonical_python_release(
        identity,
        source_root=running_source_root,
        python_build_identity=python_build_identity,
        python_build_receipt=python_build_receipt,
        wheel=canonical_wheel,
        sdist=canonical_sdist,
    )
    config = args.config.resolve(strict=True)
    verify_file(config, identity["inputs"]["optimization_config"], label="selected optimization config")
    config_value = read_json(config)
    if not isinstance(config_value, dict) or config_value.get("schema") != "kazstem-windows-optimization-config-v1":
        raise ReleaseError("freezer config is invalid")

    root = args.build_root.absolute()
    if root.exists() or root.is_symlink():
        raise ReleaseError(f"fresh build root exists: {root}")
    root.mkdir(parents=True)
    environment = actual_environment(identity, root, bootstrap, wheelhouse)
    source = root / "source"
    copy_tree_exact(payload, source)
    source_before = tree_record(source)
    if source_before != identity["inputs"]["source_payload_tree"]:
        raise ReleaseError("fresh source copy differs before the build")
    venv = root / "venv"
    venv_python = venv / "Scripts/python.exe"
    commands: list[dict[str, Any]] = []

    def execute(
        actual: list[str],
        logical: list[str],
        *,
        cwd: Path,
        logical_cwd: str,
        timeout: float = 900,
        environment_overrides: dict[str, str] | None = None,
    ) -> None:
        run(actual, cwd=cwd, environment=environment, timeout=timeout)
        commands.append(
            {
                "argv": logical,
                "cwd": logical_cwd,
                "environment_overrides": environment_overrides or {},
                "timeout_seconds": int(timeout),
                "exit_code": 0,
            }
        )

    def bootstrapped_source_tool(
        python: Path,
        entrypoint: str,
        cache: Path,
        arguments: list[str],
    ) -> list[str]:
        return [
            os.fspath(python),
            "-I",
            "-B",
            "-X",
            f"pycache_prefix={cache}",
            os.fspath(payload / "packaging/windows/release_bootstrap.py"),
            "--source-root",
            os.fspath(payload),
            "--release-identity",
            os.fspath(identity_path),
            "--materialization-root",
            os.fspath(source_materialization_root),
            "--materialization-receipt",
            os.fspath(source_receipt),
            "--materialization-execution-receipt",
            os.fspath(source_execution_receipt),
            "--cache-root",
            os.fspath(cache),
            "--expected-tree-entries",
            str(identity["inputs"]["source_payload_tree"]["entries"]),
            "--expected-tree-bytes",
            str(identity["inputs"]["source_payload_tree"]["regular_file_bytes"]),
            "--expected-tree-sha256",
            identity["inputs"]["source_payload_tree"]["sha256"],
            "--entrypoint",
            entrypoint,
            "--",
            *arguments,
        ]

    def logical_bootstrapped_source_tool(
        entrypoint: str, arguments: list[str]
    ) -> list[str]:
        prefix = release_bootstrap_prefix(identity, entrypoint)
        prefix[0] = "<BUILD-PYTHON>"
        return [*prefix, *arguments]

    execute(
        [str(bootstrap), "-m", "venv", str(venv)],
        ["<BOOTSTRAP-PYTHON>", "-m", "venv", "<FRESH-BUILD-ROOT>/venv"],
        cwd=root,
        logical_cwd="<FRESH-BUILD-ROOT>",
    )
    execute(
        [
            str(venv_python),
            "-m",
            "pip",
            "install",
            "--no-index",
            "--find-links",
            str(wheelhouse),
            "--require-hashes",
            "--only-binary=:all:",
            "--no-deps",
            "-r",
            str(requirements),
        ],
        [
            "<BUILD-PYTHON>",
            "-m",
            "pip",
            "install",
            "--no-index",
            "--find-links",
            "<WHEELHOUSE>",
            "--require-hashes",
            "--only-binary=:all:",
            "--no-deps",
            "-r",
            "packaging/windows/build-requirements.lock.txt",
        ],
        cwd=source,
        logical_cwd="<MATERIALIZED-SOURCE>",
    )
    tools = query_tools(venv_python, cwd=source, environment=environment)
    artifacts = root / "artifacts"
    artifacts.mkdir()
    wheel = artifacts / identity["artifacts"]["wheel"]["filename"]
    sdist = artifacts / identity["artifacts"]["sdist"]["filename"]
    shutil.copyfile(canonical_wheel, wheel)
    shutil.copyfile(canonical_sdist, sdist)
    verify_artifact(wheel, identity["artifacts"]["wheel"], label="consumed canonical wheel")
    verify_artifact(sdist, identity["artifacts"]["sdist"], label="consumed canonical sdist")
    audit_json = root / "python-artifact-source-audit.json"
    audit_arguments = [
        "--source", str(source), "--wheel", str(wheel), "--sdist", str(sdist),
        "--version", identity["release"], "--json", str(audit_json),
    ]
    logical_audit_arguments = [
        "--source", "<MATERIALIZED-SOURCE>", "--wheel", "<WHEEL>",
        "--sdist", "<SDIST>", "--version", identity["release"],
        "--json", "<FRESH-BUILD-ROOT>/python-artifact-source-audit.json",
    ]
    execute(
        bootstrapped_source_tool(
            venv_python,
            "packaging/windows/audit_python_artifacts.py",
            root / "audit-python-pycache",
            audit_arguments,
        ),
        logical_bootstrapped_source_tool(
            "packaging/windows/audit_python_artifacts.py",
            logical_audit_arguments,
        ),
        cwd=payload,
        logical_cwd="<MATERIALIZED-SOURCE>",
    )
    if read_json(audit_json).get("result") != "pass":
        raise ReleaseError("Python artifact source audit did not pass")
    execute(
        [str(venv_python), "-m", "pip", "install", "--no-index", "--no-deps", str(wheel)],
        ["<BUILD-PYTHON>", "-m", "pip", "install", "--no-index", "--no-deps", "<WHEEL>"],
        cwd=root,
        logical_cwd="<FRESH-BUILD-ROOT>",
    )
    pyinstaller_environment = dict(environment)
    pyinstaller_environment["KAZSTEM_ENTRYPOINT"] = str(source / "packaging/windows/entrypoint.py")
    pyinstaller_environment["KAZSTEM_NOARCHIVE"] = "1" if config_value["switches"]["noarchive"] else "0"
    dist = root / "dist"
    work = root / "pyinstaller-work"
    actual_pyinstaller = [
        str(venv_python), "-m", "PyInstaller", "--clean", "--noconfirm",
        "--distpath", str(dist), "--workpath", str(work), str(source / "packaging/windows/kazstem-minimal.spec"),
    ]
    completed = run_bounded(
        actual_pyinstaller,
        cwd=root,
        environment=pyinstaller_environment,
        timeout_seconds=1200,
    )
    if completed.returncode:
        raise ReleaseError(f"PyInstaller failed: {completed.stdout.decode('utf-8', 'replace')[-8000:]}")
    commands.append(
        {
            "argv": ["<BUILD-PYTHON>", "-m", "PyInstaller", "--clean", "--noconfirm", "--distpath", "<FRESH-BUILD-ROOT>/dist", "--workpath", "<FRESH-BUILD-ROOT>/pyinstaller-work", "packaging/windows/kazstem-minimal.spec"],
            "cwd": "<FRESH-BUILD-ROOT>",
            "environment_overrides": {
                "KAZSTEM_ENTRYPOINT": "<MATERIALIZED-SOURCE>/packaging/windows/entrypoint.py",
                "KAZSTEM_NOARCHIVE": "1" if config_value["switches"]["noarchive"] else "0",
            },
            "timeout_seconds": 1200,
            "exit_code": 0,
        }
    )
    frozen = dist / "kazstem"
    ledger = root / "freezer-ledger.json"
    ledger_arguments = [
        "--frozen", str(frozen), "--spec",
        str(source / "packaging/windows/kazstem-minimal.spec"),
        "--source-commit", identity["source_commit"], "--config", str(config),
        "--json", str(ledger),
    ]
    logical_ledger_arguments = [
        "--frozen", "<FROZEN>", "--spec", "packaging/windows/kazstem-minimal.spec",
        "--source-commit", identity["source_commit"], "--config",
        "<OPTIMIZATION-CONFIG>", "--json", "<BASE-LEDGER>",
    ]
    execute(
        bootstrapped_source_tool(
            venv_python,
            "packaging/windows/write_freezer_ledger.py",
            root / "freezer-ledger-pycache",
            ledger_arguments,
        ),
        logical_bootstrapped_source_tool(
            "packaging/windows/write_freezer_ledger.py",
            logical_ledger_arguments,
        ),
        cwd=payload,
        logical_cwd="<MATERIALIZED-SOURCE>",
    )
    if args.mode == "verify":
        verify_artifact(wheel, identity["artifacts"]["wheel"], label=f"root-{args.label} wheel")
        verify_artifact(sdist, identity["artifacts"]["sdist"], label=f"root-{args.label} sdist")
        verify_tree(frozen, identity["inputs"]["frozen_tree"], label=f"root-{args.label} frozen")
        verify_file(ledger, identity["inputs"]["base_ledger"], label=f"root-{args.label} freezer ledger")
    source_after = tree_record(source)
    if source_after != source_before:
        raise ReleaseError("materialized source copy changed during the build")
    receipt = {
        "schema": "kazstem-windows-python-freezer-build-v2",
        "result": "pass",
        "label": args.label,
        "source": {
            "commit": identity["source_commit"],
            "tree": identity["source_tree"],
            "origin": identity["source_origin"],
            "ref": identity["source_ref"],
            "payload_tree": identity["inputs"]["source_payload_tree"],
        },
        "source_receipt": identity["inputs"]["source_receipt"],
        "source_boundary": boundary,
        "root_identity": {"logical_label": args.label, "st_dev": root.stat().st_dev, "st_ino": root.stat().st_ino},
        "canonical_python_validation": {
            "identity_schema": "kazstem-canonical-python-build-identity-v2",
            "receipt_schema": "kazstem-canonical-python-build-receipt-v2",
            "execution_platform": canonical_contract["receipt"]["execution_platform"],
            "linux_roundtrip_wheel_and_sdist_identical": canonical_contract[
                "receipt"
            ]["roundtrip"]["wheel_and_sdist_identical"],
            "validated_by": identity["inputs"]["canonical_python_builder"],
            "windows_rebuild_performed": False,
        },
        "build_inputs": {
            "bootstrap_python": identity["inputs"]["bootstrap_python"],
            "wheelhouse_tree": identity["inputs"]["build_wheelhouse_tree"],
            "canonical_python_builder": identity["inputs"]["canonical_python_builder"],
            "canonical_python_build_identity": identity["inputs"]["canonical_python_build_identity"],
            "canonical_python_build_receipt": identity["inputs"]["canonical_python_build_receipt"],
            "optimization_config": identity["inputs"]["optimization_config"],
            "requirements": file_record(requirements),
            "release_support_files": identity["inputs"]["release_support_files"],
        },
        "source_tree_snapshots": {"before": source_before, "after": source_after},
        "execution": {
            "commands": commands,
            "environment": logical_environment(identity),
            "tool_versions": tools,
            "process_contract": {
                "implementation": "windows-job-object-kill-on-close",
                "captures_direct_child_and_descendants": True,
                "combined_output_limit_bytes": 16 * 1024 * 1024,
                "timeout_reaps_process_tree": True,
                "launch_order": "create-suspended-assign-job-start-reader-resume",
                "active_processes_zero_before_return": True,
                "descendants_after_direct_exit_fail": True,
            },
        },
        "outputs": {
            "frozen_tree": tree_record(frozen),
            "wheel": artifact_record(wheel, identity["artifacts"]["wheel"]["url"]),
            "sdist": artifact_record(sdist, identity["artifacts"]["sdist"]["url"]),
            "base_ledger": file_record(ledger),
        },
        "coverage": {
            "assertions": 10,
            "cases": 1,
            "checks": [
                "base-ledger",
                "canonical-artifacts-consumed",
                "canonical-linux-sdist-roundtrip-receipt",
                "canonical-v2-identity-receipt",
                "fresh-root",
                "frozen-tree",
                "hash-locked-build-environment",
                "no-network-runtime-modules",
                "python-artifact-source-parity",
                "source-tree-unchanged",
            ],
        },
    }
    receipt_path = args.receipt.absolute()
    try:
        receipt_path.resolve(strict=False).relative_to(root.resolve(strict=True))
    except ValueError as exc:
        raise ReleaseError("build receipt output must be inside the fresh build root") from exc
    if receipt_path.exists() or receipt_path.is_symlink():
        raise ReleaseError(f"build receipt exists: {receipt_path}")
    receipt_path.parent.mkdir(parents=True, exist_ok=True)
    receipt_path.write_bytes(json_bytes(receipt))
    verify_python_build_receipt(
        receipt,
        identity,
        label=args.label,
        build_root=root,
        bootstrap_python=bootstrap,
        wheelhouse=wheelhouse,
        optimization_config=config,
        python_build_identity=python_build_identity,
        python_build_receipt=python_build_receipt,
        frozen=frozen,
        wheel=wheel,
        sdist=sdist,
        base_ledger=ledger,
    )
    summary = {
        "schema": "kazstem-windows-python-freezer-build-summary-v2",
        "result": "pass",
        "mode": args.mode,
        "label": args.label,
        "build_root": root.name,
        "receipt": file_record(receipt_path),
        "outputs": receipt["outputs"],
    }
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ReleaseError, BoundedProcessError, OSError, ValueError, json.JSONDecodeError) as exc:
        raise SystemExit(f"error: {exc}") from exc
