#!/usr/bin/env python3
"""Assemble one exact candidate ready-run ZIP and issue a checked root receipt."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import zlib
from types import SimpleNamespace

import assemble_ready_run
from release_common import (
    ReleaseError,
    artifact_record,
    file_record,
    json_bytes,
    load_identity,
    read_json,
    release_bootstrap_prefix,
    require_release_bootstrap,
    tree_record,
    verify_file,
    verify_tree,
)


def main() -> int:
    boundary = require_release_bootstrap(
        "packaging/windows/assemble_optimization_candidate.py"
    )
    parser = argparse.ArgumentParser()
    parser.add_argument("--identity", required=True, type=Path)
    parser.add_argument("--name", required=True)
    parser.add_argument("--label", choices=("a", "b"), required=True)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--frozen", required=True, type=Path)
    parser.add_argument("--resources", required=True, type=Path)
    parser.add_argument("--runtime", required=True, type=Path)
    parser.add_argument("--platform-lock", required=True, type=Path)
    parser.add_argument("--documents", required=True, type=Path)
    parser.add_argument("--binary-readme-template", required=True, type=Path)
    parser.add_argument("--base-ledger", required=True, type=Path)
    parser.add_argument("--wheel", required=True, type=Path)
    parser.add_argument("--sdist", required=True, type=Path)
    parser.add_argument("--corresponding-source", required=True, type=Path)
    parser.add_argument("--work-root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--receipt", required=True, type=Path)
    args = parser.parse_args()
    identity_path = args.identity.resolve(strict=True)
    identity = load_identity(identity_path)
    expected_environment = {"LC_ALL": "C", "PYTHONHASHSEED": "0", "TZ": "UTC"}
    if {key: os.environ.get(key) for key in expected_environment} != expected_environment:
        raise ReleaseError("candidate assembler controlled environment differs")
    forbidden = sorted(
        key for key in os.environ
        if key.startswith("QAZMORPH_")
        or key.upper().endswith("_PROXY")
        or key in {"PYTHONPATH", "PYTHONHOME", "LD_PRELOAD", "LD_LIBRARY_PATH", "DYLD_INSERT_LIBRARIES"}
    )
    if forbidden:
        raise ReleaseError(f"candidate assembler inherited forbidden environment: {forbidden}")
    source_root = Path.cwd().resolve(strict=True)
    running_script = Path(__file__).resolve(strict=True)
    verify_file(
        source_root / "packaging/windows/assemble_optimization_candidate.py",
        file_record(running_script),
        label="checked candidate assembler",
    )
    bootstrap_file = {
        "bytes": identity["inputs"]["bootstrap_python"]["bytes"],
        "sha256": identity["inputs"]["bootstrap_python"]["sha256"],
    }
    verify_file(Path(sys.executable).resolve(strict=True), bootstrap_file, label="candidate assembler Python")
    if platform.python_version() != identity["platform"]["python"]:
        raise ReleaseError("candidate assembler Python version differs")

    def git(*arguments: str) -> str:
        environment = {
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "LC_ALL": "C",
            "PATH": os.environ.get("PATH", ""),
            "TZ": "UTC",
        }
        for key in ("ComSpec", "SystemRoot", "WINDIR"):
            if key in os.environ:
                environment[key] = os.environ[key]
        completed = subprocess.run(
            ["git", *arguments], cwd=source_root, env=environment,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            encoding="utf-8", errors="strict", check=False,
        )
        if completed.returncode:
            raise ReleaseError(f"candidate assembler Git check failed: {completed.stderr.strip()}")
        return completed.stdout.strip()

    if (
        git("rev-parse", "HEAD") != identity["source_commit"]
        or git("rev-parse", "HEAD^{tree}") != identity["source_tree"]
        or git("remote", "get-url", "origin") != identity["source_origin"]
        or git("rev-parse", f"{identity['source_ref']}^{{commit}}") != identity["source_commit"]
        or git("status", "--porcelain=v1", "--untracked-files=all")
    ):
        raise ReleaseError("candidate assembler checkout is not the exact clean release tag")
    config_path = args.config.resolve(strict=True)
    verify_file(config_path, identity["inputs"]["optimization_config"], label="candidate optimization config")
    config = read_json(config_path)
    import PyInstaller

    if (
        not isinstance(config, dict)
        or config.get("schema") != "kazstem-windows-optimization-config-v1"
        or config.get("name") != args.name
        or identity["optimization"]["selected"] != args.name
        or config.get("tool_versions") != {
            "python": platform.python_version(),
            "pyinstaller": PyInstaller.__version__,
            "zlib": zlib.ZLIB_RUNTIME_VERSION,
        }
    ):
        raise ReleaseError("candidate identity/config/name differ")
    frozen = args.frozen.resolve(strict=True)
    ledger = args.base_ledger.resolve(strict=True)
    verify_tree(frozen, identity["inputs"]["frozen_tree"], label="candidate frozen tree")
    verify_file(ledger, identity["inputs"]["base_ledger"], label="candidate freezer ledger")
    work_root = args.work_root.absolute()
    receipt_path = args.receipt.absolute()
    if receipt_path.exists() or receipt_path.is_symlink():
        raise ReleaseError(f"candidate assembly receipt exists: {receipt_path}")
    result = assemble_ready_run.assemble(
        SimpleNamespace(
            identity=identity_path,
            frozen=frozen,
            resources=args.resources,
            runtime=args.runtime,
            platform_lock=args.platform_lock,
            documents=args.documents,
            binary_readme_template=args.binary_readme_template,
            base_ledger=ledger,
            wheel=args.wheel,
            sdist=args.sdist,
            corresponding_source=args.corresponding_source,
            work_root=work_root,
            output=args.output,
            observation=None,
        )
    )
    root_stat = work_root.resolve(strict=True).stat()
    logical_root = f"<CANDIDATE-{args.name.upper()}-ASSEMBLY-{args.label.upper()}>"
    inner_argv = [
        "<PYTHON>",
        "packaging/windows/assemble_optimization_candidate.py",
        "--identity", f"<CANDIDATE-IDENTITY-{args.name}>",
        "--name", args.name,
        "--label", args.label,
        "--config", f"<CANDIDATE-CONFIG-{args.name}>",
        "--frozen", f"<CANDIDATE-FROZEN-{args.name}>",
        "--resources", "<RESOURCES>",
        "--runtime", "<WINDOWS-RUNTIME>",
        "--platform-lock", "<PLATFORM-LOCK>",
        "--documents", "<DOCUMENTS>",
        "--binary-readme-template", "<BINARY-README-TEMPLATE>",
        "--base-ledger", f"<CANDIDATE-LEDGER-{args.name}>",
        "--wheel", "<WHEEL>",
        "--sdist", "<SDIST>",
        "--corresponding-source", "<CORRESPONDING-SOURCE>",
        "--work-root", logical_root,
        "--output", f"<CANDIDATE-ZIP-{args.name}-{args.label}>",
        "--receipt", f"<CANDIDATE-ASSEMBLY-RECEIPT-{args.name}-{args.label}>",
    ]
    receipt = {
        "schema": "kazstem-windows-optimization-archive-assembly-v1",
        "result": "pass",
        "name": args.name,
        "label": args.label,
        "source": {
            "commit": identity["source_commit"],
            "tree": identity["source_tree"],
            "origin": identity["source_origin"],
            "ref": identity["source_ref"],
        },
        "root_identity": {
            "logical_label": f"{args.name}-{args.label}",
            "st_dev": root_stat.st_dev,
            "st_ino": root_stat.st_ino,
            "st_ctime_ns": root_stat.st_ctime_ns,
        },
        "inputs": {
            "identity": file_record(identity_path),
            "config": file_record(config_path),
            "frozen_tree": tree_record(frozen),
            "base_ledger": file_record(ledger),
        },
        "output": artifact_record(
            args.output.resolve(strict=True),
            identity["artifacts"]["ready_run"]["url"],
        ),
        "execution": {
            "script": {
                "path": "packaging/windows/assemble_optimization_candidate.py",
                "file": file_record(running_script),
            },
            "argv": [
                *release_bootstrap_prefix(
                    identity,
                    "packaging/windows/assemble_optimization_candidate.py",
                ),
                *inner_argv[2:],
            ],
            "cwd": "<MATERIALIZED-SOURCE>",
            "environment": expected_environment,
            "tool_versions": config["tool_versions"],
            "source_boundary": boundary,
            "exit_code": 0,
        },
        "coverage": {
            "assertions": 8,
            "cases": 1,
            "checks": [
                "candidate-config",
                "candidate-frozen-tree",
                "checked-source-bootstrap",
                "deterministic-ready-assembler",
                "external-fresh-pycache-root",
                "exact-toolchain",
                "fresh-assembly-root",
                "output-artifact",
            ],
        },
    }
    receipt_path.parent.mkdir(parents=True, exist_ok=True)
    receipt_path.write_bytes(json_bytes(receipt))
    print(json.dumps({"result": "pass", "archive": result["archive"], "receipt": file_record(receipt_path)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ReleaseError, OSError, ValueError, json.JSONDecodeError) as exc:
        raise SystemExit(f"error: {exc}") from exc
