#!/usr/bin/env python3
"""Run the checked source gates and bind two fresh Git materializations."""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

from bounded_windows_process import BoundedProcessError, run_bounded

from release_common import (
    ReleaseError,
    canonical_hash,
    evidence_envelope,
    evidence_record,
    file_record,
    files_equal,
    identity_sha256,
    json_bytes,
    load_identity,
    read_json,
    release_bootstrap_prefix,
    require_release_bootstrap,
    source_execution_receipt_projection,
    tree_record,
    verify_artifact,
    verify_file,
    verify_generator_runtime,
    verify_source_execution_receipt,
    verify_source_receipt,
    verify_tree,
    forbidden_loader_environment_name,
)


def stream_record(payload: bytes) -> dict[str, object]:
    return {"bytes": len(payload), "sha256": hashlib.sha256(payload).hexdigest()}


def run_checked(command: list[str], *, cwd: Path, environment: dict[str, str], timeout: int) -> subprocess.CompletedProcess[bytes]:
    completed = run_bounded(
        command,
        cwd=cwd,
        environment=environment,
        timeout_seconds=timeout,
    )
    return completed


def require_nonaliased(roots: list[Path]) -> None:
    for index, first in enumerate(roots):
        for second in roots[index + 1 :]:
            if first == second or first in second.parents or second in first.parents or first.samefile(second):
                raise ReleaseError("source-suite materialization roots are equal/nested/aliased")


def validate_suite_receipt(value: object) -> int:
    if not isinstance(value, dict) or set(value) != {
        "schema",
        "result",
        "import",
        "discovery",
        "run",
        "successes",
        "skips",
        "expected_failures",
        "unexpected",
        "tests_run",
        "runner_output",
        "discovery_order_equals_run_order",
    }:
        raise ReleaseError("source-suite test ledger fields differ")
    if (
        value["schema"] != "kazstem-source-suite-test-ledger-v1"
        or value["result"] != "pass"
        or value["discovery_order_equals_run_order"] is not True
        or type(value["tests_run"]) is not int
        or value["tests_run"] <= 0
    ):
        raise ReleaseError("source-suite test ledger did not pass")

    def sequence(record: object, label: str) -> int:
        if (
            not isinstance(record, dict)
            or set(record) != {"count", "sha256", "values"}
            or type(record["count"]) is not int
            or record["count"] < 0
            or not isinstance(record["values"], list)
            or record["count"] != len(record["values"])
            or not isinstance(record["sha256"], str)
            or len(record["sha256"]) != 64
            or any(character not in "0123456789abcdef" for character in record["sha256"])
            or record["sha256"] != canonical_hash(record["values"])
        ):
            raise ReleaseError(f"source-suite {label} identity is invalid")
        return record["count"]

    discovered = sequence(value["discovery"], "discovery")
    run = sequence(value["run"], "run")
    successes = sequence(value["successes"], "successes")
    skips = sequence(value["skips"], "skips")
    expected_failures = sequence(value["expected_failures"], "expected failures")
    if discovered != run or run != value["tests_run"]:
        raise ReleaseError("source-suite discovery/run counts differ")
    if successes + skips + expected_failures != run:
        raise ReleaseError("source-suite result partition is incomplete")
    unexpected = value["unexpected"]
    if not isinstance(unexpected, dict) or set(unexpected) != {
        "failures",
        "errors",
        "unexpected_successes",
    }:
        raise ReleaseError("source-suite unexpected-result fields differ")
    if any(sequence(unexpected[name], name) for name in sorted(unexpected)):
        raise ReleaseError("source-suite contains unexpected test results")
    runner_output = value["runner_output"]
    if runner_output != {
        "published": False,
        "reason": "raw unittest text omitted because it contains a nondeterministic duration",
    }:
        raise ReleaseError("source-suite runner output identity is invalid")
    return run


def main() -> int:
    require_release_bootstrap("packaging/windows/run_source_suite.py")
    parser = argparse.ArgumentParser()
    parser.add_argument("--identity", required=True, type=Path)
    parser.add_argument("--source-root-a", required=True, type=Path)
    parser.add_argument("--source-payload-a", required=True, type=Path)
    parser.add_argument("--source-receipt-a", required=True, type=Path)
    parser.add_argument("--source-execution-receipt-a", required=True, type=Path)
    parser.add_argument("--source-root-b", required=True, type=Path)
    parser.add_argument("--source-payload-b", required=True, type=Path)
    parser.add_argument("--source-receipt-b", required=True, type=Path)
    parser.add_argument("--source-execution-receipt-b", required=True, type=Path)
    parser.add_argument("--wheel", required=True, type=Path)
    parser.add_argument("--install-root", required=True, type=Path)
    parser.add_argument("--json", required=True, type=Path)
    args = parser.parse_args()
    forbidden_parent = sorted(
        name
        for name in os.environ
        if name.startswith("GIT_")
        or forbidden_loader_environment_name(name)
        or name.upper().startswith("QAZMORPH_")
        or name.upper().endswith("_PROXY")
        or name in {"PYTHONPATH", "PYTHONHOME"}
    )
    if forbidden_parent:
        raise ReleaseError(
            "source suite inherited forbidden parent variables: "
            + ", ".join(forbidden_parent)
        )
    identity_path = args.identity.resolve(strict=True)
    identity = load_identity(identity_path)
    roots = [args.source_root_a.resolve(strict=True), args.source_root_b.resolve(strict=True)]
    require_nonaliased(roots)
    payloads = [
        args.source_payload_a.resolve(strict=True),
        args.source_payload_b.resolve(strict=True),
    ]
    canonical_receipts = [
        args.source_receipt_a.resolve(strict=True),
        args.source_receipt_b.resolve(strict=True),
    ]
    execution_paths = [
        args.source_execution_receipt_a.resolve(strict=True),
        args.source_execution_receipt_b.resolve(strict=True),
    ]
    execution_values = []
    for index, (root, payload, canonical, execution_path) in enumerate(
        zip(roots, payloads, canonical_receipts, execution_paths)
    ):
        label = chr(ord("a") + index)
        for path in (payload, canonical, execution_path):
            try:
                path.relative_to(root)
            except ValueError as exc:
                raise ReleaseError(f"source-suite {label} input escapes its fresh root") from exc
        verify_tree(payload, identity["inputs"]["source_payload_tree"], label=f"source-suite payload {label}")
        verify_file(canonical, identity["inputs"]["source_receipt"], label=f"source-suite canonical receipt {label}")
        verify_source_receipt(read_json(canonical), identity)
        execution_value = read_json(execution_path)
        verify_source_execution_receipt(
            execution_value,
            identity,
            label=label,
            materialization_root=root,
            payload=payload,
            canonical_receipt=canonical,
        )
        execution_values.append(execution_value)
    if not files_equal(canonical_receipts[0], canonical_receipts[1]):
        raise ReleaseError("canonical Git-source receipts differ across fresh roots")
    if execution_values[0]["root_identity"] == execution_values[1]["root_identity"]:
        raise ReleaseError("source execution receipts bind the same root object")

    wheel = args.wheel.resolve(strict=True)
    verify_artifact(wheel, identity["artifacts"]["wheel"], label="source-suite wheel")
    install_root = args.install_root.absolute()
    if install_root.exists() or install_root.is_symlink():
        raise ReleaseError(f"fresh source-suite install root exists: {install_root}")
    for root in roots:
        if install_root == root or install_root in root.parents or root in install_root.parents:
            raise ReleaseError("source-suite install root aliases/nests a source root")
    install_root.mkdir(parents=True)
    site = install_root / "site"
    suite_receipt_path = install_root / "TEST-LEDGER.json"

    python = Path(sys.executable).resolve(strict=True)
    verify_file(
        python,
        {
            "bytes": identity["inputs"]["bootstrap_python"]["bytes"],
            "sha256": identity["inputs"]["bootstrap_python"]["sha256"],
        },
        label="source-suite bootstrap Python",
    )
    git_contract = execution_values[0]["execution"]["tools"]["git"]
    git_name = shutil.which("git", path=os.environ.get("PATH", ""))
    if git_name is None:
        raise ReleaseError("source suite cannot locate the identity-bound Git")
    git = Path(git_name).resolve(strict=True)
    verify_file(git, git_contract["file"], label="source-suite Git")

    system_root = Path(os.environ.get("SystemRoot", r"C:\Windows"))
    environment = {
        "LC_ALL": "C",
        "PATH": os.pathsep.join(
            [
                os.fspath(python.parent),
                os.fspath(git.parent),
                os.fspath(system_root / "System32"),
                os.fspath(system_root),
            ]
        ),
        "PIP_CONFIG_FILE": os.devnull,
        "PIP_DISABLE_PIP_VERSION_CHECK": "1",
        "PIP_NO_INDEX": "1",
        "PIP_NO_INPUT": "1",
        "PYTHONHASHSEED": "0",
        "PYTHONNOUSERSITE": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "TZ": "UTC",
    }
    for key in ("ComSpec", "SystemRoot", "WINDIR"):
        if key in os.environ:
            environment[key] = os.environ[key]
    logical_environment = {
        "COMSPEC": "<SYSTEM32>/cmd.exe",
        "LC_ALL": "C",
        "PATH": "<BOOTSTRAP-PYTHON-DIR>;<BOUND-GIT-DIR>;<SYSTEM32>;<WINDOWS>",
        "PIP_CONFIG_FILE": "<NULL-DEVICE>",
        "PIP_DISABLE_PIP_VERSION_CHECK": "1",
        "PIP_NO_INDEX": "1",
        "PIP_NO_INPUT": "1",
        "PYTHONHASHSEED": "0",
        "PYTHONNOUSERSITE": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "SYSTEMROOT": "<WINDOWS>",
        "TZ": "UTC",
        "WINDIR": "<WINDOWS>",
    }
    install_command = [
        os.fspath(python),
        "-m",
        "pip",
        "install",
        "--no-index",
        "--no-deps",
        "--no-compile",
        "--disable-pip-version-check",
        "--target",
        os.fspath(site),
        os.fspath(wheel),
    ]
    installed = run_checked(
        install_command,
        cwd=install_root,
        environment=environment,
        timeout=300,
    )
    if installed.returncode:
        raise ReleaseError(
            "offline canonical-wheel install failed: "
            + installed.stdout.decode("utf-8", "replace")[-4000:]
        )
    site_before = tree_record(site)
    sys.dont_write_bytecode = True
    if "qazmorph" in sys.modules or any(
        name.startswith("qazmorph.") for name in sys.modules
    ):
        raise ReleaseError("qazmorph was imported before the exact wheel target was selected")
    sys.path.insert(0, os.fspath(site))
    import qazmorph

    current_module = Path(qazmorph.__file__).resolve(strict=True)
    try:
        current_relative = current_module.relative_to(site).as_posix()
    except ValueError as exc:
        raise ReleaseError("current source-suite process imported outside wheel target") from exc
    current_import = {
        "distribution": "kazstem",
        "distribution_version": importlib.metadata.version("kazstem"),
        "module": "qazmorph",
        "module_path": current_relative,
        "module_bytes": current_module.stat().st_size,
        "module_sha256": hashlib.sha256(current_module.read_bytes()).hexdigest(),
        "public_version": qazmorph.__version__,
    }
    if (
        current_import["distribution_version"] != identity["release"]
        or current_import["public_version"] != identity["release"]
    ):
        raise ReleaseError("installed wheel import reports the wrong release")
    probe_code = (
        "import hashlib,importlib.metadata,json,pathlib,sys;"
        "site=pathlib.Path(sys.argv[1]).resolve(strict=True);sys.path.insert(0,str(site));"
        "import qazmorph;module=pathlib.Path(qazmorph.__file__).resolve(strict=True);"
        "relative=module.relative_to(site).as_posix();payload=module.read_bytes();"
        "print(json.dumps({'distribution':'kazstem','distribution_version':importlib.metadata.version('kazstem'),"
        "'module':'qazmorph','module_path':relative,'module_bytes':len(payload),"
        "'module_sha256':hashlib.sha256(payload).hexdigest(),'public_version':qazmorph.__version__},sort_keys=True))"
    )
    child_probe = run_checked(
        [os.fspath(python), "-I", "-c", probe_code, os.fspath(site)],
        cwd=install_root,
        environment=environment,
        timeout=60,
    )
    if child_probe.returncode:
        raise ReleaseError("isolated child import proof failed")
    child_import = json.loads(child_probe.stdout.decode("utf-8", "strict"))
    if child_import != current_import:
        raise ReleaseError("current and isolated-child wheel imports differ")

    runner = payloads[0] / "packaging/windows/source_suite_runner.py"
    runner_bootstrap = payloads[0] / "packaging/windows/release_bootstrap.py"
    runner_cache = install_root / "runner-pycache"
    suite = run_checked(
        [
            os.fspath(python),
            "-I",
            "-B",
            "-X",
            f"pycache_prefix={runner_cache}",
            os.fspath(runner_bootstrap),
            "--source-root",
            os.fspath(payloads[0]),
            "--release-identity",
            os.fspath(identity_path),
            "--materialization-root",
            os.fspath(roots[0]),
            "--materialization-receipt",
            os.fspath(canonical_receipts[0]),
            "--materialization-execution-receipt",
            os.fspath(execution_paths[0]),
            "--cache-root",
            os.fspath(runner_cache),
            "--expected-tree-entries",
            str(identity["inputs"]["source_payload_tree"]["entries"]),
            "--expected-tree-bytes",
            str(identity["inputs"]["source_payload_tree"]["regular_file_bytes"]),
            "--expected-tree-sha256",
            identity["inputs"]["source_payload_tree"]["sha256"],
            "--entrypoint",
            "packaging/windows/source_suite_runner.py",
            "--",
            "--source",
            os.fspath(payloads[0]),
            "--site",
            os.fspath(site),
            "--json",
            os.fspath(suite_receipt_path),
        ],
        cwd=payloads[0],
        environment=environment,
        timeout=3600,
    )
    if suite.returncode:
        raise ReleaseError(
            "source unit suite failed: " + suite.stdout.decode("utf-8", "replace")[-4000:]
        )
    if not runner_cache.is_dir() or any(runner_cache.iterdir()):
        raise ReleaseError("source-suite isolated runner pycache root is not empty")
    suite_receipt = read_json(suite_receipt_path)
    test_count = validate_suite_receipt(suite_receipt)
    if suite_receipt["import"] != current_import:
        raise ReleaseError("test runner imported a different wheel payload")
    if site_before != tree_record(site):
        raise ReleaseError("installed canonical wheel changed while running source tests")
    for payload in payloads:
        verify_tree(payload, identity["inputs"]["source_payload_tree"], label="post-suite source payload")
    optimized = run_checked(
        [
            os.fspath(python),
            "-O",
            "-I",
            "-B",
            "-X",
            f"pycache_prefix={install_root / 'optimized-denial-pycache'}",
            os.fspath(runner_bootstrap),
        ],
        cwd=payloads[0],
        environment=environment,
        timeout=60,
    )
    if optimized.returncode == 0 or b"must not run with Python -O" not in optimized.stdout:
        raise ReleaseError("optimized Python did not fail closed for release gates")

    logical_argv = [
        "<PYTHON>",
        "packaging/windows/run_source_suite.py",
        "--identity",
        "<RELEASE-IDENTITY>",
        "--source-root-a",
        "<SOURCE-ROOT-A>",
        "--source-payload-a",
        "<SOURCE-PAYLOAD-A>",
        "--source-receipt-a",
        "<SOURCE-RECEIPT-A>",
        "--source-execution-receipt-a",
        "<SOURCE-EXECUTION-RECEIPT-A>",
        "--source-root-b",
        "<SOURCE-ROOT-B>",
        "--source-payload-b",
        "<SOURCE-PAYLOAD-B>",
        "--source-receipt-b",
        "<SOURCE-RECEIPT-B>",
        "--source-execution-receipt-b",
        "<SOURCE-EXECUTION-RECEIPT-B>",
        "--wheel",
        "<WHEEL>",
        "--install-root",
        "<SOURCE-SUITE-INSTALL-ROOT>",
        "--json",
        "<EVIDENCE-OUTPUT>",
    ]
    record = verify_generator_runtime(
        identity,
        gate="source-suite",
        logical_argv=logical_argv,
    )
    observations = {
        "source": {
            "commit": identity["source_commit"],
            "tree": identity["source_tree"],
            "origin": identity["source_origin"],
            "ref": identity["source_ref"],
        },
        "payload_tree": tree_record(payloads[0]),
        "canonical_receipt": file_record(canonical_receipts[0]),
        "materialization_execution_receipts": [
            source_execution_receipt_projection(value)
            for value in execution_values
        ],
        "process_supervisor": {
            "implementation": "windows-job-object-kill-on-close",
            "source": file_record(
                payloads[0] / "packaging/windows/bounded_windows_process.py"
            ),
            "launch_order": "create-suspended-assign-job-start-reader-resume",
            "active_processes_zero_before_return": True,
            "descendants_after_direct_exit_fail": True,
            "timeout_and_overflow_reap_job": True,
        },
        "wheel_install": {
            "wheel": identity["artifacts"]["wheel"],
            "argv": [
                "<PYTHON>", "-m", "pip", "install", "--no-index",
                "--no-deps", "--no-compile", "--disable-pip-version-check",
                "--target", "<SOURCE-SUITE-INSTALL-ROOT>/site", "<WHEEL>",
            ],
            "cwd": "<SOURCE-SUITE-INSTALL-ROOT>",
            "environment": logical_environment,
            "exit_code": installed.returncode,
            "stdout": stream_record(installed.stdout),
            "stderr": stream_record(installed.stderr),
            "installed_tree": site_before,
            "installed_tree_unchanged_after_tests": True,
        },
        "import_proofs": {
            "current_process": current_import,
            "isolated_child": child_import,
            "identical": True,
            "child_argv": [
                "<PYTHON>", "-I", "-c", "<CHECKED-INLINE-IMPORT-PROBE>",
                "<SOURCE-SUITE-INSTALL-ROOT>/site",
            ],
            "child_exit_code": child_probe.returncode,
            "child_stdout": stream_record(child_probe.stdout),
            "child_stderr": stream_record(child_probe.stderr),
        },
        "unit_suite": {
            "argv": [
                *release_bootstrap_prefix(
                    identity, "packaging/windows/source_suite_runner.py"
                ),
                "--source", "<MATERIALIZED-SOURCE>",
                "--site", "<SOURCE-SUITE-INSTALL-ROOT>/site",
                "--json", "<SOURCE-SUITE-INSTALL-ROOT>/TEST-LEDGER.json",
            ],
            "cwd": "<MATERIALIZED-SOURCE>",
            "environment": logical_environment,
            "exit_code": suite.returncode,
            "tests": test_count,
            "runner": file_record(runner),
            "bootstrap": file_record(runner_bootstrap),
            "fresh_external_pycache_empty_after_exit": True,
            "ledger": suite_receipt,
            "ledger_file": file_record(suite_receipt_path),
            "stdout": stream_record(suite.stdout),
            "stderr": stream_record(suite.stderr),
        },
        "optimized_python_denial": {
            "argv": [
                "<PYTHON>",
                "-O",
                "-I",
                "-B",
                "-X",
                "pycache_prefix=<SOURCE-SUITE-INSTALL-ROOT>/optimized-denial-pycache",
                "<MATERIALIZED-SOURCE-A>/packaging/windows/release_bootstrap.py",
            ],
            "cwd": "<MATERIALIZED-SOURCE-A>",
            "environment": logical_environment,
            "exit_code_nonzero": True,
            "stdout": stream_record(optimized.stdout),
            "stderr": stream_record(optimized.stderr),
        },
    }
    result = evidence_envelope(
        identity,
        identity_hash=identity_sha256(identity_path),
        record=record,
        observations=observations,
    )
    if args.json.exists() or args.json.is_symlink():
        raise ReleaseError(f"source-suite evidence output exists: {args.json}")
    args.json.parent.mkdir(parents=True, exist_ok=True)
    args.json.write_bytes(json_bytes(result))
    print(f"PASS: {test_count} installed-wheel source tests across two checked materializations")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ReleaseError, BoundedProcessError, OSError, ValueError, json.JSONDecodeError, subprocess.SubprocessError) as exc:
        raise SystemExit(f"error: {exc}") from exc
