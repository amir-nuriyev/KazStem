#!/usr/bin/env python3
"""Run the complete source suite at the exact release commit and emit counts."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time
from typing import Any

from release_common import (
    ReleaseError,
    begin_gate_execution,
    assert_relative_json,
    gate_envelope,
    identity_sha256,
    json_bytes,
    load_identity,
    locked_gate_invocation,
    stream_evidence_record,
)


def _git(repository: Path, *args: str) -> str:
    process = subprocess.run(
        ["git", *args],
        cwd=repository,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=60,
        check=False,
    )
    if process.returncode:
        raise ReleaseError(f"Git source identity command failed: {args!r}")
    return process.stdout.decode("utf-8", "strict").strip()


def run(args: argparse.Namespace) -> dict[str, Any]:
    if args.output.exists() or args.output.is_symlink():
        raise ReleaseError("source-suite output already exists")
    identity_path = args.identity.resolve(strict=True)
    identity = load_identity(identity_path)
    execution = begin_gate_execution(identity, "source-suite", caller_file=__file__)
    repository = args.repository.resolve(strict=True)
    if (
        _git(repository, "rev-parse", "HEAD") != identity["source_commit"]
        or _git(repository, "rev-parse", "HEAD^{tree}") != identity["source_tree"]
        or _git(repository, "remote", "get-url", "origin") != identity["source_origin"]
        or _git(repository, "rev-parse", f"{identity['source_ref']}^{{commit}}")
        != identity["source_commit"]
        or _git(repository, "status", "--porcelain=v1", "--untracked-files=all")
    ):
        raise ReleaseError("source-suite checkout differs from the release identity")
    python = args.python.resolve(strict=True)
    generator = next(
        record["generator"]
        for record in identity["verification"]["evidence"]
        if record["gate"] == "source-suite"
    )
    with tempfile.TemporaryDirectory(prefix="kazstem-source-suite-") as temporary:
        environment = {
            "HOME": temporary,
            "LANG": "C",
            "LC_ALL": "C",
            "PYTHONHASHSEED": "0",
            "SOURCE_DATE_EPOCH": str(identity["source_date_epoch"]),
            "TZ": "UTC",
            "PATH": "/usr/bin:/bin",
        }
        version = subprocess.run(
            [str(python), "-m", "pytest", "--version"],
            cwd=repository,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=60,
            check=False,
        )
        if version.returncode:
            raise ReleaseError("bound source-suite Python lacks pytest")
        argv = [
            str(python),
            "-m",
            "pytest",
            "-q",
            "--disable-warnings",
            "--maxfail=1",
        ]
        started = time.monotonic()
        running = subprocess.Popen(
            argv,
            cwd=repository,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        try:
            stdout, stderr = running.communicate(timeout=generator["timeout_seconds"])
        except subprocess.TimeoutExpired as exc:
            os.killpg(running.pid, 9)
            running.communicate()
            raise ReleaseError(
                "source suite exceeded its identity-bound timeout"
            ) from exc
        process = subprocess.CompletedProcess(argv, running.returncode, stdout, stderr)
        seconds = time.monotonic() - started
    output = (process.stdout + b"\n" + process.stderr).decode("utf-8", "replace")
    counts = {
        name: int(match.group(1))
        if (match := re.search(rf"(\d+)\s+{name}", output))
        else 0
        for name in ("passed", "failed", "errors", "skipped", "xfailed", "xpassed")
    }
    tests_run = sum(counts.values())
    if (
        process.returncode
        or counts["passed"] <= 0
        or counts["failed"]
        or counts["errors"]
    ):
        raise ReleaseError(
            f"source suite failed: exit={process.returncode}, counts={counts}"
        )
    try:
        os.killpg(running.pid, 0)
    except ProcessLookupError:
        process_group_reaped = True
    except PermissionError:
        process_group_reaped = False
    else:
        process_group_reaped = False
    if not process_group_reaped:
        try:
            os.killpg(running.pid, 9)
        except ProcessLookupError:
            pass
        raise ReleaseError("source-suite descendant process group still exists")
    payload = {
        "schema": "kazstem-macos-source-suite-v1",
        "pass": True,
        "release": identity["release"],
        "source_commit": identity["source_commit"],
        "source_tree": identity["source_tree"],
        "source_origin": identity["source_origin"],
        "source_ref": identity["source_ref"],
        "argv": ["python", "-m", "pytest", "-q", "--disable-warnings", "--maxfail=1"],
        "environment": {
            "HOME": "controlled-home",
            "LANG": "C",
            "LC_ALL": "C",
            "PYTHONHASHSEED": "0",
            "SOURCE_DATE_EPOCH": str(identity["source_date_epoch"]),
            "TZ": "UTC",
            "PATH": "system-tools",
        },
        "exit_status": process.returncode,
        "seconds": round(seconds, 6),
        "tests_run": tests_run,
        "passed": counts["passed"],
        "failures": counts["failed"],
        "errors": counts["errors"],
        "skipped": counts["skipped"],
        "xfailed": counts["xfailed"],
        "xpassed": counts["xpassed"],
        "stdout": stream_evidence_record(process.stdout),
        "stderr": stream_evidence_record(process.stderr),
        "pytest_version": (version.stdout + version.stderr)
        .decode("utf-8", "replace")
        .strip(),
        "process_group_reaped": process_group_reaped,
    }
    assert_relative_json(payload, label="source-suite payload")
    envelope = gate_envelope(
        identity=identity,
        identity_contract_sha256=identity_sha256(identity_path),
        gate="source-suite",
        subjects=["sdist", "wheel"],
        invocation=locked_gate_invocation(
            identity,
            "source-suite",
            stdout=b"PASS: full source suite\n",
            execution=execution,
        ),
        coverage={
            "descendant_processes": 1,
            "full_descendant_coverage": True,
            "network_trace": None,
            "observations": {
                "errors": counts["errors"],
                "failed": counts["failed"],
                "passed": counts["passed"],
                "skipped": counts["skipped"],
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
    parser.add_argument("--repository", required=True, type=Path)
    parser.add_argument("--python", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    run(args)
    print("PASS: full source suite")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ReleaseError, OSError, ValueError, json.JSONDecodeError) as exc:
        raise SystemExit(f"error: {exc}") from exc
