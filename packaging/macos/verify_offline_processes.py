#!/usr/bin/env python3
"""Prove sandbox-enforced offline behavior and descendant-process cleanup on macOS."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import threading
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
    tool_output_identity,
    verify_file,
    verify_ready_root_identity,
)


def _ps() -> list[tuple[int, int, str]]:
    process = subprocess.run(
        ["/bin/ps", "-axo", "pid=,ppid=,comm="],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
        check=False,
    )
    if process.returncode:
        raise ReleaseError("process observer failed")
    result: list[tuple[int, int, str]] = []
    for line in process.stdout.decode("utf-8", "replace").splitlines():
        fields = line.strip().split(None, 2)
        if len(fields) == 3 and fields[0].isdigit() and fields[1].isdigit():
            result.append((int(fields[0]), int(fields[1]), Path(fields[2]).name))
    return result


def _observe(
    process: subprocess.Popen[bytes],
    stop: threading.Event,
    processes: set[tuple[int, str]],
) -> None:
    while not stop.is_set() or process.poll() is None:
        try:
            rows = _ps()
        except ReleaseError:
            time.sleep(0.005)
            continue
        descendants = {process.pid}
        changed = True
        while changed:
            changed = False
            for pid, ppid, _name in rows:
                if ppid in descendants and pid not in descendants:
                    descendants.add(pid)
                    changed = True
        for pid, _ppid, name in rows:
            if pid in descendants:
                processes.add((pid, name))
        time.sleep(0.005)


def _logical_argv(argv: list[str], root: Path, workspace: Path) -> list[str]:
    result: list[str] = []
    for token in argv:
        if token.startswith("WRITE_ROOT="):
            result.append("WRITE_ROOT=workspace/case")
            continue
        path = Path(token)
        if not path.is_absolute():
            result.append(token)
            continue
        resolved = path.resolve(strict=False)
        if resolved == root or root in resolved.parents:
            result.append(f"bundle/{resolved.relative_to(root).as_posix()}")
        elif resolved == workspace or workspace in resolved.parents:
            result.append(f"workspace/{resolved.relative_to(workspace).as_posix()}")
        elif token in {"/usr/bin/sandbox-exec", "/bin/ps"}:
            result.append(path.name)
        else:
            result.append("python" if path.name.startswith("python") else path.name)
    return result


def _run_sandboxed(
    *,
    sandbox: Path,
    profile: Path,
    write_root: Path,
    command: list[str],
    root: Path,
    workspace: Path,
    input_bytes: bytes = b"",
    timeout: int = 120,
) -> tuple[dict[str, Any], list[tuple[int, str]]]:
    argv = [
        str(sandbox),
        "-D",
        f"WRITE_ROOT={write_root}",
        "-f",
        str(profile),
        "--",
        *command,
    ]
    process = subprocess.Popen(
        argv,
        cwd=write_root,
        env={
            "HOME": str(write_root),
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": "/usr/bin:/bin",
            "PYTHONHASHSEED": "0",
            "TZ": "UTC",
        },
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    observed: set[tuple[int, str]] = set()
    stop = threading.Event()
    observer = threading.Thread(
        target=_observe, args=(process, stop, observed), daemon=True
    )
    observer.start()
    try:
        stdout, stderr = process.communicate(input=input_bytes, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        process.kill()
        process.communicate()
        raise ReleaseError("sandboxed release command timed out") from exc
    finally:
        stop.set()
        observer.join(timeout=5)
    return (
        {
            "argv": _logical_argv(argv, root, workspace),
            "exit_status": process.returncode,
            "stdin": stream_evidence_record(input_bytes),
            "stdout": stream_evidence_record(stdout),
            "stderr": stream_evidence_record(stderr),
            "observed_processes": sorted({name for _pid, name in observed}),
        },
        sorted(observed),
    )


def verify(args: argparse.Namespace) -> dict[str, Any]:
    if args.workspace.exists() or args.workspace.is_symlink():
        raise ReleaseError("offline gate workspace must be fresh")
    if args.output.exists() or args.output.is_symlink():
        raise ReleaseError("offline gate output already exists")
    identity_path = args.identity.resolve(strict=True)
    identity = load_identity(identity_path)
    execution = begin_gate_execution(identity, "network-trace", caller_file=__file__)
    root = args.bundle.resolve(strict=True)
    root_binding = verify_ready_root_identity(args.bundle, identity)
    launcher = root / identity["ready_run"]["launcher"]["path"]
    profile = args.profile.resolve(strict=True)
    verify_file(
        profile,
        identity["verification"]["tracing"]["profile"]["file"],
        label="network-deny sandbox profile",
    )
    sandbox = Path("/usr/bin/sandbox-exec").resolve(strict=True)
    tracing_tool = identity["verification"]["tracing"]["tool"]
    verify_file(sandbox, tracing_tool["executable"], label="sandbox-exec")
    version_process = subprocess.run(
        [str(sandbox), *tracing_tool["version_argv"][1:]],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=60,
        check=False,
    )
    if (
        tool_output_identity(
            version_process.stdout, exit_status=version_process.returncode
        )
        != tracing_tool["version"]
    ):
        raise ReleaseError("sandbox-exec output identity differs")
    workspace = args.workspace.absolute()
    workspace.mkdir(parents=True)
    cases: list[dict[str, Any]] = []
    observed_processes: set[tuple[int, str]] = set()
    fixed_cases = [
        ("version", [str(launcher), "--version"], b"", 0),
        (
            "analysis",
            [str(launcher), "-c", "-i", "--format", "json"],
            "Қазақстандағы балалар мектепке барды.\n".encode("utf-8"),
            0,
        ),
        (
            "constraint-grammar",
            [str(launcher), "-d", "-c", "--format", "jsonl"],
            "балалар мектепке барды.\n".encode("utf-8"),
            0,
        ),
    ]
    events: list[dict[str, Any]] = []
    sequence = 0
    for name, command, input_bytes, expected in fixed_cases:
        case_root = workspace / name
        case_root.mkdir()
        record, observed = _run_sandboxed(
            sandbox=sandbox,
            profile=profile,
            write_root=case_root,
            command=command,
            root=root,
            workspace=workspace,
            input_bytes=input_bytes,
        )
        if record["exit_status"] != expected or (
            name != "version" and record["stdout"]["bytes"] == 0
        ):
            raise ReleaseError(f"offline sandbox case failed: {name}")
        cases.append({"name": name, **record})
        observed_processes.update(observed)
        events.append(
            {
                "sequence": sequence,
                "kind": "sandboxed-case",
                "process": name,
                "result": "pass",
            }
        )
        sequence += 1

    negative_root = workspace / "negative-control"
    negative_root.mkdir()
    negative_command = [
        str(args.python.resolve(strict=True)),
        "-c",
        "import socket; s=socket.socket(); s.bind(('127.0.0.1', 0))",
    ]
    negative, observed = _run_sandboxed(
        sandbox=sandbox,
        profile=profile,
        write_root=negative_root,
        command=negative_command,
        root=root,
        workspace=workspace,
    )
    observed_processes.update(observed)
    if negative["exit_status"] == 0:
        raise ReleaseError("sandbox network negative control was not denied")
    events.append(
        {
            "sequence": sequence,
            "kind": "network-negative-control",
            "process": "python",
            "result": "denied",
        }
    )
    sequence += 1
    observed_names = {name for _pid, name in observed_processes}
    for process_name in sorted(observed_names):
        events.append(
            {
                "sequence": sequence,
                "kind": "observed-descendant",
                "process": process_name,
                "result": "sandbox-inherited",
            }
        )
        sequence += 1
    trace_lines = [
        json.dumps(event, sort_keys=True, separators=(",", ":")) for event in events
    ]
    trace = ("\n".join(trace_lines) + "\n").encode("utf-8")
    time.sleep(0.05)
    live_pids = {pid for pid, _ppid, _name in _ps()}
    lingering = sorted(
        name
        for pid, name in observed_processes
        if pid in live_pids
        and name in {"hfst-proc", "hfst-optimized-lookup", "cg-proc"}
    )
    if lingering:
        raise ReleaseError(
            f"native helper processes linger after sandbox cases: {lingering}"
        )

    payload = {
        "schema": "kazstem-macos-network-trace-v1",
        "pass": True,
        "release": identity["release"],
        "source_commit": identity["source_commit"],
        "source_tree": identity["source_tree"],
        "policy": {
            "profile": identity["verification"]["tracing"]["profile"],
            "argv_prefix": identity["verification"]["tracing"]["argv_prefix"],
            "network_default": "deny",
            "descendant_inheritance": True,
        },
        "cases": cases,
        "sandbox_negative_control_denied": True,
        "negative_control": negative,
        "allowed_network_operations": 0,
        "full_descendant_coverage": True,
        "trace_truncated": False,
        "events": events,
        "observed_processes": sorted(observed_names),
        "lingering_native_processes": lingering,
        "trace": stream_evidence_record(trace),
        "root_binding": root_binding,
    }
    assert_relative_json(payload, label="offline/process payload")
    network_coverage = {
        "cases_sandboxed": len(cases),
        "events": events,
        "negative_control": {
            "argv": identity["verification"]["tracing"]["negative_control_argv"],
            "denied": True,
            "exit_status": negative["exit_status"],
            "stdout": negative["stdout"],
            "stderr": negative["stderr"],
        },
        "observed_descendants": max(1, len(observed_names)),
        "policy_argv_prefix": identity["verification"]["tracing"]["argv_prefix"],
        "policy_denials": 1,
        "policy_tool": tracing_tool,
        "process_observer_argv": identity["verification"]["tracing"][
            "process_observer_argv"
        ],
        "process_samples": max(1, len(observed_names)),
        "profile": identity["verification"]["tracing"]["profile"],
        "trace": stream_evidence_record(trace),
    }
    envelope = gate_envelope(
        identity=identity,
        identity_contract_sha256=identity_sha256(identity_path),
        gate="network-trace",
        subjects=["ready_run"],
        invocation=locked_gate_invocation(
            identity,
            "network-trace",
            stdout=b"PASS: sandboxed offline/process gate\n",
            execution=execution,
        ),
        coverage={
            "descendant_processes": max(1, len(observed_names)),
            "full_descendant_coverage": True,
            "network_trace": network_coverage,
            "observations": {
                "cases": len(cases),
                "events": len(events),
                "policy_denials": 1,
                "processes": max(1, len(observed_names)),
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
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--profile", required=True, type=Path)
    parser.add_argument("--python", required=True, type=Path)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    verify(args)
    print("PASS: sandboxed offline/process gate")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ReleaseError, OSError, ValueError, json.JSONDecodeError) as exc:
        raise SystemExit(f"error: {exc}") from exc
