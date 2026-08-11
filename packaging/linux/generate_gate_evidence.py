#!/usr/bin/env python3
"""Execute a bound gate and emit a nontruncated, identity-bound evidence envelope."""

from __future__ import annotations

import argparse
import ctypes
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import types
from typing import Any

def _source_module(name: str, path: Path) -> types.ModuleType:
    module = types.ModuleType(name)
    module.__file__ = str(path)
    sys.modules[name] = module
    source = path.read_bytes()
    exec(compile(source, str(path), "exec", dont_inherit=True), module.__dict__)
    return module


_tool_directory = Path(__file__).resolve().parent
_common = _source_module(
    "_kazstem_source_release_common", _tool_directory / "release_common.py"
)
_supervisor = _source_module(
    "_kazstem_source_process_supervisor",
    _tool_directory.parent / "process_supervisor.py",
)
ReleaseError = _common.ReleaseError
archive_limits = _common.archive_limits
assert_relative_json = _common.assert_relative_json
decode_json = _common.decode_json
ensure_output_outside = _common.ensure_output_outside
extract_validated_tar = _common.extract_validated_tar
file_record = _common.file_record
gate_envelope = _common.gate_envelope
identity_sha256 = _common.identity_sha256
inspect_tar = _common.inspect_tar
json_bytes = _common.json_bytes
load_identity = _common.load_identity
logical_gate_argv = _common.logical_gate_argv
logical_network_boundary = _common.logical_network_boundary
read_json = _common.read_json
stream_evidence_record = _common.stream_evidence_record
verify_artifact = _common.verify_artifact
verify_file = _common.verify_file
SupervisionError = _supervisor.SupervisionError
run_bounded = _supervisor.run_bounded


MAX_CAPTURE_BYTES = 64 * 1024**2


def _tool(identity: dict[str, Any], name: str, *, tracing: bool = False) -> tuple[Path, dict[str, Any]]:
    if tracing:
        expected = identity["verification"]["tracing"]["tool"]
        if name != expected["name"]:
            raise ReleaseError("requested tracer differs from release identity")
    else:
        expected_by_name = {
            record["name"]: record
            for record in identity["verification"]["reproducibility"]["tools"]
        }
        expected = expected_by_name.get(name)
        if expected is None:
            raise ReleaseError(f"gate command tool is not identity-bound: {name}")
    observed = shutil.which(name)
    if observed is None:
        raise ReleaseError(f"required gate tool is unavailable: {name}")
    executable = Path(observed).resolve(strict=True)
    verify_file(executable, expected["executable"], label=f"gate tool {name}")
    version = subprocess.run(
        [str(executable), *expected["version_argv"][1:]],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=60,
        check=False,
    )
    if (
        version.returncode != 0
        or version.stdout.decode("utf-8", "replace").strip() != expected["version"]
    ):
        raise ReleaseError(f"gate tool version differs from identity: {name}")
    return executable, expected


def _seccomp_library(identity: dict[str, Any]) -> Path:
    if not sys.platform.startswith("linux"):
        raise ReleaseError("official no-network gate execution requires Linux")
    expected = identity["verification"]["network_boundary"]["library"]
    try:
        ctypes.CDLL(expected["soname"])
    except OSError as exc:
        raise ReleaseError("bound libseccomp soname cannot be loaded") from exc
    candidates: set[Path] = set()
    try:
        for line in Path("/proc/self/maps").read_text(encoding="utf-8").splitlines():
            fields = line.split()
            if fields and fields[-1].startswith("/") and "libseccomp.so" in fields[-1]:
                candidates.add(Path(fields[-1]).resolve(strict=True))
    except (OSError, UnicodeError) as exc:
        raise ReleaseError("cannot inventory loaded libseccomp mapping") from exc
    for candidate in sorted(candidates):
        try:
            verify_file(candidate, expected["file"], label="network boundary libseccomp")
        except ReleaseError:
            continue
        return candidate
    raise ReleaseError("loaded libseccomp bytes differ from release identity")


def _boundary_prefix(
    *,
    identity: dict[str, Any],
    checkout: Path,
    python: Path,
) -> tuple[list[str], dict[str, Any]]:
    boundary = identity["verification"]["network_boundary"]
    wrapper = checkout / boundary["wrapper"]["path"]
    verify_file(wrapper, boundary["wrapper"]["file"], label="network boundary wrapper")
    library = _seccomp_library(identity)
    library_file = boundary["library"]["file"]
    wrapper_file = boundary["wrapper"]["file"]
    common = [
        "--library-bytes", str(library_file["bytes"]),
        "--library-sha256", library_file["sha256"],
        "--wrapper-bytes", str(wrapper_file["bytes"]),
        "--wrapper-sha256", wrapper_file["sha256"],
        "--receipt-fd", "{supervisor_fd:boundary}",
    ]
    for name in boundary["denied_syscalls"]:
        common.extend(["--deny-syscall", name])
    actual = [
        str(python),
        str(wrapper),
        "--library", str(library),
        *common,
        "--",
    ]
    return actual, logical_network_boundary(identity)


def _validate_boundary_receipt(
    data: bytes, *, identity: dict[str, Any], logical: dict[str, Any]
) -> dict[str, Any]:
    value = decode_json(data, label="network boundary receipt")
    expected_keys = {
        "clone3_action",
        "clone_untraced_denied",
        "clone_untraced_mask",
        "default_action",
        "denied_syscalls",
        "deny_action",
        "library",
        "no_new_privs",
        "pass",
        "resolved_syscalls",
        "schema",
        "unavailable_syscalls",
        "wrapper",
    }
    boundary = identity["verification"]["network_boundary"]
    if (
        not isinstance(value, dict)
        or set(value) != expected_keys
        or value["schema"]
        != "kazstem-linux-seccomp-network-boundary-receipt-v1"
        or value["pass"] is not True
        or value["default_action"] != boundary["default_action"]
        or value["deny_action"] != boundary["deny_action"]
        or value["no_new_privs"] is not True
        or value["clone_untraced_mask"] != boundary["clone_untraced_mask"]
        or value["clone_untraced_denied"] is not True
        or value["clone3_action"] != boundary["clone3_action"]
        or value["denied_syscalls"] != boundary["denied_syscalls"]
        or value["resolved_syscalls"] != boundary["denied_syscalls"]
        or value["unavailable_syscalls"] != []
        or value["library"] != boundary["library"]["file"]
        or value["wrapper"] != boundary["wrapper"]["file"]
    ):
        raise ReleaseError("network boundary receipt differs from exact policy")
    return {**logical, "receipt": value}


def _run_captured(
    argv: list[str],
    *,
    cwd: Path,
    environment: dict[str, str],
    timeout: int,
    capture_root: Path,
) -> tuple[int, bytes, bytes, dict[str, bytes], dict[str, Any]]:
    del capture_root
    try:
        completed = run_bounded(
            argv,
            cwd=cwd,
            environment=environment,
            timeout=timeout,
            max_stdout=MAX_CAPTURE_BYTES,
            max_stderr=MAX_CAPTURE_BYTES,
            extra_stream_caps={
                name: MAX_CAPTURE_BYTES
                for name in ("boundary", "trace")
                if any("{supervisor_fd:" + name + "}" in item for item in argv)
            },
        )
    except SupervisionError as exc:
        raise ReleaseError(f"gate command supervision failed: {exc}") from exc
    return (
        completed.returncode,
        completed.stdout,
        completed.stderr,
        completed.extra_streams,
        {
            "mechanism": completed.containment,
            "observed_descendants": completed.observed_descendants,
            "descendant_peak": completed.descendant_peak,
            "final_descendants": 0,
            "tasks_max": completed.cgroup_tasks_max,
            "cgroup_kill_written": completed.cgroup_kill_written,
            "cgroup_populated_zero": completed.cgroup_populated_zero,
        },
    )


def _trace_record(
    data: bytes,
    identity: dict[str, Any],
    *,
    replacements: list[tuple[str, str]],
) -> tuple[dict[str, Any], dict[str, int]]:
    try:
        text = data.decode("utf-8")
    except UnicodeError as exc:
        raise ReleaseError("strace stream is not UTF-8") from exc
    text = text.replace("\r\n", "\n")
    for actual, logical in sorted(replacements, key=lambda item: len(item[0]), reverse=True):
        text = text.replace(actual, logical)
        text = text.replace(actual.replace("/", "\\"), logical)
    normalized = text.encode("utf-8")
    if len(normalized) > MAX_CAPTURE_BYTES:
        raise ReleaseError("aggregate strace output exceeds capture cap")
    syscall_count = 0
    syscall_counts: dict[str, int] = {}
    denied_attempt_counts: dict[str, int] = {}
    observed_forbidden: set[str] = set()
    processes: set[str] = {"main"}
    forbidden = set(identity["verification"]["tracing"]["forbidden_syscalls"])
    for line in text.splitlines():
        match = re.match(
            r"\s*(?:(?:\[pid\s+([0-9]+)\]|([0-9]+))\s+)?([A-Za-z0-9_]+)\(",
            line,
        )
        if match is not None:
            process_label = match.group(1) or match.group(2) or "main"
            processes.add(process_label)
            syscall_name = match.group(3)
            syscall_count += 1
            syscall_counts[syscall_name] = syscall_counts.get(syscall_name, 0) + 1
            if syscall_name in forbidden:
                if re.search(r"= -1 (?:EPERM|ENOSYS)(?:\s|$)", line):
                    denied_attempt_counts[syscall_name] = (
                        denied_attempt_counts.get(syscall_name, 0) + 1
                    )
                else:
                    observed_forbidden.add(syscall_name)
    if observed_forbidden:
        raise ReleaseError(
            f"forbidden network syscalls observed: {sorted(observed_forbidden)}"
        )
    record = {
        "argv_prefix": identity["verification"]["tracing"]["argv_prefix"],
        "follow_descendants": True,
        "forbidden_syscalls": [],
        "denied_attempt_counts": dict(sorted(denied_attempt_counts.items())),
        "processes": len(processes),
        "syscalls": syscall_count,
        "syscall_counts": dict(sorted(syscall_counts.items())),
        "trace": stream_evidence_record(normalized),
        "tracer": identity["verification"]["tracing"]["tool"],
    }
    return record, {"processes": len(processes), "syscalls": syscall_count}


def generate(args: argparse.Namespace) -> dict[str, Any]:
    if args.output.exists() or args.output.is_symlink():
        raise ReleaseError(f"gate evidence output already exists: {args.output}")
    identity_path = args.identity.resolve(strict=True)
    identity = load_identity(identity_path)
    helper_records = {
        item["path"]: item["file"]
        for item in identity["verification"]["reproducibility"]["helpers"]
    }
    verify_file(
        Path(_common.__file__).resolve(strict=True),
        helper_records["packaging/linux/release_common.py"],
        label="loaded release_common helper",
    )
    verify_file(
        Path(_supervisor.__file__).resolve(strict=True),
        helper_records["packaging/process_supervisor.py"],
        label="loaded process supervisor helper",
    )
    record = next(
        (
            item
            for item in identity["verification"]["evidence"]
            if item["gate"] == args.gate
        ),
        None,
    )
    if record is None:
        raise ReleaseError(f"gate is not required by the identity: {args.gate}")
    execution = record["execution"]
    generator_path = Path(__file__).resolve(strict=True)
    verify_file(
        generator_path,
        execution["generator"]["file"],
        label="gate evidence generator",
    )
    if args.source_checkout.is_symlink() or not args.source_checkout.is_dir():
        raise ReleaseError("gate source checkout must be a real directory")
    checkout = args.source_checkout.resolve(strict=True)
    git, _ = _tool(identity, "git")
    for argv, expected, label in (
        ([str(git), "rev-parse", "HEAD"], identity["source_commit"], "commit"),
        ([str(git), "rev-parse", "HEAD^{tree}"], identity["source_tree"], "tree"),
        ([str(git), "remote", "get-url", "origin"], identity["source_origin"], "origin"),
        ([str(git), "rev-parse", identity["source_ref"]], identity["source_tag_object"], "annotated tag object"),
        ([str(git), "rev-parse", f"{identity['source_ref']}^{{commit}}"], identity["source_commit"], "release tag"),
        ([str(git), "cat-file", "-t", identity["source_ref"]], "tag", "annotated tag type"),
    ):
        observed = subprocess.run(
            argv,
            cwd=checkout,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if observed.returncode or observed.stdout.strip() != expected:
            raise ReleaseError(f"gate source checkout {label} differs from identity")
    status = subprocess.run(
        [
            str(git),
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
            "--ignored=matching",
        ],
        cwd=checkout,
        stdout=subprocess.PIPE,
        check=True,
    ).stdout
    if status:
        raise ReleaseError("gate source checkout is dirty")
    script_path = checkout / execution["script"]["path"]
    verify_file(script_path, execution["script"]["file"], label="gate script")
    command = execution["argv"]
    executable, tool_record = _tool(identity, command[0])
    configuration = identity["verification"]["reproducibility"]
    with tempfile.TemporaryDirectory(prefix="kazstem-gate-") as temporary:
        work = Path(temporary)
        ensure_output_outside(args.output, work, label="gate evidence output")
        payload_path = work / "payload.json"
        replacements = {
            "{payload}": str(payload_path),
            "{identity}": str(identity_path),
            "{source_checkout}": str(checkout),
            "{work}": str(work / "python-reproducibility-work"),
        }
        logical_replacements = {
            "{payload}": "gate-output/payload.json",
            "{identity}": "release-identity.json",
            "{source_checkout}": "source-checkout",
            "{work}": "gate-work/python-reproducibility",
        }
        known_gate_inputs = {
            "artifact_dir",
            "base_ledger",
            "binary_readme_template",
            "blackbox_evidence",
            "compression_evidence",
            "documents",
            "practical_evidence",
            "producer_dir",
            "python_build_identity",
            "python_freezer_wheelhouse",
            "python_interpreter_source",
            "python_wheelhouse",
            "resources",
            "runtime",
            "runtime_provenance_raw",
            "source_payload",
            "source_readme_template",
        }
        command_tokens = set(re.findall(r"\{[a-z_]+\}", "\n".join(command)))
        supplied_gate_inputs: dict[str, Path] = {}
        artifacts_argument = getattr(args, "artifacts_dir", None)
        needs_artifact_dir = bool(record["subjects"]) or "{artifact_dir}" in command_tokens
        if needs_artifact_dir:
            if artifacts_argument is None:
                raise ReleaseError(f"gate {args.gate} requires --artifacts-dir")
            if artifacts_argument.is_symlink() or not artifacts_argument.is_dir():
                raise ReleaseError("gate artifacts directory must be a real directory")
            supplied_gate_inputs["artifact_dir"] = artifacts_argument.resolve(strict=True)
        elif artifacts_argument is not None:
            raise ReleaseError(f"gate {args.gate} forbids unused --artifacts-dir")
        for specification in getattr(args, "gate_input", []) or []:
            name, separator, raw_path = specification.partition("=")
            if (
                not separator
                or name not in known_gate_inputs
                or name in supplied_gate_inputs
            ):
                raise ReleaseError(f"invalid/duplicate --gate-input: {specification!r}")
            path = Path(raw_path)
            if path.is_symlink() or not path.exists():
                raise ReleaseError(f"gate input is missing/symlinked: {name}")
            supplied_gate_inputs[name] = path.resolve(strict=True)
        for name, path in supplied_gate_inputs.items():
            replacements["{" + name + "}"] = str(path)
            logical_replacements["{" + name + "}"] = "inputs/" + name.replace(
                "_", "-"
            )
        automatic_tokens = {
            "{payload}",
            "{identity}",
            "{source_checkout}",
            "{work}",
            "{ready_root}",
            "{fresh_root}",
            *{"{" + subject + "}" for subject in record["subjects"]},
        }
        required_external = {
            token[1:-1] for token in command_tokens - automatic_tokens
        }
        if needs_artifact_dir:
            required_external.add("artifact_dir")
        if set(supplied_gate_inputs) != required_external:
            raise ReleaseError(
                f"gate inputs differ from fixed matrix: expected={sorted(required_external)}, "
                f"observed={sorted(supplied_gate_inputs)}"
            )
        artifacts_dir = supplied_gate_inputs.get("artifact_dir")
        subject_paths: dict[str, Path] = {}
        for subject in record["subjects"]:
            if artifacts_dir is None:
                raise ReleaseError("gate subject preparation lacks artifact directory")
            token = "{" + subject + "}"
            artifact_path = artifacts_dir / identity["artifacts"][subject]["filename"]
            verify_artifact(
                artifact_path,
                identity["artifacts"][subject],
                label=f"gate subject {subject}",
            )
            subject_paths[subject] = artifact_path.resolve(strict=True)
            replacements[token] = str(subject_paths[subject])
            logical_replacements[token] = (
                "artifacts/" + identity["artifacts"][subject]["filename"]
            )
        if "{ready_root}" in command_tokens:
            ready_archive = subject_paths.get("ready_run")
            if ready_archive is None:
                raise ReleaseError("ready-root preparation lacks ready-run subject")
            ready_members = inspect_tar(
                ready_archive,
                limits=archive_limits(identity, "ready_run"),
                expected_top=identity["ready_run"]["top_level"],
            )
            ready_root = extract_validated_tar(
                ready_archive,
                work / "ready-extraction",
                members=ready_members,
                limits=archive_limits(identity, "ready_run"),
            )
            replacements["{ready_root}"] = str(ready_root)
            logical_replacements["{ready_root}"] = "prepared/ready-run-root"
        if "{fresh_root}" in command_tokens:
            replacements["{fresh_root}"] = str(work / "auditor-fresh-root")
            logical_replacements["{fresh_root}"] = "gate-work/auditor-fresh-root"
        unresolved = {
            token for token in command_tokens if token not in replacements
        }
        if unresolved:
            raise ReleaseError(
                f"gate input placeholders lack values: {sorted(unresolved)}"
            )
        def substitute(item: str, values: dict[str, str]) -> str:
            result = item
            for token, replacement in values.items():
                result = result.replace(token, replacement)
            return result
        actual_command = [
            str(executable),
            *[substitute(item, replacements) for item in command[1:]],
        ]
        logical_command = [
            substitute(item, logical_replacements) for item in command
        ]
        if logical_command != logical_gate_argv(identity, args.gate):
            raise ReleaseError("prepared gate argv differs from fixed logical matrix")
        environment = dict(configuration["environment"])
        controlled_home = work / "home"
        controlled_home.mkdir()
        pycache = work / "pycache"
        pycache.mkdir()
        process_environment = {
            **environment,
            "HOME": str(controlled_home),
            "PYTHONPYCACHEPREFIX": str(pycache),
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
        }
        network_record: dict[str, Any] | None = None
        boundary_record: dict[str, Any] | None = None
        boundary_logical: dict[str, Any] | None = None
        trace_counts = {"processes": 1, "syscalls": 0}
        if args.gate in {"network-trace", "python-reproducibility", "source-suite"}:
            tracer, _ = _tool(identity, "strace", tracing=True)
            boundary_prefix, boundary_logical = _boundary_prefix(
                identity=identity,
                checkout=checkout,
                python=executable,
            )
            prefix = [
                str(tracer)
                if item == "strace"
                else item.replace("{trace}", "{supervisor_fd:trace}")
                for item in identity["verification"]["tracing"]["argv_prefix"]
            ]
            executed = [*prefix, *boundary_prefix, *actual_command]
        else:
            executed = actual_command
        returncode, stdout, stderr, extra_streams, containment = _run_captured(
            executed,
            cwd=checkout,
            environment=process_environment,
            timeout=execution["timeout_seconds"],
            capture_root=work,
        )
        if returncode != 0:
            detail = stderr[:4096].decode("utf-8", "replace")
            raise ReleaseError(
                f"gate command failed with exit {returncode}: {detail}"
            )
        trace_data = extra_streams.get("trace")
        if trace_data is not None:
            trace_replacements = [
                (actual, logical)
                for actual, logical in zip(actual_command, logical_command, strict=True)
                if actual != logical
            ]
            trace_replacements.extend(
                [(str(checkout), "source-checkout"), (str(work), "gate-work")]
            )
            network_record, trace_counts = _trace_record(
                trace_data, identity, replacements=trace_replacements
            )
        boundary_data = extra_streams.get("boundary")
        if boundary_logical is not None:
            if boundary_data is None:
                raise ReleaseError("network boundary did not emit its receipt")
            boundary_record = _validate_boundary_receipt(
                boundary_data, identity=identity, logical=boundary_logical
            )
        elif boundary_data is not None:
            raise ReleaseError("untraced gate emitted unexpected network-boundary data")
        if payload_path.is_symlink() or not payload_path.is_file():
            raise ReleaseError("gate command did not create its structured payload")
        payload = read_json(payload_path)
        if not isinstance(payload, dict):
            raise ReleaseError("gate payload is not a JSON object")
        if not (payload.get("pass") is True or payload.get("result") == "pass"):
            raise ReleaseError("gate payload is not an explicit pass")
        observations = dict(trace_counts)
        if args.gate == "source-suite":
            for field in ("tests_run", "failures", "errors"):
                value = payload.get(field)
                if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                    raise ReleaseError(f"source-suite payload lacks {field}")
                observations[field] = value
            if payload["tests_run"] <= 0 or payload["failures"] or payload["errors"]:
                raise ReleaseError("source suite did not pass with nonzero coverage")
        envelope = gate_envelope(
            identity=identity,
            identity_contract_sha256=identity_sha256(identity_path),
            gate=args.gate,
            subjects=record["subjects"],
            invocation={
                "argv": logical_command,
                "cwd": execution["cwd"],
                "environment": environment,
                "exit_status": returncode,
                "generator": execution["generator"],
                "script": execution["script"],
                "source_tree": execution["source_tree"],
                "timeout_seconds": execution["timeout_seconds"],
                "tool": tool_record,
                "stdout": stream_evidence_record(stdout),
                "stderr": stream_evidence_record(stderr),
            },
            coverage={
                "descendant_processes": max(
                    1,
                    trace_counts["processes"],
                    containment["observed_descendants"] + 1,
                ),
                "full_descendant_coverage": (
                    False
                ),
                "network_trace": network_record,
                "network_boundary": boundary_record,
                "observations": observations,
                "process_containment": containment,
                "trace_complete": True,
                "trace_truncated": False,
            },
            payload=payload,
        )
    assert_relative_json(envelope, label="generated gate envelope")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(json_bytes(envelope))
    return envelope


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--identity", required=True, type=Path)
    parser.add_argument("--gate", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--source-checkout", required=True, type=Path)
    parser.add_argument("--artifacts-dir", type=Path)
    parser.add_argument("--gate-input", action="append", default=[])
    args = parser.parse_args()
    result = generate(args)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ReleaseError, OSError, ValueError, json.JSONDecodeError) as exc:
        raise SystemExit(f"error: {exc}") from exc
