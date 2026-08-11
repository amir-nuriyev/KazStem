#!/usr/bin/env python3
"""Record path-free host and Python evidence for a Windows runtime candidate."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import platform
import re
import struct
import subprocess
import sys


WINDOWS_PACKAGING_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(WINDOWS_PACKAGING_ROOT))

from evidence_path_contract import absolute_path_kind  # noqa: E402


SHA1 = re.compile(r"[0-9a-f]{40}")
GIT_TIMEOUT_SECONDS = 10


class HostEvidenceError(RuntimeError):
    pass


def git_head(root: Path) -> str:
    try:
        completed = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=root,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=GIT_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise HostEvidenceError("Git candidate verification timed out") from exc
    if (
        completed.returncode
        or len(completed.stdout) > 128
        or len(completed.stderr) > 64 * 1024
    ):
        raise HostEvidenceError("cannot verify candidate Git HEAD")
    try:
        return completed.stdout.decode("ascii", "strict").strip()
    except UnicodeError as exc:
        raise HostEvidenceError("candidate Git HEAD is not ASCII") from exc


def required_text(value: str, *, label: str) -> str:
    if not value or "\x00" in value or "\r" in value or "\n" in value:
        raise HostEvidenceError(f"invalid {label}")
    return value


def evidence_strings(value: object):
    if isinstance(value, str):
        yield value
    elif isinstance(value, list):
        for item in value:
            yield from evidence_strings(item)
    elif isinstance(value, dict):
        for key, item in value.items():
            yield str(key)
            yield from evidence_strings(item)


def build_evidence(args: argparse.Namespace) -> dict[str, object]:
    candidate_sha = required_text(args.candidate_sha, label="candidate SHA")
    if SHA1.fullmatch(candidate_sha) is None:
        raise HostEvidenceError("candidate SHA must be lowercase 40-hex")
    observed_head = git_head(args.root)
    if observed_head != candidate_sha:
        raise HostEvidenceError("checked-out HEAD differs from candidate SHA")
    if args.runner_label != "windows-2022":
        raise HostEvidenceError("unexpected requested runner label")
    if args.runner_os != "Windows" or args.runner_arch != "X64":
        raise HostEvidenceError("unexpected GitHub runner platform")
    if args.event_name not in {"pull_request", "workflow_dispatch"}:
        raise HostEvidenceError("unexpected GitHub event")
    if not args.run_id.isascii() or not args.run_id.isdigit():
        raise HostEvidenceError("GitHub run ID must be decimal")
    actual_system = platform.system()
    actual_machine = platform.machine()
    implementation = platform.python_implementation()
    python_version = platform.python_version()
    pointer_bits = struct.calcsize("P") * 8
    if (
        actual_system != "Windows"
        or actual_machine.casefold() not in {"amd64", "x86_64"}
        or implementation != "CPython"
        or python_version != "3.14.3"
        or pointer_bits != 64
    ):
        raise HostEvidenceError("actual host/Python differs from the Windows build contract")
    evidence = {
        "schema": "kazstem-windows-host-evidence-v1",
        "result": "pass",
        "candidate": {
            "sha": candidate_sha,
            "git_head": observed_head,
        },
        "github": {
            "event_name": required_text(args.event_name, label="event name"),
            "run_id": args.run_id,
        },
        "runner": {
            "requested_label": args.runner_label,
            "RUNNER_OS": args.runner_os,
            "RUNNER_ARCH": args.runner_arch,
            "ImageOS": required_text(args.image_os, label="ImageOS"),
            "ImageVersion": required_text(
                args.image_version, label="ImageVersion"
            ),
        },
        "host": {
            "system": actual_system,
            "release": platform.release(),
            "version": platform.version(),
            "machine": actual_machine,
        },
        "python": {
            "implementation": implementation,
            "version": python_version,
            "pointer_bits": pointer_bits,
        },
    }
    if any(
        absolute_path_kind(value) is not None
        for value in evidence_strings(evidence)
    ):
        raise HostEvidenceError("host evidence contains a machine-absolute path")
    return evidence


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--candidate-sha", required=True)
    parser.add_argument("--runner-label", required=True)
    parser.add_argument("--runner-os", required=True)
    parser.add_argument("--runner-arch", required=True)
    parser.add_argument("--image-os", required=True)
    parser.add_argument("--image-version", required=True)
    parser.add_argument("--event-name", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    args.root = args.root.resolve(strict=True)
    evidence = build_evidence(args)
    args.output.write_text(
        json.dumps(evidence, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (HostEvidenceError, OSError) as error:
        raise SystemExit(f"error: {error}") from error
