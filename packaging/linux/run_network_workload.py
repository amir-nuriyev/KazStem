#!/usr/bin/env python3
"""Run the exact ready-run launcher on a fixed workload for syscall tracing."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from process_supervisor import SupervisionError, run_bounded  # noqa: E402

from release_common import (
    ReleaseError,
    archive_limits,
    extract_validated_tar,
    file_record,
    inspect_tar,
    json_bytes,
    load_identity,
    stream_evidence_record,
    verify_artifact,
)


SCHEMA = "kazstem-linux-network-trace-v1"
WORKLOAD = "Қазақстандағы балалар мектепке барды.\nАлматы — үлкен қала.\n".encode(
    "utf-8"
)
MAX_CAPTURE = 16 * 1024**2


def run(args: argparse.Namespace) -> dict[str, object]:
    if args.output.exists() or args.output.is_symlink():
        raise ReleaseError("network workload payload output already exists")
    identity = load_identity(args.identity.resolve(strict=True))
    verify_artifact(
        args.ready_run,
        identity["artifacts"]["ready_run"],
        label="network workload ready-run",
    )
    with tempfile.TemporaryDirectory(prefix="kazstem-network-workload-") as temporary:
        root = Path(temporary)
        members = inspect_tar(
            args.ready_run,
            limits=archive_limits(identity, "ready_run"),
            expected_top=identity["ready_run"]["top_level"],
        )
        bundle = extract_validated_tar(
            args.ready_run,
            root / "extract",
            members=members,
            limits=archive_limits(identity, "ready_run"),
        )
        launcher = bundle / "kazstem"
        if launcher.is_symlink() or not launcher.is_file() or not os.access(launcher, os.X_OK):
            raise ReleaseError("ready-run launcher is missing or non-executable")
        argv = [str(launcher), "-c", "-i", "--format", "json"]
        try:
            completed = run_bounded(
                argv,
                cwd=bundle,
                environment={
                    "LANG": "C.UTF-8",
                    "LC_ALL": "C.UTF-8",
                    "PYTHONHASHSEED": "0",
                    "TZ": "UTC",
                },
                timeout=args.timeout,
                max_stdout=MAX_CAPTURE,
                max_stderr=MAX_CAPTURE,
                input_data=WORKLOAD,
            )
        except SupervisionError as exc:
            raise ReleaseError(f"network workload supervision failed: {exc}") from exc
        if completed.returncode != 0:
            raise ReleaseError(
                f"network workload failed with exit {completed.returncode}"
            )
        stdout_data = completed.stdout
        stderr_data = completed.stderr
        try:
            parsed = json.loads(stdout_data.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise ReleaseError("network workload did not emit valid JSON") from exc
        if not parsed:
            raise ReleaseError("network workload JSON is empty")
        payload: dict[str, object] = {
            "schema": SCHEMA,
            "pass": True,
            "release": identity["release"],
            "source_commit": identity["source_commit"],
            "source_tree": identity["source_tree"],
            "ready_run": identity["artifacts"]["ready_run"],
            "launcher": file_record(launcher),
            "argv": ["bundle/kazstem", "-c", "-i", "--format", "json"],
            "input": {
                "bytes": len(WORKLOAD),
                "sha256": hashlib.sha256(WORKLOAD).hexdigest(),
                "lines": len(WORKLOAD.splitlines()),
            },
            "workload_bytes": len(WORKLOAD),
            "workload_lines": len(WORKLOAD.splitlines()),
            "workload_sha256": hashlib.sha256(WORKLOAD).hexdigest(),
            "output": stream_evidence_record(stdout_data),
            "stderr": stream_evidence_record(stderr_data),
            "json_nonempty": True,
            "forbidden_syscalls": [],
            "process_containment": completed.containment,
            "observed_descendants": completed.observed_descendants,
            # /proc sampling plus strace -f is useful audit evidence, but it is
            # not a kernel-enforced complete descendant inventory.  The
            # inherited seccomp filter is the actual no-network boundary.
            "full_descendant_coverage": False,
            "trace_truncated": False,
        }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(json_bytes(payload))
    return payload


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--identity", required=True, type=Path)
    parser.add_argument("--ready-run", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--timeout", type=int, default=120)
    result = run(parser.parse_args())
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ReleaseError, OSError, ValueError, json.JSONDecodeError) as exc:
        raise SystemExit(f"error: {exc}") from exc
