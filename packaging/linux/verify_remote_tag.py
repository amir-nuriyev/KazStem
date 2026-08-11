#!/usr/bin/env python3
"""Prove that the public Git origin exposes the exact annotated release tag."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
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
    "_kazstem_remote_tag_release_common", _tool_directory / "release_common.py"
)
_supervisor = _source_module(
    "_kazstem_remote_tag_process_supervisor",
    _tool_directory.parent / "process_supervisor.py",
)
ReleaseError = _common.ReleaseError
SOURCE_AUTHORITY_SCHEMA = _common.SOURCE_AUTHORITY_SCHEMA
file_record = _common.file_record
json_bytes = _common.json_bytes
load_identity = _common.load_identity
remote_tag_argv = _common.remote_tag_argv
stream_evidence_record = _common.stream_evidence_record
validate_source_authority_payload = _common.validate_source_authority_payload
verify_file = _common.verify_file
SupervisionError = _supervisor.SupervisionError
run_bounded = _supervisor.run_bounded


MAX_CAPTURE_BYTES = 1024 * 1024


def _git_tool(identity: dict[str, Any], *, cwd: Path, environment: dict[str, str]) -> tuple[Path, dict[str, Any]]:
    tools = {
        record["name"]: record
        for record in identity["verification"]["reproducibility"]["tools"]
    }
    expected = tools.get("git")
    if expected is None:
        raise ReleaseError("source authority lacks an identity-bound Git tool")
    located = shutil.which("git")
    if located is None:
        raise ReleaseError("source authority cannot locate Git")
    executable = Path(located).resolve(strict=True)
    verify_file(executable, expected["executable"], label="source authority Git")
    try:
        completed = run_bounded(
            [str(executable), *expected["version_argv"][1:]],
            cwd=cwd,
            environment=environment,
            timeout=60,
            max_stdout=MAX_CAPTURE_BYTES,
            max_stderr=MAX_CAPTURE_BYTES,
        )
    except SupervisionError as exc:
        raise ReleaseError(f"Git version query was not contained: {exc}") from exc
    observed = (completed.stdout + completed.stderr).decode("utf-8", "replace").strip()
    if completed.returncode != 0 or observed != expected["version"]:
        raise ReleaseError("source authority Git version differs from identity")
    return executable, expected


def verify(args: argparse.Namespace) -> dict[str, Any]:
    if args.output.exists() or args.output.is_symlink():
        raise ReleaseError("source authority output already exists")
    identity_path = args.identity.resolve(strict=True)
    identity = load_identity(identity_path)
    helpers = {
        record["path"]: record["file"]
        for record in identity["verification"]["reproducibility"]["helpers"]
    }
    verify_file(
        Path(_common.__file__).resolve(strict=True),
        helpers["packaging/linux/release_common.py"],
        label="loaded source authority release_common helper",
    )
    verify_file(
        Path(_supervisor.__file__).resolve(strict=True),
        helpers["packaging/process_supervisor.py"],
        label="loaded source authority process supervisor helper",
    )
    with tempfile.TemporaryDirectory(prefix="kazstem-remote-tag-") as temporary:
        controlled_home = Path(temporary) / "home"
        controlled_home.mkdir()
        environment = {
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_TERMINAL_PROMPT": "0",
            "HOME": str(controlled_home),
            "LANG": "C",
            "LC_ALL": "C",
            "TZ": "UTC",
        }
        git, git_record = _git_tool(
            identity, cwd=Path.cwd().resolve(strict=True), environment=environment
        )
        logical_argv = remote_tag_argv(identity)
        actual_argv = [str(git), *logical_argv[1:]]
        try:
            completed = run_bounded(
                actual_argv,
                cwd=Path.cwd().resolve(strict=True),
                environment=environment,
                timeout=300,
                max_stdout=MAX_CAPTURE_BYTES,
                max_stderr=MAX_CAPTURE_BYTES,
            )
        except SupervisionError as exc:
            raise ReleaseError(f"authoritative remote query was not contained: {exc}") from exc
    if completed.returncode != 0:
        detail = completed.stderr[:4096].decode("utf-8", "replace")
        raise ReleaseError(
            f"authoritative remote tag query failed with exit {completed.returncode}: {detail}"
        )
    if completed.stderr:
        raise ReleaseError("authoritative remote tag query emitted stderr")
    expected_records = [
        {"object": identity["source_tag_object"], "ref": identity["source_ref"]},
        {
            "object": identity["source_commit"],
            "ref": f"{identity['source_ref']}^{{}}",
        },
    ]
    expected_stdout = "".join(
        f"{record['object']}\t{record['ref']}\n" for record in expected_records
    ).encode("ascii")
    if completed.stdout != expected_stdout:
        raise ReleaseError(
            "public origin does not expose the exact annotated tag object and peeled commit"
        )
    payload = {
        "schema": SOURCE_AUTHORITY_SCHEMA,
        "pass": True,
        "release": identity["release"],
        "source_commit": identity["source_commit"],
        "source_tree": identity["source_tree"],
        "source_origin": identity["source_origin"],
        "source_ref": identity["source_ref"],
        "source_tag_object": identity["source_tag_object"],
        "annotated_tag": True,
        "authoritative_remote": True,
        "remote": {
            "argv": logical_argv,
            "exit_status": completed.returncode,
            "records": expected_records,
            "stdout": stream_evidence_record(completed.stdout),
            "stderr": stream_evidence_record(completed.stderr),
            "tool": git_record,
        },
    }
    validate_source_authority_payload(payload, identity=identity)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(json_bytes(payload))
    return payload


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--identity", required=True, type=Path)
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
