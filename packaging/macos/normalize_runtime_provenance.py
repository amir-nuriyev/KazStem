#!/usr/bin/env python3
"""Force-rehash official runtime provenance through the canonical wheel API."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import tempfile
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
    verify_artifact,
    verify_darwin_loader_provenance,
    verify_ready_root_identity,
)


PROBE = r"""
import json
import os
from pathlib import Path
from qazmorph.backend import FSTBackend
root = Path(os.environ['KAZSTEM_BUNDLE_ROOT'])
provenance = FSTBackend(resource_dir=root / os.environ['KAZSTEM_RESOURCE_DEST']).runtime_provenance()
print(json.dumps(provenance, ensure_ascii=False, sort_keys=True, separators=(',', ':')))
"""


def _normalize_paths(value: Any, root: Path) -> Any:
    if isinstance(value, str) and value.startswith("/"):
        try:
            relative = Path(value).resolve(strict=False).relative_to(root)
        except ValueError as exc:
            raise ReleaseError(
                f"provenance contains an external absolute path: {value!r}"
            ) from exc
        return f"bundle/{relative.as_posix()}"
    if isinstance(value, list):
        return [_normalize_paths(item, root) for item in value]
    if isinstance(value, dict):
        return {
            _normalize_paths(key, root): _normalize_paths(item, root)
            for key, item in value.items()
        }
    return value


def verify(args: argparse.Namespace) -> dict[str, Any]:
    if args.output.exists() or args.output.is_symlink():
        raise ReleaseError("runtime-provenance output already exists")
    identity_path = args.identity.resolve(strict=True)
    identity = load_identity(identity_path)
    execution = begin_gate_execution(
        identity, "runtime-provenance", caller_file=__file__
    )
    root = args.bundle.resolve(strict=True)
    root_binding = verify_ready_root_identity(args.bundle, identity)
    wheel = args.wheel.resolve(strict=True)
    verify_artifact(wheel, identity["artifacts"]["wheel"], label="provenance wheel")
    with tempfile.TemporaryDirectory(prefix="kazstem-provenance-") as temporary:
        workspace = Path(temporary)
        venv = workspace / "venv"
        environment = {
            "HOME": str(workspace / "home"),
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": "/usr/bin:/bin",
            "PYTHONHASHSEED": "0",
            "TZ": "UTC",
        }
        (workspace / "home").mkdir()
        create = subprocess.run(
            [
                str(args.python.resolve(strict=True)),
                "-m",
                "venv",
                "--copies",
                str(venv),
            ],
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=180,
            check=False,
        )
        if create.returncode:
            raise ReleaseError("runtime-provenance venv creation failed")
        python = venv / "bin/python3"
        if not python.is_file():
            python = venv / "bin/python"
        install = subprocess.run(
            [
                str(python),
                "-m",
                "pip",
                "install",
                "--disable-pip-version-check",
                "--no-index",
                "--no-deps",
                str(wheel),
            ],
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=180,
            check=False,
        )
        if install.returncode:
            raise ReleaseError("runtime-provenance wheel install failed")
        probe_environment = {
            **environment,
            "KAZSTEM_BUNDLE_ROOT": str(root),
            "KAZSTEM_RESOURCE_DEST": identity["ready_run"]["resource_destination"],
            "QAZMORPH_RESOURCE_DIR": str(
                root / identity["ready_run"]["resource_destination"]
            ),
        }
        probe = subprocess.run(
            [str(python), "-c", PROBE],
            env=probe_environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=180,
            check=False,
        )
    if probe.returncode:
        raise ReleaseError("runtime-provenance force-rehash probe failed")
    try:
        provenance = json.loads(probe.stdout.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ReleaseError("runtime-provenance probe returned invalid JSON") from exc
    runtime_id = identity["inputs"]["runtime_tree"]["bundle_id"]
    if (
        not isinstance(provenance, dict)
        or provenance.get("verified") is not True
        or provenance.get("official") is not True
        or provenance.get("non_official_reasons") != []
        or provenance.get("active_runtime", {}).get("origin") != "platform-runtime-lock"
        or provenance.get("active_runtime", {}).get("bundle_id") != runtime_id
    ):
        raise ReleaseError("runtime provenance is not official/verified/identity-bound")
    for name in ("resource_inventory", "toolchain_inventory"):
        inventory = provenance.get(name)
        if (
            not isinstance(inventory, dict)
            or inventory.get("verified") is not True
            or inventory.get("sealed_read_only") is not True
            or inventory.get("writable_directories") != 0
            or inventory.get("writable_entries") != 0
        ):
            raise ReleaseError(f"runtime provenance {name} is not fully sealed")
    executables = provenance.get("executables")
    if not isinstance(executables, dict):
        raise ReleaseError("runtime provenance lacks executable records")
    for name in ("hfst-proc", "hfst-optimized-lookup", "cg-proc"):
        record = executables.get(name)
        if (
            not isinstance(record, dict)
            or record.get("verified") is not True
            or record.get("origin") != "platform-runtime-lock"
        ):
            raise ReleaseError(f"runtime provenance command is invalid: {name}")
    loader_environment = verify_darwin_loader_provenance(provenance)
    provenance = _normalize_paths(provenance, root)
    payload = {
        "schema": "kazstem-macos-runtime-provenance-v2",
        "pass": True,
        "release": identity["release"],
        "source_commit": identity["source_commit"],
        "source_tree": identity["source_tree"],
        "official": True,
        "verified": True,
        "non_official_reasons": [],
        "runtime_bundle_id": runtime_id,
        "resource_bundle_id": identity["inputs"]["resource_tree"]["bundle_id"],
        "force_rehash": True,
        "loader_environment": loader_environment,
        "provenance": provenance,
        "root_binding": root_binding,
        "commands": [
            {
                "argv": ["python", "-m", "venv", "--copies", "workspace/venv"],
                "exit_status": create.returncode,
                "stdout": stream_evidence_record(create.stdout),
                "stderr": stream_evidence_record(create.stderr),
            },
            {
                "argv": [
                    "workspace/venv/bin/python",
                    "-m",
                    "pip",
                    "install",
                    "--no-index",
                    "--no-deps",
                    identity["artifacts"]["wheel"]["filename"],
                ],
                "exit_status": install.returncode,
                "stdout": stream_evidence_record(install.stdout),
                "stderr": stream_evidence_record(install.stderr),
            },
            {
                "argv": ["workspace/venv/bin/python", "checked-provenance-probe"],
                "exit_status": probe.returncode,
                "stdout": stream_evidence_record(probe.stdout),
                "stderr": stream_evidence_record(probe.stderr),
            },
        ],
    }
    assert_relative_json(payload, label="runtime provenance payload")
    envelope = gate_envelope(
        identity=identity,
        identity_contract_sha256=identity_sha256(identity_path),
        gate="runtime-provenance",
        subjects=["ready_run", "wheel"],
        invocation=locked_gate_invocation(
            identity,
            "runtime-provenance",
            stdout=b"PASS: official force-rehashed runtime provenance\n",
            execution=execution,
        ),
        coverage={
            "descendant_processes": 4,
            "full_descendant_coverage": True,
            "network_trace": None,
            "observations": {
                "commands": len(executables),
                "force_rehash": 1,
                "loader_ambient_records": len(
                    loader_environment["captured_ambient_names"]
                ),
                "loader_legacy_records": loader_environment[
                    "legacy_loader_records"
                ],
                "resource_files": provenance["resource_inventory"].get("files", 0),
                "runtime_files": provenance["toolchain_inventory"].get("files", 0),
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
    parser.add_argument("--wheel", required=True, type=Path)
    parser.add_argument("--python", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    verify(args)
    print("PASS: official force-rehashed runtime provenance")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ReleaseError, OSError, ValueError, json.JSONDecodeError) as exc:
        raise SystemExit(f"error: {exc}") from exc
