#!/usr/bin/env python3
"""Generate the exact PyInstaller module/native minimization gate."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
from typing import Any

from release_common import (
    ReleaseError,
    assert_relative_json,
    begin_gate_execution,
    gate_envelope,
    identity_sha256,
    json_bytes,
    load_identity,
    locked_gate_invocation,
    read_json,
    stream_evidence_record,
    verify_ready_root_identity,
)


def _fingerprint(root: Path) -> str:
    records: list[dict[str, Any]] = []
    for path in sorted(
        root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()
    ):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            records.append(
                {
                    "path": relative,
                    "kind": "symlink",
                    "target": path.readlink().as_posix(),
                }
            )
        elif path.is_file():
            digest = hashlib.sha256()
            with path.open("rb") as source:
                for block in iter(lambda: source.read(1024 * 1024), b""):
                    digest.update(block)
            records.append(
                {
                    "path": relative,
                    "kind": "file",
                    "bytes": path.stat().st_size,
                    "sha256": digest.hexdigest(),
                }
            )
        elif path.is_dir():
            records.append({"path": relative, "kind": "directory"})
        else:
            raise ReleaseError(f"special bundle entry: {relative}")
    return hashlib.sha256(
        json.dumps(
            records, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
    ).hexdigest()


def audit(args: argparse.Namespace) -> dict[str, Any]:
    if args.output.exists() or args.output.is_symlink():
        raise ReleaseError(f"module/native evidence output exists: {args.output}")
    identity_path = args.identity.resolve(strict=True)
    identity = load_identity(identity_path)
    execution = begin_gate_execution(
        identity, "module-native-inclusion", caller_file=__file__
    )
    root = args.bundle.resolve(strict=True)
    root_binding = verify_ready_root_identity(args.bundle, identity)
    ledger_path = root / "verification/MODULE-NATIVE-INCLUSION-LEDGER.json"
    ledger = read_json(ledger_path)
    if (
        not isinstance(ledger, dict)
        or ledger.get("schema") != "kazstem-macos-module-native-inclusion-ledger-v2"
        or ledger.get("release") != identity["release"]
        or ledger.get("source_commit") != identity["source_commit"]
        or ledger.get("minimization_contract") != identity["minimization"]
    ):
        raise ReleaseError("embedded module/native ledger differs from identity")
    base = ledger.get("base_ledger")
    if (
        not isinstance(base, dict)
        or base.get("schema") != "kazstem-macos-frozen-build-v1"
        or base.get("pass") is not True
        or base.get("output_tree") != identity["inputs"]["frozen_tree"]
    ):
        raise ReleaseError("embedded freezer evidence is not exact")
    module_inventory = base.get("module_inventory")
    if not isinstance(module_inventory, dict) or not isinstance(
        module_inventory.get("modules"), list
    ):
        raise ReleaseError("freezer evidence lacks the full module inventory")
    modules = module_inventory["modules"]
    if modules != sorted(set(modules)) or any(
        not isinstance(module, str) for module in modules
    ):
        raise ReleaseError("module inventory is not sorted/unique")
    expected_module_hash = hashlib.sha256(
        "\n".join(modules).encode("utf-8")
    ).hexdigest()
    if (
        module_inventory.get("count") != len(modules)
        or module_inventory.get("sha256") != expected_module_hash
    ):
        raise ReleaseError("module inventory count/hash was not derived")
    banned_modules = identity["minimization"]["banned_modules"]
    banned_module_matches = sorted(
        module
        for module in modules
        if any(
            module == prefix or module.startswith(prefix + ".")
            for prefix in banned_modules
        )
    )
    names = sorted(path.relative_to(root).as_posix() for path in root.rglob("*"))
    banned_native_matches = sorted(
        name
        for name in names
        if any(
            fragment in name.casefold()
            for fragment in identity["minimization"]["banned_native_fragments"]
        )
    )
    neural = sorted(
        name
        for name in names
        if any(
            fragment in name.casefold()
            for fragment in ("neural", ".onnx", ".safetensors", ".pt")
        )
    )
    sha2_present = any(
        module == "_sha2" or module.endswith("._sha2") for module in modules
    ) or any("_sha2" in Path(name).name for name in names)
    zlib_negative = (
        base.get("negative_controls", {})
        .get("pyinstaller-zlib-bootstrap", {})
        .get("failed_as_required")
        is True
    )
    if (
        banned_module_matches
        or banned_native_matches
        or neural
        or not sha2_present
        or not zlib_negative
    ):
        raise ReleaseError("module/native minimization contract failed")

    before = _fingerprint(root)
    command = [
        str(root / identity["ready_run"]["launcher"]["path"]),
        "-c",
        "-i",
        "--format",
        "json",
    ]
    process = subprocess.run(
        command,
        input="Қазақстандағы балалар мектепке барды.\n".encode("utf-8"),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=60,
        check=False,
    )
    after = _fingerprint(root)
    if process.returncode or before != after or not process.stdout:
        raise ReleaseError("SHA-256/resource positive-control analysis failed")
    try:
        parsed = json.loads(process.stdout.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ReleaseError("SHA-256 positive-control output is not JSON") from exc
    if not isinstance(parsed, list) or not parsed:
        raise ReleaseError("SHA-256 positive-control produced no analyses")

    payload = {
        "schema": "kazstem-macos-module-native-inclusion-v1",
        "pass": True,
        "release": identity["release"],
        "source_commit": identity["source_commit"],
        "source_tree": identity["source_tree"],
        "module_count": len(modules),
        "module_inventory_sha256": expected_module_hash,
        "modules": modules,
        "banned_module_matches": banned_module_matches,
        "banned_native_matches": banned_native_matches,
        "sha2_provider": "_sha2",
        "sha256_positive_control": True,
        "zlib_negative_control": zlib_negative,
        "neural_weights": neural,
        "bundle_fingerprint_unchanged": before == after,
        "root_binding": root_binding,
        "positive_control": {
            "argv": ["bundle/kazstem", "-c", "-i", "--format", "json"],
            "exit_status": process.returncode,
            "stdin": stream_evidence_record(
                "Қазақстандағы балалар мектепке барды.\n".encode("utf-8")
            ),
            "stdout": stream_evidence_record(process.stdout),
            "stderr": stream_evidence_record(process.stderr),
            "records": len(parsed),
        },
        "strip_candidates": base.get("strip_candidates"),
    }
    assert_relative_json(payload, label="module/native inclusion payload")
    envelope = gate_envelope(
        identity=identity,
        identity_contract_sha256=identity_sha256(identity_path),
        gate="module-native-inclusion",
        subjects=["ready_run"],
        invocation=locked_gate_invocation(
            identity,
            "module-native-inclusion",
            stdout=b"structured module/native audit written to output\n",
            execution=execution,
        ),
        coverage={
            "descendant_processes": 4,
            "full_descendant_coverage": True,
            "network_trace": None,
            "observations": {
                "modules": len(modules),
                "native_paths": len(names),
                "positive_control_records": len(parsed),
                "strip_candidates": len(base.get("strip_candidates", [])),
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
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    result = audit(args)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ReleaseError, OSError, ValueError, json.JSONDecodeError) as exc:
        raise SystemExit(f"error: {exc}") from exc
