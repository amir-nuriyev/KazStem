#!/usr/bin/env python3
"""Generate the final optimization ledger from strict compression and behavior gates."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from release_common import (
    ReleaseError,
    assert_relative_json,
    file_record,
    identity_sha256,
    json_bytes,
    load_identity,
    read_json,
    validate_compression_comparison,
    validate_gate_envelope,
    verify_file,
)


def _payload(
    path: Path, gate: str, identity: dict[str, Any], digest: str
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    record = next(
        item for item in identity["verification"]["evidence"] if item["gate"] == gate
    )
    verify_file(path, record["file"], label=f"optimization input {gate}")
    envelope = read_json(path)
    payload = validate_gate_envelope(
        envelope,
        identity=identity,
        identity_contract_sha256=digest,
        gate=gate,
        subjects=record["subjects"],
    )
    if not (payload.get("pass") is True or payload.get("result") == "pass"):
        raise ReleaseError(f"optimization behavior input did not pass: {gate}")
    return envelope, payload, record


def generate(args: argparse.Namespace) -> dict[str, Any]:
    if args.output.exists() or args.output.is_symlink():
        raise ReleaseError(f"optimization ledger already exists: {args.output}")
    identity_path = args.identity.resolve(strict=True)
    identity = load_identity(identity_path)
    digest = identity_sha256(identity_path)
    _, compression_payload, compression_record = _payload(
        args.compression_evidence.resolve(strict=True),
        "compression-comparison",
        identity,
        digest,
    )
    compression_payload = validate_compression_comparison(
        compression_payload,
        identity=identity,
        identity_contract_sha256=digest,
    )
    behavior_records: dict[str, dict[str, Any]] = {}
    for gate, path in (
        ("blackbox", args.blackbox_evidence.resolve(strict=True)),
        ("practical", args.practical_evidence.resolve(strict=True)),
    ):
        _, _, behavior_identity_record = _payload(path, gate, identity, digest)
        behavior_records[gate] = {
            "path": behavior_identity_record["path"],
            **file_record(path),
        }
    accepted: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    selected_outputs: dict[str, dict[str, Any]] = {}
    for target in compression_payload["targets"]:
        selected = next(
            candidate
            for candidate in target["candidates"]
            if candidate["name"] == target["selected"]
        )
        selected_outputs[target["artifact"]] = target["selected_output"]
        accepted.append(
            {
                "artifact": target["artifact"],
                "name": selected["name"],
                "filename": selected["filename"],
                "bytes": selected["bytes"],
                "sha256": selected["sha256"],
                "tradeoff": selected["tradeoff"],
                "reason": "exact minimum eligible compressed size and all behavior gates passed",
            }
        )
        rejected.extend(
            {"artifact": target["artifact"], **item}
            for item in target["rejected"]
        )
    result = {
        "schema": "kazstem-linux-final-optimization-decision-ledger-v2",
        "pass": True,
        "release": identity["release"],
        "source_commit": identity["source_commit"],
        "source_tree": identity["source_tree"],
        "identity_contract_sha256": digest,
        "compression_evidence": {
            "path": compression_record["path"],
            **file_record(args.compression_evidence),
        },
        "behavior_evidence": behavior_records,
        "selection_rule": compression_payload["selection_rule"],
        "candidate_bindings": compression_payload["targets"],
        "selected_outputs": selected_outputs,
        "accepted": accepted,
        "rejected": rejected,
        "behavior_gates": ["blackbox", "practical"],
        "final_behavior_gate": "pass",
    }
    assert_relative_json(result, label="optimization ledger")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(json_bytes(result))
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--identity", required=True, type=Path)
    parser.add_argument("--compression-evidence", required=True, type=Path)
    parser.add_argument("--blackbox-evidence", required=True, type=Path)
    parser.add_argument("--practical-evidence", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    result = generate(args)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ReleaseError, OSError, ValueError, json.JSONDecodeError) as exc:
        raise SystemExit(f"error: {exc}") from exc
