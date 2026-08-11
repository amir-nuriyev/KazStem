#!/usr/bin/env python3
"""Derive the final measured-only optimization ledger from exact gate evidence."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
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
    read_json,
    validate_gate_envelope,
    verify_file,
)


def _payload(
    path: Path,
    *,
    identity: dict[str, Any],
    digest: str,
    gate: str,
) -> dict[str, Any]:
    record = next(
        item for item in identity["verification"]["evidence"] if item["gate"] == gate
    )
    verify_file(path, record["file"], label=f"{gate} evidence")
    return validate_gate_envelope(
        read_json(path),
        identity=identity,
        identity_contract_sha256=digest,
        gate=gate,
        subjects=record["subjects"],
    )


def write(args: argparse.Namespace) -> dict[str, Any]:
    if args.output.exists() or args.output.is_symlink():
        raise ReleaseError("optimization ledger output already exists")
    identity_path = args.identity.resolve(strict=True)
    identity = load_identity(identity_path)
    execution = begin_gate_execution(
        identity, "optimization-ledger", caller_file=__file__
    )
    digest = identity_sha256(identity_path)
    practical = _payload(
        args.practical.resolve(strict=True),
        identity=identity,
        digest=digest,
        gate="practical",
    )
    compression = _payload(
        args.compression.resolve(strict=True),
        identity=identity,
        digest=digest,
        gate="compression-comparison",
    )
    macho = _payload(
        args.macho.resolve(strict=True),
        identity=identity,
        digest=digest,
        gate="macho-closure",
    )
    modules = _payload(
        args.modules.resolve(strict=True),
        identity=identity,
        digest=digest,
        gate="module-native-inclusion",
    )
    if (
        practical.get("result") != "pass"
        or practical.get("bundle_fingerprint_unchanged") is not True
    ):
        raise ReleaseError("final practical behavior gate is not clean")
    if macho.get("missing") or macho.get("banned_dependencies"):
        raise ReleaseError("optimization input has an open Mach-O closure")
    if modules.get("banned_module_matches") or modules.get("banned_native_matches"):
        raise ReleaseError("optimization input retains banned modules/native files")
    strip_candidates = modules.get("strip_candidates")
    if not isinstance(strip_candidates, list) or not strip_candidates:
        raise ReleaseError("optimization input lacks measured strip candidates")
    accepted: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    saved = 0
    for candidate in strip_candidates:
        if not isinstance(candidate, dict) or not isinstance(
            candidate.get("path"), str
        ):
            raise ReleaseError("strip candidate record is malformed")
        if candidate.get("selected") is True:
            before = candidate.get("before")
            after = candidate.get("candidate")
            if (
                not isinstance(before, dict)
                or not isinstance(after, dict)
                or not isinstance(before.get("bytes"), int)
                or not isinstance(after.get("bytes"), int)
                or after["bytes"] >= before["bytes"]
                or candidate.get("architectures_equal") is not True
                or candidate.get("dependencies_equal") is not True
            ):
                raise ReleaseError("accepted strip candidate lacks size/static parity")
            delta = before["bytes"] - after["bytes"]
            saved += delta
            accepted.append(
                {
                    "kind": "macho-strip-resign",
                    "path": candidate["path"],
                    "bytes_saved": delta,
                    "before": before,
                    "after": after,
                    "reason": candidate["reason"],
                }
            )
        else:
            rejected.append(
                {
                    "kind": "macho-strip-resign",
                    "path": candidate["path"],
                    "reason": candidate.get("reason"),
                }
            )
    compression_decisions: dict[str, Any] = {}
    for asset_name, comparison in compression["assets"].items():
        selected = comparison["selected"]
        candidates = comparison["candidates"]
        eligible = [candidate for candidate in candidates if candidate["eligible"]]
        if (
            selected["format"]
            != min(
                eligible,
                key=lambda candidate: (candidate["bytes"], candidate["format"]),
            )["format"]
        ):
            raise ReleaseError("compression decision is not the eligible byte minimum")
        compression_decisions[asset_name] = {
            "canonical_tar": comparison["canonical_tar"],
            "selected": selected,
            "rejected": [
                {
                    "format": candidate["format"],
                    "bytes": candidate["bytes"],
                    "eligible": candidate["eligible"],
                    "reason": (
                        candidate["eligibility_reason"]
                        if not candidate["eligible"]
                        else "larger-than-selected"
                    ),
                }
                for candidate in candidates
                if candidate["format"] != selected["format"]
            ],
        }
    payload = {
        "schema": "kazstem-macos-final-optimization-decision-ledger-v1",
        "pass": True,
        "release": identity["release"],
        "source_commit": identity["source_commit"],
        "source_tree": identity["source_tree"],
        "claim_scope": identity["minimization"]["claim_scope"],
        "accepted": accepted,
        "rejected": rejected,
        "strip_bytes_saved": saved,
        "compression": compression_decisions,
        "module_contract": identity["minimization"],
        "sha2_positive_control": modules["sha256_positive_control"],
        "zlib_negative_control": modules["zlib_negative_control"],
        "full_behavior_cases": practical["cases"],
        "final_behavior_gate": "pass",
        "bundle_fingerprint_unchanged": practical["bundle_fingerprint_unchanged"],
        "macho_closure_sha256": identity["verification"]["evidence"][
            [record["gate"] for record in identity["verification"]["evidence"]].index(
                "macho-closure"
            )
        ]["file"]["sha256"],
    }
    assert_relative_json(payload, label="optimization ledger payload")
    envelope = gate_envelope(
        identity=identity,
        identity_contract_sha256=digest,
        gate="optimization-ledger",
        subjects=["corresponding_source", "ready_run"],
        invocation=locked_gate_invocation(
            identity,
            "optimization-ledger",
            stdout=b"PASS: measured optimization ledger derived\n",
            execution=execution,
        ),
        coverage={
            "descendant_processes": 1,
            "full_descendant_coverage": True,
            "network_trace": None,
            "observations": {
                "accepted": len(accepted),
                "compression_assets": len(compression_decisions),
                "rejected": len(rejected),
                "strip_candidates": len(strip_candidates),
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
    parser.add_argument("--practical", required=True, type=Path)
    parser.add_argument("--compression", required=True, type=Path)
    parser.add_argument("--macho", required=True, type=Path)
    parser.add_argument("--modules", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    write(args)
    print("PASS: measured optimization ledger derived")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ReleaseError, OSError, ValueError, json.JSONDecodeError) as exc:
        raise SystemExit(f"error: {exc}") from exc
