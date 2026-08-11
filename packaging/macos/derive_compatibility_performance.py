#!/usr/bin/env python3
"""Derive the compatibility/performance gate from the exact practical matrix."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

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


def derive(args: argparse.Namespace) -> dict[str, object]:
    if args.output.exists() or args.output.is_symlink():
        raise ReleaseError("compatibility/performance output already exists")
    identity_path = args.identity.resolve(strict=True)
    identity = load_identity(identity_path)
    execution = begin_gate_execution(
        identity, "compatibility-performance", caller_file=__file__
    )
    digest = identity_sha256(identity_path)
    practical_record = next(
        record
        for record in identity["verification"]["evidence"]
        if record["gate"] == "practical"
    )
    practical_path = args.practical.resolve(strict=True)
    verify_file(practical_path, practical_record["file"], label="practical evidence")
    practical = validate_gate_envelope(
        read_json(practical_path),
        identity=identity,
        identity_contract_sha256=digest,
        gate="practical",
        subjects=practical_record["subjects"],
    )
    if (
        practical.get("schema") != "kazstem-macos-practical-matrix-v1"
        or practical.get("result") != "pass"
    ):
        raise ReleaseError("practical matrix is not a clean pass")
    profiles = practical.get("profiles")
    if not isinstance(profiles, dict):
        raise ReleaseError("practical matrix lacks performance profiles")
    runs = profiles.get("realistic_workload")
    startup = profiles.get("startup_version_seconds")
    cold = profiles.get("cold_start_version_seconds")
    if (
        not isinstance(runs, list)
        or len(runs) < 2
        or not isinstance(startup, dict)
        or not isinstance(cold, (int, float))
        or any(
            not isinstance(run, dict)
            or not isinstance(run.get("seconds"), (int, float))
            or not isinstance(run.get("input_characters_per_second"), (int, float))
            or not isinstance(run.get("maximum_resident_set_size_bytes"), int)
            or not isinstance(run.get("output_sha256"), str)
            for run in runs
        )
        or len({run["output_sha256"] for run in runs}) != 1
    ):
        raise ReleaseError("performance profiles are incomplete or non-deterministic")
    parity_names = {
        "comparison-frozen",
        "comparison-wheel-cli",
        "comparison-python-module",
        "comparison-wheel-api",
    }
    cases = practical.get("results")
    if not isinstance(cases, list) or not parity_names <= {
        case.get("name") for case in cases if isinstance(case, dict)
    }:
        raise ReleaseError("wheel/module/API/frozen parity cases are incomplete")
    payload = {
        "schema": "kazstem-macos-mystem-json-performance-v2",
        "pass": True,
        "release": identity["release"],
        "source_commit": identity["source_commit"],
        "source_tree": identity["source_tree"],
        "output_identity": True,
        "parity_surfaces": sorted(parity_names),
        "cold_start_seconds": cold,
        "warm_start_seconds": startup,
        "runs": runs,
        "output_sha256": runs[0]["output_sha256"],
        "measured_not_promised_threshold": True,
    }
    assert_relative_json(payload, label="compatibility/performance payload")
    envelope = gate_envelope(
        identity=identity,
        identity_contract_sha256=digest,
        gate="compatibility-performance",
        subjects=["ready_run", "wheel"],
        invocation=locked_gate_invocation(
            identity,
            "compatibility-performance",
            stdout=b"PASS: compatibility/performance derived from practical matrix\n",
            execution=execution,
        ),
        coverage={
            "descendant_processes": 1,
            "full_descendant_coverage": True,
            "network_trace": None,
            "observations": {
                "parity_surfaces": len(parity_names),
                "realistic_runs": len(runs),
                "startup_runs": startup["runs"],
                "unique_output_hashes": 1,
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
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    derive(args)
    print("PASS: compatibility/performance derived from practical matrix")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ReleaseError, OSError, ValueError, json.JSONDecodeError) as exc:
        raise SystemExit(f"error: {exc}") from exc
