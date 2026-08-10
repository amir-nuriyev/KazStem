#!/usr/bin/env python3
"""Create the small deployed index for exact H100 parity artifacts."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


def record(path: Path) -> dict[str, object]:
    return {
        "path": path.name,
        "bytes": path.stat().st_size,
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--native", type=Path, required=True)
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--malformed", type=Path, required=True)
    parser.add_argument("--native-gzip", type=Path, required=True)
    parser.add_argument("--runtime-gzip", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    inventory = json.loads(args.inventory.read_text(encoding="utf-8"))
    runtime = json.loads(args.runtime.read_text(encoding="utf-8"))
    malformed = json.loads(args.malformed.read_text(encoding="utf-8"))
    summary = {
        "schema": "kazstem.browser-probe-ledger-summary.v1",
        "comparison": "exact ordered raw candidate arrays after NFC normalization",
        "result": "pass" if runtime["ordered_candidate_arrays_equal"] else "fail",
        "probe_count": runtime["probe_count"],
        "resource_sha256_verified_before_constructor": runtime[
            "resource_sha256_verified_before_constructor"
        ],
        "resource_sha256": runtime["resource_sha256"],
        "surface_inventory": {**record(args.inventory), "counts": inventory["counts"], "sources": inventory["sources"]},
        "native_ledger": record(args.native),
        "browser_runtime_ledger": {
            **record(args.runtime),
            "init_ms": runtime["init_ms"],
            "probe_ms": runtime["probe_ms"],
            "benchmark": runtime["benchmark"],
            "memory_bytes": runtime["memory_bytes"],
        },
        "compressed_exact_ledgers": {
            "native": record(args.native_gzip),
            "browser": record(args.runtime_gzip),
        },
        "malformed_and_cap_tests": {**record(args.malformed), **malformed},
        "att_symbol_audit": {
            "meta_symbols": ["@0@", "@_SPACE_@"],
            "identity_symbols": [],
            "unknown_symbols": [],
            "flag_diacritics": [],
        },
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(summary, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    if summary["result"] != "pass" or malformed["result"] != "pass":
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
