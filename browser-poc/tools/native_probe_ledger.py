#!/usr/bin/env python3
"""Capture ordered HFST candidates for immutable browser probes."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import unicodedata


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lookup", type=Path, required=True)
    parser.add_argument("--fst", type=Path, required=True)
    parser.add_argument("--probes", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    probes = json.loads(args.probes.read_text(encoding="utf-8"))
    surfaces = probes["surfaces"]
    normalized = [unicodedata.normalize("NFC", surface) for surface in surfaces]
    result = subprocess.run(
        [str(args.lookup), "-q", "-u", str(args.fst)],
        input="\n".join(normalized) + "\n",
        text=True,
        encoding="utf-8",
        capture_output=True,
        check=False,
        timeout=120,
    )
    if result.returncode:
        raise SystemExit(result.stderr.strip() or f"lookup failed: {result.returncode}")
    by_surface: dict[str, list[str]] = {surface: [] for surface in normalized}
    for line in result.stdout.splitlines():
        fields = line.split("\t")
        if len(fields) >= 2 and fields[0] in by_surface and "+?" not in fields[1:]:
            by_surface[fields[0]].append(fields[1])
    rows = [
        {
            "surface": surface,
            "normalized": normalized_surface,
            "candidates": by_surface[normalized_surface],
        }
        for surface, normalized_surface in zip(surfaces, normalized)
    ]
    ledger = {
        "schema": "kazstem.browser-native-probe-ledger.v1",
        "comparison": probes["comparison"],
        "project_commit": probes["project_commit"],
        "apertium_kaz_commit": probes["apertium_kaz_commit"],
        "probes_sha256": sha256(args.probes),
        "fst": {"bytes": args.fst.stat().st_size, "sha256": sha256(args.fst)},
        "rows": rows,
    }
    args.output.write_text(
        json.dumps(ledger, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
