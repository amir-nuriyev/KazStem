#!/usr/bin/env python3
"""Build a deterministic direct-lookup inventory from KTB and raw-5k text."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import unicodedata


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def ktb_forms(paths: list[Path]) -> set[str]:
    forms: set[str] = set()
    for path in paths:
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line or line.startswith("#"):
                continue
            fields = line.split("\t")
            if len(fields) == 10 and fields[0].isdigit():
                forms.add(fields[1])
    return forms


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ktb", type=Path, action="append", default=[])
    parser.add_argument("--raw", type=Path, required=True)
    parser.add_argument("--base-probes", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    base = json.loads(args.base_probes.read_text(encoding="utf-8"))
    ktb = ktb_forms(args.ktb)
    # This whitespace-token inventory is deliberately simpler than KazStem's
    # tokenizer: it is a deterministic, independently hashable stress set for
    # the exact direct transducer relation, not a tokenization gold standard.
    raw_types = set(re.findall(r"\S+", args.raw.read_text(encoding="utf-8")))
    source_surfaces = set(base["surfaces"]) | ktb | raw_types
    excluded_over_bound = sum(len(tuple(surface)) > 256 for surface in source_surfaces)
    normalized = {
        unicodedata.normalize("NFC", surface)
        for surface in source_surfaces
        if len(tuple(surface)) <= 256 and "\x00" not in surface
    }
    inventory = {
        "schema": "kazstem.browser-surface-inventory.v1",
        "project_commit": base["project_commit"],
        "apertium_kaz_commit": base["apertium_kaz_commit"],
        "comparison": "ordered raw candidate arrays after NFC normalization",
        "sources": {
            "base_probes": {"path": args.base_probes.name, "sha256": sha256(args.base_probes)},
            "ktb": [{"path": path.name, "bytes": path.stat().st_size, "sha256": sha256(path)} for path in args.ktb],
            "raw": {"path": args.raw.name, "bytes": args.raw.stat().st_size, "sha256": sha256(args.raw)},
        },
        "counts": {
            "base": len(base["surfaces"]),
            "ktb_distinct_forms": len(ktb),
            "raw_distinct_whitespace_types": len(raw_types),
            "source_union": len(source_surfaces),
            "excluded_over_256_code_points": excluded_over_bound,
            "normalized_distinct": len(normalized),
        },
        "surfaces": sorted(normalized),
    }
    args.output.write_text(
        json.dumps(inventory, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(inventory["counts"], sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
