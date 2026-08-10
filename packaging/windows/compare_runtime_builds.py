#!/usr/bin/env python3
"""Require location-independent equality of two Windows runtime builds."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import stat


class ComparisonError(RuntimeError):
    pass


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def select_runtime(parent: Path) -> Path:
    candidates = [
        path
        for path in parent.iterdir()
        if path.is_dir() and len(path.name) == 64
    ]
    if len(candidates) != 1:
        raise ComparisonError(
            f"expected one content-addressed runtime below logical build root; "
            f"observed {[path.name for path in candidates]}"
        )
    return candidates[0]


def require_distinct_roots(first: Path, second: Path) -> None:
    if first == second or first.samefile(second):
        raise ComparisonError("runtime build roots are identical or aliased")


def inventory(root: Path) -> dict[str, dict[str, object]]:
    result: dict[str, dict[str, object]] = {}
    for path in sorted(root.rglob("*"), key=lambda value: value.as_posix()):
        relative = path.relative_to(root).as_posix()
        mode = path.lstat().st_mode
        if stat.S_ISDIR(mode):
            continue
        if not stat.S_ISREG(mode) or path.is_symlink():
            raise ComparisonError(f"unsupported runtime entry: {relative}")
        result[relative] = {
            "bytes": path.stat().st_size,
            "sha256": sha256(path),
        }
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("first", type=Path)
    parser.add_argument("second", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    first_parent = args.first.resolve(strict=True)
    second_parent = args.second.resolve(strict=True)
    require_distinct_roots(first_parent, second_parent)
    first = select_runtime(first_parent)
    second = select_runtime(second_parent)
    require_distinct_roots(first, second)
    first_inventory = inventory(first)
    second_inventory = inventory(second)
    if first.name != second.name or first_inventory != second_inventory:
        raise ComparisonError("distinct-root Windows runtime builds are not byte-identical")
    result = {
        "schema": "kazstem-windows-runtime-reproducibility-v1",
        "result": "pass",
        "build_roots": ["build-a", "build-b"],
        "runtime_bundle_id": first.name,
        "regular_files": len(first_inventory),
        "bytes": sum(record["bytes"] for record in first_inventory.values()),
        "inventory": first_inventory,
        "location_independent": True,
        "byte_identical": True,
    }
    args.output.write_text(
        json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(first.name)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ComparisonError, OSError, ValueError) as error:
        raise SystemExit(f"error: {error}") from error
