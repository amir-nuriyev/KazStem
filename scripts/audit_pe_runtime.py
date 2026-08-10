#!/usr/bin/env python3
"""Statically audit a locked Windows runtime's complete PE import closure."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from write_platform_runtime_manifest import (
    ManifestError,
    audit_pe_dependency_closure,
    extracted_files,
    load_source_lock,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime-dir", required=True, type=Path)
    parser.add_argument("--lock", required=True, type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    runtime_dir = args.runtime_dir.resolve(strict=True)
    lock = load_source_lock(args.lock.resolve(strict=True))
    files = extracted_files(runtime_dir, output=runtime_dir / "manifest.json")
    result = audit_pe_dependency_closure(runtime_dir, lock, files)
    if result is None:
        raise ManifestError("source lock has no PE dependency policy")
    encoded = json.dumps(
        result, ensure_ascii=False, indent=2, sort_keys=True
    ) + "\n"
    if args.output is None:
        print(encoded, end="")
    else:
        args.output.write_text(encoded, encoding="utf-8", newline="\n")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ManifestError as error:
        raise SystemExit(f"error: {error}") from error
