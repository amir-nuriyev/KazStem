#!/usr/bin/env python3
"""Inventory the isolated POC handoff without self-referential hashing."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    root = args.root.resolve()
    output = args.output.resolve()
    files: dict[str, dict[str, object]] = {}
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.resolve() == output or "__pycache__" in path.parts:
            continue
        relative = path.relative_to(root).as_posix()
        content = path.read_bytes()
        files[relative] = {
            "bytes": len(content),
            "sha256": hashlib.sha256(content).hexdigest(),
        }
    manifest = {
        "schema": "kazstem.browser-isolated-package.v2",
        "base_project_version": "0.2.1",
        "base_project_commit": "97cf865a0cef20ee78be1610bbe76ec6c7e52006",
        "branch": "codex/browser-pages-poc",
        "package_build_state": {
            "distribution_scope": "public",
            "pages_status": "published",
            "repository_visibility": "public",
        },
        "self_excluded": output.relative_to(root).as_posix(),
        "file_count": len(files),
        "total_bytes": sum(record["bytes"] for record in files.values()),
        "files": files,
    }
    output.write_text(
        json.dumps(manifest, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
