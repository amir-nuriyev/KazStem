#!/usr/bin/env python3
"""Create a path-free deterministic ledger for one frozen Windows tree."""

from __future__ import annotations

import argparse
import ast
import json
from pathlib import Path
import platform
from typing import Any

from release_common import (
    ReleaseError,
    json_bytes,
    pe_identity,
    require_release_bootstrap,
    tree_inventory,
    tree_record,
)


REQUIRED_EXCLUSIONS = {
    "_hashlib",
    "_socket",
    "_ssl",
    "asyncio",
    "email",
    "ftplib",
    "http",
    "multiprocessing",
    "socket",
    "sqlite3",
    "tkinter",
    "urllib.request",
    "xml",
}
BANNED_FRAGMENTS = ("openssl", "libssl", "libcrypto", "_ssl.", "_hashlib.", "torch", "stanza", "neural")


def spec_exclusions(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8", errors="strict"), filename=path.name)
    values: list[str] | None = None
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name) or node.func.id != "Analysis":
            continue
        for keyword in node.keywords:
            if keyword.arg == "excludes":
                candidate = ast.literal_eval(keyword.value)
                if not isinstance(candidate, list) or any(not isinstance(item, str) for item in candidate):
                    raise ReleaseError("PyInstaller excludes must be a literal string list")
                values = candidate
    if values is None or len(values) != len(set(values)):
        raise ReleaseError("PyInstaller spec has no unique literal exclusion inventory")
    if not REQUIRED_EXCLUSIONS <= set(values):
        raise ReleaseError(f"PyInstaller spec omits network/TLS exclusions: {sorted(REQUIRED_EXCLUSIONS - set(values))}")
    return values


def main() -> int:
    require_release_bootstrap("packaging/windows/write_freezer_ledger.py")
    parser = argparse.ArgumentParser()
    parser.add_argument("--frozen", required=True, type=Path)
    parser.add_argument("--spec", required=True, type=Path)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--json", required=True, type=Path)
    args = parser.parse_args()
    frozen = args.frozen.resolve(strict=True)
    config = json.loads(args.config.resolve(strict=True).read_text(encoding="utf-8"))
    if not isinstance(config, dict) or config.get("schema") != "kazstem-windows-optimization-config-v1":
        raise ReleaseError("freezer ledger config is invalid")
    inventory = tree_inventory(frozen)
    banned = [
        item["path"]
        for item in inventory
        if any(fragment in Path(item["path"]).name.casefold() for fragment in BANNED_FRAGMENTS)
    ]
    if banned:
        raise ReleaseError(f"frozen tree contains banned TLS/network/neural files: {banned}")
    pe_files: list[dict[str, Any]] = []
    for item in inventory:
        if item["kind"] != "file" or not item["path"].casefold().endswith((".exe", ".dll", ".pyd")):
            continue
        record = pe_identity(frozen / item["path"])
        record["path"] = item["path"]
        pe_files.append(record)
    if not any(value["path"] == "kazstem.exe" for value in pe_files):
        raise ReleaseError("frozen tree lacks AMD64 PE32+ kazstem.exe")
    result = {
        "schema": "kazstem-windows-freezer-ledger-v1",
        "result": "pass",
        "source_commit": args.source_commit,
        "platform": {"system": platform.system(), "machine": platform.machine()},
        "config": config,
        "frozen_tree": tree_record(frozen),
        "declared_exclusions": spec_exclusions(args.spec.resolve(strict=True)),
        "pe_files": pe_files,
        "banned_runtime_matches": [],
        "claims": {
            "openssl": "absent by declared module exclusions and complete filename inventory",
            "network_client": "socket/http/urllib.request/email/asyncio excluded",
            "neural_weights": "no neural-weight suffix/name is present",
            "upx": False,
            "strip": False,
            "python_optimization": 0,
        },
    }
    if args.json.exists() or args.json.is_symlink():
        raise ReleaseError(f"freezer ledger output exists: {args.json}")
    args.json.parent.mkdir(parents=True, exist_ok=True)
    args.json.write_bytes(json_bytes(result))
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ReleaseError, OSError, ValueError, json.JSONDecodeError, SyntaxError) as exc:
        raise SystemExit(f"error: {exc}") from exc
