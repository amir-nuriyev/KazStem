#!/usr/bin/env python3
"""Write exact tool/switch metadata for one PyInstaller candidate."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import platform
import zlib

from release_common import ReleaseError, json_bytes, require_release_bootstrap


def main() -> int:
    require_release_bootstrap("packaging/windows/write_optimization_config.py")
    parser = argparse.ArgumentParser()
    parser.add_argument("--name", required=True)
    parser.add_argument("--noarchive", choices=("0", "1"), required=True)
    parser.add_argument("--json", required=True, type=Path)
    args = parser.parse_args()
    import PyInstaller

    if PyInstaller.__version__ != "6.22.0" or platform.python_version() != "3.14.3":
        raise ReleaseError("optimization config is not using the pinned freezer toolchain")
    result = {
        "schema": "kazstem-windows-optimization-config-v1",
        "name": args.name,
        "tool_versions": {
            "python": platform.python_version(),
            "pyinstaller": PyInstaller.__version__,
            "zlib": zlib.ZLIB_RUNTIME_VERSION,
        },
        "switches": {
            "noarchive": args.noarchive == "1",
            "python_optimize": 0,
            "strip": False,
            "upx": False,
        },
    }
    if args.json.exists() or args.json.is_symlink():
        raise ReleaseError(f"optimization config output exists: {args.json}")
    args.json.parent.mkdir(parents=True, exist_ok=True)
    args.json.write_bytes(json_bytes(result))
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ReleaseError, OSError, ValueError, json.JSONDecodeError) as exc:
        raise SystemExit(f"error: {exc}") from exc
