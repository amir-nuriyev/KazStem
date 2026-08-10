#!/usr/bin/env python3
"""Verify canonical Python artifacts across independent clean build roots."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from release_common import (
    ReleaseError,
    ensure_output_outside,
    json_bytes,
    load_identity,
    verify_artifact,
)


def verify(args: argparse.Namespace) -> dict[str, Any]:
    if args.output.exists() or args.output.is_symlink():
        raise ReleaseError(
            f"Python reproducibility output already exists: {args.output}"
        )
    identity = load_identity(args.identity.resolve(strict=True))
    if len(args.build_root) < 3:
        raise ReleaseError("at least three direct Python build roots are required")
    if any(path.is_symlink() for path in args.build_root):
        raise ReleaseError("Python build roots must not be symlinks")
    roots = [path.resolve(strict=True) for path in args.build_root]
    if len(roots) != len(set(roots)):
        raise ReleaseError("Python build roots must be distinct")
    for index, root in enumerate(roots):
        ensure_output_outside(
            args.output, root, label="Python reproducibility evidence output"
        )
        for other in roots[index + 1 :]:
            if root in other.parents or other in root.parents:
                raise ReleaseError("Python build roots must not contain one another")
    wheel = identity["artifacts"]["wheel"]
    sdist = identity["artifacts"]["sdist"]
    builds: list[dict[str, Any]] = []
    for index, root in enumerate(roots):
        verify_artifact(
            root / wheel["filename"], wheel, label=f"Python build {index} wheel"
        )
        verify_artifact(
            root / sdist["filename"], sdist, label=f"Python build {index} sdist"
        )
        builds.append(
            {
                "root": f"build-{index:02d}",
                "wheel": wheel,
                "sdist": sdist,
            }
        )
    roundtrip = args.roundtrip_wheel.resolve(strict=True)
    verify_artifact(roundtrip, wheel, label="sdist-to-wheel roundtrip")
    result = {
        "schema": "kazstem-python-artifact-reproducibility-v1",
        "pass": True,
        "release": identity["release"],
        "source_commit": identity["source_commit"],
        "wheel_direct_builds": len(roots),
        "sdist_direct_builds": len(roots),
        "sdist_to_wheel_identity": True,
        "canonical_artifacts": {"wheel": wheel, "sdist": sdist},
        "builds": builds,
        "roundtrip": {"root": "sdist-roundtrip", "wheel": wheel},
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(json_bytes(result))
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--identity", required=True, type=Path)
    parser.add_argument("--build-root", required=True, action="append", type=Path)
    parser.add_argument("--roundtrip-wheel", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    result = verify(args)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ReleaseError, OSError, ValueError, json.JSONDecodeError) as exc:
        raise SystemExit(f"error: {exc}") from exc
