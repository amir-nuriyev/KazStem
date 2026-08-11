#!/usr/bin/env python3
"""Record the exact real Windows runner used for final release gates."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import platform
import struct
import sys

from release_common import (
    ReleaseError,
    evidence_envelope,
    identity_sha256,
    json_bytes,
    load_identity,
    require_release_bootstrap,
    verify_generator_runtime,
)


def main() -> int:
    require_release_bootstrap("packaging/windows/write_final_host_evidence.py")
    parser = argparse.ArgumentParser()
    parser.add_argument("--identity", required=True, type=Path)
    parser.add_argument("--runner-os", required=True)
    parser.add_argument("--runner-arch", required=True)
    parser.add_argument("--image-os", required=True)
    parser.add_argument("--image-version", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--json", required=True, type=Path)
    args = parser.parse_args()
    identity = load_identity(args.identity.resolve(strict=True))
    observed = {
        "system": platform.system(),
        "release": platform.release(),
        "version": platform.version(),
        "machine": platform.machine(),
        "python": platform.python_version(),
        "pointer_bits": struct.calcsize("P") * 8,
    }
    if (
        sys.platform != "win32"
        or args.runner_os != "Windows"
        or args.runner_arch != "X64"
        or observed["machine"].casefold() not in {"amd64", "x86_64"}
        or observed["python"] != identity["platform"]["python"]
        or observed["pointer_bits"] != 64
        or not observed["version"].startswith(identity["platform"]["minimum_os_build"])
    ):
        raise ReleaseError(f"host does not match the Windows release contract: {observed}")
    if not args.run_id.isdecimal() or not args.image_os or not args.image_version:
        raise ReleaseError("host evidence requires exact GitHub image/run identities")
    identity_hash = identity_sha256(args.identity.resolve(strict=True))
    logical_argv = [
        "<PYTHON>",
        "packaging/windows/write_final_host_evidence.py",
        "--identity",
        "<RELEASE-IDENTITY>",
        "--runner-os",
        args.runner_os,
        "--runner-arch",
        args.runner_arch,
        "--image-os",
        args.image_os,
        "--image-version",
        args.image_version,
        "--run-id",
        args.run_id,
        "--json",
        "<EVIDENCE-OUTPUT>",
    ]
    record = verify_generator_runtime(
        identity, gate="host-identity", logical_argv=logical_argv
    )
    observations = {
        "runner": {
            "label": identity["platform"]["runner"],
            "runner_os": args.runner_os,
            "runner_arch": args.runner_arch,
            "image_os": args.image_os,
            "image_version": args.image_version,
            "run_id": args.run_id,
        },
        "host": observed,
    }
    result = evidence_envelope(
        identity,
        identity_hash=identity_hash,
        record=record,
        observations=observations,
    )
    if args.json.exists() or args.json.is_symlink():
        raise ReleaseError(f"host evidence output exists: {args.json}")
    args.json.parent.mkdir(parents=True, exist_ok=True)
    args.json.write_bytes(json_bytes(result))
    print("PASS: exact Windows Server 2022 x86-64 host recorded")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ReleaseError, OSError, ValueError, json.JSONDecodeError) as exc:
        raise SystemExit(f"error: {exc}") from exc
