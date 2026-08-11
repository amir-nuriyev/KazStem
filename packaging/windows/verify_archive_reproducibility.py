#!/usr/bin/env python3
"""Bind byte-identical two-root final ZIP assembly evidence."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from release_common import (
    ReleaseError,
    artifact_record,
    evidence_envelope,
    files_equal,
    file_record,
    identity_sha256,
    json_bytes,
    load_identity,
    require_release_bootstrap,
    verify_artifact,
    verify_generator_runtime,
)


def main() -> int:
    require_release_bootstrap("packaging/windows/verify_archive_reproducibility.py")
    parser = argparse.ArgumentParser()
    parser.add_argument("--identity", required=True, type=Path)
    parser.add_argument("--assembly-root-a", required=True, type=Path)
    parser.add_argument("--assembly-root-b", required=True, type=Path)
    parser.add_argument("--ready-a", required=True, type=Path)
    parser.add_argument("--ready-b", required=True, type=Path)
    parser.add_argument("--source-a", required=True, type=Path)
    parser.add_argument("--source-b", required=True, type=Path)
    parser.add_argument("--json", required=True, type=Path)
    args = parser.parse_args()
    identity_path = args.identity.resolve(strict=True)
    identity = load_identity(identity_path)
    identity_hash = identity_sha256(identity_path)
    roots = [args.assembly_root_a.resolve(strict=True), args.assembly_root_b.resolve(strict=True)]
    if roots[0] == roots[1] or roots[0] in roots[1].parents or roots[1] in roots[0].parents or roots[0].samefile(roots[1]):
        raise ReleaseError("archive assembly roots are equal/nested/aliased")
    ready = [args.ready_a.resolve(strict=True), args.ready_b.resolve(strict=True)]
    sources = [args.source_a.resolve(strict=True), args.source_b.resolve(strict=True)]
    for index in range(2):
        for value in (ready[index], sources[index]):
            try:
                value.relative_to(roots[index])
            except ValueError as exc:
                raise ReleaseError("archive output is outside its assembly root") from exc
        verify_artifact(ready[index], identity["artifacts"]["ready_run"], label=f"ready {index}")
        verify_artifact(sources[index], identity["artifacts"]["corresponding_source"], label=f"source {index}")
    if (
        not files_equal(ready[0], ready[1])
        or not files_equal(sources[0], sources[1])
    ):
        raise ReleaseError("two-root final archive bytes differ")
    logical_argv = [
        "<PYTHON>",
        "packaging/windows/verify_archive_reproducibility.py",
        "--identity",
        "<RELEASE-IDENTITY>",
        "--assembly-root-a",
        "<ASSEMBLY-ROOT-A>",
        "--assembly-root-b",
        "<ASSEMBLY-ROOT-B>",
        "--ready-a",
        "<READY-A>",
        "--ready-b",
        "<READY-B>",
        "--source-a",
        "<SOURCE-A>",
        "--source-b",
        "<SOURCE-B>",
        "--json",
        "<EVIDENCE-OUTPUT>",
    ]
    record = verify_generator_runtime(
        identity,
        gate="archive-reproducibility",
        logical_argv=logical_argv,
    )
    observations = {
        "ready_run": artifact_record(ready[0], identity["artifacts"]["ready_run"]["url"]),
        "corresponding_source": artifact_record(sources[0], identity["artifacts"]["corresponding_source"]["url"]),
        "assembly_root_proof": {
            "logical_labels": ["a", "b"],
            "distinct_nonnested_nonaliased": True,
        },
        "ready_run_byte_identical": True,
        "corresponding_source_byte_identical": True,
    }
    result = evidence_envelope(
        identity,
        identity_hash=identity_hash,
        record=record,
        observations=observations,
    )
    if args.json.exists() or args.json.is_symlink():
        raise ReleaseError(f"archive reproducibility evidence exists: {args.json}")
    args.json.parent.mkdir(parents=True, exist_ok=True)
    args.json.write_bytes(json_bytes(result))
    print("PASS: final ready/source ZIPs are byte-identical across two roots")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ReleaseError, OSError, ValueError, json.JSONDecodeError) as exc:
        raise SystemExit(f"error: {exc}") from exc
