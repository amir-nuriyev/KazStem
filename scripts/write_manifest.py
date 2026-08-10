#!/usr/bin/env python3
"""Write a deterministic, source- and toolchain-pinned FST resource manifest."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
from typing import Any


SCHEMA = "qazmorph-resource-manifest-v3"
REQUIRED_RESOURCES = (
    "kaz.automorf.hfstol",
    "kaz.autogen.hfstol",
    "kaz.guesser.automorf.hfstol",
    "kaz.rlx.bin",
)
SOURCE_INPUTS = (
    "apertium-kaz.kaz.lexc",
    "apertium-kaz.kaz.rlx",
    "apertium-kaz.kaz.twol",
)
BUILD_INPUTS = (
    "scripts/bootstrap_h100.sh",
    "scripts/build_resources.sh",
    "scripts/guesser_regression_probes.json",
    "scripts/toolchain_assets.lock.json",
    "scripts/verify_guesser_fst.py",
    "scripts/write_manifest.py",
    "scripts/write_toolchain_manifest.py",
)
BUILD_COMMANDS = (
    "cg-comp",
    "hfst-compose-intersect",
    "hfst-fst2fst",
    "hfst-fst2strings",
    "hfst-fst2txt",
    "hfst-invert",
    "hfst-lexc",
    "hfst-lookup",
    "hfst-minimise",
    "hfst-optimized-lookup",
    "hfst-regexp2fst",
    "hfst-subtract",
    "hfst-twolc",
)


class ManifestError(RuntimeError):
    """Raised when exact build provenance cannot be established."""


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def file_record(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise ManifestError(f"required input or output is missing: {path}")
    return {"bytes": path.stat().st_size, "sha256": sha256(path)}


def canonical_hash(value: Any) -> str:
    encoded = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def git_output(source_dir: Path, *arguments: str) -> str:
    try:
        return subprocess.check_output(
            ["git", "-C", str(source_dir), *arguments],
            text=True,
            encoding="utf-8",
            stderr=subprocess.STDOUT,
        ).strip()
    except subprocess.CalledProcessError as exc:
        raise ManifestError(
            f"git {' '.join(arguments)} failed for {source_dir}: {exc.output.strip()}"
        ) from exc


def atomic_write(path: Path, value: dict[str, Any]) -> None:
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(value, stream, ensure_ascii=False, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o644)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def load_toolchain_manifest(toolchain_dir: Path) -> dict[str, Any]:
    path = toolchain_dir / "manifest.json"
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ManifestError(f"cannot read verified toolchain manifest {path}: {exc}") from exc
    if manifest.get("schema") != "qazmorph-toolchain-manifest-v2":
        raise ManifestError(f"unsupported toolchain manifest schema: {path}")
    bundle_id = manifest.get("bundle_id")
    if not isinstance(bundle_id, str) or len(bundle_id) != 64:
        raise ManifestError(f"invalid toolchain bundle id: {path}")
    identity = {key: value for key, value in manifest.items() if key not in {"bundle_id", "version"}}
    if canonical_hash(identity) != bundle_id:
        raise ManifestError(f"toolchain manifest identity checksum is invalid: {path}")
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--resource-dir", required=True, type=Path)
    parser.add_argument("--source-dir", required=True, type=Path)
    parser.add_argument("--toolchain-dir", required=True, type=Path)
    parser.add_argument("--project-root", required=True, type=Path)
    parser.add_argument("--guesser-verification", required=True, type=Path)
    parser.add_argument("--expected-source-commit")
    args = parser.parse_args()

    resource_dir = args.resource_dir.resolve()
    source_dir = args.source_dir.resolve()
    toolchain_dir = args.toolchain_dir.resolve()
    project_root = args.project_root.resolve()
    guesser_verification_path = args.guesser_verification.resolve()
    try:
        guesser_verification = json.loads(
            guesser_verification_path.read_text(encoding="utf-8")
        )
    except (OSError, json.JSONDecodeError) as exc:
        raise ManifestError(
            f"cannot read productive-guesser verification report "
            f"{guesser_verification_path}: {exc}"
        ) from exc
    guesser_graph = (
        guesser_verification.get("graph")
        if isinstance(guesser_verification, dict)
        else None
    )
    guesser_probes = (
        guesser_verification.get("no_cap_probes")
        if isinstance(guesser_verification, dict)
        else None
    )
    if (
        not isinstance(guesser_verification, dict)
        or guesser_verification.get("schema") != "qazmorph-guesser-finiteness-v1"
        or not isinstance(guesser_graph, dict)
        or guesser_graph.get("reachable_input_epsilon_cycle") is not False
        or not isinstance(guesser_probes, dict)
        or guesser_probes.get("cycle_markers") != 0
        or guesser_probes.get("all_lemmas_match_bounded_root_relation") is not True
        or not isinstance(guesser_verification.get("optimized_runtime"), dict)
        or guesser_verification["optimized_runtime"].get(
            "candidate_sets_equal_to_standard"
        )
        is not True
        or guesser_verification["optimized_runtime"].get(
            "full_relation_equivalent_to_standard"
        )
        is not True
        or not isinstance(guesser_probes.get("required_readings_checked"), int)
        or guesser_probes["required_readings_checked"] < 1
    ):
        raise ManifestError(
            f"productive-guesser verification report is invalid: "
            f"{guesser_verification_path}"
        )

    dirty = git_output(source_dir, "status", "--porcelain=v1", "--untracked-files=all")
    if dirty:
        raise ManifestError(f"refusing dirty apertium-kaz source tree:\n{dirty}")
    commit = git_output(source_dir, "rev-parse", "HEAD")
    if args.expected_source_commit and commit != args.expected_source_commit:
        raise ManifestError(
            f"source commit is {commit}, expected {args.expected_source_commit}"
        )
    tree = git_output(source_dir, "rev-parse", "HEAD^{tree}")
    source_date_epoch = int(git_output(source_dir, "show", "-s", "--format=%ct", "HEAD"))
    declared_epoch = os.environ.get("SOURCE_DATE_EPOCH")
    if declared_epoch is None or int(declared_epoch) != source_date_epoch:
        raise ManifestError(
            "SOURCE_DATE_EPOCH must equal the locked source commit timestamp "
            f"({source_date_epoch})"
        )

    toolchain_manifest = load_toolchain_manifest(toolchain_dir)
    toolchain_manifest_path = toolchain_dir / "manifest.json"
    toolchain_commands = toolchain_manifest.get("commands", {})
    for name in BUILD_COMMANDS:
        executable = toolchain_dir / "usr/bin" / name
        record = toolchain_commands.get(name)
        if not executable.is_file() or not isinstance(record, dict):
            raise ManifestError(f"build command is absent from verified toolchain: {name}")
        if record.get("sha256") != sha256(executable):
            raise ManifestError(f"build command differs from toolchain manifest: {name}")

    source_inputs = {
        relative: file_record(source_dir / relative) for relative in SOURCE_INPUTS
    }
    build_inputs = {
        relative: file_record(project_root / relative) for relative in BUILD_INPUTS
    }
    files = {
        name: file_record(resource_dir / name) for name in REQUIRED_RESOURCES
    }
    unexpected = sorted(
        path.name
        for path in resource_dir.iterdir()
        if path.is_file() and path.name not in {*REQUIRED_RESOURCES, "manifest.json"}
    )
    if unexpected:
        raise ManifestError(f"unexpected files in staged resource bundle: {unexpected}")

    identity: dict[str, Any] = {
        "schema": SCHEMA,
        "source": {
            "name": "apertium-kaz",
            "url": "https://github.com/apertium/apertium-kaz",
            "commit": commit,
            "tree": tree,
            "commit_timestamp": datetime.fromtimestamp(
                source_date_epoch, timezone.utc
            ).isoformat(),
            "license": "GPL-3.0",
            "inputs": source_inputs,
        },
        "build": {
            "source_date_epoch": source_date_epoch,
            "locale": "C.UTF-8",
            "timezone": "UTC",
            "python_hash_seed": 0,
            "inputs": build_inputs,
            "verification": {
                "generator_subset_of_analyzer": {
                    "operation": "generation_relation - analysis_relation",
                    "required_result": "empty language",
                    "commands": ["hfst-subtract", "hfst-fst2strings"],
                },
                "productive_guesser_finite_valued": {
                    "operation": (
                        "reject every reachable input-epsilon cycle and run "
                        "the immutable no-cap bounded-root probe fixture"
                    ),
                    "required_result": (
                        "no reachable input-epsilon cycle, no cycle marker, "
                        "every unknown lemma matches the explicit bounded root "
                        "relation, and optimized serialization is relation-equivalent"
                    ),
                    "commands": [
                        "hfst-fst2fst",
                        "hfst-fst2strings",
                        "hfst-fst2txt",
                        "hfst-lookup",
                        "hfst-optimized-lookup",
                        "hfst-subtract",
                    ],
                    "verifier": "scripts/verify_guesser_fst.py",
                    "probes": "scripts/guesser_regression_probes.json",
                    "report": file_record(guesser_verification_path),
                    "result": guesser_verification,
                }
            },
            "toolchain": {
                "bundle_id": toolchain_manifest["bundle_id"],
                "version": toolchain_manifest["version"],
                "manifest": file_record(toolchain_manifest_path),
            },
        },
        "files": files,
    }
    bundle_id = canonical_hash(identity)
    manifest = {
        **identity,
        "bundle_id": bundle_id,
        "version": f"apertium-kaz-{commit[:12]}+qazmorph-{bundle_id[:16]}",
    }
    atomic_write(resource_dir / "manifest.json", manifest)
    print(bundle_id)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ManifestError, ValueError) as error:
        raise SystemExit(f"error: {error}") from error
