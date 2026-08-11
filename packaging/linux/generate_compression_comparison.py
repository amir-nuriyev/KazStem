#!/usr/bin/env python3
"""Compare both native assets from their exact normalized tar payloads."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from process_supervisor import SupervisionError, run_bounded  # noqa: E402

from release_common import (
    ReleaseError,
    archive_limits,
    assert_relative_json,
    file_record,
    identity_sha256,
    inspect_tar,
    json_bytes,
    load_identity,
    read_json,
    stream_evidence_record,
    verify_artifact,
    verify_file,
    validate_tar_producer_receipt,
)


MAX_CAPTURE_BYTES = 16 * 1024**2


def _run_bounded(
    argv: list[str], *, cwd: Path, environment: dict[str, str], timeout: int
) -> tuple[int, bytes, bytes]:
    try:
        result = run_bounded(
            argv,
            cwd=cwd,
            environment=environment,
            timeout=timeout,
            max_stdout=MAX_CAPTURE_BYTES,
            max_stderr=MAX_CAPTURE_BYTES,
        )
    except SupervisionError as exc:
        raise ReleaseError(f"compression command supervision failed: {exc}") from exc
    return result.returncode, result.stdout, result.stderr


def _normalize_stream(
    data: bytes, replacements: list[tuple[str, str]], *, label: str
) -> bytes:
    try:
        value = data.decode("utf-8")
    except UnicodeError as exc:
        raise ReleaseError(f"compression {label} is not UTF-8") from exc
    value = value.replace("\r\n", "\n")
    for actual, logical in sorted(replacements, key=lambda item: len(item[0]), reverse=True):
        value = value.replace(actual, logical)
        value = value.replace(actual.replace("/", "\\"), logical)
    return value.encode("utf-8")


def _tool(identity: dict[str, Any], name: str) -> tuple[Path, dict[str, Any]]:
    expected = next(
        (
            record
            for record in identity["verification"]["reproducibility"]["tools"]
            if record["name"] == name
        ),
        None,
    )
    if expected is None:
        raise ReleaseError(f"compression tool is not identity-bound: {name}")
    observed = shutil.which(name)
    if observed is None:
        raise ReleaseError(f"compression tool is unavailable: {name}")
    executable = Path(observed).resolve(strict=True)
    verify_file(executable, expected["executable"], label=f"compression tool {name}")
    returncode, version_stdout, version_stderr = _run_bounded(
        [str(executable), *expected["version_argv"][1:]],
        cwd=Path.cwd(),
        environment=os.environ.copy(),
        timeout=60,
    )
    if (
        returncode
        or (version_stdout + version_stderr).decode("utf-8", "replace").strip()
        != expected["version"]
    ):
        raise ReleaseError(f"compression tool version differs: {name}")
    return executable, expected


def _verify_repository(repository: Path, identity: dict[str, Any]) -> None:
    git = shutil.which("git")
    if git is None:
        raise ReleaseError("git is required to verify compression source tree")
    checks = (
        ([git, "rev-parse", "HEAD"], identity["source_commit"]),
        ([git, "rev-parse", "HEAD^{tree}"], identity["source_tree"]),
        ([git, "remote", "get-url", "origin"], identity["source_origin"]),
        ([git, "rev-parse", identity["source_ref"]], identity["source_tag_object"]),
        ([git, "rev-parse", f"{identity['source_ref']}^{{commit}}"], identity["source_commit"]),
        ([git, "cat-file", "-t", identity["source_ref"]], "tag"),
    )
    for argv, expected in checks:
        result = subprocess.run(
            argv,
            cwd=repository,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if result.returncode or result.stdout.strip() != expected:
            raise ReleaseError("compression repository differs from source identity")
    dirty = subprocess.run(
        [
            git,
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
            "--ignored=matching",
        ],
        cwd=repository,
        stdout=subprocess.PIPE,
        check=True,
    ).stdout
    if dirty:
        raise ReleaseError("compression repository is dirty")


def _candidate_runs(
    *,
    identity: dict[str, Any],
    repository: Path,
    target: dict[str, Any],
    raw_tar: Path,
    work: Path,
    environment: dict[str, str],
    timeout: int,
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for candidate in target["candidates"]:
        executable, tool_record = _tool(identity, candidate["tool"])
        runs: list[dict[str, Any]] = []
        for run_name in ("a", "b"):
            run_root = work / target["artifact"] / candidate["name"] / run_name
            run_root.mkdir(parents=True)
            output = run_root / candidate["filename"]
            actual_argv = [
                str(executable),
                *[
                    item.replace("{input}", str(raw_tar)).replace(
                        "{output}", str(output)
                    )
                    for item in candidate["argv"][1:]
                ],
            ]
            logical_argv = [
                item.replace(
                    "{input}", f"canonical/{target['input']['filename']}"
                ).replace(
                    "{output}",
                    f"candidates/{target['artifact']}/{candidate['name']}/{run_name}/{candidate['filename']}",
                )
                for item in candidate["argv"]
            ]
            started = time.time_ns()
            returncode, stdout, stderr = _run_bounded(
                actual_argv,
                cwd=repository,
                environment=environment,
                timeout=timeout,
            )
            replacements = [
                (actual, logical)
                for actual, logical in zip(actual_argv, logical_argv, strict=True)
                if actual != logical
            ]
            replacements.append((str(repository), "source-checkout"))
            replacements.append((environment["HOME"], "workspace/home"))
            replacements.append(
                (
                    environment["PYTHONPYCACHEPREFIX"],
                    identity["verification"]["reproducibility"]["environment"][
                        "PYTHONPYCACHEPREFIX"
                    ],
                )
            )
            stdout = _normalize_stream(stdout, replacements, label="stdout")
            stderr = _normalize_stream(stderr, replacements, label="stderr")
            if returncode:
                raise ReleaseError(
                    f"compression candidate failed: {target['artifact']}/{candidate['name']}/{run_name}"
                )
            if output.is_symlink() or not output.is_file():
                raise ReleaseError("compression candidate did not create a regular file")
            metadata = output.stat()
            if metadata.st_nlink != 1 or metadata.st_ctime_ns < started:
                raise ReleaseError("compression candidate output is aliased or stale")
            runs.append(
                {
                    "run": run_name,
                    "command": {
                        "argv": logical_argv,
                        "environment": identity["verification"]["reproducibility"]["environment"],
                        "exit_status": returncode,
                        "stdout": stream_evidence_record(stdout),
                        "stderr": stream_evidence_record(stderr),
                    },
                    "output": {"filename": candidate["filename"], **file_record(output)},
                }
            )
        if runs[0]["output"] != runs[1]["output"]:
            raise ReleaseError(
                f"compression candidate is not A/B deterministic: {candidate['name']}"
            )
        results.append(
            {
                **candidate,
                "tool": tool_record,
                "runs": runs,
                "bytes": runs[0]["output"]["bytes"],
                "sha256": runs[0]["output"]["sha256"],
                "byte_identical": True,
            }
        )
    return results


def generate(args: argparse.Namespace) -> dict[str, Any]:
    if args.output.exists() or args.output.is_symlink():
        raise ReleaseError(f"compression report already exists: {args.output}")
    identity_path = args.identity.resolve(strict=True)
    identity = load_identity(identity_path)
    repository = args.repository.resolve(strict=True)
    if repository.is_symlink() or not repository.is_dir():
        raise ReleaseError("compression repository must be a real directory")
    _verify_repository(repository, identity)
    artifact_dir = args.artifact_dir.resolve(strict=True)
    producer_dir = args.producer_dir.resolve(strict=True)
    configuration = identity["verification"]["compression"]
    reports: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="kazstem-compression-") as temporary:
        work = Path(temporary)
        home = work / "home"
        home.mkdir()
        pycache = work / "pycache"
        pycache.mkdir()
        environment = {
            **identity["verification"]["reproducibility"]["environment"],
            "HOME": str(home),
            "PYTHONPYCACHEPREFIX": str(pycache),
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
        }
        for target in configuration["targets"]:
            artifact = identity["artifacts"][target["artifact"]]
            selected_path = artifact_dir / artifact["filename"]
            verify_artifact(
                selected_path, artifact, label=f"selected {target['artifact']} container"
            )
            raw_tar = producer_dir / "canonical" / target["input"]["filename"]
            receipt_name = (
                "corresponding-source-tar-producer.json"
                if target["artifact"] == "corresponding_source"
                else "ready-run-tar-producer.json"
            )
            producer_receipt = read_json(
                producer_dir / "producer-receipts" / receipt_name
            )
            validate_tar_producer_receipt(
                producer_receipt,
                identity=identity,
                identity_contract_sha256=identity_sha256(identity_path),
                artifact=target["artifact"],
                raw_tar=raw_tar,
            )
            selected_members = inspect_tar(
                selected_path,
                limits=archive_limits(identity, target["artifact"]),
            )
            if inspect_tar(
                raw_tar, limits=archive_limits(identity, target["artifact"])
            ) != selected_members:
                raise ReleaseError("selected container and canonical raw tar differ")
            candidates = _candidate_runs(
                identity=identity,
                repository=repository,
                target=target,
                raw_tar=raw_tar,
                work=work,
                environment=environment,
                timeout=args.timeout,
            )
            eligible = [item for item in candidates if item["eligible"] is True]
            minimum = min(eligible, key=lambda item: (item["bytes"], item["name"]))
            if minimum["name"] != target["selected"]:
                raise ReleaseError(
                    f"identity preselects non-minimum {target['artifact']} compression"
                )
            if {
                "filename": minimum["filename"],
                "bytes": minimum["bytes"],
                "sha256": minimum["sha256"],
            } != {
                "filename": artifact["filename"],
                "bytes": artifact["bytes"],
                "sha256": artifact["sha256"],
            }:
                raise ReleaseError(
                    f"minimum {target['artifact']} candidate is not the published artifact"
                )
            rejected = [
                {
                    "name": item["name"],
                    "filename": item["filename"],
                    "bytes": item["bytes"],
                    "sha256": item["sha256"],
                    "eligible": item["eligible"],
                    "ineligible_reason": item["ineligible_reason"],
                    "tradeoff": item["tradeoff"],
                    "reason": (
                        f"ineligible: {item['ineligible_reason']}"
                        if item["eligible"] is False
                        else (
                            f"larger by {item['bytes'] - minimum['bytes']} bytes"
                            if item["bytes"] != minimum["bytes"]
                            else f"equal size; {minimum['name']} wins deterministic name tie-break"
                        )
                    ),
                }
                for item in candidates
                if item["name"] != minimum["name"]
            ]
            reports.append(
                {
                    "artifact": target["artifact"],
                    "input": target["input"],
                    "producer_receipt": producer_receipt,
                    "candidates": candidates,
                    "selected": minimum["name"],
                    "selected_output": {
                        "filename": minimum["filename"],
                        "bytes": minimum["bytes"],
                        "sha256": minimum["sha256"],
                    },
                    "rejected": rejected,
                }
            )
    result = {
        "schema": "kazstem-linux-compression-comparison-v2",
        "pass": True,
        "release": identity["release"],
        "source_commit": identity["source_commit"],
        "source_tree": identity["source_tree"],
        "identity_contract_sha256": identity_sha256(identity_path),
        "selection_rule": configuration["selection_rule"],
        "targets": reports,
    }
    assert_relative_json(result, label="compression comparison")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(json_bytes(result))
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--identity", required=True, type=Path)
    parser.add_argument("--repository", required=True, type=Path)
    parser.add_argument("--artifact-dir", required=True, type=Path)
    parser.add_argument("--producer-dir", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--timeout", type=int, default=1800)
    args = parser.parse_args()
    result = generate(args)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ReleaseError, OSError, ValueError, json.JSONDecodeError) as exc:
        raise SystemExit(f"error: {exc}") from exc
