#!/usr/bin/env python3
"""Materialize application source from one exact, clean Git commit."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import subprocess
import sys
import tarfile
from typing import Any

from release_common import (
    COMMIT,
    GIT_OBJECT,
    ReleaseError,
    file_record,
    forbidden_loader_environment_name,
    json_bytes,
    portable_path,
    release_bootstrap_prefix_for_tree,
    require_release_bootstrap,
    tree_record,
)

GIT_CONFIG_ARGUMENTS = (
    "-c",
    "core.fsmonitor=false",
    "-c",
    "core.untrackedCache=false",
)


def reject_ambient_git_environment() -> None:
    names = sorted(name for name in os.environ if name.startswith("GIT_"))
    if names:
        raise ReleaseError(
            "ambient Git control variables are forbidden: " + ", ".join(names)
        )


def reject_ambient_execution_environment() -> None:
    names = sorted(
        name
        for name in os.environ
        if name.startswith("GIT_")
        or forbidden_loader_environment_name(name)
        or name.upper().startswith("QAZMORPH_")
        or name.upper().endswith("_PROXY")
        or name in {"PYTHONPATH", "PYTHONHOME"}
    )
    if names:
        raise ReleaseError(
            "ambient source-materializer control variables are forbidden: "
            + ", ".join(names)
        )


def resolve_git_executable() -> Path:
    reject_ambient_execution_environment()
    executable = shutil.which("git", path=os.environ.get("PATH", ""))
    if executable is None:
        raise ReleaseError("Git is not available on the controlled PATH")
    return Path(executable).resolve(strict=True)


def git_environment(executable: Path | None = None) -> dict[str, str]:
    reject_ambient_execution_environment()
    selected = executable or resolve_git_executable()
    environment = {
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "LC_ALL": "C",
        "PATH": os.fspath(selected.parent),
        "TZ": "UTC",
    }
    for key in ("ComSpec", "SystemRoot", "WINDIR"):
        if key in os.environ:
            environment[key] = os.environ[key]
    return environment


def logical_git_environment() -> dict[str, str]:
    return {
        "GIT_CONFIG_GLOBAL": "<NULL-DEVICE>",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "LC_ALL": "C",
        "PATH": "<BOUND-GIT-DIR>",
        "TZ": "UTC",
    }


def git_tool(repo: Path) -> dict[str, Any]:
    executable = resolve_git_executable()
    return {
        "version": str(git(repo, ["--version"])),
        "executable": file_record(executable),
    }


def git(repo: Path, arguments: list[str], *, binary: bool = False) -> bytes | str:
    executable = resolve_git_executable()
    completed = subprocess.run(
        [os.fspath(executable), *GIT_CONFIG_ARGUMENTS, *arguments],
        cwd=repo,
        env=git_environment(executable),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode:
        raise ReleaseError(
            f"git {' '.join(arguments)} failed: "
            + completed.stderr.decode("utf-8", "replace").strip()
        )
    return completed.stdout if binary else completed.stdout.decode("utf-8", "strict").strip()


def git_blob_id(payload: bytes, algorithm: str) -> str:
    if algorithm not in {"sha1", "sha256"}:
        raise ReleaseError(f"unsupported Git object format: {algorithm}")
    digest = hashlib.new(algorithm)
    digest.update(f"blob {len(payload)}\0".encode("ascii"))
    digest.update(payload)
    return digest.hexdigest()


def tracked_files(repo: Path, commit: str) -> tuple[str, dict[str, tuple[str, str]]]:
    algorithm = str(git(repo, ["rev-parse", "--show-object-format"]))
    data = git(repo, ["ls-tree", "-r", "-z", "--full-tree", commit], binary=True)
    assert isinstance(data, bytes)
    records: dict[str, tuple[str, str]] = {}
    for raw in data.split(b"\0"):
        if not raw:
            continue
        try:
            metadata, raw_path = raw.split(b"\t", 1)
            mode, kind, object_id = metadata.decode("ascii").split(" ")
            relative = raw_path.decode("utf-8", "strict")
        except (ValueError, UnicodeError) as exc:
            raise ReleaseError("cannot decode exact Git tree inventory") from exc
        portable_path(relative, label="Git source path")
        if kind == "commit" or mode == "160000":
            raise ReleaseError(f"Git submodule is forbidden in source closure: {relative}")
        if kind != "blob" or mode not in {"100644", "100755"}:
            raise ReleaseError(f"unsupported Git source entry {mode} {kind}: {relative}")
        records[relative] = (mode, object_id)
    if not records:
        raise ReleaseError("Git source tree has no tracked files")
    return algorithm, records


def extract_and_verify(archive_path: Path, output: Path, tracked: dict[str, tuple[str, str]], algorithm: str) -> None:
    if output.exists() or output.is_symlink() or output.name != "KazStem":
        raise ReleaseError("source payload output must be a fresh directory named KazStem")
    output.parent.mkdir(parents=True, exist_ok=True)
    observed: dict[str, tuple[str, str]] = {}
    names: set[str] = set()
    try:
        with tarfile.open(archive_path, "r:") as archive:
            for member in archive:
                name = portable_path(member.name.rstrip("/"), label="Git archive member")
                if name in names:
                    raise ReleaseError(f"duplicate Git archive member: {name}")
                names.add(name)
                parts = PurePosixPath(name).parts
                if not parts or parts[0] != "KazStem":
                    raise ReleaseError(f"Git archive member has wrong prefix: {name}")
                relative = PurePosixPath(*parts[1:]).as_posix() if len(parts) > 1 else ""
                target = output if not relative else output / relative
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=False)
                    continue
                if not member.isreg() or not relative:
                    raise ReleaseError(f"Git archive contains link/special entry: {name}")
                if member.size > 64 * 1024**2:
                    raise ReleaseError(f"individual Git source file exceeds 64 MiB: {relative}")
                stream = archive.extractfile(member)
                if stream is None:
                    raise ReleaseError(f"cannot read Git archive member: {relative}")
                payload = stream.read(member.size + 1)
                if len(payload) != member.size:
                    raise ReleaseError(f"Git archive member size changed: {relative}")
                expected = tracked.get(relative)
                if expected is None or git_blob_id(payload, algorithm) != expected[1]:
                    raise ReleaseError(f"Git archive payload differs from Git object: {relative}")
                mode = "100755" if member.mode & 0o111 else "100644"
                if mode != expected[0]:
                    raise ReleaseError(f"Git archive mode differs from Git tree: {relative}")
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(payload)
                target.chmod(0o555 if mode == "100755" else 0o444)
                observed[relative] = expected
    except (OSError, tarfile.TarError) as exc:
        if isinstance(exc, ReleaseError):
            raise
        raise ReleaseError(f"cannot extract exact Git archive: {exc}") from exc
    if observed != tracked:
        raise ReleaseError(
            "Git archive inventory differs from Git tree "
            f"(missing={sorted(set(tracked) - set(observed))}, extra={sorted(set(observed) - set(tracked))})"
        )


def main() -> int:
    boundary = require_release_bootstrap(
        "packaging/windows/materialize_git_source.py"
    )
    parser = argparse.ArgumentParser()
    parser.add_argument("--label", choices=("a", "b"), required=True)
    parser.add_argument("--repo", required=True, type=Path)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--source-tree", required=True)
    parser.add_argument("--source-origin", required=True)
    parser.add_argument("--source-ref", required=True)
    parser.add_argument("--materialization-root", required=True, type=Path)
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--payload", required=True, type=Path)
    parser.add_argument("--receipt", required=True, type=Path)
    parser.add_argument("--execution-receipt", required=True, type=Path)
    args = parser.parse_args()
    reject_ambient_execution_environment()
    if COMMIT.fullmatch(args.source_commit) is None or GIT_OBJECT.fullmatch(args.source_tree) is None:
        parser.error("source commit/tree must be full lowercase Git ids")
    if args.source_origin != "https://github.com/amir-nuriyev/KazStem.git":
        parser.error("source origin must be the exact public KazStem origin")
    if args.source_ref != "refs/tags/v0.2.3":
        parser.error("source ref must be the exact v0.2.3 release tag")
    repo = args.repo.resolve(strict=True)
    root_input = args.materialization_root.absolute()
    root = root_input.parent.resolve(strict=True) / root_input.name
    if root.exists() or root.is_symlink():
        raise ReleaseError(f"fresh source materialization root exists: {root}")
    if root == repo or repo in root.parents or root in repo.parents:
        raise ReleaseError("source materialization root must not alias/nest the repository")
    bootstrap_source = Path.cwd().resolve(strict=True)
    if (
        root == bootstrap_source
        or bootstrap_source in root.parents
        or root in bootstrap_source.parents
    ):
        raise ReleaseError(
            "source materialization root must not alias/nest bootstrap source"
        )
    expected_outputs = {
        "archive": root / "SOURCE.tar",
        "payload": root / "KazStem",
        "receipt": root / "GIT-SOURCE-MATERIALIZATION.json",
        "execution_receipt": root / "MATERIALIZATION-EXECUTION.json",
    }
    for name, expected in expected_outputs.items():
        supplied = getattr(args, name).absolute()
        if supplied != expected:
            raise ReleaseError(f"{name.replace('_', ' ')} must be exactly {expected.name} in the fresh root")
    root.mkdir(parents=True)
    if git(repo, ["status", "--porcelain=v1", "--untracked-files=all"]):
        raise ReleaseError("source repository is dirty")
    if git(repo, ["rev-parse", "HEAD"]) != args.source_commit:
        raise ReleaseError("source repository HEAD differs from requested commit")
    if git(repo, ["rev-parse", f"{args.source_commit}^{{tree}}"] ) != args.source_tree:
        raise ReleaseError("source Git tree differs from requested tree")
    if git(repo, ["remote", "get-url", "origin"]) != args.source_origin:
        raise ReleaseError("source Git origin differs from exact public origin")
    if git(repo, ["rev-parse", f"{args.source_ref}^{{commit}}"] ) != args.source_commit:
        raise ReleaseError("immutable source tag does not resolve to the requested commit")
    checked_script = repo / "packaging/windows/materialize_git_source.py"
    running_script = Path(__file__).resolve(strict=True)
    if file_record(running_script) != file_record(checked_script):
        raise ReleaseError("running materializer bytes differ from the exact source commit")
    checked_common = repo / "packaging/windows/release_common.py"
    running_common = Path(sys.modules["release_common"].__file__).resolve(strict=True)
    if file_record(running_common) != file_record(checked_common):
        raise ReleaseError("loaded release_common differs from the exact source commit")
    checked_bootstrap = repo / "packaging/windows/release_bootstrap.py"
    running_bootstrap = Path(
        sys.modules["release_bootstrap"].__file__
    ).resolve(strict=True)
    if file_record(running_bootstrap) != file_record(checked_bootstrap):
        raise ReleaseError("loaded release_bootstrap differs from the exact source commit")
    dependencies = [
        {
            "path": "packaging/windows/release_bootstrap.py",
            "file": file_record(checked_bootstrap),
        },
        {
            "path": "packaging/windows/release_common.py",
            "file": file_record(checked_common),
        }
    ]
    algorithm, tracked = tracked_files(repo, args.source_commit)
    archive_path = args.archive.absolute()
    archive_path.parent.mkdir(parents=True, exist_ok=True)
    command = [
        "git",
        *GIT_CONFIG_ARGUMENTS,
        "archive",
        "--format=tar",
        "--prefix=KazStem/",
        args.source_commit,
    ]
    executable = resolve_git_executable()
    with archive_path.open("xb") as stream:
        completed = subprocess.run(
            [os.fspath(executable), *command[1:]],
            cwd=repo,
            env=git_environment(executable),
            stdout=stream,
            stderr=subprocess.PIPE,
            check=False,
        )
    if completed.returncode:
        archive_path.unlink(missing_ok=True)
        raise ReleaseError(f"git archive failed: {completed.stderr.decode('utf-8', 'replace')}")
    extract_and_verify(archive_path, args.payload.absolute(), tracked, algorithm)
    payload_tree = tree_record(args.payload.absolute())
    if boundary["source_tree"] != payload_tree:
        raise ReleaseError(
            "materializer bootstrap source differs from the exact Git payload tree"
        )
    receipt = {
        "schema": "kazstem-git-source-materialization-v2",
        "result": "pass",
        "source": {
            "commit": args.source_commit,
            "tree": args.source_tree,
            "origin": args.source_origin,
            "ref": args.source_ref,
        },
        "payload_tree": payload_tree,
        "git_archive": file_record(archive_path),
        "execution": {
            "argv": command,
            "cwd": "<SOURCE-REPOSITORY>",
            "environment": logical_git_environment(),
            "tools": {"git": git_tool(repo)},
            "dependencies": dependencies,
            "exit_code": 0,
        },
        "coverage": {
            "assertions": 14,
            "cases": 1,
            "checks": [
                "archive-content-matches-git-tree",
                "archive-sha256",
                "bootstrap-source-tree-equals-payload",
                "checked-source-bootstrap",
                "clean-worktree",
                "exact-commit",
                "exact-origin",
                "exact-ref",
                "exact-tree",
                "fsmonitor-disabled",
                "no-submodules",
                "payload-tree-record",
                "replacement-objects-disabled",
                "untracked-cache-disabled",
            ],
        },
    }
    args.receipt.write_bytes(json_bytes(receipt))
    if boundary["materialization_receipt"]["file"] != file_record(
        args.receipt.absolute()
    ):
        raise ReleaseError(
            "bootstrap and newly materialized canonical source receipts differ"
        )
    execution_path = args.execution_receipt.absolute()
    with execution_path.open("xb"):
        pass
    root_stat = root.stat()
    payload_stat = args.payload.absolute().stat()
    logical_root = f"<SOURCE-ROOT-{args.label.upper()}>"
    inner_argv = [
        "<PYTHON>",
        "packaging/windows/materialize_git_source.py",
        "--label",
        args.label,
        "--repo",
        "<SOURCE-REPOSITORY>",
        "--source-commit",
        args.source_commit,
        "--source-tree",
        args.source_tree,
        "--source-origin",
        args.source_origin,
        "--source-ref",
        args.source_ref,
        "--materialization-root",
        logical_root,
        "--archive",
        f"{logical_root}/SOURCE.tar",
        "--payload",
        f"{logical_root}/KazStem",
        "--receipt",
        f"{logical_root}/GIT-SOURCE-MATERIALIZATION.json",
        "--execution-receipt",
        f"{logical_root}/MATERIALIZATION-EXECUTION.json",
    ]
    execution_receipt = {
        "schema": "kazstem-git-source-materialization-execution-v2",
        "result": "pass",
        "label": args.label,
        "source": receipt["source"],
        "root_identity": {
            "logical_label": args.label,
            "st_dev": root_stat.st_dev,
            "st_ino": root_stat.st_ino,
            "st_ctime_ns": root_stat.st_ctime_ns,
        },
        "payload_identity": {
            "logical_path": f"{logical_root}/KazStem",
            "st_dev": payload_stat.st_dev,
            "st_ino": payload_stat.st_ino,
            "st_ctime_ns": payload_stat.st_ctime_ns,
            "tree": receipt["payload_tree"],
        },
        "canonical_receipt": file_record(args.receipt.absolute()),
        "git_archive": file_record(archive_path),
        "execution": {
            "script": {
                "path": "packaging/windows/materialize_git_source.py",
                "file": file_record(checked_script),
            },
            "dependencies": dependencies,
            "argv": [
                *release_bootstrap_prefix_for_tree(
                    payload_tree,
                    "packaging/windows/materialize_git_source.py",
                ),
                *inner_argv[2:],
            ],
            "cwd": "<BOOTSTRAP-MATERIALIZED-SOURCE>",
            "environment": logical_git_environment(),
            "tools": {
                "git": git_tool(repo),
                "python": {
                    "version": __import__("platform").python_version(),
                    "executable": file_record(Path(sys.executable).resolve(strict=True)),
                },
            },
            "source_boundary": boundary,
            "exit_code": 0,
        },
        "freshness": {
            "root_absent_before_execution": True,
            "root_created_by_process": True,
            "payload_created_by_process": True,
        },
        "coverage": {
            "assertions": 10,
            "cases": 1,
            "checks": [
                "canonical-receipt",
                "checked-bootstrap-invocation",
                "complete-bootstrap-source-inventory",
                "exact-command-and-tools",
                "external-fresh-pycache-root",
                "fresh-root-object",
                "git-archive-object",
                "nonaliased-output-layout",
                "payload-root-object",
                "source-commit-tree-origin-ref",
            ],
        },
    }
    execution_path.write_bytes(json_bytes(execution_receipt))
    print(json.dumps(receipt, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ReleaseError, OSError, ValueError, json.JSONDecodeError, subprocess.SubprocessError) as exc:
        raise SystemExit(f"error: {exc}") from exc
