#!/usr/bin/env python3
"""Bind checked-out platform-lock bytes to the exact candidate Git tree."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
import subprocess
import sys


PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))

from write_platform_runtime_manifest import (  # noqa: E402
    ManifestError,
    read_canonical_lf_json,
)


MAX_LOCK_BYTES = 1024 * 1024
GIT_TIMEOUT_SECONDS = 10
SHA1 = re.compile(r"[0-9a-f]{40}")


class LockVerificationError(RuntimeError):
    pass


def portable_repo_path(value: str) -> str:
    posix = PurePosixPath(value)
    windows = PureWindowsPath(value)
    if (
        not value
        or "\\" in value
        or posix.is_absolute()
        or windows.is_absolute()
        or windows.drive
        or value != posix.as_posix()
        or any(part in {"", ".", ".."} for part in posix.parts)
    ):
        raise LockVerificationError(f"unsafe repository path: {value!r}")
    return value


def git_output(root: Path, arguments: list[str]) -> bytes:
    try:
        completed = subprocess.run(
            ["git", *arguments],
            cwd=root,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=GIT_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise LockVerificationError("Git lock-byte verification timed out") from exc
    if len(completed.stdout) > MAX_LOCK_BYTES or len(completed.stderr) > 64 * 1024:
        raise LockVerificationError("Git lock-byte verification output exceeded its cap")
    if completed.returncode:
        raise LockVerificationError(
            f"Git lock-byte verification exited {completed.returncode}"
        )
    return completed.stdout


def verify(
    root: Path,
    *,
    expected_revision: str,
    paths: list[str],
) -> dict[str, object]:
    if SHA1.fullmatch(expected_revision) is None:
        raise LockVerificationError("candidate revision must be a lowercase 40-hex SHA")
    observed_revision = git_output(root, ["rev-parse", "HEAD"]).decode(
        "ascii", "strict"
    ).strip()
    if observed_revision != expected_revision:
        raise LockVerificationError("checked-out HEAD differs from candidate revision")
    portable_paths = [portable_repo_path(value) for value in paths]
    if len(portable_paths) != len(set(portable_paths)):
        raise LockVerificationError("duplicate lock path")
    locks: dict[str, dict[str, object]] = {}
    for relative in sorted(portable_paths):
        selected = root / relative
        if not selected.is_file() or selected.is_symlink():
            raise LockVerificationError(f"lock is not a regular file: {relative}")
        worktree = selected.read_bytes()
        if len(worktree) > MAX_LOCK_BYTES:
            raise LockVerificationError(f"lock exceeds byte cap: {relative}")
        committed = git_output(
            root, ["show", "--no-textconv", f"HEAD:{relative}"]
        )
        if worktree != committed:
            raise LockVerificationError(
                f"worktree lock bytes differ from HEAD: {relative}"
            )
        read_canonical_lf_json(selected, label="platform lock")
        locks[relative] = {
            "bytes": len(worktree),
            "sha256": hashlib.sha256(worktree).hexdigest(),
        }
    return {
        "schema": "kazstem-git-lock-byte-verification-v1",
        "result": "pass",
        "candidate_sha": expected_revision,
        "git_head": observed_revision,
        "locks": locks,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--expected-revision", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("paths", nargs="+")
    args = parser.parse_args()
    root = args.root.resolve(strict=True)
    result = verify(
        root,
        expected_revision=args.expected_revision,
        paths=args.paths,
    )
    args.output.write_text(
        json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (LockVerificationError, ManifestError, OSError, UnicodeError) as error:
        raise SystemExit(f"error: {error}") from error
