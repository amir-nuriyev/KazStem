#!/usr/bin/env python3
"""Build and statically minimize one frozen macOS tree in a fresh freezer env."""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import time
from typing import Any

from release_common import (
    ReleaseError,
    assert_relative_json,
    file_record,
    json_bytes,
    load_identity,
    tree_inventory,
    tree_record,
    verify_artifact,
    verify_file,
)


def _stream(data: bytes) -> dict[str, Any]:
    return {
        "bytes": len(data),
        "lines": len(data.splitlines()),
        "sha256": hashlib.sha256(data).hexdigest(),
        "truncated": False,
    }


def _run(
    argv: list[str],
    *,
    logical_argv: list[str],
    cwd: Path,
    environment: dict[str, str],
    timeout: int = 900,
    require_success: bool = True,
) -> tuple[subprocess.CompletedProcess[bytes], dict[str, Any]]:
    process = subprocess.run(
        argv,
        cwd=cwd,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        check=False,
    )
    record = {
        "argv": logical_argv,
        "exit_status": process.returncode,
        "stdout": _stream(process.stdout),
        "stderr": _stream(process.stderr),
    }
    if require_success and process.returncode:
        detail = process.stderr[:4096].decode("utf-8", "replace")
        raise ReleaseError(
            f"frozen-build command failed ({process.returncode}): {logical_argv!r}: {detail}"
        )
    return process, record


def _macho(path: Path) -> bool:
    with path.open("rb") as source:
        magic = source.read(4)
    return magic in {
        b"\xcf\xfa\xed\xfe",  # 64-bit little-endian Mach-O
        b"\xfe\xed\xfa\xcf",  # 64-bit big-endian Mach-O
        b"\xca\xfe\xba\xbe",  # universal (rejected by the audit)
        b"\xbe\xba\xfe\xca",
    }


def _tool_output(argv: list[str], *, label: str) -> str:
    process = subprocess.run(
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=60,
        check=False,
    )
    text = process.stdout.decode("utf-8", "replace").strip()
    if process.returncode:
        raise ReleaseError(f"{label} failed ({process.returncode}): {text[:4096]}")
    return text


def _macho_static(path: Path) -> dict[str, Any]:
    return {
        "architectures": _tool_output(["lipo", "-archs", str(path)], label="lipo"),
        "dependencies": _tool_output(
            ["otool", "-L", str(path)], label="otool -L"
        ).splitlines()[1:],
        "load_commands_sha256": hashlib.sha256(
            _tool_output(["otool", "-l", str(path)], label="otool -l").encode("utf-8")
        ).hexdigest(),
    }


def _strict_adhoc(path: Path) -> None:
    process = subprocess.run(
        ["codesign", "--verify", "--strict", "--verbose=4", str(path)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=60,
        check=False,
    )
    if process.returncode:
        raise ReleaseError(
            f"strict code-signature verification failed for {path.name}: "
            + process.stderr[:4096].decode("utf-8", "replace")
        )
    details = subprocess.run(
        ["codesign", "-d", "--verbose=4", str(path)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=60,
        check=False,
    ).stdout.decode("utf-8", "replace")
    if "Signature=adhoc" not in details or "TeamIdentifier=not set" not in details:
        raise ReleaseError(f"Mach-O is not explicitly ad-hoc signed: {path.name}")
    if "Authority=" in details:
        raise ReleaseError(
            f"unexpected signing authority in unsigned asset: {path.name}"
        )


def _strip_candidates(tree: Path, work: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    candidate_root = work / "strip-candidates"
    candidate_root.mkdir()
    for path in sorted(
        (item for item in tree.rglob("*") if item.is_file() and not item.is_symlink()),
        key=lambda item: item.relative_to(tree).as_posix(),
    ):
        if not _macho(path):
            continue
        relative = path.relative_to(tree).as_posix()
        before = {**file_record(path), "static": _macho_static(path)}
        _strict_adhoc(path)
        candidate = candidate_root / relative
        candidate.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, candidate)
        strip = subprocess.run(
            ["/usr/bin/strip", "-S", "-x", str(candidate)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=120,
            check=False,
        )
        if strip.returncode:
            records.append(
                {
                    "path": relative,
                    "before": {
                        key: value for key, value in before.items() if key != "static"
                    },
                    "candidate": None,
                    "selected": False,
                    "reason": "strip-command-failed",
                    "strip_stderr": _stream(strip.stderr),
                }
            )
            continue
        sign = subprocess.run(
            [
                "/usr/bin/codesign",
                "--force",
                "--sign",
                "-",
                "--timestamp=none",
                str(candidate),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=120,
            check=False,
        )
        if sign.returncode:
            raise ReleaseError(
                f"candidate re-sign failed for {relative}: "
                + sign.stderr[:4096].decode("utf-8", "replace")
            )
        _strict_adhoc(candidate)
        candidate_static = _macho_static(candidate)
        after = file_record(candidate)
        # The full load-command text changes when the code signature changes.
        # Architecture and dependency install names must remain byte-semantic.
        static_parity = (
            before["static"]["architectures"] == candidate_static["architectures"]
            and before["static"]["dependencies"] == candidate_static["dependencies"]
        )
        selected = after["bytes"] < before["bytes"] and static_parity
        reason = (
            "strictly-smaller-static-parity;requires-final-behavior-parity"
            if selected
            else "not-smaller-or-static-divergence"
        )
        if selected:
            shutil.copyfile(candidate, path)
            _strict_adhoc(path)
        records.append(
            {
                "path": relative,
                "before": {
                    key: value for key, value in before.items() if key != "static"
                },
                "candidate": after,
                "architectures_equal": before["static"]["architectures"]
                == candidate_static["architectures"],
                "dependencies_equal": before["static"]["dependencies"]
                == candidate_static["dependencies"],
                "selected": selected,
                "reason": reason,
                "argv": ["strip", "-S", "-x", relative],
                "resign_argv": [
                    "codesign",
                    "--force",
                    "--sign",
                    "-",
                    "--timestamp=none",
                    relative,
                ],
            }
        )
    if not records:
        raise ReleaseError("frozen tree contains no Mach-O files")
    return records


def _resign_and_verify_containers(tree: Path) -> list[dict[str, Any]]:
    containers = sorted(
        (
            path
            for path in tree.rglob("*")
            if path.is_dir()
            and not path.is_symlink()
            and path.suffix.casefold() in {".app", ".bundle", ".framework"}
        ),
        key=lambda path: (-len(path.parts), path.relative_to(tree).as_posix()),
    )
    records: list[dict[str, Any]] = []
    for path in containers:
        relative = path.relative_to(tree).as_posix()
        sign = subprocess.run(
            [
                "/usr/bin/codesign",
                "--force",
                "--sign",
                "-",
                "--timestamp=none",
                str(path),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=180,
            check=False,
        )
        if sign.returncode:
            raise ReleaseError(
                f"container re-sign failed for {relative}: "
                + sign.stderr[:4096].decode("utf-8", "replace")
            )
        verify = subprocess.run(
            [
                "/usr/bin/codesign",
                "--verify",
                "--strict",
                "--deep",
                "--verbose=4",
                str(path),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=180,
            check=False,
        )
        details = subprocess.run(
            ["/usr/bin/codesign", "-d", "--verbose=4", str(path)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=60,
            check=False,
        )
        detail_text = details.stdout.decode("utf-8", "replace")
        if (
            verify.returncode
            or details.returncode
            or "Signature=adhoc" not in detail_text
            or "TeamIdentifier=not set" not in detail_text
            or "Authority=" in detail_text
        ):
            raise ReleaseError(f"container signature is not strict ad-hoc: {relative}")
        records.append(
            {
                "path": relative,
                "sign_argv": [
                    "codesign",
                    "--force",
                    "--sign",
                    "-",
                    "--timestamp=none",
                    relative,
                ],
                "verify_argv": [
                    "codesign",
                    "--verify",
                    "--strict",
                    "--deep",
                    "--verbose=4",
                    relative,
                ],
                "sign_exit_status": sign.returncode,
                "verify_exit_status": verify.returncode,
                "signature": "adhoc",
                "team_identifier": None,
                "authorities": [],
                "sign_stdout": _stream(sign.stdout),
                "sign_stderr": _stream(sign.stderr),
                "verify_stdout": _stream(verify.stdout),
                "verify_stderr": _stream(verify.stderr),
            }
        )
    if not records:
        raise ReleaseError("frozen tree lacks the expected signed framework/container")
    return records


def _toc_modules(work: Path) -> list[str]:
    modules: set[str] = set()
    for path in sorted(work.rglob("*.toc")):
        if path.stat().st_size > 64 * 1024**2:
            raise ReleaseError(f"PyInstaller TOC exceeds audit cap: {path.name}")
        try:
            value = ast.literal_eval(path.read_text(encoding="utf-8"))
        except (SyntaxError, ValueError, UnicodeError):
            continue

        def walk(item: object) -> None:
            if isinstance(item, (list, tuple)):
                if item and isinstance(item[0], str):
                    modules.add(item[0])
                for child in item:
                    walk(child)

        walk(value)
    return sorted(modules)


def build(args: argparse.Namespace) -> dict[str, Any]:
    for path, label in (
        (args.work_root, "work root"),
        (args.output, "frozen output"),
        (args.evidence, "frozen evidence"),
    ):
        if path.exists() or path.is_symlink():
            raise ReleaseError(f"{label} must not exist: {path}")
    resolved = [
        path.resolve(strict=False)
        for path in (args.work_root, args.output, args.evidence)
    ]
    for index, path in enumerate(resolved):
        for other in resolved[index + 1 :]:
            if path == other or path in other.parents or other in path.parents:
                raise ReleaseError(
                    "work/output/evidence paths must be distinct and non-nested"
                )
    identity = load_identity(args.identity.resolve(strict=True))
    wheel = args.wheel.resolve(strict=True)
    spec = args.spec.resolve(strict=True)
    verify_artifact(wheel, identity["artifacts"]["wheel"], label="freezer wheel")
    verify_file(spec, identity["inputs"]["freezer_spec"], label="PyInstaller spec")
    freezer_python = identity["inputs"]["python_runtimes"]["freezer"]
    if platform.python_implementation() != freezer_python["implementation"]:
        raise ReleaseError("freezer Python implementation differs from identity")
    if platform.python_version() != freezer_python["version"]:
        raise ReleaseError("freezer Python version differs from identity")
    verify_file(
        Path(sys.executable).resolve(strict=True),
        freezer_python["executable"],
        label="freezer Python executable",
    )
    forbidden_environment = sorted(
        key
        for key in os.environ
        if key.startswith(("DYLD_", "LD_"))
        or key in {"PYTHONPATH", "PYTHONHOME", "PIP_INDEX_URL", "PIP_EXTRA_INDEX_URL"}
    )
    if forbidden_environment:
        raise ReleaseError(
            f"hostile freezer environment is set: {forbidden_environment}"
        )
    import importlib.metadata

    installed: dict[str, str] = {}
    for record in identity["inputs"]["build_stack"]["freezer"]:
        try:
            observed = importlib.metadata.version(record["name"])
        except importlib.metadata.PackageNotFoundError as exc:
            raise ReleaseError(f"freezer package is absent: {record['name']}") from exc
        if observed != record["version"]:
            raise ReleaseError(
                f"freezer package version differs: {record['name']}={observed!r}"
            )
        installed[record["name"]] = observed

    work = args.work_root.absolute()
    work.mkdir(parents=True)
    dist_parent = work / "pyinstaller-dist"
    pyinstaller_work = work / "pyinstaller-work"
    environment = {
        **os.environ,
        "LANG": "C",
        "LC_ALL": "C",
        "PYTHONHASHSEED": "0",
        "SOURCE_DATE_EPOCH": str(identity["source_date_epoch"]),
        "TZ": "UTC",
        "KAZSTEM_ENTRYPOINT": str(Path(sys.executable).parent / "kazstem"),
    }
    started_ns = time.time_ns()
    actual = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--clean",
        "--noconfirm",
        "--distpath",
        str(dist_parent),
        "--workpath",
        str(pyinstaller_work),
        str(spec),
    ]
    logical = [
        "freezer-python",
        "-m",
        "PyInstaller",
        "--clean",
        "--noconfirm",
        "--distpath",
        "work/pyinstaller-dist",
        "--workpath",
        "work/pyinstaller-work",
        "packaging/macos/kazstem-minimal.spec",
    ]
    _process, command = _run(
        actual,
        logical_argv=logical,
        cwd=spec.parents[2],
        environment=environment,
        timeout=1800,
    )
    built = dist_parent / "kazstem"
    if not built.is_dir() or built.is_symlink():
        raise ReleaseError("PyInstaller did not produce the expected onedir tree")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    built.rename(args.output)
    if any(
        path.stat().st_ctime_ns < started_ns
        for path in args.output.rglob("*")
        if path.is_file() and not path.is_symlink()
    ):
        raise ReleaseError("frozen output contains a file predating this build")
    transforms = _strip_candidates(args.output, work)
    container_signatures = _resign_and_verify_containers(args.output)

    launcher = args.output / "kazstem"
    version, version_record = _run(
        [str(launcher), "--version"],
        logical_argv=["frozen/kazstem", "--version"],
        cwd=args.output,
        environment=environment,
        timeout=60,
    )
    if identity["release"].encode("ascii") not in version.stdout:
        raise ReleaseError("frozen --version output does not identify the release")
    modules = _toc_modules(pyinstaller_work)
    banned = identity["minimization"]["banned_modules"]
    banned_matches = sorted(
        module
        for module in modules
        if any(module == prefix or module.startswith(prefix + ".") for prefix in banned)
    )
    if banned_matches:
        raise ReleaseError(
            f"banned modules remain in PyInstaller TOCs: {banned_matches}"
        )
    if not any(module == "_sha2" or module.endswith("/_sha2") for module in modules):
        # Native entries often retain a suffix; a final module/native auditor
        # also checks the frozen tree.  This guard still rejects a completely
        # missing positive SHA-256 provider.
        if not any("_sha2" in path.name for path in args.output.rglob("*")):
            raise ReleaseError("frozen tree lacks the required _sha2 provider")

    zlib_files = sorted(
        path
        for path in args.output.rglob("*")
        if path.is_file() and not path.is_symlink() and "zlib" in path.name.casefold()
    )
    if not zlib_files:
        raise ReleaseError("cannot run the PyInstaller zlib negative control")
    negative = work / "negative-control-no-zlib"
    shutil.copytree(args.output, negative, symlinks=True)
    removed: list[str] = []
    for original in zlib_files:
        relative = original.relative_to(args.output)
        (negative / relative).unlink()
        removed.append(relative.as_posix())
    negative_process, negative_record = _run(
        [str(negative / "kazstem"), "--version"],
        logical_argv=["negative-control-no-zlib/kazstem", "--version"],
        cwd=negative,
        environment=environment,
        timeout=60,
        require_success=False,
    )
    if negative_process.returncode == 0:
        raise ReleaseError("removing zlib did not fail the PyInstaller bootstrap")

    observed_tree = tree_record(args.output)
    if observed_tree != identity["inputs"]["frozen_tree"]:
        raise ReleaseError(
            f"frozen tree differs from identity: expected={identity['inputs']['frozen_tree']}, "
            f"observed={observed_tree}"
        )
    result = {
        "schema": "kazstem-macos-frozen-build-v1",
        "pass": True,
        "release": identity["release"],
        "source_commit": identity["source_commit"],
        "source_tree": identity["source_tree"],
        "root": "fresh-freezer-root",
        "python": {
            "implementation": platform.python_implementation(),
            "version": platform.python_version(),
            "executable": freezer_python["executable"],
        },
        "installed_freezer_stack": installed,
        "canonical_wheel": identity["artifacts"]["wheel"],
        "spec": identity["inputs"]["freezer_spec"],
        "environment": {
            "LANG": "C",
            "LC_ALL": "C",
            "PYTHONHASHSEED": "0",
            "SOURCE_DATE_EPOCH": str(identity["source_date_epoch"]),
            "TZ": "UTC",
            "KAZSTEM_ENTRYPOINT": "freezer-env/bin/kazstem",
        },
        "commands": [command, version_record],
        "strip_candidates": transforms,
        "container_signatures": container_signatures,
        "module_inventory": {
            "count": len(modules),
            "sha256": hashlib.sha256("\n".join(modules).encode("utf-8")).hexdigest(),
            "modules": modules,
            "banned_matches": [],
            "sha2_present": True,
        },
        "negative_controls": {
            "pyinstaller-zlib-bootstrap": {
                "removed": removed,
                "command": negative_record,
                "failed_as_required": True,
            }
        },
        "output_tree": observed_tree,
        "output_entries": len(tree_inventory(args.output)),
    }
    assert_relative_json(result, label="frozen build evidence")
    args.evidence.parent.mkdir(parents=True, exist_ok=True)
    args.evidence.write_bytes(json_bytes(result))
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--identity", required=True, type=Path)
    parser.add_argument("--wheel", required=True, type=Path)
    parser.add_argument("--spec", required=True, type=Path)
    parser.add_argument("--work-root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--evidence", required=True, type=Path)
    args = parser.parse_args()
    result = build(args)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ReleaseError, OSError, ValueError, json.JSONDecodeError) as exc:
        raise SystemExit(f"error: {exc}") from exc
