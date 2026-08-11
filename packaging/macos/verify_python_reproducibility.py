#!/usr/bin/env python3
"""Consume canonical Python artifacts and rebuild fresh macOS-native roots."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import selectors
import shutil
import signal
import subprocess
import time
from typing import Any

from release_common import (
    ReleaseError,
    assert_relative_json,
    begin_gate_execution,
    ensure_distinct_nonaliased_paths,
    ensure_output_outside,
    file_record,
    gate_envelope,
    identity_sha256,
    json_bytes,
    load_identity,
    locked_gate_invocation,
    verify_artifact,
    verify_file,
)
from canonical_python_authority import verify_bound_authority


def _resolved_tool(name: str, expected: dict[str, Any]) -> Path:
    observed = shutil.which(name)
    if observed is None:
        raise ReleaseError(f"required reproducibility tool is unavailable: {name}")
    path = Path(observed).resolve(strict=True)
    verify_file(path, expected["executable"], label=f"reproducibility tool {name}")
    argv = [str(path), *expected["version_argv"][1:]]
    process = subprocess.run(
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=60,
        check=False,
    )
    try:
        version = process.stdout.decode("utf-8").strip()
    except UnicodeError as exc:
        raise ReleaseError(f"{name} version output is not UTF-8") from exc
    if process.returncode != 0 or version != expected["version"]:
        raise ReleaseError(
            f"{name} version differs from identity: exit={process.returncode}, "
            f"observed={version!r}"
        )
    return path


def _stream_record(data: bytes) -> dict[str, Any]:
    return {
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "truncated": False,
        "lines": len(data.splitlines()),
    }


def _run(
    argv: list[str],
    *,
    logical_argv: list[str],
    cwd: Path,
    environment: dict[str, str],
    timeout: int = 600,
    stream_cap: int = 16 * 1024 * 1024,
) -> dict[str, Any]:
    process = subprocess.Popen(
        argv,
        cwd=cwd,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    if process.stdout is None or process.stderr is None:
        raise ReleaseError("reproducibility command capture pipes are unavailable")
    captured = {"stdout": bytearray(), "stderr": bytearray()}
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, "stdout")
    selector.register(process.stderr, selectors.EVENT_READ, "stderr")
    deadline = time.monotonic() + timeout
    failure: str | None = None
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                failure = f"command exceeded {timeout}-second timeout"
                break
            for key, _mask in selector.select(min(remaining, 0.25)):
                chunk = os.read(key.fileobj.fileno(), 64 * 1024)
                if not chunk:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                buffer = captured[key.data]
                buffer.extend(chunk)
                if len(buffer) > stream_cap:
                    failure = f"{key.data} exceeded {stream_cap}-byte capture cap"
                    break
            if failure is not None:
                break
        if failure is not None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        returncode = process.wait(timeout=30)
    finally:
        selector.close()
        for stream in (process.stdout, process.stderr):
            if not stream.closed:
                stream.close()
    if failure is not None:
        raise ReleaseError(f"reproducibility command failed closed: {failure}")
    try:
        os.killpg(process.pid, 0)
    except ProcessLookupError:
        group_reaped = True
    else:
        group_reaped = False
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    if not group_reaped:
        raise ReleaseError("reproducibility command left a descendant process group")
    stdout = bytes(captured["stdout"])
    stderr = bytes(captured["stderr"])
    result = {
        "argv": logical_argv,
        "exit_status": returncode,
        "stdout": _stream_record(stdout),
        "stderr": _stream_record(stderr),
        "capture": {
            "process_group_reaped": True,
            "stream_cap_bytes": stream_cap,
            "timeout_seconds": timeout,
        },
    }
    if returncode != 0:
        detail = stderr[:4096].decode("utf-8", "replace")
        raise ReleaseError(
            f"reproducibility command failed with exit {returncode}: "
            f"{logical_argv!r}: {detail}"
        )
    return result


def _expanded(
    configured: list[str],
    *,
    actual_values: dict[str, str],
    logical_values: dict[str, str],
) -> tuple[list[str], list[str]]:
    actual: list[str] = []
    logical: list[str] = []
    for token in configured:
        actual_token = token
        logical_token = token
        for placeholder, value in actual_values.items():
            actual_token = actual_token.replace(placeholder, value)
        for placeholder, value in logical_values.items():
            logical_token = logical_token.replace(placeholder, value)
        if "{" in actual_token or "}" in actual_token:
            raise ReleaseError(f"unresolved actual command template: {token!r}")
        if "{" in logical_token or "}" in logical_token:
            raise ReleaseError(f"unresolved logical command template: {token!r}")
        actual.append(actual_token)
        logical.append(logical_token)
    return actual, logical


def _assert_unique_regular_files(root: Path, inodes: set[tuple[int, int]]) -> int:
    count = 0
    for path in sorted(root.rglob("*")):
        if path.is_symlink() or not path.is_file():
            continue
        metadata = path.stat()
        if metadata.st_nlink != 1:
            raise ReleaseError(f"hard-linked reproduction input/output: {path.name}")
        key = (metadata.st_dev, metadata.st_ino)
        if key in inodes:
            raise ReleaseError(
                f"filesystem alias crosses independent reproduction roots: {path.name}"
            )
        inodes.add(key)
        count += 1
    return count


def _artifact_freshness(
    path: Path, *, start_ns: int, inodes: set[tuple[int, int]]
) -> dict[str, Any]:
    metadata = path.stat()
    if metadata.st_nlink != 1:
        raise ReleaseError(f"built artifact is hard-linked: {path.name}")
    key = (metadata.st_dev, metadata.st_ino)
    if key in inodes:
        raise ReleaseError(f"built artifact aliases an earlier output: {path.name}")
    inodes.add(key)
    if metadata.st_ctime_ns < start_ns:
        raise ReleaseError(f"built artifact predates its build command: {path.name}")
    return {
        "link_count": metadata.st_nlink,
        "created_by_command": True,
        **file_record(path),
    }


def _clone_exact(
    *,
    repository: Path,
    checkout: Path,
    identity: dict[str, Any],
    git: Path,
    environment: dict[str, str],
    logical_root: str,
    source_tag_object: str,
) -> dict[str, Any]:
    if checkout.exists() or checkout.is_symlink():
        raise ReleaseError(f"fresh checkout already exists: {logical_root}")
    clone = _run(
        [
            str(git),
            "clone",
            "--no-local",
            "--no-hardlinks",
            "--no-checkout",
            str(repository),
            str(checkout),
        ],
        logical_argv=[
            "git",
            "clone",
            "--no-local",
            "--no-hardlinks",
            "--no-checkout",
            "source-origin-cache",
            logical_root,
        ],
        cwd=checkout.parent,
        environment=environment,
    )
    commands = [clone]
    commands.append(
        _run(
            [str(git), "remote", "set-url", "origin", identity["source_origin"]],
            logical_argv=["git", "remote", "set-url", "origin", "source-origin"],
            cwd=checkout,
            environment=environment,
        )
    )
    commands.append(
        _run(
            [str(git), "checkout", "--detach", identity["source_commit"]],
            logical_argv=["git", "checkout", "--detach", identity["source_commit"]],
            cwd=checkout,
            environment=environment,
        )
    )
    observed_commit = subprocess.run(
        [str(git), "rev-parse", "HEAD"],
        cwd=checkout,
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        check=True,
    ).stdout.strip()
    observed_tree = subprocess.run(
        [str(git), "rev-parse", "HEAD^{tree}"],
        cwd=checkout,
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        check=True,
    ).stdout.strip()
    if (
        observed_commit != identity["source_commit"]
        or observed_tree != identity["source_tree"]
    ):
        raise ReleaseError("fresh checkout differs from the identity commit/tree")
    observed_ref = subprocess.run(
        [str(git), "rev-parse", f"{identity['source_ref']}^{{commit}}"],
        cwd=checkout,
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        check=True,
    ).stdout.strip()
    if observed_ref != identity["source_commit"]:
        raise ReleaseError("fresh checkout release tag differs from source_commit")
    observed_tag_object = subprocess.run(
        [str(git), "rev-parse", identity["source_ref"]],
        cwd=checkout,
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        check=True,
    ).stdout.strip()
    if observed_tag_object != source_tag_object:
        raise ReleaseError("fresh checkout release tag object differs from authority")
    status = subprocess.run(
        [str(git), "status", "--porcelain=v1", "--untracked-files=all"],
        cwd=checkout,
        env=environment,
        stdout=subprocess.PIPE,
        check=True,
    ).stdout
    if status:
        raise ReleaseError("fresh checkout is unexpectedly dirty")
    return {
        "source_commit": observed_commit,
        "source_tree": observed_tree,
        "source_origin": identity["source_origin"],
        "source_ref": identity["source_ref"],
        "source_tag_object": source_tag_object,
        "commands": commands,
    }


def verify(args: argparse.Namespace) -> dict[str, Any]:
    if args.output.exists() or args.output.is_symlink():
        raise ReleaseError(f"reproducibility output already exists: {args.output}")
    if args.workspace.exists() or args.workspace.is_symlink():
        raise ReleaseError(f"reproducibility workspace must be fresh: {args.workspace}")
    ensure_distinct_nonaliased_paths(
        args.workspace,
        args.output,
        labels=("reproducibility workspace", "reproducibility report"),
    )
    ensure_output_outside(
        args.output, args.workspace, label="reproducibility report output"
    )
    identity_path = args.identity.resolve(strict=True)
    identity = load_identity(identity_path)
    execution = begin_gate_execution(
        identity, "python-reproducibility", caller_file=__file__
    )
    repository = args.repository.resolve(strict=True)
    canonical = args.canonical_artifacts.resolve(strict=True)
    for name in (
        "payload",
        "resources",
        "runtime",
        "documents",
        "freezer_wheelhouse",
    ):
        path = getattr(args, name)
        if path.is_symlink() or not path.is_dir():
            raise ReleaseError(f"reproducibility input root is invalid: {name}")
    for name in (
        "binary_readme_template",
        "source_readme_template",
        "base_ledger",
        "freezer_requirements",
        "freezer_spec",
        "python_build_identity",
        "linux_release_identity",
        "linux_reproducibility",
        "python_interpreter_source",
    ):
        path = getattr(args, name)
        if path.is_symlink() or not path.is_file():
            raise ReleaseError(f"reproducibility input file is invalid: {name}")
    wheel = identity["artifacts"]["wheel"]
    sdist = identity["artifacts"]["sdist"]
    canonical_wheel = canonical / wheel["filename"]
    canonical_sdist = canonical / sdist["filename"]
    verify_artifact(canonical_wheel, wheel, label="canonical wheel")
    verify_artifact(canonical_sdist, sdist, label="canonical sdist")
    authority = verify_bound_authority(
        identity=identity,
        repository=repository,
        payload=args.payload,
        python_build_identity_path=args.python_build_identity,
        linux_release_identity_path=args.linux_release_identity,
        linux_reproducibility_path=args.linux_reproducibility,
        interpreter_source_path=args.python_interpreter_source,
        canonical_artifacts=canonical,
    )
    from release_common import verify_tree

    verify_tree(
        args.freezer_wheelhouse.resolve(strict=True),
        identity["inputs"]["freezer_wheelhouse"],
        label="freezer wheelhouse",
    )
    verify_file(
        args.freezer_requirements.resolve(strict=True),
        identity["inputs"]["freezer_requirements"],
        label="freezer requirements",
    )
    verify_file(
        args.freezer_spec.resolve(strict=True),
        identity["inputs"]["freezer_spec"],
        label="freezer spec",
    )

    configuration = identity["verification"]["reproducibility"]
    tool_records = {record["name"]: record for record in configuration["tools"]}
    tools = {
        name: _resolved_tool(name, record)
        for name, record in sorted(tool_records.items())
    }
    git = tools.get("git")
    if git is None:
        raise ReleaseError("reproducibility tool set must include git")
    environment = {key: value for key, value in configuration["environment"].items()}
    workspace = args.workspace.absolute()
    workspace.mkdir(parents=True)
    home = workspace / "controlled-home"
    home.mkdir()
    environment.update(
        {
            "HOME": str(home),
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
        }
    )
    seed_commit = subprocess.run(
        [str(git), "rev-parse", identity["source_commit"]],
        cwd=repository,
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if (
        seed_commit.returncode
        or seed_commit.stdout.strip() != identity["source_commit"]
    ):
        raise ReleaseError("seed repository does not resolve source_commit")
    seed_ref = subprocess.run(
        [str(git), "rev-parse", f"{identity['source_ref']}^{{commit}}"],
        cwd=repository,
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if seed_ref.returncode or seed_ref.stdout.strip() != identity["source_commit"]:
        raise ReleaseError("seed repository release tag differs from source_commit")
    seed_tag_object = subprocess.run(
        [str(git), "rev-parse", identity["source_ref"]],
        cwd=repository,
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if (
        seed_tag_object.returncode
        or seed_tag_object.stdout.strip() != authority["source_tag_object"]
    ):
        raise ReleaseError("seed repository release tag object differs from authority")
    seed_origin = subprocess.run(
        [str(git), "remote", "get-url", "origin"],
        cwd=repository,
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        check=False,
    )
    if (
        seed_origin.returncode
        or seed_origin.stdout.strip() != identity["source_origin"]
    ):
        raise ReleaseError("seed repository origin differs from identity")

    all_inodes: set[tuple[int, int]] = set()
    canonical_inputs: dict[str, dict[str, Any]] = {}
    for name, path in (("wheel", canonical_wheel), ("sdist", canonical_sdist)):
        metadata = path.stat()
        if metadata.st_nlink != 1:
            raise ReleaseError(f"canonical {name} is hard-linked")
        all_inodes.add((metadata.st_dev, metadata.st_ino))
        canonical_inputs[name] = {
            "path": f"artifacts/{path.name}",
            "file": file_record(path),
            "linux_authoritative": True,
        }
    builds: list[dict[str, Any]] = []
    native_roots: list[str] = []
    root_receipts: list[dict[str, Any]] = []
    for index in range(configuration["build_roots"]):
        label = f"build-{index:02d}"
        build_root = workspace / label
        checkout = build_root / "checkout"
        build_root.mkdir()
        checkout_record = _clone_exact(
            repository=repository,
            checkout=checkout,
            identity=identity,
            git=git,
            environment=environment,
            logical_root=f"{label}/checkout",
            source_tag_object=authority["source_tag_object"],
        )
        checkout_files = _assert_unique_regular_files(checkout, all_inodes)
        built_wheel = canonical_wheel
        built_sdist = canonical_sdist
        start_ns = time.time_ns()

        root_environment = {**environment, "HOME": str(build_root / "controlled-home")}
        (build_root / "controlled-home").mkdir()
        freezer_env = build_root / "freezer-env"
        python_tool = tools.get("python") or tools.get("python3")
        if python_tool is None:
            raise ReleaseError("reproducibility tools must bind the freezer Python")
        venv_command = _run(
            [str(python_tool), "-m", "venv", "--copies", str(freezer_env)],
            logical_argv=["python", "-m", "venv", "--copies", f"{label}/freezer-env"],
            cwd=checkout,
            environment=root_environment,
        )
        freezer_python = freezer_env / "bin/python3"
        if not freezer_python.is_file() or freezer_python.is_symlink():
            freezer_python = freezer_env / "bin/python"
        if not freezer_python.is_file() or freezer_python.is_symlink():
            raise ReleaseError("fresh freezer environment lacks a copied Python")
        install_actual, install_logical = _expanded(
            configuration["freezer_install_argv"],
            actual_values={
                "{freezer_python}": str(freezer_python),
                "{freezer_requirements}": str(
                    args.freezer_requirements.resolve(strict=True)
                ),
                "{freezer_wheelhouse}": str(
                    args.freezer_wheelhouse.resolve(strict=True)
                ),
                "{wheel}": str(built_wheel),
            },
            logical_values={
                "{freezer_python}": f"{label}/freezer-env/bin/python",
                "{freezer_requirements}": "inputs/freezer-requirements.lock",
                "{freezer_wheelhouse}": "inputs/freezer-wheelhouse",
                "{wheel}": f"artifacts/{wheel['filename']}",
            },
        )
        install_command = _run(
            install_actual,
            logical_argv=install_logical,
            cwd=checkout,
            environment=root_environment,
            timeout=900,
        )
        frozen = build_root / "frozen"
        freezer_work = build_root / "freezer-work"
        freezer_evidence = build_root / "frozen-build-evidence.json"
        checked_spec = checkout / "packaging/macos/kazstem-minimal.spec"
        verify_file(
            checked_spec,
            identity["inputs"]["freezer_spec"],
            label=f"{label} checked freezer spec",
        )
        frozen_actual, frozen_logical = _expanded(
            configuration["frozen_build_argv"],
            actual_values={
                "{freezer_python}": str(freezer_python),
                "{identity}": str(identity_path),
                "{wheel}": str(built_wheel),
                "{spec}": str(checked_spec),
                "{freezer_work}": str(freezer_work),
                "{frozen_dist}": str(frozen),
                "{freezer_evidence}": str(freezer_evidence),
            },
            logical_values={
                "{freezer_python}": f"{label}/freezer-env/bin/python",
                "{identity}": "release-identity.json",
                "{wheel}": f"artifacts/{wheel['filename']}",
                "{spec}": "packaging/macos/kazstem-minimal.spec",
                "{freezer_work}": f"{label}/freezer-work",
                "{frozen_dist}": f"{label}/frozen",
                "{freezer_evidence}": f"{label}/frozen-build-evidence.json",
            },
        )
        frozen_started_ns = time.time_ns()
        frozen_command = _run(
            frozen_actual,
            logical_argv=frozen_logical,
            cwd=checkout,
            environment=root_environment,
            timeout=3600,
        )
        if not freezer_evidence.is_file() or freezer_evidence.is_symlink():
            raise ReleaseError("checked freezer did not emit structured evidence")
        frozen_payload = json.loads(freezer_evidence.read_text(encoding="utf-8"))
        if (
            not isinstance(frozen_payload, dict)
            or frozen_payload.get("schema") != "kazstem-macos-frozen-build-v1"
            or frozen_payload.get("pass") is not True
            or frozen_payload.get("output_tree") != identity["inputs"]["frozen_tree"]
        ):
            raise ReleaseError(
                "fresh freezer evidence differs from the release identity"
            )
        verify_file(
            freezer_evidence,
            identity["inputs"]["base_ledger"],
            label=f"{label} exact fresh freezer ledger",
        )
        frozen_files = _assert_unique_regular_files(frozen, all_inodes)
        if any(
            path.stat().st_ctime_ns < frozen_started_ns
            for path in frozen.rglob("*")
            if path.is_file() and not path.is_symlink()
        ):
            raise ReleaseError("fresh frozen tree predates its freezer command")

        native_work = build_root / "native-work"
        native = build_root / "reproduction"
        native.mkdir()
        source_path = native / identity["artifacts"]["corresponding_source"]["filename"]
        source_receipt = native_work / "source-assembly-receipt.json"
        checked_source_assembler = (
            checkout / "packaging/macos/assemble_corresponding_source.py"
        )
        verify_file(
            checked_source_assembler,
            identity["compression"]["corresponding_source"]["canonical_tar"][
                "producer"
            ]["script"]["file"],
            label=f"{label} checked source assembler",
        )
        source_command = _run(
            [
                str(python_tool),
                "-S",
                str(checked_source_assembler),
                "--identity",
                str(identity_path),
                "--repository",
                str(checkout),
                "--payload",
                str(args.payload.resolve(strict=True)),
                "--source-readme-template",
                str(args.source_readme_template.resolve(strict=True)),
                "--wheel",
                str(built_wheel),
                "--sdist",
                str(built_sdist),
                "--work-root",
                str(native_work / "source-work"),
                "--output",
                str(source_path),
                "--receipt",
                str(source_receipt),
            ],
            logical_argv=[
                "python",
                "-S",
                "packaging/macos/assemble_corresponding_source.py",
                "--identity",
                "release-identity.json",
                "--repository",
                f"{label}/checkout",
                "--payload",
                "inputs/source-payload",
                "--source-readme-template",
                "packaging/macos/CORRESPONDING-SOURCE-README.template.md",
                "--wheel",
                f"artifacts/{wheel['filename']}",
                "--sdist",
                f"artifacts/{sdist['filename']}",
                "--work-root",
                f"{label}/native-work/source-work",
                "--output",
                f"{label}/reproduction/{source_path.name}",
                "--receipt",
                f"{label}/native-work/source-assembly-receipt.json",
            ],
            cwd=checkout,
            environment=root_environment,
            timeout=3600,
        )
        ready_path = native / identity["artifacts"]["ready_run"]["filename"]
        ready_receipt = native_work / "ready-assembly-receipt.json"
        checked_ready_assembler = checkout / "packaging/macos/assemble_ready_run.py"
        verify_file(
            checked_ready_assembler,
            identity["compression"]["ready_run"]["canonical_tar"]["producer"]["script"][
                "file"
            ],
            label=f"{label} checked ready assembler",
        )
        ready_command = _run(
            [
                str(python_tool),
                "-S",
                str(checked_ready_assembler),
                "--identity",
                str(identity_path),
                "--frozen",
                str(frozen),
                "--resources",
                str(args.resources.resolve(strict=True)),
                "--runtime",
                str(args.runtime.resolve(strict=True)),
                "--documents",
                str(args.documents.resolve(strict=True)),
                "--binary-readme-template",
                str(args.binary_readme_template.resolve(strict=True)),
                "--base-ledger",
                str(freezer_evidence),
                "--wheel",
                str(built_wheel),
                "--sdist",
                str(built_sdist),
                "--corresponding-source",
                str(source_path),
                "--work-root",
                str(native_work / "ready-work"),
                "--output",
                str(ready_path),
                "--receipt",
                str(ready_receipt),
            ],
            logical_argv=[
                "python",
                "-S",
                "packaging/macos/assemble_ready_run.py",
                "--identity",
                "release-identity.json",
                "--frozen",
                f"{label}/frozen",
                "--resources",
                "inputs/resources",
                "--runtime",
                "inputs/runtime",
                "--documents",
                "inputs/documents",
                "--binary-readme-template",
                "packaging/macos/BINARY-README.template.md",
                "--base-ledger",
                f"{label}/frozen-build-evidence.json",
                "--wheel",
                f"artifacts/{wheel['filename']}",
                "--sdist",
                f"artifacts/{sdist['filename']}",
                "--corresponding-source",
                f"{label}/reproduction/{source_path.name}",
                "--work-root",
                f"{label}/native-work/ready-work",
                "--output",
                f"{label}/reproduction/{ready_path.name}",
                "--receipt",
                f"{label}/native-work/ready-assembly-receipt.json",
            ],
            cwd=checkout,
            environment=root_environment,
            timeout=3600,
        )
        source_freshness = _artifact_freshness(
            source_path, start_ns=start_ns, inodes=all_inodes
        )
        ready_freshness = _artifact_freshness(
            ready_path, start_ns=start_ns, inodes=all_inodes
        )
        source_receipt_payload = json.loads(source_receipt.read_text(encoding="utf-8"))
        ready_receipt_payload = json.loads(ready_receipt.read_text(encoding="utf-8"))
        expected_receipts = (
            (
                "corresponding_source",
                source_receipt_payload,
                "kazstem-macos-source-assembly-receipt-v1",
                source_freshness,
            ),
            (
                "ready_run",
                ready_receipt_payload,
                "kazstem-macos-ready-assembly-receipt-v1",
                ready_freshness,
            ),
        )
        for (
            asset_name,
            receipt_payload,
            schema,
            artifact_freshness,
        ) in expected_receipts:
            if (
                not isinstance(receipt_payload, dict)
                or receipt_payload.get("schema") != schema
                or receipt_payload.get("result") != "pass"
                or receipt_payload.get("release") != identity["release"]
                or receipt_payload.get("source_commit") != identity["source_commit"]
                or receipt_payload.get("source_tree") != identity["source_tree"]
                or receipt_payload.get("archive") != identity["artifacts"][asset_name]
                or receipt_payload.get("canonical_tar")
                != {
                    "filename": identity["compression"][asset_name]["canonical_tar"][
                        "filename"
                    ],
                    "bytes": identity["compression"][asset_name]["canonical_tar"][
                        "bytes"
                    ],
                    "sha256": identity["compression"][asset_name]["canonical_tar"][
                        "sha256"
                    ],
                }
                or receipt_payload.get("compression", {})
                .get("output", {})
                .get("sha256")
                != artifact_freshness["sha256"]
            ):
                raise ReleaseError(f"{label} {asset_name} assembly receipt differs")
        native_roots.append(f"{label}/reproduction")
        native_assembly = {
            "corresponding_source": {
                "argv": [
                    *source_command["argv"],
                ],
                "exit_status": source_command["exit_status"],
                "tool": file_record(checked_source_assembler),
                "artifact": source_freshness,
                "canonical_tar": source_receipt_payload["canonical_tar"],
                "receipt": {
                    "path": f"{label}/native-work/source-assembly-receipt.json",
                    "file": file_record(source_receipt),
                    "payload": source_receipt_payload,
                },
            },
            "ready_run": {
                "argv": [*ready_command["argv"]],
                "exit_status": ready_command["exit_status"],
                "tool": file_record(checked_ready_assembler),
                "artifact": ready_freshness,
                "canonical_tar": ready_receipt_payload["canonical_tar"],
                "receipt": {
                    "path": f"{label}/native-work/ready-assembly-receipt.json",
                    "file": file_record(ready_receipt),
                    "payload": ready_receipt_payload,
                },
            },
            "used_frozen_tree": identity["inputs"]["frozen_tree"],
        }
        native_commands = [source_command, ready_command]
        root_report = {
            "schema": "kazstem-macos-root-reproduction-v1",
            "logical_root": label,
            "source_commit": identity["source_commit"],
            "source_tree": identity["source_tree"],
            "source_ref": identity["source_ref"],
            "source_tag_object": authority["source_tag_object"],
            "fresh_frozen_tree": identity["inputs"]["frozen_tree"],
            "artifacts": {
                "ready_run": identity["artifacts"]["ready_run"],
                "corresponding_source": identity["artifacts"]["corresponding_source"],
            },
            "commands": [
                venv_command,
                install_command,
                frozen_command,
                *native_commands,
            ],
        }
        root_report_path = native / "ROOT-REPRODUCTION.json"
        root_report_path.write_bytes(json_bytes(root_report))
        root_receipts.append(
            {
                "logical_root": label,
                "path": f"{label}/reproduction/ROOT-REPRODUCTION.json",
                "file": file_record(root_report_path),
            }
        )
        builds.append(
            {
                "root": label,
                "checkout": checkout_record,
                "checkout_regular_files": checkout_files,
                "canonical_python_inputs": canonical_inputs,
                "frozen_build": {
                    "fresh_environment": True,
                    "environment_root": f"{label}/freezer-env",
                    "commands": [venv_command, install_command, frozen_command],
                    "evidence": file_record(freezer_evidence),
                    "output_tree": frozen_payload["output_tree"],
                    "regular_files": frozen_files,
                },
                "native_assembly": native_assembly,
            }
        )

    result = {
        "schema": "kazstem-macos-python-native-reproducibility-v1",
        "pass": True,
        "release": identity["release"],
        "source_commit": identity["source_commit"],
        "source_tree": identity["source_tree"],
        "source_origin": identity["source_origin"],
        "source_ref": identity["source_ref"],
        "identity_contract_sha256": identity_sha256(identity_path),
        "configuration": configuration,
        "controlled_environment": {
            **configuration["environment"],
            "HOME": "workspace/controlled-home",
            "GIT_CONFIG_GLOBAL": "disabled",
            "GIT_CONFIG_NOSYSTEM": "1",
        },
        "canonical_python_authority": authority,
        "canonical_python_builds": authority["linux_reproducibility"][
            "validated_distinct_roots"
        ],
        "native_direct_assemblies": len(builds),
        "fresh_frozen_builds": len(builds),
        "frozen_tree_identity": all(
            build["frozen_build"]["output_tree"] == identity["inputs"]["frozen_tree"]
            for build in builds
        ),
        "canonical_artifacts": {"wheel": wheel, "sdist": sdist},
        "builds": builds,
        "native_reproduction_roots": native_roots,
        "root_receipts": root_receipts,
        "filesystem_aliases": [],
    }
    assert_relative_json(result, label="Python reproducibility report")
    envelope = gate_envelope(
        identity=identity,
        identity_contract_sha256=identity_sha256(identity_path),
        gate="python-reproducibility",
        subjects=["corresponding_source", "ready_run", "sdist", "wheel"],
        invocation=locked_gate_invocation(
            identity,
            "python-reproducibility",
            stdout=b"PASS: fresh macOS reproduction roots verified\n",
            execution=execution,
        ),
        coverage={
            "descendant_processes": max(1, len(builds) * 7),
            "full_descendant_coverage": True,
            "network_trace": None,
            "observations": {
                "fresh_frozen_builds": len(builds),
                "fresh_native_assemblies": len(builds),
                "root_receipts": len(root_receipts),
                "linux_canonical_python_builds": authority[
                    "linux_reproducibility"
                ]["validated_distinct_roots"],
                "mac_python_artifact_builds": 0,
            },
            "trace_complete": True,
            "trace_truncated": False,
        },
        payload=result,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(json_bytes(envelope))
    return envelope


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--identity", required=True, type=Path)
    parser.add_argument("--repository", required=True, type=Path)
    parser.add_argument("--canonical-artifacts", required=True, type=Path)
    parser.add_argument("--python-build-identity", required=True, type=Path)
    parser.add_argument("--linux-release-identity", required=True, type=Path)
    parser.add_argument("--linux-reproducibility", required=True, type=Path)
    parser.add_argument("--python-interpreter-source", required=True, type=Path)
    parser.add_argument("--payload", required=True, type=Path)
    parser.add_argument("--resources", required=True, type=Path)
    parser.add_argument("--runtime", required=True, type=Path)
    parser.add_argument("--documents", required=True, type=Path)
    parser.add_argument("--binary-readme-template", required=True, type=Path)
    parser.add_argument("--source-readme-template", required=True, type=Path)
    parser.add_argument("--base-ledger", required=True, type=Path)
    parser.add_argument("--freezer-wheelhouse", required=True, type=Path)
    parser.add_argument("--freezer-requirements", required=True, type=Path)
    parser.add_argument("--freezer-spec", required=True, type=Path)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    verify(args)
    print("PASS: fresh macOS reproduction roots verified")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ReleaseError, OSError, ValueError, json.JSONDecodeError) as exc:
        raise SystemExit(f"error: {exc}") from exc
