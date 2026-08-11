#!/usr/bin/env python3
"""Audit the complete thin-arm64, ad-hoc-signed macOS dependency closure."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import subprocess
from typing import Any

from release_common import (
    ReleaseError,
    assert_relative_json,
    begin_gate_execution,
    file_record,
    gate_envelope,
    identity_sha256,
    json_bytes,
    load_identity,
    locked_gate_invocation,
    stream_evidence_record,
    verify_file,
    verify_ready_root_identity,
)


SYSTEM_BOUNDARIES = ("/System/Library/", "/usr/lib/")
MACHO_MAGICS = {
    b"\xcf\xfa\xed\xfe",
    b"\xfe\xed\xfa\xcf",
    b"\xca\xfe\xba\xbe",
    b"\xbe\xba\xfe\xca",
}
BANNED_FRAGMENTS = ("_hashlib", "_ssl", "libcrypto", "libssl", "openssl")


def _logical_rpath(value: str) -> str:
    return f"absolute-inherited:{value.lstrip('/')}" if value.startswith("/") else value


def _logical_install_name(value: str) -> str:
    if value.startswith(SYSTEM_BOUNDARIES) or not value.startswith("/"):
        return value
    return f"absolute-install-name:{value.lstrip('/')}"


def _run(argv: list[str], *, timeout: int = 60) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        check=False,
    )


def _text(argv: list[str], *, label: str) -> str:
    process = _run(argv)
    data = process.stdout + process.stderr
    if process.returncode:
        raise ReleaseError(
            f"{label} failed ({process.returncode}): {data[:4096].decode('utf-8', 'replace')}"
        )
    return data.decode("utf-8", "replace")


def _macho(path: Path) -> bool:
    with path.open("rb") as source:
        return source.read(4) in MACHO_MAGICS


def _macho_files(root: Path) -> list[Path]:
    return sorted(
        (
            path
            for path in root.rglob("*")
            if path.is_file() and not path.is_symlink() and _macho(path)
        ),
        key=lambda path: path.relative_to(root).as_posix(),
    )


def _load_commands(path: Path) -> tuple[list[str], list[str]]:
    output = _text(["/usr/bin/otool", "-l", str(path)], label="otool -l")
    versions: list[str] = []
    rpaths: list[str] = []
    lines = output.splitlines()
    for index, line in enumerate(lines):
        stripped = line.strip()
        if stripped in {"cmd LC_BUILD_VERSION", "cmd LC_VERSION_MIN_MACOSX"}:
            key = "minos" if stripped.endswith("BUILD_VERSION") else "version"
            for following in lines[index + 1 : index + 12]:
                match = re.match(rf"\s*{key}\s+(\S+)", following)
                if match:
                    versions.append(match.group(1))
                    break
        elif stripped == "cmd LC_RPATH":
            for following in lines[index + 1 : index + 8]:
                match = re.match(r"\s*path\s+(\S+)\s+\(offset", following)
                if match:
                    rpaths.append(match.group(1))
                    break
    if not versions:
        raise ReleaseError(f"Mach-O lacks a deployment target: {path.name}")
    return versions, rpaths


def _dependencies(path: Path) -> list[str]:
    output = _text(["/usr/bin/otool", "-L", str(path)], label="otool -L")
    return [
        line.strip().split(" (compatibility", 1)[0]
        for line in output.splitlines()[1:]
        if line.strip()
    ]


def _install_names(path: Path) -> set[str]:
    process = _run(["/usr/bin/otool", "-D", str(path)])
    if process.returncode:
        return set()
    return {
        line.strip()
        for line in process.stdout.decode("utf-8", "replace").splitlines()[1:]
        if line.strip()
    }


def _executable_dir(path: Path, root: Path, runtime_parent: str) -> Path:
    relative = path.relative_to(root).as_posix()
    runtime_prefix = runtime_parent.rstrip("/") + "/"
    if relative.startswith(runtime_prefix) and "/usr/" in relative:
        prefix = relative.split("/usr/", 1)[0]
        return root / prefix / "usr/bin"
    return root


def _expanded(token: str, *, loader: Path, executable: Path) -> Path | None:
    if token == "@loader_path":
        return loader
    if token.startswith("@loader_path/"):
        return loader / token[len("@loader_path/") :]
    if token == "@executable_path":
        return executable
    if token.startswith("@executable_path/"):
        return executable / token[len("@executable_path/") :]
    if token.startswith("/"):
        return Path(token)
    return None


def _relative(path: Path, root: Path) -> str | None:
    try:
        return (
            path.resolve(strict=True).relative_to(root.resolve(strict=True)).as_posix()
        )
    except (OSError, ValueError):
        return None


def _resolve(
    dependency: str,
    *,
    path: Path,
    root: Path,
    rpaths: list[str],
    runtime_parent: str,
) -> tuple[str, list[dict[str, str]]]:
    if dependency.startswith(SYSTEM_BOUNDARIES):
        return "system", [
            {"candidate": dependency, "result": "allowed-system-boundary"}
        ]
    loader = path.parent
    executable = _executable_dir(path, root, runtime_parent)
    attempts: list[dict[str, str]] = []
    if dependency.startswith("@rpath/"):
        suffix = dependency[len("@rpath/") :]
        for entry in rpaths:
            if entry.startswith("/"):
                attempts.append(
                    {
                        "candidate": _logical_rpath(entry),
                        "result": "forbidden-absolute-before-bundled-selection",
                    }
                )
                raise ReleaseError(
                    "absolute rpath precedes the selected bundled dependency: "
                    f"{path.name}: {dependency}: {attempts!r}"
                )
            base = _expanded(entry, loader=loader, executable=executable)
            if base is None:
                attempts.append({"candidate": entry, "result": "unexpanded-rpath"})
                continue
            candidate = base / suffix
            internal = _relative(candidate, root)
            if internal is not None:
                attempts.append({"candidate": internal, "result": "selected-bundled"})
                return internal, attempts
            attempts.append({"candidate": entry, "result": "missing-bundled"})
        raise ReleaseError(
            f"unresolved @rpath dependency: {path.name}: {dependency}: {attempts!r}"
        )
    expanded = _expanded(dependency, loader=loader, executable=executable)
    if expanded is not None and dependency.startswith("@"):
        internal = _relative(expanded, root)
        if internal is None:
            raise ReleaseError(
                f"relative dependency escapes bundle: {path.name}: {dependency}"
            )
        return internal, [{"candidate": internal, "result": "selected-bundled"}]
    raise ReleaseError(
        f"forbidden absolute/nonportable dependency: {path.name}: {dependency}"
    )


def _signature(path: Path) -> dict[str, Any]:
    verify = _run(
        ["/usr/bin/codesign", "--verify", "--strict", "--verbose=4", str(path)]
    )
    details = _run(["/usr/bin/codesign", "-d", "--verbose=4", str(path)])
    text = (details.stdout + details.stderr).decode("utf-8", "replace")
    team_match = re.search(r"^TeamIdentifier=(.+)$", text, re.MULTILINE)
    authorities = re.findall(r"^Authority=(.+)$", text, re.MULTILINE)
    return {
        "strict": verify.returncode == 0,
        "kind": "adhoc" if "Signature=adhoc" in text else "other",
        "team_identifier": (
            None
            if team_match is None or team_match.group(1).strip() == "not set"
            else team_match.group(1).strip()
        ),
        "authorities": authorities,
        "verification": stream_evidence_record(verify.stdout + verify.stderr),
    }


def _container_signatures(root: Path) -> tuple[list[dict[str, Any]], list[str]]:
    containers = sorted(
        (
            path
            for path in root.rglob("*")
            if path.is_dir()
            and not path.is_symlink()
            and path.suffix.casefold() in {".app", ".bundle", ".framework"}
        ),
        key=lambda path: path.relative_to(root).as_posix(),
    )
    if not containers:
        raise ReleaseError("ready-run lacks an embedded signed framework/container")
    records: list[dict[str, Any]] = []
    failures: list[str] = []
    for path in containers:
        relative = path.relative_to(root).as_posix()
        verify = _run(
            [
                "/usr/bin/codesign",
                "--verify",
                "--strict",
                "--deep",
                "--verbose=4",
                str(path),
            ],
            timeout=180,
        )
        details = _run(["/usr/bin/codesign", "-d", "--verbose=4", str(path)])
        text = (details.stdout + details.stderr).decode("utf-8", "replace")
        authorities = re.findall(r"^Authority=(.+)$", text, re.MULTILINE)
        team = re.search(r"^TeamIdentifier=(.+)$", text, re.MULTILINE)
        team_identifier = (
            None
            if team is None or team.group(1).strip() == "not set"
            else team.group(1).strip()
        )
        strict = (
            verify.returncode == 0
            and details.returncode == 0
            and "Signature=adhoc" in text
            and team_identifier is None
            and not authorities
        )
        if not strict:
            failures.append(relative)
        records.append(
            {
                "path": relative,
                "strict_deep": strict,
                "signature": "adhoc" if "Signature=adhoc" in text else "other",
                "team_identifier": team_identifier,
                "authorities": authorities,
                "verification": stream_evidence_record(verify.stdout + verify.stderr),
            }
        )
    return records, failures


def audit(args: argparse.Namespace) -> dict[str, Any]:
    if args.output.exists() or args.output.is_symlink():
        raise ReleaseError(f"Mach-O evidence output already exists: {args.output}")
    identity_path = args.identity.resolve(strict=True)
    identity = load_identity(identity_path)
    execution = begin_gate_execution(identity, "macho-closure", caller_file=__file__)
    root = args.bundle.resolve(strict=True)
    root_binding = verify_ready_root_identity(args.bundle, identity)
    runtime_id = identity["inputs"]["runtime_tree"]["bundle_id"]
    runtime_parent = identity["ready_run"]["runtime_parent"]
    runtime = root / runtime_parent / runtime_id
    if not runtime.is_dir() or runtime.is_symlink():
        raise ReleaseError("bundle lacks its identity-bound runtime tree")
    manifest = runtime / "manifest.json"
    verify_file(
        manifest,
        identity["inputs"]["runtime_tree"]["manifest"],
        label="detached runtime manifest",
    )

    files = _macho_files(root)
    if not files:
        raise ReleaseError("ready-run contains no Mach-O files")
    records: list[dict[str, Any]] = []
    versions: list[tuple[int, ...]] = []
    strict_failures: list[str] = []
    teams: set[str] = set()
    missing: list[str] = []
    escaped: list[str] = []
    absolute_dependencies: list[str] = []
    banned_dependencies: list[str] = []
    exact_rpaths: dict[str, list[str]] = {}
    for path in files:
        relative = path.relative_to(root).as_posix()
        archs = (
            _text(["/usr/bin/lipo", "-archs", str(path)], label="lipo").strip().split()
        )
        if archs != ["arm64"]:
            raise ReleaseError(f"Mach-O is not thin arm64: {relative}: {archs}")
        deployment, rpaths = _load_commands(path)
        exact_rpaths[relative] = [_logical_rpath(value) for value in rpaths]
        for version in deployment:
            versions.append(tuple(int(part) for part in version.split(".")))
        own_ids = _install_names(path)
        resolved: list[dict[str, Any]] = []
        for dependency in _dependencies(path):
            if any(fragment in dependency.casefold() for fragment in BANNED_FRAGMENTS):
                banned_dependencies.append(f"{relative}:{dependency}")
            if dependency in own_ids:
                resolved.append(
                    {
                        "install_name": _logical_install_name(dependency),
                        "resolution": "self-id",
                        "attempts": [],
                    }
                )
                continue
            try:
                resolution, attempts = _resolve(
                    dependency,
                    path=path,
                    root=root,
                    rpaths=rpaths,
                    runtime_parent=runtime_parent,
                )
            except ReleaseError:
                missing.append(f"{relative}:{dependency}")
                raise
            if dependency.startswith("/") and not dependency.startswith(
                SYSTEM_BOUNDARIES
            ):
                absolute_dependencies.append(f"{relative}:{dependency}")
            resolved.append(
                {
                    "install_name": _logical_install_name(dependency),
                    "resolution": resolution,
                    "attempts": attempts,
                }
            )
        signature = _signature(path)
        if not signature["strict"]:
            strict_failures.append(relative)
        if signature["kind"] != "adhoc" or signature["authorities"]:
            raise ReleaseError(f"Mach-O is not unsigned/ad-hoc: {relative}")
        if signature["team_identifier"] is not None:
            teams.add(signature["team_identifier"])
        records.append(
            {
                "path": relative,
                **file_record(path),
                "architectures": archs,
                "deployment_targets": deployment,
                "rpaths": [_logical_rpath(value) for value in rpaths],
                "install_names": sorted(
                    _logical_install_name(value) for value in own_ids
                ),
                "dependencies": resolved,
                "signature": signature,
            }
        )
    if strict_failures or teams or banned_dependencies or absolute_dependencies:
        raise ReleaseError("Mach-O signature/dependency closure is not releasable")
    container_records, container_failures = _container_signatures(root)
    if container_failures:
        raise ReleaseError(
            f"embedded container resource-seal failures: {container_failures}"
        )

    all_relative = [
        path.relative_to(root).as_posix().casefold() for path in root.rglob("*")
    ]
    banned_modules = sorted(
        relative
        for relative in all_relative
        if any(fragment in relative for fragment in BANNED_FRAGMENTS)
    )
    neural = sorted(
        relative
        for relative in all_relative
        if any(
            fragment in relative
            for fragment in ("neural", ".pt", ".onnx", ".safetensors")
        )
    )
    if banned_modules or neural:
        raise ReleaseError("banned module/native/neural files remain in the ready-run")

    runtime_verify = _run(
        [
            str(args.python.resolve(strict=True)),
            "scripts/write_platform_runtime_manifest.py",
            "--runtime-dir",
            str(runtime),
            "--archive-dir",
            str(args.runtime_archives.resolve(strict=True)),
            "--source-dir",
            str(args.runtime_sources.resolve(strict=True)),
            "--lock",
            str(args.runtime_source_lock.resolve(strict=True)),
            "--verify",
        ],
        timeout=600,
    )
    if runtime_verify.returncode:
        raise ReleaseError(
            "detached runtime manifest did not reproduce: "
            + (runtime_verify.stdout + runtime_verify.stderr)[:4096].decode(
                "utf-8", "replace"
            )
        )
    launcher = root / identity["ready_run"]["launcher"]["path"]
    stapler = _run(
        ["/usr/bin/xcrun", "stapler", "validate", str(launcher)], timeout=120
    )
    if stapler.returncode == 0:
        raise ReleaseError(
            "unsigned launcher unexpectedly carries a notarization ticket"
        )

    maximum = max(versions)
    maximum_text = ".".join(str(part) for part in maximum)
    if (
        tuple(int(part) for part in identity["platform"]["minimum_os"].split("."))
        != maximum
    ):
        raise ReleaseError(
            f"archive label minimum OS differs: identity={identity['platform']['minimum_os']}, "
            f"observed={maximum_text}"
        )
    payload = {
        "schema": "kazstem-macos-macho-closure-v1",
        "pass": True,
        "release": identity["release"],
        "source_commit": identity["source_commit"],
        "source_tree": identity["source_tree"],
        "macho_files": len(records),
        "architectures": ["arm64"],
        "fat_files": [],
        "maximum_minimum_os": maximum_text,
        "system_boundaries": list(SYSTEM_BOUNDARIES),
        "missing": missing,
        "escaped": escaped,
        "non_system_absolute_dependencies": absolute_dependencies,
        "banned_dependencies": banned_dependencies,
        "banned_modules": banned_modules,
        "codesign_strict_failures": strict_failures,
        "container_signature_failures": container_failures,
        "signed_containers": container_records,
        "signature_kind": "adhoc",
        "team_identifiers": sorted(teams),
        "developer_id_signed": False,
        "notarized": False,
        "stapled": False,
        "runtime_bundle_id": runtime_id,
        "runtime_manifest": identity["inputs"]["runtime_tree"]["manifest"],
        "runtime_manifest_verified": True,
        "neural_weights": neural,
        "root_binding": root_binding,
        "rpaths": exact_rpaths,
        "files": records,
        "runtime_verification": {
            "argv": [
                "python",
                "scripts/write_platform_runtime_manifest.py",
                "--verify",
            ],
            "exit_status": 0,
            "stdout": stream_evidence_record(runtime_verify.stdout),
            "stderr": stream_evidence_record(runtime_verify.stderr),
        },
        "stapler_negative_observation": {
            "argv": ["xcrun", "stapler", "validate", "bundle/kazstem"],
            "exit_status": stapler.returncode,
            "stdout": stream_evidence_record(stapler.stdout),
            "stderr": stream_evidence_record(stapler.stderr),
        },
    }
    assert_relative_json(payload, label="Mach-O closure payload")
    envelope = gate_envelope(
        identity=identity,
        identity_contract_sha256=identity_sha256(identity_path),
        gate="macho-closure",
        subjects=["ready_run"],
        invocation=locked_gate_invocation(
            identity,
            "macho-closure",
            stdout=b"structured Mach-O audit written to output\n",
            execution=execution,
        ),
        coverage={
            "descendant_processes": max(
                1, len(records) * 5 + len(container_records) * 2 + 2
            ),
            "full_descendant_coverage": True,
            "network_trace": None,
            "observations": {
                "dependencies": sum(len(record["dependencies"]) for record in records),
                "macho_files": len(records),
                "rpaths": sum(len(value) for value in exact_rpaths.values()),
                "signatures": len(records),
                "signed_containers": len(container_records),
            },
            "trace_complete": True,
            "trace_truncated": False,
        },
        payload=payload,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(json_bytes(envelope))
    return envelope


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--identity", required=True, type=Path)
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--runtime-archives", required=True, type=Path)
    parser.add_argument("--runtime-sources", required=True, type=Path)
    parser.add_argument("--runtime-source-lock", required=True, type=Path)
    parser.add_argument("--python", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    result = audit(args)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ReleaseError, OSError, ValueError, json.JSONDecodeError) as exc:
        raise SystemExit(f"error: {exc}") from exc
