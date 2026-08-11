#!/usr/bin/env python3
"""Run native Authenticode checks over every PE in a ready-run archive."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import platform
import subprocess
import sys
import tempfile
from typing import Any

from release_common import (
    ReleaseError,
    ZipOutputContract,
    archive_limits,
    evidence_envelope,
    identity_sha256,
    json_bytes,
    load_identity,
    require_release_bootstrap,
    pe_identity,
    safe_extract_zip,
    verify_generator_runtime,
)


def powershell_status(path: Path) -> dict[str, Any]:
    script = (
        "$ErrorActionPreference='Stop'; "
        "$s=Get-AuthenticodeSignature -LiteralPath $env:KAZSTEM_PE; "
        "[ordered]@{Status=[string]$s.Status;StatusMessage=[string]$s.StatusMessage;"
        "SignerSubject=if($s.SignerCertificate){[string]$s.SignerCertificate.Subject}else{$null};"
        "TimeStamperSubject=if($s.TimeStamperCertificate){[string]$s.TimeStamperCertificate.Subject}else{$null}} | ConvertTo-Json -Compress"
    )
    environment = dict(__import__("os").environ)
    environment["KAZSTEM_PE"] = str(path)
    completed = subprocess.run(
        ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
        creationflags=0x08000000,
        timeout=30,
        check=False,
    )
    if completed.returncode:
        raise ReleaseError(f"Get-AuthenticodeSignature failed for {path.name}: {completed.stderr.decode('utf-8', 'replace')}")
    try:
        value = json.loads(completed.stdout.decode("utf-8-sig"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ReleaseError(f"invalid Authenticode result for {path.name}") from exc
    if not isinstance(value, dict):
        raise ReleaseError(f"invalid Authenticode object for {path.name}")
    return value


def main() -> int:
    require_release_bootstrap("packaging/windows/authenticode_inventory.py")
    parser = argparse.ArgumentParser()
    parser.add_argument("--identity", required=True, type=Path)
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--json", required=True, type=Path)
    args = parser.parse_args()
    if sys.platform != "win32":
        raise ReleaseError("Authenticode inventory requires native Windows")
    identity = load_identity(args.identity.resolve(strict=True))
    records: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="kazstem-authenticode-") as temporary:
        root = safe_extract_zip(
            args.archive.resolve(strict=True),
            Path(temporary) / "fresh",
            limits=archive_limits(identity, "ready_run"),
            contract=ZipOutputContract(
                identity["source_date_epoch"], (".exe", ".dll", ".pyd")
            ),
        )
        for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
            if not path.is_file() or path.suffix.casefold() not in {".exe", ".dll", ".pyd"}:
                continue
            static = pe_identity(path)
            native = powershell_status(path)
            if native.get("Status") != "NotSigned" or native.get("SignerSubject") is not None or native.get("TimeStamperSubject") is not None or static["authenticode_embedded"]:
                raise ReleaseError(f"PE signing status is not exactly unsigned: {path.name}: {native}")
            records.append(
                {
                    "path": path.relative_to(root).as_posix(),
                    "bytes": static["bytes"],
                    "sha256": static["sha256"],
                    "status": native["Status"],
                    "status_message": native.get("StatusMessage"),
                    "embedded_certificate_table": False,
                }
            )
    if not records:
        raise ReleaseError("ready-run contains no PE files")
    identity_hash = identity_sha256(args.identity.resolve(strict=True))
    logical_argv = [
        "<PYTHON>",
        "packaging/windows/authenticode_inventory.py",
        "--identity",
        "<RELEASE-IDENTITY>",
        "--archive",
        "<READY-RUN>",
        "--json",
        "<EVIDENCE-OUTPUT>",
    ]
    record = verify_generator_runtime(
        identity, gate="authenticode", logical_argv=logical_argv
    )
    observations = {
        "host": {"system": platform.system(), "version": platform.version(), "machine": platform.machine()},
        "all_unsigned": True,
        "smartscreen_warning_possible": True,
        "files": records,
    }
    result = evidence_envelope(
        identity,
        identity_hash=identity_hash,
        record=record,
        observations=observations,
    )
    if args.json.exists() or args.json.is_symlink():
        raise ReleaseError(f"Authenticode output exists: {args.json}")
    args.json.parent.mkdir(parents=True, exist_ok=True)
    args.json.write_bytes(json_bytes(result))
    print(f"PASS: {len(records)} PE files are explicitly unsigned")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ReleaseError, OSError, ValueError, json.JSONDecodeError, subprocess.SubprocessError) as exc:
        raise SystemExit(f"error: {exc}") from exc
