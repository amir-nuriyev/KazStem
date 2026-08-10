#!/usr/bin/env python3
"""Audit the complete ELF dependency boundary of an extracted Linux asset."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
from typing import Any


ELF_MAGIC = b"\x7fELF"
ALLOWED_HOST_PREFIXES = (
    "/lib/x86_64-linux-gnu/",
    "/usr/lib/x86_64-linux-gnu/",
    "/lib64/",
)
BANNED = {"libssl.so.3", "libcrypto.so.3"}


def command(arguments: list[str], *, env: dict[str, str] | None = None) -> str:
    completed = subprocess.run(
        arguments,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
        check=False,
    )
    if completed.returncode:
        raise RuntimeError(
            f"command failed ({completed.returncode}): {arguments!r}: {completed.stdout}"
        )
    return completed.stdout


def is_elf(path: Path) -> bool:
    if not path.is_file() or path.is_symlink():
        return False
    with path.open("rb") as stream:
        return stream.read(4) == ELF_MAGIC


def package(path: Path) -> dict[str, str] | None:
    completed = subprocess.run(
        ["dpkg-query", "-S", str(path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        check=False,
    )
    if completed.returncode:
        completed = subprocess.run(
            ["dpkg-query", "-S", str(path.resolve())],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            check=False,
        )
    if completed.returncode:
        return None
    owner = completed.stdout.split(":", 1)[0].strip()
    version = command(["dpkg-query", "-W", "-f=${Version}", owner]).strip()
    return {"package": owner, "version": version}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    root = args.root.resolve(strict=True)
    runtime_libs = sorted(root.glob(".qazmorph/platform-runtimes/*/usr/lib/x86_64-linux-gnu"))
    library_path = ":".join(str(path) for path in runtime_libs)
    environment = os.environ.copy()
    environment.pop("LD_PRELOAD", None)
    environment.pop("LD_AUDIT", None)
    environment["LD_LIBRARY_PATH"] = library_path

    elfs = sorted(
        (path for path in root.rglob("*") if is_elf(path)),
        key=lambda item: item.as_posix(),
    )
    records: list[dict[str, Any]] = []
    host: dict[str, dict[str, Any]] = {}
    missing: list[dict[str, str]] = []
    escaped: list[dict[str, str]] = []
    banned: list[dict[str, str]] = []
    versions: dict[str, set[str]] = {"GLIBC": set(), "GLIBCXX": set(), "CXXABI": set()}
    for elf in elfs:
        relative = elf.relative_to(root).as_posix()
        dynamic = command(["readelf", "-dW", str(elf)])
        needed = re.findall(r"\(NEEDED\).*?\[([^]]+)\]", dynamic)
        rpaths = re.findall(r"\((?:RPATH|RUNPATH)\).*?\[([^]]+)\]", dynamic)
        listing = command(["ldd", str(elf)], env=environment)
        resolved: list[dict[str, Any]] = []
        for line in listing.splitlines():
            line = line.strip()
            if (
                not line
                or line.startswith("linux-vdso")
                or line in {"statically linked", "not a dynamic executable"}
            ):
                continue
            if "=> not found" in line:
                name = line.split("=>", 1)[0].strip()
                missing.append({"elf": relative, "dependency": name})
                resolved.append({"name": name, "status": "missing"})
                continue
            if "=>" in line:
                name, remainder = line.split("=>", 1)
                selected = remainder.strip().split(" ", 1)[0]
            else:
                selected = line.split(" ", 1)[0]
                name = Path(selected).name
            selected_path = Path(selected).resolve()
            try:
                selected_relative = selected_path.relative_to(root).as_posix()
            except ValueError:
                selected_relative = None
            if selected_relative is not None:
                classification = "bundled"
            elif str(selected_path).startswith(ALLOWED_HOST_PREFIXES):
                classification = "ubuntu-host"
                key = str(selected_path)
                host.setdefault(
                    key,
                    {
                        "path": key,
                        "soname": name.strip(),
                        "owner": package(selected_path),
                    },
                )
            else:
                classification = "escaped"
                escaped.append({"elf": relative, "dependency": str(selected_path)})
            if name.strip() in BANNED or selected_path.name in BANNED:
                banned.append({"elf": relative, "dependency": selected_path.name})
            resolved.append(
                {
                    "name": name.strip(),
                    "path": selected_relative or str(selected_path),
                    "classification": classification,
                }
            )
        version_info = command(["readelf", "--version-info", "-W", str(elf)])
        for family in versions:
            versions[family].update(
                re.findall(rf"\b{family}_[0-9][0-9.]*\b", version_info)
            )
        records.append(
            {
                "path": relative,
                "bytes": elf.stat().st_size,
                "machine": re.search(r"Machine:\s*(.+)", command(["readelf", "-hW", str(elf)])).group(1).strip(),
                "needed": needed,
                "rpaths": rpaths,
                "resolved": resolved,
            }
        )

    module_names = {path.name for path in root.rglob("*") if path.is_file()}
    banned_modules = sorted(
        name for name in module_names if name.startswith(("_ssl.", "_hashlib."))
    )
    result = {
        "schema": "kazstem-linux-elf-closure-v1",
        "target": "Ubuntu 24.04 x86_64 (glibc 2.39)",
        "root": root.name,
        "elf_count": len(elfs),
        "elfs": records,
        "host_boundary": [host[key] for key in sorted(host)],
        "required_symbol_versions": {
            family: sorted(values, key=lambda value: tuple(int(x) for x in value.split("_", 1)[1].split(".")))
            for family, values in versions.items()
        },
        "missing": missing,
        "escaped": escaped,
        "banned_dependencies": banned,
        "banned_modules": banned_modules,
        "pass": bool(elfs) and not missing and not escaped and not banned and not banned_modules,
    }
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps({
        "pass": result["pass"],
        "elf_count": result["elf_count"],
        "host_dependencies": len(result["host_boundary"]),
        "missing": missing,
        "escaped": escaped,
        "banned": banned,
        "max_versions": {key: (value[-1] if value else None) for key, value in result["required_symbol_versions"].items()},
    }, indent=2, sort_keys=True))
    return 0 if result["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
