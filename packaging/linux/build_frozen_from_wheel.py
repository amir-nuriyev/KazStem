#!/usr/bin/env python3
"""Build the Linux launcher from one exact canonical wheel, offline."""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import importlib.metadata
import io
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import sys
import tempfile
import types
import zipfile


def _source_module(name: str, path: Path) -> types.ModuleType:
    module = types.ModuleType(name)
    module.__file__ = str(path)
    sys.modules[name] = module
    source = path.read_bytes()
    try:
        exec(compile(source, str(path), "exec", dont_inherit=True), module.__dict__)
    finally:
        source = b""
    return module


_HERE = Path(__file__).resolve().parent
_common = _source_module("_kazstem_frozen_release_common", _HERE / "release_common.py")

ReleaseError = _common.ReleaseError
SupervisionError = _common.SupervisionError
archive_limits = _common.archive_limits
canonical_hash = _common.canonical_hash
file_record = _common.file_record
inspect_zip = _common.inspect_zip
json_bytes = _common.json_bytes
load_identity = _common.load_identity
portable_path = _common.portable_path
run_bounded = _common.run_bounded
tree_record = _common.tree_record
verify_artifact = _common.verify_artifact
verify_file = _common.verify_file

SCHEMA = "kazstem-frozen-wheel-consumption-receipt-v2"
MAX_CAPTURE = 16 * 1024**2


def _exact(value: object, fields: set[str], label: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != fields:
        raise ReleaseError(f"{label} fields differ")
    return value


def _same_or_nested(first: Path, second: Path) -> bool:
    one = first.resolve(strict=False)
    two = second.resolve(strict=False)
    return one == two or one in two.parents or two in one.parents


def _distinct(paths: list[tuple[str, Path]]) -> None:
    for index, (first_label, first) in enumerate(paths):
        for second_label, second in paths[index + 1 :]:
            if _same_or_nested(first, second):
                raise ReleaseError(f"{first_label} and {second_label} are equal/nested")
            if first.exists() and second.exists() and os.path.samefile(first, second):
                raise ReleaseError(f"{first_label} and {second_label} are aliases")


def _stream(data: bytes) -> dict[str, object]:
    return {
        "bytes": len(data),
        "lines": len(data.splitlines()),
        "sha256": hashlib.sha256(data).hexdigest(),
        "truncated": False,
    }


def _normalize(data: bytes, replacements: list[tuple[str, str]]) -> bytes:
    try:
        text = data.decode("utf-8").replace("\r\n", "\n")
    except UnicodeError as exc:
        raise ReleaseError("freezer subprocess output is not UTF-8") from exc
    for actual, logical in sorted(replacements, key=lambda item: len(item[0]), reverse=True):
        text = text.replace(actual, logical)
        text = text.replace(actual.replace("/", "\\"), logical)
    return text.encode("utf-8")


def _run(
    actual: list[str],
    logical: list[str],
    *,
    cwd: Path,
    environment: dict[str, str],
    logical_environment: dict[str, str],
    timeout: int,
    replacements: list[tuple[str, str]],
) -> dict[str, object]:
    try:
        completed = run_bounded(
            actual,
            cwd=cwd,
            environment=environment,
            timeout=timeout,
            max_stdout=MAX_CAPTURE,
            max_stderr=MAX_CAPTURE,
        )
    except SupervisionError as exc:
        raise ReleaseError(f"freezer subprocess supervision failed: {exc}") from exc
    stdout = _normalize(completed.stdout, replacements)
    stderr = _normalize(completed.stderr, replacements)
    record = {
        "argv": logical,
        "environment": logical_environment,
        "exit_status": completed.returncode,
        "timeout_seconds": timeout,
        "stdout": _stream(stdout),
        "stderr": _stream(stderr),
        "containment": completed.containment,
        "observed_descendants": completed.observed_descendants,
    }
    if completed.returncode:
        raise ReleaseError(
            f"freezer subprocess failed ({completed.returncode}): "
            + stderr[:4096].decode("utf-8", "replace")
        )
    return record


def _wheel_inventory(wheel: Path, identity: dict[str, object]) -> dict[str, object]:
    first = wheel.read_bytes()
    second = wheel.read_bytes()
    if first != second:
        raise ReleaseError("canonical wheel changed between complete reads")
    inspect_zip(wheel, limits=archive_limits(identity, "nested"))
    with zipfile.ZipFile(io.BytesIO(first)) as archive:
        infos = [item for item in archive.infolist() if not item.is_dir()]
        files = {item.filename: archive.read(item) for item in infos}
    dist_info = sorted(
        {PurePosixPath(name).parts[0] for name in files if ".dist-info/" in name}
    )
    if len(dist_info) != 1:
        raise ReleaseError("canonical wheel lacks one dist-info directory")
    record_path = f"{dist_info[0]}/RECORD"
    try:
        rows = list(csv.reader(io.StringIO(files[record_path].decode("utf-8"))))
    except (KeyError, UnicodeError, csv.Error) as exc:
        raise ReleaseError("canonical wheel RECORD is malformed") from exc
    if len(rows) != len(files):
        raise ReleaseError("canonical wheel RECORD is incomplete")
    for row in rows:
        if len(row) != 3 or row[0] not in files:
            raise ReleaseError("canonical wheel RECORD row differs")
        name, digest, size = row
        data = files[name]
        if name == record_path:
            if digest or size:
                raise ReleaseError("canonical wheel RECORD self row differs")
            continue
        expected = "sha256=" + base64.urlsafe_b64encode(
            hashlib.sha256(data).digest()
        ).rstrip(b"=").decode("ascii")
        if digest != expected or size != str(len(data)):
            raise ReleaseError("canonical wheel RECORD hash/size differs")
    package_files = [
        {"path": name, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
        for name, data in sorted(files.items())
        if name.startswith("qazmorph/")
    ]
    if not package_files:
        raise ReleaseError("canonical wheel lacks the qazmorph package")
    modules: list[dict[str, object]] = []
    for item in package_files:
        name = str(item["path"])
        if not name.endswith(".py"):
            continue
        parts = list(PurePosixPath(name).with_suffix("").parts)
        if parts[-1] == "__init__":
            parts.pop()
        modules.append(
            {
                "module": ".".join(parts),
                "path": name,
                "file": {"bytes": item["bytes"], "sha256": item["sha256"]},
            }
        )
    return {
        "wheel_bytes": first,
        "record": {
            "path": record_path,
            "bytes": len(files[record_path]),
            "sha256": hashlib.sha256(files[record_path]).hexdigest(),
        },
        "package": {
            "root": "qazmorph",
            "files": package_files,
            "inventory_sha256": canonical_hash(package_files),
        },
        "modules": modules,
    }


def _wheelhouse(path: Path, configuration: dict[str, object]) -> dict[str, object]:
    if path.is_symlink() or not path.is_dir():
        raise ReleaseError("freezer wheelhouse is not a real directory")
    observed = [
        {"filename": item.name, **file_record(item)}
        for item in sorted(path.iterdir(), key=lambda value: value.name)
        if item.is_file() and not item.is_symlink()
    ]
    if len(observed) != len(list(path.iterdir())):
        raise ReleaseError("freezer wheelhouse contains a link/directory/special entry")
    expected = configuration["wheelhouse"]
    if not isinstance(expected, dict) or observed != expected.get("files") or canonical_hash(
        observed
    ) != expected.get("manifest_sha256"):
        raise ReleaseError("freezer wheelhouse inventory differs")
    return {"files": observed, "manifest_sha256": canonical_hash(observed)}


def _packages(root: Path) -> list[dict[str, str]]:
    result: list[dict[str, str]] = []
    seen: set[str] = set()
    for distribution in importlib.metadata.distributions(path=[str(root)]):
        name = distribution.metadata.get("Name", "").casefold().replace("_", "-")
        if not name or name in seen or not distribution.version:
            raise ReleaseError("freezer environment package metadata differs")
        seen.add(name)
        result.append({"name": name, "version": distribution.version})
    return sorted(result, key=lambda item: item["name"])


def build(args: argparse.Namespace) -> dict[str, object]:
    identity_path = args.identity.resolve(strict=True)
    identity = load_identity(identity_path)
    configuration = identity["verification"]["reproducibility"]["frozen_builder"]
    if configuration["path"] != "packaging/linux/build_frozen_from_wheel.py":
        raise ReleaseError("running freezer builder path differs")
    verify_file(Path(__file__).resolve(strict=True), configuration["file"], label="freezer builder")
    verify_file(_HERE / "release_common.py", configuration["release_common"]["file"], label="freezer release_common")
    verify_file(_HERE.parent / "process_supervisor.py", configuration["process_supervisor"]["file"], label="freezer process supervisor")
    verify_artifact(args.wheel, identity["artifacts"]["wheel"], label="freezer wheel")
    requirements_relative = portable_path(args.requirements, label="freezer requirements")
    if requirements_relative != configuration["requirements"]["path"]:
        raise ReleaseError("freezer requirements path differs")
    requirements = args.source_checkout.resolve(strict=True).joinpath(
        *PurePosixPath(requirements_relative).parts
    )
    verify_file(requirements, configuration["requirements"]["file"], label="freezer requirements")
    wheelhouse_record = _wheelhouse(args.wheelhouse.resolve(strict=True), configuration)
    for output in (args.workspace, args.frozen, args.receipt):
        if output.exists() or output.is_symlink():
            raise ReleaseError("freezer output/workspace must be fresh")
    _distinct(
        [
            ("identity", args.identity),
            ("source checkout", args.source_checkout),
            ("wheel", args.wheel),
            ("wheelhouse", args.wheelhouse),
            ("workspace", args.workspace),
            ("frozen", args.frozen),
            ("receipt", args.receipt),
        ]
    )
    inventory = _wheel_inventory(args.wheel, identity)
    args.workspace.mkdir(parents=True)
    build_env = args.workspace / "build-env"
    home = args.workspace / "home"
    temporary = args.workspace / "tmp"
    cache = args.workspace / "cache"
    pycache = args.workspace / "pycache"
    for path in (home, temporary, cache, pycache):
        path.mkdir()
    base_environment = configuration["environment"]
    logical_environment = {
        **base_environment,
        "HOME": "workspace/home",
        "PIP_CONFIG_FILE": "disabled",
        "PIP_DISABLE_PIP_VERSION_CHECK": "1",
        "PIP_NO_INDEX": "1",
        "PYTHONNOUSERSITE": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONPYCACHEPREFIX": "workspace/pycache",
        "TEMP": "workspace/tmp",
        "TMP": "workspace/tmp",
        "TMPDIR": "workspace/tmp",
        "XDG_CACHE_HOME": "workspace/cache",
    }
    actual_environment = {
        **base_environment,
        "HOME": str(home),
        "PIP_CONFIG_FILE": os.devnull,
        "PIP_DISABLE_PIP_VERSION_CHECK": "1",
        "PIP_NO_INDEX": "1",
        "PYTHONNOUSERSITE": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONPYCACHEPREFIX": str(pycache),
        "TEMP": str(temporary),
        "TMP": str(temporary),
        "TMPDIR": str(temporary),
        "XDG_CACHE_HOME": str(cache),
    }
    python = Path(sys.executable).resolve(strict=True)
    bootstrap = configuration["bootstrap_pip"]
    bootstrap_wheel = args.wheelhouse.resolve(strict=True) / bootstrap["filename"]
    verify_file(bootstrap_wheel, bootstrap["file"], label="freezer bootstrap pip")
    provision_template = configuration["provision_argv"]
    provision_actual = [
        item.replace("{python}", str(python))
        .replace("{build_env}", str(build_env))
        .replace("{wheelhouse}", str(args.wheelhouse.resolve(strict=True)))
        .replace("{requirements}", str(requirements))
        for item in provision_template
    ]
    provision_logical = [
        item.replace("{build_env}", "workspace/build-env")
        .replace("{wheelhouse}", "inputs/freezer-wheelhouse")
        .replace("{requirements}", requirements_relative)
        for item in provision_template
    ]
    provision_environment = {**actual_environment, "PYTHONPATH": str(bootstrap_wheel)}
    provision_logical_environment = {
        **logical_environment,
        "PYTHONPATH": "inputs/freezer-wheelhouse/" + bootstrap["filename"],
    }
    replacements = [
        (str(args.workspace.absolute()), "workspace"),
        (str(args.source_checkout.resolve(strict=True)), "source-checkout"),
        (str(args.wheel.resolve(strict=True)), "artifacts/" + args.wheel.name),
        (str(args.wheelhouse.resolve(strict=True)), "inputs/freezer-wheelhouse"),
        (str(python), "{python}"),
    ]
    provision = _run(
        provision_actual,
        provision_logical,
        cwd=args.source_checkout.resolve(strict=True),
        environment=provision_environment,
        logical_environment=provision_logical_environment,
        timeout=configuration["timeout_seconds"],
        replacements=replacements,
    )
    packages = _packages(build_env)
    if packages != configuration["packages"]:
        raise ReleaseError("freezer provisioned package set differs")
    spec = args.source_checkout.resolve(strict=True).joinpath(
        *PurePosixPath(configuration["spec"]["path"]).parts
    )
    bootstrap_script = args.source_checkout.resolve(strict=True).joinpath(
        *PurePosixPath(configuration["bootstrap"]["path"]).parts
    )
    verify_file(spec, configuration["spec"]["file"], label="freezer spec")
    verify_file(bootstrap_script, configuration["bootstrap"]["file"], label="freezer bootstrap")
    dist = args.workspace / "dist"
    work = args.workspace / "pyinstaller-work"
    build_template = configuration["build_argv"]
    build_actual = [
        item.replace("{python}", str(python))
        .replace("{dist}", str(dist))
        .replace("{work}", str(work))
        .replace("{spec}", str(spec))
        for item in build_template
    ]
    build_logical = [
        item.replace("{dist}", "workspace/dist")
        .replace("{work}", "workspace/pyinstaller-work")
        .replace("{spec}", configuration["spec"]["path"])
        for item in build_template
    ]
    build_environment = {
        **actual_environment,
        "PYTHONPATH": str(build_env),
        "KAZSTEM_CANONICAL_WHEEL": str(args.wheel.resolve(strict=True)),
        "KAZSTEM_FROZEN_BOOTSTRAP": str(bootstrap_script),
        "KAZSTEM_PYTHON_OPTIMIZE": configuration["python_optimize"],
    }
    build_logical_environment = {
        **logical_environment,
        "PYTHONPATH": "workspace/build-env",
        "KAZSTEM_CANONICAL_WHEEL": "artifacts/" + args.wheel.name,
        "KAZSTEM_FROZEN_BOOTSTRAP": configuration["bootstrap"]["path"],
        "KAZSTEM_PYTHON_OPTIMIZE": configuration["python_optimize"],
    }
    build_record = _run(
        build_actual,
        build_logical,
        cwd=args.source_checkout.resolve(strict=True),
        environment=build_environment,
        logical_environment=build_logical_environment,
        timeout=configuration["timeout_seconds"],
        replacements=replacements,
    )
    produced = dist / "kazstem"
    if produced.is_symlink() or not produced.is_dir():
        raise ReleaseError("PyInstaller did not produce the expected frozen tree")
    shutil.copytree(produced, args.frozen, symlinks=True)
    embedded_relative = f"_internal/{args.wheel.name}"
    embedded = args.frozen / embedded_relative
    verify_artifact(embedded, identity["artifacts"]["wheel"], label="embedded canonical wheel")
    frozen_tree = tree_record(args.frozen)
    receipt = {
        "schema": SCHEMA,
        "pass": True,
        "wheel": {
            key: identity["artifacts"]["wheel"][key]
            for key in ("filename", "bytes", "sha256")
        },
        "record": inventory["record"],
        "package": inventory["package"],
        "input_consumption": {
            "bytes_hashed_per_pass": identity["artifacts"]["wheel"]["bytes"],
            "complete_sha256_passes": 2,
            "record_verified": True,
            "source_fallbacks_disabled": True,
        },
        "embedded_package": {
            "analysis_complete": True,
            "mechanism": "exact-canonical-wheel-data-import-v1",
            "modules": inventory["modules"],
            "package_inventory_sha256": inventory["package"]["inventory_sha256"],
            "source": "canonical-wheel-only",
            "wheel_path": embedded_relative,
            "wheel": file_record(embedded),
        },
        "provision": {
            "invocation": provision,
            "packages": packages,
            "wheelhouse": wheelhouse_record,
        },
        "build": {
            "invocation": build_record,
            "bootstrap": configuration["bootstrap"],
            "spec": configuration["spec"],
        },
        "frozen_tree": frozen_tree,
    }
    args.receipt.parent.mkdir(parents=True, exist_ok=True)
    args.receipt.write_bytes(json_bytes(receipt))
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--identity", required=True, type=Path)
    parser.add_argument("--source-checkout", required=True, type=Path)
    parser.add_argument("--wheel", required=True, type=Path)
    parser.add_argument("--wheelhouse", required=True, type=Path)
    parser.add_argument("--requirements", required=True)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--frozen", required=True, type=Path)
    parser.add_argument("--receipt", required=True, type=Path)
    result = build(parser.parse_args())
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ReleaseError, OSError, ValueError, json.JSONDecodeError, zipfile.BadZipFile) as exc:
        raise SystemExit(f"error: {exc}") from exc
