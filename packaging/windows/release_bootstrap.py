#!/usr/bin/env python3
"""Fail-closed launcher for Python release tools from exact source payloads.

This file is executed as the top-level script with isolated Python.  It must
not import any adjacent project module before it has rejected bytecode caches
and inventoried the complete materialized source tree.  In particular,
``-B`` prevents new cache writes but does not prevent Python from reading an
existing unchecked-hash ``.pyc`` file.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import stat
import sys
from typing import Any
import unicodedata


SCHEMA = "kazstem-release-source-bootstrap-v1"
BYTECODE_SUFFIXES = (".pyc", ".pyo", ".pyd")
MAX_PATH_BYTES = 4096
MAX_MEMBERS = 1_000_000
MAX_TOTAL_BYTES = 64 * 1024**3
WINDOWS_DEVICES = {
    "con",
    "prn",
    "aux",
    "nul",
    *(f"com{number}" for number in range(1, 10)),
    *(f"lpt{number}" for number in range(1, 10)),
}
_ATTESTATION: dict[str, Any] | None = None


class BootstrapError(RuntimeError):
    """The release process did not cross the checked source boundary."""


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise BootstrapError(f"duplicate JSON key: {key!r}")
        value[key] = item
    return value


def _read_json(path: Path) -> Any:
    try:
        with path.open("r", encoding="utf-8", newline="") as stream:
            return json.load(stream, object_pairs_hook=_pairs)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise BootstrapError(f"cannot read strict JSON {path.name}: {exc}") from exc


def _portable_path(value: str) -> str:
    if not value or "\x00" in value or "\\" in value:
        raise BootstrapError(f"source path is not portable: {value!r}")
    if unicodedata.normalize("NFC", value) != value:
        raise BootstrapError(f"source path is not NFC-normalized: {value!r}")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise BootstrapError(f"source path contains a control character: {value!r}")
    posix = PurePosixPath(value)
    windows = PureWindowsPath(value)
    parts = posix.parts
    if (
        posix.is_absolute()
        or windows.is_absolute()
        or bool(windows.drive)
        or value != posix.as_posix()
        or any(part in {"", ".", ".."} for part in parts)
        or any(":" in part for part in parts)
        or any(part != part.rstrip(" .") for part in parts)
        or any(part.split(".", 1)[0].casefold() in WINDOWS_DEVICES for part in parts)
        or len(value.encode("utf-8")) > MAX_PATH_BYTES
    ):
        raise BootstrapError(f"source path is not portable: {value!r}")
    return value


def _sha256_file(path: Path) -> tuple[int, str]:
    before = path.stat()
    if not stat.S_ISREG(before.st_mode) or path.is_symlink() or before.st_nlink != 1:
        raise BootstrapError(f"source file is not one unaliased regular file: {path}")
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            size += len(block)
            if size > MAX_TOTAL_BYTES:
                raise BootstrapError("source tree exceeds the hard byte cap")
            digest.update(block)
    after = path.stat()
    identity = lambda item: (  # noqa: E731 - compact immutable snapshot
        item.st_dev,
        item.st_ino,
        item.st_size,
        item.st_mtime_ns,
        item.st_ctime_ns,
        item.st_nlink,
    )
    if identity(before) != identity(after) or size != before.st_size:
        raise BootstrapError(f"source file changed during inventory: {path}")
    return size, digest.hexdigest()


def tree_record(root: Path) -> dict[str, Any]:
    """Return the same canonical source-tree record as release_common."""

    resolved = root.resolve(strict=True)
    if not resolved.is_dir() or resolved.is_symlink():
        raise BootstrapError("materialized source root is not a real directory")
    records: list[dict[str, Any]] = []
    folded: set[str] = set()
    total = 0
    paths = sorted(
        resolved.rglob("*"), key=lambda item: item.relative_to(resolved).as_posix()
    )
    if len(paths) > MAX_MEMBERS:
        raise BootstrapError("source tree exceeds the hard member cap")
    for path in paths:
        relative = _portable_path(path.relative_to(resolved).as_posix())
        key = unicodedata.normalize("NFC", relative).casefold()
        if key in folded:
            raise BootstrapError(f"case/NFC-colliding source path: {relative}")
        folded.add(key)
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            raise BootstrapError(f"source symlink is forbidden: {relative}")
        if stat.S_ISDIR(metadata.st_mode):
            records.append({"path": relative, "kind": "directory"})
        elif stat.S_ISREG(metadata.st_mode):
            size, digest = _sha256_file(path)
            total += size
            if total > MAX_TOTAL_BYTES:
                raise BootstrapError("source tree exceeds the hard byte cap")
            records.append(
                {
                    "path": relative,
                    "kind": "file",
                    "bytes": size,
                    "sha256": digest,
                }
            )
        else:
            raise BootstrapError(f"source special entry is forbidden: {relative}")
    if not records:
        raise BootstrapError("materialized source tree is empty")
    payload = json.dumps(
        records, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return {
        "entries": len(records),
        "regular_file_bytes": total,
        "sha256": hashlib.sha256(payload).hexdigest(),
    }


def reject_adjacent_bytecode(root: Path) -> None:
    """Reject caches before any adjacent project module can be imported."""

    for path in root.rglob("*"):
        relative = path.relative_to(root)
        folded_parts = [part.casefold() for part in relative.parts]
        if "__pycache__" in folded_parts or (
            path.is_file() and path.suffix.casefold() in BYTECODE_SUFFIXES
        ):
            raise BootstrapError(
                "forbidden adjacent Python bytecode/cache entry: "
                + relative.as_posix()
            )


def _file_record(path: Path) -> dict[str, Any]:
    size, digest = _sha256_file(path)
    return {"bytes": size, "sha256": digest}


def _require_materialization_receipts(
    *,
    root: Path,
    source: Path,
    canonical_path: Path,
    execution_path: Path,
    expected_tree: dict[str, Any],
) -> dict[str, Any]:
    if source.parent != root or source.name != "KazStem":
        raise BootstrapError("materialized source must be the root's KazStem payload")
    if canonical_path != root / "GIT-SOURCE-MATERIALIZATION.json":
        raise BootstrapError("canonical source receipt has a noncanonical location")
    if execution_path != root / "MATERIALIZATION-EXECUTION.json":
        raise BootstrapError("source execution receipt has a noncanonical location")
    canonical = _read_json(canonical_path)
    execution = _read_json(execution_path)
    if (
        not isinstance(canonical, dict)
        or canonical.get("schema") != "kazstem-git-source-materialization-v2"
        or canonical.get("result") != "pass"
        or canonical.get("payload_tree") != expected_tree
    ):
        raise BootstrapError("canonical source materialization receipt differs")
    if (
        not isinstance(execution, dict)
        or execution.get("schema")
        != "kazstem-git-source-materialization-execution-v2"
        or execution.get("result") != "pass"
        or execution.get("source") != canonical.get("source")
        or execution.get("canonical_receipt") != _file_record(canonical_path)
        or execution.get("freshness")
        != {
            "root_absent_before_execution": True,
            "root_created_by_process": True,
            "payload_created_by_process": True,
        }
    ):
        raise BootstrapError("per-root source materialization receipt differs")
    root_identity = execution.get("root_identity")
    payload_identity = execution.get("payload_identity")
    root_stat = root.stat()
    payload_stat = source.stat()
    if not isinstance(root_identity, dict) or not isinstance(payload_identity, dict):
        raise BootstrapError("source receipt has no bound root identities")
    if (
        root_identity.get("st_dev") != root_stat.st_dev
        or root_identity.get("st_ino") != root_stat.st_ino
        or root_identity.get("st_ctime_ns") != root_stat.st_ctime_ns
        or payload_identity.get("st_dev") != payload_stat.st_dev
        or payload_identity.get("st_ino") != payload_stat.st_ino
        or payload_identity.get("st_ctime_ns") != payload_stat.st_ctime_ns
        or payload_identity.get("tree") != expected_tree
    ):
        raise BootstrapError("source materialization receipt does not bind live roots")
    source_identity = canonical.get("source")
    if not isinstance(source_identity, dict):
        raise BootstrapError("source receipt has no Git identity")
    return {
        "source": source_identity,
        "canonical_receipt": _file_record(canonical_path),
        "fresh_root_and_payload_objects_verified": True,
    }


def attestation() -> dict[str, Any]:
    if _ATTESTATION is None:
        raise BootstrapError("release tool did not enter through the source bootstrap")
    return json.loads(json.dumps(_ATTESTATION))


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-root", required=True, type=Path)
    parser.add_argument("--release-identity", required=True, type=Path)
    parser.add_argument("--materialization-root", required=True, type=Path)
    parser.add_argument("--materialization-receipt", required=True, type=Path)
    parser.add_argument(
        "--materialization-execution-receipt", required=True, type=Path
    )
    parser.add_argument("--cache-root", required=True, type=Path)
    parser.add_argument("--expected-tree-entries", required=True, type=int)
    parser.add_argument("--expected-tree-bytes", required=True, type=int)
    parser.add_argument("--expected-tree-sha256", required=True)
    parser.add_argument("--entrypoint", required=True)
    parser.add_argument("entrypoint_arguments", nargs=argparse.REMAINDER)
    value = parser.parse_args()
    if not value.entrypoint_arguments or value.entrypoint_arguments[0] != "--":
        parser.error("entrypoint arguments must follow an exact -- separator")
    value.entrypoint_arguments = value.entrypoint_arguments[1:]
    return value


def main() -> int:
    global _ATTESTATION
    if not __debug__:
        raise BootstrapError("release bootstrap must not run with Python -O")
    args = _arguments()
    source = args.source_root.resolve(strict=True)
    materialization_root = args.materialization_root.resolve(strict=True)
    canonical_receipt = args.materialization_receipt.resolve(strict=True)
    execution_receipt = args.materialization_execution_receipt.resolve(strict=True)
    cache_input = args.cache_root.absolute()
    cache = cache_input.parent.resolve(strict=True) / cache_input.name
    expected_tree = {
        "entries": args.expected_tree_entries,
        "regular_file_bytes": args.expected_tree_bytes,
        "sha256": args.expected_tree_sha256,
    }
    if (
        args.expected_tree_entries <= 0
        or args.expected_tree_bytes <= 0
        or len(args.expected_tree_sha256) != 64
        or any(character not in "0123456789abcdef" for character in args.expected_tree_sha256)
    ):
        raise BootstrapError("expected source tree record is invalid")
    if cache.exists() or cache.is_symlink():
        raise BootstrapError("isolated pycache root must be absent before execution")
    if cache == source or cache in source.parents or source in cache.parents:
        raise BootstrapError("isolated pycache root aliases/nests protected source")
    entrypoint_name = _portable_path(args.entrypoint)
    entrypoint = (source / entrypoint_name).resolve(strict=True)
    try:
        entrypoint.relative_to(source)
    except ValueError as exc:
        raise BootstrapError("release entrypoint escapes materialized source") from exc
    bootstrap = Path(__file__).resolve(strict=True)
    expected_bootstrap = source / "packaging/windows/release_bootstrap.py"
    if bootstrap != expected_bootstrap or entrypoint == bootstrap:
        raise BootstrapError("top-level bootstrap/entrypoint location is not exact")
    original = sys.orig_argv[1:]
    if (
        len(original) < 5
        or original[:3] != ["-I", "-B", "-X"]
        or not original[3].startswith("pycache_prefix=")
        or Path(original[4]).resolve(strict=True) != bootstrap
        or original[5:] != sys.argv[1:]
    ):
        raise BootstrapError("interpreter flags or bootstrap invocation are not exact")
    if sys.flags.isolated != 1 or not sys.dont_write_bytecode:
        raise BootstrapError("release bootstrap requires exact -I -B flags")
    configured_prefix = Path(sys.pycache_prefix or "").resolve(strict=False)
    original_prefix = Path(original[3].split("=", 1)[1]).resolve(strict=False)
    if configured_prefix != cache or original_prefix != cache:
        raise BootstrapError("release bootstrap pycache_prefix differs from cache root")

    # This scan is deliberately before any adjacent/project import.
    reject_adjacent_bytecode(source)
    before = tree_record(source)
    if before != expected_tree:
        raise BootstrapError(
            f"materialized source inventory differs: expected={expected_tree}, observed={before}"
        )
    materialization = _require_materialization_receipts(
        root=materialization_root,
        source=source,
        canonical_path=canonical_receipt,
        execution_path=execution_receipt,
        expected_tree=expected_tree,
    )
    identity_path = args.release_identity.resolve(strict=True)
    if (
        identity_path == source
        or identity_path in source.parents
        or source in identity_path.parents
        or identity_path == cache
        or identity_path in cache.parents
        or cache in identity_path.parents
    ):
        raise BootstrapError("release identity aliases/nests source or pycache root")
    identity = _read_json(identity_path)
    if not isinstance(identity, dict) or identity.get("schema") != "kazstem-windows-release-identity-v1":
        raise BootstrapError("release identity schema differs at source bootstrap")
    inputs = identity.get("inputs")
    source_identity = {
        "commit": identity.get("source_commit"),
        "tree": identity.get("source_tree"),
        "origin": identity.get("source_origin"),
        "ref": identity.get("source_ref"),
    }
    if (
        not isinstance(inputs, dict)
        or inputs.get("source_payload_tree") != expected_tree
        or inputs.get("source_receipt") != _file_record(canonical_receipt)
        or source_identity != materialization["source"]
    ):
        raise BootstrapError("release identity differs from materialized source")
    support_records = inputs.get("release_support_files")
    if not isinstance(support_records, list) or not support_records:
        raise BootstrapError("release identity has no support-file bundle")
    support: dict[str, Any] = {}
    for record in support_records:
        if not isinstance(record, dict) or set(record) != {"path", "file"}:
            raise BootstrapError("release support record fields differ")
        relative = _portable_path(record["path"])
        if relative in support:
            raise BootstrapError(f"duplicate release support record: {relative}")
        support[relative] = record["file"]
        if record["file"] != _file_record(source / relative):
            raise BootstrapError(f"release support identity differs: {relative}")
    for required in (
        "packaging/windows/release_bootstrap.py",
        "packaging/windows/release_common.py",
    ):
        if required not in support:
            raise BootstrapError(f"release support identity is missing: {required}")
    cache.mkdir(mode=0o700)
    if any(cache.iterdir()):
        raise BootstrapError("fresh isolated pycache root is not empty")
    _ATTESTATION = {
        "schema": SCHEMA,
        "source_root": "<MATERIALIZED-SOURCE>",
        "source_tree": expected_tree,
        "release_identity": "<RELEASE-IDENTITY>",
        "release_identity_verified": True,
        "materialization_root": "<SOURCE-MATERIALIZATION-ROOT>",
        "materialization_receipt": {
            "path": "<SOURCE-MATERIALIZATION-RECEIPT>",
            "file": materialization["canonical_receipt"],
        },
        "materialization_execution_receipt":
        "<SOURCE-MATERIALIZATION-EXECUTION-RECEIPT>",
        "materialization_source": materialization["source"],
        "fresh_materialization_objects_verified": materialization[
            "fresh_root_and_payload_objects_verified"
        ],
        "entrypoint": entrypoint_name,
        "cache_root": "<FRESH-PYCACHE-ROOT>",
        "cache_absent_before_execution": True,
        "cache_outside_source": True,
        "interpreter_flags": [
            "-I",
            "-B",
            "-X",
            "pycache_prefix=<FRESH-PYCACHE-ROOT>",
        ],
        "adjacent_bytecode_rejected_before_local_imports": True,
        "complete_source_inventory_verified_before_local_imports": True,
    }
    # Make the already-verified top-level source available under its support
    # module name; importing a second adjacent copy is unnecessary.
    sys.modules["release_bootstrap"] = sys.modules[__name__]
    sys.path.insert(0, os.fspath(source / "packaging/windows"))
    sys.path.insert(1, os.fspath(source))
    previous_argv = sys.argv
    sys.argv = [os.fspath(entrypoint), *args.entrypoint_arguments]
    pending: BaseException | None = None
    try:
        payload = entrypoint.read_bytes()
        code = compile(payload, os.fspath(entrypoint), "exec", dont_inherit=True, optimize=0)
        namespace = {
            "__name__": "__main__",
            "__file__": os.fspath(entrypoint),
            "__cached__": None,
            "__package__": None,
            "__spec__": None,
        }
        exec(code, namespace, namespace)
    except BaseException as exc:  # preserve target exit after post-execution checks
        pending = exc
    finally:
        sys.argv = previous_argv
    reject_adjacent_bytecode(source)
    after = tree_record(source)
    if after != before:
        raise BootstrapError("protected materialized source changed during release tool execution")
    if not cache.is_dir() or cache.is_symlink() or any(cache.iterdir()):
        raise BootstrapError("isolated pycache root was removed, replaced, or populated")
    if pending is not None:
        raise pending
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (BootstrapError, OSError, ValueError) as exc:
        raise SystemExit(f"error: {exc}") from exc
