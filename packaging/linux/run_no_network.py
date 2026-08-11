#!/usr/bin/env python3
"""Apply the exact Linux no-network seccomp policy, then exec a workload."""

from __future__ import annotations

import argparse
import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
from typing import Any


SCHEMA = "kazstem-linux-seccomp-network-boundary-receipt-v1"
SCMP_ACT_ALLOW = 0x7FFF0000
SCMP_ACT_ERRNO = 0x00050000
SCMP_CMP_MASKED_EQ = 7
PR_SET_NO_NEW_PRIVS = 38
CLONE_UNTRACED = 0x00800000
MAX_LIBRARY_BYTES = 64 * 1024**2


class BoundaryError(RuntimeError):
    """The no-network boundary could not be established exactly."""


class ScmpArgCmp(ctypes.Structure):
    _fields_ = [
        ("arg", ctypes.c_uint),
        ("op", ctypes.c_uint),
        ("datum_a", ctypes.c_uint64),
        ("datum_b", ctypes.c_uint64),
    ]


def _record(path: Path) -> dict[str, Any]:
    metadata = path.stat()
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
        raise BoundaryError("boundary input is not a regular non-symlink file")
    if metadata.st_size <= 0 or metadata.st_size > MAX_LIBRARY_BYTES:
        raise BoundaryError("boundary input size exceeds policy")
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return {"bytes": metadata.st_size, "sha256": digest.hexdigest()}


def _json_bytes(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _load_policy(args: argparse.Namespace) -> tuple[Any, dict[str, Any]]:
    library_path = args.library
    observed_library = _record(library_path)
    expected_library = {"bytes": args.library_bytes, "sha256": args.library_sha256}
    if observed_library != expected_library:
        raise BoundaryError("loaded libseccomp bytes differ from the bound identity")
    wrapper_path = Path(__file__).resolve(strict=True)
    observed_wrapper = _record(wrapper_path)
    expected_wrapper = {"bytes": args.wrapper_bytes, "sha256": args.wrapper_sha256}
    if observed_wrapper != expected_wrapper:
        raise BoundaryError("network-boundary wrapper bytes differ from identity")
    library = ctypes.CDLL(str(library_path), use_errno=True)
    library.seccomp_init.argtypes = [ctypes.c_uint32]
    library.seccomp_init.restype = ctypes.c_void_p
    library.seccomp_release.argtypes = [ctypes.c_void_p]
    library.seccomp_release.restype = None
    library.seccomp_load.argtypes = [ctypes.c_void_p]
    library.seccomp_load.restype = ctypes.c_int
    library.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    library.seccomp_syscall_resolve_name.restype = ctypes.c_int
    library.seccomp_rule_add.argtypes = [
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_int,
        ctypes.c_uint,
    ]
    library.seccomp_rule_add.restype = ctypes.c_int
    library.seccomp_rule_add_array.argtypes = [
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_int,
        ctypes.c_uint,
        ctypes.POINTER(ScmpArgCmp),
    ]
    library.seccomp_rule_add_array.restype = ctypes.c_int
    return library, {
        "library": observed_library,
        "wrapper": observed_wrapper,
    }


def _check(status: int, label: str) -> None:
    if status != 0:
        raise BoundaryError(f"libseccomp {label} failed: status={status}")


def apply_and_exec(args: argparse.Namespace) -> None:
    if not args.command:
        raise BoundaryError("network boundary lacks an exec command")
    denied = sorted(set(args.deny_syscall))
    if denied != args.deny_syscall or not denied:
        raise BoundaryError("denied syscall list must be sorted and unique")
    library, identities = _load_policy(args)
    context = library.seccomp_init(SCMP_ACT_ALLOW)
    if not context:
        raise BoundaryError("libseccomp could not allocate a filter context")
    resolved: list[str] = []
    unavailable: list[str] = []
    try:
        for name in denied:
            number = library.seccomp_syscall_resolve_name(name.encode("ascii"))
            if number < 0:
                unavailable.append(name)
                continue
            _check(
                library.seccomp_rule_add(
                    context, SCMP_ACT_ERRNO | errno.EPERM, number, 0
                ),
                f"rule-add({name})",
            )
            resolved.append(name)
        clone_number = library.seccomp_syscall_resolve_name(b"clone")
        if clone_number < 0:
            raise BoundaryError("clone syscall cannot be resolved for CLONE_UNTRACED rule")
        comparison = ScmpArgCmp(
            arg=0,
            op=SCMP_CMP_MASKED_EQ,
            datum_a=CLONE_UNTRACED,
            datum_b=CLONE_UNTRACED,
        )
        _check(
            library.seccomp_rule_add_array(
                context,
                SCMP_ACT_ERRNO | errno.EPERM,
                clone_number,
                1,
                ctypes.byref(comparison),
            ),
            "masked clone(CLONE_UNTRACED) rule",
        )
        clone3_number = library.seccomp_syscall_resolve_name(b"clone3")
        clone3_resolved = clone3_number >= 0
        if clone3_resolved:
            _check(
                library.seccomp_rule_add(
                    context, SCMP_ACT_ERRNO | errno.ENOSYS, clone3_number, 0
                ),
                "clone3 compatibility rule",
            )
        libc = ctypes.CDLL(None, use_errno=True)
        if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
            raise BoundaryError(
                f"PR_SET_NO_NEW_PRIVS failed: errno={ctypes.get_errno()}"
            )
        _check(library.seccomp_load(context), "filter load")
    finally:
        library.seccomp_release(context)
    receipt = {
        "schema": SCHEMA,
        "pass": True,
        "default_action": "allow",
        "deny_action": "errno-EPERM",
        "no_new_privs": True,
        "clone_untraced_mask": CLONE_UNTRACED,
        "clone_untraced_denied": True,
        "clone3_action": "errno-ENOSYS" if clone3_resolved else "unavailable",
        "denied_syscalls": denied,
        "resolved_syscalls": resolved,
        "unavailable_syscalls": unavailable,
        **identities,
    }
    receipt_path = args.receipt_fd
    with receipt_path.open("wb", buffering=0) as output:
        output.write(_json_bytes(receipt))
    environment = {
        key: value
        for key, value in os.environ.items()
        if key != "PYTHONPATH" and not key.startswith("LD_")
    }
    os.execvpe(args.command[0], args.command, environment)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--library", required=True, type=Path)
    parser.add_argument("--library-bytes", required=True, type=int)
    parser.add_argument("--library-sha256", required=True)
    parser.add_argument("--wrapper-bytes", required=True, type=int)
    parser.add_argument("--wrapper-sha256", required=True)
    parser.add_argument("--receipt-fd", required=True, type=Path)
    parser.add_argument("--deny-syscall", action="append", default=[])
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if args.command and args.command[0] == "--":
        args.command = args.command[1:]
    apply_and_exec(args)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (BoundaryError, OSError, UnicodeError, ValueError) as exc:
        raise SystemExit(f"error: {exc}") from exc
