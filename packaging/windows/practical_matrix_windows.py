#!/usr/bin/env python3
"""Fresh-extract Windows behavior, integrity, cleanup, and performance gate."""

from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes
import hashlib
import json
import os
from pathlib import Path
import platform
import random
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from typing import Any
from xml.etree import ElementTree

from release_common import (
    ReleaseError,
    ZipOutputContract,
    archive_limits,
    canonical_hash,
    copy_tree_exact,
    evidence_envelope,
    FORBIDDEN_LOADER_ENVIRONMENT,
    GLIBC_TUNABLES_VARIABLE,
    identity_sha256,
    json_bytes,
    load_identity,
    require_release_bootstrap,
    file_record,
    pe_identity,
    read_json,
    safe_extract_zip,
    sha256_file,
    verify_generator_runtime,
    verify_artifact,
    WINDOWS_BEHAVIOR_EQUIVALENCE_CASES,
    forbidden_loader_environment_name,
)


CREATE_NO_WINDOW = 0x08000000
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
TH32CS_SNAPPROCESS = 0x00000002
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
def trusted_windows_loader_path() -> str:
    """Return only kernel-resolved System32 and Windows directories."""

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetSystemDirectoryW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint]
    kernel32.GetSystemDirectoryW.restype = ctypes.c_uint
    kernel32.GetWindowsDirectoryW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint]
    kernel32.GetWindowsDirectoryW.restype = ctypes.c_uint

    def query(function: Any, label: str) -> str:
        buffer = ctypes.create_unicode_buffer(32768)
        length = function(buffer, len(buffer))
        if not length or length >= len(buffer):
            raise ReleaseError(
                f"cannot resolve trusted {label} directory: {ctypes.get_last_error()}"
            )
        return buffer.value

    return os.pathsep.join(
        [
            query(kernel32.GetSystemDirectoryW, "System32"),
            query(kernel32.GetWindowsDirectoryW, "Windows"),
        ]
    )


class PROCESS_MEMORY_COUNTERS_EX(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("PageFaultCount", wintypes.DWORD),
        ("PeakWorkingSetSize", ctypes.c_size_t),
        ("WorkingSetSize", ctypes.c_size_t),
        ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
        ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
        ("PagefileUsage", ctypes.c_size_t),
        ("PeakPagefileUsage", ctypes.c_size_t),
        ("PrivateUsage", ctypes.c_size_t),
    ]


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.c_size_t),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", wintypes.LONG),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", wintypes.WCHAR * 260),
    ]


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def jsonl_rows(value: bytes) -> list[dict[str, Any]]:
    return [json.loads(line) for line in value.decode("utf-8").splitlines() if line]


def reconstruct_jsonl(value: bytes) -> str:
    return "".join(str(row["text"]) for row in jsonl_rows(value) if row.get("consumes_input") is True)


def tree_content_fingerprint(root: Path) -> str:
    records: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            raise AssertionError(f"unexpected symlink: {relative}")
        if path.is_dir():
            records.append({"path": relative, "kind": "directory"})
        elif path.is_file():
            records.append({"path": relative, "kind": "file", "bytes": path.stat().st_size, "sha256": sha256_file(path)})
        else:
            raise AssertionError(f"special bundle entry: {relative}")
    return canonical_hash(records)


def windows_memory(pid: int) -> tuple[int, int] | None:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    psapi = ctypes.WinDLL("psapi", use_last_error=True)
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    psapi.GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD]
    psapi.GetProcessMemoryInfo.restype = wintypes.BOOL
    handle = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if not handle:
        return None
    try:
        counters = PROCESS_MEMORY_COUNTERS_EX()
        counters.cb = ctypes.sizeof(counters)
        if not psapi.GetProcessMemoryInfo(handle, ctypes.byref(counters), counters.cb):
            return None
        return int(counters.WorkingSetSize), int(counters.PeakWorkingSetSize)
    finally:
        kernel32.CloseHandle(handle)


def windows_process_tree(pid: int) -> set[int]:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    kernel32.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
    kernel32.Process32FirstW.restype = wintypes.BOOL
    kernel32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
    kernel32.Process32NextW.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snapshot == INVALID_HANDLE_VALUE:
        raise AssertionError(f"CreateToolhelp32Snapshot failed: {ctypes.get_last_error()}")
    parents: dict[int, int] = {}
    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(entry)
        if kernel32.Process32FirstW(snapshot, ctypes.byref(entry)):
            while True:
                parents[int(entry.th32ProcessID)] = int(entry.th32ParentProcessID)
                if not kernel32.Process32NextW(snapshot, ctypes.byref(entry)):
                    break
    finally:
        kernel32.CloseHandle(snapshot)
    reached = {pid}
    while True:
        added = {child for child, parent in parents.items() if parent in reached}
        if added <= reached:
            return reached
        reached.update(added)


def terminate_tree(pid: int) -> None:
    subprocess.run(
        ["taskkill.exe", "/PID", str(pid), "/T", "/F"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
        creationflags=CREATE_NO_WINDOW,
    )


class Matrix:
    def __init__(self, identity_path: Path, archive: Path | None, candidate_root: Path | None, wheel: Path, bootstrap_python: Path) -> None:
        if sys.platform != "win32" or platform.machine().casefold() not in {"amd64", "x86_64"}:
            raise ReleaseError("the practical matrix requires native 64-bit Windows")
        ambient_loader_overrides = sorted(
            name
            for name in os.environ
            if forbidden_loader_environment_name(name)
        )
        if ambient_loader_overrides:
            raise ReleaseError(
                "the release matrix process started with ambient loader overrides: "
                + ", ".join(ambient_loader_overrides)
            )
        self.identity_path = identity_path.resolve(strict=True)
        self.identity = load_identity(self.identity_path)
        self.identity_hash = identity_sha256(self.identity_path)
        self.archive = archive.resolve(strict=True) if archive is not None else None
        self.wheel = wheel.resolve(strict=True)
        self.python = bootstrap_python.resolve(strict=True)
        verify_artifact(self.wheel, self.identity["artifacts"]["wheel"], label="practical-matrix wheel")
        if (
            not Path(sys.executable).resolve(strict=True).samefile(self.python)
            or
            pe_identity(self.python) != self.identity["inputs"]["bootstrap_python"]
            or platform.python_version() != self.identity["platform"]["python"]
        ):
            raise ReleaseError("practical-matrix Python differs from the bound AMD64 bootstrap")
        self.temporary = tempfile.TemporaryDirectory(prefix="kazstem-win-matrix-")
        self.temp = Path(self.temporary.name)
        if self.archive is not None:
            verify_artifact(
                self.archive,
                self.identity["artifacts"]["ready_run"],
                label="practical-matrix ready-run",
            )
            self.root = safe_extract_zip(
                self.archive,
                self.temp / "fresh-extract",
                limits=archive_limits(self.identity, "ready_run"),
                contract=ZipOutputContract(
                    self.identity["source_date_epoch"],
                    (".exe", ".dll", ".pyd"),
                ),
            )
        else:
            if candidate_root is None:
                raise ReleaseError("either an archive or candidate root is required")
            self.root = self.temp / "fresh-candidate"
            copy_tree_exact(candidate_root.resolve(strict=True), self.root)
        self.executable = self.root / "kazstem.exe"
        safe_path = trusted_windows_loader_path()
        self.environment = {
            key: value
            for key, value in os.environ.items()
            if not key.upper().startswith("QAZMORPH_")
            and not key.upper().endswith("_PROXY")
            and key.upper() not in {
                "CG3_DEFAULT",
                "CG3_OVERRIDE",
                "PYTHONPATH",
                "PYTHONHOME",
                "PATH",
            }
            and not forbidden_loader_environment_name(key)
        }
        self.environment.update(
            {
                "PATH": safe_path,
                "HOME": str(self.temp / "offline-home"),
                "USERPROFILE": str(self.temp / "offline-home"),
                "HTTP_PROXY": "http://127.0.0.1:9",
                "HTTPS_PROXY": "http://127.0.0.1:9",
                "ALL_PROXY": "http://127.0.0.1:9",
                "NO_PROXY": "",
                "LC_ALL": "C",
                "LANG": "C",
                "TZ": "UTC",
            }
        )
        (self.temp / "offline-home").mkdir()
        self.results: list[dict[str, Any]] = []
        self.profiles: dict[str, Any] = {}
        self.before = tree_content_fingerprint(self.root)

    def close(self) -> None:
        self.temporary.cleanup()

    def run(
        self,
        name: str,
        command: list[str],
        *,
        input_bytes: bytes = b"",
        expected: int | set[int] | None = 0,
        cwd: Path | None = None,
        environment: dict[str, str] | None = None,
        timeout: float = 90.0,
        capture_limit: int = 256 * 1024 * 1024,
    ) -> subprocess.CompletedProcess[bytes]:
        started = time.perf_counter()
        process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=cwd or self.temp,
            env=environment or self.environment,
            creationflags=CREATE_NO_WINDOW,
        )
        try:
            stdout, stderr = process.communicate(input_bytes, timeout=timeout)
        except subprocess.TimeoutExpired:
            terminate_tree(process.pid)
            process.wait(timeout=10)
            raise AssertionError(f"{name}: timed out after {timeout}s")
        elapsed = time.perf_counter() - started
        if len(stdout) > capture_limit or len(stderr) > 16 * 1024 * 1024:
            raise AssertionError(f"{name}: captured output exceeded matrix cap")
        expected_set = ({expected} if isinstance(expected, int) else expected)
        accepted = process.returncode != 0 if expected_set is None else process.returncode in expected_set
        if not accepted:
            raise AssertionError(
                f"{name}: rc={process.returncode}, expected={'nonzero' if expected_set is None else sorted(expected_set)}, "
                f"stderr={stderr.decode('utf-8', 'replace')[:2000]!r}"
            )
        self.results.append(
            {
                "name": name,
                "returncode": process.returncode,
                "seconds": round(elapsed, 6),
                "stdin_bytes": len(input_bytes),
                "stdout_bytes": len(stdout),
                "stdout_sha256": sha256_bytes(stdout),
                "stderr_bytes": len(stderr),
                "stderr_sha256": sha256_bytes(stderr),
            }
        )
        return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)

    def binary(self, name: str, flags: list[str], *, text: str = "", expected: int | set[int] | None = 0, timeout: float = 90.0) -> subprocess.CompletedProcess[bytes]:
        return self.run(name, [str(self.executable), *flags], input_bytes=text.encode("utf-8"), expected=expected, timeout=timeout)

    def profile_file(self, name: str, command: list[str], *, timeout: float) -> tuple[subprocess.CompletedProcess[bytes], int | None, int | None, float]:
        started = time.perf_counter()
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=self.temp,
            env=self.environment,
            creationflags=CREATE_NO_WINDOW,
        )
        peak = 0
        tree_peak = 0
        try:
            while process.poll() is None:
                process_ids = windows_process_tree(process.pid)
                current_total = 0
                for process_id in process_ids:
                    observed = windows_memory(process_id)
                    if observed is not None:
                        current_total += observed[0]
                        if process_id == process.pid:
                            peak = max(peak, observed[1])
                tree_peak = max(tree_peak, current_total)
                time.sleep(0.01)
                if time.perf_counter() - started > timeout:
                    terminate_tree(process.pid)
                    raise AssertionError(f"{name}: timed out")
            stdout, stderr = process.communicate(timeout=10)
        finally:
            if process.poll() is None:
                terminate_tree(process.pid)
                process.wait(timeout=10)
        elapsed = time.perf_counter() - started
        if process.returncode:
            raise AssertionError(f"{name}: rc={process.returncode}: {stderr.decode('utf-8', 'replace')[:2000]}")
        self.results.append(
            {
                "name": name,
                "returncode": process.returncode,
                "seconds": round(elapsed, 6),
                "stdin_bytes": 0,
                "stdout_bytes": len(stdout),
                "stdout_sha256": sha256_bytes(stdout),
                "stderr_bytes": len(stderr),
                "stderr_sha256": sha256_bytes(stderr),
            }
        )
        return (
            subprocess.CompletedProcess(command, process.returncode, stdout, stderr),
            (peak or None),
            (tree_peak or None),
            elapsed,
        )

    def make_read_only(self) -> None:
        for selected in (
            self.root / self.identity["ready_run"]["resource_destination"],
            self.root / self.identity["ready_run"]["runtime_parent"],
        ):
            for path in selected.rglob("*"):
                if path.is_file():
                    os.chmod(path, 0o444)

    def dll_denial(self, runtime: Path) -> dict[str, Any]:
        manifest = read_json(runtime / "manifest.json")
        closure = manifest["dependency_closure"]["files"]
        commands = manifest["commands"]
        roots = {value["path"]: value for value in commands.values()}

        def product_invocation(root: str) -> tuple[list[str], bytes]:
            lowered = root.casefold()
            if lowered.endswith("cg-proc.exe"):
                return [str(self.executable), "-d", "-c", "--format", "jsonl"], "балалар мектепке барды.\n".encode("utf-8")
            if lowered.endswith("hfst-optimized-lookup.exe"):
                return [str(self.executable), "-c", "--format", "jsonl"], "суперқазақшалар\n".encode("utf-8")
            return [str(self.executable), "-c", "--format", "jsonl"], "балалар\n".encode("utf-8")

        def descendants(root: str) -> set[str]:
            reached: set[str] = set()
            queue = [root]
            while queue:
                value = queue.pop(0)
                if value in reached:
                    continue
                reached.add(value)
                queue.extend(closure[value]["bundled_dependencies"])
            return reached

        reaches = {root: descendants(root) for root in roots}
        hostile = self.temp / "hostile-dll-path"
        hostile.mkdir()
        hostile_cwd = self.temp / "hostile-dll-cwd"
        hostile_cwd.mkdir()
        environment = dict(self.environment)
        environment["PATH"] = str(hostile) + os.pathsep + environment["PATH"]
        checks: list[dict[str, Any]] = []
        dlls = sorted(relative for relative in closure if relative.casefold().endswith(".dll"))
        for index, relative in enumerate(dlls):
            applicable = next((root for root in sorted(roots) if relative in reaches[root]), None)
            if applicable is None:
                raise AssertionError(f"unreachable DLL in closure: {relative}")
            original = runtime / relative
            backup = original.with_name(original.name + ".kazstem-missing")
            path_copy = hostile / original.name
            cwd_copy = hostile_cwd / original.name
            if backup.exists() or path_copy.exists() or cwd_copy.exists():
                raise AssertionError("DLL denial scratch collision")
            os.chmod(original, 0o666)
            original.rename(backup)
            try:
                product_command, product_input = product_invocation(applicable)
                missing = self.run(
                    f"dll-missing-{index:02d}",
                    product_command,
                    input_bytes=product_input,
                    expected=None,
                    environment=self.environment,
                    timeout=40,
                )
                shutil.copyfile(backup, path_copy)
                injected = self.run(
                    f"dll-path-denied-{index:02d}",
                    product_command,
                    input_bytes=product_input,
                    expected=None,
                    environment=environment,
                    timeout=40,
                )
                shutil.copyfile(backup, cwd_copy)
                hostile_cwd_result = self.run(
                    f"dll-cwd-denied-{index:02d}",
                    product_command,
                    input_bytes=product_input,
                    expected=None,
                    environment=self.environment,
                    cwd=hostile_cwd,
                    timeout=40,
                )
                if any(
                    b"Traceback" in result.stderr
                    for result in (missing, injected, hostile_cwd_result)
                ):
                    raise AssertionError(f"DLL denial leaked a traceback: {relative}")
                if any(
                    result.returncode == 0
                    for result in (missing, injected, hostile_cwd_result)
                ):
                    raise AssertionError(
                        f"missing adjacent DLL was accepted through a fallback path: {relative}"
                    )
                checks.append(
                    {
                        "dll": relative,
                        "command": applicable,
                        "missing_returncode": missing.returncode,
                        "path_injection_returncode": injected.returncode,
                        "cwd_injection_returncode": hostile_cwd_result.returncode,
                    }
                )
            finally:
                path_copy.unlink(missing_ok=True)
                cwd_copy.unlink(missing_ok=True)
                backup.rename(original)
                os.chmod(original, 0o444)
        normal_successes: list[dict[str, Any]] = []
        for index, root in enumerate(sorted(roots)):
            command, input_bytes = product_invocation(root)
            result = self.run(
                f"dll-adjacent-success-{index:02d}",
                command,
                input_bytes=input_bytes,
                timeout=40,
            )
            normal_successes.append(
                {
                    "command": root,
                    "returncode": result.returncode,
                }
            )
        return {
            "result": "pass",
            "normal_adjacent_closure_success": bool(normal_successes)
            and all(value["returncode"] == 0 for value in normal_successes),
            "normal_adjacent_commands": normal_successes,
            "dlls": checks,
        }

    def helper_path_denial(self, runtime: Path) -> dict[str, Any]:
        helper = runtime / "usr/bin/hfst-proc.exe"
        backup = helper.with_name("hfst-proc.exe.kazstem-renamed")
        hostile = self.temp / "hostile-helper-path"
        hostile.mkdir()
        copied = hostile / "hfst-proc.exe"
        hostile_cwd = self.temp / "hostile-helper-cwd"
        hostile_cwd.mkdir()
        cwd_copied = hostile_cwd / "hfst-proc.exe"
        environment = dict(self.environment)
        environment["PATH"] = str(hostile) + os.pathsep + environment["PATH"]
        os.chmod(helper, 0o666)
        helper.rename(backup)
        try:
            shutil.copyfile(backup, copied)
            failed = self.run(
                "helper-path-denied",
                [str(self.executable), "-c", "--format", "jsonl"],
                input_bytes="балалар\n".encode("utf-8"),
                expected=None,
                environment=environment,
                timeout=30,
            )
            shutil.copyfile(backup, cwd_copied)
            cwd_failed = self.run(
                "helper-cwd-denied",
                [str(self.executable), "-c", "--format", "jsonl"],
                input_bytes="балалар\n".encode("utf-8"),
                expected=None,
                environment=self.environment,
                cwd=hostile_cwd,
                timeout=30,
            )
            if b"Traceback" in failed.stderr:
                raise AssertionError("renamed helper failure leaked a traceback")
            if b"Traceback" in cwd_failed.stderr:
                raise AssertionError("hostile-cwd helper failure leaked a traceback")
            if failed.returncode == 0 or cwd_failed.returncode == 0:
                raise AssertionError("renamed helper was accepted through PATH or cwd")
        finally:
            copied.unlink(missing_ok=True)
            cwd_copied.unlink(missing_ok=True)
            backup.rename(helper)
            os.chmod(helper, 0o444)
        normal = self.run(
            "helper-adjacent-success",
            [str(self.executable), "-c", "--format", "jsonl"],
            input_bytes="балалар\n".encode("utf-8"),
            timeout=30,
        )
        return {
            "result": "pass",
            "helper": "usr/bin/hfst-proc.exe",
            "path_substitution_used": False,
            "cwd_substitution_used": False,
            "path_denial_returncode": failed.returncode,
            "cwd_denial_returncode": cwd_failed.returncode,
            "normal_adjacent_returncode": normal.returncode,
        }

    def no_lingering_processes(self) -> list[dict[str, Any]]:
        script = (
            "$ErrorActionPreference='Stop'; "
            "$root=$env:KAZSTEM_AUDIT_ROOT; "
            "$v=Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -and $_.ExecutablePath.StartsWith($root,[System.StringComparison]::OrdinalIgnoreCase) } | "
            "Select-Object ProcessId,ParentProcessId,Name,ExecutablePath; "
            "$v | ConvertTo-Json -Compress"
        )
        env = dict(self.environment)
        env["KAZSTEM_AUDIT_ROOT"] = str(self.root)
        completed = subprocess.run(
            ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            creationflags=CREATE_NO_WINDOW,
            timeout=30,
            check=False,
        )
        if completed.returncode:
            raise AssertionError(f"CIM process audit failed: {completed.stderr.decode('utf-8', 'replace')}")
        text = completed.stdout.decode("utf-8-sig").strip()
        if not text:
            return []
        value = json.loads(text)
        rows = value if isinstance(value, list) else [value]
        return [
            {"pid": row["ProcessId"], "parent_pid": row["ParentProcessId"], "name": row["Name"]}
            for row in rows
        ]

    def timeout_reap(self, input_path: Path) -> dict[str, Any]:
        output_path = self.temp / "timeout-reap-output.jsonl"
        process = subprocess.Popen(
            [
                str(self.executable),
                "-c",
                "--format",
                "jsonl",
                str(input_path),
                str(output_path),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=self.temp,
            env=self.environment,
            creationflags=CREATE_NO_WINDOW,
        )
        started = time.perf_counter()
        observed: list[dict[str, Any]] = []
        while time.perf_counter() - started < 2.0 and process.poll() is None:
            observed = self.no_lingering_processes()
            if observed:
                break
            time.sleep(0.01)
        if process.poll() is not None:
            stdout, stderr = process.communicate(timeout=10)
            raise AssertionError(
                "timeout-reap workload exited before forced termination: "
                + stderr.decode("utf-8", "replace")[:1000]
            )
        if not observed:
            terminate_tree(process.pid)
            process.communicate(timeout=20)
            raise AssertionError(
                "timeout-reap gate did not observe the live bundle process tree"
            )
        terminate_tree(process.pid)
        stdout, stderr = process.communicate(timeout=20)
        deadline = time.perf_counter() + 10.0
        lingering: list[dict[str, Any]] = []
        while time.perf_counter() < deadline:
            lingering = self.no_lingering_processes()
            if not lingering:
                break
            time.sleep(0.05)
        if lingering:
            raise AssertionError(f"forced-timeout process tree remained alive: {lingering}")
        self.results.append(
            {
                "name": "timeout-process-tree-reap",
                "returncode": process.returncode,
                "seconds": round(time.perf_counter() - started, 6),
                "stdin_bytes": 0,
                "stdout_bytes": len(stdout),
                "stdout_sha256": sha256_bytes(stdout),
                "stderr_bytes": len(stderr),
                "stderr_sha256": sha256_bytes(stderr),
            }
        )
        return {
            "result": "pass",
            "root_pid": process.pid,
            "observed_bundle_processes_before_kill": len(observed),
            "returncode_after_taskkill_tree": process.returncode,
            "lingering_bundle_processes": [],
        }

    def execute(self) -> dict[str, Any]:
        assert self.executable.is_file()
        inclusion_ledger = read_json(
            self.root / "verification/MODULE-NATIVE-INCLUSION-LEDGER.json"
        )
        base_ledger = inclusion_ledger.get("base_ledger", {}) if isinstance(inclusion_ledger, dict) else {}
        required_exclusions = {
            "_hashlib", "_socket", "_ssl", "asyncio", "email", "ftplib", "http",
            "multiprocessing", "socket", "sqlite3", "tkinter", "urllib.request", "xml",
        }
        if (
            inclusion_ledger.get("schema") != "kazstem-windows-module-native-inclusion-ledger-v1"
            or base_ledger.get("result") != "pass"
            or not required_exclusions <= set(base_ledger.get("declared_exclusions", []))
            or base_ledger.get("banned_runtime_matches") != []
            or base_ledger.get("claims", {}).get("upx") is not False
            or base_ledger.get("claims", {}).get("python_optimization") != 0
        ):
            raise AssertionError("embedded network/TLS/neural/freezer exclusion ledger is incomplete")
        absence_inventory = {
            "declared_exclusions": sorted(required_exclusions),
            "banned_runtime_matches": [],
            "claims": base_ledger["claims"],
        }
        self.make_read_only()
        version = self.binary("version", ["--version"])
        assert version.stdout == f"kazstem {self.identity['release']}\n".encode("ascii")
        help_result = self.binary("help", ["--help"])
        assert b"--format" in help_result.stdout and b"--generate-all" in help_result.stdout
        for alias in self.identity["ready_run"]["aliases"]:
            result = self.run(f"alias-{alias}", [str(self.root / alias), "--version"])
            assert result.stdout == version.stdout

        text = "Қазақстан & балалар мектепке барды.\r\n"
        text_result = self.binary("format-text", ["-c", "-i", "--format", "text"], text=text)
        assert "Қазақстан" in text_result.stdout.decode("utf-8")
        json_result = self.binary("format-json", ["-c", "-i", "--format", "json"], text=text)
        json_rows = json.loads(json_result.stdout)
        assert "".join(row["text"] for row in json_rows) == text
        assert json_result.stdout.startswith(b'[{"analysis":')
        jsonl_result = self.binary("format-jsonl", ["-c", "--format", "jsonl"], text=text)
        assert reconstruct_jsonl(jsonl_result.stdout) == text
        xml_result = self.binary("format-xml", ["-c", "-i", "--format", "xml"], text=text)
        assert "".join(ElementTree.fromstring(xml_result.stdout).itertext()) == text
        conllu = self.binary("format-conllu", ["--format", "conllu"], text=text)
        lines = [line for line in conllu.stdout.decode("utf-8").splitlines() if line and not line.startswith("#")]
        assert lines and all(len(line.split("\t")) == 10 for line in lines)

        oov = self.binary("productive-oov", ["--format", "jsonl"], text="суперқазақшалар\n")
        assert any(
            analysis.get("source") == "guesser" and analysis.get("guessed") is True
            for row in jsonl_rows(oov.stdout)
            for analysis in row.get("analysis", [])
        )
        cg = self.binary("constraint-grammar", ["-d", "-c", "--format", "jsonl"], text="балалар мектепке барды.\n")
        assert {row.get("mode") for row in jsonl_rows(cg.stdout) if row.get("record_type") == "token"} == {"contextual"}

        runtime = self.root / self.identity["ready_run"]["runtime_parent"] / self.identity["inputs"]["runtime_tree"]["bundle_id"]
        generator = self.root / self.identity["ready_run"]["resource_destination"] / "kaz.autogen.hfstol"
        generated = self.run(
            "generation",
            [str(runtime / "usr/bin/hfst-optimized-lookup.exe"), "-q", "-u", "-n", "128", str(generator)],
            input_bytes="кітап<n><pl><dat>\n".encode("utf-8"),
        )
        assert "кітаптарға" in generated.stdout.decode("utf-8")
        roundtrip = self.binary("generation-roundtrip", ["-c", "--format", "json"], text="кітаптарға")
        assert any(value["lex"] == "кітап" for value in json.loads(roundtrip.stdout)[0]["analysis"])

        protected = "бір\rекі\nүш\r\nи\u0306 ^$[]{}\\/\x00соң"
        protected_result = self.binary("unicode-crlf-reserved-nul", ["-c", "--format", "jsonl"], text=protected)
        assert reconstruct_jsonl(protected_result.stdout) == protected
        xml_error = self.binary("xml-nul-controlled", ["-c", "--format", "xml"], text="a\x00b", expected=2)
        assert b"U+0000" in xml_error.stderr and b"Traceback" not in xml_error.stderr
        malformed = self.run("malformed-utf8", [str(self.executable), "-e", "utf-8"], input_bytes=b"\xff", expected=2)
        assert b"Traceback" not in malformed.stderr
        cp1251_text = "тест\r\n"
        cp1251 = self.run(
            "cp1251",
            [str(self.executable), "-c", "-e", "cp1251", "--format", "text"],
            input_bytes=cp1251_text.encode("cp1251"),
        )
        assert cp1251_text in cp1251.stdout.decode("cp1251")
        for encoding in ("base64_codec", "not-a-real-codec"):
            failure = self.binary(f"invalid-encoding-{encoding}", ["-e", encoding], expected=2)
            assert b"Traceback" not in failure.stderr

        hostile = self.temp / "hostile cwd Қазақ []^$() !"
        hostile.mkdir()
        hostile_bin = hostile / "fake PATH"
        hostile_bin.mkdir()
        hostile_environment = dict(self.environment)
        hostile_environment["PATH"] = str(hostile_bin) + os.pathsep + hostile_environment["PATH"]
        input_path = hostile / "кіріс Қазақ []^$() !.txt"
        output_path = hostile / "шығыс Қазақ []^$() !.json"
        file_text = "Қазақстан ^$[]{} мектеп\r\n"
        input_path.write_text(file_text, encoding="utf-8", newline="")
        self.run(
            "hostile-offline-file-paths",
            [str(self.executable), "-c", "--format", "json", str(input_path), str(output_path)],
            cwd=hostile,
            environment=hostile_environment,
        )
        assert "".join(row["text"] for row in json.loads(output_path.read_bytes())) == file_text

        wheel_site = self.temp / "wheel-site"
        self.run(
            "wheel-install-offline",
            [str(self.python), "-m", "pip", "install", "--no-index", "--no-deps", "--target", str(wheel_site), str(self.wheel)],
            timeout=120,
        )
        wheel_env = dict(self.environment)
        wheel_env["PYTHONPATH"] = str(wheel_site)
        wheel_env["PYTHONNOUSERSITE"] = "1"
        wheel_env["QAZMORPH_RESOURCE_DIR"] = str(self.root / self.identity["ready_run"]["resource_destination"])
        comparison_text = "Қазақстан & балалар мектепке барды.\r\n"
        frozen = self.binary("parity-frozen", ["-c", "--format", "jsonl"], text=comparison_text)
        module = self.run(
            "parity-python-module",
            [str(self.python), "-m", "qazmorph", "-c", "--format", "jsonl"],
            input_bytes=comparison_text.encode("utf-8"),
            environment=wheel_env,
        )
        api_code = (
            "from qazmorph import Analyzer\n"
            "from qazmorph.formats import format_jsonl\n"
            f"text={comparison_text!r}\n"
            "with Analyzer() as analyzer:\n"
            " print(format_jsonl(analyzer.analyze(text), copy_input=True), end='')\n"
        )
        api = self.run("parity-python-api", [str(self.python), "-c", api_code], environment=wheel_env)
        assert frozen.stdout == module.stdout == api.stdout

        provenance_code = (
            "import json\n"
            "from qazmorph import Analyzer\n"
            "with Analyzer() as analyzer:\n"
            " p=analyzer.backend.runtime_provenance()\n"
            " out={'official':p['official'],'verified':p['verified'],'non_official_reasons':p['non_official_reasons'],"
            "'resource_inventory':{k:p['resource_inventory'].get(k) for k in ('verified','integrity_seal_verified','sealed_read_only','content_rehashed','force_rehash')},"
            "'toolchain_inventory':{k:p['toolchain_inventory'].get(k) for k in ('verified','integrity_seal_verified','sealed_read_only','content_rehashed','force_rehash')},"
            "'active_runtime':p['active_runtime'],'environment':p['environment']}\n"
            " print(json.dumps(out,sort_keys=True))\n"
        )
        provenance_result = self.run("forced-rehash-provenance", [str(self.python), "-c", provenance_code], environment=wheel_env, timeout=180)
        provenance = json.loads(provenance_result.stdout)
        assert provenance["official"] is True and provenance["verified"] is True
        assert provenance["non_official_reasons"] == []
        assert provenance["resource_inventory"]["content_rehashed"] is True
        assert provenance["toolchain_inventory"]["force_rehash"] is True
        assert provenance["toolchain_inventory"]["content_rehashed"] is True
        assert provenance["active_runtime"]["origin"] == "platform-runtime-lock"
        assert provenance["active_runtime"]["bundle_id"] == self.identity["inputs"]["runtime_tree"]["bundle_id"]
        assert provenance["environment"]["PATH"] == {
            "ambient_present": True,
            "ambient_untrusted": False,
            "removed_from_helper_environment": True,
        }
        for name in FORBIDDEN_LOADER_ENVIRONMENT:
            loader_record = provenance["environment"][name]
            assert loader_record["ambient_present"] is False
            assert loader_record["removed_from_helper_environment"] is True
            assert loader_record["sha256"] is None
        assert provenance["environment"][GLIBC_TUNABLES_VARIABLE] == {
            "ambient_present": False,
            "removed_from_helper_environment": True,
            "sha256": None,
        }
        assert provenance["environment"]["loader_policy"] == {
            "schema": "qazmorph-native-helper-loader-environment-v2",
            "captured_name_policy": {
                "exact_uppercase_prefixes": ["LD_", "DYLD_"],
                "exact_names": ["GLIBC_TUNABLES"],
            },
            "ambient_records": {},
            "glibc_tunables": {
                "ambient_present": False,
                "removed_from_helper_environment": True,
                "sha256": None,
            },
            "clean_parent_startup": True,
            "all_ambient_values_removed_from_helper_environment": True,
            "linux_helper_ld_library_path": None,
        }

        hostile_provenance_environment = dict(wheel_env)
        hostile_provenance_environment["PATH"] = (
            str(self.temp / "provenance-hostile-path")
            + os.pathsep
            + hostile_provenance_environment["PATH"]
        )
        hostile_provenance = json.loads(
            self.run(
                "hostile-path-provenance",
                [str(self.python), "-c", provenance_code],
                environment=hostile_provenance_environment,
                timeout=180,
            ).stdout
        )
        assert hostile_provenance["official"] is False
        assert hostile_provenance["environment"]["PATH"] == {
            "ambient_present": True,
            "ambient_untrusted": True,
            "removed_from_helper_environment": True,
        }
        assert any(
            "ambient Windows PATH" in reason
            for reason in hostile_provenance["non_official_reasons"]
        )

        dll_result = self.dll_denial(runtime)
        helper_result = self.helper_path_denial(runtime)

        performance = self.identity["performance"]
        startup: list[float] = []
        for index in range(performance["startup_runs"]):
            self.binary(f"startup-{index:02d}", ["--version"])
            startup.append(float(self.results[-1]["seconds"]))
        self.profiles["startup"] = {
            "runs": len(startup),
            "median_seconds": round(statistics.median(startup), 6),
            "minimum_seconds": round(min(startup), 6),
            "maximum_seconds": round(max(startup), 6),
        }
        if self.profiles["startup"]["median_seconds"] > performance["startup_median_seconds_max"]:
            raise AssertionError(
                "startup median exceeded the bound release performance contract"
            )

        phrase = "Қазақстандағы балалар мектепке барып, кітаптарды оқыды.\r\n"
        workload_size = performance["large_input_characters"]
        workload = (phrase * (workload_size // len(phrase) + 1))[:workload_size]
        input_file = self.temp / "large-input.txt"
        input_file.write_text(workload, encoding="utf-8", newline="")
        workload_records: list[dict[str, Any]] = []
        for index in range(performance["large_runs"]):
            output_file = self.temp / f"large-output-{index}.jsonl"
            _, launcher_peak, tree_peak, elapsed = self.profile_file(
                f"large-deterministic-{index}",
                [str(self.executable), "-c", "--format", "jsonl", str(input_file), str(output_file)],
                timeout=performance["large_timeout_seconds"],
            )
            reconstructed = "".join(
                str(row["text"])
                for line in output_file.read_text(encoding="utf-8").splitlines()
                if (row := json.loads(line)).get("consumes_input") is True
            )
            assert reconstructed == workload
            workload_records.append(
                {
                    "run": index,
                    "input_characters": len(workload),
                    "input_utf8_bytes": len(workload.encode("utf-8")),
                    "output_bytes": output_file.stat().st_size,
                    "output_sha256": sha256_file(output_file),
                    "seconds": round(elapsed, 6),
                    "characters_per_second": round(len(workload) / elapsed, 3),
                    "launcher_peak_working_set_bytes": launcher_peak,
                    "process_tree_peak_working_set_bytes": tree_peak,
                }
            )
        if len({record["output_sha256"] for record in workload_records}) != 1:
            raise AssertionError("large-workload outputs are not deterministic")
        for record in workload_records:
            if record["characters_per_second"] < performance["minimum_characters_per_second"]:
                raise AssertionError("large-workload throughput is below the release contract")
            if (
                record["process_tree_peak_working_set_bytes"] is None
                or record["process_tree_peak_working_set_bytes"]
                > performance["maximum_peak_working_set_bytes"]
            ):
                raise AssertionError("process-tree peak working set exceeds the release contract")
        self.profiles["large_workload"] = workload_records

        timeout_input = self.temp / "timeout-reap-input.txt"
        timeout_input.write_text(workload * 20, encoding="utf-8", newline="")
        timeout_reap = self.timeout_reap(timeout_input)

        lingering = self.no_lingering_processes()
        assert lingering == [], lingering
        after = tree_content_fingerprint(self.root)
        assert self.before == after

        equivalence_results = [
            record
            for record in self.results
            if record["name"] in WINDOWS_BEHAVIOR_EQUIVALENCE_CASES
        ]
        if (
            len(equivalence_results) != len(WINDOWS_BEHAVIOR_EQUIVALENCE_CASES)
            or [record["name"] for record in equivalence_results]
            != list(WINDOWS_BEHAVIOR_EQUIVALENCE_CASES)
        ):
            raise AssertionError("functional behavior-equivalence case inventory differs")
        behavior_projection = [
            {
                key: record[key]
                for key in ("name", "returncode", "stdin_bytes", "stdout_bytes", "stdout_sha256", "stderr_bytes", "stderr_sha256")
            }
            for record in equivalence_results
        ]
        return {
            "schema": "kazstem-windows-practical-matrix-v1",
            "result": "pass",
            "release_identity_sha256": self.identity_hash,
            "root": self.root.name,
            "host": {
                "system": platform.system(),
                "release": platform.release(),
                "version": platform.version(),
                "machine": platform.machine(),
                "python": platform.python_version(),
                "pointer_bits": 8 * __import__("struct").calcsize("P"),
            },
            "cases": len(self.results),
            "results": self.results,
            "profiles": self.profiles,
            "behavior_fingerprint": canonical_hash(behavior_projection),
            "coverage": {
                "formats": ["text", "json", "jsonl", "xml", "conllu"],
                "engines": ["lexicon", "productive OOV", "Constraint Grammar", "generation", "round-trip"],
                "encodings": ["UTF-8", "CP1251", "malformed UTF-8"],
                "io": ["stdin", "positional input/output", "Unicode hostile paths", "CR/LF/CRLF", "literal NUL"],
                "parity": ["kazstem.exe", "qazmorph.exe", "mystem-kz.exe", "wheel module CLI", "wheel API"],
                "security": ["clean loader environment", "offline hostile environment", "missing DLL", "renamed DLL", "PATH DLL denial", "cwd DLL denial", "PATH helper denial", "cwd helper denial", "adjacent closure success", "forced rehash", "read-only resources", "process-tree cleanup", "timeout process-tree reap"],
            },
            "runtime_provenance": provenance,
            "dll_denial": dll_result,
            "helper_path_denial": helper_result,
            "bundle_content_fingerprint_unchanged": True,
            "lingering_bundle_processes": [],
            "timeout_reap": timeout_reap,
            "network_tls_neural_assets_absent": True,
            "network_tls_neural_absence_inventory": absence_inventory,
        }


def main() -> int:
    require_release_bootstrap("packaging/windows/practical_matrix_windows.py")
    parser = argparse.ArgumentParser()
    parser.add_argument("--identity", required=True, type=Path)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--archive", type=Path)
    source.add_argument("--root", type=Path)
    parser.add_argument("--wheel", required=True, type=Path)
    parser.add_argument("--python", required=True, type=Path)
    parser.add_argument("--json", required=True, type=Path)
    parser.add_argument("--candidate-observation", action="store_true")
    parser.add_argument("--candidate-name")
    parser.add_argument("--candidate-config", type=Path)
    parser.add_argument(
        "--candidate-role",
        choices=("equivalence", "selected-full-regression"),
    )
    args = parser.parse_args()
    matrix = Matrix(args.identity, args.archive, args.root, args.wheel, args.python)
    try:
        result = matrix.execute()
    finally:
        matrix.close()
    if args.json.exists() or args.json.is_symlink():
        raise ReleaseError(f"matrix output exists: {args.json}")
    args.json.parent.mkdir(parents=True, exist_ok=True)
    if args.candidate_observation:
        if not args.candidate_name or args.candidate_config is None or args.candidate_role is None:
            raise ReleaseError("candidate observation requires exact name/config/role")
        config_path = args.candidate_config.resolve(strict=True)
        config = read_json(config_path)
        if (
            not isinstance(config, dict)
            or config.get("schema") != "kazstem-windows-optimization-config-v1"
            or config.get("name") != args.candidate_name
            or file_record(config_path)
            != load_identity(args.identity.resolve(strict=True))["inputs"]["optimization_config"]
        ):
            raise ReleaseError("candidate observation config/name differs")
        result["candidate"] = {
            "name": args.candidate_name,
            "role": args.candidate_role,
            "config": file_record(config_path),
            "archive": file_record(args.archive.resolve(strict=True)) if args.archive else None,
        }
        args.json.write_bytes(json_bytes(result))
    else:
        if args.archive is None:
            raise ReleaseError("final practical evidence requires --archive")
        identity = load_identity(args.identity.resolve(strict=True))
        logical_argv = [
            "<PYTHON>",
            "packaging/windows/practical_matrix_windows.py",
            "--identity",
            "<RELEASE-IDENTITY>",
            "--archive",
            "<READY-RUN>",
            "--wheel",
            "<WHEEL>",
            "--python",
            "<PYTHON>",
            "--json",
            "<EVIDENCE-OUTPUT>",
        ]
        record = verify_generator_runtime(
            identity,
            gate="fresh-extract-practical",
            logical_argv=logical_argv,
        )
        observations = {
            key: value
            for key, value in result.items()
            if key not in {"schema", "result", "release_identity_sha256"}
        }
        args.json.write_bytes(
            json_bytes(
                evidence_envelope(
                    identity,
                    identity_hash=identity_sha256(args.identity.resolve(strict=True)),
                    record=record,
                    observations=observations,
                )
            )
        )
    print(f"PASS: {result['cases']} Windows practical/performance cases")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ReleaseError, AssertionError, OSError, ValueError, json.JSONDecodeError, subprocess.SubprocessError) as exc:
        raise SystemExit(f"error: {exc}") from exc
