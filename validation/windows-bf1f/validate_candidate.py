#!/usr/bin/env python3
"""Temporary, non-release Windows bf1f/native-runtime acceptance matrix."""

from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import shutil
import statistics
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
from typing import Any
import unittest
from xml.etree import ElementTree


BASE_COMMIT = "693a752fb89602b5512a105687de431bf3f9546d"
BF1F = "bf1f31ff6e5860585b9e4134f12dcfb9d6df8030ee87b368e5a5f29eb45c1188"
F03 = "f03e703d3e2a67044a7d91fd7d575b92cb4e61aa782fb67cff91b0a5ff0ebd5a"
RUNTIME = "17a69ae11ff3fd92a555e8c95571223cbe8b217ec409a0b9b368f0aed90ee465"
RUNTIME_MANIFEST = {
    "bytes": 20_697,
    "sha256": "554a776a942e2db65ca34bb6e05e0c258976848203cbece38ababc0067d1ee46",
}
RESOURCE_MANIFEST = {
    "bytes": 18_092,
    "sha256": "8d596011020b21a903244490cc7201d348d7bcc5442ef736ec7e4ac5435083e1",
}
WHEEL = {
    "bytes": 101_042,
    "sha256": "2c82ed5e9455eb59b84465ff8c8a0706317c64be9074c63b8c11a88b91743b8f",
}
CREATE_NO_WINDOW = 0x08000000
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
TH32CS_SNAPPROCESS = 0x00000002
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


class ValidationError(RuntimeError):
    pass


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def file_record(path: Path) -> dict[str, Any]:
    resolved = path.resolve(strict=True)
    if resolved.is_symlink() or not resolved.is_file():
        raise ValidationError(f"expected a regular file: {path}")
    return {"bytes": resolved.stat().st_size, "sha256": sha256_file(resolved)}


def json_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")


def read_json(path: Path) -> Any:
    payload = path.resolve(strict=True).read_bytes()
    if b"\r" in payload or payload != payload.rstrip(b" \t\r\n") + b"\n":
        raise ValidationError(f"JSON is not canonical LF text: {path.name}")
    return json.loads(payload.decode("utf-8"))


def expect(condition: object, message: str) -> None:
    if not condition:
        raise ValidationError(message)


def expected_candidate_lock(base: dict[str, Any]) -> dict[str, Any]:
    value = json.loads(json.dumps(base))
    expect(
        isinstance(value, dict)
        and set(value) == {"schema", "runtimes"}
        and value.get("schema") == "kazstem-platform-runtime-lock-v1",
        "base platform lock schema differs",
    )
    matches = [
        entry
        for entry in value["runtimes"]
        if entry.get("platform") == {"machine": "x86_64", "system": "windows"}
    ]
    expect(len(matches) == 1, "base lock does not have one Windows x86-64 entry")
    entry = matches[0]
    expect(entry.get("bundle_id") == RUNTIME, "Windows runtime ID differs")
    expect(entry.get("manifest") == RUNTIME_MANIFEST, "Windows manifest binding differs")
    expect(entry.get("resource_bundle_ids") == [F03], "base Windows binding is not f03-only")
    entry["resource_bundle_ids"] = [BF1F, F03]
    return value


def prepare_lock(base_path: Path, output: Path) -> None:
    if output.exists() or output.is_symlink():
        raise ValidationError("candidate lock output must be absent")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(json_bytes(expected_candidate_lock(read_json(base_path))))
    print(f"prepared candidate lock {file_record(output)}")


class ExactResult(unittest.TextTestResult):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.statuses: dict[str, dict[str, Any]] = {}

    def addSuccess(self, test: unittest.case.TestCase) -> None:
        super().addSuccess(test)
        self.statuses[test.id()] = {"status": "passed"}

    def addSkip(self, test: unittest.case.TestCase, reason: str) -> None:
        super().addSkip(test, reason)
        self.statuses[test.id()] = {"status": "skipped", "reason": reason}

    def addFailure(self, test: unittest.case.TestCase, err: Any) -> None:
        super().addFailure(test, err)
        self.statuses[test.id()] = {"status": "failed"}

    def addError(self, test: unittest.case.TestCase, err: Any) -> None:
        super().addError(test, err)
        self.statuses[test.id()] = {"status": "error"}

    def addExpectedFailure(self, test: unittest.case.TestCase, err: Any) -> None:
        super().addExpectedFailure(test, err)
        self.statuses[test.id()] = {"status": "expected-failure"}

    def addUnexpectedSuccess(self, test: unittest.case.TestCase) -> None:
        super().addUnexpectedSuccess(test)
        self.statuses[test.id()] = {"status": "unexpected-success"}


def run_integration_tests(repository: Path, site_packages: Path, output: Path) -> None:
    imported = Path(__import__("qazmorph").__file__).resolve(strict=True)
    expect(imported.is_relative_to(site_packages.resolve(strict=True)), "tests did not import the installed wheel")
    sys.path.append(str(repository.resolve(strict=True)))
    suite = unittest.defaultTestLoader.loadTestsFromName(
        "tests.test_integration_resources"
    )
    discovered: list[str] = []

    def collect(value: unittest.TestSuite | unittest.case.TestCase) -> None:
        if isinstance(value, unittest.TestSuite):
            for child in value:
                collect(child)
        else:
            discovered.append(value.id())

    collect(suite)
    stream = io.StringIO()
    runner = unittest.TextTestRunner(
        stream=stream, verbosity=2, resultclass=ExactResult
    )
    result = runner.run(suite)
    assert isinstance(result, ExactResult)
    expected_skip = (
        "tests.test_integration_resources.ResourceIntegrationTests."
        "test_bf1f_resolves_the_locked_linux_runtime_as_official"
    )
    skipped = sorted(
        test_id
        for test_id, record in result.statuses.items()
        if record["status"] == "skipped"
    )
    if not result.wasSuccessful() or skipped != [expected_skip]:
        raise ValidationError("resource integration suite failed:\n" + stream.getvalue())
    receipt = {
        "schema": "kazstem-windows-bf1f-wheel-integration-v1",
        "result": "pass",
        "wheel_import": "<VENV>/Lib/site-packages/qazmorph",
        "discovered": sorted(discovered),
        "statuses": {name: result.statuses[name] for name in sorted(result.statuses)},
        "counts": {
            "discovered": len(discovered),
            "passed": sum(value["status"] == "passed" for value in result.statuses.values()),
            "skipped": len(skipped),
            "failures": len(result.failures),
            "errors": len(result.errors),
            "unexpected_successes": len(result.unexpectedSuccesses),
        },
        "expected_platform_skip": expected_skip,
        "test_id_sha256": sha256_bytes("\n".join(sorted(discovered)).encode("utf-8")),
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(json_bytes(receipt))
    print(stream.getvalue(), end="")


def probe_hfst_proc(helper: Path, fst: Path, hfst_source: Path, output: Path) -> None:
    if sys.platform != "win32":
        raise ValidationError("hfst-proc pipe probe requires native Windows")
    selected_helper = helper.resolve(strict=True)
    selected_fst = fst.resolve(strict=True)
    selected_source = hfst_source.resolve(strict=True)
    stream_payload = "Сәлем\nсәлем\nоқу\nҚазақстан\n".encode("utf-8")
    atomic_payload = "Сәлем\0сәлем\0оқу\0Қазақстан\0".encode("utf-8")
    environment = {
        name: value
        for name, value in os.environ.items()
        if not name.upper().startswith("QAZMORPH_")
        and not name.upper().endswith("_PROXY")
        and not name.startswith("LD_")
        and not name.startswith("DYLD_")
        and name not in {"GLIBC_TUNABLES", "PATH", "PYTHONHOME", "PYTHONPATH"}
    }
    environment["PATH"] = ""
    output.parent.mkdir(parents=True, exist_ok=True)
    records: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="kazstem-hfst-proc-probe-") as temporary:
        root = Path(temporary)
        stream_input = root / "stream-input.utf8"
        atomic_input = root / "atomic-input.utf8"
        stream_output = root / "stream-output.utf8"
        atomic_output = root / "atomic-output.utf8"
        stream_input.write_bytes(stream_payload)
        atomic_input.write_bytes(atomic_payload)
        cases = (
            (
                "stream-redirected-stdin",
                [str(selected_helper), "-w", str(selected_fst)],
                stream_payload,
                None,
                None,
            ),
            (
                "stream-positional-input-stdout",
                [str(selected_helper), "-w", str(selected_fst), str(stream_input)],
                None,
                None,
                stream_input,
            ),
            (
                "stream-positional-input-output",
                [
                    str(selected_helper),
                    "-w",
                    str(selected_fst),
                    str(stream_input),
                    str(stream_output),
                ],
                None,
                stream_output,
                stream_input,
            ),
            (
                "atomic-redirected-stdin",
                [str(selected_helper), "-w", "-z", str(selected_fst)],
                atomic_payload,
                None,
                None,
            ),
            (
                "atomic-positional-input-stdout",
                [str(selected_helper), "-w", "-z", str(selected_fst), str(atomic_input)],
                None,
                None,
                atomic_input,
            ),
            (
                "atomic-positional-input-output",
                [
                    str(selected_helper),
                    "-w",
                    "-z",
                    str(selected_fst),
                    str(atomic_input),
                    str(atomic_output),
                ],
                None,
                atomic_output,
                atomic_input,
            ),
        )
        for name, command, stdin, declared_output, declared_input in cases:
            completed = subprocess.run(
                command,
                input=stdin,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=selected_helper.parent,
                env=environment,
                timeout=30,
                check=False,
                creationflags=CREATE_NO_WINDOW,
            )
            stdout_bytes = (
                declared_output.read_bytes()
                if declared_output is not None and declared_output.is_file()
                else completed.stdout
            )
            records[name] = {
                "argv": [
                    "hfst-proc.exe",
                    "-w",
                    *(["-z"] if "atomic" in name else []),
                    "<BF1F-AUTOMORF>",
                    *(
                        ["<UTF8-INPUT>", "<UTF8-OUTPUT>"]
                        if declared_output is not None
                        else (["<UTF8-INPUT>"] if stdin is None else [])
                    ),
                ],
                "returncode": completed.returncode,
                "stdin_sha256": sha256_bytes(stdin) if stdin is not None else None,
                "input_file": file_record(declared_input) if declared_input is not None else None,
                "stdout": stdout_bytes.decode("utf-8", "strict"),
                "stdout_sha256": sha256_bytes(stdout_bytes),
                "stderr": completed.stderr.decode("utf-8", "replace"),
                "stderr_sha256": sha256_bytes(completed.stderr),
            }
        for name, zero_flush, text_payload in (
            ("stream-python-text-mode", False, stream_payload.decode("utf-8")),
            ("atomic-python-text-mode", True, atomic_payload.decode("utf-8")),
        ):
            command = [
                str(selected_helper),
                "-w",
                *(["-z"] if zero_flush else []),
                str(selected_fst),
            ]
            completed = subprocess.run(
                command,
                input=text_payload,
                text=True,
                encoding="utf-8",
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=selected_helper.parent,
                env=environment,
                timeout=30,
                check=False,
                creationflags=CREATE_NO_WINDOW,
            )
            stdout_bytes = completed.stdout.encode("utf-8")
            stderr_bytes = completed.stderr.encode("utf-8")
            records[name] = {
                "argv": [
                    "hfst-proc.exe",
                    "-w",
                    *(["-z"] if zero_flush else []),
                    "<BF1F-AUTOMORF>",
                ],
                "python_text_mode": True,
                "returncode": completed.returncode,
                "stdout": completed.stdout,
                "stdout_sha256": sha256_bytes(stdout_bytes),
                "stderr": completed.stderr,
                "stderr_sha256": sha256_bytes(stderr_bytes),
            }
        case_payload = (
            "Сәлем\nсәлем\nСӘЛЕМ\n"
            "Оқу\nоқу\nОҚУ\n"
            "Қазақстан\nҚАЗАҚСТАН\n"
            "болып табылады\nБолып табылады\nБОЛЫП ТАБЫЛАДЫ\n"
            "\\[Қазақстан\\] \\^сөз\\$ \\\\ C++ \\{қазақ\\}\n"
        ).encode("utf-8")
        for mode, mode_args in (
            ("ignore-case-default", []),
            ("dictionary-case", ["-w"]),
            ("case-sensitive", ["-c"]),
        ):
            command = [str(selected_helper), *mode_args, str(selected_fst)]
            completed = subprocess.run(
                command,
                input=case_payload,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=selected_helper.parent,
                env=environment,
                timeout=30,
                check=False,
                creationflags=CREATE_NO_WINDOW,
            )
            records[f"case-mode-{mode}"] = {
                "argv": ["hfst-proc.exe", *mode_args, "<BF1F-AUTOMORF>"],
                "returncode": completed.returncode,
                "stdin": case_payload.decode("utf-8"),
                "stdin_sha256": sha256_bytes(case_payload),
                "stdout": completed.stdout.decode("utf-8", "strict"),
                "stdout_sha256": sha256_bytes(completed.stdout),
                "stderr": completed.stderr.decode("utf-8", "replace"),
                "stderr_sha256": sha256_bytes(completed.stderr),
            }
    stream_control = records["stream-redirected-stdin"]
    stream_input_only = records["stream-positional-input-stdout"]
    stream_explicit = records["stream-positional-input-output"]
    atomic_control = records["atomic-redirected-stdin"]
    atomic_input_only = records["atomic-positional-input-stdout"]
    atomic_explicit = records["atomic-positional-input-output"]

    def lf(value: str) -> str:
        return value.replace("\r\n", "\n")

    commands_ok = all(record["returncode"] == 0 for record in records.values())
    comparisons = {
        "stream_binary_pipe_equals_positional": (
            lf(stream_control["stdout"])
            == lf(stream_input_only["stdout"])
            == lf(stream_explicit["stdout"])
        ),
        "atomic_binary_pipe_equals_positional": (
            lf(atomic_control["stdout"])
            == lf(atomic_input_only["stdout"])
            == lf(atomic_explicit["stdout"])
        ),
        "stream_python_text_equals_binary": (
            lf(records["stream-python-text-mode"]["stdout"])
            == lf(stream_control["stdout"])
        ),
        "atomic_python_text_equals_binary": (
            lf(records["atomic-python-text-mode"]["stdout"])
            == lf(atomic_control["stdout"])
        ),
    }
    result = "pass" if commands_ok else "fail"
    conclusion = "observational stdin/text/positional I/O control completed"
    source_members: dict[str, dict[str, Any]] = {}
    expected_source_members = {
        "tools/src/hfst-proc/hfst-proc.cc": {
            "bytes": 17_142,
            "sha256": "0d9d3e305e54968074fa3ecd8c561d8e26a6527eeda29dd6458367cb2730ab50",
        },
        "tools/src/hfst-proc/hfst-proc.h": {
            "bytes": 2_923,
            "sha256": "3e61c00c1f9eea1013b0d5d23854a1423040cc4722a6ff56956b94d35d4426ba",
        },
        "tools/src/hfst-proc/applicators.cc": {
            "bytes": 19_047,
            "sha256": "c6b3c78c885f367bc5ebd2d141bf1ae32a4c84e426a03c4a1ec309ab091e03bf",
        },
    }
    with tarfile.open(selected_source, "r:gz") as archive:
        for suffix, expected in expected_source_members.items():
            matches = [
                member
                for member in archive.getmembers()
                if member.name.endswith("/" + suffix) and member.isfile()
            ]
            expect(len(matches) == 1, f"HFST source member mismatch: {suffix}")
            member_stream = archive.extractfile(matches[0])
            expect(member_stream is not None, f"cannot read HFST source member: {suffix}")
            payload = member_stream.read(expected["bytes"] + 1)
            actual = {"bytes": len(payload), "sha256": sha256_bytes(payload)}
            expect(actual == expected, f"HFST source member identity mismatch: {suffix}")
            source_members[suffix] = actual
    output.write_bytes(
        json_bytes(
            {
                "schema": "kazstem-windows-hfst-proc-positional-file-probe-v1",
                "result": result,
                "helper": file_record(selected_helper),
                "fst": file_record(selected_fst),
                "hfst_source_archive": file_record(selected_source),
                "hfst_source_members": source_members,
                "records": records,
                "comparisons": comparisons,
                "conclusion": conclusion,
            }
        )
    )
    expect(commands_ok, "hfst-proc I/O control command failed")
    print("PASS: Windows hfst-proc I/O controls completed")


def trusted_windows_directories() -> tuple[Path, Path]:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetSystemDirectoryW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint]
    kernel32.GetSystemDirectoryW.restype = ctypes.c_uint
    kernel32.GetWindowsDirectoryW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint]
    kernel32.GetWindowsDirectoryW.restype = ctypes.c_uint

    def query(function: Any, label: str) -> str:
        buffer = ctypes.create_unicode_buffer(32768)
        length = function(buffer, len(buffer))
        if not length or length >= len(buffer):
            raise ValidationError(f"cannot resolve Windows {label}")
        return buffer.value

    return (
        Path(query(kernel32.GetSystemDirectoryW, "System32")).resolve(strict=True),
        Path(query(kernel32.GetWindowsDirectoryW, "directory")).resolve(strict=True),
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
        raise ValidationError("cannot snapshot the Windows process tree")
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


class Matrix:
    def __init__(self, args: argparse.Namespace) -> None:
        if sys.platform != "win32" or platform.machine().casefold() not in {"amd64", "x86_64"}:
            raise ValidationError("matrix requires genuine Windows x86-64")
        self.args = args
        self.resource = args.resource.resolve(strict=True)
        self.runtime = args.runtime.resolve(strict=True)
        self.wheel = args.wheel.resolve(strict=True)
        self.python = args.python.resolve(strict=True)
        self.scripts = args.scripts.resolve(strict=True)
        self.temp_owner = tempfile.TemporaryDirectory(prefix="kazstem-bf1f-windows-")
        self.temp = Path(self.temp_owner.name)
        self.results: list[dict[str, Any]] = []
        self.system32, self.windows = trusted_windows_directories()
        self.safe_path = os.pathsep.join([str(self.system32), str(self.windows)])
        self.taskkill = (self.system32 / "taskkill.exe").resolve(strict=True)
        self.powershell = (
            self.system32 / "WindowsPowerShell/v1.0/powershell.exe"
        ).resolve(strict=True)
        self.environment = {
            name: value
            for name, value in os.environ.items()
            if not name.upper().startswith("QAZMORPH_")
            and not name.upper().endswith("_PROXY")
            and not name.startswith("GIT_")
            and not name.startswith("LD_")
            and not name.startswith("DYLD_")
            and name not in {
                "CG3_DEFAULT",
                "CG3_OVERRIDE",
                "GLIBC_TUNABLES",
                "HOME",
                "PATH",
                "PYTHONHOME",
                "PYTHONPATH",
                "USERPROFILE",
            }
        }
        offline_home = self.temp / "offline-home"
        offline_home.mkdir()
        self.environment.update(
            {
                "ALL_PROXY": "http://127.0.0.1:9",
                "HOME": str(offline_home),
                "HTTP_PROXY": "http://127.0.0.1:9",
                "HTTPS_PROXY": "http://127.0.0.1:9",
                "LANG": "C",
                "LC_ALL": "C",
                "NO_PROXY": "",
                "PATH": self.safe_path,
                "QAZMORPH_RESOURCE_DIR": str(self.resource),
                "TZ": "UTC",
                "USERPROFILE": str(offline_home),
            }
        )
        self.executable = self.entry("kazstem")
        self.before = self.tree_fingerprint(self.resource.parent)

    def close(self) -> None:
        self.temp_owner.cleanup()

    def entry(self, name: str) -> Path:
        path = self.scripts / f"{name}.exe"
        if not path.is_file():
            raise ValidationError(f"installed console entry point is absent: {name}.exe")
        return path.resolve(strict=True)

    @staticmethod
    def tree_fingerprint(root: Path) -> str:
        records: list[dict[str, Any]] = []
        for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
            relative = path.relative_to(root).as_posix()
            if path.is_symlink():
                raise ValidationError(f"runtime/resource tree has a symlink: {relative}")
            if path.is_file():
                records.append({"path": relative, **file_record(path)})
            elif not path.is_dir():
                raise ValidationError(f"runtime/resource tree has a special entry: {relative}")
        return sha256_bytes(json.dumps(records, sort_keys=True, separators=(",", ":")).encode("utf-8"))

    def run(
        self,
        name: str,
        command: list[str],
        *,
        input_bytes: bytes = b"",
        expected: int | set[int] | None = 0,
        environment: dict[str, str] | None = None,
        cwd: Path | None = None,
        timeout: float = 120.0,
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
            subprocess.run(
                [str(self.taskkill), "/PID", str(process.pid), "/T", "/F"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
                creationflags=CREATE_NO_WINDOW,
            )
            process.wait(timeout=20)
            raise ValidationError(f"{name} exceeded {timeout:g}s")
        if len(stdout) > 256 * 1024**2 or len(stderr) > 16 * 1024**2:
            raise ValidationError(f"{name} exceeded the validation capture cap")
        accepted = process.returncode != 0 if expected is None else process.returncode in ({expected} if isinstance(expected, int) else expected)
        if not accepted:
            raise ValidationError(
                f"{name} returned {process.returncode}: "
                + stderr.decode("utf-8", "replace")[:2000]
            )
        elapsed = time.perf_counter() - started
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

    def cli(
        self,
        name: str,
        flags: list[str],
        *,
        text: str = "",
        expected: int | set[int] | None = 0,
        environment: dict[str, str] | None = None,
        cwd: Path | None = None,
        timeout: float = 120.0,
    ) -> subprocess.CompletedProcess[bytes]:
        return self.run(
            name,
            [str(self.executable), *flags],
            input_bytes=text.encode("utf-8"),
            expected=expected,
            environment=environment,
            cwd=cwd,
            timeout=timeout,
        )

    def bundle_processes(self) -> list[dict[str, Any]]:
        script = (
            "$root=$env:KAZSTEM_AUDIT_ROOT; "
            "$v=Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -and "
            "$_.ExecutablePath.StartsWith($root,[System.StringComparison]::OrdinalIgnoreCase) } | "
            "Select-Object ProcessId,ParentProcessId,Name; $v | ConvertTo-Json -Compress"
        )
        environment = dict(self.environment)
        environment["KAZSTEM_AUDIT_ROOT"] = str(self.runtime)
        completed = subprocess.run(
            [str(self.powershell), "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
            creationflags=CREATE_NO_WINDOW,
            timeout=30,
            check=False,
        )
        if completed.returncode:
            raise ValidationError("cannot audit lingering runtime processes")
        text = completed.stdout.decode("utf-8-sig").strip()
        if not text:
            return []
        value = json.loads(text)
        rows = value if isinstance(value, list) else [value]
        return [
            {"pid": row["ProcessId"], "parent_pid": row["ParentProcessId"], "name": row["Name"]}
            for row in rows
        ]

    def verify_inputs(self) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
        expect(file_record(self.wheel) == WHEEL, "canonical wheel bytes differ")
        producer = self.args.producer_manifest.resolve(strict=True)
        resource_manifest = self.resource / "manifest.json"
        expect(file_record(producer) == RESOURCE_MANIFEST, "producer manifest binding differs")
        expect(resource_manifest.read_bytes() == producer.read_bytes(), "external bf1f manifest differs from producer")
        resource_value = read_json(resource_manifest)
        expect(resource_value.get("schema") == "qazmorph-resource-manifest-v4", "resource schema differs")
        expect(resource_value.get("bundle_id") == BF1F, "resource bundle ID differs")
        expected_names = sorted([*resource_value["files"], "manifest.json"])
        observed_names = sorted(path.name for path in self.resource.iterdir() if path.is_file())
        expect(observed_names == expected_names, "bf1f resource inventory differs")
        for name, record in resource_value["files"].items():
            expect(file_record(self.resource / name) == {"bytes": record["bytes"], "sha256": record["sha256"]}, f"bf1f file differs: {name}")

        runtime_manifest = self.runtime / "manifest.json"
        expect(file_record(runtime_manifest) == RUNTIME_MANIFEST, "runtime manifest bytes differ")
        runtime_value = read_json(runtime_manifest)
        expect(runtime_value.get("schema") == "kazstem-platform-runtime-manifest-v1", "runtime schema differs")
        expect(runtime_value.get("bundle_id") == RUNTIME, "runtime bundle ID differs")
        expect(runtime_value.get("platform") == {"machine": "x86_64", "system": "windows"}, "runtime platform differs")
        expected_runtime_names = sorted([*runtime_value["files"], "manifest.json"])
        observed_runtime_names = sorted(
            path.relative_to(self.runtime).as_posix()
            for path in self.runtime.rglob("*")
            if path.is_file()
        )
        expect(observed_runtime_names == expected_runtime_names, "runtime file inventory differs")
        for name, record in runtime_value["files"].items():
            expect(file_record(self.runtime / name) == {"bytes": record["bytes"], "sha256": record["sha256"]}, f"runtime file differs: {name}")

        candidate = read_json(self.args.candidate_lock)
        base = read_json(self.args.base_lock)
        expect(candidate == expected_candidate_lock(base), "candidate lock changes more than the Windows bf1f binding")
        installed_lock = self.args.installed_lock.resolve(strict=True)
        expect(installed_lock.read_bytes() == self.args.candidate_lock.resolve(strict=True).read_bytes(), "installed wheel lock differs from candidate")
        integration = read_json(self.args.integration_receipt)
        expect(integration.get("result") == "pass", "wheel integration receipt is not passing")
        pe_audit = read_json(self.args.pe_audit)
        expect(pe_audit == runtime_value["dependency_closure"], "fresh PE audit differs from runtime manifest")
        return resource_value, runtime_value, integration

    @staticmethod
    def jsonl_rows(value: bytes) -> list[dict[str, Any]]:
        return [json.loads(line) for line in value.decode("utf-8").splitlines() if line]

    @classmethod
    def reconstruct_jsonl(cls, value: bytes) -> str:
        return "".join(str(row["text"]) for row in cls.jsonl_rows(value) if row.get("consumes_input") is True)

    def provenance(self, environment: dict[str, str]) -> dict[str, Any]:
        code = (
            "import json\n"
            "from qazmorph import Analyzer\n"
            "with Analyzer() as analyzer:\n"
            " p=analyzer.backend.runtime_provenance()\n"
            " a=p['active_runtime']\n"
            " out={'official':p['official'],'verified':p['verified'],'non_official_reasons':p['non_official_reasons'],"
            "'resource_bundle_id':p['resource_bundle_id'],'resource_inventory':{k:p['resource_inventory'].get(k) for k in ('verified','integrity_seal_verified','content_rehashed','force_rehash')},"
            "'toolchain_inventory':{k:p['toolchain_inventory'].get(k) for k in ('verified','integrity_seal_verified','content_rehashed','force_rehash')},"
            "'active_runtime':{k:a.get(k) for k in ('origin','bundle_id','binding','platform_lock')},'environment':p['environment']}\n"
            " print(json.dumps(out,sort_keys=True))\n"
        )
        result = self.run(
            "forced-rehash-provenance",
            [str(self.python), "-I", "-B", "-c", code],
            environment=environment,
            timeout=180,
        )
        return json.loads(result.stdout)

    def dll_denial(self, runtime_value: dict[str, Any]) -> dict[str, Any]:
        closure = runtime_value["dependency_closure"]["files"]
        roots = sorted(runtime_value["dependency_closure"]["roots"])

        def descendants(root: str) -> set[str]:
            reached: set[str] = set()
            queue = [root]
            while queue:
                current = queue.pop(0)
                if current in reached:
                    continue
                reached.add(current)
                queue.extend(closure[current]["bundled_dependencies"])
            return reached

        reaches = {root: descendants(root) for root in roots}

        def invocation(root: str) -> tuple[list[str], bytes]:
            if root.endswith("cg-proc.exe"):
                return [str(self.executable), "-d", "-c", "--format", "jsonl"], "балалар мектепке барды.\n".encode("utf-8")
            if root.endswith("hfst-optimized-lookup.exe"):
                return [str(self.executable), "-c", "--format", "jsonl"], "суперқазақшалар\n".encode("utf-8")
            return [str(self.executable), "-c", "--format", "jsonl"], "балалар\n".encode("utf-8")

        hostile_path = self.temp / "hostile-dll-path"
        hostile_cwd = self.temp / "hostile-dll-cwd"
        hostile_path.mkdir()
        hostile_cwd.mkdir()
        injected_environment = dict(self.environment)
        injected_environment["PATH"] = str(hostile_path) + os.pathsep + self.safe_path
        checks: list[dict[str, Any]] = []
        dlls = sorted(name for name in closure if name.casefold().endswith(".dll"))
        for index, name in enumerate(dlls):
            root = next((candidate for candidate in roots if name in reaches[candidate]), None)
            expect(root is not None, f"runtime contains unreachable DLL: {name}")
            original = self.runtime / name
            backup = original.with_name(original.name + ".validation-missing")
            path_copy = hostile_path / original.name
            cwd_copy = hostile_cwd / original.name
            os.chmod(original, stat.S_IWRITE | stat.S_IREAD)
            original.rename(backup)
            try:
                command, payload = invocation(root)
                missing = self.run(f"dll-missing-{index:02d}", command, input_bytes=payload, expected=None, timeout=45)
                shutil.copyfile(backup, path_copy)
                path_denied = self.run(f"dll-path-denied-{index:02d}", command, input_bytes=payload, expected=None, environment=injected_environment, timeout=45)
                shutil.copyfile(backup, cwd_copy)
                cwd_denied = self.run(f"dll-cwd-denied-{index:02d}", command, input_bytes=payload, expected=None, cwd=hostile_cwd, timeout=45)
                for result in (missing, path_denied, cwd_denied):
                    expect(result.returncode != 0 and b"Traceback" not in result.stderr, f"DLL denial failed closed incorrectly: {name}")
                checks.append({"dll": name, "root": root, "missing": missing.returncode, "path": path_denied.returncode, "cwd": cwd_denied.returncode})
            finally:
                path_copy.unlink(missing_ok=True)
                cwd_copy.unlink(missing_ok=True)
                backup.rename(original)
                os.chmod(original, stat.S_IREAD)
        for index, root in enumerate(roots):
            command, payload = invocation(root)
            self.run(f"dll-restored-success-{index:02d}", command, input_bytes=payload, timeout=45)
        return {"result": "pass", "dll_count": len(checks), "checks": checks, "restored_roots": roots}

    def helper_denial(self) -> dict[str, Any]:
        helper = self.runtime / "usr/bin/hfst-proc.exe"
        backup = helper.with_name(helper.name + ".validation-missing")
        hostile_path = self.temp / "hostile-helper-path"
        hostile_cwd = self.temp / "hostile-helper-cwd"
        hostile_path.mkdir()
        hostile_cwd.mkdir()
        path_copy = hostile_path / helper.name
        cwd_copy = hostile_cwd / helper.name
        injected = dict(self.environment)
        injected["PATH"] = str(hostile_path) + os.pathsep + self.safe_path
        os.chmod(helper, stat.S_IWRITE | stat.S_IREAD)
        helper.rename(backup)
        try:
            shutil.copyfile(backup, path_copy)
            path_denied = self.cli("helper-path-denied", ["-c", "--format", "jsonl"], text="балалар\n", expected=None, environment=injected)
            shutil.copyfile(backup, cwd_copy)
            cwd_denied = self.cli("helper-cwd-denied", ["-c", "--format", "jsonl"], text="балалар\n", expected=None, cwd=hostile_cwd)
            expect(path_denied.returncode != 0 and cwd_denied.returncode != 0, "renamed helper was accepted through PATH/cwd")
            expect(b"Traceback" not in path_denied.stderr + cwd_denied.stderr, "helper denial leaked a traceback")
        finally:
            path_copy.unlink(missing_ok=True)
            cwd_copy.unlink(missing_ok=True)
            backup.rename(helper)
            os.chmod(helper, stat.S_IREAD)
        self.cli("helper-restored-success", ["-c", "--format", "jsonl"], text="балалар\n")
        return {"result": "pass", "path_returncode": path_denied.returncode, "cwd_returncode": cwd_denied.returncode, "restored_success": True}

    def bounded_process_cleanup(self) -> dict[str, Any]:
        windows_modules = self.args.repository.resolve(strict=True) / "packaging/windows"
        sys.path.insert(0, str(windows_modules))
        import bounded_windows_process as bounded

        helper = self.runtime / "usr/bin/hfst-optimized-lookup.exe"
        child_code = (
            "import subprocess,sys,time\n"
            "p=subprocess.Popen([sys.argv[1],'-q','-u',sys.argv[2]],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)\n"
            "print(p.pid,flush=True)\n"
            "time.sleep(60)\n"
        )
        timed_out = False
        try:
            bounded.run_bounded(
                [str(self.python), "-I", "-B", "-c", child_code, str(helper), str(self.resource / "kaz.guesser.automorf.hfstol")],
                cwd=self.temp,
                environment=self.environment,
                timeout_seconds=0.5,
                output_limit_bytes=4096,
            )
        except bounded.BoundedProcessError as exc:
            timed_out = "exceeded" in str(exc)
        expect(timed_out, "bounded actual-helper process tree did not hit the timeout gate")
        expect(self.bundle_processes() == [], "actual helper survived bounded timeout cleanup")
        overflowed = False
        try:
            bounded.run_bounded(
                [str(self.runtime / "usr/bin/hfst-proc.exe"), "--help"],
                cwd=self.runtime / "usr/bin",
                environment=self.environment,
                timeout_seconds=20,
                output_limit_bytes=1,
            )
        except bounded.BoundedProcessError as exc:
            overflowed = "output exceeded" in str(exc)
        expect(overflowed, "actual helper did not hit bounded output cleanup")
        expect(self.bundle_processes() == [], "actual helper survived bounded overflow cleanup")
        return {
            "result": "pass",
            "support_module": file_record(windows_modules / "bounded_windows_process.py"),
            "actual_helper_timeout_reaped": True,
            "actual_helper_overflow_reaped": True,
            "active_processes_zero": True,
        }

    def profile_file(self, name: str, input_path: Path, output_path: Path, timeout: float) -> dict[str, Any]:
        started = time.perf_counter()
        process = subprocess.Popen(
            [str(self.executable), "-c", "--format", "jsonl", str(input_path), str(output_path)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=self.temp,
            env=self.environment,
            creationflags=CREATE_NO_WINDOW,
        )
        process_peak = 0
        tree_peak = 0
        while process.poll() is None:
            current_tree = 0
            for process_id in windows_process_tree(process.pid):
                observed = windows_memory(process_id)
                if observed is not None:
                    current_tree += observed[0]
                    if process_id == process.pid:
                        process_peak = max(process_peak, observed[1])
            tree_peak = max(tree_peak, current_tree)
            if time.perf_counter() - started > timeout:
                subprocess.run([str(self.taskkill), "/PID", str(process.pid), "/T", "/F"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=CREATE_NO_WINDOW)
                raise ValidationError(f"{name} exceeded {timeout:g}s")
            time.sleep(0.01)
        stdout, stderr = process.communicate(timeout=20)
        expect(process.returncode == 0, f"{name} failed: {stderr.decode('utf-8', 'replace')[:1000]}")
        elapsed = time.perf_counter() - started
        self.results.append({"name": name, "returncode": process.returncode, "seconds": round(elapsed, 6), "stdin_bytes": 0, "stdout_bytes": len(stdout), "stdout_sha256": sha256_bytes(stdout), "stderr_bytes": len(stderr), "stderr_sha256": sha256_bytes(stderr)})
        return {
            "seconds": round(elapsed, 6),
            "launcher_peak_working_set_bytes": process_peak or None,
            "process_tree_peak_working_set_bytes": tree_peak or None,
            "output": file_record(output_path),
        }

    def execute(self) -> dict[str, Any]:
        resource_value, runtime_value, integration = self.verify_inputs()
        for root in (self.resource, self.runtime):
            for path in root.rglob("*"):
                if path.is_file():
                    os.chmod(path, stat.S_IREAD)

        versions = {}
        for alias in ("kazstem", "qazmorph", "mystem-kz"):
            result = self.run(f"alias-{alias}", [str(self.entry(alias)), "--version"])
            versions[alias] = result.stdout.decode("utf-8", "strict").strip()
        expect(len(set(versions.values())) == 1, "console aliases differ")

        text = "Қазақстан & балалар мектепке барды.\r\n"
        text_result = self.cli("format-text", ["-c", "-i", "--format", "text"], text=text)
        expect(text_result.stdout.decode("utf-8") == text, "text copy mode is not lossless")
        json_result = self.cli("format-json", ["-c", "-i", "--format", "json"], text=text)
        expect("".join(row["text"] for row in json.loads(json_result.stdout)) == text, "JSON is not lossless")
        jsonl_result = self.cli("format-jsonl", ["-c", "--format", "jsonl"], text=text)
        expect(self.reconstruct_jsonl(jsonl_result.stdout) == text, "JSONL is not lossless")
        xml_result = self.cli("format-xml", ["-c", "-i", "--format", "xml"], text=text)
        expect("".join(ElementTree.fromstring(xml_result.stdout).itertext()) == text, "XML is not lossless")
        conllu = self.cli("format-conllu", ["--format", "conllu"], text=text)
        conllu_lines = [line for line in conllu.stdout.decode("utf-8").splitlines() if line and not line.startswith("#")]
        expect(bool(conllu_lines) and all(len(line.split("\t")) == 10 for line in conllu_lines), "CoNLL-U shape differs")

        oov = self.cli("productive-oov", ["--format", "jsonl"], text="суперқазақшалар\n")
        expect(any(analysis.get("source") == "guesser" and analysis.get("guessed") is True for row in self.jsonl_rows(oov.stdout) for analysis in row.get("analysis", [])), "bf1f productive OOV was not used")
        cg = self.cli("constraint-grammar", ["-d", "-c", "--format", "jsonl"], text="балалар мектепке барды.\n")
        expect({row.get("mode") for row in self.jsonl_rows(cg.stdout) if row.get("record_type") == "token"} == {"contextual"}, "Constraint Grammar mode differs")

        generated = self.run(
            "direct-generation",
            [str(self.runtime / "usr/bin/hfst-optimized-lookup.exe"), "-q", "-u", "-n", "128", str(self.resource / "kaz.autogen.hfstol")],
            input_bytes="кітап<n><pl><dat>\n".encode("utf-8"),
        )
        expect("кітаптарға" in generated.stdout.decode("utf-8"), "dictionary generation differs")
        roundtrip = self.cli("generation-roundtrip", ["-c", "--format", "json"], text="кітаптарға")
        expect(any(value["lex"] == "кітап" for value in json.loads(roundtrip.stdout)[0]["analysis"]), "generation round-trip differs")

        protected = "бір\rекі\nүш\r\nи\u0306 ^$[]{}\\/\x00соң"
        protected_result = self.cli("unicode-crlf-reserved-nul", ["-c", "--format", "jsonl"], text=protected)
        expect(self.reconstruct_jsonl(protected_result.stdout) == protected, "Unicode/CRLF/NUL round-trip differs")
        xml_error = self.cli("xml-nul-controlled", ["-c", "--format", "xml"], text="a\x00b", expected=2)
        expect(b"U+0000" in xml_error.stderr and b"Traceback" not in xml_error.stderr, "XML NUL failure is uncontrolled")
        malformed = self.run("malformed-utf8", [str(self.executable), "-e", "utf-8"], input_bytes=b"\xff", expected=2)
        expect(b"Traceback" not in malformed.stderr, "malformed UTF-8 leaked traceback")
        cp1251_text = "тест\r\n"
        cp1251 = self.run("cp1251", [str(self.executable), "-c", "-e", "cp1251", "--format", "text"], input_bytes=cp1251_text.encode("cp1251"))
        expect(cp1251_text in cp1251.stdout.decode("cp1251"), "CP1251 round-trip differs")
        cap_code = (
            "from qazmorph import Analyzer\n"
            "with Analyzer(guess=True) as a:\n"
            " assert len(a.generate('сөз',('n','nom'),limit=1)) <= 1\n"
            " for value in ('x\\n','x\\0','x'*4097):\n"
            "  try: a.backend.generate(value,limit=1)\n"
            "  except ValueError: pass\n"
            "  else: raise AssertionError('invalid generator query accepted')\n"
        )
        self.run("malformed-and-generation-caps", [str(self.python), "-I", "-B", "-c", cap_code])

        hostile = self.temp / "hostile cwd Қазақ []^$() !"
        hostile.mkdir()
        hostile_bin = hostile / "fake PATH"
        hostile_bin.mkdir()
        hostile_environment = dict(self.environment)
        hostile_environment["PATH"] = str(hostile_bin) + os.pathsep + self.safe_path
        input_path = hostile / "кіріс Қазақ []^$() !.txt"
        output_path = hostile / "шығыс Қазақ []^$() !.json"
        hostile_text = "Қазақстан ^$[]{} мектеп\r\n"
        input_path.write_text(hostile_text, encoding="utf-8", newline="")
        self.run("hostile-offline-file-paths", [str(self.executable), "-c", "--format", "json", str(input_path), str(output_path)], cwd=hostile, environment=hostile_environment)
        expect("".join(row["text"] for row in json.loads(output_path.read_bytes())) == hostile_text, "hostile file paths differ")

        api_code = (
            "from qazmorph import Analyzer\n"
            "from qazmorph.formats import format_jsonl\n"
            f"text={text!r}\n"
            "with Analyzer() as analyzer:\n"
            " print(format_jsonl(analyzer.analyze(text),copy_input=True),end='')\n"
        )
        api = self.run("wheel-api-parity", [str(self.python), "-I", "-B", "-c", api_code])
        expect(api.stdout == jsonl_result.stdout, "installed wheel API and CLI differ")

        provenance = self.provenance(self.environment)
        expect(provenance["official"] is True and provenance["verified"] is True, "clean bf1f Windows provenance is not official")
        expect(provenance["non_official_reasons"] == [], "clean provenance has non-official reasons")
        expect(provenance["resource_bundle_id"] == BF1F, "provenance resource ID differs")
        expect(provenance["active_runtime"]["origin"] == "platform-runtime-lock", "runtime origin differs")
        expect(provenance["active_runtime"]["bundle_id"] == RUNTIME, "active runtime ID differs")
        expect(provenance["active_runtime"]["platform_lock"]["resource_bundle_ids"] == [BF1F, F03], "active runtime lock does not preserve both resources")
        expect(provenance["resource_inventory"]["content_rehashed"] is True, "resource inventory was not rehashed")
        expect(provenance["toolchain_inventory"]["content_rehashed"] is True, "runtime inventory was not rehashed")
        expect(provenance["environment"]["loader_policy"]["clean_parent_startup"] is True, "parent loader state is not clean")

        hostile_provenance_environment = dict(self.environment)
        hostile_provenance_environment["PATH"] = str(hostile_bin) + os.pathsep + self.safe_path
        hostile_provenance = self.provenance(hostile_provenance_environment)
        expect(hostile_provenance["official"] is False, "hostile parent PATH remained official")
        expect(hostile_provenance["environment"]["PATH"]["removed_from_helper_environment"] is True, "hostile PATH reached child helpers")

        dlls = self.dll_denial(runtime_value)
        helper = self.helper_denial()
        bounded = self.bounded_process_cleanup()

        startup = []
        for index in range(5):
            self.run(f"startup-{index:02d}", [str(self.executable), "--version"])
            startup.append(self.results[-1]["seconds"])
        startup_profile = {"runs": len(startup), "median_seconds": round(statistics.median(startup), 6), "max_seconds": round(max(startup), 6), "threshold_seconds": 5.0}
        expect(startup_profile["median_seconds"] <= 5.0, "startup median exceeded five seconds")

        phrase = "Қазақстандағы балалар мектепке барып, кітаптарды оқыды.\r\n"
        workload = (phrase * (300_000 // len(phrase) + 1))[:300_000]
        workload_path = self.temp / "large-input.txt"
        workload_path.write_text(workload, encoding="utf-8", newline="")
        large = []
        for index in range(2):
            output = self.temp / f"large-{index}.jsonl"
            record = self.profile_file(f"large-deterministic-{index}", workload_path, output, 600)
            record["characters"] = len(workload)
            record["characters_per_second"] = round(len(workload) / record["seconds"], 3)
            large.append(record)
        expect(len({record["output"]["sha256"] for record in large}) == 1, "large outputs are not deterministic")
        expect(all(record["characters_per_second"] >= 500 for record in large), "throughput is below 500 characters/second")
        expect(all(record["process_tree_peak_working_set_bytes"] is not None and record["process_tree_peak_working_set_bytes"] <= 512 * 1024**2 for record in large), "process-tree peak working set exceeded 512 MiB")

        expect(self.bundle_processes() == [], "runtime processes lingered after the practical matrix")
        after = self.tree_fingerprint(self.resource.parent)
        expect(after == self.before, "resource/runtime tree changed during validation")
        return {
            "schema": "kazstem-windows-bf1f-native-acceptance-v1",
            "result": "pass",
            "source": {"base_commit": BASE_COMMIT, "validation_commit": self.args.validation_commit},
            "host": {"system": platform.system(), "release": platform.release(), "version": platform.version(), "machine": platform.machine(), "python": platform.python_version(), "pointer_bits": 8 * __import__("struct").calcsize("P")},
            "inputs": {
                "wheel": file_record(self.wheel),
                "resource_manifest": file_record(self.resource / "manifest.json"),
                "producer_manifest": file_record(self.args.producer_manifest),
                "candidate_lock": file_record(self.args.candidate_lock),
                "runtime_manifest": file_record(self.runtime / "manifest.json"),
                "runtime_build_receipt": file_record(self.args.runtime_build),
                "pe_audit": file_record(self.args.pe_audit),
                "integration_receipt": file_record(self.args.integration_receipt),
                "host_evidence": file_record(self.args.host_evidence),
            },
            "bindings": {"resource_bundle_id": resource_value["bundle_id"], "runtime_bundle_id": runtime_value["bundle_id"], "resource_bundle_ids": [BF1F, F03]},
            "integration": integration,
            "aliases": versions,
            "runtime_provenance": provenance,
            "hostile_path_provenance": {"official": hostile_provenance["official"], "non_official_reasons": hostile_provenance["non_official_reasons"], "path": hostile_provenance["environment"]["PATH"]},
            "dll_denial": dlls,
            "helper_denial": helper,
            "process_cleanup": bounded,
            "performance": {"startup": startup_profile, "large_workload": large},
            "cases": self.results,
            "coverage": {
                "formats": ["text", "json", "jsonl", "xml", "conllu"],
                "engines": ["dictionary", "productive-analysis", "productive-generation", "constraint-grammar", "generation-roundtrip"],
                "boundaries": ["unicode", "CR", "LF", "CRLF", "NUL", "CP1251", "malformed-UTF8", "query-caps", "hostile-paths"],
                "security": ["offline-wheel", "clean-provenance", "forced-rehash", "all-DLL-missing-PATH-cwd-denial", "helper-PATH-cwd-denial", "job-timeout", "job-overflow", "no-lingering-processes", "resource-runtime-unchanged"],
                "performance": ["five-startups", "two-300k-character-runs", "deterministic-output", "peak-working-set"],
            },
        }


def validate(args: argparse.Namespace) -> None:
    expect(args.base_commit == BASE_COMMIT, "validation base commit differs")
    matrix = Matrix(args)
    try:
        evidence = matrix.execute()
    finally:
        matrix.close()
    if args.output.exists() or args.output.is_symlink():
        raise ValidationError("validation evidence output must be absent")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(json_bytes(evidence))
    print(f"PASS: {len(evidence['cases'])} Windows bf1f practical cases")


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser()
    commands = value.add_subparsers(dest="command", required=True)
    prepare = commands.add_parser("prepare-lock")
    prepare.add_argument("--base-lock", required=True, type=Path)
    prepare.add_argument("--output", required=True, type=Path)

    integration = commands.add_parser("integration")
    integration.add_argument("--repository", required=True, type=Path)
    integration.add_argument("--site-packages", required=True, type=Path)
    integration.add_argument("--output", required=True, type=Path)

    probe = commands.add_parser("probe-hfst-proc")
    probe.add_argument("--helper", required=True, type=Path)
    probe.add_argument("--fst", required=True, type=Path)
    probe.add_argument("--hfst-source", required=True, type=Path)
    probe.add_argument("--output", required=True, type=Path)

    run = commands.add_parser("validate")
    run.add_argument("--repository", required=True, type=Path)
    run.add_argument("--base-commit", required=True)
    run.add_argument("--validation-commit", required=True)
    run.add_argument("--base-lock", required=True, type=Path)
    run.add_argument("--candidate-lock", required=True, type=Path)
    run.add_argument("--installed-lock", required=True, type=Path)
    run.add_argument("--resource", required=True, type=Path)
    run.add_argument("--producer-manifest", required=True, type=Path)
    run.add_argument("--runtime", required=True, type=Path)
    run.add_argument("--wheel", required=True, type=Path)
    run.add_argument("--python", required=True, type=Path)
    run.add_argument("--scripts", required=True, type=Path)
    run.add_argument("--integration-receipt", required=True, type=Path)
    run.add_argument("--runtime-build", required=True, type=Path)
    run.add_argument("--pe-audit", required=True, type=Path)
    run.add_argument("--host-evidence", required=True, type=Path)
    run.add_argument("--output", required=True, type=Path)
    return value


def main() -> int:
    args = parser().parse_args()
    if args.command == "prepare-lock":
        prepare_lock(args.base_lock, args.output)
    elif args.command == "integration":
        run_integration_tests(args.repository, args.site_packages, args.output)
    elif args.command == "probe-hfst-proc":
        probe_hfst_proc(args.helper, args.fst, args.hfst_source, args.output)
    else:
        validate(args)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValidationError, AssertionError, OSError, ValueError, json.JSONDecodeError, subprocess.SubprocessError) as exc:
        raise SystemExit(f"error: {exc}") from exc
