"""Bounded Windows subprocess capture with a kill-on-close process-tree job."""

from __future__ import annotations

import ctypes
from ctypes import wintypes
from pathlib import Path
import subprocess
import threading
import time
from typing import Any


CREATE_NO_WINDOW = 0x08000000
CREATE_SUSPENDED = 0x00000004
JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9
JOB_OBJECT_BASIC_ACCOUNTING_INFORMATION = 1


class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("PerProcessUserTimeLimit", ctypes.c_longlong),
        ("PerJobUserTimeLimit", ctypes.c_longlong),
        ("LimitFlags", wintypes.DWORD),
        ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t),
        ("ActiveProcessLimit", wintypes.DWORD),
        ("Affinity", ctypes.c_size_t),
        ("PriorityClass", wintypes.DWORD),
        ("SchedulingClass", wintypes.DWORD),
    ]


class IO_COUNTERS(ctypes.Structure):
    _fields_ = [
        ("ReadOperationCount", ctypes.c_ulonglong),
        ("WriteOperationCount", ctypes.c_ulonglong),
        ("OtherOperationCount", ctypes.c_ulonglong),
        ("ReadTransferCount", ctypes.c_ulonglong),
        ("WriteTransferCount", ctypes.c_ulonglong),
        ("OtherTransferCount", ctypes.c_ulonglong),
    ]


class JOBOBJECT_EXTENDED_LIMIT_INFORMATION_STRUCT(ctypes.Structure):
    _fields_ = [
        ("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION),
        ("IoInfo", IO_COUNTERS),
        ("ProcessMemoryLimit", ctypes.c_size_t),
        ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryUsed", ctypes.c_size_t),
        ("PeakJobMemoryUsed", ctypes.c_size_t),
    ]


class JOBOBJECT_BASIC_ACCOUNTING_INFORMATION_STRUCT(ctypes.Structure):
    _fields_ = [
        ("TotalUserTime", ctypes.c_longlong),
        ("TotalKernelTime", ctypes.c_longlong),
        ("ThisPeriodTotalUserTime", ctypes.c_longlong),
        ("ThisPeriodTotalKernelTime", ctypes.c_longlong),
        ("TotalPageFaultCount", wintypes.DWORD),
        ("TotalProcesses", wintypes.DWORD),
        ("ActiveProcesses", wintypes.DWORD),
        ("TotalTerminatedProcesses", wintypes.DWORD),
    ]


class BoundedProcessError(RuntimeError):
    pass


def _assign_process(kernel32: Any, job: Any, process_handle: Any) -> bool:
    """Patch boundary used by the Windows failure-ordering regressions."""

    return bool(kernel32.AssignProcessToJobObject(job, process_handle))


def _start_reader(thread: threading.Thread) -> None:
    """Start capture only after assignment and before the child is resumed."""

    thread.start()


def _active_processes(kernel32: Any, job: Any) -> int:
    accounting = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION_STRUCT()
    if not kernel32.QueryInformationJobObject(
        job,
        JOB_OBJECT_BASIC_ACCOUNTING_INFORMATION,
        ctypes.byref(accounting),
        ctypes.sizeof(accounting),
        None,
    ):
        raise BoundedProcessError(
            f"QueryInformationJobObject failed: {ctypes.get_last_error()}"
        )
    return int(accounting.ActiveProcesses)


def _wait_for_empty_job(kernel32: Any, job: Any, *, timeout_seconds: float) -> None:
    deadline = time.monotonic() + timeout_seconds
    while _active_processes(kernel32, job):
        if time.monotonic() >= deadline:
            raise BoundedProcessError(
                "Windows process job retained active descendants past the reap bound"
            )
        time.sleep(0.01)


def _terminate_nonempty_job(kernel32: Any, job: Any, exit_code: int) -> None:
    if _active_processes(kernel32, job) and not kernel32.TerminateJobObject(
        job, exit_code
    ):
        raise BoundedProcessError(
            f"TerminateJobObject failed: {ctypes.get_last_error()}"
        )


def run_bounded(
    command: list[str],
    *,
    cwd: Path,
    environment: dict[str, str],
    timeout_seconds: float,
    output_limit_bytes: int = 16 * 1024 * 1024,
) -> subprocess.CompletedProcess[bytes]:
    if output_limit_bytes <= 0 or timeout_seconds <= 0:
        raise ValueError("process bounds must be positive")
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
    kernel32.CreateJobObjectW.restype = wintypes.HANDLE
    kernel32.SetInformationJobObject.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
    ]
    kernel32.SetInformationJobObject.restype = wintypes.BOOL
    kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
    kernel32.QueryInformationJobObject.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    kernel32.QueryInformationJobObject.restype = wintypes.BOOL
    kernel32.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
    kernel32.TerminateJobObject.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
    ntdll.NtResumeProcess.argtypes = [wintypes.HANDLE]
    ntdll.NtResumeProcess.restype = ctypes.c_long

    job = kernel32.CreateJobObjectW(None, None)
    if not job:
        raise BoundedProcessError(f"CreateJobObjectW failed: {ctypes.get_last_error()}")
    process: subprocess.Popen[bytes] | None = None
    thread: threading.Thread | None = None
    result: subprocess.CompletedProcess[bytes] | None = None
    failure: BaseException | None = None
    failure_traceback = None
    try:
        limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION_STRUCT()
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if not kernel32.SetInformationJobObject(
            job,
            JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
            ctypes.byref(limits),
            ctypes.sizeof(limits),
        ):
            raise BoundedProcessError(
                f"SetInformationJobObject failed: {ctypes.get_last_error()}"
            )
        process = subprocess.Popen(
            command,
            cwd=cwd,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            creationflags=CREATE_NO_WINDOW | CREATE_SUSPENDED,
        )
        if not _assign_process(
            kernel32, job, wintypes.HANDLE(process._handle)
        ):
            raise BoundedProcessError(
                f"AssignProcessToJobObject failed: {ctypes.get_last_error()}"
            )
        if process.stdout is None:
            raise BoundedProcessError("bounded process stdout pipe was not created")
        captured = bytearray()
        overflow = threading.Event()
        reader_failed = threading.Event()
        reader_errors: list[BaseException] = []

        def reader() -> None:
            try:
                while True:
                    block = process.stdout.read(64 * 1024)
                    if not block:
                        return
                    remaining = output_limit_bytes + 1 - len(captured)
                    if remaining > 0:
                        captured.extend(block[:remaining])
                    if len(captured) > output_limit_bytes:
                        overflow.set()
                        return
            except BaseException as exc:  # propagated on the supervising thread
                reader_errors.append(exc)
                reader_failed.set()

        thread = threading.Thread(target=reader, name="kazstem-bounded-capture", daemon=True)
        try:
            _start_reader(thread)
        except BaseException as exc:
            thread = None
            raise BoundedProcessError(
                f"cannot start bounded output reader: {exc}"
            ) from exc
        resume_status = int(ntdll.NtResumeProcess(wintypes.HANDLE(process._handle)))
        if resume_status < 0:
            raise BoundedProcessError(
                f"NtResumeProcess failed with NTSTATUS 0x{resume_status & 0xffffffff:08x}"
            )
        deadline = time.monotonic() + timeout_seconds
        timed_out = False
        while process.poll() is None:
            if reader_failed.is_set():
                _terminate_nonempty_job(kernel32, job, 0xE0000004)
                break
            if overflow.is_set():
                _terminate_nonempty_job(kernel32, job, 0xE0000001)
                break
            if time.monotonic() >= deadline:
                timed_out = True
                _terminate_nonempty_job(kernel32, job, 0xE0000002)
                break
            time.sleep(0.02)
        # A successful direct child is not permission to leave a detached
        # grandchild. Reap it, but fail the command instead of silently
        # converting a process-tree escape into success.
        abnormal_termination = reader_failed.is_set() or overflow.is_set() or timed_out
        if abnormal_termination:
            _terminate_nonempty_job(kernel32, job, 0xE0000007)
        else:
            descendants_after_direct_exit = _active_processes(kernel32, job)
            if descendants_after_direct_exit:
                _terminate_nonempty_job(kernel32, job, 0xE0000005)
                _wait_for_empty_job(kernel32, job, timeout_seconds=20)
                raise BoundedProcessError(
                    "direct child exited while the Windows job still contained "
                    f"{descendants_after_direct_exit} active descendant(s)"
                )
        _wait_for_empty_job(kernel32, job, timeout_seconds=20)
        try:
            process.wait(timeout=20)
        except subprocess.TimeoutExpired as exc:
            raise BoundedProcessError("job did not terminate within the reap bound") from exc
        thread.join(timeout=20)
        if thread.is_alive():
            raise BoundedProcessError("bounded output reader did not terminate")
        if reader_errors:
            raise BoundedProcessError(
                f"bounded output reader failed: {reader_errors[0]}"
            ) from reader_errors[0]
        if overflow.is_set():
            raise BoundedProcessError(
                f"process output exceeded {output_limit_bytes} bytes"
            )
        if timed_out:
            raise BoundedProcessError(
                f"process exceeded {timeout_seconds:g} seconds"
            )
        result = subprocess.CompletedProcess(
            command, process.returncode, bytes(captured), b""
        )
    except BaseException as exc:
        failure = exc
        failure_traceback = exc.__traceback__
    finally:
        cleanup_error: BaseException | None = None
        try:
            _terminate_nonempty_job(kernel32, job, 0xE0000006)
            _wait_for_empty_job(kernel32, job, timeout_seconds=20)
            if process is not None and process.poll() is None:
                # Assignment may have failed, in which case the suspended
                # direct child is not a job member and needs explicit reaping.
                process.kill()
                process.wait(timeout=20)
            if thread is not None:
                thread.join(timeout=20)
                if thread.is_alive():
                    raise BoundedProcessError(
                        "bounded output reader survived final cleanup"
                    )
        except BaseException as exc:
            cleanup_error = exc
        if not kernel32.CloseHandle(job) and cleanup_error is None:
            cleanup_error = BoundedProcessError(
                f"CloseHandle(job) failed: {ctypes.get_last_error()}"
            )
        if failure is not None:
            if cleanup_error is not None and hasattr(failure, "add_note"):
                failure.add_note(f"process cleanup also failed: {cleanup_error}")
        elif cleanup_error is not None:
            failure = cleanup_error
            failure_traceback = cleanup_error.__traceback__
    if failure is not None:
        raise failure.with_traceback(failure_traceback)
    if result is None:
        raise BoundedProcessError("bounded process completed without a result")
    return result
