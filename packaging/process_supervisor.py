#!/usr/bin/env python3
"""Bound subprocess streams and contain descendants for release tooling.

The production release boundary is Linux. There every top-level command runs
inside a dedicated systemd user slice with exact ``TasksMax``/``pids.max``;
the supervisor writes ``cgroup.kill`` and waits for
``cgroup.events: populated 0`` before returning. Inside that kernel boundary
it also acts as a child subreaper, inventories descendants by
``(pid, /proc starttime)``, and kills/reaps every newly adopted descendant.
Other POSIX systems retain process-group containment for source-only tests;
the returned containment label makes that weaker boundary explicit.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
import ctypes
import json
import os
from pathlib import Path
import platform
import selectors
import signal
import subprocess
import sys
import tempfile
import time
from typing import Mapping, Sequence
import unicodedata


PR_SET_CHILD_SUBREAPER = 36
DEFAULT_FORK_CAP = 4096
POLL_SECONDS = 0.01
CLEANUP_SECONDS = 3.0
SYSTEMD_RESULT_SCHEMA = "kazstem-systemd-cgroup-worker-result-v1"
SYSTEMD_UNIT_PREFIX = "kazstem-release-"
SYSTEMD_START_SECONDS = 10.0


class SupervisionError(RuntimeError):
    """A command exceeded its resource or process-containment contract."""


class PaxFormatError(ValueError):
    """A POSIX.1-2001 extended-header record is not strict/canonical."""


def parse_pax_records(
    data: bytes,
    *,
    path_cap: int,
    allowed_keys: frozenset[str],
) -> dict[str, str]:
    """Parse a complete strict PAX body and reject every undeclared override.

    Callers choose a deliberately small exact key set for their archive type.
    The dangerous ``size`` override is forbidden irrespective of that set.
    Global PAX headers are rejected by the physical scanner before this helper
    is called, so the returned mapping always applies to one following member.
    """

    if (
        not isinstance(data, bytes)
        or isinstance(path_cap, bool)
        or not isinstance(path_cap, int)
        or path_cap <= 0
        or not isinstance(allowed_keys, frozenset)
        or any(not isinstance(key, str) or not key for key in allowed_keys)
    ):
        raise PaxFormatError("invalid strict PAX parser contract")
    offset = 0
    result: dict[str, str] = {}
    while offset < len(data):
        separator = data.find(b" ", offset)
        if separator < 0:
            raise PaxFormatError("malformed PAX metadata length")
        raw_length = data[offset:separator]
        if (
            not raw_length.isdigit()
            or raw_length.startswith(b"0")
            or len(raw_length) > 20
        ):
            raise PaxFormatError("malformed PAX metadata length")
        length = int(raw_length)
        if raw_length != str(length).encode("ascii"):
            raise PaxFormatError("noncanonical PAX metadata length")
        end = offset + length
        if (
            length <= separator - offset + 3
            or end > len(data)
            or data[end - 1 : end] != b"\n"
        ):
            raise PaxFormatError("truncated PAX metadata record")
        record = data[separator + 1 : end - 1]
        raw_key, equals, raw_value = record.partition(b"=")
        if not equals or not raw_key:
            raise PaxFormatError("invalid PAX metadata record")
        try:
            key = raw_key.decode("utf-8")
            value = raw_value.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise PaxFormatError("PAX metadata is not UTF-8") from exc
        if key == "size":
            raise PaxFormatError("PAX size overrides are forbidden")
        if (
            key in result
            or key not in allowed_keys
            or not value
            or unicodedata.normalize("NFC", key) != key
            or unicodedata.normalize("NFC", value) != value
            or any(ord(character) < 33 or ord(character) == 127 for character in key)
            or any(ord(character) < 32 or ord(character) == 127 for character in value)
        ):
            raise PaxFormatError("forbidden, duplicate, or noncanonical PAX metadata")
        if key in {"path", "linkpath"} and len(raw_value) > path_cap:
            raise PaxFormatError("PAX path metadata exceeds archive path cap")
        result[key] = value
        offset = end
    if offset != len(data) or not result:
        raise PaxFormatError("empty or malformed PAX metadata body")
    return result


@dataclass(frozen=True)
class ProcessIdentity:
    pid: int
    starttime: int
    ppid: int


@dataclass(frozen=True)
class Completed:
    returncode: int
    stdout: bytes
    stderr: bytes
    containment: str
    observed_descendants: int
    descendant_peak: int
    extra_streams: dict[str, bytes]
    cgroup_tasks_max: int | None
    cgroup_kill_written: bool
    cgroup_populated_zero: bool


_SUBREAPER_ENABLED = False


def _enable_linux_subreaper() -> bool:
    global _SUBREAPER_ENABLED
    if platform.system() != "Linux":
        return False
    if _SUBREAPER_ENABLED:
        return True
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0:
        error = ctypes.get_errno()
        raise SupervisionError(
            f"cannot enable PR_SET_CHILD_SUBREAPER: errno={error}"
        )
    _SUBREAPER_ENABLED = True
    return True


def _process_identity(pid: int) -> ProcessIdentity | None:
    if platform.system() != "Linux":
        return None
    try:
        value = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
        closing = value.rfind(")")
        if closing < 0:
            return None
        fields = value[closing + 2 :].split()
        # fields[0] is state (proc field 3), fields[1] is PPID (field 4),
        # and fields[19] is starttime (field 22).
        return ProcessIdentity(pid, int(fields[19]), int(fields[1]))
    except (FileNotFoundError, PermissionError, OSError, UnicodeError, ValueError):
        return None


def _descendants(parent_pid: int) -> dict[tuple[int, int], ProcessIdentity]:
    if platform.system() != "Linux":
        return {}
    processes: dict[int, ProcessIdentity] = {}
    for entry in Path("/proc").glob("[0-9]*"):
        try:
            pid = int(entry.name)
        except ValueError:
            continue
        identity = _process_identity(pid)
        if identity is not None:
            processes[pid] = identity
    result: dict[tuple[int, int], ProcessIdentity] = {}
    frontier = {parent_pid}
    while frontier:
        children = {
            identity.pid
            for identity in processes.values()
            if identity.ppid in frontier
            and (identity.pid, identity.starttime) not in result
        }
        for pid in children:
            identity = processes[pid]
            result[(pid, identity.starttime)] = identity
        frontier = children
    return result


def _pidfd(identity: ProcessIdentity) -> int | None:
    opener = getattr(os, "pidfd_open", None)
    if opener is None:
        return None
    try:
        return opener(identity.pid, 0)
    except (OSError, PermissionError, ProcessLookupError):
        return None


def _kill_identity(identity: ProcessIdentity, pidfd: int | None) -> None:
    sender = getattr(signal, "pidfd_send_signal", None)
    if pidfd is not None and sender is not None:
        try:
            sender(pidfd, signal.SIGKILL)
        except ProcessLookupError:
            pass
        return
    current = _process_identity(identity.pid)
    if current is None or current.starttime != identity.starttime:
        return
    try:
        os.kill(identity.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def _kill_process_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except PermissionError:
        # macOS can report EPERM in the narrow exit/reap race.  Still kill the
        # exact direct child object if it remains alive; Linux production uses
        # the independently inventoried descendant sweep as well.
        if process.poll() is None:
            process.kill()


def _reap_identity(identity: ProcessIdentity) -> None:
    try:
        os.waitpid(identity.pid, os.WNOHANG)
    except (ChildProcessError, ProcessLookupError):
        pass


def _run_bounded_direct(
    argv: Sequence[str],
    *,
    cwd: Path,
    environment: Mapping[str, str],
    timeout: float,
    max_stdout: int,
    max_stderr: int,
    input_data: bytes | None = None,
    fork_cap: int = DEFAULT_FORK_CAP,
    extra_stream_caps: Mapping[str, int] | None = None,
) -> Completed:
    """Direct process-group/subreaper implementation used inside a cgroup."""
    if (
        not argv
        or any(not isinstance(item, str) or not item for item in argv)
        or timeout <= 0
        or max_stdout <= 0
        or max_stderr <= 0
        or fork_cap <= 0
    ):
        raise SupervisionError("invalid bounded-process invocation")
    if os.name != "posix":
        raise SupervisionError("release subprocess supervision requires POSIX")
    extra_caps = dict(extra_stream_caps or {})
    if any(
        not name
        or not isinstance(limit, int)
        or isinstance(limit, bool)
        or limit <= 0
        for name, limit in extra_caps.items()
    ):
        raise SupervisionError("invalid extra capture stream contract")
    actual_argv = list(argv)
    for name in sorted(extra_caps):
        token = "{supervisor_fd:" + name + "}"
        if sum(item.count(token) for item in actual_argv) != 1:
            raise SupervisionError(
                f"extra capture token must occur exactly once: {name}"
            )
    extra_pipes: dict[str, tuple[int, int]] = {
        name: os.pipe() for name in sorted(extra_caps)
    }
    for name, (_read_fd, write_fd) in extra_pipes.items():
        token = "{supervisor_fd:" + name + "}"
        fd_path = f"/proc/self/fd/{write_fd}" if platform.system() == "Linux" else f"/dev/fd/{write_fd}"
        actual_argv = [item.replace(token, fd_path) for item in actual_argv]
    linux = _enable_linux_subreaper()
    parent_pid = os.getpid()
    baseline = _descendants(parent_pid) if linux else {}
    if baseline:
        raise SupervisionError(
            "single-purpose supervisor has pre-existing descendant processes"
        )
    try:
        process = subprocess.Popen(
            actual_argv,
            cwd=cwd,
            env=dict(environment),
            stdin=subprocess.PIPE if input_data is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
            pass_fds=tuple(write_fd for _read_fd, write_fd in extra_pipes.values()),
        )
    except BaseException:
        for read_fd, write_fd in extra_pipes.values():
            os.close(read_fd)
            os.close(write_fd)
        raise
    for _read_fd, write_fd in extra_pipes.values():
        os.close(write_fd)
    direct_process_identity = _process_identity(process.pid) if linux else None
    direct_identity = (
        (direct_process_identity.pid, direct_process_identity.starttime)
        if direct_process_identity is not None
        else None
    )
    if process.stdout is None or process.stderr is None:
        _kill_process_group(process)
        process.wait()
        raise SupervisionError("cannot create bounded command pipes")

    selector = selectors.DefaultSelector()
    buffers = {
        "stdout": bytearray(),
        "stderr": bytearray(),
        **{f"extra:{name}": bytearray() for name in extra_pipes},
    }
    selector.register(process.stdout, selectors.EVENT_READ, ("read", "stdout"))
    selector.register(process.stderr, selectors.EVENT_READ, ("read", "stderr"))
    for name, (read_fd, _write_fd) in extra_pipes.items():
        os.set_blocking(read_fd, False)
        selector.register(read_fd, selectors.EVENT_READ, ("read", f"extra:{name}"))
    input_view = memoryview(input_data or b"")
    input_position = 0
    if process.stdin is not None:
        if input_view:
            os.set_blocking(process.stdin.fileno(), False)
            selector.register(process.stdin, selectors.EVENT_WRITE, ("write", "stdin"))
        else:
            process.stdin.close()
    for stream in (process.stdout, process.stderr):
        os.set_blocking(stream.fileno(), False)

    observed: dict[tuple[int, int], ProcessIdentity] = {}
    pidfds: dict[tuple[int, int], int] = {}
    descendant_peak = 0
    deadline = time.monotonic() + timeout
    failure: BaseException | None = None
    lingering = False
    fork_cap_breached = False

    def observe(*, enforce_cap: bool = True) -> dict[tuple[int, int], ProcessIdentity]:
        nonlocal descendant_peak, fork_cap_breached
        if not linux:
            return {}
        current = _descendants(parent_pid)
        new = {key: value for key, value in current.items() if key not in baseline}
        for key, identity in new.items():
            if key not in observed:
                observed[key] = identity
                descriptor = _pidfd(identity)
                if descriptor is not None:
                    pidfds[key] = descriptor
        descendant_peak = max(descendant_peak, len(new))
        if len(observed) > fork_cap:
            fork_cap_breached = True
        if fork_cap_breached and enforce_cap:
            raise SupervisionError("command exceeded descendant/fork inventory cap")
        return new

    try:
        while selector.get_map():
            try:
                current = observe()
            except BaseException as exc:
                failure = exc
                break
            if process.poll() is not None:
                remaining = {
                    key: identity
                    for key, identity in current.items()
                    if key != direct_identity
                }
                if remaining:
                    lingering = True
                    for key, identity in remaining.items():
                        _kill_identity(identity, pidfds.get(key))
                elif not linux:
                    try:
                        os.killpg(process.pid, 0)
                    except ProcessLookupError:
                        pass
                    else:
                        lingering = True
                        _kill_process_group(process)
            remaining_time = deadline - time.monotonic()
            if remaining_time <= 0:
                failure = SupervisionError("command exceeded timeout")
                break
            for key, _events in selector.select(min(POLL_SECONDS, remaining_time)):
                operation, label = key.data
                stream = key.fileobj
                if operation == "write":
                    try:
                        written = os.write(
                            stream.fileno(), input_view[input_position : input_position + 65536]
                        )
                    except BrokenPipeError:
                        written = 0
                    input_position += written
                    if written == 0 or input_position == len(input_view):
                        selector.unregister(stream)
                        stream.close()
                    continue
                try:
                    descriptor = stream if isinstance(stream, int) else stream.fileno()
                    chunk = os.read(descriptor, 65536)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(stream)
                    if isinstance(stream, int):
                        os.close(stream)
                    else:
                        stream.close()
                    continue
                buffer = buffers[label]
                buffer.extend(chunk)
                limit = (
                    max_stdout
                    if label == "stdout"
                    else max_stderr
                    if label == "stderr"
                    else extra_caps[label.removeprefix("extra:")]
                )
                if len(buffer) > limit:
                    failure = SupervisionError(
                        f"command {label} exceeded capture cap"
                    )
                    break
            if failure is not None:
                break
    except BaseException as exc:
        failure = exc
    finally:
        if failure is not None:
            _kill_process_group(process)
        elif process.poll() is None:
            try:
                process.wait(timeout=0.1)
            except subprocess.TimeoutExpired:
                failure = SupervisionError(
                    "command closed streams but direct process did not exit"
                )
                _kill_process_group(process)
        cleanup_deadline = time.monotonic() + CLEANUP_SECONDS
        while True:
            # Cleanup must never repeat the cap exception before descendants have
            # been killed and all descriptors have been closed.
            current = observe(enforce_cap=False) if linux else {}
            remaining = {
                key: identity
                for key, identity in current.items()
                if key != direct_identity
            }
            if remaining:
                lingering = True
                for key, identity in remaining.items():
                    _kill_identity(identity, pidfds.get(key))
                    _reap_identity(identity)
            if process.poll() is None:
                try:
                    process.wait(timeout=0.02)
                except subprocess.TimeoutExpired:
                    pass
            for identity in observed.values():
                _reap_identity(identity)
            if not remaining and process.poll() is not None:
                # A second scan closes the race with a last-moment fork/reparent.
                if not linux or not {
                    key: value
                    for key, value in _descendants(parent_pid).items()
                    if key not in baseline and key != direct_identity
                }:
                    break
            if time.monotonic() >= cleanup_deadline:
                previous = f"; prior failure: {failure}" if failure is not None else ""
                failure = SupervisionError(
                    "command descendants survived cleanup deadline" + previous
                )
                break
            time.sleep(POLL_SECONDS)
        for key in list(selector.get_map().values()):
            try:
                selector.unregister(key.fileobj)
            except (KeyError, ValueError):
                pass
            try:
                if isinstance(key.fileobj, int):
                    os.close(key.fileobj)
                else:
                    key.fileobj.close()
            except OSError:
                pass
        selector.close()
        if process.poll() is None:
            _kill_process_group(process)
            process.wait()

        if linux:
            final_remaining = {
                key: identity
                for key, identity in _descendants(parent_pid).items()
                if key not in baseline and key != direct_identity
            }
            if final_remaining:
                for key, identity in final_remaining.items():
                    _kill_identity(identity, pidfds.get(key))
                    _reap_identity(identity)
                previous = f"; prior failure: {failure}" if failure is not None else ""
                failure = SupervisionError(
                    "command containment ended with surviving descendants" + previous
                )
        for descriptor in pidfds.values():
            try:
                os.close(descriptor)
            except OSError:
                pass

    if fork_cap_breached and failure is None:
        failure = SupervisionError("command exceeded descendant/fork inventory cap")

    if failure is not None:
        if isinstance(failure, SupervisionError):
            raise failure
        raise SupervisionError(f"bounded command supervision failed: {failure}") from failure
    if lingering:
        raise SupervisionError("command left descendant processes running")
    return Completed(
        returncode=process.returncode,
        stdout=bytes(buffers["stdout"]),
        stderr=bytes(buffers["stderr"]),
        containment=(
            "linux-prctl-subreaper-proc-starttime-pidfd"
            if linux
            else "posix-process-group-source-test-only"
        ),
        observed_descendants=max(0, len(observed) - (1 if direct_identity else 0)),
        descendant_peak=max(0, descendant_peak - (1 if direct_identity else 0)),
        extra_streams={
            name: bytes(buffers[f"extra:{name}"]) for name in sorted(extra_pipes)
        },
        cgroup_tasks_max=None,
        cgroup_kill_written=False,
        cgroup_populated_zero=False,
    )


def _unified_cgroup_relative() -> str:
    try:
        lines = Path("/proc/self/cgroup").read_text(encoding="ascii").splitlines()
    except (OSError, UnicodeError) as exc:
        raise SupervisionError("cannot read the unified cgroup identity") from exc
    matches = [line[3:] for line in lines if line.startswith("0::/")]
    if len(matches) != 1:
        raise SupervisionError("process is not in exactly one unified cgroup")
    relative = "/" + matches[0].lstrip("/")
    if "\x00" in relative or any(part in {"", ".", ".."} for part in relative[1:].split("/")):
        raise SupervisionError("unified cgroup path is not canonical")
    return relative


def _cgroup_directory(relative: str, *, expected_unit: str | None) -> Path:
    root = Path("/sys/fs/cgroup").resolve(strict=True)
    candidate = (root / relative.lstrip("/")).resolve(strict=True)
    if candidate != root and root not in candidate.parents:
        raise SupervisionError("unified cgroup escaped cgroupfs")
    if expected_unit is not None and candidate.name != expected_unit:
        raise SupervisionError("systemd worker entered an unexpected cgroup")
    for name in ("cgroup.events", "cgroup.kill", "pids.max"):
        if not (candidate / name).is_file():
            raise SupervisionError(f"systemd cgroup lacks {name}")
    return candidate


def _read_pids_max(cgroup: Path) -> int:
    try:
        value = (cgroup / "pids.max").read_text(encoding="ascii").strip()
    except (OSError, UnicodeError) as exc:
        raise SupervisionError("cannot read cgroup pids.max") from exc
    if not value.isdigit() or int(value) <= 0:
        raise SupervisionError("systemd cgroup pids.max is not finite")
    return int(value)


def _read_cgroup_events_fd(descriptor: int) -> dict[str, int]:
    try:
        os.lseek(descriptor, 0, os.SEEK_SET)
        data = os.read(descriptor, 4096)
        text = data.decode("ascii")
    except (OSError, UnicodeError) as exc:
        raise SupervisionError("cannot read cgroup.events") from exc
    result: dict[str, int] = {}
    for line in text.splitlines():
        key, separator, raw_value = line.partition(" ")
        if not separator or not key or not raw_value.isdigit() or key in result:
            raise SupervisionError("cgroup.events is malformed")
        result[key] = int(raw_value)
    if "populated" not in result:
        raise SupervisionError("cgroup.events lacks populated")
    return result


def _json_file_create(path: Path, value: object) -> None:
    data = (json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "ascii"
    )
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        position = 0
        while position < len(data):
            position += os.write(descriptor, data[position:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _systemd_worker(request_path: Path) -> int:
    """Run one direct supervisor inside a bounded transient systemd service."""

    try:
        request = json.loads(request_path.read_text(encoding="ascii"))
        if not isinstance(request, dict) or set(request) != {
            "argv",
            "cwd",
            "environment",
            "expected_unit",
            "extra_stream_caps",
            "fork_cap",
            "input_data",
            "max_stderr",
            "max_stdout",
            "slice_relative",
            "tasks_max",
            "timeout",
        }:
            raise SupervisionError("systemd worker request fields differ")
        relative = _unified_cgroup_relative()
        service_cgroup = _cgroup_directory(
            relative, expected_unit=request["expected_unit"]
        )
        tasks_max = _read_pids_max(service_cgroup)
        slice_relative = request["slice_relative"]
        if (
            tasks_max != request["tasks_max"]
            or not isinstance(slice_relative, str)
            or not relative.startswith(slice_relative.rstrip("/") + "/")
        ):
            raise SupervisionError("systemd service/slice TasksMax placement differs")
        completed = _run_bounded_direct(
            request["argv"],
            cwd=Path(request["cwd"]),
            environment=request["environment"],
            timeout=request["timeout"],
            max_stdout=request["max_stdout"],
            max_stderr=request["max_stderr"],
            input_data=(
                None
                if request["input_data"] is None
                else base64.b64decode(request["input_data"], validate=True)
            ),
            fork_cap=request["fork_cap"],
            extra_stream_caps=request["extra_stream_caps"],
        )
        result = {
            "schema": SYSTEMD_RESULT_SCHEMA,
            "ok": True,
            "tasks_max": tasks_max,
            "returncode": completed.returncode,
            "stdout": base64.b64encode(completed.stdout).decode("ascii"),
            "stderr": base64.b64encode(completed.stderr).decode("ascii"),
            "observed_descendants": completed.observed_descendants,
            "descendant_peak": completed.descendant_peak,
            "extra_streams": {
                key: base64.b64encode(value).decode("ascii")
                for key, value in completed.extra_streams.items()
            },
        }
    except BaseException as exc:
        result = {
            "schema": SYSTEMD_RESULT_SCHEMA,
            "ok": False,
            "error_type": type(exc).__name__,
            "error": str(exc),
            "tasks_max": None,
        }
    encoded = (
        json.dumps(result, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("ascii")
    os.write(1, encoded)
    return 0


def _systemd_available() -> bool:
    if platform.system() != "Linux":
        return False
    runtime = Path(f"/run/user/{os.getuid()}")
    return (runtime / "bus").exists() and all(
        path.is_file()
        for path in (
            Path("/usr/bin/systemd-run"),
            Path("/usr/bin/systemctl"),
            Path("/sys/fs/cgroup/cgroup.controllers"),
        )
    )


def _inside_kazstem_systemd_scope() -> tuple[Path, int] | None:
    if platform.system() != "Linux":
        return None
    try:
        relative = _unified_cgroup_relative()
        cgroup = _cgroup_directory(relative, expected_unit=None)
        if not any(
            part.startswith(SYSTEMD_UNIT_PREFIX) and part.endswith(".service")
            for part in cgroup.parts
        ):
            return None
        return cgroup, _read_pids_max(cgroup)
    except (OSError, SupervisionError):
        return None


def _systemctl_cleanup(unit: str, *, kill: bool, revert: bool = False) -> None:
    base = [
        "/usr/bin/systemctl",
        "--user",
    ]
    commands = []
    if kill:
        commands.append(base + ["kill", "--kill-whom=all", "--signal=KILL", unit])
    commands.append(base + ["stop", unit])
    if revert:
        commands.append(base + ["revert", unit])
    commands.append(base + ["reset-failed", unit])
    control_environment = {
        "DBUS_SESSION_BUS_ADDRESS": f"unix:path=/run/user/{os.getuid()}/bus",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
        "XDG_RUNTIME_DIR": f"/run/user/{os.getuid()}",
    }
    for command in commands:
        process: subprocess.Popen[bytes] | None = None
        try:
            process = subprocess.Popen(
                command,
                env=control_environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
            process.wait(timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            try:
                if process is not None:
                    os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass


def _systemctl_output(arguments: list[str], environment: dict[str, str]) -> bytes:
    completed = _run_bounded_direct(
        ["/usr/bin/systemctl", "--user", *arguments],
        cwd=Path("/"),
        environment=environment,
        timeout=10,
        max_stdout=1024 * 1024,
        max_stderr=1024 * 1024,
        fork_cap=64,
    )
    if completed.returncode != 0:
        detail = completed.stderr[:4096].decode("utf-8", "replace")
        raise SupervisionError(
            f"systemctl {' '.join(arguments)} failed with exit "
            f"{completed.returncode}: {detail}"
        )
    return completed.stdout


def _decode_worker_result(
    value: object,
    *,
    extra_names: set[str],
) -> tuple[Completed | None, str, int | None]:
    if not isinstance(value, dict) or value.get("schema") != SYSTEMD_RESULT_SCHEMA:
        raise SupervisionError("systemd worker result schema differs")
    tasks_max = value.get("tasks_max")
    if value.get("ok") is not True:
        if not isinstance(value.get("error"), str) or not isinstance(
            value.get("error_type"), str
        ):
            raise SupervisionError("systemd worker failure record is malformed")
        return None, f"{value['error_type']}: {value['error']}", tasks_max
    expected = {
        "schema",
        "ok",
        "tasks_max",
        "returncode",
        "stdout",
        "stderr",
        "observed_descendants",
        "descendant_peak",
        "extra_streams",
    }
    if (
        set(value) != expected
        or isinstance(tasks_max, bool)
        or not isinstance(tasks_max, int)
    ):
        raise SupervisionError("systemd worker success fields differ")
    try:
        stdout = base64.b64decode(value["stdout"], validate=True)
        stderr = base64.b64decode(value["stderr"], validate=True)
        raw_extra = value["extra_streams"]
        if not isinstance(raw_extra, dict) or set(raw_extra) != extra_names:
            raise SupervisionError("systemd worker extra-stream inventory differs")
        extra = {
            key: base64.b64decode(raw_extra[key], validate=True)
            for key in sorted(raw_extra)
        }
    except (TypeError, ValueError) as exc:
        raise SupervisionError("systemd worker stream encoding is invalid") from exc
    for name in ("returncode", "observed_descendants", "descendant_peak"):
        if isinstance(value[name], bool) or not isinstance(value[name], int):
            raise SupervisionError("systemd worker numeric result is invalid")
    return (
        Completed(
            returncode=value["returncode"],
            stdout=stdout,
            stderr=stderr,
            containment=(
                "linux-systemd-user-service-cgroup-v2+"
                "prctl-subreaper-proc-starttime-pidfd"
            ),
            observed_descendants=value["observed_descendants"],
            descendant_peak=value["descendant_peak"],
            extra_streams=extra,
            cgroup_tasks_max=tasks_max,
            cgroup_kill_written=False,
            cgroup_populated_zero=False,
        ),
        "",
        tasks_max,
    )


def _run_bounded_systemd(
    argv: Sequence[str],
    *,
    cwd: Path,
    environment: Mapping[str, str],
    timeout: float,
    max_stdout: int,
    max_stderr: int,
    input_data: bytes | None,
    fork_cap: int,
    extra_stream_caps: Mapping[str, int] | None,
) -> Completed:
    tasks_max = fork_cap + 1
    random_token = os.urandom(8).hex()
    token = f"{os.getpid()}-{random_token}"
    unit = f"{SYSTEMD_UNIT_PREFIX}{token}.service"
    # Hyphens encode a hierarchy in systemd slice names.  Keep this leaf name
    # dash-free so stopping it cannot leave implicit parent slices behind.
    slice_unit = f"kazstemrelease{os.getpid()}{random_token}.slice"
    control_environment = {
        "DBUS_SESSION_BUS_ADDRESS": f"unix:path=/run/user/{os.getuid()}/bus",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
        "XDG_RUNTIME_DIR": f"/run/user/{os.getuid()}",
    }
    extra_caps = dict(extra_stream_caps or {})
    aggregate_cap = max_stdout + max_stderr + sum(extra_caps.values())
    result_cap = aggregate_cap * 2 + 1024 * 1024
    slice_cgroup: Path | None = None
    events_fd: int | None = None
    kill_written = False
    populated_zero = False
    with tempfile.TemporaryDirectory(prefix="kazstem-systemd-scope-") as temporary:
        communication = Path(temporary)
        os.chmod(communication, 0o700)
        request_path = communication / "request.json"
        try:
            _systemctl_output(["start", slice_unit], control_environment)
            _systemctl_output(
                ["set-property", "--runtime", slice_unit, f"TasksMax={tasks_max}"],
                control_environment,
            )
            raw_slice_relative = _systemctl_output(
                ["show", slice_unit, "--property=ControlGroup", "--value"],
                control_environment,
            )
            try:
                slice_relative = raw_slice_relative.decode("ascii").strip()
            except UnicodeError as exc:
                raise SupervisionError("systemd slice cgroup is not ASCII") from exc
            if not slice_relative:
                raise SupervisionError("systemd slice lacks a ControlGroup")
            slice_cgroup = _cgroup_directory(
                slice_relative, expected_unit=slice_unit
            )
            if _read_pids_max(slice_cgroup) != tasks_max:
                raise SupervisionError("systemd slice TasksMax/pids.max differs")
            events_fd = os.open(slice_cgroup / "cgroup.events", os.O_RDONLY)
        except BaseException:
            _systemctl_cleanup(slice_unit, kill=True, revert=True)
            raise
        request = {
            "argv": list(argv),
            "cwd": str(cwd),
            "environment": dict(environment),
            "expected_unit": unit,
            "extra_stream_caps": extra_caps,
            "fork_cap": fork_cap,
            "input_data": (
                None if input_data is None else base64.b64encode(input_data).decode("ascii")
            ),
            "max_stderr": max_stderr,
            "max_stdout": max_stdout,
            "slice_relative": slice_relative,
            "tasks_max": tasks_max,
            "timeout": timeout,
        }
        _json_file_create(request_path, request)
        command = [
            "/usr/bin/systemd-run",
            "--user",
            "--quiet",
            "--wait",
            "--pipe",
            "--collect",
            f"--unit={unit}",
            f"--slice={slice_unit}",
            "--property=Type=exec",
            f"--property=TasksMax={tasks_max}",
            "--property=KillMode=control-group",
            "--property=TimeoutStopSec=5s",
            "--",
            sys.executable,
            "-I",
            "-S",
            str(Path(__file__).resolve(strict=True)),
            "--systemd-worker",
            str(request_path),
        ]
        try:
            controller = _run_bounded_direct(
                command,
                cwd=Path("/"),
                environment=control_environment,
                timeout=timeout + SYSTEMD_START_SECONDS + CLEANUP_SECONDS,
                max_stdout=result_cap,
                max_stderr=1024 * 1024,
                fork_cap=64,
            )
            if controller.returncode != 0:
                detail = controller.stderr[:4096].decode("utf-8", "replace")
                raise SupervisionError(
                    f"systemd-run failed with exit {controller.returncode}: {detail}"
                )
            try:
                worker_value = json.loads(controller.stdout.decode("ascii"))
            except (UnicodeError, json.JSONDecodeError) as exc:
                raise SupervisionError("systemd worker output is not strict JSON") from exc
            completed, worker_error, observed_tasks_max = (
                _decode_worker_result(worker_value, extra_names=set(extra_caps))
            )
            if observed_tasks_max not in {None, tasks_max}:
                raise SupervisionError("systemd service TasksMax/pids.max proof differs")
            if slice_cgroup is None or events_fd is None:
                raise SupervisionError("systemd slice proof was not initialized")
            kill_fd = os.open(slice_cgroup / "cgroup.kill", os.O_WRONLY)
            try:
                os.write(kill_fd, b"1\n")
                kill_written = True
            finally:
                os.close(kill_fd)
            cleanup_deadline = time.monotonic() + CLEANUP_SECONDS
            while time.monotonic() < cleanup_deadline:
                if _read_cgroup_events_fd(events_fd)["populated"] == 0:
                    populated_zero = True
                    break
                time.sleep(POLL_SECONDS)
            if not populated_zero:
                raise SupervisionError("systemd slice remained populated after cgroup.kill")
            if worker_error:
                raise SupervisionError(f"contained worker failed: {worker_error}")
            if completed is None:
                raise SupervisionError("contained worker omitted its completion")
            return Completed(
                returncode=completed.returncode,
                stdout=completed.stdout,
                stderr=completed.stderr,
                containment=(
                    "linux-systemd-user-slice-cgroup-v2+"
                    "prctl-subreaper-proc-starttime-pidfd"
                ),
                observed_descendants=completed.observed_descendants,
                descendant_peak=completed.descendant_peak,
                extra_streams=completed.extra_streams,
                cgroup_tasks_max=tasks_max,
                cgroup_kill_written=kill_written,
                cgroup_populated_zero=populated_zero,
            )
        except BaseException as exc:
            if slice_cgroup is not None and not kill_written:
                try:
                    (slice_cgroup / "cgroup.kill").write_text("1\n", encoding="ascii")
                    kill_written = True
                except OSError:
                    pass
            if events_fd is not None and kill_written and not populated_zero:
                cleanup_deadline = time.monotonic() + CLEANUP_SECONDS
                while time.monotonic() < cleanup_deadline:
                    try:
                        if _read_cgroup_events_fd(events_fd)["populated"] == 0:
                            populated_zero = True
                            break
                    except SupervisionError:
                        break
                    time.sleep(POLL_SECONDS)
            _systemctl_cleanup(unit, kill=True)
            if not kill_written or not populated_zero:
                raise SupervisionError(
                    f"systemd cgroup cleanup proof failed; prior failure: {exc}"
                ) from exc
            raise
        finally:
            if events_fd is not None:
                try:
                    os.close(events_fd)
                except OSError:
                    pass
            _systemctl_cleanup(slice_unit, kill=not populated_zero, revert=True)


def run_bounded(
    argv: Sequence[str],
    *,
    cwd: Path,
    environment: Mapping[str, str],
    timeout: float,
    max_stdout: int,
    max_stderr: int,
    input_data: bytes | None = None,
    fork_cap: int = DEFAULT_FORK_CAP,
    extra_stream_caps: Mapping[str, int] | None = None,
) -> Completed:
    """Run with bounded streams and the strongest available process boundary."""

    inherited = _inside_kazstem_systemd_scope()
    if inherited is not None:
        _cgroup, tasks_max = inherited
        completed = _run_bounded_direct(
            argv,
            cwd=cwd,
            environment=environment,
            timeout=timeout,
            max_stdout=max_stdout,
            max_stderr=max_stderr,
            input_data=input_data,
            fork_cap=fork_cap,
            extra_stream_caps=extra_stream_caps,
        )
        return Completed(
            returncode=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
            containment=(
                "linux-inherited-systemd-user-service-cgroup-v2+"
                "prctl-subreaper-proc-starttime-pidfd"
            ),
            observed_descendants=completed.observed_descendants,
            descendant_peak=completed.descendant_peak,
            extra_streams=completed.extra_streams,
            cgroup_tasks_max=tasks_max,
            cgroup_kill_written=False,
            cgroup_populated_zero=False,
        )
    if _systemd_available():
        return _run_bounded_systemd(
            argv,
            cwd=cwd,
            environment=environment,
            timeout=timeout,
            max_stdout=max_stdout,
            max_stderr=max_stderr,
            input_data=input_data,
            fork_cap=fork_cap,
            extra_stream_caps=extra_stream_caps,
        )
    return _run_bounded_direct(
        argv,
        cwd=cwd,
        environment=environment,
        timeout=timeout,
        max_stdout=max_stdout,
        max_stderr=max_stderr,
        input_data=input_data,
        fork_cap=fork_cap,
        extra_stream_caps=extra_stream_caps,
    )


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--systemd-worker":
        raise SystemExit(_systemd_worker(Path(sys.argv[2])))
    raise SystemExit("process_supervisor.py is an internal helper")
