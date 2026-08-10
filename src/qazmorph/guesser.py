"""Bounded open-class guesses produced by the same Kazakh two-level grammar."""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass, replace
import math
import os
from pathlib import Path
import selectors
import subprocess
import sys
import threading
import time
from typing import Literal, Mapping, Sequence
import unicodedata
import warnings

from .backend import BackendError, FSTBackend, RESOURCE_MANIFEST_V2
from .stream import parse_analysis
from .tags import UD_PROFILES
from .types import Analysis


VOWELS = frozenset("аәеёиіоөұүуыэюя")
KAZAKH_CYRILLIC = frozenset("аәбвгғдеёжзийкқлмнңоөпрстуұүфхһцчшщъыіьэюя")
MAX_GUESS_SURFACE_LENGTH = 32
MAX_GUESS_REQUEST_BYTES = MAX_GUESS_SURFACE_LENGTH * 4
MAX_LOOKUP_REQUEST_BYTES = 4096
GUESS_CACHE_CAPACITY = 8192
CYCLE_MARKER = "[...cyclic...]"
WINDOWS_STDERR_BYTE_CAP = 65_536
WINDOWS_PIPE_READ_CHUNK = 65_536
STEM_FINAL_ALTERNATIONS = frozenset(
    {
        ("б", "п"),
        ("г", "к"),
        ("ғ", "қ"),
    }
)
LOW_INFORMATION = frozenset(
    {
        "n",
        "v",
        "adj",
        "tv",
        "iv",
        "nom",
        "attr",
        "subst",
        "advl",
        "cop",
        "aor",
        "p2",
        "p3",
        "sg",
        "pl",
    }
)


class _LookupTimeout(BackendError):
    pass


class _LookupFailure(BackendError):
    pass


class _LookupProtocolFailure(_LookupFailure):
    """A complete process response that violates the HFST wire grammar."""

    pass


@dataclass(frozen=True, slots=True)
class _LookupResponse:
    """A bounded response plus whether its terminating record was observed."""

    lines: tuple[str, ...]
    complete: bool
    reason: str | None = None


@dataclass(frozen=True, slots=True)
class _GuessOutcome:
    """One cache-stable result without collapsing failure into a true zero."""

    candidates: tuple[Analysis, ...]
    complete: bool
    reason: str | None = None


def productive_root_kind(
    surface: str, lemma: str
) -> Literal["identity", "stem_final_alternation"] | None:
    """Classify the exact bounded relation accepted for an unknown root.

    The baseline is a nonempty identity-copied surface prefix. Kazakh
    intervocalic stem-final voicing is additionally licensed once, immediately
    before a nonempty suffix. No epsilon-bearing root template is accepted.
    """

    word = surface.casefold()
    root = lemma.casefold()
    if not root or len(root) > len(word):
        return None
    if word.startswith(root):
        return "identity"
    surface_root = word[: len(root)]
    if (
        len(root) >= 2
        and len(root) < len(word)
        and surface_root[:-1] == root[:-1]
        and (surface_root[-1], root[-1]) in STEM_FINAL_ALTERNATIONS
    ):
        return "stem_final_alternation"
    return None


class _PersistentLookupWorker:
    """One serialized, restartable ``hfst-lookup`` pipe.

    In ``--pipe-mode=both``, HFST flushes a blank-line-terminated response for
    every input line.  Waiting for that terminator lets us distinguish a
    complete result from a timeout or crashed process; partial output is never
    mistaken for a complete guess lattice.
    """

    def __init__(
        self,
        command: Sequence[str],
        environment: Mapping[str, str],
        *,
        working_directory: Path | None = None,
    ) -> None:
        self.command = tuple(command)
        self.environment = dict(environment)
        self.working_directory = working_directory
        self._process: subprocess.Popen[bytes] | None = None
        self._pending = b""
        self._stderr_buffer = bytearray()
        self._owner_pid = os.getpid()
        self._lock = threading.RLock()
        self.start_count = 0
        self.cap_abort_count = 0
        self.cycle_truncation_count = 0
        self.idle_restart_count = 0
        self.protocol_restart_count = 0
        self.oneshot_reap_count = 0
        self.leading_separator_record_count = 0
        self.leading_separator_byte_count = 0
        # Production helpers accept options immediately after argv[0]. Tests
        # may run a Python script explicitly and move this insertion point
        # past the interpreter and script path.
        self._windows_option_index = 1

    def _ensure_process_identity(self) -> None:
        # A lock held by another thread at fork remains permanently locked in
        # the child.  Replace it before attempting acquisition there.
        if os.getpid() != self._owner_pid:
            self._lock = threading.RLock()
            self._discard_inherited_process()

    def _discard_inherited_process(self) -> None:
        """Detach pipes inherited across ``fork`` without killing the parent worker."""

        process = self._process
        self._process = None
        self._pending = b""
        self._stderr_buffer.clear()
        self._owner_pid = os.getpid()
        if process is None:
            return
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream is not None:
                try:
                    stream.close()
                except OSError:
                    pass
        # This Popen object refers to the parent's still-running child.  Mark
        # only the inherited Python wrapper as settled so its destructor in
        # the forked process neither warns nor attempts parent-owned cleanup.
        process.returncode = 0

    def _start(self) -> subprocess.Popen[bytes]:
        self._ensure_process_identity()
        process = self._process
        if process is not None and process.poll() is None:
            return process
        if process is not None:
            returncode = process.returncode
            detail = self._stderr(process)
            self._process = None
            self._close_streams(process)
            suffix = f": {detail}" if detail else ""
            self.idle_restart_count += 1
            warnings.warn(
                "HFST guesser lookup exited between queries"
                f"{f' with status {returncode}' if returncode is not None else ''}{suffix}; "
                "restarting before the next query",
                RuntimeWarning,
                stacklevel=4,
            )
        try:
            process = subprocess.Popen(
                self.command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=self.environment,
                cwd=(
                    str(self.working_directory)
                    if sys.platform == "win32" and self.working_directory
                    else None
                ),
                bufsize=0,
            )
        except OSError as exc:
            raise _LookupFailure(f"HFST guesser lookup could not start: {exc}") from exc
        self._process = process
        self._pending = b""
        self._stderr_buffer.clear()
        self._owner_pid = os.getpid()
        self.start_count += 1
        return process

    @staticmethod
    def _close_streams(process: subprocess.Popen[bytes]) -> None:
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream is not None:
                try:
                    stream.close()
                except OSError:
                    pass

    def _remember_stderr(self, chunk: bytes) -> None:
        self._stderr_buffer.extend(chunk)
        overflow = len(self._stderr_buffer) - 8192
        if overflow > 0:
            del self._stderr_buffer[:overflow]

    def _stderr(self, process: subprocess.Popen[bytes]) -> str:
        if process.stderr is None or process.poll() is None:
            return self._stderr_buffer.decode("utf-8", errors="replace").strip()
        try:
            self._remember_stderr(process.stderr.read(8192))
        except OSError:
            pass
        return self._stderr_buffer.decode("utf-8", errors="replace").strip()

    def _abort(self) -> None:
        process = self._process
        self._process = None
        self._pending = b""
        if process is None:
            return
        if os.getpid() == self._owner_pid and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=0.2)
            except subprocess.TimeoutExpired:
                process.kill()
            process.wait()
        self._close_streams(process)

    def _reset_after_protocol_error(
        self, *, retrying: bool, timeout: float | None = None
    ) -> bool:
        """Discard an uncorrelated response without escaping the caller deadline."""

        self._ensure_process_identity()
        if timeout is None:
            acquired = self._lock.acquire()
        else:
            acquired = self._lock.acquire(blocking=False)
            if not acquired and timeout > 0:
                acquired = self._lock.acquire(timeout=timeout)
        if not acquired:
            return False
        try:
            if retrying:
                self.protocol_restart_count += 1
            self._abort()
            return True
        finally:
            self._lock.release()

    def _discard_buffered_response_separators(self) -> tuple[int, int]:
        """Consume buffered blank records and return record/byte counts."""

        records = 0
        discarded_bytes = 0
        while True:
            if self._pending.startswith(b"\r\n"):
                self._pending = self._pending[2:]
                records += 1
                discarded_bytes += 2
                continue
            if self._pending.startswith(b"\n"):
                self._pending = self._pending[1:]
                records += 1
                discarded_bytes += 1
                continue
            return records, discarded_bytes

    @staticmethod
    def _decode_response_record(raw_line: bytes, *, context: str) -> str:
        """Decode exactly one LF-delimited HFST record, rejecting ambiguity."""

        if raw_line.endswith(b"\r"):
            raw_line = raw_line[:-1]
        if b"\r" in raw_line:
            raise _LookupProtocolFailure(f"{context} contains a bare CR")
        try:
            decoded = raw_line.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise _LookupProtocolFailure(f"{context} is not valid UTF-8") from exc
        printable = decoded.replace("\t", "")
        if printable and not printable.isprintable():
            raise _LookupProtocolFailure(
                f"{context} contains a Unicode control or separator"
            )
        return decoded

    @staticmethod
    def _candidate_analysis_shape_valid(candidate: str) -> bool:
        """Match the parser's cheap acceptance gate without projecting UD twice."""

        if (
            not candidate
            or candidate.startswith("*")
            or candidate.endswith("+?")
        ):
            return False

        # ``parse_analysis`` first splits on unescaped ``+`` and then searches
        # each part for ``<([^<>]+)>``.  Mirror only that acceptance predicate
        # here; the caller still performs the full projection exactly once when
        # materializing candidates.  This avoids doing all UD/morpheme work a
        # second time solely for protocol validation.
        escaped = False
        tag_length = -1
        for character in candidate:
            was_escaped = escaped
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True

            if character == "+" and not was_escaped:
                tag_length = -1
            elif character == "<":
                tag_length = 0
            elif character == ">":
                if tag_length > 0:
                    return True
                tag_length = -1
            elif tag_length >= 0:
                tag_length += 1
        return False

    def close(self) -> None:
        """Close the pipe; a later query may lazily start a fresh worker."""

        self._ensure_process_identity()
        with self._lock:
            process = self._process
            self._process = None
            self._pending = b""
            if process is None:
                return
            if process.stdin is not None:
                try:
                    process.stdin.close()
                except OSError:
                    pass
            if process.poll() is None:
                try:
                    process.wait(timeout=1.0)
                except subprocess.TimeoutExpired:
                    process.terminate()
                    try:
                        process.wait(timeout=0.2)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()
            self._close_streams(process)

    def query(
        self,
        surface: str,
        *,
        max_lines: int,
        timeout: float,
        max_bytes: int,
        max_request_bytes: int = MAX_LOOKUP_REQUEST_BYTES,
    ) -> _LookupResponse:
        integer_bounds = (max_lines, max_bytes, max_request_bytes)
        if (
            any(
                not isinstance(bound, int)
                or isinstance(bound, bool)
                or bound < 1
                for bound in integer_bounds
            )
            or not isinstance(timeout, (int, float))
            or isinstance(timeout, bool)
            or not math.isfinite(timeout)
            or timeout <= 0
        ):
            raise ValueError("HFST lookup bounds must be positive")
        if not isinstance(surface, str):
            raise ValueError("HFST lookup surface must be a string")
        if any(character in surface for character in "\r\n\0"):
            raise ValueError("HFST lookup surface contains a record delimiter")
        encoded_surface = surface.encode("utf-8")
        if len(encoded_surface) > max_request_bytes:
            raise ValueError(
                "HFST lookup request exceeds the encoded byte limit "
                f"({len(encoded_surface)} > {max_request_bytes})"
            )
        request = encoded_surface + b"\n"

        self._ensure_process_identity()
        deadline = time.monotonic() + float(timeout)
        acquired = self._lock.acquire(blocking=False)
        if not acquired:
            remaining = deadline - time.monotonic()
            if remaining > 0:
                acquired = self._lock.acquire(timeout=remaining)
            if not acquired:
                raise _LookupTimeout(
                    f"HFST guesser lookup for {surface!r} timed out after "
                    f"{timeout:.3f}s; partial response discarded"
                )
        try:
            if sys.platform == "win32":
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise _LookupTimeout(
                        f"HFST guesser lookup for {surface!r} timed out after "
                        f"{timeout:.3f}s; partial response discarded"
                    )
                response = self._query_windows_oneshot(
                    surface,
                    max_lines=max_lines,
                    timeout=remaining,
                    max_bytes=max_bytes,
                )
                if time.monotonic() >= deadline:
                    raise _LookupTimeout(
                        f"HFST guesser lookup for {surface!r} timed out after "
                        f"{timeout:.3f}s during response validation; "
                        "response discarded"
                    )
                return response
            process = self._start()
            assert process.stdin is not None and process.stdout is not None
            if time.monotonic() >= deadline:
                self._abort()
                raise _LookupTimeout(
                    f"HFST guesser lookup for {surface!r} timed out after "
                    f"{timeout:.3f}s while starting the worker; "
                    "partial response discarded"
                )

            stdin_fd = process.stdin.fileno()
            try:
                os.set_blocking(stdin_fd, False)
            except OSError as exc:
                self._abort()
                raise _LookupFailure(
                    f"HFST guesser lookup could not make stdin nonblocking: {exc}"
                ) from exc

            request_offset = 0
            write_selector = selectors.DefaultSelector()
            write_selector.register(process.stdin, selectors.EVENT_WRITE, "stdin")
            if process.stderr is not None:
                write_selector.register(process.stderr, selectors.EVENT_READ, "stderr")
            try:
                while request_offset < len(request):
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        self._abort()
                        raise _LookupTimeout(
                            f"HFST guesser lookup for {surface!r} timed out after "
                            f"{timeout:.3f}s while writing the request; "
                            "partial request discarded"
                        )
                    events = write_selector.select(remaining)
                    if not events:
                        self._abort()
                        raise _LookupTimeout(
                            f"HFST guesser lookup for {surface!r} timed out after "
                            f"{timeout:.3f}s while writing the request; "
                            "partial request discarded"
                        )
                    for key, _ in events:
                        if key.data == "stderr":
                            stderr_chunk = os.read(key.fileobj.fileno(), 65536)
                            if stderr_chunk:
                                self._remember_stderr(stderr_chunk)
                            else:
                                write_selector.unregister(key.fileobj)
                            continue
                        try:
                            written = os.write(stdin_fd, request[request_offset:])
                        except BlockingIOError:
                            continue
                        except (BrokenPipeError, OSError) as exc:
                            returncode = process.poll()
                            detail = self._stderr(process)
                            self._abort()
                            suffix = f": {detail}" if detail else ""
                            raise _LookupFailure(
                                "HFST guesser lookup pipe failed"
                                f"{f' ({returncode})' if returncode is not None else ''}"
                                f"{suffix}"
                            ) from exc
                        if written <= 0:
                            self._abort()
                            raise _LookupFailure(
                                "HFST guesser lookup pipe accepted zero request bytes"
                            )
                        request_offset += written
            finally:
                write_selector.close()

            selector = selectors.DefaultSelector()
            selector.register(process.stdout, selectors.EVENT_READ, "stdout")
            if process.stderr is not None:
                selector.register(process.stderr, selectors.EVENT_READ, "stderr")
            consumed = 0
            lines: list[str] = []
            try:
                while True:
                    newline = self._pending.find(b"\n")
                    if newline >= 0:
                        raw_line = self._pending[:newline]
                        self._pending = self._pending[newline + 1 :]
                        consumed += newline + 1
                        if consumed > max_bytes:
                            # This is an explicit deterministic response cap,
                            # not a load-dependent timeout.  Retain only the
                            # same complete-line prefix as the former bounded
                            # one-shot implementation and restart on demand.
                            self.cap_abort_count += 1
                            self._abort()
                            return _LookupResponse(
                                tuple(lines), False, "response_cap"
                            )
                        if raw_line in {b"", b"\r"}:
                            separator_records = 1
                            separator_bytes = newline + 1
                            extra_records, extra_bytes = (
                                self._discard_buffered_response_separators()
                            )
                            separator_records += extra_records
                            separator_bytes += extra_bytes
                            consumed += extra_bytes
                            if not lines:
                                self.leading_separator_record_count += separator_records
                                self.leading_separator_byte_count += separator_bytes
                            if consumed > max_bytes:
                                self.cap_abort_count += 1
                                self._abort()
                                return _LookupResponse(
                                    tuple(lines), False, "response_cap"
                                )
                            if not lines:
                                # A delayed redundant terminator from the prior
                                # response must not become this query's empty
                                # response. Keep waiting for a keyed record under
                                # the original deadline and byte cap.
                                continue
                            return _LookupResponse(tuple(lines), True)
                        try:
                            decoded_line = self._decode_response_record(
                                raw_line,
                                context="HFST guesser lookup response record",
                            )
                        except _LookupProtocolFailure:
                            self._abort()
                            raise
                        if CYCLE_MARKER in decoded_line:
                            # This is a semantic HFST truncation, not a regular
                            # candidate.  Count it even for direct/raw callers;
                            # the public guess path below then fails closed.
                            self.cycle_truncation_count += 1
                        if len(lines) < max_lines:
                            lines.append(decoded_line)
                        if len(lines) >= max_lines:
                            _, discarded_bytes = (
                                self._discard_buffered_response_separators()
                            )
                            consumed += discarded_bytes
                            if consumed > max_bytes:
                                self.cap_abort_count += 1
                                self._abort()
                                return _LookupResponse(
                                    tuple(lines), False, "response_cap"
                                )
                            if discarded_bytes:
                                # The response has exactly ``max_lines`` and
                                # its terminator arrived in the same read; the
                                # worker remains synchronized and reusable.
                                return _LookupResponse(tuple(lines), True)
                            # hfst-lookup cannot limit non-optimized FST
                            # results itself.  Ending this worker at the exact
                            # public prefix cap avoids an unbounded drain while
                            # preserving candidate order and cap semantics.
                            self.cap_abort_count += 1
                            self._abort()
                            return _LookupResponse(
                                tuple(lines), False, "response_cap"
                            )
                        continue

                    buffered = consumed + len(self._pending)
                    if buffered >= max_bytes:
                        self.cap_abort_count += 1
                        self._abort()
                        return _LookupResponse(tuple(lines), False, "response_cap")
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        self._abort()
                        raise _LookupTimeout(
                            f"HFST guesser lookup for {surface!r} timed out after {timeout:.3f}s; "
                            "partial response discarded"
                        )
                    events = selector.select(remaining)
                    if not events:
                        returncode = process.poll()
                        if returncode is None:
                            self._abort()
                            raise _LookupTimeout(
                                f"HFST guesser lookup for {surface!r} timed out after "
                                f"{timeout:.3f}s; "
                                "partial response discarded"
                            )
                        detail = self._stderr(process)
                        self._abort()
                        suffix = f": {detail}" if detail else ""
                        raise _LookupFailure(
                            f"HFST guesser lookup exited with status {returncode} "
                            f"before completing a response{suffix}"
                        )
                    stdout_ready = False
                    for key, _ in events:
                        if key.data == "stdout":
                            stdout_ready = True
                            continue
                        stderr_chunk = os.read(key.fileobj.fileno(), 65536)
                        if stderr_chunk:
                            self._remember_stderr(stderr_chunk)
                        else:
                            selector.unregister(key.fileobj)
                    if not stdout_ready:
                        continue
                    chunk = os.read(
                        process.stdout.fileno(),
                        min(65536, max_bytes + 1 - buffered),
                    )
                    if not chunk:
                        try:
                            returncode = process.wait(timeout=0.2)
                        except subprocess.TimeoutExpired:
                            returncode = process.poll()
                        detail = self._stderr(process)
                        self._abort()
                        suffix = f": {detail}" if detail else ""
                        raise _LookupFailure(
                            "HFST guesser lookup closed its output"
                            f"{f' with status {returncode}' if returncode is not None else ''} "
                            f"before completing a response{suffix}"
                        )
                    self._pending += chunk
            finally:
                selector.close()
        finally:
            self._lock.release()

    def _query_windows_oneshot(
        self,
        surface: str,
        *,
        max_lines: int,
        timeout: float,
        max_bytes: int,
    ) -> _LookupResponse:
        """Use a bounded fresh HFST process where pipe selectors are invalid.

        CPython's Windows selector accepts sockets, not anonymous subprocess
        pipes.  A blocking selector around ``hfst-optimized-lookup`` would
        therefore fail with ``WSAENOTSOCK``. Keeping HFST pipe mode is required
        for redirected stdin on Windows; closing stdin after one query supplies
        an unambiguous EOF boundary and the bounded runner supplies a strong
        process-level timeout. It is intentionally less optimized than the
        POSIX persistent worker, but preserves correctness and cleanup.
        """

        command = self._windows_oneshot_command(max_lines=max_lines)

        self._stderr_buffer.clear()
        self.start_count += 1
        try:
            completed = self._run_windows_bounded(
                command,
                input=(surface + "\n").encode("utf-8"),
                timeout=timeout,
                max_stdout_bytes=max_bytes,
            )
        except subprocess.TimeoutExpired as exc:
            self.idle_restart_count += 1
            raise _LookupTimeout(
                f"HFST guesser lookup for {surface!r} timed out after {timeout:.3f}s; "
                "partial response discarded"
            ) from exc
        if completed.returncode:
            detail = self._stderr_buffer.decode(
                "utf-8", errors="replace"
            ).strip()
            suffix = f": {detail}" if detail else ""
            raise _LookupFailure(
                f"HFST guesser lookup exited with status {completed.returncode} "
                f"before completing a response{suffix}"
            )
        return self._parse_windows_oneshot_response(
            completed.stdout,
            max_lines=max_lines,
            max_bytes=max_bytes,
        )

    def _windows_oneshot_command(self, *, max_lines: int) -> list[str]:
        base_command = list(self.command)
        # Both hfst-optimized-lookup (``--analyses``) and hfst-lookup
        # (``--max-number``) spell their result bound ``-n``. Request one
        # candidate beyond the public prefix: its presence is a completeness
        # sentinel that makes the parser fail closed instead of caching a
        # silently truncated lattice. The exact Project.JJ executables are
        # probed for this option on the native Windows runner.
        option_index = min(self._windows_option_index, len(base_command))
        command = [
            *base_command[:option_index],
            "-n",
            str(max_lines + 1),
            *base_command[option_index:],
        ]
        return command

    def _run_windows_bounded(
        self,
        command: Sequence[str],
        *,
        input: bytes,
        timeout: float,
        max_stdout_bytes: int,
    ) -> subprocess.CompletedProcess[bytes]:
        """Run one helper with hard in-memory pipe bounds and guaranteed reap.

        Windows anonymous pipes cannot be consumed with ``selectors``. Two
        reader threads keep stdout and stderr independent so either stream can
        fill without deadlocking the child. The stdout reader retains at most
        ``max_stdout_bytes + 1`` bytes and stderr retains only the existing
        8-KiB diagnostic ring while counting up to a fixed hard cap. Crossing
        either boundary signals the owner thread to terminate and reap the
        process; no partial payload is returned to the protocol parser.
        """

        started = time.monotonic()
        try:
            process = subprocess.Popen(
                command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=self.environment,
                cwd=str(self.working_directory) if self.working_directory else None,
                bufsize=0,
            )
        except OSError as exc:
            raise _LookupFailure(f"HFST guesser lookup could not start: {exc}") from exc

        assert process.stdin is not None
        assert process.stdout is not None
        assert process.stderr is not None
        stop_requested = threading.Event()
        stdout_chunks: list[bytes] = []
        failures: list[tuple[str, BaseException | None]] = []

        def fail(kind: str, error: BaseException | None = None) -> None:
            failures.append((kind, error))
            stop_requested.set()

        def read_stdout() -> None:
            retained = 0
            try:
                while True:
                    request = min(
                        WINDOWS_PIPE_READ_CHUNK,
                        max_stdout_bytes + 1 - retained,
                    )
                    if request <= 0:
                        fail("stdout-cap")
                        return
                    chunk = process.stdout.read(request)
                    if not chunk:
                        return
                    stdout_chunks.append(chunk)
                    retained += len(chunk)
                    if retained > max_stdout_bytes:
                        fail("stdout-cap")
                        return
            except (OSError, ValueError) as exc:
                fail("stdout-read", exc)

        def read_stderr() -> None:
            observed = 0
            try:
                while True:
                    request = min(
                        WINDOWS_PIPE_READ_CHUNK,
                        WINDOWS_STDERR_BYTE_CAP + 1 - observed,
                    )
                    if request <= 0:
                        fail("stderr-cap")
                        return
                    chunk = process.stderr.read(request)
                    if not chunk:
                        return
                    observed += len(chunk)
                    self._remember_stderr(chunk)
                    if observed > WINDOWS_STDERR_BYTE_CAP:
                        fail("stderr-cap")
                        return
            except (OSError, ValueError) as exc:
                fail("stderr-read", exc)

        readers = [
            threading.Thread(target=read_stdout, name="kazstem-hfst-stdout", daemon=True),
            threading.Thread(target=read_stderr, name="kazstem-hfst-stderr", daemon=True),
        ]
        started_readers: list[threading.Thread] = []
        timed_out = False
        input_error: BaseException | None = None
        try:
            try:
                for reader in readers:
                    reader.start()
                    started_readers.append(reader)
            except RuntimeError as exc:
                raise _LookupFailure(
                    f"HFST guesser lookup pipe reader could not start: {exc}"
                ) from exc
            try:
                process.stdin.write(input)
                process.stdin.close()
            except (BrokenPipeError, OSError, ValueError) as exc:
                input_error = exc

            deadline = started + timeout
            while process.poll() is None and not stop_requested.is_set():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    timed_out = True
                    break
                stop_requested.wait(min(remaining, 0.02))

            if timed_out or stop_requested.is_set():
                self._terminate_and_reap(process)
            else:
                process.wait()

            for reader in started_readers:
                reader.join(timeout=1.0)
            if any(reader.is_alive() for reader in started_readers):
                self._terminate_and_reap(process)
                fail("reader-cleanup")
                for stream in (process.stdout, process.stderr):
                    try:
                        stream.close()
                    except OSError:
                        pass
                for reader in started_readers:
                    reader.join(timeout=0.5)
            if any(reader.is_alive() for reader in started_readers):
                raise _LookupFailure(
                    "HFST guesser lookup pipe reader did not stop after process cleanup"
                )
        finally:
            if process.poll() is None:
                self._terminate_and_reap(process)
            else:
                process.wait()
            for reader in started_readers:
                reader.join(timeout=0.5)
            lingering_readers = [
                reader for reader in started_readers if reader.is_alive()
            ]
            if lingering_readers:
                for stream in (process.stdout, process.stderr):
                    try:
                        stream.close()
                    except (OSError, ValueError):
                        pass
                for reader in lingering_readers:
                    reader.join(timeout=0.5)
            self._close_streams(process)
            self.oneshot_reap_count += 1
            if any(reader.is_alive() for reader in started_readers):
                raise _LookupFailure(
                    "HFST guesser lookup pipe reader survived process cleanup"
                )

        if timed_out:
            raise subprocess.TimeoutExpired(command, timeout)
        kinds = {kind for kind, _error in failures}
        if "stdout-cap" in kinds:
            self.cap_abort_count += 1
            raise _LookupFailure(
                "HFST guesser lookup exceeded the byte cap; partial response discarded"
            )
        if "stderr-cap" in kinds:
            raise _LookupFailure(
                "HFST guesser lookup exceeded the stderr byte cap; response discarded"
            )
        if failures:
            kind, error = failures[0]
            raise _LookupFailure(
                f"HFST guesser lookup {kind.replace('-', ' ')} failed: {error}"
            ) from error
        if input_error is not None and process.returncode == 0:
            raise _LookupFailure(
                f"HFST guesser lookup input pipe failed: {input_error}"
            ) from input_error
        return subprocess.CompletedProcess(
            args=list(command),
            returncode=process.returncode,
            stdout=b"".join(stdout_chunks),
            stderr=bytes(self._stderr_buffer),
        )

    @staticmethod
    def _terminate_and_reap(process: subprocess.Popen[bytes]) -> None:
        if process.poll() is not None:
            process.wait()
            return
        try:
            process.terminate()
        except OSError:
            pass
        try:
            process.wait(timeout=0.25)
            return
        except subprocess.TimeoutExpired:
            pass
        try:
            process.kill()
        except OSError:
            pass
        try:
            process.wait(timeout=1.0)
        except subprocess.TimeoutExpired as exc:
            raise _LookupFailure(
                "HFST guesser lookup process could not be reaped after termination"
            ) from exc

    def _parse_windows_oneshot_response(
        self,
        payload: bytes,
        *,
        max_lines: int,
        max_bytes: int,
    ) -> _LookupResponse:
        """Parse one EOF-bounded HFST response without accepting partial data.

        Only LF records with an optional immediately preceding CR are valid.
        Python's ``bytes.splitlines`` recognizes additional control characters
        as separators and replacement decoding hides corrupt output, so both
        are deliberately avoided here.  Unlike the persistent POSIX prefix
        cap, a one-shot response is already fully available: exceeding either
        cap fails closed instead of returning candidates from an incomplete
        prefix that could enter the OOV cache.
        """

        if len(payload) > max_bytes:
            self.cap_abort_count += 1
            raise _LookupFailure(
                "HFST guesser lookup exceeded the byte cap; partial response "
                "discarded"
            )
        if payload and not payload.endswith(b"\n"):
            raise _LookupProtocolFailure(
                "one-shot HFST response is not terminated by LF"
            )

        raw_records = payload[:-1].split(b"\n") if payload else []
        lines: list[str] = []
        saw_terminator = False
        for raw_line in raw_records:
            if raw_line in {b"", b"\r"}:
                saw_terminator = True
                continue
            if saw_terminator:
                raise _LookupProtocolFailure(
                    "one-shot HFST response has output after its blank terminator"
                )
            decoded_line = self._decode_response_record(
                raw_line,
                context="one-shot HFST response record",
            )
            if len(lines) >= max_lines:
                self.cap_abort_count += 1
                raise _LookupFailure(
                    "HFST guesser lookup exceeded the line cap; partial response "
                    "discarded"
                )
            if CYCLE_MARKER in decoded_line:
                self.cycle_truncation_count += 1
            lines.append(decoded_line)
        return _LookupResponse(tuple(lines), True)


class OpenClassGuesser:
    """Query a deliberately overgenerating FST and retain a safe finite prefix."""

    def __init__(
        self, backend: FSTBackend, *, ud_profile: str = "universal"
    ) -> None:
        if ud_profile not in UD_PROFILES:
            raise ValueError(f"unknown UD projection profile: {ud_profile}")
        self.backend = backend
        self.ud_profile = ud_profile
        self._optimized = bool(
            getattr(
                self.backend,
                "guesser_optimized",
                self.backend.guesser_path.suffix == ".hfstol",
            )
        )
        self._productive_safe = bool(
            getattr(
                self.backend,
                "guesser_productive_safe",
                getattr(self.backend, "manifest", {}).get("schema")
                != RESOURCE_MANIFEST_V2,
            )
        )
        command = (
            [
                str(self.backend.hfst_optimized_lookup),
                "-q",
                "--pipe-mode=both",
                str(self.backend.guesser_path),
            ]
            if self._optimized
            else [
                str(self.backend.hfst_lookup),
                "-q",
                "--pipe-mode=both",
                "-i",
                str(self.backend.guesser_path),
                "-c",
                "0",
            ]
        )
        helper = Path(command[0])
        self._worker = _PersistentLookupWorker(
            command,
            self.backend.environment,
            working_directory=helper.parent if helper.is_absolute() else None,
        )
        self._cache: OrderedDict[
            tuple[str, int, bool], _GuessOutcome
        ] = OrderedDict()
        self._cache_lock = threading.RLock()
        self._owner_pid = os.getpid()
        self._diagnostics = {
            "cache_hits": 0,
            "cache_misses": 0,
            "lookup_queries": 0,
            "prefilter_skips": 0,
            "unsafe_resource_skips": 0,
            "timeouts": 0,
            "failures": 0,
        }

    def close(self) -> None:
        self._worker.close()

    def _ensure_process_identity(self) -> None:
        if os.getpid() != self._owner_pid:
            self._cache_lock = threading.RLock()
            # Detach inherited worker pipes even when the next operation is a
            # cache hit and therefore never reaches ``worker.query``.
            self._worker._ensure_process_identity()
            self._owner_pid = os.getpid()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            # Destructors run during partially torn-down interpreter states.
            pass

    @property
    def diagnostics(self) -> dict[str, int]:
        """Return a snapshot of bounded-lookup behavior for audits/benchmarks."""

        self._ensure_process_identity()
        with self._cache_lock:
            return {
                **self._diagnostics,
                "cache_entries": len(self._cache),
                "worker_starts": self._worker.start_count,
                "cap_aborts": self._worker.cap_abort_count,
                "cycle_truncations": self._worker.cycle_truncation_count,
                "idle_restarts": self._worker.idle_restart_count,
                "protocol_restarts": self._worker.protocol_restart_count,
                "oneshot_reaps": self._worker.oneshot_reap_count,
                "leading_separator_records": (
                    self._worker.leading_separator_record_count
                ),
                "leading_separator_bytes": self._worker.leading_separator_byte_count,
                "productive_resource_safe": int(self._productive_safe),
            }

    @property
    def available(self) -> bool:
        return bool(
            (
                self.backend.hfst_optimized_lookup
                if self._optimized
                else self.backend.hfst_lookup
            )
            and self._productive_safe
            and self.backend.guesser_path.is_file()
        )

    def _raw_lookup(
        self,
        surface: str,
        *,
        max_lines: int = 512,
        timeout: float = 2.0,
        max_bytes: int = 1_500_000,
    ) -> list[str]:
        return list(
            self._raw_lookup_detailed(
                surface,
                max_lines=max_lines,
                timeout=timeout,
                max_bytes=max_bytes,
            ).lines
        )

    def _raw_lookup_detailed(
        self,
        surface: str,
        *,
        max_lines: int = 512,
        timeout: float = 2.0,
        max_bytes: int = 1_500_000,
    ) -> _LookupResponse:
        if not self.available:
            return _LookupResponse((), False, "unavailable")
        first_problem: str | None = None
        if (
            not isinstance(timeout, (int, float))
            or isinstance(timeout, bool)
            or not math.isfinite(timeout)
            or timeout <= 0
        ):
            raise ValueError("HFST lookup timeout must be finite and positive")
        deadline = time.monotonic() + float(timeout)
        for attempt in range(2):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise _LookupTimeout(
                    f"HFST guesser lookup for {surface!r} timed out after "
                    f"{timeout:.3f}s; partial response discarded"
                )
            try:
                response = self._worker.query(
                    surface,
                    max_lines=max_lines,
                    timeout=remaining,
                    max_bytes=max_bytes,
                    max_request_bytes=MAX_GUESS_REQUEST_BYTES,
                )
                problem = self._response_protocol_problem(
                    surface, response.lines
                )
            except _LookupProtocolFailure as exc:
                problem = str(exc)
                response = _LookupResponse((), False, "protocol_failure")
            if time.monotonic() >= deadline:
                raise _LookupTimeout(
                    f"HFST guesser lookup for {surface!r} timed out after "
                    f"{timeout:.3f}s during response validation; "
                    "response discarded"
                )
            if problem is None:
                return response
            if attempt == 0:
                first_problem = problem
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not self._worker._reset_after_protocol_error(
                    retrying=True, timeout=remaining
                ):
                    raise _LookupTimeout(
                        f"HFST guesser lookup for {surface!r} timed out after "
                        f"{timeout:.3f}s while restarting after a protocol error; "
                        "response discarded"
                    )
                continue
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not self._worker._reset_after_protocol_error(
                retrying=False, timeout=remaining
            ):
                raise _LookupTimeout(
                    f"HFST guesser lookup for {surface!r} timed out after "
                    f"{timeout:.3f}s while discarding a protocol error; "
                    "response discarded"
                )
            if time.monotonic() >= deadline:
                raise _LookupTimeout(
                    f"HFST guesser lookup for {surface!r} timed out after "
                    f"{timeout:.3f}s while discarding a protocol error; "
                    "response discarded"
                )
            raise _LookupFailure(
                "HFST guesser lookup protocol could not correlate a complete "
                f"response for {surface!r} after one restart "
                f"(first response: {first_problem}; second response: {problem})"
            )
        raise AssertionError("bounded HFST protocol retry did not terminate")

    def _response_protocol_problem(
        self, surface: str, lines: Sequence[str]
    ) -> str | None:
        if not lines:
            return "zero lines"
        candidate_records = 0
        negative_records = 0
        for line in lines:
            fields = line.split("\t")
            if not fields:
                return "empty record"
            if fields[0] != surface:
                return f"surface {fields[0]!r}"
            if self._optimized:
                if fields == [surface, surface, "+?"]:
                    negative_records += 1
                    continue
                if len(fields) != 2:
                    return "optimized record does not have exactly two fields"
            else:
                if fields == [surface, f"{surface}+?", "inf"]:
                    negative_records += 1
                    continue
                if len(fields) != 3:
                    return "standard record does not have exactly three fields"
                try:
                    weight = float(fields[2])
                except ValueError:
                    return "standard record has a nonnumeric weight"
                if not math.isfinite(weight):
                    return "standard candidate has a nonfinite weight"

            candidate = fields[1]
            if not candidate:
                return "empty candidate"
            if any(character in candidate for character in "[]{}"):
                return "candidate contains a control marker"
            if not self._worker._candidate_analysis_shape_valid(candidate):
                return "candidate is not a valid analysis"
            candidate_records += 1
        if negative_records:
            if negative_records != 1:
                return "duplicate negative records"
            if candidate_records:
                return "mixed negative and candidate records"
        return None

    @staticmethod
    def _eligible_surface(surface: str) -> bool:
        """Limit productive guessing to simple, bounded Kazakh Cyrillic words."""

        return (
            bool(surface)
            and len(surface) <= MAX_GUESS_SURFACE_LENGTH
            and surface == unicodedata.normalize("NFC", surface)
            and all(character.casefold() in KAZAKH_CYRILLIC for character in surface)
            # Three identical code points in a row are an elongation/noise
            # pattern in this scope and can trigger enormous noisy lattices.
            and not any(
                surface[index] == surface[index + 1] == surface[index + 2]
                for index in range(len(surface) - 2)
            )
        )

    @staticmethod
    def _plausibility(surface: str, analysis: Analysis) -> float | None:
        lemma = analysis.lemma.casefold()
        word = surface.casefold()
        if len(lemma) < 2 or not any(char in VOWELS for char in lemma):
            return None
        if any(char in lemma for char in "<>[]{}"):
            return None
        if lemma.endswith(("ь", "ъ")) or "ыы" in lemma or "іі" in lemma:
            return None
        if len(lemma) > len(word) + 2:
            return None

        informative = [tag for tag in analysis.tags if tag not in LOW_INFORMATION]
        stripped = max(0, len(word) - len(lemma))
        score = 0.35 + 1.15 * len(informative) + 0.18 * stripped
        if analysis.upos == "NOUN":
            score += 0.75
            has_possessor = any(tag.startswith("px") for tag in analysis.tags)
            has_case = any(tag in analysis.tags for tag in ("gen", "dat", "acc", "abl", "loc", "ins"))
            if "pl" in analysis.tags and has_possessor and has_case:
                # A complete plural + possessive + case chain is much stronger
                # evidence than a coincidental verbal suffix boundary.
                score += 2.4
            elif has_possessor and has_case:
                score += 1.0
        elif analysis.upos == "ADJ" and "subst" in analysis.tags:
            score += 0.1
        if any(tag in analysis.tags for tag in ("neg", "pass", "caus", "comp")):
            score += 0.7
        if lemma == word:
            score -= 1.0
        if analysis.raw.endswith("<imp><p2><sg>") and lemma == word:
            score -= 0.8
        return score

    def _guess_uncached_detailed(
        self,
        surface: str,
        limit: int,
        generate_all: bool,
        timeout: float,
    ) -> _GuessOutcome:
        if not self._productive_safe:
            self._diagnostics["unsafe_resource_skips"] += 1
            return _GuessOutcome((), False, "unsafe_resource")
        if not self._eligible_surface(surface):
            self._diagnostics["prefilter_skips"] += 1
            return _GuessOutcome((), True)

        candidates: dict[tuple[str, str, tuple[tuple[str, str], ...], str], Analysis] = {}
        scored: list[tuple[float, Analysis]] = []
        self._diagnostics["lookup_queries"] += 1
        try:
            raw_response = self._raw_lookup_detailed(
                surface,
                max_lines=2048 if generate_all else 512,
                timeout=timeout,
            )
        except _LookupTimeout as exc:
            self._diagnostics["timeouts"] += 1
            warnings.warn(
                f"{exc}; returning an explicit unknown analysis for this OOV",
                RuntimeWarning,
                stacklevel=3,
            )
            return _GuessOutcome((), False, "timeout")
        except _LookupFailure as exc:
            self._diagnostics["failures"] += 1
            warnings.warn(
                f"{exc}; returning an explicit unknown analysis for this OOV",
                RuntimeWarning,
                stacklevel=3,
            )
            return _GuessOutcome((), False, "failure")

        raw_lines = raw_response.lines
        if any(CYCLE_MARKER in line for line in raw_lines):
            warnings.warn(
                "HFST guesser reported a cyclic response; discarding partial "
                "candidates and returning an explicit unknown analysis for this OOV",
                RuntimeWarning,
                stacklevel=3,
            )
            return _GuessOutcome((), False, "cyclic_response")

        for line in raw_lines:
            if not line:
                continue
            fields = line.split("\t")
            if (
                fields == [surface, surface, "+?"]
                or fields == [surface, f"{surface}+?", "inf"]
            ):
                continue
            if len(fields) < 2 or fields[0] != surface:
                continue
            parsed = parse_analysis(
                fields[1],
                source="guesser",
                guessed=True,
                ud_profile=self.ud_profile,
            )
            if parsed is None:
                continue
            if productive_root_kind(surface, parsed.lemma) is None:
                continue
            score = self._plausibility(surface, parsed)
            if score is None:
                continue
            parsed = replace(parsed, score=score)
            old = candidates.get(parsed.identity)
            if old is None or (old.score if old.score is not None else -math.inf) < score:
                candidates[parsed.identity] = parsed

        scored.extend(
            ((analysis.score if analysis.score is not None else -math.inf), analysis)
            for analysis in candidates.values()
        )
        scored.sort(key=lambda item: (-item[0], len(item[1].lemma), item[1].raw))
        cap = 256 if generate_all else max(1, limit)
        selected = [analysis for _, analysis in scored[:cap]]
        if not selected:
            return _GuessOutcome(
                (), raw_response.complete, raw_response.reason
            )

        # Scores in the public API are normalized within the returned lattice.
        numeric_scores = [analysis.score if analysis.score is not None else -math.inf for analysis in selected]
        peak = max(numeric_scores)
        weights = [math.exp(score - peak) for score in numeric_scores]
        total = sum(weights)
        return _GuessOutcome(
            tuple(
                replace(analysis, score=weight / total)
                for analysis, weight in zip(selected, weights)
            ),
            raw_response.complete,
            raw_response.reason,
        )

    def _guess_uncached(
        self, surface: str, limit: int, generate_all: bool
    ) -> tuple[Analysis, ...]:
        """Compatibility wrapper for the pre-outcome private helper."""

        return self._guess_uncached_detailed(
            surface, limit, generate_all, 2.0
        ).candidates

    def _guess_detailed(
        self,
        surface: str,
        *,
        limit: int = 8,
        generate_all: bool = False,
        timeout: float = 2.0,
    ) -> _GuessOutcome:
        if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
            raise ValueError("guess limit must be positive")
        if (
            not isinstance(timeout, (int, float))
            or isinstance(timeout, bool)
            or not math.isfinite(timeout)
            or timeout <= 0
        ):
            raise ValueError("guess timeout must be finite and positive")
        key = (surface, limit, generate_all)
        self._ensure_process_identity()
        deadline = time.monotonic() + float(timeout)
        acquired = self._cache_lock.acquire(blocking=False)
        if not acquired:
            remaining = deadline - time.monotonic()
            if remaining > 0:
                acquired = self._cache_lock.acquire(timeout=remaining)
            if not acquired:
                self._diagnostics["timeouts"] += 1
                warnings.warn(
                    f"guesser cache wait for {surface!r} timed out after "
                    f"{timeout:.3f}s; returning an explicit unknown analysis for this OOV",
                    RuntimeWarning,
                    stacklevel=3,
                )
                return _GuessOutcome((), False, "timeout")
        try:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                self._diagnostics["timeouts"] += 1
                return _GuessOutcome((), False, "timeout")
            cached = self._cache.get(key)
            if cached is not None:
                self._diagnostics["cache_hits"] += 1
                self._cache.move_to_end(key)
                return cached
            self._diagnostics["cache_misses"] += 1
            outcome = self._guess_uncached_detailed(
                surface,
                limit,
                generate_all,
                remaining,
            )
            if outcome.complete and time.monotonic() >= deadline:
                self._diagnostics["timeouts"] += 1
                warnings.warn(
                    f"guesser processing for {surface!r} timed out after "
                    f"{timeout:.3f}s; returning an explicit unknown analysis for this OOV",
                    RuntimeWarning,
                    stacklevel=3,
                )
                outcome = _GuessOutcome((), False, "timeout")
            # Alternate deadlines are diagnostic probes and must not create an
            # unbounded family of cache policies.  The public two-second path
            # retains both candidates and the completion bit, including a
            # stable instance-local failure fallback.
            if timeout == 2.0:
                self._cache[key] = outcome
                self._cache.move_to_end(key)
                if len(self._cache) > GUESS_CACHE_CAPACITY:
                    self._cache.popitem(last=False)
            return outcome
        finally:
            self._cache_lock.release()

    def _guess_cached(
        self, surface: str, limit: int, generate_all: bool
    ) -> tuple[Analysis, ...]:
        return self._guess_detailed(
            surface,
            limit=limit,
            generate_all=generate_all,
        ).candidates

    def guess(self, surface: str, *, limit: int = 8, generate_all: bool = False) -> list[Analysis]:
        return list(self._guess_cached(surface, limit, generate_all))
