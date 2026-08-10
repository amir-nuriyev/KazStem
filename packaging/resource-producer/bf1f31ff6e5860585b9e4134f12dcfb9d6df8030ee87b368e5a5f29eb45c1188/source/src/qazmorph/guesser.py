"""Bounded open-class guesses produced by the same Kazakh two-level grammar."""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass, replace
import math
import os
import selectors
import subprocess
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
STEM_FINAL_ALTERNATIONS = frozenset(
    {
        ("б", "п"),
        ("г", "к"),
        ("ғ", "қ"),
    }
)
NOUN_HIGH_VOWEL_SYNCOPE = frozenset("ыі")
SYNCOPE_FINAL_CONSONANTS = frozenset("бвгғджзйкқлмнңпрстфхһцчшщьъ")
LOAN_BACK_SUFFIX_INITIALS = frozenset("аы")
LOAN_BACK_HARMONY_LEMMA_SUFFIX = "кубок"
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


def _lemma_key(analysis: Analysis) -> str:
    """Return the canonical root key used for bounded result diversity."""

    return unicodedata.normalize("NFC", analysis.lemma).casefold()


def _depthwise_lemma_interleave(
    ranked: Sequence[Analysis], cap: int
) -> list[Analysis]:
    """Keep stable plausibility order while preventing one root monopolizing a cap.

    Each root's first candidate is emitted before any root's second candidate,
    then second candidates before third candidates, and so on.  Consequently,
    every root present in the old top-k remains present in the new top-k: its
    first occurrence had at most k distinct roots at or ahead of it.
    """

    groups: OrderedDict[str, list[Analysis]] = OrderedDict()
    for analysis in ranked:
        groups.setdefault(_lemma_key(analysis), []).append(analysis)

    interleaved: list[Analysis] = []
    depth = 0
    while len(interleaved) < cap:
        layer = [items[depth] for items in groups.values() if depth < len(items)]
        if not layer:
            break
        interleaved.extend(layer)
        depth += 1
    return interleaved[:cap]


def productive_surface_eligible(surface: str) -> bool:
    """Return whether ``surface`` may enter the bounded productive relation.

    This is the single public prefilter shared by analysis and productive
    generation.  Keeping the predicate here prevents the generator from
    returning a surface which the public analyzer will reject before lookup.
    """

    return (
        bool(surface)
        and len(surface) <= MAX_GUESS_SURFACE_LENGTH
        and surface == unicodedata.normalize("NFC", surface)
        and all(character.casefold() in KAZAKH_CYRILLIC for character in surface)
        # Three identical code points in a row are an elongation/noise pattern
        # in this scope and can trigger enormous noisy lattices.
        and not any(
            surface[index] == surface[index + 1] == surface[index + 2]
            for index in range(len(surface) - 2)
        )
    )


def productive_root_eligible(lemma: str) -> bool:
    """Return whether an exact lowercase lemma can survive public guessing."""

    return (
        productive_surface_eligible(lemma)
        and lemma == lemma.casefold()
        and len(lemma) >= 2
        and any(character in VOWELS for character in lemma)
        and not lemma.endswith(("ь", "ъ"))
        and "ыы" not in lemma
        and "іі" not in lemma
    )


class _LookupTimeout(BackendError):
    pass


class _LookupFailure(BackendError):
    pass


@dataclass(frozen=True, slots=True)
class _LookupResponse:
    lines: tuple[str, ...]
    complete: bool
    reason: str | None = None


@dataclass(frozen=True, slots=True)
class _GuessOutcome:
    """One cache-stable guess result, including whether lookup was complete."""

    candidates: tuple[Analysis, ...]
    complete: bool
    reason: str | None = None


def productive_root_kind(
    surface: str,
    lemma: str,
    tags: Sequence[str] | None = None,
) -> Literal[
    "identity",
    "stem_final_alternation",
    "noun_high_vowel_syncope",
    "loan_back_harmony_kubok",
] | None:
    """Classify the exact bounded relation accepted for an unknown root.

    The baseline is a nonempty identity-copied surface prefix. Kazakh
    intervocalic stem-final voicing is additionally licensed once, immediately
    before a nonempty suffix. Two narrower noun-only paths are also accepted:
    one bounded output-only high vowel immediately before the final root
    consonant, and back-harmony inflection of the literal ``кубок`` compound
    head. The latter is deliberately not generalized to arbitrary ``г``/``к``
    pairs because forms such as ``блогы`` and ``каталогы`` would hallucinate
    the lemmas ``блок`` and ``каталок``.
    """

    word = surface.casefold()
    root = lemma.casefold()
    if not root or len(root) > len(word):
        return None
    if word.startswith(root):
        return "identity"
    surface_root = word[: len(root)]
    noun_reading = bool(tags) and tags[0] == "n"
    if (
        len(root) >= 2
        and len(root) < len(word)
        and surface_root[:-1] == root[:-1]
        and (surface_root[-1], root[-1]) in STEM_FINAL_ALTERNATIONS
    ):
        suffix = word[len(root) :]
        if (
            (surface_root[-1], root[-1]) == ("г", "к")
            and suffix[:1] in LOAN_BACK_SUFFIX_INITIALS
        ):
            if noun_reading and root.endswith(LOAN_BACK_HARMONY_LEMMA_SUFFIX):
                return "loan_back_harmony_kubok"
            return None
        return "stem_final_alternation"
    if (
        noun_reading
        and len(root) >= 3
        and root[-2] in NOUN_HIGH_VOWEL_SYNCOPE
        and root[-1] in SYNCOPE_FINAL_CONSONANTS
    ):
        contracted_root = root[:-2] + root[-1]
        if len(contracted_root) < len(word) and word.startswith(contracted_root):
            return "noun_high_vowel_syncope"
    return None


class _PersistentLookupWorker:
    """One serialized, restartable ``hfst-lookup`` pipe.

    In ``--pipe-mode=both``, HFST flushes a blank-line-terminated response for
    every input line.  Waiting for that terminator lets us distinguish a
    complete result from a timeout or crashed process; partial output is never
    mistaken for a complete guess lattice.
    """

    def __init__(self, command: Sequence[str], environment: Mapping[str, str]) -> None:
        self.command = tuple(command)
        self.environment = dict(environment)
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
        self.leading_separator_record_count = 0
        self.leading_separator_byte_count = 0

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

    def _reset_after_protocol_error(self, *, retrying: bool) -> None:
        """Discard an uncorrelated worker response before a bounded retry."""

        self._ensure_process_identity()
        with self._lock:
            if retrying:
                self.protocol_restart_count += 1
            self._abort()

    def _discard_buffered_response_separators(self) -> tuple[int, int]:
        """Consume buffered blank records and return their record/byte counts."""

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
        if (
            max_lines < 1
            or max_bytes < 1
            or max_request_bytes < 1
            or not isinstance(timeout, (int, float))
            or isinstance(timeout, bool)
            or not math.isfinite(timeout)
            or timeout <= 0
        ):
            raise ValueError("HFST lookup bounds must be positive")
        if any(character in surface for character in "\r\n\0"):
            raise ValueError("HFST lookup surface contains a record delimiter")
        request = surface.encode("utf-8")
        if len(request) > max_request_bytes:
            raise ValueError(
                "HFST lookup request exceeds the encoded byte limit "
                f"({len(request)} > {max_request_bytes})"
            )
        request += b"\n"

        self._ensure_process_identity()
        deadline = time.monotonic() + timeout
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not self._lock.acquire(timeout=remaining):
            raise _LookupTimeout(
                f"HFST guesser lookup for {surface!r} timed out after {timeout:.3f}s; "
                "partial response discarded"
            )
        try:
            process = self._start()
            assert process.stdin is not None and process.stdout is not None
            stdin_fd = process.stdin.fileno()
            os.set_blocking(stdin_fd, False)
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
                            f"{timeout:.3f}s while writing the request; partial request discarded"
                        )
                    events = write_selector.select(remaining)
                    if not events:
                        self._abort()
                        raise _LookupTimeout(
                            f"HFST guesser lookup for {surface!r} timed out after "
                            f"{timeout:.3f}s while writing the request; partial request discarded"
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
                            return _LookupResponse(tuple(lines), False, "response_cap")
                        if raw_line.endswith(b"\r"):
                            raw_line = raw_line[:-1]
                        if not raw_line:
                            separator_bytes = newline + 1
                            separator_records = 1
                            extra_records, extra_bytes = (
                                self._discard_buffered_response_separators()
                            )
                            separator_records += extra_records
                            separator_bytes += extra_bytes
                            consumed += extra_bytes
                            if not lines:
                                self.leading_separator_record_count += (
                                    separator_records
                                )
                                self.leading_separator_byte_count += separator_bytes
                            if consumed > max_bytes:
                                self.cap_abort_count += 1
                                self._abort()
                                return _LookupResponse(
                                    tuple(lines), False, "response_cap"
                                )
                            if not lines:
                                # HFST always emits either keyed candidates or
                                # one keyed +? negative.  Some runtimes append
                                # redundant separators in a later pipe write;
                                # they belong to the preceding response and
                                # must not become an empty response for this
                                # query.  Keep waiting under this query's
                                # original deadline and byte cap.
                                continue
                            return _LookupResponse(tuple(lines), True)
                        try:
                            decoded_line = raw_line.decode("utf-8")
                        except UnicodeDecodeError as exc:
                            self._abort()
                            raise _LookupFailure(
                                "HFST guesser lookup returned invalid UTF-8; "
                                "partial response discarded"
                            ) from exc
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
                            return _LookupResponse(tuple(lines), False, "response_cap")
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
        self._worker = _PersistentLookupWorker(command, self.backend.environment)
        self._cache: OrderedDict[tuple[str, int, bool], _GuessOutcome] = OrderedDict()
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
        deadline = time.monotonic() + timeout
        for attempt in range(2):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise _LookupTimeout(
                    f"HFST guesser lookup for {surface!r} timed out after "
                    f"{timeout:.3f}s; partial response discarded"
                )
            response = self._worker.query(
                surface,
                max_lines=max_lines,
                timeout=remaining,
                max_bytes=max_bytes,
                max_request_bytes=MAX_GUESS_REQUEST_BYTES,
            )
            problem = self._response_protocol_problem(surface, response.lines)
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
                self._worker._reset_after_protocol_error(retrying=True)
                continue
            self._worker._reset_after_protocol_error(retrying=False)
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
            parsed = parse_analysis(
                candidate,
                source="guesser",
                guessed=True,
                ud_profile=self.ud_profile,
            )
            if parsed is None:
                return "candidate is not a valid analysis"
            if not parsed.tags:
                return "candidate is an untagged identity"
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

        return productive_surface_eligible(surface)

    @staticmethod
    def _plausibility(surface: str, analysis: Analysis) -> float | None:
        if not productive_root_eligible(analysis.lemma):
            return None
        lemma = analysis.lemma
        word = surface.casefold()
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
            if productive_root_kind(surface, parsed.lemma, parsed.tags) is None:
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
        ranked = [analysis for _, analysis in scored]
        cap = 256 if generate_all else max(1, limit)
        selected = (
            ranked[:cap]
            if generate_all
            else _depthwise_lemma_interleave(ranked, cap)
        )
        if not selected:
            return _GuessOutcome((), raw_response.complete, raw_response.reason)

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
        deadline = time.monotonic() + timeout
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not self._cache_lock.acquire(timeout=remaining):
            self._diagnostics["timeouts"] += 1
            warnings.warn(
                f"guesser cache wait for {surface!r} timed out after {timeout:.3f}s; "
                "returning an explicit unknown analysis for this OOV",
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
