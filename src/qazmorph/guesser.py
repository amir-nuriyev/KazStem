"""Bounded open-class guesses produced by the same Kazakh two-level grammar."""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import replace
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
GUESS_CACHE_CAPACITY = 8192
CYCLE_MARKER = "[...cyclic...]"
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

    def _discard_buffered_response_separators(self) -> int:
        """Consume redundant blank records already buffered after a response."""

        discarded = 0
        while True:
            if self._pending.startswith(b"\r\n"):
                self._pending = self._pending[2:]
                discarded += 2
                continue
            if self._pending.startswith(b"\n"):
                self._pending = self._pending[1:]
                discarded += 1
                continue
            return discarded

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
    ) -> list[str]:
        if max_lines < 1 or max_bytes < 1 or timeout <= 0:
            raise ValueError("HFST lookup bounds must be positive")
        if any(character in surface for character in "\r\n\0"):
            raise ValueError("HFST lookup surface contains a record delimiter")

        self._ensure_process_identity()
        with self._lock:
            process = self._start()
            assert process.stdin is not None and process.stdout is not None
            try:
                process.stdin.write((surface + "\n").encode("utf-8"))
                process.stdin.flush()
            except (BrokenPipeError, OSError) as exc:
                returncode = process.poll()
                detail = self._stderr(process)
                self._abort()
                suffix = f": {detail}" if detail else ""
                raise _LookupFailure(
                    f"HFST guesser lookup pipe failed"
                    f"{f' ({returncode})' if returncode is not None else ''}{suffix}"
                ) from exc

            selector = selectors.DefaultSelector()
            selector.register(process.stdout, selectors.EVENT_READ, "stdout")
            if process.stderr is not None:
                selector.register(process.stderr, selectors.EVENT_READ, "stderr")
            deadline = time.monotonic() + timeout
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
                            return lines
                        if raw_line.endswith(b"\r"):
                            raw_line = raw_line[:-1]
                        if not raw_line:
                            consumed += self._discard_buffered_response_separators()
                            if consumed > max_bytes:
                                self.cap_abort_count += 1
                                self._abort()
                            return lines
                        decoded_line = raw_line.decode("utf-8", errors="replace")
                        if CYCLE_MARKER in decoded_line:
                            # This is a semantic HFST truncation, not a regular
                            # candidate.  Count it even for direct/raw callers;
                            # the public guess path below then fails closed.
                            self.cycle_truncation_count += 1
                        if len(lines) < max_lines:
                            lines.append(decoded_line)
                        if len(lines) >= max_lines:
                            discarded = self._discard_buffered_response_separators()
                            if discarded:
                                # The response has exactly ``max_lines`` and
                                # its terminator arrived in the same read; the
                                # worker remains synchronized and reusable.
                                return lines
                            # hfst-lookup cannot limit non-optimized FST
                            # results itself.  Ending this worker at the exact
                            # public prefix cap avoids an unbounded drain while
                            # preserving candidate order and cap semantics.
                            self.cap_abort_count += 1
                            self._abort()
                            return lines
                        continue

                    buffered = consumed + len(self._pending)
                    if buffered >= max_bytes:
                        self.cap_abort_count += 1
                        self._abort()
                        return lines
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
        self._cache: OrderedDict[tuple[str, int, bool], tuple[Analysis, ...]] = OrderedDict()
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
        if not self.available:
            return []
        first_problem: str | None = None
        for attempt in range(2):
            lines = self._worker.query(
                surface,
                max_lines=max_lines,
                timeout=timeout,
                max_bytes=max_bytes,
            )
            problem = self._response_protocol_problem(surface, lines)
            if problem is None:
                return lines
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

    @staticmethod
    def _response_protocol_problem(surface: str, lines: Sequence[str]) -> str | None:
        if not lines:
            return "zero lines"
        for line in lines:
            if CYCLE_MARKER in line:
                continue
            fields = line.split("\t")
            if len(fields) < 2:
                return "malformed line"
            if fields[0] != surface:
                return f"surface {fields[0]!r}"
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

    def _guess_uncached(self, surface: str, limit: int, generate_all: bool) -> tuple[Analysis, ...]:
        if not self._productive_safe:
            self._diagnostics["unsafe_resource_skips"] += 1
            return ()
        if not self._eligible_surface(surface):
            self._diagnostics["prefilter_skips"] += 1
            return ()

        candidates: dict[tuple[str, str, tuple[tuple[str, str], ...], str], Analysis] = {}
        scored: list[tuple[float, Analysis]] = []
        self._diagnostics["lookup_queries"] += 1
        try:
            raw_lines = self._raw_lookup(surface, max_lines=2048 if generate_all else 512)
        except _LookupTimeout as exc:
            self._diagnostics["timeouts"] += 1
            warnings.warn(
                f"{exc}; returning an explicit unknown analysis for this OOV",
                RuntimeWarning,
                stacklevel=3,
            )
            return ()
        except _LookupFailure as exc:
            self._diagnostics["failures"] += 1
            warnings.warn(
                f"{exc}; returning an explicit unknown analysis for this OOV",
                RuntimeWarning,
                stacklevel=3,
            )
            return ()

        if any(CYCLE_MARKER in line for line in raw_lines):
            warnings.warn(
                "HFST guesser reported a cyclic response; discarding partial "
                "candidates and returning an explicit unknown analysis for this OOV",
                RuntimeWarning,
                stacklevel=3,
            )
            return ()

        for line in raw_lines:
            if not line:
                continue
            fields = line.split("\t")
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
            return ()

        # Scores in the public API are normalized within the returned lattice.
        numeric_scores = [analysis.score if analysis.score is not None else -math.inf for analysis in selected]
        peak = max(numeric_scores)
        weights = [math.exp(score - peak) for score in numeric_scores]
        total = sum(weights)
        return tuple(
            replace(analysis, score=weight / total)
            for analysis, weight in zip(selected, weights)
        )

    def _guess_cached(self, surface: str, limit: int, generate_all: bool) -> tuple[Analysis, ...]:
        key = (surface, limit, generate_all)
        self._ensure_process_identity()
        with self._cache_lock:
            cached = self._cache.get(key)
            if cached is not None:
                self._diagnostics["cache_hits"] += 1
                self._cache.move_to_end(key)
                return cached
            self._diagnostics["cache_misses"] += 1
            guessed = self._guess_uncached(surface, limit, generate_all)
            self._cache[key] = guessed
            self._cache.move_to_end(key)
            if len(self._cache) > GUESS_CACHE_CAPACITY:
                self._cache.popitem(last=False)
            return guessed

    def guess(self, surface: str, *, limit: int = 8, generate_all: bool = False) -> list[Analysis]:
        if limit < 1:
            raise ValueError("guess limit must be positive")
        return list(self._guess_cached(surface, limit, generate_all))
