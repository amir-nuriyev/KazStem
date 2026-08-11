"""Dictionary-first, bounded productive morphological generation."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
import math
import os
import re
import threading
import time
from typing import Callable, Literal

from .backend import BackendError, FSTBackend
from .guesser import (
    MAX_LOOKUP_REQUEST_BYTES,
    _LookupFailure,
    _LookupTimeout,
    _PersistentLookupWorker,
    productive_root_eligible,
    productive_surface_eligible,
)


GENERATION_HARD_LIMIT = 128
GENERATION_RESPONSE_LINE_LIMIT = GENERATION_HARD_LIMIT + 1
GENERATION_RESPONSE_BYTE_LIMIT = 64 * 1024
GENERATION_QUERY_BYTE_LIMIT = MAX_LOOKUP_REQUEST_BYTES
GENERATION_LOOKUP_TIMEOUT_SECONDS = 2.0
PRODUCTIVE_POS_TAGS = frozenset({"n", "adj", "v"})
TAG_ATOM_RE = re.compile(r"[A-Za-z0-9_:-]+")
CONTROL_MARKER_RE = re.compile(r"\[[^\]\r\n]*\]")
RECORD_CONTROL_CHARACTERS = frozenset("<>[]{}\t\r\n\0")


GenerationSource = Literal["dictionary", "productive", "none"]
PublicRoundtripCheck = Callable[[str, str, float], bool]


@dataclass(frozen=True, slots=True)
class GenerationResult:
    """One complete, source-attributed exact lexical lookup result."""

    forms: tuple[str, ...]
    source: GenerationSource
    productive_attempted: bool
    reason: str | None = None


def exact_lexical_form(lemma: str, tags: Sequence[str]) -> str:
    """Serialize already-canonical structured input without lossy stripping."""

    if not isinstance(lemma, str) or not lemma:
        raise ValueError("lemma must be a nonempty string")
    if any(character in lemma for character in RECORD_CONTROL_CHARACTERS):
        raise ValueError("lemma contains reserved morphology syntax")
    if isinstance(tags, (str, bytes)) or not isinstance(tags, Sequence) or not tags:
        raise ValueError("at least one exact morphology tag is required")
    if any(
        not isinstance(tag, str) or TAG_ATOM_RE.fullmatch(tag) is None
        for tag in tags
    ):
        raise ValueError("invalid exact morphology tag")
    escaped_lemma = lemma.replace("\\", "\\\\").replace("+", "\\+")
    lexical_form = escaped_lemma + "".join(f"<{tag}>" for tag in tags)
    if len(lexical_form.encode("utf-8")) > GENERATION_QUERY_BYTE_LIMIT:
        raise ValueError(
            "exact morphology query exceeds the bounded generator input size"
        )
    return lexical_form


def productive_lemma_eligible(lemma: str) -> bool:
    """Accept only the exact single-root alphabet proven by the analyzer gate."""

    return productive_root_eligible(lemma)


class ProductiveGenerator:
    """Query the compiled dictionary first and the exact inverse only on zero.

    Both subprocesses are lazy, serialized, fork-safe persistent workers.  A
    response at the public hard limit is rejected rather than silently
    truncated, and every non-cycle record must correlate to the exact lexical
    query before any form is returned.
    """

    def __init__(self, backend: FSTBackend) -> None:
        self.backend = backend
        executable = backend.hfst_optimized_lookup
        common = (
            [
                str(executable),
                "-q",
                "-u",
                "-n",
                str(GENERATION_RESPONSE_LINE_LIMIT),
                "--pipe-mode=both",
            ]
            if executable
            else [""]
        )
        self._dictionary_worker = _PersistentLookupWorker(
            [*common, str(backend.generator_path)], backend.environment
        )
        self._productive_worker = _PersistentLookupWorker(
            [*common, str(backend.productive_generator_path)], backend.environment
        )
        self._owner_pid = os.getpid()
        self._diagnostics_lock = threading.RLock()
        self._diagnostics = {
            "dictionary_queries": 0,
            "dictionary_hits": 0,
            "dictionary_zero": 0,
            "productive_queries": 0,
            "productive_hits": 0,
            "productive_zero": 0,
            "productive_raw_candidates": 0,
            "ineligible_lemma_skips": 0,
            "unsupported_pos_skips": 0,
            "unavailable_productive_skips": 0,
            "unavailable_backcheck_skips": 0,
            "surface_ineligible_rejects": 0,
            "roundtrip_queries": 0,
            "roundtrip_accepted": 0,
            "roundtrip_rejected": 0,
            "roundtrip_failures": 0,
            "timeouts": 0,
            "failures": 0,
            "response_cap_failures": 0,
        }

    def _ensure_process_identity(self) -> None:
        if os.getpid() != self._owner_pid:
            self._diagnostics_lock = threading.RLock()
            self._dictionary_worker._ensure_process_identity()
            self._productive_worker._ensure_process_identity()
            self._owner_pid = os.getpid()

    @property
    def productive_available(self) -> bool:
        return bool(
            self.backend.hfst_optimized_lookup
            and self.backend.productive_generator_safe
            and self.backend.productive_generator_path.is_file()
        )

    @property
    def diagnostics(self) -> dict[str, int]:
        self._ensure_process_identity()
        with self._diagnostics_lock:
            return {
                **self._diagnostics,
                "dictionary_worker_starts": self._dictionary_worker.start_count,
                "dictionary_cap_aborts": self._dictionary_worker.cap_abort_count,
                "dictionary_cycle_truncations": (
                    self._dictionary_worker.cycle_truncation_count
                ),
                "dictionary_idle_restarts": (
                    self._dictionary_worker.idle_restart_count
                ),
                "dictionary_protocol_restarts": (
                    self._dictionary_worker.protocol_restart_count
                ),
                "dictionary_leading_separator_records": (
                    self._dictionary_worker.leading_separator_record_count
                ),
                "dictionary_leading_separator_bytes": (
                    self._dictionary_worker.leading_separator_byte_count
                ),
                "productive_worker_starts": self._productive_worker.start_count,
                "productive_cap_aborts": self._productive_worker.cap_abort_count,
                "productive_cycle_truncations": (
                    self._productive_worker.cycle_truncation_count
                ),
                "productive_idle_restarts": (
                    self._productive_worker.idle_restart_count
                ),
                "productive_protocol_restarts": (
                    self._productive_worker.protocol_restart_count
                ),
                "productive_leading_separator_records": (
                    self._productive_worker.leading_separator_record_count
                ),
                "productive_leading_separator_bytes": (
                    self._productive_worker.leading_separator_byte_count
                ),
                "productive_resource_safe": int(
                    self.backend.productive_generator_safe
                ),
                "productive_available": int(self.productive_available),
            }

    def close(self) -> None:
        self._dictionary_worker.close()
        self._productive_worker.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass

    @staticmethod
    def _response_problem(lexical_form: str, lines: Sequence[str]) -> str | None:
        if not lines:
            return "zero lines"
        negative_records = 0
        candidate_records = 0
        for line in lines:
            if CONTROL_MARKER_RE.search(line):
                return "control marker"
            fields = line.split("\t")
            if len(fields) not in {2, 3}:
                return "malformed field count"
            if fields[0] != lexical_form:
                return f"query key {fields[0]!r}"
            if len(fields) == 3:
                if fields[2] != "+?" or fields[1] != lexical_form:
                    return "malformed negative or unexpected weight field"
                negative_records += 1
            else:
                candidate = fields[1]
                if not candidate:
                    return "empty generated form"
                if candidate == lexical_form:
                    return "query echo candidate"
                if "+?" in candidate:
                    return "pseudo-negative candidate"
                if any(character in candidate for character in RECORD_CONTROL_CHARACTERS):
                    return "candidate contains morphology control syntax"
                candidate_records += 1
        if negative_records and candidate_records:
            return "mixed negative and candidate records"
        if negative_records != 0 and negative_records != 1:
            return "multiple negative records"
        return None

    def _lookup(
        self,
        worker: _PersistentLookupWorker,
        lexical_form: str,
        *,
        label: str,
        deadline: float | None = None,
    ) -> tuple[str, ...]:
        first_problem: str | None = None
        try:
            for attempt in range(2):
                timeout = GENERATION_LOOKUP_TIMEOUT_SECONDS
                if deadline is not None:
                    timeout = min(timeout, deadline - time.monotonic())
                    if timeout <= 0:
                        raise _LookupTimeout(
                            f"HFST {label} generation exceeded its total deadline"
                        )
                cap_aborts_before = worker.cap_abort_count
                cycles_before = worker.cycle_truncation_count
                response = worker.query(
                    lexical_form,
                    max_lines=GENERATION_RESPONSE_LINE_LIMIT,
                    timeout=timeout,
                    max_bytes=GENERATION_RESPONSE_BYTE_LIMIT,
                    max_request_bytes=GENERATION_QUERY_BYTE_LIMIT,
                )
                if deadline is not None and time.monotonic() >= deadline:
                    raise _LookupTimeout(
                        f"HFST {label} generation exceeded its total deadline"
                    )
                if worker.cap_abort_count != cap_aborts_before:
                    with self._diagnostics_lock:
                        self._diagnostics["response_cap_failures"] += 1
                    raise BackendError(
                        f"HFST {label} generation exceeded a response bound"
                    )
                if not response.complete:
                    worker._reset_after_protocol_error(retrying=False)
                    if response.reason == "response_cap":
                        with self._diagnostics_lock:
                            self._diagnostics["response_cap_failures"] += 1
                    raise _LookupFailure(
                        f"HFST {label} generation returned an incomplete response"
                        f" ({response.reason or 'unknown reason'})"
                    )
                lines = response.lines
                if worker.cycle_truncation_count != cycles_before:
                    worker._reset_after_protocol_error(retrying=False)
                    raise _LookupFailure(
                        f"HFST {label} generation returned a cycle marker"
                    )
                if len(lines) >= GENERATION_RESPONSE_LINE_LIMIT:
                    worker._reset_after_protocol_error(retrying=False)
                    with self._diagnostics_lock:
                        self._diagnostics["response_cap_failures"] += 1
                    raise BackendError(
                        f"HFST {label} generation reached the hard raw-record cap"
                    )
                problem = self._response_problem(lexical_form, lines)
                if problem is None:
                    break
                if problem == "control marker":
                    worker._reset_after_protocol_error(retrying=False)
                    raise _LookupFailure(
                        f"HFST {label} generation returned a control marker"
                    )
                if attempt == 0:
                    first_problem = problem
                    worker._reset_after_protocol_error(retrying=True)
                    continue
                worker._reset_after_protocol_error(retrying=False)
                raise _LookupFailure(
                    f"HFST {label} generation could not correlate a complete "
                    f"response for {lexical_form!r} after one restart "
                    f"(first response: {first_problem}; second response: {problem})"
                )
            else:
                raise AssertionError("bounded generation retry did not terminate")
        except _LookupTimeout:
            with self._diagnostics_lock:
                self._diagnostics["timeouts"] += 1
            raise
        except _LookupFailure:
            with self._diagnostics_lock:
                self._diagnostics["failures"] += 1
            raise

        forms: list[str] = []
        for line in lines:
            fields = line.split("\t")
            if len(fields) == 2:
                forms.append(fields[1])
        unique = tuple(dict.fromkeys(forms))
        return unique

    def _backcheck_productive_forms(
        self,
        forms: Sequence[str],
        lexical_form: str,
        *,
        limit: int,
        deadline: float,
        public_roundtrip_check: PublicRoundtripCheck | None,
    ) -> tuple[str, ...]:
        check = public_roundtrip_check
        if check is None:
            with self._diagnostics_lock:
                self._diagnostics["unavailable_backcheck_skips"] += 1
            return ()

        accepted: list[str] = []
        for surface in forms:
            if not productive_surface_eligible(surface):
                with self._diagnostics_lock:
                    self._diagnostics["surface_ineligible_rejects"] += 1
                    self._diagnostics["roundtrip_rejected"] += 1
                continue
            if time.monotonic() >= deadline:
                with self._diagnostics_lock:
                    self._diagnostics["timeouts"] += 1
                raise _LookupTimeout(
                    "productive generation exceeded its total public-backcheck deadline"
                )
            with self._diagnostics_lock:
                self._diagnostics["roundtrip_queries"] += 1
            try:
                roundtrips = check(surface, lexical_form, deadline)
            except BackendError:
                with self._diagnostics_lock:
                    self._diagnostics["roundtrip_failures"] += 1
                raise
            except Exception as exc:
                with self._diagnostics_lock:
                    self._diagnostics["roundtrip_failures"] += 1
                raise BackendError(
                    "public productive-analyzer backcheck failed"
                ) from exc
            if not isinstance(roundtrips, bool):
                with self._diagnostics_lock:
                    self._diagnostics["roundtrip_failures"] += 1
                raise BackendError(
                    "public productive-analyzer backcheck returned an invalid result"
                )
            if time.monotonic() >= deadline:
                with self._diagnostics_lock:
                    self._diagnostics["timeouts"] += 1
                    self._diagnostics["roundtrip_failures"] += 1
                raise _LookupTimeout(
                    "productive generation exceeded its total public-backcheck deadline"
                )
            if roundtrips:
                accepted.append(surface)
                with self._diagnostics_lock:
                    self._diagnostics["roundtrip_accepted"] += 1
                if len(accepted) >= limit:
                    break
            else:
                with self._diagnostics_lock:
                    self._diagnostics["roundtrip_rejected"] += 1
        return tuple(accepted)

    def generate(
        self,
        lemma: str,
        tags: Sequence[str],
        *,
        limit: int = GENERATION_HARD_LIMIT,
        timeout: float | None = None,
        public_roundtrip_check: PublicRoundtripCheck | None = None,
    ) -> GenerationResult:
        if (
            not isinstance(limit, int)
            or isinstance(limit, bool)
            or not 1 <= limit <= GENERATION_HARD_LIMIT
        ):
            raise ValueError(
                f"generation limit must be between 1 and {GENERATION_HARD_LIMIT}"
            )
        effective_timeout = (
            GENERATION_LOOKUP_TIMEOUT_SECONDS if timeout is None else timeout
        )
        if (
            isinstance(effective_timeout, bool)
            or not isinstance(effective_timeout, (int, float))
            or not math.isfinite(effective_timeout)
            or effective_timeout <= 0
        ):
            raise ValueError("generation timeout must be finite and positive")
        deadline = time.monotonic() + effective_timeout
        lexical_form = exact_lexical_form(lemma, tags)
        if not self.backend.hfst_optimized_lookup or not self.backend.generator_path.is_file():
            raise BackendError(
                "Morphological generator resource or hfst-optimized-lookup is unavailable"
            )

        self._ensure_process_identity()
        with self._diagnostics_lock:
            self._diagnostics["dictionary_queries"] += 1
        dictionary = self._lookup(
            self._dictionary_worker,
            lexical_form,
            label="dictionary",
            deadline=deadline,
        )
        if dictionary:
            with self._diagnostics_lock:
                self._diagnostics["dictionary_hits"] += 1
            return GenerationResult(
                dictionary[:limit], "dictionary", productive_attempted=False
            )
        with self._diagnostics_lock:
            self._diagnostics["dictionary_zero"] += 1

        if not productive_lemma_eligible(lemma):
            with self._diagnostics_lock:
                self._diagnostics["ineligible_lemma_skips"] += 1
            return GenerationResult(
                (), "none", productive_attempted=False, reason="ineligible_lemma"
            )
        if tags[0] not in PRODUCTIVE_POS_TAGS:
            with self._diagnostics_lock:
                self._diagnostics["unsupported_pos_skips"] += 1
            return GenerationResult(
                (), "none", productive_attempted=False, reason="unsupported_pos"
            )
        if not self.productive_available:
            with self._diagnostics_lock:
                self._diagnostics["unavailable_productive_skips"] += 1
            return GenerationResult(
                (),
                "none",
                productive_attempted=False,
                reason="productive_resource_unavailable",
            )
        if public_roundtrip_check is None:
            with self._diagnostics_lock:
                self._diagnostics["unavailable_backcheck_skips"] += 1
            return GenerationResult(
                (),
                "none",
                productive_attempted=False,
                reason="public_backcheck_unavailable",
            )

        with self._diagnostics_lock:
            self._diagnostics["productive_queries"] += 1
        productive = self._lookup(
            self._productive_worker,
            lexical_form,
            label="productive",
            deadline=deadline,
        )
        if productive:
            with self._diagnostics_lock:
                self._diagnostics["productive_raw_candidates"] += len(productive)
            accepted = self._backcheck_productive_forms(
                productive,
                lexical_form,
                limit=limit,
                deadline=deadline,
                public_roundtrip_check=public_roundtrip_check,
            )
            if accepted:
                with self._diagnostics_lock:
                    self._diagnostics["productive_hits"] += 1
                return GenerationResult(
                    accepted, "productive", productive_attempted=True
                )
            with self._diagnostics_lock:
                self._diagnostics["productive_zero"] += 1
            return GenerationResult(
                (),
                "none",
                productive_attempted=True,
                reason="public_roundtrip_rejected",
            )
        with self._diagnostics_lock:
            self._diagnostics["productive_zero"] += 1
        return GenerationResult(
            (),
            "none",
            productive_attempted=True,
            reason="unsupported_tag_sequence",
        )
