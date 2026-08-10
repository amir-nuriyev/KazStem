"""High-level ambiguity-preserving Kazakh analyzer."""

from __future__ import annotations

import os
import re
import time
import unicodedata
from bisect import bisect_left, bisect_right
from collections.abc import Sequence
from dataclasses import dataclass, replace

from .backend import (
    BackendError,
    DASH_PUNCTUATION,
    FSTBackend,
    ORTHOGRAPHIC_HYPHENS,
    PROTECTED_CHARACTERS,
)
from .fixlist import load_fixlist
from .generator import GenerationResult, ProductiveGenerator, exact_lexical_form
from .guesser import OpenClassGuesser, productive_surface_eligible
from .normalization import nfc_with_boundary_map
from .stream import RawSegment, parse_analysis, parse_apertium_stream
from .tags import UD_PROFILES, project_ud_alternatives
from .types import Analysis, AnalysisSpan, Document, Morpheme, Token


GENERATION_QUERY_BYTE_LIMIT = 4096
GENERATION_RECORD_CONTROLS = frozenset("<>[]{}\t\r\n\0")


@dataclass(frozen=True, slots=True)
class _AlignedSegment:
    segment: RawSegment
    start: int
    end: int


def _segment_kind(segment: RawSegment, analyses: list[Analysis]) -> str:
    if segment.text.isspace() or not segment.text:
        return "space"
    if analyses and all(analysis.upos == "PUNCT" for analysis in analyses):
        return "punct"
    if analyses and all(analysis.upos == "NUM" for analysis in analyses):
        return "number"
    categories = {unicodedata.category(char)[0] for char in segment.text if not char.isspace()}
    if "L" in categories:
        return "word"
    if categories and categories <= {"N"}:
        return "number"
    if categories and categories <= {"P"}:
        return "punct"
    return "symbol"


def _unknown_analysis(surface: str) -> Analysis:
    lemma = unicodedata.normalize("NFC", surface).casefold()
    return Analysis(
        lemma=lemma,
        upos="X",
        features=(),
        tags=("unknown",),
        morphemes=(Morpheme(lemma, ("unknown",), "X", ()),),
        raw=f"{lemma}<unknown>",
        source="unknown",
        guessed=True,
    )


def _number_analysis(surface: str) -> Analysis:
    """Return a deterministic analysis for an otherwise uncovered numeral."""

    lemma = unicodedata.normalize("NFC", surface)
    features = (("NumType", "Card"),)
    tags = ("num",)
    return Analysis(
        lemma=lemma,
        upos="NUM",
        features=features,
        tags=tags,
        morphemes=(Morpheme(lemma, tags, "NUM", features),),
        raw=f"{lemma}<num>",
        source="rule",
        guessed=True,
    )


def _projection_rule_candidates(
    surface: str, analysis: Analysis, *, ud_profile: str
) -> tuple[Analysis, ...]:
    """Decorate one compiled reading with evidence-backed UD alternatives.

    The caller is responsible for passing only non-guessed ``source=lexicon``
    readings.  Every alternative keeps the licensed raw string and ordered tags
    and changes the top-level and primary-morpheme projections together.
    """

    primary_index = next(
        (
            index
            for index, morpheme in enumerate(analysis.morphemes)
            if morpheme.lemma or morpheme.tags
        ),
        None,
    )
    if primary_index is None:
        return ()
    primary = analysis.morphemes[primary_index]
    alternatives = project_ud_alternatives(
        primary.tags,
        profile=ud_profile,
        bare_decimal=surface.isdecimal(),
    )
    candidates: list[Analysis] = []
    for upos, features in alternatives:
        morphemes = list(analysis.morphemes)
        morphemes[primary_index] = replace(primary, upos=upos, features=features)
        candidates.append(
            replace(
                analysis,
                upos=upos,
                features=features,
                morphemes=tuple(morphemes),
                source="rule",
                score=None,
            )
        )
    return tuple(candidates)


def _normalize_scores(analyses: list[Analysis], *, selected: bool) -> list[Analysis]:
    # The compiled analyzer and Constraint Grammar do not expose calibrated
    # probabilities. Keep score nullable instead of fabricating confidence.
    return analyses


class Analyzer:
    """Analyze Kazakh text with full ambiguity or fast contextual selection."""

    def __init__(
        self,
        resource_dir: str | os.PathLike[str] | None = None,
        *,
        disambiguate: bool = False,
        guess: bool = True,
        fixlist: str | os.PathLike[str] | None = None,
        guess_limit: int = 8,
        neural: bool = False,
        neural_model_dir: str | os.PathLike[str] | None = None,
        neural_use_gpu: bool | None = None,
        ud_profile: str = "universal",
    ) -> None:
        if guess_limit < 1:
            raise ValueError("guess_limit must be positive")
        if ud_profile not in UD_PROFILES:
            raise ValueError(f"unknown UD projection profile: {ud_profile}")
        if neural and disambiguate:
            raise ValueError(
                "neural and Constraint Grammar modes are mutually exclusive"
            )
        self.backend = FSTBackend(resource_dir)
        self.default_disambiguate = disambiguate
        self.use_guesser = guess
        self.guess_limit = guess_limit
        self.ud_profile = ud_profile
        self.guesser = OpenClassGuesser(
            self.backend, ud_profile=ud_profile
        )
        self.productive_generator = ProductiveGenerator(self.backend)
        self.fixlist = (
            load_fixlist(fixlist, ud_profile=ud_profile) if fixlist else {}
        )
        self.neural_ranker = None
        if neural:
            from .neural import StanzaCandidateRanker

            model_dir = neural_model_dir or (self.backend.runtime_dir / "neural" / "stanza")
            self.neural_ranker = StanzaCandidateRanker(model_dir, use_gpu=neural_use_gpu)

    def close(self) -> None:
        """Release the lazily started OOV lookup worker."""

        self.guesser.close()
        self.productive_generator.close()

    def __enter__(self) -> Analyzer:
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()

    def generate(
        self,
        lemma: str,
        tags: list[str] | tuple[str, ...],
        *,
        limit: int = 128,
        productive: bool = False,
        timeout: float | None = None,
    ) -> list[str]:
        """Generate one reading, optionally using the proven OOV inverse.

        The default dictionary-only path retains the strict 0.2.3 public input
        contract. Productive generation is explicit and is attempted only
        after a complete dictionary zero.
        """

        return list(
            self.generate_detailed(
                lemma,
                tags,
                limit=limit,
                productive=productive,
                timeout=timeout,
            ).forms
        )

    def generate_detailed(
        self,
        lemma: str,
        tags: list[str] | tuple[str, ...],
        *,
        limit: int = 128,
        productive: bool = False,
        timeout: float | None = None,
    ) -> GenerationResult:
        """Return generated forms with dictionary/productive provenance."""

        if not isinstance(productive, bool):
            raise ValueError("productive must be a boolean")
        if productive:
            # Validate the exact structured record before any helper sees it.
            exact_lexical_form(lemma, tags)
            return self.productive_generator.generate(
                lemma,
                tuple(tags),
                limit=limit,
                timeout=timeout,
                public_roundtrip_check=self._productive_generation_roundtrip,
            )

        if timeout is not None:
            raise ValueError("generation timeout is supported only in productive mode")

        # This is the audited 0.2.3 dictionary-generation validation contract.
        if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
            raise ValueError("generation limit must be positive")
        if not isinstance(lemma, str) or not lemma:
            raise ValueError("lemma must be a nonempty string")
        if any(
            char in GENERATION_RECORD_CONTROLS
            or unicodedata.category(char) in {"Cc", "Cs", "Zl", "Zp"}
            for char in lemma
        ):
            raise ValueError("lemma contains reserved morphology syntax")
        if (
            isinstance(tags, (str, bytes))
            or not isinstance(tags, Sequence)
            or not tags
            or any(not isinstance(tag, str) for tag in tags)
        ):
            raise ValueError("tags must be a nonempty sequence of strings")
        normalized_tags = tuple(tag.strip(" <>") for tag in tags)
        if any(
            not re.fullmatch(r"[A-Za-z0-9_:-]+", tag)
            for tag in normalized_tags
        ):
            raise ValueError("invalid morphology tag")
        escaped_lemma = lemma.replace("\\", "\\\\").replace("+", "\\+")
        lexical_form = escaped_lemma + "".join(
            f"<{tag}>" for tag in normalized_tags
        )
        if len(lexical_form.encode("utf-8")) > GENERATION_QUERY_BYTE_LIMIT:
            raise ValueError(
                "exact morphology query exceeds the bounded generator input size"
            )
        forms = tuple(self.backend.generate(lexical_form, limit=limit))
        return GenerationResult(
            forms,
            "dictionary" if forms else "none",
            productive_attempted=False,
            reason=None if forms else "dictionary_zero",
        )

    def _productive_generation_roundtrip(
        self,
        surface: str,
        lexical_form: str,
        deadline: float,
    ) -> bool:
        """Check one candidate against the exact public single-token lattice."""

        if not productive_surface_eligible(surface):
            return False

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise BackendError(
                "productive generation public-lattice deadline expired before analysis"
            )
        lattice_stream, _ = self.backend.analyze_stream_pair(
            surface,
            disambiguate=False,
            timeout=remaining,
        )
        segments = self._align_segments(
            surface,
            parse_apertium_stream(lattice_stream),
        )
        intervals = self._atomic_intervals(surface, segments)
        if intervals != ((0, len(surface)),):
            return False
        if not self._is_exact_partition(intervals, segments):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise BackendError(
                    "productive generation public-lattice deadline expired "
                    "before exact atomic analysis"
                )
            atomic_stream, _ = self.backend.analyze_atomic_stream_pair(
                surface,
                intervals,
                disambiguate=False,
                timeout=remaining,
            )
            segments = self._split_plain_segments_at_intervals(
                intervals,
                self._align_segments(
                    surface,
                    parse_apertium_stream(atomic_stream),
                ),
            )
        indexed = self._raw_by_interval(intervals, segments)
        raw_candidates, _sentence_end, exact = indexed[0]
        if not exact and raw_candidates:
            raise BackendError(
                "productive generation backcheck received an inexact backend cohort"
            )
        analyses = self._raw_analyses(
            surface,
            raw_candidates if exact else (),
            preserve_backend=False,
        )
        if analyses:
            return any(analysis.raw == lexical_form for analysis in analyses)
        if not self.use_guesser:
            return False

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise BackendError(
                "productive generation public-lattice deadline expired before guessing"
            )
        outcome = self.guesser._guess_detailed(
            surface,
            limit=self.guess_limit,
            generate_all=False,
            timeout=remaining,
        )
        if not outcome.complete:
            raise BackendError(
                "public productive-analyzer backcheck was incomplete"
                f" ({outcome.reason or 'unknown reason'})"
            )
        return any(
            analysis.raw == lexical_form for analysis in outcome.candidates
        )

    @property
    def generation_diagnostics(self) -> dict[str, int]:
        """Snapshot bounded productive-generation worker diagnostics."""

        return self.productive_generator.diagnostics

    @staticmethod
    def _align(source: str, cursor: int, surface: str) -> tuple[int, int, bool]:
        if source.startswith(surface, cursor):
            return cursor, cursor + len(surface), True
        search_end = min(len(source), cursor + 64 + len(surface))
        found = source.find(surface, cursor, search_end)
        if found >= 0:
            return found, found + len(surface), True
        return cursor, cursor, False

    def _align_segments(
        self, source: str, raw_segments: list[RawSegment]
    ) -> list[_AlignedSegment]:
        aligned: list[_AlignedSegment] = []
        cursor = 0
        for segment in raw_segments:
            start, end, matched_source = self._align(source, cursor, segment.text)
            if (
                not matched_source
                and segment.text == "."
                and any("<sent>" in raw for raw in segment.analyses)
            ):
                # hfst-proc may append a zero-span synthetic sentence boundary
                # after ? or !. It is backend control data, not caller input.
                continue
            if not matched_source or start != cursor:
                raise BackendError(
                    "HFST output could not be aligned losslessly at character "
                    f"{cursor}: backend surface {segment.text!r}"
                )
            aligned.append(_AlignedSegment(segment, start, end))
            cursor = end
        if cursor != len(source):
            raise BackendError("HFST output did not cover the normalized input exactly")
        return aligned

    @staticmethod
    def _hyphen_component(character: str) -> bool:
        category = unicodedata.category(character)
        return category.startswith("L") or category.startswith("M")

    @classmethod
    def _atomic_intervals(
        cls, text: str, segments: list[_AlignedSegment]
    ) -> tuple[tuple[int, int], ...]:
        """Derive the consuming token partition independently of HFST cohorts."""

        if not text:
            return ()
        boundaries = {0, len(text)}
        for item in segments:
            boundaries.update((item.start, item.end))

        # Whitespace runs are always their own consuming gap tokens, including
        # whitespace that the dictionary placed inside one lexical MWE cohort.
        for index in range(1, len(text)):
            if text[index - 1].isspace() != text[index].isspace():
                boundaries.add(index)
        for boundary in tuple(boundaries):
            if (
                0 < boundary < len(text)
                and text[boundary - 1].isspace()
                and text[boundary].isspace()
            ):
                boundaries.discard(boundary)

        # Internal letter/mark-hyphen-letter/mark chains are one orthographic
        # token even when hfst-proc emitted three cohorts. A leading/trailing
        # or otherwise punctuation-like dash is forced onto its own token.
        for index, character in enumerate(text):
            if character in DASH_PUNCTUATION:
                boundaries.update((index, index + 1))
                continue
            if character not in ORTHOGRAPHIC_HYPHENS:
                continue
            internal = (
                index > 0
                and index + 1 < len(text)
                and cls._hyphen_component(text[index - 1])
                and cls._hyphen_component(text[index + 1])
            )
            if internal:
                boundaries.discard(index)
                boundaries.discard(index + 1)
            elif index == 0 or index + 1 == len(text):
                # A leading/trailing hyphen is punctuation. For a medial
                # non-letter case, retain an exact whole backend cohort (for
                # example dictionary-licensed ``51%-дан``); if HFST already
                # split it, its cohort boundaries remain in place.
                boundaries.update((index, index + 1))

        ordered = sorted(boundaries)
        intervals = tuple(zip(ordered, ordered[1:]))
        if any(end <= start for start, end in intervals):
            raise BackendError("atomic tokenizer produced an empty interval")
        return intervals

    def _raw_analyses(
        self,
        surface: str,
        raw_candidates: tuple[str, ...],
        *,
        preserve_backend: bool,
    ) -> list[Analysis]:
        licensed: list[Analysis] = []
        for raw in raw_candidates:
            protected_rule = len(surface) == 1 and surface in PROTECTED_CHARACTERS
            analysis = parse_analysis(
                raw,
                source="rule" if protected_rule else "lexicon",
                guessed=protected_rule,
                ud_profile=self.ud_profile,
            )
            if analysis is not None:
                licensed.append(analysis)

        # Atomic tokens keep the complete FST sequence as an unchanged prefix.
        # Projection aliases follow in raw order, use deterministic rule
        # provenance, and only decorate genuine compiled readings. Phrase
        # spans remain the exact backend sequence/provenance layer.
        parsed = list(licensed)
        seen_aliases = {analysis.identity for analysis in licensed}
        if not preserve_backend:
            for analysis in licensed:
                if analysis.source != "lexicon" or analysis.guessed:
                    continue
                for candidate in _projection_rule_candidates(
                    surface, analysis, ud_profile=self.ud_profile
                ):
                    if candidate.identity not in seen_aliases:
                        parsed.append(candidate)
                        seen_aliases.add(candidate.identity)

        override = self.fixlist.get(surface.casefold())
        if override:
            if preserve_backend:
                # Span provenance is append-only: an override may add a
                # preferred reading but must not erase the licensed raw MWE
                # lattice that this layer exists to expose.
                parsed.extend(override)
            else:
                parsed = list(override)

        if preserve_backend:
            return parsed

        unique: list[Analysis] = []
        seen: set[tuple[str, str, tuple[tuple[str, str], ...], str]] = set()
        for analysis in parsed:
            if analysis.identity not in seen:
                unique.append(analysis)
                seen.add(analysis.identity)
        return unique

    @staticmethod
    def _raw_by_interval(
        intervals: tuple[tuple[int, int], ...],
        segments: Sequence[_AlignedSegment],
    ) -> list[tuple[tuple[str, ...], bool, bool]]:
        """Index cohort readings onto intervals in one monotonic sweep."""

        indexed: list[tuple[tuple[str, ...], bool, bool]] = []
        cursor = 0
        for start, end in intervals:
            exact: _AlignedSegment | None = None
            contained_count = 0
            sentence_end = False
            while cursor < len(segments) and segments[cursor].start < end:
                item = segments[cursor]
                cursor += 1
                if item.start < start or item.end > end:
                    raise BackendError(
                        "aligned cohort crosses an atomic token boundary"
                    )
                contained_count += 1
                if item.start == start and item.end == end:
                    exact = item
                sentence_end = sentence_end or any(
                    "<sent>" in raw for raw in item.segment.analyses
                )
            if contained_count == 1 and exact is not None:
                indexed.append((exact.segment.analyses, sentence_end, True))
            else:
                # A predetermined orthographic atom can cover several backend
                # cohorts (notably an unknown hyphen compound). Combining their
                # morphology would be heuristic; retain only sentence evidence.
                indexed.append(((), sentence_end, False))
        if cursor != len(segments):
            raise BackendError("aligned cohorts do not fit the atomic partition")
        return indexed

    @staticmethod
    def _split_plain_segments_at_intervals(
        intervals: tuple[tuple[int, int], ...],
        segments: list[_AlignedSegment],
    ) -> list[_AlignedSegment]:
        """Restore NUL-fenced boundaries coalesced between plain gap chunks.

        ``hfst-proc -z`` may emit two analysis-free surface fragments separated
        only by its control NUL. The backend removes that control byte before
        parsing, so adjacent punctuation/whitespace fragments can coalesce.
        Exact surface slicing is safe only when no lexical readings exist;
        analyzed cohorts continue to fail in ``_raw_by_interval``.
        """

        boundaries = [end for _start, end in intervals[:-1]]
        repaired: list[_AlignedSegment] = []
        for item in segments:
            left = bisect_right(boundaries, item.start)
            right = bisect_left(boundaries, item.end)
            cuts = boundaries[left:right]
            if not cuts or item.segment.analyses:
                repaired.append(item)
                continue
            points = [item.start, *cuts, item.end]
            for start, end in zip(points, points[1:]):
                repaired.append(
                    _AlignedSegment(
                        RawSegment(
                            item.segment.text[
                                start - item.start : end - item.start
                            ]
                        ),
                        start,
                        end,
                    )
                )
        return repaired

    @staticmethod
    def _is_exact_partition(
        intervals: tuple[tuple[int, int], ...], segments: list[_AlignedSegment]
    ) -> bool:
        """Return whether aligned cohorts already are the atomic partition."""

        return len(intervals) == len(segments) and all(
            interval == (segment.start, segment.end)
            for interval, segment in zip(intervals, segments)
        )

    @staticmethod
    def _contextual_span_selection(
        analyses: list[Analysis], contextual_raw: tuple[str, ...] | None
    ) -> int | None:
        if len(analyses) == 1:
            return 0
        if contextual_raw is None:
            return None
        genuine = [raw for raw in contextual_raw if raw and not raw.startswith("*")]
        if len(genuine) != 1:
            return None
        matches = [
            index for index, analysis in enumerate(analyses) if analysis.raw == genuine[0]
        ]
        return matches[0] if len(matches) == 1 else None

    def analyze(
        self,
        text: str,
        *,
        disambiguate: bool | None = None,
        generate_all: bool = False,
    ) -> Document:
        contextual = self.default_disambiguate if disambiguate is None else disambiguate
        if self.neural_ranker is not None and contextual:
            raise ValueError(
                "neural and Constraint Grammar modes are mutually exclusive"
            )
        normalized, original_boundaries = nfc_with_boundary_map(text)
        backend_contextual = contextual and self.neural_ranker is None
        if not normalized:
            return Document(
                text=text,
                normalized_text=normalized if normalized != text else None,
                tokens=[],
                mode="neural" if self.neural_ranker is not None else (
                    "contextual" if contextual else "lattice"
                ),
                resource_version=self.backend.resource_version,
                ud_profile=self.ud_profile,
            )

        phrase_lattice_stream, phrase_contextual_stream = self.backend.analyze_stream_pair(
            normalized, disambiguate=backend_contextual
        )
        phrase_lattice = self._align_segments(
            normalized, parse_apertium_stream(phrase_lattice_stream)
        )
        phrase_contextual = (
            self._align_segments(
                normalized, parse_apertium_stream(phrase_contextual_stream)
            )
            if phrase_contextual_stream is not None
            else []
        )

        intervals = self._atomic_intervals(normalized, phrase_lattice)
        lattice_partition_exact = self._is_exact_partition(intervals, phrase_lattice)
        contextual_partition_exact = (
            not backend_contextual
            or self._is_exact_partition(intervals, phrase_contextual)
        )
        if lattice_partition_exact and contextual_partition_exact:
            # Most ordinary text is already emitted as the desired orthographic
            # partition. Reuse the lossless phrase pass rather than paying for
            # an identical NUL-fenced subprocess round trip. Whitespace MWEs,
            # hyphen merges, punctuation splits, and any CG partition mismatch
            # fail this structural test and still take the exact-surface pass.
            atomic_lattice = phrase_lattice
            atomic_contextual = phrase_contextual
        else:
            atomic_lattice_stream, atomic_contextual_stream = (
                self.backend.analyze_atomic_stream_pair(
                    normalized, intervals, disambiguate=backend_contextual
                )
            )
            atomic_lattice = self._align_segments(
                normalized, parse_apertium_stream(atomic_lattice_stream)
            )
            atomic_contextual = (
                self._align_segments(
                    normalized, parse_apertium_stream(atomic_contextual_stream)
                )
                if atomic_contextual_stream is not None
                else []
            )

        atomic_lattice = self._split_plain_segments_at_intervals(
            intervals, atomic_lattice
        )
        atomic_contextual = self._split_plain_segments_at_intervals(
            intervals, atomic_contextual
        )
        lattice_by_interval = self._raw_by_interval(intervals, atomic_lattice)
        contextual_by_interval = (
            self._raw_by_interval(intervals, atomic_contextual)
            if atomic_contextual
            else [((), False, False)] * len(intervals)
        )

        tokens: list[Token] = []
        for token_index, interval in enumerate(intervals):
            start, end = interval
            normalized_surface = normalized[start:end]
            original_start = original_boundaries[start]
            original_end = original_boundaries[end]
            original_surface = text[original_start:original_end]
            if (
                not original_surface
                or unicodedata.normalize("NFC", original_surface) != normalized_surface
            ):
                raise BackendError(
                    "normalization boundary map could not represent atomic surface "
                    f"{normalized_surface!r} at normalized span {start}:{end}"
                )

            lattice_raw, lattice_sentence_end, _lattice_exact = lattice_by_interval[
                token_index
            ]
            contextual_raw, contextual_sentence_end, contextual_exact = (
                contextual_by_interval[token_index]
            )
            active_raw = (
                contextual_raw
                if backend_contextual and contextual_exact
                else lattice_raw
            )
            analyses = self._raw_analyses(
                normalized_surface, active_raw, preserve_backend=False
            )
            visible_segment = RawSegment(original_surface, active_raw)
            kind = _segment_kind(visible_segment, analyses)
            if not analyses and kind in {"word", "number"}:
                if kind == "number":
                    analyses = [_number_analysis(normalized_surface)]
                else:
                    if self.use_guesser:
                        analyses = self.guesser.guess(
                            normalized_surface.casefold(),
                            limit=self.guess_limit,
                            generate_all=generate_all,
                        )
                    if not analyses:
                        analyses = [_unknown_analysis(normalized_surface)]

            if analyses and all(analysis.source == "guesser" for analysis in analyses):
                # OOV lookup already supplied its deterministic ranking.
                normalized_analyses = analyses
            else:
                normalized_analyses = _normalize_scores(analyses, selected=False)
            kind = _segment_kind(visible_segment, normalized_analyses)
            sentence_end = lattice_sentence_end or contextual_sentence_end or any(
                "sent" in analysis.tags for analysis in normalized_analyses
            )
            tokens.append(
                Token(
                    text=original_surface,
                    start=original_start,
                    end=original_end,
                    kind=kind,
                    normalized=(
                        normalized_surface if normalized_surface != original_surface else None
                    ),
                    analyses=normalized_analyses,
                    selected=0 if len(normalized_analyses) == 1 else None,
                    sentence_end=sentence_end,
                )
            )

        contextual_by_span = {
            (item.start, item.end, item.segment.text): item.segment.analyses
            for item in phrase_contextual
            if any(character.isspace() for character in item.segment.text)
        }
        interval_starts = [start for start, _end in intervals]
        interval_ends = [end for _start, end in intervals]
        spans: list[AnalysisSpan] = []
        for item in phrase_lattice:
            segment = item.segment
            if not any(character.isspace() for character in segment.text):
                continue
            analyses = self._raw_analyses(
                segment.text, segment.analyses, preserve_backend=True
            )
            if not analyses:
                continue
            token_start = bisect_right(interval_starts, item.start) - 1
            token_end_inclusive = bisect_left(interval_ends, item.end)
            if (
                token_start < 0
                or token_end_inclusive >= len(intervals)
                or not intervals[token_start][0] <= item.start < intervals[token_start][1]
                or not (
                    intervals[token_end_inclusive][0]
                    < item.end
                    <= intervals[token_end_inclusive][1]
                )
            ):
                raise BackendError("multi-token FST span has no atomic token coverage")
            token_end = token_end_inclusive + 1
            original_start = original_boundaries[item.start]
            original_end = original_boundaries[item.end]
            original_surface = text[original_start:original_end]
            if unicodedata.normalize("NFC", original_surface) != segment.text:
                raise BackendError("multi-token FST span normalization is not lossless")
            contextual_raw = contextual_by_span.get(
                (item.start, item.end, segment.text)
            )
            spans.append(
                AnalysisSpan(
                    text=original_surface,
                    start=original_start,
                    end=original_end,
                    token_start=token_start,
                    token_end=token_end,
                    analyses=tuple(analyses),
                    selected=self._contextual_span_selection(
                        analyses, contextual_raw
                    ),
                    sentence_end=any(
                        "sent" in analysis.tags for analysis in analyses
                    ),
                    normalized=(
                        segment.text if segment.text != original_surface else None
                    ),
                )
            )

        if "".join(token.text for token in tokens) != text:
            raise BackendError("atomic tokens did not cover the input text exactly")

        if self.neural_ranker is not None:
            self.neural_ranker.rerank(text, tokens)
            mode = "neural"
        else:
            mode = "contextual" if contextual else "lattice"
        return Document(
            text=text,
            normalized_text=normalized if normalized != text else None,
            tokens=tokens,
            analysis_spans=tuple(spans),
            mode=mode,
            resource_version=self.backend.resource_version,
            ud_profile=self.ud_profile,
        )
