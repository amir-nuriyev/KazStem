#!/usr/bin/env python3
"""Measure lossless coverage and throughput on existing raw Kazakh text.

This utility never downloads data.  It reads bounded line-aligned chunks and
keeps one Analyzer instance alive, which exercises the production OOV cache and
persistent lookup worker without loading a large corpus into Python memory.
"""

from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import asdict, dataclass, field
import hashlib
import json
from pathlib import Path
import platform
import resource
import sys
import time
from typing import Any, Iterator, Sequence
import unicodedata


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = PROJECT_ROOT / "src"
if SOURCE_ROOT.is_dir() and str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))

from qazmorph.guesser import productive_root_kind


SCHEMA_VERSION = "qazmorph.raw-evaluation.v3"


class RawEvaluationError(RuntimeError):
    """Raised when an input cannot be evaluated completely and losslessly."""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _file_identity(path: Path) -> dict[str, Any]:
    resolved = path.resolve()
    try:
        return {
            "path": str(resolved),
            "bytes": resolved.stat().st_size,
            "sha256": _sha256(resolved),
        }
    except OSError as exc:
        raise RawEvaluationError(
            f"provenance artifact is unavailable: {resolved}: {exc}"
        ) from exc


def _software_provenance() -> dict[str, Any]:
    paths = [Path(__file__).resolve(), *sorted((SOURCE_ROOT / "qazmorph").glob("*.py"))]
    files = {
        path.relative_to(PROJECT_ROOT).as_posix(): {
            "bytes": path.stat().st_size,
            "sha256": _sha256(path),
        }
        for path in paths
    }
    identity = json.dumps(
        files, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return {"files": files, "bundle_sha256": hashlib.sha256(identity).hexdigest()}


def _resource_provenance(analyzer: Any) -> dict[str, Any]:
    manifest = dict(analyzer.backend.manifest)
    manifest_files = manifest.get("files")
    if not isinstance(manifest_files, dict):
        raise RawEvaluationError("resource manifest has no artifact inventory")
    resource_dir = Path(analyzer.backend.resource_dir).resolve()
    return {
        "resource_dir": str(resource_dir),
        "resource_version": analyzer.backend.resource_version,
        "manifest": manifest,
        "manifest_file": _file_identity(resource_dir / "manifest.json"),
        "resource_artifacts": {
            str(name): _file_identity(resource_dir / str(name))
            for name in sorted(manifest_files)
        },
        "runtime": analyzer.backend.runtime_provenance(),
    }


def _expand_inputs(values: Sequence[str]) -> list[Path]:
    paths: list[Path] = []
    seen: set[Path] = set()
    for value in values:
        candidate = Path(value).expanduser()
        if not candidate.exists():
            raise RawEvaluationError(f"input does not exist: {candidate}")
        discovered = sorted(path for path in candidate.rglob("*.txt") if path.is_file()) if candidate.is_dir() else [candidate]
        if not discovered:
            raise RawEvaluationError(f"input directory contains no .txt files: {candidate}")
        for path in discovered:
            resolved = path.resolve()
            if resolved not in seen:
                seen.add(resolved)
                paths.append(resolved)
    return paths


def _iter_line_chunks(
    path: Path,
    *,
    encoding: str,
    max_chars: int,
) -> Iterator[tuple[int, str]]:
    """Yield ``(input_character_offset, text)`` without splitting normal lines."""

    offset = 0
    chunks: list[str] = []
    chunk_chars = 0
    chunk_start = 0
    with path.open("r", encoding=encoding, newline="") as stream:
        for line in stream:
            if chunks and chunk_chars + len(line) > max_chars:
                value = "".join(chunks)
                yield chunk_start, value
                offset += len(value)
                chunks = []
                chunk_chars = 0
                chunk_start = offset
            # A single unusually long physical line remains one chunk. Splitting
            # it would change token/context boundaries and invalidate coverage.
            chunks.append(line)
            chunk_chars += len(line)
        if chunks:
            yield chunk_start, "".join(chunks)


def _prefix_through_complete_lines(text: str, limit: int) -> str:
    """Return the longest whole-physical-line prefix no longer than ``limit``."""

    if limit < 0:
        raise ValueError("line-prefix limit cannot be negative")
    chosen: list[str] = []
    characters = 0
    for line in text.splitlines(keepends=True):
        if characters + len(line) > limit:
            break
        chosen.append(line)
        characters += len(line)
    return "".join(chosen)


@dataclass(slots=True)
class RawCounts:
    chunks: int = 0
    characters: int = 0
    utf8_bytes: int = 0
    all_nonspace_tokens: int = 0
    lexical_tokens: int = 0
    dictionary_tokens: int = 0
    fixlist_only_tokens: int = 0
    deterministic_rule_only_tokens: int = 0
    analyzer_guess_only_tokens: int = 0
    guesser_only_tokens: int = 0
    guesser_tokens_with_shorter_lemma: int = 0
    guesser_tokens_with_top1_shorter_lemma: int = 0
    guesser_tokens_with_shorter_identity_lemma: int = 0
    guesser_tokens_with_stem_final_alternation: int = 0
    guesser_tokens_with_top1_stem_final_alternation: int = 0
    guesser_candidate_analyses: int = 0
    guesser_candidates_with_shorter_lemma: int = 0
    guesser_candidates_with_stem_final_alternation: int = 0
    unknown_only_tokens: int = 0
    zero_analysis_tokens: int = 0
    candidate_analyses: int = 0
    maximum_candidates: int = 0
    token_kinds: Counter[str] = field(default_factory=Counter)
    lexical_analysis_sources: Counter[str] = field(default_factory=Counter)

    def add_document(self, document: Any, source_text: str) -> None:
        reconstructed = "".join(token.text for token in document.tokens)
        if reconstructed != source_text:
            raise RawEvaluationError("analyzer document failed exact reconstruction")
        self.chunks += 1
        self.characters += len(source_text)
        self.utf8_bytes += len(source_text.encode("utf-8"))
        for token in document.tokens:
            self.token_kinds[token.kind] += 1
            if token.kind == "space" or not token.text:
                continue
            self.all_nonspace_tokens += 1
            genuine = [analysis for analysis in token.analyses if analysis.source != "unknown"]
            if token.kind not in {"word", "number"}:
                continue
            self.lexical_tokens += 1
            self.lexical_analysis_sources.update(
                analysis.source for analysis in token.analyses
            )
            self.candidate_analyses += len(genuine)
            self.maximum_candidates = max(self.maximum_candidates, len(genuine))
            has_dictionary = any(
                analysis.source == "lexicon" and not analysis.guessed
                for analysis in genuine
            )
            has_fixlist = any(
                analysis.source == "fixlist" and not analysis.guessed
                for analysis in genuine
            )
            has_guesser = any(analysis.source == "guesser" for analysis in genuine)
            if has_guesser:
                guesser_candidates = [
                    analysis for analysis in genuine if analysis.source == "guesser"
                ]
                # The productive guesser sees Analyzer's NFC surface, while
                # ``token.text`` deliberately preserves the original bytes for
                # exact reconstruction.  Validate and classify roots against
                # the same normalized surface that was sent to HFST.
                folded_surface = (
                    token.normalized
                    if token.normalized is not None
                    else unicodedata.normalize("NFC", token.text)
                ).casefold()
                kinds = [
                    productive_root_kind(folded_surface, analysis.lemma)
                    for analysis in guesser_candidates
                ]
                if any(kind is None for kind in kinds):
                    raise RawEvaluationError(
                        "productive guesser emitted a lemma outside its bounded root "
                        f"relation for {token.text!r}"
                    )
                shorter_identity = sum(
                    kind == "identity"
                    and len(analysis.lemma.casefold()) < len(folded_surface)
                    for analysis, kind in zip(guesser_candidates, kinds)
                )
                alternations = sum(
                    kind == "stem_final_alternation" for kind in kinds
                )
                shorter = shorter_identity + alternations
                self.guesser_candidate_analyses += len(guesser_candidates)
                self.guesser_candidates_with_shorter_lemma += shorter
                self.guesser_candidates_with_stem_final_alternation += alternations
                self.guesser_tokens_with_shorter_lemma += int(shorter > 0)
                self.guesser_tokens_with_shorter_identity_lemma += int(
                    shorter_identity > 0
                )
                self.guesser_tokens_with_stem_final_alternation += int(
                    alternations > 0
                )
                self.guesser_tokens_with_top1_shorter_lemma += int(
                    bool(guesser_candidates)
                    and (
                        kinds[0] == "stem_final_alternation"
                        or (
                            kinds[0] == "identity"
                            and len(guesser_candidates[0].lemma.casefold())
                            < len(folded_surface)
                        )
                    )
                )
                self.guesser_tokens_with_top1_stem_final_alternation += int(
                    bool(kinds) and kinds[0] == "stem_final_alternation"
                )
            has_deterministic_rule = any(
                analysis.source == "rule" for analysis in genuine
            )
            has_analyzer_guess = bool(genuine) and all(
                analysis.guessed for analysis in genuine
            )
            has_unknown = any(analysis.source == "unknown" for analysis in token.analyses)
            if has_dictionary:
                self.dictionary_tokens += 1
            elif has_fixlist:
                self.fixlist_only_tokens += 1
            elif has_guesser:
                self.guesser_only_tokens += 1
            elif has_deterministic_rule:
                self.deterministic_rule_only_tokens += 1
            elif has_analyzer_guess:
                # The base analyzer can emit licensed ``<unk>`` readings (for
                # example unknown proper names).  They are real candidates,
                # but they are neither dictionary coverage nor the separate
                # productive OOV guesser and must not be reported as zero.
                self.analyzer_guess_only_tokens += 1
            elif has_unknown:
                self.unknown_only_tokens += 1
            else:
                self.zero_analysis_tokens += 1

    @staticmethod
    def _ratio(value: int, total: int) -> dict[str, int | float | None]:
        return {"count": value, "total": total, "value": value / total if total else None}

    def as_json(self) -> dict[str, Any]:
        classified = (
            self.dictionary_tokens
            + self.fixlist_only_tokens
            + self.deterministic_rule_only_tokens
            + self.analyzer_guess_only_tokens
            + self.guesser_only_tokens
            + self.unknown_only_tokens
            + self.zero_analysis_tokens
        )
        if classified != self.lexical_tokens:
            raise AssertionError("raw lexical origin buckets are not exhaustive")
        value = asdict(self)
        value["token_kinds"] = dict(sorted(self.token_kinds.items()))
        value["lexical_analysis_sources"] = dict(
            sorted(self.lexical_analysis_sources.items())
        )
        value["dictionary_coverage"] = self._ratio(
            self.dictionary_tokens, self.lexical_tokens
        )
        value["fixlist_only_coverage"] = self._ratio(
            self.fixlist_only_tokens, self.lexical_tokens
        )
        value["deterministic_rule_only_coverage"] = self._ratio(
            self.deterministic_rule_only_tokens, self.lexical_tokens
        )
        value["analyzer_guess_only_coverage"] = self._ratio(
            self.analyzer_guess_only_tokens, self.lexical_tokens
        )
        value["guesser_only_coverage"] = self._ratio(
            self.guesser_only_tokens, self.lexical_tokens
        )
        value["guesser_tokens_with_shorter_lemma_rate"] = self._ratio(
            self.guesser_tokens_with_shorter_lemma, self.guesser_only_tokens
        )
        value["guesser_tokens_with_top1_shorter_lemma_rate"] = self._ratio(
            self.guesser_tokens_with_top1_shorter_lemma, self.guesser_only_tokens
        )
        value["guesser_tokens_with_shorter_identity_lemma_rate"] = self._ratio(
            self.guesser_tokens_with_shorter_identity_lemma,
            self.guesser_only_tokens,
        )
        value["guesser_tokens_with_stem_final_alternation_rate"] = self._ratio(
            self.guesser_tokens_with_stem_final_alternation,
            self.guesser_only_tokens,
        )
        value[
            "guesser_tokens_with_top1_stem_final_alternation_rate"
        ] = self._ratio(
            self.guesser_tokens_with_top1_stem_final_alternation,
            self.guesser_only_tokens,
        )
        value["guesser_candidates_with_shorter_lemma_rate"] = self._ratio(
            self.guesser_candidates_with_shorter_lemma,
            self.guesser_candidate_analyses,
        )
        value["guesser_candidates_with_stem_final_alternation_rate"] = self._ratio(
            self.guesser_candidates_with_stem_final_alternation,
            self.guesser_candidate_analyses,
        )
        value["explicit_unknown_rate"] = self._ratio(
            self.unknown_only_tokens, self.lexical_tokens
        )
        value["zero_analysis_rate"] = self._ratio(
            self.zero_analysis_tokens, self.lexical_tokens
        )
        value["mean_candidates_per_lexical_token"] = (
            self.candidate_analyses / self.lexical_tokens if self.lexical_tokens else None
        )
        value["origin_buckets_exhaustive"] = {
            "classified": classified,
            "total": self.lexical_tokens,
            "value": classified == self.lexical_tokens,
        }
        return value


def _rss_bytes(who: int = resource.RUSAGE_SELF) -> int | None:
    try:
        raw = resource.getrusage(who).ru_maxrss
    except (AttributeError, OSError, ValueError):
        return None
    return int(raw if sys.platform == "darwin" else raw * 1024)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Evaluate losslessness, operational coverage, and throughput on existing raw text; no data is downloaded."
    )
    parser.add_argument("input", nargs="+", help="existing UTF text file or directory")
    parser.add_argument("--resource-dir")
    parser.add_argument("--fixlist")
    parser.add_argument("--output", default="-")
    parser.add_argument("--pretty", action="store_true")
    parser.add_argument("--encoding", default="utf-8")
    parser.add_argument("--chunk-chars", type=int, default=100_000, metavar="N")
    parser.add_argument("--max-chars", type=int, metavar="N")
    parser.add_argument("--no-guesser", action="store_true")
    parser.add_argument("--guess-limit", type=int, default=8, metavar="N")
    parser.add_argument(
        "--ud-profile",
        choices=("universal", "ktb"),
        default="universal",
        help="UD projection profile (default: universal)",
    )
    parser.add_argument("--generate-all", action="store_true")
    parser.add_argument("--progress-every", type=int, default=0, metavar="N")
    return parser


def run(args: argparse.Namespace) -> dict[str, Any]:
    try:
        from qazmorph import Analyzer, __version__
    except ImportError as exc:
        raise RawEvaluationError("qazmorph is not importable from this checkout") from exc

    software_snapshot = _software_provenance()
    paths = _expand_inputs(args.input)
    inputs = [
        {"path": str(path), "bytes": path.stat().st_size, "sha256": _sha256(path)}
        for path in paths
    ]
    input_manifests = []
    for path in paths:
        sidecar = path.with_name(path.name + ".json")
        if sidecar.is_file():
            input_manifests.append(
                {
                    "path": str(sidecar.resolve()),
                    "bytes": sidecar.stat().st_size,
                    "sha256": _sha256(sidecar),
                }
            )
    fixlist_metadata = None
    if args.fixlist:
        fixlist_path = Path(args.fixlist).expanduser().resolve()
        fixlist_metadata = {
            "path": str(fixlist_path),
            "bytes": fixlist_path.stat().st_size,
            "sha256": _sha256(fixlist_path),
        }
    analyzer = Analyzer(
        args.resource_dir,
        guess=not args.no_guesser,
        fixlist=args.fixlist,
        guess_limit=args.guess_limit,
        ud_profile=args.ud_profile,
    )
    resource_snapshot = _resource_provenance(analyzer)
    runtime_official = resource_snapshot["runtime"].get("official") is True
    runtime_validity = {
        "official_runtime": runtime_official,
        "valid_for_official_result_claims": runtime_official,
        "non_official_reasons": list(
            resource_snapshot["runtime"].get("non_official_reasons", ())
        ),
    }
    counts = RawCounts()
    input_characters = 0
    started = time.perf_counter()
    try:
        stop = False
        for path in paths:
            for offset, text in _iter_line_chunks(
                path, encoding=args.encoding, max_chars=args.chunk_chars
            ):
                truncated_at_line_boundary = False
                if args.max_chars is not None:
                    remaining = args.max_chars - input_characters
                    if remaining <= 0:
                        stop = True
                        break
                    if len(text) > remaining:
                        text = _prefix_through_complete_lines(text, remaining)
                        truncated_at_line_boundary = True
                        if not text:
                            stop = True
                            break
                try:
                    document = analyzer.analyze(text, generate_all=args.generate_all)
                except Exception as exc:
                    raise RawEvaluationError(
                        f"analysis failed for {path} at character {offset}: {exc}"
                    ) from exc
                counts.add_document(document, text)
                input_characters += len(text)
                if args.progress_every and counts.chunks % args.progress_every == 0:
                    print(
                        f"evaluated {counts.chunks} chunks / {counts.characters} characters",
                        file=sys.stderr,
                        flush=True,
                    )
                if truncated_at_line_boundary or (
                    args.max_chars is not None and input_characters >= args.max_chars
                ):
                    stop = True
                    break
            if stop:
                break
    finally:
        elapsed = time.perf_counter() - started
        guesser_diagnostics = analyzer.guesser.diagnostics
        analyzer.close()
        child_peak_rss = _rss_bytes(resource.RUSAGE_CHILDREN)

    if counts.chunks == 0:
        raise RawEvaluationError("inputs contain no evaluable text")
    final_inputs = [
        {"path": str(path), "bytes": path.stat().st_size, "sha256": _sha256(path)}
        for path in paths
    ]
    if final_inputs != inputs:
        raise RawEvaluationError("an input changed while evaluation was running")
    final_input_manifests = []
    for item in input_manifests:
        sidecar = Path(item["path"])
        final_input_manifests.append(
            {
                "path": str(sidecar),
                "bytes": sidecar.stat().st_size,
                "sha256": _sha256(sidecar),
            }
        )
    if final_input_manifests != input_manifests:
        raise RawEvaluationError("an input provenance manifest changed during evaluation")
    if args.fixlist:
        fixlist_path = Path(args.fixlist).expanduser().resolve()
        final_fixlist_metadata = {
            "path": str(fixlist_path),
            "bytes": fixlist_path.stat().st_size,
            "sha256": _sha256(fixlist_path),
        }
        if final_fixlist_metadata != fixlist_metadata:
            raise RawEvaluationError("fixlist changed while evaluation was running")
    if _software_provenance() != software_snapshot:
        raise RawEvaluationError("evaluator or imported qazmorph sources changed during evaluation")
    if _resource_provenance(analyzer) != resource_snapshot:
        raise RawEvaluationError("resource or runtime provenance changed during evaluation")

    return {
        "schema_version": SCHEMA_VERSION,
        "tool": {
            "qazmorph_version": __version__,
            "python_version": platform.python_version(),
            "platform": platform.platform(),
            "hostname": platform.node(),
            "software": software_snapshot,
        },
        "configuration": {
            "guesser": not args.no_guesser,
            "guess_limit": args.guess_limit,
            "ud_profile": args.ud_profile,
            "generate_all": args.generate_all,
            "encoding": args.encoding,
            "chunk_chars": args.chunk_chars,
            "max_chars": args.max_chars,
            "max_chars_policy": "never split a physical line",
            "fixlist": fixlist_metadata,
        },
        "inputs": inputs,
        "input_manifests": input_manifests,
        "resources": resource_snapshot,
        "validity": runtime_validity,
        "lossless_reconstruction": {
            "correct_chunks": counts.chunks,
            "total_chunks": counts.chunks,
            "value": 1.0,
        },
        "coverage": counts.as_json(),
        "oov_lattice_completeness": {
            "status": (
                "not_applicable_disabled"
                if args.no_guesser
                else (
                    "complete"
                    if not any(
                        guesser_diagnostics.get(name, 0)
                        for name in (
                            "cap_aborts",
                            "timeouts",
                            "failures",
                            "cycle_truncations",
                            "unsafe_resource_skips",
                        )
                    )
                    and bool(
                        guesser_diagnostics.get("productive_resource_safe", 1)
                    )
                    else "incomplete"
                )
            ),
            "complete": (
                None
                if args.no_guesser
                else not any(
                    guesser_diagnostics.get(name, 0)
                    for name in (
                        "cap_aborts",
                        "timeouts",
                        "failures",
                        "cycle_truncations",
                        "unsafe_resource_skips",
                    )
                )
                and bool(guesser_diagnostics.get("productive_resource_safe", 1))
            ),
            "definition": (
                "when the guesser is enabled, false means a productive lookup hit a "
                "deterministic response cap, timed out, failed, or emitted HFST's cyclic "
                "truncation marker, or was disabled for an unsafe legacy resource; "
                "lossless reconstruction and explicit fallback coverage remain valid, "
                "but the OOV lattice is bounded"
            ),
        },
        "guesser_diagnostics": guesser_diagnostics,
        "performance": {
            "elapsed_scope": (
                "wall time after Analyzer initialization through file decoding, analysis, "
                "and counting; excludes Analyzer initialization, provenance hashing, JSON "
                "serialization, and final close"
            ),
            "elapsed_seconds": elapsed,
            "tokens_per_second": counts.all_nonspace_tokens / elapsed,
            "lexical_tokens_per_second": counts.lexical_tokens / elapsed,
            "characters_per_second": counts.characters / elapsed,
            "utf8_bytes_per_second": counts.utf8_bytes / elapsed,
            "python_peak_rss_bytes": _rss_bytes(),
            "largest_child_peak_rss_bytes": child_peak_rss,
        },
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.chunk_chars < 1:
        parser.error("--chunk-chars must be positive")
    if args.max_chars is not None and args.max_chars < 1:
        parser.error("--max-chars must be positive")
    if args.guess_limit < 1:
        parser.error("--guess-limit must be positive")
    if args.progress_every < 0:
        parser.error("--progress-every cannot be negative")
    try:
        report = run(args)
        encoded = json.dumps(
            report,
            ensure_ascii=False,
            indent=2 if args.pretty else None,
            sort_keys=True,
            separators=None if args.pretty else (",", ":"),
        ) + "\n"
        if args.output == "-":
            sys.stdout.write(encoded)
        else:
            Path(args.output).expanduser().write_text(encoded, encoding="utf-8")
    except (RawEvaluationError, OSError, UnicodeError, ValueError) as exc:
        parser.exit(2, f"evaluate_raw.py: error: {exc}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
