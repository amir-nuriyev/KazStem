#!/usr/bin/env python3
"""Formally verify the bounded productive generator and its runtime image."""

from __future__ import annotations

import argparse
from collections import defaultdict
from dataclasses import dataclass
import hashlib
import json
import math
import os
from pathlib import Path
import re
import subprocess
import tempfile
from typing import Any, Iterable, Sequence
import unicodedata


SCHEMA = "qazmorph-productive-generator-finiteness-v2"
PROBE_SCHEMA = "qazmorph-guesser-regression-probes-v1"
DIRECTION_PROBE_SCHEMA = "qazmorph-productive-generator-probes-v1"
EPSILON_INPUTS = frozenset({"@0@", "@_EPSILON_SYMBOL_@"})
CYCLE_MARKER = "[...cyclic...]"
CONTROL_MARKER_RE = re.compile(r"\[[^\]\r\n]*\]", re.IGNORECASE)
GRAPH_EXPORT_TIMEOUT_SECONDS = 60.0
FORMAL_COMMAND_TIMEOUT_SECONDS = 120.0
LOOKUP_TIMEOUT_SECONDS = 60.0
EXPECTED_DIRECTION_PROBES = {
    "canonical_short_instrumental_only": (
        "тосынтүбір<n><ins>",
        ("тосынтүбірмен",),
        ("тосынтүбірменен",),
    ),
    "canonical_adjective_comparative_only": (
        "тосынсапа<adj><comp>",
        ("тосынсапарақ",),
        ("тосынсапалау",),
    ),
    "canonical_verb_future_plan_only": (
        "тосынет<v><iv><fut_plan><p3><sg>",
        ("тосынетпек",),
        ("тосынетпекші",),
    ),
}


class VerificationError(RuntimeError):
    """Raised when a generator relation violates its formal contract."""


@dataclass(frozen=True)
class ProbePairs:
    required: tuple[tuple[str, str], ...]
    forbidden: tuple[tuple[str, str], ...]
    queries: tuple[str, ...]


def _file_identity(path: Path) -> dict[str, int | str]:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
        stat = os.fstat(stream.fileno())
    return {"bytes": stat.st_size, "sha256": digest.hexdigest()}


def _atomic_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(value, stream, ensure_ascii=False, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o644)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _run_command(
    command: Sequence[str],
    *,
    timeout: float = FORMAL_COMMAND_TIMEOUT_SECONDS,
    input_text: str | None = None,
    operation: str,
) -> subprocess.CompletedProcess[str]:
    try:
        completed = subprocess.run(
            list(command),
            input=input_text,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="strict",
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise VerificationError(
            f"{operation} exceeded its {timeout:.1f}s timeout"
        ) from exc
    except (OSError, UnicodeError) as exc:
        raise VerificationError(f"{operation} could not run: {exc}") from exc
    if completed.returncode:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise VerificationError(
            f"{operation} failed with status {completed.returncode}: {detail}"
        )
    return completed


def _control_markers(*texts: str) -> tuple[int, int, tuple[str, ...]]:
    markers: list[str] = []
    for text in texts:
        markers.extend(match.group(0) for match in CONTROL_MARKER_RE.finditer(text))
    cycles = sum(marker.casefold() == CYCLE_MARKER for marker in markers)
    caps = len(markers) - cycles
    return cycles, caps, tuple(markers)


def _reject_control_markers(operation: str, *texts: str) -> None:
    cycles, caps, markers = _control_markers(*texts)
    if cycles or caps:
        raise VerificationError(
            f"{operation} emitted a cycle/cap control marker: {markers[0]!r}"
        )


def _parse_graph(
    lines: Iterable[str],
) -> tuple[
    set[int],
    set[int],
    dict[int, set[int]],
    dict[int, set[int]],
    int,
    int,
]:
    states: set[int] = {0}
    finals: set[int] = set()
    adjacency: dict[int, set[int]] = defaultdict(set)
    epsilon_adjacency: dict[int, set[int]] = defaultdict(set)
    arc_count = 0
    epsilon_arc_count = 0
    separators = 0

    for line_number, raw_line in enumerate(lines, start=1):
        line = raw_line.rstrip("\r\n")
        if not line:
            continue
        if line == "--":
            separators += 1
            continue
        fields = line.split("\t")
        try:
            if len(fields) in {4, 5}:
                source = int(fields[0])
                target = int(fields[1])
                input_symbol = fields[2]
                if source < 0 or target < 0 or not input_symbol:
                    raise ValueError("invalid state or input symbol")
                if len(fields) == 5 and not math.isfinite(float(fields[4])):
                    raise ValueError("non-finite arc weight")
                states.update((source, target))
                adjacency[source].add(target)
                arc_count += 1
                if input_symbol in EPSILON_INPUTS:
                    epsilon_adjacency[source].add(target)
                    epsilon_arc_count += 1
            elif len(fields) in {1, 2}:
                state = int(fields[0])
                if state < 0:
                    raise ValueError("negative final state")
                if len(fields) == 2 and not math.isfinite(float(fields[1])):
                    raise ValueError("non-finite final weight")
                states.add(state)
                finals.add(state)
            else:
                raise ValueError("unsupported field count")
        except ValueError as exc:
            raise VerificationError(
                f"cannot parse hfst-fst2txt line {line_number}: {line!r}"
            ) from exc

    if separators:
        raise VerificationError(
            f"expected one transducer, found {separators + 1} in hfst-fst2txt output"
        )
    if not finals:
        raise VerificationError("productive generator transducer has no final state")
    return (
        states,
        finals,
        dict(adjacency),
        dict(epsilon_adjacency),
        arc_count,
        epsilon_arc_count,
    )


def _reachable(initial: int, adjacency: dict[int, set[int]]) -> set[int]:
    reached = {initial}
    pending = [initial]
    while pending:
        source = pending.pop()
        for target in adjacency.get(source, ()):
            if target not in reached:
                reached.add(target)
                pending.append(target)
    return reached


def find_reachable_input_epsilon_cycle(
    adjacency: dict[int, set[int]], epsilon_adjacency: dict[int, set[int]]
) -> tuple[int, ...] | None:
    """Return a deterministic reachable input-epsilon cycle, if one exists."""

    reachable = _reachable(0, adjacency)
    colour: dict[int, int] = {}
    path: list[int] = []
    positions: dict[int, int] = {}

    for start in sorted(reachable):
        if colour.get(start, 0):
            continue
        colour[start] = 1
        positions[start] = len(path)
        path.append(start)
        stack: list[tuple[int, Any]] = [
            (start, iter(sorted(epsilon_adjacency.get(start, ()))))
        ]
        while stack:
            source, targets = stack[-1]
            try:
                target = next(targets)
            except StopIteration:
                stack.pop()
                finished = path.pop()
                positions.pop(finished, None)
                colour[finished] = 2
                continue
            if target not in reachable:
                continue
            target_colour = colour.get(target, 0)
            if target_colour == 1:
                return tuple(path[positions[target] :] + [target])
            if target_colour == 0:
                colour[target] = 1
                positions[target] = len(path)
                path.append(target)
                stack.append(
                    (target, iter(sorted(epsilon_adjacency.get(target, ()))))
                )
    return None


def verify_graph(fst: Path, fst2txt: str) -> dict[str, int | bool | str]:
    completed = _run_command(
        [fst2txt, str(fst)],
        timeout=GRAPH_EXPORT_TIMEOUT_SECONDS,
        operation="productive-generator graph export",
    )
    _reject_control_markers(
        "productive-generator graph export", completed.stdout, completed.stderr
    )
    states, finals, adjacency, epsilon_adjacency, arcs, epsilon_arcs = _parse_graph(
        completed.stdout.splitlines()
    )
    reachable = _reachable(0, adjacency)
    cycle = find_reachable_input_epsilon_cycle(adjacency, epsilon_adjacency)
    if cycle is not None:
        rendered = " -> ".join(str(state) for state in cycle[:20])
        if len(cycle) > 20:
            rendered += " -> ..."
        raise VerificationError(
            "productive generator has a reachable input-epsilon cycle: " + rendered
        )
    return {
        "orientation": "lexical_analysis_to_surface",
        "states": len(states),
        "reachable_states": len(reachable),
        "final_states": len(finals),
        "arcs": arcs,
        "input_epsilon_arcs": epsilon_arcs,
        "reachable_input_epsilon_cycle": False,
        "finite_valued_per_finite_lexical_input": True,
    }


def _require_created(path: Path, operation: str) -> None:
    if not path.is_file():
        raise VerificationError(f"{operation} did not create its output transducer")


def _invert(source: Path, destination: Path, invert: str, operation: str) -> None:
    _run_command(
        [invert, str(source), "-o", str(destination)], operation=operation
    )
    _require_created(destination, operation)


def _disjunct(
    first: Path, second: Path, destination: Path, disjunct: str, operation: str
) -> None:
    _run_command(
        [
            disjunct,
            "-1",
            str(first),
            "-2",
            str(second),
            "-o",
            str(destination),
        ],
        operation=operation,
    )
    _require_created(destination, operation)


def _first_counterexample(fst: Path, fst2strings: str, operation: str) -> str:
    completed = _run_command(
        [fst2strings, "-n", "1", str(fst)], operation=operation
    )
    _reject_control_markers(operation, completed.stdout, completed.stderr)
    return completed.stdout.strip()


def _difference_is_empty(
    first: Path,
    second: Path,
    destination: Path,
    *,
    subtract: str,
    fst2strings: str,
    operation: str,
) -> bool:
    _run_command(
        [
            subtract,
            "-1",
            str(first),
            "-2",
            str(second),
            "-o",
            str(destination),
        ],
        operation=operation,
    )
    _require_created(destination, operation)
    counterexample = _first_counterexample(
        destination, fst2strings, f"{operation} counterexample search"
    )
    if counterexample:
        raise VerificationError(
            f"{operation} is non-empty; counterexample: {counterexample!r}"
        )
    return True


def verify_inverse_relation(
    analyzer_fst: Path,
    generator_fst: Path,
    *,
    invert: str,
    subtract: str,
    fst2strings: str,
) -> dict[str, bool | str]:
    with tempfile.TemporaryDirectory(prefix="qazmorph-generator-inverse.") as temporary:
        root = Path(temporary)
        generator_inverse = root / "generator-inverse.hfst"
        analyzer_only = root / "analyzer-not-generator-inverse.hfst"
        inverse_only = root / "generator-inverse-not-analyzer.hfst"
        _invert(
            generator_fst,
            generator_inverse,
            invert,
            "productive-generator inversion",
        )
        _difference_is_empty(
            analyzer_fst,
            generator_inverse,
            analyzer_only,
            subtract=subtract,
            fst2strings=fst2strings,
            operation="productive analyzer minus generator inverse",
        )
        _difference_is_empty(
            generator_inverse,
            analyzer_fst,
            inverse_only,
            subtract=subtract,
            fst2strings=fst2strings,
            operation="generator inverse minus productive analyzer",
        )
    return {
        "generator_inverse_equals_productive_analyzer": True,
        "productive_analyzer_minus_generator_inverse_empty": True,
        "generator_inverse_minus_productive_analyzer_empty": True,
        "operation": (
            "productive_analyzer - inverse(productive_generator) = empty and "
            "inverse(productive_generator) - productive_analyzer = empty"
        ),
    }


def verify_generation_direction_relation(
    generation_safe_analyzer_fst: Path,
    full_analyzer_fst: Path,
    *,
    subtract: str,
    fst2strings: str,
) -> dict[str, bool | str]:
    """Prove generation-safe morphology is a strict subset of analysis."""

    with tempfile.TemporaryDirectory(prefix="qazmorph-generator-direction.") as temporary:
        root = Path(temporary)
        safe_only = root / "generation-safe-not-full.hfst"
        analysis_only = root / "full-not-generation-safe.hfst"
        _difference_is_empty(
            generation_safe_analyzer_fst,
            full_analyzer_fst,
            safe_only,
            subtract=subtract,
            fst2strings=fst2strings,
            operation="generation-safe productive analyzer minus full analyzer",
        )
        _run_command(
            [
                subtract,
                "-1",
                str(full_analyzer_fst),
                "-2",
                str(generation_safe_analyzer_fst),
                "-o",
                str(analysis_only),
            ],
            operation="full productive analyzer minus generation-safe analyzer",
        )
        _require_created(
            analysis_only,
            "full productive analyzer minus generation-safe analyzer",
        )
        counterexample = _first_counterexample(
            analysis_only,
            fst2strings,
            "analysis-only productive-relation counterexample search",
        )
        if not counterexample:
            raise VerificationError(
                "generation-safe analyzer unexpectedly equals the full analyzer; "
                "the Dir/LR exclusion is not evidenced"
            )
    return {
        "generation_safe_analyzer_subset_of_full_analyzer": True,
        "generation_safe_minus_full_empty": True,
        "full_minus_generation_safe_nonempty": True,
        "analysis_only_counterexample_present": True,
        "operation": (
            "generation_safe - full = empty and full - generation_safe is non-empty"
        ),
    }


def verify_optimized_relation(
    standard_fst: Path,
    optimized_fst: Path,
    *,
    fst2fst: str,
    subtract: str,
    fst2strings: str,
) -> dict[str, bool | str]:
    with tempfile.TemporaryDirectory(prefix="qazmorph-generator-optimized.") as temporary:
        root = Path(temporary)
        round_trip = root / "optimized-roundtrip.hfst"
        standard_only = root / "standard-not-optimized.hfst"
        optimized_only = root / "optimized-not-standard.hfst"
        _run_command(
            [
                fst2fst,
                "-f",
                "openfst-tropical",
                str(optimized_fst),
                "-o",
                str(round_trip),
            ],
            operation="optimized productive-generator round trip",
        )
        _require_created(round_trip, "optimized productive-generator round trip")
        _difference_is_empty(
            standard_fst,
            round_trip,
            standard_only,
            subtract=subtract,
            fst2strings=fst2strings,
            operation="standard generator minus optimized round trip",
        )
        _difference_is_empty(
            round_trip,
            standard_fst,
            optimized_only,
            subtract=subtract,
            fst2strings=fst2strings,
            operation="optimized round trip minus standard generator",
        )
    return {
        "full_relation_equivalent_to_standard": True,
        "standard_minus_optimized_roundtrip_empty": True,
        "optimized_roundtrip_minus_standard_empty": True,
        "operation": (
            "standard - optimized_roundtrip = empty and "
            "optimized_roundtrip - standard = empty"
        ),
    }


def verify_installed_artifact_relations(
    dictionary_generator_fst: Path,
    dictionary_generator_optimized_fst: Path,
    dictionary_analyzer_fst: Path,
    dictionary_analyzer_optimized_fst: Path,
    full_productive_analyzer_fst: Path,
    full_productive_analyzer_optimized_fst: Path,
    *,
    invert: str,
    fst2fst: str,
    subtract: str,
    fst2strings: str,
) -> dict[str, Any]:
    """Prove all installed optimized morphology images preserve relations."""

    dictionary_generator = verify_optimized_relation(
        dictionary_generator_fst,
        dictionary_generator_optimized_fst,
        fst2fst=fst2fst,
        subtract=subtract,
        fst2strings=fst2strings,
    )
    full_productive_analyzer = verify_optimized_relation(
        full_productive_analyzer_fst,
        full_productive_analyzer_optimized_fst,
        fst2fst=fst2fst,
        subtract=subtract,
        fst2strings=fst2strings,
    )
    with tempfile.TemporaryDirectory(prefix="qazmorph-installed-analyzer.") as temporary:
        dictionary_analyzer_surface_to_lexical = (
            Path(temporary) / "dictionary-analyzer-surface-to-lexical.hfst"
        )
        _invert(
            dictionary_analyzer_fst,
            dictionary_analyzer_surface_to_lexical,
            invert,
            "dictionary-analyzer orientation inversion",
        )
        dictionary_analyzer = verify_optimized_relation(
            dictionary_analyzer_surface_to_lexical,
            dictionary_analyzer_optimized_fst,
            fst2fst=fst2fst,
            subtract=subtract,
            fst2strings=fst2strings,
        )
    return {
        "dictionary_generator": dictionary_generator,
        "dictionary_analyzer_surface_to_lexical": dictionary_analyzer,
        "full_productive_analyzer": full_productive_analyzer,
        "all_installed_relations_equivalent_to_standard": True,
    }


def _load_probe_pairs(path: Path) -> ProbePairs:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise VerificationError(f"cannot load probe fixture {path}: {exc}") from exc
    if not isinstance(payload, dict) or payload.get("schema") != PROBE_SCHEMA:
        raise VerificationError(f"unsupported probe fixture schema: {path}")
    probes = payload.get("probes")
    if not isinstance(probes, list) or not probes:
        raise VerificationError(f"probe fixture is empty or malformed: {path}")

    required: set[tuple[str, str]] = set()
    forbidden: set[tuple[str, str]] = set()
    seen_surfaces: set[str] = set()
    for index, probe in enumerate(probes):
        if not isinstance(probe, dict):
            raise VerificationError(f"probe {index} is not an object")
        surface = probe.get("surface")
        expected = probe.get("expected_readings", [])
        excluded = probe.get("forbidden_readings", [])
        if (
            not isinstance(surface, str)
            or not surface
            or surface != unicodedata.normalize("NFC", surface)
            or any(character in surface for character in "\t\r\n\0")
            or surface in seen_surfaces
            or not isinstance(expected, list)
            or not isinstance(excluded, list)
            or any(
                not isinstance(reading, str)
                or not reading
                or reading != unicodedata.normalize("NFC", reading)
                or any(character in reading for character in "\t\r\n\0")
                for reading in expected + excluded
            )
            or bool(set(expected) & set(excluded))
        ):
            raise VerificationError(f"probe {index} is invalid: {probe!r}")
        seen_surfaces.add(surface)
        required.update((reading, surface) for reading in expected)
        forbidden.update((reading, surface) for reading in excluded)

    if not required:
        raise VerificationError("probe fixture has no required inversion pair")
    if not forbidden:
        raise VerificationError("probe fixture has no forbidden inversion pair")
    overlap = required & forbidden
    if overlap:
        raise VerificationError(
            f"probe fixture requires and forbids the same inversion pair: {sorted(overlap)!r}"
        )
    queries = tuple(sorted({reading for reading, _ in required | forbidden}))
    return ProbePairs(tuple(sorted(required)), tuple(sorted(forbidden)), queries)


def _load_direction_probe_pairs(path: Path) -> ProbePairs:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise VerificationError(f"cannot load direction probe fixture {path}: {exc}") from exc
    if not isinstance(payload, dict) or payload.get("schema") != DIRECTION_PROBE_SCHEMA:
        raise VerificationError(f"unsupported direction probe fixture schema: {path}")
    probes = payload.get("probes")
    if not isinstance(probes, list) or not probes:
        raise VerificationError(f"direction probe fixture is empty or malformed: {path}")

    required: set[tuple[str, str]] = set()
    forbidden: set[tuple[str, str]] = set()
    seen_queries: set[str] = set()
    seen_classes: set[str] = set()
    for index, probe in enumerate(probes):
        if not isinstance(probe, dict):
            raise VerificationError(f"direction probe {index} is not an object")
        query = probe.get("query")
        probe_class = probe.get("class")
        expected = probe.get("required_surfaces")
        excluded = probe.get("forbidden_surfaces")
        strings = (
            [query]
            if isinstance(query, str)
            else []
        ) + (
            expected if isinstance(expected, list) else []
        ) + (
            excluded if isinstance(excluded, list) else []
        )
        if (
            not isinstance(query, str)
            or not query
            or query in seen_queries
            or not isinstance(probe_class, str)
            or probe_class in seen_classes
            or probe_class not in EXPECTED_DIRECTION_PROBES
            or not isinstance(expected, list)
            or not expected
            or not isinstance(excluded, list)
            or not excluded
            or any(
                not isinstance(value, str)
                or not value
                or value != unicodedata.normalize("NFC", value)
                or any(character in value for character in "\t\r\n\0")
                for value in strings
            )
            or bool(set(expected) & set(excluded))
        ):
            raise VerificationError(
                f"direction probe {index} is invalid: {probe!r}"
            )
        expected_probe = EXPECTED_DIRECTION_PROBES[probe_class]
        if (
            query,
            tuple(expected),
            tuple(excluded),
        ) != expected_probe:
            raise VerificationError(
                f"direction probe {probe_class!r} changed its immutable pair panel"
            )
        seen_classes.add(probe_class)
        seen_queries.add(query)
        required.update((query, surface) for surface in expected)
        forbidden.update((query, surface) for surface in excluded)

    if seen_classes != set(EXPECTED_DIRECTION_PROBES):
        raise VerificationError(
            "direction probe fixture does not contain the exact required class set"
        )
    overlap = required & forbidden
    if overlap:
        raise VerificationError(
            "direction fixture requires and forbids the same pair: "
            f"{sorted(overlap)!r}"
        )
    queries = tuple(sorted(seen_queries))
    return ProbePairs(tuple(sorted(required)), tuple(sorted(forbidden)), queries)


def _merge_probe_pairs(*fixtures: ProbePairs) -> ProbePairs:
    required = set().union(*(fixture.required for fixture in fixtures))
    forbidden = set().union(*(fixture.forbidden for fixture in fixtures))
    overlap = required & forbidden
    if overlap:
        raise VerificationError(
            f"merged fixtures require and forbid the same pair: {sorted(overlap)!r}"
        )
    queries = tuple(sorted({query for query, _surface in required | forbidden}))
    return ProbePairs(tuple(sorted(required)), tuple(sorted(forbidden)), queries)


def _parse_lookup_output(
    output: str, queries: Sequence[str]
) -> dict[str, tuple[str, ...]]:
    requested = set(queries)
    if not requested or len(requested) != len(queries):
        raise VerificationError("lookup query set is empty or contains duplicates")
    _reject_control_markers("productive-generator lookup", output)
    candidates: dict[str, set[str]] = {query: set() for query in queries}
    responded: set[str] = set()
    negative: set[str] = set()

    for line_number, line in enumerate(output.splitlines(), start=1):
        if not line:
            continue
        fields = line.split("\t")
        if len(fields) not in {2, 3}:
            raise VerificationError(
                f"malformed generator response line {line_number}: {line!r}"
            )
        query = fields[0]
        if not query or query not in requested:
            raise VerificationError(
                f"unkeyed generator response line {line_number}: {line!r}"
            )
        responded.add(query)
        standard_negative = (
            len(fields) == 3
            and fields[1] == query + "+?"
            and fields[2].casefold() == "inf"
        )
        optimized_negative = (
            len(fields) == 3 and fields[1] == query and fields[2] == "+?"
        )
        has_negative_syntax = fields[1].endswith("+?") or "+?" in fields[1:]
        if has_negative_syntax and not (standard_negative or optimized_negative):
            raise VerificationError(
                f"malformed negative generator response line {line_number}: {line!r}"
            )
        is_negative = standard_negative or optimized_negative
        if is_negative:
            if candidates[query]:
                raise VerificationError(
                    f"generator mixed candidates with a negative response for {query!r}"
                )
            negative.add(query)
            continue
        if query in negative:
            raise VerificationError(
                f"generator mixed a negative response with candidates for {query!r}"
            )
        candidate = fields[1]
        if not candidate:
            raise VerificationError(
                f"generator emitted an empty candidate for query {query!r}"
            )
        if candidate == query or any(
            character in candidate for character in "<>[]{}\t\r\n\0"
        ):
            raise VerificationError(
                f"generator emitted morphology control syntax for query {query!r}"
            )
        if len(fields) == 3:
            try:
                weight = float(fields[2])
            except ValueError as exc:
                raise VerificationError(
                    f"generator emitted a malformed weight on line {line_number}: {line!r}"
                ) from exc
            if not math.isfinite(weight):
                raise VerificationError(
                    f"generator emitted a non-finite candidate weight on line {line_number}"
                )
        candidates[query].add(candidate)

    missing = sorted(requested - responded)
    if missing:
        raise VerificationError(
            "generator returned no keyed response for: "
            + ", ".join(repr(query) for query in missing[:10])
        )
    return {
        query: tuple(sorted(candidates[query]))
        for query in sorted(candidates)
    }


def _lookup_candidates(
    fst: Path,
    executable: str,
    queries: Sequence[str],
    *,
    optimized: bool,
) -> dict[str, tuple[str, ...]]:
    command = (
        [executable, "-q", "-u", str(fst)]
        if optimized
        else [executable, "-q", "-c", "0", "-i", str(fst)]
    )
    completed = _run_command(
        command,
        timeout=LOOKUP_TIMEOUT_SECONDS,
        input_text="\n".join(queries) + "\n",
        operation=(
            "optimized productive-generator fixture lookup"
            if optimized
            else "standard productive-generator fixture lookup"
        ),
    )
    _reject_control_markers(
        "productive-generator fixture lookup", completed.stdout, completed.stderr
    )
    return _parse_lookup_output(completed.stdout, queries)


def verify_inversion_probes(
    standard_fst: Path,
    optimized_fst: Path,
    probes_path: Path,
    direction_probes_path: Path,
    *,
    lookup: str,
    optimized_lookup: str,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    baseline_pairs = _load_probe_pairs(probes_path)
    direction_pairs = _load_direction_probe_pairs(direction_probes_path)
    pairs = _merge_probe_pairs(baseline_pairs, direction_pairs)
    standard = _lookup_candidates(
        standard_fst, lookup, pairs.queries, optimized=False
    )
    optimized = _lookup_candidates(
        optimized_fst, optimized_lookup, pairs.queries, optimized=True
    )
    mismatches = sorted(
        query for query in pairs.queries if standard[query] != optimized[query]
    )
    if mismatches:
        raise VerificationError(
            "optimized productive generator changed fixture candidate sets for: "
            + ", ".join(repr(query) for query in mismatches[:10])
        )

    missing = [
        {"reading": reading, "surface": surface}
        for reading, surface in pairs.required
        if surface not in standard[reading]
    ]
    if missing:
        raise VerificationError(
            f"productive generator is missing required inversion pairs: {missing[:10]!r}"
        )
    found = [
        {"reading": reading, "surface": surface}
        for reading, surface in pairs.forbidden
        if surface in standard[reading]
    ]
    if found:
        raise VerificationError(
            f"productive generator contains forbidden inversion pairs: {found[:10]!r}"
        )

    maximum = max((len(values) for values in standard.values()), default=0)
    probe_report: dict[str, Any] = {
        "required_pairs_checked": len(pairs.required),
        "required_pairs_missing": [],
        "forbidden_pairs_checked": len(pairs.forbidden),
        "forbidden_pairs_observed": 0,
        "forbidden_pairs_found": [],
        "queries": len(pairs.queries),
        "all_queries_keyed": True,
        "cycle_markers": 0,
        "cap_markers": 0,
        "lookup_result_cap_enabled": False,
        "input_epsilon_cycle_follow_limit_enabled": False,
        "maximum_distinct_candidates_per_query": maximum,
    }
    optimized_report: dict[str, Any] = {
        "candidate_sets_equal_to_standard": True,
        "standard_optimized_mismatches": [],
        "queries": len(pairs.queries),
        "cycle_markers": 0,
        "cap_markers": 0,
        "lookup_result_cap_enabled": False,
    }
    direction_report: dict[str, Any] = {
        "required_pairs_checked": len(direction_pairs.required),
        "required_pairs_missing": [],
        "forbidden_pairs_checked": len(direction_pairs.forbidden),
        "forbidden_pairs_observed": 0,
        "forbidden_pairs_found": [],
        "required_pairs": [
            {"query": query, "surface": surface}
            for query, surface in direction_pairs.required
        ],
        "forbidden_pairs": [
            {"query": query, "surface": surface}
            for query, surface in direction_pairs.forbidden
        ],
        "queries": len(direction_pairs.queries),
        "canonical_short_instrumental_only": True,
        "analysis_only_adjective_comparative_excluded": True,
        "analysis_only_verb_future_plan_excluded": True,
    }
    return probe_report, optimized_report, direction_report


def verify_combined_generation_subset(
    dictionary_generator_optimized_fst: Path,
    productive_generator_optimized_fst: Path,
    dictionary_analyzer_optimized_fst: Path,
    productive_analyzer_optimized_fst: Path,
    *,
    invert: str,
    disjunct: str,
    fst2fst: str,
    subtract: str,
    fst2strings: str,
) -> dict[str, bool | str]:
    with tempfile.TemporaryDirectory(prefix="qazmorph-combined-generation.") as temporary:
        root = Path(temporary)
        dictionary_generator = root / "dictionary-generator-runtime.hfst"
        productive_generator = root / "productive-generator-runtime.hfst"
        dictionary_analyzer_surface = root / "dictionary-analyzer-runtime.hfst"
        productive_analyzer_surface = root / "productive-analyzer-runtime.hfst"
        dictionary_analyzer_inverse = root / "dictionary-analyzer-inverse.hfst"
        productive_analyzer_inverse = root / "productive-analyzer-inverse.hfst"
        generated = root / "dictionary-plus-productive-generator.hfst"
        accepted = root / "compiled-plus-productive-analyzer.hfst"
        difference = root / "generated-not-accepted.hfst"
        for source, destination, label in (
            (
                dictionary_generator_optimized_fst,
                dictionary_generator,
                "installed dictionary generator",
            ),
            (
                productive_generator_optimized_fst,
                productive_generator,
                "installed productive generator",
            ),
            (
                dictionary_analyzer_optimized_fst,
                dictionary_analyzer_surface,
                "installed dictionary analyzer",
            ),
            (
                productive_analyzer_optimized_fst,
                productive_analyzer_surface,
                "installed productive analyzer",
            ),
        ):
            _run_command(
                [
                    fst2fst,
                    "-f",
                    "openfst-tropical",
                    str(source),
                    "-o",
                    str(destination),
                ],
                operation=f"{label} round trip for combined acceptance",
            )
            _require_created(
                destination,
                f"{label} round trip for combined acceptance",
            )
        _invert(
            dictionary_analyzer_surface,
            dictionary_analyzer_inverse,
            invert,
            "installed dictionary-analyzer inversion for combined acceptance",
        )
        _invert(
            productive_analyzer_surface,
            productive_analyzer_inverse,
            invert,
            "installed productive-analyzer inversion for combined acceptance",
        )
        _disjunct(
            dictionary_generator,
            productive_generator,
            generated,
            disjunct,
            "dictionary/productive generator union",
        )
        _disjunct(
            dictionary_analyzer_inverse,
            productive_analyzer_inverse,
            accepted,
            disjunct,
            "compiled/productive analyzer union",
        )
        _difference_is_empty(
            generated,
            accepted,
            difference,
            subtract=subtract,
            fst2strings=fst2strings,
            operation="combined generated relation minus combined accepted relation",
        )
    return {
        "dictionary_and_productive_generator_subset_of_analyzers": True,
        "generated_minus_accepted_empty": True,
        "operation": (
            "(installed_dictionary_generator | installed_productive_generator) - "
            "(inverse(installed_dictionary_analyzer) | "
            "inverse(installed_productive_analyzer)) = empty"
        ),
    }


def _validate_inputs(args: argparse.Namespace) -> None:
    inputs = (
        args.analyzer_fst,
        args.full_analyzer_fst,
        args.full_analyzer_optimized_fst,
        args.fst,
        args.optimized_fst,
        args.dictionary_generator_fst,
        args.dictionary_generator_optimized_fst,
        args.dictionary_analyzer_fst,
        args.dictionary_analyzer_optimized_fst,
        args.probes,
        args.direction_probes,
    )
    for path in inputs:
        if not path.is_file():
            raise VerificationError(f"required verifier input is missing: {path}")
    output_resolved = args.output.resolve(strict=False)
    if any(output_resolved == path.resolve() for path in inputs):
        raise VerificationError("verification output aliases a verifier input")
    if args.output.is_symlink() or (args.output.exists() and not args.output.is_file()):
        raise VerificationError("verification output must be a regular non-symlink path")


def _verification_input_identities(
    args: argparse.Namespace,
) -> dict[str, dict[str, int | str]]:
    return {
        "generation_safe_productive_analyzer_standard": _file_identity(
            args.analyzer_fst
        ),
        "full_productive_analyzer_standard": _file_identity(
            args.full_analyzer_fst
        ),
        "full_productive_analyzer_optimized": _file_identity(
            args.full_analyzer_optimized_fst
        ),
        "productive_generator_standard": _file_identity(args.fst),
        "productive_generator_optimized": _file_identity(args.optimized_fst),
        "dictionary_generator_standard": _file_identity(
            args.dictionary_generator_fst
        ),
        "dictionary_generator_optimized": _file_identity(
            args.dictionary_generator_optimized_fst
        ),
        "dictionary_analyzer_lexical_to_surface_standard": _file_identity(
            args.dictionary_analyzer_fst
        ),
        "dictionary_analyzer_surface_to_lexical_optimized": _file_identity(
            args.dictionary_analyzer_optimized_fst
        ),
        "baseline_probes": _file_identity(args.probes),
        "direction_probes": _file_identity(args.direction_probes),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--analyzer-fst", required=True, type=Path)
    parser.add_argument("--full-analyzer-fst", required=True, type=Path)
    parser.add_argument("--full-analyzer-optimized-fst", required=True, type=Path)
    parser.add_argument("--fst", required=True, type=Path)
    parser.add_argument("--optimized-fst", required=True, type=Path)
    parser.add_argument("--dictionary-generator-fst", required=True, type=Path)
    parser.add_argument(
        "--dictionary-generator-optimized-fst", required=True, type=Path
    )
    parser.add_argument("--dictionary-analyzer-fst", required=True, type=Path)
    parser.add_argument(
        "--dictionary-analyzer-optimized-fst", required=True, type=Path
    )
    parser.add_argument("--fst2fst", required=True)
    parser.add_argument("--fst2strings", required=True)
    parser.add_argument("--fst2txt", required=True)
    parser.add_argument("--lookup", required=True)
    parser.add_argument("--optimized-lookup", required=True)
    parser.add_argument("--subtract", required=True)
    parser.add_argument("--invert", required=True)
    parser.add_argument("--disjunct", required=True)
    parser.add_argument("--probes", required=True, type=Path)
    parser.add_argument("--direction-probes", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    _validate_inputs(args)
    initial_inputs = _verification_input_identities(args)

    graph = verify_graph(args.fst, args.fst2txt)
    inverse_relation = verify_inverse_relation(
        args.analyzer_fst,
        args.fst,
        invert=args.invert,
        subtract=args.subtract,
        fst2strings=args.fst2strings,
    )
    generation_direction_relation = verify_generation_direction_relation(
        args.analyzer_fst,
        args.full_analyzer_fst,
        subtract=args.subtract,
        fst2strings=args.fst2strings,
    )
    optimized_relation = verify_optimized_relation(
        args.fst,
        args.optimized_fst,
        fst2fst=args.fst2fst,
        subtract=args.subtract,
        fst2strings=args.fst2strings,
    )
    inversion_probes, optimized_probes, directionality_probes = verify_inversion_probes(
        args.fst,
        args.optimized_fst,
        args.probes,
        args.direction_probes,
        lookup=args.lookup,
        optimized_lookup=args.optimized_lookup,
    )
    installed_artifacts = verify_installed_artifact_relations(
        args.dictionary_generator_fst,
        args.dictionary_generator_optimized_fst,
        args.dictionary_analyzer_fst,
        args.dictionary_analyzer_optimized_fst,
        args.full_analyzer_fst,
        args.full_analyzer_optimized_fst,
        invert=args.invert,
        fst2fst=args.fst2fst,
        subtract=args.subtract,
        fst2strings=args.fst2strings,
    )
    combined_subset = verify_combined_generation_subset(
        args.dictionary_generator_optimized_fst,
        args.optimized_fst,
        args.dictionary_analyzer_optimized_fst,
        args.full_analyzer_optimized_fst,
        invert=args.invert,
        disjunct=args.disjunct,
        fst2fst=args.fst2fst,
        subtract=args.subtract,
        fst2strings=args.fst2strings,
    )
    final_inputs = _verification_input_identities(args)
    if final_inputs != initial_inputs:
        raise VerificationError(
            "a productive-generator proof input changed during verification"
        )
    result = {
        "schema": SCHEMA,
        "definition": (
            "finite-valued productive generator: no input-epsilon cycle is "
            "reachable in lexical-to-surface orientation; its complete relation is "
            "the exact inverse of the productive analyzer, survives optimized "
            "serialization, inverts every required probe pair, excludes every "
            "forbidden pair, and adds no generated pair outside the union of the "
            "compiled and productive analyzers"
        ),
        "inputs": initial_inputs,
        "graph": graph,
        "inverse_relation": inverse_relation,
        "generation_direction_relation": generation_direction_relation,
        "optimized_runtime": {**optimized_relation, **optimized_probes},
        "inversion_probes": inversion_probes,
        "directionality_probes": directionality_probes,
        "installed_artifacts": installed_artifacts,
        "combined_generation_subset": combined_subset,
    }
    _atomic_json(args.output, result)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except VerificationError as error:
        raise SystemExit(f"error: {error}") from error
