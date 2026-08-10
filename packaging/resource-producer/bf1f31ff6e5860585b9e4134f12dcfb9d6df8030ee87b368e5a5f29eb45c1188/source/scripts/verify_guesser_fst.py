#!/usr/bin/env python3
"""Prove productive-guesser finiteness and run immutable no-cap probes."""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import json
import os
from pathlib import Path
import random
import re
import subprocess
import sys
import tempfile
from typing import Any, Iterable
import unicodedata


SCHEMA = "qazmorph-guesser-finiteness-v2"
PROBE_SCHEMA = "qazmorph-guesser-regression-probes-v1"
ADVERSARIAL_SCHEMA = "qazmorph-guesser-adversarial-generation-v1"
CYCLE_MARKER = "[...cyclic...]"
EPSILON_INPUTS = frozenset({"@0@", "@_EPSILON_SYMBOL_@"})
GRAPH_EXPORT_TIMEOUT_SECONDS = 30.0
EQUIVALENCE_COMMAND_TIMEOUT_SECONDS = 30.0
STEM_FINAL_ALTERNATIONS = frozenset(
    {("б", "п"), ("г", "к"), ("ғ", "қ")}
)
NOUN_HIGH_VOWEL_SYNCOPE = frozenset("ыі")
SYNCOPE_FINAL_CONSONANTS = frozenset("бвгғджзйкқлмнңпрстфхһцчшщьъ")
LOAN_BACK_SUFFIX_INITIALS = frozenset("аы")
LOAN_BACK_HARMONY_LEMMA_SUFFIX = "кубок"
ADVERSARIAL_CONSONANTS = "абвгғджзклмнңпрстфхқ"
ADVERSARIAL_VOWELS = "аәеіоөұүы"


class VerificationError(RuntimeError):
    """Raised when the productive relation is cyclic or violates its contract."""


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
            if len(fields) >= 4:
                source = int(fields[0])
                target = int(fields[1])
                input_symbol = fields[2]
                states.update((source, target))
                adjacency[source].add(target)
                arc_count += 1
                if input_symbol in EPSILON_INPUTS:
                    epsilon_adjacency[source].add(target)
                    epsilon_arc_count += 1
            elif len(fields) in {1, 2}:
                state = int(fields[0])
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
        raise VerificationError("productive guesser transducer has no final state")
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
    """Return one reachable input-epsilon cycle, or ``None`` when acyclic."""

    reachable = _reachable(0, adjacency)
    sys.setrecursionlimit(max(sys.getrecursionlimit(), len(reachable) * 2 + 100))
    colour: dict[int, int] = {}
    stack: list[int] = []
    positions: dict[int, int] = {}

    def visit(source: int) -> tuple[int, ...] | None:
        colour[source] = 1
        positions[source] = len(stack)
        stack.append(source)
        for target in epsilon_adjacency.get(source, ()):
            if target not in reachable:
                continue
            target_colour = colour.get(target, 0)
            if target_colour == 1:
                start = positions[target]
                return tuple(stack[start:] + [target])
            if target_colour == 0:
                cycle = visit(target)
                if cycle is not None:
                    return cycle
        stack.pop()
        positions.pop(source, None)
        colour[source] = 2
        return None

    # The graph produced by HFST is normally fully reachable, but iterate only
    # over the proven reachable component so dead implementation states cannot
    # turn a semantic build gate into a false failure.
    for state in sorted(reachable):
        if colour.get(state, 0) == 0:
            cycle = visit(state)
            if cycle is not None:
                return cycle
    return None


def verify_graph(fst: Path, fst2txt: str) -> dict[str, int | bool]:
    try:
        completed = subprocess.run(
            [fst2txt, str(fst)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=GRAPH_EXPORT_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise VerificationError(
            "hfst-fst2txt exceeded the formal graph-gate timeout "
            f"of {GRAPH_EXPORT_TIMEOUT_SECONDS:.1f}s for {fst}"
        ) from exc
    if completed.returncode:
        raise VerificationError(
            f"hfst-fst2txt failed with status {completed.returncode}: "
            f"{completed.stderr.strip()}"
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
            "productive guesser has a reachable input-epsilon cycle: " + rendered
        )
    return {
        "states": len(states),
        "reachable_states": len(reachable),
        "final_states": len(finals),
        "arcs": arcs,
        "input_epsilon_arcs": epsilon_arcs,
        "reachable_input_epsilon_cycle": False,
    }


def _run_equivalence_command(command: list[str]) -> subprocess.CompletedProcess[str]:
    try:
        completed = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=EQUIVALENCE_COMMAND_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise VerificationError(
            f"optimized-equivalence command exceeded "
            f"{EQUIVALENCE_COMMAND_TIMEOUT_SECONDS:.1f}s: {' '.join(command)}"
        ) from exc
    if completed.returncode:
        raise VerificationError(
            f"optimized-equivalence command failed with status "
            f"{completed.returncode}: {' '.join(command)}: "
            f"{completed.stderr.strip()}"
        )
    return completed


def verify_optimized_equivalence(
    standard_fst: Path,
    optimized_fst: Path,
    *,
    fst2fst: str,
    fst2strings: str,
    subtract: str,
) -> dict[str, bool | str]:
    """Prove optimized serialization preserves the complete binary relation."""

    with tempfile.TemporaryDirectory(prefix="qazmorph-guesser-equivalence.") as temporary:
        root = Path(temporary)
        round_trip = root / "optimized-roundtrip.hfst"
        standard_only = root / "standard-not-optimized.hfst"
        optimized_only = root / "optimized-not-standard.hfst"
        _run_equivalence_command(
            [
                fst2fst,
                "-f",
                "openfst-tropical",
                str(optimized_fst),
                "-o",
                str(round_trip),
            ]
        )
        _run_equivalence_command(
            [
                subtract,
                "-1",
                str(standard_fst),
                "-2",
                str(round_trip),
                "-o",
                str(standard_only),
            ]
        )
        _run_equivalence_command(
            [
                subtract,
                "-1",
                str(round_trip),
                "-2",
                str(standard_fst),
                "-o",
                str(optimized_only),
            ]
        )
        standard_counterexample = _run_equivalence_command(
            [fst2strings, "-n", "1", str(standard_only)]
        ).stdout.strip()
        optimized_counterexample = _run_equivalence_command(
            [fst2strings, "-n", "1", str(optimized_only)]
        ).stdout.strip()
        if standard_counterexample or optimized_counterexample:
            raise VerificationError(
                "optimized serialization changed the productive relation: "
                f"standard-only={standard_counterexample!r}, "
                f"optimized-only={optimized_counterexample!r}"
            )
    return {
        "full_relation_equivalent_to_standard": True,
        "operation": (
            "standard - optimized_roundtrip = empty and "
            "optimized_roundtrip - standard = empty"
        ),
    }


def verify_baseline_inclusion(
    baseline_fst: Path,
    final_fst: Path,
    *,
    fst2strings: str,
    subtract: str,
) -> dict[str, bool | str]:
    """Prove that extending the productive relation removed no old path."""

    with tempfile.TemporaryDirectory(prefix="qazmorph-guesser-baseline.") as temporary:
        difference = Path(temporary) / "baseline-not-final.hfst"
        _run_equivalence_command(
            [
                subtract,
                "-1",
                str(baseline_fst),
                "-2",
                str(final_fst),
                "-o",
                str(difference),
            ]
        )
        counterexample = _run_equivalence_command(
            [fst2strings, "-n", "1", str(difference)]
        ).stdout.strip()
        if counterexample:
            raise VerificationError(
                "productive extension removed a baseline path: "
                + counterexample
            )
    return {
        "baseline_subset_of_final": True,
        "operation": "baseline_relation - final_relation = empty",
    }


def _generated_adversarial_probes(
    specification: Any, seen: set[str]
) -> list[dict[str, Any]]:
    if (
        not isinstance(specification, dict)
        or specification.get("schema") != ADVERSARIAL_SCHEMA
        or specification.get("generator") != "alternating_cyrillic_v1"
        or not isinstance(specification.get("seed"), int)
        or isinstance(specification.get("seed"), bool)
        or not isinstance(specification.get("count"), int)
        or isinstance(specification.get("count"), bool)
        or not 1 <= specification["count"] <= 4096
        or not isinstance(specification.get("max_surface_length"), int)
        or isinstance(specification.get("max_surface_length"), bool)
        or not 4 <= specification["max_surface_length"] <= 32
    ):
        raise VerificationError("invalid deterministic adversarial probe specification")

    rng = random.Random(specification["seed"])
    maximum = specification["max_surface_length"]
    generated: list[dict[str, Any]] = []
    attempts = 0
    while len(generated) < specification["count"]:
        attempts += 1
        if attempts > specification["count"] * 20:
            raise VerificationError("could not generate unique adversarial probes")
        length = rng.randint(2, min(27, maximum - 2))
        surface = "".join(
            rng.choice(ADVERSARIAL_VOWELS if index % 3 == 1 else ADVERSARIAL_CONSONANTS)
            for index in range(length)
        )
        if len(generated) % 2 == 0:
            surface = (
                surface[: maximum - 2]
                + rng.choice(ADVERSARIAL_CONSONANTS)
                + rng.choice("ыі")
            )
        surface = surface[:maximum]
        if surface in seen:
            continue
        seen.add(surface)
        generated.append(
            {
                "surface": surface,
                "class": "deterministic_adversarial",
                "expected_readings": [],
                "forbidden_readings": [],
                "tracked_readings": [],
            }
        )
    return generated


def _load_probes(path: Path) -> list[dict[str, Any]]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise VerificationError(f"cannot load probe fixture {path}: {exc}") from exc
    if not isinstance(payload, dict) or payload.get("schema") != PROBE_SCHEMA:
        raise VerificationError(f"unsupported probe fixture schema: {path}")
    probes = payload.get("probes")
    if not isinstance(probes, list) or not probes:
        raise VerificationError(f"probe fixture is empty or malformed: {path}")
    seen: set[str] = set()
    for index, probe in enumerate(probes):
        if not isinstance(probe, dict):
            raise VerificationError(f"probe {index} is not an object")
        surface = probe.get("surface")
        expected = probe.get("expected_readings", [])
        forbidden = probe.get("forbidden_readings", [])
        tracked = probe.get("tracked_readings", [])
        if (
            not isinstance(surface, str)
            or not surface
            or surface != unicodedata.normalize("NFC", surface)
            or surface != surface.casefold()
            or any(character in surface for character in "\r\n\0")
            or surface in seen
            or not isinstance(expected, list)
            or any(not isinstance(reading, str) or not reading for reading in expected)
            or not isinstance(forbidden, list)
            or any(
                not isinstance(reading, str) or not reading
                for reading in forbidden
            )
            or bool(set(expected) & set(forbidden))
            or not isinstance(tracked, list)
            or any(not isinstance(reading, str) or not reading for reading in tracked)
        ):
            raise VerificationError(f"probe {index} is invalid: {probe!r}")
        seen.add(surface)
    return probes + _generated_adversarial_probes(
        payload.get("adversarial_generation"), seen
    )


def _raw_tags(raw: str) -> tuple[str, ...]:
    return tuple(re.findall(r"<([^<>]+)>", raw))


def _root_kind(
    surface: str, lemma: str, tags: tuple[str, ...] | list[str] | None = None
) -> str | None:
    if not lemma or len(lemma) > len(surface):
        return None
    if surface.startswith(lemma):
        return "identity"
    noun_reading = bool(tags) and tags[0] == "n"
    surface_root = surface[: len(lemma)]
    if (
        len(lemma) >= 2
        and len(lemma) < len(surface)
        and surface_root[:-1] == lemma[:-1]
        and (surface_root[-1], lemma[-1]) in STEM_FINAL_ALTERNATIONS
    ):
        suffix = surface[len(lemma) :]
        if (
            (surface_root[-1], lemma[-1]) == ("г", "к")
            and suffix[:1] in LOAN_BACK_SUFFIX_INITIALS
        ):
            if noun_reading and lemma.endswith(LOAN_BACK_HARMONY_LEMMA_SUFFIX):
                return "loan_back_harmony_kubok"
            return None
        return "stem_final_alternation"
    if (
        noun_reading
        and len(lemma) >= 3
        and lemma[-2] in NOUN_HIGH_VOWEL_SYNCOPE
        and lemma[-1] in SYNCOPE_FINAL_CONSONANTS
    ):
        contracted_root = lemma[:-2] + lemma[-1]
        if len(contracted_root) < len(surface) and surface.startswith(contracted_root):
            return "noun_high_vowel_syncope"
    return None


def verify_probes(
    fst: Path,
    lookup: str,
    probes_path: Path,
    *,
    optimized: bool = False,
) -> tuple[dict[str, Any], dict[str, set[str]]]:
    probes = _load_probes(probes_path)
    total_readings = 0
    maximum_readings = 0
    probes_with_shorter_lemma = 0
    probes_with_required_readings = 0
    required_readings_checked = 0
    required_shorter_lemma_readings = 0
    tracked_readings_checked = 0
    tracked_readings_present = 0
    tracked_readings_missing: list[dict[str, str]] = []
    forbidden_readings_checked = 0
    root_readings: Counter[str] = Counter()
    probes_by_root_kind: Counter[str] = Counter()
    readings_by_surface: dict[str, set[str]] = {}
    for probe in probes:
        surface = probe["surface"]
        command = (
            [lookup, "-q", str(fst)]
            if optimized
            else [lookup, "-q", "-c", "0", "-i", str(fst)]
        )
        try:
            completed = subprocess.run(
                command,
                input=surface + "\n",
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=5.0,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise VerificationError(f"no-cap lookup timed out for {surface!r}") from exc
        if completed.returncode:
            raise VerificationError(
                f"no-cap lookup failed for {surface!r} with status "
                f"{completed.returncode}: {completed.stderr.strip()}"
            )

        lines = [line for line in completed.stdout.splitlines() if line]
        if any(CYCLE_MARKER in line for line in lines):
            raise VerificationError(f"cycle marker observed for probe {surface!r}")
        readings: set[str] = set()
        has_shorter_lemma = False
        observed_root_kinds: set[str] = set()
        for line in lines:
            fields = line.split("\t")
            if len(fields) < 2 or fields[0] != surface:
                raise VerificationError(
                    f"malformed no-cap response for {surface!r}: {line!r}"
                )
            raw = fields[1]
            tag_start = raw.find("<")
            lemma = raw[:tag_start] if tag_start >= 0 else ""
            root_kind = _root_kind(surface, lemma, _raw_tags(raw))
            if root_kind is None:
                raise VerificationError(
                    f"unknown lemma is outside the bounded root relation for "
                    f"{surface!r}: {raw!r}"
                )
            root_readings[root_kind] += 1
            observed_root_kinds.add(root_kind)
            has_shorter_lemma = has_shorter_lemma or len(lemma) < len(surface)
            readings.add(raw)
        if not readings:
            raise VerificationError(f"probe has no productive reading: {surface!r}")
        expected = set(probe.get("expected_readings", ()))
        missing = sorted(expected - readings)
        if missing:
            raise VerificationError(
                f"probe {surface!r} is missing required readings: {missing}"
            )
        forbidden = set(probe.get("forbidden_readings", ()))
        unexpected = sorted(forbidden & readings)
        if unexpected:
            raise VerificationError(
                f"probe {surface!r} contains forbidden readings: {unexpected}"
            )
        forbidden_readings_checked += len(forbidden)
        if expected:
            probes_with_required_readings += 1
        required_readings_checked += len(expected)
        required_shorter_lemma_readings += sum(
            len(reading.split("<", 1)[0]) < len(surface) for reading in expected
        )
        tracked = set(probe.get("tracked_readings", ()))
        tracked_readings_checked += len(tracked)
        tracked_readings_present += len(tracked & readings)
        tracked_readings_missing.extend(
            {"surface": surface, "reading": reading}
            for reading in sorted(tracked - readings)
        )
        probes_with_shorter_lemma += int(has_shorter_lemma)
        probes_by_root_kind.update(observed_root_kinds)
        total_readings += len(readings)
        maximum_readings = max(maximum_readings, len(readings))
        readings_by_surface[surface] = readings

    return {
        "probes": len(probes),
        "all_have_readings": True,
        "all_lemmas_match_bounded_root_relation": True,
        "bounded_root_relation": {
            "identity_copy_nonempty_surface_prefix": True,
            "one_shot_surface_to_lemma_final_pairs": [
                [surface, lemma]
                for surface, lemma in sorted(STEM_FINAL_ALTERNATIONS)
            ],
            "noun_high_vowel_syncope": {
                "noun_only": True,
                "one_shot_output_only_vowels": ["ы", "і"],
                "position": "immediately_before_final_root_consonant",
                "requires_nonempty_surface_suffix": True,
            },
            "loan_back_harmony": {
                "noun_only": True,
                "lemma_suffix": LOAN_BACK_HARMONY_LEMMA_SUFFIX,
                "surface_to_lemma_final_pair": ["г", "к"],
                "consuming_surface_normalizations": [["ы", "і"], ["а", "е"]],
                "generic_back_harmony_g_to_k": False,
            },
            "unbounded_input_epsilon_root_templates": False,
        },
        "cycle_markers": 0,
        "forbidden_readings_observed": 0,
        "forbidden_readings_checked": forbidden_readings_checked,
        "explicit_fixture_probes": sum(
            probe.get("class") != "deterministic_adversarial" for probe in probes
        ),
        "deterministic_adversarial_probes": sum(
            probe.get("class") == "deterministic_adversarial" for probe in probes
        ),
        "total_distinct_readings": total_readings,
        "root_readings": dict(sorted(root_readings.items())),
        "probes_by_root_kind": dict(sorted(probes_by_root_kind.items())),
        "maximum_distinct_readings_per_probe": maximum_readings,
        "probes_with_shorter_lemma_reading": probes_with_shorter_lemma,
        "probes_with_required_readings": probes_with_required_readings,
        "required_readings_checked": required_readings_checked,
        "required_shorter_lemma_readings": required_shorter_lemma_readings,
        "tracked_readings_checked": tracked_readings_checked,
        "tracked_readings_present": tracked_readings_present,
        "tracked_readings_missing": tracked_readings_missing,
    }, readings_by_surface


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--baseline-fst", required=True, type=Path)
    parser.add_argument("--fst", required=True, type=Path)
    parser.add_argument("--optimized-fst", required=True, type=Path)
    parser.add_argument("--fst2fst", required=True)
    parser.add_argument("--fst2strings", required=True)
    parser.add_argument("--fst2txt", required=True)
    parser.add_argument("--lookup", required=True)
    parser.add_argument("--optimized-lookup", required=True)
    parser.add_argument("--subtract", required=True)
    parser.add_argument("--probes", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    for fst in (args.baseline_fst, args.fst, args.optimized_fst):
        if not fst.is_file():
            raise VerificationError(f"productive guesser is missing: {fst}")
    standard_report, standard_readings = verify_probes(
        args.fst, args.lookup, args.probes
    )
    optimized_report, optimized_readings = verify_probes(
        args.optimized_fst,
        args.optimized_lookup,
        args.probes,
        optimized=True,
    )
    if standard_readings != optimized_readings:
        mismatches = sorted(
            surface
            for surface in set(standard_readings) | set(optimized_readings)
            if standard_readings.get(surface) != optimized_readings.get(surface)
        )
        raise VerificationError(
            "optimized lookup changed probe candidate sets for: "
            + ", ".join(repr(surface) for surface in mismatches[:10])
        )
    optimized_equivalence = verify_optimized_equivalence(
        args.fst,
        args.optimized_fst,
        fst2fst=args.fst2fst,
        fst2strings=args.fst2strings,
        subtract=args.subtract,
    )
    baseline_inclusion = verify_baseline_inclusion(
        args.baseline_fst,
        args.fst,
        fst2strings=args.fst2strings,
        subtract=args.subtract,
    )
    result = {
        "schema": SCHEMA,
        "definition": (
            "finite-valued productive analyzer: no input-epsilon cycle is reachable "
            "from the initial state; every checked unknown lemma matches the explicit "
            "identity, stem-final, one-shot noun-syncope, or kubok-family root relation; "
            "the original productive relation remains a formal subset"
        ),
        "graph": verify_graph(args.fst, args.fst2txt),
        "baseline_relation": baseline_inclusion,
        "no_cap_probes": standard_report,
        "optimized_runtime": {
            **optimized_equivalence,
            "candidate_sets_equal_to_standard": True,
            "probes": optimized_report["probes"],
            "cycle_markers": optimized_report["cycle_markers"],
            "total_distinct_readings": optimized_report[
                "total_distinct_readings"
            ],
        },
    }
    _atomic_json(args.output, result)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except VerificationError as error:
        raise SystemExit(f"error: {error}") from error
