from __future__ import annotations

import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest import mock

from qazmorph.backend import BackendError
from qazmorph.analyzer import Analyzer
from qazmorph.generator import (
    GENERATION_HARD_LIMIT,
    GENERATION_QUERY_BYTE_LIMIT,
    GENERATION_RESPONSE_LINE_LIMIT,
    ProductiveGenerator,
    exact_lexical_form,
    productive_lemma_eligible,
)
from qazmorph.guesser import (
    _GuessOutcome,
    _LookupFailure,
    _LookupResponse,
    _LookupTimeout,
)
from qazmorph.stream import parse_analysis


class _Worker:
    def __init__(self, responses: list[object] | None = None) -> None:
        self.responses = list(responses or [])
        self.queries: list[str] = []
        self.resets: list[bool] = []
        self.closed = False
        self.identity_checks = 0
        self.start_count = 0
        self.cap_abort_count = 0
        self.cycle_truncation_count = 0
        self.idle_restart_count = 0
        self.protocol_restart_count = 0
        self.oneshot_reap_count = 0
        self.leading_separator_record_count = 0
        self.leading_separator_byte_count = 0

    def query(self, value: str, **bounds: object) -> _LookupResponse:
        self.queries.append(value)
        self.bounds = bounds
        response = self.responses.pop(0)
        if isinstance(response, BaseException):
            raise response
        if isinstance(response, _LookupResponse):
            if not response.complete and response.reason == "response_cap":
                self.cap_abort_count += 1
            return response
        return _LookupResponse(tuple(response), True)  # type: ignore[arg-type]

    def _reset_after_protocol_error(
        self, *, retrying: bool, timeout: float | None = None
    ) -> bool:
        del timeout
        self.resets.append(retrying)
        self.protocol_restart_count += int(retrying)
        return True

    def _ensure_process_identity(self) -> None:
        self.identity_checks += 1

    def close(self) -> None:
        self.closed = True


class _Backend:
    def __init__(self, root: Path) -> None:
        self.hfst_optimized_lookup = "/verified/hfst-optimized-lookup"
        self.generator_path = root / "kaz.autogen.hfstol"
        self.productive_generator_path = root / "kaz.guesser.autogen.hfstol"
        self.generator_path.write_bytes(b"dictionary")
        self.productive_generator_path.write_bytes(b"productive")
        self.productive_generator_safe = True
        self.environment = {}


class _LatticeBackend:
    resource_version = "test"

    def __init__(self, stream: str) -> None:
        self.stream = stream
        self.timeouts: list[float] = []

    def analyze_stream_pair(
        self, text: str, *, disambiguate: bool, timeout: float
    ) -> tuple[str, None]:
        self.timeouts.append(timeout)
        return self.stream, None


class _DetailedGuesser:
    def __init__(self, outcome: _GuessOutcome) -> None:
        self.outcome = outcome
        self.calls: list[tuple[str, int, bool, float]] = []

    def _guess_detailed(
        self,
        surface: str,
        *,
        limit: int,
        generate_all: bool,
        timeout: float,
    ) -> _GuessOutcome:
        self.calls.append((surface, limit, generate_all, timeout))
        return self.outcome


class ProductiveGeneratorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.backend = _Backend(self.root)
        self.generator = ProductiveGenerator(self.backend)  # type: ignore[arg-type]

    def tearDown(self) -> None:
        self.generator.close()
        self.temporary.cleanup()

    def workers(
        self, dictionary: list[object], productive: list[object]
    ) -> tuple[_Worker, _Worker]:
        left = _Worker(dictionary)
        right = _Worker(productive)
        self.generator._dictionary_worker = left  # type: ignore[assignment]
        self.generator._productive_worker = right  # type: ignore[assignment]
        return left, right

    def test_diagnostics_expose_drained_leading_separators_as_informational(self) -> None:
        dictionary, productive = self.workers([], [])
        dictionary.leading_separator_record_count = 2
        dictionary.leading_separator_byte_count = 3
        productive.leading_separator_record_count = 4
        productive.leading_separator_byte_count = 5

        diagnostics = self.generator.diagnostics

        self.assertEqual(diagnostics["dictionary_leading_separator_records"], 2)
        self.assertEqual(diagnostics["dictionary_leading_separator_bytes"], 3)
        self.assertEqual(diagnostics["productive_leading_separator_records"], 4)
        self.assertEqual(diagnostics["productive_leading_separator_bytes"], 5)

    @staticmethod
    def lattice_analyzer(
        stream: str,
        outcome: _GuessOutcome,
        *,
        use_guesser: bool = True,
    ) -> tuple[Analyzer, _DetailedGuesser]:
        analyzer = Analyzer.__new__(Analyzer)
        analyzer.backend = _LatticeBackend(stream)
        analyzer.use_guesser = use_guesser
        analyzer.guess_limit = 8
        guesser = _DetailedGuesser(outcome)
        analyzer.guesser = guesser
        analyzer.fixlist = {}
        analyzer.ud_profile = "universal"
        return analyzer, guesser

    def test_exact_serializer_never_strips_or_accepts_record_injection(self) -> None:
        self.assertEqual(exact_lexical_form("сөз", ("n", "nom")), "сөз<n><nom>")
        for tags in (
            (),
            "nom",
            b"nom",
            ("<n>",),
            (" n",),
            ("n ",),
            ("n><v",),
            ("",),
        ):
            with self.subTest(tags=tags), self.assertRaises(ValueError):
                exact_lexical_form("сөз", tags)
        for lemma in (
            "",
            "сөз\n",
            "сөз\r",
            "сөз\t",
            "сөз\0",
            "сөз\x85",
            "сөз\u2028",
            "сөз\ud800",
            "сөз<n>",
            "сөз[control]",
            None,
        ):
            with self.subTest(lemma=repr(lemma)), self.assertRaises(ValueError):
                exact_lexical_form(lemma, ("n", "nom"))

        exact = exact_lexical_form("а", ("a" * 4092,))
        self.assertEqual(len(exact.encode("utf-8")), GENERATION_QUERY_BYTE_LIMIT)
        with self.assertRaisesRegex(ValueError, "bounded generator input"):
            exact_lexical_form("а", ("a" * 4093,))
        dictionary, productive = self.workers([], [])
        with self.assertRaisesRegex(ValueError, "bounded generator input"):
            self.generator.generate("а", ("a" * 4093,))
        self.assertEqual(dictionary.queries, [])
        self.assertEqual(productive.queries, [])

    def test_one_deadline_covers_validation_and_protocol_reset(self) -> None:
        query = "сөз<n><nom>"
        dictionary, productive = self.workers([[f"{query}\tсөз"]], [])
        original_problem = self.generator._response_problem

        def delayed_validation(value: str, lines: object) -> str | None:
            time.sleep(0.02)
            return original_problem(value, lines)  # type: ignore[arg-type]

        with mock.patch.object(
            self.generator, "_response_problem", side_effect=delayed_validation
        ), self.assertRaises(_LookupTimeout):
            self.generator.generate("сөз", ("n", "nom"), timeout=0.005)
        self.assertEqual(productive.queries, [])

        dictionary, productive = self.workers(
            [["wrong\twrong"], [f"{query}\tсөз"]], []
        )
        original_reset = dictionary._reset_after_protocol_error

        def delayed_reset(*, retrying: bool, timeout: float | None = None) -> bool:
            time.sleep(0.02)
            return original_reset(retrying=retrying, timeout=timeout)

        dictionary._reset_after_protocol_error = delayed_reset  # type: ignore[method-assign]
        with self.assertRaises(_LookupTimeout):
            self.generator.generate("сөз", ("n", "nom"), timeout=0.005)
        self.assertEqual(dictionary.resets, [True])
        self.assertEqual(productive.queries, [])

    def test_dictionary_and_productive_queries_share_one_total_deadline(self) -> None:
        query = "жаңасөз<n><nom>"
        dictionary, productive = self.workers(
            [[f"{query}\t{query}\t+?"]],
            [[f"{query}\tжаңасөз"]],
        )
        original_query = dictionary.query

        def delayed_query(value: str, **bounds: object) -> _LookupResponse:
            time.sleep(0.02)
            return original_query(value, **bounds)

        dictionary.query = delayed_query  # type: ignore[method-assign]
        with self.assertRaises(_LookupTimeout):
            self.generator.generate(
                "жаңасөз",
                ("n", "nom"),
                timeout=0.005,
                public_roundtrip_check=lambda *_args: True,
            )
        self.assertEqual(productive.queries, [])

    def test_productive_root_contract_is_exact(self) -> None:
        self.assertTrue(productive_lemma_eligible("жаңасөз"))
        for lemma in (
            "Жаңасөз",
            "жаңа сөз",
            "жаңа-сөз",
            "и\u0306",
            "",
            "а" * 33,
            "word",
            "ааа",
            "сөззз",
            "б",
            "бб",
            "роль",
            "съ",
            "қыын",
            "тііс",
        ):
            with self.subTest(lemma=lemma):
                self.assertFalse(productive_lemma_eligible(lemma))

    def test_dictionary_hit_has_exact_priority_and_product_stays_lazy(self) -> None:
        query = "сөз<n><nom>"
        dictionary, productive = self.workers([[f"{query}\tсөз"]], [])
        result = self.generator.generate("сөз", ("n", "nom"))
        self.assertEqual((result.forms, result.source), (("сөз",), "dictionary"))
        self.assertEqual(dictionary.queries, [query])
        self.assertEqual(productive.queries, [])

    def test_hfst_internal_cutoff_is_disabled(self) -> None:
        for worker in (
            self.generator._dictionary_worker,
            self.generator._productive_worker,
        ):
            self.assertNotIn("-t", worker.command)
            self.assertIn("--pipe-mode=both", worker.command)

    def test_windows_oneshot_adds_one_unambiguous_plus_one_result_bound(self) -> None:
        command = self.generator._dictionary_worker._windows_oneshot_command(
            max_lines=GENERATION_RESPONSE_LINE_LIMIT
        )
        self.assertEqual(command.count("-n"), 1)
        index = command.index("-n")
        self.assertEqual(
            command[index + 1], str(GENERATION_RESPONSE_LINE_LIMIT + 1)
        )

    def test_dictionary_zero_uses_productive_exact_inverse(self) -> None:
        query = "жаңасөз<n><pl><dat>"
        dictionary, productive = self.workers(
            [[f"{query}\t{query}\t+?"]],
            [[f"{query}\tжаңасөздерге"]],
        )
        checked: list[tuple[str, str]] = []

        def roundtrip(surface: str, lexical: str, _deadline: float) -> bool:
            checked.append((surface, lexical))
            return (surface, lexical) == ("жаңасөздерге", query)

        result = self.generator.generate(
            "жаңасөз",
            ("n", "pl", "dat"),
            public_roundtrip_check=roundtrip,
        )
        self.assertEqual(result.forms, ("жаңасөздерге",))
        self.assertEqual(result.source, "productive")
        self.assertTrue(result.productive_attempted)
        self.assertEqual(productive.queries, [query])
        self.assertEqual(checked, [("жаңасөздерге", query)])
        self.assertEqual(self.generator.diagnostics["productive_hits"], 1)

    def test_ineligible_and_closed_class_zero_never_query_product(self) -> None:
        for lemma, tags, reason in (
            ("Алматы", ("n", "nom"), "ineligible_lemma"),
            ("от сөндіргіш", ("n", "nom"), "ineligible_lemma"),
            ("бір-бір", ("n", "nom"), "ineligible_lemma"),
            ("ааа", ("n", "nom"), "ineligible_lemma"),
            ("сөззз", ("n", "nom"), "ineligible_lemma"),
            ("б", ("n", "nom"), "ineligible_lemma"),
            ("бб", ("n", "nom"), "ineligible_lemma"),
            ("роль", ("n", "nom"), "ineligible_lemma"),
            ("съ", ("n", "nom"), "ineligible_lemma"),
            ("қыын", ("n", "nom"), "ineligible_lemma"),
            ("тііс", ("n", "nom"), "ineligible_lemma"),
            ("жаңасөз", ("prn", "nom"), "unsupported_pos"),
        ):
            with self.subTest(lemma=lemma, tags=tags):
                query = exact_lexical_form(lemma, tags)
                _, productive = self.workers(
                    [[f"{query}\t{query}\t+?"]], []
                )
                result = self.generator.generate(lemma, tags)
                self.assertEqual((result.forms, result.reason), ((), reason))
                self.assertEqual(productive.queries, [])

    def test_exact_but_impossible_tag_sequence_is_controlled_zero(self) -> None:
        query = "сөз<n><pl><pl><nom>"
        self.workers(
            [[f"{query}\t{query}\t+?"]],
            [[f"{query}\t{query}\t+?"]],
        )
        result = self.generator.generate(
            "сөз",
            ("n", "pl", "pl", "nom"),
            public_roundtrip_check=lambda *_args: True,
        )
        self.assertEqual(result.forms, ())
        self.assertEqual(result.reason, "unsupported_tag_sequence")
        self.assertTrue(result.productive_attempted)

    def test_missing_public_backcheck_never_queries_productive_relation(self) -> None:
        query = "жаңасөз<n><nom>"
        _, productive = self.workers(
            [[f"{query}\t{query}\t+?"]],
            [[f"{query}\tжаңасөз"]],
        )
        result = self.generator.generate("жаңасөз", ("n", "nom"))
        self.assertEqual(result.reason, "public_backcheck_unavailable")
        self.assertEqual(productive.queries, [])

    def test_v3_rollback_skips_unavailable_productive_relation(self) -> None:
        self.backend.productive_generator_safe = False
        query = "жаңасөз<n><nom>"
        _, productive = self.workers([[f"{query}\t{query}\t+?"]], [])
        result = self.generator.generate("жаңасөз", ("n", "nom"))
        self.assertEqual(result.reason, "productive_resource_unavailable")
        self.assertEqual(productive.queries, [])

    def test_candidate_and_public_limit_are_hard(self) -> None:
        with self.assertRaises(ValueError):
            self.generator.generate("сөз", ("n", "nom"), limit=0)
        with self.assertRaises(ValueError):
            self.generator.generate("сөз", ("n", "nom"), limit=True)
        with self.assertRaises(ValueError):
            self.generator.generate(
                "сөз", ("n", "nom"), limit=GENERATION_HARD_LIMIT + 1
            )
        for timeout in (0, -1, True, float("inf"), float("nan"), "2"):
            with self.subTest(timeout=timeout), self.assertRaises(ValueError):
                self.generator.generate(
                    "сөз", ("n", "nom"), timeout=timeout  # type: ignore[arg-type]
                )

        query = "сөз<n><nom>"
        candidates = [f"{query}\tсөз{index}" for index in range(129)]
        worker, _ = self.workers([candidates], [])
        with self.assertRaisesRegex(BackendError, "hard raw-record cap"):
            self.generator.generate("сөз", ("n", "nom"))
        self.assertEqual(worker.resets, [False])
        self.assertEqual(
            worker.bounds["max_request_bytes"],
            GENERATION_QUERY_BYTE_LIMIT,
        )

        duplicate_lines = [f"{query}\tсөз" for _ in range(129)]
        worker, _ = self.workers([duplicate_lines], [])
        with self.assertRaisesRegex(BackendError, "hard raw-record cap"):
            self.generator.generate("сөз", ("n", "nom"))
        self.assertEqual(worker.resets, [False])

    def test_malformed_and_mixed_correlated_records_fail_closed(self) -> None:
        query = "сөз<n><nom>"
        malformed = (
            [f"{query}\t"],
            [f"{query}\tсөз\textra\tfield"],
            [f"{query}\tсөз\tnot-a-weight"],
            [f"{query}\t{query}\t+?", f"{query}\tсөз"],
            [f"{query}\t{query}+?"],
            [f"{query}\t{query}"],
            [f"{query}\tсөз<n>"],
        )
        for first in malformed:
            with self.subTest(first=first):
                worker, productive = self.workers([first, first], [])
                with self.assertRaises(_LookupFailure):
                    self.generator.generate("сөз", ("n", "nom"))
                self.assertEqual(worker.resets, [True, False])
                self.assertEqual(productive.queries, [])

        worker, productive = self.workers(
            [[f"{query}\t[...truncated...]"]], []
        )
        with self.assertRaises(_LookupFailure):
            self.generator.generate("сөз", ("n", "nom"))
        self.assertEqual(worker.resets, [False])
        self.assertEqual(productive.queries, [])

        incomplete = _LookupResponse(
            (f"{query}\tсөз",),
            False,
            "response_cap",
        )
        worker, productive = self.workers([incomplete], [])
        with self.assertRaisesRegex(BackendError, "response bound"):
            self.generator.generate("сөз", ("n", "nom"))
        self.assertEqual(productive.queries, [])

    def test_protocol_mismatch_restarts_once_then_correlates(self) -> None:
        query = "сөз<n><nom>"
        dictionary, _ = self.workers(
            [["басқа<n><nom>\tбасқа"], [f"{query}\tсөз"]], []
        )
        result = self.generator.generate("сөз", ("n", "nom"))
        self.assertEqual(result.forms, ("сөз",))
        self.assertEqual(dictionary.resets, [True])
        self.assertEqual(dictionary.protocol_restart_count, 1)

    def test_second_protocol_mismatch_and_cycle_fail_closed(self) -> None:
        query = "сөз<n><nom>"
        dictionary, _ = self.workers(
            [["bad\tbad"], ["still-bad\tbad"]], []
        )
        with self.assertRaises(_LookupFailure):
            self.generator.generate("сөз", ("n", "nom"))
        self.assertEqual(dictionary.resets, [True, False])

        dictionary, _ = self.workers([[f"{query}\t[...cyclic...]"]], [])
        with self.assertRaises(_LookupFailure):
            self.generator.generate("сөз", ("n", "nom"))
        self.assertEqual(dictionary.resets, [False])

    def test_public_backcheck_filters_ranked_out_and_overlong_surfaces(self) -> None:
        query = "жаңасөз<n><pl><dat>"
        surface = "жаңасөздерге"
        self.workers(
            [[f"{query}\t{query}\t+?"]],
            [[f"{query}\t{surface}"]],
        )
        checked: list[tuple[str, str]] = []

        def rejected(candidate: str, lexical: str, _deadline: float) -> bool:
            checked.append((candidate, lexical))
            return False

        result = self.generator.generate(
            "жаңасөз",
            ("n", "pl", "dat"),
            public_roundtrip_check=rejected,
        )
        self.assertEqual(result.forms, ())
        self.assertEqual(result.reason, "public_roundtrip_rejected")
        self.assertEqual(checked, [(surface, query)])
        self.assertEqual(self.generator.diagnostics["roundtrip_rejected"], 1)

        self.workers(
            [[f"{query}\t{query}\t+?"]],
            [[f"{query}\t{surface}"]],
        )
        result = self.generator.generate(
            "жаңасөз",
            ("n", "pl", "dat"),
            public_roundtrip_check=lambda candidate, lexical, _deadline: (
                candidate,
                lexical,
            )
            == (surface, query),
        )
        self.assertEqual(result.forms, (surface,))

        root = "ба" * 15 + "б"
        self.assertEqual(len(root), 31)
        long_surface = root + "тар"
        long_query = f"{root}<n><pl><nom>"
        _, productive = self.workers(
            [[f"{long_query}\t{long_query}\t+?"]],
            [[f"{long_query}\t{long_surface}"]],
        )
        result = self.generator.generate(
            root,
            ("n", "pl", "nom"),
            public_roundtrip_check=lambda *_args: True,
        )
        self.assertEqual(result.forms, ())
        self.assertEqual(result.reason, "public_roundtrip_rejected")
        self.assertEqual(productive.queries, [long_query])
        self.assertEqual(self.generator.diagnostics["surface_ineligible_rejects"], 1)

    def test_exact_32_character_surface_can_survive_backcheck(self) -> None:
        root = "ба" * 16
        self.assertEqual(len(root), 32)
        query = f"{root}<n><nom>"
        self.workers(
            [[f"{query}\t{query}\t+?"]],
            [[f"{query}\t{root}"]],
        )
        result = self.generator.generate(
            root,
            ("n", "nom"),
            public_roundtrip_check=lambda surface, lexical, _deadline: (
                surface,
                lexical,
            )
            == (root, query),
        )
        self.assertEqual(result.forms, (root,))

    def test_public_backcheck_failure_invalidates_generation(self) -> None:
        query = "жаңасөз<n><nom>"
        def failing_check(
            _surface: str, _lexical: str, _deadline: float
        ) -> bool:
            raise BackendError("backcheck was incomplete")

        self.workers(
            [[f"{query}\t{query}\t+?"]],
            [[f"{query}\tжаңасөз"]],
        )
        with self.assertRaisesRegex(BackendError, "backcheck was incomplete"):
            self.generator.generate(
                "жаңасөз",
                ("n", "nom"),
                public_roundtrip_check=failing_check,
            )
        self.assertEqual(self.generator.diagnostics["roundtrip_failures"], 1)

    def test_analyzer_backcheck_matches_public_dictionary_fixlist_and_guess_precedence(self) -> None:
        surface = "жаңасөздерге"
        lexical = "жаңасөз<n><pl><dat>"
        compiled, guesser = self.lattice_analyzer(
            f"^{surface}/{lexical}$",
            _GuessOutcome((), True),
        )
        self.assertTrue(
            compiled._productive_generation_roundtrip(
                surface, lexical, time.monotonic() + 10.0
            )
        )
        self.assertEqual(guesser.calls, [])

        replacement = parse_analysis(
            "басқасөз<n><nom>", source="fixlist", guessed=False
        )
        assert replacement is not None
        compiled.fixlist = {surface: (replacement,)}
        self.assertFalse(
            compiled._productive_generation_roundtrip(
                surface, lexical, time.monotonic() + 10.0
            )
        )
        self.assertEqual(guesser.calls, [])

        guessed = parse_analysis(lexical, source="guesser", guessed=True)
        assert guessed is not None
        unknown_stream = f"^{surface}/*{surface}$"
        unknown, guesser = self.lattice_analyzer(
            unknown_stream,
            _GuessOutcome((guessed,), True),
        )
        self.assertTrue(
            unknown._productive_generation_roundtrip(
                surface, lexical, time.monotonic() + 10.0
            )
        )
        self.assertEqual(len(guesser.calls), 1)
        self.assertEqual(guesser.calls[0][:3], (surface, 8, False))

        disabled, guesser = self.lattice_analyzer(
            unknown_stream,
            _GuessOutcome((guessed,), True),
            use_guesser=False,
        )
        self.assertFalse(
            disabled._productive_generation_roundtrip(
                surface, lexical, time.monotonic() + 10.0
            )
        )
        self.assertEqual(guesser.calls, [])

    def test_analyzer_backcheck_rejects_incomplete_cached_guess_outcome(self) -> None:
        surface = "жаңасөздерге"
        lexical = "жаңасөз<n><pl><dat>"
        guessed = parse_analysis(lexical, source="guesser", guessed=True)
        assert guessed is not None
        analyzer, _ = self.lattice_analyzer(
            f"^{surface}/*{surface}$",
            _GuessOutcome((guessed,), False, "response_cap"),
        )
        with self.assertRaisesRegex(BackendError, "backcheck was incomplete"):
            analyzer._productive_generation_roundtrip(
                surface, lexical, time.monotonic() + 10.0
            )

    def test_timeout_is_counted_and_propagated(self) -> None:
        self.workers([[_LookupTimeout("timeout")][0]], [])
        with self.assertRaises(_LookupTimeout):
            self.generator.generate("сөз", ("n", "nom"))
        self.assertEqual(self.generator.diagnostics["timeouts"], 1)

    def test_close_and_fork_identity_cover_both_lazy_workers(self) -> None:
        left, right = self.workers([], [])
        self.generator.close()
        self.assertTrue(left.closed)
        self.assertTrue(right.closed)

        self.generator._owner_pid = -1
        with mock.patch.object(os, "getpid", return_value=123):
            self.generator._ensure_process_identity()
        self.assertEqual((left.identity_checks, right.identity_checks), (1, 1))


if __name__ == "__main__":
    unittest.main()
