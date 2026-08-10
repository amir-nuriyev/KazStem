from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import os
from pathlib import Path
import select
import sys
import tempfile
import textwrap
import threading
import time
import unittest
from unittest import mock
import warnings

from qazmorph.analyzer import Analyzer
from qazmorph.backend import BackendError, FSTBackend, RESOURCE_MANIFEST_V2
from qazmorph.guesser import (
    GUESS_CACHE_CAPACITY,
    MAX_GUESS_REQUEST_BYTES,
    MAX_LOOKUP_REQUEST_BYTES,
    OpenClassGuesser,
    _GuessOutcome,
    _LookupResponse,
    _PersistentLookupWorker,
    productive_root_kind,
)
from qazmorph.stream import parse_analysis


class ProductiveRootRelationTests(unittest.TestCase):
    def test_identity_and_one_shot_stem_final_voicing_are_classified(self) -> None:
        self.assertEqual(productive_root_kind("сөздер", "сөз"), "identity")
        for surface, lemma in (
            ("кітабы", "кітап"),
            ("жүрегі", "жүрек"),
            ("қазағы", "қазақ"),
        ):
            with self.subTest(surface=surface, lemma=lemma):
                self.assertEqual(
                    productive_root_kind(surface, lemma),
                    "stem_final_alternation",
                )

    def test_unlicensed_or_unsuffixed_root_changes_are_rejected(self) -> None:
        for surface, lemma in (
            ("аузы", "ауыз"),
            ("орны", "орын"),
            ("кітаты", "кітап"),
            ("кітаб", "кітап"),
            ("бы", "п"),
        ):
            with self.subTest(surface=surface, lemma=lemma):
                self.assertIsNone(productive_root_kind(surface, lemma))

    def test_fast_protocol_shape_gate_matches_public_parser_acceptance(self) -> None:
        candidates = (
            "сөз<n><nom>",
            r"C\+\+<n><nom>",
            "сөз<n>+е<cop><aor><p3><sg>",
            "сөз<unknown_tag>",
            "сөз",
            "",
            "*сөз",
            "сөз+?",
            "сөз<>",
            "сөз<n><>",
        )
        for candidate in candidates:
            with self.subTest(candidate=candidate):
                parsed = parse_analysis(
                    candidate,
                    source="guesser",
                    guessed=True,
                )
                expected = bool(parsed is not None and parsed.tags)
                self.assertEqual(
                    _PersistentLookupWorker._candidate_analysis_shape_valid(
                        candidate
                    ),
                    expected,
                )


@unittest.skipUnless(
    os.environ.get("QAZMORPH_PROTOCOL_RESOURCE_DIRS"),
    "real standard/optimized protocol probes require explicit resource dirs",
)
class RealGuesserProtocolTests(unittest.TestCase):
    def test_standard_and_optimized_response_grammars_on_every_bundle(self) -> None:
        resource_dirs = os.environ["QAZMORPH_PROTOCOL_RESOURCE_DIRS"].split(
            os.pathsep
        )
        for resource_dir in resource_dirs:
            for optimized in (True, False):
                with self.subTest(
                    resource_dir=resource_dir, optimized=optimized
                ):
                    backend = FSTBackend(resource_dir)
                    backend.guesser_optimized = optimized
                    guesser = OpenClassGuesser(backend)
                    try:
                        candidates = guesser._raw_lookup(
                            "алмасөз", timeout=2.0
                        )
                        negative = guesser._raw_lookup(
                            "latin", timeout=2.0
                        )
                        self.assertTrue(candidates)
                        expected_fields = 2 if optimized else 3
                        self.assertTrue(
                            all(
                                len(line.split("\t")) == expected_fields
                                for line in candidates
                            )
                        )
                        self.assertEqual(
                            negative,
                            [
                                "latin\tlatin\t+?"
                                if optimized
                                else "latin\tlatin+?\tinf"
                            ],
                        )
                        diagnostics = guesser.diagnostics
                        self.assertEqual(
                            diagnostics["protocol_restarts"], 0
                        )
                        self.assertEqual(diagnostics["failures"], 0)
                        self.assertEqual(diagnostics["timeouts"], 0)
                    finally:
                        guesser.close()


class _FakeBackend:
    def __init__(self, root: Path, helper: Path, mode_file: Path, counter: Path) -> None:
        self.hfst_lookup = str(helper)
        self.hfst_optimized_lookup = str(helper)
        self.guesser_optimized = True
        self.guesser_path = root / "fake-guesser.hfst"
        self.guesser_path.write_bytes(b"fake")
        self.environment = os.environ.copy()
        self.environment["QAZMORPH_FAKE_LOOKUP_MODE"] = str(mode_file)
        self.environment["QAZMORPH_FAKE_LOOKUP_COUNTER"] = str(counter)
        self.environment["QAZMORPH_FAKE_LOOKUP_CWD"] = str(root / "helper-cwd")


class PersistentGuesserTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.mode_file = self.root / "mode"
        self.mode_file.write_text("normal", encoding="utf-8")
        self.counter = self.root / "launches"
        self.helper = self.root / "fake-hfst-lookup"
        self.helper.write_text(
            textwrap.dedent(
                """\
                #!/usr/bin/env python3
                import os
                from pathlib import Path
                import sys
                import time

                counter = Path(os.environ["QAZMORPH_FAKE_LOOKUP_COUNTER"])
                with counter.open("a", encoding="utf-8") as handle:
                    handle.write("started\\n")
                Path(os.environ["QAZMORPH_FAKE_LOOKUP_CWD"]).write_text(
                    str(Path.cwd()), encoding="utf-8"
                )
                mode_file = Path(os.environ["QAZMORPH_FAKE_LOOKUP_MODE"])
                optimized = "-i" not in sys.argv

                def emit_candidate(surface, reading, weight="0.0"):
                    suffix = "" if optimized else f"\\t{weight}"
                    sys.stdout.write(f"{surface}\\t{reading}{suffix}\\n")

                def emit_negative(surface):
                    if optimized:
                        sys.stdout.write(f"{surface}\\t{surface}\\t+?\\n")
                    else:
                        sys.stdout.write(f"{surface}\\t{surface}+?\\tinf\\n")

                sys.stdout.reconfigure(
                    encoding="utf-8", errors="strict", newline="\\n", write_through=True
                )
                sys.stderr.reconfigure(
                    encoding="utf-8", errors="strict", newline="\\n", write_through=True
                )

                for record in sys.stdin.buffer:
                    surface = record.rstrip(b"\\r\\n").decode(
                        "utf-8", errors="strict"
                    )
                    mode = mode_file.read_text(encoding="utf-8").strip()
                    if mode == "failure":
                        print("deliberate lookup failure", file=sys.stderr, flush=True)
                        raise SystemExit(7)
                    if mode == "timeout":
                        emit_candidate(surface, f"{surface}<n><nom>")
                        sys.stdout.flush()
                        time.sleep(5)
                        continue
                    if mode == "stdout_flood":
                        suffix = "" if optimized else "\\t0.0"
                        row = f"{surface}\\t{surface}<n><nom>{suffix}\\n".encode("utf-8")
                        while True:
                            sys.stdout.buffer.write(row * 256)
                            sys.stdout.buffer.flush()
                    if mode in {"invalid_utf8", "invalid_utf8_once"}:
                        if mode.endswith("_once"):
                            mode_file.write_text("normal", encoding="utf-8")
                        suffix = b"" if optimized else b"\\t0.0"
                        sys.stdout.buffer.write(
                            surface.encode("utf-8")
                            + b"\\tbad\\xff"
                            + suffix
                            + b"\\n\\n"
                        )
                        sys.stdout.buffer.flush()
                        continue
                    if mode == "bare_cr":
                        suffix = "" if optimized else "\\t0.0"
                        sys.stdout.write(f"{surface}\\tbad\\rmiddle{suffix}\\n\\n")
                        sys.stdout.flush()
                        continue
                    if mode == "extra_output":
                        suffix = "" if optimized else "\\t0.0"
                        sys.stdout.write(
                            f"{surface}\\t{surface}<n><nom>{suffix}\\n\\n"
                            f"{surface}\\t{surface}<adj>{suffix}\\n"
                        )
                        sys.stdout.flush()
                        continue
                    if mode == "unterminated":
                        suffix = "" if optimized else "\\t0.0"
                        sys.stdout.write(f"{surface}\\t{surface}<n><nom>{suffix}")
                        sys.stdout.flush()
                        continue
                    if mode == "cyclic":
                        emit_candidate(surface, f"{surface}<n><nom>")
                        emit_candidate(surface, "[...cyclic...]")
                        sys.stdout.write("\\n")
                        sys.stdout.flush()
                        continue
                    if mode == "unknown_extra":
                        emit_negative(surface)
                        sys.stdout.write("\\n\\n\\n")
                        sys.stdout.flush()
                        continue
                    if mode == "late_separator":
                        emit_negative(surface)
                        sys.stdout.write("\\n")
                        sys.stdout.flush()
                        time.sleep(0.05)
                        sys.stdout.write("\\n")
                        sys.stdout.flush()
                        continue
                    if mode == "blank_flood":
                        sys.stdout.write("\\n" * 4096)
                        sys.stdout.flush()
                        continue
                    if mode == "blank_only_timeout":
                        sys.stdout.write("\\n\\n")
                        sys.stdout.flush()
                        time.sleep(5)
                        continue
                    if mode == "blank_only_exit":
                        sys.stdout.write("\\n\\n")
                        sys.stdout.flush()
                        raise SystemExit(8)
                    if mode == "mixed_negative":
                        emit_candidate(surface, f"{surface}<n><nom>")
                        emit_negative(surface)
                        sys.stdout.write("\\n")
                        sys.stdout.flush()
                        continue
                    if mode == "duplicate_negative":
                        emit_negative(surface)
                        emit_negative(surface)
                        sys.stdout.write("\\n")
                        sys.stdout.flush()
                        continue
                    if mode == "empty_candidate":
                        emit_candidate(surface, "")
                        sys.stdout.write("\\n")
                        sys.stdout.flush()
                        continue
                    if mode == "tagless_identity":
                        emit_candidate(surface, surface)
                        sys.stdout.write("\\n")
                        sys.stdout.flush()
                        continue
                    if mode == "control_marker":
                        emit_candidate(surface, "[...control...]")
                        sys.stdout.write("\\n")
                        sys.stdout.flush()
                        continue
                    if mode == "extra_field":
                        sys.stdout.write(
                            f"{surface}\\t{surface}<n><nom>\\t0.0\\tgarbage\\n\\n"
                        )
                        sys.stdout.flush()
                        continue
                    if mode in {
                        "nonfinite_weight",
                        "infinite_weight",
                        "garbage_weight",
                    }:
                        weight = {
                            "nonfinite_weight": "nan",
                            "infinite_weight": "inf",
                            "garbage_weight": "garbage",
                        }[mode]
                        sys.stdout.write(
                            f"{surface}\\t{surface}<n><nom>\\t{weight}\\n\\n"
                        )
                        sys.stdout.flush()
                        continue
                    if mode == "misroute_once":
                        mode_file.write_text("normal", encoding="utf-8")
                        surface = "бөгдесөз"
                    elif mode == "misroute":
                        surface = "бөгдесөз"
                    if mode == "stderr_flood":
                        sys.stderr.write("diagnostic " * 40000)
                        sys.stderr.flush()
                    readings = (
                        f"{surface}<n><nom>",
                        f"{surface}<adj>",
                        f"{surface}<n><attr>",
                        f"{surface}<v><iv><imp><p2><sg>",
                    )
                    for reading in readings:
                        emit_candidate(surface, reading)
                    sys.stdout.write("\\n")
                    sys.stdout.flush()
                    if mode == "exit_after":
                        raise SystemExit(9)
                """
            ),
            encoding="utf-8",
        )
        self.helper.chmod(0o755)
        self.backend = _FakeBackend(
            self.root,
            self.helper,
            self.mode_file,
            self.counter,
        )
        self.guesser = OpenClassGuesser(self.backend)  # type: ignore[arg-type]
        # Make the fake executable portable to the native Windows test runner:
        # invoke the script through the active Python rather than relying on a
        # POSIX shebang. Helper options belong after that script argument.
        self.guesser._worker.command = (
            sys.executable,
            str(self.helper),
            "--pipe-mode=both",
        )
        self.guesser._worker._windows_option_index = 2

    def tearDown(self) -> None:
        self.guesser.close()
        self.temporary.cleanup()

    def test_windows_uses_bounded_one_shot_queries_instead_of_pipe_selectors(self) -> None:
        with mock.patch("qazmorph.guesser.sys.platform", "win32"), mock.patch(
            "qazmorph.guesser.selectors.DefaultSelector",
            side_effect=AssertionError("Windows subprocess pipes are not selectable"),
        ):
            first = self.guesser._raw_lookup(
                "алмасөз", max_lines=8, timeout=2.0
            )
            second = self.guesser._raw_lookup(
                "басқасөз", max_lines=8, timeout=2.0
            )
        self.assertEqual(len(first), 4)
        self.assertEqual(len(second), 4)
        self.assertEqual(self.counter.read_text(encoding="utf-8").count("started"), 2)
        self.assertEqual(self.guesser.diagnostics["worker_starts"], 2)
        self.assertEqual(
            Path(
                (self.root / "helper-cwd").read_text(encoding="utf-8")
            ).resolve(),
            self.root.resolve(),
        )

    def test_windows_one_shot_passes_a_plus_one_completeness_sentinel(self) -> None:
        command = self.guesser._worker._windows_oneshot_command(max_lines=7)
        self.assertEqual(
            command[:4],
            [sys.executable, str(self.helper), "-n", "8"],
        )
        with mock.patch("qazmorph.guesser.sys.platform", "win32"):
            response = self.guesser._worker._query_windows_oneshot(
                "сөз", max_lines=7, timeout=2.0, max_bytes=4096
            )

        self.assertIn("--pipe-mode=both", command)
        self.assertTrue(response.complete)
        self.assertEqual(len(response.lines), 4)

    def test_windows_one_shot_timeout_terminates_the_helper(self) -> None:
        self.mode_file.write_text("timeout", encoding="utf-8")
        with mock.patch("qazmorph.guesser.sys.platform", "win32"):
            with self.assertRaisesRegex(BackendError, "timed out"):
                self.guesser._raw_lookup("баяусөз", timeout=0.1)
        self.assertEqual(self.guesser.diagnostics["idle_restarts"], 1)
        self.assertEqual(self.guesser.diagnostics["oneshot_reaps"], 1)
        self.assertIsNone(self.guesser._worker._process)

    def test_windows_one_shot_retries_strict_utf8_protocol_failure_once(self) -> None:
        self.mode_file.write_text("invalid_utf8_once", encoding="utf-8")
        with mock.patch("qazmorph.guesser.sys.platform", "win32"):
            lines = self.guesser._raw_lookup("қаталсөз", timeout=2.0)

        self.assertEqual(len(lines), 4)
        self.assertEqual(self.guesser.diagnostics["protocol_restarts"], 1)
        self.assertEqual(
            self.counter.read_text(encoding="utf-8").splitlines(),
            ["started", "started"],
        )

    def test_windows_one_shot_rejects_non_lf_controls_and_extra_output(self) -> None:
        with mock.patch("qazmorph.guesser.sys.platform", "win32"):
            for mode in ("invalid_utf8", "bare_cr", "extra_output", "unterminated"):
                with self.subTest(mode=mode):
                    self.mode_file.write_text(mode, encoding="utf-8")
                    with self.assertRaisesRegex(
                        BackendError, "protocol could not correlate"
                    ):
                        self.guesser._raw_lookup("ақаусөз", timeout=2.0)

    def test_windows_one_shot_composes_with_strict_optimized_grammar(self) -> None:
        with mock.patch("qazmorph.guesser.sys.platform", "win32"):
            for mode, surface in (
                ("mixed_negative", "араласөз"),
                ("duplicate_negative", "қоссөз"),
                ("empty_candidate", "боссөз"),
                ("tagless_identity", "тегсізсөз"),
                ("control_marker", "басқарсөз"),
                ("extra_field", "артықсөз"),
            ):
                with self.subTest(mode=mode):
                    self.mode_file.write_text(mode, encoding="utf-8")
                    with self.assertRaisesRegex(
                        BackendError, "protocol could not correlate"
                    ):
                        self.guesser._raw_lookup(surface, timeout=2.0)

    def test_windows_one_shot_composes_with_strict_standard_grammar(self) -> None:
        backend = _FakeBackend(
            self.root, self.helper, self.mode_file, self.counter
        )
        backend.guesser_optimized = False
        legacy = OpenClassGuesser(backend)  # type: ignore[arg-type]
        legacy._worker.command = (
            sys.executable,
            str(self.helper),
            "-i",
            "--pipe-mode=both",
        )
        legacy._worker._windows_option_index = 2
        try:
            with mock.patch("qazmorph.guesser.sys.platform", "win32"):
                self.mode_file.write_text("unknown_extra", encoding="utf-8")
                negative = legacy._guess_detailed(
                    "кеңесіуінің", timeout=1.0
                )
                self.assertTrue(negative.complete)
                self.assertEqual(negative.candidates, ())
                for mode, surface in (
                    ("nonfinite_weight", "сансызсөз"),
                    ("infinite_weight", "шексізсөз"),
                    ("garbage_weight", "қоқыссөз"),
                    ("extra_field", "артықсөз"),
                ):
                    with self.subTest(mode=mode):
                        self.mode_file.write_text(mode, encoding="utf-8")
                        with self.assertRaisesRegex(
                            BackendError, "protocol could not correlate"
                        ):
                            legacy._raw_lookup(surface, timeout=2.0)
        finally:
            legacy.close()

    def test_windows_one_shot_caps_discard_every_partial_candidate(self) -> None:
        with mock.patch("qazmorph.guesser.sys.platform", "win32"):
            with self.assertRaisesRegex(BackendError, "byte cap.*partial.*discarded"):
                self.guesser._raw_lookup(
                    "көлемсөз", max_lines=8, max_bytes=32, timeout=2.0
                )
            with self.assertRaisesRegex(BackendError, "line cap.*partial.*discarded"):
                self.guesser._raw_lookup(
                    "жолсөз", max_lines=2, max_bytes=4096, timeout=2.0
                )

        self.assertEqual(self.guesser.diagnostics["cap_aborts"], 2)

    def test_windows_hard_stdout_cap_never_caches_partial_candidates(self) -> None:
        self.mode_file.write_text("stdout_flood", encoding="utf-8")
        with mock.patch("qazmorph.guesser.sys.platform", "win32"):
            with self.assertWarnsRegex(RuntimeWarning, "byte cap.*partial.*discarded"):
                self.assertEqual(self.guesser.guess("тасқынсөз"), [])
            starts = self.guesser.diagnostics["worker_starts"]
            with warnings.catch_warnings(record=True) as repeated:
                warnings.simplefilter("always")
                self.assertEqual(self.guesser.guess("тасқынсөз"), [])

        self.assertEqual(repeated, [])
        self.assertEqual(self.guesser.diagnostics["worker_starts"], starts)
        self.assertEqual(self.guesser.diagnostics["oneshot_reaps"], 1)
        cached = self.guesser._cache[("тасқынсөз", 8, False)]
        self.assertEqual(cached.candidates, ())
        self.assertFalse(cached.complete)

    def test_windows_hard_stderr_cap_reaps_helper_and_recovers(self) -> None:
        self.mode_file.write_text("stderr_flood", encoding="utf-8")
        with mock.patch("qazmorph.guesser.sys.platform", "win32"):
            with self.assertRaisesRegex(BackendError, "stderr byte cap"):
                self.guesser._raw_lookup("диагсөз", timeout=2.0)
            self.mode_file.write_text("normal", encoding="utf-8")
            self.assertEqual(
                len(self.guesser._raw_lookup("жаңасөз", timeout=2.0)),
                4,
            )

        self.assertEqual(self.guesser.diagnostics["oneshot_reaps"], 2)
        self.assertIsNone(self.guesser._worker._process)

    def test_windows_reader_start_failure_still_reaps_helper(self) -> None:
        original_start = threading.Thread.start
        calls = 0

        def fail_second_start(thread: threading.Thread) -> None:
            nonlocal calls
            calls += 1
            if calls == 2:
                raise RuntimeError("deliberate reader start failure")
            original_start(thread)

        with mock.patch(
            "qazmorph.guesser.threading.Thread.start",
            autospec=True,
            side_effect=fail_second_start,
        ), mock.patch("qazmorph.guesser.sys.platform", "win32"):
            with self.assertRaisesRegex(BackendError, "reader could not start"):
                self.guesser._raw_lookup("жіпсөз", timeout=2.0)

        self.assertEqual(self.guesser.diagnostics["oneshot_reaps"], 1)
        self.assertIsNone(self.guesser._worker._process)

    def test_worker_is_reused_across_complete_responses(self) -> None:
        first = self.guesser._raw_lookup("алмасөз", max_lines=8, timeout=2.0)
        second = self.guesser._raw_lookup("басқасөз", max_lines=8, timeout=2.0)

        self.assertEqual(
            first[:2],
            [
                "алмасөз\tалмасөз<n><nom>",
                "алмасөз\tалмасөз<adj>",
            ],
        )
        self.assertEqual(
            second[:2],
            [
                "басқасөз\tбасқасөз<n><nom>",
                "басқасөз\tбасқасөз<adj>",
            ],
        )
        self.assertEqual(len(first), 4)
        self.assertEqual(len(second), 4)
        self.assertEqual(self.counter.read_text(encoding="utf-8").splitlines(), ["started"])

    def test_correlated_unknown_with_extra_separators_does_not_shift_responses(self) -> None:
        self.mode_file.write_text("unknown_extra", encoding="utf-8")
        negative = self.guesser._raw_lookup("кеңесіуінің", timeout=2.0)
        self.mode_file.write_text("normal", encoding="utf-8")
        first = self.guesser._raw_lookup("жұптық", timeout=2.0)
        second = self.guesser._raw_lookup("ағылш", timeout=2.0)

        self.assertEqual(negative, ["кеңесіуінің\tкеңесіуінің\t+?"])
        self.assertTrue(first)
        self.assertTrue(second)
        self.assertTrue(all(line.split("\t", 1)[0] == "жұптық" for line in first))
        self.assertTrue(all(line.split("\t", 1)[0] == "ағылш" for line in second))
        self.assertEqual(self.guesser.diagnostics["protocol_restarts"], 0)
        self.assertEqual(
            self.counter.read_text(encoding="utf-8").splitlines(), ["started"]
        )

    def test_late_blank_separator_is_drained_before_next_keyed_response(self) -> None:
        self.mode_file.write_text("late_separator", encoding="utf-8")
        negative = self.guesser._raw_lookup("кеңесіуінің", timeout=2.0)
        self.mode_file.write_text("normal", encoding="utf-8")
        candidates = self.guesser._raw_lookup("жұптық", timeout=2.0)

        self.assertEqual(negative, ["кеңесіуінің\tкеңесіуінің\t+?"])
        self.assertTrue(candidates)
        self.assertTrue(
            all(line.split("\t", 1)[0] == "жұптық" for line in candidates)
        )
        diagnostics = self.guesser.diagnostics
        self.assertEqual(diagnostics["protocol_restarts"], 0)
        self.assertEqual(diagnostics["leading_separator_records"], 1)
        self.assertEqual(diagnostics["leading_separator_bytes"], 1)
        self.assertEqual(
            self.counter.read_text(encoding="utf-8").splitlines(), ["started"]
        )

    def test_blank_flood_uses_existing_response_byte_cap(self) -> None:
        self.mode_file.write_text("blank_flood", encoding="utf-8")
        response = self.guesser._worker.query(
            "тасқынсөз",
            max_lines=8,
            max_bytes=8,
            max_request_bytes=MAX_GUESS_REQUEST_BYTES,
            timeout=1.0,
        )

        self.assertFalse(response.complete)
        self.assertEqual(response.lines, ())
        self.assertEqual(response.reason, "response_cap")
        diagnostics = self.guesser.diagnostics
        self.assertEqual(diagnostics["cap_aborts"], 1)
        self.assertEqual(diagnostics["leading_separator_records"], 9)
        self.assertEqual(diagnostics["leading_separator_bytes"], 9)
        self.mode_file.write_text("normal", encoding="utf-8")
        self.assertTrue(self.guesser._raw_lookup("жаңасөз", timeout=1.0))

    def test_blank_only_response_times_out_and_discards_worker(self) -> None:
        self.mode_file.write_text("blank_only_timeout", encoding="utf-8")
        with self.assertRaisesRegex(
            BackendError, "timed out.*partial response discarded"
        ):
            self.guesser._raw_lookup("баяусөз", timeout=0.1)
        self.assertIsNone(self.guesser._worker._process)
        self.assertEqual(
            self.guesser.diagnostics["leading_separator_records"], 2
        )

    def test_blank_only_response_exit_fails_closed(self) -> None:
        self.mode_file.write_text("blank_only_exit", encoding="utf-8")
        with self.assertRaisesRegex(BackendError, "closed its output.*status 8"):
            self.guesser._raw_lookup("ақаусөз", timeout=1.0)
        self.assertIsNone(self.guesser._worker._process)
        self.assertEqual(
            self.guesser.diagnostics["leading_separator_records"], 2
        )

    def test_exact_optimized_negative_is_complete_zero(self) -> None:
        self.mode_file.write_text("unknown_extra", encoding="utf-8")
        outcome = self.guesser._guess_detailed("кеңесіуінің", timeout=1.0)
        self.assertTrue(outcome.complete)
        self.assertEqual(outcome.candidates, ())
        self.assertIsNone(outcome.reason)
        self.assertEqual(self.guesser.diagnostics["protocol_restarts"], 0)

    def test_exact_standard_negative_is_complete_zero(self) -> None:
        self.mode_file.write_text("unknown_extra", encoding="utf-8")
        backend = _FakeBackend(
            self.root, self.helper, self.mode_file, self.counter
        )
        backend.guesser_optimized = False
        legacy = OpenClassGuesser(backend)  # type: ignore[arg-type]
        try:
            outcome = legacy._guess_detailed("кеңесіуінің", timeout=1.0)
            self.assertTrue(outcome.complete)
            self.assertEqual(outcome.candidates, ())
            self.assertIsNone(outcome.reason)
            self.assertEqual(legacy.diagnostics["protocol_restarts"], 0)
        finally:
            legacy.close()

    def test_malformed_optimized_grammars_restart_then_fail_incomplete(self) -> None:
        cases = (
            ("mixed_negative", "араласөз"),
            ("duplicate_negative", "қоссөз"),
            ("empty_candidate", "боссөз"),
            ("tagless_identity", "тегсізсөз"),
            ("control_marker", "басқарсөз"),
            ("extra_field", "артықсөз"),
        )
        for mode, surface in cases:
            with self.subTest(mode=mode):
                self.mode_file.write_text(mode, encoding="utf-8")
                with self.assertWarnsRegex(
                    RuntimeWarning, "protocol could not correlate"
                ):
                    outcome = self.guesser._guess_detailed(
                        surface, timeout=2.0
                    )
                self.assertFalse(outcome.complete)
                self.assertEqual(outcome.candidates, ())
                self.assertEqual(outcome.reason, "failure")
        self.assertEqual(
            self.guesser.diagnostics["protocol_restarts"], len(cases)
        )

    def test_bad_standard_weights_never_reach_candidate_parsing(self) -> None:
        backend = _FakeBackend(
            self.root, self.helper, self.mode_file, self.counter
        )
        backend.guesser_optimized = False
        legacy = OpenClassGuesser(backend)  # type: ignore[arg-type]
        try:
            cases = (
                ("nonfinite_weight", "сансызсөз"),
                ("infinite_weight", "шексізсөз"),
                ("garbage_weight", "қоқыссөз"),
                ("extra_field", "артықсөз"),
            )
            for mode, surface in cases:
                with self.subTest(mode=mode):
                    self.mode_file.write_text(mode, encoding="utf-8")
                    with self.assertWarnsRegex(
                        RuntimeWarning, "protocol could not correlate"
                    ):
                        outcome = legacy._guess_detailed(
                            surface, timeout=2.0
                        )
                    self.assertFalse(outcome.complete)
                    self.assertEqual(outcome.candidates, ())
                    self.assertEqual(outcome.reason, "failure")
            self.assertEqual(
                legacy.diagnostics["protocol_restarts"], len(cases)
            )
        finally:
            legacy.close()

    def test_mismatched_surface_restarts_once_and_recovers(self) -> None:
        self.mode_file.write_text("misroute_once", encoding="utf-8")
        lines = self.guesser._raw_lookup("жұптық", timeout=2.0)

        self.assertTrue(lines)
        self.assertTrue(all(line.split("\t", 1)[0] == "жұптық" for line in lines))
        self.assertEqual(self.guesser.diagnostics["protocol_restarts"], 1)
        self.assertEqual(
            self.counter.read_text(encoding="utf-8").splitlines(),
            ["started", "started"],
        )

    def test_second_mismatched_surface_fails_closed(self) -> None:
        self.mode_file.write_text("misroute", encoding="utf-8")
        with self.assertWarnsRegex(RuntimeWarning, "explicit unknown analysis"):
            self.assertEqual(self.guesser.guess("жұптық"), [])

        diagnostics = self.guesser.diagnostics
        self.assertEqual(diagnostics["protocol_restarts"], 1)
        self.assertEqual(diagnostics["failures"], 1)

    def test_cache_retains_capacity_and_replays_exact_candidates(self) -> None:
        self.assertEqual(GUESS_CACHE_CAPACITY, 8192)

        def produce(surface: str, limit: int, generate_all: bool, timeout: float):
            return _GuessOutcome((f"{surface}:{limit}:{generate_all}",), True)

        with mock.patch.object(
            self.guesser, "_guess_uncached_detailed", side_effect=produce
        ) as uncached:
            first = self.guesser._guess_cached("кэш0", 8, False)
            for index in range(1, GUESS_CACHE_CAPACITY):
                self.guesser._guess_cached(f"кэш{index}", 8, False)
            repeated = self.guesser._guess_cached("кэш0", 8, False)
            public = self.guesser.guess("кэш0")

        self.assertIs(first, repeated)
        self.assertEqual(public, ["кэш0:8:False"])
        self.assertEqual(uncached.call_count, GUESS_CACHE_CAPACITY)
        diagnostics = self.guesser.diagnostics
        self.assertEqual(diagnostics["cache_entries"], GUESS_CACHE_CAPACITY)
        self.assertEqual(diagnostics["cache_misses"], GUESS_CACHE_CAPACITY)
        self.assertEqual(diagnostics["cache_hits"], 2)
        self.assertEqual(diagnostics["lookup_queries"], 0)

    def test_cache_entry_past_capacity_evicts_only_the_oldest(self) -> None:
        with mock.patch.object(
            self.guesser,
            "_guess_uncached_detailed",
            side_effect=lambda surface, limit, generate_all, timeout: _GuessOutcome(
                (surface,), True
            ),
        ):
            for index in range(GUESS_CACHE_CAPACITY):
                self.guesser._guess_cached(f"кэш{index}", 8, False)
            self.guesser._guess_cached(
                f"кэш{GUESS_CACHE_CAPACITY}", 8, False
            )

        self.assertEqual(len(self.guesser._cache), GUESS_CACHE_CAPACITY)
        self.assertNotIn(("кэш0", 8, False), self.guesser._cache)
        self.assertIn(("кэш1", 8, False), self.guesser._cache)
        self.assertIn(
            (f"кэш{GUESS_CACHE_CAPACITY}", 8, False), self.guesser._cache
        )
        diagnostics = self.guesser.diagnostics
        self.assertEqual(diagnostics["cache_entries"], GUESS_CACHE_CAPACITY)
        self.assertEqual(diagnostics["cache_misses"], GUESS_CACHE_CAPACITY + 1)
        self.assertEqual(diagnostics["cache_hits"], 0)

    def test_legacy_standard_resource_uses_standard_lookup_protocol(self) -> None:
        legacy_backend = _FakeBackend(
            self.root,
            self.helper,
            self.mode_file,
            self.counter,
        )
        legacy_backend.guesser_optimized = False
        legacy = OpenClassGuesser(legacy_backend)  # type: ignore[arg-type]
        try:
            self.assertFalse(legacy._optimized)
            self.assertTrue(legacy.guess("мұрасөз"))
        finally:
            legacy.close()

    def test_cyclic_legacy_resource_disables_productive_guessing(self) -> None:
        legacy_backend = _FakeBackend(
            self.root,
            self.helper,
            self.mode_file,
            self.counter,
        )
        legacy_backend.guesser_optimized = False
        legacy_backend.manifest = {"schema": RESOURCE_MANIFEST_V2}
        legacy = OpenClassGuesser(legacy_backend)  # type: ignore[arg-type]
        try:
            self.assertFalse(legacy.available)
            self.assertEqual(legacy.guess("мұрасөз"), [])
            self.assertFalse(self.counter.exists())
            self.assertEqual(legacy.diagnostics["unsafe_resource_skips"], 1)
            self.assertEqual(legacy.diagnostics["productive_resource_safe"], 0)
        finally:
            legacy.close()

    def test_line_cap_preserves_prefix_and_restarts_without_draining(self) -> None:
        capped = self.guesser._raw_lookup_detailed(
            "алмасөз", max_lines=2, timeout=2.0
        )
        complete = self.guesser._raw_lookup("басқасөз", max_lines=8, timeout=2.0)

        self.assertEqual(
            capped.lines,
            (
                "алмасөз\tалмасөз<n><nom>",
                "алмасөз\tалмасөз<adj>",
            ),
        )
        self.assertFalse(capped.complete)
        self.assertEqual(capped.reason, "response_cap")
        self.assertEqual(len(complete), 4)
        self.assertEqual(
            self.counter.read_text(encoding="utf-8").splitlines(),
            ["started", "started"],
        )

    def test_timeout_discards_partial_response_and_restarts_worker(self) -> None:
        self.mode_file.write_text("timeout", encoding="utf-8")
        with self.assertRaisesRegex(BackendError, "partial response discarded"):
            self.guesser._raw_lookup("баяусөз", timeout=0.1)

        self.mode_file.write_text("normal", encoding="utf-8")
        complete = self.guesser._raw_lookup("жаңасөз", max_lines=1, timeout=2.0)
        self.assertEqual(complete, ["жаңасөз\tжаңасөз<n><nom>"])
        # The internal monotonic counter observes both Popen calls directly;
        # unlike the terminated fake helper's test-only file append, it is a
        # platform-independent assertion of the restart contract.
        self.assertEqual(self.guesser.diagnostics["worker_starts"], 2)

    def test_nonzero_exit_is_reported(self) -> None:
        self.mode_file.write_text("failure", encoding="utf-8")
        with self.assertRaisesRegex(BackendError, "status 7.*deliberate lookup failure"):
            self.guesser._raw_lookup("ақаусөз", timeout=2.0)

    def test_exit_between_queries_warns_and_transparently_restarts(self) -> None:
        self.mode_file.write_text("exit_after", encoding="utf-8")
        self.assertEqual(len(self.guesser._raw_lookup("бірсөз", timeout=2.0)), 4)
        process = self.guesser._worker._process
        self.assertIsNotNone(process)
        assert process is not None
        self.assertEqual(process.wait(timeout=2.0), 9)

        self.mode_file.write_text("normal", encoding="utf-8")
        with self.assertWarnsRegex(RuntimeWarning, "between queries.*status 9"):
            self.assertTrue(self.guesser.guess("екіншісөз"))
        self.assertTrue(self.guesser.guess("үшіншісөз"))
        self.assertEqual(self.guesser.diagnostics["failures"], 0)
        self.assertEqual(self.guesser.diagnostics["idle_restarts"], 1)

    def test_guess_failure_warns_once_then_uses_cached_empty_result(self) -> None:
        self.mode_file.write_text("failure", encoding="utf-8")
        with self.assertWarnsRegex(RuntimeWarning, "explicit unknown analysis"):
            self.assertEqual(self.guesser.guess("ақаусөз"), [])

        with warnings.catch_warnings(record=True) as repeated:
            warnings.simplefilter("always")
            self.assertEqual(self.guesser.guess("ақаусөз"), [])
        self.assertEqual(repeated, [])
        self.assertEqual(self.guesser.diagnostics["failures"], 1)
        self.assertEqual(self.guesser.diagnostics["cache_hits"], 1)

        # The negative cache is deliberately instance-local, not permanent or
        # process-global: a new analyzer/guesser retries the same OOV.
        self.mode_file.write_text("normal", encoding="utf-8")
        replacement = OpenClassGuesser(self.backend)  # type: ignore[arg-type]
        try:
            self.assertTrue(replacement.guess("ақаусөз"))
        finally:
            replacement.close()

    def test_guess_timeout_warns_and_returns_no_partial_candidates(self) -> None:
        self.mode_file.write_text("timeout", encoding="utf-8")
        with self.assertWarnsRegex(RuntimeWarning, "partial response discarded"):
            outcome = self.guesser._guess_detailed("баяусөз", timeout=0.1)
        self.assertEqual(outcome.candidates, ())
        self.assertFalse(outcome.complete)
        self.assertEqual(outcome.reason, "timeout")
        self.assertEqual(self.guesser.diagnostics["timeouts"], 1)

    def test_stalled_stdin_write_obeys_same_absolute_deadline(self) -> None:
        with mock.patch(
            "qazmorph.guesser.os.write", side_effect=BlockingIOError
        ), self.assertWarnsRegex(RuntimeWarning, "while writing the request"):
            outcome = self.guesser._guess_detailed(
                "баяусөз", timeout=0.05
            )
        self.assertEqual(outcome.candidates, ())
        self.assertFalse(outcome.complete)
        self.assertEqual(outcome.reason, "timeout")
        self.assertIsNone(self.guesser._worker._process)

        recovered = self.guesser._guess_detailed("жаңасөз", timeout=1.0)
        self.assertTrue(recovered.complete)
        self.assertTrue(recovered.candidates)

    def test_response_validation_cannot_extend_absolute_deadline(self) -> None:
        self.assertTrue(self.guesser._raw_lookup("жылысөз", timeout=1.0))
        validate = self.guesser._response_protocol_problem

        def slow_validation(
            surface: str, lines: tuple[str, ...]
        ) -> str | None:
            time.sleep(0.1)
            return validate(surface, lines)

        with mock.patch.object(
            self.guesser,
            "_response_protocol_problem",
            side_effect=slow_validation,
        ), self.assertWarnsRegex(RuntimeWarning, "during response validation"):
            outcome = self.guesser._guess_detailed(
                "баяусөз", timeout=0.05
            )
        self.assertFalse(outcome.complete)
        self.assertEqual(outcome.candidates, ())
        self.assertEqual(outcome.reason, "timeout")

        recovered = self.guesser._guess_detailed("жаңасөз", timeout=1.0)
        self.assertTrue(recovered.complete)
        self.assertTrue(recovered.candidates)

    def test_request_byte_caps_are_caller_specific(self) -> None:
        oversized_guess = "а" * (MAX_GUESS_REQUEST_BYTES // 2 + 1)
        with self.assertRaisesRegex(ValueError, "encoded byte limit"):
            self.guesser._worker.query(
                oversized_guess,
                max_lines=8,
                timeout=1.0,
                max_bytes=4096,
                max_request_bytes=MAX_GUESS_REQUEST_BYTES,
            )
        self.assertFalse(self.counter.exists())

        lexical = (
            "а" * (MAX_GUESS_REQUEST_BYTES // 2 + 1) + "<n><nom>"
        )
        response = self.guesser._worker.query(
            lexical,
            max_lines=8,
            timeout=1.0,
            max_bytes=4096,
            max_request_bytes=MAX_LOOKUP_REQUEST_BYTES,
        )
        self.assertTrue(response.complete)
        self.assertEqual(len(response.lines), 4)

    def test_invalid_utf8_is_incomplete_and_worker_is_reset(self) -> None:
        self.mode_file.write_text("invalid_utf8", encoding="utf-8")
        with self.assertWarnsRegex(RuntimeWarning, "valid UTF-8"):
            invalid = self.guesser._guess_detailed(
                "ақаусөз", timeout=1.0
            )
        self.assertEqual(invalid.candidates, ())
        self.assertFalse(invalid.complete)
        self.assertEqual(invalid.reason, "failure")
        self.assertIsNone(self.guesser._worker._process)

        self.mode_file.write_text("normal", encoding="utf-8")
        recovered = self.guesser._guess_detailed("ақаусөз")
        self.assertTrue(recovered.complete)
        self.assertTrue(recovered.candidates)

    def test_nondefault_deadlines_do_not_grow_standard_cache(self) -> None:
        with mock.patch.object(
            self.guesser,
            "_guess_uncached_detailed",
            return_value=_GuessOutcome((), False, "timeout"),
        ) as uncached:
            for index in range(20):
                outcome = self.guesser._guess_detailed(
                    "баяусөз", timeout=0.1 + index / 1000
                )
                self.assertFalse(outcome.complete)
        self.assertEqual(uncached.call_count, 20)
        self.assertEqual(self.guesser.diagnostics["cache_entries"], 0)

    def test_deadline_includes_wait_for_concurrent_cache_owner(self) -> None:
        ready = threading.Event()
        release = threading.Event()

        def hold_cache() -> None:
            with self.guesser._cache_lock:
                ready.set()
                release.wait(timeout=2.0)

        holder = threading.Thread(target=hold_cache)
        holder.start()
        self.assertTrue(ready.wait(timeout=1.0))
        try:
            with self.assertWarnsRegex(RuntimeWarning, "cache wait"):
                outcome = self.guesser._guess_detailed(
                    "баяусөз", timeout=0.05
                )
        finally:
            release.set()
            holder.join(timeout=1.0)
        self.assertFalse(outcome.complete)
        self.assertEqual(outcome.reason, "timeout")
        self.assertFalse(self.counter.exists())

    def test_deadline_includes_wait_for_concurrent_worker_owner(self) -> None:
        ready = threading.Event()
        release = threading.Event()

        def hold_worker() -> None:
            with self.guesser._worker._lock:
                ready.set()
                release.wait(timeout=2.0)

        holder = threading.Thread(target=hold_worker)
        holder.start()
        self.assertTrue(ready.wait(timeout=1.0))
        try:
            with self.assertRaisesRegex(BackendError, "timed out"):
                self.guesser._raw_lookup("баяусөз", timeout=0.05)
        finally:
            release.set()
            holder.join(timeout=1.0)
        self.assertFalse(self.counter.exists())

    def test_deadline_includes_protocol_reset_lock_race(self) -> None:
        ready = threading.Event()
        release = threading.Event()

        def hold_worker() -> None:
            with self.guesser._worker._lock:
                ready.set()
                release.wait(timeout=2.0)

        holder = threading.Thread(target=hold_worker)
        holder.start()
        self.assertTrue(ready.wait(timeout=1.0))
        started = time.monotonic()
        try:
            with mock.patch.object(
                self.guesser._worker,
                "query",
                return_value=_LookupResponse(
                    ("бөгдесөз\tбөгдесөз<n><nom>",), True
                ),
            ), self.assertRaisesRegex(BackendError, "while restarting"):
                self.guesser._raw_lookup("баяусөз", timeout=0.05)
        finally:
            release.set()
            holder.join(timeout=1.0)
        self.assertLess(time.monotonic() - started, 0.5)
        self.assertEqual(
            self.guesser.diagnostics["protocol_restarts"], 0
        )

    def test_default_cache_preserves_incomplete_outcome_atomically(self) -> None:
        self.mode_file.write_text("failure", encoding="utf-8")
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", RuntimeWarning)
            with ThreadPoolExecutor(max_workers=4) as executor:
                outcomes = list(
                    executor.map(
                        lambda _: self.guesser._guess_detailed("ақаусөз"),
                        range(4),
                    )
                )
        self.assertTrue(all(outcome is outcomes[0] for outcome in outcomes))
        self.assertFalse(outcomes[0].complete)
        self.assertEqual(outcomes[0].reason, "failure")
        self.assertEqual(self.guesser.diagnostics["failures"], 1)
        self.assertEqual(self.guesser.diagnostics["cache_entries"], 1)

    def test_incomplete_candidate_prefix_keeps_completion_bit_in_cache(self) -> None:
        line = "алмасөз\tалмасөз<n><nom>"
        with mock.patch.object(
            self.guesser,
            "_raw_lookup_detailed",
            return_value=_LookupResponse((line,), False, "response_cap"),
        ):
            outcome = self.guesser._guess_detailed("алмасөз")
            repeated = self.guesser._guess_detailed("алмасөз")
        self.assertTrue(outcome.candidates)
        self.assertFalse(outcome.complete)
        self.assertEqual(outcome.reason, "response_cap")
        self.assertIs(repeated, outcome)

    def test_cycle_marker_is_counted_and_partial_candidates_fail_closed(self) -> None:
        self.mode_file.write_text("cyclic", encoding="utf-8")
        with self.assertWarnsRegex(RuntimeWarning, "protocol could not correlate"):
            self.assertEqual(self.guesser.guess("айналмасөз"), [])
        self.assertEqual(self.guesser.diagnostics["cycle_truncations"], 2)
        self.assertEqual(self.guesser.diagnostics["protocol_restarts"], 1)

        # The empty result is cached just like timeout/failure fallbacks, so a
        # repeated token neither replays the marker nor repeats the warning.
        with warnings.catch_warnings(record=True) as repeated:
            warnings.simplefilter("always")
            self.assertEqual(self.guesser.guess("айналмасөз"), [])
        self.assertEqual(repeated, [])
        self.assertEqual(self.guesser.diagnostics["cycle_truncations"], 2)

    def test_prefilter_skips_non_cyrillic_and_overlong_surfaces_without_launch(self) -> None:
        self.assertTrue(self.guesser._eligible_surface("Қазақстанның"))
        self.assertEqual(self.guesser.guess("latin"), [])
        self.assertEqual(self.guesser.guess("а" * 33), [])
        self.assertEqual(self.guesser.guess("туууу"), [])
        self.assertFalse(self.counter.exists())
        self.assertEqual(self.guesser.diagnostics["prefilter_skips"], 3)

    def test_stderr_is_drained_while_a_query_runs(self) -> None:
        self.mode_file.write_text("stderr_flood", encoding="utf-8")
        self.assertEqual(len(self.guesser._raw_lookup("сөз", timeout=2.0)), 4)

    def test_byte_cap_returns_complete_line_prefix_and_restarts(self) -> None:
        self.assertEqual(
            self.guesser._raw_lookup("алмасөз", max_lines=8, max_bytes=50, timeout=2.0),
            ["алмасөз\tалмасөз<n><nom>"],
        )
        self.assertEqual(len(self.guesser._raw_lookup("басқасөз", timeout=2.0)), 4)
        self.assertEqual(self.guesser.diagnostics["cap_aborts"], 1)
        self.assertEqual(self.guesser.diagnostics["worker_starts"], 2)

    def test_close_allows_lazy_reopen(self) -> None:
        self.assertEqual(len(self.guesser._raw_lookup("алмасөз", timeout=2.0)), 4)
        self.guesser.close()
        self.assertEqual(len(self.guesser._raw_lookup("басқасөз", timeout=2.0)), 4)
        self.assertEqual(self.guesser.diagnostics["worker_starts"], 2)

    def test_concurrent_callers_are_serialized_and_scores_are_normalized(self) -> None:
        words = [f"сөз{suffix}" for suffix in ("а", "ә", "е", "і", "о", "ө", "ұ", "ү")]
        with ThreadPoolExecutor(max_workers=8) as executor:
            results = list(executor.map(self.guesser.guess, words))
        self.assertTrue(all(results))
        self.assertEqual(self.guesser.diagnostics["worker_starts"], 1)

        ranked = self.guesser.guess("алмасөз", limit=2)
        self.assertEqual(len(ranked), 2)
        self.assertAlmostEqual(sum(item.score or 0.0 for item in ranked), 1.0)
        self.assertGreaterEqual(ranked[0].score or 0.0, ranked[1].score or 0.0)

    def test_nonpositive_limits_are_rejected_by_python_apis(self) -> None:
        with self.assertRaisesRegex(ValueError, "limit must be positive"):
            self.guesser.guess("сөз", limit=0)
        with self.assertRaisesRegex(ValueError, "guess_limit must be positive"):
            Analyzer(resource_dir=self.root, guess_limit=0)

    @unittest.skipUnless(hasattr(os, "fork"), "requires POSIX fork")
    def test_child_reinitializes_locks_held_by_parent_threads(self) -> None:
        self.assertTrue(self.guesser.guess("алмасөз"))
        ready = threading.Event()
        release = threading.Event()

        def hold_parent_locks() -> None:
            with self.guesser._cache_lock, self.guesser._worker._lock:
                ready.set()
                release.wait(timeout=5.0)

        holder = threading.Thread(target=hold_parent_locks)
        holder.start()
        self.assertTrue(ready.wait(timeout=2.0))
        read_fd, write_fd = os.pipe()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            child_pid = os.fork()
        if child_pid == 0:
            os.close(read_fd)
            try:
                # Exercise the cache-hit branch: it must still detach every
                # pipe inherited from the parent's live HFST worker.
                result = self.guesser.guess("алмасөз")
                detached = self.guesser._worker._process is None
                os.write(write_fd, b"ok" if result and detached else b"leaked")
                os._exit(0)
            except BaseException as exc:
                os.write(write_fd, f"error:{exc}".encode("utf-8", errors="replace"))
                os._exit(1)

        os.close(write_fd)
        release.set()
        holder.join(timeout=2.0)
        readable, _, _ = select.select([read_fd], [], [], 4.0)
        self.assertEqual(readable, [read_fd], "forked child deadlocked on an inherited lock")
        child_result = os.read(read_fd, 4096)
        os.close(read_fd)
        _, status = os.waitpid(child_pid, 0)
        self.assertEqual(status, 0, child_result.decode("utf-8", errors="replace"))
        self.assertEqual(child_result, b"ok")


if __name__ == "__main__":
    unittest.main()
