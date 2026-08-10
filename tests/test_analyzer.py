from __future__ import annotations

import unittest
from unittest import mock

from qazmorph.analyzer import Analyzer, _AlignedSegment
from qazmorph.backend import BackendError
from qazmorph.stream import RawSegment, parse_analysis


class DictionaryGenerationInputTests(unittest.TestCase):
    def setUp(self) -> None:
        self.analyzer = Analyzer.__new__(Analyzer)
        self.analyzer.backend = mock.Mock()
        self.analyzer.backend.generate.return_value = ["сөз"]

    def test_exact_valid_query_is_forwarded_without_record_loss(self) -> None:
        self.assertEqual(
            self.analyzer.generate(r"сөз+түбір\бөлік", ("<n>", " nom ")),
            ["сөз"],
        )
        self.analyzer.backend.generate.assert_called_once_with(
            r"сөз\+түбір\\бөлік<n><nom>",
            limit=128,
        )

    def test_tags_are_a_nonempty_sequence_not_a_string(self) -> None:
        for tags in ("nom", b"nom", (), [], 1, ("n", 1)):
            with self.subTest(tags=repr(tags)), self.assertRaisesRegex(
                ValueError, "tags must be a nonempty sequence"
            ):
                self.analyzer.generate("сөз", tags)  # type: ignore[arg-type]
        self.analyzer.backend.generate.assert_not_called()

    def test_lemma_is_exact_nonempty_text_without_record_controls(self) -> None:
        for lemma in (
            None,
            "",
            "сөз<n>",
            "сөз[control]",
            "сөз{control}",
            "сөз\t",
            "сөз\r",
            "сөз\n",
            "сөз\0",
            "сөз\x01",
            "сөз\x85",
            "сөз\u2028",
            "сөз\ud800",
        ):
            with self.subTest(lemma=repr(lemma)), self.assertRaises(ValueError):
                self.analyzer.generate(lemma, ("n",))  # type: ignore[arg-type]
        self.analyzer.backend.generate.assert_not_called()

    def test_encoded_query_has_an_exact_4096_byte_ceiling(self) -> None:
        exact = "a" * 4093
        self.analyzer.generate(exact, ("n",))
        query = self.analyzer.backend.generate.call_args.args[0]
        self.assertEqual(len(query.encode("utf-8")), 4096)

        self.analyzer.backend.reset_mock()
        with self.assertRaisesRegex(ValueError, "bounded generator input"):
            self.analyzer.generate("a" * 4094, ("n",))
        self.analyzer.backend.generate.assert_not_called()

    def test_limit_must_be_a_positive_integer_not_bool(self) -> None:
        for limit in (0, -1, True, False, 1.5, float("inf"), "2"):
            with self.subTest(limit=limit), self.assertRaisesRegex(
                ValueError, "generation limit"
            ):
                self.analyzer.generate("сөз", ("n",), limit=limit)  # type: ignore[arg-type]
        self.analyzer.backend.generate.assert_not_called()


class _NoGuess:
    def guess(self, *args: object, **kwargs: object) -> list[object]:
        raise AssertionError("CG alignment fallback must not invoke OOV guessing")


class _SplitCgBackend:
    resource_version = "test"

    def analyze_stream_pair(
        self, text: str, *, disambiguate: bool = False
    ) -> tuple[str, str | None]:
        lattice = "^сөз/сөз<n><nom>$"
        # Force the exact-surface path: the phrase-level CG stream has a
        # different partition even though the lattice itself is already exact.
        contextual = "^с/с<n>$^өз/өз<n>$" if disambiguate else None
        return lattice, contextual

    def analyze_atomic_stream_pair(
        self,
        text: str,
        boundaries: tuple[tuple[int, int], ...],
        *,
        disambiguate: bool = False,
    ) -> tuple[str, str | None]:
        self.boundaries = boundaries
        # A deliberately different CG cohort partition still covers the input.
        # The analyzer must retain the exact lattice cohort for the atomic token.
        return "^сөз/сөз<n><nom>$", "^с/с<n>$^өз/өз<n>$" if disambiguate else None


class _CountingBackend:
    resource_version = "test"

    def __init__(self, *, phrase_mwe: bool = False) -> None:
        self.phrase_mwe = phrase_mwe
        self.phrase_calls = 0
        self.atomic_calls = 0

    def analyze_stream_pair(
        self, text: str, *, disambiguate: bool = False
    ) -> tuple[str, str | None]:
        self.phrase_calls += 1
        if self.phrase_mwe:
            stream = "^екі сөз/екі<num>+сөз<n><nom>$"
        else:
            stream = "^Сәлем/сәлем<n><nom>$"
        return stream, stream if disambiguate else None

    def analyze_atomic_stream_pair(
        self,
        text: str,
        boundaries: tuple[tuple[int, int], ...],
        *,
        disambiguate: bool = False,
    ) -> tuple[str, str | None]:
        self.atomic_calls += 1
        if not self.phrase_mwe:
            raise AssertionError("exact ordinary phrase partition must be reused")
        self.boundaries = boundaries
        stream = "^екі/екі<num>$ ^сөз/сөз<n><nom>$"
        return stream, stream if disambiguate else None


class _CrossingAtomicBackend(_CountingBackend):
    def __init__(self) -> None:
        super().__init__(phrase_mwe=True)

    def analyze_atomic_stream_pair(
        self,
        text: str,
        boundaries: tuple[tuple[int, int], ...],
        *,
        disambiguate: bool = False,
    ) -> tuple[str, str | None]:
        self.atomic_calls += 1
        # Simulate a broken -z backend that ignored fences and returned one
        # cohort crossing all three predetermined atomic intervals.
        stream = "^екі сөз/екі<num>+сөз<n><nom>$"
        return stream, stream if disambiguate else None


class _NumericBackend:
    resource_version = "test"

    def analyze_stream_pair(
        self, text: str, *, disambiguate: bool = False
    ) -> tuple[str, str | None]:
        stream = "^1991/1991<num>$"
        return stream, stream if disambiguate else None

    def analyze_atomic_stream_pair(
        self,
        text: str,
        boundaries: tuple[tuple[int, int], ...],
        *,
        disambiguate: bool = False,
    ) -> tuple[str, str | None]:
        raise AssertionError("the exact numeric partition must be reused")

class AnalyzerFallbackTests(unittest.TestCase):
    @staticmethod
    def analyzer_for(backend: object, *, disambiguate: bool = False) -> Analyzer:
        analyzer = Analyzer.__new__(Analyzer)
        analyzer.backend = backend
        analyzer.default_disambiguate = disambiguate
        analyzer.use_guesser = True
        analyzer.guess_limit = 8
        analyzer.guesser = _NoGuess()
        analyzer.fixlist = {}
        analyzer.neural_ranker = None
        analyzer.ud_profile = "universal"
        return analyzer

    def test_missing_exact_atomic_cg_interval_falls_back_to_lattice(self) -> None:
        analyzer = self.analyzer_for(_SplitCgBackend(), disambiguate=True)

        document = analyzer.analyze("сөз", disambiguate=True)
        self.assertEqual(analyzer.backend.boundaries, ((0, 3),))
        self.assertEqual([analysis.raw for analysis in document.tokens[0].analyses], ["сөз<n><nom>"])
        self.assertEqual(document.tokens[0].analyses[0].source, "lexicon")

    def test_exact_phrase_partition_reuses_the_single_backend_pass(self) -> None:
        backend = _CountingBackend()
        analyzer = self.analyzer_for(backend)

        document = analyzer.analyze("Сәлем")

        self.assertEqual(backend.phrase_calls, 1)
        self.assertEqual(backend.atomic_calls, 0)
        self.assertEqual([token.text for token in document.tokens], ["Сәлем"])
        self.assertEqual(document.analysis_spans, ())

    def test_changed_mwe_partition_uses_atomic_pass_and_retains_span(self) -> None:
        backend = _CountingBackend(phrase_mwe=True)
        analyzer = self.analyzer_for(backend)

        document = analyzer.analyze("екі сөз")

        self.assertEqual(backend.phrase_calls, 1)
        self.assertEqual(backend.atomic_calls, 1)
        self.assertEqual(backend.boundaries, ((0, 3), (3, 4), (4, 7)))
        self.assertEqual([token.text for token in document.tokens], ["екі", " ", "сөз"])
        self.assertEqual([span.text for span in document.analysis_spans], ["екі сөз"])

    def test_interval_indexing_reads_aligned_cohorts_linearly(self) -> None:
        class CountingSegments:
            def __init__(self, values: list[_AlignedSegment]) -> None:
                self.values = values
                self.reads = 0

            def __len__(self) -> int:
                return len(self.values)

            def __getitem__(self, index: int) -> _AlignedSegment:
                self.reads += 1
                return self.values[index]

        count = 2_000
        intervals = tuple((index, index + 1) for index in range(count))
        segments = CountingSegments(
            [
                _AlignedSegment(RawSegment("а", ("а<n>",)), index, index + 1)
                for index in range(count)
            ]
        )

        indexed = Analyzer._raw_by_interval(intervals, segments)

        self.assertEqual(len(indexed), count)
        self.assertTrue(all(exact for _raw, _sent, exact in indexed))
        self.assertLess(segments.reads, count * 6)

    def test_atomic_cohort_crossing_a_fence_is_fatal_not_guessed(self) -> None:
        analyzer = self.analyzer_for(_CrossingAtomicBackend())

        with self.assertRaisesRegex(BackendError, "crosses an atomic token boundary"):
            analyzer.analyze("екі сөз")

    def test_plain_gap_coalesced_across_fences_is_split_exactly(self) -> None:
        intervals = ((0, 1), (1, 2), (2, 4))
        coalesced = [_AlignedSegment(RawSegment("_\n  "), 0, 4)]

        repaired = Analyzer._split_plain_segments_at_intervals(
            intervals, coalesced
        )
        indexed = Analyzer._raw_by_interval(intervals, repaired)

        self.assertEqual(
            [(item.segment.text, item.start, item.end) for item in repaired],
            [("_", 0, 1), ("\n", 1, 2), ("  ", 2, 4)],
        )
        self.assertTrue(all(exact for _raw, _sent, exact in indexed))

    def test_invalid_ud_profile_is_rejected_before_resource_discovery(self) -> None:
        with self.assertRaisesRegex(ValueError, "unknown UD projection profile"):
            Analyzer(ud_profile="legacy")

    def test_neural_and_cg_init_is_rejected_before_backend_or_ranker_construction(self) -> None:
        with mock.patch("qazmorph.analyzer.FSTBackend") as backend, mock.patch(
            "qazmorph.neural.StanzaCandidateRanker"
        ) as ranker:
            with self.assertRaisesRegex(ValueError, "mutually exclusive"):
                Analyzer(disambiguate=True, neural=True)

        backend.assert_not_called()
        ranker.assert_not_called()

    def test_neural_analyzer_rejects_per_call_cg_before_backend_work(self) -> None:
        backend = _CountingBackend()
        analyzer = self.analyzer_for(backend)
        ranker = mock.Mock()
        analyzer.neural_ranker = ranker

        with self.assertRaisesRegex(ValueError, "mutually exclusive"):
            analyzer.analyze("Сәлем", disambiguate=True)

        self.assertEqual(backend.phrase_calls, 0)
        self.assertEqual(backend.atomic_calls, 0)
        ranker.rerank.assert_not_called()

    def test_cg_abstains_when_one_raw_reading_has_projection_alternatives(self) -> None:
        analyzer = self.analyzer_for(_NumericBackend(), disambiguate=True)

        token = analyzer.analyze("1991", disambiguate=True).tokens[0]

        self.assertEqual(
            [analysis.feature_map for analysis in token.analyses],
            [{"NumType": "Card"}, {"NumType": "Ord"}],
        )
        self.assertIsNone(token.selected)
        self.assertIsNone(token.chosen)


class ProjectionAlternativeTests(unittest.TestCase):
    @staticmethod
    def analyzer_for(*, ud_profile: str = "universal") -> Analyzer:
        analyzer = Analyzer.__new__(Analyzer)
        analyzer.fixlist = {}
        analyzer.ud_profile = ud_profile
        return analyzer

    def test_universal_decimal_alias_is_appended_after_complete_fst_prefix(self) -> None:
        analyzer = self.analyzer_for()
        raw = ("1991<num>", "1991<num><subst><nom>")

        analyses = analyzer._raw_analyses("1991", raw, preserve_backend=False)

        self.assertEqual([analysis.raw for analysis in analyses[:2]], list(raw))
        self.assertTrue(all(analysis.source == "lexicon" for analysis in analyses[:2]))
        self.assertEqual(
            [analysis.feature_map for analysis in analyses[2:]],
            [
                {"NumType": "Ord"},
                {"Case": "Nom", "NumType": "Ord"},
            ],
        )
        for analysis in analyses[2:]:
            self.assertEqual(analysis.source, "rule")
            self.assertFalse(analysis.guessed)
            self.assertIn(analysis.raw, raw)
            self.assertEqual(analysis.upos, analysis.morphemes[0].upos)
            self.assertEqual(analysis.features, analysis.morphemes[0].features)
        self.assertIsNone(
            Analyzer._contextual_span_selection(analyses, ("1991<num>",))
        )

    def test_phrase_span_mode_remains_the_exact_backend_sequence(self) -> None:
        analyzer = self.analyzer_for()
        raw = (
            "жақсы<adj><subst><nom>+сөз<n><nom>",
            "жақсы<adj><advl>+сөйле<v><iv><imp><p2><sg>",
        )

        analyses = analyzer._raw_analyses(
            "жақсы сөз", raw, preserve_backend=True
        )

        self.assertEqual([analysis.raw for analysis in analyses], list(raw))
        self.assertTrue(all(analysis.source == "lexicon" for analysis in analyses))

    def test_ktb_decimal_aliases_have_deterministic_per_reading_order(self) -> None:
        analyzer = self.analyzer_for(ud_profile="ktb")
        analyses = analyzer._raw_analyses(
            "7", ("7<num>", "7<num><subst><nom>"), preserve_backend=False
        )

        self.assertEqual(
            [(analysis.raw, analysis.feature_map) for analysis in analyses],
            [
                ("7<num>", {"NumType": "Card"}),
                ("7<num><subst><nom>", {"Case": "Nom", "NumType": "Card"}),
                ("7<num>", {"NumType": "Ord"}),
                ("7<num>", {"NumType": "Card,Ord"}),
                ("7<num><subst><nom>", {"Case": "Nom", "NumType": "Ord"}),
                (
                    "7<num><subst><nom>",
                    {"Case": "Nom", "NumType": "Card,Ord"},
                ),
            ],
        )
        self.assertEqual(len({analysis.identity for analysis in analyses}), len(analyses))

    def test_semantic_aliases_never_decorate_guessed_or_unmatched_numerals(self) -> None:
        analyzer = self.analyzer_for(ud_profile="ktb")
        self.assertEqual(
            analyzer._raw_analyses("00", ("*00",), preserve_backend=False), []
        )
        guessed = parse_analysis("00<num><unk>", guessed=True)
        self.assertIsNotNone(guessed)
        assert guessed is not None
        # The public helper boundary is enforced by _raw_analyses: a backend
        # <unk> reading remains the sole base-analyzer hypothesis.
        analyses = analyzer._raw_analyses(
            "00", ("00<num><unk>",), preserve_backend=False
        )
        self.assertEqual(len(analyses), 1)
        self.assertTrue(analyses[0].guessed)
        self.assertEqual(analyses[0].source, "lexicon")

    def test_nonbare_or_explicit_numerals_do_not_gain_semantic_aliases(self) -> None:
        analyzer = self.analyzer_for(ud_profile="ktb")
        cases = {
            "1.5": ("1.5<num>",),
            "51%": ("51<num><percent><nom>",),
            "бірінші": ("бір<num><ord>",),
        }
        for surface, raw in cases.items():
            with self.subTest(surface=surface):
                analyses = analyzer._raw_analyses(
                    surface, raw, preserve_backend=False
                )
                self.assertEqual(len(analyses), 1)
                self.assertEqual(analyses[0].source, "lexicon")

    def test_raw_usage_aliases_are_additive_and_structurally_consistent(self) -> None:
        analyzer = self.analyzer_for()
        cases = {
            ("жақсылар", "жақсы<adj><subst><pl><nom>"): "NOUN",
            ("үйдегі", "үй<n><loc><attr>"): "ADJ",
            ("жақсырақ", "жақсы<adj><comp><advl>"): "ADV",
        }
        for (surface, raw), expected_upos in cases.items():
            with self.subTest(raw=raw):
                analyses = analyzer._raw_analyses(
                    surface, (raw,), preserve_backend=False
                )
                self.assertEqual(len(analyses), 2)
                original, alias = analyses
                self.assertEqual(original.source, "lexicon")
                self.assertEqual(alias.source, "rule")
                self.assertFalse(alias.guessed)
                self.assertEqual(alias.raw, original.raw)
                self.assertEqual(alias.tags, original.tags)
                self.assertEqual(alias.features, original.features)
                self.assertEqual(alias.upos, expected_upos)
                self.assertEqual(alias.upos, alias.morphemes[0].upos)
                self.assertEqual(alias.features, alias.morphemes[0].features)

    def test_raw_pronoun_and_determiner_readings_are_not_swapped(self) -> None:
        analyzer = self.analyzer_for(ud_profile="ktb")
        for surface, raw in (
            ("бұл", "бұл<prn><dem><nom>"),
            ("әр", "әр<det><qnt>"),
        ):
            with self.subTest(raw=raw):
                analyses = analyzer._raw_analyses(
                    surface, (raw,), preserve_backend=False
                )
                self.assertEqual(len(analyses), 1)
                self.assertEqual(analyses[0].source, "lexicon")


if __name__ == "__main__":
    unittest.main()
