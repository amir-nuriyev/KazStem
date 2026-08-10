from __future__ import annotations

import os
import json
from pathlib import Path
import random
import tempfile
import unittest
import unicodedata

from qazmorph import Analyzer
from qazmorph.stream import parse_analysis, parse_apertium_stream


RESOURCE_DIR = os.environ.get("QAZMORPH_RESOURCE_DIR")


def mixed_unicode_fuzz_text() -> str:
    rng = random.Random(20260810)
    letters = (
        "абвгғдеёжзийкқлмнңоөпрстуұүфхһцчшщъыіьэюя"
        "ӘҒҚҢӨҰҮҺІABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    )
    punctuation = "[]{}^$/\\<>@#*+_-.,!?;:'\"()%&=|~`"
    parts: list[str] = []
    for _ in range(2_500):
        kind = rng.randrange(6)
        if kind == 0:
            parts.append(
                "".join(rng.choice(letters) for _ in range(rng.randint(1, 18)))
            )
        elif kind == 1:
            parts.append(
                "-".join(
                    "".join(rng.choice(letters) for _ in range(rng.randint(1, 6)))
                    for _ in range(rng.randint(2, 6))
                )
            )
        elif kind == 2:
            parts.append(
                "".join(rng.choice(punctuation) for _ in range(rng.randint(1, 8)))
            )
        elif kind == 3:
            parts.append(rng.choice((" ", "  ", "\t", "\n", "\r\n")))
        elif kind == 4:
            parts.append(rng.choice(("и\u0306", "е\u0308", "А\u0308", "ә\u0301")))
        else:
            parts.append(
                rng.choice(
                    ("C++", "[Қазақстан]", "^сөз$", "Има-а-а", "а-а", "foo\\bar")
                )
            )
    return "".join(parts)


@unittest.skipUnless(
    RESOURCE_DIR,
    "resource-backed integration tests run only when QAZMORPH_RESOURCE_DIR is set",
)
class ResourceIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        assert RESOURCE_DIR is not None
        cls.resource_dir = Path(RESOURCE_DIR)
        cls.analyzer = Analyzer(resource_dir=cls.resource_dir, guess=False)

    def test_manifest_version_and_resource_path_are_exposed(self) -> None:
        self.assertEqual(self.analyzer.backend.resource_dir, self.resource_dir.resolve())
        self.assertIsInstance(self.analyzer.backend.resource_version, str)
        self.assertTrue(self.analyzer.backend.resource_version)

    def test_common_greeting_has_a_dictionary_analysis(self) -> None:
        document = self.analyzer.analyze("Сәлем")
        self.assertEqual(document.text, "Сәлем")
        self.assertEqual(document.mode, "lattice")
        self.assertEqual(len(document.tokens), 1)
        token = document.tokens[0]
        self.assertEqual((token.text, token.start, token.end, token.kind), ("Сәлем", 0, 5, "word"))
        self.assertTrue(token.is_dictionary_word)
        self.assertTrue(any(analysis.lemma == "сәлем" for analysis in token.analyses))
        self.assertTrue(all(analysis.raw for analysis in token.analyses))

    def assert_atomic_partition(self, text: str) -> None:
        document = self.analyzer.analyze(text)
        self.assertEqual("".join(token.text for token in document.tokens), text)
        cursor = 0
        for token in document.tokens:
            self.assertEqual(token.start, cursor)
            self.assertEqual(token.text, text[token.start : token.end])
            if token.kind == "space":
                self.assertTrue(token.text.isspace())
            else:
                self.assertFalse(any(character.isspace() for character in token.text))
            cursor = token.end
        self.assertEqual(cursor, len(text))

    def test_geographical_name_preserves_proper_noun_projection(self) -> None:
        document = self.analyzer.analyze("Қазақстан")
        token = document.tokens[0]
        candidates = [analysis for analysis in token.analyses if analysis.upos == "PROPN"]
        self.assertTrue(candidates)
        self.assertTrue(any(a.feature_map.get("NameType") == "Geo" for a in candidates))
        self.assertTrue(any(a.lemma == "Қазақстан" for a in candidates))

    def test_ktb_profile_is_opt_in_and_recorded_without_changing_raw_tags(self) -> None:
        with Analyzer(
            resource_dir=self.resource_dir,
            guess=False,
            ud_profile="ktb",
        ) as analyzer:
            document = analyzer.analyze("Қазақстан")
        self.assertEqual(document.ud_profile, "ktb")
        candidates = [a for a in document.tokens[0].analyses if "top" in a.tags]
        self.assertTrue(candidates)
        self.assertTrue(all("NameType" not in a.feature_map for a in candidates))

    def test_unknown_ascii_word_receives_lossless_fallback(self) -> None:
        document = self.analyzer.analyze("qazmorphzzzz")
        token = document.tokens[0]
        self.assertEqual(token.text, "qazmorphzzzz")
        self.assertEqual((token.start, token.end), (0, 12))
        self.assertTrue(token.analyses)
        self.assertTrue(all(analysis.guessed for analysis in token.analyses))
        self.assertTrue(any(analysis.upos == "X" for analysis in token.analyses))

    def test_uncovered_numerals_receive_a_cardinal_analysis(self) -> None:
        for text in ("00", "١٢٣", "１２３", "Ⅻ"):
            with self.subTest(text=text):
                token = self.analyzer.analyze(text).tokens[0]
                self.assertEqual(token.kind, "number")
                self.assertTrue(token.analyses)
                self.assertEqual(token.analyses[0].upos, "NUM")
                self.assertEqual(token.analyses[0].feature_map, {"NumType": "Card"})
                self.assertEqual(token.analyses[0].source, "rule")
                self.assertTrue(token.analyses[0].guessed)
                self.assertFalse(
                    any(
                        analysis.feature_map.get("NumType") in {"Ord", "Card,Ord"}
                        for analysis in token.analyses
                    )
                )

    def test_compiled_decimal_gets_additive_profiled_semantic_aliases(self) -> None:
        universal = self.analyzer.analyze("1991").tokens[0]
        self.assertEqual(
            [(analysis.raw, analysis.source) for analysis in universal.analyses[:2]],
            [
                ("1991<num>", "lexicon"),
                ("1991<num><subst><nom>", "lexicon"),
            ],
        )
        self.assertEqual(
            [
                analysis.feature_map
                for analysis in universal.analyses
                if analysis.source == "rule"
            ],
            [
                {"NumType": "Ord"},
                {"Case": "Nom", "NumType": "Ord"},
            ],
        )
        self.assertTrue(universal.is_dictionary_word)
        self.assertTrue(
            all(not analysis.guessed for analysis in universal.analyses)
        )

        with Analyzer(
            resource_dir=self.resource_dir,
            guess=False,
            ud_profile="ktb",
        ) as analyzer:
            ktb = analyzer.analyze("1991").tokens[0]
        self.assertEqual(
            [
                analysis.feature_map
                for analysis in ktb.analyses
                if analysis.source == "rule"
            ],
            [
                {"NumType": "Ord"},
                {"NumType": "Card,Ord"},
                {"Case": "Nom", "NumType": "Ord"},
                {"Case": "Nom", "NumType": "Card,Ord"},
            ],
        )

    def test_contextual_decimal_abstains_between_shared_raw_semantics(self) -> None:
        token = self.analyzer.analyze("1991", disambiguate=True).tokens[0]
        self.assertEqual(
            [analysis.feature_map for analysis in token.analyses],
            [{"NumType": "Card"}, {"NumType": "Ord"}],
        )
        self.assertIsNone(token.selected)

    def test_compiled_usage_tags_gain_only_the_explicit_upos_aliases(self) -> None:
        cases = {
            "жақсылар": ("жақсы<adj><subst><pl><nom>", "NOUN"),
            "үйдегі": ("үй<n><loc><attr>", "ADJ"),
            "жақсырақ": ("жақсы<adj><comp><advl>", "ADV"),
        }
        for surface, (raw, expected_upos) in cases.items():
            with self.subTest(surface=surface):
                token = self.analyzer.analyze(surface).tokens[0]
                originals = [
                    analysis
                    for analysis in token.analyses
                    if analysis.raw == raw and analysis.source == "lexicon"
                ]
                aliases = [
                    analysis
                    for analysis in token.analyses
                    if analysis.raw == raw and analysis.source == "rule"
                ]
                self.assertEqual(len(originals), 1)
                self.assertEqual(len(aliases), 1)
                self.assertEqual(aliases[0].upos, expected_upos)
                self.assertEqual(aliases[0].features, originals[0].features)
                self.assertFalse(aliases[0].guessed)

    def test_analysed_decimal_is_classified_as_a_number(self) -> None:
        token = self.analyzer.analyze("1.5").tokens[0]
        self.assertEqual(token.kind, "number")
        self.assertTrue(all(analysis.upos == "NUM" for analysis in token.analyses))

    def test_percent_numeral_keeps_its_dictionary_licensed_reading(self) -> None:
        cases = {"51%": "nom", "51%-дан": "abl", "51%-ға": "dat"}
        for contextual in (False, True):
            for text, expected_case in cases.items():
                with self.subTest(contextual=contextual, text=text):
                    document = self.analyzer.analyze(text, disambiguate=contextual)
                    self.assertEqual(len(document.tokens), 1)
                    token = document.tokens[0]
                    self.assertEqual((token.text, token.kind), (text, "number"))
                    self.assertTrue(
                        any(
                            "percent" in analysis.tags
                            and expected_case in analysis.tags
                            for analysis in token.analyses
                        )
                    )

    def test_synthetic_reserved_characters_have_rule_provenance(self) -> None:
        document = self.analyzer.analyze("[+]")
        self.assertTrue(document.tokens)
        for token in document.tokens:
            self.assertTrue(token.analyses)
            self.assertTrue(all(a.source == "rule" for a in token.analyses))

    def test_generation_round_trip_when_generator_is_installed(self) -> None:
        generator = self.resource_dir / "kaz.autogen.hfstol"
        if not generator.is_file() or not self.analyzer.backend.hfst_optimized_lookup:
            self.skipTest("resource bundle has no generator runtime")
        forms = self.analyzer.generate("сөз", ("n", "nom"))
        self.assertIn("сөз", forms)
        round_trip = self.analyzer.analyze("сөз")
        self.assertTrue(any(a.lemma == "сөз" for a in round_trip.tokens[0].analyses))

    def test_generated_multiword_reading_round_trips_as_a_span(self) -> None:
        generator = self.resource_dir / "kaz.autogen.hfstol"
        if not generator.is_file() or not self.analyzer.backend.hfst_optimized_lookup:
            self.skipTest("resource bundle has no generator runtime")
        tags = ("v", "iv", "aor", "p3", "sg")
        forms = self.analyzer.generate("болып табыл", tags)
        self.assertIn("болып табылады", forms)
        document = self.analyzer.analyze("болып табылады")
        self.assertTrue(
            any(
                analysis.raw == "болып табыл<v><iv><aor><p3><sg>"
                for span in document.analysis_spans
                for analysis in span.analyses
            )
        )

    def test_generator_excludes_analysis_only_long_instrumental(self) -> None:
        generator = self.resource_dir / "kaz.autogen.hfstol"
        if not generator.is_file() or not self.analyzer.backend.hfst_optimized_lookup:
            self.skipTest("resource bundle has no generator runtime")
        forms = self.analyzer.generate("ине", ("n", "ins"))
        self.assertIn("инемен", forms)
        self.assertNotIn("инеменен", forms)

    def test_lossy_ud_projection_does_not_collapse_raw_readings(self) -> None:
        readings = self.analyzer.analyze("Оқу").tokens[0].analyses
        raw = {analysis.raw for analysis in readings}
        self.assertIn("оқу<n><attr>", raw)
        self.assertIn("оқу<n><nom>", raw)

    def test_reserved_stream_syntax_is_lossless_and_covered(self) -> None:
        text = "[Қазақстан] ^сөз$ \\ C++ {қазақ}"
        for contextual in (False, True):
            with self.subTest(contextual=contextual):
                document = self.analyzer.analyze(text, disambiguate=contextual)
                self.assertEqual("".join(token.text for token in document.tokens), text)
                self.assertEqual(document.tokens[0].start, 0)
                self.assertEqual(document.tokens[-1].end, len(text))
                for left, right in zip(document.tokens, document.tokens[1:]):
                    self.assertEqual(left.end, right.start)
                letter_tokens = [token for token in document.tokens if token.kind == "word"]
                self.assertTrue(letter_tokens)
                self.assertTrue(all(token.analyses for token in letter_tokens))

    def test_repeated_hyphenated_unknown_is_never_consumed_by_tokenizer(self) -> None:
        text = "Има-а-а! йа-а және Сан-Себрия-де-Вальяльта"
        for contextual in (False, True):
            with self.subTest(contextual=contextual):
                document = self.analyzer.analyze(text, disambiguate=contextual)
                self.assertEqual("".join(token.text for token in document.tokens), text)
                self.assertEqual(document.tokens[0].start, 0)
                self.assertEqual(document.tokens[-1].end, len(text))
                for left, right in zip(document.tokens, document.tokens[1:]):
                    self.assertEqual(left.end, right.start)
                visible = [token.text for token in document.tokens]
                self.assertIn("Има-а-а", visible)
                self.assertIn("йа-а", visible)
                self.assertIn("Сан-Себрия-де-Вальяльта", visible)

    def test_known_hyphenated_dictionary_form_remains_one_analysis_token(self) -> None:
        cases = {
            "а-а": "а-а<ij>",
            "сөз-ау": "сөз<n><nom>+ау<mod_emo>",
            "азық-түлік": "азық-түлік<n><attr>",
        }
        for text, raw in cases.items():
            with self.subTest(text=text):
                token = self.analyzer.analyze(text).tokens[0]
                self.assertEqual(token.text, text)
                self.assertTrue(any(analysis.raw == raw for analysis in token.analyses))

    def test_unknown_internal_hyphen_is_one_atom_but_dash_punctuation_is_not(self) -> None:
        document = self.analyzer.analyze("құрал-жабдық сөз—сөз ӘЧ-")
        self.assert_atomic_partition(document.text)
        visible = [token.text for token in document.tokens if token.kind != "space"]
        self.assertIn("құрал-жабдық", visible)
        dash = visible.index("—")
        self.assertEqual(visible[dash - 1 : dash + 2], ["сөз", "—", "сөз"])
        self.assertEqual(visible[-2:], ["ӘЧ", "-"])

    def test_suffix_a_after_start_punctuation_or_symbol_is_lossless(self) -> None:
        for text in ("-а", "№-а", "!-а"):
            for contextual in (False, True):
                with self.subTest(text=text, contextual=contextual):
                    document = self.analyzer.analyze(text, disambiguate=contextual)
                    self.assertEqual("".join(token.text for token in document.tokens), text)
                    self.assertEqual(document.tokens[0].start, 0)
                    self.assertEqual(document.tokens[-1].end, len(text))

    def test_abbreviation_periods_never_create_whitespace_forms(self) -> None:
        for text in ("млрд.", "мм.", "Сөз."):
            with self.subTest(text=text):
                document = self.analyzer.analyze(text)
                self.assertEqual("".join(token.text for token in document.tokens), text)
                self.assertTrue(
                    all(
                        token.kind == "space"
                        or not any(character.isspace() for character in token.text)
                        for token in document.tokens
                    )
                )
        sentence = self.analyzer.analyze("Сөз.")
        self.assertEqual([token.text for token in sentence.tokens], ["Сөз", "."])

    def test_multiword_fst_units_become_atomic_tokens_plus_lossless_spans(self) -> None:
        cases = {
            "жоқ қой": "joined",
            "болып табылады": "single",
            "ауыл шаруашылығы": "mixed",
            "шығып кетеді де": "three",
            "он екі елі ішек": "four",
        }
        for text, expected in cases.items():
            with self.subTest(text=text, expected=expected):
                document = self.analyzer.analyze(text)
                self.assertEqual("".join(token.text for token in document.tokens), text)
                self.assertTrue(
                    all(
                        token.kind == "space"
                        or not any(character.isspace() for character in token.text)
                        for token in document.tokens
                    )
                )
                span = next(item for item in document.analysis_spans if item.text == text)
                self.assertEqual(
                    "".join(
                        token.text
                        for token in document.tokens[span.token_start : span.token_end]
                    ),
                    text,
                )
                self.assertTrue(span.analyses)
                if expected == "joined":
                    self.assertTrue(all(len(a.morphemes) > 1 for a in span.analyses))
                elif expected == "single":
                    self.assertTrue(all(len(a.morphemes) == 1 for a in span.analyses))
                elif expected == "mixed":
                    sizes = {len(a.morphemes) for a in span.analyses}
                    self.assertIn(1, sizes)
                    self.assertTrue(any(size > 1 for size in sizes))

    def test_phrase_span_preserves_backend_raw_order_and_contextual_selection(self) -> None:
        text = "жоқ қой"
        raw_stream = self.analyzer.backend.analyze_stream(text, disambiguate=False)
        backend_unit = next(
            segment for segment in parse_apertium_stream(raw_stream) if segment.text == text
        )
        expected = tuple(
            raw for raw in backend_unit.analyses if parse_analysis(raw) is not None
        )
        lattice = self.analyzer.analyze(text)
        lattice_span = next(span for span in lattice.analysis_spans if span.text == text)
        self.assertEqual(tuple(a.raw for a in lattice_span.analyses), expected)

        if self.analyzer.backend.cg_proc and self.analyzer.backend.grammar_path.is_file():
            contextual = self.analyzer.analyze(text, disambiguate=True)
            contextual_span = next(span for span in contextual.analysis_spans if span.text == text)
            self.assertEqual(tuple(a.raw for a in contextual_span.analyses), expected)
            if contextual_span.chosen is not None:
                self.assertIn(contextual_span.chosen.raw, expected)

    def test_fixlist_overrides_atomic_token_but_appends_to_phrase_span(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "fixlist.jsonl"
            rows = [
                {"form": "жоқ", "lemma": "атом", "tags": ["n", "nom"]},
                {"form": "жоқ қой", "lemma": "тіркес", "tags": ["n", "nom"]},
            ]
            path.write_text(
                "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows),
                encoding="utf-8",
            )
            with Analyzer(
                resource_dir=self.resource_dir,
                guess=False,
                fixlist=path,
            ) as analyzer:
                document = analyzer.analyze("жоқ қой")

        first = document.tokens[0]
        self.assertEqual([analysis.source for analysis in first.analyses], ["fixlist"])
        self.assertEqual(first.analyses[0].lemma, "атом")
        span = next(item for item in document.analysis_spans if item.text == "жоқ қой")
        self.assertTrue(span.analyses)
        self.assertTrue(all(a.source == "lexicon" for a in span.analyses[:-1]))
        self.assertEqual((span.analyses[-1].source, span.analyses[-1].lemma), ("fixlist", "тіркес"))

    def test_atomic_partition_handles_all_whitespace_nul_and_unicode_boundaries(self) -> None:
        texts = (
            "жоқ\tқой",
            "жоқ  қой",
            "жоқ\nқой",
            "жоқ\u00a0қой",
            "и\u0306 жоқ қой",
            "가\u11a8 жоқ қой",
            "бір\x00екі",
            "и\u0306 \u0301",
        )
        for text in texts:
            with self.subTest(text=repr(text)):
                self.assert_atomic_partition(text)

    def test_uppercase_unknown_hyphenated_heading_is_lossless(self) -> None:
        text = "ЖАҚ-БЕТ БӨЛІМІ\nҚабылдау"
        document = self.analyzer.analyze(text)
        self.assertEqual("".join(token.text for token in document.tokens), text)

    def test_unknown_generation_does_not_echo_the_lexical_query(self) -> None:
        generator = self.resource_dir / "kaz.autogen.hfstol"
        if not generator.is_file() or not self.analyzer.backend.hfst_optimized_lookup:
            self.skipTest("resource bundle has no generator runtime")
        self.assertEqual(self.analyzer.generate("мүлдемжоқлемма", ("n", "nom")), [])

    def test_deterministic_mixed_unicode_fuzz_is_lossless(self) -> None:
        text = mixed_unicode_fuzz_text()
        document = self.analyzer.analyze(text)
        self.assertEqual("".join(token.text for token in document.tokens), text)
        self.assertEqual(document.tokens[0].start, 0)
        self.assertEqual(document.tokens[-1].end, len(text))
        for left, right in zip(document.tokens, document.tokens[1:]):
            self.assertEqual(left.end, right.start)

    def test_decomposed_unicode_retains_original_surface_offsets(self) -> None:
        text = "и\u0306"
        document = self.analyzer.analyze(text)
        self.assertEqual(document.text, text)
        self.assertEqual(document.normalized_text, "й")
        self.assertEqual(len(document.tokens), 1)
        self.assertEqual(document.tokens[0].text, text)
        self.assertEqual((document.tokens[0].start, document.tokens[0].end), (0, 2))
        self.assertEqual(document.tokens[0].normalized, "й")

    def test_combining_mark_after_space_never_creates_an_empty_token(self) -> None:
        text = "и\u0306 \u0301"
        document = self.analyzer.analyze(text)
        self.assertEqual("".join(token.text for token in document.tokens), text)
        self.assertTrue(all(token.text for token in document.tokens))
        for token in document.tokens:
            expected = token.normalized if token.normalized is not None else token.text
            self.assertEqual(unicodedata.normalize("NFC", token.text), expected)

    def test_contextual_mode_selects_at_most_one_candidate_per_token(self) -> None:
        if not self.analyzer.backend.cg_proc or not self.analyzer.backend.grammar_path.is_file():
            self.skipTest("resource bundle has no Constraint Grammar runtime")
        document = self.analyzer.analyze("Сәлем, Қазақстан!", disambiguate=True)
        self.assertEqual(document.mode, "contextual")
        for token in document.tokens:
            if token.analyses:
                if len(token.analyses) == 1:
                    self.assertIsNotNone(token.chosen)
                if token.chosen is not None:
                    self.assertEqual(token.selected, 0)


if __name__ == "__main__":
    unittest.main()
