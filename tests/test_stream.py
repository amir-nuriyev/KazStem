from __future__ import annotations

import unittest

from qazmorph.stream import RawSegment, parse_analysis, parse_apertium_stream


class ApertiumStreamTests(unittest.TestCase):
    def test_gaps_surfaces_and_all_readings_are_preserved(self) -> None:
        stream = (
            "Алдында "
            "^Сәлем/сәлем<ij>/сәлем<n><nom>/сәлем<ij>+е<cop><aor><p3><sg>$"
            " соңында"
        )
        segments = parse_apertium_stream(stream)
        self.assertEqual(
            segments,
            [
                RawSegment("Алдында "),
                RawSegment(
                    "Сәлем",
                    (
                        "сәлем<ij>",
                        "сәлем<n><nom>",
                        "сәлем<ij>+е<cop><aor><p3><sg>",
                    ),
                ),
                RawSegment(" соңында"),
            ],
        )

    def test_unescaped_slashes_separate_readings_only_inside_a_unit(self) -> None:
        segments = parse_apertium_stream("outside/slash ^x/x<n>/x<ij>$")
        self.assertEqual(segments[0], RawSegment("outside/slash "))
        self.assertEqual(segments[1].text, "x")
        self.assertEqual(segments[1].analyses, ("x<n>", "x<ij>"))

    def test_escaped_reserved_characters_remain_literal(self) -> None:
        segments = parse_apertium_stream(
            r"left \^caret ^a\/b\$/a\/b\$<n><nom>$ right \$dollar"
        )
        self.assertEqual(segments[0], RawSegment("left ^caret "))
        self.assertEqual(segments[1].text, "a/b$")
        self.assertEqual(len(segments[1].analyses), 1)
        analysis = parse_analysis(segments[1].analyses[0])
        self.assertIsNotNone(analysis)
        assert analysis is not None
        self.assertEqual(analysis.lemma, "a/b$")
        self.assertEqual(analysis.tags, ("n", "nom"))
        self.assertEqual(segments[2], RawSegment(" right $dollar"))

    def test_unterminated_lexical_unit_is_retained_as_plain_text(self) -> None:
        self.assertEqual(
            parse_apertium_stream("prefix ^unterminated<n>"),
            [RawSegment("prefix "), RawSegment("^unterminated<n>")],
        )

    def test_empty_reading_fields_are_not_reported_as_analyses(self) -> None:
        self.assertEqual(
            parse_apertium_stream("^word//word<n>/$"),
            [RawSegment("word", ("word<n>",))],
        )

    def test_empty_stream_returns_no_segments(self) -> None:
        self.assertEqual(parse_apertium_stream(""), [])

    def test_backend_sentence_boundary_units_are_preserved_for_alignment(self) -> None:
        segments = parse_apertium_stream("^?/?<sent>$^./.<sent>$")
        self.assertEqual(
            segments,
            [RawSegment("?", ("?<sent>",)), RawSegment(".", (".<sent>",))],
        )


class AnalysisParserTests(unittest.TestCase):
    def test_readme_style_ambiguity_preserves_each_reading(self) -> None:
        raw_readings = parse_apertium_stream(
            "^Сәлем/сәлем<ij>/сәлем<n><nom>/сәлем<ij>+е<cop><aor><p3><sg>$"
        )[0].analyses
        analyses = [parse_analysis(raw) for raw in raw_readings]
        self.assertTrue(all(analysis is not None for analysis in analyses))
        first, second, third = analyses
        assert first is not None and second is not None and third is not None

        self.assertEqual((first.lemma, first.upos), ("сәлем", "INTJ"))
        self.assertEqual((second.lemma, second.upos), ("сәлем", "NOUN"))
        self.assertEqual(dict(second.features), {"Case": "Nom"})
        self.assertEqual(len(third.morphemes), 2)
        self.assertEqual(third.morphemes[0].upos, "INTJ")
        self.assertEqual(third.morphemes[1].upos, "AUX")
        self.assertNotIn("Tense", third.feature_map)
        self.assertEqual(dict(third.morphemes[1].features)["Tense"], "Pres")

    def test_visible_joined_segments_have_independent_ud_projection(self) -> None:
        analysis = parse_analysis("бақша<n><loc>+ма<qst>")
        self.assertIsNotNone(analysis)
        assert analysis is not None
        self.assertEqual([m.lemma for m in analysis.morphemes], ["бақша", "ма"])
        self.assertEqual([m.upos for m in analysis.morphemes], ["NOUN", "PART"])
        self.assertEqual(dict(analysis.morphemes[0].features), {"Case": "Loc"})
        self.assertEqual(dict(analysis.morphemes[1].features), {"PartType": "Int"})

    def test_fused_noun_and_postposition_remain_two_segments(self) -> None:
        analysis = parse_analysis("кедергі<n>+сыз<post>")
        self.assertIsNotNone(analysis)
        assert analysis is not None
        self.assertEqual(
            [(m.lemma, m.upos) for m in analysis.morphemes],
            [("кедергі", "NOUN"), ("сыз", "ADP")],
        )

    def test_zero_surface_copula_features_do_not_leak_to_noun(self) -> None:
        analysis = parse_analysis("келісімшарт<n><nom>+е<cop><aor><p3><sg>")
        self.assertIsNotNone(analysis)
        assert analysis is not None
        self.assertEqual(analysis.upos, "NOUN")
        self.assertEqual(analysis.feature_map, {"Case": "Nom"})
        self.assertEqual(len(analysis.morphemes), 2)
        copula = analysis.morphemes[1]
        self.assertEqual(copula.upos, "AUX")
        self.assertEqual(dict(copula.features)["VerbForm"], "Fin")
        self.assertEqual(dict(copula.features)["Person"], "3")

    def test_escaped_plus_is_lemma_text_not_a_segment_boundary(self) -> None:
        segment = parse_apertium_stream(r"^C\+\+/C\+\+<abbr>$")[0]
        self.assertEqual(segment.text, "C++")
        self.assertEqual(len(segment.analyses), 1)
        analysis = parse_analysis(segment.analyses[0])
        self.assertIsNotNone(analysis)
        assert analysis is not None
        self.assertEqual(analysis.lemma, "C++")
        self.assertEqual(len(analysis.morphemes), 1)
        self.assertEqual(analysis.upos, "NOUN")
        self.assertEqual(analysis.feature_map, {"Abbr": "Yes"})

    def test_spaces_inside_surface_and_lemma_do_not_split_a_reading(self) -> None:
        segment = parse_apertium_stream(
            "^жүзеге асыру/жүзеге асыр<v><tv><ger><nom>$"
        )[0]
        self.assertEqual(segment.text, "жүзеге асыру")
        analysis = parse_analysis(segment.analyses[0])
        self.assertIsNotNone(analysis)
        assert analysis is not None
        self.assertEqual(analysis.lemma, "жүзеге асыр")
        self.assertEqual(len(analysis.morphemes), 1)
        self.assertEqual(analysis.upos, "VERB")
        self.assertEqual(analysis.feature_map["VerbForm"], "Ger")

    def test_guessed_proper_noun_is_not_an_unmatched_reading(self) -> None:
        analysis = parse_analysis("Foobar<np><unk>")
        self.assertIsNotNone(analysis)
        assert analysis is not None
        self.assertEqual(analysis.lemma, "Foobar")
        self.assertEqual(analysis.upos, "PROPN")
        self.assertTrue(analysis.guessed)
        self.assertEqual(analysis.source, "lexicon")
        self.assertEqual(analysis.feature_map["Foreign"], "Yes")

    def test_uppercase_abbreviation_lemma_is_not_normalized(self) -> None:
        analysis = parse_analysis("БҰҰ<abbr>")
        self.assertIsNotNone(analysis)
        assert analysis is not None
        self.assertEqual(analysis.lemma, "БҰҰ")
        self.assertEqual(analysis.upos, "NOUN")
        self.assertEqual(analysis.feature_map, {"Abbr": "Yes"})

    def test_ktb_profile_is_applied_to_every_morpheme_projection(self) -> None:
        analysis = parse_analysis(
            "Алматы<np><top><nom>+е<cop><ifi_evid><p3><sg>",
            ud_profile="ktb",
        )
        self.assertIsNotNone(analysis)
        assert analysis is not None
        self.assertNotIn("NameType", analysis.feature_map)
        self.assertNotIn("NameType", dict(analysis.morphemes[0].features))
        self.assertEqual(
            dict(analysis.morphemes[1].features)["Evident"], "Fh"
        )

    def test_explicit_guessed_argument_marks_a_regular_reading(self) -> None:
        analysis = parse_analysis("сөз<n><nom>", source="guesser", guessed=True)
        self.assertIsNotNone(analysis)
        assert analysis is not None
        self.assertTrue(analysis.guessed)
        self.assertEqual(analysis.source, "guesser")

    def test_unmatched_and_failed_lookup_readings_return_none(self) -> None:
        for raw in ("", "*foobar", "foobar+?"):
            with self.subTest(raw=raw):
                self.assertIsNone(parse_analysis(raw))

    def test_invalid_ud_profile_is_rejected_even_for_an_empty_reading(self) -> None:
        with self.assertRaisesRegex(ValueError, "unknown UD projection profile"):
            parse_analysis("", ud_profile="legacy")

    def test_percent_numeral_is_not_punctuation(self) -> None:
        analysis = parse_analysis("51<num><percent><nom>")
        self.assertIsNotNone(analysis)
        assert analysis is not None
        self.assertEqual(analysis.upos, "NUM")
        self.assertEqual(analysis.feature_map["NumType"], "Card")

    def test_unknown_tags_and_ordered_raw_tags_are_retained(self) -> None:
        raw = "сөз<n><future_tag><loc>"
        analysis = parse_analysis(raw)
        self.assertIsNotNone(analysis)
        assert analysis is not None
        self.assertEqual(analysis.raw, raw)
        self.assertEqual(analysis.tags, ("n", "future_tag", "loc"))
        self.assertEqual(analysis.morphemes[0].tags, analysis.tags)
        self.assertEqual(analysis.feature_map, {"Case": "Loc"})

    def test_orthographic_variant_is_exposed(self) -> None:
        analysis = parse_analysis("қате<n><err_orth><nom>")
        self.assertIsNotNone(analysis)
        assert analysis is not None
        self.assertTrue(analysis.orthographic_variant)
        self.assertEqual(analysis.feature_map["Typo"], "Yes")

    def test_plain_untagged_reading_is_losslessly_represented_as_x(self) -> None:
        analysis = parse_analysis("opaque")
        self.assertIsNotNone(analysis)
        assert analysis is not None
        self.assertEqual(analysis.lemma, "opaque")
        self.assertEqual(analysis.upos, "X")
        self.assertEqual(analysis.tags, ())
        self.assertEqual(analysis.raw, "opaque")


if __name__ == "__main__":
    unittest.main()
