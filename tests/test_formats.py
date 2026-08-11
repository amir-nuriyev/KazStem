from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
import tempfile
import unittest
from xml.etree import ElementTree
from xml.sax.saxutils import escape as sax_escape
from xml.sax.saxutils import quoteattr as sax_quoteattr

from qazmorph.fixlist import load_fixlist
from qazmorph.formats import (
    XMLFormatError,
    _escape_xml_text,
    _quote_xml_attribute,
    format_conllu,
    format_jsonl,
    format_mystem_json,
    format_text,
    format_xml,
    visible_analyses,
)
from qazmorph.types import Analysis, AnalysisSpan, Document, Morpheme, Token


def make_analysis(
    lemma: str,
    upos: str,
    *,
    features: tuple[tuple[str, str], ...] = (),
    tags: tuple[str, ...] = (),
    raw: str | None = None,
    source: str = "lexicon",
    score: float = 1.0,
    guessed: bool = False,
    morphemes: tuple[Morpheme, ...] | None = None,
) -> Analysis:
    if morphemes is None:
        morphemes = (Morpheme(lemma, tags, upos, features),)
    return Analysis(
        lemma=lemma,
        upos=upos,
        features=features,
        tags=tags,
        morphemes=morphemes,
        raw=raw or lemma + "".join(f"<{tag}>" for tag in tags),
        source=source,
        score=score,
        guessed=guessed,
    )


def sample_document() -> Document:
    noun = make_analysis(
        "сәлем",
        "NOUN",
        features=(("Case", "Nom"),),
        tags=("n", "nom"),
        score=0.75,
    )
    interjection = make_analysis(
        "сәлем", "INTJ", tags=("ij",), score=0.25
    )
    tokens = [
        Token("Сәлем", 0, 5, "word", [noun, interjection], selected=0),
        Token(" ", 5, 6, "space"),
        Token("!", 6, 7, "punct", sentence_end=True),
    ]
    return Document("Сәлем !", tokens, "contextual", "test")


class VisibilityTests(unittest.TestCase):
    def test_filters_match_raw_tags_upos_and_ud_feature_strings(self) -> None:
        token = sample_document().tokens[0]
        self.assertEqual(
            visible_analyses(token, frozenset({"NOUN", "Case=Nom", "nom"}), False),
            [token.analyses[0]],
        )
        self.assertEqual(
            visible_analyses(token, frozenset({"INTJ", "ij"}), False),
            [token.analyses[1]],
        )
        self.assertEqual(visible_analyses(token, frozenset({"VERB"}), False), [])

    def test_dictionary_only_excludes_guessed_analyses(self) -> None:
        dictionary = make_analysis("сөз", "NOUN", tags=("n",))
        guessed = make_analysis(
            "сөз", "NOUN", tags=("n", "unk"), source="guesser", guessed=True
        )
        token = Token("сөз", 0, 3, "word", [guessed, dictionary])
        self.assertEqual(visible_analyses(token, frozenset(), True), [dictionary])

    def test_dictionary_only_keeps_alias_of_a_licensed_reading_not_oov_rule(self) -> None:
        licensed = make_analysis(
            "7", "NUM", features=(("NumType", "Card"),), tags=("num",)
        )
        alias = replace(
            licensed,
            features=(("NumType", "Ord"),),
            morphemes=(
                replace(
                    licensed.morphemes[0], features=(("NumType", "Ord"),)
                ),
            ),
            source="rule",
            guessed=False,
        )
        oov_rule = make_analysis(
            "00",
            "NUM",
            features=(("NumType", "Card"),),
            tags=("num",),
            source="rule",
            guessed=True,
        )

        licensed_token = Token("7", 0, 1, "number", [licensed, alias])
        oov_token = Token("00", 0, 2, "number", [oov_rule])

        self.assertEqual(
            visible_analyses(licensed_token, frozenset(), True), [licensed, alias]
        )
        self.assertEqual(visible_analyses(oov_token, frozenset(), True), [])

    def test_filters_accept_lexical_and_contextual_projections(self) -> None:
        lexical = make_analysis(
            "бол", "VERB", features=(("VerbForm", "Fin"),), tags=("v",)
        )
        contextual = replace(
            lexical,
            context_upos="AUX",
            context_features=(("Mood", "Ind"),),
        )
        token = Token("болды", 0, 5, "word", [contextual], selected=0)
        self.assertEqual(
            visible_analyses(token, frozenset({"AUX", "Mood=Ind"}), False),
            [contextual],
        )
        self.assertEqual(
            visible_analyses(token, frozenset({"VERB", "VerbForm=Fin"}), False),
            [contextual],
        )


class TextFormatterTests(unittest.TestCase):
    def test_default_text_output_emits_only_lexical_tokens(self) -> None:
        self.assertEqual(
            format_text(sample_document()),
            "Сәлем{сәлем}",
        )

    def test_copy_input_preserves_spaces_and_punctuation(self) -> None:
        self.assertEqual(
            format_text(sample_document(), copy_input=True),
            "Сәлем{сәлем} !",
        )

    def test_lemmas_grammar_and_weights_are_independently_selectable(self) -> None:
        document = sample_document()
        self.assertEqual(
            format_text(
                document,
                lemmas_only=True,
                gram_info=True,
                weights=True,
            ),
            "сәлем:0.750000=NOUN,Case=Nom|сәлем:0.250000=INTJ",
        )

    def test_merge_combines_same_lemma_grammars_and_sums_scores(self) -> None:
        self.assertEqual(
            format_text(
                sample_document(),
                lemmas_only=True,
                gram_info=True,
                weights=True,
                merge=True,
            ),
            "сәлем:1.000000=(NOUN,Case=Nom|INTJ)",
        )

    def test_merged_lemma_is_guessed_only_when_every_member_is_guessed(self) -> None:
        guessed_noun = make_analysis("foo", "NOUN", guessed=True, score=0.4)
        guessed_verb = make_analysis("foo", "VERB", guessed=True, score=0.6)
        mixed = make_analysis("bar", "NOUN", guessed=True, score=0.5)
        known = make_analysis("bar", "PROPN", guessed=False, score=0.5)
        document = Document(
            "foo bar",
            [
                Token("foo", 0, 3, "word", [guessed_noun, guessed_verb]),
                Token(" ", 3, 4, "space"),
                Token("bar", 4, 7, "word", [mixed, known]),
            ],
            "lattice",
            "test",
        )
        self.assertEqual(
            format_text(document, lemmas_only=True, merge=True),
            "foo?bar",
        )

    def test_newline_mode_escapes_gap_characters(self) -> None:
        known = make_analysis("сөз", "NOUN")
        document = Document(
            "сөз _\n",
            [
                Token("сөз", 0, 3, "word", [known]),
                Token(" ", 3, 4, "space"),
                Token("_", 4, 5, "symbol"),
                Token("\n", 5, 6, "space"),
            ],
            "lattice",
            "test",
        )
        self.assertEqual(
            format_text(document, copy_input=True, newline=True),
            "сөз{сөз}\n_\n\\_\n\\n\n",
        )

    def test_sentence_markers_follow_sentence_ending_tokens(self) -> None:
        self.assertEqual(
            format_text(
                sample_document(), copy_input=True, sentence_markers=True
            ),
            "Сәлем{сәлем} !{\\s}",
        )

    def test_physical_line_endings_survive_without_copy_mode(self) -> None:
        known = make_analysis("сөз", "NOUN")
        document = Document(
            "сөз \nсөз",
            [
                Token("сөз", 0, 3, "word", [known]),
                Token(" \n", 3, 5, "space"),
                Token("сөз", 5, 8, "word", [known]),
            ],
            "lattice",
            "test",
        )
        self.assertEqual(format_text(document), "сөз{сөз}\nсөз{сөз}")
        self.assertEqual(
            format_text(document, newline=True),
            "сөз{сөз}\nсөз{сөз}\n",
        )

    def test_dictionary_only_and_filters_apply_before_rendering(self) -> None:
        guessed = make_analysis("foo", "NOUN", tags=("n", "unk"), guessed=True)
        known = make_analysis("foo", "VERB", tags=("v", "imp"))
        token = Token("foo", 0, 3, "word", [guessed, known])
        document = Document("foo", [token], "lattice", "test")
        self.assertEqual(
            format_text(document, dictionary_only=True, filters=frozenset({"VERB"})),
            "foo{foo}",
        )
        self.assertEqual(
            format_text(document, dictionary_only=True, filters=frozenset({"NOUN"})),
            "",
        )


class JsonlFormatterTests(unittest.TestCase):
    def test_jsonl_preserves_unicode_offsets_candidates_and_selection(self) -> None:
        output = format_jsonl(sample_document())
        self.assertTrue(output.endswith("\n"))
        rows = [json.loads(line) for line in output.splitlines()]
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row["schema_version"], "qazmorph.jsonl-record.v2")
        self.assertEqual(row["record_type"], "token")
        self.assertIs(row["consumes_input"], True)
        self.assertEqual(row["mode"], "contextual")
        self.assertEqual(row["resource_version"], "test")
        self.assertEqual(row["ud_profile"], "universal")
        self.assertIsNone(row["normalized"])
        self.assertEqual(row["text"], "Сәлем")
        self.assertEqual((row["start"], row["end"]), (0, 5))
        self.assertEqual(row["kind"], "word")
        self.assertEqual(row["selected"], 0)
        self.assertEqual(len(row["analysis"]), 2)
        self.assertEqual(row["analysis"][0]["lex"], "сәлем")
        self.assertEqual(row["analysis"][0]["gr"], "NOUN,Case=Nom")
        self.assertIsNone(row["analysis"][0]["qual"])

    def test_jsonl_copy_input_includes_spaces_and_punctuation(self) -> None:
        rows = [
            json.loads(line)
            for line in format_jsonl(sample_document(), copy_input=True).splitlines()
        ]
        self.assertEqual([row["kind"] for row in rows], ["word", "space", "punct"])
        self.assertEqual(rows[1]["analysis"], [])
        self.assertTrue(rows[2]["sentence_end"])

    def test_jsonl_marks_guessed_analysis(self) -> None:
        guessed = make_analysis(
            "foobar", "PROPN", tags=("np", "unk"), guessed=True
        )
        document = Document(
            "Foobar", [Token("Foobar", 0, 6, "word", [guessed])], "lattice", "test"
        )
        row = json.loads(format_jsonl(document))
        self.assertEqual(row["analysis"][0]["qual"], "guessed")

    def test_filtered_selection_is_remapped_to_visible_candidate_index(self) -> None:
        noun, interjection = sample_document().tokens[0].analyses
        token = Token("Сәлем", 0, 5, "word", [noun, interjection], selected=1)
        document = Document("Сәлем", [token], "contextual", "test")
        row = json.loads(format_jsonl(document, filters=frozenset({"INTJ"})))
        self.assertEqual(row["selected"], 0)

    def test_dictionary_only_omits_tokens_without_visible_dictionary_analysis(self) -> None:
        guessed = make_analysis("foo", "NOUN", guessed=True)
        document = Document(
            "foo", [Token("foo", 0, 3, "word", [guessed])], "lattice", "test"
        )
        self.assertEqual(format_jsonl(document, dictionary_only=True), "")

    def test_copy_and_dictionary_only_still_preserve_nonlexical_records(self) -> None:
        guessed = make_analysis("foo", "NOUN", guessed=True)
        document = Document(
            "foo !",
            [
                Token("foo", 0, 3, "word", [guessed]),
                Token(" ", 3, 4, "space"),
                Token("!", 4, 5, "punct", sentence_end=True),
            ],
            "lattice",
            "test",
        )
        rows = [
            json.loads(line)
            for line in format_jsonl(
                document,
                copy_input=True,
                dictionary_only=True,
            ).splitlines()
        ]
        self.assertEqual([row["text"] for row in rows], [" ", "!"])

    def test_jsonl_tokens_reconstruct_once_and_span_retains_full_lattice(self) -> None:
        first = make_analysis("жоқ", "ADJ", raw="жоқ<adj>")
        particle = make_analysis("ғой", "PART", raw="ғой<mod_ass>")
        phrase = make_analysis(
            "жоқ",
            "ADJ",
            raw="жоқ<adj>+ғой<mod_ass>",
            morphemes=(first.morphemes[0], particle.morphemes[0]),
        )
        document = Document(
            "жоқ қой",
            [
                Token("жоқ", 0, 3, "word", [first], selected=0),
                Token(" ", 3, 4, "space"),
                Token("қой", 4, 7, "word", [particle], selected=0),
            ],
            "contextual",
            "test",
            analysis_spans=(
                AnalysisSpan("жоқ қой", 0, 7, 0, 3, (phrase,), selected=0),
            ),
        )
        rows = [
            json.loads(line)
            for line in format_jsonl(document, copy_input=True).splitlines()
        ]
        token_rows = [row for row in rows if row["record_type"] == "token"]
        span_rows = [row for row in rows if row["record_type"] == "analysis_span"]
        self.assertEqual("".join(row["text"] for row in token_rows), document.text)
        self.assertTrue(all(row["consumes_input"] for row in token_rows))
        self.assertEqual(len(span_rows), 1)
        self.assertIs(span_rows[0]["consumes_input"], False)
        self.assertEqual(
            (span_rows[0]["token_start"], span_rows[0]["token_end"]),
            (0, 3),
        )
        self.assertEqual(span_rows[0]["analysis"][0]["raw"], phrase.raw)

    def test_jsonl_filters_and_dictionary_only_apply_to_spans_independently(self) -> None:
        guessed = make_analysis("тосын", "NOUN", guessed=True, source="guesser")
        known = make_analysis("тосын", "VERB", raw="тосын<v>")
        document = Document(
            "тосын сөз",
            [
                Token("тосын", 0, 5, "word", [guessed]),
                Token(" ", 5, 6, "space"),
                Token("сөз", 6, 9, "word", [known]),
            ],
            "lattice",
            "test",
            analysis_spans=(
                AnalysisSpan("тосын сөз", 0, 9, 0, 3, (guessed, known)),
            ),
        )
        rows = [
            json.loads(line)
            for line in format_jsonl(
                document,
                copy_input=True,
                dictionary_only=True,
                filters=frozenset({"VERB"}),
            ).splitlines()
        ]
        span = next(row for row in rows if row["record_type"] == "analysis_span")
        self.assertEqual([analysis["raw"] for analysis in span["analysis"]], ["тосын<v>"])
        self.assertIsNone(span["selected"])


class MyStemJsonFormatterTests(unittest.TestCase):
    def test_compatibility_json_uses_only_public_mystem_record_fields(self) -> None:
        rows = json.loads(
            format_mystem_json(
                sample_document(),
                copy_input=True,
                gram_info=True,
                weights=True,
            )
        )
        self.assertEqual([row["text"] for row in rows], ["Сәлем", " ", "!"])
        self.assertEqual(set(rows[0]), {"text", "analysis"})
        self.assertEqual(
            rows[0]["analysis"][0],
            {"lex": "сәлем", "gr": "NOUN,Case=Nom", "wt": 0.75},
        )
        self.assertEqual(rows[1], {"text": " "})

    def test_compatibility_json_uses_bastard_and_honors_i_g_weight(self) -> None:
        guessed_noun = make_analysis("foo", "NOUN", guessed=True, score=0.4)
        guessed_verb = make_analysis("foo", "VERB", guessed=True, score=0.6)
        document = Document(
            "foo",
            [Token("foo", 0, 3, "word", [guessed_noun, guessed_verb])],
            "lattice",
            "test",
        )
        plain = json.loads(format_mystem_json(document))[0]["analysis"]
        self.assertEqual(plain, [{"lex": "foo", "qual": "bastard"}])
        merged = json.loads(
            format_mystem_json(
                document,
                gram_info=True,
                merge=True,
                weights=True,
            )
        )[0]["analysis"]
        self.assertEqual(
            merged,
            [
                {
                    "lex": "foo",
                    "wt": 1.0,
                    "qual": "bastard",
                    "gr": "(NOUN|VERB)",
                }
            ],
        )

    def test_compatibility_json_uses_mystem_serialized_field_order(self) -> None:
        analysis = make_analysis("foo", "NOUN", guessed=True, score=0.4)
        document = Document(
            "foo", [Token("foo", 0, 3, "word", [analysis])], "lattice", "test"
        )
        self.assertEqual(
            format_mystem_json(
                document,
                gram_info=True,
                weights=True,
            ),
            '[{"analysis":[{"lex":"foo","wt":0.4,"qual":"bastard","gr":"NOUN"}],"text":"foo"}]\n',
        )

    def test_newline_mode_emits_one_mystem_object_per_line(self) -> None:
        lines = format_mystem_json(
            sample_document(),
            copy_input=True,
            newline=True,
        ).splitlines()
        self.assertEqual(len(lines), 3)
        self.assertEqual(json.loads(lines[0])["text"], "Сәлем")
        self.assertEqual(json.loads(lines[1]), {"text": " "})


class MyStemProjectionDeduplicationTests(unittest.TestCase):
    def setUp(self) -> None:
        features = (("Case", "Nom"), ("Number", "Plur"))
        self.analyses = [
            make_analysis(
                "кітап",
                "NOUN",
                features=features,
                tags=("n", "pl", "nom"),
                raw="кітап<n><pl><nom>",
            ),
            make_analysis(
                "кітап",
                "NOUN",
                features=features,
                tags=("n", "pl", "nom"),
                raw="кітап<n><nom><pl>",
            ),
            make_analysis(
                "кітап",
                "NOUN",
                features=features,
                tags=("n", "pl", "nom"),
                raw="кітап<n><pl><nom><attr>",
            ),
        ]
        self.document = Document(
            "кітаптар",
            [Token("кітаптар", 0, 8, "word", self.analyses)],
            "lattice",
            "test",
        )

    def test_lossy_mystem_formats_stably_deduplicate_projected_rows(self) -> None:
        expected = "кітап=NOUN,Case=Nom,Number=Plur"
        self.assertEqual(format_text(self.document, gram_info=True), f"кітаптар{{{expected}}}")

        json_rows = json.loads(
            format_mystem_json(self.document, gram_info=True)
        )
        self.assertEqual(
            json_rows[0]["analysis"],
            [{"lex": "кітап", "gr": "NOUN,Case=Nom,Number=Plur"}],
        )

        xml_word = ElementTree.fromstring(
            format_xml(self.document).encode("utf-8")
        ).find("./body/se/w")
        self.assertIsNotNone(xml_word)
        assert xml_word is not None
        self.assertEqual(len(xml_word.findall("ana")), 1)

    def test_rich_jsonl_retains_every_distinct_raw_reading(self) -> None:
        row = json.loads(format_jsonl(self.document).splitlines()[0])
        self.assertEqual(
            [analysis["raw"] for analysis in row["analysis"]],
            [analysis.raw for analysis in self.analyses],
        )

    def test_visible_weight_or_qualifier_differences_are_not_collapsed(self) -> None:
        weighted = Document(
            "foo",
            [
                Token(
                    "foo",
                    0,
                    3,
                    "word",
                    [
                        make_analysis("foo", "NOUN", raw="foo<n><a>", score=0.4),
                        make_analysis("foo", "NOUN", raw="foo<n><b>", score=0.6),
                        make_analysis(
                            "foo",
                            "NOUN",
                            raw="foo<n><c>",
                            score=0.4,
                            guessed=True,
                        ),
                    ],
                )
            ],
            "lattice",
            "test",
        )
        rows = json.loads(
            format_mystem_json(weighted, gram_info=True, weights=True)
        )[0]["analysis"]
        self.assertEqual(len(rows), 3)
        self.assertEqual([row.get("wt") for row in rows], [0.4, 0.6, 0.4])
        self.assertNotIn("qual", rows[0])
        self.assertEqual(rows[2]["qual"], "bastard")


class XmlFormatterTests(unittest.TestCase):
    def test_local_xml_escaping_matches_the_prior_stdlib_behavior(self) -> None:
        values = (
            "",
            "plain ASCII",
            "қазақша 😀",
            "&<>",
            "single'quote",
            'double"quote',
            'both\'"quotes',
            "line\ncarriage\rtab\tend",
            "&amp; is input text, not a pre-escaped entity",
        )
        for value in values:
            with self.subTest(value=value):
                self.assertEqual(_escape_xml_text(value), sax_escape(value))
                self.assertEqual(
                    _quote_xml_attribute(value),
                    sax_quoteattr(value),
                )

    def test_xml_escapes_text_and_attributes_and_is_well_formed_shape(self) -> None:
        analysis = make_analysis('a&"b', "NOUN", score=0.5)
        document = Document(
            "<&>",
            [
                Token("<", 0, 1, "punct"),
                Token("&", 1, 2, "word", [analysis]),
                Token(">", 2, 3, "punct", sentence_end=True),
            ],
            "lattice",
            "test",
        )
        output = format_xml(document)
        self.assertTrue(output.startswith('<?xml version="1.0" encoding="UTF-8"?>'))
        self.assertIn("&lt;<w>", output)
        self.assertIn('lex=\'a&amp;"b\'', output)
        self.assertIn('gr="NOUN"', output)
        self.assertIn(
            '<w><ana lex=\'a&amp;"b\' gr="NOUN" />&amp;</w>',
            output,
        )
        self.assertNotIn("wt=", output)
        self.assertNotIn("</se><se>", output)
        self.assertTrue(output.endswith("</se></body></html>\n"))
        ElementTree.fromstring(output.encode("utf-8"))

    def test_xml_emits_analyses_before_surface_like_mystem(self) -> None:
        analyses = [
            make_analysis("кітап", "NOUN"),
            make_analysis("кітапта", "VERB", guessed=True),
        ]
        document = Document(
            "кітап", [Token("кітап", 0, 5, "word", analyses)], "lattice", "test"
        )
        output = format_xml(document)
        word = ElementTree.fromstring(output.encode("utf-8")).find("./body/se/w")
        self.assertIsNotNone(word)
        assert word is not None
        self.assertIsNone(word.text)
        self.assertEqual([child.tag for child in word], ["ana", "ana"])
        self.assertEqual(word[-1].tail, "кітап")

    def test_xml_exposes_guessed_qualifier(self) -> None:
        guessed = make_analysis("foo", "NOUN", guessed=True)
        document = Document(
            "foo", [Token("foo", 0, 3, "word", [guessed])], "lattice", "test"
        )
        self.assertIn('qual="bastard"', format_xml(document))

    def test_xml_uses_mystem_analysis_attribute_order(self) -> None:
        guessed = make_analysis("foo", "NOUN", guessed=True, score=0.4)
        document = Document(
            "foo", [Token("foo", 0, 3, "word", [guessed])], "lattice", "test"
        )
        self.assertIn(
            '<ana lex="foo" wt="0.4" qual="bastard" gr="NOUN" />foo',
            format_xml(document, weights=True),
        )

    def test_xml_can_omit_nonlexical_input(self) -> None:
        output = format_xml(sample_document(), copy_input=False)
        self.assertNotIn(" !", output)
        self.assertNotIn("</se><se>", output)

    def test_xml_honors_grammar_weight_merge_and_sentence_flags(self) -> None:
        document = sample_document()
        output = format_xml(
            document,
            copy_input=True,
            gram_info=False,
            weights=True,
        )
        self.assertNotIn(" gr=", output)
        self.assertIn('wt="0.75"', output)

        two_sentences = Document(
            "Сәлем ! Сәлем",
            [
                *document.tokens,
                Token(" ", 7, 8, "space"),
                Token("Сәлем", 8, 13, "word", document.tokens[0].analyses),
            ],
            "lattice",
            "test",
        )
        split = format_xml(
            two_sentences,
            copy_input=True,
            sentence_markers=True,
        )
        self.assertEqual(split.count("<se>"), 2)
        self.assertEqual(split.count("</se>"), 2)

    def test_xml_accepts_only_the_xml_10_character_repertoire(self) -> None:
        forbidden = tuple(
            codepoint
            for codepoint in range(0x20)
            if codepoint not in {0x09, 0x0A, 0x0D}
        ) + (
            0xD800,  # first surrogate
            0xDFFF,  # last surrogate
            0xFFFE,
            0xFFFF,
        )
        for codepoint in forbidden:
            character = chr(codepoint)
            kind = "space" if character.isspace() else "symbol"
            document = Document(
                character,
                [Token(character, 0, 1, kind)],
                "lattice",
                "test",
            )
            with self.subTest(codepoint=f"U+{codepoint:04X}"), self.assertRaisesRegex(
                XMLFormatError,
                f"U\\+{codepoint:04X}",
            ):
                format_xml(document, copy_input=True)

        allowed_controls = "\t\n\r"
        allowed = Document(
            allowed_controls,
            [Token(allowed_controls, 0, len(allowed_controls), "space")],
            "lattice",
            "test",
        )
        ElementTree.fromstring(
            format_xml(allowed, copy_input=True).encode("utf-8")
        )

    def test_xml_validates_every_emitted_analysis_attribute(self) -> None:
        invalid_analyses = (
            make_analysis("bad\x00lemma", "NOUN"),
            make_analysis("lemma", "NOUN\x01"),
            make_analysis(
                "lemma",
                "NOUN",
                features=(("Case", "Nom\ud800"),),
            ),
        )
        for analysis in invalid_analyses:
            document = Document(
                "сөз",
                [Token("сөз", 0, 3, "word", [analysis])],
                "lattice",
                "test",
            )
            with self.subTest(raw=repr(analysis.raw)), self.assertRaisesRegex(
                XMLFormatError,
                "XML 1.0-forbidden code point",
            ):
                format_xml(document)

        with self.assertRaisesRegex(XMLFormatError, "declaration encoding"):
            format_xml(sample_document(), encoding="UTF-8\x00")

    def test_xml_rejects_an_unrepresentable_fixlist_lemma(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "fixlist.jsonl"
            path.write_text(
                json.dumps(
                    {"form": "сөз", "lemma": "bad\x00lemma", "tags": ["n"]},
                    ensure_ascii=True,
                )
                + "\n",
                encoding="utf-8",
            )
            analysis = load_fixlist(path)["сөз"][0]

        document = Document(
            "сөз",
            [Token("сөз", 0, 3, "word", [analysis])],
            "lattice",
            "test",
        )
        with self.assertRaisesRegex(XMLFormatError, "analysis lex.*U\\+0000"):
            format_xml(document)

    def test_non_xml_formats_retain_xml_forbidden_input_losslessly(self) -> None:
        document = Document(
            "\x00",
            [Token("\x00", 0, 1, "symbol")],
            "lattice",
            "test",
        )
        self.assertEqual(format_text(document, copy_input=True), "\x00")
        self.assertEqual(
            json.loads(format_mystem_json(document, copy_input=True)),
            [{"text": "\x00"}],
        )
        self.assertEqual(
            json.loads(format_jsonl(document, copy_input=True))["text"],
            "\x00",
        )

        # Validation is applied to values that the selected XML view emits. An
        # omitted nonlexical gap does not make the otherwise empty XML invalid.
        ElementTree.fromstring(format_xml(document, copy_input=False).encode("utf-8"))


class ConlluFormatterTests(unittest.TestCase):
    def test_conllu_uses_selection_features_offsets_and_candidate_count(self) -> None:
        output = format_conllu(sample_document())
        self.assertTrue(
            output.endswith("\n\n"),
            "CoNLL-U sentences must be terminated by a blank line",
        )
        lines = output.rstrip("\n").splitlines()
        self.assertEqual(
            lines[0],
            "1\tСәлем\tсәлем\tNOUN\t_\tCase=Nom\t_\t_\t_\t"
            "StartChar=0|EndChar=5|Candidates=2",
        )
        self.assertEqual(
            lines[1],
            "2\t!\t_\tPUNCT\t_\t_\t_\t_\t_\tStartChar=6|EndChar=7",
        )

    def test_conllu_falls_back_to_x_and_marks_guesses(self) -> None:
        guessed = make_analysis("foobar", "X", guessed=True)
        document = Document(
            "Foobar №",
            [
                Token("Foobar", 0, 6, "word", [guessed]),
                Token(" ", 6, 7, "space"),
                Token("№", 7, 8, "symbol"),
            ],
            "lattice",
            "test",
        )
        lines = format_conllu(document).splitlines()
        self.assertIn("Guess=Yes", lines[0])
        self.assertEqual(lines[1].split("\t")[2:6], ["_", "X", "_", "_"])

    def test_dictionary_only_retains_nonlexical_rule_tokens(self) -> None:
        rule = make_analysis("+", "SYM", source="rule", guessed=True)
        document = Document(
            "+",
            [Token("+", 0, 1, "symbol", [rule])],
            "lattice",
            "test",
        )
        row = format_conllu(document, dictionary_only=True).splitlines()[0]
        self.assertEqual(row.split("\t")[1:4], ["+", "_", "X"])

    def test_sentence_end_resets_token_ids(self) -> None:
        noun = make_analysis("бір", "NOUN")
        second = make_analysis("екі", "NUM")
        document = Document(
            "бір! екі",
            [
                Token("бір", 0, 3, "word", [noun]),
                Token("!", 3, 4, "punct", sentence_end=True),
                Token(" ", 4, 5, "space"),
                Token("екі", 5, 8, "word", [second]),
            ],
            "lattice",
            "test",
        )
        ids = [line.split("\t", 1)[0] for line in format_conllu(document).splitlines() if line]
        self.assertEqual(ids, ["1", "2", "1"])

    def test_conllu_uses_only_atomic_forms_when_phrase_spans_exist(self) -> None:
        word = make_analysis("сөз", "NOUN")
        phrase = make_analysis("екі сөз", "NOUN", raw="екі сөз<n>")
        document = Document(
            "екі сөз",
            [
                Token("екі", 0, 3, "word", [word]),
                Token(" ", 3, 4, "space"),
                Token("сөз", 4, 7, "word", [word]),
            ],
            "lattice",
            "test",
            analysis_spans=(AnalysisSpan("екі сөз", 0, 7, 0, 3, (phrase,)),),
        )
        forms = [line.split("\t")[1] for line in format_conllu(document).splitlines() if line]
        self.assertEqual(forms, ["екі", "сөз"])
        self.assertTrue(all(not any(char.isspace() for char in form) for form in forms))

    def test_fused_segments_remain_available_in_json_even_if_conllu_is_flat(self) -> None:
        morphemes = (
            Morpheme("кедергі", ("n",), "NOUN", ()),
            Morpheme("сыз", ("post",), "ADP", ()),
        )
        analysis = make_analysis(
            "кедергі",
            "NOUN",
            tags=("n", "post"),
            raw="кедергі<n>+сыз<post>",
            morphemes=morphemes,
        )
        document = Document(
            "кедергісіз",
            [Token("кедергісіз", 0, 10, "word", [analysis])],
            "lattice",
            "test",
        )
        row = json.loads(format_jsonl(document))
        self.assertEqual(
            [(part["lemma"], part["upos"]) for part in row["analysis"][0]["morphemes"]],
            [("кедергі", "NOUN"), ("сыз", "ADP")],
        )

    @unittest.skip(
        "TODO: emit CoNLL-U MWT rows after morpheme surface spans are represented"
    )
    def test_fused_visible_segments_export_as_a_multiword_token(self) -> None:
        self.fail("surface spans are required to distinguish visible and zero-surface segments")


if __name__ == "__main__":
    unittest.main()
