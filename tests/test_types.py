from __future__ import annotations

from dataclasses import FrozenInstanceError
import unittest

from qazmorph.types import Analysis, AnalysisSpan, Document, Morpheme, Token


def make_analysis(
    lemma: str = "сөз",
    *,
    upos: str = "NOUN",
    features: tuple[tuple[str, str], ...] = (("Case", "Nom"),),
    tags: tuple[str, ...] = ("n", "nom"),
    raw: str = "сөз<n><nom>",
    source: str = "lexicon",
    score: float = 0.75,
    guessed: bool = False,
    orthographic_variant: bool = False,
) -> Analysis:
    morpheme = Morpheme(lemma=lemma, tags=tags, upos=upos, features=features)
    return Analysis(
        lemma=lemma,
        upos=upos,
        features=features,
        tags=tags,
        morphemes=(morpheme,),
        raw=raw,
        source=source,
        score=score,
        guessed=guessed,
        orthographic_variant=orthographic_variant,
    )


class MorphemeTests(unittest.TestCase):
    def test_as_dict_uses_json_friendly_collections(self) -> None:
        morpheme = Morpheme(
            lemma="Қазақстан",
            tags=("np", "top", "gen"),
            upos="PROPN",
            features=(("Case", "Gen"), ("NameType", "Geo")),
        )
        self.assertEqual(
            morpheme.as_dict(),
            {
                "lemma": "Қазақстан",
                "tags": ["np", "top", "gen"],
                "upos": "PROPN",
                "features": {"Case": "Gen", "NameType": "Geo"},
            },
        )

    def test_morpheme_is_immutable(self) -> None:
        morpheme = Morpheme("сөз", ("n",))
        with self.assertRaises(FrozenInstanceError):
            morpheme.lemma = "өзгерді"  # type: ignore[misc]


class AnalysisTests(unittest.TestCase):
    def test_feature_map_is_a_fresh_mutable_projection(self) -> None:
        analysis = make_analysis()
        projection = analysis.feature_map
        projection["Case"] = "Dat"
        self.assertEqual(analysis.feature_map, {"Case": "Nom"})

    def test_signature_is_casefolded_and_ignores_score_and_provenance(self) -> None:
        first = make_analysis(lemma="СӨЗ", score=0.1, source="lexicon")
        second = make_analysis(lemma="сөз", score=0.9, source="fixlist")
        self.assertEqual(first.signature, second.signature)
        self.assertEqual(first.signature, ("сөз", "NOUN", (("Case", "Nom"),)))

    def test_as_dict_exposes_stable_schema_and_nested_morphemes(self) -> None:
        analysis = make_analysis(
            score=0.123456789,
            guessed=True,
            orthographic_variant=True,
            source="guesser",
        )
        value = analysis.as_dict()
        self.assertEqual(value["schema_version"], "qazmorph.analysis.v1")
        self.assertEqual(value["lemma"], "сөз")
        self.assertEqual(value["features"], {"Case": "Nom"})
        self.assertEqual(value["tags"], ["n", "nom"])
        self.assertEqual(value["morphemes"], [analysis.morphemes[0].as_dict()])
        self.assertEqual(value["source"], "guesser")
        self.assertEqual(value["score"], 0.12345679)
        self.assertIs(value["guessed"], True)
        self.assertIs(value["orthographic_variant"], True)

    def test_analysis_is_immutable(self) -> None:
        analysis = make_analysis()
        with self.assertRaises(FrozenInstanceError):
            analysis.score = 1.0  # type: ignore[misc]


class TokenTests(unittest.TestCase):
    def test_single_analysis_is_chosen_without_explicit_selection(self) -> None:
        analysis = make_analysis()
        token = Token("сөз", 0, 3, "word", [analysis])
        self.assertIs(token.chosen, analysis)

    def test_ambiguous_token_requires_explicit_selection(self) -> None:
        noun = make_analysis()
        verb = make_analysis(
            lemma="сөйле",
            upos="VERB",
            features=(("Mood", "Imp"), ("VerbForm", "Fin")),
            tags=("v", "imp"),
            raw="сөйле<v><imp>",
        )
        token = Token("сөз", 0, 3, "word", [noun, verb])
        self.assertIsNone(token.chosen)
        token.selected = 1
        self.assertIs(token.chosen, verb)

    def test_out_of_range_or_negative_selection_is_ignored(self) -> None:
        analysis = make_analysis()
        for selected in (-1, 1, 100):
            with self.subTest(selected=selected):
                token = Token("сөз", 0, 3, "word", [analysis], selected=selected)
                self.assertIs(token.chosen, analysis)

    def test_dictionary_word_requires_at_least_one_non_guessed_analysis(self) -> None:
        dictionary = make_analysis()
        guessed = make_analysis(guessed=True, source="guesser")
        self.assertFalse(Token("x", 0, 1, "word").is_dictionary_word)
        self.assertFalse(Token("x", 0, 1, "word", [guessed]).is_dictionary_word)
        self.assertTrue(Token("x", 0, 1, "word", [guessed, dictionary]).is_dictionary_word)

    def test_as_dict_serializes_selected_analysis_and_all_candidates(self) -> None:
        first = make_analysis(score=0.6)
        second = make_analysis(
            lemma="Сөз",
            upos="PROPN",
            features=(("Case", "Nom"),),
            tags=("np", "nom"),
            raw="Сөз<np><nom>",
            score=0.4,
        )
        token = Token(
            "Сөз", 4, 7, "word", [first, second], selected=1, sentence_end=True
        )
        value = token.as_dict()
        self.assertEqual(value["text"], "Сөз")
        self.assertEqual((value["start"], value["end"]), (4, 7))
        self.assertEqual(value["kind"], "word")
        self.assertIs(value["sentence_end"], True)
        self.assertEqual(value["selected"], second.as_dict())
        self.assertEqual(value["analyses"], [first.as_dict(), second.as_dict()])


class DocumentTests(unittest.TestCase):
    def test_lexical_tokens_excludes_only_spaces(self) -> None:
        tokens = [
            Token("сөз", 0, 3, "word", [make_analysis()]),
            Token(" ", 3, 4, "space"),
            Token("!", 4, 5, "punct", sentence_end=True),
            Token("№", 5, 6, "symbol"),
        ]
        document = Document("сөз !№", tokens, "lattice", "test-resource")
        self.assertEqual(document.lexical_tokens, [tokens[0], tokens[2], tokens[3]])

    def test_as_dict_preserves_document_metadata_and_token_order(self) -> None:
        token = Token("сөз", 0, 3, "word", [make_analysis()], selected=0)
        document = Document("сөз", [token], "contextual", "2026-08-10")
        self.assertEqual(
            document.as_dict(),
            {
                "schema_version": "qazmorph.document.v2",
                "text": "сөз",
                "mode": "contextual",
                "resource_version": "2026-08-10",
                "ud_profile": "universal",
                "tokens": [token.as_dict()],
                "analysis_spans": [],
            },
        )

    def test_analysis_span_is_immutable_versioned_and_token_aligned(self) -> None:
        first = Token("жоқ", 0, 3, "word", [make_analysis()])
        gap = Token(" ", 3, 4, "space")
        last = Token("қой", 4, 7, "word", [make_analysis()])
        analysis = make_analysis(raw="жоқ<adj>+ғой<mod_ass>")
        span = AnalysisSpan("жоқ қой", 0, 7, 0, 3, (analysis,), selected=0)
        document = Document(
            "жоқ қой",
            [first, gap, last],
            "contextual",
            "test",
            analysis_spans=(span,),
        )
        self.assertIs(span.chosen, analysis)
        self.assertEqual(span.as_dict()["schema_version"], "qazmorph.analysis-span.v1")
        self.assertEqual(document.as_dict()["analysis_spans"], [span.as_dict()])
        with self.assertRaises(FrozenInstanceError):
            span.selected = None  # type: ignore[misc]

    def test_document_rejects_non_atomic_or_noncontiguous_tokens(self) -> None:
        with self.assertRaisesRegex(ValueError, "contains whitespace"):
            Document("жоқ қой", [Token("жоқ қой", 0, 7, "word")], "lattice", "test")
        with self.assertRaisesRegex(ValueError, "contiguous"):
            Document(
                "екі сөз",
                [Token("екі", 0, 3, "word"), Token("сөз", 4, 7, "word")],
                "lattice",
                "test",
            )

    def test_document_records_and_validates_ud_projection_profile(self) -> None:
        token = Token("сөз", 0, 3, "word", [make_analysis()])
        document = Document(
            "сөз", [token], "lattice", "test", ud_profile="ktb"
        )
        self.assertEqual(document.as_dict()["ud_profile"], "ktb")
        with self.assertRaisesRegex(ValueError, "unknown UD projection profile"):
            Document("сөз", [token], "lattice", "test", ud_profile="legacy")

    def test_document_accepts_partial_edge_tokens_but_rejects_wrong_coverage(self) -> None:
        tokens = [Token("екі", 0, 3, "word"), Token(" ", 3, 4, "space"), Token("сөз", 4, 7, "word")]
        span = AnalysisSpan("кі сө", 1, 6, 0, 3, (make_analysis(),))
        document = Document("екі сөз", tokens, "lattice", "test", analysis_spans=(span,))
        self.assertEqual(document.analysis_spans, (span,))
        wrong = AnalysisSpan("кі сө", 1, 6, 1, 3, (make_analysis(),))
        with self.assertRaisesRegex(ValueError, "start coverage"):
            Document("екі сөз", tokens, "lattice", "test", analysis_spans=(wrong,))


if __name__ == "__main__":
    unittest.main()
