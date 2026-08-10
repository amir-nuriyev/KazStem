from __future__ import annotations

from dataclasses import replace
import unittest

from qazmorph.neural import NeuralPrediction, StanzaCandidateRanker
from qazmorph.types import Analysis, Morpheme, Token


def analysis(lemma: str, upos: str, *, features=()) -> Analysis:
    tags = (upos.casefold(),)
    return Analysis(
        lemma=lemma,
        upos=upos,
        features=tuple(features),
        tags=tags,
        morphemes=(Morpheme(lemma, tags, upos, tuple(features)),),
        raw=f"{lemma}<{upos.casefold()}>",
    )


def ranker_with(*predictions: NeuralPrediction) -> StanzaCandidateRanker:
    ranker = StanzaCandidateRanker.__new__(StanzaCandidateRanker)
    ranker._predict = lambda _text: list(predictions)  # type: ignore[method-assign]
    return ranker


class NeuralCandidateRankerTests(unittest.TestCase):
    def test_ranking_preserves_candidate_identity_order_and_normalizes_scores(self) -> None:
        noun = analysis("жаз", "NOUN")
        verb = analysis("жаз", "VERB", features=(("VerbForm", "Fin"),))
        token = Token("жаз", 0, 3, "word", [noun, verb])
        prediction = NeuralPrediction(
            "жаз", 0, 3, "жаз", "VERB", (("VerbForm", "Fin"),)
        )
        ranker_with(prediction).rerank("жаз", [token])

        self.assertEqual([item.identity for item in token.analyses], [noun.identity, verb.identity])
        self.assertEqual(token.selected, 1)
        self.assertAlmostEqual(sum(item.score or 0.0 for item in token.analyses), 1.0)

    def test_missing_exact_span_abstains_without_changing_candidates(self) -> None:
        candidates = [analysis("сөз", "NOUN"), analysis("сөз", "VERB")]
        token = Token("сөз", 4, 7, "word", list(candidates))
        mismatch = NeuralPrediction("сөз", 0, 3, "сөз", "NOUN", ())
        ranker_with(mismatch).rerank("xxx сөз", [token])

        self.assertIsNone(token.selected)
        self.assertEqual(token.analyses, candidates)

    def test_exact_tie_selects_the_first_candidate_deterministically(self) -> None:
        first = analysis("ат", "NOUN")
        second = analysis("ат", "NOUN")
        token = Token("ат", 0, 2, "word", [first, second])
        prediction = NeuralPrediction("ат", 0, 2, "ат", "NOUN", ())
        ranker_with(prediction).rerank("ат", [token])

        self.assertEqual(token.selected, 0)
        self.assertAlmostEqual(token.analyses[0].score or 0.0, 0.5)
        self.assertAlmostEqual(token.analyses[1].score or 0.0, 0.5)

    def test_featureless_numeric_tie_keeps_original_before_rule_alias(self) -> None:
        original = analysis("7", "NUM", features=(("NumType", "Card"),))
        alias = replace(
            original,
            features=(("NumType", "Ord"),),
            morphemes=(
                replace(original.morphemes[0], features=(("NumType", "Ord"),)),
            ),
            source="rule",
            guessed=False,
        )
        token = Token("7", 0, 1, "number", [original, alias])
        featureless = NeuralPrediction("7", 0, 1, "7", "NUM", ())

        ranker_with(featureless).rerank("7", [token])

        self.assertEqual(token.selected, 0)
        self.assertEqual(token.analyses[0].source, "lexicon")
        self.assertAlmostEqual(token.analyses[0].score or 0.0, 0.5)
        self.assertAlmostEqual(token.analyses[1].score or 0.0, 0.5)

    def test_numeric_feature_evidence_can_select_rule_alias(self) -> None:
        original = analysis("7", "NUM", features=(("NumType", "Card"),))
        alias = replace(
            original,
            features=(("NumType", "Ord"),),
            morphemes=(
                replace(original.morphemes[0], features=(("NumType", "Ord"),)),
            ),
            source="rule",
            guessed=False,
        )
        token = Token("7", 0, 1, "number", [original, alias])
        ordinal = NeuralPrediction(
            "7", 0, 1, "7", "NUM", (("NumType", "Ord"),)
        )

        ranker_with(ordinal).rerank("7", [token])

        self.assertEqual(token.selected, 1)
        self.assertEqual(token.analyses[1].source, "rule")

    def test_auxiliary_projection_does_not_mutate_lexical_provenance(self) -> None:
        verb = analysis("бол", "VERB")
        noun = analysis("бол", "NOUN")
        token = Token("бол", 0, 3, "word", [verb, noun])
        prediction = NeuralPrediction("бол", 0, 3, "бол", "AUX", ())
        ranker_with(prediction).rerank("бол", [token])

        self.assertEqual(token.selected, 0)
        selected = token.analyses[0]
        self.assertEqual(selected.upos, "VERB")
        self.assertEqual(selected.context_upos, "AUX")
        self.assertEqual(selected.source, "lexicon")
        self.assertEqual(selected.raw, verb.raw)


if __name__ == "__main__":
    unittest.main()
