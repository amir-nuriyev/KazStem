"""Optional candidate-constrained contextual reranking."""

from __future__ import annotations

from dataclasses import dataclass, replace
import math
from pathlib import Path
from typing import Any

from .backend import BackendError
from .types import Analysis, Token


AUXILIARY_LEMMAS = frozenset({"ал", "бер", "бол", "е", "жат", "жүр", "кел", "отыр", "тұр", "қал"})


@dataclass(frozen=True, slots=True)
class NeuralPrediction:
    text: str
    start: int
    end: int
    lemma: str
    upos: str
    features: tuple[tuple[str, str], ...]


def _parse_features(value: str | None) -> tuple[tuple[str, str], ...]:
    features: dict[str, str] = {}
    if value:
        for item in value.split("|"):
            if "=" in item:
                key, feature_value = item.split("=", 1)
                features[key] = feature_value
    return tuple(sorted(features.items()))


class StanzaCandidateRanker:
    """Use a Kazakh contextual model only to rank FST-licensed readings."""

    def __init__(self, model_dir: str | Path, *, use_gpu: bool | None = None) -> None:
        try:
            import stanza
        except ImportError as exc:
            raise BackendError(
                "Neural mode requires stanza; run scripts/bootstrap_neural_h100.sh "
                "on its supported platform and use the generated virtual environment"
            ) from exc
        directory = Path(model_dir).expanduser().resolve()
        if not directory.is_dir():
            raise BackendError(f"Kazakh neural model directory does not exist: {directory}")
        try:
            self.pipeline = stanza.Pipeline(
                "kk",
                processors="tokenize,pos,lemma",
                model_dir=str(directory),
                use_gpu=True if use_gpu is None else use_gpu,
                download_method=None,
                verbose=False,
            )
        except Exception as exc:  # stanza exposes several backend-specific error types
            raise BackendError(f"Could not load Kazakh neural models from {directory}: {exc}") from exc

    def _predict(self, text: str) -> list[NeuralPrediction]:
        try:
            document = self.pipeline(text)
        except Exception as exc:
            raise BackendError(f"Kazakh neural inference failed: {exc}") from exc
        predictions: list[NeuralPrediction] = []
        for sentence in document.sentences:
            for parent in sentence.tokens:
                for word in parent.words:
                    start = getattr(word, "start_char", None)
                    end = getattr(word, "end_char", None)
                    if start is None:
                        start = getattr(parent, "start_char", None)
                    if end is None:
                        end = getattr(parent, "end_char", None)
                    if start is None or end is None:
                        continue
                    predictions.append(
                        NeuralPrediction(
                            text=word.text,
                            start=int(start),
                            end=int(end),
                            lemma=word.lemma or word.text.casefold(),
                            upos=word.upos or "X",
                            features=_parse_features(word.feats),
                        )
                    )
        return predictions

    @staticmethod
    def _candidate_score(prediction: NeuralPrediction, analysis: Analysis) -> float:
        # A weak FST-order prior breaks otherwise exact ties without overruling
        # contextual evidence.
        prior = analysis.score if analysis.score is not None else 1.0
        score = 0.12 * math.log(max(prior, 1e-12))
        if analysis.lemma.casefold() == prediction.lemma.casefold():
            score += 6.0
        elif analysis.lemma.casefold() == prediction.text.casefold():
            score += 1.0

        if analysis.upos == prediction.upos:
            score += 3.0
        elif (
            prediction.upos == "AUX"
            and analysis.upos == "VERB"
            and analysis.lemma.casefold() in AUXILIARY_LEMMAS
        ):
            score += 2.75

        predicted_features = dict(prediction.features)
        candidate_features = dict(analysis.features)
        for key in predicted_features.keys() | candidate_features.keys():
            if key in predicted_features and key in candidate_features:
                score += 0.55 if predicted_features[key] == candidate_features[key] else -0.2
        return score

    def rerank(self, text: str, tokens: list[Token]) -> None:
        predictions = {(item.start, item.end): item for item in self._predict(text)}
        for token in tokens:
            if not token.analyses or token.kind not in {"word", "number"}:
                continue
            prediction = predictions.get((token.start, token.end))
            if prediction is None:
                continue
            raw_scores = [self._candidate_score(prediction, analysis) for analysis in token.analyses]
            peak = max(raw_scores)
            weights = [math.exp(score - peak) for score in raw_scores]
            total = sum(weights)
            token.analyses = [
                replace(analysis, score=weight / total)
                for analysis, weight in zip(token.analyses, weights)
            ]
            token.selected = max(range(len(raw_scores)), key=raw_scores.__getitem__)

            selected = token.analyses[token.selected]
            if (
                prediction.upos == "AUX"
                and selected.upos == "VERB"
                and selected.lemma.casefold() in AUXILIARY_LEMMAS
            ):
                token.analyses[token.selected] = replace(
                    selected,
                    context_upos="AUX",
                )
