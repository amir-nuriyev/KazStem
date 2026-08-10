#!/usr/bin/env python3
"""Evaluate qazmorph against one or more existing UD CoNLL-U corpora.

The script intentionally has no downloader and uses only the Python standard
library.  Point it at CoNLL-U files that already exist on the machine where the
evaluation is run (the project convention is to run it through ``ssh h100``).

Candidate recall is measured on the ambiguity-preserving lattice.  Contextual
accuracy is measured in a separate disambiguating pass.  End-to-end scores keep
unaligned gold tokens in their denominators; aligned-only scores are also
reported so tokenization and morphology errors can be distinguished.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
import hashlib
from importlib import metadata as importlib_metadata
from itertools import islice
import json
from pathlib import Path
import platform
import subprocess
import sys
from typing import Any, Iterable, Iterator, Sequence
import unicodedata


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = PROJECT_ROOT / "src"
if SOURCE_ROOT.is_dir() and str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))


SCHEMA_VERSION = "qazmorph.ud-evaluation.v4"
ALIGNMENT_APOSTROPHES = str.maketrans({"\u2018": "'", "\u2019": "'", "\u02bc": "'", "\u02bb": "'"})
ALIGNMENT_DASHES = str.maketrans(
    {
        "\u2010": "-",
        "\u2011": "-",
        "\u2012": "-",
        "\u2013": "-",
        "\u2014": "-",
        "\u2212": "-",
    }
)


class EvaluationError(RuntimeError):
    """Raised for invalid input or an analyzer failure with corpus context."""


def _analyzer_mode_flags(mode: str) -> dict[str, bool]:
    """Return the mutually exclusive Analyzer flags for an evaluation engine."""

    if mode not in {"lattice", "cg", "neural"}:
        raise ValueError(f"unknown analyzer mode: {mode}")
    return {
        "disambiguate": mode == "cg",
        "neural": mode == "neural",
    }


@dataclass(frozen=True, slots=True)
class GoldToken:
    token_id: int
    form: str
    lemma: str
    upos: str
    features: tuple[tuple[str, str], ...]
    misc: str


@dataclass(frozen=True, slots=True)
class SurfaceToken:
    start_id: int
    end_id: int
    form: str
    misc: str


@dataclass(frozen=True, slots=True)
class GoldSentence:
    source: Path
    ordinal: int
    sent_id: str
    text: str
    tokens: tuple[GoldToken, ...]
    multiword_tokens: int
    empty_nodes: int
    used_text_comment: bool
    multiword_spans: tuple[SurfaceToken, ...] = ()


@dataclass(frozen=True, slots=True)
class PredictedToken:
    text: str
    kind: str
    analyses: tuple[Any, ...]
    chosen: Any | None
    selected: int | None
    start: int | None = None
    end: int | None = None


@dataclass(slots=True)
class Ratio:
    correct: int = 0
    total: int = 0

    def add(self, success: bool) -> None:
        self.total += 1
        self.correct += int(success)

    def as_json(self) -> dict[str, int | float | None]:
        return {
            "correct": self.correct,
            "total": self.total,
            "value": self.correct / self.total if self.total else None,
        }


@dataclass(slots=True)
class MetricSet:
    lemma: Ratio = field(default_factory=Ratio)
    upos: Ratio = field(default_factory=Ratio)
    feature_bundle: Ratio = field(default_factory=Ratio)
    lemma_upos: Ratio = field(default_factory=Ratio)
    full_analysis: Ratio = field(default_factory=Ratio)
    feature_gold_subset_candidate: Ratio = field(default_factory=Ratio)
    feature_candidate_subset_gold: Ratio = field(default_factory=Ratio)
    full_gold_subset_candidate: Ratio = field(default_factory=Ratio)
    full_candidate_subset_gold: Ratio = field(default_factory=Ratio)

    def add(
        self,
        gold: GoldToken,
        analyses: Sequence[Any],
        *,
        case_sensitive_lemmas: bool,
        contextual_projection: bool = False,
    ) -> None:
        # ``source=unknown`` is a diagnostic placeholder, not a morphological
        # hypothesis.  It must never earn recall merely because gold also uses
        # lemma=surface, UPOS=X, and an empty feature bundle.
        analyses = tuple(analysis for analysis in analyses if analysis.source != "unknown")
        lemma_known = bool(gold.lemma and gold.lemma != "_")
        upos_known = bool(gold.upos and gold.upos != "_")
        gold_lemma = _lemma_key(gold.lemma, case_sensitive=case_sensitive_lemmas)
        gold_upos = gold.upos.upper()
        gold_features = gold.features
        gold_feature_set = set(gold_features)

        def analysis_upos(analysis: Any) -> str:
            if contextual_projection:
                return getattr(analysis, "context_upos", None) or analysis.upos
            return analysis.upos

        def analysis_features(analysis: Any) -> tuple[tuple[str, str], ...]:
            if contextual_projection:
                contextual = getattr(analysis, "context_features", ())
                return tuple(sorted(contextual or analysis.features))
            return tuple(sorted(analysis.features))

        lemma_matches = [
            analysis
            for analysis in analyses
            if lemma_known
            and _lemma_key(str(analysis.lemma), case_sensitive=case_sensitive_lemmas) == gold_lemma
        ]
        upos_matches = [
            analysis for analysis in analyses if upos_known and analysis_upos(analysis) == gold_upos
        ]

        if lemma_known:
            self.lemma.add(bool(lemma_matches))
        if upos_known:
            self.upos.add(bool(upos_matches))
        self.feature_bundle.add(
            any(analysis_features(analysis) == gold_features for analysis in analyses)
        )
        candidate_feature_sets = [
            set(analysis_features(analysis)) for analysis in analyses
        ]
        self.feature_gold_subset_candidate.add(
            any(gold_feature_set <= candidate for candidate in candidate_feature_sets)
        )
        self.feature_candidate_subset_gold.add(
            any(candidate <= gold_feature_set for candidate in candidate_feature_sets)
        )

        if lemma_known and upos_known:
            self.lemma_upos.add(
                any(
                    _lemma_key(str(analysis.lemma), case_sensitive=case_sensitive_lemmas)
                    == gold_lemma
                    and analysis_upos(analysis) == gold_upos
                    for analysis in analyses
                )
            )
            self.full_analysis.add(
                any(
                    _lemma_key(str(analysis.lemma), case_sensitive=case_sensitive_lemmas)
                    == gold_lemma
                    and analysis_upos(analysis) == gold_upos
                    and analysis_features(analysis) == gold_features
                    for analysis in analyses
                )
            )
            lemma_upos_analyses = [
                analysis
                for analysis in analyses
                if _lemma_key(
                    str(analysis.lemma), case_sensitive=case_sensitive_lemmas
                )
                == gold_lemma
                and analysis_upos(analysis) == gold_upos
            ]
            lemma_upos_feature_sets = [
                set(analysis_features(analysis))
                for analysis in lemma_upos_analyses
            ]
            self.full_gold_subset_candidate.add(
                any(
                    gold_feature_set <= candidate
                    for candidate in lemma_upos_feature_sets
                )
            )
            self.full_candidate_subset_gold.add(
                any(
                    candidate <= gold_feature_set
                    for candidate in lemma_upos_feature_sets
                )
            )

    def as_json(self, *, candidate: bool) -> dict[str, dict[str, int | float | None]]:
        suffix = "recall" if candidate else "accuracy"
        return {
            f"lemma_{suffix}": self.lemma.as_json(),
            f"upos_{suffix}": self.upos.as_json(),
            f"feature_bundle_{suffix}": self.feature_bundle.as_json(),
            f"lemma_upos_{suffix}": self.lemma_upos.as_json(),
            f"full_analysis_{suffix}": self.full_analysis.as_json(),
            f"feature_bundle_gold_subset_or_equal_candidate_{suffix}": (
                self.feature_gold_subset_candidate.as_json()
            ),
            f"feature_bundle_candidate_subset_or_equal_gold_{suffix}": (
                self.feature_candidate_subset_gold.as_json()
            ),
            f"full_analysis_gold_subset_or_equal_candidate_{suffix}": (
                self.full_gold_subset_candidate.as_json()
            ),
            f"full_analysis_candidate_subset_or_equal_gold_{suffix}": (
                self.full_candidate_subset_gold.as_json()
            ),
        }


@dataclass(slots=True)
class AlignmentCounts:
    sentences: int = 0
    gold_tokens: int = 0
    predicted_tokens: int = 0
    one_to_one_exact: int = 0
    one_to_one_normalized: int = 0
    grouped_operations: int = 0
    grouped_gold_tokens: int = 0
    grouped_predicted_tokens: int = 0
    unaligned_gold_tokens: int = 0
    unaligned_predicted_tokens: int = 0

    def add(self, other: "AlignmentCounts") -> None:
        for name in self.__dataclass_fields__:
            setattr(self, name, getattr(self, name) + getattr(other, name))

    def as_json(self) -> dict[str, int | float | None]:
        one_to_one = self.one_to_one_exact + self.one_to_one_normalized
        accounted = one_to_one + self.grouped_gold_tokens
        return {
            "sentences": self.sentences,
            "gold_tokens": self.gold_tokens,
            "predicted_tokens": self.predicted_tokens,
            "one_to_one_tokens": one_to_one,
            "one_to_one_exact": self.one_to_one_exact,
            "one_to_one_normalized": self.one_to_one_normalized,
            "grouped_operations": self.grouped_operations,
            "grouped_gold_tokens": self.grouped_gold_tokens,
            "grouped_predicted_tokens": self.grouped_predicted_tokens,
            "unaligned_gold_tokens": self.unaligned_gold_tokens,
            "unaligned_predicted_tokens": self.unaligned_predicted_tokens,
            "scorable_gold_tokens": one_to_one,
            "non_scorable_grouped_gold_tokens": self.grouped_gold_tokens,
            "one_to_one_rate": one_to_one / self.gold_tokens if self.gold_tokens else None,
            "surface_accounted_gold_rate": (
                accounted / self.gold_tokens if self.gold_tokens else None
            ),
        }


@dataclass(frozen=True, slots=True)
class AlignmentOperation:
    gold_start: int
    predicted_start: int
    kind: str
    gold_size: int
    predicted_size: int
    match_kind: str


@dataclass(frozen=True, slots=True)
class AlignmentResult:
    direct: dict[int, int]
    counts: AlignmentCounts
    operations: tuple[AlignmentOperation, ...]


@dataclass(slots=True)
class AlignmentDiagnostics:
    """Aggregate bounded, non-scorable alignment decisions for auditability."""

    sample_limit: int = 20
    group_class_sample_limit: int = 5
    group_size_distribution: dict[str, int] = field(default_factory=dict)
    group_direction_distribution: dict[str, int] = field(default_factory=dict)
    group_evidence_class_distribution: dict[str, int] = field(default_factory=dict)
    groups_matching_exact_ud_mwt_span: int = 0
    groups_not_matching_exact_ud_mwt_span: int = 0
    ud_mwt_groups_with_concatenative_component_forms: int = 0
    ud_mwt_groups_with_nonconcatenative_component_forms: int = 0
    groups_with_predicted_internal_whitespace: int = 0
    groups_with_predicted_punctuation_token: int = 0
    group_samples_by_evidence_class: dict[str, list[dict[str, Any]]] = field(
        default_factory=dict
    )
    unaligned_gold_samples: list[dict[str, Any]] = field(default_factory=list)
    unaligned_predicted_samples: list[dict[str, Any]] = field(default_factory=list)

    @staticmethod
    def _increment(target: dict[str, int], key: str) -> None:
        target[key] = target.get(key, 0) + 1

    @staticmethod
    def _location(sentence: GoldSentence) -> dict[str, Any]:
        return {
            "source": str(sentence.source),
            "sentence_ordinal": sentence.ordinal,
            "sent_id": sentence.sent_id,
            "text": sentence.text,
        }

    @staticmethod
    def _gold_items(tokens: Sequence[GoldToken]) -> list[dict[str, Any]]:
        return [
            {
                "token_id": token.token_id,
                "form": token.form,
                "lemma": token.lemma,
                "upos": token.upos,
            }
            for token in tokens
        ]

    @staticmethod
    def _predicted_items(tokens: Sequence[PredictedToken]) -> list[dict[str, Any]]:
        return [
            {
                "text": token.text,
                "kind": token.kind,
                "candidate_count": sum(
                    analysis.source != "unknown" for analysis in token.analyses
                ),
            }
            for token in tokens
        ]

    def add(
        self,
        sentence: GoldSentence,
        predicted: Sequence[PredictedToken],
        alignment: AlignmentResult,
    ) -> None:
        for operation in alignment.operations:
            gold = sentence.tokens[
                operation.gold_start : operation.gold_start + operation.gold_size
            ]
            predicted_group = predicted[
                operation.predicted_start : operation.predicted_start
                + operation.predicted_size
            ]
            if operation.match_kind == "group":
                shape = f"{operation.gold_size}:{operation.predicted_size}"
                self._increment(self.group_size_distribution, shape)
                if operation.gold_size > 1 and operation.predicted_size == 1:
                    direction = "multiple_gold_to_one_predicted"
                elif operation.gold_size == 1 and operation.predicted_size > 1:
                    direction = "one_gold_to_multiple_predicted"
                else:
                    direction = "multiple_gold_to_multiple_predicted"
                self._increment(self.group_direction_distribution, direction)

                gold_start_id = gold[0].token_id
                gold_end_id = gold[-1].token_id
                exact_mwt = next(
                    (
                        span
                        for span in sentence.multiword_spans
                        if span.start_id == gold_start_id and span.end_id == gold_end_id
                    ),
                    None,
                )
                self.groups_matching_exact_ud_mwt_span += int(exact_mwt is not None)
                self.groups_not_matching_exact_ud_mwt_span += int(exact_mwt is None)
                has_internal_whitespace = any(
                    any(char.isspace() for char in token.text) for token in predicted_group
                )
                has_punctuation = any(token.kind == "punct" for token in predicted_group)
                self.groups_with_predicted_internal_whitespace += int(has_internal_whitespace)
                self.groups_with_predicted_punctuation_token += int(has_punctuation)

                if exact_mwt is not None:
                    evidence_class = "ud_multiword_token_surface"
                    components_are_concatenative = (
                        _alignment_key("".join(token.form for token in gold))
                        == _alignment_key(exact_mwt.form)
                    )
                    self.ud_mwt_groups_with_concatenative_component_forms += int(
                        components_are_concatenative
                    )
                    self.ud_mwt_groups_with_nonconcatenative_component_forms += int(
                        not components_are_concatenative
                    )
                elif (
                    operation.gold_size > 1
                    and operation.predicted_size == 1
                    and has_internal_whitespace
                ):
                    evidence_class = "analyzer_multiword_fusion"
                    components_are_concatenative = None
                elif (
                    operation.gold_size == 1
                    and operation.predicted_size > 1
                    and has_punctuation
                ):
                    evidence_class = "analyzer_punctuation_split"
                    components_are_concatenative = None
                else:
                    evidence_class = "other_surface_group"
                    components_are_concatenative = None
                self._increment(self.group_evidence_class_distribution, evidence_class)

                class_samples = self.group_samples_by_evidence_class.setdefault(
                    evidence_class, []
                )
                if len(class_samples) < self.group_class_sample_limit:
                    sample = self._location(sentence)
                    sample.update(
                        {
                            "shape": shape,
                            "direction": direction,
                            "gold": self._gold_items(gold),
                            "predicted": self._predicted_items(predicted_group),
                            "exact_ud_multiword_token": (
                                {
                                    "start_id": exact_mwt.start_id,
                                    "end_id": exact_mwt.end_id,
                                    "form": exact_mwt.form,
                                }
                                if exact_mwt is not None
                                else None
                            ),
                            "ud_mwt_component_forms_are_concatenative": (
                                components_are_concatenative
                            ),
                            "predicted_internal_whitespace": has_internal_whitespace,
                            "predicted_contains_punctuation_token": has_punctuation,
                        }
                    )
                    class_samples.append(sample)
            elif (
                operation.kind == "skip_gold"
                and len(self.unaligned_gold_samples) < self.sample_limit
            ):
                sample = self._location(sentence)
                sample.update(
                    {
                        "gold": self._gold_items(gold),
                        "gold_index": operation.gold_start,
                    }
                )
                self.unaligned_gold_samples.append(sample)
            elif (
                operation.kind == "skip_predicted"
                and len(self.unaligned_predicted_samples) < self.sample_limit
            ):
                sample = self._location(sentence)
                sample.update(
                    {
                        "predicted": self._predicted_items(predicted_group),
                        "predicted_index": operation.predicted_start,
                    }
                )
                self.unaligned_predicted_samples.append(sample)

    def as_json(self) -> dict[str, Any]:
        return {
            "group_size_distribution": dict(sorted(self.group_size_distribution.items())),
            "group_direction_distribution": dict(
                sorted(self.group_direction_distribution.items())
            ),
            "group_evidence_class_distribution": dict(
                sorted(self.group_evidence_class_distribution.items())
            ),
            "group_evidence_class_definitions": {
                "ud_multiword_token_surface": (
                    "gold range exactly matches a UD multiword-token row and uses that row's "
                    "surface FORM"
                ),
                "analyzer_multiword_fusion": (
                    "one analyzer token containing whitespace covers multiple gold tokens"
                ),
                "analyzer_punctuation_split": (
                    "multiple analyzer tokens, including punctuation, cover one gold token"
                ),
                "other_surface_group": (
                    "surface-equivalent split or merge not covered by the preceding classes"
                ),
            },
            "groups_matching_exact_ud_multiword_token_span": (
                self.groups_matching_exact_ud_mwt_span
            ),
            "groups_not_matching_exact_ud_multiword_token_span": (
                self.groups_not_matching_exact_ud_mwt_span
            ),
            "ud_mwt_groups_with_concatenative_component_forms": (
                self.ud_mwt_groups_with_concatenative_component_forms
            ),
            "ud_mwt_groups_with_nonconcatenative_component_forms": (
                self.ud_mwt_groups_with_nonconcatenative_component_forms
            ),
            "groups_with_predicted_internal_whitespace": (
                self.groups_with_predicted_internal_whitespace
            ),
            "groups_with_predicted_punctuation_token": (
                self.groups_with_predicted_punctuation_token
            ),
            "group_sample_limit_per_evidence_class": self.group_class_sample_limit,
            "unaligned_sample_limit_per_side": self.sample_limit,
            "group_samples_by_evidence_class": dict(
                sorted(self.group_samples_by_evidence_class.items())
            ),
            "unaligned_gold_samples": self.unaligned_gold_samples,
            "unaligned_predicted_samples": self.unaligned_predicted_samples,
        }


@dataclass(slots=True)
class CoverageStats:
    gold_lexical_tokens: int = 0
    aligned_lexical_tokens: int = 0
    tokens_with_analysis: int = 0
    tokens_with_compiled_lexicon_analysis: int = 0
    tokens_with_fixlist_analysis: int = 0
    tokens_with_effective_dictionary_analysis: int = 0
    tokens_with_deterministic_rule_analysis: int = 0
    tokens_with_analyzer_guess_analysis: int = 0
    operational_oov_tokens: int = 0
    oov_with_guesser_hypothesis: int = 0
    tokens_with_unknown_placeholder: int = 0
    total_candidates: int = 0
    max_candidates: int = 0
    all_types: set[str] = field(default_factory=set)
    aligned_types: set[str] = field(default_factory=set)
    compiled_lexicon_types: set[str] = field(default_factory=set)
    fixlist_types: set[str] = field(default_factory=set)
    analyzer_guess_types: set[str] = field(default_factory=set)
    operational_oov_types: set[str] = field(default_factory=set)

    def add_gold(self, gold: GoldToken, predicted: PredictedToken | None) -> None:
        if gold.upos == "PUNCT":
            return
        form_key = _alignment_key(gold.form)
        self.gold_lexical_tokens += 1
        self.all_types.add(form_key)
        if predicted is None:
            return

        self.aligned_lexical_tokens += 1
        self.aligned_types.add(form_key)
        returned_analyses = predicted.analyses
        analyses = tuple(
            analysis for analysis in returned_analyses if analysis.source != "unknown"
        )
        self.total_candidates += len(analyses)
        self.max_candidates = max(self.max_candidates, len(analyses))
        has_analysis = bool(analyses)
        has_compiled_lexicon = any(
            analysis.source == "lexicon" and not analysis.guessed
            for analysis in analyses
        )
        has_fixlist = any(
            analysis.source == "fixlist" and not analysis.guessed
            for analysis in analyses
        )
        has_analyzer_guess = any(
            analysis.source == "lexicon" and analysis.guessed
            for analysis in analyses
        )
        has_effective_dictionary = has_compiled_lexicon or has_fixlist
        has_rule = any(analysis.source == "rule" for analysis in analyses)
        has_guesser = any(analysis.source == "guesser" for analysis in analyses)
        has_unknown = any(analysis.source == "unknown" for analysis in returned_analyses)
        self.tokens_with_analysis += int(has_analysis)
        self.tokens_with_compiled_lexicon_analysis += int(has_compiled_lexicon)
        self.tokens_with_fixlist_analysis += int(has_fixlist)
        self.tokens_with_effective_dictionary_analysis += int(has_effective_dictionary)
        self.tokens_with_deterministic_rule_analysis += int(has_rule)
        self.tokens_with_analyzer_guess_analysis += int(has_analyzer_guess)
        self.tokens_with_unknown_placeholder += int(has_unknown)
        if has_compiled_lexicon:
            self.compiled_lexicon_types.add(form_key)
        if has_fixlist:
            self.fixlist_types.add(form_key)
        if has_analyzer_guess:
            self.analyzer_guess_types.add(form_key)
        if not has_effective_dictionary:
            self.operational_oov_tokens += 1
            self.operational_oov_types.add(form_key)
            self.oov_with_guesser_hypothesis += int(has_guesser)

    @staticmethod
    def _ratio(correct: int, total: int) -> dict[str, int | float | None]:
        return {
            "correct": correct,
            "total": total,
            "value": correct / total if total else None,
        }

    def as_json(self) -> dict[str, Any]:
        return {
            "scope": (
                "gold UPOS other than PUNCT; all origin labels describe candidates actually "
                "returned by the ambiguity-preserving lattice"
            ),
            "origin_policy": (
                "compiled_lexicon means source=lexicon and guessed=false; fixlist means "
                "source=fixlist and guessed=false; effective_dictionary is their union. "
                "source=lexicon readings tagged <unk> are reported separately as base analyzer "
                "unknown readings. A fixlist overrides the compiled lookup, so this report does "
                "not infer whether a hidden compiled reading also exists."
            ),
            "gold_lexical_tokens": self.gold_lexical_tokens,
            "aligned_lexical_tokens": self.aligned_lexical_tokens,
            "analysis_coverage_end_to_end": self._ratio(
                self.tokens_with_analysis, self.gold_lexical_tokens
            ),
            "analysis_coverage_aligned": self._ratio(
                self.tokens_with_analysis, self.aligned_lexical_tokens
            ),
            "compiled_lexicon_coverage_end_to_end": self._ratio(
                self.tokens_with_compiled_lexicon_analysis, self.gold_lexical_tokens
            ),
            "compiled_lexicon_coverage_aligned": self._ratio(
                self.tokens_with_compiled_lexicon_analysis, self.aligned_lexical_tokens
            ),
            "fixlist_coverage_end_to_end": self._ratio(
                self.tokens_with_fixlist_analysis, self.gold_lexical_tokens
            ),
            "fixlist_coverage_aligned": self._ratio(
                self.tokens_with_fixlist_analysis, self.aligned_lexical_tokens
            ),
            "effective_dictionary_coverage_end_to_end": self._ratio(
                self.tokens_with_effective_dictionary_analysis, self.gold_lexical_tokens
            ),
            "effective_dictionary_coverage_aligned": self._ratio(
                self.tokens_with_effective_dictionary_analysis, self.aligned_lexical_tokens
            ),
            "deterministic_rule_coverage_aligned": self._ratio(
                self.tokens_with_deterministic_rule_analysis, self.aligned_lexical_tokens
            ),
            "deterministic_rule_coverage_end_to_end": self._ratio(
                self.tokens_with_deterministic_rule_analysis, self.gold_lexical_tokens
            ),
            "base_analyzer_unknown_reading_coverage_aligned": self._ratio(
                self.tokens_with_analyzer_guess_analysis, self.aligned_lexical_tokens
            ),
            "base_analyzer_unknown_reading_coverage_end_to_end": self._ratio(
                self.tokens_with_analyzer_guess_analysis, self.gold_lexical_tokens
            ),
            "operational_oov": self._ratio(
                self.operational_oov_tokens, self.aligned_lexical_tokens
            ),
            "oov_with_guesser_hypothesis": self._ratio(
                self.oov_with_guesser_hypothesis, self.operational_oov_tokens
            ),
            "unknown_placeholder_rate": self._ratio(
                self.tokens_with_unknown_placeholder, self.aligned_lexical_tokens
            ),
            "candidate_count": {
                "definition": (
                    "all genuine returned candidates (compiled lexicon, fixlist, deterministic "
                    "rule, base-analyzer <unk> reading, and productive guesser); unknown "
                    "placeholders excluded"
                ),
                "total": self.total_candidates,
                "mean_per_aligned_lexical_token": (
                    self.total_candidates / self.aligned_lexical_tokens
                    if self.aligned_lexical_tokens
                    else None
                ),
                "maximum": self.max_candidates,
            },
            "types": {
                "gold": len(self.all_types),
                "aligned": len(self.aligned_types),
                "compiled_lexicon": len(self.compiled_lexicon_types),
                "fixlist": len(self.fixlist_types),
                "base_analyzer_unknown_reading": len(self.analyzer_guess_types),
                "operational_oov": len(self.operational_oov_types),
                "operational_oov_rate_among_aligned": (
                    len(self.operational_oov_types) / len(self.aligned_types)
                    if self.aligned_types
                    else None
                ),
            },
        }


@dataclass(slots=True)
class SelectedRawContainment:
    """Audit that contextual choices really came from the separate lattice pass."""

    sample_limit: int = 20
    selected_genuine_tokens: int = 0
    contained_raw_analyses: int = 0
    missing_lattice_span: int = 0
    selected_raw_missing_from_lattice: int = 0
    samples: list[dict[str, Any]] = field(default_factory=list)

    def add(
        self,
        sentence: GoldSentence,
        lattice: Sequence[PredictedToken],
        contextual: Sequence[PredictedToken],
    ) -> None:
        lattice_by_span: dict[tuple[int, int, str], list[PredictedToken]] = {}
        for token in lattice:
            if token.start is None or token.end is None:
                continue
            key = (token.start, token.end, token.text)
            lattice_by_span.setdefault(key, []).append(token)

        for token in contextual:
            chosen = token.chosen
            if chosen is None or chosen.source == "unknown":
                continue
            self.selected_genuine_tokens += 1
            key = (token.start, token.end, token.text)
            matches = lattice_by_span.get(key, []) if None not in key[:2] else []
            lattice_analyses = [
                analysis
                for match in matches
                for analysis in match.analyses
                if analysis.source != "unknown"
            ]
            if not matches:
                self.missing_lattice_span += 1
                reason = "no_identical_lattice_span"
            elif any(analysis.raw == chosen.raw for analysis in lattice_analyses):
                self.contained_raw_analyses += 1
                continue
            else:
                self.selected_raw_missing_from_lattice += 1
                reason = "selected_raw_analysis_absent"

            if len(self.samples) < self.sample_limit:
                self.samples.append(
                    {
                        "source": str(sentence.source),
                        "sentence_ordinal": sentence.ordinal,
                        "sent_id": sentence.sent_id,
                        "token": {
                            "text": token.text,
                            "start": token.start,
                            "end": token.end,
                        },
                        "reason": reason,
                        "selected": {"raw": chosen.raw, "source": chosen.source},
                        "lattice": [
                            {"raw": analysis.raw, "source": analysis.source}
                            for analysis in lattice_analyses
                        ],
                    }
                )

    @property
    def mismatch_count(self) -> int:
        return self.missing_lattice_span + self.selected_raw_missing_from_lattice

    @property
    def valid(self) -> bool:
        return self.mismatch_count == 0

    def as_json(self) -> dict[str, Any]:
        return {
            "assertion": (
                "every genuine contextual selected raw analysis must occur on the exact same "
                "character span in the independently executed lattice pass"
            ),
            "status": "valid" if self.valid else "invalid",
            "valid_for_candidate_recall_bound": self.valid,
            "selected_genuine_tokens": self.selected_genuine_tokens,
            "contained_raw_analyses": self.contained_raw_analyses,
            "mismatch_count": self.mismatch_count,
            "missing_lattice_span": self.missing_lattice_span,
            "selected_raw_missing_from_lattice": self.selected_raw_missing_from_lattice,
            "sample_limit": self.sample_limit,
            "samples": self.samples,
        }


@dataclass(slots=True)
class NeuralResolutionStats:
    evaluated_gold_tokens: int = 0
    gold_without_one_to_one_qazmorph_alignment: int = 0
    one_to_one_aligned_tokens: int = 0
    no_genuine_candidates: int = 0
    deterministic_single_candidate: int = 0
    ambiguous_tokens_selected_by_neural: int = 0
    ambiguous_lexical_tokens_without_neural_span: int = 0
    ambiguous_nonlexical_tokens_outside_neural_scope: int = 0

    def add(self, predicted: PredictedToken | None) -> None:
        self.evaluated_gold_tokens += 1
        if predicted is None:
            self.gold_without_one_to_one_qazmorph_alignment += 1
            return
        self.one_to_one_aligned_tokens += 1
        genuine = tuple(
            analysis for analysis in predicted.analyses if analysis.source != "unknown"
        )
        if not genuine:
            self.no_genuine_candidates += 1
        elif len(genuine) == 1:
            self.deterministic_single_candidate += 1
        elif predicted.selected is not None and predicted.chosen is not None:
            self.ambiguous_tokens_selected_by_neural += 1
        elif predicted.kind in {"word", "number"}:
            # The neural ranker selects every ambiguous lexical token for which
            # it finds an exact Stanza/FST span. Remaining cases are therefore
            # operational span/tokenization mismatches.
            self.ambiguous_lexical_tokens_without_neural_span += 1
        else:
            self.ambiguous_nonlexical_tokens_outside_neural_scope += 1

    def as_json(self) -> dict[str, Any]:
        mismatch_total = (
            self.gold_without_one_to_one_qazmorph_alignment
            + self.ambiguous_lexical_tokens_without_neural_span
        )
        return {
            "definition": (
                "tokenization/span unresolved = no one-to-one gold/qazmorph alignment, or an "
                "aligned ambiguous word/number left unselected because no exact neural span matched"
            ),
            "evaluated_gold_tokens": self.evaluated_gold_tokens,
            "one_to_one_aligned_tokens": self.one_to_one_aligned_tokens,
            "gold_without_one_to_one_qazmorph_alignment": (
                self.gold_without_one_to_one_qazmorph_alignment
            ),
            "no_genuine_candidates": self.no_genuine_candidates,
            "deterministic_single_candidate": self.deterministic_single_candidate,
            "ambiguous_tokens_selected_by_neural": self.ambiguous_tokens_selected_by_neural,
            "ambiguous_lexical_tokens_without_neural_span": (
                self.ambiguous_lexical_tokens_without_neural_span
            ),
            "ambiguous_nonlexical_tokens_outside_neural_scope": (
                self.ambiguous_nonlexical_tokens_outside_neural_scope
            ),
            "unresolved_due_tokenization_or_span_mismatch": {
                "count": mismatch_total,
                "total": self.evaluated_gold_tokens,
                "value": (
                    mismatch_total / self.evaluated_gold_tokens
                    if self.evaluated_gold_tokens
                    else None
                ),
            },
        }


@dataclass(slots=True)
class SelectionStats:
    """Account for contextual certainty separately from top-1 correctness."""

    evaluated_gold_tokens: int = 0
    gold_without_one_to_one_alignment: int = 0
    one_to_one_aligned_tokens: int = 0
    no_genuine_candidates: int = 0
    deterministic_single_candidate: int = 0
    ambiguous_selected: int = 0
    ambiguous_unresolved: int = 0

    def add(self, predicted: PredictedToken | None) -> None:
        self.evaluated_gold_tokens += 1
        if predicted is None:
            self.gold_without_one_to_one_alignment += 1
            return
        self.one_to_one_aligned_tokens += 1
        genuine = tuple(
            analysis for analysis in predicted.analyses if analysis.source != "unknown"
        )
        if not genuine:
            self.no_genuine_candidates += 1
        elif len(genuine) == 1:
            self.deterministic_single_candidate += 1
        elif predicted.chosen is not None and predicted.chosen.source != "unknown":
            self.ambiguous_selected += 1
        else:
            self.ambiguous_unresolved += 1

    @staticmethod
    def _ratio(value: int, total: int) -> dict[str, int | float | None]:
        return {
            "count": value,
            "total": total,
            "value": value / total if total else None,
        }

    def as_json(self) -> dict[str, Any]:
        selected = self.deterministic_single_candidate + self.ambiguous_selected
        ambiguous = self.ambiguous_selected + self.ambiguous_unresolved
        return {
            "definition": (
                "a selected analysis is either the only genuine candidate or an explicit "
                "contextual choice; unknown placeholders and unresolved ambiguity are abstentions"
            ),
            "evaluated_gold_tokens": self.evaluated_gold_tokens,
            "one_to_one_aligned_tokens": self.one_to_one_aligned_tokens,
            "gold_without_one_to_one_alignment": self.gold_without_one_to_one_alignment,
            "no_genuine_candidates": self.no_genuine_candidates,
            "deterministic_single_candidate": self.deterministic_single_candidate,
            "ambiguous_selected": self.ambiguous_selected,
            "ambiguous_unresolved": self.ambiguous_unresolved,
            "selected_coverage_aligned": self._ratio(
                selected, self.one_to_one_aligned_tokens
            ),
            "selected_coverage_end_to_end": self._ratio(
                selected, self.evaluated_gold_tokens
            ),
            "ambiguous_selection_coverage": self._ratio(
                self.ambiguous_selected, ambiguous
            ),
        }


@dataclass(slots=True)
class EvaluationStats:
    sentences: int = 0
    gold_tokens: int = 0
    evaluated_tokens: int = 0
    punctuation_tokens_excluded: int = 0
    multiword_tokens: int = 0
    empty_nodes: int = 0
    sentences_using_text_comment: int = 0
    candidate_alignment: AlignmentCounts = field(default_factory=AlignmentCounts)
    contextual_alignment: AlignmentCounts = field(default_factory=AlignmentCounts)
    candidate_alignment_diagnostics: AlignmentDiagnostics = field(
        default_factory=AlignmentDiagnostics
    )
    contextual_alignment_diagnostics: AlignmentDiagnostics = field(
        default_factory=AlignmentDiagnostics
    )
    candidate_end_to_end: MetricSet = field(default_factory=MetricSet)
    candidate_aligned_only: MetricSet = field(default_factory=MetricSet)
    contextual_end_to_end: MetricSet = field(default_factory=MetricSet)
    contextual_aligned_only: MetricSet = field(default_factory=MetricSet)
    contextual_selected_only: MetricSet = field(default_factory=MetricSet)
    neural_projected_end_to_end: MetricSet = field(default_factory=MetricSet)
    neural_projected_aligned_only: MetricSet = field(default_factory=MetricSet)
    neural_projected_selected_only: MetricSet = field(default_factory=MetricSet)
    contextual_selection: SelectionStats = field(default_factory=SelectionStats)
    selected_raw_containment: SelectedRawContainment = field(
        default_factory=SelectedRawContainment
    )
    coverage: CoverageStats = field(default_factory=CoverageStats)
    neural_resolution: NeuralResolutionStats = field(default_factory=NeuralResolutionStats)


def _nfc(value: str) -> str:
    return unicodedata.normalize("NFC", value)


def _alignment_key(value: str) -> str:
    value = _nfc(value).casefold().translate(ALIGNMENT_APOSTROPHES).translate(ALIGNMENT_DASHES)
    return "".join(char for char in value if not char.isspace())


def _lemma_key(value: str, *, case_sensitive: bool) -> str:
    value = _nfc(value)
    return value if case_sensitive else value.casefold()


def _parse_features(value: str, *, source: Path, line_number: int) -> tuple[tuple[str, str], ...]:
    if value == "_":
        return ()
    features: dict[str, str] = {}
    for item in value.split("|"):
        if "=" not in item:
            raise EvaluationError(f"{source}:{line_number}: invalid FEATS item {item!r}")
        key, feature_value = item.split("=", 1)
        if not key or not feature_value:
            raise EvaluationError(f"{source}:{line_number}: invalid FEATS item {item!r}")
        if key in features:
            raise EvaluationError(f"{source}:{line_number}: duplicate FEATS key {key!r}")
        features[key] = feature_value
    return tuple(sorted(features.items()))


def _misc_map(value: str) -> dict[str, str | None]:
    if value == "_":
        return {}
    result: dict[str, str | None] = {}
    for item in value.split("|"):
        if "=" in item:
            key, item_value = item.split("=", 1)
            result[key] = item_value
        else:
            result[item] = None
    return result


def _decode_ud_spaces(value: str) -> str:
    replacements = {"s": " ", "n": "\n", "t": "\t", "r": "\r", "p": "|", "\\": "\\"}
    result: list[str] = []
    index = 0
    while index < len(value):
        if value[index] == "\\" and index + 1 < len(value):
            result.append(replacements.get(value[index + 1], value[index + 1]))
            index += 2
        else:
            result.append(value[index])
            index += 1
    return "".join(result)


def _reconstruct_text(tokens: Sequence[GoldToken], multiwords: Sequence[SurfaceToken]) -> str:
    multiword_by_start = {token.start_id: token for token in multiwords}
    surface: list[tuple[str, str]] = []
    index = 0
    while index < len(tokens):
        token = tokens[index]
        multiword = multiword_by_start.get(token.token_id)
        if multiword is not None:
            surface.append((multiword.form, multiword.misc))
            while index < len(tokens) and tokens[index].token_id <= multiword.end_id:
                index += 1
            continue
        surface.append((token.form, token.misc))
        index += 1

    chunks: list[str] = []
    previous_misc: dict[str, str | None] | None = None
    for surface_index, (form, misc_value) in enumerate(surface):
        misc = _misc_map(misc_value)
        if surface_index == 0:
            if misc.get("SpacesBefore") is not None:
                chunks.append(_decode_ud_spaces(str(misc["SpacesBefore"])))
        elif misc.get("SpacesBefore") is not None:
            chunks.append(_decode_ud_spaces(str(misc["SpacesBefore"])))
        elif previous_misc is not None and previous_misc.get("SpacesAfter") is not None:
            chunks.append(_decode_ud_spaces(str(previous_misc["SpacesAfter"])))
        elif previous_misc is None or previous_misc.get("SpaceAfter") != "No":
            chunks.append(" ")
        chunks.append(form)
        previous_misc = misc
    if previous_misc is not None and previous_misc.get("SpacesAfter") is not None:
        chunks.append(_decode_ud_spaces(str(previous_misc["SpacesAfter"])))
    return _nfc("".join(chunks))


def iter_conllu(path: Path) -> Iterator[GoldSentence]:
    comments: dict[str, str] = {}
    tokens: list[GoldToken] = []
    multiwords: list[SurfaceToken] = []
    empty_nodes = 0
    ordinal = 0

    def flush() -> GoldSentence | None:
        nonlocal comments, tokens, multiwords, empty_nodes, ordinal
        if not tokens:
            comments = {}
            multiwords = []
            empty_nodes = 0
            return None
        ordinal += 1
        text_comment = comments.get("text")
        text = _nfc(text_comment) if text_comment is not None else _reconstruct_text(tokens, multiwords)
        sentence = GoldSentence(
            source=path,
            ordinal=ordinal,
            sent_id=comments.get("sent_id", f"{path.name}:{ordinal}"),
            text=text,
            tokens=tuple(tokens),
            multiword_tokens=len(multiwords),
            empty_nodes=empty_nodes,
            used_text_comment=text_comment is not None,
            multiword_spans=tuple(multiwords),
        )
        comments = {}
        tokens = []
        multiwords = []
        empty_nodes = 0
        return sentence

    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        for line_number, raw_line in enumerate(handle, start=1):
            line = raw_line.rstrip("\r\n")
            if not line:
                sentence = flush()
                if sentence is not None:
                    yield sentence
                continue
            if line.startswith("#"):
                comment = line[1:].strip()
                if "=" in comment:
                    key, value = comment.split("=", 1)
                    comments[key.strip()] = value.lstrip()
                continue

            columns = line.split("\t")
            if len(columns) != 10:
                raise EvaluationError(
                    f"{path}:{line_number}: expected 10 tab-separated columns, got {len(columns)}"
                )
            token_id = columns[0]
            if "-" in token_id:
                try:
                    start_text, end_text = token_id.split("-", 1)
                    start_id, end_id = int(start_text), int(end_text)
                except ValueError as exc:
                    raise EvaluationError(
                        f"{path}:{line_number}: invalid multiword token ID {token_id!r}"
                    ) from exc
                multiwords.append(SurfaceToken(start_id, end_id, columns[1], columns[9]))
                continue
            if "." in token_id:
                empty_nodes += 1
                continue
            try:
                integer_id = int(token_id)
            except ValueError as exc:
                raise EvaluationError(f"{path}:{line_number}: invalid token ID {token_id!r}") from exc
            tokens.append(
                GoldToken(
                    token_id=integer_id,
                    form=_nfc(columns[1]),
                    lemma=_nfc(columns[2]),
                    upos=columns[3].upper(),
                    features=_parse_features(columns[5], source=path, line_number=line_number),
                    misc=columns[9],
                )
            )

    sentence = flush()
    if sentence is not None:
        yield sentence


def _predicted_tokens(document: Any) -> list[PredictedToken]:
    return [
        PredictedToken(
            token.text,
            token.kind,
            tuple(token.analyses),
            token.chosen,
            token.selected,
            token.start,
            token.end,
        )
        for token in document.tokens
        if token.text and not token.text.isspace() and token.kind != "space"
    ]


def align_tokens(
    gold: Sequence[GoldToken],
    predicted: Sequence[PredictedToken],
    *,
    max_group: int,
    multiword_spans: Sequence[SurfaceToken] = (),
) -> AlignmentResult:
    """Globally align token sequences, admitting bounded splits and merges.

    The objective first minimizes unaligned tokens, then the number of tokens
    participating in grouped matches, then unnecessarily broad many-to-many
    groups, and finally normalization-only matches.  Only one-to-one matches
    are returned as directly scorable; split/merge groups remain explicit,
    non-scorable operations in the result.
    """

    gold_count, predicted_count = len(gold), len(predicted)
    infinity = (10**12, 10**12, 10**12, 10**12)
    best: list[list[tuple[int, int, int, int]]] = [
        [infinity for _ in range(predicted_count + 1)] for _ in range(gold_count + 1)
    ]
    back: list[list[tuple[int, int, str, int, int, str] | None]] = [
        [None for _ in range(predicted_count + 1)] for _ in range(gold_count + 1)
    ]
    best[0][0] = (0, 0, 0, 0)

    gold_id_to_index = {token.token_id: index for index, token in enumerate(gold)}
    indexed_multiwords: list[tuple[int, int, SurfaceToken]] = []
    multiword_by_start: dict[int, tuple[int, SurfaceToken]] = {}
    for span in multiword_spans:
        start_index = gold_id_to_index.get(span.start_id)
        end_index = gold_id_to_index.get(span.end_id)
        if start_index is None or end_index is None or start_index > end_index:
            continue
        end_exclusive = end_index + 1
        indexed_multiwords.append((start_index, end_exclusive, span))
        multiword_by_start[start_index] = (end_exclusive, span)

    def gold_surface_key(start: int, size: int) -> str | None:
        """Return the UD surface key, rejecting ranges that cut an MWT row."""

        end = start + size
        for mwt_start, mwt_end, _span in indexed_multiwords:
            overlaps = start < mwt_end and mwt_start < end
            contains = start <= mwt_start and mwt_end <= end
            if overlaps and not contains:
                return None

        chunks: list[str] = []
        cursor = start
        while cursor < end:
            multiword = multiword_by_start.get(cursor)
            if multiword is not None and multiword[0] <= end:
                cursor_end, span = multiword
                chunks.append(_alignment_key(span.form))
                cursor = cursor_end
            else:
                chunks.append(_alignment_key(gold[cursor].form))
                cursor += 1
        return "".join(chunks)

    gold_group_keys: dict[tuple[int, int], str] = {}
    predicted_group_keys: dict[tuple[int, int], str] = {}
    for start in range(gold_count):
        for size in range(1, min(max_group, gold_count - start) + 1):
            joined = gold_surface_key(start, size)
            if joined is not None:
                gold_group_keys[(start, size)] = joined
    for start in range(predicted_count):
        joined = ""
        for size in range(1, min(max_group, predicted_count - start) + 1):
            joined += _alignment_key(predicted[start + size - 1].text)
            predicted_group_keys[(start, size)] = joined

    def relax(
        old_i: int,
        old_j: int,
        new_i: int,
        new_j: int,
        increment: tuple[int, int, int, int],
        operation: tuple[int, int, str, int, int, str],
    ) -> None:
        base = best[old_i][old_j]
        candidate = tuple(base[index] + increment[index] for index in range(4))
        if candidate < best[new_i][new_j]:
            best[new_i][new_j] = candidate
            back[new_i][new_j] = operation

    for gold_index in range(gold_count + 1):
        for predicted_index in range(predicted_count + 1):
            if best[gold_index][predicted_index] == infinity:
                continue
            max_gold_group = min(max_group, gold_count - gold_index)
            max_predicted_group = min(max_group, predicted_count - predicted_index)
            for gold_size in range(1, max_gold_group + 1):
                gold_key = gold_group_keys.get((gold_index, gold_size))
                if not gold_key:
                    continue
                for predicted_size in range(1, max_predicted_group + 1):
                    if gold_key != predicted_group_keys[(predicted_index, predicted_size)]:
                        continue
                    if gold_size == predicted_size == 1:
                        exact = _nfc(gold[gold_index].form) == _nfc(predicted[predicted_index].text)
                        match_kind = "exact" if exact else "normalized"
                        increment = (0, 0, 0, 0 if exact else 1)
                    else:
                        match_kind = "group"
                        increment = (
                            0,
                            gold_size + predicted_size,
                            (gold_size - 1) * (predicted_size - 1),
                            0,
                        )
                    relax(
                        gold_index,
                        predicted_index,
                        gold_index + gold_size,
                        predicted_index + predicted_size,
                        increment,
                        (
                            gold_index,
                            predicted_index,
                            "match",
                            gold_size,
                            predicted_size,
                            match_kind,
                        ),
                    )
            if gold_index < gold_count:
                relax(
                    gold_index,
                    predicted_index,
                    gold_index + 1,
                    predicted_index,
                    (1, 0, 0, 0),
                    (gold_index, predicted_index, "skip_gold", 1, 0, ""),
                )
            if predicted_index < predicted_count:
                relax(
                    gold_index,
                    predicted_index,
                    gold_index,
                    predicted_index + 1,
                    (1, 0, 0, 0),
                    (gold_index, predicted_index, "skip_predicted", 0, 1, ""),
                )

    raw_operations: list[tuple[int, int, str, int, int, str]] = []
    cursor_i, cursor_j = gold_count, predicted_count
    while cursor_i or cursor_j:
        operation = back[cursor_i][cursor_j]
        if operation is None:
            raise EvaluationError("internal alignment failure")
        raw_operations.append(operation)
        cursor_i, cursor_j = operation[0], operation[1]
    raw_operations.reverse()
    operations = tuple(AlignmentOperation(*operation) for operation in raw_operations)

    direct: dict[int, int] = {}
    counts = AlignmentCounts(sentences=1, gold_tokens=gold_count, predicted_tokens=predicted_count)
    for operation in operations:
        if operation.kind == "skip_gold":
            counts.unaligned_gold_tokens += 1
        elif operation.kind == "skip_predicted":
            counts.unaligned_predicted_tokens += 1
        elif operation.gold_size == operation.predicted_size == 1:
            direct[operation.gold_start] = operation.predicted_start
            if operation.match_kind == "exact":
                counts.one_to_one_exact += 1
            else:
                counts.one_to_one_normalized += 1
        else:
            counts.grouped_operations += 1
            counts.grouped_gold_tokens += operation.gold_size
            counts.grouped_predicted_tokens += operation.predicted_size
    return AlignmentResult(direct=direct, counts=counts, operations=operations)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            block = handle.read(1024 * 1024)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def _file_identity(path: Path) -> dict[str, Any]:
    """Capture the immutable fields used to bind a run to one exact file."""

    resolved = path.resolve()
    return {
        "path": str(resolved),
        "bytes": resolved.stat().st_size,
        "sha256": _sha256(resolved),
    }


def _rehash_inputs(
    snapshots: Sequence[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Rehash every input, returning all verifications and all mismatches.

    This deliberately does not stop on the first mismatch: every corpus file is
    re-read even when an earlier file changed or disappeared.
    """

    verifications: list[dict[str, Any]] = []
    mismatches: list[dict[str, Any]] = []
    for snapshot in snapshots:
        expected = {
            "path": str(snapshot["path"]),
            "bytes": int(snapshot["bytes"]),
            "sha256": str(snapshot["sha256"]),
        }
        try:
            observed = _file_identity(Path(expected["path"]))
            unchanged = observed == expected
            error = None
        except OSError as exc:
            observed = None
            unchanged = False
            error = f"{type(exc).__name__}: {exc}"
        item = {
            "path": expected["path"],
            "unchanged": unchanged,
            "expected": expected,
            "observed": observed,
            "error": error,
        }
        verifications.append(item)
        if not unchanged:
            mismatches.append(item)
    return verifications, mismatches


def _software_provenance() -> dict[str, Any]:
    """Hash the exact evaluator and importable project sources used in a run."""

    paths = [Path(__file__).resolve(), *sorted((SOURCE_ROOT / "qazmorph").glob("*.py"))]
    files = {
        path.relative_to(PROJECT_ROOT).as_posix(): {
            "bytes": path.stat().st_size,
            "sha256": _sha256(path),
        }
        for path in paths
    }
    identity = json.dumps(
        files, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return {
        "files": files,
        "bundle_sha256": hashlib.sha256(identity).hexdigest(),
    }


def _expand_inputs(values: Sequence[str]) -> list[Path]:
    paths: list[Path] = []
    seen: set[Path] = set()
    for value in values:
        candidate = Path(value).expanduser()
        if not candidate.exists():
            raise EvaluationError(f"input does not exist: {candidate}")
        discovered = sorted(candidate.rglob("*.conllu")) if candidate.is_dir() else [candidate]
        if candidate.is_dir() and not discovered:
            raise EvaluationError(f"directory contains no .conllu files: {candidate}")
        for path in discovered:
            resolved = path.resolve()
            if resolved not in seen:
                paths.append(resolved)
                seen.add(resolved)
    return paths


def _resource_provenance(analyzer: Any) -> dict[str, Any]:
    manifest = dict(analyzer.backend.manifest)
    resource_dir = Path(analyzer.backend.resource_dir).resolve()
    manifest_path = resource_dir / "manifest.json"
    manifest_files = manifest.get("files", {})
    artifacts = {
        str(name): _file_identity(resource_dir / str(name))
        for name in sorted(manifest_files)
    }
    return {
        "resource_dir": str(resource_dir),
        "resource_version": analyzer.backend.resource_version,
        "manifest": manifest,
        "manifest_file": _file_identity(manifest_path),
        "resource_artifacts": artifacts,
        "backend_runtime": analyzer.backend.runtime_provenance(),
    }


def _require_matching_resource_provenance(
    lattice: dict[str, Any], contextual: dict[str, Any] | None, *, stage: str
) -> None:
    if contextual is not None and contextual != lattice:
        raise EvaluationError(
            f"lattice and contextual analyzers have different full resource "
            f"provenance at {stage}"
        )


def _runtime_validity(
    named_runtimes: dict[str, dict[str, Any] | None]
) -> dict[str, Any]:
    active = {name: value for name, value in named_runtimes.items() if value is not None}
    reasons = [
        f"{name}: {reason}"
        for name, value in sorted(active.items())
        for reason in value.get("non_official_reasons", ())
    ]
    official = bool(active) and all(value.get("official") is True for value in active.values())
    if not official and not reasons:
        reasons.append("one or more analyzer backends did not attest an official verified runtime")
    return {
        "official_runtime": official,
        "valid_for_official_result_claims": official,
        "non_official_reasons": reasons,
        "backend_status": {
            name: {
                "official": value.get("official"),
                "verified": value.get("verified"),
            }
            for name, value in sorted(active.items())
        },
    }
GUESSER_COUNTERS = (
    "cache_hits",
    "cache_misses",
    "lookup_queries",
    "prefilter_skips",
    "unsafe_resource_skips",
    "timeouts",
    "failures",
    "worker_starts",
    "cap_aborts",
    "cycle_truncations",
    "idle_restarts",
    "protocol_restarts",
)


def _guesser_run_diagnostics(
    initial: dict[str, int], final: dict[str, int]
) -> dict[str, Any]:
    counters = {
        name: {
            "initial": int(initial.get(name, 0)),
            "final": int(final.get(name, 0)),
            "during_run": int(final.get(name, 0)) - int(initial.get(name, 0)),
        }
        for name in GUESSER_COUNTERS
    }
    return {
        "counters": counters,
        "cache_entries_initial": int(initial.get("cache_entries", 0)),
        "cache_entries_final": int(final.get("cache_entries", 0)),
        "productive_resource_safe": bool(final.get("productive_resource_safe", 1)),
    }


def _oov_lattice_completeness(
    *, guesser_enabled: bool, diagnostics: dict[str, Any], guess_limit: int
) -> dict[str, Any]:
    counters = diagnostics["counters"]
    incidents = {
        name: counters[name]["during_run"]
        for name in (
            "timeouts",
            "failures",
            "cap_aborts",
            "cycle_truncations",
            "unsafe_resource_skips",
        )
    }
    incidents["unsafe_resource_configuration"] = int(
        not diagnostics.get("productive_resource_safe", True)
    )
    complete = guesser_enabled and not any(incidents.values())
    return {
        "scope": (
            "operational completeness of the bounded productive OOV lookup under the "
            "configured guess_limit; this is not a claim that every linguistically possible "
            "analysis is enumerated; response caps, timeouts, failures, and HFST cyclic "
            "truncation markers and a disabled unsafe legacy resource are all "
            "incompleteness events"
        ),
        "guesser_enabled": guesser_enabled,
        "guess_limit": guess_limit,
        "status": (
            "not_applicable_disabled"
            if not guesser_enabled
            else ("complete" if complete else "incomplete")
        ),
        "complete": complete if guesser_enabled else None,
        "incompleteness_events": incidents,
        "lookup_queries": counters["lookup_queries"]["during_run"],
        "prefilter_skips": counters["prefilter_skips"]["during_run"],
    }


def _close_analyzers(*analyzers: Any | None) -> list[str]:
    """Close each distinct initialized analyzer and return bounded errors."""

    errors: list[str] = []
    seen: set[int] = set()
    for analyzer in analyzers:
        if analyzer is None or id(analyzer) in seen:
            continue
        seen.add(id(analyzer))
        try:
            analyzer.close()
        except Exception as exc:  # Closing must not hide the primary evaluation error.
            errors.append(f"{type(exc).__name__}: {exc}")
    return errors


def _manifest_object(path: Path, label: str) -> tuple[dict[str, Any] | None, str | None]:
    if not path.is_file():
        return None, f"{label} is missing: {path}"
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        return None, f"cannot read {label} {path}: {type(exc).__name__}: {exc}"
    if not isinstance(value, dict):
        return None, f"{label} root is not an object: {path}"
    return value, None


def _device_family(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = value.casefold()
    if normalized.startswith("cuda"):
        return "gpu"
    if normalized.startswith("cpu"):
        return "cpu"
    return None


def _visible_distribution_versions() -> dict[str, str | list[str]]:
    observed: dict[str, set[str]] = {}
    for distribution in importlib_metadata.distributions():
        raw_name = distribution.metadata.get("Name")
        if not raw_name:
            continue
        name = raw_name.lower().replace("_", "-").replace(".", "-")
        observed.setdefault(name, set()).add(distribution.version)
    return {
        name: next(iter(versions)) if len(versions) == 1 else sorted(versions)
        for name, versions in sorted(observed.items())
    }


def _processor_device_inventory(pipeline: Any) -> dict[str, dict[str, Any]]:
    """Classify actual model parameters separately from parameterless processors."""

    inventory: dict[str, dict[str, Any]] = {}
    processors = getattr(pipeline, "processors", {}) if pipeline is not None else {}
    if not isinstance(processors, dict):
        return inventory
    for name, processor in sorted(processors.items()):
        candidates: list[Any] = []
        direct_model = getattr(processor, "model", None)
        if direct_model is not None:
            candidates.append(direct_model)
        for attribute in ("trainer", "_trainer"):
            trainer = getattr(processor, attribute, None)
            model = getattr(trainer, "model", None) if trainer is not None else None
            if model is not None and all(model is not candidate for candidate in candidates):
                candidates.append(model)

        devices: set[str] = set()
        parameter_count = 0
        errors: list[str] = []
        for model in candidates:
            parameters = getattr(model, "parameters", None)
            if not callable(parameters):
                errors.append("model exposes no parameters() iterator")
                continue
            try:
                for parameter in parameters():
                    parameter_count += 1
                    devices.add(str(parameter.device))
            except (AttributeError, RuntimeError, TypeError) as exc:
                errors.append(f"{type(exc).__name__}: {exc}")

        if errors:
            status = "unresolved_model_device"
        elif devices:
            status = "model_parameters_observed"
        elif candidates and not errors and parameter_count == 0:
            status = "verified_parameterless_model"
        elif not candidates:
            status = "unresolved_model_device"
        else:
            status = "unresolved_model_device"
        inventory[str(name)] = {
            "devices": sorted(devices) or None,
            "parameter_count": parameter_count,
            "status": status,
            "errors": errors,
        }
    return inventory


def _neural_device_verification(
    *,
    requested_device: str,
    pipeline_device: str | None,
    processor_model_devices: dict[str, list[str] | None],
    cuda_available: bool,
    processor_device_status: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Verify requested, pipeline, and processor parameter devices agree."""

    reasons: list[str] = []
    pipeline_family = _device_family(pipeline_device)
    if pipeline_family is None:
        reasons.append(f"pipeline device is unavailable or unsupported: {pipeline_device!r}")
    expected_family = (
        pipeline_family if requested_device == "auto" else requested_device
    )
    if expected_family not in {"cpu", "gpu"}:
        reasons.append(f"requested neural device cannot be resolved: {requested_device!r}")
    elif pipeline_family != expected_family:
        reasons.append(
            f"requested device {requested_device!r} resolved to {expected_family!r}, "
            f"but pipeline uses {pipeline_device!r}"
        )
    if expected_family == "gpu" and not cuda_available:
        reasons.append("GPU execution was requested/resolved but CUDA is unavailable")

    processor_families: dict[str, list[str] | None] = {}
    if not processor_model_devices:
        reasons.append("pipeline exposes no processor model devices")
    for name, devices in sorted(processor_model_devices.items()):
        status = (processor_device_status or {}).get(name)
        if not devices:
            processor_families[name] = None
            if status not in {
                "verified_parameterless_model",
            }:
                reasons.append(
                    f"processor {name!r} exposes no verifiable model parameter device"
                )
            continue
        if status is not None and status != "model_parameters_observed":
            reasons.append(
                f"processor {name!r} model-device inspection is incomplete: {status!r}"
            )
        unknown_devices = sorted(
            device for device in devices if _device_family(device) is None
        )
        if unknown_devices:
            reasons.append(
                f"processor {name!r} exposes unsupported devices {unknown_devices!r}"
            )
        families = sorted(
            {family for device in devices if (family := _device_family(device)) is not None}
        )
        processor_families[name] = families or None
        if len(families) != 1 or families[0] != expected_family:
            reasons.append(
                f"processor {name!r} devices {devices!r} do not agree with "
                f"resolved device {expected_family!r}"
            )

    return {
        "verified": not reasons,
        "requested_device": requested_device,
        "resolved_device_family": expected_family,
        "pipeline_device": pipeline_device,
        "pipeline_device_family": pipeline_family,
        "processor_model_devices": processor_model_devices,
        "processor_device_status": processor_device_status,
        "processor_device_families": processor_families,
        "reasons": reasons,
    }


def _neural_manifest_verification(
    model_dir: Path, environment_manifest: Path
) -> dict[str, Any]:
    """Run the checked-in lock/model/project/live-environment verifier."""

    verifier = (PROJECT_ROOT / "scripts" / "write_neural_manifest.py").resolve()
    lock_path = (PROJECT_ROOT / "scripts" / "neural_assets.lock.json").resolve()
    model_manifest_path = model_dir / "manifest.json"
    reasons: list[str] = []
    model_manifest, model_error = _manifest_object(
        model_manifest_path, "neural model manifest"
    )
    environment, environment_error = _manifest_object(
        environment_manifest, "neural environment manifest"
    )
    if model_error:
        reasons.append(model_error)
    if environment_error:
        reasons.append(environment_error)

    selected_model_bundle_id = (
        model_manifest.get("bundle_id") if model_manifest is not None else None
    )
    environment_model_bundle_id = (
        environment.get("model_bundle_id") if environment is not None else None
    )
    environment_bundle_id = (
        environment.get("bundle_id") if environment is not None else None
    )
    for label, value in (
        ("selected model bundle", selected_model_bundle_id),
        ("environment model bundle", environment_model_bundle_id),
        ("environment bundle", environment_bundle_id),
    ):
        if not isinstance(value, str) or len(value) != 64:
            reasons.append(f"{label} identity is missing or malformed")
    if (
        isinstance(selected_model_bundle_id, str)
        and isinstance(environment_model_bundle_id, str)
        and selected_model_bundle_id != environment_model_bundle_id
    ):
        reasons.append(
            "selected model bundle does not match the live environment manifest"
        )

    verifier_record = _file_identity(verifier) if verifier.is_file() else None
    lock_record = _file_identity(lock_path) if lock_path.is_file() else None
    if verifier_record is None:
        reasons.append(f"checked-in neural verifier is missing: {verifier}")
    if lock_record is None:
        reasons.append(f"checked-in neural lock is missing: {lock_path}")

    command = [
        sys.executable,
        str(verifier),
        "--lock",
        str(lock_path),
        "--model-dir",
        str(model_dir),
        "--project-root",
        str(PROJECT_ROOT),
        "--verify-environment-manifest",
    ]
    returncode: int | None = None
    stdout = ""
    diagnostic: str | None = None
    if verifier_record is not None and lock_record is not None and model_dir.is_dir():
        try:
            completed = subprocess.run(
                command,
                text=True,
                encoding="utf-8",
                capture_output=True,
                check=False,
                timeout=300,
            )
            returncode = int(completed.returncode)
            stdout = completed.stdout.strip()
            if returncode:
                diagnostic = (completed.stderr.strip() or stdout or "no diagnostic")[-2000:]
                reasons.append(
                    f"checked-in neural verifier exited with {returncode}: {diagnostic}"
                )
        except (OSError, subprocess.TimeoutExpired) as exc:
            diagnostic = f"{type(exc).__name__}: {exc}"
            reasons.append(f"checked-in neural verifier could not complete: {diagnostic}")
    else:
        reasons.append("checked-in neural verifier was not runnable")

    if (
        returncode == 0
        and isinstance(environment_bundle_id, str)
        and stdout.splitlines()[-1:] != [environment_bundle_id]
    ):
        reasons.append("neural verifier output does not name the live environment bundle")

    return {
        "verified": not reasons,
        "reasons": reasons,
        "selected_model_bundle_id": selected_model_bundle_id,
        "environment_model_bundle_id": environment_model_bundle_id,
        "environment_bundle_id": environment_bundle_id,
        "verifier": verifier_record,
        "lock": lock_record,
        "command": command,
        "returncode": returncode,
        "stdout": stdout[-1000:],
        "diagnostic": diagnostic,
    }


def _apply_neural_validity(
    validity: dict[str, Any], neural: dict[str, Any]
) -> dict[str, Any]:
    combined = dict(validity)
    verification = neural["verification"]
    reasons = [
        f"neural: {reason}" for reason in verification.get("reasons", ())
    ]
    verified = verification.get("verified") is True
    combined["neural_status"] = {
        "verified": verified,
        "selected_model_bundle_id": verification.get("selected_model_bundle_id"),
        "manifest_verified": verification["manifest"].get("verified") is True,
        "device_verified": verification["device"].get("verified") is True,
    }
    combined["non_official_reasons"] = [
        *combined.get("non_official_reasons", ()),
        *reasons,
    ]
    combined["official_runtime"] = bool(
        combined.get("official_runtime") is True and verified
    )
    combined["valid_for_official_result_claims"] = bool(
        combined.get("valid_for_official_result_claims") is True and verified
    )
    return combined


def _neural_resource_provenance(
    analyzer: Any,
    explicit_model_dir: str | None,
    *,
    requested_device: str,
) -> dict[str, Any]:
    model_dir = (
        Path(explicit_model_dir).expanduser().resolve()
        if explicit_model_dir
        else (analyzer.backend.runtime_dir / "neural" / "stanza").resolve()
    )
    resources_json = model_dir / "resources.json"
    model_manifest = model_dir / "manifest.json"
    model_files: dict[str, dict[str, int | str]] = {}
    for path in sorted(model_dir.rglob("*")):
        if path.is_file():
            model_files[path.relative_to(model_dir).as_posix()] = {
                "bytes": path.stat().st_size,
                "sha256": _sha256(path),
            }
    environment_manifest = Path(sys.prefix) / "qazmorph-neural-environment.json"
    try:
        stanza_version = importlib_metadata.version("stanza")
    except importlib_metadata.PackageNotFoundError:
        stanza_version = None
    try:
        torch_version_from_metadata = importlib_metadata.version("torch")
    except importlib_metadata.PackageNotFoundError:
        torch_version_from_metadata = None

    torch_runtime: dict[str, Any]
    try:
        import torch

        cuda_available = bool(torch.cuda.is_available())
        torch_runtime = {
            "module_version": str(torch.__version__),
            "distribution_version": torch_version_from_metadata,
            "cuda_runtime_version": torch.version.cuda,
            "cuda_available": cuda_available,
            "cuda_device_count": int(torch.cuda.device_count()) if cuda_available else 0,
            "cudnn_version": (
                torch.backends.cudnn.version()
                if getattr(torch.backends, "cudnn", None) is not None
                else None
            ),
        }
    except (ImportError, RuntimeError) as exc:
        torch = None  # type: ignore[assignment]
        cuda_available = False
        torch_runtime = {
            "module_version": None,
            "distribution_version": torch_version_from_metadata,
            "cuda_runtime_version": None,
            "cuda_available": False,
            "cuda_device_count": 0,
            "cudnn_version": None,
            "error": f"{type(exc).__name__}: {exc}",
        }

    ranker = getattr(analyzer, "neural_ranker", None)
    pipeline = getattr(ranker, "pipeline", None)
    pipeline_device = (
        str(getattr(pipeline, "device"))
        if pipeline is not None and getattr(pipeline, "device", None) is not None
        else None
    )
    processor_inventory = _processor_device_inventory(pipeline)
    processor_model_devices = {
        name: item["devices"] for name, item in processor_inventory.items()
    }
    processor_device_status = {
        name: str(item["status"]) for name, item in processor_inventory.items()
    }

    selected_gpu = None
    if (
        torch is not None
        and cuda_available
        and pipeline_device is not None
        and pipeline_device.startswith("cuda")
    ):
        try:
            device_index = (
                int(pipeline_device.split(":", 1)[1])
                if ":" in pipeline_device
                else int(torch.cuda.current_device())
            )
            selected_gpu = {
                "index": device_index,
                "name": torch.cuda.get_device_name(device_index),
                "capability": list(torch.cuda.get_device_capability(device_index)),
            }
        except (RuntimeError, ValueError, IndexError) as exc:
            selected_gpu = {"error": f"{type(exc).__name__}: {exc}"}

    manifest_verification = _neural_manifest_verification(
        model_dir, environment_manifest
    )
    device_verification = _neural_device_verification(
        requested_device=requested_device,
        pipeline_device=pipeline_device,
        processor_model_devices=processor_model_devices,
        cuda_available=cuda_available,
        processor_device_status=processor_device_status,
    )
    verification_reasons = [
        *(f"manifest: {reason}" for reason in manifest_verification["reasons"]),
        *(f"device: {reason}" for reason in device_verification["reasons"]),
    ]
    return {
        "model_dir": str(model_dir),
        "resources_json": (
            {
                "path": str(resources_json),
                "bytes": resources_json.stat().st_size,
                "sha256": _sha256(resources_json),
            }
            if resources_json.is_file()
            else None
        ),
        "model_artifacts": {
            "files": model_files,
            "file_count": len(model_files),
            "total_bytes": sum(int(item["bytes"]) for item in model_files.values()),
        },
        "model_manifest": _file_identity(model_manifest) if model_manifest.is_file() else None,
        "environment": {
            "sys_prefix": str(Path(sys.prefix).resolve()),
            "manifest": (
                _file_identity(environment_manifest)
                if environment_manifest.is_file()
                else None
            ),
        },
        "runtime": {
            "python_executable": str(Path(sys.executable).resolve()),
            "python_prefix": str(Path(sys.prefix).resolve()),
            "visible_distribution_versions": _visible_distribution_versions(),
            "stanza_distribution_version": stanza_version,
            "torch": torch_runtime,
            "pipeline_device": pipeline_device,
            "processor_model_devices": processor_model_devices,
            "processor_device_inventory": processor_inventory,
            "selected_gpu": selected_gpu,
        },
        "verification": {
            "verified": not verification_reasons,
            "reasons": verification_reasons,
            "selected_model_bundle_id": manifest_verification.get(
                "selected_model_bundle_id"
            ),
            "manifest": manifest_verification,
            "device": device_verification,
        },
    }


def _evaluate_sentence(
    sentence: GoldSentence,
    *,
    lattice_analyzer: Any,
    contextual_analyzer: Any | None,
    stats: EvaluationStats,
    max_alignment_group: int,
    exclude_punct: bool,
    case_sensitive_lemmas: bool,
    top1_engine: str,
    contextual_disambiguate: bool,
) -> None:
    try:
        lattice_document = lattice_analyzer.analyze(sentence.text, disambiguate=False)
    except Exception as exc:  # Preserve corpus location around backend/tool errors.
        raise EvaluationError(
            f"lattice analysis failed for {sentence.source}:{sentence.sent_id}: {exc}"
        ) from exc
    lattice_tokens = _predicted_tokens(lattice_document)
    lattice_alignment = align_tokens(
        sentence.tokens,
        lattice_tokens,
        max_group=max_alignment_group,
        multiword_spans=sentence.multiword_spans,
    )
    stats.candidate_alignment.add(lattice_alignment.counts)
    stats.candidate_alignment_diagnostics.add(sentence, lattice_tokens, lattice_alignment)

    contextual_tokens: list[PredictedToken] = []
    contextual_alignment: AlignmentResult | None = None
    if contextual_analyzer is not None:
        try:
            contextual_document = contextual_analyzer.analyze(
                sentence.text, disambiguate=contextual_disambiguate
            )
        except Exception as exc:
            raise EvaluationError(
                f"contextual analysis failed for {sentence.source}:{sentence.sent_id}: {exc}"
            ) from exc
        contextual_tokens = _predicted_tokens(contextual_document)
        contextual_alignment = align_tokens(
            sentence.tokens,
            contextual_tokens,
            max_group=max_alignment_group,
            multiword_spans=sentence.multiword_spans,
        )
        stats.contextual_alignment.add(contextual_alignment.counts)
        stats.contextual_alignment_diagnostics.add(
            sentence, contextual_tokens, contextual_alignment
        )
        stats.selected_raw_containment.add(
            sentence, lattice_tokens, contextual_tokens
        )

    stats.sentences += 1
    stats.gold_tokens += len(sentence.tokens)
    stats.multiword_tokens += sentence.multiword_tokens
    stats.empty_nodes += sentence.empty_nodes
    stats.sentences_using_text_comment += int(sentence.used_text_comment)

    for gold_index, gold in enumerate(sentence.tokens):
        lattice_predicted_index = lattice_alignment.direct.get(gold_index)
        lattice_predicted = (
            lattice_tokens[lattice_predicted_index] if lattice_predicted_index is not None else None
        )
        stats.coverage.add_gold(gold, lattice_predicted)

        if exclude_punct and gold.upos == "PUNCT":
            stats.punctuation_tokens_excluded += 1
            continue
        stats.evaluated_tokens += 1
        lattice_analyses = lattice_predicted.analyses if lattice_predicted is not None else ()
        stats.candidate_end_to_end.add(
            gold, lattice_analyses, case_sensitive_lemmas=case_sensitive_lemmas
        )
        if lattice_predicted is not None:
            stats.candidate_aligned_only.add(
                gold, lattice_analyses, case_sensitive_lemmas=case_sensitive_lemmas
            )

        if contextual_alignment is None:
            continue
        contextual_predicted_index = contextual_alignment.direct.get(gold_index)
        contextual_predicted = (
            contextual_tokens[contextual_predicted_index]
            if contextual_predicted_index is not None
            else None
        )
        stats.contextual_selection.add(contextual_predicted)
        if top1_engine == "neural":
            stats.neural_resolution.add(contextual_predicted)
        contextual_analysis = contextual_predicted.chosen if contextual_predicted is not None else None
        top_one = (contextual_analysis,) if contextual_analysis is not None else ()
        stats.contextual_end_to_end.add(
            gold,
            top_one,
            case_sensitive_lemmas=case_sensitive_lemmas,
            contextual_projection=False,
        )
        if contextual_predicted is not None:
            stats.contextual_aligned_only.add(
                gold,
                top_one,
                case_sensitive_lemmas=case_sensitive_lemmas,
                contextual_projection=False,
            )
        if contextual_analysis is not None and contextual_analysis.source != "unknown":
            stats.contextual_selected_only.add(
                gold,
                (contextual_analysis,),
                case_sensitive_lemmas=case_sensitive_lemmas,
                contextual_projection=False,
            )
        if top1_engine == "neural":
            stats.neural_projected_end_to_end.add(
                gold,
                top_one,
                case_sensitive_lemmas=case_sensitive_lemmas,
                contextual_projection=True,
            )
            if contextual_predicted is not None:
                stats.neural_projected_aligned_only.add(
                    gold,
                    top_one,
                    case_sensitive_lemmas=case_sensitive_lemmas,
                    contextual_projection=True,
                )
            if contextual_analysis is not None and contextual_analysis.source != "unknown":
                stats.neural_projected_selected_only.add(
                    gold,
                    (contextual_analysis,),
                    case_sensitive_lemmas=case_sensitive_lemmas,
                    contextual_projection=True,
                )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Evaluate qazmorph lattice recall and contextual top-1 accuracy on existing "
            "UD CoNLL-U files. No data is downloaded."
        )
    )
    parser.add_argument("conllu", nargs="+", help="CoNLL-U file or directory (directories recurse)")
    parser.add_argument("--resource-dir", help="directory containing compiled qazmorph resources")
    parser.add_argument("--fixlist", help="optional qazmorph JSONL/TSV fixlist")
    parser.add_argument("--output", default="-", help="JSON output path (default: stdout)")
    parser.add_argument("--pretty", action="store_true", help="indent JSON output")
    parser.add_argument("--no-guesser", action="store_true", help="disable open-class OOV guessing")
    parser.add_argument("--guess-limit", type=int, default=8, metavar="N")
    parser.add_argument(
        "--ud-profile",
        choices=("universal", "ktb"),
        default="universal",
        help="UD projection profile (default: universal; ktb is compatibility-only)",
    )
    parser.add_argument(
        "--no-contextual",
        action="store_true",
        help="deprecated alias for --mode lattice",
    )
    parser.add_argument(
        "--mode",
        choices=("lattice", "cg", "neural"),
        default="cg",
        help="top-1 engine; lattice reports candidate recall only (default: cg)",
    )
    parser.add_argument(
        "--neural-model-dir",
        help="Stanza Kazakh model directory for --mode neural",
    )
    parser.add_argument(
        "--neural-device",
        choices=("auto", "cpu", "gpu"),
        default="auto",
        help="neural inference device (default: auto)",
    )
    parser.add_argument(
        "--exclude-punct",
        action="store_true",
        help="exclude UPOS=PUNCT from morphology metrics (alignment still includes it)",
    )
    parser.add_argument(
        "--case-sensitive-lemmas",
        action="store_true",
        help="compare lemmas after NFC only instead of NFC plus Unicode casefold",
    )
    parser.add_argument(
        "--max-alignment-group",
        type=int,
        default=4,
        metavar="N",
        help="largest gold/predicted split or merge considered (default: 4)",
    )
    parser.add_argument("--max-sentences", type=int, metavar="N", help="evaluate a deterministic prefix")
    parser.add_argument(
        "--progress-every",
        type=int,
        default=0,
        metavar="N",
        help="write a progress line to stderr every N sentences (default: disabled)",
    )
    return parser


def _validate_args(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    if args.guess_limit < 1:
        parser.error("--guess-limit must be positive")
    if args.max_alignment_group < 1:
        parser.error("--max-alignment-group must be positive")
    if args.max_sentences is not None and args.max_sentences < 1:
        parser.error("--max-sentences must be positive")
    if args.progress_every < 0:
        parser.error("--progress-every cannot be negative")
    if args.no_contextual and args.mode == "neural":
        parser.error("--no-contextual conflicts with --mode neural")


def _contextual_report(
    stats: EvaluationStats, *, engine: str, enabled: bool
) -> dict[str, Any]:
    if not enabled:
        return {
            "enabled": False,
            "engine": None,
            "lexical_selected_top1": None,
            "context_projected_ud_top1": None,
            "selection": None,
            "neural_resolution": None,
            "selected_raw_containment": None,
            "projection_for_legacy_metric_keys": None,
            "end_to_end": None,
            "aligned_only": None,
            "selected_only": None,
        }

    containment = stats.selected_raw_containment.as_json()
    lexical = {
        "definition": (
            "the selected candidate's lexical lemma, UPOS, and features exactly as licensed "
            "by qazmorph; no neural context projection is substituted"
        ),
        "end_to_end": stats.contextual_end_to_end.as_json(candidate=False),
        "aligned_only": stats.contextual_aligned_only.as_json(candidate=False),
        "selected_only": stats.contextual_selected_only.as_json(candidate=False),
        "candidate_recall_upper_bound": {
            "applicable": True,
            "valid": containment["valid_for_candidate_recall_bound"],
            "basis": "selected raw-analysis containment in the separate lattice pass",
            "invalid_reason": (
                None
                if containment["valid_for_candidate_recall_bound"]
                else "one or more selected raw analyses were absent from the separate lattice pass"
            ),
        },
    }
    projected = None
    if engine == "neural":
        projected = {
            "definition": (
                "the same candidate-constrained lexical selection, with available contextual "
                "UD UPOS/features projected by the neural layer for scoring"
            ),
            "end_to_end": stats.neural_projected_end_to_end.as_json(candidate=False),
            "aligned_only": stats.neural_projected_aligned_only.as_json(candidate=False),
            "selected_only": stats.neural_projected_selected_only.as_json(candidate=False),
            "candidate_recall_upper_bound": {
                "applicable": False,
                "valid": None,
                "reason": (
                    "context-projected UD fields need not occur on any raw FST candidate; only "
                    "lexical_selected_top1 is bounded by lattice candidate recall"
                ),
            },
        }
    return {
        "enabled": True,
        "engine": engine,
        "lexical_selected_top1": lexical,
        "context_projected_ud_top1": projected,
        "selection": stats.contextual_selection.as_json(),
        "neural_resolution": (
            stats.neural_resolution.as_json() if engine == "neural" else None
        ),
        "selected_raw_containment": containment,
        # V3 keeps these explicit lexical aliases for readers of V2 reports.
        "projection_for_legacy_metric_keys": "lexical_raw_analysis",
        "end_to_end": lexical["end_to_end"],
        "aligned_only": lexical["aligned_only"],
        "selected_only": lexical["selected_only"],
    }


def run(args: argparse.Namespace) -> dict[str, Any]:
    # Capture before imports, corpus reads, model initialization, or analysis.
    software_snapshot = _software_provenance()
    try:
        from qazmorph import Analyzer, __version__
    except ImportError as exc:
        raise EvaluationError(
            "qazmorph is not importable; install the project or run this script from its checkout"
        ) from exc

    paths = _expand_inputs(args.conllu)
    input_snapshots = [_file_identity(path) for path in paths]
    input_metadata = [
        {
            **snapshot,
            "sentences_evaluated": 0,
            "gold_tokens_evaluated": 0,
        }
        for snapshot in input_snapshots
    ]
    input_by_path = {Path(item["path"]): item for item in input_metadata}

    fixlist_metadata = None
    if args.fixlist:
        fixlist_path = Path(args.fixlist).expanduser().resolve()
        fixlist_metadata = _file_identity(fixlist_path)

    analyzer_options = {
        "resource_dir": args.resource_dir,
        "guess": not args.no_guesser,
        "fixlist": args.fixlist,
        "guess_limit": args.guess_limit,
        "ud_profile": args.ud_profile,
    }
    top1_mode = "lattice" if args.no_contextual else args.mode
    neural_use_gpu = {
        "auto": None,
        "cpu": False,
        "gpu": True,
    }[args.neural_device]
    lattice_mode_flags = _analyzer_mode_flags("lattice")
    contextual_mode_flags = _analyzer_mode_flags(top1_mode)
    lattice_analyzer: Any | None = None
    contextual_analyzer: Any | None = None
    stats = EvaluationStats()
    report: dict[str, Any] | None = None
    try:
        try:
            lattice_analyzer = Analyzer(**lattice_mode_flags, **analyzer_options)
            contextual_analyzer = (
                None
                if top1_mode == "lattice"
                else Analyzer(
                    **contextual_mode_flags,
                    neural_model_dir=args.neural_model_dir,
                    neural_use_gpu=neural_use_gpu,
                    **analyzer_options,
                )
            )
        except Exception as exc:
            raise EvaluationError(
                f"could not initialize {top1_mode} evaluator: {exc}"
            ) from exc

        # Bind resources and executable selection before processing any corpus
        # text, then compare fresh hashes after the last sentence.
        lattice_resource_initial = _resource_provenance(lattice_analyzer)
        contextual_resource_initial = (
            _resource_provenance(contextual_analyzer)
            if contextual_analyzer is not None
            else None
        )
        _require_matching_resource_provenance(
            lattice_resource_initial, contextual_resource_initial, stage="initialization"
        )
        neural_resource_initial = (
            _neural_resource_provenance(
                contextual_analyzer,
                args.neural_model_dir,
                requested_device=args.neural_device,
            )
            if top1_mode == "neural" and contextual_analyzer is not None
            else None
        )
        lattice_guesser_initial = dict(lattice_analyzer.guesser.diagnostics)
        contextual_guesser_initial = (
            dict(contextual_analyzer.guesser.diagnostics)
            if contextual_analyzer is not None
            else None
        )

        for path in paths:
            metadata = input_by_path[path]
            remaining = (
                None
                if args.max_sentences is None
                else args.max_sentences - stats.sentences
            )
            if remaining is not None and remaining <= 0:
                break
            sentences: Iterable[GoldSentence] = iter_conllu(path)
            if remaining is not None:
                sentences = islice(sentences, remaining)
            for sentence in sentences:
                _evaluate_sentence(
                    sentence,
                    lattice_analyzer=lattice_analyzer,
                    contextual_analyzer=contextual_analyzer,
                    stats=stats,
                    max_alignment_group=args.max_alignment_group,
                    exclude_punct=args.exclude_punct,
                    case_sensitive_lemmas=args.case_sensitive_lemmas,
                    top1_engine=top1_mode,
                    contextual_disambiguate=contextual_mode_flags["disambiguate"],
                )
                metadata["sentences_evaluated"] += 1
                metadata["gold_tokens_evaluated"] += len(sentence.tokens)
                if args.progress_every and stats.sentences % args.progress_every == 0:
                    print(
                        f"evaluated {stats.sentences} sentences / {stats.gold_tokens} gold tokens",
                        file=sys.stderr,
                        flush=True,
                    )

        if not stats.sentences:
            raise EvaluationError(
                "the selected inputs contain no evaluable integer-ID UD tokens"
            )

        lattice_guesser = _guesser_run_diagnostics(
            lattice_guesser_initial, dict(lattice_analyzer.guesser.diagnostics)
        )
        contextual_guesser = (
            _guesser_run_diagnostics(
                contextual_guesser_initial or {},
                dict(contextual_analyzer.guesser.diagnostics),
            )
            if contextual_analyzer is not None
            else None
        )

        lattice_resource_final = _resource_provenance(lattice_analyzer)
        if lattice_resource_final != lattice_resource_initial:
            raise EvaluationError(
                "lattice resources, artifacts, or backend runtime changed while "
                "evaluation was running"
            )
        contextual_resource_final = (
            _resource_provenance(contextual_analyzer)
            if contextual_analyzer is not None
            else None
        )
        if contextual_resource_final != contextual_resource_initial:
            raise EvaluationError(
                "contextual resources, artifacts, or backend runtime changed while "
                "evaluation was running"
            )
        _require_matching_resource_provenance(
            lattice_resource_final, contextual_resource_final, stage="post-run rehash"
        )
        resource_provenance = dict(lattice_resource_final)
        resource_provenance["analyzer_resources"] = {
            "lattice": lattice_resource_final,
            "contextual": contextual_resource_final,
        }
        resource_provenance["analyzer_backends"] = {
            "lattice": lattice_resource_final["backend_runtime"],
            "contextual": (
                contextual_resource_final["backend_runtime"]
                if contextual_resource_final is not None
                else None
            ),
        }
        runtime_validity = _runtime_validity(
            resource_provenance["analyzer_backends"]
        )
        if top1_mode == "neural" and contextual_analyzer is not None:
            neural_resource_final = _neural_resource_provenance(
                contextual_analyzer,
                args.neural_model_dir,
                requested_device=args.neural_device,
            )
            if neural_resource_final != neural_resource_initial:
                raise EvaluationError(
                    "neural model or runtime changed while evaluation was running"
                )
            resource_provenance["neural"] = neural_resource_final
            runtime_validity = _apply_neural_validity(
                runtime_validity, neural_resource_final
            )
        resource_provenance["reverified_unchanged_after_run"] = True

        report = {
        "schema_version": SCHEMA_VERSION,
        "tool": {
            "qazmorph_version": __version__,
            "python_version": platform.python_version(),
            "platform": platform.platform(),
            "hostname": platform.node(),
            "software": software_snapshot,
            "software_reverified_unchanged_after_run": False,
        },
        "configuration": {
            "guesser": not args.no_guesser,
            "guess_limit": args.guess_limit,
            "ud_profile": args.ud_profile,
            "mode": top1_mode,
            "contextual": contextual_analyzer is not None,
            "neural_model_dir": (
                str(Path(args.neural_model_dir).expanduser().resolve())
                if args.neural_model_dir
                else None
            ),
            "neural_device": args.neural_device if top1_mode == "neural" else None,
            "exclude_punct": args.exclude_punct,
            "lemma_normalization": "NFC" if args.case_sensitive_lemmas else "NFC+casefold",
            "feature_match": (
                "exact sorted UD feature bundle plus separately reported "
                "gold-subset-of-candidate and candidate-subset-of-gold relations"
            ),
            "max_alignment_group": args.max_alignment_group,
            "max_sentences": args.max_sentences,
            "fixlist": fixlist_metadata,
        },
        "resources": resource_provenance,
        "validity": runtime_validity,
        "inputs": input_metadata,
        "corpus": {
            "sentences": stats.sentences,
            "gold_tokens": stats.gold_tokens,
            "evaluated_tokens": stats.evaluated_tokens,
            "punctuation_tokens_excluded": stats.punctuation_tokens_excluded,
            "multiword_token_rows": stats.multiword_tokens,
            "empty_node_rows": stats.empty_nodes,
            "sentences_using_text_comment": stats.sentences_using_text_comment,
            "sentences_using_reconstructed_text": (
                stats.sentences - stats.sentences_using_text_comment
            ),
        },
        "alignment": {
            "normalization": "NFC+casefold+common apostrophe/dash folding+whitespace removal",
            "gold_surface_policy": (
                "integer-ID FORM values are used outside UD multiword-token rows; an exact "
                "multiword range uses the row's surface FORM and partial multiword ranges "
                "cannot match"
            ),
            "scoring_policy": (
                "only one-to-one matches are morphologically scorable; grouped and unaligned "
                "gold tokens receive misses in end-to-end metrics and are excluded from "
                "aligned-only metrics; surface-accounted rates are alignment diagnostics, "
                "not morphology scores"
            ),
            "lattice": {
                **stats.candidate_alignment.as_json(),
                "diagnostics": stats.candidate_alignment_diagnostics.as_json(),
            },
            "contextual": (
                {
                    **stats.contextual_alignment.as_json(),
                    "diagnostics": stats.contextual_alignment_diagnostics.as_json(),
                }
                if contextual_analyzer is not None
                else None
            ),
        },
        "candidate_recall": {
            "definition": (
                "a gold field is recalled when at least one lattice candidate matches it; "
                "full_analysis requires one candidate matching lemma, UPOS, and the exact feature bundle"
            ),
            "feature_bundle_relations": {
                "exact": "candidate feature set equals the gold feature set",
                "gold_subset_or_equal_candidate": (
                    "one candidate contains every gold feature and may retain additional legal detail"
                ),
                "candidate_subset_or_equal_gold": (
                    "one candidate contains no feature outside gold and may be underspecified"
                ),
                "scope": (
                    "relations are independent oracle-existence rates and may overlap when "
                    "different candidates license different bundles"
                ),
            },
            "end_to_end": stats.candidate_end_to_end.as_json(candidate=True),
            "aligned_only": stats.candidate_aligned_only.as_json(candidate=True),
        },
        "contextual_top1": _contextual_report(
            stats,
            engine=top1_mode,
            enabled=contextual_analyzer is not None,
        ),
        "coverage": stats.coverage.as_json(),
        "oov_lookup": {
            "lattice_completeness": _oov_lattice_completeness(
                guesser_enabled=not args.no_guesser,
                diagnostics=lattice_guesser,
                guess_limit=args.guess_limit,
            ),
            "analyzer_diagnostics": {
                "lattice": lattice_guesser,
                "contextual": contextual_guesser,
            },
        },
        }
    finally:
        closing_during_error = sys.exc_info()[0] is not None
        close_errors = _close_analyzers(contextual_analyzer, lattice_analyzer)
        if close_errors and not closing_during_error:
            raise EvaluationError(
                "could not close evaluator analyzers: " + "; ".join(close_errors)
            )

    # Re-read all corpus bytes even if only a deterministic prefix was scored.
    input_verifications, input_mismatches = _rehash_inputs(input_snapshots)
    for metadata, verification in zip(input_metadata, input_verifications):
        metadata["post_run_verification"] = {
            "unchanged": verification["unchanged"],
            "observed": verification["observed"],
            "error": verification["error"],
        }
    if input_mismatches:
        changed = ", ".join(item["path"] for item in input_mismatches)
        raise EvaluationError(
            f"corpus input changed or became unreadable while evaluation was running: {changed}"
        )

    if fixlist_metadata is not None:
        fixlist_verifications, fixlist_mismatches = _rehash_inputs([fixlist_metadata])
        verification = fixlist_verifications[0]
        fixlist_metadata["post_run_verification"] = {
            "unchanged": verification["unchanged"],
            "observed": verification["observed"],
            "error": verification["error"],
        }
        if fixlist_mismatches:
            raise EvaluationError("fixlist changed while the evaluation was running")

    software_after = _software_provenance()
    if software_after != software_snapshot:
        raise EvaluationError(
            "evaluator or imported qazmorph source changed while evaluation was running"
        )
    if report is None:  # Defensive: successful work must always produce a report.
        raise EvaluationError("evaluation completed without constructing a report")
    report["tool"]["software_reverified_unchanged_after_run"] = True
    return report


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    _validate_args(parser, args)
    try:
        report = run(args)
        encoded = json.dumps(
            report,
            ensure_ascii=False,
            indent=2 if args.pretty else None,
            sort_keys=True,
            separators=None if args.pretty else (",", ":"),
        ) + "\n"
        if args.output == "-":
            sys.stdout.write(encoded)
        else:
            Path(args.output).expanduser().write_text(encoded, encoding="utf-8")
    except (EvaluationError, OSError, UnicodeError, ValueError) as exc:
        parser.exit(2, f"evaluate_ud.py: error: {exc}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
