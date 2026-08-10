"""Stable data model used by the Python API and serializers.

``Document.tokens`` is the one consuming surface partition.  Dictionary
expressions that cover more than one of those tokens live in
``Document.analysis_spans`` and therefore never duplicate input text.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class Morpheme:
    lemma: str
    tags: tuple[str, ...]
    upos: str = "X"
    features: tuple[tuple[str, str], ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "lemma": self.lemma,
            "tags": list(self.tags),
            "upos": self.upos,
            "features": dict(self.features),
        }


@dataclass(frozen=True, slots=True)
class Analysis:
    lemma: str
    upos: str
    features: tuple[tuple[str, str], ...]
    tags: tuple[str, ...]
    morphemes: tuple[Morpheme, ...]
    raw: str
    source: str = "lexicon"
    score: float | None = None
    guessed: bool = False
    orthographic_variant: bool = False
    context_upos: str | None = None
    context_features: tuple[tuple[str, str], ...] = ()

    @property
    def feature_map(self) -> dict[str, str]:
        return dict(self.features)

    @property
    def signature(self) -> tuple[str, str, tuple[tuple[str, str], ...]]:
        """Lossy UD-level signature, useful for evaluation and grouping."""

        return (self.lemma.casefold(), self.upos, self.features)

    @property
    def identity(self) -> tuple[str, str, tuple[tuple[str, str], ...], str]:
        """Lossless reading identity used for lattice deduplication."""

        return (*self.signature, self.raw)

    def as_dict(self) -> dict[str, Any]:
        value = {
            "schema_version": "qazmorph.analysis.v1",
            "lemma": self.lemma,
            "upos": self.upos,
            "features": dict(self.features),
            "tags": list(self.tags),
            "morphemes": [m.as_dict() for m in self.morphemes],
            "raw": self.raw,
            "source": self.source,
            "score": round(self.score, 8) if self.score is not None else None,
            "guessed": self.guessed,
            "orthographic_variant": self.orthographic_variant,
        }
        if self.context_upos:
            value["context_upos"] = self.context_upos
        if self.context_features:
            value["context_features"] = dict(self.context_features)
        return value


@dataclass(slots=True)
class Token:
    text: str
    start: int
    end: int
    kind: str
    analyses: list[Analysis] = field(default_factory=list)
    selected: int | None = None
    sentence_end: bool = False
    normalized: str | None = None

    @property
    def chosen(self) -> Analysis | None:
        if self.selected is not None and 0 <= self.selected < len(self.analyses):
            return self.analyses[self.selected]
        return self.analyses[0] if len(self.analyses) == 1 else None

    @property
    def is_dictionary_word(self) -> bool:
        return bool(self.analyses) and any(not a.guessed for a in self.analyses)

    def as_dict(self) -> dict[str, Any]:
        chosen = self.chosen
        return {
            "schema_version": "qazmorph.token.v1",
            "text": self.text,
            "start": self.start,
            "end": self.end,
            "kind": self.kind,
            "normalized": self.normalized,
            "sentence_end": self.sentence_end,
            "selected": chosen.as_dict() if chosen else None,
            "analyses": [a.as_dict() for a in self.analyses],
        }


@dataclass(frozen=True, slots=True)
class AnalysisSpan:
    """An immutable FST cohort covering one or more atomic input tokens.

    ``token_start`` is inclusive and ``token_end`` is exclusive and names the
    exact set of atomic tokens intersected by the character span. Character
    offsets are authoritative and may begin or end inside an orthographic
    token (for example an MWE ending at ``мекен`` inside ``мекен-жайға``).
    A span is non-consuming: its surface is already represented exactly once
    by the covered token rows.
    """

    text: str
    start: int
    end: int
    token_start: int
    token_end: int
    analyses: tuple[Analysis, ...]
    selected: int | None = None
    sentence_end: bool = False
    normalized: str | None = None

    def __post_init__(self) -> None:
        if not self.text:
            raise ValueError("analysis span text must be non-empty")
        if self.start < 0 or self.end <= self.start:
            raise ValueError("analysis span character offsets must be increasing")
        if self.token_start < 0 or self.token_end <= self.token_start:
            raise ValueError("analysis span token coverage must be non-empty")
        if self.selected is not None and not 0 <= self.selected < len(self.analyses):
            raise ValueError("analysis span selected index is out of range")

    @property
    def chosen(self) -> Analysis | None:
        if self.selected is not None:
            return self.analyses[self.selected]
        return self.analyses[0] if len(self.analyses) == 1 else None

    @property
    def is_dictionary_word(self) -> bool:
        return bool(self.analyses) and any(not analysis.guessed for analysis in self.analyses)

    def as_dict(self) -> dict[str, Any]:
        chosen = self.chosen
        return {
            "schema_version": "qazmorph.analysis-span.v1",
            "text": self.text,
            "start": self.start,
            "end": self.end,
            "token_start": self.token_start,
            "token_end": self.token_end,
            "normalized": self.normalized,
            "sentence_end": self.sentence_end,
            "selected": chosen.as_dict() if chosen else None,
            "analyses": [analysis.as_dict() for analysis in self.analyses],
        }


@dataclass(slots=True)
class Document:
    text: str
    tokens: list[Token]
    mode: str
    resource_version: str
    normalized_text: str | None = None
    analysis_spans: tuple[AnalysisSpan, ...] = ()
    ud_profile: str = "universal"

    def __post_init__(self) -> None:
        if self.ud_profile not in {"universal", "ktb"}:
            raise ValueError(f"unknown UD projection profile: {self.ud_profile}")
        cursor = 0
        for index, token in enumerate(self.tokens):
            if not token.text:
                raise ValueError(f"token {index} has empty text")
            if token.start != cursor or token.end != token.start + len(token.text):
                raise ValueError(f"token {index} does not form a contiguous exact partition")
            if self.text[token.start : token.end] != token.text:
                raise ValueError(f"token {index} surface does not match document text")
            has_whitespace = any(character.isspace() for character in token.text)
            if token.kind == "space":
                if not token.text.isspace():
                    raise ValueError(f"space token {index} contains non-whitespace")
            elif has_whitespace:
                raise ValueError(f"non-space token {index} contains whitespace")
            cursor = token.end
        if cursor != len(self.text):
            raise ValueError("tokens do not cover the document text exactly")

        for index, span in enumerate(self.analysis_spans):
            if span.end > len(self.text) or self.text[span.start : span.end] != span.text:
                raise ValueError(f"analysis span {index} surface does not match document text")
            if span.token_end > len(self.tokens):
                raise ValueError(f"analysis span {index} token coverage is out of range")
            first = self.tokens[span.token_start]
            last = self.tokens[span.token_end - 1]
            if not (first.start <= span.start < first.end):
                raise ValueError(f"analysis span {index} token start coverage is not exact")
            if not (last.start < span.end <= last.end):
                raise ValueError(f"analysis span {index} token end coverage is not exact")
            if span.token_start > 0 and self.tokens[span.token_start - 1].end > span.start:
                raise ValueError(f"analysis span {index} omits an intersecting start token")
            if span.token_end < len(self.tokens) and self.tokens[span.token_end].start < span.end:
                raise ValueError(f"analysis span {index} omits an intersecting end token")

    @property
    def lexical_tokens(self) -> list[Token]:
        return [token for token in self.tokens if token.kind != "space"]

    def as_dict(self) -> dict[str, Any]:
        value = {
            "schema_version": "qazmorph.document.v2",
            "text": self.text,
            "mode": self.mode,
            "resource_version": self.resource_version,
            "ud_profile": self.ud_profile,
            "tokens": [token.as_dict() for token in self.tokens],
            "analysis_spans": [span.as_dict() for span in self.analysis_spans],
        }
        if self.normalized_text and self.normalized_text != self.text:
            value["normalized_text"] = self.normalized_text
        return value
