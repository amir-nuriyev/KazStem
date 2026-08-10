"""Parser for the escaped lexical-unit stream emitted by HFST/Apertium."""

from __future__ import annotations

from dataclasses import dataclass
import re

from .tags import UD_PROFILES, project_ud
from .types import Analysis, Morpheme


@dataclass(frozen=True, slots=True)
class RawSegment:
    text: str
    analyses: tuple[str, ...] = ()


def _unescape(value: str) -> str:
    out: list[str] = []
    escaped = False
    for char in value:
        if escaped:
            out.append(char)
            escaped = False
        elif char == "\\":
            escaped = True
        else:
            out.append(char)
    if escaped:
        out.append("\\")
    return "".join(out)


def _split_unescaped(value: str, delimiter: str) -> list[str]:
    parts: list[str] = []
    current: list[str] = []
    escaped = False
    for char in value:
        if escaped:
            current.extend(("\\", char))
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == delimiter:
            parts.append("".join(current))
            current = []
        else:
            current.append(char)
    if escaped:
        current.append("\\")
    parts.append("".join(current))
    return parts


def _find_unescaped(value: str, target: str) -> int:
    escaped = False
    for index, char in enumerate(value):
        if escaped:
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == target:
            return index
    return -1


def parse_apertium_stream(stream: str) -> list[RawSegment]:
    """Parse a stream while retaining every gap and lexical surface form."""

    segments: list[RawSegment] = []
    gap: list[str] = []
    index = 0
    length = len(stream)

    while index < length:
        char = stream[index]
        if char == "\\" and index + 1 < length:
            gap.append(stream[index + 1])
            index += 2
            continue
        if char != "^":
            gap.append(char)
            index += 1
            continue

        if gap:
            segments.append(RawSegment("".join(gap)))
            gap = []

        index += 1
        unit: list[str] = []
        escaped = False
        while index < length:
            char = stream[index]
            if escaped:
                unit.extend(("\\", char))
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == "$":
                break
            else:
                unit.append(char)
            index += 1
        if index >= length:
            # A malformed backend stream is kept losslessly as plain text.
            if escaped:
                unit.append("\\")
            gap.extend(("^", *unit))
            break
        index += 1

        fields = _split_unescaped("".join(unit), "/")
        surface = _unescape(fields[0]) if fields else ""
        # Keep escapes in readings until parse_analysis has separated joined
        # morphemes. Otherwise a literal ``\+`` (for example C++) becomes a
        # false morpheme boundary.
        analyses = tuple(field for field in fields[1:] if field)
        segments.append(RawSegment(surface, analyses))

    if gap:
        segments.append(RawSegment("".join(gap)))
    return segments


TAG_RE = re.compile(r"<([^<>]+)>")


def parse_analysis(
    raw: str,
    *,
    source: str = "lexicon",
    guessed: bool = False,
    ud_profile: str = "universal",
) -> Analysis | None:
    """Convert one lexical reading into the stable structured representation."""

    if ud_profile not in UD_PROFILES:
        raise ValueError(f"unknown UD projection profile: {ud_profile}")
    if not raw or raw.startswith("*") or raw.endswith("+?"):
        return None

    parts = _split_unescaped(raw, "+")
    morphemes: list[Morpheme] = []
    all_tags: list[str] = []
    for part in parts:
        tag_start = _find_unescaped(part, "<")
        lemma = _unescape(part if tag_start < 0 else part[:tag_start])
        tags = tuple(TAG_RE.findall(part))
        all_tags.extend(tags)
        segment_upos, segment_features = project_ud(tags, profile=ud_profile)
        morphemes.append(
            Morpheme(lemma=lemma, tags=tags, upos=segment_upos, features=segment_features)
        )

    lemma = next((m.lemma for m in morphemes if m.lemma), raw)
    primary = next((m for m in morphemes if m.lemma or m.tags), None)
    upos, features = (
        (primary.upos, primary.features)
        if primary
        else project_ud(all_tags, profile=ud_profile)
    )
    is_guessed = guessed or "unk" in all_tags
    return Analysis(
        lemma=lemma,
        upos=upos,
        features=features,
        tags=tuple(all_tags),
        morphemes=tuple(morphemes),
        raw=raw,
        source=source,
        guessed=is_guessed,
        orthographic_variant="err_orth" in all_tags,
    )
