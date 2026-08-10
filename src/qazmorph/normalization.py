"""Unicode normalization that preserves offsets into the exact input string."""

from __future__ import annotations

import unicodedata


def nfc_with_boundary_map(text: str) -> tuple[str, list[int]]:
    """Return NFC text and a map from every NFC boundary to an input boundary."""

    if unicodedata.is_normalized("NFC", text):
        return text, list(range(len(text) + 1))

    # Start with canonical combining sequences, then merge any adjacent
    # sequences whose individually normalized forms still interact.  The
    # second step is essential for compositions whose following code point has
    # combining class zero, most visibly Hangul L+V(+T) Jamo.
    clusters: list[tuple[int, int, str]] = []
    start = 0
    while start < len(text):
        end = start + 1
        while end < len(text) and unicodedata.combining(text[end]):
            end += 1
        clusters.append((start, end, unicodedata.normalize("NFC", text[start:end])))
        while len(clusters) >= 2:
            left_start, _left_end, left = clusters[-2]
            _right_start, right_end, right = clusters[-1]
            joined = unicodedata.normalize("NFC", left + right)
            if joined == left + right:
                break
            clusters[-2:] = [(left_start, right_end, joined)]
        start = end

    normalized = "".join(part for _start, _end, part in clusters)
    # This invariant also detects any future Unicode interaction not captured
    # by the local composition stack.
    if normalized != unicodedata.normalize("NFC", text):
        raise AssertionError("normalization clusters are not independently NFC-safe")

    boundaries = [0]
    for start, end, part in clusters:
        source_part = text[start:end]
        if source_part == part:
            # The cluster was already normalized (it may simply have been
            # joined to a preceding non-NFC cluster), so every boundary is
            # exact and tokenizer-visible boundaries such as whitespace remain.
            boundaries.extend(range(start + 1, end + 1))
        else:
            # Unsafe interior boundaries inside a composition/reordering map
            # monotonically to the source start; the final boundary consumes
            # the complete source cluster.
            boundaries.extend([start] * max(0, len(part) - 1))
            if part:
                boundaries.append(end)
    if len(boundaries) != len(normalized) + 1:
        raise AssertionError("normalization boundary map is inconsistent")
    if any(left > right for left, right in zip(boundaries, boundaries[1:])):
        raise AssertionError("normalization boundary map is not monotone")
    return normalized, boundaries
