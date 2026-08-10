#!/usr/bin/env python3
"""Generate native v0.2.1 format expectations for the browser port."""

from __future__ import annotations

import json
from pathlib import Path
import sys
import unicodedata


PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from qazmorph.formats import (  # noqa: E402
    XMLFormatError,
    format_conllu,
    format_jsonl,
    format_mystem_json,
    format_text,
    format_xml,
)
from qazmorph.stream import parse_analysis  # noqa: E402
from qazmorph.types import Analysis, AnalysisSpan, Document, Morpheme, Token  # noqa: E402


def unknown(surface: str) -> Analysis:
    lemma = unicodedata.normalize("NFC", surface).casefold()
    return Analysis(
        lemma=lemma,
        upos="X",
        features=(),
        tags=("unknown",),
        morphemes=(Morpheme(lemma, ("unknown",), "X", ()),),
        raw=f"{lemma}<unknown>",
        source="unknown",
        guessed=True,
    )


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: generate_format_fixture.py OUTPUT")
    raw = "кітап<n><pl><px1pl><abl>"
    known = parse_analysis(raw)
    assert known is not None
    surfaces = [
        ("😀", "symbol", []),
        (" ", "space", []),
        ("кіта\u0301п", "word", [unknown("кіта\u0301п")]),
        ("\r\n", "space", []),
        ("кітап", "word", [known]),
        (".", "punct", []),
    ]
    tokens: list[Token] = []
    cursor = 0
    for surface, kind, analyses in surfaces:
        tokens.append(
            Token(
                text=surface,
                start=cursor,
                end=cursor + len(surface),
                kind=kind,
                analyses=analyses,
                selected=0 if len(analyses) == 1 else None,
                sentence_end=surface == ".",
                normalized=(
                    unicodedata.normalize("NFC", surface)
                    if unicodedata.normalize("NFC", surface) != surface
                    else None
                ),
            )
        )
        cursor += len(surface)
    text = "".join(token.text for token in tokens)
    span = AnalysisSpan(
        text=text[tokens[2].start : tokens[4].end],
        start=tokens[2].start,
        end=tokens[4].end,
        token_start=2,
        token_end=5,
        analyses=(known,),
        selected=0,
        normalized=unicodedata.normalize("NFC", text[tokens[2].start : tokens[4].end]),
    )
    document = Document(
        text=text,
        normalized_text=unicodedata.normalize("NFC", text),
        tokens=tokens,
        analysis_spans=(span,),
        mode="lattice",
        resource_version="fixture",
        ud_profile="universal",
    )
    expected = {
        "text": format_text(document, copy_input=True, gram_info=True),
        "json": format_mystem_json(document, copy_input=True, gram_info=True),
        "jsonl": format_jsonl(document, copy_input=True),
        "xml": format_xml(document),
        "conllu": format_conllu(document),
    }
    invalid = Document(
        text="\0",
        tokens=[Token("\0", 0, 1, "symbol")],
        mode="lattice",
        resource_version="fixture",
    )
    try:
        format_xml(invalid)
    except XMLFormatError as exc:
        xml_error = str(exc)
    else:
        raise AssertionError("native XML formatter unexpectedly accepted NUL")
    fixture = {
        "schema": "kazstem.browser-native-format-fixture.v1",
        "raw_analysis": raw,
        "analysis": known.as_dict(),
        "document": {
            "text": text,
            "normalized_text": document.normalized_text,
            "tokens": [
                {
                    "text": token.text,
                    "start": token.start,
                    "end": token.end,
                    "kind": token.kind,
                    "normalized": token.normalized,
                    "analysis_kind": (
                        "known" if token.analyses and not token.analyses[0].guessed
                        else "unknown" if token.analyses
                        else None
                    ),
                    "selected": token.selected,
                    "sentence_end": token.sentence_end,
                }
                for token in tokens
            ],
            "span": {
                "text": span.text,
                "start": span.start,
                "end": span.end,
                "token_start": span.token_start,
                "token_end": span.token_end,
                "normalized": span.normalized,
                "selected": span.selected,
                "sentence_end": span.sentence_end,
            },
        },
        "expected": expected,
        "xml_nul_error": xml_error,
        "casefold_examples": [
            {"input": value, "expected": value.casefold()}
            for value in ("IİßΣς", "ҚАЗАҚСТАН", "Straße", "ﬃ")
        ],
    }
    Path(sys.argv[1]).write_text(
        json.dumps(fixture, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
