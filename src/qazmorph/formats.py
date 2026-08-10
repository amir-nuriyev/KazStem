"""MyStem-like text/JSON/XML serializers plus a CoNLL-U projection."""

from __future__ import annotations

from collections import OrderedDict
import json
import re
from xml.sax.saxutils import escape, quoteattr

from .types import Analysis, AnalysisSpan, Document, Token


class XMLFormatError(ValueError):
    """Raised when a value cannot be represented in a well-formed XML document."""


_XML_ENCODING_NAME = re.compile(r"[A-Za-z][A-Za-z0-9._-]*\Z")


def _validate_xml_10(value: str, *, field: str) -> str:
    """Reject characters outside the XML 1.0 ``Char`` production."""

    for index, character in enumerate(value):
        codepoint = ord(character)
        valid = (
            codepoint in {0x09, 0x0A, 0x0D}
            or 0x20 <= codepoint <= 0xD7FF
            or 0xE000 <= codepoint <= 0xFFFD
            or 0x10000 <= codepoint <= 0x10FFFF
        )
        if not valid:
            raise XMLFormatError(
                f"XML output {field} contains XML 1.0-forbidden code point "
                f"U+{codepoint:04X} at character {index}"
            )
    return value


def _xml_text(value: str, *, field: str) -> str:
    return escape(_validate_xml_10(value, field=field))


def _xml_attribute(value: object, *, field: str) -> str:
    return quoteattr(_validate_xml_10(str(value), field=field))


def _xml_encoding_attribute(encoding: str) -> str:
    _validate_xml_10(encoding, field="declaration encoding")
    if not _XML_ENCODING_NAME.fullmatch(encoding):
        raise XMLFormatError(
            "XML declaration encoding must match the XML EncName syntax"
        )
    return quoteattr(encoding)


def _matches_filter(analysis: Analysis, filters: frozenset[str]) -> bool:
    if not filters:
        return True
    feature_strings = {f"{key}={value}" for key, value in analysis.features}
    contextual_feature_strings = {
        f"{key}={value}" for key, value in analysis.context_features
    }
    available = (
        set(analysis.tags)
        | feature_strings
        | contextual_feature_strings
        | {analysis.upos}
    )
    if analysis.context_upos:
        available.add(analysis.context_upos)
    return filters <= available


def visible_analyses(
    token: Token | AnalysisSpan,
    filters: frozenset[str],
    dictionary_only: bool,
) -> list[Analysis]:
    return [
        analysis
        for analysis in token.analyses
        if _matches_filter(analysis, filters) and (not dictionary_only or not analysis.guessed)
    ]


def _grammar(analysis: Analysis) -> str:
    projected_features = analysis.context_features or analysis.features
    features = ",".join(f"{key}={value}" for key, value in projected_features)
    upos = analysis.context_upos or analysis.upos
    return upos + (("," + features) if features else "")


def _analysis_text(analysis: Analysis, *, gram_info: bool, weights: bool) -> str:
    value = analysis.lemma
    if analysis.guessed:
        value += "?"
    if weights and analysis.score is not None:
        value += f":{analysis.score:.6f}"
    if gram_info:
        value += "=" + _grammar(analysis)
    return value


def _merged_analysis_text(analyses: list[Analysis], *, gram_info: bool, weights: bool) -> list[str]:
    groups: OrderedDict[str, list[Analysis]] = OrderedDict()
    for analysis in analyses:
        groups.setdefault(analysis.lemma, []).append(analysis)
    values: list[str] = []
    for lemma, group in groups.items():
        guessed = all(analysis.guessed for analysis in group)
        value = lemma + ("?" if guessed else "")
        available_scores = [analysis.score for analysis in group if analysis.score is not None]
        if weights and len(available_scores) == len(group):
            value += f":{sum(available_scores):.6f}"
        if gram_info:
            grammars = list(dict.fromkeys(_grammar(analysis) for analysis in group))
            value += "=" + (grammars[0] if len(grammars) == 1 else "(" + "|".join(grammars) + ")")
        values.append(value)
    return values


def _escape_gap(value: str) -> str:
    return (
        value.replace("\\", "\\\\")
        .replace("_", "\\_")
        .replace(" ", "_")
        .replace("\r", "\\r")
        .replace("\n", "\\n")
    )


def _line_endings(value: str) -> str:
    """Retain physical input lines in MyStem text mode without ``-c``."""

    return "".join(char for char in value if char in "\r\n")


def format_text(
    document: Document,
    *,
    copy_input: bool = False,
    newline: bool = False,
    lemmas_only: bool = False,
    gram_info: bool = False,
    merge: bool = False,
    sentence_markers: bool = False,
    weights: bool = False,
    dictionary_only: bool = False,
    filters: frozenset[str] = frozenset(),
    selected_only: bool = False,
) -> str:
    chunks: list[str] = []
    for token in document.tokens:
        analyses = visible_analyses(token, filters, dictionary_only)
        if selected_only and token.chosen is not None:
            analyses = [analysis for analysis in analyses if analysis.identity == token.chosen.identity]
        is_lexical = token.kind in {"word", "number"}
        if not is_lexical:
            if copy_input:
                chunks.append(_escape_gap(token.text) if newline else token.text)
                if sentence_markers and token.sentence_end:
                    chunks.append(r"{\s}")
            elif not newline:
                # MyStem processes physical input lines independently even
                # when inter-word material is not copied. Retaining only line
                # endings avoids joining the last word of one line directly
                # to the first word of the next.
                chunks.append(_line_endings(token.text))
            continue
        if not analyses:
            if copy_input and not dictionary_only:
                chunks.append(token.text)
            continue

        if merge:
            rendered = _merged_analysis_text(analyses, gram_info=gram_info, weights=weights)
        else:
            rendered = [
                _analysis_text(analysis, gram_info=gram_info, weights=weights) for analysis in analyses
            ]
        body = "|".join(rendered)
        chunks.append(body if lemmas_only else f"{token.text}{{{body}}}")
        if sentence_markers and token.sentence_end:
            chunks.append(r"{\s}")

    if newline:
        return "\n".join(chunks) + ("\n" if chunks else "")
    return "".join(chunks)


def _analysis_json(analysis: Analysis) -> dict[str, object]:
    value = analysis.as_dict()
    value.update(
        {
            "lex": analysis.lemma,
            "gr": _grammar(analysis),
            "qual": "guessed" if analysis.guessed else None,
        }
    )
    return value


def _mystem_analysis_json(
    analyses: list[Analysis],
    *,
    gram_info: bool,
    merge: bool,
    weights: bool,
) -> list[dict[str, object]]:
    """Project analyses to MyStem's public ``lex/gr/qual/wt`` schema."""

    groups: list[list[Analysis]]
    if merge:
        grouped: OrderedDict[str, list[Analysis]] = OrderedDict()
        for analysis in analyses:
            grouped.setdefault(analysis.lemma, []).append(analysis)
        groups = list(grouped.values())
    else:
        groups = [[analysis] for analysis in analyses]

    rows: list[dict[str, object]] = []
    for group in groups:
        first = group[0]
        row: dict[str, object] = {"lex": first.lemma}
        if gram_info:
            grammars = list(dict.fromkeys(_grammar(analysis) for analysis in group))
            row["gr"] = grammars[0] if len(grammars) == 1 else "(" + "|".join(grammars) + ")"
        if all(analysis.guessed for analysis in group):
            # ``bastard`` is MyStem's documented qualifier for a generated
            # (non-dictionary) hypothesis. The richer JSONL schema retains
            # QazMorph's clearer boolean/provenance fields.
            row["qual"] = "bastard"
        available_scores = [analysis.score for analysis in group if analysis.score is not None]
        if weights and len(available_scores) == len(group):
            row["wt"] = round(sum(available_scores), 8)
        rows.append(row)
    return rows


def format_mystem_json(
    document: Document,
    *,
    copy_input: bool = False,
    newline: bool = False,
    gram_info: bool = False,
    merge: bool = False,
    weights: bool = False,
    dictionary_only: bool = False,
    filters: frozenset[str] = frozenset(),
    selected_only: bool = False,
) -> str:
    """Return a compact JSON array using MyStem's public record shape.

    ``jsonl`` remains the lossless QazMorph schema. This compatibility view
    deliberately contains only ``text`` plus optional ``analysis`` records
    with ``lex``, ``gr``, ``qual``, and ``wt`` fields.
    """

    rows: list[dict[str, object]] = []
    for token in document.tokens:
        analyses = visible_analyses(token, filters, dictionary_only)
        if selected_only and token.chosen is not None:
            analyses = [
                analysis for analysis in analyses if analysis.identity == token.chosen.identity
            ]
        is_lexical = token.kind in {"word", "number"}
        if not is_lexical:
            if copy_input:
                rows.append({"text": token.text})
            continue
        if dictionary_only and token.kind in {"word", "number"} and not analyses:
            continue
        row: dict[str, object] = {"text": token.text}
        if analyses:
            row["analysis"] = _mystem_analysis_json(
                analyses,
                gram_info=gram_info,
                merge=merge,
                weights=weights,
            )
        rows.append(row)
    if newline:
        return "\n".join(
            json.dumps(row, ensure_ascii=False, separators=(",", ":")) for row in rows
        ) + ("\n" if rows else "")
    return json.dumps(rows, ensure_ascii=False, separators=(",", ":")) + "\n"


def format_jsonl(
    document: Document,
    *,
    copy_input: bool = False,
    dictionary_only: bool = False,
    filters: frozenset[str] = frozenset(),
) -> str:
    """Serialize consuming atomic tokens and non-consuming FST spans.

    Version 2 uses one common record schema.  Consumers reconstruct input by
    concatenating only rows whose ``record_type`` is ``token`` and
    ``consumes_input`` is true; analysis-span rows deliberately overlap them.
    """

    rows: list[str] = []
    for token_index, token in enumerate(document.tokens):
        is_lexical = token.kind in {"word", "number"}
        if not copy_input and not is_lexical:
            continue
        analyses = visible_analyses(token, filters, dictionary_only)
        if dictionary_only and is_lexical and not analyses:
            continue
        selected = None
        if token.chosen:
            for index, analysis in enumerate(analyses):
                if analysis.identity == token.chosen.identity:
                    selected = index
                    break
        row = {
            "schema_version": "qazmorph.jsonl-record.v2",
            "record_type": "token",
            "consumes_input": True,
            "token_index": token_index,
            "text": token.text,
            "start": token.start,
            "end": token.end,
            "kind": token.kind,
            "normalized": token.normalized,
            "mode": document.mode,
            "resource_version": document.resource_version,
            "ud_profile": document.ud_profile,
            "analysis": [_analysis_json(analysis) for analysis in analyses],
            "selected": selected,
            "sentence_end": token.sentence_end,
        }
        rows.append(json.dumps(row, ensure_ascii=False, separators=(",", ":")))

    for span_index, span in enumerate(document.analysis_spans):
        analyses = visible_analyses(span, filters, dictionary_only)
        if not analyses:
            continue
        selected = None
        if span.chosen:
            for index, analysis in enumerate(analyses):
                if analysis.identity == span.chosen.identity:
                    selected = index
                    break
        row = {
            "schema_version": "qazmorph.jsonl-record.v2",
            "record_type": "analysis_span",
            "consumes_input": False,
            "span_index": span_index,
            "text": span.text,
            "start": span.start,
            "end": span.end,
            "token_start": span.token_start,
            "token_end": span.token_end,
            "normalized": span.normalized,
            "mode": document.mode,
            "resource_version": document.resource_version,
            "ud_profile": document.ud_profile,
            "analysis": [_analysis_json(analysis) for analysis in analyses],
            "selected": selected,
            "sentence_end": span.sentence_end,
        }
        rows.append(json.dumps(row, ensure_ascii=False, separators=(",", ":")))
    return "\n".join(rows) + ("\n" if rows else "")


def format_xml(
    document: Document,
    *,
    copy_input: bool = True,
    dictionary_only: bool = False,
    filters: frozenset[str] = frozenset(),
    selected_only: bool = False,
    gram_info: bool = True,
    merge: bool = False,
    sentence_markers: bool = False,
    weights: bool = False,
    encoding: str = "UTF-8",
) -> str:
    """Serialize one MyStem-shaped, well-formed XML 1.0 document.

    XML's character repertoire is narrower than Python's Unicode strings. Any
    unrepresentable value selected for output fails explicitly instead of
    returning XML that a conforming parser must reject.
    """

    chunks = [
        f"<?xml version=\"1.0\" encoding={_xml_encoding_attribute(encoding)}?>",
        "<html><body><se>",
    ]
    last_emitted_lexical = max(
        (
            index
            for index, token in enumerate(document.tokens)
            if token.kind in {"word", "number"}
            and (
                not dictionary_only
                or visible_analyses(token, filters, dictionary_only)
            )
        ),
        default=-1,
    )
    for index, token in enumerate(document.tokens):
        analyses = visible_analyses(token, filters, dictionary_only)
        if selected_only and token.chosen is not None:
            analyses = [analysis for analysis in analyses if analysis.identity == token.chosen.identity]
        if token.kind not in {"word", "number"}:
            if copy_input:
                chunks.append(_xml_text(token.text, field="token text"))
            if sentence_markers and token.sentence_end and index < last_emitted_lexical:
                chunks.append("</se><se>")
            continue
        if dictionary_only and not analyses:
            continue
        chunks.append("<w>")
        chunks.append(_xml_text(token.text, field="token text"))
        for row in _mystem_analysis_json(
            analyses,
            gram_info=gram_info,
            merge=merge,
            weights=weights,
        ):
            attrs = [f"lex={_xml_attribute(row['lex'], field='analysis lex')}"]
            if "qual" in row:
                attrs.append(
                    f"qual={_xml_attribute(row['qual'], field='analysis qual')}"
                )
            if "gr" in row:
                attrs.append(f"gr={_xml_attribute(row['gr'], field='analysis gr')}")
            if "wt" in row:
                attrs.append(f"wt={_xml_attribute(row['wt'], field='analysis wt')}")
            chunks.append("<ana " + " ".join(attrs) + " />")
        chunks.append("</w>")
        if sentence_markers and token.sentence_end and index < last_emitted_lexical:
            chunks.append("</se><se>")
    chunks.append("</se></body></html>\n")
    return "".join(chunks)


def format_conllu(
    document: Document,
    *,
    dictionary_only: bool = False,
    filters: frozenset[str] = frozenset(),
) -> str:
    lines: list[str] = []
    index = 1
    for token in document.tokens:
        if token.kind == "space":
            continue
        if any(character.isspace() for character in token.text):
            raise ValueError("CoNLL-U FORM cannot contain whitespace")
        analyses = visible_analyses(token, filters, dictionary_only)
        if dictionary_only and token.kind in {"word", "number"} and not analyses:
            continue
        analysis = None
        if token.chosen and any(item.identity == token.chosen.identity for item in analyses):
            analysis = token.chosen
        elif len(analyses) == 1:
            analysis = analyses[0]
        lemma = analysis.lemma if analysis else "_"
        upos = (
            (analysis.context_upos or analysis.upos)
            if analysis
            else ("PUNCT" if token.kind == "punct" else "X")
        )
        features = "_"
        projected_features = analysis.context_features or analysis.features if analysis else ()
        if projected_features:
            features = "|".join(f"{key}={value}" for key, value in projected_features)
        misc = [f"StartChar={token.start}", f"EndChar={token.end}"]
        if len(analyses) > 1:
            misc.append(f"Candidates={len(analyses)}")
            if analysis is None:
                misc.append("Unresolved=Yes")
        if analysis and analysis.guessed:
            misc.append("Guess=Yes")
        lines.append(
            "\t".join(
                (str(index), token.text, lemma, upos, "_", features, "_", "_", "_", "|".join(misc))
            )
        )
        index += 1
        if token.sentence_end:
            lines.append("")
            index = 1
    if lines and lines[-1] != "":
        lines.append("")
    return "\n".join(lines) + ("\n" if lines else "")
