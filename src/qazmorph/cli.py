"""Console interface intentionally familiar to MyStem users."""

from __future__ import annotations

import argparse
import codecs
from pathlib import Path
import sys

from . import __version__
from .analyzer import Analyzer
from .backend import BackendError
from .fixlist import FixlistError
from .formats import (
    XMLFormatError,
    format_conllu,
    format_jsonl,
    format_mystem_json,
    format_text,
    format_xml,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="kazstem",
        description="Ambiguity-preserving Kazakh morphological analyzer",
    )
    parser.add_argument("-?", action="help", help=argparse.SUPPRESS)
    parser.add_argument("input", nargs="?", default="-", help="text file, or - for stdin")
    parser.add_argument("output", nargs="?", default="-", help="output file, or - for stdout")
    parser.add_argument(
        "-n",
        action="store_true",
        dest="newline",
        help="put every emitted text/JSON segment on a line",
    )
    parser.add_argument("-c", action="store_true", dest="copy_input", help="retain gaps and punctuation")
    parser.add_argument("-w", action="store_true", dest="dictionary_only", help="emit dictionary readings only")
    parser.add_argument("-l", action="store_true", dest="lemmas_only", help="suppress surface forms in text output")
    parser.add_argument("-i", action="store_true", dest="gram_info", help="include UPOS and UD features")
    parser.add_argument(
        "-g",
        action="store_true",
        dest="merge",
        help="group readings that share a lemma; requires -i",
    )
    parser.add_argument(
        "-s",
        action="store_true",
        dest="sentence_markers",
        help="emit text/XML sentence boundaries; requires -c",
    )
    parser.add_argument(
        "-d",
        action="store_true",
        dest="disambiguate",
        help="prune readings with Constraint Grammar; unresolved ambiguity is retained",
    )
    parser.add_argument("--neural", action="store_true", help="rank the legal FST lattice with Kazakh contextual models")
    parser.add_argument("--neural-model-dir", metavar="PATH", help="Stanza Kazakh model directory")
    parser.add_argument("--cpu", action="store_true", help="force neural mode onto CPU")
    parser.add_argument("-e", "--encoding", default="utf-8", help="input/output encoding (default: utf-8)")
    parser.add_argument("--eng-gr", action="store_true", help="accepted for compatibility; public tags are English/UD")
    parser.add_argument("--filter-gram", action="append", default=[], metavar="TAG[,TAG]", help="require tags/features")
    parser.add_argument("--fixlist", metavar="PATH", help="JSONL or form/lemma/tags TSV override dictionary")
    parser.add_argument(
        "--format",
        choices=("text", "json", "jsonl", "xml", "conllu"),
        default="text",
        help=(
            "output format: MyStem text/json/xml or extended JSONL v2 "
            "token/span records and CoNLL-U (default: text)"
        ),
    )
    parser.add_argument("--generate-all", action="store_true", help="retain up to 256 bounded OOV hypotheses")
    parser.add_argument(
        "--weight",
        action="store_true",
        help="emit scores when a scoring layer supplied them",
    )
    parser.add_argument("--no-guesser", action="store_true", help="return explicit unknowns instead of OOV hypotheses")
    parser.add_argument("--guess-limit", type=int, default=8, metavar="N", help="maximum OOV hypotheses (default: 8)")
    parser.add_argument("--resource-dir", metavar="PATH", help="directory containing compiled FST/CG resources")
    parser.add_argument(
        "--ud-profile",
        choices=("universal", "ktb"),
        default="universal",
        help="UD projection profile (default: universal; ktb is corpus compatibility)",
    )
    parser.add_argument("-v", "--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def _read(path: str, encoding: str) -> str:
    if path == "-":
        return sys.stdin.buffer.read().decode(encoding)
    # ``Path.read_text`` uses universal-newline translation.  Opening with an
    # explicit empty ``newline`` value recognizes every line-ending convention
    # while returning CR, CRLF, and LF exactly as they appeared in the file.
    with Path(path).open("r", encoding=encoding, newline="") as stream:
        return stream.read()


def _write(path: str, value: str, encoding: str) -> None:
    if path == "-":
        sys.stdout.buffer.write(value.encode(encoding))
        return
    # Keep formatter-selected line endings byte-faithful on every platform.
    with Path(path).open("w", encoding=encoding, newline="") as stream:
        stream.write(value)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.sentence_markers and not args.copy_input:
        parser.error("-s requires -c")
    if args.sentence_markers and args.format == "json":
        parser.error("-s with --format json is not defined; use jsonl sentence_end fields")
    if args.merge and not args.gram_info:
        parser.error("-g requires -i")
    if args.disambiguate and args.neural:
        parser.error("choose either -d (Constraint Grammar) or --neural")
    if args.guess_limit < 1:
        parser.error("--guess-limit must be positive")
    try:
        codec = codecs.lookup(args.encoding)
        encoded_probe = codec.encode("")[0]
        decoded_probe = codec.decode(b"")[0]
        if not isinstance(encoded_probe, bytes) or not isinstance(decoded_probe, str):
            raise TypeError("codec is not a text encoding")
    except (LookupError, TypeError, ValueError):
        parser.error(f"unsupported text encoding: {args.encoding}")

    filters = frozenset(
        item.strip()
        for group in args.filter_gram
        for item in group.split(",")
        if item.strip()
    )
    try:
        analyzer = Analyzer(
            args.resource_dir,
            disambiguate=args.disambiguate,
            guess=not args.no_guesser,
            fixlist=args.fixlist,
            guess_limit=args.guess_limit,
            neural=args.neural,
            neural_model_dir=args.neural_model_dir,
            neural_use_gpu=False if args.cpu else None,
            ud_profile=args.ud_profile,
        )
        with analyzer:
            document = analyzer.analyze(
                _read(args.input, args.encoding), generate_all=args.generate_all
            )
            if args.format == "text":
                output = format_text(
                    document,
                    copy_input=args.copy_input,
                    newline=args.newline,
                    lemmas_only=args.lemmas_only,
                    gram_info=args.gram_info,
                    merge=args.merge,
                    sentence_markers=args.sentence_markers,
                    weights=args.weight,
                    dictionary_only=args.dictionary_only,
                    filters=filters,
                    selected_only=args.neural,
                )
            elif args.format == "json":
                output = format_mystem_json(
                    document,
                    copy_input=args.copy_input,
                    newline=args.newline,
                    gram_info=args.gram_info,
                    merge=args.merge,
                    weights=args.weight,
                    dictionary_only=args.dictionary_only,
                    filters=filters,
                    selected_only=args.neural,
                )
            elif args.format == "jsonl":
                output = format_jsonl(
                    document,
                    copy_input=args.copy_input,
                    dictionary_only=args.dictionary_only,
                    filters=filters,
                )
            elif args.format == "xml":
                output = format_xml(
                    document,
                    copy_input=args.copy_input,
                    dictionary_only=args.dictionary_only,
                    filters=filters,
                    selected_only=args.neural,
                    gram_info=args.gram_info,
                    merge=args.merge,
                    sentence_markers=args.sentence_markers,
                    weights=args.weight,
                    encoding=codec.name,
                )
            else:
                output = format_conllu(
                    document,
                    dictionary_only=args.dictionary_only,
                    filters=filters,
                )
        _write(args.output, output, args.encoding)
    except (BackendError, FixlistError, XMLFormatError, OSError, UnicodeError) as exc:
        parser.exit(2, f"kazstem: error: {exc}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
