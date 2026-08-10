from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from qazmorph import __version__
from qazmorph.cli import _read, _write, build_parser, main
from qazmorph.formats import (
    format_conllu,
    format_jsonl,
    format_mystem_json,
    format_text,
    format_xml,
)
from qazmorph.types import Document, Token


class CliCompatibilityTests(unittest.TestCase):
    @staticmethod
    def _lossless_echo_document(text: str) -> Document:
        tokens: list[Token] = []
        start = 0
        while start < len(text):
            whitespace = text[start].isspace()
            end = start + 1
            while end < len(text) and text[end].isspace() == whitespace:
                end += 1
            tokens.append(
                Token(
                    text[start:end],
                    start,
                    end,
                    "space" if whitespace else "symbol",
                )
            )
            start = end
        return Document(text, tokens, "lattice", "test")

    def test_public_and_package_versions_are_0_2_0(self) -> None:
        project = (
            Path(__file__).resolve().parents[1] / "pyproject.toml"
        ).read_text(
            encoding="utf-8"
        )
        self.assertEqual(__version__, "0.2.0")
        self.assertIn(f'version = "{__version__}"', project)

    def test_unix_short_options_can_be_clustered(self) -> None:
        args = build_parser().parse_args(["-cin"])
        self.assertTrue(args.copy_input)
        self.assertTrue(args.gram_info)
        self.assertTrue(args.newline)

    def test_ud_profile_is_explicit_and_defaults_to_universal(self) -> None:
        self.assertEqual(build_parser().parse_args([]).ud_profile, "universal")
        self.assertEqual(
            build_parser().parse_args(["--ud-profile", "ktb"]).ud_profile,
            "ktb",
        )

    def test_legacy_help_and_version_aliases_exit_successfully(self) -> None:
        for option in ("-?", "-v"):
            output = io.StringIO()
            with self.subTest(option=option), redirect_stdout(output):
                with self.assertRaises(SystemExit) as raised:
                    build_parser().parse_args([option])
                self.assertEqual(raised.exception.code, 0)
            if option == "-v":
                self.assertEqual(output.getvalue(), f"kazstem {__version__}\n")

    def test_merge_requires_grammar_information(self) -> None:
        with redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as raised:
                main(["-g"])
        self.assertEqual(raised.exception.code, 2)

    def test_sentence_markers_require_copy_mode(self) -> None:
        with redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as raised:
                main(["-s"])
        self.assertEqual(raised.exception.code, 2)

    def test_json_sentence_marker_shape_is_rejected_not_invented(self) -> None:
        with redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as raised:
                main(["-cs", "--format", "json"])
        self.assertEqual(raised.exception.code, 2)

    def test_binary_transform_codec_is_rejected_as_an_encoding(self) -> None:
        with redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as raised:
                main(["-e", "base64_codec"])
        self.assertEqual(raised.exception.code, 2)

    def test_filename_helpers_preserve_newlines_unicode_and_reserved_characters(self) -> None:
        payload = "А\u0301^[]{}$/\\<>@#*+\rБ\r\nВ\nГ"
        encoded = payload.encode("utf-8")
        with tempfile.TemporaryDirectory() as temporary:
            input_path = Path(temporary) / "input.txt"
            output_path = Path(temporary) / "output.txt"
            input_path.write_bytes(encoded)

            self.assertEqual(_read(str(input_path), "utf-8"), payload)
            _write(str(output_path), payload, "utf-8")

            self.assertEqual(output_path.read_bytes(), encoded)

    def test_positional_file_io_preserves_exact_input_for_every_output_mode(self) -> None:
        payload = "А\u0301^[]{}$/\\<>@#*+\rБ\r\nВ\nГ"

        class EchoAnalyzer:
            last_text: str | None = None

            def __init__(self, *args: object, **kwargs: object) -> None:
                pass

            def __enter__(self) -> "EchoAnalyzer":
                return self

            def __exit__(self, *args: object) -> None:
                pass

            def analyze(self, text: str, **kwargs: object) -> Document:
                type(self).last_text = text
                return CliCompatibilityTests._lossless_echo_document(text)

        document = self._lossless_echo_document(payload)
        expected = {
            "text": format_text(document, copy_input=True),
            "json": format_mystem_json(document, copy_input=True),
            "jsonl": format_jsonl(document, copy_input=True),
            "xml": format_xml(document, copy_input=True, gram_info=False, encoding="utf-8"),
            "conllu": format_conllu(document),
        }
        with tempfile.TemporaryDirectory() as temporary, mock.patch(
            "qazmorph.cli.Analyzer", EchoAnalyzer
        ):
            root = Path(temporary)
            input_path = root / "input.txt"
            input_path.write_bytes(payload.encode("utf-8"))
            for output_format, expected_output in expected.items():
                with self.subTest(output_format=output_format):
                    output_path = root / f"output.{output_format}"
                    EchoAnalyzer.last_text = None

                    self.assertEqual(
                        main(
                            [
                                "-c",
                                "--format",
                                output_format,
                                str(input_path),
                                str(output_path),
                            ]
                        ),
                        0,
                    )

                    self.assertEqual(EchoAnalyzer.last_text, payload)
                    self.assertEqual(
                        output_path.read_bytes(), expected_output.encode("utf-8")
                    )
                    if output_format == "json":
                        self.assertEqual(
                            "".join(row["text"] for row in json.loads(expected_output)),
                            payload,
                        )
                    elif output_format == "jsonl":
                        self.assertEqual(
                            "".join(
                                json.loads(line)["text"]
                                for line in expected_output.splitlines()
                            ),
                            payload,
                        )

    def test_xml_forbidden_input_exits_cleanly_without_a_traceback(self) -> None:
        class FakeAnalyzer:
            def __init__(self, *args: object, **kwargs: object) -> None:
                pass

            def __enter__(self) -> "FakeAnalyzer":
                return self

            def __exit__(self, *args: object) -> None:
                pass

            def analyze(self, *args: object, **kwargs: object) -> Document:
                return Document(
                    "\x00",
                    [Token("\x00", 0, 1, "symbol")],
                    "lattice",
                    "test",
                )

        errors = io.StringIO()
        with mock.patch("qazmorph.cli.Analyzer", FakeAnalyzer), mock.patch(
            "qazmorph.cli._read", return_value="\x00"
        ), redirect_stderr(errors):
            with self.assertRaises(SystemExit) as raised:
                main(["-c", "--format", "xml"])

        self.assertEqual(raised.exception.code, 2)
        diagnostic = errors.getvalue()
        self.assertIn("XML 1.0-forbidden code point U+0000", diagnostic)
        self.assertNotIn("Traceback", diagnostic)


if __name__ == "__main__":
    unittest.main()
