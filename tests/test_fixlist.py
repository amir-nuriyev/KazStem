from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from qazmorph.fixlist import FixlistError, load_fixlist


class FixlistTests(unittest.TestCase):
    def load_text(
        self,
        contents: str,
        *,
        suffix: str = ".txt",
        ud_profile: str = "universal",
    ):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "fixlist" + suffix)
            path.write_text(contents, encoding="utf-8")
            return load_fixlist(path, ud_profile=ud_profile)

    def test_tsv_entries_accept_comma_separated_tags(self) -> None:
        entries = self.load_text("Алматы\tАлматы\tnp,top,nom\n")
        self.assertEqual(set(entries), {"алматы"})
        analysis = entries["алматы"][0]
        self.assertEqual(analysis.lemma, "Алматы")
        self.assertEqual(analysis.tags, ("np", "top", "nom"))
        self.assertEqual(analysis.upos, "PROPN")
        self.assertEqual(
            analysis.feature_map, {"Case": "Nom", "NameType": "Geo"}
        )
        self.assertEqual(analysis.source, "fixlist")

    def test_tsv_entries_accept_angle_bracket_tag_notation(self) -> None:
        entries = self.load_text("сөз\tсөз\t<n><pl><nom>\n")
        analysis = entries["сөз"][0]
        self.assertEqual(analysis.tags, ("n", "pl", "nom"))
        self.assertEqual(
            analysis.feature_map, {"Case": "Nom", "Number": "Plur"}
        )

    def test_ktb_profile_is_used_for_fixlist_projection(self) -> None:
        entries = self.load_text(
            "Алматы\tАлматы\tnp,top,nom\n", ud_profile="ktb"
        )
        self.assertEqual(entries["алматы"][0].feature_map, {"Case": "Nom"})

    def test_jsonl_entries_preserve_unicode_and_tags(self) -> None:
        row = {"form": "ӨЗІ", "lemma": "өз", "tags": ["prn", "ref", "px3sp", "nom"]}
        entries = self.load_text(json.dumps(row, ensure_ascii=False) + "\n", suffix=".jsonl")
        analysis = entries["өзі"][0]
        self.assertEqual(analysis.lemma, "өз")
        self.assertEqual(analysis.upos, "PRON")
        self.assertEqual(analysis.feature_map["Reflex"], "Yes")
        self.assertEqual(analysis.feature_map["Person[psor]"], "3")

    def test_jsonl_defaults_to_an_explicit_x_tag(self) -> None:
        entries = self.load_text('{"form":"opaque","lemma":"opaque"}\n')
        analysis = entries["opaque"][0]
        self.assertEqual(analysis.tags, ("x",))
        self.assertEqual(analysis.upos, "X")

    def test_comments_blank_lines_and_whitespace_are_ignored(self) -> None:
        entries = self.load_text(
            "\n   # comment\n\t\nсөз\tсөз\tn,nom\n# another comment\n"
        )
        self.assertEqual(list(entries), ["сөз"])

    def test_duplicate_forms_accumulate_in_file_order_case_insensitively(self) -> None:
        entries = self.load_text(
            "СӨЗ\tсөз\tn,nom\n"
            "сөз\tсөз\tv,imp,p2,sg\n"
            "Сөз\tСөз\tnp,nom\n"
        )
        self.assertEqual(list(entries), ["сөз"])
        self.assertEqual(
            [analysis.upos for analysis in entries["сөз"]],
            ["NOUN", "VERB", "PROPN"],
        )
        self.assertTrue(all(a.source == "fixlist" for a in entries["сөз"]))

    def test_malformed_tsv_reports_path_and_line_number(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "bad.tsv")
            path.write_text("# valid comment\nword\tlemma\n", encoding="utf-8")
            with self.assertRaises(FixlistError) as caught:
                load_fixlist(path)
        message = str(caught.exception)
        self.assertIn("bad.tsv:2", message)
        self.assertIn("expected three tab-separated columns", message)

    def test_malformed_json_reports_path_and_line_number(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "bad.jsonl")
            path.write_text("\n{not json}\n", encoding="utf-8")
            with self.assertRaises(FixlistError) as caught:
                load_fixlist(path)
        message = str(caught.exception)
        self.assertIn("bad.jsonl:2", message)

    def test_missing_required_json_field_is_a_fixlist_error(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "missing.jsonl")
            path.write_text('{"form":"word","tags":["n"]}\n', encoding="utf-8")
            with self.assertRaises(FixlistError) as caught:
                load_fixlist(path)
        self.assertIn("missing.jsonl:1", str(caught.exception))

    def test_non_iterable_json_tags_are_a_fixlist_error(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "bad-tags.jsonl")
            path.write_text(
                '{"form":"word","lemma":"word","tags":42}\n',
                encoding="utf-8",
            )
            with self.assertRaises(FixlistError) as caught:
                load_fixlist(path)
        self.assertIn("bad-tags.jsonl:1", str(caught.exception))

    def test_missing_file_error_is_not_hidden(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory, "missing.tsv")
            with self.assertRaises(FileNotFoundError):
                load_fixlist(missing)

    def test_invalid_ud_profile_is_rejected_before_file_io(self) -> None:
        with self.assertRaisesRegex(ValueError, "unknown UD projection profile"):
            load_fixlist("missing.tsv", ud_profile="legacy")


if __name__ == "__main__":
    unittest.main()
