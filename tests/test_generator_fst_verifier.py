from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = PROJECT_ROOT / "scripts" / "verify_generator_fst.py"
SPEC = importlib.util.spec_from_file_location(
    "qazmorph_verify_generator_fst", SCRIPT
)
assert SPEC is not None and SPEC.loader is not None
verifier = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = verifier
SPEC.loader.exec_module(verifier)


class GeneratorFstVerifierTests(unittest.TestCase):
    def test_schema_is_stable(self) -> None:
        self.assertEqual(
            verifier.SCHEMA,
            "qazmorph-productive-generator-finiteness-v2",
        )

    def test_reachable_input_epsilon_cycle_is_reported(self) -> None:
        adjacency = {0: {1}, 1: {2}, 2: {1, 3}}
        epsilon = {1: {2}, 2: {1}}
        cycle = verifier.find_reachable_input_epsilon_cycle(adjacency, epsilon)
        self.assertEqual(cycle, (1, 2, 1))

    def test_unreachable_input_epsilon_cycle_is_ignored(self) -> None:
        adjacency = {0: {1}, 8: {9}, 9: {8}}
        epsilon = {8: {9}, 9: {8}}
        self.assertIsNone(
            verifier.find_reachable_input_epsilon_cycle(adjacency, epsilon)
        )

    def test_input_consuming_cycle_is_finite_valued_per_input(self) -> None:
        adjacency = {0: {1}, 1: {1, 2}}
        self.assertIsNone(
            verifier.find_reachable_input_epsilon_cycle(adjacency, {})
        )

    def test_graph_parser_rejects_multiple_transducers_and_malformed_rows(self) -> None:
        with self.assertRaisesRegex(verifier.VerificationError, "one transducer"):
            verifier._parse_graph(["0\t1\ta\ta", "1", "--", "0"])
        with self.assertRaisesRegex(verifier.VerificationError, "cannot parse"):
            verifier._parse_graph(["0\tbad\ta\ta", "1"])
        with self.assertRaisesRegex(verifier.VerificationError, "cannot parse"):
            verifier._parse_graph(["0\t1\ta\ta\tnot-a-weight", "1"])

    def test_checked_in_fixture_has_required_and_forbidden_inverse_pairs(self) -> None:
        pairs = verifier._load_probe_pairs(
            PROJECT_ROOT / "scripts" / "guesser_regression_probes.json"
        )
        self.assertEqual(len(pairs.required), 64)
        self.assertEqual(len(pairs.forbidden), 7)
        self.assertEqual(len(pairs.queries), 71)
        self.assertIn(
            ("кітап<n><px3sp><nom>", "кітабы"),
            pairs.required,
        )
        self.assertIn(
            ("каталок<n><px3sp><nom>", "каталогы"),
            pairs.forbidden,
        )

    def test_direction_fixture_is_exact_and_immutable(self) -> None:
        pairs = verifier._load_direction_probe_pairs(
            PROJECT_ROOT / "scripts" / "generator_regression_probes.json"
        )
        self.assertEqual(len(pairs.required), 3)
        self.assertEqual(len(pairs.forbidden), 3)
        self.assertEqual(len(pairs.queries), 3)
        self.assertIn(("тосынтүбір<n><ins>", "тосынтүбірмен"), pairs.required)
        self.assertIn(
            ("тосынтүбір<n><ins>", "тосынтүбірменен"),
            pairs.forbidden,
        )

    def test_standard_and_optimized_lookup_framing_parse_to_same_sets(self) -> None:
        queries = ("кітап<n><px3sp><nom>", "жоқ<n><nom>")
        standard = verifier._parse_lookup_output(
            "кітап<n><px3sp><nom>\tкітабы\t0.000000\n\n"
            "жоқ<n><nom>\tжоқ<n><nom>+?\tinf\n\n",
            queries,
        )
        optimized = verifier._parse_lookup_output(
            "кітап<n><px3sp><nom>\tкітабы\n\n"
            "жоқ<n><nom>\tжоқ<n><nom>\t+?\n\n",
            queries,
        )
        self.assertEqual(standard, optimized)
        self.assertEqual(standard["кітап<n><px3sp><nom>"], ("кітабы",))
        self.assertEqual(standard["жоқ<n><nom>"], ())

    def test_lookup_parser_rejects_unkeyed_and_missing_responses(self) -> None:
        with self.assertRaisesRegex(verifier.VerificationError, "unkeyed"):
            verifier._parse_lookup_output("other\tform\n", ("query",))
        with self.assertRaisesRegex(verifier.VerificationError, "no keyed response"):
            verifier._parse_lookup_output("", ("query",))

    def test_lookup_parser_rejects_malformed_lines_and_weights(self) -> None:
        with self.assertRaisesRegex(verifier.VerificationError, "malformed"):
            verifier._parse_lookup_output("query\n", ("query",))
        with self.assertRaisesRegex(verifier.VerificationError, "malformed weight"):
            verifier._parse_lookup_output(
                "query\tform\tnot-a-weight\n", ("query",)
            )
        with self.assertRaisesRegex(verifier.VerificationError, "non-finite"):
            verifier._parse_lookup_output("query\tform\tinf\n", ("query",))
        with self.assertRaisesRegex(verifier.VerificationError, "malformed negative"):
            verifier._parse_lookup_output("query\tother\t+?\n", ("query",))
        with self.assertRaisesRegex(verifier.VerificationError, "control syntax"):
            verifier._parse_lookup_output("query\tquery\n", ("query",))
        with self.assertRaisesRegex(verifier.VerificationError, "control syntax"):
            verifier._parse_lookup_output("query\tform<n>\n", ("query",))

    def test_lookup_parser_rejects_cycle_and_cap_control_markers(self) -> None:
        with self.assertRaisesRegex(verifier.VerificationError, "control marker"):
            verifier._parse_lookup_output(
                "query\t[...cyclic...]\t0.0\n", ("query",)
            )
        with self.assertRaisesRegex(verifier.VerificationError, "control marker"):
            verifier._parse_lookup_output(
                "query\t[...truncated...]\t0.0\n", ("query",)
            )
        with self.assertRaisesRegex(verifier.VerificationError, "control marker"):
            verifier._parse_lookup_output(
                "query\t[arbitrary-control]\t0.0\n", ("query",)
            )

    def test_lookup_parser_rejects_mixed_negative_and_candidates(self) -> None:
        with self.assertRaisesRegex(verifier.VerificationError, "mixed"):
            verifier._parse_lookup_output(
                "query\tquery+?\tinf\nquery\tform\t0.0\n",
                ("query",),
            )

    def test_atomic_json_is_sorted_utf8_and_replaces_complete_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "report.json"
            verifier._atomic_json(output, {"z": "қазақ", "a": 1})
            self.assertEqual(
                output.read_text(encoding="utf-8"),
                '{\n  "a": 1,\n  "z": "қазақ"\n}\n',
            )
            self.assertEqual(json.loads(output.read_text(encoding="utf-8"))["a"], 1)
            self.assertEqual(list(output.parent.glob(".report.json.*.tmp")), [])


if __name__ == "__main__":
    unittest.main()
