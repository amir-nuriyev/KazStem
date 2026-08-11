from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
import unittest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = PROJECT_ROOT / "scripts" / "verify_guesser_fst.py"
SPEC = importlib.util.spec_from_file_location("qazmorph_verify_guesser_fst", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
verifier = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = verifier
SPEC.loader.exec_module(verifier)


class GuesserFinitenessPrimitiveTests(unittest.TestCase):
    def test_verifier_schema_names_the_extended_bounded_relation(self) -> None:
        self.assertEqual(verifier.SCHEMA, "qazmorph-guesser-finiteness-v2")

    def test_reachable_input_epsilon_cycle_is_reported(self) -> None:
        adjacency = {0: {1}, 1: {2}, 2: {1, 3}}
        epsilon = {1: {2}, 2: {1}}
        cycle = verifier.find_reachable_input_epsilon_cycle(adjacency, epsilon)
        self.assertIsNotNone(cycle)
        assert cycle is not None
        self.assertEqual(cycle[0], cycle[-1])

    def test_unreachable_epsilon_cycle_does_not_fail_reachable_gate(self) -> None:
        adjacency = {0: {1}, 8: {9}, 9: {8}}
        epsilon = {8: {9}, 9: {8}}
        self.assertIsNone(
            verifier.find_reachable_input_epsilon_cycle(adjacency, epsilon)
        )

    def test_input_consuming_cycle_is_finite_valued_per_input(self) -> None:
        adjacency = {0: {1}, 1: {1, 2}}
        epsilon: dict[int, set[int]] = {}
        self.assertIsNone(
            verifier.find_reachable_input_epsilon_cycle(adjacency, epsilon)
        )

    def test_bounded_root_classifier_matches_runtime_contract(self) -> None:
        self.assertEqual(verifier._root_kind("сөздер", "сөз"), "identity")
        self.assertEqual(
            verifier._root_kind("кітабы", "кітап"),
            "stem_final_alternation",
        )
        self.assertEqual(
            verifier._root_kind("аузы", "ауыз", ("n", "px3sp", "nom")),
            "noun_high_vowel_syncope",
        )
        self.assertEqual(
            verifier._root_kind(
                "суперкубогы", "суперкубок", ("n", "px3sp", "nom")
            ),
            "loan_back_harmony_kubok",
        )
        self.assertIsNone(verifier._root_kind("аузы", "ауыз"))
        self.assertIsNone(
            verifier._root_kind(
                "каталогы", "каталок", ("n", "px3sp", "nom")
            )
        )

    def test_checked_in_probe_fixture_is_explicit_and_stratified(self) -> None:
        path = PROJECT_ROOT / "scripts" / "guesser_regression_probes.json"
        probes = verifier._load_probes(path)
        payload = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(
            len(probes),
            len(payload["probes"])
            + payload["adversarial_generation"]["count"],
        )
        self.assertGreaterEqual(len(probes), 362)
        self.assertEqual(
            sum(
                probe.get("class") == "deterministic_adversarial"
                for probe in probes
            ),
            256,
        )
        self.assertGreaterEqual(
            sum(bool(probe.get("expected_readings")) for probe in probes), 20
        )
        self.assertGreaterEqual(
            sum(bool(probe.get("tracked_readings")) for probe in probes), 5
        )
        self.assertGreaterEqual(
            sum(len(probe.get("forbidden_readings", ())) for probe in probes),
            7,
        )


if __name__ == "__main__":
    unittest.main()
