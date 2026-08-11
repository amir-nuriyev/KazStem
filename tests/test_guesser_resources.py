from __future__ import annotations

from copy import deepcopy
import json
import os
from pathlib import Path
import re
import unittest

from qazmorph import Analyzer
from qazmorph.backend import _has_verified_v3_guesser_gate, GUESSER_FINITE_SCHEMA_V2
from qazmorph.guesser import (
    CYCLE_MARKER,
    OpenClassGuesser,
    productive_root_kind,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]
RESOURCE_DIR = os.environ.get("QAZMORPH_RESOURCE_DIR")


@unittest.skipUnless(
    RESOURCE_DIR,
    "resource-backed guesser tests run only when QAZMORPH_RESOURCE_DIR is set",
)
class ProductiveGuesserResourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        assert RESOURCE_DIR is not None
        cls.analyzer = Analyzer(resource_dir=RESOURCE_DIR, guess=False)
        cls.guesser = OpenClassGuesser(cls.analyzer.backend)
        payload = json.loads(
            (PROJECT_ROOT / "scripts" / "guesser_regression_probes.json").read_text(
                encoding="utf-8"
            )
        )
        cls.probes = payload["probes"]

    @classmethod
    def tearDownClass(cls) -> None:
        cls.guesser.close()
        cls.analyzer.close()

    def test_no_cap_probe_responses_are_finite_and_bounded_rooted(self) -> None:
        for probe in self.probes:
            surface = probe["surface"]
            with self.subTest(surface=surface):
                lines = self.guesser._raw_lookup(surface, max_lines=512, timeout=5.0)
                self.assertTrue(lines)
                self.assertFalse(any(CYCLE_MARKER in line for line in lines))
                readings: set[str] = set()
                for line in lines:
                    fields = line.split("\t")
                    self.assertGreaterEqual(len(fields), 2)
                    self.assertEqual(fields[0], surface)
                    raw = fields[1]
                    lemma = raw.split("<", 1)[0] if "<" in raw else ""
                    tags = tuple(re.findall(r"<([^<>]+)>", raw))
                    self.assertTrue(lemma)
                    self.assertIsNotNone(
                        productive_root_kind(surface, lemma, tags), raw
                    )
                    readings.add(raw)
                self.assertTrue(set(probe.get("expected_readings", ())) <= readings)
                self.assertTrue(
                    set(probe.get("forbidden_readings", ())).isdisjoint(readings)
                )

        diagnostics = self.guesser.diagnostics
        for counter in (
            "cap_aborts",
            "cycle_truncations",
            "timeouts",
            "failures",
        ):
            self.assertEqual(diagnostics[counter], 0)

    def test_correlated_negative_cannot_shift_later_productive_responses(self) -> None:
        negative = "кеңесіуінің"
        lines = self.guesser._raw_lookup(negative, max_lines=512, timeout=5.0)
        self.assertEqual(lines, [f"{negative}\t{negative}\t+?"])

        for surface in (
            "хаттамалық",
            "процессуалдық",
            "кішігірім",
            "жұптық",
            "ағылш",
        ):
            with self.subTest(surface=surface):
                response = self.guesser._raw_lookup(
                    surface, max_lines=512, timeout=5.0
                )
                self.assertTrue(response)
                self.assertTrue(
                    all(line.split("\t", 1)[0] == surface for line in response)
                )

        self.assertEqual(self.guesser.diagnostics["protocol_restarts"], 0)

    def test_active_v2_gate_is_accepted_and_tamper_sensitive(self) -> None:
        manifest = self.analyzer.backend.manifest
        result = manifest["build"]["verification"][
            "productive_guesser_finite_valued"
        ]["result"]
        if result.get("schema") != GUESSER_FINITE_SCHEMA_V2:
            self.skipTest("active resource does not carry the v2 guesser gate")
        self.assertTrue(_has_verified_v3_guesser_gate(manifest))

        mutations = []
        for section, field, value in (
            ("graph", "reachable_input_epsilon_cycle", True),
            ("baseline_relation", "baseline_subset_of_final", False),
            ("no_cap_probes", "forbidden_readings_observed", 1),
        ):
            changed = deepcopy(manifest)
            changed["build"]["verification"][
                "productive_guesser_finite_valued"
            ]["result"][section][field] = value
            mutations.append(changed)
        generic_loan = deepcopy(manifest)
        generic_loan["build"]["verification"][
            "productive_guesser_finite_valued"
        ]["result"]["no_cap_probes"]["bounded_root_relation"][
            "loan_back_harmony"
        ]["generic_back_harmony_g_to_k"] = True
        mutations.append(generic_loan)
        for index, changed in enumerate(mutations):
            with self.subTest(mutation=index):
                self.assertFalse(_has_verified_v3_guesser_gate(changed))


if __name__ == "__main__":
    unittest.main()
