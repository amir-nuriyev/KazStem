from __future__ import annotations

import json
import os
from pathlib import Path
import unittest

from qazmorph import Analyzer
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
                    self.assertTrue(lemma)
                    self.assertIsNotNone(productive_root_kind(surface, lemma), raw)
                    readings.add(raw)
                self.assertTrue(set(probe.get("expected_readings", ())) <= readings)

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


if __name__ == "__main__":
    unittest.main()
