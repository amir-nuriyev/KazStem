from __future__ import annotations

import unittest
import unicodedata

from qazmorph.normalization import nfc_with_boundary_map


class NormalizationTests(unittest.TestCase):
    def test_decomposed_cyrillic_cluster_maps_to_original_boundaries(self) -> None:
        normalized, boundaries = nfc_with_boundary_map("Aи\u0306B")
        self.assertEqual(normalized, "AйB")
        self.assertEqual(boundaries, [0, 1, 3, 4])

    def test_already_normalized_text_uses_identity_boundaries(self) -> None:
        text = "Қазақстан"
        normalized, boundaries = nfc_with_boundary_map(text)
        self.assertEqual(normalized, text)
        self.assertEqual(boundaries, list(range(len(text) + 1)))

    def test_zero_combining_class_hangul_jamo_are_composed(self) -> None:
        normalized, boundaries = nfc_with_boundary_map("X\u1100\u1161\u11A8Y")
        self.assertEqual(normalized, "X각Y")
        self.assertEqual(boundaries, [0, 1, 4, 5])

    def test_tokenizable_space_boundary_survives_a_following_combining_mark(self) -> None:
        normalized, boundaries = nfc_with_boundary_map("и\u0306 \u0301")
        self.assertEqual(normalized, "й \u0301")
        self.assertEqual(boundaries, [0, 2, 3, 4])

    def test_reordered_marks_never_make_boundaries_move_backward(self) -> None:
        normalized, boundaries = nfc_with_boundary_map("а\u0301\u0323")
        self.assertEqual(normalized, unicodedata.normalize("NFC", "а\u0301\u0323"))
        self.assertEqual(boundaries[0], 0)
        self.assertEqual(boundaries[-1], 3)
        self.assertTrue(all(a <= b for a, b in zip(boundaries, boundaries[1:])))


if __name__ == "__main__":
    unittest.main()
