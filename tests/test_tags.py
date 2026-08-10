from __future__ import annotations

import unittest

from qazmorph.tags import POS_MAP, project_ud, project_ud_alternatives


class ProjectUdPosTests(unittest.TestCase):
    def test_every_declared_pos_tag_projects_to_its_declared_upos(self) -> None:
        for tag, expected in POS_MAP.items():
            with self.subTest(tag=tag):
                upos, _ = project_ud((tag,))
                self.assertEqual(upos, expected)

    def test_unknown_or_usage_only_tags_do_not_invent_a_pos(self) -> None:
        for tags in ((), ("future_tag",), ("attr",), ("subst",), ("advl",)):
            with self.subTest(tags=tags):
                self.assertEqual(project_ud(tags)[0], "X")

    def test_usage_tags_do_not_relabel_the_lexical_pos(self) -> None:
        cases = {
            ("adj", "advl"): "ADJ",
            ("adj", "subst"): "ADJ",
            ("adv", "attr"): "ADV",
            ("v", "subst"): "VERB",
        }
        for tags, expected in cases.items():
            with self.subTest(tags=tags):
                self.assertEqual(project_ud(tags)[0], expected)

    def test_explicit_usage_tags_license_additive_upos_views(self) -> None:
        cases = {
            ("adj", "subst", "pl", "nom"): (
                "NOUN",
                {"Case": "Nom", "Number": "Plur"},
            ),
            ("n", "loc", "attr"): ("ADJ", {"Case": "Loc"}),
            ("adj", "comp", "advl"): ("ADV", {"Degree": "Cmp"}),
        }
        for tags, (expected_upos, expected_features) in cases.items():
            with self.subTest(tags=tags):
                alternatives = project_ud_alternatives(tags)
                self.assertEqual(
                    alternatives,
                    ((expected_upos, tuple(sorted(expected_features.items()))),),
                )

    def test_pronoun_determiner_swaps_are_not_invented(self) -> None:
        for tags in (
            ("prn", "dem", "nom"),
            ("prn", "qnt", "nom"),
            ("det", "dem"),
            ("det", "ref"),
        ):
            with self.subTest(tags=tags):
                self.assertEqual(project_ud_alternatives(tags), ())

    def test_ordinary_verbs_are_not_relabelled_as_auxiliaries(self) -> None:
        upos, _ = project_ud(("v", "aor", "p3", "sg"))
        self.assertEqual(upos, "VERB")


class ProjectUdNominalTests(unittest.TestCase):
    def assertProjection(
        self,
        tags: tuple[str, ...],
        expected_upos: str,
        expected_features: dict[str, str],
        *,
        profile: str = "universal",
    ) -> None:
        upos, features = project_ud(tags, profile=profile)
        self.assertEqual(upos, expected_upos)
        self.assertEqual(dict(features), expected_features)
        self.assertEqual(features, tuple(sorted(features)))

    def test_geographical_proper_noun(self) -> None:
        self.assertProjection(
            ("np", "top", "gen"),
            "PROPN",
            {"Case": "Gen", "NameType": "Geo"},
        )

    def test_abbreviation_is_a_noun_with_abbreviation_feature(self) -> None:
        self.assertProjection(("abbr",), "NOUN", {"Abbr": "Yes"})

    def test_primary_case_wins_over_attr_and_secondary_cases(self) -> None:
        cases = {
            ("n", "loc", "attr"): "Loc",
            ("prn", "dem", "sim", "acc"): "Acc",
            ("n", "gen", "subst", "nom"): "Nom",
            ("n", "abe", "dat"): "Dat",
        }
        for tags, expected_case in cases.items():
            with self.subTest(tags=tags):
                _, features = project_ud(tags)
                self.assertEqual(dict(features)["Case"], expected_case)

    def test_last_primary_case_is_selected(self) -> None:
        _, features = project_ud(("n", "loc", "abl", "nom"))
        self.assertEqual(dict(features)["Case"], "Nom")

    def test_secondary_case_is_used_when_no_primary_case_exists(self) -> None:
        cases = {
            "sim": "Equ",
            "equ": "Equ",
            "abe": "Abe",
            "reas": "Cau",
        }
        for tag, expected in cases.items():
            with self.subTest(tag=tag):
                _, features = project_ud(("n", tag))
                self.assertEqual(dict(features)["Case"], expected)

    def test_bare_attributive_usage_defaults_to_nominative(self) -> None:
        self.assertProjection(("adj", "attr"), "ADJ", {"Case": "Nom"})

    def test_reflexive_pronoun_and_underspecified_possessor(self) -> None:
        self.assertProjection(
            ("prn", "ref", "px3sp", "nom"),
            "PRON",
            {
                "Case": "Nom",
                "Number[psor]": "Plur,Sing",
                "Person[psor]": "3",
                "PronType": "Prs",
                "Reflex": "Yes",
            },
        )

    def test_reflexive_determiner_keeps_reflex_feature(self) -> None:
        self.assertProjection(
            ("det", "ref"),
            "DET",
            {"PronType": "Prs", "Reflex": "Yes"},
        )

    def test_demonstrative_overrides_combined_quantifying_pronoun_type(self) -> None:
        self.assertProjection(
            ("prn", "dem", "qnt", "nom"),
            "PRON",
            {"Case": "Nom", "PronType": "Dem"},
        )

    def test_collective_numeral_uses_legal_universal_value(self) -> None:
        self.assertProjection(
            ("num", "coll", "px3sp", "nom"),
            "NUM",
            {
                "Case": "Nom",
                "Number[psor]": "Plur,Sing",
                "NumType": "Sets",
                "Person[psor]": "3",
            },
        )

    def test_ktb_profile_retains_treebank_collective_convention(self) -> None:
        self.assertProjection(
            ("num", "coll"),
            "NUM",
            {"NumType": "Coll"},
            profile="ktb",
        )

    def test_ktb_profile_omits_detail_absent_from_treebank_inventory(self) -> None:
        self.assertProjection(
            ("np", "top", "abbr", "equ"),
            "PROPN",
            {},
            profile="ktb",
        )

    def test_bare_and_specialized_numerals(self) -> None:
        cases = {
            ("num",): "Card",
            ("num", "ord"): "Ord",
            ("num", "dist"): "Dist",
            ("num", "percent", "nom"): "Card",
        }
        for tags, num_type in cases.items():
            with self.subTest(tags=tags):
                upos, features = project_ud(tags)
                self.assertEqual(upos, "NUM")
                self.assertEqual(dict(features)["NumType"], num_type)

    def test_bare_decimal_numeric_semantics_are_additive_and_profiled(self) -> None:
        self.assertEqual(
            project_ud_alternatives(("num",), bare_decimal=True),
            (("NUM", (("NumType", "Ord"),)),),
        )
        self.assertEqual(
            project_ud_alternatives(
                ("num", "subst", "nom"), profile="ktb", bare_decimal=True
            ),
            (
                ("NUM", (("Case", "Nom"), ("NumType", "Ord"))),
                ("NUM", (("Case", "Nom"), ("NumType", "Card,Ord"))),
            ),
        )

    def test_explicit_numeric_semantics_and_nondecimal_surfaces_get_no_alias(self) -> None:
        for tags, bare_decimal in (
            (("num",), False),
            (("num", "ord"), True),
            (("num", "coll"), True),
            (("num", "dist"), True),
        ):
            with self.subTest(tags=tags, bare_decimal=bare_decimal):
                self.assertEqual(
                    project_ud_alternatives(tags, bare_decimal=bare_decimal), ()
                )

    def test_proper_name_and_gender_mappings(self) -> None:
        cases = {
            "top": "Geo",
            "ant": "Giv",
            "cog": "Sur",
            "pat": "Pat",
            "org": "Com",
            "al": "Oth",
        }
        for tag, name_type in cases.items():
            with self.subTest(tag=tag):
                _, features = project_ud(("np", tag, "m"))
                self.assertEqual(
                    dict(features), {"Gender": "Masc", "NameType": name_type}
                )

        _, common_gender = project_ud(("np", "mf"))
        self.assertNotIn("Gender", dict(common_gender))
        _, common_noun = project_ud(("n", "f"))
        self.assertNotIn("Gender", dict(common_noun))


class ProjectUdVerbalTests(unittest.TestCase):
    def assertFeatures(self, tags: tuple[str, ...], expected: dict[str, str]) -> None:
        upos, features = project_ud(tags)
        self.assertEqual(upos, "VERB")
        self.assertEqual(dict(features), expected)

    def test_evidential_definite_past(self) -> None:
        self.assertFeatures(
            ("v", "iv", "ifi", "evid", "p3", "sg"),
            {
                "Evident": "Nfh",
                "Mood": "Ind",
                "Number": "Sing",
                "Person": "3",
                "Tense": "Past",
                "VerbForm": "Fin",
            },
        )

    def test_compound_evidential_tag_and_ktb_profile(self) -> None:
        _, universal = project_ud(("v", "ifi_evid", "p3", "sg"))
        _, ktb = project_ud(("v", "ifi_evid", "p3", "sg"), profile="ktb")
        self.assertEqual(dict(universal)["Evident"], "Nfh")
        self.assertEqual(dict(ktb)["Evident"], "Fh")

    def test_aorist_is_legal_ud_habitual_present(self) -> None:
        self.assertFeatures(
            ("v", "iv", "aor", "p3", "sg"),
            {
                "Aspect": "Hab",
                "Mood": "Ind",
                "Number": "Sing",
                "Person": "3",
                "Tense": "Pres",
                "VerbForm": "Fin",
            },
        )

    def test_perfect_prc_is_infinitive_in_the_projection(self) -> None:
        self.assertFeatures(
            ("v", "tv", "pass", "prc_perf"),
            {"Aspect": "Perf", "VerbForm": "Inf", "Voice": "Pass"},
        )

    def test_perfect_converb(self) -> None:
        self.assertFeatures(
            ("v", "iv", "gna_perf"),
            {"Aspect": "Perf", "VerbForm": "Conv"},
        )

    def test_multiple_voices_are_sorted_in_one_feature(self) -> None:
        self.assertFeatures(
            ("v", "caus", "pass", "prc_perf"),
            {"Aspect": "Perf", "VerbForm": "Inf", "Voice": "Cau,Pass"},
        )

    def test_finite_and_nonfinite_form_families(self) -> None:
        cases = {
            ("v", "imp"): {"Mood": "Imp", "VerbForm": "Fin"},
            ("v", "opt"): {"Mood": "Opt", "VerbForm": "Fin"},
            ("v", "pres"): {"Mood": "Ind", "Tense": "Pres", "VerbForm": "Fin"},
            ("v", "fut_plan"): {"Mood": "Des", "Tense": "Fut", "VerbForm": "Fin"},
            ("v", "prc_plan"): {"Mood": "Prp", "VerbForm": "Inf"},
            ("v", "gna_cond"): {"Mood": "Cnd", "VerbForm": "Conv"},
            ("v", "gpr_pot"): {"Mood": "Pot", "VerbForm": "Part"},
            ("v", "ger_ppot"): {"Mood": "Pot", "Tense": "Past", "VerbForm": "Ger"},
        }
        for tags, expected in cases.items():
            with self.subTest(tags=tags):
                self.assertFeatures(tags, expected)

    def test_negative_tag_is_pos_sensitive(self) -> None:
        _, verbal = project_ud(("v", "neg", "pres"))
        _, pronominal = project_ud(("prn", "neg"))
        _, nominal = project_ud(("n", "neg"))
        self.assertEqual(dict(verbal)["Polarity"], "Neg")
        self.assertEqual(dict(pronominal)["PronType"], "Neg")
        self.assertNotIn("Polarity", dict(nominal))
        self.assertNotIn("PronType", dict(nominal))


class ProjectUdGeneralTests(unittest.TestCase):
    def test_particles_receive_specific_part_type(self) -> None:
        cases = {
            "qst": "Int",
            "emph": "Emp",
            "mod": "Mod",
            "mod_ass": "Mod",
            "mod_emo": "Mod",
        }
        for tag, expected in cases.items():
            with self.subTest(tag=tag):
                upos, features = project_ud((tag,))
                self.assertEqual(upos, "PART")
                self.assertEqual(dict(features)["PartType"], expected)

    def test_guessed_and_orthographic_error_flags(self) -> None:
        upos, features = project_ud(("np", "unk", "err_orth"))
        self.assertEqual(upos, "PROPN")
        self.assertEqual(dict(features), {"Foreign": "Yes", "Typo": "Yes"})

    def test_unknown_tags_are_ignored_without_losing_known_projection(self) -> None:
        baseline = project_ud(("n", "loc"))
        projected = project_ud(("n", "future_tag", "loc"))
        self.assertEqual(projected, baseline)

    def test_iterables_are_accepted(self) -> None:
        upos, features = project_ud(tag for tag in ("n", "pl", "nom"))
        self.assertEqual(upos, "NOUN")
        self.assertEqual(dict(features), {"Case": "Nom", "Number": "Plur"})

    def test_features_are_canonically_sorted(self) -> None:
        _, features = project_ud(("v", "pass", "ifi", "evid", "p3", "pl"))
        self.assertEqual(features, tuple(sorted(features)))

    def test_unknown_profile_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "unknown UD projection profile"):
            project_ud(("n",), profile="legacy")


if __name__ == "__main__":
    unittest.main()
