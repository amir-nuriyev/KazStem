from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest

from qazmorph import Analysis, Document, Morpheme, Token


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def load_script(name: str):
    path = PROJECT_ROOT / "scripts" / name
    module_name = f"qazmorph_test_{path.stem}"
    specification = importlib.util.spec_from_file_location(module_name, path)
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    sys.modules[module_name] = module
    specification.loader.exec_module(module)
    return module


evaluation = load_script("evaluate_ud.py")
benchmark = load_script("benchmark.py")
raw_evaluation = load_script("evaluate_raw.py")


def gold(
    token_id: int,
    form: str,
    lemma: str | None = None,
    upos: str = "NOUN",
    features: tuple[tuple[str, str], ...] = (),
):
    return evaluation.GoldToken(
        token_id,
        form,
        lemma if lemma is not None else form.casefold(),
        upos,
        features,
        "_",
    )


def predicted(text: str, *, kind: str = "word", analyses=()):
    analyses = tuple(analyses)
    chosen = analyses[0] if len(analyses) == 1 else None
    return evaluation.PredictedToken(
        text,
        kind,
        analyses,
        chosen,
        0 if chosen is not None else None,
    )


def analysis(
    lemma: str,
    upos: str,
    features: tuple[tuple[str, str], ...] = (),
    *,
    source: str = "lexicon",
    guessed: bool = False,
    context_upos: str | None = None,
    context_features: tuple[tuple[str, str], ...] = (),
    raw: str | None = None,
) -> Analysis:
    tags = (upos.casefold(),)
    return Analysis(
        lemma,
        upos,
        features,
        tags,
        (Morpheme(lemma, tags, upos, features),),
        raw if raw is not None else lemma + "<" + upos.casefold() + ">",
        source=source,
        guessed=guessed,
        context_upos=context_upos,
        context_features=context_features,
    )


class UdAlignmentTests(unittest.TestCase):
    def test_exact_one_to_one_alignment_is_directly_scorable(self) -> None:
        result = evaluation.align_tokens(
            (gold(1, "Бір"), gold(2, "сөз")),
            (predicted("Бір"), predicted("сөз")),
            max_group=4,
        )
        self.assertEqual(result.direct, {0: 0, 1: 1})
        self.assertEqual(result.counts.one_to_one_exact, 2)
        self.assertEqual(result.counts.grouped_operations, 0)
        self.assertEqual(result.counts.unaligned_gold_tokens, 0)

    def test_nonconcatenative_ud_mwt_uses_authoritative_surface(self) -> None:
        result = evaluation.align_tokens(
            (gold(1, "бұз", upos="VERB"), gold(2, "ау", upos="PART")),
            (predicted("бұзылады-ау"),),
            max_group=4,
            multiword_spans=(evaluation.SurfaceToken(1, 2, "бұзылады-ау", "_"),),
        )
        self.assertEqual(result.direct, {})
        self.assertEqual(result.counts.grouped_operations, 1)
        self.assertEqual(result.counts.grouped_gold_tokens, 2)
        self.assertEqual(result.counts.grouped_predicted_tokens, 1)
        self.assertEqual(result.counts.unaligned_gold_tokens, 0)

    def test_partial_mwt_components_cannot_be_scored_as_direct_matches(self) -> None:
        result = evaluation.align_tokens(
            (gold(1, "бұз"), gold(2, "ау"), gold(3, "сөз")),
            (predicted("бұз"), predicted("ау"), predicted("сөз")),
            max_group=4,
            multiword_spans=(evaluation.SurfaceToken(1, 2, "бұзылады-ау", "_"),),
        )
        self.assertEqual(result.direct, {2: 2})
        self.assertEqual(result.counts.one_to_one_exact, 1)
        self.assertEqual(result.counts.unaligned_gold_tokens, 2)
        self.assertEqual(result.counts.unaligned_predicted_tokens, 2)

    def test_group_diagnostics_classify_ud_mwt_without_morphology_scoring(self) -> None:
        tokens = (gold(1, "бала"), gold(2, "сыз", upos="ADP"))
        span = evaluation.SurfaceToken(1, 2, "Баласыз", "_")
        sentence = evaluation.GoldSentence(
            Path("synthetic.conllu"),
            1,
            "synthetic-1",
            "Баласыз",
            tokens,
            1,
            0,
            True,
            (span,),
        )
        predicted_tokens = (predicted("Баласыз"),)
        result = evaluation.align_tokens(
            tokens, predicted_tokens, max_group=4, multiword_spans=(span,)
        )
        diagnostics = evaluation.AlignmentDiagnostics()
        diagnostics.add(sentence, predicted_tokens, result)
        rendered = diagnostics.as_json()
        self.assertEqual(
            rendered["group_evidence_class_distribution"],
            {"ud_multiword_token_surface": 1},
        )
        self.assertEqual(rendered["groups_matching_exact_ud_multiword_token_span"], 1)


class UdMetricTests(unittest.TestCase):
    def test_v4_schema_is_explicit(self) -> None:
        self.assertEqual(evaluation.SCHEMA_VERSION, "qazmorph.ud-evaluation.v4")

    def test_contextual_projection_is_used_only_when_requested(self) -> None:
        candidate = analysis(
            "бол",
            "VERB",
            (("VerbForm", "Fin"),),
            context_upos="AUX",
            context_features=(("Tense", "Pres"),),
        )
        target = gold(
            1,
            "болады",
            lemma="бол",
            upos="AUX",
            features=(("Tense", "Pres"),),
        )
        lexical = evaluation.MetricSet()
        lexical.add(target, (candidate,), case_sensitive_lemmas=False)
        contextual = evaluation.MetricSet()
        contextual.add(
            target,
            (candidate,),
            case_sensitive_lemmas=False,
            contextual_projection=True,
        )
        self.assertEqual(lexical.upos.correct, 0)
        self.assertEqual(contextual.upos.correct, 1)
        self.assertEqual(contextual.full_analysis.correct, 1)

    def test_unknown_placeholder_never_earns_gold_credit(self) -> None:
        placeholder = analysis("foo", "X", source="unknown")
        target = gold(1, "foo", lemma="foo", upos="X")
        metrics = evaluation.MetricSet()
        metrics.add(target, (placeholder,), case_sensitive_lemmas=False)
        self.assertEqual(metrics.lemma.as_json(), {"correct": 0, "total": 1, "value": 0.0})
        self.assertEqual(metrics.full_analysis.correct, 0)

    def test_feature_bundle_subset_relations_are_separate_from_exact(self) -> None:
        target = gold(
            1,
            "Алматы",
            lemma="Алматы",
            upos="PROPN",
            features=(("Case", "Nom"),),
        )
        richer = analysis(
            "Алматы",
            "PROPN",
            (("Case", "Nom"), ("NameType", "Geo")),
        )
        metrics = evaluation.MetricSet()
        metrics.add(target, (richer,), case_sensitive_lemmas=True)
        self.assertEqual(metrics.full_analysis.correct, 0)
        self.assertEqual(metrics.full_gold_subset_candidate.correct, 1)
        self.assertEqual(metrics.full_candidate_subset_gold.correct, 0)

        poorer = analysis("Алматы", "PROPN", ())
        inverse = evaluation.MetricSet()
        inverse.add(target, (poorer,), case_sensitive_lemmas=True)
        self.assertEqual(inverse.full_analysis.correct, 0)
        self.assertEqual(inverse.full_gold_subset_candidate.correct, 0)
        self.assertEqual(inverse.full_candidate_subset_gold.correct, 1)

    def test_selection_stats_separate_abstention_from_wrong_top_one(self) -> None:
        first = analysis("бар", "VERB")
        second = analysis("бар", "NOUN")
        stats = evaluation.SelectionStats()
        stats.add(None)
        stats.add(predicted("сөз", analyses=(first,)))
        stats.add(
            evaluation.PredictedToken(
                "бар", "word", (first, second), second, 1
            )
        )
        stats.add(predicted("бар", analyses=(first, second)))
        rendered = stats.as_json()
        self.assertEqual(rendered["deterministic_single_candidate"], 1)
        self.assertEqual(rendered["ambiguous_selected"], 1)
        self.assertEqual(rendered["ambiguous_unresolved"], 1)
        self.assertEqual(rendered["selected_coverage_aligned"]["value"], 2 / 3)
        self.assertEqual(rendered["selected_coverage_end_to_end"]["value"], 0.5)

    def test_coverage_labels_compiled_lexicon_and_fixlist_strictly(self) -> None:
        stats = evaluation.CoverageStats()
        stats.add_gold(
            gold(1, "сөз"),
            predicted("сөз", analyses=(analysis("сөз", "NOUN", source="lexicon"),)),
        )
        stats.add_gold(
            gold(2, "қате"),
            predicted("қате", analyses=(analysis("қате", "NOUN", source="fixlist"),)),
        )
        stats.add_gold(
            gold(3, "тосын"),
            predicted("тосын", analyses=(analysis("тосын", "NOUN", source="guesser"),)),
        )
        stats.add_gold(
            gold(4, "беймәлім"),
            predicted(
                "беймәлім",
                analyses=(
                    analysis(
                        "беймәлім", "PROPN", source="lexicon", guessed=True
                    ),
                ),
            ),
        )
        rendered = stats.as_json()
        self.assertEqual(rendered["compiled_lexicon_coverage_aligned"]["correct"], 1)
        self.assertEqual(rendered["fixlist_coverage_aligned"]["correct"], 1)
        self.assertEqual(rendered["effective_dictionary_coverage_aligned"]["correct"], 2)
        self.assertEqual(
            rendered["base_analyzer_unknown_reading_coverage_aligned"]["correct"], 1
        )
        self.assertEqual(rendered["operational_oov"]["correct"], 2)
        self.assertNotIn("dictionary_coverage_aligned", rendered)

    def test_selected_raw_containment_reports_valid_and_invalid_choices(self) -> None:
        sentence = evaluation.GoldSentence(
            Path("synthetic.conllu"),
            1,
            "containment-1",
            "бар кел",
            (gold(1, "бар"), gold(2, "кел")),
            0,
            0,
            True,
        )
        bar = analysis("бар", "VERB", raw="бар<v><imp><p2><sg>")
        come_lattice = analysis("кел", "VERB", raw="кел<v><imp><p2><sg>")
        come_selected = analysis("кел", "VERB", raw="кел<v><ger>")
        lattice = (
            evaluation.PredictedToken("бар", "word", (bar,), bar, 0, 0, 3),
            evaluation.PredictedToken(
                "кел", "word", (come_lattice,), come_lattice, 0, 4, 7
            ),
        )
        contextual = (
            evaluation.PredictedToken("бар", "word", (bar,), bar, 0, 0, 3),
            evaluation.PredictedToken(
                "кел", "word", (come_selected,), come_selected, 0, 4, 7
            ),
        )
        containment = evaluation.SelectedRawContainment()
        containment.add(sentence, lattice, contextual)
        rendered = containment.as_json()
        self.assertEqual(rendered["contained_raw_analyses"], 1)
        self.assertEqual(rendered["selected_raw_missing_from_lattice"], 1)
        self.assertEqual(rendered["mismatch_count"], 1)
        self.assertEqual(rendered["status"], "invalid")
        self.assertFalse(rendered["valid_for_candidate_recall_bound"])
        self.assertEqual(rendered["samples"][0]["reason"], "selected_raw_analysis_absent")

    def test_neural_report_separates_lexical_and_projected_top_one(self) -> None:
        target = gold(1, "болады", lemma="бол", upos="AUX")
        chosen = analysis("бол", "VERB", context_upos="AUX")
        stats = evaluation.EvaluationStats()
        stats.contextual_end_to_end.add(
            target, (chosen,), case_sensitive_lemmas=False, contextual_projection=False
        )
        stats.neural_projected_end_to_end.add(
            target, (chosen,), case_sensitive_lemmas=False, contextual_projection=True
        )
        report = evaluation._contextual_report(stats, engine="neural", enabled=True)
        lexical = report["lexical_selected_top1"]
        projected = report["context_projected_ud_top1"]
        self.assertEqual(lexical["end_to_end"]["upos_accuracy"]["correct"], 0)
        self.assertEqual(projected["end_to_end"]["upos_accuracy"]["correct"], 1)
        self.assertTrue(lexical["candidate_recall_upper_bound"]["applicable"])
        self.assertFalse(projected["candidate_recall_upper_bound"]["applicable"])


class EvaluationHardeningPrimitiveTests(unittest.TestCase):
    def test_analyzer_mode_flags_keep_neural_and_cg_mutually_exclusive(self) -> None:
        self.assertEqual(
            evaluation._analyzer_mode_flags("lattice"),
            {"disambiguate": False, "neural": False},
        )
        self.assertEqual(
            evaluation._analyzer_mode_flags("cg"),
            {"disambiguate": True, "neural": False},
        )
        self.assertEqual(
            evaluation._analyzer_mode_flags("neural"),
            {"disambiguate": False, "neural": True},
        )

    def test_sentence_calls_use_the_selected_engine_disambiguation_flag(self) -> None:
        class RecordingAnalyzer:
            def __init__(self) -> None:
                self.disambiguate_calls: list[bool] = []

            def analyze(self, _text: str, *, disambiguate: bool) -> object:
                self.disambiguate_calls.append(disambiguate)
                return SimpleNamespace(tokens=[])

        sentence = evaluation.GoldSentence(
            Path("synthetic.conllu"),
            1,
            "mode-dispatch",
            "",
            (),
            0,
            0,
            True,
        )
        for mode in ("lattice", "cg", "neural"):
            with self.subTest(mode=mode):
                flags = evaluation._analyzer_mode_flags(mode)
                lattice = RecordingAnalyzer()
                contextual = None if mode == "lattice" else RecordingAnalyzer()
                evaluation._evaluate_sentence(
                    sentence,
                    lattice_analyzer=lattice,
                    contextual_analyzer=contextual,
                    stats=evaluation.EvaluationStats(),
                    max_alignment_group=4,
                    exclude_punct=False,
                    case_sensitive_lemmas=False,
                    top1_engine=mode,
                    contextual_disambiguate=flags["disambiguate"],
                )
                self.assertEqual(lattice.disambiguate_calls, [False])
                if contextual is not None:
                    self.assertEqual(
                        contextual.disambiguate_calls,
                        [mode == "cg"],
                    )

    def test_runtime_validity_rejects_an_unverified_override(self) -> None:
        rendered = evaluation._runtime_validity(
            {
                "lattice": {
                    "official": False,
                    "verified": False,
                    "non_official_reasons": ["explicit override"],
                },
                "contextual": {
                    "official": True,
                    "verified": True,
                    "non_official_reasons": [],
                },
            }
        )
        self.assertFalse(rendered["valid_for_official_result_claims"])
        self.assertEqual(
            rendered["non_official_reasons"], ["lattice: explicit override"]
        )

    def test_rehash_inputs_checks_every_snapshot_before_returning_mismatches(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            first = Path(temporary) / "first.conllu"
            second = Path(temporary) / "second.conllu"
            first.write_text("first", encoding="utf-8")
            second.write_text("second", encoding="utf-8")
            snapshots = [
                evaluation._file_identity(first),
                evaluation._file_identity(second),
            ]
            first.write_text("changed first", encoding="utf-8")
            second.write_text("changed second", encoding="utf-8")
            verifications, mismatches = evaluation._rehash_inputs(snapshots)
        self.assertEqual(len(verifications), 2)
        self.assertEqual(len(mismatches), 2)
        self.assertTrue(all(not item["unchanged"] for item in verifications))

    def test_guesser_completeness_exposes_timeout_failure_and_cap_events(self) -> None:
        initial = {name: 0 for name in evaluation.GUESSER_COUNTERS}
        initial["cache_entries"] = 0
        final = dict(initial)
        final.update(
            {
                "lookup_queries": 9,
                "timeouts": 1,
                "failures": 2,
                "cap_aborts": 3,
                "cycle_truncations": 4,
                "unsafe_resource_skips": 5,
                "protocol_restarts": 6,
                "cache_entries": 4,
            }
        )
        diagnostics = evaluation._guesser_run_diagnostics(initial, final)
        rendered = evaluation._oov_lattice_completeness(
            guesser_enabled=True, diagnostics=diagnostics, guess_limit=8
        )
        self.assertEqual(rendered["status"], "incomplete")
        self.assertFalse(rendered["complete"])
        self.assertEqual(
            rendered["incompleteness_events"],
            {
                "timeouts": 1,
                "failures": 2,
                "cap_aborts": 3,
                "cycle_truncations": 4,
                "unsafe_resource_skips": 5,
                "unsafe_resource_configuration": 0,
            },
        )
        self.assertEqual(
            diagnostics["counters"]["protocol_restarts"]["during_run"], 6
        )
        disabled = evaluation._oov_lattice_completeness(
            guesser_enabled=False, diagnostics=diagnostics, guess_limit=8
        )
        self.assertEqual(disabled["status"], "not_applicable_disabled")
        self.assertIsNone(disabled["complete"])

    def test_resource_provenance_hashes_manifest_artifacts_and_runtime(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            resource_dir = Path(temporary)
            (resource_dir / "manifest.json").write_text("{}", encoding="utf-8")
            artifact = resource_dir / "analyzer.bin"
            artifact.write_bytes(b"first")

            class FakeBackend:
                manifest = {"version": "test", "files": {"analyzer.bin": {}}}
                resource_version = "test"

                def __init__(self, directory: Path) -> None:
                    self.resource_dir = directory

                @staticmethod
                def runtime_provenance():
                    return {"executables": {"hfst-proc": {"sha256": "a" * 64}}}

            class FakeAnalyzer:
                def __init__(self, directory: Path) -> None:
                    self.backend = FakeBackend(directory)

            analyzer = FakeAnalyzer(resource_dir)
            before = evaluation._resource_provenance(analyzer)
            artifact.write_bytes(b"second")
            after = evaluation._resource_provenance(analyzer)
        self.assertIn("manifest_file", before)
        self.assertIn("backend_runtime", before)
        self.assertNotEqual(before, after)

    def test_close_analyzers_closes_each_distinct_instance_once(self) -> None:
        class FakeAnalyzer:
            def __init__(self) -> None:
                self.close_calls = 0

            def close(self) -> None:
                self.close_calls += 1

        analyzer = FakeAnalyzer()
        self.assertEqual(evaluation._close_analyzers(analyzer, analyzer, None), [])
        self.assertEqual(analyzer.close_calls, 1)


class EvaluationInputTests(unittest.TestCase):
    def test_conllu_parser_preserves_nonconcatenative_mwt_surface(self) -> None:
        value = (
            "# sent_id = synthetic\n"
            "# text = бұзылады-ау\n"
            "1-2\tбұзылады-ау\t_\t_\t_\t_\t_\t_\t_\t_\n"
            "1\tбұз\tбұз\tVERB\t_\t_\t0\troot\t_\t_\n"
            "2\tау\tау\tPART\t_\t_\t1\tdiscourse\t_\t_\n\n"
        )
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "sample.conllu"
            path.write_text(value, encoding="utf-8")
            sentences = list(evaluation.iter_conllu(path))
        self.assertEqual(len(sentences), 1)
        self.assertEqual(sentences[0].text, "бұзылады-ау")
        self.assertEqual(sentences[0].multiword_spans[0].form, "бұзылады-ау")


class BenchmarkPrimitiveTests(unittest.TestCase):
    def test_interpolated_percentiles_and_empty_summary(self) -> None:
        self.assertEqual(benchmark._percentile((1.0, 2.0, 3.0), 0.5), 2.0)
        self.assertEqual(benchmark._percentile((1.0, 3.0), 0.5), 2.0)
        self.assertIsNone(benchmark._summary([])["p95"])

    def test_conllu_workload_uses_mwt_surface_once(self) -> None:
        value = (
            "# text = бұзылады-ау\n"
            "1-2\tбұзылады-ау\t_\t_\t_\t_\t_\t_\t_\t_\n"
            "1\tбұз\t_\t_\t_\t_\t_\t_\t_\t_\n"
            "2\tау\t_\t_\t_\t_\t_\t_\t_\t_\n\n"
        )
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "sample.conllu"
            path.write_text(value, encoding="utf-8")
            self.assertEqual(list(benchmark._conllu_texts(path)), ["бұзылады-ау"])

    def test_reports_bind_exact_source_files(self) -> None:
        for provenance in (
            evaluation._software_provenance(),
            benchmark._software_provenance(),
            raw_evaluation._software_provenance(),
        ):
            self.assertRegex(provenance["bundle_sha256"], r"^[0-9a-f]{64}$")
            self.assertIn("src/qazmorph/analyzer.py", provenance["files"])


class RawEvaluationTests(unittest.TestCase):
    def test_resource_provenance_rehashes_manifest_and_every_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            resource_dir = Path(temporary)
            artifacts = {
                "analyzer.bin": b"alpha",
                "generator.bin": b"bravo",
            }
            manifest = {
                "version": "test",
                "files": {name: {} for name in artifacts},
            }
            manifest_path = resource_dir / "manifest.json"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            for name, data in artifacts.items():
                (resource_dir / name).write_bytes(data)

            class FakeBackend:
                resource_version = "test"

                def __init__(self, directory: Path) -> None:
                    self.resource_dir = directory
                    self.manifest = manifest

                @staticmethod
                def runtime_provenance():
                    return {"official": True}

            class FakeAnalyzer:
                def __init__(self, directory: Path) -> None:
                    self.backend = FakeBackend(directory)

            analyzer = FakeAnalyzer(resource_dir)
            before = raw_evaluation._resource_provenance(analyzer)
            self.assertIn("manifest_file", before)
            self.assertEqual(
                set(before["resource_artifacts"]), set(artifacts)
            )

            (resource_dir / "generator.bin").write_bytes(b"cider")
            after_artifact = raw_evaluation._resource_provenance(analyzer)
            self.assertEqual(before["manifest_file"], after_artifact["manifest_file"])
            self.assertNotEqual(
                before["resource_artifacts"]["generator.bin"],
                after_artifact["resource_artifacts"]["generator.bin"],
            )

            manifest_bytes = manifest_path.read_bytes()
            manifest_path.write_bytes(b"x" * len(manifest_bytes))
            after_manifest = raw_evaluation._resource_provenance(analyzer)
            self.assertNotEqual(
                after_artifact["manifest_file"], after_manifest["manifest_file"]
            )

    def test_line_chunks_reconstruct_the_input_with_exact_offsets(self) -> None:
        value = "бірінші жол\n" + ("ұ" * 30) + "\nсоңғы"
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "raw.txt"
            path.write_text(value, encoding="utf-8", newline="")
            chunks = list(
                raw_evaluation._iter_line_chunks(
                    path, encoding="utf-8", max_chars=16
                )
            )
        self.assertEqual("".join(text for _offset, text in chunks), value)
        self.assertEqual([offset for offset, _text in chunks], [0, 12, 43])

    def test_maximum_character_prefix_never_splits_a_physical_line(self) -> None:
        value = "бір\nекінші ұзын жол\nсоңғы"
        self.assertEqual(
            raw_evaluation._prefix_through_complete_lines(value, 9), "бір\n"
        )
        self.assertEqual(raw_evaluation._prefix_through_complete_lines(value, 2), "")

    def test_raw_counts_distinguish_all_candidate_origins_and_zero(self) -> None:
        known = analysis("сөз", "NOUN")
        fixed = analysis("қате", "NOUN", source="fixlist")
        rule = analysis("00", "NUM", source="rule", guessed=True)
        analyzer_guess = analysis("Name", "PROPN", guessed=True)
        guessed_short = analysis("тос", "NOUN", source="guesser", guessed=True)
        guessed = analysis("тосын", "NOUN", source="guesser", guessed=True)
        unknown = analysis("latin", "X", source="unknown", guessed=True)
        tokens = [
            Token("сөз", 0, 3, "word", [known], 0),
            Token(" ", 3, 4, "space"),
            Token("қате", 4, 8, "word", [fixed], 0),
            Token(" ", 8, 9, "space"),
            Token("00", 9, 11, "number", [rule], 0),
            Token(" ", 11, 12, "space"),
            Token("Name", 12, 16, "word", [analyzer_guess], 0),
            Token(" ", 16, 17, "space"),
            Token("тосын", 17, 22, "word", [guessed_short, guessed], 0),
            Token(" ", 22, 23, "space"),
            Token("latin", 23, 28, "word", [unknown], 0),
            Token(" ", 28, 29, "space"),
            Token("Ⅻ", 29, 30, "number"),
        ]
        document = Document("сөз қате 00 Name тосын latin Ⅻ", tokens, "lattice", "test")
        counts = raw_evaluation.RawCounts()
        counts.add_document(document, document.text)
        rendered = counts.as_json()
        self.assertEqual(rendered["lexical_tokens"], 7)
        self.assertEqual(rendered["dictionary_tokens"], 1)
        self.assertEqual(rendered["fixlist_only_tokens"], 1)
        self.assertEqual(rendered["deterministic_rule_only_tokens"], 1)
        self.assertEqual(rendered["analyzer_guess_only_tokens"], 1)
        self.assertEqual(rendered["guesser_only_tokens"], 1)
        self.assertEqual(rendered["unknown_only_tokens"], 1)
        self.assertEqual(rendered["zero_analysis_tokens"], 1)
        self.assertEqual(rendered["guesser_candidate_analyses"], 2)
        self.assertEqual(rendered["guesser_candidates_with_shorter_lemma"], 1)
        self.assertEqual(rendered["guesser_tokens_with_shorter_lemma"], 1)
        self.assertEqual(rendered["guesser_tokens_with_top1_shorter_lemma"], 1)
        self.assertEqual(rendered["guesser_tokens_with_shorter_identity_lemma"], 1)
        self.assertEqual(rendered["guesser_tokens_with_stem_final_alternation"], 0)
        self.assertEqual(
            rendered["guesser_candidates_with_stem_final_alternation"], 0
        )

    def test_raw_counts_validate_guesser_roots_against_analyzer_nfc_surface(self) -> None:
        original = "Баи\u0306танаев"
        normalized = "Байтанаев"
        guessed = analysis(
            "байтана", "NOUN", source="guesser", guessed=True
        )
        document = Document(
            original,
            [
                Token(
                    original,
                    0,
                    len(original),
                    "word",
                    [guessed],
                    0,
                    normalized=normalized,
                )
            ],
            "lattice",
            "test",
        )
        counts = raw_evaluation.RawCounts()
        counts.add_document(document, original)
        rendered = counts.as_json()
        self.assertEqual(rendered["guesser_only_tokens"], 1)
        self.assertEqual(rendered["guesser_tokens_with_shorter_identity_lemma"], 1)


if __name__ == "__main__":
    unittest.main()
