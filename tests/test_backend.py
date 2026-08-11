from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from qazmorph.backend import (
    _guesser_safety_reason,
    _helper_working_directory,
    _has_verified_v4_productive_generator_gate,
    _has_verified_v3_guesser_gate,
    _hyphen_chains,
    _integrity_seal_status,
    _runtime_executable_file_available,
    BackendError,
    escape_apertium_text,
    FSTBackend,
    GLIBC_TUNABLES_VARIABLE,
    GUESSER_FINITE_SCHEMA_V1,
    GUESSER_FINITE_SCHEMA_V2,
    LOADER_OVERRIDE_VARIABLES,
    PINNED_LEGACY_V1_BUNDLE_ID,
    RESOURCE_FILES_BY_SCHEMA,
    RESOURCE_MANIFEST_V2,
    RESOURCE_MANIFEST_V3,
    RESOURCE_MANIFEST_V4,
    prepare_apertium_text,
    strip_boundary_superblanks,
)
from qazmorph.platform_runtime import PlatformRuntimeBinding


class ApertiumBoundaryTests(unittest.TestCase):
    def test_reserved_user_brackets_remain_distinct_from_control_boundaries(self) -> None:
        prepared = prepare_apertium_text("[] Има-а-а")
        self.assertTrue(prepared.startswith("[QAZMORPH-U00005B][QAZMORPH-U00005D] "))
        self.assertEqual(prepared.count("[]"), 4)
        restored = strip_boundary_superblanks(prepared)
        self.assertIn(r"^\[/\[<punct>$", restored)
        self.assertIn(r"^\]/\]<punct>$", restored)
        self.assertNotIn("QAZMORPH-U", restored)

    def test_only_three_or_more_hyphenated_components_are_forced_apart(self) -> None:
        self.assertEqual(prepare_apertium_text("а-а"), "а-а")
        self.assertEqual(prepare_apertium_text("Има-а-а"), "Има[]-[]а[]-[]а")
        self.assertEqual(
            prepare_apertium_text("Сан-Себрия-де-Вальяльта"),
            "Сан[]-[]Себрия[]-[]де[]-[]Вальяльта",
        )

    def test_hyphen_chain_scanner_retains_absolute_indices_and_marks(self) -> None:
        self.assertEqual(
            _hyphen_chains("x а-а, йа-а-а"),
            [("а-а", (3,)), ("йа-а-а", (9, 11))],
        )

    def test_regular_apertium_escaping_is_unchanged(self) -> None:
        value = r"[Қазақстан] ^сөз$ \ C++ {қазақ}"
        prepared = prepare_apertium_text(value)
        self.assertNotEqual(prepared, escape_apertium_text(value))
        restored = strip_boundary_superblanks(prepared)
        self.assertNotIn("QAZMORPH-U", restored)
        self.assertIn("Қазақстан", restored)

    def test_percent_is_left_for_dictionary_morphology(self) -> None:
        self.assertEqual(prepare_apertium_text("51%"), "51%")

    def test_carriage_returns_are_round_tripped_through_a_superblank(self) -> None:
        prepared = prepare_apertium_text("сөз\r\nкелесі")
        self.assertEqual(prepared, "сөз[QAZMORPH-CARRIAGE-RETURN]\nкелесі")
        self.assertEqual(strip_boundary_superblanks(prepared), "сөз\r\nкелесі")

    def test_literal_nul_is_distinct_from_atomic_flush_control(self) -> None:
        prepared = prepare_apertium_text("бір\x00екі")
        self.assertNotIn("\x00", prepared)
        self.assertIn("QAZMORPH-USER-NUL", prepared)
        self.assertEqual(strip_boundary_superblanks(prepared), "бір\x00екі")

    def test_en_and_em_dashes_are_not_orthographic_hyphens(self) -> None:
        self.assertEqual(_hyphen_chains("сөз-сөз сөз‐сөз сөз‑сөз"), [
            ("сөз-сөз", (3,)),
            ("сөз‐сөз", (11,)),
            ("сөз‑сөз", (19,)),
        ])
        self.assertEqual(_hyphen_chains("сөз–сөз сөз—сөз"), [])

    def test_suffix_a_is_protected_without_a_left_word_component(self) -> None:
        text = "-а №-а !-а а-а Има-а-а"
        protected = FSTBackend._hyphen_protection_indices(text, timeout=1.0)
        for needle in ("-а", "№-а", "!-а"):
            start = text.index(needle)
            self.assertIn(start + needle.index("-"), protected)
        lexical = text.index("а-а") + 1
        self.assertNotIn(lexical, protected)
        repeated_start = text.index("Има-а-а")
        self.assertTrue(
            {repeated_start + 3, repeated_start + 5} <= protected
        )


class DictionaryGeneratorBoundaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.backend = FSTBackend.__new__(FSTBackend)

    def test_direct_query_rejects_invalid_limits_and_timeouts_before_launch(self) -> None:
        for limit in (0, -1, True, False, 1.5, float("inf"), "2"):
            with self.subTest(limit=limit), self.assertRaisesRegex(
                ValueError, "generation limit"
            ):
                self.backend.generate("сөз<n>", limit=limit)  # type: ignore[arg-type]
        for timeout in (
            0,
            -1,
            True,
            False,
            float("inf"),
            float("nan"),
            "2",
        ):
            with self.subTest(timeout=timeout), self.assertRaisesRegex(
                ValueError, "generation timeout"
            ):
                self.backend.generate(
                    "сөз<n>", timeout=timeout  # type: ignore[arg-type]
                )

    def test_direct_query_rejects_record_injection_and_encoded_overflow(self) -> None:
        for query in (
            None,
            "",
            "сөз<n>\n",
            "сөз<n>\r",
            "сөз<n>\t",
            "сөз<n>\0",
            "сөз<n>\x01",
            "сөз<n>\x85",
            "сөз<n>\u2028",
            "сөз<n>\ud800",
        ):
            with self.subTest(query=repr(query)), self.assertRaises(ValueError):
                self.backend.generate(query)  # type: ignore[arg-type]
        with self.assertRaisesRegex(ValueError, "bounded generator input"):
            self.backend.generate("a" * 4097)

    def test_direct_query_accepts_exact_4096_byte_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "kaz.autogen.hfstol").write_bytes(b"generator")
            self.backend.resource_dir = root
            self.backend.hfst_optimized_lookup = root / "hfst-optimized-lookup"
            self.backend.environment = {}
            query = "a" * 4096
            completed = mock.Mock(returncode=0, stdout="", stderr="")
            with mock.patch(
                "qazmorph.backend.subprocess.run", return_value=completed
            ) as run:
                self.assertEqual(self.backend.generate(query), [])
            self.assertEqual(run.call_args.kwargs["input"], query + "\n")


class ResourceManifestTests(unittest.TestCase):
    @staticmethod
    def finite_guesser_gate(
        schema: str = GUESSER_FINITE_SCHEMA_V1,
    ) -> dict[str, object]:
        result: dict[str, object] = {
            "schema": schema,
            "graph": {"reachable_input_epsilon_cycle": False},
            "no_cap_probes": {
                "all_lemmas_match_bounded_root_relation": True,
                "cycle_markers": 0,
            },
            "optimized_runtime": {
                "full_relation_equivalent_to_standard": True,
                "candidate_sets_equal_to_standard": True,
                "cycle_markers": 0,
            },
        }
        if schema == GUESSER_FINITE_SCHEMA_V2:
            result["baseline_relation"] = {"baseline_subset_of_final": True}
            result["no_cap_probes"] = {
                **result["no_cap_probes"],
                "forbidden_readings_observed": 0,
                "forbidden_readings_checked": 7,
                "probes": 363,
                "deterministic_adversarial_probes": 256,
                "tracked_readings_missing": [],
                "bounded_root_relation": {
                    "unbounded_input_epsilon_root_templates": False,
                    "noun_high_vowel_syncope": {
                        "noun_only": True,
                        "requires_nonempty_surface_suffix": True,
                    },
                    "loan_back_harmony": {
                        "noun_only": True,
                        "lemma_suffix": "кубок",
                        "generic_back_harmony_g_to_k": False,
                    },
                },
            }
        return {
            "verification": {
                "productive_guesser_finite_valued": {
                    "result": result
                }
            }
        }

    @staticmethod
    def finite_generator_gate(
        files: dict[str, object],
    ) -> dict[str, object]:
        baseline_probe = {"bytes": 10, "sha256": "a" * 64}
        direction_probe = {"bytes": 11, "sha256": "b" * 64}
        equivalent = {
            "full_relation_equivalent_to_standard": True,
            "standard_minus_optimized_roundtrip_empty": True,
            "optimized_roundtrip_minus_standard_empty": True,
        }
        return {
            "productive_generator_finite_valued": {
                "result": {
                    "schema": "qazmorph-productive-generator-finiteness-v2",
                    "inputs": {
                        "generation_safe_productive_analyzer_standard": {"bytes": 1, "sha256": "5" * 64},
                        "full_productive_analyzer_standard": {"bytes": 1, "sha256": "6" * 64},
                        "full_productive_analyzer_optimized": files["kaz.guesser.automorf.hfstol"],
                        "productive_generator_standard": {"bytes": 1, "sha256": "7" * 64},
                        "productive_generator_optimized": files["kaz.guesser.autogen.hfstol"],
                        "dictionary_generator_standard": {"bytes": 1, "sha256": "8" * 64},
                        "dictionary_generator_optimized": files["kaz.autogen.hfstol"],
                        "dictionary_analyzer_lexical_to_surface_standard": {"bytes": 1, "sha256": "9" * 64},
                        "dictionary_analyzer_surface_to_lexical_optimized": files["kaz.automorf.hfstol"],
                        "baseline_probes": baseline_probe,
                        "direction_probes": direction_probe,
                    },
                    "graph": {"reachable_input_epsilon_cycle": False},
                    "inverse_relation": {
                        "generator_inverse_equals_productive_analyzer": True,
                        "productive_analyzer_minus_generator_inverse_empty": True,
                        "generator_inverse_minus_productive_analyzer_empty": True,
                    },
                    "optimized_runtime": {
                        **equivalent,
                        "candidate_sets_equal_to_standard": True,
                        "standard_optimized_mismatches": [],
                        "cycle_markers": 0,
                        "cap_markers": 0,
                        "queries": 71,
                    },
                    "inversion_probes": {
                        "required_pairs_checked": 67,
                        "required_pairs_missing": [],
                        "forbidden_pairs_checked": 10,
                        "forbidden_pairs_observed": 0,
                        "forbidden_pairs_found": [],
                        "all_queries_keyed": True,
                        "cycle_markers": 0,
                        "cap_markers": 0,
                    },
                    "generation_direction_relation": {
                        "generation_safe_analyzer_subset_of_full_analyzer": True,
                        "generation_safe_minus_full_empty": True,
                        "full_minus_generation_safe_nonempty": True,
                    },
                    "directionality_probes": {
                        "required_pairs_checked": 3,
                        "required_pairs_missing": [],
                        "forbidden_pairs_checked": 3,
                        "forbidden_pairs_observed": 0,
                        "forbidden_pairs_found": [],
                        "canonical_short_instrumental_only": True,
                        "analysis_only_adjective_comparative_excluded": True,
                        "analysis_only_verb_future_plan_excluded": True,
                    },
                    "installed_artifacts": {
                        "dictionary_generator": dict(equivalent),
                        "dictionary_analyzer_surface_to_lexical": dict(equivalent),
                        "full_productive_analyzer": dict(equivalent),
                        "all_installed_relations_equivalent_to_standard": True,
                    },
                    "combined_generation_subset": {
                        "dictionary_and_productive_generator_subset_of_analyzers": True,
                        "generated_minus_accepted_empty": True,
                    },
                }
            }
        }

    @staticmethod
    def write_resource_manifest(root: Path, schema: str) -> dict[str, object]:
        files = {}
        for name in RESOURCE_FILES_BY_SCHEMA[schema]:
            data = f"fixture:{name}".encode()
            (root / name).write_bytes(data)
            files[name] = {
                "bytes": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
            }
        identity = {
            "schema": schema,
            "files": files,
            "source": {},
            "build": (
                {
                    "inputs": {
                        "scripts/guesser_regression_probes.json": {
                            "bytes": 10,
                            "sha256": "a" * 64,
                        },
                        "scripts/generator_regression_probes.json": {
                            "bytes": 11,
                            "sha256": "b" * 64,
                        },
                    },
                    "verification": {
                        **ResourceManifestTests.finite_guesser_gate(
                            GUESSER_FINITE_SCHEMA_V2
                        )["verification"],
                        **ResourceManifestTests.finite_generator_gate(files),
                    },
                }
                if schema == RESOURCE_MANIFEST_V4
                else (
                    ResourceManifestTests.finite_guesser_gate()
                    if schema == RESOURCE_MANIFEST_V3
                    else {}
                )
            ),
        }
        encoded = json.dumps(
            identity, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode()
        manifest = {
            **identity,
            "version": "test",
            "bundle_id": hashlib.sha256(encoded).hexdigest(),
        }
        (root / "manifest.json").write_text(
            json.dumps(manifest, ensure_ascii=False), encoding="utf-8"
        )
        return manifest

    @staticmethod
    def seal_resource_bundle(root: Path) -> None:
        for path in root.rglob("*"):
            if not path.is_symlink():
                path.chmod(path.stat().st_mode & ~0o222)
        root.chmod(root.stat().st_mode & ~0o222)

    @staticmethod
    def runtime_backend(
        resource_dir: Path,
        manifest: dict[str, object],
        toolchain_dir: Path,
    ) -> FSTBackend:
        toolchain_dir.mkdir(parents=True, exist_ok=True)
        library = toolchain_dir / "usr" / "lib" / "libfixture.so"
        library.parent.mkdir(parents=True)
        library_data = b"verified-non-command-library"
        library.write_bytes(library_data)
        command = toolchain_dir / "usr" / "bin" / "hfst-proc"
        command.parent.mkdir(parents=True)
        command_data = b"verified-bound-command"
        command.write_bytes(command_data)
        command.chmod(0o755)
        toolchain_identity = {
            "schema": "qazmorph-test-toolchain-v1",
            "commands": {
                "hfst-proc": {
                    "path": "usr/bin/hfst-proc",
                    "sha256": hashlib.sha256(command_data).hexdigest(),
                }
            },
            "files": {
                "usr/bin/hfst-proc": {
                    "kind": "file",
                    "bytes": len(command_data),
                    "sha256": hashlib.sha256(command_data).hexdigest(),
                },
                "usr/lib/libfixture.so": {
                    "kind": "file",
                    "bytes": len(library_data),
                    "sha256": hashlib.sha256(library_data).hexdigest(),
                }
            },
        }
        toolchain_bundle = hashlib.sha256(
            json.dumps(
                toolchain_identity,
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        ).hexdigest()
        toolchain_manifest = {
            **toolchain_identity,
            "bundle_id": toolchain_bundle,
        }
        toolchain_manifest_data = (
            json.dumps(toolchain_manifest, sort_keys=True, separators=(",", ":"))
            + "\n"
        ).encode()
        (toolchain_dir / "manifest.json").write_bytes(toolchain_manifest_data)
        manifest["build"]["toolchain"] = {
            "bundle_id": toolchain_bundle,
            "manifest": {
                "bytes": len(toolchain_manifest_data),
                "sha256": hashlib.sha256(toolchain_manifest_data).hexdigest(),
            },
        }
        resource_identity = {
            key: value
            for key, value in manifest.items()
            if key not in {"bundle_id", "version"}
        }
        manifest["bundle_id"] = hashlib.sha256(
            json.dumps(
                resource_identity,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        ).hexdigest()
        (resource_dir / "manifest.json").write_text(
            json.dumps(manifest, ensure_ascii=False), encoding="utf-8"
        )
        ResourceManifestTests.seal_resource_bundle(toolchain_dir)

        backend = FSTBackend.__new__(FSTBackend)
        backend.resource_dir = resource_dir
        backend.manifest = manifest
        backend._resource_inventory = backend._verify_resource_inventory()
        backend.toolchain_dir = toolchain_dir
        backend.toolchain_manifest = toolchain_manifest
        backend._toolchain_inventory = backend._verify_bound_toolchain_inventory()
        backend.guesser_format = "optimized"
        backend.guesser_verified_finite = True
        backend.guesser_productive_safe = True
        backend.guesser_safety_reason = "test"
        backend.generator_path = resource_dir / "kaz.autogen.hfstol"
        backend.productive_generator_path = (
            resource_dir / "kaz.guesser.autogen.hfstol"
        )
        backend.productive_generator_verified_finite = (
            _has_verified_v4_productive_generator_gate(manifest)
        )
        backend.productive_generator_safe = (
            backend.productive_generator_verified_finite
        )
        backend.productive_generator_safety_reason = (
            "verified productive generator"
            if backend.productive_generator_verified_finite
            else "functional rollback without productive generation"
        )
        backend._executable_origins = {"hfst-proc": "resource-bound-toolchain"}
        backend._executable_verified = {"hfst-proc": True}
        backend.hfst_proc = str(command)
        backend.cg_proc = None
        backend.hfst_lookup = None
        backend.hfst_optimized_lookup = None
        backend.environment = {}
        backend._ambient_library_path = None
        backend._ambient_ld_preload = None
        backend._ambient_ld_audit = None
        return backend

    def test_missing_manifest_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            backend = FSTBackend.__new__(FSTBackend)
            backend.resource_dir = Path(temporary)
            with self.assertRaisesRegex(BackendError, "Invalid resource manifest"):
                backend._read_manifest()

    def test_empty_self_description_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "manifest.json").write_text(
                json.dumps({"version": "forged", "files": {}}), encoding="utf-8"
            )
            backend = FSTBackend.__new__(FSTBackend)
            backend.resource_dir = root
            with self.assertRaisesRegex(BackendError, "schema"):
                backend._read_manifest()

    def test_v2_v3_and_v4_resource_layouts_are_additively_valid(self) -> None:
        for schema, guesser_name in (
            (RESOURCE_MANIFEST_V2, "kaz.guesser.automorf.hfst"),
            (RESOURCE_MANIFEST_V3, "kaz.guesser.automorf.hfstol"),
            (RESOURCE_MANIFEST_V4, "kaz.guesser.automorf.hfstol"),
        ):
            with self.subTest(schema=schema), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                expected = self.write_resource_manifest(root, schema)
                backend = FSTBackend.__new__(FSTBackend)
                backend.resource_dir = root
                observed = backend._read_manifest()
                self.assertEqual(observed, expected)
                self.assertIn(guesser_name, observed["files"])
                self.assertEqual(
                    "kaz.guesser.autogen.hfstol" in observed["files"],
                    schema == RESOURCE_MANIFEST_V4,
                )

    def test_v2_manifest_cannot_claim_the_v3_optimized_guesser_layout(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = self.write_resource_manifest(root, RESOURCE_MANIFEST_V3)
            manifest["schema"] = RESOURCE_MANIFEST_V2
            identity = {
                key: value
                for key, value in manifest.items()
                if key not in {"bundle_id", "version"}
            }
            manifest["bundle_id"] = hashlib.sha256(
                json.dumps(
                    identity,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode()
            ).hexdigest()
            (root / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
            backend = FSTBackend.__new__(FSTBackend)
            backend.resource_dir = root
            with self.assertRaisesRegex(BackendError, "file set"):
                backend._read_manifest()

    def test_v4_manifest_requires_every_productive_generator_gate(self) -> None:
        mutations = (
            ("graph", "reachable_input_epsilon_cycle", True),
            ("inverse_relation", "generator_inverse_equals_productive_analyzer", False),
            ("optimized_runtime", "candidate_sets_equal_to_standard", False),
            ("optimized_runtime", "standard_optimized_mismatches", ["query"]),
            ("inversion_probes", "required_pairs_missing", ["pair"]),
            ("inversion_probes", "forbidden_pairs_observed", 1),
            (
                "generation_direction_relation",
                "generation_safe_minus_full_empty",
                False,
            ),
            ("directionality_probes", "forbidden_pairs_observed", 1),
            (
                "installed_artifacts",
                "all_installed_relations_equivalent_to_standard",
                False,
            ),
            ("combined_generation_subset", "generated_minus_accepted_empty", False),
        )
        for section, field, changed in mutations:
            with self.subTest(section=section, field=field), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                manifest = self.write_resource_manifest(root, RESOURCE_MANIFEST_V4)
                result = manifest["build"]["verification"][
                    "productive_generator_finite_valued"
                ]["result"]
                result[section][field] = changed
                identity = {
                    key: value
                    for key, value in manifest.items()
                    if key not in {"bundle_id", "version"}
                }
                manifest["bundle_id"] = hashlib.sha256(
                    json.dumps(
                        identity,
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    ).encode()
                ).hexdigest()
                (root / "manifest.json").write_text(
                    json.dumps(manifest, ensure_ascii=False), encoding="utf-8"
                )
                backend = FSTBackend.__new__(FSTBackend)
                backend.resource_dir = root
                with self.assertRaisesRegex(
                    BackendError, "productive-generator verification"
                ):
                    backend._read_manifest()

    def test_v4_generator_proof_inputs_are_bound_to_installed_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = self.write_resource_manifest(root, RESOURCE_MANIFEST_V4)
            result = manifest["build"]["verification"][
                "productive_generator_finite_valued"
            ]["result"]
            result["inputs"]["productive_generator_optimized"] = {
                "bytes": 1,
                "sha256": "f" * 64,
            }
            identity = {
                key: value
                for key, value in manifest.items()
                if key not in {"bundle_id", "version"}
            }
            manifest["bundle_id"] = hashlib.sha256(
                json.dumps(
                    identity,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode()
            ).hexdigest()
            (root / "manifest.json").write_text(
                json.dumps(manifest, ensure_ascii=False), encoding="utf-8"
            )
            backend = FSTBackend.__new__(FSTBackend)
            backend.resource_dir = root
            with self.assertRaisesRegex(
                BackendError, "productive-generator verification"
            ):
                backend._read_manifest()

    def test_v4_guesser_v2_proof_is_tamper_sensitive(self) -> None:
        for mutation in ("baseline", "forbidden", "unbounded_epsilon", "generic_loan"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                manifest = self.write_resource_manifest(root, RESOURCE_MANIFEST_V4)
                result = manifest["build"]["verification"][
                    "productive_guesser_finite_valued"
                ]["result"]
                if mutation == "baseline":
                    result["baseline_relation"]["baseline_subset_of_final"] = False
                elif mutation == "forbidden":
                    result["no_cap_probes"]["forbidden_readings_observed"] = 1
                elif mutation == "unbounded_epsilon":
                    result["no_cap_probes"]["bounded_root_relation"][
                        "unbounded_input_epsilon_root_templates"
                    ] = True
                else:
                    result["no_cap_probes"]["bounded_root_relation"][
                        "loan_back_harmony"
                    ]["generic_back_harmony_g_to_k"] = True
                identity = {
                    key: value
                    for key, value in manifest.items()
                    if key not in {"bundle_id", "version"}
                }
                manifest["bundle_id"] = hashlib.sha256(
                    json.dumps(
                        identity,
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    ).encode()
                ).hexdigest()
                (root / "manifest.json").write_text(
                    json.dumps(manifest, ensure_ascii=False), encoding="utf-8"
                )
                backend = FSTBackend.__new__(FSTBackend)
                backend.resource_dir = root
                with self.assertRaisesRegex(BackendError, "finite-guesser verification"):
                    backend._read_manifest()

    def test_v3_manifest_rejects_malformed_legacy_finite_guesser_proof(self) -> None:
        for mutation in (
            "missing",
            "result_shape",
            "graph_shape",
            "probes_shape",
            "optimized_shape",
            "boolean_shape",
            "count_shape",
        ):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                manifest = self.write_resource_manifest(root, RESOURCE_MANIFEST_V3)
                result = manifest["build"]["verification"][
                    "productive_guesser_finite_valued"
                ]["result"]
                if mutation == "missing":
                    manifest["build"].pop("verification")
                elif mutation == "result_shape":
                    manifest["build"]["verification"][
                        "productive_guesser_finite_valued"
                    ]["result"] = []
                elif mutation == "graph_shape":
                    result["graph"] = []
                elif mutation == "probes_shape":
                    result["no_cap_probes"] = []
                elif mutation == "optimized_shape":
                    result["optimized_runtime"] = []
                elif mutation == "boolean_shape":
                    result["graph"]["reachable_input_epsilon_cycle"] = 0
                else:
                    result["no_cap_probes"]["cycle_markers"] = False
                identity = {
                    key: value
                    for key, value in manifest.items()
                    if key not in {"bundle_id", "version"}
                }
                manifest["bundle_id"] = hashlib.sha256(
                    json.dumps(
                        identity,
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    ).encode()
                ).hexdigest()
                (root / "manifest.json").write_text(
                    json.dumps(manifest), encoding="utf-8"
                )
                backend = FSTBackend.__new__(FSTBackend)
                backend.resource_dir = root
                with self.assertRaisesRegex(
                    BackendError, "finite-guesser verification.*malformed"
                ):
                    backend._read_manifest()

    def test_only_exact_pinned_f03e_v1_gate_can_activate_productive_guessing(self) -> None:
        manifest = {
            "schema": RESOURCE_MANIFEST_V3,
            "bundle_id": PINNED_LEGACY_V1_BUNDLE_ID,
            "build": self.finite_guesser_gate(),
        }
        self.assertEqual(
            manifest["build"]["verification"][
                "productive_guesser_finite_valued"
            ]["result"]["schema"],
            GUESSER_FINITE_SCHEMA_V1,
        )
        self.assertTrue(_has_verified_v3_guesser_gate(manifest))

        manifest["bundle_id"] = "0" * 64
        self.assertFalse(_has_verified_v3_guesser_gate(manifest))

    def test_forged_v1_cannot_claim_the_pinned_f03e_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = self.write_resource_manifest(
                root, RESOURCE_MANIFEST_V3
            )
            manifest["bundle_id"] = PINNED_LEGACY_V1_BUNDLE_ID
            (root / "manifest.json").write_text(
                json.dumps(manifest, ensure_ascii=False), encoding="utf-8"
            )
            backend = FSTBackend.__new__(FSTBackend)
            backend.resource_dir = root
            with self.assertRaisesRegex(BackendError, "identity checksum"):
                backend._read_manifest()

    def test_unknown_valid_v1_loads_nonproductive_and_nonofficial(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            resource_dir = root / "resources"
            resource_dir.mkdir()
            manifest = self.write_resource_manifest(
                resource_dir, RESOURCE_MANIFEST_V3
            )
            self.assertNotEqual(
                manifest["bundle_id"], PINNED_LEGACY_V1_BUNDLE_ID
            )

            loader = FSTBackend.__new__(FSTBackend)
            loader.resource_dir = resource_dir
            self.assertEqual(loader._read_manifest(), manifest)
            self.assertFalse(_has_verified_v3_guesser_gate(manifest))

            backend = self.runtime_backend(
                resource_dir, manifest, root / "toolchain"
            )
            backend.guesser_verified_finite = False
            backend.guesser_productive_safe = False
            backend.guesser_safety_reason = _guesser_safety_reason(
                manifest, verified=False
            )
            self.seal_resource_bundle(resource_dir)
            for platform in ("darwin", "linux", "win32"):
                with self.subTest(platform=platform), mock.patch(
                    "qazmorph.backend.sys.platform", platform
                ):
                    provenance = backend.runtime_provenance()
                    self.assertFalse(provenance["official"])
                    self.assertFalse(
                        provenance["guesser_runtime"]["productive_safe"]
                    )
                    self.assertEqual(
                        provenance["guesser_runtime"]["reason"],
                        backend.guesser_safety_reason,
                    )
                    self.assertTrue(
                        any(
                            backend.guesser_safety_reason in reason
                            for reason in provenance["non_official_reasons"]
                        )
                    )

    def test_resource_inventory_requires_exact_bytes_and_a_read_only_seal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "resources"
            root.mkdir()
            manifest = self.write_resource_manifest(root, RESOURCE_MANIFEST_V3)
            backend = FSTBackend.__new__(FSTBackend)
            backend.resource_dir = root
            backend.manifest = manifest

            writable = backend._verify_resource_inventory()
            self.assertTrue(writable["verified"])
            self.assertFalse(writable["sealed_read_only"])
            self.assertGreater(writable["writable_entries"], 0)
            self.assertGreater(writable["writable_directories"], 0)

            unexpected = root / "unexpected.bin"
            unexpected.write_bytes(b"extra")
            with_extra = backend._verify_resource_inventory()
            self.assertFalse(with_extra["verified"])
            self.assertEqual(with_extra["unexpected_entries"], ["unexpected.bin"])
            unexpected.unlink()

            artifact = root / next(iter(RESOURCE_FILES_BY_SCHEMA[RESOURCE_MANIFEST_V3]))
            original = artifact.read_bytes()
            artifact.write_bytes(b"x" * len(original))
            self.assertFalse(backend._verify_resource_inventory()["verified"])
            artifact.write_bytes(original)

            self.seal_resource_bundle(root)
            sealed = backend._verify_resource_inventory()
            self.assertTrue(sealed["verified"])
            self.assertTrue(sealed["sealed_read_only"])
            self.assertEqual(sealed["writable_entries"], 0)
            self.assertEqual(sealed["writable_directories"], 0)

    def test_windows_integrity_seal_uses_fresh_hashes_not_posix_directory_bits(self) -> None:
        with mock.patch("qazmorph.backend.sys.platform", "win32"):
            observed = _integrity_seal_status(
                verified=True,
                manifest_read_only=False,
                root_read_only=False,
                writable_entries=7,
                writable_directories=3,
                content_rehashed=True,
            )
        self.assertEqual(
            observed["seal_model"],
            "windows-complete-inventory-force-rehash-v1",
        )
        self.assertFalse(observed["directory_modes_enforced"])
        self.assertFalse(observed["sealed_read_only"])
        self.assertTrue(observed["integrity_seal_verified"])

    def test_windows_integrity_seal_never_accepts_a_cached_or_partial_inventory(self) -> None:
        for verified, content_rehashed in ((False, True), (True, False)):
            with self.subTest(
                verified=verified, content_rehashed=content_rehashed
            ), mock.patch("qazmorph.backend.sys.platform", "win32"):
                observed = _integrity_seal_status(
                    verified=verified,
                    manifest_read_only=True,
                    root_read_only=True,
                    writable_entries=0,
                    writable_directories=0,
                    content_rehashed=content_rehashed,
                )
            self.assertFalse(observed["integrity_seal_verified"])

    def test_windows_exe_availability_does_not_depend_on_posix_x_ok(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            executable = root / "helper.exe"
            executable.write_bytes(b"MZfixture")
            non_executable = root / "helper.txt"
            non_executable.write_bytes(b"not a PE launcher")
            with mock.patch("qazmorph.backend.sys.platform", "win32"), mock.patch(
                "qazmorph.backend.os.access", return_value=False
            ):
                self.assertTrue(_runtime_executable_file_available(executable))
                self.assertFalse(_runtime_executable_file_available(non_executable))

    def test_windows_bound_exe_requires_successful_manifest_version_execution(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            executable = root / "usr" / "bin" / "cg-proc.exe"
            executable.parent.mkdir(parents=True)
            payload = b"MZfixture"
            executable.write_bytes(payload)
            digest = hashlib.sha256(payload).hexdigest()
            backend = FSTBackend.__new__(FSTBackend)
            backend.toolchain_dir = root
            backend.toolchain_manifest = {
                "commands": {
                    "cg-proc": {
                        "path": "usr/bin/cg-proc.exe",
                        "sha256": digest,
                        "version_args": ["-v"],
                        "version_output": "CG-3 1.6.8",
                    }
                },
                "files": {
                    "usr/bin/cg-proc.exe": {
                        "kind": "file",
                        "bytes": len(payload),
                        "sha256": digest,
                    }
                },
            }
            backend.environment = {}
            backend._executable_origins = {}
            backend._executable_verified = {}
            completed = mock.Mock(
                returncode=0,
                stdout=b"CG-3 1.6.8\r\n",
            )
            with mock.patch("qazmorph.backend.sys.platform", "win32"), mock.patch(
                "qazmorph.backend.os.access", return_value=False
            ), mock.patch("qazmorph.backend.subprocess.run", return_value=completed) as run:
                selected = backend._find_executable(
                    "cg-proc", "QAZMORPH_TEST_CG_PROC"
                )
            self.assertEqual(selected, str(executable))
            self.assertTrue(backend._executable_verified["cg-proc"])
            self.assertEqual(run.call_args.args[0], [str(executable), "-v"])

            backend.toolchain_manifest["commands"]["cg-proc"][
                "version_output"
            ] = "different"
            with mock.patch("qazmorph.backend.sys.platform", "win32"), mock.patch(
                "qazmorph.backend.os.access", return_value=False
            ), mock.patch("qazmorph.backend.subprocess.run", return_value=completed), self.assertRaisesRegex(
                BackendError, "version output changed"
            ):
                backend._find_executable("cg-proc", "QAZMORPH_TEST_CG_PROC")

    def test_windows_complete_rehash_can_be_official_with_writable_zip_directories(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            resource_dir = root / "resources"
            resource_dir.mkdir()
            manifest = self.write_resource_manifest(
                resource_dir, RESOURCE_MANIFEST_V3
            )
            backend = self.runtime_backend(resource_dir, manifest, root / "toolchain")

            with mock.patch("qazmorph.backend.sys.platform", "win32"), mock.patch(
                "qazmorph.backend.os.access", return_value=False
            ):
                provenance = backend.runtime_provenance()

            self.assertTrue(provenance["official"])
            self.assertTrue(
                provenance["resource_inventory"]["integrity_seal_verified"]
            )
            self.assertTrue(
                provenance["toolchain_inventory"]["integrity_seal_verified"]
            )
            self.assertTrue(provenance["toolchain_inventory"]["content_rehashed"])
            self.assertFalse(
                provenance["toolchain_inventory"]["sealed_read_only"]
            )
            executable = provenance["executables"]["hfst-proc"]
            self.assertFalse(executable["os_access_x_ok"])
            self.assertEqual(
                executable["availability_contract"],
                "regular-exe-manifest-hash-successful-version-execution",
            )

    def test_v3_runtime_requires_a_sealed_resource_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            resource_dir = root / "resources"
            resource_dir.mkdir()
            manifest = self.write_resource_manifest(
                resource_dir, RESOURCE_MANIFEST_V3
            )
            backend = self.runtime_backend(resource_dir, manifest, root / "toolchain")

            writable = backend.runtime_provenance()
            self.assertTrue(writable["verified"])
            self.assertFalse(writable["official"])
            self.assertIn(
                "resource v3 bundle is not sealed read-only",
                writable["non_official_reasons"],
            )

            self.seal_resource_bundle(resource_dir)
            sealed = backend.runtime_provenance()
            self.assertTrue(sealed["resource_inventory"]["sealed_read_only"])
            self.assertTrue(sealed["official"])

    def test_runtime_provenance_force_rehash_keeps_unchanged_toolchain_official(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            resource_dir = root / "resources"
            resource_dir.mkdir()
            manifest = self.write_resource_manifest(
                resource_dir, RESOURCE_MANIFEST_V3
            )
            backend = self.runtime_backend(resource_dir, manifest, root / "toolchain")
            self.seal_resource_bundle(resource_dir)

            provenance = backend.runtime_provenance()
            self.assertTrue(provenance["official"])
            self.assertTrue(provenance["verified"])
            self.assertTrue(provenance["toolchain_manifest"]["verified"])
            self.assertTrue(provenance["toolchain_inventory"]["force_rehash"])
            self.assertTrue(provenance["toolchain_inventory"]["content_rehashed"])
            self.assertTrue(
                provenance["executables"]["hfst-proc"]["verified"]
            )

    def test_runtime_provenance_detects_noncommand_library_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            resource_dir = root / "resources"
            resource_dir.mkdir()
            manifest = self.write_resource_manifest(
                resource_dir, RESOURCE_MANIFEST_V3
            )
            toolchain_dir = root / "toolchain"
            backend = self.runtime_backend(resource_dir, manifest, toolchain_dir)
            self.seal_resource_bundle(resource_dir)
            self.assertTrue(backend.runtime_provenance()["official"])

            library = toolchain_dir / "usr" / "lib" / "libfixture.so"
            stat = library.stat()
            library.chmod(stat.st_mode | 0o200)
            library.write_bytes(b"x" * stat.st_size)
            os.utime(library, ns=(stat.st_atime_ns, stat.st_mtime_ns))
            library.chmod(stat.st_mode)

            provenance = backend.runtime_provenance()
            self.assertFalse(provenance["official"])
            self.assertFalse(provenance["verified"])
            self.assertFalse(provenance["toolchain_inventory"]["verified"])
            self.assertFalse(
                provenance["toolchain_inventory"]["sealed_read_only"]
            )
            self.assertIn(
                "libfixture.so", provenance["toolchain_inventory"]["error"]
            )

    def test_runtime_provenance_detects_toolchain_mode_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            resource_dir = root / "resources"
            resource_dir.mkdir()
            manifest = self.write_resource_manifest(
                resource_dir, RESOURCE_MANIFEST_V3
            )
            toolchain_dir = root / "toolchain"
            backend = self.runtime_backend(resource_dir, manifest, toolchain_dir)
            self.seal_resource_bundle(resource_dir)
            library = toolchain_dir / "usr" / "lib" / "libfixture.so"
            library.chmod(library.stat().st_mode | 0o200)

            provenance = backend.runtime_provenance()
            self.assertTrue(provenance["verified"])
            self.assertFalse(provenance["official"])
            self.assertFalse(
                provenance["toolchain_inventory"]["sealed_read_only"]
            )
            self.assertIn(
                "resource v3 bound toolchain is not sealed read-only",
                provenance["non_official_reasons"],
            )

    def test_runtime_provenance_detects_toolchain_manifest_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            resource_dir = root / "resources"
            resource_dir.mkdir()
            manifest = self.write_resource_manifest(
                resource_dir, RESOURCE_MANIFEST_V3
            )
            toolchain_dir = root / "toolchain"
            backend = self.runtime_backend(resource_dir, manifest, toolchain_dir)
            self.seal_resource_bundle(resource_dir)
            self.assertTrue(backend.runtime_provenance()["official"])

            manifest_path = toolchain_dir / "manifest.json"
            stat = manifest_path.stat()
            described = json.loads(manifest_path.read_text(encoding="utf-8"))
            described["bundle_id"] = "0" * 64
            mutated = (
                json.dumps(described, sort_keys=True, separators=(",", ":")) + "\n"
            ).encode()
            self.assertEqual(len(mutated), stat.st_size)
            manifest_path.chmod(stat.st_mode | 0o200)
            manifest_path.write_bytes(mutated)
            os.utime(manifest_path, ns=(stat.st_atime_ns, stat.st_mtime_ns))
            manifest_path.chmod(stat.st_mode)

            provenance = backend.runtime_provenance()
            self.assertFalse(provenance["official"])
            self.assertFalse(provenance["verified"])
            self.assertFalse(provenance["toolchain_manifest"]["verified"])
            self.assertIn(
                "identity differs from the resource binding",
                provenance["toolchain_manifest"]["error"],
            )

    def test_runtime_provenance_rechecks_bound_executable_after_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            resource_dir = root / "resources"
            resource_dir.mkdir()
            manifest = self.write_resource_manifest(
                resource_dir, RESOURCE_MANIFEST_V3
            )
            toolchain_dir = root / "toolchain"
            backend = self.runtime_backend(resource_dir, manifest, toolchain_dir)
            self.seal_resource_bundle(resource_dir)
            command = toolchain_dir / "usr" / "bin" / "hfst-proc"
            original_verify = backend._verify_bound_toolchain_inventory

            def mutate_after_inventory(*, force_rehash: bool = False):
                result = original_verify(force_rehash=force_rehash)
                stat = command.stat()
                command.chmod(stat.st_mode | 0o200)
                command.write_bytes(b"x" * stat.st_size)
                os.utime(command, ns=(stat.st_atime_ns, stat.st_mtime_ns))
                command.chmod(stat.st_mode)
                return result

            with mock.patch.object(
                backend,
                "_verify_bound_toolchain_inventory",
                side_effect=mutate_after_inventory,
            ):
                provenance = backend.runtime_provenance()
            command_record = provenance["executables"]["hfst-proc"]
            self.assertFalse(provenance["official"])
            self.assertFalse(provenance["verified"])
            self.assertFalse(command_record["verified"])
            self.assertIn("changed after inventory", command_record["error"])
            self.assertIn(
                "hfst-proc", provenance["toolchain_inventory"]["error"]
            )

    def test_loader_injection_env_is_hashed_not_disclosed_and_nonofficial(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            resource_dir = root / "resources"
            resource_dir.mkdir()
            manifest = self.write_resource_manifest(
                resource_dir, RESOURCE_MANIFEST_V3
            )
            backend = self.runtime_backend(resource_dir, manifest, root / "toolchain")
            self.seal_resource_bundle(resource_dir)
            for name in ("LD_LIBRARY_PATH", "LD_PRELOAD", "LD_AUDIT"):
                with self.subTest(name=name):
                    secret_value = f"/sensitive/{name.casefold()}-inject.so"
                    with mock.patch(
                        "qazmorph.backend.sys.platform", "linux"
                    ), mock.patch.dict("os.environ", {name: secret_value}, clear=True):
                        backend.environment = backend._environment()
                    if name == "LD_LIBRARY_PATH":
                        self.assertEqual(
                            backend.environment[name],
                            str(backend.toolchain_dir / "usr" / "lib"),
                        )
                        self.assertNotIn(secret_value, backend.environment[name])
                    else:
                        self.assertNotIn(name, backend.environment)

                    with mock.patch("qazmorph.backend.sys.platform", "linux"):
                        provenance = backend.runtime_provenance()
                    identity = provenance["environment"][name]
                    expected_identity = {
                        "ambient_present": True,
                        "removed_from_helper_environment": True,
                        "sha256": hashlib.sha256(
                            os.fsencode(secret_value)
                        ).hexdigest(),
                    }
                    if name == "LD_LIBRARY_PATH":
                        expected_identity.update(
                            {
                                "helper_value_source": "manifest-bound-runtime",
                                "helper_relative_paths": ["usr/lib"],
                            }
                        )
                    self.assertEqual(identity, expected_identity)
                    self.assertNotIn(secret_value, json.dumps(provenance))
                    self.assertFalse(provenance["official"])
                    self.assertIn(
                        f"ambient {name} was present at parent startup; it was removed from helper launches but may already have affected the Python process",
                        provenance["non_official_reasons"],
                    )

    def test_loader_injection_hash_accepts_surrogateescaped_bytes(self) -> None:
        raw_value = b"/sensitive/non-utf8-\xff.so"
        ambient_value = os.fsdecode(raw_value)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            resource_dir = root / "resources"
            resource_dir.mkdir()
            manifest = self.write_resource_manifest(
                resource_dir, RESOURCE_MANIFEST_V3
            )
            backend = self.runtime_backend(resource_dir, manifest, root / "toolchain")
            self.seal_resource_bundle(resource_dir)
            with mock.patch.dict(
                "os.environ", {"LD_PRELOAD": ambient_value}, clear=True
            ):
                backend.environment = backend._environment()

            with mock.patch("qazmorph.backend.sys.platform", "linux"):
                provenance = backend.runtime_provenance()
            self.assertNotIn("LD_PRELOAD", backend.environment)
            self.assertEqual(
                provenance["environment"]["LD_PRELOAD"],
                {
                    "ambient_present": True,
                    "removed_from_helper_environment": True,
                    "sha256": hashlib.sha256(raw_value).hexdigest(),
                },
            )
            self.assertFalse(provenance["official"])

    def test_resource_resolves_bound_immutable_toolchain_not_newer_stable_link(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            runtime = Path(temporary)
            old = runtime / "toolchains" / "old"
            new = runtime / "toolchains" / "new"
            old.mkdir(parents=True)
            new.mkdir(parents=True)
            old_data = (json.dumps({"bundle_id": "old-bundle"}) + "\n").encode()
            new_data = (json.dumps({"bundle_id": "new-bundle"}) + "\n").encode()
            (old / "manifest.json").write_bytes(old_data)
            (new / "manifest.json").write_bytes(new_data)
            (runtime / "toolchain").symlink_to(new, target_is_directory=True)

            backend = FSTBackend.__new__(FSTBackend)
            backend.runtime_dir = runtime
            manifest = {
                "build": {
                    "toolchain": {
                        "bundle_id": "old-bundle",
                        "manifest": {
                            "bytes": len(old_data),
                            "sha256": hashlib.sha256(old_data).hexdigest(),
                        },
                    }
                }
            }
            self.assertEqual(backend._resolve_toolchain_dir(manifest), old.resolve())

    def test_backend_keeps_resource_build_binding_distinct_from_detached_runtime(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            resource = root / "resources"
            resource.mkdir()
            active = root / "platform-runtimes" / ("a" * 64)
            active.mkdir(parents=True)
            original = {
                "bundle_id": "b" * 64,
                "manifest": {"bytes": 10, "sha256": "c" * 64},
            }
            detached = {
                "bundle_id": "a" * 64,
                "manifest": {"bytes": 20, "sha256": "d" * 64},
            }
            selection = PlatformRuntimeBinding(
                directory=active,
                binding=detached,
                lock_entry={
                    "platform": {"system": "darwin", "machine": "arm64"},
                    "resource_bundle_ids": ["e" * 64],
                    **detached,
                },
                manifest={"commands": {}, "files": {}, "bundle_id": "a" * 64},
            )
            backend = FSTBackend.__new__(FSTBackend)
            backend.resource_dir = resource
            backend.runtime_dir = root
            backend.manifest = {
                "bundle_id": "e" * 64,
                "build": {"toolchain": original},
            }
            with mock.patch(
                "qazmorph.backend.resolve_platform_runtime", return_value=selection
            ):
                backend._select_runtime_toolchain()

            self.assertEqual(backend.resource_build_toolchain_binding, original)
            self.assertEqual(backend.toolchain_binding, detached)
            self.assertEqual(backend.toolchain_origin, "platform-runtime-lock")
            self.assertEqual(backend.toolchain_dir, active)

    def test_detached_runtime_provenance_reports_original_build_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            resource_dir = root / "resources"
            resource_dir.mkdir()
            manifest = self.write_resource_manifest(resource_dir, RESOURCE_MANIFEST_V3)
            backend = self.runtime_backend(resource_dir, manifest, root / "toolchain")
            self.seal_resource_bundle(resource_dir)
            backend.toolchain_dir = backend.toolchain_dir.resolve()
            backend.hfst_proc = str(Path(backend.hfst_proc).resolve())
            original = {
                "bundle_id": "f" * 64,
                "manifest": {"bytes": 99, "sha256": "e" * 64},
            }
            backend.resource_build_toolchain_binding = original
            backend.toolchain_binding = dict(manifest["build"]["toolchain"])
            backend.toolchain_origin = "platform-runtime-lock"
            backend.platform_runtime_lock_entry = {
                "platform": {"system": "darwin", "machine": "arm64"},
                "resource_bundle_ids": [manifest["bundle_id"]],
                **backend.toolchain_binding,
            }
            backend._executable_origins["hfst-proc"] = "platform-runtime-lock"

            provenance = backend.runtime_provenance()

            self.assertEqual(provenance["resource_build_toolchain"], original)
            self.assertEqual(
                provenance["active_runtime"]["origin"], "platform-runtime-lock"
            )
            self.assertEqual(
                provenance["active_runtime"]["bundle_id"],
                backend.toolchain_binding["bundle_id"],
            )
            self.assertTrue(provenance["executables"]["hfst-proc"]["verified"])

            backend._ambient_dyld_library_path = "/untrusted/dylibs"
            backend._ambient_loader_overrides = {
                "DYLD_LIBRARY_PATH": "/untrusted/dylibs"
            }
            with mock.patch("qazmorph.backend.sys.platform", "darwin"):
                injected = backend.runtime_provenance()
            self.assertFalse(injected["official"])
            self.assertIn(
                "ambient DYLD_LIBRARY_PATH was present at parent startup; it was removed from helper launches but may already have affected the Python process",
                injected["non_official_reasons"],
            )
            self.assertNotIn("/untrusted/dylibs", json.dumps(injected))

    def test_darwin_runtime_uses_rpaths_and_records_dyld_injection(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            backend = FSTBackend.__new__(FSTBackend)
            backend.toolchain_dir = Path(temporary)
            hostile = {
                name: f"/untrusted/{name.casefold()}"
                for name in LOADER_OVERRIDE_VARIABLES
            }
            with mock.patch("qazmorph.backend.sys.platform", "darwin"), mock.patch.dict(
                os.environ,
                hostile,
                clear=True,
            ):
                environment = backend._environment()

            for name in LOADER_OVERRIDE_VARIABLES:
                self.assertNotIn(name, environment)
            self.assertEqual(
                backend._ambient_dyld_library_path,
                hostile["DYLD_LIBRARY_PATH"],
            )
            self.assertEqual(
                backend._ambient_dyld_insert_libraries,
                hostile["DYLD_INSERT_LIBRARIES"],
            )

    def test_missing_resource_bound_toolchain_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            backend = FSTBackend.__new__(FSTBackend)
            backend.runtime_dir = Path(temporary)
            manifest = {
                "build": {
                    "toolchain": {
                        "bundle_id": "missing",
                        "manifest": {"bytes": 1, "sha256": "0" * 64},
                    }
                }
            }
            with self.assertRaisesRegex(BackendError, "unavailable"):
                backend._resolve_toolchain_dir(manifest)

    def test_bound_command_binary_tampering_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            executable = root / "usr" / "bin" / "hfst-apertium-proc"
            executable.parent.mkdir(parents=True)
            original = b"verified-binary"
            executable.write_bytes(original)
            executable.chmod(0o755)
            digest = hashlib.sha256(original).hexdigest()
            backend = FSTBackend.__new__(FSTBackend)
            backend.toolchain_dir = root
            backend.toolchain_manifest = {
                "commands": {
                    "hfst-proc": {
                        "path": "usr/bin/hfst-apertium-proc",
                        "sha256": digest,
                    }
                },
                "files": {
                    "usr/bin/hfst-apertium-proc": {
                        "bytes": len(original),
                        "sha256": digest,
                    }
                },
            }
            backend._executable_origins = {}
            executable.write_bytes(b"tampered-binary")
            with mock.patch.dict("os.environ", {}, clear=False), self.assertRaisesRegex(
                BackendError, "checksum failed"
            ):
                backend._find_executable("hfst-proc", "QAZMORPH_TEST_HFST_PROC")

    def test_required_command_missing_from_bound_manifest_is_rejected(self) -> None:
        backend = FSTBackend.__new__(FSTBackend)
        backend.toolchain_dir = Path("/unreachable")
        backend.toolchain_manifest = {"commands": {}, "files": {}}
        backend._executable_origins = {}
        with mock.patch.dict("os.environ", {}, clear=False), self.assertRaisesRegex(
            BackendError, "no command"
        ):
                backend._find_executable("hfst-proc", "QAZMORPH_TEST_HFST_PROC")

    def test_explicit_command_override_is_hashed_but_marked_unverified(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            resource_dir = root / "resources"
            resource_dir.mkdir()
            manifest_value = self.write_resource_manifest(
                resource_dir, RESOURCE_MANIFEST_V3
            )
            toolchain_dir = root / "toolchain"
            backend = self.runtime_backend(
                resource_dir, manifest_value, toolchain_dir
            )
            self.seal_resource_bundle(resource_dir)
            executable = root / "override"
            executable.write_bytes(b"explicit-runtime")
            executable.chmod(0o755)
            with mock.patch.dict(
                "os.environ", {"QAZMORPH_TEST_HFST_PROC": str(executable)}
            ):
                backend.hfst_proc = backend._find_executable(
                    "hfst-proc", "QAZMORPH_TEST_HFST_PROC"
                )
            provenance = backend.runtime_provenance()
            command = provenance["executables"]["hfst-proc"]
            self.assertEqual(command["origin"], "explicit:QAZMORPH_TEST_HFST_PROC")
            self.assertFalse(command["verified"])
            self.assertFalse(provenance["official"])
            self.assertFalse(provenance["verified"])
            self.assertIn("QAZMORPH_TEST_HFST_PROC", provenance["non_official_reasons"][0])

            with mock.patch("qazmorph.backend.sys.platform", "win32"), mock.patch(
                "qazmorph.backend.os.access", return_value=False
            ):
                windows_provenance = backend.runtime_provenance()
            self.assertEqual(
                windows_provenance["executables"]["hfst-proc"][
                    "availability_contract"
                ],
                "regular-exe-successful-version-execution-unverified-override",
            )

            backend.guesser_verified_finite = False
            backend.guesser_productive_safe = False
            proofless = backend.runtime_provenance()
            self.assertTrue(
                any(
                    "finite-guesser proof" in reason
                    for reason in proofless["non_official_reasons"]
                )
            )

    def test_complete_bound_toolchain_inventory_rejects_tampered_library(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            library = root / "usr" / "lib" / "libexample.so"
            library.parent.mkdir(parents=True)
            library.write_bytes(b"tampered")
            expected = b"verified"
            manifest_path = root / "manifest.json"
            manifest_path.write_text("{}\n", encoding="utf-8")
            manifest_path.chmod(0o444)
            backend = FSTBackend.__new__(FSTBackend)
            backend.toolchain_dir = root
            backend.toolchain_manifest = {
                "files": {
                    "usr/lib/libexample.so": {
                        "kind": "file",
                        "bytes": len(expected),
                        "sha256": hashlib.sha256(expected).hexdigest(),
                    }
                }
            }
            with self.assertRaisesRegex(BackendError, "checksum failed"):
                backend._verify_bound_toolchain_inventory()

    def test_inventory_cache_detects_same_size_mutation_with_restored_mtime(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            library = root / "usr" / "lib" / "libexample.so"
            library.parent.mkdir(parents=True)
            original = b"verified"
            library.write_bytes(original)
            manifest_path = root / "manifest.json"
            manifest_path.write_text("{}\n", encoding="utf-8")
            manifest_path.chmod(0o444)
            described = {
                "files": {
                    "usr/lib/libexample.so": {
                        "kind": "file",
                        "bytes": len(original),
                        "sha256": hashlib.sha256(original).hexdigest(),
                    }
                }
            }
            first = FSTBackend.__new__(FSTBackend)
            first.toolchain_dir = root
            first.toolchain_manifest = described
            self.assertTrue(first._verify_bound_toolchain_inventory()["verified"])

            stat = library.stat()
            library.write_bytes(b"tampered")
            os.utime(library, ns=(stat.st_atime_ns, stat.st_mtime_ns))
            second = FSTBackend.__new__(FSTBackend)
            second.toolchain_dir = root
            second.toolchain_manifest = described
            with self.assertRaisesRegex(BackendError, "checksum failed"):
                second._verify_bound_toolchain_inventory()

    def test_manifest_chmod_is_rechecked_across_cached_analyzers(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            library = root / "libexample.so"
            library.write_bytes(b"verified")
            manifest_path = root / "manifest.json"
            manifest_path.write_text("{}\n", encoding="utf-8")
            manifest_path.chmod(0o444)
            described = {
                "files": {
                    "libexample.so": {
                        "kind": "file",
                        "bytes": len(b"verified"),
                        "sha256": hashlib.sha256(b"verified").hexdigest(),
                    }
                }
            }
            first = FSTBackend.__new__(FSTBackend)
            first.toolchain_dir = root
            first.toolchain_manifest = described
            self.assertTrue(
                first._verify_bound_toolchain_inventory()["manifest_read_only"]
            )

            manifest_path.chmod(0o644)
            second = FSTBackend.__new__(FSTBackend)
            second.toolchain_dir = root
            second.toolchain_manifest = described
            observed = second._verify_bound_toolchain_inventory()
            self.assertFalse(observed["manifest_read_only"])
            self.assertFalse(observed["sealed_read_only"])


    def test_prefix_wide_loader_and_glibc_tunables_are_scrubbed_and_recorded(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            resource_dir = root / "resources"
            resource_dir.mkdir()
            manifest = self.write_resource_manifest(
                resource_dir, RESOURCE_MANIFEST_V3
            )
            backend = self.runtime_backend(resource_dir, manifest, root / "toolchain")
            self.seal_resource_bundle(resource_dir)
            ambient = {
                "LD_FUTURE_INJECTOR": "/sensitive/future-ld.so",
                "DYLD_FUTURE_INJECTOR": "/sensitive/future-dyld.dylib",
                GLIBC_TUNABLES_VARIABLE: "",
            }
            with mock.patch("qazmorph.backend.sys.platform", "linux"), mock.patch.dict(
                os.environ, ambient, clear=True
            ):
                backend.environment = backend._environment()
            for name in ambient:
                self.assertNotIn(name, backend.environment)

            with mock.patch("qazmorph.backend.sys.platform", "linux"):
                provenance = backend.runtime_provenance()
            policy = provenance["environment"]["loader_policy"]
            self.assertEqual(
                policy["schema"],
                "qazmorph-native-helper-loader-environment-v2",
            )
            self.assertEqual(
                policy["captured_name_policy"],
                {
                    "exact_uppercase_prefixes": ["LD_", "DYLD_"],
                    "exact_names": ["GLIBC_TUNABLES"],
                },
            )
            self.assertFalse(policy["clean_parent_startup"])
            self.assertTrue(
                policy["all_ambient_values_removed_from_helper_environment"]
            )
            self.assertEqual(
                set(policy["ambient_records"]),
                {"LD_FUTURE_INJECTOR", "DYLD_FUTURE_INJECTOR"},
            )
            for name in ("LD_FUTURE_INJECTOR", "DYLD_FUTURE_INJECTOR"):
                self.assertEqual(
                    policy["ambient_records"][name],
                    {
                        "ambient_present": True,
                        "removed_from_helper_environment": True,
                        "sha256": hashlib.sha256(
                            os.fsencode(ambient[name])
                        ).hexdigest(),
                    },
                )
            self.assertEqual(
                policy["glibc_tunables"],
                {
                    "ambient_present": True,
                    "removed_from_helper_environment": True,
                    "sha256": hashlib.sha256(b"").hexdigest(),
                },
            )
            self.assertFalse(provenance["official"])
            for name in ambient:
                self.assertTrue(
                    any(name in reason for reason in provenance["non_official_reasons"])
                )
            self.assertNotIn("/sensitive/", json.dumps(provenance))

    def test_loader_prefix_policy_is_exact_uppercase(self) -> None:
        backend = FSTBackend.__new__(FSTBackend)
        backend.toolchain_dir = Path("/nonexistent-manifest-bound-toolchain")
        lower = {"ld_preload": "lower-ld", "dyld_insert_libraries": "lower-dyld"}
        with mock.patch("qazmorph.backend.sys.platform", "linux"), mock.patch.dict(
            os.environ, lower, clear=True
        ):
            environment = backend._environment()
        self.assertEqual({name: environment[name] for name in lower}, lower)
        self.assertEqual(backend._ambient_loader_overrides, {})

    def test_linux_helper_environment_uses_only_manifest_bound_library_dirs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "usr/lib").mkdir(parents=True)
            backend = FSTBackend.__new__(FSTBackend)
            backend.toolchain_dir = root
            with mock.patch("qazmorph.backend.sys.platform", "linux"), mock.patch.dict(
                os.environ,
                {
                    "LD_LIBRARY_PATH": "/hostile/libs",
                    "LD_PRELOAD": "/hostile/inject.so",
                    "LD_AUDIT": "/hostile/audit.so",
                },
                clear=True,
            ):
                environment = backend._environment()

            self.assertEqual(environment["LD_LIBRARY_PATH"], str(root / "usr/lib"))
            self.assertNotIn("/hostile", environment["LD_LIBRARY_PATH"])
            self.assertNotIn("LD_PRELOAD", environment)
            self.assertNotIn("LD_AUDIT", environment)
            self.assertEqual(backend._bound_linux_library_paths, ["usr/lib"])

    def test_windows_helper_environment_empties_untrusted_path(self) -> None:
        backend = FSTBackend.__new__(FSTBackend)
        with mock.patch("qazmorph.backend.sys.platform", "win32"), mock.patch(
            "qazmorph.backend._trusted_windows_loader_directories",
            return_value=(r"C:\Windows\System32", r"C:\Windows"),
        ), mock.patch.dict(
            os.environ,
            {"PATH": r"C:\hostile;C:\Windows\System32;C:\Windows"},
            clear=True,
        ):
            environment = backend._environment()

        self.assertEqual(environment["PATH"], "")
        self.assertTrue(backend._ambient_windows_path_present)
        self.assertTrue(backend._ambient_windows_path_risk)

        with mock.patch("qazmorph.backend.sys.platform", "win32"), mock.patch(
            "qazmorph.backend._trusted_windows_loader_directories",
            return_value=(r"C:\Windows\System32", r"C:\Windows"),
        ), mock.patch.dict(
            os.environ,
            {"PATH": r"C:\Windows\System32;C:\Windows"},
            clear=True,
        ):
            backend._environment()
        self.assertFalse(backend._ambient_windows_path_risk)

    def test_windows_absolute_helper_uses_its_own_directory_as_cwd(self) -> None:
        with mock.patch("qazmorph.backend.sys.platform", "win32"):
            helper = Path("/trusted/bundle/usr/bin/hfst-proc.exe")
            self.assertEqual(
                _helper_working_directory(helper),
                str(helper.parent),
            )
            with self.assertRaises(BackendError):
                _helper_working_directory(Path("relative-helper.exe"))


if __name__ == "__main__":
    unittest.main()
