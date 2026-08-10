from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from qazmorph.backend import (
    _hyphen_chains,
    BackendError,
    escape_apertium_text,
    FSTBackend,
    RESOURCE_FILES_BY_SCHEMA,
    RESOURCE_MANIFEST_V2,
    RESOURCE_MANIFEST_V3,
    prepare_apertium_text,
    strip_boundary_superblanks,
)


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


class ResourceManifestTests(unittest.TestCase):
    @staticmethod
    def finite_guesser_gate() -> dict[str, object]:
        return {
            "verification": {
                "productive_guesser_finite_valued": {
                    "result": {
                        "schema": "qazmorph-guesser-finiteness-v1",
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
                ResourceManifestTests.finite_guesser_gate()
                if schema == RESOURCE_MANIFEST_V3
                else {}
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

    def test_v2_standard_and_v3_optimized_resource_layouts_are_both_valid(self) -> None:
        for schema, guesser_name in (
            (RESOURCE_MANIFEST_V2, "kaz.guesser.automorf.hfst"),
            (RESOURCE_MANIFEST_V3, "kaz.guesser.automorf.hfstol"),
        ):
            with self.subTest(schema=schema), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                expected = self.write_resource_manifest(root, schema)
                backend = FSTBackend.__new__(FSTBackend)
                backend.resource_dir = root
                observed = backend._read_manifest()
                self.assertEqual(observed, expected)
                self.assertIn(guesser_name, observed["files"])

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

    def test_v3_manifest_requires_the_embedded_finite_guesser_proof(self) -> None:
        for mutation in ("missing", "cycle", "bounded_root", "relation", "candidates"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                manifest = self.write_resource_manifest(root, RESOURCE_MANIFEST_V3)
                result = manifest["build"]["verification"][
                    "productive_guesser_finite_valued"
                ]["result"]
                if mutation == "missing":
                    manifest["build"].pop("verification")
                elif mutation == "cycle":
                    result["graph"]["reachable_input_epsilon_cycle"] = True
                elif mutation == "bounded_root":
                    result["no_cap_probes"][
                        "all_lemmas_match_bounded_root_relation"
                    ] = False
                elif mutation == "relation":
                    result["optimized_runtime"][
                        "full_relation_equivalent_to_standard"
                    ] = False
                else:
                    result["optimized_runtime"][
                        "candidate_sets_equal_to_standard"
                    ] = False
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
                with self.assertRaisesRegex(BackendError, "finite-guesser verification"):
                    backend._read_manifest()

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
            for name in ("LD_PRELOAD", "LD_AUDIT"):
                with self.subTest(name=name):
                    secret_value = f"/sensitive/{name.casefold()}-inject.so"
                    with mock.patch.dict(
                        "os.environ", {name: secret_value}, clear=True
                    ):
                        backend.environment = backend._environment()
                    self.assertEqual(backend.environment[name], secret_value)

                    provenance = backend.runtime_provenance()
                    identity = provenance["environment"][name]
                    self.assertEqual(
                        identity,
                        {
                            "present": True,
                            "sha256": hashlib.sha256(
                                os.fsencode(secret_value)
                            ).hexdigest(),
                        },
                    )
                    self.assertNotIn(secret_value, json.dumps(provenance))
                    self.assertFalse(provenance["official"])
                    self.assertIn(
                        f"ambient {name} is present and can inject unverified code",
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

            provenance = backend.runtime_provenance()
            self.assertEqual(backend.environment["LD_PRELOAD"], ambient_value)
            self.assertEqual(
                provenance["environment"]["LD_PRELOAD"],
                {
                    "present": True,
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


if __name__ == "__main__":
    unittest.main()
