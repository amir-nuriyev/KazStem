from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def load_script(name: str):
    path = PROJECT_ROOT / "scripts" / name
    specification = importlib.util.spec_from_file_location(f"test_{path.stem}", path)
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


neural = load_script("write_neural_manifest.py")
toolchain = load_script("write_toolchain_manifest.py")
platform_runtime = load_script("write_platform_runtime_manifest.py")
resources = load_script("write_manifest.py")


class NeuralModelManifestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.model_dir = self.root / "model"
        self.model_dir.mkdir()
        self.model_file = self.model_dir / "kk" / "tokenize" / "test.pt"
        self.model_file.parent.mkdir(parents=True)
        self.model_file.write_bytes(b"locked-model")
        self.lock_path = self.root / "lock.json"
        self.lock = {
            "schema": "qazmorph-neural-lock-v1",
            "python": "3.12",
            "installer": {"uv_version": "test", "uv_sha256": "0" * 64},
            "stanza": {
                "language": "kk",
                "processors": "tokenize,pos,lemma",
                "version": "test",
            },
            "venv_packages": {},
            "host_packages": {},
            "host_runtime": {},
            "model_files": {
                "kk/tokenize/test.pt": neural.file_record(self.model_file),
            },
        }
        self.lock_path.write_text(
            json.dumps(self.lock, sort_keys=True) + "\n", encoding="utf-8"
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_model_manifest_is_deterministic_and_self_verifying(self) -> None:
        first = neural.model_manifest(self.lock, self.lock_path, self.model_dir)
        second = neural.model_manifest(self.lock, self.lock_path, self.model_dir)
        self.assertEqual(first, second)
        self.assertRegex(first["bundle_id"], r"^[0-9a-f]{64}$")

        neural.atomic_write(self.model_dir / neural.MODEL_MANIFEST, first)
        self.assertEqual(
            neural.load_verified_model_manifest(
                self.lock, self.lock_path, self.model_dir
            ),
            first,
        )

    def test_model_byte_tampering_is_rejected(self) -> None:
        self.model_file.write_bytes(b"tampered-model")
        with self.assertRaisesRegex(neural.ManifestError, "differs from lock"):
            neural.verify_model_files(self.lock, self.model_dir)

    def test_unlocked_extra_model_file_is_rejected(self) -> None:
        (self.model_dir / "unexpected.bin").write_bytes(b"unexpected")
        with self.assertRaisesRegex(neural.ManifestError, "extra=.*unexpected.bin"):
            neural.verify_model_files(self.lock, self.model_dir)

    def test_visible_distribution_snapshot_retains_overlay_versions(self) -> None:
        class Distribution:
            def __init__(self, name: str, version: str) -> None:
                self.metadata = {"Name": name}
                self.version = version

        distributions = [
            Distribution("typing_extensions", "4.15.0"),
            Distribution("typing-extensions", "4.16.0"),
            Distribution("stanza", "1.14.0"),
        ]
        with mock.patch.object(neural.metadata, "distributions", return_value=distributions):
            observed = neural.observed_distribution_closure()
        self.assertEqual(observed["typing-extensions"], ["4.15.0", "4.16.0"])
        self.assertEqual(observed["stanza"], "1.14.0")


class ToolchainManifestPrimitiveTests(unittest.TestCase):
    @staticmethod
    def archive_record() -> dict[str, object]:
        return {
            "filename": "tool_1.0_amd64.deb",
            "package": "tool",
            "version": "1.0",
            "architecture": "amd64",
            "bytes": 123,
            "sha256": "a" * 64,
        }

    def test_canonical_hash_is_independent_of_mapping_order(self) -> None:
        self.assertEqual(
            toolchain.canonical_hash({"b": 2, "a": 1}),
            toolchain.canonical_hash({"a": 1, "b": 2}),
        )

    def test_atomic_write_replaces_complete_json(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "manifest.json"
            toolchain.atomic_write(destination, {"version": 1})
            toolchain.atomic_write(destination, {"version": 2})
            self.assertEqual(json.loads(destination.read_text()), {"version": 2})
            self.assertEqual(list(Path(temporary).glob("*.tmp")), [])

    def test_exact_archive_record_is_accepted(self) -> None:
        record = self.archive_record()
        self.assertEqual(
            toolchain.verify_archive_records([record], [dict(record)]), [record]
        )
    def test_every_locked_archive_dimension_is_enforced(self) -> None:
        record = self.archive_record()
        alternatives = {
            "filename": "other_1.0_amd64.deb",
            "package": "other",
            "version": "1.1",
            "architecture": "arm64",
            "bytes": 124,
            "sha256": "b" * 64,
        }
        for field, changed_value in alternatives.items():
            with self.subTest(field=field):
                changed = {**record, field: changed_value}
                with self.assertRaisesRegex(
                    toolchain.ManifestError, "differ from the checked-in lock"
                ):
                    toolchain.verify_archive_records([record], [changed])

    def test_archive_lock_rejects_duplicate_commands(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            lock_path = Path(temporary) / "lock.json"
            lock_path.write_text(
                json.dumps(
                    {
                        "schema": toolchain.LOCK_SCHEMA,
                        "distribution": "Test",
                        "architecture": "amd64",
                        "required_commands": ["tool", "tool"],
                        "packages": [self.archive_record()],
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                toolchain.ManifestError, "invalid required command set"
            ):
                toolchain.load_archive_lock(lock_path)

    def test_checked_in_lock_declares_archives_and_formal_gate_tools(self) -> None:
        lock = toolchain.load_archive_lock(
            PROJECT_ROOT / "scripts" / "toolchain_assets.lock.json"
        )
        self.assertEqual(len(lock["packages"]), 6)
        self.assertIn("hfst-subtract", lock["required_commands"])
        self.assertIn("hfst-fst2strings", lock["required_commands"])
        self.assertIn("hfst-fst2txt", lock["required_commands"])
        self.assertIn("hfst-regexp2fst", lock["required_commands"])


class PlatformRuntimeManifestTests(unittest.TestCase):
    def test_checked_in_source_lock_has_exact_mac_archives_and_commands(self) -> None:
        lock = platform_runtime.load_source_lock(
            PROJECT_ROOT / "scripts" / "platform_runtime_sources.lock.json"
        )
        self.assertEqual(lock["platform"]["minimum_os"], "14.0")
        self.assertEqual(
            {record["sha256"] for record in lock["archives"]},
            {
                "c5396b147315eae17a3d3b193b8545f90354ba90324310b31593b4f6ccef5ab1",
                "78b4b47596dfa06222e225e5fc45cae385643c9bec33260d3ad3a8b92ae7017c",
            },
        )
        self.assertEqual(
            {record["name"] for record in lock["required_commands"]},
            {"hfst-proc", "hfst-optimized-lookup", "cg-proc"},
        )

    def test_runtime_inventory_records_symlink_and_regular_file_separately(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "usr" / "bin" / "actual"
            target.parent.mkdir(parents=True)
            target.write_bytes(b"runtime")
            target.chmod(0o555)
            (target.parent / "alias").symlink_to("actual")
            output = root / "manifest.json"
            output.write_text("{}\n", encoding="utf-8")
            (root / "manifest-alias").symlink_to("manifest.json")

            inventory = platform_runtime.extracted_files(root, output=output)

            self.assertEqual(inventory["usr/bin/alias"]["target"], "actual")
            self.assertEqual(
                inventory["manifest-alias"]["target"], "manifest.json"
            )
            self.assertNotIn("manifest.json", inventory)
            self.assertEqual(inventory["usr/bin/actual"]["bytes"], 7)
            self.assertEqual(
                inventory["usr/bin/actual"]["sha256"],
                platform_runtime.sha256(target),
            )

    def test_corresponding_source_directory_tampering_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source.tar.gz"
            source.write_bytes(b"source")
            record = {
                "filename": source.name,
                "bytes": source.stat().st_size,
                "sha256": platform_runtime.sha256(source),
            }
            source.write_bytes(b"changed")
            with self.assertRaisesRegex(platform_runtime.ManifestError, "identity mismatch"):
                platform_runtime.verify_record_directory(
                    [record], root, label="source"
                )

    def test_runtime_inventory_rejects_unsupported_special_entries(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fifo = root / "unexpected.fifo"
            os.mkfifo(fifo)
            with self.assertRaisesRegex(
                platform_runtime.ManifestError, "unsupported.*entry type"
            ):
                platform_runtime.extracted_files(
                    root, output=root / "manifest.json"
                )


class BuildScriptOrderingTests(unittest.TestCase):
    def test_guesser_gate_sources_are_resource_build_inputs(self) -> None:
        self.assertEqual(resources.SCHEMA, "qazmorph-resource-manifest-v3")
        self.assertIn("scripts/bootstrap_h100.sh", resources.BUILD_INPUTS)
        self.assertIn(
            "scripts/verify_guesser_fst.py", resources.BUILD_INPUTS
        )
        self.assertIn(
            "scripts/guesser_regression_probes.json", resources.BUILD_INPUTS
        )
        self.assertIn("scripts/toolchain_assets.lock.json", resources.BUILD_INPUTS)
        self.assertIn("scripts/write_toolchain_manifest.py", resources.BUILD_INPUTS)
        self.assertIn("hfst-fst2txt", resources.BUILD_COMMANDS)
        self.assertIn("hfst-regexp2fst", resources.BUILD_COMMANDS)

    def test_archives_are_verified_before_any_extraction(self) -> None:
        script = (PROJECT_ROOT / "scripts" / "bootstrap_h100.sh").read_text(
            encoding="utf-8"
        )
        self.assertLess(script.index("--verify-archives-only"), script.index("dpkg-deb -x"))

    def test_toolchain_is_sealed_read_only_before_activation(self) -> None:
        script = (PROJECT_ROOT / "scripts" / "bootstrap_h100.sh").read_text(
            encoding="utf-8"
        )
        seal = script.index('find "$toolchain_stage/prefix" -mindepth 1')
        activate = script.index('mv "$toolchain_stage/prefix" "$toolchain_target"')
        seal_root = script.index('chmod a-w "$toolchain_target" "$debs_target"')
        writable_gate = script.index('-perm /222 -print -quit')
        stable_link = script.index('toolchain_link="$runtime_dir/.toolchain-link.$$"')
        self.assertLess(seal, activate)
        self.assertLess(activate, seal_root)
        self.assertLess(seal_root, writable_gate)
        self.assertLess(writable_gate, stable_link)

    def test_formal_subset_gate_precedes_resource_optimization(self) -> None:
        script = (PROJECT_ROOT / "scripts" / "build_resources.sh").read_text(
            encoding="utf-8"
        )
        self.assertLess(
            script.index("hfst-subtract -1 kaz.generation.hfst"),
            script.index("hfst-invert kaz.analysis.hfst"),
        )

    def test_productive_guesser_filter_precedes_formal_finiteness_gate(self) -> None:
        script = (PROJECT_ROOT / "scripts" / "build_resources.sh").read_text(
            encoding="utf-8"
        )
        self.assertLess(
            script.index("hfst-regexp2fst -f openfst-tropical"),
            script.index("scripts/verify_guesser_fst.py"),
        )

    def test_resource_build_pins_immutable_toolchain_before_compilation(self) -> None:
        script = (PROJECT_ROOT / "scripts" / "build_resources.sh").read_text(
            encoding="utf-8"
        )
        resolve = script.index('toolchain_dir=$(readlink -f -- "$runtime_dir/toolchain")')
        verify = script.index('scripts/write_toolchain_manifest.py" \\\n')
        compile_step = script.index('export PATH="$toolchain_dir/usr/bin:$PATH"')
        self.assertLess(resolve, verify)
        self.assertLess(verify, compile_step)

    def test_existing_identical_resource_bundle_is_resealed_before_activation(self) -> None:
        script = (PROJECT_ROOT / "scripts" / "build_resources.sh").read_text(
            encoding="utf-8"
        )
        existing_branch = script.index('if [[ -e "$bundle_dir" ]]')
        branch_end = script.index("\nfi\n", existing_branch)
        seal = script.index('chmod -R a-w "$bundle_dir"', existing_branch)
        writable_gate = script.index(
            'find "$bundle_dir" \\( -type f -o -type d \\) -perm /222',
            existing_branch,
        )
        stable_link = script.index('link_stage="$runtime_dir/.resources-link.$$"')
        self.assertEqual(script.count('chmod -R a-w "$bundle_dir"'), 1)
        self.assertLess(branch_end, seal)
        self.assertLess(seal, writable_gate)
        self.assertLess(writable_gate, stable_link)


if __name__ == "__main__":
    unittest.main()
