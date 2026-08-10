from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
BUNDLE_ID = "bf1f31ff6e5860585b9e4134f12dcfb9d6df8030ee87b368e5a5f29eb45c1188"
SNAPSHOT_ROOT = PROJECT_ROOT / "packaging" / "resource-producer" / BUNDLE_ID
SCRIPT = PROJECT_ROOT / "packaging" / "verify_resource_producer_snapshot.py"
SPEC = importlib.util.spec_from_file_location("verify_resource_snapshot", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
verification = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verification)


def mutate_path(
    value: dict[str, object],
    path: tuple[str | int, ...],
    replacement: object,
) -> None:
    selected: object = value
    for part in path[:-1]:
        if isinstance(selected, list):
            assert isinstance(part, int)
            selected = selected[part]
        else:
            assert isinstance(selected, dict) and isinstance(part, str)
            selected = selected[part]
    final = path[-1]
    if isinstance(selected, list):
        assert isinstance(final, int)
        selected[final] = replacement
    else:
        assert isinstance(selected, dict) and isinstance(final, str)
        selected[final] = replacement


def leaf_paths(
    value: object, prefix: tuple[str | int, ...] = ()
):
    if isinstance(value, dict):
        for key, child in value.items():
            yield from leaf_paths(child, (*prefix, key))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from leaf_paths(child, (*prefix, index))
    else:
        yield prefix, value


def changed_leaf(value: object) -> object:
    if isinstance(value, bool):
        return not value
    if isinstance(value, int):
        return value + 1
    if isinstance(value, str):
        return "tampered"
    raise AssertionError(f"unsupported fixture leaf: {value!r}")


class ResourceProducerSnapshotTests(unittest.TestCase):
    @staticmethod
    def load_snapshot() -> dict[str, object]:
        return json.loads((SNAPSHOT_ROOT / "SNAPSHOT.json").read_text())

    @classmethod
    def validated_snapshot_parts(
        cls,
    ) -> tuple[
        dict[str, object],
        dict[str, dict[str, int | str]],
        dict[str, object],
    ]:
        payload = verification._snapshot_metadata(cls.load_snapshot())
        build_inputs, _paths = verification._producer_inputs(SNAPSHOT_ROOT, payload)
        manifest = json.loads(
            (SNAPSHOT_ROOT / "RESOURCE-MANIFEST.json").read_text()
        )
        return payload, build_inputs, manifest

    def test_exact_snapshot_is_separate_from_hardened_runtime_consumer(self) -> None:
        receipt = verification.verify_snapshot(
            SNAPSHOT_ROOT,
            consumer_root=PROJECT_ROOT,
            resource_manifest=None,
        )
        self.assertTrue(receipt["snapshot_verified"])
        self.assertTrue(receipt["sealed_manifest_snapshot_verified"])
        self.assertTrue(receipt["canonical_bundle_identity_verified"])
        self.assertTrue(receipt["consumer_source_separate"])
        self.assertTrue(receipt["closure_lock_verified"])
        self.assertFalse(receipt["release_closure_complete"])
        self.assertEqual(receipt["producer_inputs"], 11)
        lock = self.load_snapshot()
        for relative in ("src/qazmorph/generator.py", "src/qazmorph/guesser.py"):
            self.assertNotEqual(
                receipt["consumer_records"][relative]["sha256"],
                lock["producer_build_inputs"][relative]["sha256"],
            )

    def test_changed_missing_and_extra_producer_files_fail_closed(self) -> None:
        for case in ("changed", "missing", "extra"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                copied = Path(temporary) / "snapshot"
                shutil.copytree(SNAPSHOT_ROOT, copied)
                target = copied / "source" / "scripts" / "bootstrap_h100.sh"
                if case == "changed":
                    target.write_bytes(target.read_bytes() + b"\n")
                elif case == "missing":
                    target.unlink()
                else:
                    (copied / "source" / "unexpected.txt").write_text("unexpected")
                with self.assertRaises(verification.SnapshotError):
                    verification.verify_snapshot(
                        copied,
                        consumer_root=PROJECT_ROOT,
                        resource_manifest=None,
                    )

    def test_sealed_manifest_recomputes_exact_bundle_and_external_bindings(self) -> None:
        payload, build_inputs, manifest = self.validated_snapshot_parts()
        verified = verification._validate_resource_manifest(
            manifest, payload, build_inputs
        )
        self.assertEqual(verified["bundle_id"], BUNDLE_ID)
        identity = {
            key: value
            for key, value in manifest.items()
            if key not in {"bundle_id", "version"}
        }
        self.assertEqual(verification._canonical_hash(identity), BUNDLE_ID)

    def test_incomplete_release_closure_request_fails_closed(self) -> None:
        with self.assertRaisesRegex(
            verification.SnapshotError, "full release-closure verification"
        ):
            verification.verify_snapshot(
                SNAPSHOT_ROOT,
                consumer_root=PROJECT_ROOT,
                resource_manifest=SNAPSHOT_ROOT / "RESOURCE-MANIFEST.json",
            )

    def test_every_external_revision_license_and_closure_binding_is_tamper_sensitive(
        self,
    ) -> None:
        original = self.load_snapshot()
        mutations = []
        for section in (
            "resource_manifest",
            "external_resource_source",
            "external_toolchain",
        ):
            mutations.extend(
                (
                    (section, *path),
                    changed_leaf(value),
                )
                for path, value in leaf_paths(original[section])
            )
        for path, replacement in mutations:
            with self.subTest(
                path=".".join(str(part) for part in path)
            ), tempfile.TemporaryDirectory() as temporary:
                copied = Path(temporary) / "snapshot"
                shutil.copytree(SNAPSHOT_ROOT, copied)
                changed = copy.deepcopy(original)
                mutate_path(changed, path, replacement)
                (copied / "SNAPSHOT.json").write_text(json.dumps(changed))
                with self.assertRaises(verification.SnapshotError):
                    verification.verify_snapshot(
                        copied,
                        consumer_root=PROJECT_ROOT,
                        resource_manifest=None,
                    )

    def test_manifest_source_toolchain_proofs_and_artifacts_fail_canonical_identity(
        self,
    ) -> None:
        payload, build_inputs, original = self.validated_snapshot_parts()
        mutations = [
            (("schema",), "wrong"),
            (("bundle_id",), "0" * 64),
            (("version",), "wrong"),
            (
                (
                    "build",
                    "inputs",
                    "src/qazmorph/generator.py",
                    "sha256",
                ),
                "0" * 64,
            ),
            (
                (
                    "build",
                    "verification",
                    "productive_generator_finite_valued",
                    "result",
                    "graph",
                    "reachable_input_epsilon_cycle",
                ),
                True,
            ),
            (("files", "kaz.guesser.autogen.hfstol", "sha256"), "0" * 64),
        ]
        for section_path, section in (
            (("source",), original["source"]),
            (("build", "toolchain"), original["build"]["toolchain"]),
        ):
            mutations.extend(
                ((*section_path, *path), changed_leaf(value))
                for path, value in leaf_paths(section)
            )
        for path, replacement in mutations:
            with self.subTest(path=".".join(path)):
                changed = copy.deepcopy(original)
                mutate_path(changed, path, replacement)
                with self.assertRaises(verification.SnapshotError):
                    verification._validate_resource_manifest(
                        changed, payload, build_inputs
                    )

    def test_closure_lock_tampering_including_component_license_fails(self) -> None:
        payload, _build_inputs, _manifest = self.validated_snapshot_parts()
        binding = payload["external_toolchain"]["release_closure"]
        lock_path = PROJECT_ROOT / binding["lock_path"]
        original = json.loads(lock_path.read_text())
        toolchain_manifest = {
            "packages": [
                {
                    "filename": item["filename"],
                    "bytes": item["bytes"],
                    "sha256": item["sha256"],
                }
                for item in original["archives"]
            ]
        }
        mutations = [
            (path, changed_leaf(value))
            for path, value in leaf_paths(original)
        ]
        for path, replacement in mutations:
            with self.subTest(
                path=".".join(str(part) for part in path)
            ), tempfile.TemporaryDirectory() as temporary:
                changed = copy.deepcopy(original)
                mutate_path(changed, path, replacement)
                candidate = Path(temporary) / "closure.json"
                candidate.write_text(json.dumps(changed))
                with self.assertRaises(verification.SnapshotError):
                    verification._verify_closure_lock(
                        candidate, binding, toolchain_manifest
                    )

    def test_physical_closure_inventory_rejects_changed_missing_extra_and_links(
        self,
    ) -> None:
        content = b"locked archive"
        records = [
            {
                "filename": "archive.tar.xz",
                "bytes": len(content),
                "sha256": hashlib.sha256(content).hexdigest(),
            }
        ]
        for case in ("exact", "changed", "missing", "extra", "symlink"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / "closure"
                root.mkdir()
                target = root / "archive.tar.xz"
                if case != "missing":
                    target.write_bytes(
                        b"changed" if case == "changed" else content
                    )
                if case == "extra":
                    (root / "extra").write_bytes(b"extra")
                if case == "symlink":
                    target.unlink()
                    target.symlink_to(root / "outside")
                if case == "exact":
                    receipt = verification._verify_locked_directory(
                        root, records, label="fixture"
                    )
                    self.assertEqual(set(receipt), {"archive.tar.xz"})
                else:
                    with self.assertRaises(verification.SnapshotError):
                        verification._verify_locked_directory(
                            root, records, label="fixture"
                        )

    def test_manifest_and_canonical_builder_hook_are_packaged_once(self) -> None:
        manifest_include = (PROJECT_ROOT / "MANIFEST.in").read_text()
        self.assertIn(
            "recursive-include packaging/resource-producer *",
            manifest_include,
        )
        readme = (SNAPSHOT_ROOT / "README.md").read_text()
        self.assertIn("canonical release builder", readme)
        self.assertIn("release_closure_identity", readme)
        verifier = SCRIPT.read_text()
        self.assertNotIn("tarfile", verifier)
        self.assertNotIn("zipfile", verifier)


if __name__ == "__main__":
    unittest.main()
