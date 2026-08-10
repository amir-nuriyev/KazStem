from __future__ import annotations

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


class ResourceProducerSnapshotTests(unittest.TestCase):
    def test_exact_snapshot_is_separate_from_hardened_runtime_consumer(self) -> None:
        receipt = verification.verify_snapshot(
            SNAPSHOT_ROOT,
            consumer_root=PROJECT_ROOT,
            resource_manifest=None,
        )
        self.assertTrue(receipt["snapshot_verified"])
        self.assertTrue(receipt["consumer_source_separate"])
        self.assertEqual(receipt["producer_inputs"], 11)
        lock = json.loads((SNAPSHOT_ROOT / "SNAPSHOT.json").read_text())
        for relative in ("src/qazmorph/generator.py", "src/qazmorph/guesser.py"):
            self.assertNotEqual(
                receipt["consumer_records"][relative]["sha256"],
                lock["producer_build_inputs"][relative]["sha256"],
            )

    def test_changed_missing_and_extra_producer_files_fail_closed(self) -> None:
        cases = ("changed", "missing", "extra")
        for case in cases:
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

    def test_manifest_build_inputs_must_match_exact_snapshot(self) -> None:
        lock = json.loads((SNAPSHOT_ROOT / "SNAPSHOT.json").read_text())
        inputs = {
            name: {"bytes": value["bytes"], "sha256": value["sha256"]}
            for name, value in lock["producer_build_inputs"].items()
        }
        manifest = {
            "schema": "qazmorph-resource-manifest-v4",
            "bundle_id": BUNDLE_ID,
            "build": {"inputs": inputs},
        }
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "manifest.json"
            path.write_text(json.dumps(manifest), encoding="utf-8")
            receipt = verification.verify_snapshot(
                SNAPSHOT_ROOT,
                consumer_root=PROJECT_ROOT,
                resource_manifest=path,
            )
            self.assertTrue(receipt["resource_manifest_verified"])
            manifest["build"]["inputs"]["src/qazmorph/generator.py"][
                "sha256"
            ] = "0" * 64
            path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaises(verification.SnapshotError):
                verification.verify_snapshot(
                    SNAPSHOT_ROOT,
                    consumer_root=PROJECT_ROOT,
                    resource_manifest=path,
                )


if __name__ == "__main__":
    unittest.main()
