from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from qazmorph.platform_runtime import (
    PLATFORM_RUNTIME_LOCK_SCHEMA,
    PlatformRuntimeError,
    load_platform_runtime_lock,
    normalized_runtime_platform,
    resolve_platform_runtime,
)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


RESOURCE_ID = "b" * 64
BF1F_RESOURCE_ID = (
    "bf1f31ff6e5860585b9e4134f12dcfb9d6df8030ee87b368e5a5f29eb45c1188"
)
F03E_RESOURCE_ID = (
    "f03e703d3e2a67044a7d91fd7d575b92cb4e61aa782fb67cff91b0a5ff0ebd5a"
)


class PlatformRuntimeTests(unittest.TestCase):
    @staticmethod
    def write_runtime(
        root: Path, *, directory_bundle_id: str | None = None
    ) -> tuple[Path, bytes, str]:
        provisional = root / "runtime-build"
        runtime = provisional
        command = runtime / "usr" / "bin" / "hfst-proc"
        command.parent.mkdir(parents=True)
        command.write_bytes(b"native-command")
        command.chmod(0o555)
        identity = {
            "schema": "kazstem-platform-runtime-manifest-v1",
            "platform": {"system": "darwin", "machine": "arm64"},
            "commands": {
                "hfst-proc": {
                    "path": "usr/bin/hfst-proc",
                    "sha256": sha256(b"native-command"),
                }
            },
            "files": {
                "usr/bin/hfst-proc": {
                    "kind": "file",
                    "mode": "0555",
                    "bytes": len(b"native-command"),
                    "sha256": sha256(b"native-command"),
                }
            },
        }
        bundle_id = sha256(
            json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()
        )
        manifest = {**identity, "bundle_id": bundle_id}
        data = (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode()
        (runtime / "manifest.json").write_bytes(data)
        final = root / "platform-runtimes" / (directory_bundle_id or bundle_id)
        final.parent.mkdir(exist_ok=True)
        runtime.rename(final)
        return final, data, bundle_id

    @staticmethod
    def lock(data: bytes, *, bundle_id: str, resource_id: str = RESOURCE_ID) -> dict[str, object]:
        return {
            "schema": PLATFORM_RUNTIME_LOCK_SCHEMA,
            "runtimes": [
                {
                    "platform": {"system": "darwin", "machine": "arm64"},
                    "resource_bundle_ids": [resource_id],
                    "bundle_id": bundle_id,
                    "manifest": {"bytes": len(data), "sha256": sha256(data)},
                }
            ],
        }

    def test_platform_aliases_are_canonicalized(self) -> None:
        self.assertEqual(normalized_runtime_platform("darwin", "aarch64"), ("darwin", "arm64"))
        self.assertEqual(normalized_runtime_platform("win32", "AMD64"), ("windows", "x86_64"))
        self.assertEqual(normalized_runtime_platform("linux", "x86_64"), ("linux", "x86_64"))

    def test_matching_runtime_is_selected_only_beside_resource_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            bundled_root = Path(temporary) / "bundle" / ".qazmorph"
            resource = bundled_root / "resources"
            resource.mkdir(parents=True)
            runtime, data, bundle_id = self.write_runtime(bundled_root)
            selected = resolve_platform_runtime(
                resource,
                RESOURCE_ID,
                lock=self.lock(data, bundle_id=bundle_id),
                platform=("darwin", "arm64"),
            )

            self.assertIsNotNone(selected)
            assert selected is not None
            self.assertEqual(selected.directory, runtime.resolve())
            self.assertEqual(selected.origin, "platform-runtime-lock")
            self.assertEqual(selected.binding["bundle_id"], bundle_id)

    def test_unlocked_platform_or_resource_falls_back_to_resource_binding(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            resource = root / "resources"
            resource.mkdir()
            _runtime, data, bundle_id = self.write_runtime(root)
            lock = self.lock(data, bundle_id=bundle_id)

            self.assertIsNone(
                resolve_platform_runtime(
                    resource,
                    RESOURCE_ID,
                    lock=lock,
                    platform=("linux", "x86_64"),
                )
            )
            self.assertIsNone(
                resolve_platform_runtime(
                    resource,
                "c" * 64,
                    lock=lock,
                    platform=("darwin", "arm64"),
                )
            )

    def test_matching_lock_fails_closed_when_manifest_is_missing_or_tampered(self) -> None:
        for mutation in ("missing", "tampered"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                resource = root / "resources"
                resource.mkdir()
                runtime, data, bundle_id = self.write_runtime(root)
                lock = self.lock(data, bundle_id=bundle_id)
                if mutation == "missing":
                    (runtime / "manifest.json").unlink()
                else:
                    (runtime / "manifest.json").write_bytes(data + b" ")
                with self.assertRaisesRegex(PlatformRuntimeError, "platform runtime.*unavailable"):
                    resolve_platform_runtime(
                        resource,
                        RESOURCE_ID,
                        lock=lock,
                        platform=("darwin", "arm64"),
                    )

    def test_mutable_link_cannot_escape_or_replace_locked_immutable_runtime(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            resource = root / "resources"
            resource.mkdir()
            runtime, data, bundle_id = self.write_runtime(root)
            outside = Path(temporary).parent / "outside-runtime"
            (root / "platform-runtime").symlink_to(outside, target_is_directory=True)

            selected = resolve_platform_runtime(
                resource,
                RESOURCE_ID,
                lock=self.lock(data, bundle_id=bundle_id),
                platform=("darwin", "arm64"),
            )
            assert selected is not None
            self.assertEqual(selected.directory, runtime.resolve())

    def test_manifest_bundle_identity_must_match_the_lock(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            resource = root / "resources"
            resource.mkdir()
            locked_id = "e" * 64
            _runtime, data, _bundle_id = self.write_runtime(
                root, directory_bundle_id=locked_id
            )
            lock = self.lock(data, bundle_id=locked_id)
            with self.assertRaisesRegex(PlatformRuntimeError, "platform runtime.*unavailable"):
                resolve_platform_runtime(
                    resource,
                    RESOURCE_ID,
                    lock=lock,
                    platform=("darwin", "arm64"),
                )

    def test_checked_in_lock_has_strict_schema(self) -> None:
        lock = load_platform_runtime_lock()
        self.assertEqual(lock["schema"], PLATFORM_RUNTIME_LOCK_SCHEMA)
        self.assertTrue(lock["runtimes"])
        resource_ids = {
            (
                entry["platform"]["system"],
                entry["platform"]["machine"],
            ): entry["resource_bundle_ids"]
            for entry in lock["runtimes"]
        }
        self.assertEqual(
            resource_ids[("linux", "x86_64")],
            [BF1F_RESOURCE_ID, F03E_RESOURCE_ID],
        )
        self.assertEqual(
            resource_ids[("darwin", "arm64")], [F03E_RESOURCE_ID]
        )
        self.assertEqual(
            resource_ids[("windows", "x86_64")], [F03E_RESOURCE_ID]
        )

    def test_checked_in_lock_rejects_noncanonical_line_endings(self) -> None:
        source = (
            Path(__file__).resolve().parents[1]
            / "src/qazmorph/platform_runtime_assets.lock.json"
        )
        payload = source.read_bytes()
        for mutation in (
            payload.replace(b"\n", b"\r\n"),
            payload.removesuffix(b"\n"),
            payload + b"\n",
            payload.removesuffix(b"\n") + b" \n",
        ):
            with self.subTest(
                bytes=len(mutation)
            ), tempfile.TemporaryDirectory() as temporary:
                selected = Path(temporary) / "platform_runtime_assets.lock.json"
                selected.write_bytes(mutation)
                with self.assertRaisesRegex(PlatformRuntimeError, "LF-only lines"):
                    load_platform_runtime_lock(selected)


if __name__ == "__main__":
    unittest.main()
