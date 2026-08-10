from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import struct
import stat
import tempfile
import unittest
from unittest import mock
import zipfile


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


def load_file(path: Path, module_name: str):
    specification = importlib.util.spec_from_file_location(module_name, path)
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


windows_runtime = load_file(
    PROJECT_ROOT / "packaging" / "windows" / "build_runtime.py",
    "test_windows_build_runtime",
)
windows_evidence = load_file(
    PROJECT_ROOT / "packaging" / "windows" / "audit_evidence_paths.py",
    "test_windows_evidence_paths",
)
windows_probe = load_file(
    PROJECT_ROOT / "packaging" / "windows" / "probe_hfst_bounds.py",
    "test_windows_probe_hfst_bounds",
)
linux_runtime = load_file(
    PROJECT_ROOT / "packaging" / "linux" / "build_minimal_runtime.py",
    "test_linux_build_runtime",
)


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
    @staticmethod
    def write_minimal_pe(
        path: Path, imports: list[str], *, machine: int = 0x8664
    ) -> None:
        pe_offset = 0x80
        optional_size = 0xF0
        raw_offset = 0x200
        virtual_address = 0x1000
        data = bytearray(raw_offset + 0x1000)
        data[:2] = b"MZ"
        struct.pack_into("<I", data, 0x3C, pe_offset)
        data[pe_offset : pe_offset + 4] = b"PE\x00\x00"
        struct.pack_into(
            "<HHIIIHH",
            data,
            pe_offset + 4,
            machine,
            1,
            0,
            0,
            0,
            optional_size,
            0x2022,
        )
        optional = pe_offset + 24
        struct.pack_into("<H", data, optional, 0x20B)
        struct.pack_into("<Q", data, optional + 24, 0x140000000)
        struct.pack_into("<I", data, optional + 108, 16)
        descriptor_bytes = (len(imports) + 1) * 20
        if imports:
            struct.pack_into(
                "<II", data, optional + 112 + 8, virtual_address, descriptor_bytes
            )
        section = optional + optional_size
        struct.pack_into(
            "<8sIIII",
            data,
            section,
            b".rdata\x00\x00",
            0x1000,
            virtual_address,
            0x1000,
            raw_offset,
        )
        name_offset = raw_offset + descriptor_bytes
        for index, name in enumerate(imports):
            encoded = name.encode("ascii") + b"\x00"
            name_rva = virtual_address + name_offset - raw_offset
            struct.pack_into(
                "<IIIII",
                data,
                raw_offset + index * 20,
                0,
                0,
                0,
                name_rva,
                0,
            )
            data[name_offset : name_offset + len(encoded)] = encoded
            name_offset += len(encoded)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)

    @staticmethod
    def pe_lock() -> dict[str, object]:
        return {
            "required_commands": [
                {
                    "name": "tool",
                    "path": "usr/bin/tool.exe",
                    "version_args": ["--version"],
                }
            ],
            "dependency_policy": {
                "format": "pe-import-closure-v1",
                "allowed_system_libraries": ["kernel32.dll"],
            },
        }

    def test_legacy_macos_runtime_version_label_remains_byte_compatible(self) -> None:
        self.assertEqual(
            platform_runtime.runtime_version_label(
                {
                    "platform": {
                        "system": "darwin",
                        "machine": "arm64",
                        "minimum_os": "14.0",
                    }
                }
            ),
            "macos-arm64-hfst3.17.2-cg3-1.6.8",
        )

    def test_new_platform_runtime_version_label_is_explicit(self) -> None:
        lock = {
            "platform": {
                "system": "windows",
                "machine": "x86_64",
                "minimum_os": "10.0.20348",
            },
            "runtime_version_label": "windows-x86_64-hfst3.17.2-cg3-1.6.8",
        }
        self.assertEqual(
            platform_runtime.runtime_version_label(lock),
            lock["runtime_version_label"],
        )
        lock.pop("runtime_version_label")
        with self.assertRaisesRegex(
            platform_runtime.ManifestError, "requires runtime_version_label"
        ):
            platform_runtime.runtime_version_label(lock)

    def test_source_lock_paths_are_portable_and_drive_relative_paths_are_rejected(self) -> None:
        for value in (
            "../escape.exe",
            "usr\\bin\\tool.exe",
            "C:/tool.exe",
            "C:tool.exe",
            "/absolute/tool.exe",
            "usr/./bin/tool.exe",
        ):
            with self.subTest(value=value):
                self.assertIsNone(platform_runtime.safe_relative_path(value))
        self.assertEqual(
            platform_runtime.safe_relative_path("usr/bin/hfst-proc.exe"),
            "usr/bin/hfst-proc.exe",
        )

    def test_pe_dependency_audit_proves_exact_reachable_x86_64_closure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            tool = root / "usr/bin/tool.exe"
            dependency = root / "usr/bin/dep.dll"
            self.write_minimal_pe(tool, ["DEP.DLL", "KERNEL32.dll"])
            self.write_minimal_pe(dependency, ["kernel32.dll"])
            files = {
                "usr/bin/tool.exe": {},
                "usr/bin/dep.dll": {},
            }

            observed = platform_runtime.audit_pe_dependency_closure(
                root, self.pe_lock(), files
            )

            assert observed is not None
            self.assertEqual(observed["machine"], "x86_64")
            self.assertEqual(observed["system_libraries"], ["kernel32.dll"])
            self.assertEqual(
                observed["files"]["usr/bin/tool.exe"]["bundled_dependencies"],
                ["usr/bin/dep.dll"],
            )

    def test_pe_dependency_audit_rejects_missing_unreachable_and_wrong_machine_files(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            tool = root / "usr/bin/tool.exe"
            self.write_minimal_pe(tool, ["missing.dll"])
            with self.assertRaisesRegex(
                platform_runtime.ManifestError, "neither bundled nor allowlisted"
            ):
                platform_runtime.audit_pe_dependency_closure(
                    root, self.pe_lock(), {"usr/bin/tool.exe": {}}
                )

            self.write_minimal_pe(tool, ["kernel32.dll"])
            self.write_minimal_pe(root / "usr/bin/unused.dll", [])
            with self.assertRaisesRegex(
                platform_runtime.ManifestError, "unreachable files"
            ):
                platform_runtime.audit_pe_dependency_closure(
                    root,
                    self.pe_lock(),
                    {"usr/bin/tool.exe": {}, "usr/bin/unused.dll": {}},
                )

            self.write_minimal_pe(tool, [], machine=0x014C)
            with self.assertRaisesRegex(
                platform_runtime.ManifestError, "non-x86_64"
            ):
                platform_runtime.audit_pe_dependency_closure(
                    root, self.pe_lock(), {"usr/bin/tool.exe": {}}
                )

    def test_checked_in_windows_source_lock_is_exact_and_contains_no_openssl(self) -> None:
        path = (
            PROJECT_ROOT
            / "scripts"
            / "platform_runtime_sources.windows-x86_64.lock.json"
        )
        lock = platform_runtime.load_source_lock(path)
        self.assertEqual(
            lock["platform"],
            {
                "system": "windows",
                "machine": "x86_64",
                "minimum_os": "10.0.20348",
            },
        )
        self.assertEqual(
            {record["sha256"] for record in lock["archives"]},
            {
                "a28df94fd80d3d6fe2401f5d71c31b96fad7c01c973e2b26c539ce1016e4542e",
                "6df5801f2dfec584822b68ade4f3d25618cdfdad6cb0a1fb3704364c9a10c45b",
            },
        )
        self.assertEqual(
            {record["name"] for record in lock["required_commands"]},
            {"hfst-proc", "hfst-optimized-lookup", "cg-proc"},
        )
        self.assertNotIn("openssl", json.dumps(lock).casefold())

    def test_windows_zip_inventory_rejects_cross_platform_escapes_and_links(self) -> None:
        with self.assertRaisesRegex(
            windows_runtime.BuildError, "unsafe ZIP member path"
        ):
            windows_runtime.portable_zip_name("usr\\bin\\escape.exe")
        for member in (
            "../escape.exe",
            "C:/escape.exe",
        ):
            with self.subTest(member=member), tempfile.TemporaryDirectory() as temporary:
                archive = Path(temporary) / "unsafe.zip"
                with zipfile.ZipFile(archive, "w") as output:
                    output.writestr(member, b"payload")
                with self.assertRaisesRegex(
                    windows_runtime.BuildError, "unsafe ZIP member path"
                ):
                    windows_runtime.zip_inventory(archive)

        with tempfile.TemporaryDirectory() as temporary:
            archive = Path(temporary) / "link.zip"
            info = zipfile.ZipInfo("usr/bin/link.dll")
            info.create_system = 3
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            with zipfile.ZipFile(archive, "w") as output:
                output.writestr(info, b"outside.dll")
            with self.assertRaisesRegex(
                windows_runtime.BuildError, "unsupported ZIP member type"
            ):
                windows_runtime.zip_inventory(archive)

    def test_windows_evidence_audit_decodes_json_and_scans_plain_text(self) -> None:
        for filename, payload in (
            ("escaped.json", json.dumps({"path": r"C:\runner\temp\build-a"})),
            ("plain.txt", "candidate at C:/runner/temp/build-b\n"),
        ):
            with self.subTest(filename=filename), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / "evidence"
                root.mkdir()
                (root / filename).write_text(payload, encoding="utf-8")
                with mock.patch(
                    "sys.argv",
                    [
                        "audit_evidence_paths.py",
                        "--root",
                        str(root),
                        "--forbid",
                        r"C:\runner\temp",
                        "--output",
                        str(root / "audit.json"),
                    ],
                ), self.assertRaisesRegex(
                    windows_evidence.EvidenceError, "absolute build roots leaked"
                ):
                    windows_evidence.main()

    def test_windows_evidence_audit_accepts_logical_labels_and_skips_its_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "evidence"
            root.mkdir()
            (root / "record.json").write_text(
                json.dumps({"build_roots": ["build-a", "build-b"]}), encoding="utf-8"
            )
            (root / "record.txt").write_text("bundle/platform-runtimes\n", encoding="utf-8")
            output = root / "audit.json"
            output.write_text(r"C:\runner\temp\self", encoding="utf-8")
            with mock.patch(
                "sys.argv",
                [
                    "audit_evidence_paths.py",
                    "--root",
                    str(root),
                    "--forbid",
                    r"C:\runner\temp",
                    "--output",
                    str(output),
                ],
            ):
                self.assertEqual(windows_evidence.main(), 0)
            report = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(report["result"], "pass")
            self.assertEqual(report["text_files_checked"], ["record.json", "record.txt"])

    def test_windows_evidence_audit_rejects_lexical_and_resolved_root_aliases(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            container = Path(temporary)
            physical = container / "physical-runner"
            physical.mkdir()
            alias = container / "runner-alias"
            alias.symlink_to(physical.name, target_is_directory=True)
            for leaked in (alias / "build-a", physical / "build-b"):
                with self.subTest(leaked=leaked):
                    root = container / f"evidence-{leaked.name}"
                    root.mkdir()
                    (root / "record.txt").write_text(str(leaked), encoding="utf-8")
                    with mock.patch(
                        "sys.argv",
                        [
                            "audit_evidence_paths.py",
                            "--root",
                            str(root),
                            "--forbid",
                            str(alias),
                            "--output",
                            str(root / "audit.json"),
                        ],
                    ), self.assertRaisesRegex(
                        windows_evidence.EvidenceError, "absolute build roots leaked"
                    ):
                        windows_evidence.main()

    def test_windows_evidence_audit_rejects_invalid_json_and_utf8(self) -> None:
        for filename, payload in (
            ("broken.json", b"{not-json}"),
            ("broken.txt", b"\xff"),
        ):
            with self.subTest(filename=filename), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / "evidence"
                root.mkdir()
                (root / filename).write_bytes(payload)
                with mock.patch(
                    "sys.argv",
                    [
                        "audit_evidence_paths.py",
                        "--root",
                        str(root),
                        "--forbid",
                        r"C:\runner\temp",
                        "--output",
                        str(root / "audit.json"),
                    ],
                ), self.assertRaises(windows_evidence.EvidenceError):
                    windows_evidence.main()

    def test_windows_hfst_bound_probe_has_timeout_and_semantic_control(self) -> None:
        with mock.patch.object(
            windows_probe.subprocess,
            "run",
            side_effect=windows_probe.subprocess.TimeoutExpired(["helper"], 10),
        ) as run:
            with self.assertRaisesRegex(windows_probe.ProbeError, "timed out"):
                windows_probe.run(["helper"])
            self.assertEqual(run.call_args.kwargs["timeout"], 10)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "hfst"
            for relative in (
                "hfst/bin/hfst-optimized-lookup.exe",
                "hfst/bin/hfst-lookup.exe",
                "hfst/bin/hfst-regexp2fst.exe",
                "hfst/bin/hfst-fst2fst.exe",
            ):
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"fake")
            output = Path(temporary) / "probe.json"

            def fake_run(command: list[str], *, input_bytes: bytes | None = None) -> bytes:
                executable = Path(command[0]).name
                if "--help" in command:
                    option = "--analyses" if executable.startswith("hfst-optimized") else "--max-number"
                    return f"-n {option} --pipe-mode\n".encode()
                if "--version" in command:
                    self.assertIn("--pipe-mode=both", command)
                    return b"HFST 3.17.2\n"
                if executable in {"hfst-regexp2fst.exe", "hfst-fst2fst.exe"}:
                    destination = Path(command[command.index("-o") + 1])
                    destination.write_bytes(b"fake-fst")
                    return b""
                self.assertEqual(input_bytes, b"a\n")
                if "-n" in command:
                    return b"a\tb\t0.0\n\n"
                return b"a\tb\t0.0\na\tc\t0.0\n\n"

            with mock.patch.object(windows_probe, "run", side_effect=fake_run), mock.patch(
                "sys.argv",
                [
                    "probe_hfst_bounds.py",
                    "--root",
                    str(root),
                    "--output",
                    str(output),
                ],
            ):
                self.assertEqual(windows_probe.main(), 0)
            report = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(report["semantic_query"]["status"], "pass")
            self.assertEqual(report["semantic_query"]["control_nonempty_rows"], 2)
            self.assertEqual(report["semantic_query"]["bounded_nonempty_rows"], 1)

    def test_windows_builder_reports_x_ok_without_using_it_as_the_gate(self) -> None:
        builder = (
            PROJECT_ROOT / "packaging" / "windows" / "build_runtime.py"
        ).read_text(encoding="utf-8")
        self.assertIn('"os_access_x_ok": executable_access[name]', builder)
        self.assertIn(
            '"regular-exe-manifest-hash-successful-version-execution"',
            builder,
        )
        self.assertNotIn("if not all(executable_access.values())", builder)
        manifest_writer = (
            PROJECT_ROOT / "scripts" / "write_platform_runtime_manifest.py"
        ).read_text(encoding="utf-8")
        self.assertNotIn('command_record["os_access_x_ok"]', manifest_writer)

    def test_checked_in_linux_recipe_reproduces_the_locked_runtime_identity(self) -> None:
        lock_path = (
            PROJECT_ROOT
            / "scripts"
            / "platform_runtime_sources.linux-x86_64.lock.json"
        )
        self.assertEqual(
            platform_runtime.sha256(lock_path),
            "bededc4a7522fb610c9c1ea87b3b44b31e1abd85cd160beea6262c3407857581",
        )
        linux_spec = (
            PROJECT_ROOT / "packaging" / "linux" / "kazstem-minimal.spec"
        ).read_text(encoding="utf-8")
        self.assertNotIn("KAZSTEM_LINUX_RUNTIME_LOCK", linux_spec)
        self.assertIn('collect_data_files("qazmorph")', linux_spec)
        runtime_lock = json.loads(
            (
                PROJECT_ROOT
                / "src"
                / "qazmorph"
                / "platform_runtime_assets.lock.json"
            ).read_text(encoding="utf-8")
        )
        entries = {
            (entry["platform"]["system"], entry["platform"]["machine"]): entry
            for entry in runtime_lock["runtimes"]
        }
        self.assertEqual(
            entries[("linux", "x86_64")]["bundle_id"],
            "39a01ea673d024b0d6080739b5bb23c76daf0f7ed7bdb95dd1157d9dce4b627e",
        )
        manifest_include = (PROJECT_ROOT / "MANIFEST.in").read_text(
            encoding="utf-8"
        )
        self.assertIn("recursive-include packaging *.json *.md *.py *.spec", manifest_include)
        linux_builder = (
            PROJECT_ROOT / "packaging" / "linux" / "build_minimal_runtime.py"
        ).read_text(encoding="utf-8")
        self.assertIn("runtimes.sort(key=runtime_sort_key)", linux_builder)
        entries = [
            {"platform": {"system": "windows", "machine": "x86_64"}},
            {"platform": {"system": "darwin", "machine": "arm64"}},
            {"platform": {"system": "linux", "machine": "x86_64"}},
        ]
        self.assertEqual(
            [
                linux_runtime.runtime_sort_key(entry)
                for entry in sorted(entries, key=linux_runtime.runtime_sort_key)
            ],
            [("darwin", "arm64"), ("linux", "x86_64"), ("windows", "x86_64")],
        )
        practical = (
            PROJECT_ROOT / "packaging" / "linux" / "practical_matrix_linux.py"
        ).read_text(encoding="utf-8")
        self.assertNotIn("write_bytes(\n            (self.root / \"_internal/qazmorph/platform_runtime_assets.lock.json\")", practical)
        self.assertIn("wheel_lock.read_bytes() == frozen_lock.read_bytes()", practical)
        self.assertIn('"NO_PROXY": ""', practical)
        self.assertIn('not key.upper().endswith("_PROXY")', practical)
        elf_audit = (
            PROJECT_ROOT / "packaging" / "linux" / "audit_elf_closure.py"
        ).read_text(encoding="utf-8")
        self.assertIn('"root": root.name', elf_audit)
        self.assertNotIn('"root": str(root)', elf_audit)

        for recipe in (
            "audit_elf_closure.py",
            "blackbox_linux_bundle.py",
            "build_minimal_runtime.py",
            "practical_matrix_linux.py",
        ):
            with self.subTest(recipe=recipe):
                text = (PROJECT_ROOT / "packaging" / "linux" / recipe).read_text(
                    encoding="utf-8"
                )
                self.assertNotIn("0.2.2", text)
                self.assertNotIn("3e5a7ed86af98d06bfaee222a00f0c612fdba88c", text)
                if recipe in {"blackbox_linux_bundle.py", "practical_matrix_linux.py"}:
                    self.assertIn("if not __debug__:", text)

        companion_template = (
            PROJECT_ROOT
            / "packaging"
            / "linux"
            / "CORRESPONDING-SOURCE-README.template.md"
        ).read_text(encoding="utf-8")
        for placeholder in (
            "@VERSION@",
            "@BINARY_ARCHIVE@",
            "@SOURCE_COMMIT@",
            "@WHEEL_SHA256@",
            "@SDIST_SHA256@",
            "@RESOURCE_BUNDLE_ID@",
            "@RUNTIME_BUNDLE_ID@",
        ):
            self.assertIn(placeholder, companion_template)

    def test_windows_inventory_workflow_is_safe_on_a_draft_pull_request(self) -> None:
        workflow = (
            PROJECT_ROOT
            / ".github"
            / "workflows"
            / "windows-runtime-inventory.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("  pull_request:\n", workflow)
        self.assertIn("runs-on: windows-2022", workflow)
        self.assertIn("contents: read", workflow)
        self.assertNotIn("contents: write", workflow)
        self.assertNotIn("pull_request_target", workflow)
        self.assertNotIn("actions/checkout@v", workflow)
        self.assertIn("bounded-helper-options.json", workflow)
        self.assertIn("probe_hfst_bounds.py", workflow)
        self.assertIn("audit_evidence_paths.py", workflow)
        self.assertIn(
            "test_windows_hard_stdout_cap_never_caches_partial_candidates",
            workflow,
        )
        self.assertEqual(
            workflow.count("if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }"),
            workflow.count("\n          python "),
        )

    def test_unpublished_0_2_2_changelog_is_folded_into_0_2_3(self) -> None:
        changelog = (PROJECT_ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        self.assertNotIn("## 0.2.2", changelog)
        self.assertIn("private, unpublished 0.2.2", changelog)

    def test_macos_frozen_recipe_excludes_unused_generic_stacks(self) -> None:
        spec = (PROJECT_ROOT / "packaging/macos/kazstem-minimal.spec").read_text(
            encoding="utf-8"
        )
        for module in (
            "ssl",
            "_ssl",
            "socket",
            "urllib",
            "email",
            "asyncio",
            "multiprocessing",
            "sqlite3",
            "tkinter",
            "xml",
            "_hashlib",
            "unittest",
            "distutils",
            "setuptools",
            "pip",
        ):
            with self.subTest(module=module):
                self.assertIn(json.dumps(module), spec)
        self.assertIn('entry[0] != "pyi_rth_inspect"', spec)
        self.assertNotIn(json.dumps("_sha2"), spec)

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
        transitive = {
            record["component"]: record["sha256"]
            for record in lock["corresponding_sources"]
        }
        self.assertEqual(
            {name: transitive[name] for name in ("ICU", "ncurses", "SQLite", "zlib")},
            {
                "ICU": "3a2e7a47604ba702f345878308e6fefeca612ee895cf4a5f222e7955fabfe0c0",
                "ncurses": "4c8e657b439659396c2935d70a9259220097c4a3b5d520fa3409ef5e1f9caae2",
                "SQLite": "81f5be397049b0cae1b167f2225af7646fc0f82e4a9b3c48c9ea3a533e21d77a",
                "zlib": "bb329a0a2cd0274d05519d61c667c062e06990d72e125ee2dfa8de64f0119d16",
            },
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

    def test_runtime_inventory_canonicalizes_a_symlinked_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            container = Path(temporary)
            physical_root = container / "physical-runtime"
            physical_root.mkdir()
            alias_root = container / "runtime-alias"
            alias_root.symlink_to(physical_root.name, target_is_directory=True)
            target = physical_root / "usr" / "bin" / "actual"
            target.parent.mkdir(parents=True)
            target.write_bytes(b"runtime")
            (target.parent / "alias").symlink_to("actual")

            inventory = platform_runtime.extracted_files(
                alias_root, output=alias_root / "manifest.json"
            )

            self.assertEqual(inventory["usr/bin/alias"]["target"], "actual")
            self.assertEqual(inventory["usr/bin/actual"]["bytes"], 7)

    def test_posix_command_symlink_is_preserved_but_windows_rejects_it(self) -> None:
        def fixture(root: Path, *, system: str) -> tuple[dict[str, object], Path, Path, Path, Path]:
            runtime = root / "runtime"
            binary = runtime / "usr" / "bin"
            binary.mkdir(parents=True)
            suffix = ".exe" if system == "windows" else ""
            target = binary / f"tool-real{suffix}"
            target.write_text("#!/bin/sh\nprintf 'tool 1\\n'\n", encoding="utf-8")
            target.chmod(0o755)
            command = binary / f"tool{suffix}"
            command.symlink_to(target.name)
            archives = root / "archives"
            sources = root / "sources"
            archives.mkdir()
            sources.mkdir()
            archive = archives / "tool.zip"
            source = sources / "tool-source.tar.gz"
            archive.write_bytes(b"archive")
            source.write_bytes(b"source")
            lock_path = root / "source-lock.json"
            lock_path.write_text("{}\n", encoding="utf-8")
            lock: dict[str, object] = {
                "schema": platform_runtime.LOCK_SCHEMA,
                "distribution": "fixture",
                "platform": {
                    "system": system,
                    "machine": "x86_64",
                    "minimum_os": "fixture",
                },
                "runtime_version_label": f"{system}-fixture",
                "required_commands": [
                    {
                        "name": "tool",
                        "path": f"usr/bin/tool{suffix}",
                        "version_args": ["--version"],
                    }
                ],
                "archives": [
                    {
                        "component": "tool",
                        "filename": archive.name,
                        "url": "https://example.invalid/tool.zip",
                        **platform_runtime.file_record(archive),
                    }
                ],
                "corresponding_sources": [
                    {
                        "component": "tool",
                        "revision": "fixture",
                        "filename": source.name,
                        "url": "https://example.invalid/tool-source.tar.gz",
                        **platform_runtime.file_record(source),
                    }
                ],
                "components": [
                    {"name": "tool", "version": "1", "license": "fixture"}
                ],
            }
            return lock, runtime, archives, sources, lock_path

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            lock, runtime, archives, sources, lock_path = fixture(
                root, system="linux"
            )
            manifest = platform_runtime.build_manifest(
                runtime,
                archives,
                sources,
                runtime / "manifest.json",
                lock,
                lock_path,
            )
            self.assertEqual(
                manifest["files"]["usr/bin/tool"]["target"], "tool-real"
            )
            self.assertEqual(
                manifest["commands"]["tool"]["sha256"],
                platform_runtime.sha256(runtime / "usr/bin/tool-real"),
            )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            lock, runtime, archives, sources, lock_path = fixture(
                root, system="windows"
            )
            with self.assertRaisesRegex(
                platform_runtime.ManifestError, "required runtime executable"
            ):
                platform_runtime.build_manifest(
                    runtime,
                    archives,
                    sources,
                    runtime / "manifest.json",
                    lock,
                    lock_path,
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
