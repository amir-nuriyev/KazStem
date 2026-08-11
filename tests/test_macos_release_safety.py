from __future__ import annotations

import argparse
import copy
import gzip
import io
import json
import lzma
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock
import unicodedata
import zipfile


PROJECT_ROOT = Path(__file__).resolve().parents[1]
MACOS_TOOLS = PROJECT_ROOT / "packaging" / "macos"
sys.path.insert(0, str(MACOS_TOOLS))

import audit_macho_closure as macho  # noqa: E402
import compare_compression as compression  # noqa: E402
import prepare_bf1f_validation as bf1f  # noqa: E402
import release_common as common  # noqa: E402
import verify_python_reproducibility as reproduction  # noqa: E402


def raw_tar_member(
    name: str,
    data: bytes,
    *,
    typeflag: bytes = tarfile.REGTYPE,
    linkname: str = "",
    mode: int = 0o444,
) -> bytes:
    info = tarfile.TarInfo(name)
    info.type = typeflag
    info.linkname = linkname
    info.mode = mode
    info.size = len(data)
    header = info.tobuf(format=tarfile.USTAR_FORMAT)
    return header + data + b"\0" * ((-len(data)) % common.TAR_BLOCK_BYTES)


def raw_tar(*members: bytes) -> bytes:
    return b"".join(members) + b"\0" * (2 * common.TAR_BLOCK_BYTES)


def pax_record(key: str, value: str) -> bytes:
    payload = f"{key}={value}\n".encode("utf-8")
    length = len(payload) + 2
    while True:
        encoded = f"{length} ".encode("ascii") + payload
        if len(encoded) == length:
            return encoded
        length = len(encoded)


class MacOSReleaseSafetyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.limits = common.ArchiveLimits(
            max_members=16,
            max_file_bytes=4096,
            max_total_bytes=16 * 1024,
            max_path_bytes=128,
        )

    def test_darwin_loader_provenance_requires_exact_clean_v2_schema(self) -> None:
        clean_record = {
            "ambient_present": False,
            "removed_from_helper_environment": True,
            "sha256": None,
        }
        environment: dict[str, object] = {
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": {
                "ambient_present": False,
                "ambient_untrusted": False,
                "removed_from_helper_environment": False,
            },
            common.GLIBC_TUNABLES_VARIABLE: copy.deepcopy(clean_record),
            "loader_policy": {
                "schema": common.LOADER_POLICY_SCHEMA,
                "captured_name_policy": {
                    "exact_uppercase_prefixes": list(
                        common.LOADER_OVERRIDE_PREFIXES
                    ),
                    "exact_names": [common.GLIBC_TUNABLES_VARIABLE],
                },
                "ambient_records": {},
                "glibc_tunables": copy.deepcopy(clean_record),
                "clean_parent_startup": True,
                "all_ambient_values_removed_from_helper_environment": True,
                "linux_helper_ld_library_path": None,
            },
        }
        for name in common.LOADER_OVERRIDE_VARIABLES:
            environment[name] = copy.deepcopy(clean_record)
        provenance = {"environment": environment}
        summary = common.verify_darwin_loader_provenance(provenance)
        self.assertEqual(summary["captured_ambient_names"], [])
        self.assertEqual(
            summary["legacy_loader_records"],
            len(common.LOADER_OVERRIDE_VARIABLES),
        )

        hostile_mutations = []
        ambient = copy.deepcopy(provenance)
        ambient["environment"]["DYLD_INSERT_LIBRARIES"] = {
            "ambient_present": True,
            "removed_from_helper_environment": True,
            "sha256": "a" * 64,
        }
        hostile_mutations.append(ambient)
        unknown = copy.deepcopy(provenance)
        unknown["environment"]["loader_policy"]["ambient_records"] = {
            "DYLD_FUTURE_INJECTOR": {
                "ambient_present": True,
                "removed_from_helper_environment": True,
                "sha256": "b" * 64,
            }
        }
        hostile_mutations.append(unknown)
        linux_helper = copy.deepcopy(provenance)
        linux_helper["environment"]["loader_policy"][
            "linux_helper_ld_library_path"
        ] = {"source": "manifest-bound-runtime", "relative_paths": ["usr/lib"]}
        hostile_mutations.append(linux_helper)
        missing = copy.deepcopy(provenance)
        del missing["environment"]["DYLD_ROOT_PATH"]
        hostile_mutations.append(missing)
        windows_path = copy.deepcopy(provenance)
        windows_path["environment"]["PATH"][
            "removed_from_helper_environment"
        ] = True
        hostile_mutations.append(windows_path)
        for mutation in hostile_mutations:
            with self.subTest(mutation=mutation):
                with self.assertRaises(common.ReleaseError):
                    common.verify_darwin_loader_provenance(mutation)

    def test_bf1f_preparation_emits_external_candidate_without_enabling_it(self) -> None:
        source_lock = PROJECT_ROOT / bf1f.PLATFORM_LOCK_PATH
        before = common.file_record(source_lock)
        with tempfile.TemporaryDirectory(prefix="kazstem-bf1f-preparation-") as temp:
            root = Path(temp)
            candidate_lock = root / "candidate-lock.json"
            receipt_path = root / "receipt.json"
            receipt = bf1f.prepare(
                argparse.Namespace(
                    repository=PROJECT_ROOT,
                    matrix=PROJECT_ROOT / bf1f.MATRIX_PATH,
                    platform_lock=source_lock,
                    candidate_lock_output=candidate_lock,
                    output=receipt_path,
                )
            )
            self.assertFalse(receipt["release_enabled"])
            self.assertFalse(receipt["native_validation_complete"])
            candidate = common.read_json(candidate_lock)
            darwin = next(
                record
                for record in candidate["runtimes"]
                if record["platform"]
                == {"system": "darwin", "machine": "arm64"}
            )
            self.assertEqual(darwin["bundle_id"], bf1f.DARWIN_RUNTIME_ID)
            self.assertEqual(darwin["manifest"], bf1f.DARWIN_RUNTIME_MANIFEST)
            self.assertEqual(darwin["resource_bundle_ids"], [bf1f.BF1F_RESOURCE_ID])
            self.assertEqual(common.file_record(source_lock), before)

        matrix = copy.deepcopy(
            common.read_json(PROJECT_ROOT / bf1f.MATRIX_PATH)
        )
        matrix["activation"]["automatic"] = True
        with self.assertRaises(common.ReleaseError):
            bf1f._validate_matrix(matrix)

    def test_portable_paths_reject_cross_platform_hostile_names(self) -> None:
        hostile = (
            "/tmp/escape",
            "../escape",
            "C:/Windows/system32",
            "C:\\Windows\\system32",
            "\\\\server\\share",
            "\\\\?\\C:\\device",
            "folder/file:stream",
            "folder/CON.txt",
            "folder/trailing.",
            "folder/trailing ",
            "folder\\backslash",
            unicodedata.normalize("NFD", "қазақ/café.txt"),
        )
        for value in hostile:
            with self.subTest(value=value), self.assertRaises(common.ReleaseError):
                common.portable_path(value, label="hostile")
        self.assertEqual(
            common.portable_path("қазақ/ә.txt", label="valid"), "қазақ/ә.txt"
        )

    def test_evidence_scanner_checks_keys_values_and_text(self) -> None:
        allowed = {
            "url": "https://github.com/amir-nuriyev/KazStem/releases/tag/v0.2.3",
            "system": [
                "/usr/lib/libSystem.B.dylib",
                "/System/Library/Frameworks/CoreFoundation.framework",
            ],
        }
        common.assert_relative_json(allowed)
        hostile = (
            {"path": "/private/tmp/build"},
            {"C:/root": "value"},
            {"path": "file:///tmp/leak"},
            {"path": "\\\\server\\share"},
        )
        for value in hostile:
            with (
                self.subTest(value=value),
                self.assertRaisesRegex(common.ReleaseError, "absolute path"),
            ):
                common.assert_relative_json(value)

    def test_tar_caps_cover_raw_expansion_extensions_headers_and_padding(self) -> None:
        limits = common.ArchiveLimits(1, 1024, 1024, 64)
        raw_cap, expanded_cap, _header_cap, extension_cap = common._tar_stream_caps(
            limits
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            raw_bomb = root / "raw"
            raw_bomb.write_bytes(b"\0" * (raw_cap + 1))
            with self.assertRaisesRegex(common.ReleaseError, "raw tar stream"):
                common.inspect_tar(raw_bomb, limits=limits)

            expanded_bomb = root / "expanded"
            expanded_bomb.write_bytes(gzip.compress(b"\0" * (expanded_cap + 1)))
            with self.assertRaisesRegex(common.ReleaseError, "expanded tar stream"):
                common.inspect_tar(expanded_bomb, limits=limits)

            metadata_bomb = root / "metadata"
            metadata_bomb.write_bytes(
                raw_tar(
                    raw_tar_member(
                        "PaxHeader",
                        b"x" * (extension_cap + 1),
                        typeflag=tarfile.XHDTYPE,
                    )
                )
            )
            with self.assertRaisesRegex(common.ReleaseError, "extension metadata"):
                common.inspect_tar(metadata_bomb, limits=limits)

            many_extensions = root / "many-extensions"
            record = pax_record("comment", "bounded")
            many_extensions.write_bytes(
                raw_tar(
                    *(
                        raw_tar_member(
                            f"PaxHeader{index}", record, typeflag=tarfile.XGLTYPE
                        )
                        for index in range(11)
                    )
                )
            )
            with self.assertRaisesRegex(common.ReleaseError, "extension record count"):
                common.inspect_tar(many_extensions, limits=limits)

            bad_padding = root / "padding"
            member = bytearray(raw_tar_member("root/file", b"x"))
            member[-1] = 1
            bad_padding.write_bytes(raw_tar(bytes(member)))
            with self.assertRaisesRegex(
                common.ReleaseError, "non-zero tar member padding"
            ):
                common.inspect_tar(bad_padding, limits=limits)

    def test_tar_rejects_nonfile_bodies_pax_overrides_and_truncation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            symlink_body = root / "symlink-body.tar"
            symlink_body.write_bytes(
                raw_tar(
                    raw_tar_member(
                        "root/link",
                        b"x",
                        typeflag=tarfile.SYMTYPE,
                        linkname="target",
                    )
                )
            )
            with self.assertRaisesRegex(common.ReleaseError, "non-file tar member"):
                common.inspect_tar(symlink_body, limits=self.limits)

            pax_size = root / "pax-size.tar"
            pax_size.write_bytes(
                raw_tar(
                    raw_tar_member(
                        "PaxHeader",
                        pax_record("size", "1"),
                        typeflag=tarfile.XHDTYPE,
                    ),
                    raw_tar_member("root/file", b"x"),
                )
            )
            with self.assertRaisesRegex(common.ReleaseError, "size overrides"):
                common.inspect_tar(pax_size, limits=self.limits)

            truncated = root / "truncated.tar"
            full = raw_tar(raw_tar_member("root/file", b"content"))
            truncated.write_bytes(full[: -common.TAR_BLOCK_BYTES])
            with self.assertRaisesRegex(common.ReleaseError, "end marker"):
                common.inspect_tar(truncated, limits=self.limits)

    def test_tar_rejects_path_collisions_and_unsafe_links(self) -> None:
        cases = {
            "case-prefix": raw_tar(
                raw_tar_member("root/A/one", b"1"),
                raw_tar_member("root/a/two", b"2"),
            ),
            "file-parent": raw_tar(
                raw_tar_member("root/parent", b"file"),
                raw_tar_member("root/parent/child", b"child"),
            ),
            "symlink-parent": raw_tar(
                raw_tar_member(
                    "root/link", b"", typeflag=tarfile.SYMTYPE, linkname="target"
                ),
                raw_tar_member("root/link/child", b"child"),
            ),
            "escape": raw_tar(raw_tar_member("root/../../escape", b"x")),
            "absolute": raw_tar(raw_tar_member("/root/file", b"x")),
            "hardlink": raw_tar(
                raw_tar_member(
                    "root/link", b"", typeflag=tarfile.LNKTYPE, linkname="root/file"
                )
            ),
            "fifo": raw_tar(
                raw_tar_member("root/fifo", b"", typeflag=tarfile.FIFOTYPE)
            ),
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name, data in cases.items():
                with self.subTest(name=name):
                    archive = root / name
                    archive.write_bytes(data)
                    with self.assertRaises(common.ReleaseError):
                        common.inspect_tar(archive, limits=self.limits)

    def test_symlink_extraction_is_order_independent_and_revalidated(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "chain.tar"
            archive.write_bytes(
                raw_tar(
                    raw_tar_member(
                        "root/a", b"", typeflag=tarfile.SYMTYPE, linkname="b"
                    ),
                    raw_tar_member(
                        "root/b", b"", typeflag=tarfile.SYMTYPE, linkname="target"
                    ),
                    raw_tar_member("root/target", b"resolved"),
                )
            )
            members = common.inspect_tar(
                archive, limits=self.limits, expected_top="root"
            )
            extracted = common.extract_validated_tar(
                archive, root / "fresh", members=members, limits=self.limits
            )
            self.assertEqual((extracted / "a").read_bytes(), b"resolved")
            self.assertEqual((extracted / "b").read_bytes(), b"resolved")

    def test_exact_normalized_modes_bind_executable_inventory(self) -> None:
        members = [
            common.ArchiveMember("root", "directory", 0, 0o555),
            common.ArchiveMember("root/data", "file", 1, 0o444),
            common.ArchiveMember("root/tool", "file", 1, 0o555),
            common.ArchiveMember("root/link", "symlink", 0, 0o777, "tool"),
        ]
        common.verify_sealed_archive_modes(members, executable_paths={"root/tool"})
        with self.assertRaisesRegex(common.ReleaseError, "exactly normalized"):
            common.verify_sealed_archive_modes(members, executable_paths={"root/data"})
        with self.assertRaisesRegex(common.ReleaseError, "names non-files"):
            common.verify_sealed_archive_modes(
                members, executable_paths={"root/missing"}
            )

    def test_magic_inventory_is_suffix_independent_and_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            tar_gzip = root / "opaque.bin"
            with tarfile.open(tar_gzip, "w:gz") as archive:
                info = tarfile.TarInfo("source/file")
                info.size = 6
                archive.addfile(info, io.BytesIO(b"source"))
            self.assertEqual(common.detect_archive_format(tar_gzip), "tar")

            raw = io.BytesIO()
            with tarfile.open(fileobj=raw, mode="w") as archive:
                info = tarfile.TarInfo("source/xz")
                info.size = 2
                archive.addfile(info, io.BytesIO(b"xz"))
            tar_xz = root / "also-opaque"
            tar_xz.write_bytes(lzma.compress(raw.getvalue()))
            self.assertEqual(common.detect_archive_format(tar_xz), "tar")

            wheel = root / "wheel.disguised"
            with zipfile.ZipFile(wheel, "w") as archive:
                archive.writestr("package/module.py", b"pass\n")
            declared = {
                "also-opaque": "tar",
                "opaque.bin": "tar",
                "wheel.disguised": "zip",
            }
            self.assertEqual(
                common.verify_declared_archive_inventory(root, declared), declared
            )
            with self.assertRaisesRegex(common.ReleaseError, "undeclared"):
                common.verify_declared_archive_inventory(root, {})

            unsupported = root / "unsupported"
            unsupported.mkdir()
            (unsupported / "innocent.txt").write_bytes(
                b"7z\xbc\xaf\x27\x1c" + b"\0" * 32
            )
            with self.assertRaisesRegex(common.ReleaseError, "recognized unsupported"):
                common.verify_declared_archive_inventory(unsupported, {})

    def test_zip_raw_stream_trailing_bytes_and_encryption_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "safe.zip"
            with zipfile.ZipFile(archive, "w") as output:
                output.writestr("root/file", b"payload")
            details = common.inspect_zip(archive, limits=self.limits)
            self.assertEqual(details["raw_bytes"], archive.stat().st_size)

            trailing = root / "trailing.zip"
            trailing.write_bytes(archive.read_bytes() + b"unreferenced")
            with self.assertRaisesRegex(common.ReleaseError, "trailing/unreferenced"):
                common.inspect_zip(trailing, limits=self.limits)

            encrypted = root / "encrypted.zip"
            data = bytearray(archive.read_bytes())
            local = data.index(b"PK\x03\x04")
            central = data.index(b"PK\x01\x02")
            data[local + 6 : local + 8] = (1).to_bytes(2, "little")
            data[central + 8 : central + 10] = (1).to_bytes(2, "little")
            encrypted.write_bytes(data)
            with self.assertRaisesRegex(common.ReleaseError, "encrypted"):
                common.inspect_zip(encrypted, limits=self.limits)

    def test_tree_inventory_rejects_hardlinks_and_special_entries(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = root / "first"
            first.write_bytes(b"same inode")
            os.link(first, root / "second")
            with self.assertRaisesRegex(common.ReleaseError, "hard-linked"):
                common.tree_inventory(root)

            first.unlink()
            (root / "second").unlink()
            fifo = root / "fifo"
            os.mkfifo(fifo)
            with self.assertRaisesRegex(common.ReleaseError, "unsupported|special"):
                common.tree_inventory(root)

    def test_tree_inventory_allows_only_os_managed_provenance_xattr(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "file"
            path.write_bytes(b"content")
            common.tree_inventory(root)
            with mock.patch.object(
                common,
                "_list_xattrs",
                side_effect=lambda item: (
                    ["com.apple.provenance"] if Path(item) == path else []
                ),
            ):
                common.tree_inventory(root, allow_os_provenance=True)
                with self.assertRaisesRegex(
                    common.ReleaseError, "extended attributes"
                ):
                    common.tree_inventory(root, allow_os_provenance=False)
            with mock.patch.object(
                common,
                "_list_xattrs",
                side_effect=lambda item: (
                    ["com.example.fixture"] if Path(item) == path else []
                ),
            ):
                with self.assertRaisesRegex(
                    common.ReleaseError, "extended attributes"
                ):
                    common.tree_inventory(root, allow_os_provenance=True)

    def test_canonical_compression_rejects_already_compressed_input(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name, data in (
                ("gzip.tar", gzip.compress(b"not raw")),
                ("xz.tar", lzma.compress(b"not raw")),
                ("zstd.tar", b"\x28\xb5\x2f\xfd" + b"x" * 32),
            ):
                path = root / name
                path.write_bytes(data)
                with (
                    self.subTest(name=name),
                    self.assertRaisesRegex(
                        common.ReleaseError, "compressed input|uncompressed tar"
                    ),
                ):
                    compression._reject_compressed_input(path)

    def test_macho_rpath_rejects_absolute_entry_before_internal_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / "bin"
            binary.write_bytes(b"x")
            bundled = root / "lib/libdependency.dylib"
            bundled.parent.mkdir()
            bundled.write_bytes(b"x")
            with self.assertRaisesRegex(common.ReleaseError, "absolute rpath precedes"):
                macho._resolve(
                    "@rpath/libdependency.dylib",
                    path=binary,
                    root=root,
                    rpaths=["/opt/local/lib", "@loader_path/lib"],
                    runtime_parent="runtime",
                )

    def test_live_gate_context_binds_argv_environment_source_and_script(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            source = workspace / "source-tree"
            source.mkdir()
            shutil.copyfile(
                MACOS_TOOLS / "release_common.py", source / "release_common.py"
            )
            gate_script = source / "gate.py"
            gate_script.write_text(
                "from pathlib import Path\n"
                "import json\n"
                "from release_common import begin_gate_execution\n"
                "identity=json.loads(Path('identity.json').read_text())\n"
                "begin_gate_execution(identity, 'fixture', caller_file=__file__)\n"
                "print('verified')\n",
                encoding="utf-8",
            )
            subprocess.run(["git", "init", "-q"], cwd=source, check=True)
            subprocess.run(
                [
                    "git",
                    "remote",
                    "add",
                    "origin",
                    "https://github.com/example/KazStem.git",
                ],
                cwd=source,
                check=True,
            )
            subprocess.run(["git", "add", "."], cwd=source, check=True)
            commit_env = {
                **os.environ,
                "GIT_AUTHOR_NAME": "Fixture",
                "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
                "GIT_COMMITTER_NAME": "Fixture",
                "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
            }
            subprocess.run(
                ["git", "commit", "-q", "-m", "fixture"],
                cwd=source,
                env=commit_env,
                check=True,
            )
            commit = subprocess.check_output(
                ["git", "rev-parse", "HEAD"], cwd=source, text=True
            ).strip()
            subprocess.run(["git", "tag", "v9.8.7", commit], cwd=source, check=True)
            tree = subprocess.check_output(
                ["git", "rev-parse", "HEAD^{tree}"], cwd=source, text=True
            ).strip()
            python = Path(sys.executable).resolve()
            gate_file = common.file_record(gate_script)
            environment = {
                "LANG": "C",
                "LC_ALL": "C",
                "PYTHONHASHSEED": "0",
                "SOURCE_DATE_EPOCH": "1",
                "TZ": "UTC",
            }
            identity = {
                "source_commit": commit,
                "source_tree": tree,
                "source_origin": "https://github.com/example/KazStem.git",
                "source_ref": "refs/tags/v9.8.7",
                "verification": {
                    "reproducibility": {
                        "tools": [
                            {
                                "name": "python-fixture",
                                "version_argv": ["python-fixture", "--version"],
                                "version": "fixture",
                                "executable": common.file_record(python),
                            }
                        ]
                    },
                    "evidence": [
                        {
                            "gate": "fixture",
                            "generator": {
                                "argv": [
                                    "python-fixture",
                                    "-S",
                                    "source-tree/gate.py",
                                ],
                                "cwd": "release-workspace",
                                "environment": environment,
                                "script": {
                                    "path": "source-tree/gate.py",
                                    "file": gate_file,
                                },
                                "source_commit": commit,
                                "source_tree": tree,
                                "timeout_seconds": 30,
                                "tool": "python-fixture",
                            },
                        }
                    ],
                },
            }
            (workspace / "identity.json").write_text(
                json.dumps(identity), encoding="utf-8"
            )
            process_env = {
                key: value
                for key, value in os.environ.items()
                if key
                not in {"PYTHONHOME", "PYTHONPATH", "PYTHONSTARTUP", "PYTHONINSPECT"}
            }
            process_env.update(environment)
            passing = subprocess.run(
                [str(python), "-S", "source-tree/gate.py"],
                cwd=workspace,
                env=process_env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            self.assertEqual(passing.returncode, 0, passing.stderr)
            self.assertEqual(passing.stdout.strip(), "verified")

            forged = subprocess.run(
                [str(python), "-S", "source-tree/gate.py", "extra"],
                cwd=workspace,
                env=process_env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            self.assertNotEqual(forged.returncode, 0)
            self.assertIn("live argv differs", forged.stderr)

    def test_reproduction_command_capture_is_bounded_and_reaps_process_group(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            environment = {**os.environ, "PYTHONUNBUFFERED": "1"}
            record = reproduction._run(
                [sys.executable, "-c", "print('captured')"],
                logical_argv=["python", "-c", "checked-fixture"],
                cwd=root,
                environment=environment,
                timeout=10,
                stream_cap=1024,
            )
            self.assertEqual(record["exit_status"], 0)
            self.assertTrue(record["capture"]["process_group_reaped"])
            self.assertEqual(record["capture"]["stream_cap_bytes"], 1024)
            with self.assertRaisesRegex(common.ReleaseError, "capture cap"):
                reproduction._run(
                    [sys.executable, "-c", "import sys; sys.stdout.write('x'*2048)"],
                    logical_argv=["python", "-c", "oversize-fixture"],
                    cwd=root,
                    environment=environment,
                    timeout=10,
                    stream_cap=128,
                )
            with self.assertRaisesRegex(common.ReleaseError, "timeout"):
                reproduction._run(
                    [
                        sys.executable,
                        "-c",
                        "import subprocess; subprocess.Popen(['sleep','10'])",
                    ],
                    logical_argv=["python", "-c", "lingering-descendant-fixture"],
                    cwd=root,
                    environment=environment,
                    timeout=1,
                    stream_cap=1024,
                )


if __name__ == "__main__":
    unittest.main()
