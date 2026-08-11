from __future__ import annotations

import argparse
import hashlib
import inspect
import importlib.util
import json
import os
from pathlib import Path
import py_compile
import shutil
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import time
import types
import unittest
from unittest import mock
import zipfile


ROOT = Path(__file__).resolve().parents[1]
WINDOWS = ROOT / "packaging/windows"
sys.path.insert(0, str(WINDOWS))

# The combined cross-platform suite imports Linux release modules first.  The
# platform scripts intentionally use adjacent top-level helper names when run
# as standalone entry points, so discard any same-named module whose source is
# not the Windows implementation before importing this platform's helpers.
# Previously materialize_git_source received Linux release_common, and the
# support-file verifier likewise observed Linux assembler modules.
for _adjacent_file in WINDOWS.glob("*.py"):
    _adjacent_name = _adjacent_file.stem
    _loaded = sys.modules.get(_adjacent_name)
    _loaded_file = getattr(_loaded, "__file__", None)
    if _loaded is not None and (
        _loaded_file is None
        or Path(_loaded_file).resolve() != _adjacent_file.resolve()
    ):
        sys.modules.pop(_adjacent_name, None)

import release_common as common  # noqa: E402
import assemble_ready_run  # noqa: E402
import audit_ready_run_archive  # noqa: E402
import bounded_windows_process  # noqa: E402
import materialize_git_source  # noqa: E402
import select_optimization_candidate  # noqa: E402
import source_suite_runner  # noqa: E402
from audit_corresponding_source_archive import inspect_tar, magic_archive_inventory  # noqa: E402


def file_identity(byte: str = "0") -> dict[str, object]:
    return {"bytes": 1, "sha256": byte * 64}


def artifact(name: str, version: str = "0.2.3", byte: str = "0") -> dict[str, object]:
    return {
        "filename": name,
        "bytes": 1,
        "sha256": byte * 64,
        "url": f"https://github.com/amir-nuriyev/KazStem/releases/download/v{version}/{name}",
    }


def pe_record(byte: str = "0", name: str = "python.exe") -> dict[str, object]:
    return {
        "path": name,
        "machine": "AMD64",
        "format": "PE32+",
        "sections": 3,
        "coff_timestamp": 0,
        "optional_header_bytes": 240,
        "characteristics": 2,
        "authenticode_embedded": False,
        "authenticode_file_offset": 0,
        "authenticode_bytes": 0,
        "bytes": 1,
        "sha256": byte * 64,
    }


def write_amd64_pe(path: Path) -> None:
    data = bytearray(0x80 + 24 + 240)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 0x84, 0x8664, 3, 0, 0, 0, 240, 2)
    struct.pack_into("<H", data, 0x80 + 24, 0x20B)
    path.write_bytes(data)


def clean_windows_loader_environment() -> dict[str, object]:
    absent = {
        "ambient_present": False,
        "removed_from_helper_environment": True,
        "sha256": None,
    }
    return {
        "PATH": {
            "ambient_present": True,
            "ambient_untrusted": False,
            "removed_from_helper_environment": True,
        },
        **{
            name: dict(absent)
            for name in common.FORBIDDEN_LOADER_ENVIRONMENT
        },
        common.GLIBC_TUNABLES_VARIABLE: dict(absent),
        "loader_policy": {
            "schema": "qazmorph-native-helper-loader-environment-v2",
            "captured_name_policy": {
                "exact_uppercase_prefixes": ["LD_", "DYLD_"],
                "exact_names": ["GLIBC_TUNABLES"],
            },
            "ambient_records": {},
            "glibc_tunables": dict(absent),
            "clean_parent_startup": True,
            "all_ambient_values_removed_from_helper_environment": True,
            "linux_helper_ld_library_path": None,
        },
    }


def identity() -> dict[str, object]:
    version = "0.2.3"
    label = "windows-server-2022-x86_64"
    ready_name = f"kazstem-{version}-{label}-ready-run.zip"
    source_name = f"kazstem-{version}-{label}-corresponding-source.zip"
    result = {
        "schema": common.IDENTITY_SCHEMA,
        "release": version,
        "source_commit": "1" * 40,
        "source_tree": "2" * 40,
        "source_origin": "https://github.com/amir-nuriyev/KazStem.git",
        "source_ref": "refs/tags/v0.2.3",
        "source_date_epoch": 1_786_320_000,
        "release_url": f"https://github.com/amir-nuriyev/KazStem/releases/tag/v{version}",
        "platform": {
            "system": "windows",
            "machine": "x86_64",
            "label": label,
            "runner": "windows-2022",
            "minimum_os_build": "10.0.20348",
            "python": "3.14.3",
            "pyinstaller": "6.22.0",
            "archive_writer": {"implementation": "cpython-zipfile-3.14.3", "compression": "deflate-9"},
            "unsigned": True,
        },
        "artifacts": {
            "wheel": artifact(f"kazstem-{version}-py3-none-any.whl", byte="1"),
            "sdist": artifact(f"kazstem-{version}.tar.gz", byte="2"),
            "ready_run": artifact(ready_name, byte="3"),
            "corresponding_source": artifact(source_name, byte="4"),
        },
        "inputs": {
            "frozen_tree": {"entries": 1, "regular_file_bytes": 1, "sha256": "5" * 64},
            "resource_tree": {
                "bundle_id": "f03e703d3e2a67044a7d91fd7d575b92cb4e61aa782fb67cff91b0a5ff0ebd5a",
                "manifest": file_identity("6"),
                "tree": {"entries": 1, "regular_file_bytes": 1, "sha256": "7" * 64},
            },
            "runtime_tree": {
                "bundle_id": "17a69ae11ff3fd92a555e8c95571223cbe8b217ec409a0b9b368f0aed90ee465",
                "manifest": {"bytes": 20697, "sha256": "554a776a942e2db65ca34bb6e05e0c258976848203cbece38ababc0067d1ee46"},
                "tree": {"entries": 1, "regular_file_bytes": 1, "sha256": "8" * 64},
            },
            "source_payload_tree": {"entries": 1, "regular_file_bytes": 1, "sha256": "9" * 64},
            "source_receipt": file_identity("9"),
            "bootstrap_python": pe_record("0"),
            "build_wheelhouse_tree": {
                "entries": 1,
                "regular_file_bytes": 1,
                "sha256": "1" * 64,
            },
            "canonical_python_builder": file_identity("6"),
            "canonical_python_build_identity": file_identity("7"),
            "canonical_python_build_receipt": file_identity("8"),
            "optimization_config": file_identity("2"),
            "platform_lock": file_identity("a"),
            "base_ledger": file_identity("b"),
            "binary_readme_template": file_identity("c"),
            "source_readme_template": file_identity("d"),
            "release_support_files": [
                {
                    "path": path,
                    "file": common.file_record(ROOT / path),
                }
                for path in common.RELEASE_SUPPORT_PATHS
            ],
            "documents": [
                {"source": "LICENSE", "destination": "LICENSE", "file": file_identity("e")},
            ],
        },
        "ready_run": {
            "top_level": ready_name[:-4],
            "launcher": {"path": "kazstem.exe", "file": file_identity("f")},
            "aliases": ["mystem-kz.exe", "qazmorph.exe"],
            "platform_lock_path": "_internal/qazmorph/platform_runtime_assets.lock.json",
            "resource_destination": ".qazmorph/resources",
            "runtime_parent": ".qazmorph/platform-runtimes",
            "remove_frozen_files": [],
            "required_paths": ["README-WINDOWS.md", "kazstem.exe", "verification/BUNDLE-MANIFEST.json"],
            "banned_name_fragments": ["libcrypto", "libssl", "neural", "openssl", "pytorch", "stanza", "torch"],
        },
        "corresponding_source": {
            "top_level": source_name[:-4],
            "categories": {
                "application": "application",
                "build": "build",
                "native": "native",
                "evidence": "evidence",
                "licenses": "licenses",
            },
            "source_commit_file": "SOURCE-COMMIT.txt",
            "source_date_epoch_file": "SOURCE-DATE-EPOCH.txt",
            "components": [
                {
                    "name": "CPython",
                    "version": "3.14.3",
                    "license": "PSF-2.0",
                    "category": "build",
                    "source": "cpython.tar.gz",
                    "destination": "build/cpython.tar.gz",
                    "artifact": {"filename": "cpython.tar.gz", "bytes": 1, "sha256": "a" * 64, "url": "https://example.com/cpython.tar.gz"},
                },
                {
                    "name": "PyInstaller",
                    "version": "6.22.0",
                    "license": "GPL-2.0-or-later WITH bootloader-exception",
                    "category": "build",
                    "source": "pyinstaller.tar.gz",
                    "destination": "build/pyinstaller.tar.gz",
                    "artifact": {"filename": "pyinstaller.tar.gz", "bytes": 1, "sha256": "b" * 64, "url": "https://example.com/pyinstaller.tar.gz"},
                },
            ],
            "nested_archives": [
                {"path": "build/cpython.tar.gz", "kind": "tar-gzip"},
                {"path": "build/pyinstaller.tar.gz", "kind": "tar-gzip"},
            ],
            "wheelhouse_destination": "build/freezer-wheelhouse",
            "required_paths": ["README.md", "SOURCE-CLOSURE.json", "SOURCE-MANIFEST.json"],
        },
        "optimization": {
            "selected": "compact",
            "candidates": [
                {
                    "name": "baseline",
                    "config": file_identity("3"),
                    "behavior": file_identity("4"),
                },
                {
                    "name": "compact",
                    "config": file_identity("2"),
                    "behavior": file_identity("5"),
                },
            ],
            "selected_full_regression": file_identity("6"),
        },
        "performance": {
            "startup_runs": 15,
            "startup_median_seconds_max": 5.0,
            "large_input_characters": 300_000,
            "large_runs": 2,
            "large_timeout_seconds": 600,
            "minimum_characters_per_second": 500,
            "maximum_peak_working_set_bytes": 536_870_912,
        },
        "archive_limits": {
            name: {"max_members": 1000, "max_file_bytes": 10_000_000, "max_total_bytes": 20_000_000, "max_path_bytes": 512}
            for name in ("ready_run", "corresponding_source", "nested")
        },
        "verification": {"minimum_distinct_roots": 2, "evidence": []},
    }
    subject_hash = common.release_subject_sha256(result)
    evidence_records = []
    for index, (gate, schema) in enumerate(
        sorted(common.REQUIRED_EVIDENCE_GATES.items()), start=1
    ):
        entrypoint_argv = common.canonical_generator_entrypoint_argv(result, gate)
        if entrypoint_argv is None:
            entrypoint_argv = [
                "<PYTHON>",
                common.GENERATOR_SCRIPTS[gate],
                "--identity",
                "<RELEASE-IDENTITY>",
                "--runner-os",
                "Windows",
                "--runner-arch",
                "X64",
                "--image-os",
                "win22",
                "--image-version",
                "20260801.1",
                "--run-id",
                "123",
                "--json",
                "<EVIDENCE-OUTPUT>",
            ]
        evidence_records.append(
            {
            "gate": gate,
            "schema": schema,
            "subject_sha256": subject_hash,
            "path": f"evidence/{gate}.json",
            "file": file_identity(hex(index % 16)[2:]),
            "generator": {
                "script": {
                    "path": common.GENERATOR_SCRIPTS[gate],
                    "file": file_identity("a"),
                },
                "argv": common.wrap_release_tool_argv(result, entrypoint_argv),
                "cwd": "<MATERIALIZED-SOURCE>",
                "environment": {
                    "LC_ALL": "C",
                    "PYTHONHASHSEED": "0",
                    "TZ": "UTC",
                },
                "timeout_seconds": 3600,
                "tool": {
                    "name": "CPython",
                    "executable": "<PYTHON>",
                    "version": "3.14.3",
                    "file": file_identity("0"),
                },
                "source_boundary": common.source_boundary_contract(
                    result, common.GENERATOR_SCRIPTS[gate]
                ),
                "dependencies": result["inputs"]["release_support_files"],
                "payload_schema": schema + "-observations-v1",
                "required_coverage": {
                    "assertions": len(common.MINIMUM_GATE_CHECKS[gate]),
                    "cases": 1,
                    "checks": sorted(common.MINIMUM_GATE_CHECKS[gate]),
                },
            },
            }
        )
    result["verification"]["evidence"] = evidence_records
    return result


def refresh_subject(value: dict[str, object]) -> None:
    subject_hash = common.release_subject_sha256(value)
    for record in value["verification"]["evidence"]:
        record["subject_sha256"] = subject_hash


class WindowsReleaseCommonTests(unittest.TestCase):
    def test_source_suite_runner_binds_exact_ids_skips_xfails_and_import(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            site = root / "site"
            tests = source / "tests"
            package = site / "qazmorph"
            metadata = site / "kazstem-0.2.3.dist-info"
            tests.mkdir(parents=True)
            package.mkdir(parents=True)
            metadata.mkdir()
            (package / "__init__.py").write_text(
                "__version__ = '0.2.3'\n", encoding="utf-8"
            )
            (metadata / "METADATA").write_text(
                "Metadata-Version: 2.4\nName: kazstem\nVersion: 0.2.3\n",
                encoding="utf-8",
            )
            (tests / "__init__.py").write_text("", encoding="utf-8")
            (tests / "test_fixture.py").write_text(
                "import unittest\n"
                "import qazmorph\n"
                "class Fixture(unittest.TestCase):\n"
                " def test_success(self): self.assertEqual(qazmorph.__version__, '0.2.3')\n"
                " @unittest.skip('bound skip reason')\n"
                " def test_skip(self): pass\n"
                " @unittest.expectedFailure\n"
                " def test_expected_failure(self): self.fail('bound xfail')\n",
                encoding="utf-8",
            )
            output = root / "ledger.json"
            direct_test_driver = (
                "import importlib.util,sys;path=sys.argv[1];"
                "spec=importlib.util.spec_from_file_location('source_suite_runner_fixture',path);"
                "module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);"
                "sys.argv=[path,*sys.argv[2:]];"
                "raise SystemExit(module.main(require_bootstrap_boundary=False))"
            )
            source_cache = WINDOWS / "__pycache__"

            def runner_command(result: Path, cache: Path) -> list[str]:
                return [
                    sys.executable,
                    "-I",
                    "-B",
                    "-X",
                    f"pycache_prefix={cache}",
                    "-c",
                    direct_test_driver,
                    str(WINDOWS / "source_suite_runner.py"),
                    "--source",
                    str(source),
                    "--site",
                    str(site),
                    "--json",
                    str(result),
                ]

            runner_cache = root / "runner-driver-pycache"
            completed = subprocess.run(
                runner_command(output, runner_cache),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr.decode())
            ledger = json.loads(output.read_text(encoding="utf-8"))
            common._validate_source_suite_ledger(ledger)
            self.assertEqual(ledger["tests_run"], 3)
            self.assertEqual(ledger["successes"]["count"], 1)
            self.assertEqual(ledger["skips"]["count"], 1)
            self.assertEqual(ledger["expected_failures"]["count"], 1)
            self.assertEqual(ledger["discovery"], ledger["run"])
            self.assertEqual(ledger["import"]["module_path"], "qazmorph/__init__.py")
            repeated = root / "ledger-repeated.json"
            repeated_cache = root / "runner-driver-repeated-pycache"
            repeated_run = subprocess.run(
                runner_command(repeated, repeated_cache),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(
                repeated_run.returncode,
                0,
                repeated_run.stderr.decode(),
            )
            self.assertEqual(output.read_bytes(), repeated.read_bytes())
            self.assertFalse(runner_cache.exists())
            self.assertFalse(repeated_cache.exists())
            self.assertFalse(
                source_cache.exists()
                and any(source_cache.glob("source_suite_runner.*.py[co]"))
            )
            changed = json.loads(json.dumps(ledger))
            changed["unexpected"]["errors"]["count"] = 1
            with self.assertRaises(common.ReleaseError):
                common._validate_source_suite_ledger(changed)

    def test_bounded_job_assigns_suspended_child_before_reader_and_resume(self) -> None:
        source = inspect.getsource(bounded_windows_process.run_bounded)
        creation = source.index("CREATE_NO_WINDOW | CREATE_SUSPENDED")
        assignment = source.index("_assign_process", creation)
        reader = source.index("_start_reader", assignment)
        resume = source.index("NtResumeProcess", reader)
        self.assertLess(creation, assignment)
        self.assertLess(assignment, reader)
        self.assertLess(reader, resume)
        finally_block = source.index("finally:")
        self.assertIn("_wait_for_empty_job", source[finally_block:])

    @unittest.skipUnless(sys.platform == "win32", "requires native Windows jobs")
    def test_bounded_job_contains_immediate_grandchildren_on_every_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            grandchild = (
                "import pathlib,sys,time;"
                "time.sleep(1.0);"
                "pathlib.Path(sys.argv[1]).write_text('escaped',encoding='utf-8')"
            )
            parent = (
                "import subprocess,sys,time;"
                "subprocess.Popen([sys.executable,'-c',sys.argv[2],sys.argv[1]]);"
                "mode=sys.argv[3];"
                "print('x'*200000 if mode=='overflow' else 'parent',flush=True);"
                "time.sleep(60 if mode in {'timeout','overflow'} else 0)"
            )

            def command(marker: Path, mode: str) -> list[str]:
                return [
                    sys.executable,
                    "-c",
                    parent,
                    str(marker),
                    grandchild,
                    mode,
                ]

            success_marker = root / "success-escaped"
            with self.assertRaisesRegex(
                bounded_windows_process.BoundedProcessError,
                "active descendant",
            ):
                bounded_windows_process.run_bounded(
                    command(success_marker, "success"),
                    cwd=root,
                    environment=dict(os.environ),
                    timeout_seconds=10,
                )
            time.sleep(1.2)
            self.assertFalse(success_marker.exists())

            for mode, timeout, limit in (
                ("timeout", 0.2, 1024 * 1024),
                ("overflow", 10, 1024),
            ):
                marker = root / f"{mode}-escaped"
                with self.subTest(mode=mode), self.assertRaises(
                    bounded_windows_process.BoundedProcessError
                ):
                    bounded_windows_process.run_bounded(
                        command(marker, mode),
                        cwd=root,
                        environment=dict(os.environ),
                        timeout_seconds=timeout,
                        output_limit_bytes=limit,
                    )
                time.sleep(1.2)
                self.assertFalse(marker.exists())

            for failure_name, target in (
                ("assignment", "_assign_process"),
                ("reader-start", "_start_reader"),
            ):
                marker = root / f"{failure_name}-escaped"
                replacement = (
                    (lambda *arguments, **keywords: False)
                    if failure_name == "assignment"
                    else mock.Mock(side_effect=RuntimeError("forced reader failure"))
                )
                with self.subTest(failure=failure_name), mock.patch.object(
                    bounded_windows_process, target, replacement
                ), self.assertRaises(bounded_windows_process.BoundedProcessError):
                    bounded_windows_process.run_bounded(
                        command(marker, "success"),
                        cwd=root,
                        environment=dict(os.environ),
                        timeout_seconds=10,
                    )
                time.sleep(1.2)
                self.assertFalse(marker.exists())

    def test_git_dir_and_work_tree_environment_bypasses_are_rejected(self) -> None:
        for name in ("GIT_DIR", "GIT_WORK_TREE", "GIT_OBJECT_DIRECTORY"):
            with self.subTest(name=name), mock.patch.dict(
                os.environ,
                {"PATH": os.environ.get("PATH", ""), name: "/attacker/repository"},
                clear=True,
            ):
                with self.assertRaises(common.ReleaseError):
                    materialize_git_source.git_environment()

        value = identity()
        record = common.evidence_record(value, "source-suite")
        with mock.patch.dict(
            os.environ,
            {"GIT_DIR": "/attacker/repository"},
            clear=True,
        ), self.assertRaises(common.ReleaseError):
            common.verify_generator_runtime(
                value,
                gate="source-suite",
                logical_argv=record["generator"]["argv"],
            )

    def test_git_source_inventory_is_complete_and_recursive(self) -> None:
        if shutil.which("git") is None:
            self.skipTest("Git is unavailable")
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary) / "repo"
            subprocess.run(["git", "init", "-q", str(repo)], check=True)
            subprocess.run(
                ["git", "config", "core.autocrlf", "false"], cwd=repo, check=True
            )
            subprocess.run(
                ["git", "config", "core.eol", "lf"], cwd=repo, check=True
            )
            (repo / "root.txt").write_text("root\n", encoding="utf-8")
            (repo / "nested/deeper").mkdir(parents=True)
            (repo / "nested/deeper/file.txt").write_text("nested\n", encoding="utf-8")
            subprocess.run(["git", "add", "--", "root.txt", "nested/deeper/file.txt"], cwd=repo, check=True)
            tree = subprocess.run(
                ["git", "write-tree"],
                cwd=repo,
                check=True,
                stdout=subprocess.PIPE,
                text=True,
            ).stdout.strip()
            clean_environment = {
                name: value
                for name, value in os.environ.items()
                if not name.startswith("GIT_")
            }
            with mock.patch.dict(os.environ, clean_environment, clear=True):
                _, records = materialize_git_source.tracked_files(repo, tree)
            self.assertEqual(sorted(records), ["nested/deeper/file.txt", "root.txt"])
            archive = Path(temporary) / "source.tar"
            with archive.open("wb") as stream:
                subprocess.run(
                    ["git", "archive", "--format=tar", "--prefix=KazStem/", tree],
                    cwd=repo,
                    check=True,
                    stdout=stream,
                )
            algorithm = subprocess.run(
                ["git", "rev-parse", "--show-object-format"],
                cwd=repo,
                check=True,
                stdout=subprocess.PIPE,
                text=True,
            ).stdout.strip()
            output = Path(temporary) / "KazStem"
            materialize_git_source.extract_and_verify(archive, output, records, algorithm)
            self.assertEqual(
                sorted(path.relative_to(output).as_posix() for path in output.rglob("*") if path.is_file()),
                ["nested/deeper/file.txt", "root.txt"],
            )

    def test_release_identity_requires_exact_git_tree_and_origin(self) -> None:
        value = identity()
        del value["source_tree"]
        del value["source_origin"]
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "identity.json"
            path.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaises(common.ReleaseError):
                common.load_identity(path)

    def test_source_binding_projection_does_not_include_ready_hash_or_size(self) -> None:
        first = identity()
        second = json.loads(json.dumps(first))
        second["artifacts"]["ready_run"]["bytes"] = 999
        second["artifacts"]["ready_run"]["sha256"] = "9" * 64
        self.assertEqual(
            common.source_ready_location(first),
            common.source_ready_location(second),
        )

    def test_evidence_rejects_two_token_self_asserted_pass(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "evidence.json"
            path.write_text(
                json.dumps(
                    {
                        "result": "pass",
                        "release_identity_sha256": "0" * 64,
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaises(common.ReleaseError):
                common.verify_evidence_file(
                    path,
                    record={
                        "gate": "binary-archive-audit",
                        "schema": common.READY_AUDIT_SCHEMA,
                        "subject_sha256": common.release_subject_sha256(identity()),
                        "path": "evidence/binary.json",
                        "file": common.file_record(path),
                    },
                    identity=identity(),
                    identity_hash="0" * 64,
                )

    def test_identity_rejects_mutated_generator_argv_and_coverage(self) -> None:
        mutations = []
        value = identity()
        value["verification"]["evidence"][0]["generator"]["argv"].append("--network-eligible")
        mutations.append(value)
        value = identity()
        value["verification"]["evidence"][0]["generator"]["required_coverage"]["checks"].append("self-asserted-extra")
        value["verification"]["evidence"][0]["generator"]["required_coverage"]["assertions"] += 1
        mutations.append(value)
        for index, value in enumerate(mutations):
            with self.subTest(index=index), tempfile.TemporaryDirectory() as temporary:
                path = Path(temporary) / "identity.json"
                path.write_bytes(common.json_bytes(value))
                with self.assertRaises(common.ReleaseError):
                    common.load_identity(path)

    def test_every_generator_binds_the_isolated_materialized_source_boundary(self) -> None:
        value = identity()
        for record in value["verification"]["evidence"]:
            generator = record["generator"]
            script = generator["script"]["path"]
            prefix = common.release_bootstrap_prefix(value, script)
            with self.subTest(gate=record["gate"]):
                self.assertEqual(generator["argv"][: len(prefix)], prefix)
                self.assertEqual(generator["cwd"], "<MATERIALIZED-SOURCE>")
                self.assertEqual(
                    generator["source_boundary"],
                    common.source_boundary_contract(value, script),
                )
                source = (ROOT / script).read_text(encoding="utf-8")
                self.assertLess(
                    source.index("require_release_bootstrap("),
                    source.index("argparse.ArgumentParser()"),
                )

        for mutation in ("-B", "pycache_prefix=<FRESH-PYCACHE-ROOT>"):
            changed = identity()
            generator = changed["verification"]["evidence"][0]["generator"]
            generator["argv"].remove(mutation)
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                path = Path(temporary) / "identity.json"
                path.write_bytes(common.json_bytes(changed))
                with self.assertRaises(common.ReleaseError):
                    common.load_identity(path)

        release_entrypoints = {
            *common.GENERATOR_SCRIPTS.values(),
            "packaging/windows/assemble_corresponding_source.py",
            "packaging/windows/assemble_optimization_candidate.py",
            "packaging/windows/assemble_ready_run.py",
            "packaging/windows/audit_python_artifacts.py",
            "packaging/windows/build_python_freezer.py",
            "packaging/windows/finalize_release.py",
            "packaging/windows/materialize_git_source.py",
            "packaging/windows/write_freezer_ledger.py",
            "packaging/windows/write_optimization_config.py",
        }
        for script in sorted(release_entrypoints):
            source = (ROOT / script).read_text(encoding="utf-8")
            with self.subTest(release_entrypoint=script):
                self.assertLess(
                    source.index("require_release_bootstrap("),
                    source.index("argparse.ArgumentParser()"),
                )
        runner_source = (
            ROOT / "packaging/windows/source_suite_runner.py"
        ).read_text(encoding="utf-8")
        self.assertIn("require_source_bootstrap()", runner_source)

    def test_swapped_transitive_release_helper_is_rejected(self) -> None:
        value = identity()
        records = value["inputs"]["release_support_files"]
        records[0]["file"], records[1]["file"] = (
            records[1]["file"],
            records[0]["file"],
        )
        for evidence in value["verification"]["evidence"]:
            evidence["generator"]["dependencies"] = records
        refresh_subject(value)
        with self.assertRaises(common.ReleaseError):
            common.verify_release_support_files(value, ROOT)

        changed_bootstrap = identity()
        bootstrap_record = next(
            record
            for record in changed_bootstrap["inputs"]["release_support_files"]
            if record["path"] == "packaging/windows/release_bootstrap.py"
        )
        bootstrap_record["file"] = common.file_record(
            ROOT / "packaging/windows/release_common.py"
        )
        for evidence in changed_bootstrap["verification"]["evidence"]:
            evidence["generator"]["dependencies"] = changed_bootstrap["inputs"][
                "release_support_files"
            ]
            evidence["generator"]["source_boundary"]["bootstrap"] = bootstrap_record
        refresh_subject(changed_bootstrap)
        with self.assertRaises(common.ReleaseError):
            common.verify_release_support_files(changed_bootstrap, ROOT)

        with tempfile.TemporaryDirectory() as temporary:
            shadow = Path(temporary) / "audit_evidence_paths.py"
            shadow.write_text("# hostile shadow\n", encoding="utf-8")
            with mock.patch.dict(
                sys.modules,
                {
                    "audit_evidence_paths": types.SimpleNamespace(
                        __file__=str(shadow)
                    )
                },
            ), self.assertRaises(common.ReleaseError):
                common.verify_release_support_files(identity(), ROOT)

        record = common.evidence_record(identity(), "source-suite")
        with mock.patch.dict(
            os.environ,
            {"PYTHONPATH": "/attacker/shadow"},
            clear=True,
        ), self.assertRaisesRegex(common.ReleaseError, "forbidden environment"):
            common.verify_generator_runtime(
                identity(),
                gate="source-suite",
                logical_argv=record["generator"]["argv"],
            )

    def test_bootstrap_rejects_real_unchecked_hash_pyc_before_import(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            materialization = base / "source-materialization"
            source = materialization / "KazStem"
            windows = source / "packaging/windows"
            windows.mkdir(parents=True)
            shutil.copyfile(
                WINDOWS / "release_bootstrap.py",
                windows / "release_bootstrap.py",
            )
            shutil.copyfile(
                WINDOWS / "release_common.py",
                windows / "release_common.py",
            )
            helper = source / "helper.py"
            helper.write_text("VALUE = 'safe'\n", encoding="utf-8")
            target = source / "target.py"
            target.write_text(
                "import helper\n"
                "if helper.VALUE != 'safe': raise RuntimeError('hostile helper ran')\n",
                encoding="utf-8",
            )
            expected_tree = common.tree_record(source)
            source_identity = {
                "commit": "1" * 40,
                "tree": "2" * 40,
                "origin": "https://github.com/amir-nuriyev/KazStem.git",
                "ref": "refs/tags/v0.2.3",
            }
            canonical_path = materialization / "GIT-SOURCE-MATERIALIZATION.json"
            canonical_path.write_bytes(
                common.json_bytes(
                    {
                        "schema": "kazstem-git-source-materialization-v2",
                        "result": "pass",
                        "source": source_identity,
                        "payload_tree": expected_tree,
                    }
                )
            )
            execution_path = materialization / "MATERIALIZATION-EXECUTION.json"
            execution_path.touch()
            root_stat = materialization.stat()
            payload_stat = source.stat()
            execution_path.write_bytes(
                common.json_bytes(
                    {
                        "schema":
                        "kazstem-git-source-materialization-execution-v2",
                        "result": "pass",
                        "source": source_identity,
                        "root_identity": {
                            "logical_label": "fixture",
                            "st_dev": root_stat.st_dev,
                            "st_ino": root_stat.st_ino,
                            "st_ctime_ns": root_stat.st_ctime_ns,
                        },
                        "payload_identity": {
                            "logical_path": "<SOURCE-ROOT-FIXTURE>/KazStem",
                            "st_dev": payload_stat.st_dev,
                            "st_ino": payload_stat.st_ino,
                            "st_ctime_ns": payload_stat.st_ctime_ns,
                            "tree": expected_tree,
                        },
                        "canonical_receipt": common.file_record(canonical_path),
                        "freshness": {
                            "root_absent_before_execution": True,
                            "root_created_by_process": True,
                            "payload_created_by_process": True,
                        },
                    }
                )
            )
            identity_path = base / "release-identity.json"
            identity_path.write_bytes(
                common.json_bytes(
                    {
                        "schema": common.IDENTITY_SCHEMA,
                        "source_commit": source_identity["commit"],
                        "source_tree": source_identity["tree"],
                        "source_origin": source_identity["origin"],
                        "source_ref": source_identity["ref"],
                        "inputs": {
                            "source_payload_tree": expected_tree,
                            "source_receipt": common.file_record(canonical_path),
                            "release_support_files": [
                                {
                                    "path": f"packaging/windows/{name}",
                                    "file": common.file_record(windows / name),
                                }
                                for name in (
                                    "release_bootstrap.py",
                                    "release_common.py",
                                )
                            ],
                        },
                    }
                )
            )

            def bootstrap_command(cache: Path) -> list[str]:
                return [
                    sys.executable,
                    "-I",
                    "-B",
                    "-X",
                    f"pycache_prefix={cache}",
                    str(windows / "release_bootstrap.py"),
                    "--source-root",
                    str(source),
                    "--release-identity",
                    str(identity_path),
                    "--materialization-root",
                    str(materialization),
                    "--materialization-receipt",
                    str(canonical_path),
                    "--materialization-execution-receipt",
                    str(execution_path),
                    "--cache-root",
                    str(cache),
                    "--expected-tree-entries",
                    str(expected_tree["entries"]),
                    "--expected-tree-bytes",
                    str(expected_tree["regular_file_bytes"]),
                    "--expected-tree-sha256",
                    str(expected_tree["sha256"]),
                    "--entrypoint",
                    "target.py",
                    "--",
                ]

            nested_cache = source / "forbidden-pycache"
            nested = subprocess.run(
                bootstrap_command(nested_cache),
                cwd=source,
                env={"PATH": os.environ.get("PATH", "")},
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            self.assertNotEqual(nested.returncode, 0)
            self.assertIn("aliases/nests protected source", nested.stderr)
            self.assertFalse(nested_cache.exists())

            clean_cache = base / "clean-pycache"
            clean = subprocess.run(
                bootstrap_command(clean_cache),
                cwd=source,
                env={"PATH": os.environ.get("PATH", "")},
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            self.assertEqual(clean.returncode, 0, clean.stderr)
            self.assertTrue(clean_cache.is_dir())
            self.assertEqual(list(clean_cache.iterdir()), [])

            sentinel = base / "unchecked-hash-sentinel"
            hostile_source = base / "hostile-helper.py"
            hostile_source.write_text(
                "from pathlib import Path\n"
                f"Path({str(sentinel)!r}).write_text('executed', encoding='utf-8')\n"
                "VALUE = 'hostile'\n",
                encoding="utf-8",
            )
            with mock.patch.object(sys, "pycache_prefix", None):
                pyc = Path(importlib.util.cache_from_source(str(helper)))
            pyc.parent.mkdir()
            py_compile.compile(
                str(hostile_source),
                cfile=str(pyc),
                dfile=str(helper),
                doraise=True,
                invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH,
            )
            control = subprocess.run(
                [
                    sys.executable,
                    "-B",
                    "-c",
                    "import sys;sys.path.insert(0,sys.argv[1]);import helper",
                    str(source),
                ],
                cwd=base,
                env={"PATH": os.environ.get("PATH", "")},
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            self.assertEqual(control.returncode, 0, control.stderr)
            self.assertEqual(sentinel.read_text(encoding="utf-8"), "executed")
            sentinel.unlink()

            hostile_cache = base / "hostile-pycache"
            rejected = subprocess.run(
                bootstrap_command(hostile_cache),
                cwd=source,
                env={"PATH": os.environ.get("PATH", "")},
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn(
                "forbidden adjacent Python bytecode/cache entry",
                rejected.stderr,
            )
            self.assertFalse(sentinel.exists())
            self.assertFalse(hostile_cache.exists())

    def test_strict_evidence_rejects_well_shaped_but_false_observations(self) -> None:
        value = identity()
        record = common.evidence_record(value, "authenticode")
        envelope = common.evidence_envelope(
            value,
            identity_hash="0" * 64,
            record=record,
            observations={
                "host": {"system": "Windows"},
                "all_unsigned": True,
                "smartscreen_warning_possible": True,
                "files": [
                    {
                        "path": "kazstem.exe",
                        "status": "NotSigned",
                        "embedded_certificate_table": False,
                    }
                ],
            },
        )
        envelope["observations"]["all_unsigned"] = False
        envelope["observations"]["files"][0].update(
            {"status": "Valid", "embedded_certificate_table": True}
        )
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "authenticode.json"
            path.write_bytes(common.json_bytes(envelope))
            checked_record = json.loads(json.dumps(record))
            checked_record["file"] = common.file_record(path)
            with self.assertRaises(common.ReleaseError):
                common.verify_evidence_file(
                    path,
                    record=checked_record,
                    identity=value,
                    identity_hash="0" * 64,
                )

    def test_runtime_provenance_gate_requires_clean_parent_loader_state(self) -> None:
        value = identity()
        environment = clean_windows_loader_environment()
        provenance = {
            "official": True,
            "verified": True,
            "non_official_reasons": [],
            "environment": environment,
        }
        observations = {
            "schema": common.evidence_record(value, "runtime-provenance")[
                "generator"
            ]["payload_schema"],
            "result": "pass",
            "runtime_provenance": provenance,
            "matrix_file": common.evidence_record(
                value, "fresh-extract-practical"
            )["file"],
        }
        common.validate_evidence_observations(
            "runtime-provenance", observations, value
        )
        for mutation in ("LD_PRELOAD", "DYLD_INSERT_LIBRARIES", "PATH"):
            with self.subTest(mutation=mutation):
                changed = json.loads(json.dumps(observations))
                if mutation == "PATH":
                    changed["runtime_provenance"]["environment"][mutation][
                        "ambient_untrusted"
                    ] = True
                else:
                    changed["runtime_provenance"]["environment"][mutation].update(
                        {"ambient_present": True, "sha256": "a" * 64}
                    )
                with self.assertRaises(common.ReleaseError):
                    common.validate_evidence_observations(
                        "runtime-provenance", changed, value
                    )

    def test_dll_gate_requires_denial_and_restored_adjacent_success(self) -> None:
        value = identity()
        observations = {
            "schema": common.evidence_record(value, "dll-denial")["generator"][
                "payload_schema"
            ],
            "result": "pass",
            "matrix_file": common.evidence_record(
                value, "fresh-extract-practical"
            )["file"],
            "dll_denial": {
                "result": "pass",
                "normal_adjacent_closure_success": True,
                "normal_adjacent_commands": [
                    {"command": command, "returncode": 0}
                    for command in common.WINDOWS_RUNTIME_COMMANDS
                ],
                "dlls": [
                    {
                        "dll": dll,
                        "command": "usr/bin/hfst-proc.exe",
                        "missing_returncode": 2,
                        "path_injection_returncode": 2,
                        "cwd_injection_returncode": 2,
                    }
                    for dll in common.WINDOWS_RUNTIME_DLLS
                ],
            },
            "helper_path_denial": {
                "result": "pass",
                "helper": "usr/bin/hfst-proc.exe",
                "path_substitution_used": False,
                "cwd_substitution_used": False,
                "path_denial_returncode": 2,
                "cwd_denial_returncode": 2,
                "normal_adjacent_returncode": 0,
            },
        }
        common.validate_evidence_observations("dll-denial", observations, value)
        mutations = [
            ("dll_denial", "dlls", 0, "path_injection_returncode"),
            ("helper_path_denial", "path_denial_returncode"),
            ("helper_path_denial", "normal_adjacent_returncode"),
        ]
        for index, location in enumerate(mutations):
            with self.subTest(index=index):
                changed = json.loads(json.dumps(observations))
                if len(location) == 4:
                    changed[location[0]][location[1]][location[2]][location[3]] = 0
                elif location[-1] == "normal_adjacent_returncode":
                    changed[location[0]][location[1]] = 1
                else:
                    changed[location[0]][location[1]] = 0
                with self.assertRaises(common.ReleaseError):
                    common.validate_evidence_observations(
                        "dll-denial", changed, value
                    )

    def test_optimization_behavior_projection_ignores_paths_pids_and_timing(self) -> None:
        functional = [
            {
                "name": name,
                "returncode": 0,
                "seconds": 0.1,
                "stdin_bytes": index,
                "stdout_bytes": index + 1,
                "stdout_sha256": f"{index + 1:064x}",
                "stderr_bytes": 0,
                "stderr_sha256": hashlib.sha256(b"").hexdigest(),
            }
            for index, name in enumerate(
                common.WINDOWS_BEHAVIOR_EQUIVALENCE_CASES, start=1
            )
        ]
        stable_streams = [
            {
                key: record[key]
                for key in (
                    "name",
                    "returncode",
                    "stdin_bytes",
                    "stdout_bytes",
                    "stdout_sha256",
                    "stderr_bytes",
                    "stderr_sha256",
                )
            }
            for record in functional
        ]
        provenance = {
            "official": True,
            "verified": True,
            "non_official_reasons": [],
            "environment": clean_windows_loader_environment(),
        }
        dll_denial = {
            "result": "pass",
            "normal_adjacent_closure_success": True,
            "normal_adjacent_commands": [
                {"command": command, "returncode": 0}
                for command in common.WINDOWS_RUNTIME_COMMANDS
            ],
            "dlls": [
                {
                    "dll": dll,
                    "command": "usr/bin/hfst-proc.exe",
                    "missing_returncode": 2,
                    "path_injection_returncode": 2,
                    "cwd_injection_returncode": 2,
                }
                for dll in common.WINDOWS_RUNTIME_DLLS
            ],
        }
        helper_denial = {
            "result": "pass",
            "helper": "usr/bin/hfst-proc.exe",
            "path_substitution_used": False,
            "cwd_substitution_used": False,
            "path_denial_returncode": 2,
            "cwd_denial_returncode": 2,
            "normal_adjacent_returncode": 0,
        }
        extra = {
            "name": "wheel-install-offline",
            "returncode": 0,
            "seconds": 99.0,
            "stdin_bytes": 0,
            "stdout_bytes": 12,
            "stdout_sha256": "a" * 64,
            "stderr_bytes": 0,
            "stderr_sha256": hashlib.sha256(b"").hexdigest(),
        }
        matrix = {
            "schema": "kazstem-windows-practical-matrix-v1",
            "result": "pass",
            "candidate": {"name": "compact"},
            "results": [*functional, extra],
            "cases": len(functional) + 1,
            "coverage": {"formats": ["text", "json", "jsonl", "xml", "conllu"]},
            "behavior_fingerprint": common.canonical_hash(stable_streams),
            "runtime_provenance": provenance,
            "dll_denial": dll_denial,
            "helper_path_denial": helper_denial,
            "timeout_reap": {
                "result": "pass",
                "root_pid": 123,
                "observed_bundle_processes_before_kill": 3,
                "returncode_after_taskkill_tree": 1,
                "lingering_bundle_processes": [],
            },
            "network_tls_neural_assets_absent": True,
        }
        first = select_optimization_candidate.behavior_projection(matrix, "compact")
        changed = json.loads(json.dumps(matrix))
        changed["results"][-1].update(
            {"seconds": 1.0, "stdout_sha256": "b" * 64}
        )
        changed["timeout_reap"].update(
            {"root_pid": 987654, "observed_bundle_processes_before_kill": 1}
        )
        self.assertEqual(
            first,
            select_optimization_candidate.behavior_projection(changed, "compact"),
        )
        changed["results"][0]["stdout_sha256"] = "c" * 64
        with self.assertRaises(common.ReleaseError):
            select_optimization_candidate.behavior_projection(changed, "compact")

    def test_zip_physical_audit_rejects_trailing_bytes_and_comments(self) -> None:
        limits = common.ArchiveLimits(100, 1000, 5000, 200)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            trailing = root / "trailing.zip"
            with zipfile.ZipFile(trailing, "w") as archive:
                archive.writestr("root/file", b"value")
            with trailing.open("ab") as stream:
                stream.write(b"hidden")
            with self.assertRaises(common.ReleaseError):
                common.inspect_zip(trailing, limits=limits)
            commented = root / "commented.zip"
            with zipfile.ZipFile(commented, "w") as archive:
                archive.comment = b"hidden"
                archive.writestr("root/file", b"value")
            with self.assertRaises(common.ReleaseError):
                common.inspect_zip(commented, limits=limits)

    def test_normalized_zip_contract_rejects_timestamp_compression_attrs_version_and_flags(self) -> None:
        limits = common.ArchiveLimits(100, 1000, 5000, 200)
        epoch = 1_786_320_000
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle = root / "bundle"
            bundle.mkdir()
            (bundle / "kazstem.exe").write_bytes(b"MZ fixture payload")
            original = root / "original.zip"
            common.write_deterministic_zip(bundle, original, epoch=epoch, limits=limits)
            payload = original.read_bytes()
            eocd = payload.rfind(b"PK\x05\x06")
            central_offset = struct.unpack_from("<I", payload, eocd + 16)[0]
            cursor = central_offset
            file_central = None
            file_local = None
            while cursor < eocd:
                fields = struct.unpack_from("<I6H3I5H2I", payload, cursor)
                name_length, extra_length, comment_length = fields[10:13]
                name = payload[cursor + 46 : cursor + 46 + name_length].decode("utf-8")
                if name.endswith("kazstem.exe"):
                    file_central = cursor
                    file_local = fields[-1]
                    break
                cursor += 46 + name_length + extra_length + comment_length
            self.assertIsNotNone(file_central)
            self.assertIsNotNone(file_local)
            mutations = {
                "timestamp": [(file_central + 14, b"\x01\x00"), (file_local + 12, b"\x01\x00")],
                "compression": [(file_central + 10, b"\0\0"), (file_local + 8, b"\0\0")],
                "attributes": [(file_central + 38, b"\0\0\0\0")],
                "create-version": [(file_central + 4, b"\x14\x00")],
                "flags": [(file_central + 8, b"\0\x08"), (file_local + 6, b"\0\x08")],
            }
            for name, changes in mutations.items():
                with self.subTest(name=name):
                    changed = bytearray(payload)
                    for offset, value in changes:
                        changed[offset : offset + len(value)] = value
                    path = root / f"{name}.zip"
                    path.write_bytes(changed)
                    with self.assertRaises(common.ReleaseError):
                        common.inspect_zip(
                            path,
                            limits=limits,
                            contract=common.ZipOutputContract(epoch, (".exe",)),
                        )

    def test_nested_tar_physical_audit_rejects_nonzero_trailing_blocks(self) -> None:
        limits = common.ArchiveLimits(100, 1000, 10000, 200)
        with tempfile.TemporaryDirectory() as temporary:
            archive_path = Path(temporary) / "value.tar"
            payload = Path(temporary) / "payload"
            payload.write_bytes(b"value")
            with tarfile.open(archive_path, "w") as archive:
                archive.add(payload, arcname="top/payload")
            with archive_path.open("ab") as stream:
                stream.write(b"nonzero-hidden-tail")
            with self.assertRaises(common.ReleaseError):
                inspect_tar(archive_path, limits=limits)

    def test_magic_inventory_finds_neutral_extension_zip_tar_and_rejects_7z_rar(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "payload"
            root.mkdir()
            with zipfile.ZipFile(root / "upstream-zip.bin", "w") as archive:
                archive.writestr("top/file", b"value")
            payload = Path(temporary) / "source-file"
            payload.write_bytes(b"value")
            with tarfile.open(root / "upstream-tar.bin", "w") as archive:
                archive.add(payload, arcname="top/file")
            self.assertEqual(
                magic_archive_inventory(root),
                {
                    "upstream-tar.bin": "tar-raw",
                    "upstream-zip.bin": "zip",
                },
            )
            (root / "opaque.bin").write_bytes(b"7z\xbc\xaf'\x1c" + b"\0" * 32)
            with self.assertRaises(common.ReleaseError):
                magic_archive_inventory(root)
            (root / "opaque.bin").unlink()
            (root / "opaque.bin").write_bytes(b"Rar!\x1a\x07\x00" + b"\0" * 32)
            with self.assertRaises(common.ReleaseError):
                magic_archive_inventory(root)

    def test_strict_identity_accepts_complete_contract(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "identity.json"
            path.write_text(json.dumps(identity()), encoding="utf-8")
            self.assertEqual(common.load_identity(path)["release"], "0.2.3")

    def test_windows_adapter_validates_exact_v2_receipt_without_rebuilding(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            dist = root / "dist"
            source.mkdir()
            dist.mkdir()
            python_identity = root / "identity.json"
            python_receipt = root / "receipt.json"
            python_identity.write_bytes(b"{}\n")
            python_receipt.write_bytes(b"{}\n")
            wheel = dist / "kazstem-0.2.3-py3-none-any.whl"
            sdist = dist / "kazstem-0.2.3.tar.gz"
            wheel.write_bytes(b"wheel")
            sdist.write_bytes(b"sdist")
            value = identity()
            release_base = "https://github.com/amir-nuriyev/KazStem/releases/download/v0.2.3/"
            value["artifacts"]["wheel"] = common.artifact_record(
                wheel, release_base + wheel.name
            )
            value["artifacts"]["sdist"] = common.artifact_record(
                sdist, release_base + sdist.name
            )
            value["inputs"]["canonical_python_build_identity"] = common.file_record(
                python_identity
            )
            value["inputs"]["canonical_python_build_receipt"] = common.file_record(
                python_receipt
            )
            canonical_identity = {
                name: value[name]
                for name in (
                    "release",
                    "source_commit",
                    "source_tree",
                    "source_origin",
                    "source_ref",
                    "source_date_epoch",
                )
            }
            canonical_identity["artifacts"] = {
                name: {
                    "filename": value["artifacts"][name]["filename"],
                    "bytes": value["artifacts"][name]["bytes"],
                    "sha256": value["artifacts"][name]["sha256"],
                }
                for name in ("wheel", "sdist")
            }
            canonical_identity["canonicalizer"] = {
                "path": "packaging/build_canonical_python_artifacts.py",
                "file": value["inputs"]["canonical_python_builder"],
            }
            validator = types.SimpleNamespace(
                load_identity=mock.Mock(return_value=canonical_identity),
                validate_receipt=mock.Mock(return_value={"pass": True}),
            )
            with mock.patch.object(
                common, "_load_canonical_python_builder", return_value=validator
            ):
                observed = common.verify_canonical_python_release(
                    value,
                    source_root=source,
                    python_build_identity=python_identity,
                    python_build_receipt=python_receipt,
                    wheel=wheel,
                    sdist=sdist,
                )
            self.assertEqual(
                observed["receipt_file"],
                value["inputs"]["canonical_python_build_receipt"],
            )
            validator.validate_receipt.assert_called_once()
            receipt, = validator.validate_receipt.call_args.args
            self.assertEqual(receipt, {})
            self.assertEqual(
                validator.validate_receipt.call_args.kwargs["identity"],
                canonical_identity,
            )
            observed_output = validator.validate_receipt.call_args.kwargs["output_dir"]
            self.assertTrue(observed_output.samefile(dist))
            canonical_identity["source_commit"] = "0" * 40
            with mock.patch.object(
                common, "_load_canonical_python_builder", return_value=validator
            ), self.assertRaisesRegex(common.ReleaseError, "release source"):
                common.verify_canonical_python_release(
                    value,
                    source_root=source,
                    python_build_identity=python_identity,
                    python_build_receipt=python_receipt,
                    wheel=wheel,
                    sdist=sdist,
                )

    def test_python_build_receipt_consumes_v2_pair_and_rejects_changed_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            build_root = base / "build"
            frozen = build_root / "dist/kazstem"
            artifacts = build_root / "artifacts"
            source_packaging = build_root / "source/packaging/windows"
            shared_packaging = build_root / "source/packaging"
            for path in (frozen, artifacts, source_packaging):
                path.mkdir(parents=True, exist_ok=True)
            (frozen / "payload.bin").write_bytes(b"frozen")
            wheel = artifacts / "kazstem-0.2.3-py3-none-any.whl"
            sdist = artifacts / "kazstem-0.2.3.tar.gz"
            wheel.write_bytes(b"wheel")
            sdist.write_bytes(b"sdist")
            ledger = build_root / "freezer-ledger.json"
            ledger.write_bytes(b"{}\n")
            requirements = source_packaging / "build-requirements.lock.txt"
            requirements.write_bytes(b"build==1 --hash=sha256:" + b"0" * 64 + b"\n")
            canonical_builder = shared_packaging / "build_canonical_python_artifacts.py"
            canonical_builder.write_bytes(b"# fixture\n")
            canonical_receipt = base / "canonical-python-build-receipt.json"
            canonical_receipt.write_bytes(b"{}\n")
            bootstrap = base / "python.exe"
            write_amd64_pe(bootstrap)
            wheelhouse = base / "wheelhouse"
            wheelhouse.mkdir()
            (wheelhouse / "build.whl").write_bytes(b"offline")
            config = base / "optimization.json"
            config.write_bytes(
                common.json_bytes(
                    {
                        "schema": "kazstem-windows-optimization-config-v1",
                        "name": "compact",
                        "tool_versions": {
                            "python": "3.14.3",
                            "pyinstaller": "6.22.0",
                            "zlib": "1.3.1",
                        },
                        "switches": {
                            "noarchive": True,
                            "python_optimize": 0,
                            "strip": False,
                            "upx": False,
                        },
                    }
                )
            )
            python_identity = base / "python-build-identity.json"
            python_identity.write_bytes(b'{"schema":"kazstem-canonical-python-build-identity-v2"}\n')

            value = identity()
            for support in value["inputs"]["release_support_files"]:
                destination = build_root / "source" / support["path"]
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes((ROOT / support["path"]).read_bytes())
            release_base = "https://github.com/amir-nuriyev/KazStem/releases/download/v0.2.3/"
            value["inputs"]["bootstrap_python"] = common.pe_identity(bootstrap)
            value["inputs"]["source_payload_tree"] = common.tree_record(build_root / "source")
            value["inputs"]["build_wheelhouse_tree"] = common.tree_record(wheelhouse)
            value["inputs"]["optimization_config"] = common.file_record(config)
            value["inputs"]["canonical_python_build_identity"] = common.file_record(python_identity)
            value["inputs"]["canonical_python_build_receipt"] = common.file_record(canonical_receipt)
            value["inputs"]["canonical_python_builder"] = common.file_record(canonical_builder)
            value["inputs"]["frozen_tree"] = common.tree_record(frozen)
            value["inputs"]["base_ledger"] = common.file_record(ledger)
            value["artifacts"]["wheel"] = common.artifact_record(wheel, release_base + wheel.name)
            value["artifacts"]["sdist"] = common.artifact_record(sdist, release_base + sdist.name)
            value["optimization"]["candidates"][1]["config"] = common.file_record(config)
            for record in value["verification"]["evidence"]:
                record["generator"]["tool"]["file"] = common.file_record(bootstrap)
            refresh_subject(value)

            environment = {
                "COMSPEC": "<SYSTEM32>/cmd.exe",
                "HOME": "<FRESH-BUILD-ROOT>/home",
                "LC_ALL": "C",
                "PATH": "<BOOTSTRAP-PYTHON-DIR>;<SYSTEM32>;<WINDOWS>",
                "PATHEXT": ".COM;.EXE;.BAT;.CMD",
                "PIP_DISABLE_PIP_VERSION_CHECK": "1",
                "PIP_FIND_LINKS": "<WHEELHOUSE>",
                "PIP_NO_INDEX": "1",
                "PIP_NO_INPUT": "1",
                "PYINSTALLER_CONFIG_DIR": "<FRESH-BUILD-ROOT>/pyinstaller-cache",
                "PYTHONHASHSEED": "0",
                "PYTHONNOUSERSITE": "1",
                "PYTHONDONTWRITEBYTECODE": "1",
                "SOURCE_DATE_EPOCH": str(value["source_date_epoch"]),
                "SYSTEMROOT": "<WINDOWS>",
                "TEMP": "<FRESH-BUILD-ROOT>/tmp",
                "TMP": "<FRESH-BUILD-ROOT>/tmp",
                "TZ": "UTC",
                "USERPROFILE": "<FRESH-BUILD-ROOT>/home",
                "WINDIR": "<WINDOWS>",
            }
            build_source_boundary = common.source_boundary_contract(
                value, "packaging/windows/build_python_freezer.py"
            )
            build_source_boundary.pop("bootstrap")
            receipt = {
                "schema": "kazstem-windows-python-freezer-build-v2",
                "result": "pass",
                "label": "a",
                "source": {
                    "commit": value["source_commit"],
                    "tree": value["source_tree"],
                    "origin": value["source_origin"],
                    "ref": value["source_ref"],
                    "payload_tree": value["inputs"]["source_payload_tree"],
                },
                "source_receipt": value["inputs"]["source_receipt"],
                "source_boundary": build_source_boundary,
                "root_identity": {
                    "logical_label": "a",
                    "st_dev": build_root.stat().st_dev,
                    "st_ino": build_root.stat().st_ino,
                },
                "canonical_python_validation": {
                    "identity_schema": "kazstem-canonical-python-build-identity-v2",
                    "receipt_schema": "kazstem-canonical-python-build-receipt-v2",
                    "execution_platform": {"system": "linux", "machine": "x86_64"},
                    "linux_roundtrip_wheel_and_sdist_identical": True,
                    "validated_by": value["inputs"]["canonical_python_builder"],
                    "windows_rebuild_performed": False,
                },
                "build_inputs": {
                    "bootstrap_python": value["inputs"]["bootstrap_python"],
                    "wheelhouse_tree": value["inputs"]["build_wheelhouse_tree"],
                    "canonical_python_builder": value["inputs"]["canonical_python_builder"],
                    "canonical_python_build_identity": value["inputs"]["canonical_python_build_identity"],
                    "canonical_python_build_receipt": value["inputs"]["canonical_python_build_receipt"],
                    "optimization_config": value["inputs"]["optimization_config"],
                    "requirements": common.file_record(requirements),
                    "release_support_files": value["inputs"]["release_support_files"],
                },
                "source_tree_snapshots": {
                    "before": value["inputs"]["source_payload_tree"],
                    "after": value["inputs"]["source_payload_tree"],
                },
                "execution": {
                    "commands": common.python_build_commands(value, noarchive=True),
                    "environment": environment,
                    "tool_versions": {
                        "python": "3.14.3",
                        "pip": "26.0",
                        "build": "1.4.0",
                        "setuptools": "82.0.1",
                        "wheel": "0.46.3",
                        "pyinstaller": "6.22.0",
                        "zlib": "1.3.1",
                    },
                    "process_contract": {
                        "implementation": "windows-job-object-kill-on-close",
                        "captures_direct_child_and_descendants": True,
                        "combined_output_limit_bytes": 16 * 1024 * 1024,
                        "timeout_reaps_process_tree": True,
                        "launch_order": "create-suspended-assign-job-start-reader-resume",
                        "active_processes_zero_before_return": True,
                        "descendants_after_direct_exit_fail": True,
                    },
                },
                "outputs": {
                    "frozen_tree": common.tree_record(frozen),
                    "wheel": value["artifacts"]["wheel"],
                    "sdist": value["artifacts"]["sdist"],
                    "base_ledger": common.file_record(ledger),
                },
                "coverage": {
                    "assertions": 10,
                    "cases": 1,
                    "checks": [
                        "base-ledger", "canonical-artifacts-consumed",
                        "canonical-linux-sdist-roundtrip-receipt",
                        "canonical-v2-identity-receipt", "fresh-root", "frozen-tree",
                        "hash-locked-build-environment", "no-network-runtime-modules",
                        "python-artifact-source-parity", "source-tree-unchanged",
                    ],
                },
            }

            arguments = dict(
                identity=value,
                label="a",
                build_root=build_root,
                bootstrap_python=bootstrap,
                wheelhouse=wheelhouse,
                optimization_config=config,
                python_build_identity=python_identity,
                python_build_receipt=canonical_receipt,
                frozen=frozen,
                wheel=wheel,
                sdist=sdist,
                base_ledger=ledger,
            )
            canonical_contract = {
                "receipt": {
                    "execution_platform": {"system": "linux", "machine": "x86_64"},
                    "roundtrip": {"wheel_and_sdist_identical": True},
                }
            }
            with mock.patch.object(
                common,
                "verify_canonical_python_release",
                return_value=canonical_contract,
            ):
                common.verify_python_build_receipt(receipt, **arguments)

            network_eligible = json.loads(json.dumps(receipt))
            network_eligible["execution"]["commands"][1]["argv"].remove("--no-index")
            with mock.patch.object(
                common,
                "verify_canonical_python_release",
                return_value=canonical_contract,
            ), self.assertRaises(common.ReleaseError):
                common.verify_python_build_receipt(network_eligible, **arguments)
            changed_config = base / "changed-config.json"
            changed_config.write_bytes(config.read_bytes() + b" ")
            with mock.patch.object(
                common,
                "verify_canonical_python_release",
                return_value=canonical_contract,
            ), self.assertRaises(common.ReleaseError):
                common.verify_python_build_receipt(
                    receipt,
                    **{**arguments, "optimization_config": changed_config},
                )
            changed_bootstrap = base / "changed-python.exe"
            changed_bootstrap.write_bytes(bootstrap.read_bytes() + b"changed")
            with mock.patch.object(
                common,
                "verify_canonical_python_release",
                return_value=canonical_contract,
            ), self.assertRaises(common.ReleaseError):
                common.verify_python_build_receipt(
                    receipt,
                    **{**arguments, "bootstrap_python": changed_bootstrap},
                )

    def test_identity_binds_runtime_platform_and_all_evidence(self) -> None:
        mutations = []
        value = identity()
        value["inputs"]["runtime_tree"]["bundle_id"] = "0" * 64
        mutations.append(value)
        value = identity()
        value["inputs"]["resource_tree"]["bundle_id"] = (
            "bf1f31ff6e5860585b9e4134f12dcfb9d6df8030ee87b368e5a5f29eb45c1188"
        )
        mutations.append(value)
        value = identity()
        value["platform"]["unsigned"] = False
        mutations.append(value)
        value = identity()
        value["verification"]["evidence"] = value["verification"]["evidence"][:-1]
        mutations.append(value)
        for index, candidate in enumerate(mutations):
            with self.subTest(index=index), tempfile.TemporaryDirectory() as temporary:
                path = Path(temporary) / "identity.json"
                path.write_text(json.dumps(candidate), encoding="utf-8")
                with self.assertRaises(common.ReleaseError):
                    common.load_identity(path)

    def test_portable_path_rejects_windows_escapes_ads_devices_and_collisions(self) -> None:
        bad = [
            "../escape",
            "/absolute",
            r"C:\escape",
            "C:drive-relative",
            r"dir\file",
            "safe/file:stream",
            "safe/CON.txt",
            "safe/name. ",
            "safe/e\u0301.txt",
            "safe/line\nfeed",
        ]
        for value in bad:
            with self.subTest(value=value), self.assertRaises(common.ReleaseError):
                common.portable_path(value, label="test")
        self.assertEqual(common.portable_path("Қазақ/é.txt", label="test"), "Қазақ/é.txt")

    def test_zip_audit_rejects_duplicate_case_reserved_and_symlink_members(self) -> None:
        limits = common.ArchiveLimits(100, 1000, 5000, 200)
        cases = [
            [("root/A.txt", b"a", None), ("root/a.txt", b"b", None)],
            [("root/NUL.txt", b"a", None)],
            [("root/name:ads", b"a", None)],
            [("root/e\u0301.txt", b"a", None)],
            [("root/link", b"target", stat.S_IFLNK | 0o777)],
        ]
        for index, members in enumerate(cases):
            with self.subTest(index=index), tempfile.TemporaryDirectory() as temporary:
                path = Path(temporary) / "bad.zip"
                with zipfile.ZipFile(path, "w") as archive:
                    for name, payload, mode in members:
                        info = zipfile.ZipInfo(name)
                        if mode is not None:
                            info.create_system = 3
                            info.external_attr = mode << 16
                        archive.writestr(info, payload)
                with self.assertRaises(common.ReleaseError):
                    common.inspect_zip(path, limits=limits)

    def test_zip_audit_enforces_member_and_total_caps(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "large.zip"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("root/file", b"12345")
            with self.assertRaises(common.ReleaseError):
                common.inspect_zip(path, limits=common.ArchiveLimits(10, 4, 10, 100))

    def test_tree_inventory_rejects_hardlinks(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "tree"
            root.mkdir()
            first = root / "first"
            first.write_bytes(b"x")
            os.link(first, root / "second")
            with self.assertRaises(common.ReleaseError):
                common.tree_inventory(root)

    def test_deterministic_zip_is_identical_across_distinct_roots(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            roots = []
            for name in ("a", "b"):
                root = base / name / "bundle"
                (root / "dir").mkdir(parents=True)
                (root / "dir/Қазақ.txt").write_bytes("бір\n".encode("utf-8"))
                (root / "kazstem.exe").write_bytes(b"MZ fixture")
                roots.append(root)
            limits = common.ArchiveLimits(100, 1000, 5000, 200)
            outputs = [base / "a.zip", base / "b.zip"]
            for root, output in zip(roots, outputs):
                common.write_deterministic_zip(root, output, epoch=1_786_320_000, limits=limits)
            self.assertEqual(outputs[0].read_bytes(), outputs[1].read_bytes())
            extracted = common.safe_extract_zip(
                outputs[0],
                base / "fresh",
                limits=limits,
                contract=common.ZipOutputContract(
                    1_786_320_000, (".exe", ".dll", ".pyd")
                ),
            )
            self.assertEqual(
                (extracted / "dir/Қазақ.txt").read_bytes(),
                "бір\n".encode("utf-8"),
            )

    def test_pe_identity_requires_amd64_pe32_plus_and_reports_certificate_table(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "value.exe"
            data = bytearray(0x80 + 24 + 240)
            data[:2] = b"MZ"
            struct.pack_into("<I", data, 0x3C, 0x80)
            data[0x80:0x84] = b"PE\0\0"
            struct.pack_into("<HHIIIHH", data, 0x84, 0x8664, 3, 123, 0, 0, 240, 2)
            optional = 0x80 + 24
            struct.pack_into("<H", data, optional, 0x20B)
            struct.pack_into("<II", data, optional + 144, 4096, 512)
            path.write_bytes(data)
            record = common.pe_identity(path)
            self.assertEqual(record["machine"], "AMD64")
            self.assertTrue(record["authenticode_embedded"])
            data[0x84:0x86] = struct.pack("<H", 0x14C)
            path.write_bytes(data)
            with self.assertRaises(common.ReleaseError):
                common.pe_identity(path)

    def test_relative_evidence_rejects_drive_unc_and_posix_roots(self) -> None:
        for leaked in (r"C:\runner\work", r"\\server\share\x", "/home/runner/work"):
            with self.subTest(leaked=leaked), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / "evidence"
                root.mkdir()
                (root / "record.json").write_text(json.dumps({"path": leaked}), encoding="utf-8")
                with self.assertRaises(common.ReleaseError):
                    common.assert_relative_evidence(root)

    def test_nested_tar_rejects_escaping_links_and_special_entries(self) -> None:
        limits = common.ArchiveLimits(100, 1000, 5000, 200)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            link_archive = root / "link.tar"
            with tarfile.open(link_archive, "w") as archive:
                info = tarfile.TarInfo("top/link")
                info.type = tarfile.SYMTYPE
                info.linkname = "../../escape"
                archive.addfile(info)
            with self.assertRaises(common.ReleaseError):
                inspect_tar(link_archive, limits=limits)
            special_archive = root / "special.tar"
            with tarfile.open(special_archive, "w") as archive:
                info = tarfile.TarInfo("top/fifo")
                info.type = tarfile.FIFOTYPE
                archive.addfile(info)
            with self.assertRaises(common.ReleaseError):
                inspect_tar(special_archive, limits=limits)

    @unittest.skipUnless(
        os.environ.get("KAZSTEM_WINDOWS_RUNTIME_FIXTURE"),
        "set KAZSTEM_WINDOWS_RUNTIME_FIXTURE to the audited 17a69ae runtime",
    )
    def test_end_to_end_ready_assembler_and_static_audit_with_bound_runtime(self) -> None:
        runtime = Path(os.environ["KAZSTEM_WINDOWS_RUNTIME_FIXTURE"]).resolve(strict=True)
        self.assertEqual(runtime.name, "17a69ae11ff3fd92a555e8c95571223cbe8b217ec409a0b9b368f0aed90ee465")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            frozen = root / "frozen"
            resources = root / "resources"
            documents = root / "documents"
            frozen_lock = frozen / "_internal/qazmorph/platform_runtime_assets.lock.json"
            frozen_lock.parent.mkdir(parents=True)
            resources.mkdir()
            documents.mkdir()
            lock_source = ROOT / "src/qazmorph/platform_runtime_assets.lock.json"
            frozen_lock.write_bytes(lock_source.read_bytes())
            launcher_source = runtime / "usr/bin/hfst-proc.exe"
            (frozen / "kazstem.exe").write_bytes(launcher_source.read_bytes())
            resource_manifest = resources / "manifest.json"
            resource_manifest.write_text(
                json.dumps({"bundle_id": "f03e703d3e2a67044a7d91fd7d575b92cb4e61aa782fb67cff91b0a5ff0ebd5a"}),
                encoding="utf-8",
            )
            (resources / "fixture.bin").write_bytes(b"fixture")
            (documents / "LICENSE").write_bytes((ROOT / "LICENSE").read_bytes())
            ledger = root / "ledger.json"
            ledger.write_text('{"schema":"fixture-ledger"}\n', encoding="utf-8")
            paired_source = root / "kazstem-0.2.3-windows-server-2022-x86_64-corresponding-source.zip"
            paired_source.write_bytes(b"source fixture")
            sdist = root / "kazstem-0.2.3.tar.gz"
            sdist.write_bytes(b"sdist fixture")
            wheel = root / "kazstem-0.2.3-py3-none-any.whl"
            with zipfile.ZipFile(wheel, "w") as archive:
                archive.writestr("qazmorph/platform_runtime_assets.lock.json", lock_source.read_bytes())

            value = identity()
            release_download = "https://github.com/amir-nuriyev/KazStem/releases/download/v0.2.3/"
            def observed_artifact(path: Path) -> dict[str, object]:
                return {
                    "filename": path.name,
                    "bytes": path.stat().st_size,
                    "sha256": common.sha256_file(path),
                    "url": release_download + path.name,
                }
            value["artifacts"]["wheel"] = observed_artifact(wheel)
            value["artifacts"]["sdist"] = observed_artifact(sdist)
            value["artifacts"]["corresponding_source"] = observed_artifact(paired_source)
            value["inputs"]["frozen_tree"] = common.tree_record(frozen)
            value["inputs"]["resource_tree"] = {
                "bundle_id": "f03e703d3e2a67044a7d91fd7d575b92cb4e61aa782fb67cff91b0a5ff0ebd5a",
                "manifest": common.file_record(resource_manifest),
                "tree": common.tree_record(resources),
            }
            value["inputs"]["runtime_tree"] = {
                "bundle_id": runtime.name,
                "manifest": common.file_record(runtime / "manifest.json"),
                "tree": common.tree_record(runtime),
            }
            value["inputs"]["platform_lock"] = common.file_record(lock_source)
            value["inputs"]["base_ledger"] = common.file_record(ledger)
            value["inputs"]["binary_readme_template"] = common.file_record(WINDOWS / "BINARY-README.template.md")
            value["inputs"]["source_readme_template"] = common.file_record(WINDOWS / "CORRESPONDING-SOURCE-README.template.md")
            value["inputs"]["documents"] = [
                {"source": "LICENSE", "destination": "LICENSE", "file": common.file_record(documents / "LICENSE")},
            ]
            value["ready_run"]["launcher"]["file"] = common.file_record(frozen / "kazstem.exe")
            value["ready_run"]["required_paths"] = [
                ".qazmorph/resources/manifest.json",
                "README-WINDOWS.md",
                "kazstem.exe",
                "verification/BUNDLE-MANIFEST.json",
            ]
            value["archive_limits"]["ready_run"].update(
                {"max_file_bytes": 80_000_000, "max_total_bytes": 200_000_000}
            )
            refresh_subject(value)
            identity_path = root / "identity.json"
            identity_path.write_bytes(common.json_bytes(value))

            observation = root / "observation.json"
            candidate = root / value["artifacts"]["ready_run"]["filename"]
            arguments = dict(
                identity=identity_path,
                frozen=frozen,
                resources=resources,
                runtime=runtime,
                platform_lock=lock_source,
                documents=documents,
                binary_readme_template=WINDOWS / "BINARY-README.template.md",
                base_ledger=ledger,
                wheel=wheel,
                sdist=sdist,
                corresponding_source=paired_source,
            )
            with self.assertRaises(common.ReleaseError) as observed_error:
                assemble_ready_run.assemble(
                    argparse.Namespace(
                        **arguments,
                        work_root=root / "observe-work",
                        output=candidate,
                        observation=observation,
                    )
                )
            if not observation.is_file():
                self.fail(f"assembler failed before observation: {observed_error.exception}")
            value["artifacts"]["ready_run"] = json.loads(observation.read_text())
            refresh_subject(value)
            identity_path.write_bytes(common.json_bytes(value))
            result = assemble_ready_run.assemble(
                argparse.Namespace(
                    **arguments,
                    work_root=root / "verified-work",
                    output=candidate,
                    observation=None,
                )
            )
            self.assertEqual(result["result"], "pass")
            audited = audit_ready_run_archive.audit(
                argparse.Namespace(
                    identity=identity_path,
                    release_identity_sha256=common.identity_sha256(identity_path),
                    archive=candidate,
                )
            )
            self.assertEqual(audited["result"], "pass")
            self.assertEqual(audited["runtime_files"], 19)


if __name__ == "__main__":
    unittest.main()
