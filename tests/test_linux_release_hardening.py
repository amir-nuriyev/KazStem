from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import py_compile
import shutil
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock


PROJECT_ROOT = Path(__file__).resolve().parents[1]
LINUX_TOOLS = PROJECT_ROOT / "packaging" / "linux"
sys.path.insert(0, str(LINUX_TOOLS))

import release_common as common  # noqa: E402
import audit_corresponding_source_archive as source_auditor  # noqa: E402
import audit_elf_closure as elf_auditor  # noqa: E402
import audit_ready_run_archive as ready_auditor  # noqa: E402
import benchmark_compat_linux as compatibility_benchmark  # noqa: E402
import blackbox_linux_bundle as blackbox_gate  # noqa: E402
import finalize_release as finalizer  # noqa: E402
import generate_gate_evidence as gate_generator  # noqa: E402
import generate_compression_comparison as compression_generator  # noqa: E402
import generate_optimization_ledger as optimization_generator  # noqa: E402
import normalize_runtime_provenance as provenance_normalizer  # noqa: E402
import practical_matrix_linux as practical_gate  # noqa: E402
import run_network_workload as network_workload  # noqa: E402
import run_source_suite as source_suite  # noqa: E402
import verify_remote_tag as remote_tag  # noqa: E402
import verify_python_reproducibility as python_reproducibility  # noqa: E402
from tests.test_linux_release_tooling import ReleaseFixture, write_json  # noqa: E402


class ActualGateProducerSmokeTests(unittest.TestCase):
    @staticmethod
    def _invoke_main(module: object, arguments: list[str]) -> int:
        with mock.patch.object(
            sys,
            "argv",
            [str(Path(module.__file__).resolve()), *arguments],
        ), contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(
            io.StringIO()
        ):
            return int(module.main())

    def test_every_real_gate_producer_emits_strictly_valid_evidence(self) -> None:
        """Run every checked producer to a successful, finalizer-valid payload."""

        with tempfile.TemporaryDirectory() as temporary:
            fixture = ReleaseFixture(Path(temporary))
            modules = {
                "blackbox": blackbox_gate,
                "compatibility-performance": compatibility_benchmark,
                "compression-comparison": compression_generator,
                "elf-closure": elf_auditor,
                "network-trace": network_workload,
                "optimization-ledger": optimization_generator,
                "practical": practical_gate,
                "python-reproducibility": python_reproducibility,
                "ready-archive-audit": ready_auditor,
                "runtime-provenance": provenance_normalizer,
                "source-archive-audit": source_auditor,
                "source-authority": remote_tag,
                "source-suite": source_suite,
            }
            self.assertEqual(set(modules), set(common.GATE_SCRIPT_PATHS))
            records = {
                record["gate"]: record
                for record in fixture.identity["verification"]["evidence"]
            }
            for gate, module in modules.items():
                expected = (PROJECT_ROOT / common.GATE_SCRIPT_PATHS[gate]).resolve()
                self.assertEqual(Path(module.__file__).resolve(), expected)
                records[gate]["execution"]["script"]["file"] = common.file_record(
                    expected
                )

            suite_root = fixture.root / "actual-source-suite"
            tests_root = suite_root / "tests"
            tests_root.mkdir(parents=True)
            (tests_root / "__init__.py").write_text("", encoding="utf-8")
            (tests_root / "test_gate_smoke.py").write_text(
                "import unittest\n"
                "import qazmorph\n\n"
                "class ActualGateSmokeCase(unittest.TestCase):\n"
                "    def test_00(self): self.assertEqual(qazmorph.VALUE, 1)\n"
                "    def test_01(self): self.assertTrue(qazmorph.__file__)\n"
                "    def test_02(self): self.assertEqual(1 + 1, 2)\n"
                "    def test_03(self): self.assertFalse(False)\n",
                encoding="utf-8",
            )
            test_ids = [
                f"tests.test_gate_smoke.ActualGateSmokeCase.test_{index:02d}"
                for index in range(4)
            ]
            test_ids_sha256 = hashlib.sha256(
                ("\n".join(test_ids) + "\n").encode("utf-8")
            ).hexdigest()
            source_expectations = records["source-suite"]["execution"][
                "payload_expectations"
            ]
            source_expectations.update(
                {
                    "tests_discovered": 4,
                    "test_ids_sha256": test_ids_sha256,
                    "skipped": 0,
                    "expected_failures": 0,
                }
            )
            fixture.evidence_payloads["source-suite.json"].update(
                {
                    "tests_run": 4,
                    "tests_discovered": 4,
                    "test_ids_sha256": test_ids_sha256,
                    "skipped": 0,
                    "expected_failures": 0,
                }
            )
            workload_record = {
                "workload_bytes": len(network_workload.WORKLOAD),
                "workload_lines": len(network_workload.WORKLOAD.splitlines()),
                "workload_sha256": hashlib.sha256(
                    network_workload.WORKLOAD
                ).hexdigest(),
            }
            records["network-trace"]["execution"][
                "payload_expectations"
            ].update(workload_record)
            fixture.evidence_payloads["network-trace.json"].update(workload_record)
            fixture.write_identity()

            reproduction, _ = fixture.seal_artifacts()
            ready_archive = reproduction / fixture.ready_name
            source_archive = reproduction / fixture.source_name
            canonical_artifacts = fixture.root / "actual-canonical-artifacts"
            canonical_artifacts.mkdir()
            shutil.copyfile(
                fixture.wheel, canonical_artifacts / fixture.wheel_name
            )
            shutil.copyfile(
                fixture.sdist, canonical_artifacts / fixture.sdist_name
            )
            members = common.inspect_tar(
                ready_archive,
                limits=common.archive_limits(fixture.identity, "ready_run"),
                expected_top=fixture.identity["ready_run"]["top_level"],
            )
            ready_root = common.extract_validated_tar(
                ready_archive,
                fixture.root / "actual-ready-extract",
                members=members,
                limits=common.archive_limits(fixture.identity, "ready_run"),
            )
            evidence = fixture.root / "actual-producer-evidence"
            evidence.mkdir()
            produced: set[str] = set()

            def accept(gate: str, payload: dict[str, object]) -> dict[str, object]:
                destination = evidence / records[gate]["path"]
                write_json(destination, fixture.wrap_evidence_payload(gate, payload))
                records[gate]["file"] = common.file_record(destination)
                fixture.write_identity()
                validated = finalizer._gate_evidence(
                    destination,
                    gate,
                    records[gate]["kind"],
                    records[gate]["subjects"],
                    fixture.identity,
                    common.identity_sha256(fixture.identity_path),
                    canonical_artifacts,
                )
                produced.add(gate)
                self.assertTrue(
                    validated.get("pass") is True
                    or validated.get("result") == "pass",
                    gate,
                )
                return validated

            ready_raw = fixture.root / "actual-ready-audit.json"
            accept(
                "ready-archive-audit",
                ready_auditor.audit(
                    argparse.Namespace(
                        identity=fixture.identity_path,
                        archive=ready_archive,
                        fresh_root=fixture.root / "actual-ready-audit-root",
                        output=ready_raw,
                    )
                ),
            )
            source_raw = fixture.root / "actual-source-audit.json"
            accept(
                "source-archive-audit",
                source_auditor.audit(
                    argparse.Namespace(
                        identity=fixture.identity_path,
                        archive=source_archive,
                        fresh_root=fixture.root / "actual-source-audit-root",
                        output=source_raw,
                    )
                ),
            )

            compression_payload = compression_generator.generate(
                argparse.Namespace(
                    identity=fixture.identity_path,
                    repository=fixture.repository,
                    artifact_dir=reproduction,
                    producer_dir=reproduction,
                    output=fixture.root / "actual-compression.json",
                    timeout=60,
                )
            )
            accept("compression-comparison", compression_payload)

            blackbox_output = fixture.root / "actual-blackbox.json"
            blackbox_summary = {
                "schema": "kazstem-linux-blackbox-v1",
                "root": ready_root.name,
                "tests": 13,
                "results": [{"name": f"minimal-{index:02d}"} for index in range(13)],
                "source_checksums": "verified by the paired-source gate",
                "symlinks": [
                    {"path": "mystem-kz", "target": "kazstem"},
                    {"path": "qazmorph", "target": "kazstem"},
                ],
                "unsupported_special_entries": [],
                "neural_weight_files": [],
            }
            with mock.patch.object(
                blackbox_gate,
                "read_json",
                return_value={
                    "bundle_id": fixture.resource_id,
                    "version": "fixture-resource-v1",
                },
            ), mock.patch.object(
                blackbox_gate.Gate,
                "execute",
                return_value=blackbox_summary,
            ):
                self.assertEqual(
                    self._invoke_main(
                        blackbox_gate,
                        [
                            str(ready_root),
                            "--identity",
                            str(fixture.identity_path),
                            "--json",
                            str(blackbox_output),
                        ],
                    ),
                    0,
                )
            accept("blackbox", json.loads(blackbox_output.read_text()))

            practical_output = fixture.root / "actual-practical.json"
            practical_summary = {
                "schema": "kazstem-linux-practical-matrix-v1",
                "root": ready_root.name,
                "source_commit": fixture.commit,
                "host": {"platform": "fixture", "machine": "fixture", "python": "fixture"},
                "cases": 70,
                "results": [{"name": f"minimal-{index:02d}"} for index in range(70)],
                "profiles": {},
                "coverage": {},
                "bundle_fingerprint_unchanged": True,
                "read_only_resource_runtime_unchanged": True,
                "lingering_native_processes": [],
                "network_tls_modules_absent": True,
                "neural_weights": [],
                "optimization_review": {
                    "additional_pruning_accepted": [],
                    "decision": "minimal fixture retains the checked bundle",
                    "retained": {},
                },
                "result": "pass",
            }
            with mock.patch.object(
                practical_gate.Matrix,
                "execute",
                return_value=practical_summary,
            ):
                self.assertEqual(
                    self._invoke_main(
                        practical_gate,
                        [
                            str(ready_root),
                            "--identity",
                            str(fixture.identity_path),
                            "--wheel",
                            str(fixture.wheel),
                            "--json",
                            str(practical_output),
                        ],
                    ),
                    0,
                )
            accept("practical", json.loads(practical_output.read_text()))

            def fake_benchmark_run(
                arguments: list[str], **_kwargs: object
            ) -> subprocess.CompletedProcess[bytes]:
                source = Path(arguments[-2])
                destination = Path(arguments[-1])
                destination.write_text(
                    json.dumps(
                        [{"text": source.read_text(encoding="utf-8")}],
                        ensure_ascii=False,
                    ),
                    encoding="utf-8",
                )
                return subprocess.CompletedProcess(
                    arguments,
                    0,
                    b"",
                    b"Maximum resident set size (kbytes): 12\n",
                )

            compatibility_output = fixture.root / "actual-compatibility.json"
            with mock.patch.object(
                compatibility_benchmark.subprocess,
                "run",
                side_effect=fake_benchmark_run,
            ):
                self.assertEqual(
                    self._invoke_main(
                        compatibility_benchmark,
                        [
                            str(ready_root),
                            "--identity",
                            str(fixture.identity_path),
                            "--output",
                            str(compatibility_output),
                            "--characters",
                            "1000",
                            "--runs",
                            "2",
                            "--timeout",
                            "30",
                        ],
                    ),
                    0,
                )
            accept(
                "compatibility-performance",
                json.loads(compatibility_output.read_text()),
            )

            def fake_elf_command(arguments: list[str], **_kwargs: object) -> str:
                if arguments[:2] == ["readelf", "-dW"]:
                    return ""
                if arguments[0] == "ldd":
                    return "statically linked\n"
                if arguments[:2] == ["readelf", "--version-info"]:
                    return ""
                if arguments[:2] == ["readelf", "-hW"]:
                    return "Machine: Advanced Micro Devices X86-64\n"
                raise AssertionError(arguments)

            elf_output = fixture.root / "actual-elf.json"
            with mock.patch.object(
                elf_auditor,
                "is_elf",
                side_effect=lambda path: path.name == "kazstem" and path.is_file(),
            ), mock.patch.object(
                elf_auditor,
                "command",
                side_effect=fake_elf_command,
            ):
                self.assertEqual(
                    self._invoke_main(
                        elf_auditor,
                        [
                            str(ready_root),
                            "--identity",
                            str(fixture.identity_path),
                            "--output",
                            str(elf_output),
                        ],
                    ),
                    0,
                )
            accept("elf-closure", json.loads(elf_output.read_text()))

            network_output = fixture.root / "actual-network.json"
            network_result = types.SimpleNamespace(
                returncode=0,
                stdout=b'[{"text":"minimal network-free fixture"}]\n',
                stderr=b"",
                containment={
                    "mechanism": "fixture-supervisor",
                    "observed_descendants": 0,
                    "final_descendants": 0,
                },
                observed_descendants=0,
            )
            with mock.patch.object(
                network_workload,
                "run_bounded",
                return_value=network_result,
            ):
                accept(
                    "network-trace",
                    network_workload.run(
                        argparse.Namespace(
                            identity=fixture.identity_path,
                            ready_run=ready_archive,
                            output=network_output,
                            timeout=30,
                        )
                    ),
                )

            runtime_root = next(
                (ready_root / ".qazmorph/platform-runtimes").iterdir()
            )
            runtime_manifest = runtime_root / "manifest.json"
            runtime_executable = runtime_root / "usr/bin/hfst-proc"
            relative_libraries = ["usr/lib/x86_64-linux-gnu", "usr/lib"]
            absent_loader = {
                "ambient_present": False,
                "removed_from_helper_environment": True,
                "sha256": None,
            }
            raw_environment = {
                name: dict(absent_loader)
                for name in provenance_normalizer.LOADER_OVERRIDE_VARIABLES
            }
            raw_environment["GLIBC_TUNABLES"] = dict(absent_loader)
            raw_environment["LD_LIBRARY_PATH"].update(
                {
                    "helper_value_source": "manifest-bound-runtime",
                    "helper_relative_paths": relative_libraries,
                }
            )
            raw_environment["loader_policy"] = {
                "schema": "qazmorph-native-helper-loader-environment-v2",
                "captured_name_policy": {
                    "exact_uppercase_prefixes": ["LD_", "DYLD_"],
                    "exact_names": ["GLIBC_TUNABLES"],
                },
                "ambient_records": {},
                "glibc_tunables": dict(absent_loader),
                "clean_parent_startup": True,
                "all_ambient_values_removed_from_helper_environment": True,
                "linux_helper_ld_library_path": {
                    "source": "manifest-bound-runtime",
                    "relative_paths": relative_libraries,
                },
            }
            raw_provenance = {
                "official": True,
                "verified": True,
                "non_official_reasons": [],
                "active_runtime": {
                    "bundle_id": fixture.runtime_id,
                    "platform_lock": {
                        "bundle_id": fixture.runtime_id,
                        "manifest": fixture.identity["inputs"]["runtime_tree"][
                            "manifest"
                        ],
                        "resource_bundle_ids": [fixture.resource_id],
                    },
                },
                "toolchain_manifest": {
                    "bundle_id": fixture.runtime_id,
                    **common.file_record(runtime_manifest),
                    "path": str(runtime_manifest),
                    "verified": True,
                },
                "executables": {
                    "hfst-proc": {
                        **common.file_record(runtime_executable),
                        "path": str(runtime_executable),
                        "verified": True,
                    }
                },
                "environment": raw_environment,
            }
            raw_provenance_path = fixture.root / "actual-runtime-raw.json"
            write_json(raw_provenance_path, raw_provenance)
            accept(
                "runtime-provenance",
                provenance_normalizer.normalize(
                    argparse.Namespace(
                        identity=fixture.identity_path,
                        bundle_root=ready_root,
                        input=raw_provenance_path,
                        output=fixture.root / "actual-runtime.json",
                    )
                ),
            )

            expected_remote = (
                f"{fixture.source_tag_object}\t{fixture.source_ref}\n"
                f"{fixture.commit}\t{fixture.source_ref}^{{}}\n"
            ).encode("ascii")
            bounded_results = [
                types.SimpleNamespace(
                    returncode=0,
                    stdout=(fixture.git_version + "\n").encode("utf-8"),
                    stderr=b"",
                ),
                types.SimpleNamespace(
                    returncode=0,
                    stdout=expected_remote,
                    stderr=b"",
                ),
            ]
            with mock.patch.object(
                remote_tag,
                "run_bounded",
                side_effect=bounded_results,
            ):
                accept(
                    "source-authority",
                    remote_tag.verify(
                        argparse.Namespace(
                            identity=fixture.identity_path,
                            output=fixture.root / "actual-source-authority.json",
                        )
                    ),
                )

            source_suite_output = fixture.root / "actual-source-suite.json"
            source_suite_completed = subprocess.run(
                [
                    sys.executable,
                    str(Path(source_suite.__file__).resolve()),
                    "--identity",
                    str(fixture.identity_path),
                    "--wheel",
                    str(fixture.wheel),
                    "--sdist",
                    str(fixture.sdist),
                    "--pip-wheelhouse",
                    str(fixture.python_freezer_wheelhouse),
                    "--output",
                    str(source_suite_output),
                ],
                cwd=suite_root,
                env={
                    **os.environ,
                    "PYTHONDONTWRITEBYTECODE": "1",
                    "PYTHONPYCACHEPREFIX": str(fixture.root / "source-suite-pycache"),
                },
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=180,
                check=False,
            )
            self.assertEqual(
                source_suite_completed.returncode,
                0,
                source_suite_completed.stderr.decode("utf-8", "replace"),
            )
            accept("source-suite", json.loads(source_suite_output.read_text()))

            reproduction_workspace = fixture.root / "actual-python-reproduction"
            repro_payload = python_reproducibility.verify(
                argparse.Namespace(
                    identity=fixture.identity_path,
                    repository=fixture.repository,
                    canonical_artifacts=canonical_artifacts,
                    python_build_identity=fixture.python_build_identity_path,
                    python_wheelhouse=fixture.python_wheelhouse,
                    python_freezer_wheelhouse=fixture.python_freezer_wheelhouse,
                    python_interpreter_source=fixture.python_interpreter_source,
                    payload=fixture.payload,
                    resources=fixture.resources,
                    runtime=fixture.runtime,
                    documents=fixture.documents,
                    binary_readme_template=fixture.binary_template,
                    source_readme_template=fixture.source_template,
                    base_ledger=fixture.base_ledger,
                    workspace=reproduction_workspace,
                    output=fixture.root / "actual-python-reproducibility.json",
                )
            )
            accept("python-reproducibility", repro_payload)

            optimization_payload = optimization_generator.generate(
                argparse.Namespace(
                    identity=fixture.identity_path,
                    compression_evidence=evidence / records["compression-comparison"][
                        "path"
                    ],
                    blackbox_evidence=evidence / records["blackbox"]["path"],
                    practical_evidence=evidence / records["practical"]["path"],
                    output=fixture.root / "actual-optimization.json",
                )
            )
            accept("optimization-ledger", optimization_payload)

            self.assertEqual(produced, set(common.GATE_SCRIPT_PATHS))


class WholeEvidencePathScannerTests(unittest.TestCase):
    def test_rejects_absolute_paths_in_json_keys_and_values(self) -> None:
        hostile = (
            {"build=/private/tmp/root": "logical/value"},
            {"path": "work=C:\\Users\\builder\\repo"},
            {"path": "device=\\\\?\\C:\\build\\repo"},
            {"path": "unc=\\\\server\\share\\repo"},
            {"path": "rooted=\\Windows\\Temp\\repo"},
            {"path": "uri=file:///private/tmp/repo"},
        )
        for index, value in enumerate(hostile):
            with self.subTest(index=index):
                with self.assertRaisesRegex(common.ReleaseError, "absolute path"):
                    common.assert_relative_json(value)

    def test_allows_urls_and_documented_logical_namespaces(self) -> None:
        common.assert_relative_json(
            {
                "release_url": "https://github.com/amir-nuriyev/KazStem/releases/tag/v0.2.3",
                "paths": [
                    "bundle/.qazmorph/resources/manifest.json",
                    "ubuntu-host/libc.so.6",
                    "build-00/dist/kazstem.whl",
                ],
            }
        )


class OutputAliasingTests(unittest.TestCase):
    def test_rejects_equal_nested_and_hardlinked_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = root / "first"
            first.write_bytes(b"candidate")
            hardlink = root / "hardlink"
            hardlink.hardlink_to(first)
            for second in (first, hardlink):
                with self.subTest(second=second.name):
                    with self.assertRaises(common.ReleaseError):
                        common.ensure_distinct_nonaliased_paths(
                            first, second, labels=("artifact", "observation")
                        )
            with self.assertRaises(common.ReleaseError):
                common.ensure_distinct_nonaliased_paths(
                    root / "artifact",
                    root / "artifact" / "report.json",
                    labels=("artifact", "observation"),
                )


class GitSourceIdentityTests(unittest.TestCase):
    def test_materializer_resolves_exact_commit_tree_origin_and_archive(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = root / "repository"
            repository.mkdir()
            subprocess_env = {
                **os.environ,
                "GIT_AUTHOR_NAME": "Fixture",
                "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
                "GIT_COMMITTER_NAME": "Fixture",
                "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
                "GIT_AUTHOR_DATE": "2026-08-10T00:00:00Z",
                "GIT_COMMITTER_DATE": "2026-08-10T00:00:00Z",
            }
            import subprocess

            subprocess.run(["git", "init", "-q"], cwd=repository, check=True)
            (repository / "tracked.txt").write_text("exact tree\n", encoding="utf-8")
            subprocess.run(["git", "add", "tracked.txt"], cwd=repository, check=True)
            subprocess.run(
                ["git", "commit", "-q", "-m", "fixture"],
                cwd=repository,
                env=subprocess_env,
                check=True,
            )
            origin = "https://github.com/owner/repository.git"
            subprocess.run(
                ["git", "remote", "add", "origin", origin],
                cwd=repository,
                check=True,
            )
            branch = subprocess.run(
                ["git", "symbolic-ref", "--short", "HEAD"],
                cwd=repository,
                text=True,
                stdout=subprocess.PIPE,
                check=True,
            ).stdout.strip()
            commit = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=repository,
                text=True,
                stdout=subprocess.PIPE,
                check=True,
            ).stdout.strip()
            tree = subprocess.run(
                ["git", "rev-parse", "HEAD^{tree}"],
                cwd=repository,
                text=True,
                stdout=subprocess.PIPE,
                check=True,
            ).stdout.strip()
            source_ref = f"refs/remotes/origin/{branch}"
            subprocess.run(
                ["git", "update-ref", source_ref, commit],
                cwd=repository,
                check=True,
            )
            version = subprocess.run(
                ["git", "--version"],
                text=True,
                stdout=subprocess.PIPE,
                check=True,
            ).stdout.strip()
            archive = subprocess.run(
                ["git", "archive", "--format=tar", "--prefix=tree/", commit],
                cwd=repository,
                stdout=subprocess.PIPE,
                check=True,
            ).stdout
            expected = root / "expected.tar"
            expected.write_bytes(archive)
            identity = {
                "source_commit": commit,
                "source_tree": tree,
                "source_origin": origin,
                "source_ref": source_ref,
                "inputs": {
                    "git_archive": {
                        "argv": [
                            "git",
                            "archive",
                            "--format=tar",
                            "--prefix=tree/",
                            commit,
                        ],
                        "file": common.file_record(expected),
                        "prefix": "tree/",
                        "tool_version": version,
                    }
                },
            }
            output = root / "observed.tar"
            result = common.materialize_git_archive(repository, identity, output)
            self.assertEqual(output.read_bytes(), archive)
            self.assertEqual(result["source_commit"], commit)
            self.assertEqual(result["source_tree"], tree)
            self.assertEqual(result["source_origin"], origin)

            hostile = json.loads(json.dumps(identity))
            hostile["source_commit"] = "f" * 40
            with self.assertRaises(common.ReleaseError):
                common.materialize_git_archive(
                    repository, hostile, root / "hostile.tar"
                )


class StructuredEvidenceGeneratorTests(unittest.TestCase):
    def test_trace_distinguishes_seccomp_denial_from_successful_network_call(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = ReleaseFixture(Path(temporary))
            record, _counts = gate_generator._trace_record(
                b"123 socket(AF_INET, SOCK_STREAM, IPPROTO_IP) = -1 EPERM (Operation not permitted)\n",
                fixture.identity,
                replacements=[],
            )
            self.assertEqual(record["forbidden_syscalls"], [])
            self.assertEqual(record["denied_attempt_counts"], {"socket": 1})
            with self.assertRaisesRegex(
                gate_generator.ReleaseError, "forbidden network"
            ):
                gate_generator._trace_record(
                    b"123 socket(AF_INET, SOCK_STREAM, IPPROTO_IP) = 3\n",
                    fixture.identity,
                    replacements=[],
                )

    def test_remote_tag_gate_binds_annotated_object_and_peeled_commit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = ReleaseFixture(Path(temporary))
            fake_bin = fixture.root / "fake-bin"
            fake_bin.mkdir()
            fake_git = fake_bin / "git"
            expected_stdout = (
                f"{fixture.source_tag_object}\t{fixture.source_ref}\n"
                f"{fixture.commit}\t{fixture.source_ref}^{{}}\n"
            )
            fake_git.write_text(
                f"#!{sys.executable}\n"
                "import sys\n"
                f"expected = {common.remote_tag_argv(fixture.identity)[1:]!r}\n"
                "if sys.argv[1:] == ['--version']:\n"
                "    print('git version fixture-authority')\n"
                "elif sys.argv[1:] == expected:\n"
                f"    sys.stdout.write({expected_stdout!r})\n"
                "else:\n"
                "    raise SystemExit(91)\n",
                encoding="utf-8",
            )
            fake_git.chmod(0o755)
            git_record = next(
                item
                for item in fixture.identity["verification"]["reproducibility"]["tools"]
                if item["name"] == "git"
            )
            git_record["version"] = "git version fixture-authority"
            git_record["executable"] = common.file_record(fake_git)
            fixture.write_identity()
            output = fixture.root / "source-authority-payload.json"
            with mock.patch.dict(
                os.environ,
                {"PATH": f"{fake_bin}{os.pathsep}{os.environ.get('PATH', '')}"},
            ), mock.patch("pathlib.Path.cwd", return_value=fixture.repository):
                payload = remote_tag.verify(
                    argparse.Namespace(identity=fixture.identity_path, output=output)
                )
            common.validate_source_authority_payload(
                payload, identity=fixture.identity
            )
            hostile = json.loads(json.dumps(payload))
            hostile["remote"]["records"][1]["object"] = "f" * 40
            with self.assertRaisesRegex(common.ReleaseError, "remote query"):
                common.validate_source_authority_payload(
                    hostile, identity=fixture.identity
                )

    def test_generator_source_load_ignores_unchecked_helper_pyc(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "packaging"
            linux = root / "linux"
            linux.mkdir(parents=True)
            for source, destination in (
                (LINUX_TOOLS / "generate_gate_evidence.py", linux / "generate_gate_evidence.py"),
                (LINUX_TOOLS / "release_common.py", linux / "release_common.py"),
                (PROJECT_ROOT / "packaging/process_supervisor.py", root / "process_supervisor.py"),
            ):
                shutil.copyfile(source, destination)
            markers: list[Path] = []
            for helper in (linux / "release_common.py", root / "process_supervisor.py"):
                clean = helper.read_bytes()
                marker = helper.with_suffix(".malicious-executed")
                markers.append(marker)
                helper.write_text(
                    f"from pathlib import Path\nPath({str(marker)!r}).write_text('bad')\n"
                    "raise RuntimeError('unchecked helper pyc executed')\n",
                    encoding="utf-8",
                )
                py_compile.compile(
                    str(helper),
                    invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH,
                    doraise=True,
                )
                helper.write_bytes(clean)
            completed = subprocess.run(
                [sys.executable, str(linux / "generate_gate_evidence.py"), "--help"],
                cwd=root.parent,
                env={**os.environ, "PYTHONPATH": str(root)},
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=20,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr.decode())
            self.assertFalse(any(marker.exists() for marker in markers))

    def test_generator_binds_command_artifact_identity_and_nontruncated_streams(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = ReleaseFixture(Path(temporary))
            artifacts, _reproduction_b = fixture.seal_artifacts()
            output = fixture.root / "generated-blackbox-envelope.json"
            envelope = gate_generator.generate(
                argparse.Namespace(
                    identity=fixture.identity_path,
                    gate="blackbox",
                    output=output,
                    source_checkout=fixture.repository,
                    artifacts_dir=artifacts,
                    gate_input=[],
                )
            )
            self.assertEqual(envelope["identity_contract_sha256"], common.identity_sha256(fixture.identity_path))
            self.assertEqual(envelope["subjects"]["ready_run"], fixture.identity["artifacts"]["ready_run"])
            self.assertFalse(envelope["invocation"]["stdout"]["truncated"])
            hostile = json.loads(json.dumps(envelope))
            hostile["invocation"]["stderr"]["truncated"] = True
            with self.assertRaisesRegex(common.ReleaseError, "nontruncated"):
                common.validate_gate_envelope(
                    hostile,
                    identity=fixture.identity,
                    identity_contract_sha256=common.identity_sha256(
                        fixture.identity_path
                    ),
                    gate="blackbox",
                    subjects=["ready_run"],
                )
            hostile = json.loads(json.dumps(envelope))
            hostile["invocation"]["argv"] = [
                "python3",
                "-c",
                "write_fake_pass()",
            ]
            with self.assertRaisesRegex(common.ReleaseError, "clean exit"):
                common.validate_gate_envelope(
                    hostile,
                    identity=fixture.identity,
                    identity_contract_sha256=common.identity_sha256(
                        fixture.identity_path
                    ),
                    gate="blackbox",
                    subjects=["ready_run"],
                )
            (fixture.repository / "untracked-evidence-forgery.py").write_text(
                "pass\n", encoding="utf-8"
            )
            with self.assertRaisesRegex(gate_generator.ReleaseError, "dirty"):
                gate_generator.generate(
                    argparse.Namespace(
                        identity=fixture.identity_path,
                        gate="blackbox",
                        output=fixture.root / "dirty-envelope.json",
                        source_checkout=fixture.repository,
                        artifacts_dir=artifacts,
                        gate_input=[],
                    )
                )


class CompressionGeneratorTests(unittest.TestCase):
    def test_ab_determinism_and_exact_minimum_are_rechecked(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = ReleaseFixture(Path(temporary))
            false_exclusion = json.loads(json.dumps(fixture.identity))
            false_exclusion["verification"]["compression"]["targets"][0][
                "candidates"
            ][0]["eligible"] = False
            false_exclusion["verification"]["compression"]["targets"][0][
                "candidates"
            ][0]["ineligible_reason"] = "operator preference"
            hostile_identity = fixture.root / "false-compression-exclusion.json"
            hostile_identity.write_text(
                json.dumps(false_exclusion, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                common.ReleaseError, "fixed no-install decoder matrix"
            ):
                common.load_identity(hostile_identity)
            reproduction, _ = fixture.seal_artifacts()
            report = compression_generator.generate(
                argparse.Namespace(
                    identity=fixture.identity_path,
                    repository=fixture.repository,
                    artifact_dir=reproduction,
                    producer_dir=reproduction,
                    output=fixture.root / "compression.json",
                    timeout=60,
                )
            )
            common.validate_compression_comparison(
                report,
                identity=fixture.identity,
                identity_contract_sha256=common.identity_sha256(
                    fixture.identity_path
                ),
            )
            for target in report["targets"]:
                zstd = next(
                    item for item in target["candidates"] if item["name"] == "zstd"
                )
                self.assertFalse(zstd["eligible"])
                self.assertEqual(len(zstd["runs"]), 2)
                self.assertTrue(zstd["byte_identical"])
            hostile = json.loads(json.dumps(report))
            hostile["targets"][0]["selected"] = next(
                item["name"]
                for item in hostile["targets"][0]["candidates"]
                if item["eligible"] is True
                and item["name"] != report["targets"][0]["selected"]
            )
            with self.assertRaisesRegex(common.ReleaseError, "exact eligible minimum"):
                common.validate_compression_comparison(
                    hostile,
                    identity=fixture.identity,
                    identity_contract_sha256=common.identity_sha256(
                        fixture.identity_path
                    ),
                )
            hostile = json.loads(json.dumps(report))
            hostile["targets"][0]["selected_output"]["sha256"] = "e" * 64
            with self.assertRaisesRegex(common.ReleaseError, "published asset"):
                common.validate_compression_comparison(
                    hostile,
                    identity=fixture.identity,
                    identity_contract_sha256=common.identity_sha256(
                        fixture.identity_path
                    ),
                )
            double_compressed = json.loads(json.dumps(fixture.identity))
            ready_artifact = fixture.identity["artifacts"]["ready_run"]
            ready_target = next(
                target
                for target in double_compressed["verification"]["compression"][
                    "targets"
                ]
                if target["artifact"] == "ready_run"
            )
            ready_target["input"] = {
                "filename": ready_artifact["filename"],
                "producer": "deterministic-gnu-tar-v1",
                "bytes": ready_artifact["bytes"],
                "sha256": ready_artifact["sha256"],
            }
            hostile_identity = fixture.root / "double-compressed-identity.json"
            hostile_identity.write_bytes(common.json_bytes(double_compressed))
            with self.assertRaisesRegex(common.ReleaseError, "canonical raw tar"):
                common.load_identity(hostile_identity)
            hostile = json.loads(json.dumps(report))
            hostile["targets"][0]["candidates"][0]["runs"][1]["output"][
                "sha256"
            ] = "f" * 64
            with self.assertRaisesRegex(common.ReleaseError, "A/B run"):
                common.validate_compression_comparison(
                    hostile,
                    identity=fixture.identity,
                    identity_contract_sha256=common.identity_sha256(
                        fixture.identity_path
                    ),
                )
            hostile = json.loads(json.dumps(report))
            hostile["targets"][0]["producer_receipt"]["runs"][1]["output"][
                "sha256"
            ] = "a" * 64
            with self.assertRaisesRegex(common.ReleaseError, "producer receipt"):
                common.validate_compression_comparison(
                    hostile,
                    identity=fixture.identity,
                    identity_contract_sha256=common.identity_sha256(
                        fixture.identity_path
                    ),
                )
    @unittest.skipUnless(shutil.which("strace"), "requires real strace")
    def test_strace_generator_covers_source_suite_and_network_descendants(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = ReleaseFixture(Path(temporary))
            reproduction, _reproduction_b = fixture.seal_artifacts()
            gate_artifacts = fixture.root / "gate-artifacts"
            gate_artifacts.mkdir()
            for source in (
                fixture.wheel,
                fixture.sdist,
                reproduction / fixture.ready_name,
                reproduction / fixture.source_name,
            ):
                shutil.copyfile(source, gate_artifacts / source.name)
            for gate in ("source-suite", "network-trace", "python-reproducibility"):
                with self.subTest(gate=gate):
                    gate_inputs = (
                        [
                            f"base_ledger={fixture.base_ledger}",
                            f"binary_readme_template={fixture.binary_template}",
                            f"documents={fixture.documents}",
                            f"python_build_identity={fixture.python_build_identity_path}",
                            f"python_interpreter_source={fixture.python_interpreter_source}",
                            f"python_wheelhouse={fixture.python_wheelhouse}",
                            f"python_freezer_wheelhouse={fixture.python_freezer_wheelhouse}",
                            f"resources={fixture.resources}",
                            f"runtime={fixture.runtime}",
                            f"source_payload={fixture.payload}",
                            f"source_readme_template={fixture.source_template}",
                        ]
                        if gate == "python-reproducibility"
                        else (
                            [
                                "python_freezer_wheelhouse="
                                f"{fixture.python_freezer_wheelhouse}"
                            ]
                            if gate == "source-suite"
                            else []
                        )
                    )
                    envelope = gate_generator.generate(
                        argparse.Namespace(
                            identity=fixture.identity_path,
                            gate=gate,
                            output=fixture.root / f"{gate}-generated.json",
                            source_checkout=fixture.repository,
                            artifacts_dir=gate_artifacts,
                            gate_input=gate_inputs,
                        )
                    )
                    self.assertFalse(
                        envelope["coverage"]["full_descendant_coverage"]
                    )
                    self.assertFalse(
                        envelope["coverage"]["network_trace"]["trace"][
                            "truncated"
                        ]
                    )


if __name__ == "__main__":
    unittest.main()
