from __future__ import annotations

import argparse
import copy
import hashlib
import io
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock
import zipfile


PROJECT_ROOT = Path(__file__).resolve().parents[1]
MACOS_TOOLS = PROJECT_ROOT / "packaging" / "macos"
sys.path.insert(0, str(MACOS_TOOLS))

import prepare_release_identity as identity_generator  # noqa: E402
import audit_corresponding_source_archive as source_auditor  # noqa: E402
import audit_ready_run_archive as ready_auditor  # noqa: E402
import finalize_release as finalizer  # noqa: E402
import release_common as common  # noqa: E402
import stage_release_candidates as staging  # noqa: E402


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(common.json_bytes(value))


def fixture_invocation(
    identity: dict[str, object], gate: str, *, stdout: bytes
) -> dict[str, object]:
    generator = next(
        record["generator"]
        for record in identity["verification"]["evidence"]
        if record["gate"] == gate
    )
    tool = next(
        record
        for record in identity["verification"]["reproducibility"]["tools"]
        if record["name"] == generator["tool"]
    )
    return {
        "argv": generator["argv"],
        "cwd": generator["cwd"],
        "environment": generator["environment"],
        "exit_status": 0,
        "script": generator["script"],
        "source_commit": generator["source_commit"],
        "source_tree": generator["source_tree"],
        "timeout_seconds": generator["timeout_seconds"],
        "tool": tool,
        "stdout": common.stream_evidence_record(stdout),
        "stderr": common.stream_evidence_record(b""),
    }


def captured_command(name: str) -> dict[str, object]:
    return {
        "argv": ["fixture", name],
        "exit_status": 0,
        "stdout": common.stream_evidence_record(b"fixture command\n"),
        "stderr": common.stream_evidence_record(b""),
        "capture": {
            "process_group_reaped": True,
            "stream_cap_bytes": 16 * 1024 * 1024,
            "timeout_seconds": 60,
        },
    }


def clean_darwin_loader_provenance() -> dict[str, object]:
    clean = {
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
        "GLIBC_TUNABLES": copy.deepcopy(clean),
        "loader_policy": {
            "schema": common.LOADER_POLICY_SCHEMA,
            "captured_name_policy": {
                "exact_uppercase_prefixes": list(common.LOADER_OVERRIDE_PREFIXES),
                "exact_names": [common.GLIBC_TUNABLES_VARIABLE],
            },
            "ambient_records": {},
            "glibc_tunables": copy.deepcopy(clean),
            "clean_parent_startup": True,
            "all_ambient_values_removed_from_helper_environment": True,
            "linux_helper_ld_library_path": None,
        },
    }
    for name in common.LOADER_OVERRIDE_VARIABLES:
        environment[name] = copy.deepcopy(clean)
    return {"environment": environment}


def gate_coverage(identity: dict[str, object], gate: str) -> dict[str, object]:
    if gate != "network-trace":
        return {
            "descendant_processes": 1,
            "full_descendant_coverage": True,
            "network_trace": None,
            "observations": {"fixture": 1},
            "trace_complete": True,
            "trace_truncated": False,
        }
    trace = common.stream_evidence_record(b"fixture denied network event\n")
    events = [
        {
            "kind": "network-denial",
            "process": "kazstem",
            "result": "denied",
            "sequence": 0,
        }
    ]
    tracing = identity["verification"]["tracing"]
    return {
        "descendant_processes": 1,
        "full_descendant_coverage": True,
        "network_trace": {
            "cases_sandboxed": 1,
            "events": events,
            "negative_control": {
                "argv": tracing["negative_control_argv"],
                "denied": True,
                "exit_status": 1,
                "stdout": common.stream_evidence_record(b""),
                "stderr": common.stream_evidence_record(b"denied\n"),
            },
            "observed_descendants": 1,
            "policy_argv_prefix": tracing["argv_prefix"],
            "policy_denials": 1,
            "policy_tool": tracing["tool"],
            "process_observer_argv": tracing["process_observer_argv"],
            "process_samples": 1,
            "profile": tracing["profile"],
            "trace": trace,
        },
        "observations": {"events": 1},
        "trace_complete": True,
        "trace_truncated": False,
    }


class ReleaseFixture:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.release = "9.8.7"
        self.epoch = 1_786_361_661
        self.label = "macos15-arm64-test"
        self.release_url = "https://github.com/owner/repository/releases/tag/v9.8.7"
        self.origin = "https://github.com/owner/repository.git"
        self.ready_top = f"kazstem-{self.release}-{self.label}-ready-run-unsigned"
        self.source_top = f"kazstem-{self.release}-{self.label}-corresponding-source"
        self.ready_name = self.ready_top + ".tar.xz"
        self.source_name = self.source_top + ".tar.xz"
        self.wheel_name = f"kazstem-{self.release}-py3-none-any.whl"
        self.sdist_name = f"kazstem-{self.release}.tar.gz"
        self.repository = root / "repository"
        self._repository()
        self._python_artifacts()
        self._binary_inputs()
        self._source_payload()
        self.identity = self._identity()
        self.identity_path = root / "bootstrap-identity.json"
        write_json(self.identity_path, self.identity)
        self.assert_valid_identity()

    def _repository(self) -> None:
        self.repository.mkdir()
        subprocess.run(["git", "init", "-q"], cwd=self.repository, check=True)
        for source in sorted(MACOS_TOOLS.iterdir()):
            if source.is_file() and source.suffix in {".py", ".md", ".sb"}:
                destination = self.repository / "packaging/macos" / source.name
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, destination)
        spec = MACOS_TOOLS / "kazstem-minimal.spec"
        destination_spec = self.repository / "packaging/macos/kazstem-minimal.spec"
        shutil.copyfile(spec, destination_spec)
        for relative in (
            "packaging/build_canonical_python_artifacts.py",
            "packaging/process_supervisor.py",
            "packaging/linux/release_common.py",
            "packaging/linux/verify_python_reproducibility.py",
        ):
            destination = self.repository / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(PROJECT_ROOT / relative, destination)
        (self.repository / "module.py").write_text("VALUE = 1\n", encoding="utf-8")
        subprocess.run(["git", "add", "."], cwd=self.repository, check=True)
        git_environment = {
            **os.environ,
            "GIT_AUTHOR_NAME": "Fixture",
            "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
            "GIT_COMMITTER_NAME": "Fixture",
            "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
            "GIT_AUTHOR_DATE": f"@{self.epoch} +0000",
            "GIT_COMMITTER_DATE": f"@{self.epoch} +0000",
        }
        subprocess.run(
            ["git", "commit", "-q", "-m", "fixture source"],
            cwd=self.repository,
            env=git_environment,
            check=True,
        )
        subprocess.run(
            ["git", "tag", f"v{self.release}"], cwd=self.repository, check=True
        )
        subprocess.run(
            ["git", "remote", "add", "origin", self.origin],
            cwd=self.repository,
            check=True,
        )
        self.commit = self._git("rev-parse", "HEAD")
        self.tree = self._git("rev-parse", "HEAD^{tree}")
        self.source_ref = f"refs/tags/v{self.release}"
        self.source_tag_object = self._git("rev-parse", self.source_ref)
        self.git_version = self._git("--version")
        self.git_archive = self.root / "canonical-git-archive.tar"
        self.git_archive.write_bytes(
            subprocess.run(
                [
                    "git",
                    "archive",
                    "--format=tar",
                    "--prefix=tree/",
                    self.commit,
                ],
                cwd=self.repository,
                stdout=subprocess.PIPE,
                check=True,
            ).stdout
        )

    def _git(self, *arguments: str) -> str:
        return subprocess.run(
            ["git", *arguments],
            cwd=self.repository,
            text=True,
            stdout=subprocess.PIPE,
            check=True,
        ).stdout.strip()

    def _python_artifacts(self) -> None:
        self.wheel = self.root / self.wheel_name
        with zipfile.ZipFile(
            self.wheel, "x", compression=zipfile.ZIP_DEFLATED
        ) as archive:
            archive.writestr("kazstem/__init__.py", "__version__ = '9.8.7'\n")
            archive.writestr(
                f"kazstem-{self.release}.dist-info/METADATA",
                f"Metadata-Version: 2.1\nName: kazstem\nVersion: {self.release}\n\n",
            )
        self.sdist = self.root / self.sdist_name
        with tarfile.open(self.sdist, "w:gz") as archive:
            data = b"fixture source\n"
            info = tarfile.TarInfo(f"kazstem-{self.release}/README.md")
            info.mode = 0o644
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))

    def _binary_inputs(self) -> None:
        self.frozen = self.root / "frozen"
        launcher = self.frozen / "kazstem"
        launcher.parent.mkdir()
        launcher.write_text("#!/bin/sh\nprintf 'kazstem 9.8.7\\n'\n", encoding="utf-8")
        launcher.chmod(0o755)
        self.platform_lock = (
            self.frozen / "_internal/qazmorph/platform_runtime_assets.lock.json"
        )
        write_json(
            self.platform_lock,
            {"schema": "kazstem-platform-runtime-lock-v1", "runtimes": []},
        )
        self.removed = self.frozen / "_internal/libz.dylib"
        self.removed.write_bytes(b"unused host dylib\n")

        self.resource_id = "a" * 64
        self.resources = self.root / "resources"
        write_json(self.resources / "manifest.json", {"bundle_id": self.resource_id})
        (self.resources / "morphology.bin").write_bytes(b"fixture morphology\n")

        self.runtime_id = "b" * 64
        self.runtime = self.root / "runtime"
        write_json(self.runtime / "manifest.json", {"bundle_id": self.runtime_id})
        native = self.runtime / "usr/bin/hfst-proc"
        native.parent.mkdir(parents=True)
        native.write_bytes(b"fixture native tool\n")
        native.chmod(0o755)

        self.documents = self.root / "documents"
        self.documents.mkdir()
        (self.documents / "LICENSE.txt").write_text(
            "fixture license\n", encoding="utf-8"
        )
        self.binary_template = self.root / "BINARY-README.template.md"
        self.binary_template.write_text(
            "KazStem @VERSION@ for @TARGET@. Source @SOURCE_FILENAME@ "
            "@SOURCE_SHA256@ @SOURCE_URL@. Resources @RESOURCE_BUNDLE_ID@; "
            "runtime @RUNTIME_BUNDLE_ID@.\n",
            encoding="utf-8",
        )
        self.source_template = self.root / "SOURCE-README.template.md"
        self.source_template.write_text(
            "Source @VERSION@ for @BINARY_ARCHIVE@ @BINARY_URL@ at "
            "@SOURCE_COMMIT@/@SOURCE_DATE_EPOCH@. @WHEEL_FILENAME@ "
            "@WHEEL_SHA256@ @SDIST_FILENAME@ @SDIST_SHA256@ resources "
            "@RESOURCE_BUNDLE_ID@ runtime @RUNTIME_BUNDLE_ID@ release "
            "@RELEASE_URL@.\n",
            encoding="utf-8",
        )
        self.runtime_source_lock = self.root / "runtime-sources.lock.json"
        write_json(self.runtime_source_lock, {"schema": "fixture-runtime-lock-v1"})
        self.base_ledger = self.root / "frozen-build-ledger.json"
        self.freezer_wheelhouse = self.root / "freezer-wheelhouse"
        self.freezer_wheelhouse.mkdir()
        (self.freezer_wheelhouse / "fixture.whl").write_bytes(b"not an archive\n")
        self.freezer_requirements = self.root / "freezer-requirements.lock"
        self.freezer_requirements.write_text(
            "fixture==1 --hash=sha256:" + "1" * 64 + "\n", encoding="utf-8"
        )
        self.sandbox = self.root / "sandbox-exec"
        self.sandbox.write_text(
            "#!/bin/sh\nprintf 'fixture sandbox-exec help\\n'\n",
            encoding="utf-8",
        )
        self.sandbox.chmod(0o755)

    def _source_payload(self) -> None:
        self.payload = self.root / "source-payload"
        categories = {
            "build-inputs": "build inputs\n",
            "evidence": '{"schema":"fixture-evidence-v1"}\n',
            "freezer-source": "freezer source\n",
            "licenses": "license notice\n",
            "resource-source": "resource source\n",
        }
        for directory, text in categories.items():
            path = self.payload / directory / "README.txt"
            path.parent.mkdir(parents=True)
            path.write_text(text, encoding="utf-8")
        upstream = self.payload / "runtime-source/upstream.bin"
        upstream.parent.mkdir(parents=True)
        with tarfile.open(upstream, "w:gz") as archive:
            data = b"runtime source\n"
            info = tarfile.TarInfo("runtime-1.0/README")
            info.mode = 0o644
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
        self.python_build_identity = self.root / "PYTHON-BUILD-IDENTITY.json"
        write_json(
            self.python_build_identity,
            {"schema": "kazstem-canonical-python-build-identity-v2"},
        )
        self.linux_release_identity = self.root / "LINUX-RELEASE-IDENTITY.json"
        write_json(
            self.linux_release_identity,
            {"schema": "kazstem-linux-release-identity-v2"},
        )
        self.linux_reproducibility = self.root / "linux-python-reproducibility.json"
        write_json(
            self.linux_reproducibility,
            {"schema": "kazstem-python-artifact-reproducibility-v2"},
        )
        self.python_interpreter_source = self.root / "Python-3.12.3.tgz"
        self.python_interpreter_source.write_bytes(b"fixture CPython source\n")
        authority_sources = (
            (
                self.python_build_identity,
                "build-inputs/PYTHON-BUILD-IDENTITY.json",
                "canonical-python-identity",
            ),
            (
                self.python_interpreter_source,
                "build-inputs/Python-3.12.3.tgz",
                "cpython-source",
            ),
            (
                self.linux_release_identity,
                "evidence/linux/RELEASE-IDENTITY.json",
                "linux-release-identity",
            ),
            (
                self.linux_reproducibility,
                "evidence/linux/python-reproducibility.json",
                "linux-reproducibility-evidence",
            ),
        )
        self.authority_source_companions = []
        for source, relative, role in authority_sources:
            destination = self.payload / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)
            self.authority_source_companions.append(
                {
                    "path": relative,
                    "role": role,
                    "subject": "fixture-authority",
                    "source_member": None,
                    "file": common.file_record(destination),
                }
            )
        self.authority_source_companions.sort(key=lambda item: item["path"])

    def _tool(
        self, name: str, path: Path, version_argv: list[str]
    ) -> dict[str, object]:
        process = subprocess.run(
            [str(path), *version_argv[1:]],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
        )
        return {
            "name": name,
            "version_argv": version_argv,
            "version": process.stdout.strip(),
            "executable": common.file_record(path),
        }

    def _identity(self) -> dict[str, object]:
        wheel_artifact = self._artifact(self.wheel)
        sdist_artifact = self._artifact(self.sdist)
        zero_native = {"bytes": 1, "sha256": "0" * 64}
        ready_artifact = {
            "filename": self.ready_name,
            **zero_native,
            "url": self._url(self.ready_name),
        }
        source_artifact = {
            "filename": self.source_name,
            **zero_native,
            "url": self._url(self.source_name),
        }
        authority = {
            "schema": "kazstem-macos-canonical-python-authority-v1",
            "adapter": {
                "path": "packaging/macos/canonical_python_authority.py",
                "file": common.file_record(
                    self.repository / "packaging/macos/canonical_python_authority.py"
                ),
                "schema": "kazstem-macos-canonical-python-authority-v1",
            },
            "builder": {
                "path": "packaging/build_canonical_python_artifacts.py",
                "file": common.file_record(
                    self.repository / "packaging/build_canonical_python_artifacts.py"
                ),
                "identity_schema": "kazstem-canonical-python-build-identity-v2",
                "receipt_schema": "kazstem-canonical-python-build-receipt-v2",
            },
            "process_supervisor": {
                "path": "packaging/process_supervisor.py",
                "file": common.file_record(
                    self.repository / "packaging/process_supervisor.py"
                ),
            },
            "linux_release_common": {
                "path": "packaging/linux/release_common.py",
                "file": common.file_record(
                    self.repository / "packaging/linux/release_common.py"
                ),
                "identity_schema": "kazstem-linux-release-identity-v2",
            },
            "linux_validator": {
                "path": "packaging/linux/verify_python_reproducibility.py",
                "file": common.file_record(
                    self.repository
                    / "packaging/linux/verify_python_reproducibility.py"
                ),
                "payload_schema": "kazstem-python-artifact-reproducibility-v2",
                "entrypoint": "validate_reproducibility_payload",
            },
            "python_build_identity": {
                "path": "inputs/PYTHON-BUILD-IDENTITY.json",
                "schema": "kazstem-canonical-python-build-identity-v2",
                "file": common.file_record(self.python_build_identity),
            },
            "linux_release_identity": {
                "path": "inputs/LINUX-RELEASE-IDENTITY.json",
                "schema": "kazstem-linux-release-identity-v2",
                "identity_contract_sha256": hashlib.sha256(
                    self.linux_release_identity.read_bytes()
                ).hexdigest(),
                "file": common.file_record(self.linux_release_identity),
            },
            "linux_reproducibility": {
                "path": "inputs/linux-python-reproducibility.json",
                "schema": "kazstem-python-artifact-reproducibility-v2",
                "minimum_distinct_roots": 3,
                "validated_distinct_roots": 3,
                "file": common.file_record(self.linux_reproducibility),
            },
            "interpreter_source": {
                "path": "inputs/interpreter-source/Python-3.12.3.tgz",
                "corresponding_source_path": "build-inputs/Python-3.12.3.tgz",
                "file": common.file_record(self.python_interpreter_source),
            },
            "source_tag_object": self.source_tag_object,
            "canonical_artifacts": {
                "wheel": wheel_artifact,
                "sdist": sdist_artifact,
            },
            "source_companions": self.authority_source_companions,
        }

        frozen_tree = common.tree_record(self.frozen)
        write_json(
            self.base_ledger,
            {
                "schema": "kazstem-macos-frozen-build-v1",
                "pass": True,
                "release": self.release,
                "source_commit": self.commit,
                "source_tree": self.tree,
                "output_tree": frozen_tree,
                "module_inventory": {"modules": ["_sha2", "kazstem"]},
                "negative_controls": {
                    "pyinstaller-zlib-bootstrap": {"failed_as_required": True}
                },
                "strip_candidates": [],
            },
        )
        python_path = Path(sys.executable).resolve(strict=True)
        zstd_path = Path(shutil.which("zstd") or "").resolve(strict=True)
        git_path = Path(shutil.which("git") or "").resolve(strict=True)
        python_tool = self._tool("python3.14", python_path, ["python3.14", "--version"])
        zstd_tool = self._tool("zstd", zstd_path, ["zstd", "--version"])
        git_tool = self._tool("git", git_path, ["git", "--version"])
        stack_artifact = {
            "wheel": wheel_artifact,
            "source": sdist_artifact,
        }
        canonical_names = [
            "build",
            "packaging",
            "pyproject-hooks",
            "setuptools",
            "wheel",
        ]
        freezer_names = [
            "altgraph",
            "macholib",
            "pip",
            "pyinstaller",
            "pyinstaller-hooks-contrib",
            "setuptools",
            "wheel",
        ]
        build_stack = {
            "canonical": [
                {"name": name, "version": "1", **stack_artifact}
                for name in canonical_names
            ],
            "freezer": [
                {"name": name, "version": "1", **stack_artifact}
                for name in freezer_names
            ],
        }

        def producer(script: str) -> dict[str, object]:
            return {
                "argv": [
                    "python3.14",
                    script,
                    "--identity",
                    "release-identity.json",
                ],
                "script": {
                    "path": script,
                    "file": common.file_record(self.repository / script),
                },
                "source_commit": self.commit,
                "source_tree": self.tree,
            }

        compressors = {
            "gzip": {
                **python_tool,
                "argv": [
                    "python3.14",
                    "stdlib:gzip",
                    "compresslevel=9",
                    "mtime=0",
                    "filename=",
                ],
            },
            "xz": {
                **python_tool,
                "argv": [
                    "python3.14",
                    "stdlib:lzma",
                    "format=xz",
                    "check=crc64",
                    "preset=9e",
                ],
            },
            "zstd": {
                **zstd_tool,
                "argv": [
                    "zstd",
                    "-19",
                    "--ultra",
                    "--threads=1",
                    "--no-progress",
                    "--stdout",
                    "canonical.tar",
                ],
            },
        }
        compression = {}
        for name, top, script in (
            (
                "ready_run",
                self.ready_top,
                "packaging/macos/assemble_ready_run.py",
            ),
            (
                "corresponding_source",
                self.source_top,
                "packaging/macos/assemble_corresponding_source.py",
            ),
        ):
            compression[name] = {
                "canonical_tar": {
                    "filename": top + ".tar",
                    **zero_native,
                    "producer": producer(script),
                },
                "compressors": compressors,
                "eligibility": [
                    {
                        "format": format_name,
                        "eligible": True,
                        "reason": "fixture tool and extraction support are available",
                    }
                    for format_name in ("gzip", "xz", "zstd")
                ],
                "selected_format": "xz",
                "selection_rule": "smallest-eligible-byte-identical",
            }

        app = "application-source"
        source_categories = {
            "application_source": app,
            "build_inputs": "build-inputs",
            "evidence": "evidence",
            "freezer_source": "freezer-source",
            "licenses": "licenses",
            "resource_source": "resource-source",
            "runtime_source": "runtime-source",
        }
        marker_paths = {
            "source_commit_file": f"{app}/SOURCE-COMMIT",
            "source_tree_file": f"{app}/SOURCE-TREE",
            "source_origin_file": f"{app}/SOURCE-ORIGIN",
            "git_archive_file": f"{app}/source.git.tar",
            "source_date_epoch_file": f"{app}/SOURCE-DATE-EPOCH",
        }
        nested_archives = sorted(
            [
                {
                    "path": marker_paths["git_archive_file"],
                    "format": "tar",
                    **common.file_record(self.git_archive),
                },
                {
                    "path": f"python-artifacts/{self.wheel_name}",
                    "format": "zip",
                    **common.file_record(self.wheel),
                },
                {
                    "path": f"python-artifacts/{self.sdist_name}",
                    "format": "tar",
                    **common.file_record(self.sdist),
                },
                {
                    "path": "runtime-source/upstream.bin",
                    "format": "tar",
                    **common.file_record(self.payload / "runtime-source/upstream.bin"),
                },
            ],
            key=lambda item: item["path"],
        )

        environment = {
            "LANG": "C",
            "LC_ALL": "C",
            "PYTHONHASHSEED": "0",
            "SOURCE_DATE_EPOCH": str(self.epoch),
            "TZ": "UTC",
        }
        tools = sorted(
            [git_tool, python_tool, zstd_tool], key=lambda item: item["name"]
        )
        evidence = []
        for gate in sorted(common.REQUIRED_EVIDENCE_GATES):
            source_script = identity_generator.GATE_SCRIPTS[gate]
            evidence.append(
                {
                    "path": f"gates/{gate}.json",
                    "gate": gate,
                    "kind": "envelope",
                    "subjects": identity_generator.GATE_SUBJECTS[gate],
                    "file": {"bytes": 1, "sha256": "1" * 64},
                    "generator": {
                        "argv": [
                            "python3.14",
                            "-S",
                            f"source-tree/{source_script}",
                            "--fixture",
                        ],
                        "cwd": "release-workspace",
                        "environment": environment,
                        "script": {
                            "path": f"source-tree/{source_script}",
                            "file": common.file_record(self.repository / source_script),
                        },
                        "source_commit": self.commit,
                        "source_tree": self.tree,
                        "timeout_seconds": 60,
                        "tool": "python3.14",
                    },
                }
            )
        sandbox = self.sandbox
        sandbox_process = subprocess.run(
            [str(sandbox), "-h"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )
        sandbox_output = common.tool_output_identity(
            sandbox_process.stdout, exit_status=sandbox_process.returncode
        )

        required_source = sorted(
            set(source_categories.values())
            | set(marker_paths.values())
            | {
                f"{app}/GIT-SOURCE.json",
                f"{app}/tree",
                "python-artifacts",
                *[item["path"] for item in self.authority_source_companions],
            }
        )
        required_ready = sorted(
            {
                "kazstem",
                "mystem-kz",
                "qazmorph",
                "README.md",
                "CORRESPONDING-SOURCE.json",
                "LICENSE.txt",
                "_internal/qazmorph/platform_runtime_assets.lock.json",
                "resources/manifest.json",
                f"runtime/{self.runtime_id}/manifest.json",
                "verification/BUILD-IDENTITY.json",
            }
        )
        return {
            "schema": common.IDENTITY_SCHEMA,
            "release": self.release,
            "source_commit": self.commit,
            "source_tree": self.tree,
            "source_origin": self.origin,
            "source_ref": self.source_ref,
            "source_date_epoch": self.epoch,
            "release_url": self.release_url,
            "platform": {
                "system": "darwin",
                "machine": "arm64",
                "label": self.label,
                "advertised_target": "macOS 15 arm64 fixture",
                "minimum_os": "15.0",
                "unsigned": True,
                "notarized": False,
            },
            "artifacts": {
                "wheel": wheel_artifact,
                "sdist": sdist_artifact,
                "ready_run": ready_artifact,
                "corresponding_source": source_artifact,
            },
            "inputs": {
                "frozen_tree": frozen_tree,
                "resource_tree": {
                    "bundle_id": self.resource_id,
                    "manifest": common.file_record(self.resources / "manifest.json"),
                    "tree": common.tree_record(self.resources),
                },
                "runtime_tree": {
                    "bundle_id": self.runtime_id,
                    "manifest": common.file_record(self.runtime / "manifest.json"),
                    "tree": common.tree_record(self.runtime),
                },
                "source_payload_tree": common.tree_record(self.payload),
                "git_archive": {
                    "argv": [
                        "git",
                        "archive",
                        "--format=tar",
                        "--prefix=tree/",
                        self.commit,
                    ],
                    "file": common.file_record(self.git_archive),
                    "prefix": "tree/",
                    "tool_version": self.git_version,
                },
                "base_ledger": common.file_record(self.base_ledger),
                "binary_readme_template": common.file_record(self.binary_template),
                "source_readme_template": common.file_record(self.source_template),
                "runtime_source_lock": common.file_record(self.runtime_source_lock),
                "platform_asset_lock": common.file_record(self.platform_lock),
                "build_stack": build_stack,
                "freezer_wheelhouse": common.tree_record(self.freezer_wheelhouse),
                "freezer_requirements": common.file_record(self.freezer_requirements),
                "freezer_spec": common.file_record(
                    self.repository / "packaging/macos/kazstem-minimal.spec"
                ),
                "staging_receipt": {
                    "file": zero_native,
                    "generator": {
                        "path": "packaging/macos/stage_release_candidates.py",
                        "file": common.file_record(
                            self.repository
                            / "packaging/macos/stage_release_candidates.py"
                        ),
                        "schema": staging.SCHEMA,
                    },
                },
                "python_runtimes": {
                    "freezer": {
                        "implementation": "CPython",
                        "version": "3.14.3",
                        "executable": common.file_record(python_path),
                    },
                },
                "documents": [
                    {
                        "source": "LICENSE.txt",
                        "destination": "LICENSE.txt",
                        "file": common.file_record(self.documents / "LICENSE.txt"),
                    }
                ],
            },
            "ready_run": {
                "top_level": self.ready_top,
                "launcher": {
                    "path": "kazstem",
                    "file": common.file_record(self.frozen / "kazstem"),
                },
                "platform_lock": {
                    "path": "_internal/qazmorph/platform_runtime_assets.lock.json",
                    "file": common.file_record(self.platform_lock),
                },
                "resource_destination": "resources",
                "runtime_parent": "runtime",
                "aliases": ["mystem-kz", "qazmorph"],
                "remove_frozen_files": [
                    {
                        "path": "_internal/libz.dylib",
                        "file": common.file_record(self.removed),
                    }
                ],
                "required_paths": required_ready,
                "banned_name_fragments": [
                    "_hashlib",
                    "_ssl",
                    "libcrypto",
                    "libssl",
                    "openssl",
                ],
            },
            "corresponding_source": {
                "top_level": self.source_top,
                "evidence_root": "evidence",
                "source_categories": source_categories,
                **marker_paths,
                "required_paths": required_source,
                "nested_archives": nested_archives,
            },
            "archive_limits": {
                name: {
                    "max_members": 20_000,
                    "max_file_bytes": 16 * 1024 * 1024,
                    "max_total_bytes": 128 * 1024 * 1024,
                    "max_path_bytes": 1024,
                }
                for name in ("ready_run", "corresponding_source", "nested")
            },
            "compression": compression,
            "mach_o": {
                "architecture": "arm64",
                "format": "thin",
                "system_boundaries": ["/System/Library/", "/usr/lib/"],
                "runtime_bundle_id": self.runtime_id,
                "runtime_manifest": common.file_record(self.runtime / "manifest.json"),
                "signature": {
                    "kind": "adhoc",
                    "team_identifier": None,
                    "developer_id": False,
                    "notarized": False,
                    "stapled": False,
                },
                "rpath_policy": {
                    "bind_exact_observed_rpaths": True,
                    "bundle_relative_precedes_inherited": True,
                    "external_resolution_forbidden": True,
                },
            },
            "minimization": {
                "banned_modules": ["_hashlib", "_ssl", "socket", "ssl", "urllib"],
                "banned_native_fragments": ["libcrypto", "libssl", "openssl"],
                "required_modules": ["_sha2", "kazstem"],
                "negative_controls": ["pyinstaller-zlib-bootstrap"],
                "compression_candidates": ["gzip", "xz", "zstd"],
                "compression_selection": "smallest-byte-identical-passing",
                "strip_selection": "smaller-with-full-parity-and-resign",
                "claim_scope": "measured-candidates-component-floor",
            },
            "verification": {
                "minimum_distinct_roots": 2,
                "reproducibility": {
                    "build_roots": 2,
                    "canonical_python_authority": authority,
                    "freezer_install_argv": [
                        "{freezer_python}",
                        "-m",
                        "pip",
                        "install",
                        "--disable-pip-version-check",
                        "--no-index",
                        "--no-deps",
                        "--require-hashes",
                        "--find-links",
                        "{freezer_wheelhouse}",
                        "-r",
                        "{freezer_requirements}",
                        "{wheel}",
                    ],
                    "frozen_build_argv": [
                        "{freezer_python}",
                        "packaging/macos/build_frozen_runtime.py",
                        "--identity",
                        "{identity}",
                        "--wheel",
                        "{wheel}",
                        "--spec",
                        "{spec}",
                        "--work-root",
                        "{freezer_work}",
                        "--output",
                        "{frozen_dist}",
                        "--evidence",
                        "{freezer_evidence}",
                    ],
                    "environment": environment,
                    "tools": tools,
                },
                "tracing": {
                    "argv_prefix": [
                        "sandbox-exec",
                        "-D",
                        "WRITE_ROOT={write_root}",
                        "-f",
                        "{profile}",
                        "--",
                    ],
                    "negative_control_argv": [
                        "python",
                        "-c",
                        "import socket; s=socket.socket(); s.bind(('127.0.0.1', 0))",
                    ],
                    "process_observer_argv": ["ps", "-axo", "pid=,ppid=,comm="],
                    "profile": {
                        "path": "packaging/macos/network-deny.sb",
                        "file": common.file_record(
                            self.repository / "packaging/macos/network-deny.sb"
                        ),
                    },
                    "tool": {
                        "name": "sandbox-exec",
                        "version_argv": ["sandbox-exec", "-h"],
                        "version": sandbox_output,
                        "executable": common.file_record(sandbox),
                    },
                },
                "evidence": evidence,
            },
        }

    def _url(self, filename: str) -> str:
        return self.release_url.replace("/tag/", "/download/") + "/" + filename

    def _artifact(self, path: Path) -> dict[str, object]:
        return {
            "filename": path.name,
            **common.file_record(path),
            "url": self._url(path.name),
        }

    def assert_valid_identity(self) -> None:
        self.assert_identity = common.load_identity(self.identity_path)
        if self.assert_identity != self.identity:
            raise AssertionError("fixture identity changed during validation")

    def stage(self) -> dict[str, object]:
        self.staging_workspace = self.root / "staging"
        self.staging_receipt = self.root / "staging-receipt.json"
        return staging.stage(
            argparse.Namespace(
                bootstrap_identity=self.identity_path,
                repository=self.repository,
                payload=self.payload,
                source_readme_template=self.source_template,
                frozen=self.frozen,
                resources=self.resources,
                runtime=self.runtime,
                documents=self.documents,
                binary_readme_template=self.binary_template,
                base_ledger=self.base_ledger,
                wheel=self.wheel,
                sdist=self.sdist,
                workspace=self.staging_workspace,
                receipt=self.staging_receipt,
            )
        )

    def finalize(
        self,
        *,
        receipt: dict[str, object],
        staged_identity_path: Path,
        ready_audit_payload: dict[str, object],
        source_audit_payload: dict[str, object],
    ) -> tuple[dict[str, object], Path, list[Path]]:
        identity = copy.deepcopy(common.load_identity(staged_identity_path))
        identity["inputs"]["staging_receipt"]["file"] = common.file_record(
            self.staging_receipt
        )
        artifacts_dir = self.root / "final-artifacts"
        artifacts_dir.mkdir()
        recheck = receipt["independent_recheck"]
        source_native = self.staging_workspace / recheck["corresponding_source"]["path"]
        ready_native = self.staging_workspace / recheck["ready_run"]["path"]
        sources = {
            "wheel": self.wheel,
            "sdist": self.sdist,
            "corresponding_source": source_native,
            "ready_run": ready_native,
        }
        for name, source in sources.items():
            destination = artifacts_dir / identity["artifacts"][name]["filename"]
            shutil.copyfile(source, destination)
            common.verify_artifact(
                destination, identity["artifacts"][name], label=f"fixture {name}"
            )

        commands = [captured_command(f"command-{index}") for index in range(3)]
        repro_roots: list[Path] = []
        root_receipts: list[dict[str, object]] = []
        builds: list[dict[str, object]] = []
        for index in range(2):
            logical = f"build-{index:02d}"
            root = self.root / f"reproduction-{index}"
            root.mkdir()
            for name in ("ready_run", "corresponding_source"):
                filename = identity["artifacts"][name]["filename"]
                shutil.copyfile(artifacts_dir / filename, root / filename)
            root_report = {
                "schema": "kazstem-macos-root-reproduction-v1",
                "logical_root": logical,
                "source_commit": identity["source_commit"],
                "source_tree": identity["source_tree"],
                "source_ref": identity["source_ref"],
                "source_tag_object": identity["verification"]["reproducibility"][
                    "canonical_python_authority"
                ]["source_tag_object"],
                "fresh_frozen_tree": identity["inputs"]["frozen_tree"],
                "artifacts": {
                    "ready_run": identity["artifacts"]["ready_run"],
                    "corresponding_source": identity["artifacts"][
                        "corresponding_source"
                    ],
                },
                "commands": commands,
            }
            root_report_path = root / "ROOT-REPRODUCTION.json"
            write_json(root_report_path, root_report)
            root_receipts.append(
                {
                    "logical_root": logical,
                    "path": f"{logical}/reproduction/ROOT-REPRODUCTION.json",
                    "file": common.file_record(root_report_path),
                }
            )
            native_assemblies: dict[str, object] = {
                "used_frozen_tree": identity["inputs"]["frozen_tree"]
            }
            for asset_name, schema in (
                (
                    "corresponding_source",
                    "kazstem-macos-source-assembly-receipt-v1",
                ),
                ("ready_run", "kazstem-macos-ready-assembly-receipt-v1"),
            ):
                canonical = identity["compression"][asset_name]["canonical_tar"]
                payload = {
                    "schema": schema,
                    "result": "pass",
                    "release": identity["release"],
                    "source_commit": identity["source_commit"],
                    "source_tree": identity["source_tree"],
                    "archive": identity["artifacts"][asset_name],
                    "canonical_tar": {
                        "filename": canonical["filename"],
                        "bytes": canonical["bytes"],
                        "sha256": canonical["sha256"],
                    },
                    "compression": {},
                }
                receipt_bytes = common.json_bytes(payload)
                native_assemblies[asset_name] = {
                    "canonical_tar": payload["canonical_tar"],
                    "receipt": {
                        "path": f"{logical}/native-work/{asset_name}-assembly-receipt.json",
                        "file": {
                            "bytes": len(receipt_bytes),
                            "sha256": hashlib.sha256(receipt_bytes).hexdigest(),
                        },
                        "payload": payload,
                    },
                }
            builds.append(
                {
                    "root": logical,
                    "canonical_python_inputs": {
                        name: {
                            "path": f"artifacts/{identity['artifacts'][name]['filename']}",
                            "file": {
                                "bytes": identity["artifacts"][name]["bytes"],
                                "sha256": identity["artifacts"][name]["sha256"],
                            },
                            "linux_authoritative": True,
                        }
                        for name in ("wheel", "sdist")
                    },
                    "frozen_build": {
                        "output_tree": identity["inputs"]["frozen_tree"],
                        "fresh_environment": True,
                        "commands": commands,
                    },
                    "native_assembly": native_assemblies,
                }
            )
            repro_roots.append(root)

        fixed = next(
            item for item in receipt["hypotheses"] if item["fixed_point"] is True
        )
        compression_assets: dict[str, object] = {}
        for name in ("ready_run", "corresponding_source"):
            comparison = copy.deepcopy(fixed[name])
            comparison["published"] = identity["artifacts"][name]
            comparison["selected"]["filename"] = identity["artifacts"][name]["filename"]
            comparison["canonical_tar"]["producer_receipts"] = [
                {
                    "root": build["root"],
                    "path": build["native_assembly"][name]["receipt"]["path"],
                    "file": build["native_assembly"][name]["receipt"]["file"],
                    "canonical_tar": build["native_assembly"][name]["canonical_tar"],
                }
                for build in builds
            ]
            compression_assets[name] = comparison

        events = [
            {
                "kind": "network-denial",
                "process": "kazstem",
                "result": "denied",
                "sequence": 0,
            }
        ]
        payloads: dict[str, dict[str, object]] = {
            "blackbox": {
                "schema": "kazstem-macos-blackbox-v1",
                "pass": True,
                "release": identity["release"],
                "source_commit": identity["source_commit"],
                "tests": 13,
                "resource_bundle_id": identity["inputs"]["resource_tree"][
                    "bundle_id"
                ],
                "resource_version": "fixture-resource-v1",
                "unsupported_special_entries": [],
                "neural_weight_files": [],
            },
            "compatibility-performance": {
                "schema": "kazstem-macos-mystem-json-performance-v2",
                "pass": True,
                "release": identity["release"],
                "source_commit": identity["source_commit"],
                "output_identity": True,
                "runs": [{"run": 1}, {"run": 2}],
            },
            "compression-comparison": {
                "schema": "kazstem-macos-compression-comparison-v2",
                "pass": True,
                "release": identity["release"],
                "source_commit": identity["source_commit"],
                "assets": compression_assets,
            },
            "macho-closure": {
                "schema": "kazstem-macos-macho-closure-v1",
                "pass": True,
                "release": identity["release"],
                "source_commit": identity["source_commit"],
                "architectures": ["arm64"],
                "fat_files": [],
                "missing": [],
                "escaped": [],
                "non_system_absolute_dependencies": [],
                "banned_dependencies": [],
                "banned_modules": [],
                "codesign_strict_failures": [],
                "container_signature_failures": [],
                "signed_containers": [
                    {
                        "strict_deep": True,
                        "signature": "adhoc",
                        "team_identifier": None,
                        "authorities": [],
                    }
                ],
                "signature_kind": "adhoc",
                "team_identifiers": [],
                "developer_id_signed": False,
                "notarized": False,
                "stapled": False,
                "maximum_minimum_os": "15.0",
                "runtime_manifest_verified": True,
                "runtime_bundle_id": identity["inputs"]["runtime_tree"]["bundle_id"],
            },
            "module-native-inclusion": {
                "schema": "kazstem-macos-module-native-inclusion-v1",
                "pass": True,
                "release": identity["release"],
                "source_commit": identity["source_commit"],
                "banned_module_matches": [],
                "banned_native_matches": [],
                "sha2_provider": "_sha2",
                "sha256_positive_control": True,
                "zlib_negative_control": True,
                "neural_weights": [],
            },
            "network-trace": {
                "schema": "kazstem-macos-network-trace-v1",
                "pass": True,
                "release": identity["release"],
                "source_commit": identity["source_commit"],
                "allowed_network_operations": 0,
                "sandbox_negative_control_denied": True,
                "full_descendant_coverage": True,
                "trace_truncated": False,
                "events": events,
            },
            "optimization-ledger": {
                "schema": "kazstem-macos-final-optimization-decision-ledger-v1",
                "pass": True,
                "release": identity["release"],
                "source_commit": identity["source_commit"],
                "accepted": [],
                "rejected": [{"candidate": "fixture-global-minimum-claim"}],
                "final_behavior_gate": "pass",
            },
            "practical": {
                "schema": "kazstem-macos-practical-matrix-v1",
                "pass": True,
                "release": identity["release"],
                "source_commit": identity["source_commit"],
                "cases": 70,
                "resource_bundle_id": identity["inputs"]["resource_tree"][
                    "bundle_id"
                ],
                "resource_schema": "fixture-resource-v1",
                "coverage": {
                    "bf1f_productive_generation": {
                        "required": False,
                        "executed_cases": 0,
                        "probe_schema": (
                            "kazstem-bf1f-productive-generation-probe-v1"
                        ),
                    },
                    "loader_environment": {
                        "clean_parent_official_gate": True,
                        "hostile_parent_non_official_probe": (
                            "kazstem-hostile-loader-scrub-probe-v1"
                        ),
                        "captured_names": [
                            "DYLD_FUTURE_INJECTOR",
                            "DYLD_INSERT_LIBRARIES",
                            "DYLD_LIBRARY_PATH",
                            "LD_FUTURE_INJECTOR",
                        ],
                        "glibc_tunables_captured": True,
                        "helper_environment_scrubbed": True,
                    },
                },
                "bundle_fingerprint_unchanged": True,
                "read_only_resource_runtime_unchanged": True,
                "network_tls_modules_absent": True,
                "lingering_native_processes": [],
            },
            "python-reproducibility": {
                "schema": "kazstem-macos-python-native-reproducibility-v1",
                "pass": True,
                "release": identity["release"],
                "source_commit": identity["source_commit"],
                "canonical_python_authority": identity["verification"][
                    "reproducibility"
                ]["canonical_python_authority"],
                "canonical_python_builds": 3,
                "canonical_artifacts": {
                    name: identity["artifacts"][name] for name in ("wheel", "sdist")
                },
                "native_direct_assemblies": 2,
                "fresh_frozen_builds": 2,
                "frozen_tree_identity": True,
                "filesystem_aliases": [],
                "builds": builds,
                "root_receipts": root_receipts,
            },
            "ready-archive-audit": copy.deepcopy(ready_audit_payload),
            "runtime-provenance": {
                "schema": "kazstem-macos-runtime-provenance-v2",
                "pass": True,
                "release": identity["release"],
                "source_commit": identity["source_commit"],
                "official": True,
                "verified": True,
                "non_official_reasons": [],
                "runtime_bundle_id": identity["inputs"]["runtime_tree"][
                    "bundle_id"
                ],
                "resource_bundle_id": identity["inputs"]["resource_tree"][
                    "bundle_id"
                ],
                "force_rehash": True,
                "provenance": clean_darwin_loader_provenance(),
                "loader_environment": common.verify_darwin_loader_provenance(
                    clean_darwin_loader_provenance()
                ),
            },
            "source-archive-audit": copy.deepcopy(source_audit_payload),
            "source-suite": {
                "schema": "kazstem-macos-source-suite-v1",
                "pass": True,
                "release": identity["release"],
                "source_commit": identity["source_commit"],
                "tests_run": 4,
                "failures": 0,
                "errors": 0,
                "skipped": 0,
            },
        }

        evidence_dir = self.root / "final-evidence"
        digest_path = self.root / "final-identity.json"
        digest_path.write_bytes(common.json_bytes(identity))
        digest = common.identity_sha256(digest_path)
        for audit_gate in ("ready-archive-audit", "source-archive-audit"):
            payloads[audit_gate]["identity_contract_sha256"] = digest
        for record in identity["verification"]["evidence"]:
            gate = record["gate"]
            envelope = common.gate_envelope(
                identity=identity,
                identity_contract_sha256=digest,
                gate=gate,
                subjects=record["subjects"],
                invocation=fixture_invocation(
                    identity, gate, stdout=b"fixture gate completed\n"
                ),
                coverage=gate_coverage(identity, gate),
                payload=payloads[gate],
            )
            path = evidence_dir / record["path"]
            write_json(path, envelope)
            record["file"] = common.file_record(path)
        digest_path.write_bytes(common.json_bytes(identity))
        if common.identity_sha256(digest_path) != digest:
            raise AssertionError(
                "evidence file records changed the stable identity digest"
            )
        common.load_identity(digest_path)
        output = self.root / "finalization.json"
        report = finalizer.finalize(
            argparse.Namespace(
                identity=digest_path,
                artifacts=artifacts_dir,
                evidence=evidence_dir,
                repro_root=repro_roots,
                output=output,
            )
        )
        return report, digest_path, repro_roots


class MacOSReleaseToolingTests(unittest.TestCase):
    def test_canonical_python_authority_contract_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = ReleaseFixture(Path(temporary))
            hostile = copy.deepcopy(fixture.identity)
            hostile["verification"]["reproducibility"][
                "canonical_python_authority"
            ]["linux_reproducibility"]["validated_distinct_roots"] = 2
            hostile_path = fixture.root / "hostile-authority-identity.json"
            write_json(hostile_path, hostile)
            with self.assertRaisesRegex(common.ReleaseError, "Linux root proof"):
                common.load_identity(hostile_path)

    def test_staging_rejects_ambiguous_compression_name_fixed_points(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = ReleaseFixture(Path(temporary))

            def ambiguous(
                _args: argparse.Namespace,
                *,
                base: dict[str, object],
                format_name: str,
                root: Path,
            ) -> tuple[dict[str, object], dict[str, object], dict[str, Path]]:
                del root
                return (
                    {"hypothesis": format_name, "fixed_point": True},
                    copy.deepcopy(base),
                    {},
                )

            with (
                mock.patch.object(staging, "_one_hypothesis", side_effect=ambiguous),
                self.assertRaisesRegex(common.ReleaseError, "unique fixed point"),
            ):
                fixture.stage()

    def test_staging_finds_unique_fixed_point_and_reproduces_both_archives(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = ReleaseFixture(Path(temporary))
            receipt = fixture.stage()
            self.assertTrue(receipt["pass"])
            fixed = [item for item in receipt["hypotheses"] if item["fixed_point"]]
            self.assertEqual(len(fixed), 1)
            selected = receipt["selected"]
            staged_path = (
                fixture.staging_workspace / selected["staged_identity"]["path"]
            )
            staged = common.load_identity(staged_path)
            self.assertEqual(staged["artifacts"]["ready_run"], selected["ready_run"])
            self.assertEqual(
                staged["artifacts"]["corresponding_source"],
                selected["corresponding_source"],
            )
            projection = common.source_identity_projection(staged)
            encoded = common.json_bytes(projection)
            self.assertNotIn(
                staged["artifacts"]["corresponding_source"]["sha256"].encode(),
                encoded,
            )
            self.assertNotIn(
                staged["artifacts"]["corresponding_source"]["filename"].encode(),
                encoded,
            )
            self.assertEqual(
                receipt["independent_recheck"]["ready_run"]["file"],
                {
                    "bytes": selected["ready_run"]["bytes"],
                    "sha256": selected["ready_run"]["sha256"],
                },
            )
            assets = fixture.staging_workspace / "final-recheck/assets"
            evidence = fixture.root / "archive-evidence"
            with (
                mock.patch.object(
                    ready_auditor, "begin_gate_execution", return_value=object()
                ),
                mock.patch.object(
                    ready_auditor,
                    "locked_gate_invocation",
                    side_effect=lambda identity,
                    gate,
                    stdout,
                    execution: fixture_invocation(identity, gate, stdout=stdout),
                ),
            ):
                ready_envelope = ready_auditor.audit(
                    argparse.Namespace(
                        archive=assets / selected["ready_run"]["filename"],
                        identity=staged_path,
                        fresh_root=fixture.root / "fresh-ready-audit",
                        output=evidence / "ready.json",
                    )
                )
            with (
                mock.patch.object(
                    source_auditor, "begin_gate_execution", return_value=object()
                ),
                mock.patch.object(
                    source_auditor,
                    "locked_gate_invocation",
                    side_effect=lambda identity,
                    gate,
                    stdout,
                    execution: fixture_invocation(identity, gate, stdout=stdout),
                ),
            ):
                source_envelope = source_auditor.audit(
                    argparse.Namespace(
                        archive=assets / selected["corresponding_source"]["filename"],
                        identity=staged_path,
                        fresh_root=fixture.root / "fresh-source-audit",
                        output=evidence / "source.json",
                    )
                )
            self.assertTrue(ready_envelope["payload"]["pass"])
            self.assertTrue(source_envelope["payload"]["nested_archives_pass"])
            report, final_identity, repro_roots = fixture.finalize(
                receipt=receipt,
                staged_identity_path=staged_path,
                ready_audit_payload=ready_envelope["payload"],
                source_audit_payload=source_envelope["payload"],
            )
            self.assertTrue(report["pass"])
            self.assertEqual(report["distinct_reproduction_roots"], 2)

            report_path = repro_roots[0] / "ROOT-REPRODUCTION.json"
            original_report = report_path.read_bytes()
            forged = common.read_json(report_path)
            forged["commands"].append(captured_command("forged-unbound-command"))
            write_json(report_path, forged)
            with self.assertRaisesRegex(common.ReleaseError, "not hash-bound"):
                finalizer.finalize(
                    argparse.Namespace(
                        identity=final_identity,
                        artifacts=fixture.root / "final-artifacts",
                        evidence=fixture.root / "final-evidence",
                        repro_root=repro_roots,
                        output=fixture.root / "forged-finalization.json",
                    )
                )
            report_path.write_bytes(original_report)

            final_ready = (
                fixture.root
                / "final-artifacts"
                / report["artifacts"]["ready_run"]["filename"]
            )
            root_ready = repro_roots[0] / final_ready.name
            root_ready.unlink()
            os.link(final_ready, root_ready)
            with self.assertRaisesRegex(common.ReleaseError, "hard-linked"):
                finalizer.finalize(
                    argparse.Namespace(
                        identity=final_identity,
                        artifacts=fixture.root / "final-artifacts",
                        evidence=fixture.root / "final-evidence",
                        repro_root=repro_roots,
                        output=fixture.root / "aliased-finalization.json",
                    )
                )


if __name__ == "__main__":
    unittest.main()
