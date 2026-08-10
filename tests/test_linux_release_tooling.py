from __future__ import annotations

import argparse
import copy
import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile


PROJECT_ROOT = Path(__file__).resolve().parents[1]
LINUX_TOOLS = PROJECT_ROOT / "packaging" / "linux"
sys.path.insert(0, str(LINUX_TOOLS))

import assemble_corresponding_source as source_assembler  # noqa: E402
import assemble_ready_run as ready_assembler  # noqa: E402
import audit_corresponding_source_archive as source_auditor  # noqa: E402
import audit_ready_run_archive as ready_auditor  # noqa: E402
import finalize_release as finalizer  # noqa: E402
import normalize_runtime_provenance as provenance_normalizer  # noqa: E402
import release_common as common  # noqa: E402
import verify_python_reproducibility as python_reproducibility  # noqa: E402


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(common.json_bytes(value))


def archive_url(release_url: str, filename: str) -> str:
    return release_url.replace("/tag/", "/download/") + "/" + filename


def tar_bytes(member_name: str) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        data = b"payload\n"
        info = tarfile.TarInfo(member_name)
        info.size = len(data)
        archive.addfile(info, io.BytesIO(data))
    return output.getvalue()


def write_ar(path: Path, members: list[tuple[str, bytes]]) -> None:
    with path.open("wb") as output:
        output.write(b"!<arch>\n")
        for name, data in members:
            fields = (
                (name + "/").encode("ascii").ljust(16),
                b"0".ljust(12),
                b"0".ljust(6),
                b"0".ljust(6),
                b"100644".ljust(8),
                str(len(data)).encode("ascii").ljust(10),
                b"`\n",
            )
            output.write(b"".join(fields))
            output.write(data)
            if len(data) & 1:
                output.write(b"\n")


class ReleaseFixture:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.release = "9.8.7"
        self.commit = "1" * 40
        self.epoch = 1_786_361_661
        self.release_url = "https://github.com/owner/repository/releases/tag/v9.8.7"
        self.label = "linux-x86_64-test"
        self.ready_name = f"kazstem-{self.release}-{self.label}-ready-run.tar.xz"
        self.source_name = (
            f"kazstem-{self.release}-{self.label}-corresponding-source.tar.xz"
        )
        self.wheel_name = f"kazstem-{self.release}-py3-none-any.whl"
        self.sdist_name = f"kazstem-{self.release}.tar.gz"

        self.frozen = root / "frozen"
        launcher = self.frozen / "kazstem"
        launcher.parent.mkdir()
        launcher.write_text("#!/bin/sh\nprintf 'kazstem 9.8.7\\n'\n", encoding="utf-8")
        launcher.chmod(0o755)
        lock = self.frozen / "_internal/qazmorph/platform_runtime_assets.lock.json"
        write_json(lock, {"schema": "kazstem-platform-runtime-lock-v1", "runtimes": []})
        removed = self.frozen / "_internal/libz.so.1"
        removed.write_bytes(b"host-z")

        self.resource_id = "a" * 64
        self.resources = root / "resources"
        write_json(self.resources / "manifest.json", {"bundle_id": self.resource_id})
        (self.resources / "morphology.bin").write_bytes(b"kazakh-morphology")

        self.runtime_id = "b" * 64
        self.runtime = root / "runtime"
        write_json(self.runtime / "manifest.json", {"bundle_id": self.runtime_id})
        tool = self.runtime / "usr/bin/hfst-proc"
        tool.parent.mkdir(parents=True)
        tool.write_bytes(b"native-tool")
        tool.chmod(0o755)

        self.documents = root / "documents"
        self.documents.mkdir()
        (self.documents / "LICENSE").write_text("test license\n", encoding="utf-8")
        self.base_ledger = root / "base-ledger.json"
        write_json(
            self.base_ledger,
            {"schema": "test-freezer-ledger-v1", "paths": ["qazmorph/cli.py"]},
        )

        self.wheel = root / self.wheel_name
        with zipfile.ZipFile(
            self.wheel, "w", compression=zipfile.ZIP_DEFLATED
        ) as archive:
            archive.writestr("qazmorph/__init__.py", "__version__ = '9.8.7'\n")
        self.sdist = root / self.sdist_name
        with tarfile.open(self.sdist, "w:gz") as archive:
            data = b"source\n"
            info = tarfile.TarInfo(f"kazstem-{self.release}/README.md")
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))

        self.payload = root / "source-payload"
        (self.payload / "kazstem-source").mkdir(parents=True)
        (self.payload / "kazstem-source/SOURCE-COMMIT").write_text(
            self.commit + "\n", encoding="utf-8"
        )
        (self.payload / "kazstem-source/SOURCE_DATE_EPOCH").write_text(
            f"{self.epoch}\n", encoding="utf-8"
        )
        (self.payload / "kazstem-source/module.py").write_text(
            "VALUE = 1\n", encoding="utf-8"
        )
        for directory, filename in (
            ("build-inputs", "build-wheel.txt"),
            ("freezer-source", "pyinstaller-source.txt"),
            ("licenses", "LICENSE.txt"),
            ("resource-source", "morphology-source.txt"),
        ):
            target = self.payload / directory / filename
            target.parent.mkdir(parents=True)
            target.write_text(f"{directory}\n", encoding="utf-8")
        write_json(
            self.payload / "evidence/source-suite.json",
            {"pass": True, "log": "logs/source-suite.log"},
        )
        upstream = self.payload / "runtime-sources/upstream.tar.gz"
        upstream.parent.mkdir(parents=True)
        with tarfile.open(upstream, "w:gz") as archive:
            data = b"upstream source\n"
            info = tarfile.TarInfo("upstream-1.0/README")
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))

        evidence_seed_root = root / "evidence-seed"
        seed_values: dict[str, object] = {
            "blackbox.json": {
                "tests": 13,
                "unsupported_special_entries": [],
                "neural_weight_files": [],
            },
            "compatibility-performance.json": {
                "pass": True,
                "output_identity": True,
                "runs": [{"run": 0}, {"run": 1}],
            },
            "compression-comparison.json": {
                "candidates": [
                    {"format": "gzip", "byte_identical": True},
                    {"format": "xz", "byte_identical": True},
                ],
                "selected": "xz",
            },
            "elf-closure.json": {
                "pass": True,
                "missing": [],
                "escaped": [],
                "banned_dependencies": [],
                "banned_modules": [],
            },
            "optimization-ledger.json": {
                "accepted": [],
                "rejected": [],
                "final_behavior_gate": "pass",
            },
            "practical.json": {
                "result": "pass",
                "cases": 70,
                "bundle_fingerprint_unchanged": True,
                "read_only_resource_runtime_unchanged": True,
                "network_tls_modules_absent": True,
                "lingering_native_processes": [],
            },
            "python-reproducibility.json": {
                "pass": True,
                "wheel_direct_builds": 3,
                "sdist_direct_builds": 3,
                "sdist_to_wheel_identity": True,
            },
            "runtime-provenance.json": {
                "schema": "kazstem-linux-runtime-provenance-v2",
                "official": True,
                "verified": True,
                "non_official_reasons": [],
            },
        }
        seed_schemas = {
            "blackbox.json": "kazstem-linux-blackbox-v1",
            "compatibility-performance.json": "kazstem-linux-mystem-json-performance-v2",
            "compression-comparison.json": "kazstem-linux-compression-comparison-v1",
            "elf-closure.json": "kazstem-linux-elf-closure-v1",
            "optimization-ledger.json": "kazstem-linux-final-optimization-decision-ledger-v1",
            "practical.json": "kazstem-linux-practical-matrix-v1",
            "python-reproducibility.json": "kazstem-python-artifact-reproducibility-v1",
            "runtime-provenance.json": "kazstem-linux-runtime-provenance-v2",
        }
        for name, value in seed_values.items():
            if not isinstance(value, dict):
                raise AssertionError(name)
            value.update(
                {
                    "schema": seed_schemas[name],
                    "release": self.release,
                    "source_commit": self.commit,
                }
            )
        self.evidence_seed: dict[str, Path] = {}
        for name, value in seed_values.items():
            path = evidence_seed_root / name
            write_json(path, value)
            self.evidence_seed[name] = path
        for name, text in {
            "network-trace.log": "network syscalls: none\n",
            "source-suite.log": "Ran 1 test in 0.001s\n\nOK\n",
        }.items():
            path = evidence_seed_root / name
            path.write_text(text, encoding="utf-8")
            self.evidence_seed[name] = path
        self.binary_template = LINUX_TOOLS / "BINARY-README.template.md"
        self.source_template = LINUX_TOOLS / "CORRESPONDING-SOURCE-README.template.md"
        dummy = {"bytes": 1, "sha256": "0" * 64}
        ready_url = archive_url(self.release_url, self.ready_name)
        source_url = archive_url(self.release_url, self.source_name)
        wheel_url = archive_url(self.release_url, self.wheel_name)
        sdist_url = archive_url(self.release_url, self.sdist_name)
        nested = [
            {
                "path": f"python-artifacts/{self.sdist_name}",
                "format": "tar",
                **common.file_record(self.sdist),
            },
            {
                "path": f"python-artifacts/{self.wheel_name}",
                "format": "zip",
                **common.file_record(self.wheel),
            },
            {
                "path": "runtime-sources/upstream.tar.gz",
                "format": "tar",
                **common.file_record(upstream),
            },
        ]
        nested.sort(key=lambda item: item["path"])
        self.identity: dict[str, object] = {
            "schema": common.IDENTITY_SCHEMA,
            "release": self.release,
            "source_commit": self.commit,
            "source_date_epoch": self.epoch,
            "release_url": self.release_url,
            "platform": {
                "system": "linux",
                "machine": "x86_64",
                "label": self.label,
                "advertised_target": "Test Linux x86_64 (fixture only)",
                "generic_linux": False,
            },
            "artifacts": {
                "wheel": {
                    "filename": self.wheel_name,
                    **common.file_record(self.wheel),
                    "url": wheel_url,
                },
                "sdist": {
                    "filename": self.sdist_name,
                    **common.file_record(self.sdist),
                    "url": sdist_url,
                },
                "ready_run": {"filename": self.ready_name, **dummy, "url": ready_url},
                "corresponding_source": {
                    "filename": self.source_name,
                    **dummy,
                    "url": source_url,
                },
            },
            "inputs": {
                "frozen_tree": common.tree_record(self.frozen),
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
                "base_ledger": common.file_record(self.base_ledger),
                "binary_readme_template": common.file_record(self.binary_template),
                "source_readme_template": common.file_record(self.source_template),
                "documents": [
                    {
                        "source": "LICENSE",
                        "destination": "LICENSE",
                        "file": common.file_record(self.documents / "LICENSE"),
                    }
                ],
            },
            "ready_run": {
                "top_level": self.ready_name[:-7],
                "launcher": {"path": "kazstem", "file": common.file_record(launcher)},
                "platform_lock": {
                    "path": "_internal/qazmorph/platform_runtime_assets.lock.json",
                    "file": common.file_record(lock),
                },
                "resource_destination": ".qazmorph/resources",
                "runtime_parent": ".qazmorph/platform-runtimes",
                "aliases": ["mystem-kz", "qazmorph"],
                "remove_frozen_files": [
                    {"path": "_internal/libz.so.1", "file": common.file_record(removed)}
                ],
                "required_paths": sorted(
                    [
                        ".qazmorph/resources/manifest.json",
                        f".qazmorph/platform-runtimes/{self.runtime_id}/manifest.json",
                        "CORRESPONDING-SOURCE.json",
                        "LICENSE",
                        "README.md",
                        "kazstem",
                        "mystem-kz",
                        "qazmorph",
                        "verification/BUNDLE-MANIFEST.json",
                        "verification/BUNDLED-FILES.sha256",
                    ]
                ),
                "banned_name_fragments": sorted(
                    ["_hashlib.", "_ssl.", "libcrypto", "libssl"]
                ),
            },
            "corresponding_source": {
                "top_level": self.source_name[:-7],
                "evidence_root": "evidence",
                "source_categories": {
                    "application_source": "kazstem-source",
                    "build_inputs": "build-inputs",
                    "evidence": "evidence",
                    "freezer_source": "freezer-source",
                    "licenses": "licenses",
                    "resource_source": "resource-source",
                    "runtime_source": "runtime-sources",
                },
                "source_commit_file": "kazstem-source/SOURCE-COMMIT",
                "source_date_epoch_file": "kazstem-source/SOURCE_DATE_EPOCH",
                "required_paths": sorted(
                    [
                        "README.md",
                        "SHA256SUMS",
                        "SOURCE-IDENTITY.json",
                        "SOURCE-MANIFEST.json",
                        "build-inputs",
                        "build-inputs/build-wheel.txt",
                        "evidence",
                        "evidence/source-suite.json",
                        "freezer-source",
                        "freezer-source/pyinstaller-source.txt",
                        "kazstem-source",
                        "kazstem-source/SOURCE-COMMIT",
                        "kazstem-source/SOURCE_DATE_EPOCH",
                        "kazstem-source/module.py",
                        "licenses",
                        "licenses/LICENSE.txt",
                        f"python-artifacts/{self.sdist_name}",
                        f"python-artifacts/{self.wheel_name}",
                        "resource-source",
                        "resource-source/morphology-source.txt",
                        "runtime-sources",
                        "runtime-sources/upstream.tar.gz",
                    ]
                ),
                "nested_archives": nested,
            },
            "archive_limits": {
                "ready_run": {
                    "max_members": 1000,
                    "max_file_bytes": 2 * 1024**2,
                    "max_total_bytes": 8 * 1024**2,
                    "max_path_bytes": 512,
                },
                "corresponding_source": {
                    "max_members": 1000,
                    "max_file_bytes": 2 * 1024**2,
                    "max_total_bytes": 8 * 1024**2,
                    "max_path_bytes": 512,
                },
                "nested": {
                    "max_members": 1000,
                    "max_file_bytes": 2 * 1024**2,
                    "max_total_bytes": 8 * 1024**2,
                    "max_path_bytes": 512,
                },
            },
            "verification": {
                "minimum_distinct_roots": 2,
                "evidence": sorted(
                    [
                        {
                            "path": "blackbox.json",
                            "gate": "blackbox",
                            "kind": "json",
                            "file": common.file_record(
                                self.evidence_seed["blackbox.json"]
                            ),
                        },
                        {
                            "path": "compatibility-performance.json",
                            "gate": "compatibility-performance",
                            "kind": "json-pass",
                            "file": common.file_record(
                                self.evidence_seed["compatibility-performance.json"]
                            ),
                        },
                        {
                            "path": "compression-comparison.json",
                            "gate": "compression-comparison",
                            "kind": "json",
                            "file": common.file_record(
                                self.evidence_seed["compression-comparison.json"]
                            ),
                        },
                        {
                            "path": "elf-closure.json",
                            "gate": "elf-closure",
                            "kind": "json-pass",
                            "file": common.file_record(
                                self.evidence_seed["elf-closure.json"]
                            ),
                        },
                        {
                            "path": "network-trace.log",
                            "gate": "network-trace",
                            "kind": "text",
                            "file": common.file_record(
                                self.evidence_seed["network-trace.log"]
                            ),
                        },
                        {
                            "path": "optimization-ledger.json",
                            "gate": "optimization-ledger",
                            "kind": "json",
                            "file": common.file_record(
                                self.evidence_seed["optimization-ledger.json"]
                            ),
                        },
                        {
                            "path": "practical.json",
                            "gate": "practical",
                            "kind": "json-pass",
                            "file": common.file_record(
                                self.evidence_seed["practical.json"]
                            ),
                        },
                        {
                            "path": "python-reproducibility.json",
                            "gate": "python-reproducibility",
                            "kind": "json-pass",
                            "file": common.file_record(
                                self.evidence_seed["python-reproducibility.json"]
                            ),
                        },
                        {
                            "path": "ready-audit.json",
                            "gate": "ready-archive-audit",
                            "kind": "json-pass",
                            "file": dummy,
                        },
                        {
                            "path": "runtime-provenance.json",
                            "gate": "runtime-provenance",
                            "kind": "json",
                            "file": common.file_record(
                                self.evidence_seed["runtime-provenance.json"]
                            ),
                        },
                        {
                            "path": "source-audit.json",
                            "gate": "source-archive-audit",
                            "kind": "json-pass",
                            "file": dummy,
                        },
                        {
                            "path": "source-suite.log",
                            "gate": "source-suite",
                            "kind": "text",
                            "file": common.file_record(
                                self.evidence_seed["source-suite.log"]
                            ),
                        },
                    ],
                    key=lambda record: record["path"],
                ),
            },
        }
        self.identity_path = root / "release-identity.json"
        self.write_identity()

    def write_identity(self) -> None:
        write_json(self.identity_path, self.identity)

    def source_args(
        self, parent: Path, *, observation: Path | None = None
    ) -> argparse.Namespace:
        parent.mkdir(parents=True, exist_ok=True)
        return argparse.Namespace(
            identity=self.identity_path,
            payload=self.payload,
            source_readme_template=self.source_template,
            wheel=self.wheel,
            sdist=self.sdist,
            work_root=parent / "source-work",
            output=parent / self.source_name,
            observation=observation,
        )

    def ready_args(
        self, parent: Path, source: Path, *, observation: Path | None = None
    ) -> argparse.Namespace:
        parent.mkdir(parents=True, exist_ok=True)
        return argparse.Namespace(
            identity=self.identity_path,
            frozen=self.frozen,
            resources=self.resources,
            runtime=self.runtime,
            documents=self.documents,
            binary_readme_template=self.binary_template,
            base_ledger=self.base_ledger,
            wheel=self.wheel,
            sdist=self.sdist,
            corresponding_source=source,
            work_root=parent / "ready-work",
            output=parent / self.ready_name,
            observation=observation,
        )

    def seal_artifacts(self) -> tuple[Path, Path]:
        source_probe = self.root / "source-probe"
        observation = self.root / "source-observation.json"
        with self._expect_output_mismatch():
            source_assembler.assemble(
                self.source_args(source_probe, observation=observation)
            )
        if (source_probe / self.source_name).exists() or not list(
            source_probe.glob(f"{self.source_name}.unsealed-*")
        ):
            raise AssertionError("source mismatch was not quarantined")
        self.identity["artifacts"]["corresponding_source"] = json.loads(
            observation.read_text()
        )
        self.write_identity()

        sealed_source = self.root / "sealed-source"
        source_assembler.assemble(self.source_args(sealed_source))

        ready_probe = self.root / "ready-probe"
        ready_observation = self.root / "ready-observation.json"
        with self._expect_output_mismatch():
            ready_assembler.assemble(
                self.ready_args(
                    ready_probe,
                    sealed_source / self.source_name,
                    observation=ready_observation,
                )
            )
        if (ready_probe / self.ready_name).exists() or not list(
            ready_probe.glob(f"{self.ready_name}.unsealed-*")
        ):
            raise AssertionError("ready-run mismatch was not quarantined")
        self.identity["artifacts"]["ready_run"] = json.loads(
            ready_observation.read_text()
        )
        self.write_identity()

        reproduction_a = self.root / "reproduction-a"
        source_assembler.assemble(self.source_args(reproduction_a))
        ready_assembler.assemble(
            self.ready_args(reproduction_a, reproduction_a / self.source_name)
        )
        reproduction_b = self.root / "reproduction-b"
        source_assembler.assemble(self.source_args(reproduction_b))
        ready_assembler.assemble(
            self.ready_args(reproduction_b, reproduction_b / self.source_name)
        )
        return reproduction_a, reproduction_b

    @staticmethod
    def _expect_output_mismatch():
        return unittest.TestCase().assertRaisesRegex(
            common.ReleaseError, "output identity mismatch"
        )


class LinuxReleaseToolingTests(unittest.TestCase):
    def test_strict_identity_rejects_extra_fields_and_absolute_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = ReleaseFixture(Path(temporary))
            common.load_identity(fixture.identity_path)
            changed = copy.deepcopy(fixture.identity)
            changed["unexpected"] = True
            write_json(fixture.identity_path, changed)
            with self.assertRaisesRegex(common.ReleaseError, "fields differ"):
                common.load_identity(fixture.identity_path)
            changed = copy.deepcopy(fixture.identity)
            changed["verification"]["evidence"].pop()
            write_json(fixture.identity_path, changed)
            with self.assertRaisesRegex(common.ReleaseError, "evidence gates differ"):
                common.load_identity(fixture.identity_path)
            evidence = fixture.root / "bad-evidence"
            write_json(
                evidence / "gate.json", {"pass": True, "path": "/private/tmp/build"}
            )
            with self.assertRaisesRegex(common.ReleaseError, "absolute path"):
                common.assert_relative_evidence(evidence)

    def test_tar_and_zip_safety_rejects_hostile_members(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            limits = common.ArchiveLimits(20, 1024, 4096, 128)
            cases = [
                ("traversal", [("../escape", b"x", tarfile.REGTYPE, "")]),
                (
                    "duplicate",
                    [
                        ("root/a", b"x", tarfile.REGTYPE, ""),
                        ("root/a", b"y", tarfile.REGTYPE, ""),
                    ],
                ),
                (
                    "case",
                    [
                        ("root/A", b"x", tarfile.REGTYPE, ""),
                        ("root/a", b"y", tarfile.REGTYPE, ""),
                    ],
                ),
                ("ads", [("root/file:stream", b"x", tarfile.REGTYPE, "")]),
                ("special", [("root/fifo", b"", tarfile.FIFOTYPE, "")]),
                ("hardlink", [("root/hard", b"", tarfile.LNKTYPE, "root/target")]),
                ("symlink", [("root/link", b"", tarfile.SYMTYPE, "../../escape")]),
            ]
            for name, entries in cases:
                with self.subTest(name=name):
                    path = root / f"{name}.tar"
                    with tarfile.open(path, "w") as archive:
                        for member_name, data, member_type, linkname in entries:
                            info = tarfile.TarInfo(member_name)
                            info.type = member_type
                            info.linkname = linkname
                            info.size = (
                                len(data) if member_type == tarfile.REGTYPE else 0
                            )
                            archive.addfile(info, io.BytesIO(data) if data else None)
                    with self.assertRaises(common.ReleaseError):
                        common.inspect_tar(path, limits=limits)

            oversized = root / "oversized.tar"
            with tarfile.open(oversized, "w") as archive:
                data = b"x" * 1025
                info = tarfile.TarInfo("root/large")
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
            with self.assertRaisesRegex(common.ReleaseError, "file cap"):
                common.inspect_tar(oversized, limits=limits)

            hostile_zip = root / "hostile.zip"
            with zipfile.ZipFile(hostile_zip, "w") as archive:
                archive.writestr("root/A", b"x")
                archive.writestr("root/a", b"y")
            with self.assertRaisesRegex(common.ReleaseError, "case-colliding"):
                common.inspect_zip(hostile_zip, limits=limits)

            safe_deb = root / "safe.deb"
            write_ar(
                safe_deb,
                [
                    ("debian-binary", b"2.0\n"),
                    ("control.tar.gz", tar_bytes("control")),
                    ("data.tar.gz", tar_bytes("usr/bin/tool")),
                ],
            )
            deb_result = common.inspect_deb(safe_deb, limits=limits)
            self.assertGreaterEqual(deb_result["embedded_tar_members"], 2)
            hostile_deb = root / "hostile.deb"
            write_ar(
                hostile_deb,
                [
                    ("debian-binary", b"2.0\n"),
                    ("control.tar.gz", tar_bytes("control")),
                    ("data.tar.gz", tar_bytes("../../escape")),
                ],
            )
            with self.assertRaises(common.ReleaseError):
                common.inspect_deb(hostile_deb, limits=limits)

            zstd = Path("/usr/bin/zstd")
            if zstd.is_file():
                raw_tar = io.BytesIO()
                with tarfile.open(fileobj=raw_tar, mode="w") as archive:
                    data = b"zstd payload\n"
                    info = tarfile.TarInfo("usr/bin/tool")
                    info.size = len(data)
                    archive.addfile(info, io.BytesIO(data))
                compressed = subprocess.run(
                    [str(zstd), "-q", "-c"],
                    input=raw_tar.getvalue(),
                    stdout=subprocess.PIPE,
                    check=True,
                ).stdout
                zstd_deb = root / "zstd.deb"
                write_ar(
                    zstd_deb,
                    [
                        ("debian-binary", b"2.0\n"),
                        ("control.tar.zst", compressed),
                        ("data.tar.zst", compressed),
                    ],
                )
                self.assertGreater(
                    common.inspect_deb(zstd_deb, limits=limits)["embedded_tar_members"],
                    0,
                )

    def test_sdist_manifest_covers_every_linux_release_tool(self) -> None:
        manifest = (PROJECT_ROOT / "MANIFEST.in").read_text(encoding="utf-8")
        expected = {
            "packaging/linux/BINARY-README.template.md",
            "packaging/linux/CORRESPONDING-SOURCE-README.template.md",
            "packaging/linux/RELEASE-IDENTITY.md",
            "packaging/linux/assemble_corresponding_source.py",
            "packaging/linux/assemble_ready_run.py",
            "packaging/linux/audit_corresponding_source_archive.py",
            "packaging/linux/audit_ready_run_archive.py",
            "packaging/linux/benchmark_compat_linux.py",
            "packaging/linux/finalize_release.py",
            "packaging/linux/normalize_runtime_provenance.py",
            "packaging/linux/release_common.py",
            "packaging/linux/verify_python_reproducibility.py",
        }
        for relative in expected:
            with self.subTest(relative=relative):
                self.assertTrue((PROJECT_ROOT / relative).is_file())
                self.assertIn(f"include {relative}", manifest)

    def test_runtime_provenance_is_bound_and_made_bundle_relative(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = ReleaseFixture(Path(temporary))
            bundle = fixture.root / fixture.identity["ready_run"]["top_level"]
            runtime = bundle / ".qazmorph/platform-runtimes" / fixture.runtime_id
            runtime.parent.mkdir(parents=True)
            shutil.copytree(fixture.runtime, runtime)
            lib_a = runtime / "usr/lib/x86_64-linux-gnu"
            lib_b = runtime / "usr/lib"
            lib_a.mkdir(parents=True)
            lib_b.mkdir(exist_ok=True)
            manifest = runtime / "manifest.json"
            executable = runtime / "usr/bin/hfst-proc"
            raw = {
                "official": True,
                "verified": True,
                "non_official_reasons": [],
                "active_runtime": {
                    "bundle_id": fixture.runtime_id,
                    "platform_lock": {
                        "bundle_id": fixture.runtime_id,
                        "manifest": common.file_record(manifest),
                        "resource_bundle_ids": [fixture.resource_id],
                    },
                },
                "toolchain_manifest": {
                    "bundle_id": fixture.runtime_id,
                    **common.file_record(manifest),
                    "path": str(manifest),
                    "verified": True,
                },
                "executables": {
                    "hfst-proc": {
                        **common.file_record(executable),
                        "path": str(executable),
                        "verified": True,
                    }
                },
                "environment": {
                    "LD_LIBRARY_PATH": f"{lib_a}:{lib_b}",
                },
            }
            raw_path = fixture.root / "raw-provenance.json"
            write_json(raw_path, raw)
            output = fixture.root / "normalized-provenance.json"
            result = provenance_normalizer.normalize(
                argparse.Namespace(
                    identity=fixture.identity_path,
                    bundle_root=bundle,
                    input=raw_path,
                    output=output,
                )
            )
            rendered = output.read_text(encoding="utf-8")
            self.assertEqual(result["schema"], "kazstem-linux-runtime-provenance-v2")
            self.assertIn("bundle/.qazmorph/platform-runtimes", rendered)
            self.assertNotIn(str(fixture.root), rendered)

            raw["outside"] = "/etc/passwd"
            outside = fixture.root / "outside-provenance.json"
            write_json(outside, raw)
            with self.assertRaisesRegex(
                common.ReleaseError, "outside the extracted bundle"
            ):
                provenance_normalizer.normalize(
                    argparse.Namespace(
                        identity=fixture.identity_path,
                        bundle_root=bundle,
                        input=outside,
                        output=fixture.root / "outside-normalized.json",
                    )
                )

    def test_python_artifact_reproducibility_requires_three_roots_and_roundtrip(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = ReleaseFixture(Path(temporary))
            roots: list[Path] = []
            for index in range(3):
                root = fixture.root / f"python-build-{index}"
                root.mkdir()
                shutil.copyfile(fixture.wheel, root / fixture.wheel_name)
                shutil.copyfile(fixture.sdist, root / fixture.sdist_name)
                roots.append(root)
            roundtrip_root = fixture.root / "sdist-roundtrip"
            roundtrip_root.mkdir()
            roundtrip = roundtrip_root / fixture.wheel_name
            shutil.copyfile(fixture.wheel, roundtrip)
            output = fixture.root / "python-reproducibility.json"
            result = python_reproducibility.verify(
                argparse.Namespace(
                    identity=fixture.identity_path,
                    build_root=roots,
                    roundtrip_wheel=roundtrip,
                    output=output,
                )
            )
            self.assertTrue(result["pass"])
            self.assertEqual(result["wheel_direct_builds"], 3)
            self.assertEqual(result["sdist_direct_builds"], 3)
            self.assertTrue(result["sdist_to_wheel_identity"])
            self.assertNotIn(str(fixture.root), output.read_text(encoding="utf-8"))

    def test_deterministic_assemblers_auditors_and_finalizer(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = ReleaseFixture(Path(temporary))
            reproduction_a, reproduction_b = fixture.seal_artifacts()
            for filename in (fixture.source_name, fixture.ready_name):
                self.assertEqual(
                    (reproduction_a / filename).read_bytes(),
                    (reproduction_b / filename).read_bytes(),
                )

            evidence = fixture.root / "final-evidence"
            evidence.mkdir()
            for name, source in fixture.evidence_seed.items():
                shutil.copyfile(source, evidence / name)
            ready_report = evidence / "ready-audit.json"
            source_report = evidence / "source-audit.json"
            ready_auditor.audit(
                argparse.Namespace(
                    identity=fixture.identity_path,
                    archive=reproduction_a / fixture.ready_name,
                    fresh_root=fixture.root / "ready-extract",
                    output=ready_report,
                )
            )
            source_auditor.audit(
                argparse.Namespace(
                    identity=fixture.identity_path,
                    archive=reproduction_a / fixture.source_name,
                    fresh_root=fixture.root / "source-extract",
                    output=source_report,
                )
            )
            records = fixture.identity["verification"]["evidence"]
            by_gate = {record["gate"]: record for record in records}
            by_gate["ready-archive-audit"]["file"] = common.file_record(ready_report)
            by_gate["source-archive-audit"]["file"] = common.file_record(source_report)
            fixture.write_identity()

            repeated_ready = fixture.root / "ready-audit-repeat.json"
            repeated_source = fixture.root / "source-audit-repeat.json"
            ready_auditor.audit(
                argparse.Namespace(
                    identity=fixture.identity_path,
                    archive=reproduction_a / fixture.ready_name,
                    fresh_root=fixture.root / "ready-extract-repeat",
                    output=repeated_ready,
                )
            )
            source_auditor.audit(
                argparse.Namespace(
                    identity=fixture.identity_path,
                    archive=reproduction_a / fixture.source_name,
                    fresh_root=fixture.root / "source-extract-repeat",
                    output=repeated_source,
                )
            )
            self.assertEqual(ready_report.read_bytes(), repeated_ready.read_bytes())
            self.assertEqual(source_report.read_bytes(), repeated_source.read_bytes())

            artifacts = fixture.root / "artifacts"
            artifacts.mkdir()
            for source in (
                fixture.wheel,
                fixture.sdist,
                reproduction_a / fixture.ready_name,
                reproduction_a / fixture.source_name,
            ):
                shutil.copyfile(source, artifacts / source.name)
            result = finalizer.finalize(
                argparse.Namespace(
                    identity=fixture.identity_path,
                    artifacts=artifacts,
                    evidence=evidence,
                    repro_root=[reproduction_a, reproduction_b],
                    output=fixture.root / "final-release.json",
                )
            )
            self.assertTrue(result["pass"])
            self.assertEqual(
                {path.name for path in artifacts.iterdir()},
                {
                    fixture.wheel_name,
                    fixture.sdist_name,
                    fixture.ready_name,
                    fixture.source_name,
                    "SHA256SUMS",
                },
            )


if __name__ == "__main__":
    unittest.main()
