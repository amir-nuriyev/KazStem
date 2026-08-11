from __future__ import annotations

import argparse
import base64
import csv
import gzip
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
import tarfile
import unittest
import zipfile


PROJECT_ROOT = Path(__file__).resolve().parents[1]
PACKAGING_ROOT = PROJECT_ROOT / "packaging"
sys.path.insert(0, str(PACKAGING_ROOT))

import build_canonical_python_artifacts as canonical  # noqa: E402


PYTHON_VERSION = ".".join(str(component) for component in sys.version_info[:3])
PYTHON_SOURCE_FILENAME = f"Python-{PYTHON_VERSION}.tgz"
PYTHON_SOURCE_URL = (
    f"https://www.python.org/ftp/python/{PYTHON_VERSION}/{PYTHON_SOURCE_FILENAME}"
)


def write_json(path: Path, value: object) -> None:
    path.write_bytes(canonical._json_bytes(value))


def write_stack_wheel(
    path: Path, *, distribution: str, version: str, module: str
) -> None:
    normalized = distribution.replace("-", "_")
    dist_info = f"{normalized}-{version}.dist-info"
    main = b""
    if distribution == "twine":
        main = b"print('fixture twine strict')\n"
    elif distribution == "pip":
        main = b"""from pathlib import Path
import sys, zipfile
arguments = sys.argv[1:]
target = Path(arguments[arguments.index('--target') + 1])
wheelhouse = Path(arguments[arguments.index('--find-links') + 1])
target.mkdir(parents=True)
for wheel in sorted(wheelhouse.glob('*.whl')):
    with zipfile.ZipFile(wheel) as archive:
        archive.extractall(target)
"""
    files = {
        f"{module}/__init__.py": b"",
        f"{module}/__main__.py": main,
        f"{dist_info}/METADATA": (
            f"Metadata-Version: 2.1\nName: {distribution}\nVersion: {version}\n\n"
        ).encode(),
        f"{dist_info}/WHEEL": (
            b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
        ),
    }
    record_name = f"{dist_info}/RECORD"
    rows = []
    for name, data in sorted(files.items()):
        digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=")
        rows.append((name, "sha256=" + digest.decode(), str(len(data))))
    rows.append((record_name, "", ""))
    record = io.StringIO()
    csv.writer(record, lineterminator="\n").writerows(rows)
    files[record_name] = record.getvalue().encode()
    with zipfile.ZipFile(path, "x", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in sorted(files.items()):
            info = zipfile.ZipInfo(name, (2026, 8, 10, 0, 0, 0))
            info.create_system = 3
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, data)


class CanonicalPythonArtifactBuilderTests(unittest.TestCase):
    def test_raw_sdist_pax_parser_is_strict_and_matches_tarfile(self) -> None:
        def pax_record(key: str, value: str) -> bytes:
            suffix = f" {key}={value}\n".encode()
            length = len(suffix) + 1
            while True:
                candidate = str(length).encode() + suffix
                if len(candidate) == length:
                    return candidate
                length = len(candidate)

        def header(name: str, size: int, entry_type: bytes) -> bytes:
            info = tarfile.TarInfo(name)
            info.size = size
            info.type = entry_type
            info.mode = 0o644
            return info.tobuf(format=tarfile.USTAR_FORMAT)

        def archive_bytes(
            metadata: bytes, *, global_header: bool = False
        ) -> bytes:
            result = bytearray()
            result.extend(
                header(
                    "././@PaxHeader",
                    len(metadata),
                    tarfile.XGLTYPE if global_header else tarfile.XHDTYPE,
                )
            )
            result.extend(metadata)
            result.extend(b"\0" * ((-len(metadata)) % 512))
            result.extend(header("short", 1, tarfile.REGTYPE))
            result.extend(b"x" + b"\0" * 511)
            result.extend(b"\0" * 1024)
            return gzip.compress(bytes(result), compresslevel=9, mtime=0)

        limits = {
            "max_artifact_bytes": 1024 * 1024,
            "max_members": 20,
            "max_total_uncompressed_bytes": 1024 * 1024,
        }
        identity = {"limits": limits}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            candidate = root / "candidate.tar.gz"
            valid_path = "kazstem-1.2.3/" + "n" * 120
            candidate.write_bytes(archive_bytes(pax_record("path", valid_path)))
            files = canonical._read_sdist(candidate, identity)
            self.assertEqual(files, {valid_path: (b"x", False)})

            hostile = {
                "size override": pax_record("size", "99"),
                "unknown override": pax_record("vendor.unknown", "x"),
                "duplicate key": pax_record("path", "one") + pax_record("path", "two"),
                "bad UTF-8": b"14 path=bad\xff\n",
                "bad length": b"099 path=x\n",
            }
            for label, metadata in hostile.items():
                with self.subTest(label=label):
                    candidate.write_bytes(archive_bytes(metadata))
                    with self.assertRaises(canonical.BuildError):
                        canonical._read_sdist(candidate, identity)
            candidate.write_bytes(
                archive_bytes(pax_record("path", valid_path), global_header=True)
            )
            with self.assertRaisesRegex(canonical.BuildError, "global"):
                canonical._read_sdist(candidate, identity)

    def test_source_load_ignores_unchecked_hash_supervisor_pyc(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            builder = root / "build_canonical_python_artifacts.py"
            supervisor = root / "process_supervisor.py"
            shutil.copyfile(PACKAGING_ROOT / builder.name, builder)
            clean_source = (PACKAGING_ROOT / supervisor.name).read_bytes()
            marker = root / "malicious-pyc-executed"
            supervisor.write_text(
                f"from pathlib import Path\nPath({str(marker)!r}).write_text('bad')\n"
                "raise RuntimeError('unchecked hash pyc executed')\n",
                encoding="utf-8",
            )
            py_compile.compile(
                str(supervisor),
                invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH,
                doraise=True,
            )
            supervisor.write_bytes(clean_source)
            completed = subprocess.run(
                [sys.executable, str(builder), "--help"],
                cwd=root,
                env={**os.environ, "PYTHONPATH": str(root)},
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=20,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr.decode())
            self.assertFalse(marker.exists())

    def test_documented_v2_interface_and_portable_paths_are_strict(self) -> None:
        documentation = (PACKAGING_ROOT / "CANONICAL-PYTHON-ARTIFACTS.md").read_text(
            encoding="utf-8"
        )
        for expected in (
            canonical.IDENTITY_SCHEMA,
            canonical.RECEIPT_SCHEMA,
            "--wheelhouse",
            "--requirements",
            "--interpreter-source",
            "--roundtrip-workspace",
            "USTAR",
        ):
            self.assertIn(expected, documentation)
        self.assertIn("not** a complete host-runtime", documentation)
        self.assertIn("ambient-system-dso-closure", documentation)
        for hostile in (
            "CON.txt",
            "folder/trailing. ",
            "folder/control\x01.txt",
            "folder/e\u0301.txt",
            "C:/rooted.txt",
        ):
            with self.subTest(path=hostile), self.assertRaises(canonical.BuildError):
                canonical._portable(hostile, "hostile path")

    def test_identity_rejects_unneeded_openssl_package_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _repository, identity_path, identity, _wheelhouse, _requirements = (
                self._fixture(root)
            )
            identity["interpreter_provenance"]["runtime_closure"][
                "source_packages"
            ].append(
                {
                    "name": "openssl",
                    "version": "3.0.0",
                    "architecture": "source",
                    "filename": "openssl-3.0.0.tar.gz",
                    "url": "https://example.invalid/openssl-3.0.0.tar.gz",
                    "file": canonical._file_record(root / PYTHON_SOURCE_FILENAME),
                }
            )
            identity["interpreter_provenance"]["runtime_closure"][
                "source_packages"
            ].sort(key=lambda item: item["filename"])
            write_json(identity_path, identity)
            with self.assertRaisesRegex(canonical.BuildError, "OpenSSL"):
                canonical.load_identity(identity_path)

    def _fixture(
        self, root: Path, *, raw_builder_tail: str = ""
    ) -> tuple[Path, Path, dict[str, object], Path, str]:
        repository = root / "repository"
        repository.mkdir()
        subprocess.run(["git", "init", "-q"], cwd=repository, check=True)
        shared = repository / "packaging/build_canonical_python_artifacts.py"
        shared.parent.mkdir()
        shutil.copyfile(PACKAGING_ROOT / "build_canonical_python_artifacts.py", shared)
        supervisor = repository / "packaging/process_supervisor.py"
        shutil.copyfile(PACKAGING_ROOT / "process_supervisor.py", supervisor)
        (repository / "pyproject.toml").write_text(
            "[build-system]\nrequires=[]\nbuild-backend='unused'\n",
            encoding="utf-8",
        )
        (repository / "packaging/cpython-BUILD.txt").write_text(
            "fixture CPython build recipe\n", encoding="utf-8"
        )
        (repository / "packaging/cpython-LICENSE").write_text(
            "fixture CPython license\n", encoding="utf-8"
        )
        interpreter_source = root / PYTHON_SOURCE_FILENAME
        interpreter_source.write_bytes(b"fixture CPython corresponding source\n")
        wheelhouse = root / "wheelhouse"
        wheelhouse.mkdir()
        stack_packages = [
            ("build", "build"),
            ("packaging", "packaging"),
            ("pip", "pip"),
            ("pyproject-hooks", "pyproject_hooks"),
            ("setuptools", "setuptools"),
            ("twine", "twine"),
            ("wheel", "wheel"),
        ]
        requirements_relative = "packaging/python-build-requirements.lock"
        requirements = []
        for distribution, module in stack_packages:
            filename = f"{distribution.replace('-', '_')}-1.0.0-py3-none-any.whl"
            path = wheelhouse / filename
            write_stack_wheel(
                path, distribution=distribution, version="1.0.0", module=module
            )
            requirements.append(
                f"{distribution}==1.0.0 --hash=sha256:{canonical._file_record(path)['sha256']}"
            )
        (repository / requirements_relative).write_text(
            "\n".join(requirements) + "\n", encoding="utf-8"
        )
        (repository / "raw_builder.py").write_text(
            """from __future__ import annotations
import base64
import csv
import gzip
import hashlib
import io
from pathlib import Path
import sys
import tarfile
import time
import zipfile

release = "1.2.3"
destination = Path(sys.argv[1])
destination.mkdir(parents=True)
wheel = destination / f"kazstem-{release}-py3-none-any.whl"
metadata = f"Metadata-Version: 2.1\\nName: kazstem\\nVersion: {release}\\n\\n".encode()
wheel_metadata = b"Wheel-Version: 1.0\\nGenerator: fixture\\nRoot-Is-Purelib: true\\nTag: py3-none-any\\n"
files = {
    "qazmorph/__init__.py": f"__version__ = '{release}'\\n".encode(),
    f"kazstem-{release}.dist-info/METADATA": metadata,
    f"kazstem-{release}.dist-info/WHEEL": wheel_metadata,
}
record_name = f"kazstem-{release}.dist-info/RECORD"
rows = []
for name, data in sorted(files.items()):
    digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
    rows.append((name, f"sha256={digest}", str(len(data))))
rows.append((record_name, "", ""))
buffer = io.StringIO()
csv.writer(buffer, lineterminator="\\n").writerows(rows)
files[record_name] = buffer.getvalue().encode()
stamp = time.localtime(Path("raw_builder.py").stat().st_mtime)
zip_stamp = (max(1980, stamp.tm_year), stamp.tm_mon, stamp.tm_mday, stamp.tm_hour, stamp.tm_min, stamp.tm_sec // 2 * 2)
with zipfile.ZipFile(wheel, "x", compression=zipfile.ZIP_DEFLATED) as archive:
    for name, data in files.items():
        info = zipfile.ZipInfo(name, zip_stamp)
        info.create_system = 3
        info.compress_type = zipfile.ZIP_DEFLATED
        info.external_attr = 0o100644 << 16
        archive.writestr(info, data)
sdist = destination / f"kazstem-{release}.tar.gz"
top = f"kazstem-{release}"
source_names = ["packaging/build_canonical_python_artifacts.py", "packaging/process_supervisor.py", "packaging/cpython-BUILD.txt", "packaging/cpython-LICENSE", "packaging/python-build-requirements.lock", "pyproject.toml", "raw_builder.py"]
with tarfile.open(sdist, "w:gz", format=tarfile.PAX_FORMAT) as archive:
    for relative in source_names:
        path = Path(relative)
        data = path.read_bytes()
        info = tarfile.TarInfo(f"{top}/{relative}")
        info.size = len(data)
        info.mode = 0o644
        info.mtime = int(path.stat().st_mtime)
        archive.addfile(info, io.BytesIO(data))
    info = tarfile.TarInfo(f"{top}/PKG-INFO")
    info.size = len(metadata)
    info.mode = 0o644
    info.mtime = int(Path("raw_builder.py").stat().st_mtime)
    archive.addfile(info, io.BytesIO(metadata))
""",
            encoding="utf-8",
        )
        if raw_builder_tail:
            raw_builder = repository / "raw_builder.py"
            raw_builder.write_text(
                raw_builder.read_text(encoding="utf-8") + "\n" + raw_builder_tail,
                encoding="utf-8",
            )
        subprocess.run(
            [
                "git",
                "add",
                "packaging/build_canonical_python_artifacts.py",
                "packaging/process_supervisor.py",
                "packaging/cpython-BUILD.txt",
                "packaging/cpython-LICENSE",
                requirements_relative,
                "pyproject.toml",
                "raw_builder.py",
            ],
            cwd=repository,
            check=True,
        )
        epoch = 1_786_361_661
        environment = {
            **os.environ,
            "GIT_AUTHOR_NAME": "Fixture",
            "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
            "GIT_COMMITTER_NAME": "Fixture",
            "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
            "GIT_AUTHOR_DATE": f"@{epoch} +0000",
            "GIT_COMMITTER_DATE": f"@{epoch} +0000",
        }
        subprocess.run(
            ["git", "commit", "-q", "-m", "canonical builder fixture"],
            cwd=repository,
            env=environment,
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
        source_ref = "refs/tags/v1.2.3"
        subprocess.run(
            ["git", "tag", "v1.2.3", commit],
            cwd=repository,
            check=True,
        )
        python = Path(shutil.which("python3") or sys.executable).resolve()
        tool = {
            "name": "python3",
            "version_argv": ["python3", "--version"],
            "version": subprocess.run(
                [str(python), "--version"],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                check=True,
            ).stdout.strip(),
            "executable": canonical._file_record(python),
        }
        dummy = {"bytes": 1, "sha256": "0" * 64}
        build_environment = {
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "PYTHONHASHSEED": "0",
            "SOURCE_DATE_EPOCH": str(epoch),
            "TZ": "UTC",
        }
        runtime_closure = {
            "schema": "kazstem-python-builder-byte-inputs-v1",
            "evidence_scope": {
                "statement": "canonical-artifact-byte-inputs-not-complete-system-runtime-v1",
                "bound_components": [
                    "declared-provider-binary-and-source-package-records",
                    "interpreter-executable",
                    "loaded-libz",
                    "standard-library-tree-with-declared-exclusions",
                    "zlib-extension-or-built-in-module",
                ],
                "not_claimed": [
                    "ambient-system-dso-closure",
                    "compiler-toolchain-derivation",
                    "interpreter-binary-rebuild-from-declared-source",
                ],
            },
            "provider": {
                "kind": "source-build",
                "name": "CPython",
                "upstream_version": PYTHON_VERSION,
                "version": PYTHON_VERSION,
                "architecture": canonical.platform.machine().casefold(),
                "build_id": None,
            },
            **canonical.interpreter_runtime_observation(),
            "packages": [],
            "source_packages": [
                {
                    "name": "cpython",
                    "version": PYTHON_VERSION,
                    "architecture": "source",
                    "filename": interpreter_source.name,
                    "url": PYTHON_SOURCE_URL,
                    "file": canonical._file_record(interpreter_source),
                }
            ],
        }
        identity: dict[str, object] = {
            "schema": canonical.IDENTITY_SCHEMA,
            "release": "1.2.3",
            "source_commit": commit,
            "source_tree": tree,
            "source_origin": origin,
            "source_ref": source_ref,
            "source_date_epoch": epoch,
            "distribution": "kazstem",
            "execution_platform": {
                "system": canonical.platform.system().casefold(),
                "machine": canonical.platform.machine().casefold(),
                "python_implementation": canonical.platform.python_implementation(),
            },
            "interpreter_provenance": {
                "implementation": "CPython",
                "runtime_closure": runtime_closure,
                "corresponding_source_path": (
                    f"build-inputs/{PYTHON_SOURCE_FILENAME}"
                ),
                "source_archive": {
                    "filename": interpreter_source.name,
                    "url": PYTHON_SOURCE_URL,
                    **canonical._file_record(interpreter_source),
                },
                "build_recipe": {
                    "path": "packaging/cpython-BUILD.txt",
                    "file": canonical._file_record(
                        repository / "packaging/cpython-BUILD.txt"
                    ),
                },
                "license": {
                    "path": "packaging/cpython-LICENSE",
                    "file": canonical._file_record(
                        repository / "packaging/cpython-LICENSE"
                    ),
                },
            },
            "git": {
                "name": "git",
                "version_argv": ["git", "--version"],
                "version": subprocess.run(
                    ["git", "--version"],
                    text=True,
                    stdout=subprocess.PIPE,
                    check=True,
                ).stdout.strip(),
                "executable": canonical._file_record(
                    Path(shutil.which("git") or "git").resolve()
                ),
            },
            "compression": {
                "implementation": "python-stdlib-zlib-deflate-9",
                "zlib_compile_version": canonical.zlib.ZLIB_VERSION,
                "zlib_runtime_version": canonical.zlib.ZLIB_RUNTIME_VERSION,
            },
            "metadata": {
                "metadata_version": "2.1",
                "license_expression": None,
                "required_classifiers": [],
                "wheel_version": "1.0",
            },
            "artifacts": {
                "wheel": {
                    "filename": "kazstem-1.2.3-py3-none-any.whl",
                    **dummy,
                },
                "sdist": {"filename": "kazstem-1.2.3.tar.gz", **dummy},
            },
            "build": {
                "argv": ["{python}", "-S", "raw_builder.py", "{raw_dist}"],
                "environment": build_environment,
                "tool": tool,
                "timeout_seconds": 60,
            },
            "roundtrip": {
                "argv": ["{python}", "-S", "raw_builder.py", "{raw_dist}"],
                "environment": build_environment,
                "tool": tool,
                "timeout_seconds": 60,
            },
            "build_stack": {
                "bootstrap_pip": {
                    "filename": "pip-1.0.0-py3-none-any.whl",
                    "version": "1.0.0",
                    "file": canonical._file_record(
                        wheelhouse / "pip-1.0.0-py3-none-any.whl"
                    ),
                },
                "requirements": {
                    "path": requirements_relative,
                    "file": canonical._file_record(repository / requirements_relative),
                },
                "wheelhouse": {
                    "files": [
                        {"filename": path.name, **canonical._file_record(path)}
                        for path in sorted(wheelhouse.iterdir())
                    ],
                    "manifest_sha256": canonical._canonical_hash(
                        [
                            {"filename": path.name, **canonical._file_record(path)}
                            for path in sorted(wheelhouse.iterdir())
                        ]
                    ),
                },
                "packages": [
                    {"name": name, "version": "1.0.0"}
                    for name, _module in stack_packages
                ],
                "provision_argv": [
                    "{python}", "-S", "-m", "pip", "install", "--no-index",
                    "--require-hashes", "--no-deps", "--only-binary=:all:",
                    "--target", "{build_env}", "--find-links", "{wheelhouse}",
                    "-r", "{requirements}",
                ],
                "metadata_check_argv": [
                    "{python}", "-S", "-m", "twine", "check", "--strict",
                    "{wheel}", "{sdist}",
                ],
            },
            "source_inputs": [
                {
                    "path": "packaging/cpython-BUILD.txt",
                    "file": canonical._file_record(
                        repository / "packaging/cpython-BUILD.txt"
                    ),
                },
                {
                    "path": "packaging/cpython-LICENSE",
                    "file": canonical._file_record(
                        repository / "packaging/cpython-LICENSE"
                    ),
                },
                {
                    "path": "packaging/process_supervisor.py",
                    "file": canonical._file_record(supervisor),
                },
                {
                    "path": requirements_relative,
                    "file": canonical._file_record(repository / requirements_relative),
                },
                {
                    "path": "pyproject.toml",
                    "file": canonical._file_record(repository / "pyproject.toml"),
                },
                {
                    "path": "raw_builder.py",
                    "file": canonical._file_record(repository / "raw_builder.py"),
                },
            ],
            "canonicalizer": {
                "path": "packaging/build_canonical_python_artifacts.py",
                "file": canonical._file_record(shared),
            },
            "helpers": {
                "process_supervisor": {
                    "path": "packaging/process_supervisor.py",
                    "file": canonical._file_record(supervisor),
                }
            },
            "limits": {
                "max_artifact_bytes": 8 * 1024**2,
                "max_members": 1000,
                "max_total_uncompressed_bytes": 32 * 1024**2,
            },
        }
        identity_path = root / "python-build-identity.json"
        write_json(identity_path, identity)
        return repository, identity_path, identity, wheelhouse, requirements_relative

    def test_normalizes_metadata_and_roundtrips_after_adversarial_retime(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository, identity_path, identity, wheelhouse, requirements = self._fixture(root)
            observation = root / "observation.json"
            with self.assertRaisesRegex(canonical.BuildError, "identity mismatch"):
                canonical.build(
                    argparse.Namespace(
                        identity=identity_path,
                        source_checkout=repository,
                        wheelhouse=wheelhouse,
                        interpreter_source=root / PYTHON_SOURCE_FILENAME,
                        requirements=requirements,
                        workspace=root / "probe-work",
                        roundtrip_workspace=root / "probe-roundtrip",
                        output_dir=root / "probe-dist",
                        receipt=root / "probe-receipt.json",
                        observation=observation,
                    )
                )
            identity["artifacts"] = json.loads(
                observation.read_text(encoding="utf-8")
            )["canonical_artifacts"]
            write_json(identity_path, identity)

            first = canonical.build(
                argparse.Namespace(
                    identity=identity_path,
                    source_checkout=repository,
                    wheelhouse=wheelhouse,
                    interpreter_source=root / PYTHON_SOURCE_FILENAME,
                    requirements=requirements,
                    workspace=root / "first-work",
                    roundtrip_workspace=root / "first-roundtrip",
                    output_dir=root / "first-dist",
                    receipt=root / "first-receipt.json",
                    observation=None,
                )
            )
            self.assertTrue(first["roundtrip"]["wheel_and_sdist_identical"])
            self.assertTrue(
                first["roundtrip"]["adversarial_retime"][
                    "all_differ_from_source_date_epoch"
                ]
            )
            for index, path in enumerate(sorted(repository.rglob("*"))):
                if path.is_file() and ".git" not in path.parts:
                    stamp = identity["source_date_epoch"] + 30 * 24 * 60 * 60 + index
                    os.utime(path, (stamp, stamp))
            second = canonical.build(
                argparse.Namespace(
                    identity=identity_path,
                    source_checkout=repository,
                    wheelhouse=wheelhouse,
                    interpreter_source=root / PYTHON_SOURCE_FILENAME,
                    requirements=requirements,
                    workspace=root / "second-work",
                    roundtrip_workspace=root / "second-roundtrip",
                    output_dir=root / "second-dist",
                    receipt=root / "second-receipt.json",
                    observation=None,
                )
            )
            self.assertEqual(first["canonical_artifacts"], second["canonical_artifacts"])
            for name in ("kazstem-1.2.3-py3-none-any.whl", "kazstem-1.2.3.tar.gz"):
                self.assertEqual(
                    (root / "first-dist" / name).read_bytes(),
                    (root / "second-dist" / name).read_bytes(),
                )

    def test_rejects_nested_roundtrip_root_and_corrupt_wheel_record(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository, identity_path, identity, wheelhouse, requirements = self._fixture(root)
            with self.assertRaisesRegex(canonical.BuildError, "equal/nested"):
                canonical.build(
                    argparse.Namespace(
                        identity=identity_path,
                        source_checkout=repository,
                        wheelhouse=wheelhouse,
                        interpreter_source=root / PYTHON_SOURCE_FILENAME,
                        requirements=requirements,
                        workspace=root / "work",
                        roundtrip_workspace=root / "work/roundtrip",
                        output_dir=root / "dist",
                        receipt=root / "receipt.json",
                        observation=None,
                    )
                )

            raw = root / "corrupt.whl"
            import zipfile

            with zipfile.ZipFile(raw, "w") as archive:
                archive.writestr("qazmorph/__init__.py", b"pass\n")
                archive.writestr(
                    "kazstem-1.2.3.dist-info/METADATA",
                    b"Metadata-Version: 2.1\nName: kazstem\nVersion: 1.2.3\n\n",
                )
                archive.writestr(
                    "kazstem-1.2.3.dist-info/WHEEL",
                    b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
                )
                archive.writestr(
                    "kazstem-1.2.3.dist-info/RECORD",
                    b"qazmorph/__init__.py,sha256=wrong,5\n",
                )
            loaded = canonical.load_identity(identity_path)
            with self.assertRaisesRegex(canonical.BuildError, "RECORD"):
                canonical._repack_wheel(raw, root / "corrupt-output.whl", loaded)

    def test_hard_caps_output_kills_descendants_and_rejects_source_symlink(self) -> None:
        cases = {
            "flood": "import os\nos.write(1, b'x' * (17 * 1024 * 1024))\n",
            "descendant": (
                "import subprocess\n"
                "subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])\n"
            ),
        }
        for name, tail in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                repository, identity_path, _identity, wheelhouse, requirements = (
                    self._fixture(root, raw_builder_tail=tail)
                )
                with self.assertRaisesRegex(
                    canonical.BuildError, "command (failed|left descendant|output)"
                ):
                    canonical.build(
                        argparse.Namespace(
                            identity=identity_path,
                            source_checkout=repository,
                            wheelhouse=wheelhouse,
                            interpreter_source=root / PYTHON_SOURCE_FILENAME,
                            requirements=requirements,
                            workspace=root / "work",
                            roundtrip_workspace=root / "roundtrip",
                            output_dir=root / "dist",
                            receipt=root / "receipt.json",
                            observation=root / "observation.json",
                        )
                    )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository, identity_path, _identity, wheelhouse, requirements = self._fixture(root)
            source_link = root / "source-link"
            source_link.symlink_to(repository, target_is_directory=True)
            with self.assertRaisesRegex(canonical.BuildError, "non-symlink"):
                canonical.build(
                    argparse.Namespace(
                        identity=identity_path,
                        source_checkout=source_link,
                        wheelhouse=wheelhouse,
                        interpreter_source=root / PYTHON_SOURCE_FILENAME,
                        requirements=requirements,
                        workspace=root / "work",
                        roundtrip_workspace=root / "roundtrip",
                        output_dir=root / "dist",
                        receipt=root / "receipt.json",
                        observation=root / "observation.json",
                    )
                )


if __name__ == "__main__":
    unittest.main()
