from __future__ import annotations

import argparse
import base64
import copy
import csv
import hashlib
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
import zipfile


PROJECT_ROOT = Path(__file__).resolve().parents[1]
PACKAGING_ROOT = PROJECT_ROOT / "packaging"
LINUX_TOOLS = PROJECT_ROOT / "packaging" / "linux"
sys.path.insert(0, str(LINUX_TOOLS))
sys.path.insert(0, str(PACKAGING_ROOT))

import assemble_corresponding_source as source_assembler  # noqa: E402
import build_canonical_python_artifacts as canonical_python_builder  # noqa: E402
import assemble_ready_run as ready_assembler  # noqa: E402
import audit_corresponding_source_archive as source_auditor  # noqa: E402
import audit_ready_run_archive as ready_auditor  # noqa: E402
import finalize_release as finalizer  # noqa: E402
import generate_compression_comparison as compression_generator  # noqa: E402
import generate_optimization_ledger as optimization_generator  # noqa: E402
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


def write_build_stack_wheel(
    path: Path, *, distribution: str, version: str, module: str
) -> None:
    normalized = distribution.replace("-", "_")
    dist_info = f"{normalized}-{version}.dist-info"
    main = b""
    if distribution == "twine":
        main = b"import sys\nprint('fixture metadata check')\nraise SystemExit(0)\n"
    elif distribution == "pip":
        main = b"""from pathlib import Path
import sys, zipfile
arguments = sys.argv[1:]
if arguments == ['--version']:
    print('pip 1.0.0 from identity-bound-wheel')
    raise SystemExit(0)
target = Path(arguments[arguments.index('--target') + 1])
target.mkdir(parents=True)
if '--find-links' in arguments:
    wheels = sorted(Path(arguments[arguments.index('--find-links') + 1]).glob('*.whl'))
else:
    wheels = [Path(arguments[-1])]
for wheel in wheels:
    with zipfile.ZipFile(wheel) as archive:
        archive.extractall(target)
"""
    elif distribution == "pyinstaller":
        main = b"""from pathlib import Path
import json, os, shutil, sys
arguments = sys.argv[1:]
dist = Path(arguments[arguments.index('--distpath') + 1]) / 'kazstem'
wheel = Path(os.environ['KAZSTEM_CANONICAL_WHEEL'])
dist.mkdir(parents=True)
launcher = dist / 'kazstem'
launcher.write_text('#!/bin/sh\\nprintf \\'kazstem 9.8.7\\\\n\\'\\n', encoding='utf-8')
launcher.chmod(0o755)
internal = dist / '_internal'
internal.mkdir()
shutil.copyfile(wheel, internal / wheel.name)
lock = internal / 'qazmorph/platform_runtime_assets.lock.json'
lock.parent.mkdir()
lock.write_text(json.dumps({'schema': 'kazstem-platform-runtime-lock-v1', 'runtimes': []}, indent=2, sort_keys=True) + '\\n', encoding='utf-8')
(internal / 'libz.so.1').write_bytes(b'host-z')
"""
    files = {
        f"{module}/__init__.py": b"",
        f"{module}/__main__.py": main,
        f"{dist_info}/METADATA": (
            f"Metadata-Version: 2.1\nName: {distribution}\nVersion: {version}\n\n"
        ).encode("utf-8"),
        f"{dist_info}/WHEEL": (
            b"Wheel-Version: 1.0\nGenerator: fixture\nRoot-Is-Purelib: true\n"
            b"Tag: py3-none-any\n"
        ),
        f"{dist_info}/licenses/LICENSE": (
            f"fixture license for {distribution}\n"
        ).encode("utf-8"),
    }
    record_name = f"{dist_info}/RECORD"
    rows: list[tuple[str, str, str]] = []
    for name, data in sorted(files.items()):
        digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=")
        rows.append((name, "sha256=" + digest.decode("ascii"), str(len(data))))
    rows.append((record_name, "", ""))
    output = io.StringIO()
    csv.writer(output, lineterminator="\n").writerows(rows)
    files[record_name] = output.getvalue().encode("utf-8")
    with zipfile.ZipFile(path, "x", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in sorted(files.items()):
            info = zipfile.ZipInfo(name, (2026, 8, 10, 0, 0, 0))
            info.create_system = 3
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, data)


def fixture_seccomp_library() -> Path:
    for candidate in (
        Path("/lib/x86_64-linux-gnu/libseccomp.so.2"),
        Path("/usr/lib/x86_64-linux-gnu/libseccomp.so.2"),
        Path("/lib64/libseccomp.so.2"),
        Path("/usr/lib64/libseccomp.so.2"),
    ):
        if candidate.exists():
            return candidate.resolve(strict=True)
    # Non-Linux source-only tests never execute the seccomp gate, but the
    # strict identity still requires a bounded regular-file record.
    return Path(sys.executable).resolve(strict=True)


class ReleaseFixture:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.release = "9.8.7"
        self.epoch = 1_786_361_661
        self.release_url = "https://github.com/owner/repository/releases/tag/v9.8.7"
        self.label = "linux-x86_64-test"
        self.ready_name = f"kazstem-{self.release}-{self.label}-ready-run.tar.xz"
        self.source_name = (
            f"kazstem-{self.release}-{self.label}-corresponding-source.tar.xz"
        )
        self.wheel_name = f"kazstem-{self.release}-py3-none-any.whl"
        self.sdist_name = f"kazstem-{self.release}.tar.gz"

        self.repository = root / "repository"
        self.repository.mkdir()
        subprocess.run(["git", "init", "-q"], cwd=self.repository, check=True)
        (self.repository / "module.py").write_text("VALUE = 1\n", encoding="utf-8")
        (self.repository / "build_fixture.py").write_text(
            """from __future__ import annotations
import base64
import csv
import hashlib
import io
from pathlib import Path
import sys
import tarfile
import zipfile

release = "9.8.7"
epoch = 1786361661
destination = Path(sys.argv[1])
destination.mkdir(parents=True, exist_ok=True)
module = Path("module.py").read_bytes()
wheel = destination / f"kazstem-{release}-py3-none-any.whl"
metadata = f"Metadata-Version: 2.1\\nName: kazstem\\nVersion: {release}\\n\\n".encode()
wheel_metadata = b"Wheel-Version: 1.0\\nGenerator: fixture\\nRoot-Is-Purelib: true\\nTag: py3-none-any\\n"
files = {
    "qazmorph/__init__.py": module,
    f"kazstem-{release}.dist-info/METADATA": metadata,
    f"kazstem-{release}.dist-info/WHEEL": wheel_metadata,
}
record_name = f"kazstem-{release}.dist-info/RECORD"
rows = []
for name, data in sorted(files.items()):
    digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
    rows.append((name, f"sha256={digest}", str(len(data))))
rows.append((record_name, "", ""))
record = io.StringIO()
csv.writer(record, lineterminator="\\n").writerows(rows)
files[record_name] = record.getvalue().encode()
with zipfile.ZipFile(wheel, "x", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
    for name, data in files.items():
        info = zipfile.ZipInfo(name, (2026, 8, 10, 0, 0, 0))
        info.create_system = 3
        info.compress_type = zipfile.ZIP_DEFLATED
        info.external_attr = 0o100644 << 16
        archive.writestr(info, data)
sdist = destination / f"kazstem-{release}.tar.gz"
with tarfile.open(sdist, "w:gz", format=tarfile.PAX_FORMAT) as archive:
    for relative in (
        "build_fixture.py",
        "module.py",
        "packaging/build_canonical_python_artifacts.py",
        "packaging/process_supervisor.py",
        "packaging/cpython-BUILD.txt",
        "packaging/cpython-LICENSE",
        "packaging/python-build-requirements.lock",
        "pyproject.toml",
    ):
        data = Path(relative).read_bytes()
        info = tarfile.TarInfo(f"kazstem-{release}/{relative}")
        info.size = len(data)
        info.mode = 0o644
        info.mtime = int(Path(relative).stat().st_mtime)
        archive.addfile(info, io.BytesIO(data))
    info = tarfile.TarInfo(f"kazstem-{release}/PKG-INFO")
    info.size = len(metadata)
    info.mode = 0o644
    info.mtime = int(Path("build_fixture.py").stat().st_mtime)
    archive.addfile(info, io.BytesIO(metadata))
""",
            encoding="utf-8",
        )
        (self.repository / "build_frozen_fixture.py").write_text(
            """from pathlib import Path, PurePosixPath
import base64
import csv
import hashlib
import io
import json
import sys
import zipfile

sys.path.insert(0, str(Path("packaging/linux").resolve()))
import release_common

wheel = Path(sys.argv[1])
if not wheel.is_file() or not wheel.name.endswith("-py3-none-any.whl"):
    raise SystemExit("canonical wheel missing")
first = wheel.read_bytes()
second = wheel.read_bytes()
if hashlib.sha256(first).digest() != hashlib.sha256(second).digest():
    raise SystemExit("wheel changed between complete reads")
destination = Path(sys.argv[2])
receipt_path = Path(sys.argv[3])
destination.mkdir(parents=True)
launcher = destination / "kazstem"
launcher.write_text("#!/bin/sh\\nprintf 'kazstem 9.8.7\\\\n'\\n", encoding="utf-8")
launcher.chmod(0o755)
lock = destination / "_internal/qazmorph/platform_runtime_assets.lock.json"
lock.parent.mkdir(parents=True)
lock.write_text(json.dumps({"schema": "kazstem-platform-runtime-lock-v1", "runtimes": []}, indent=2, sort_keys=True) + "\\n", encoding="utf-8")
(destination / "_internal/libz.so.1").write_bytes(b"host-z")
with zipfile.ZipFile(wheel) as archive:
    files = {info.filename: archive.read(info) for info in archive.infolist() if not info.is_dir()}
record_path = next(name for name in files if name.endswith(".dist-info/RECORD"))
rows = list(csv.reader(io.StringIO(files[record_path].decode("utf-8"))))
if len(rows) != len(files):
    raise SystemExit("incomplete wheel RECORD")
for name, digest, size in rows:
    if name == record_path:
        if digest or size:
            raise SystemExit("bad RECORD self row")
        continue
    data = files[name]
    observed = "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode("ascii")
    if digest != observed or size != str(len(data)):
        raise SystemExit("wheel RECORD mismatch")
package_files = [
    {"path": name, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
    for name, data in sorted(files.items()) if name.startswith("qazmorph/")
]
modules = []
for item in package_files:
    if not item["path"].endswith(".py"):
        continue
    parts = list(PurePosixPath(item["path"]).with_suffix("").parts)
    if parts[-1] == "__init__":
        parts.pop()
    modules.append({"module": ".".join(parts), "path": item["path"], "file": {"bytes": item["bytes"], "sha256": item["sha256"]}})
receipt = {
    "schema": "kazstem-frozen-wheel-consumption-receipt-v1",
    "pass": True,
    "wheel": {"filename": wheel.name, "bytes": len(first), "sha256": hashlib.sha256(first).hexdigest()},
    "record": {"path": record_path, "bytes": len(files[record_path]), "sha256": hashlib.sha256(files[record_path]).hexdigest()},
    "package": {"root": "qazmorph", "files": package_files, "inventory_sha256": release_common.canonical_hash(package_files)},
    "input_consumption": {"bytes_hashed_per_pass": len(first), "complete_sha256_passes": 2, "record_verified": True, "source_fallbacks_disabled": True},
    "embedded_package": {"analysis_complete": True, "mechanism": "checked-wheel-staging-to-frozen-analysis-v1", "modules": modules, "package_inventory_sha256": release_common.canonical_hash(package_files), "source": "canonical-wheel-only"},
    "frozen_tree": release_common.tree_record(destination),
}
receipt_path.write_bytes(release_common.json_bytes(receipt))
""",
            encoding="utf-8",
        )
        (self.repository / "compress_fixture.py").write_text(
            """from pathlib import Path
import gzip
import lzma
import sys

kind, source_name, destination_name = sys.argv[1:]
data = Path(source_name).read_bytes()
destination = Path(destination_name)
if kind == "gzip":
    with destination.open("xb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0, compresslevel=9) as output:
            output.write(data)
elif kind == "xz":
    destination.write_bytes(lzma.compress(data, format=lzma.FORMAT_XZ, preset=9 | lzma.PRESET_EXTREME))
else:
    raise SystemExit("unknown compressor")
""",
            encoding="utf-8",
        )
        (self.repository / "gate_payload_fixture.py").write_text(
            """from pathlib import Path
import json
import hashlib
import subprocess
import sys

gate_by_script = {
    "audit_corresponding_source_archive.py": "source-archive-audit",
    "audit_elf_closure.py": "elf-closure",
    "audit_ready_run_archive.py": "ready-archive-audit",
    "benchmark_compat_linux.py": "compatibility-performance",
    "blackbox_linux_bundle.py": "blackbox",
    "generate_compression_comparison.py": "compression-comparison",
    "generate_optimization_ledger.py": "optimization-ledger",
    "normalize_runtime_provenance.py": "runtime-provenance",
    "practical_matrix_linux.py": "practical",
    "run_network_workload.py": "network-trace",
    "run_source_suite.py": "source-suite",
    "verify_remote_tag.py": "source-authority",
    "verify_python_reproducibility.py": "python-reproducibility",
}
gate = gate_by_script[Path(__file__).name]
option = "--json" if "--json" in sys.argv else "--output"
output_name = sys.argv[sys.argv.index(option) + 1]
identity = json.loads(Path(sys.argv[sys.argv.index("--identity") + 1]).read_text(encoding="utf-8"))
commit = subprocess.run(["git", "rev-parse", "HEAD"], text=True, stdout=subprocess.PIPE, check=True).stdout.strip()
base = {"pass": True, "release": identity["release"], "source_commit": commit}
schemas = {
    "blackbox": "kazstem-linux-blackbox-v1",
    "compatibility-performance": "kazstem-linux-mystem-json-performance-v2",
    "compression-comparison": "kazstem-linux-compression-comparison-v2",
    "elf-closure": "kazstem-linux-elf-closure-v1",
    "network-trace": "kazstem-linux-network-trace-v1",
    "optimization-ledger": "kazstem-linux-final-optimization-decision-ledger-v2",
    "practical": "kazstem-linux-practical-matrix-v1",
    "python-reproducibility": "kazstem-python-artifact-reproducibility-v2",
    "ready-archive-audit": "kazstem-linux-ready-run-archive-audit-v2",
    "runtime-provenance": "kazstem-linux-runtime-provenance-v2",
    "source-archive-audit": "kazstem-linux-corresponding-source-audit-v2",
    "source-authority": "kazstem-linux-remote-tag-authority-v1",
    "source-suite": "kazstem-linux-source-suite-v1",
}
tag_records = [
    {"object": identity["source_tag_object"], "ref": identity["source_ref"]},
    {"object": identity["source_commit"], "ref": identity["source_ref"] + "^{}"},
]
tag_stdout = "".join(record["object"] + "\\t" + record["ref"] + "\\n" for record in tag_records).encode("ascii")
def stream(data):
    return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(), "lines": len(data.splitlines()), "truncated": False}
git_tool = next(item for item in identity["verification"]["reproducibility"]["tools"] if item["name"] == "git")
payloads = {
    "blackbox": {"schema": "kazstem-linux-blackbox-v1", "tests": 13, "unsupported_special_entries": [], "neural_weight_files": []},
    "source-suite": {"schema": "kazstem-linux-source-suite-v1", "tests_run": 4, "tests_discovered": 4, "test_ids_sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", "failures": 0, "errors": 0, "skipped": 0, "skipped_test_ids_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "expected_failures": 0, "expected_failure_test_ids_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "unexpected_successes": 0},
    "network-trace": {"schema": "kazstem-linux-network-trace-v1", "forbidden_syscalls": [], "full_descendant_coverage": False, "trace_truncated": False, "workload_bytes": 64, "workload_lines": 2, "workload_sha256": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"},
    "source-authority": {"schema": "kazstem-linux-remote-tag-authority-v1", "source_tree": identity["source_tree"], "source_origin": identity["source_origin"], "source_ref": identity["source_ref"], "source_tag_object": identity["source_tag_object"], "annotated_tag": True, "authoritative_remote": True, "remote": {"argv": ["git", "ls-remote", "--exit-code", "--tags", identity["source_origin"], identity["source_ref"], identity["source_ref"] + "^{}"], "exit_status": 0, "records": tag_records, "stdout": stream(tag_stdout), "stderr": stream(b""), "tool": git_tool}},
}
payload = {**base, "schema": schemas[gate], **payloads.get(gate, {})}
Path(output_name).write_text(json.dumps(payload, sort_keys=True) + "\\n", encoding="utf-8")
""",
            encoding="utf-8",
        )
        fixture_gate_paths = sorted(set(common.GATE_SCRIPT_PATHS.values()))
        gate_fixture_source = (
            self.repository / "gate_payload_fixture.py"
        ).read_text(encoding="utf-8")
        for relative in fixture_gate_paths:
            destination = self.repository / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(gate_fixture_source, encoding="utf-8")
        network_boundary_wrapper = (
            self.repository / "packaging/linux/run_no_network.py"
        )
        shutil.copyfile(
            LINUX_TOOLS / "run_no_network.py", network_boundary_wrapper
        )
        shutil.copyfile(
            LINUX_TOOLS / "verify_python_reproducibility.py",
            self.repository / "packaging/linux/verify_python_reproducibility.py",
        )
        shared_builder = self.repository / "packaging/build_canonical_python_artifacts.py"
        shared_builder.parent.mkdir(exist_ok=True)
        shutil.copyfile(
            PACKAGING_ROOT / "build_canonical_python_artifacts.py", shared_builder
        )
        shared_supervisor = self.repository / "packaging/process_supervisor.py"
        shutil.copyfile(PACKAGING_ROOT / "process_supervisor.py", shared_supervisor)
        fixture_linux = self.repository / "packaging/linux"
        fixture_linux.mkdir(exist_ok=True)
        for filename in (
            "assemble_corresponding_source.py",
            "assemble_ready_run.py",
            "build_frozen_from_wheel.py",
            "finalize_release.py",
            "frozen_wheel_entrypoint.py",
            "kazstem-minimal.spec",
            "release_common.py",
        ):
            shutil.copyfile(LINUX_TOOLS / filename, fixture_linux / filename)
        (self.repository / "pyproject.toml").write_text(
            "[build-system]\nrequires=[]\nbuild-backend='unused'\n",
            encoding="utf-8",
        )
        (self.repository / "packaging/cpython-BUILD.txt").write_text(
            "fixture CPython build recipe\n", encoding="utf-8"
        )
        (self.repository / "packaging/cpython-LICENSE").write_text(
            "fixture CPython license\n", encoding="utf-8"
        )
        self.python_version = ".".join(str(value) for value in sys.version_info[:3])
        self.python_interpreter_source = root / f"Python-{self.python_version}.tgz"
        self.python_interpreter_source.write_bytes(
            tar_bytes(f"Python-{self.python_version}/README")
        )
        self.python_wheelhouse = root / "python-build-wheelhouse"
        self.python_wheelhouse.mkdir()
        build_packages = [
            ("build", "build"),
            ("packaging", "packaging"),
            ("pip", "pip"),
            ("pyproject-hooks", "pyproject_hooks"),
            ("setuptools", "setuptools"),
            ("twine", "twine"),
            ("wheel", "wheel"),
        ]
        requirement_lines: list[str] = []
        for distribution, module in build_packages:
            filename = f"{distribution.replace('-', '_')}-1.0.0-py3-none-any.whl"
            wheel_path = self.python_wheelhouse / filename
            write_build_stack_wheel(
                wheel_path,
                distribution=distribution,
                version="1.0.0",
                module=module,
            )
            requirement_lines.append(
                f"{distribution}==1.0.0 --hash=sha256:"
                f"{canonical_python_builder._file_record(wheel_path)['sha256']}"
            )
        self.python_freezer_wheelhouse = root / "python-freezer-wheelhouse"
        self.python_freezer_wheelhouse.mkdir()
        freezer_packages = [
            ("altgraph", "altgraph"),
            ("packaging", "packaging"),
            ("pip", "pip"),
            ("pyinstaller", "PyInstaller"),
            ("pyinstaller-hooks-contrib", "pyinstaller_hooks_contrib"),
            ("setuptools", "setuptools"),
        ]
        freezer_requirement_lines: list[str] = []
        for distribution, module in freezer_packages:
            filename = f"{distribution.replace('-', '_')}-1.0.0-py3-none-any.whl"
            wheel_path = self.python_freezer_wheelhouse / filename
            write_build_stack_wheel(
                wheel_path,
                distribution=distribution,
                version="1.0.0",
                module=module,
            )
            freezer_requirement_lines.append(
                f"{distribution}==1.0.0 --hash=sha256:"
                f"{canonical_python_builder._file_record(wheel_path)['sha256']}"
            )
        self.python_freezer_requirements_relative = (
            "packaging/linux/python-freezer-requirements.lock"
        )
        (self.repository / self.python_freezer_requirements_relative).write_text(
            "\n".join(freezer_requirement_lines) + "\n", encoding="utf-8"
        )
        self.python_requirements_relative = "packaging/python-build-requirements.lock"
        (self.repository / self.python_requirements_relative).write_text(
            "\n".join(requirement_lines) + "\n", encoding="utf-8"
        )
        subprocess.run(
            [
                "git",
                "add",
                "build_fixture.py",
                "build_frozen_fixture.py",
                "compress_fixture.py",
                "gate_payload_fixture.py",
                "module.py",
                "packaging/build_canonical_python_artifacts.py",
                "packaging/process_supervisor.py",
                "packaging/cpython-BUILD.txt",
                "packaging/cpython-LICENSE",
                "packaging/linux/assemble_corresponding_source.py",
                "packaging/linux/assemble_ready_run.py",
                "packaging/linux/build_frozen_from_wheel.py",
                "packaging/linux/finalize_release.py",
                "packaging/linux/frozen_wheel_entrypoint.py",
                "packaging/linux/kazstem-minimal.spec",
                "packaging/linux/release_common.py",
                "packaging/linux/run_no_network.py",
                self.python_freezer_requirements_relative,
                self.python_requirements_relative,
                "pyproject.toml",
                *fixture_gate_paths,
            ],
            cwd=self.repository,
            check=True,
        )
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
        self.source_origin = "https://github.com/owner/repository.git"
        subprocess.run(
            ["git", "remote", "add", "origin", self.source_origin],
            cwd=self.repository,
            check=True,
        )
        branch = subprocess.run(
            ["git", "symbolic-ref", "--short", "HEAD"],
            cwd=self.repository,
            text=True,
            stdout=subprocess.PIPE,
            check=True,
        ).stdout.strip()
        self.commit = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=self.repository,
            text=True,
            stdout=subprocess.PIPE,
            check=True,
        ).stdout.strip()
        self.source_tree = subprocess.run(
            ["git", "rev-parse", "HEAD^{tree}"],
            cwd=self.repository,
            text=True,
            stdout=subprocess.PIPE,
            check=True,
        ).stdout.strip()
        self.source_ref = f"refs/tags/v{self.release}"
        subprocess.run(
            [
                "git",
                "tag",
                "-a",
                "-m",
                f"KazStem {self.release} fixture",
                f"v{self.release}",
                self.commit,
            ],
            cwd=self.repository,
            env=git_environment,
            check=True,
        )
        self.source_tag_object = subprocess.run(
            ["git", "rev-parse", f"{self.source_ref}^{{tag}}"],
            cwd=self.repository,
            text=True,
            stdout=subprocess.PIPE,
            check=True,
        ).stdout.strip()
        self.git_version = subprocess.run(
            ["git", "--version"],
            text=True,
            stdout=subprocess.PIPE,
            check=True,
        ).stdout.strip()
        self.git_archive = root / "canonical-git-archive.tar"
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

        python_path = Path(shutil.which("python3") or sys.executable).resolve()
        python_tool = {
            "name": "python3",
            "version_argv": ["python3", "--version"],
            "version": subprocess.run(
                [str(python_path), "--version"],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                check=True,
            ).stdout.strip(),
            "executable": canonical_python_builder._file_record(python_path),
        }
        build_environment = {
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "PYTHONHASHSEED": "0",
            "SOURCE_DATE_EPOCH": str(self.epoch),
            "TZ": "UTC",
        }
        python_dummy = {"bytes": 1, "sha256": "0" * 64}
        python_wheels = [
            {"filename": path.name, **canonical_python_builder._file_record(path)}
            for path in sorted(self.python_wheelhouse.iterdir())
        ]
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
                "upstream_version": self.python_version,
                "version": self.python_version,
                "architecture": canonical_python_builder.platform.machine().casefold(),
                "build_id": None,
            },
            **canonical_python_builder.interpreter_runtime_observation(),
            "packages": [],
            "source_packages": [
                {
                    "name": "cpython",
                    "version": self.python_version,
                    "architecture": "source",
                    "filename": self.python_interpreter_source.name,
                    "url": (
                        f"https://www.python.org/ftp/python/{self.python_version}/"
                        f"Python-{self.python_version}.tgz"
                    ),
                    "file": canonical_python_builder._file_record(
                        self.python_interpreter_source
                    ),
                }
            ],
        }
        self.python_build_identity: dict[str, object] = {
            "schema": canonical_python_builder.IDENTITY_SCHEMA,
            "release": self.release,
            "source_commit": self.commit,
            "source_tree": self.source_tree,
            "source_origin": self.source_origin,
            "source_ref": self.source_ref,
            "source_date_epoch": self.epoch,
            "distribution": "kazstem",
            "execution_platform": {
                "system": canonical_python_builder.platform.system().casefold(),
                "machine": canonical_python_builder.platform.machine().casefold(),
                "python_implementation": canonical_python_builder.platform.python_implementation(),
            },
            "interpreter_provenance": {
                "implementation": "CPython",
                "runtime_closure": runtime_closure,
                "corresponding_source_path": (
                    f"build-inputs/Python-{self.python_version}.tgz"
                ),
                "source_archive": {
                    "filename": self.python_interpreter_source.name,
                    "url": (
                        f"https://www.python.org/ftp/python/{self.python_version}/"
                        f"Python-{self.python_version}.tgz"
                    ),
                    **canonical_python_builder._file_record(
                        self.python_interpreter_source
                    ),
                },
                "build_recipe": {
                    "path": "packaging/cpython-BUILD.txt",
                    "file": canonical_python_builder._file_record(
                        self.repository / "packaging/cpython-BUILD.txt"
                    ),
                },
                "license": {
                    "path": "packaging/cpython-LICENSE",
                    "file": canonical_python_builder._file_record(
                        self.repository / "packaging/cpython-LICENSE"
                    ),
                },
            },
            "git": {
                "name": "git",
                "version_argv": ["git", "--version"],
                "version": self.git_version,
                "executable": canonical_python_builder._file_record(
                    Path(shutil.which("git") or "git").resolve()
                ),
            },
            "compression": {
                "implementation": "python-stdlib-zlib-deflate-9",
                "zlib_compile_version": canonical_python_builder.zlib.ZLIB_VERSION,
                "zlib_runtime_version": canonical_python_builder.zlib.ZLIB_RUNTIME_VERSION,
            },
            "metadata": {
                "metadata_version": "2.1",
                "license_expression": None,
                "required_classifiers": [],
                "wheel_version": "1.0",
            },
            "artifacts": {
                "wheel": {"filename": self.wheel_name, **python_dummy},
                "sdist": {"filename": self.sdist_name, **python_dummy},
            },
            "build": {
                "argv": ["{python}", "-S", "build_fixture.py", "{raw_dist}"],
                "environment": build_environment,
                "tool": python_tool,
                "timeout_seconds": 60,
            },
            "roundtrip": {
                "argv": ["{python}", "-S", "build_fixture.py", "{raw_dist}"],
                "environment": build_environment,
                "tool": python_tool,
                "timeout_seconds": 60,
            },
            "build_stack": {
                "bootstrap_pip": {
                    "filename": "pip-1.0.0-py3-none-any.whl",
                    "version": "1.0.0",
                    "file": canonical_python_builder._file_record(
                        self.python_wheelhouse / "pip-1.0.0-py3-none-any.whl"
                    ),
                },
                "requirements": {
                    "path": self.python_requirements_relative,
                    "file": canonical_python_builder._file_record(
                        self.repository / self.python_requirements_relative
                    ),
                },
                "wheelhouse": {
                    "files": python_wheels,
                    "manifest_sha256": canonical_python_builder._canonical_hash(
                        python_wheels
                    ),
                },
                "packages": [
                    {"name": name, "version": "1.0.0"}
                    for name in sorted(
                        [
                            "build",
                            "packaging",
                            "pip",
                            "pyproject-hooks",
                            "setuptools",
                            "twine",
                            "wheel",
                        ]
                    )
                ],
                "provision_argv": [
                    "{python}",
                    "-S",
                    "-m",
                    "pip",
                    "install",
                    "--no-index",
                    "--require-hashes",
                    "--no-deps",
                    "--only-binary=:all:",
                    "--target",
                    "{build_env}",
                    "--find-links",
                    "{wheelhouse}",
                    "-r",
                    "{requirements}",
                ],
                "metadata_check_argv": [
                    "{python}",
                    "-S",
                    "-m",
                    "twine",
                    "check",
                    "--strict",
                    "{wheel}",
                    "{sdist}",
                ],
            },
            "source_inputs": [
                {
                    "path": "build_fixture.py",
                    "file": canonical_python_builder._file_record(
                        self.repository / "build_fixture.py"
                    ),
                },
                {
                    "path": "packaging/cpython-BUILD.txt",
                    "file": canonical_python_builder._file_record(
                        self.repository / "packaging/cpython-BUILD.txt"
                    ),
                },
                {
                    "path": "packaging/cpython-LICENSE",
                    "file": canonical_python_builder._file_record(
                        self.repository / "packaging/cpython-LICENSE"
                    ),
                },
                {
                    "path": "packaging/process_supervisor.py",
                    "file": canonical_python_builder._file_record(
                        shared_supervisor
                    ),
                },
                {
                    "path": self.python_requirements_relative,
                    "file": canonical_python_builder._file_record(
                        self.repository / self.python_requirements_relative
                    ),
                },
                {
                    "path": "pyproject.toml",
                    "file": canonical_python_builder._file_record(
                        self.repository / "pyproject.toml"
                    ),
                },
            ],
            "canonicalizer": {
                "path": "packaging/build_canonical_python_artifacts.py",
                "file": canonical_python_builder._file_record(shared_builder),
            },
            "helpers": {
                "process_supervisor": {
                    "path": "packaging/process_supervisor.py",
                    "file": canonical_python_builder._file_record(
                        shared_supervisor
                    ),
                }
            },
            "limits": {
                "max_artifact_bytes": 8 * 1024**2,
                "max_members": 1000,
                "max_total_uncompressed_bytes": 32 * 1024**2,
            },
        }
        self.python_build_identity_path = root / "python-build-identity.json"
        write_json(self.python_build_identity_path, self.python_build_identity)
        python_observation = root / "python-build-observation.json"
        with unittest.TestCase().assertRaisesRegex(
            canonical_python_builder.BuildError, "identity mismatch"
        ):
            canonical_python_builder.build(
                argparse.Namespace(
                    identity=self.python_build_identity_path,
                    source_checkout=self.repository,
                    wheelhouse=self.python_wheelhouse,
                    interpreter_source=self.python_interpreter_source,
                    requirements=self.python_requirements_relative,
                    workspace=root / "python-probe-work",
                    roundtrip_workspace=root / "python-probe-roundtrip",
                    output_dir=root / "python-probe-dist",
                    receipt=root / "python-probe-receipt.json",
                    observation=python_observation,
                )
            )
        self.python_build_identity["artifacts"] = json.loads(
            python_observation.read_text(encoding="utf-8")
        )["canonical_artifacts"]
        write_json(self.python_build_identity_path, self.python_build_identity)
        canonical_python_builder.build(
            argparse.Namespace(
                identity=self.python_build_identity_path,
                source_checkout=self.repository,
                wheelhouse=self.python_wheelhouse,
                interpreter_source=self.python_interpreter_source,
                requirements=self.python_requirements_relative,
                workspace=root / "python-canonical-work",
                roundtrip_workspace=root / "python-canonical-roundtrip",
                output_dir=root / "python-canonical-dist",
                receipt=root / "python-canonical-receipt.json",
                observation=None,
            )
        )
        self.wheel = root / self.wheel_name
        self.sdist = root / self.sdist_name
        shutil.copyfile(root / "python-canonical-dist" / self.wheel_name, self.wheel)
        shutil.copyfile(root / "python-canonical-dist" / self.sdist_name, self.sdist)
        shutil.copyfile(
            self.wheel,
            self.frozen / "_internal" / self.wheel_name,
        )

        self.payload = root / "source-payload"
        for directory, filename in (
            ("build-inputs", "build-wheel.txt"),
            ("freezer-source", "pyinstaller-source.txt"),
            ("licenses", "LICENSE.txt"),
            ("resource-source", "morphology-source.txt"),
        ):
            target = self.payload / directory / filename
            target.parent.mkdir(parents=True)
            target.write_text(f"{directory}\n", encoding="utf-8")
        material_license_paths = {
            "freezer": self.payload / "licenses/freezer-LICENSE.txt",
            self.resource_id: self.payload / "licenses/resource-LICENSE.txt",
            self.runtime_id: self.payload / "licenses/runtime-LICENSE.txt",
        }
        for subject, path in material_license_paths.items():
            path.write_text(f"fixture license for {subject}\n", encoding="utf-8")
        shutil.copyfile(
            self.python_interpreter_source,
            self.payload / "build-inputs" / self.python_interpreter_source.name,
        )
        python_identity_companion = self.payload / "build-inputs/PYTHON-BUILD-IDENTITY.json"
        shutil.copyfile(self.python_build_identity_path, python_identity_companion)
        requirements_companion = self.payload / "build-inputs/python-build-requirements.lock"
        shutil.copyfile(
            self.repository / self.python_requirements_relative,
            requirements_companion,
        )
        recipe_companion = self.payload / "build-inputs/cpython-BUILD.txt"
        shutil.copyfile(
            self.repository / "packaging/cpython-BUILD.txt", recipe_companion
        )
        cpython_license_companion = self.payload / "licenses/cpython-LICENSE"
        shutil.copyfile(
            self.repository / "packaging/cpython-LICENSE",
            cpython_license_companion,
        )
        wheelhouse_companion_root = self.payload / "build-inputs/python-build-wheelhouse"
        wheelhouse_companion_root.mkdir()
        license_companion_root = self.payload / "licenses/python-build"
        license_companion_root.mkdir()
        self.python_source_companions = [
            {
                "path": "build-inputs/PYTHON-BUILD-IDENTITY.json",
                "role": "canonical-python-identity",
                "subject": "identity",
                "source_member": None,
                "file": common.file_record(python_identity_companion),
            },
            {
                "path": f"build-inputs/{self.python_interpreter_source.name}",
                "role": "cpython-source",
                "subject": "cpython",
                "source_member": None,
                "file": common.file_record(self.python_interpreter_source),
            },
            {
                "path": "build-inputs/cpython-BUILD.txt",
                "role": "cpython-build-recipe",
                "subject": "cpython",
                "source_member": None,
                "file": common.file_record(recipe_companion),
            },
            {
                "path": "build-inputs/python-build-requirements.lock",
                "role": "canonical-python-requirements",
                "subject": "requirements",
                "source_member": None,
                "file": common.file_record(requirements_companion),
            },
            {
                "path": "licenses/cpython-LICENSE",
                "role": "cpython-license",
                "subject": "cpython",
                "source_member": None,
                "file": common.file_record(cpython_license_companion),
            },
        ]
        for wheel_path in sorted(self.python_wheelhouse.iterdir()):
            wheel_companion = wheelhouse_companion_root / wheel_path.name
            shutil.copyfile(wheel_path, wheel_companion)
            self.python_source_companions.append(
                {
                    "path": f"build-inputs/python-build-wheelhouse/{wheel_path.name}",
                    "role": "build-wheel",
                    "subject": wheel_path.name,
                    "source_member": None,
                    "file": common.file_record(wheel_companion),
                }
            )
            with zipfile.ZipFile(wheel_path) as archive:
                license_members = sorted(
                    name
                    for name in archive.namelist()
                    if ".dist-info/licenses/" in name and not name.endswith("/")
                )
                if len(license_members) != 1:
                    raise AssertionError(f"fixture wheel license inventory: {wheel_path}")
                license_data = archive.read(license_members[0])
            license_path = license_companion_root / f"{wheel_path.name}.LICENSE.txt"
            license_path.write_bytes(license_data)
            self.python_source_companions.append(
                {
                    "path": f"licenses/python-build/{wheel_path.name}.LICENSE.txt",
                    "role": "build-wheel-license",
                    "subject": wheel_path.name,
                    "source_member": license_members[0],
                    "file": common.file_record(license_path),
                }
            )
        self.python_source_companions.sort(key=lambda item: item["path"])
        freezer_requirements_companion = (
            self.payload / "build-inputs/python-freezer-requirements.lock"
        )
        shutil.copyfile(
            self.repository / self.python_freezer_requirements_relative,
            freezer_requirements_companion,
        )
        freezer_wheel_root = self.payload / "build-inputs/python-freezer-wheelhouse"
        freezer_wheel_root.mkdir()
        freezer_license_root = self.payload / "licenses/python-freezer"
        freezer_license_root.mkdir()
        freezer_source_root = self.payload / "freezer-source/python-packages"
        freezer_source_root.mkdir(parents=True)
        self.freezer_source_packages = []
        self.freezer_source_companions = [
            {
                "path": "build-inputs/python-freezer-requirements.lock",
                "role": "freezer-requirements",
                "subject": "requirements",
                "source_member": None,
                "file": common.file_record(freezer_requirements_companion),
            }
        ]
        for distribution, _module in freezer_packages:
            source_filename = f"{distribution}-1.0.0.tar.gz"
            source_path = freezer_source_root / source_filename
            source_path.write_bytes(tar_bytes(f"{distribution}-1.0.0/README"))
            source_record = {
                "distribution": distribution,
                "version": "1.0.0",
                "filename": source_filename,
                "url": (
                    "https://files.pythonhosted.org/packages/source/"
                    f"{distribution[0]}/{distribution}/{source_filename}"
                ),
                "file": common.file_record(source_path),
            }
            self.freezer_source_packages.append(source_record)
            self.freezer_source_companions.append(
                {
                    "path": f"freezer-source/python-packages/{source_filename}",
                    "role": "freezer-source-archive",
                    "subject": distribution,
                    "source_member": None,
                    "file": source_record["file"],
                }
            )
        for wheel_path in sorted(self.python_freezer_wheelhouse.iterdir()):
            wheel_companion = freezer_wheel_root / wheel_path.name
            shutil.copyfile(wheel_path, wheel_companion)
            self.freezer_source_companions.append(
                {
                    "path": f"build-inputs/python-freezer-wheelhouse/{wheel_path.name}",
                    "role": "freezer-build-wheel",
                    "subject": wheel_path.name,
                    "source_member": None,
                    "file": common.file_record(wheel_companion),
                }
            )
            with zipfile.ZipFile(wheel_path) as archive:
                license_members = sorted(
                    name
                    for name in archive.namelist()
                    if ".dist-info/licenses/" in name and not name.endswith("/")
                )
                if len(license_members) != 1:
                    raise AssertionError(f"fixture freezer wheel license: {wheel_path}")
                license_data = archive.read(license_members[0])
            license_path = freezer_license_root / f"{wheel_path.name}.LICENSE.txt"
            license_path.write_bytes(license_data)
            self.freezer_source_companions.append(
                {
                    "path": f"licenses/python-freezer/{wheel_path.name}.LICENSE.txt",
                    "role": "freezer-build-wheel-license",
                    "subject": wheel_path.name,
                    "source_member": license_members[0],
                    "file": common.file_record(license_path),
                }
            )
        self.freezer_source_packages.sort(key=lambda item: item["distribution"])
        self.freezer_source_companions.sort(key=lambda item: item["path"])
        write_json(
            self.payload / "evidence/source-suite-command.json",
            {
                "argv": ["python3", "-m", "unittest", "discover"],
                "expected_minimum_tests": 1,
            },
        )
        upstream = self.payload / "runtime-sources/upstream.tar.gz"
        upstream.parent.mkdir(parents=True)
        with tarfile.open(upstream, "w:gz") as archive:
            data = b"upstream source\n"
            info = tarfile.TarInfo("upstream-1.0/README")
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
        self.bound_source_materials = sorted(
            [
                {
                    "path": "freezer-source/pyinstaller-source.txt",
                    "role": "source",
                    "subject": "freezer",
                    "file": common.file_record(
                        self.payload / "freezer-source/pyinstaller-source.txt"
                    ),
                },
                {
                    "path": "licenses/freezer-LICENSE.txt",
                    "role": "license",
                    "subject": "freezer",
                    "file": common.file_record(material_license_paths["freezer"]),
                },
                {
                    "path": "resource-source/morphology-source.txt",
                    "role": "source",
                    "subject": self.resource_id,
                    "file": common.file_record(
                        self.payload / "resource-source/morphology-source.txt"
                    ),
                },
                {
                    "path": "licenses/resource-LICENSE.txt",
                    "role": "license",
                    "subject": self.resource_id,
                    "file": common.file_record(
                        material_license_paths[self.resource_id]
                    ),
                },
                {
                    "path": "runtime-sources/upstream.tar.gz",
                    "role": "source",
                    "subject": self.runtime_id,
                    "file": common.file_record(upstream),
                },
                {
                    "path": "licenses/runtime-LICENSE.txt",
                    "role": "license",
                    "subject": self.runtime_id,
                    "file": common.file_record(
                        material_license_paths[self.runtime_id]
                    ),
                },
            ],
            key=lambda item: item["path"],
        )

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
                "native_direct_assemblies": 3,
                "sdist_to_wheel_identity": True,
                "filesystem_aliases": [],
            },
            "runtime-provenance.json": {
                "schema": "kazstem-linux-runtime-provenance-v2",
                "official": True,
                "verified": True,
                "non_official_reasons": [],
            },
            "network-trace.json": {
                "pass": True,
                "forbidden_syscalls": [],
                "full_descendant_coverage": False,
                "trace_truncated": False,
                "workload_bytes": 64,
                "workload_lines": 2,
                "workload_sha256": "d" * 64,
            },
            "source-authority.json": {
                "source_tree": self.source_tree,
                "source_origin": self.source_origin,
                "source_ref": self.source_ref,
                "source_tag_object": self.source_tag_object,
                "annotated_tag": True,
                "authoritative_remote": True,
                "remote": {
                    "argv": [
                        "git",
                        "ls-remote",
                        "--exit-code",
                        "--tags",
                        self.source_origin,
                        self.source_ref,
                        f"{self.source_ref}^{{}}",
                    ],
                    "exit_status": 0,
                    "records": [
                        {
                            "object": self.source_tag_object,
                            "ref": self.source_ref,
                        },
                        {
                            "object": self.commit,
                            "ref": f"{self.source_ref}^{{}}",
                        },
                    ],
                    "stdout": common.stream_evidence_record(
                        (
                            f"{self.source_tag_object}\t{self.source_ref}\n"
                            f"{self.commit}\t{self.source_ref}^{{}}\n"
                        ).encode("ascii")
                    ),
                    "stderr": common.stream_evidence_record(b""),
                    "tool": {
                        "name": "git",
                        "version_argv": ["git", "--version"],
                        "version": self.git_version,
                        "executable": common.file_record(
                            Path(shutil.which("git") or "").resolve()
                        ),
                    },
                },
            },
            "source-suite.json": {
                "pass": True,
                "tests_run": 4,
                "tests_discovered": 4,
                "test_ids_sha256": "c" * 64,
                "failures": 0,
                "errors": 0,
                "skipped": 0,
                "expected_failures": 0,
                "expected_failure_test_ids_sha256": (
                    "e3b0c44298fc1c149afbf4c8996fb924"
                    "27ae41e4649b934ca495991b7852b855"
                ),
                "skipped_test_ids_sha256": (
                    "e3b0c44298fc1c149afbf4c8996fb924"
                    "27ae41e4649b934ca495991b7852b855"
                ),
                "unexpected_successes": 0,
            },
        }
        seed_schemas = {
            "blackbox.json": "kazstem-linux-blackbox-v1",
            "compatibility-performance.json": "kazstem-linux-mystem-json-performance-v2",
            "compression-comparison.json": "kazstem-linux-compression-comparison-v2",
            "elf-closure.json": "kazstem-linux-elf-closure-v1",
            "optimization-ledger.json": "kazstem-linux-final-optimization-decision-ledger-v2",
            "practical.json": "kazstem-linux-practical-matrix-v1",
            "python-reproducibility.json": "kazstem-python-artifact-reproducibility-v2",
            "runtime-provenance.json": "kazstem-linux-runtime-provenance-v2",
            "network-trace.json": "kazstem-linux-network-trace-v1",
            "source-authority.json": common.SOURCE_AUTHORITY_SCHEMA,
            "source-suite.json": "kazstem-linux-source-suite-v1",
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
            value.setdefault("pass", True)
        self.evidence_seed: dict[str, Path] = {}
        self.evidence_payloads = seed_values
        for name, value in seed_values.items():
            path = evidence_seed_root / name
            write_json(path, value)
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
                "path": f"build-inputs/{self.python_interpreter_source.name}",
                "format": "tar",
                **common.file_record(self.python_interpreter_source),
            },
            {
                "path": "kazstem-source/GIT-ARCHIVE.tar",
                "format": "tar",
                **common.file_record(self.git_archive),
            },
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
        nested.extend(
            {
                "path": item["path"],
                "format": "zip",
                **item["file"],
            }
            for item in self.python_source_companions
            if item["role"] == "build-wheel"
        )
        nested.extend(
            {
                "path": item["path"],
                "format": (
                    "zip"
                    if item["role"] == "freezer-build-wheel"
                    else "tar"
                ),
                **item["file"],
            }
            for item in self.freezer_source_companions
            if item["role"]
            in {"freezer-build-wheel", "freezer-source-archive"}
        )
        nested.sort(key=lambda item: item["path"])
        reproduction_tools = sorted(
            [
                {
                    "name": name,
                    "version_argv": [name, "--version"],
                    "version": subprocess.run(
                        [str(Path(shutil.which(name) or "").resolve()), "--version"],
                        text=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        check=True,
                    ).stdout.strip(),
                    "executable": common.file_record(
                        Path(shutil.which(name) or "").resolve()
                    ),
                }
                for name in ("git", "python3", "zstd")
            ],
            key=lambda record: record["name"],
        )
        self.python_tool_record = next(
            record for record in reproduction_tools if record["name"] == "python3"
        )
        strace_executable = shutil.which("strace")
        if strace_executable:
            strace_path = Path(strace_executable).resolve()
            strace_version = subprocess.run(
                [str(strace_path), "--version"],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                check=True,
            ).stdout.strip()
        else:
            strace_path = Path(shutil.which("git") or "").resolve()
            strace_version = "strace fixture 1.0"
        self.tracing_tool_record = {
            "name": "strace",
            "version_argv": ["strace", "--version"],
            "version": strace_version,
            "executable": common.file_record(strace_path),
        }
        evidence_specs = [
            ("blackbox.json", "blackbox", ["ready_run"]),
            (
                "compatibility-performance.json",
                "compatibility-performance",
                ["ready_run"],
            ),
            ("compression-comparison.json", "compression-comparison", ["ready_run"]),
            ("elf-closure.json", "elf-closure", ["ready_run"]),
            ("network-trace.json", "network-trace", ["ready_run"]),
            ("optimization-ledger.json", "optimization-ledger", ["ready_run"]),
            ("practical.json", "practical", ["ready_run"]),
            (
                "python-reproducibility.json",
                "python-reproducibility",
                ["corresponding_source", "ready_run", "sdist", "wheel"],
            ),
            ("ready-audit.json", "ready-archive-audit", ["ready_run"]),
            ("runtime-provenance.json", "runtime-provenance", ["ready_run"]),
            (
                "source-audit.json",
                "source-archive-audit",
                ["corresponding_source"],
            ),
            ("source-authority.json", "source-authority", []),
            ("source-suite.json", "source-suite", ["sdist", "wheel"]),
        ]
        compression_targets = []
        for artifact_name, filename in (
            ("corresponding_source", self.source_name),
            ("ready_run", self.ready_name),
        ):
            top_level = filename.removesuffix(".tar.xz")
            compression_targets.append(
                {
                    "artifact": artifact_name,
                    "input": {
                        "filename": f"{top_level}.tar",
                        "producer": "deterministic-gnu-tar-v1",
                        **dummy,
                    },
                    "selected": "xz",
                    "candidates": [
                        {
                            "name": "gzip",
                            "eligible": True,
                            "format": "gzip",
                            "ineligible_reason": None,
                            "filename": f"{top_level}.tar.gz",
                            "tool": "python3",
                            "argv": [
                                "python3",
                                "compress_fixture.py",
                                "gzip",
                                "{input}",
                                "{output}",
                            ],
                            "tradeoff": "portable extraction but usually larger",
                        },
                        {
                            "name": "xz",
                            "eligible": True,
                            "format": "xz",
                            "ineligible_reason": None,
                            "filename": f"{top_level}.tar.xz",
                            "tool": "python3",
                            "argv": [
                                "python3",
                                "compress_fixture.py",
                                "xz",
                                "{input}",
                                "{output}",
                            ],
                            "tradeoff": "higher compression CPU with stdlib extraction",
                        },
                        {
                            "name": "zstd",
                            "eligible": False,
                            "format": "zstd",
                            "ineligible_reason": "no-install extraction cannot assume an external zstd decoder",
                            "filename": f"{top_level}.tar.zst",
                            "tool": "zstd",
                            "argv": [
                                "zstd",
                                "-19",
                                "--ultra",
                                "--threads=1",
                                "--no-progress",
                                "--force",
                                "-o",
                                "{output}",
                                "{input}",
                            ],
                            "tradeoff": "measured aggressively but requires an external decoder",
                        },
                    ],
                }
            )
        self.identity: dict[str, object] = {
            "schema": common.IDENTITY_SCHEMA,
            "release": self.release,
            "source_commit": self.commit,
            "source_tag_object": self.source_tag_object,
            "source_tree": self.source_tree,
            "source_origin": self.source_origin,
            "source_ref": self.source_ref,
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
                "nested_archives": [
                    {
                        "path": f"_internal/{self.wheel_name}",
                        "format": "zip",
                        **common.file_record(self.wheel),
                    }
                ],
                "resource_destination": ".qazmorph/resources",
                "runtime_parent": ".qazmorph/platform-runtimes",
                "aliases": ["mystem-kz", "qazmorph"],
                "remove_frozen_files": [
                    {"path": "_internal/libz.so.1", "file": common.file_record(removed)}
                ],
                "required_paths": sorted(
                    {
                        ".qazmorph/resources/manifest.json",
                        f".qazmorph/platform-runtimes/{self.runtime_id}/manifest.json",
                        "CORRESPONDING-SOURCE.json",
                        f"_internal/{self.wheel_name}",
                        "LICENSE",
                        "README.md",
                        "kazstem",
                        "mystem-kz",
                        "qazmorph",
                        "verification/BUNDLE-MANIFEST.json",
                        "verification/BUNDLED-FILES.sha256",
                    }
                ),
                "banned_name_fragments": sorted(
                    ["_hashlib.", "_ssl.", "libcrypto", "libssl", "openssl"]
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
                "source_tree_file": "kazstem-source/SOURCE-TREE",
                "source_origin_file": "kazstem-source/SOURCE-ORIGIN",
                "git_archive_file": "kazstem-source/GIT-ARCHIVE.tar",
                "source_date_epoch_file": "kazstem-source/SOURCE_DATE_EPOCH",
                "required_paths": sorted(
                    {
                        "README.md",
                        "SHA256SUMS",
                        "SOURCE-IDENTITY.json",
                        "SOURCE-MANIFEST.json",
                        "build-inputs",
                        "build-inputs/build-wheel.txt",
                        f"build-inputs/{self.python_interpreter_source.name}",
                        "evidence",
                        "evidence/source-suite-command.json",
                        "freezer-source",
                        "freezer-source/pyinstaller-source.txt",
                        "kazstem-source",
                        "kazstem-source/GIT-ARCHIVE.tar",
                        "kazstem-source/GIT-SOURCE.json",
                        "kazstem-source/SOURCE-COMMIT",
                        "kazstem-source/SOURCE_DATE_EPOCH",
                        "kazstem-source/SOURCE-ORIGIN",
                        "kazstem-source/SOURCE-TREE",
                        "kazstem-source/tree",
                        "kazstem-source/tree/module.py",
                        "licenses",
                        "licenses/LICENSE.txt",
                        f"python-artifacts/{self.sdist_name}",
                        f"python-artifacts/{self.wheel_name}",
                        "resource-source",
                        "resource-source/morphology-source.txt",
                        "runtime-sources",
                        "runtime-sources/upstream.tar.gz",
                        *[
                            item["path"]
                            for item in self.python_source_companions
                        ],
                        *[
                            item["path"]
                            for item in self.freezer_source_companions
                        ],
                        *[
                            item["path"]
                            for item in self.bound_source_materials
                        ],
                    }
                ),
                "bound_source_materials": self.bound_source_materials,
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
                "finalizer": {
                    "path": "packaging/linux/finalize_release.py",
                    "file": common.file_record(
                        self.repository / "packaging/linux/finalize_release.py"
                    ),
                },
                "network_boundary": {
                    "schema": "kazstem-linux-seccomp-network-boundary-v1",
                    "default_action": "allow",
                    "deny_action": "errno-EPERM",
                    "clone3_action": "errno-ENOSYS",
                    "clone_untraced_mask": 0x00800000,
                    "no_new_privs": True,
                    "denied_syscalls": common.NETWORK_BOUNDARY_DENIED_SYSCALLS,
                    "wrapper": {
                        "path": "packaging/linux/run_no_network.py",
                        "file": common.file_record(network_boundary_wrapper),
                    },
                    "library": {
                        "soname": "libseccomp.so.2",
                        "file": common.file_record(fixture_seccomp_library()),
                    },
                },
                "reproducibility": {
                    "build_roots": 3,
                    "canonical_python": {
                        "builder": {
                            "path": "packaging/build_canonical_python_artifacts.py",
                            "file": common.file_record(
                                PACKAGING_ROOT
                                / "build_canonical_python_artifacts.py"
                            ),
                            "receipt_schema": canonical_python_builder.RECEIPT_SCHEMA,
                        },
                        "identity": {
                            "schema": canonical_python_builder.IDENTITY_SCHEMA,
                            "file": common.file_record(
                                self.python_build_identity_path
                            ),
                        },
                        "interpreter_source": {
                            "path": self.python_build_identity[
                                "interpreter_provenance"
                            ]["corresponding_source_path"],
                            "file": common.file_record(
                                self.python_interpreter_source
                            ),
                        },
                        "interpreter_build_recipe": self.python_build_identity[
                            "interpreter_provenance"
                        ]["build_recipe"],
                        "interpreter_license": self.python_build_identity[
                            "interpreter_provenance"
                        ]["license"],
                        "requirements_file": self.python_build_identity[
                            "build_stack"
                        ]["requirements"],
                        "requirements_path": self.python_requirements_relative,
                        "runtime_packages": self.python_build_identity[
                            "interpreter_provenance"
                        ]["runtime_closure"]["packages"],
                        "runtime_source_packages": self.python_build_identity[
                            "interpreter_provenance"
                        ]["runtime_closure"]["source_packages"],
                        "source_companions": self.python_source_companions,
                        "wheelhouse_files": self.python_build_identity[
                            "build_stack"
                        ]["wheelhouse"]["files"],
                        "wheelhouse_manifest_sha256": self.python_build_identity[
                            "build_stack"
                        ]["wheelhouse"]["manifest_sha256"],
                    },
                    "frozen_build_argv": [
                        "python3",
                        "-S",
                        "packaging/linux/build_frozen_from_wheel.py",
                        "--identity",
                        "release-identity.json",
                        "--source-checkout",
                        "{source_checkout}",
                        "--wheel",
                        "{wheel}",
                        "--wheelhouse",
                        "{freezer_wheelhouse}",
                        "--requirements",
                        self.python_freezer_requirements_relative,
                        "--workspace",
                        "{freezer_workspace}",
                        "--frozen",
                        "{frozen}",
                        "--receipt",
                        "{frozen_receipt}",
                    ],
                    "frozen_builder": {
                        "path": "packaging/linux/build_frozen_from_wheel.py",
                        "file": common.file_record(
                            self.repository
                            / "packaging/linux/build_frozen_from_wheel.py"
                        ),
                        "receipt_schema": (
                            "kazstem-frozen-wheel-consumption-receipt-v2"
                        ),
                        "release_common": {
                            "path": "packaging/linux/release_common.py",
                            "file": common.file_record(
                                self.repository / "packaging/linux/release_common.py"
                            ),
                        },
                        "process_supervisor": {
                            "path": "packaging/process_supervisor.py",
                            "file": common.file_record(
                                self.repository / "packaging/process_supervisor.py"
                            ),
                        },
                        "bootstrap": {
                            "path": "packaging/linux/frozen_wheel_entrypoint.py",
                            "file": common.file_record(
                                self.repository
                                / "packaging/linux/frozen_wheel_entrypoint.py"
                            ),
                        },
                        "spec": {
                            "path": "packaging/linux/kazstem-minimal.spec",
                            "file": common.file_record(
                                self.repository / "packaging/linux/kazstem-minimal.spec"
                            ),
                        },
                        "requirements": {
                            "path": self.python_freezer_requirements_relative,
                            "file": common.file_record(
                                self.repository
                                / self.python_freezer_requirements_relative
                            ),
                        },
                        "source_packages": self.freezer_source_packages,
                        "source_companions": self.freezer_source_companions,
                        "wheelhouse": {
                            "files": [
                                {"filename": path.name, **common.file_record(path)}
                                for path in sorted(
                                    self.python_freezer_wheelhouse.iterdir()
                                )
                            ],
                            "manifest_sha256": common.canonical_hash(
                                [
                                    {
                                        "filename": path.name,
                                        **common.file_record(path),
                                    }
                                    for path in sorted(
                                        self.python_freezer_wheelhouse.iterdir()
                                    )
                                ]
                            ),
                        },
                        "bootstrap_pip": {
                            "filename": "pip-1.0.0-py3-none-any.whl",
                            "version": "1.0.0",
                            "file": common.file_record(
                                self.python_freezer_wheelhouse
                                / "pip-1.0.0-py3-none-any.whl"
                            ),
                        },
                        "packages": [
                            {"name": distribution, "version": "1.0.0"}
                            for distribution, _module in freezer_packages
                        ],
                        "provision_argv": [
                            "{python}", "-S", "-m", "pip", "install",
                            "--no-index", "--require-hashes", "--no-deps",
                            "--only-binary=:all:", "--target", "{build_env}",
                            "--find-links", "{wheelhouse}", "-r", "{requirements}",
                        ],
                        "build_argv": [
                            "{python}", "-S", "-m", "PyInstaller", "--clean",
                            "--noconfirm", "--distpath", "{dist}", "--workpath",
                            "{work}", "{spec}",
                        ],
                        "environment": build_environment,
                        "python_optimize": "0",
                        "timeout_seconds": 60,
                    },
                    "native_assemblers": {
                        name: {
                            "path": f"packaging/linux/{filename}",
                            "file": common.file_record(
                                self.repository / "packaging/linux" / filename
                            ),
                        }
                        for name, filename in (
                            ("ready_run", "assemble_ready_run.py"),
                            ("release_common", "release_common.py"),
                            ("source", "assemble_corresponding_source.py"),
                        )
                    },
                    "environment": {
                        "LANG": "C.UTF-8",
                        "LC_ALL": "C.UTF-8",
                        "PYTHONDONTWRITEBYTECODE": "1",
                        "PYTHONPYCACHEPREFIX": "workspace/pycache",
                        "PYTHONHASHSEED": "0",
                        "SOURCE_DATE_EPOCH": str(self.epoch),
                        "TZ": "UTC",
                    },
                    "helpers": [
                        {
                            "path": "packaging/linux/release_common.py",
                            "file": common.file_record(
                                self.repository
                                / "packaging/linux/release_common.py"
                            ),
                        },
                        {
                            "path": "packaging/process_supervisor.py",
                            "file": common.file_record(
                                self.repository / "packaging/process_supervisor.py"
                            ),
                        },
                    ],
                    "tools": reproduction_tools,
                },
                "compression": {
                    "selection_rule": "minimum-bytes-then-name",
                    "targets": compression_targets,
                },
                "tracing": {
                    "argv_prefix": [
                        "strace",
                        "-f",
                        "-qq",
                        "-e",
                        "trace=network",
                        "-o",
                        "{trace}",
                    ],
                    "forbidden_syscalls": sorted(
                        [
                            "accept",
                            "accept4",
                            "bind",
                            "connect",
                            "getpeername",
                            "getsockname",
                            "getsockopt",
                            "listen",
                            "recvfrom",
                            "recvmmsg",
                            "recvmsg",
                            "sendmmsg",
                            "sendmsg",
                            "sendto",
                            "setsockopt",
                            "shutdown",
                            "socket",
                            "socketpair",
                        ]
                    ),
                    "tool": self.tracing_tool_record,
                },
                "evidence": sorted(
                    [
                        {
                            "path": "blackbox.json",
                            "gate": "blackbox",
                            "kind": "envelope",
                            "subjects": ["ready_run"],
                            "file": common.file_record(
                                self.evidence_seed["blackbox.json"]
                            ),
                        },
                        {
                            "path": "compatibility-performance.json",
                            "gate": "compatibility-performance",
                            "kind": "envelope",
                            "subjects": ["ready_run"],
                            "file": common.file_record(
                                self.evidence_seed["compatibility-performance.json"]
                            ),
                        },
                        {
                            "path": "compression-comparison.json",
                            "gate": "compression-comparison",
                            "kind": "envelope",
                            "subjects": ["corresponding_source", "ready_run"],
                            "file": common.file_record(
                                self.evidence_seed["compression-comparison.json"]
                            ),
                        },
                        {
                            "path": "elf-closure.json",
                            "gate": "elf-closure",
                            "kind": "envelope",
                            "subjects": ["ready_run"],
                            "file": common.file_record(
                                self.evidence_seed["elf-closure.json"]
                            ),
                        },
                        {
                            "path": "network-trace.json",
                            "gate": "network-trace",
                            "kind": "envelope",
                            "subjects": ["ready_run"],
                            "file": common.file_record(
                                self.evidence_seed["network-trace.json"]
                            ),
                        },
                        {
                            "path": "optimization-ledger.json",
                            "gate": "optimization-ledger",
                            "kind": "envelope",
                            "subjects": ["corresponding_source", "ready_run"],
                            "file": common.file_record(
                                self.evidence_seed["optimization-ledger.json"]
                            ),
                        },
                        {
                            "path": "practical.json",
                            "gate": "practical",
                            "kind": "envelope",
                            "subjects": ["ready_run"],
                            "file": common.file_record(
                                self.evidence_seed["practical.json"]
                            ),
                        },
                        {
                            "path": "python-reproducibility.json",
                            "gate": "python-reproducibility",
                            "kind": "envelope",
                            "subjects": [
                                "corresponding_source",
                                "ready_run",
                                "sdist",
                                "wheel",
                            ],
                            "file": common.file_record(
                                self.evidence_seed["python-reproducibility.json"]
                            ),
                        },
                        {
                            "path": "ready-audit.json",
                            "gate": "ready-archive-audit",
                            "kind": "envelope",
                            "subjects": ["ready_run"],
                            "file": dummy,
                        },
                        {
                            "path": "runtime-provenance.json",
                            "gate": "runtime-provenance",
                            "kind": "envelope",
                            "subjects": ["ready_run"],
                            "file": common.file_record(
                                self.evidence_seed["runtime-provenance.json"]
                            ),
                        },
                        {
                            "path": "source-audit.json",
                            "gate": "source-archive-audit",
                            "kind": "envelope",
                            "subjects": ["corresponding_source"],
                            "file": dummy,
                        },
                        {
                            "path": "source-authority.json",
                            "gate": "source-authority",
                            "kind": "envelope",
                            "subjects": [],
                            "file": common.file_record(
                                self.evidence_seed["source-authority.json"]
                            ),
                        },
                        {
                            "path": "source-suite.json",
                            "gate": "source-suite",
                            "kind": "envelope",
                            "subjects": ["sdist", "wheel"],
                            "file": common.file_record(
                                self.evidence_seed["source-suite.json"]
                            ),
                        },
                    ],
                    key=lambda record: record["path"],
                ),
            },
        }
        payload_schemas = {
            "blackbox": "kazstem-linux-blackbox-v1",
            "compatibility-performance": "kazstem-linux-mystem-json-performance-v2",
            "compression-comparison": "kazstem-linux-compression-comparison-v2",
            "elf-closure": "kazstem-linux-elf-closure-v1",
            "network-trace": "kazstem-linux-network-trace-v1",
            "optimization-ledger": "kazstem-linux-final-optimization-decision-ledger-v2",
            "practical": "kazstem-linux-practical-matrix-v1",
            "python-reproducibility": "kazstem-python-artifact-reproducibility-v2",
            "ready-archive-audit": common.READY_AUDIT_SCHEMA,
            "runtime-provenance": "kazstem-linux-runtime-provenance-v2",
            "source-archive-audit": common.SOURCE_AUDIT_SCHEMA,
            "source-authority": common.SOURCE_AUTHORITY_SCHEMA,
            "source-suite": "kazstem-linux-source-suite-v1",
        }
        generator = LINUX_TOOLS / "generate_gate_evidence.py"
        for record in self.identity["verification"]["evidence"]:
            gate_script_relative = common.GATE_SCRIPT_PATHS[record["gate"]]
            gate_script = self.repository / gate_script_relative
            record["execution"] = {
                "argv": common.GATE_EXECUTION_ARGV[record["gate"]],
                "cwd": "source-checkout",
                "environment": self.identity["verification"]["reproducibility"][
                    "environment"
                ],
                "generator": {
                    "path": "packaging/linux/generate_gate_evidence.py",
                    "file": common.file_record(generator),
                },
                "network_syscall_ledger": record["gate"]
                in {"network-trace", "python-reproducibility", "source-suite"},
                "payload_expectations": (
                    {
                        "tests_discovered": 4,
                        "test_ids_sha256": "c" * 64,
                        "skipped": 0,
                        "skipped_test_ids_sha256": (
                            "e3b0c44298fc1c149afbf4c8996fb924"
                            "27ae41e4649b934ca495991b7852b855"
                        ),
                        "expected_failures": 0,
                        "expected_failure_test_ids_sha256": (
                            "e3b0c44298fc1c149afbf4c8996fb924"
                            "27ae41e4649b934ca495991b7852b855"
                        ),
                    }
                    if record["gate"] == "source-suite"
                    else (
                        {
                            "workload_bytes": 64,
                            "workload_lines": 2,
                            "workload_sha256": "d" * 64,
                        }
                        if record["gate"] == "network-trace"
                        else {}
                    )
                ),
                "payload_schema": payload_schemas[record["gate"]],
                "script": {
                    "path": gate_script_relative,
                    "file": common.file_record(gate_script),
                },
                "source_tree": self.source_tree,
                "timeout_seconds": 1800,
            }
        self.identity_path = root / "release-identity.json"
        self.write_identity()

    def write_identity(self) -> None:
        write_json(self.identity_path, self.identity)

    def fixture_network_boundary_evidence(self) -> dict[str, object]:
        boundary = self.identity["verification"]["network_boundary"]
        return {
            **common.logical_network_boundary(self.identity),
            "receipt": {
                "schema": "kazstem-linux-seccomp-network-boundary-receipt-v1",
                "pass": True,
                "default_action": boundary["default_action"],
                "deny_action": boundary["deny_action"],
                "no_new_privs": True,
                "clone_untraced_mask": boundary["clone_untraced_mask"],
                "clone_untraced_denied": True,
                "clone3_action": boundary["clone3_action"],
                "denied_syscalls": boundary["denied_syscalls"],
                "resolved_syscalls": boundary["denied_syscalls"],
                "unavailable_syscalls": [],
                "library": boundary["library"]["file"],
                "wrapper": boundary["wrapper"]["file"],
            },
        }

    def refresh_evidence_envelopes(self) -> None:
        self.write_identity()
        digest = common.identity_sha256(self.identity_path)
        records = {
            record["gate"]: record
            for record in self.identity["verification"]["evidence"]
        }
        empty_stream = common.stream_evidence_record(b"")
        for path_name, payload in self.evidence_payloads.items():
            gate = next(
                record["gate"]
                for record in records.values()
                if record["path"] == path_name
            )
            record = records[gate]
            observations: dict[str, int] = {}
            if gate == "source-suite":
                observations = {
                    "tests_run": int(payload["tests_run"]),
                    "failures": int(payload["failures"]),
                    "errors": int(payload["errors"]),
                }
            coverage = {
                "descendant_processes": 1,
                "full_descendant_coverage": False,
                "network_boundary": None,
                "network_trace": None,
                "observations": observations,
                "process_containment": {
                    "mechanism": "linux-systemd-user-slice-cgroup-v2+prctl-subreaper-proc-starttime-pidfd",
                    "observed_descendants": 0,
                    "descendant_peak": 0,
                    "final_descendants": 0,
                    "tasks_max": 4097,
                    "cgroup_kill_written": True,
                    "cgroup_populated_zero": True,
                },
                "trace_complete": True,
                "trace_truncated": False,
            }
            if gate in {"network-trace", "python-reproducibility", "source-suite"}:
                coverage["network_boundary"] = (
                    self.fixture_network_boundary_evidence()
                )
                coverage["network_trace"] = {
                    "argv_prefix": self.identity["verification"]["tracing"][
                        "argv_prefix"
                    ],
                    "denied_attempt_counts": {},
                    "follow_descendants": True,
                    "forbidden_syscalls": [],
                    "processes": 1,
                    "syscall_counts": {},
                    "syscalls": 0,
                    "trace": empty_stream,
                    "tracer": self.tracing_tool_record,
                }
            envelope = common.gate_envelope(
                identity=self.identity,
                identity_contract_sha256=digest,
                gate=gate,
                subjects=record["subjects"],
                invocation={
                    "argv": common.logical_gate_argv(self.identity, gate),
                    "cwd": record["execution"]["cwd"],
                    "environment": record["execution"]["environment"],
                    "exit_status": 0,
                    "generator": record["execution"]["generator"],
                    "script": record["execution"]["script"],
                    "source_tree": record["execution"]["source_tree"],
                    "timeout_seconds": record["execution"]["timeout_seconds"],
                    "tool": self.python_tool_record,
                    "stdout": empty_stream,
                    "stderr": empty_stream,
                },
                coverage=coverage,
                payload=payload,
            )
            path = self.evidence_seed[path_name]
            write_json(path, envelope)
            record["file"] = common.file_record(path)
        self.write_identity()

    def wrap_evidence_payload(
        self, gate: str, payload: dict[str, object]
    ) -> dict[str, object]:
        digest = common.identity_sha256(self.identity_path)
        record = next(
            item
            for item in self.identity["verification"]["evidence"]
            if item["gate"] == gate
        )
        empty_stream = common.stream_evidence_record(b"")
        traced = gate in {
            "network-trace",
            "python-reproducibility",
            "source-suite",
        }
        network_trace = None
        if traced:
            network_trace = {
                "argv_prefix": self.identity["verification"]["tracing"][
                    "argv_prefix"
                ],
                "denied_attempt_counts": {},
                "follow_descendants": True,
                "forbidden_syscalls": [],
                "processes": 1,
                "syscall_counts": {},
                "syscalls": 0,
                "trace": empty_stream,
                "tracer": self.tracing_tool_record,
            }
        observations: dict[str, int] = {}
        if gate == "source-suite":
            observations = {
                "tests_run": int(payload["tests_run"]),
                "failures": int(payload["failures"]),
                "errors": int(payload["errors"]),
            }
        return common.gate_envelope(
            identity=self.identity,
            identity_contract_sha256=digest,
            gate=gate,
            subjects=record["subjects"],
            invocation={
                "argv": common.logical_gate_argv(self.identity, gate),
                "cwd": record["execution"]["cwd"],
                "environment": record["execution"]["environment"],
                "exit_status": 0,
                "generator": record["execution"]["generator"],
                "script": record["execution"]["script"],
                "source_tree": record["execution"]["source_tree"],
                "timeout_seconds": record["execution"]["timeout_seconds"],
                "tool": self.python_tool_record,
                "stdout": empty_stream,
                "stderr": empty_stream,
            },
            coverage={
                "descendant_processes": 1,
                "full_descendant_coverage": False,
                "network_boundary": (
                    self.fixture_network_boundary_evidence() if traced else None
                ),
                "network_trace": network_trace,
                "observations": observations,
                "process_containment": {
                    "mechanism": "linux-systemd-user-slice-cgroup-v2+prctl-subreaper-proc-starttime-pidfd",
                    "observed_descendants": 0,
                    "descendant_peak": 0,
                    "final_descendants": 0,
                    "tasks_max": 4097,
                    "cgroup_kill_written": True,
                    "cgroup_populated_zero": True,
                },
                "trace_complete": True,
                "trace_truncated": False,
            },
            payload=payload,
        )

    def source_args(
        self,
        parent: Path,
        *,
        observation: Path | None = None,
        producer: bool = False,
    ) -> argparse.Namespace:
        parent.mkdir(parents=True, exist_ok=True)
        target = next(
            item
            for item in self.identity["verification"]["compression"]["targets"]
            if item["artifact"] == "corresponding_source"
        )
        return argparse.Namespace(
            identity=self.identity_path,
            payload=self.payload,
            repository=self.repository,
            source_readme_template=self.source_template,
            wheel=self.wheel,
            sdist=self.sdist,
            work_root=parent / "source-work",
            output=parent / self.source_name,
            observation=observation,
            raw_tar_output=(
                parent / "canonical" / target["input"]["filename"]
                if producer
                else None
            ),
            producer_receipt=(
                parent / "producer-receipts/corresponding-source-tar-producer.json"
                if producer
                else None
            ),
        )

    def ready_args(
        self,
        parent: Path,
        source: Path,
        *,
        observation: Path | None = None,
        producer: bool = False,
    ) -> argparse.Namespace:
        parent.mkdir(parents=True, exist_ok=True)
        target = next(
            item
            for item in self.identity["verification"]["compression"]["targets"]
            if item["artifact"] == "ready_run"
        )
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
            raw_tar_output=(
                parent / "canonical" / target["input"]["filename"]
                if producer
                else None
            ),
            producer_receipt=(
                parent / "producer-receipts/ready-run-tar-producer.json"
                if producer
                else None
            ),
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
        ready_candidate = next(ready_probe.glob(f"{self.ready_name}.unsealed-*"))
        compression_paths = {
            "corresponding_source": sealed_source / self.source_name,
            "ready_run": ready_candidate,
        }
        for target in self.identity["verification"]["compression"]["targets"]:
            raw_path = self.root / target["input"]["filename"]
            with lzma.open(compression_paths[target["artifact"]], "rb") as source:
                raw_path.write_bytes(source.read())
            target["input"].update(common.file_record(raw_path))
        self.write_identity()
        self.refresh_evidence_envelopes()

        with mock.patch.dict(
            os.environ,
            self.identity["verification"]["reproducibility"]["environment"],
            clear=False,
        ):
            reproduction_a = self.root / "reproduction-a"
            source_assembler.assemble(self.source_args(reproduction_a, producer=True))
            ready_assembler.assemble(
                self.ready_args(
                    reproduction_a,
                    reproduction_a / self.source_name,
                    producer=True,
                )
            )
            reproduction_b = self.root / "reproduction-b"
            source_assembler.assemble(self.source_args(reproduction_b, producer=True))
            ready_assembler.assemble(
                self.ready_args(
                    reproduction_b,
                    reproduction_b / self.source_name,
                    producer=True,
                )
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
            changed = copy.deepcopy(fixture.identity)
            companions = changed["verification"]["reproducibility"][
                "canonical_python"
            ]["source_companions"]
            companions.remove(
                next(
                    item
                    for item in companions
                    if item["role"] == "build-wheel-license"
                )
            )
            write_json(fixture.identity_path, changed)
            with self.assertRaisesRegex(common.ReleaseError, "license companion"):
                common.load_identity(fixture.identity_path)
            changed = copy.deepcopy(fixture.identity)
            changed["ready_run"]["banned_name_fragments"].remove("openssl")
            write_json(fixture.identity_path, changed)
            with self.assertRaisesRegex(common.ReleaseError, "OpenSSL"):
                common.load_identity(fixture.identity_path)
            changed = copy.deepcopy(fixture.identity)
            changed["corresponding_source"]["required_paths"].append(
                "build-inputs/openssl-source.tar.gz"
            )
            changed["corresponding_source"]["required_paths"].sort()
            write_json(fixture.identity_path, changed)
            with self.assertRaisesRegex(common.ReleaseError, "OpenSSL"):
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
                zstd_record = {
                    "name": "zstd",
                    "version_argv": ["zstd", "--version"],
                    "version": subprocess.run(
                        [str(zstd), "--version"],
                        text=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        check=True,
                    ).stdout.strip(),
                    "executable": common.file_record(zstd),
                }
                self.assertGreater(
                    common.inspect_deb(
                        zstd_deb, limits=limits, zstd_tool=zstd_record
                    )["embedded_tar_members"],
                    0,
                )

    def test_sdist_manifest_covers_every_linux_release_tool(self) -> None:
        manifest = (PROJECT_ROOT / "MANIFEST.in").read_text(encoding="utf-8")
        expected = {
            "packaging/linux/BINARY-README.template.md",
            "packaging/CANONICAL-PYTHON-ARTIFACTS.md",
            "packaging/build_canonical_python_artifacts.py",
            "packaging/process_supervisor.py",
            "packaging/python-build-requirements.lock",
            "packaging/linux/python-freezer-requirements.lock",
            "packaging/linux/build_frozen_from_wheel.py",
            "packaging/linux/frozen_wheel_entrypoint.py",
            "packaging/linux/kazstem-minimal.spec",
            "packaging/cpython-BUILD.txt",
            "packaging/cpython-LICENSE",
            "packaging/linux/CORRESPONDING-SOURCE-README.template.md",
            "packaging/linux/RELEASE-IDENTITY.md",
            "packaging/linux/assemble_corresponding_source.py",
            "packaging/linux/assemble_ready_run.py",
            "packaging/linux/audit_corresponding_source_archive.py",
            "packaging/linux/audit_ready_run_archive.py",
            "packaging/linux/benchmark_compat_linux.py",
            "packaging/linux/finalize_release.py",
            "packaging/linux/generate_compression_comparison.py",
            "packaging/linux/generate_gate_evidence.py",
            "packaging/linux/generate_optimization_ledger.py",
            "packaging/linux/normalize_runtime_provenance.py",
            "packaging/linux/release_common.py",
            "packaging/linux/run_network_workload.py",
            "packaging/linux/run_no_network.py",
            "packaging/linux/run_source_suite.py",
            "packaging/linux/verify_python_reproducibility.py",
            "packaging/linux/verify_remote_tag.py",
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
                    **{
                        name: {
                            "ambient_present": False,
                            "removed_from_helper_environment": True,
                            "sha256": None,
                        }
                        for name in provenance_normalizer.LOADER_OVERRIDE_VARIABLES
                    },
                    "GLIBC_TUNABLES": {
                        "ambient_present": False,
                        "removed_from_helper_environment": True,
                        "sha256": None,
                    },
                    "loader_policy": {
                        "schema": "qazmorph-native-helper-loader-environment-v2",
                        "captured_name_policy": {
                            "exact_uppercase_prefixes": ["LD_", "DYLD_"],
                            "exact_names": ["GLIBC_TUNABLES"],
                        },
                        "ambient_records": {},
                        "glibc_tunables": {
                            "ambient_present": False,
                            "removed_from_helper_environment": True,
                            "sha256": None,
                        },
                        "clean_parent_startup": True,
                        "all_ambient_values_removed_from_helper_environment": True,
                        "linux_helper_ld_library_path": {
                            "source": "manifest-bound-runtime",
                            "relative_paths": [
                                "usr/lib/x86_64-linux-gnu",
                                "usr/lib",
                            ],
                        },
                    },
                },
            }
            raw["environment"]["LD_LIBRARY_PATH"].update(
                {
                    "helper_value_source": "manifest-bound-runtime",
                    "helper_relative_paths": [
                        "usr/lib/x86_64-linux-gnu",
                        "usr/lib",
                    ],
                }
            )
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

            poisoned = json.loads(json.dumps(raw))
            poisoned["environment"]["loader_policy"]["ambient_records"] = {
                "LD_FAKE": {
                    "ambient_present": True,
                    "removed_from_helper_environment": True,
                    "sha256": "0" * 64,
                }
            }
            poisoned["environment"]["loader_policy"]["clean_parent_startup"] = False
            poisoned_path = fixture.root / "poisoned-provenance.json"
            write_json(poisoned_path, poisoned)
            with self.assertRaisesRegex(common.ReleaseError, "clean parent/helper"):
                provenance_normalizer.normalize(
                    argparse.Namespace(
                        identity=fixture.identity_path,
                        bundle_root=bundle,
                        input=poisoned_path,
                        output=fixture.root / "poisoned-normalized.json",
                    )
                )

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

    def test_reproducibility_orchestrator_builds_three_roots_and_sdist_roundtrip(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = ReleaseFixture(Path(temporary))
            fixture.seal_artifacts()
            canonical_python_inputs = fixture.root / "canonical-python-inputs"
            canonical_python_inputs.mkdir()
            shutil.copyfile(
                fixture.wheel, canonical_python_inputs / fixture.wheel_name
            )
            shutil.copyfile(
                fixture.sdist, canonical_python_inputs / fixture.sdist_name
            )
            output = fixture.root / "python-reproducibility.json"
            with self.assertRaisesRegex(
                python_reproducibility.ReleaseError, "distinct, non-nested"
            ):
                python_reproducibility.verify(
                    argparse.Namespace(
                        identity=fixture.identity_path,
                        repository=fixture.repository,
                        canonical_artifacts=canonical_python_inputs,
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
                        workspace=fixture.repository / "nested-workspace",
                        output=fixture.root / "nested-workspace-report.json",
                    )
                )
            result = python_reproducibility.verify(
                argparse.Namespace(
                    identity=fixture.identity_path,
                    repository=fixture.repository,
                    canonical_artifacts=canonical_python_inputs,
                    python_build_identity=fixture.python_build_identity_path,
                    python_wheelhouse=fixture.python_wheelhouse,
                    python_freezer_wheelhouse=fixture.python_freezer_wheelhouse,
                    python_interpreter_source=fixture.python_interpreter_source,
                    payload=fixture.payload,
                    frozen=fixture.frozen,
                    resources=fixture.resources,
                    runtime=fixture.runtime,
                    documents=fixture.documents,
                    binary_readme_template=fixture.binary_template,
                    source_readme_template=fixture.source_template,
                    base_ledger=fixture.base_ledger,
                    workspace=fixture.root / "orchestrated-reproduction",
                    output=output,
                )
            )
            self.assertTrue(result["pass"])
            self.assertEqual(result["wheel_direct_builds"], 3)
            self.assertEqual(result["sdist_direct_builds"], 3)
            self.assertTrue(result["sdist_to_wheel_identity"])
            self.assertNotIn(str(fixture.root), output.read_text(encoding="utf-8"))
            hostile = copy.deepcopy(result)
            hostile["builds"][0]["canonical_python_build"]["command"]["argv"] = [
                "python3",
                "-c",
                "forge_receipt()",
            ]
            with self.assertRaisesRegex(
                python_reproducibility.ReleaseError, "argv/exit"
            ):
                python_reproducibility.validate_reproducibility_payload(
                    hostile,
                    identity=fixture.identity,
                    identity_contract_sha256=common.identity_sha256(
                        fixture.identity_path
                    ),
                    canonical_artifacts=canonical_python_inputs,
                )
            ignored_wheel = copy.deepcopy(result)
            ignored_wheel["builds"][0]["frozen_build"]["receipt_payload"][
                "embedded_package"
            ]["modules"] = []
            with self.assertRaisesRegex(
                python_reproducibility.ReleaseError,
                "consumption/package audit",
            ):
                python_reproducibility.validate_reproducibility_payload(
                    ignored_wheel,
                    identity=fixture.identity,
                    identity_contract_sha256=common.identity_sha256(
                        fixture.identity_path
                    ),
                    canonical_artifacts=canonical_python_inputs,
                )
            missing_embedded_wheel = copy.deepcopy(result)
            missing_embedded_wheel["builds"][0]["frozen_build"]["inventory"] = [
                item
                for item in missing_embedded_wheel["builds"][0]["frozen_build"][
                    "inventory"
                ]
                if item["path"] != f"_internal/{fixture.wheel_name}"
            ]
            with self.assertRaisesRegex(
                python_reproducibility.ReleaseError,
                "frozen output proof|inventory|embedded canonical wheel",
            ):
                python_reproducibility.validate_reproducibility_payload(
                    missing_embedded_wheel,
                    identity=fixture.identity,
                    identity_contract_sha256=common.identity_sha256(
                        fixture.identity_path
                    ),
                    canonical_artifacts=canonical_python_inputs,
                )
            first_wheel = (
                fixture.root
                / "orchestrated-reproduction/build-00/python-dist"
                / fixture.wheel_name
            )
            self.assertFalse(first_wheel.samefile(fixture.wheel))

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
            write_json(
                ready_report,
                fixture.wrap_evidence_payload(
                    "ready-archive-audit", json.loads(ready_report.read_text())
                ),
            )
            write_json(
                source_report,
                fixture.wrap_evidence_payload(
                    "source-archive-audit", json.loads(source_report.read_text())
                ),
            )
            by_gate["ready-archive-audit"]["file"] = common.file_record(ready_report)
            by_gate["source-archive-audit"]["file"] = common.file_record(source_report)
            fixture.write_identity()

            compression_payload = compression_generator.generate(
                argparse.Namespace(
                    identity=fixture.identity_path,
                    repository=fixture.repository,
                    artifact_dir=reproduction_a,
                    producer_dir=reproduction_a,
                    output=fixture.root / "raw-compression-comparison.json",
                    timeout=60,
                )
            )
            compression_evidence = evidence / "compression-comparison.json"
            write_json(
                compression_evidence,
                fixture.wrap_evidence_payload(
                    "compression-comparison", compression_payload
                ),
            )
            by_gate["compression-comparison"]["file"] = common.file_record(
                compression_evidence
            )
            fixture.write_identity()
            optimization_payload = optimization_generator.generate(
                argparse.Namespace(
                    identity=fixture.identity_path,
                    compression_evidence=compression_evidence,
                    blackbox_evidence=evidence / "blackbox.json",
                    practical_evidence=evidence / "practical.json",
                    output=fixture.root / "raw-optimization-ledger.json",
                )
            )
            optimization_evidence = evidence / "optimization-ledger.json"
            write_json(
                optimization_evidence,
                fixture.wrap_evidence_payload(
                    "optimization-ledger", optimization_payload
                ),
            )
            by_gate["optimization-ledger"]["file"] = common.file_record(
                optimization_evidence
            )
            fixture.write_identity()

            repro_workspace = fixture.root / "final-reproduction"
            raw_repro_report = fixture.root / "raw-python-reproduction.json"
            canonical_python_inputs = fixture.root / "final-canonical-python-inputs"
            canonical_python_inputs.mkdir()
            shutil.copyfile(
                fixture.wheel, canonical_python_inputs / fixture.wheel_name
            )
            shutil.copyfile(
                fixture.sdist, canonical_python_inputs / fixture.sdist_name
            )
            repro_payload = python_reproducibility.verify(
                argparse.Namespace(
                    identity=fixture.identity_path,
                    repository=fixture.repository,
                    canonical_artifacts=canonical_python_inputs,
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
                    workspace=repro_workspace,
                    output=raw_repro_report,
                )
            )
            repro_evidence = evidence / "python-reproducibility.json"
            write_json(
                repro_evidence,
                fixture.wrap_evidence_payload(
                    "python-reproducibility", repro_payload
                ),
            )
            by_gate["python-reproducibility"]["file"] = common.file_record(
                repro_evidence
            )
            fixture.write_identity()
            receipt_roots = sorted(repro_workspace.glob("build-*/native"))

            artifacts = fixture.root / "artifacts"
            artifacts.mkdir()
            for source in (
                fixture.wheel,
                fixture.sdist,
                reproduction_a / fixture.ready_name,
                reproduction_a / fixture.source_name,
            ):
                shutil.copyfile(source, artifacts / source.name)
            original_source_envelope = json.loads(source_report.read_text())
            hostile_source_envelope = copy.deepcopy(original_source_envelope)
            hostile_source_envelope["payload"]["identity_contract_sha256"] = "f" * 64
            write_json(source_report, hostile_source_envelope)
            by_gate["source-archive-audit"]["file"] = common.file_record(source_report)
            fixture.write_identity()
            with self.assertRaisesRegex(
                finalizer.ReleaseError, "corresponding-source nested audit"
            ):
                finalizer.finalize(
                    argparse.Namespace(
                        identity=fixture.identity_path,
                        artifacts=artifacts,
                        evidence=evidence,
                        repro_root=receipt_roots,
                        output=fixture.root / "bad-audit-digest.json",
                    )
                )
            write_json(source_report, original_source_envelope)
            by_gate["source-archive-audit"]["file"] = common.file_record(source_report)
            fixture.write_identity()
            with self.assertRaisesRegex(finalizer.ReleaseError, "receipts"):
                finalizer.finalize(
                    argparse.Namespace(
                        identity=fixture.identity_path,
                        artifacts=artifacts,
                        evidence=evidence,
                        repro_root=[reproduction_a, reproduction_b],
                        output=fixture.root / "bare-copy-roots.json",
                    )
                )
            with self.assertRaisesRegex(
                finalizer.ReleaseError, "distinct, non-nested"
            ):
                finalizer.finalize(
                    argparse.Namespace(
                        identity=fixture.identity_path,
                        artifacts=artifacts,
                        evidence=evidence,
                        repro_root=receipt_roots,
                        output=receipt_roots[0] / "report-inside-root.json",
                    )
                )
            original_gate_reader = finalizer._gate_evidence
            ready_final_path = artifacts / fixture.ready_name
            ready_final_bytes = ready_final_path.read_bytes()
            swapped = False

            def swap_after_snapshot(*call_args: object, **call_kwargs: object):
                nonlocal swapped
                value = original_gate_reader(*call_args, **call_kwargs)
                if not swapped:
                    ready_final_path.write_bytes(b"swapped-after-snapshot")
                    swapped = True
                return value

            with mock.patch.object(
                finalizer, "_gate_evidence", side_effect=swap_after_snapshot
            ), self.assertRaisesRegex(
                finalizer.ReleaseError, "pre-sidecar artifact"
            ):
                finalizer.finalize(
                    argparse.Namespace(
                        identity=fixture.identity_path,
                        artifacts=artifacts,
                        evidence=evidence,
                        repro_root=receipt_roots,
                        output=fixture.root / "swapped-artifact-report.json",
                    )
                )
            ready_final_path.write_bytes(ready_final_bytes)
            result = finalizer.finalize(
                argparse.Namespace(
                    identity=fixture.identity_path,
                    artifacts=artifacts,
                    evidence=evidence,
                    repro_root=receipt_roots,
                    output=fixture.root / "final-release.json",
                )
            )
            self.assertTrue(result["pass"])
            report_path = fixture.root / "final-release.json"
            self.assertEqual(
                (fixture.root / "final-release.json.sha256").read_text(
                    encoding="utf-8"
                ),
                f"{common.sha256_file(report_path)}  final-release.json\n",
            )
            self.assertEqual(
                {path.name for path in artifacts.iterdir()},
                {
                    fixture.wheel_name,
                    fixture.sdist_name,
                    fixture.ready_name,
                    fixture.source_name,
                    "EVIDENCE-SHA256SUMS",
                    "RELEASE-IDENTITY.json",
                    "SHA256SUMS",
                },
            )


if __name__ == "__main__":
    unittest.main()
