#!/usr/bin/env python3
"""Run the tagged source test suite against the exact canonical wheel/sdist."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import types
import unittest


def _source_module(name: str, path: Path) -> types.ModuleType:
    module = types.ModuleType(name)
    module.__file__ = str(path)
    sys.modules[name] = module
    source = path.read_bytes()
    try:
        exec(compile(source, str(path), "exec", dont_inherit=True), module.__dict__)
    finally:
        source = b""
    return module


_common = _source_module(
    "_kazstem_source_suite_release_common",
    Path(__file__).resolve().with_name("release_common.py"),
)
ReleaseError = _common.ReleaseError
SupervisionError = _common.SupervisionError
archive_limits = _common.archive_limits
file_record = _common.file_record
inspect_tar = _common.inspect_tar
json_bytes = _common.json_bytes
load_identity = _common.load_identity
run_bounded = _common.run_bounded
stream_evidence_record = _common.stream_evidence_record
verify_artifact = _common.verify_artifact


SCHEMA = "kazstem-linux-source-suite-v1"
DISCOVERY = [
    "{python}",
    "-m",
    "unittest",
    "discover",
    "-s",
    "tests",
    "-t",
    ".",
    "-p",
    "test*.py",
]
MAX_RUNNER_OUTPUT = 16 * 1024**2


def _run_bounded(
    argv: list[str], *, cwd: Path, environment: dict[str, str], timeout: int
) -> tuple[int, bytes, bytes]:
    try:
        completed = run_bounded(
            argv,
            cwd=cwd,
            environment=environment,
            timeout=timeout,
            max_stdout=MAX_RUNNER_OUTPUT,
            max_stderr=MAX_RUNNER_OUTPUT,
        )
    except SupervisionError as exc:
        raise ReleaseError(f"source-suite subprocess supervision failed: {exc}") from exc
    return completed.returncode, completed.stdout, completed.stderr


def _test_ids(suite: unittest.TestSuite) -> list[str]:
    result: list[str] = []
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            result.extend(_test_ids(item))
        else:
            result.append(item.id())
    return result


def _normalize_log(data: bytes, replacements: list[tuple[str, str]]) -> bytes:
    try:
        text = data.decode("utf-8")
    except UnicodeError as exc:
        raise ReleaseError("source-suite subprocess output is not UTF-8") from exc
    text = text.replace("\r\n", "\n")
    for actual, logical in sorted(replacements, key=lambda item: len(item[0]), reverse=True):
        text = text.replace(actual, logical)
        text = text.replace(actual.replace("/", "\\"), logical)
    return text.encode("utf-8")


def run(args: argparse.Namespace) -> dict[str, object]:
    if args.output.exists() or args.output.is_symlink():
        raise ReleaseError("source-suite payload output already exists")
    identity = load_identity(args.identity.resolve(strict=True))
    verify_artifact(args.wheel, identity["artifacts"]["wheel"], label="source-suite wheel")
    verify_artifact(args.sdist, identity["artifacts"]["sdist"], label="source-suite sdist")
    sdist_members = inspect_tar(
        args.sdist,
        limits=archive_limits(identity, "nested"),
        expected_top=f"kazstem-{identity['release']}",
    )
    if not sdist_members:
        raise ReleaseError("canonical sdist is empty")
    freezer = identity["verification"]["reproducibility"]["frozen_builder"]
    if args.pip_wheelhouse.is_symlink() or not args.pip_wheelhouse.is_dir():
        raise ReleaseError("source-suite pip wheelhouse is not a real directory")
    observed_wheelhouse = [
        {"filename": path.name, **file_record(path)}
        for path in sorted(args.pip_wheelhouse.iterdir(), key=lambda item: item.name)
        if path.is_file() and not path.is_symlink()
    ]
    if (
        len(observed_wheelhouse) != len(list(args.pip_wheelhouse.iterdir()))
        or observed_wheelhouse != freezer["wheelhouse"]["files"]
        or _common.canonical_hash(observed_wheelhouse)
        != freezer["wheelhouse"]["manifest_sha256"]
    ):
        raise ReleaseError("source-suite pip wheelhouse differs from identity")
    pip_wheel = args.pip_wheelhouse / freezer["bootstrap_pip"]["filename"]
    _common.verify_file(
        pip_wheel,
        freezer["bootstrap_pip"]["file"],
        label="source-suite bootstrap pip wheel",
    )

    controlled = {
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PIP_CONFIG_FILE": os.devnull,
        "PIP_DISABLE_PIP_VERSION_CHECK": "1",
        "PIP_NO_INDEX": "1",
        "PYTHONHASHSEED": "0",
        "PYTHONNOUSERSITE": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONPATH": str(pip_wheel.resolve(strict=True)),
        "TZ": "UTC",
    }
    pip_returncode, pip_version_output, pip_version_stderr = _run_bounded(
        [sys.executable, "-S", "-m", "pip", "--version"],
        cwd=Path.cwd(),
        environment=controlled,
        timeout=60,
    )
    if pip_returncode or pip_version_stderr:
        raise ReleaseError("source-suite pip identity command failed")
    with tempfile.TemporaryDirectory(prefix="kazstem-wheel-install-") as temporary:
        install_root = Path(temporary) / "installed"
        install_returncode, install_stdout, install_stderr = _run_bounded(
            [
                sys.executable,
                "-S",
                "-m",
                "pip",
                "install",
                "--no-index",
                "--no-deps",
                "--no-compile",
                "--quiet",
                "--target",
                str(install_root),
                str(args.wheel.resolve(strict=True)),
            ],
            cwd=Path.cwd(),
            environment=controlled,
            timeout=300,
        )
        if install_returncode:
            raise ReleaseError("offline canonical wheel installation failed")
        install_replacements = [
            (str(args.wheel.resolve(strict=True)), f"artifacts/{args.wheel.name}"),
            (str(install_root), "wheel-install"),
            (str(Path(temporary)), "wheel-install-root"),
            (
                str(args.pip_wheelhouse.resolve(strict=True)),
                "inputs/python-freezer-wheelhouse",
            ),
            (
                str(pip_wheel.resolve(strict=True)),
                "inputs/python-freezer-wheelhouse/" + pip_wheel.name,
            ),
            (str(Path(sys.prefix).resolve()), "python-prefix"),
            (str(Path(sys.executable).resolve()), "{python}"),
        ]
        install_stdout = _normalize_log(install_stdout, install_replacements)
        install_stderr = _normalize_log(install_stderr, install_replacements)
        pip_version_output = _normalize_log(
            pip_version_output,
            [
                (str(Path(sys.prefix).resolve()), "python-prefix"),
                (str(Path(sys.executable).resolve()), "{python}"),
                (
                    str(args.pip_wheelhouse.resolve(strict=True)),
                    "inputs/python-freezer-wheelhouse",
                ),
                (
                    str(pip_wheel.resolve(strict=True)),
                    "inputs/python-freezer-wheelhouse/" + pip_wheel.name,
                ),
            ],
        )
        sys.path.insert(0, str(install_root))
        os.environ["PYTHONPATH"] = str(install_root)
        try:
            import qazmorph  # type: ignore[import-not-found]
        except Exception as exc:
            raise ReleaseError(f"installed canonical wheel cannot be imported: {exc}") from exc
        module_path = Path(qazmorph.__file__ or "").resolve(strict=True)
        if install_root.resolve(strict=True) not in module_path.parents:
            raise ReleaseError("source suite did not import the installed canonical wheel")
        probe_returncode, probe_stdout, probe_stderr = _run_bounded(
            [
                sys.executable,
                "-c",
                "import pathlib,qazmorph; print(pathlib.Path(qazmorph.__file__).resolve())",
            ],
            cwd=Path.cwd(),
            environment={**controlled, "PYTHONPATH": str(install_root)},
            timeout=60,
        )
        if (
            probe_returncode
            or probe_stderr
            or install_root.resolve(strict=True)
            not in Path(probe_stdout.decode("utf-8").strip()).parents
        ):
            raise ReleaseError("child process did not import the installed wheel")
        probe_stdout = _normalize_log(probe_stdout, install_replacements)

        suite = unittest.defaultTestLoader.discover(
            start_dir="tests", pattern="test*.py", top_level_dir="."
        )
        test_ids = sorted(_test_ids(suite))
        if not test_ids or len(test_ids) != len(set(test_ids)):
            raise ReleaseError("source suite discovery is empty or has duplicate test ids")
        test_inventory_sha256 = hashlib.sha256(
            ("\n".join(test_ids) + "\n").encode("utf-8")
        ).hexdigest()
        stream = io.StringIO()
        result = unittest.TextTestRunner(stream=stream, verbosity=2).run(suite)
        runner_text = re.sub(
            r"(?m)^Ran ([0-9]+) tests? in [0-9.]+s$",
            r"Ran \1 tests in <duration>s",
            stream.getvalue(),
        )
        runner_bytes = runner_text.encode("utf-8")
        if len(runner_bytes) > MAX_RUNNER_OUTPUT:
            raise ReleaseError("source-suite runner output exceeds cap")
        skipped_ids = sorted(test.id() for test, _reason in result.skipped)
        expected_failure_ids = sorted(
            test.id() for test, _detail in result.expectedFailures
        )
        skipped_ids_sha256 = hashlib.sha256(
            (("\n".join(skipped_ids) + "\n") if skipped_ids else "").encode("utf-8")
        ).hexdigest()
        expected_failure_ids_sha256 = hashlib.sha256(
            (
                ("\n".join(expected_failure_ids) + "\n")
                if expected_failure_ids
                else ""
            ).encode("utf-8")
        ).hexdigest()
    payload: dict[str, object] = {
        "schema": SCHEMA,
        "pass": result.wasSuccessful() and result.testsRun > 0,
        "release": identity["release"],
        "source_commit": identity["source_commit"],
        "source_tree": identity["source_tree"],
        "unittest_discovery_argv": DISCOVERY,
        "tests_run": result.testsRun,
        "tests_discovered": len(test_ids),
        "test_ids_sha256": test_inventory_sha256,
        "failures": len(result.failures),
        "errors": len(result.errors),
        "skipped": len(result.skipped),
        "skipped_test_ids_sha256": skipped_ids_sha256,
        "expected_failures": len(result.expectedFailures),
        "expected_failure_test_ids_sha256": expected_failure_ids_sha256,
        "unexpected_successes": len(result.unexpectedSuccesses),
        "wheel": identity["artifacts"]["wheel"],
        "sdist": identity["artifacts"]["sdist"],
        "sdist_members": len(sdist_members),
        "wheel_import": {
            "distribution": "kazstem",
            "artifact": file_record(args.wheel),
            "install_argv": [
                "{python}", "-S", "-m", "pip", "install", "--no-index", "--no-deps",
                "--no-compile", "--quiet", "--target", "wheel-install",
                f"artifacts/{args.wheel.name}",
            ],
            "install_stdout": stream_evidence_record(install_stdout),
            "install_stderr": stream_evidence_record(install_stderr),
            "pip_version": stream_evidence_record(pip_version_output),
            "pip": {
                "filename": freezer["bootstrap_pip"]["filename"],
                **freezer["bootstrap_pip"]["file"],
                "version": freezer["bootstrap_pip"]["version"],
            },
            "wheelhouse_manifest_sha256": freezer["wheelhouse"][
                "manifest_sha256"
            ],
            "child_import": stream_evidence_record(probe_stdout),
            "from_canonical_wheel": True,
        },
        "runner_output": stream_evidence_record(runner_bytes),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(json_bytes(payload))
    if payload["pass"] is not True:
        raise ReleaseError("source suite failed")
    return payload


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--identity", required=True, type=Path)
    parser.add_argument("--wheel", required=True, type=Path)
    parser.add_argument("--sdist", required=True, type=Path)
    parser.add_argument("--pip-wheelhouse", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    result = run(parser.parse_args())
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ReleaseError, OSError, ValueError, json.JSONDecodeError) as exc:
        raise SystemExit(f"error: {exc}") from exc
