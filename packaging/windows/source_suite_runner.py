#!/usr/bin/env python3
"""Run the source tests against one explicitly installed wheel target."""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import sys
import traceback
import unittest
from typing import Any, Iterable


def require_source_bootstrap() -> None:
    try:
        import release_bootstrap

        value = release_bootstrap.attestation()
    except (ImportError, AttributeError, RuntimeError, ValueError) as exc:
        raise RuntimeError(
            "source_suite_runner.py must run through release_bootstrap.py"
        ) from exc
    if (
        value.get("schema") != "kazstem-release-source-bootstrap-v1"
        or value.get("entrypoint")
        != "packaging/windows/source_suite_runner.py"
        or value.get("release_identity") != "<RELEASE-IDENTITY>"
        or value.get("release_identity_verified") is not True
        or value.get("cache_absent_before_execution") is not True
        or value.get("cache_outside_source") is not True
        or value.get("adjacent_bytecode_rejected_before_local_imports") is not True
        or value.get("complete_source_inventory_verified_before_local_imports")
        is not True
    ):
        raise RuntimeError("source-suite runner bootstrap attestation differs")


def json_bytes(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def canonical_hash(value: Any) -> str:
    payload = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def sequence_record(values: Iterable[Any]) -> dict[str, Any]:
    materialized = list(values)
    return {
        "count": len(materialized),
        "sha256": canonical_hash(materialized),
        "values": materialized,
    }


def flatten(suite: unittest.TestSuite) -> list[unittest.TestCase]:
    result: list[unittest.TestCase] = []
    for value in suite:
        if isinstance(value, unittest.TestSuite):
            result.extend(flatten(value))
        else:
            result.append(value)
    return result


class RecordingResult(unittest.TextTestResult):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.run_ids: list[str] = []
        self.success_ids: list[str] = []

    def startTest(self, test: unittest.TestCase) -> None:
        self.run_ids.append(test.id())
        super().startTest(test)

    def addSuccess(self, test: unittest.TestCase) -> None:
        self.success_ids.append(test.id())
        super().addSuccess(test)


def failure_records(values: list[tuple[unittest.TestCase, str]]) -> list[dict[str, str]]:
    # Published passing ledgers only need the exact test IDs. Traceback text
    # embeds fresh extraction roots and would make an expected-failure receipt
    # host/run dependent.
    return [{"id": test.id()} for test, _error in values]


def import_identity(site: Path) -> dict[str, Any]:
    import qazmorph

    module = Path(qazmorph.__file__).resolve(strict=True)
    try:
        relative = module.relative_to(site).as_posix()
    except ValueError as exc:
        raise RuntimeError(f"qazmorph imported outside the installed target: {module}") from exc
    payload = module.read_bytes()
    return {
        "distribution": "kazstem",
        "distribution_version": importlib.metadata.version("kazstem"),
        "module": "qazmorph",
        "module_path": relative,
        "module_bytes": len(payload),
        "module_sha256": hashlib.sha256(payload).hexdigest(),
        "public_version": qazmorph.__version__,
    }


def main(*, require_bootstrap_boundary: bool = True) -> int:
    if require_bootstrap_boundary:
        require_source_bootstrap()
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--site", required=True, type=Path)
    parser.add_argument("--json", required=True, type=Path)
    args = parser.parse_args()
    source = args.source.resolve(strict=True)
    site = args.site.resolve(strict=True)
    output = args.json.absolute()
    if output.exists() or output.is_symlink():
        raise RuntimeError(f"suite receipt exists: {output}")
    if source == site or source in site.parents or site in source.parents:
        raise RuntimeError("source and installed-wheel target are equal or nested")
    sys.dont_write_bytecode = True
    sys.path.insert(0, os.fspath(site))
    imported = import_identity(site)
    os.chdir(source)
    loader = unittest.TestLoader()
    suite = loader.discover(
        start_dir=os.fspath(source / "tests"),
        pattern="test*.py",
        top_level_dir=os.fspath(source),
    )
    if loader.errors:
        raise RuntimeError("test discovery errors: " + "\n".join(loader.errors))
    discovered = [test.id() for test in flatten(suite)]
    if not discovered or len(set(discovered)) != len(discovered):
        raise RuntimeError("test discovery is empty or contains duplicate IDs")
    stream = __import__("io").StringIO()
    runner = unittest.TextTestRunner(
        stream=stream,
        verbosity=2,
        resultclass=RecordingResult,
    )
    result = runner.run(suite)
    skips = [
        {"id": test.id(), "reason_sha256": hashlib.sha256(reason.encode("utf-8")).hexdigest()}
        for test, reason in result.skipped
    ]
    expected_failures = failure_records(result.expectedFailures)
    failures = failure_records(result.failures)
    errors = failure_records(result.errors)
    unexpected_successes = [test.id() for test in result.unexpectedSuccesses]
    unexpected = {
        "failures": sequence_record(failures),
        "errors": sequence_record(errors),
        "unexpected_successes": sequence_record(unexpected_successes),
    }
    complete = (
        result.testsRun == len(discovered) == len(result.run_ids)
        and discovered == result.run_ids
        and result.wasSuccessful()
        and not failures
        and not errors
        and not unexpected_successes
        and len(result.success_ids) + len(skips) + len(expected_failures)
        == result.testsRun
    )
    receipt = {
        "schema": "kazstem-source-suite-test-ledger-v1",
        "result": "pass" if complete else "fail",
        "import": imported,
        "discovery": sequence_record(discovered),
        "run": sequence_record(result.run_ids),
        "successes": sequence_record(result.success_ids),
        "skips": sequence_record(skips),
        "expected_failures": sequence_record(expected_failures),
        "unexpected": unexpected,
        "tests_run": result.testsRun,
        "runner_output": {
            "published": False,
            "reason": "raw unittest text omitted because it contains a nondeterministic duration",
        },
        "discovery_order_equals_run_order": discovered == result.run_ids,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(json_bytes(receipt))
    if not complete:
        sys.stderr.write(stream.getvalue()[-8000:])
        return 1
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        traceback.print_exception(exc)
        raise SystemExit(2) from exc
