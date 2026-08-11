#!/usr/bin/env python3
"""Verify two truly independent Windows builds without publishing them."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import assemble_corresponding_source
import assemble_ready_run
from audit_corresponding_source_archive import audit as audit_source
from audit_ready_run_archive import audit as audit_ready
from release_common import (
    ReleaseError,
    artifact_record,
    assert_relative_evidence,
    file_record,
    files_equal,
    identity_sha256,
    json_bytes,
    load_identity,
    read_json,
    python_build_receipt_projection,
    require_release_bootstrap,
    source_execution_receipt_projection,
    tree_record,
    verify_artifact,
    verify_evidence_file,
    verify_file,
    verify_python_build_receipt,
    verify_source_receipt,
    verify_source_execution_receipt,
    verify_tree,
)


def require_distinct_nonaliased(first: Path, second: Path, *, label: str) -> tuple[Path, Path]:
    a = first.resolve(strict=True)
    b = second.resolve(strict=True)
    if a == b or a in b.parents or b in a.parents or a.samefile(b):
        raise ReleaseError(f"{label} roots are equal, nested, or aliased")
    return a, b


def require_contained(root: Path, values: list[Path], *, label: str) -> None:
    for value in values:
        try:
            value.resolve(strict=True).relative_to(root)
        except ValueError as exc:
            raise ReleaseError(f"{label} input is outside its fresh root: {value.name}") from exc


def ready_namespace(
    args: argparse.Namespace,
    *,
    frozen: Path,
    ledger: Path,
    wheel: Path,
    sdist: Path,
    corresponding_source: Path,
    work: Path,
    output: Path,
) -> SimpleNamespace:
    return SimpleNamespace(
        identity=args.identity,
        frozen=frozen,
        resources=args.resources,
        runtime=args.runtime,
        platform_lock=args.platform_lock,
        documents=args.documents,
        binary_readme_template=args.binary_readme_template,
        base_ledger=ledger,
        wheel=wheel,
        sdist=sdist,
        python_build_identity=args.python_build_identity,
        corresponding_source=corresponding_source,
        work_root=work,
        output=output,
        observation=None,
    )


def source_namespace(
    args: argparse.Namespace,
    *,
    payload: Path,
    receipt: Path,
    wheel: Path,
    sdist: Path,
    work: Path,
    output: Path,
) -> SimpleNamespace:
    return SimpleNamespace(
        identity=args.identity,
        source_payload=payload,
        source_receipt=receipt,
        components=args.components,
        source_readme_template=args.source_readme_template,
        wheel=wheel,
        sdist=sdist,
        work_root=work,
        output=output,
        observation=None,
    )


def finalize(args: argparse.Namespace) -> dict[str, Any]:
    identity_path = args.identity.resolve(strict=True)
    identity = load_identity(identity_path)
    identity_hash = identity_sha256(identity_path)

    source_roots = require_distinct_nonaliased(args.source_root_a, args.source_root_b, label="source materialization")
    build_roots = require_distinct_nonaliased(args.build_root_a, args.build_root_b, label="Python/freezer build")
    if any(source_root == build_root or source_root in build_root.parents or build_root in source_root.parents for source_root in source_roots for build_root in build_roots):
        raise ReleaseError("source materialization and Python/freezer roots must not alias/nest")

    payloads = [args.source_payload_a.resolve(strict=True), args.source_payload_b.resolve(strict=True)]
    source_receipts = [args.source_receipt_a.resolve(strict=True), args.source_receipt_b.resolve(strict=True)]
    source_execution_receipts = [
        args.source_execution_receipt_a.resolve(strict=True),
        args.source_execution_receipt_b.resolve(strict=True),
    ]
    for index, (root, payload, receipt, execution_receipt) in enumerate(
        zip(source_roots, payloads, source_receipts, source_execution_receipts)
    ):
        label = chr(ord("a") + index)
        require_contained(root, [payload, receipt, execution_receipt], label=f"source root {label}")
        verify_tree(payload, identity["inputs"]["source_payload_tree"], label=f"source payload {index}")
        verify_file(receipt, identity["inputs"]["source_receipt"], label=f"source receipt {index}")
        verify_source_receipt(read_json(receipt), identity)
        verify_source_execution_receipt(
            read_json(execution_receipt),
            identity,
            label=label,
            materialization_root=root,
            payload=payload,
            canonical_receipt=receipt,
        )
    if not files_equal(source_receipts[0], source_receipts[1]):
        raise ReleaseError("independent source materialization receipts differ")
    if files_equal(source_execution_receipts[0], source_execution_receipts[1]):
        raise ReleaseError("per-root source execution receipts are unexpectedly identical")

    roundtrip_roots = require_distinct_nonaliased(
        args.roundtrip_root_a,
        args.roundtrip_root_b,
        label="sdist roundtrip",
    )
    all_fresh_roots = [*source_roots, *build_roots, *roundtrip_roots]
    for index, first in enumerate(all_fresh_roots):
        for second in all_fresh_roots[index + 1 :]:
            if first == second or first in second.parents or second in first.parents or first.samefile(second):
                raise ReleaseError("source/build/sdist roundtrip roots are not mutually nonaliased")

    frozen = [args.frozen_a.resolve(strict=True), args.frozen_b.resolve(strict=True)]
    wheels = [args.wheel_a.resolve(strict=True), args.wheel_b.resolve(strict=True)]
    sdists = [args.sdist_a.resolve(strict=True), args.sdist_b.resolve(strict=True)]
    ledgers = [args.base_ledger_a.resolve(strict=True), args.base_ledger_b.resolve(strict=True)]
    build_receipts = [args.build_receipt_a.resolve(strict=True), args.build_receipt_b.resolve(strict=True)]
    receipt_values: list[dict[str, Any]] = []
    for index, (root, selected_frozen, wheel, sdist, ledger, receipt) in enumerate(
        zip(build_roots, frozen, wheels, sdists, ledgers, build_receipts)
    ):
        label = chr(ord("a") + index)
        require_contained(root, [selected_frozen, wheel, sdist, ledger, receipt], label=f"build root {label}")
        value = read_json(receipt)
        verify_python_build_receipt(
            value,
            identity,
            label=label,
            build_root=root,
            roundtrip_root=roundtrip_roots[index],
            bootstrap_python=args.bootstrap_python,
            wheelhouse=args.wheelhouse,
            optimization_config=args.optimization_config,
            python_build_identity=args.python_build_identity,
            frozen=selected_frozen,
            wheel=wheel,
            sdist=sdist,
            base_ledger=ledger,
        )
        verify_tree(selected_frozen, identity["inputs"]["frozen_tree"], label=f"frozen root {label}")
        verify_artifact(wheel, identity["artifacts"]["wheel"], label=f"wheel root {label}")
        verify_artifact(sdist, identity["artifacts"]["sdist"], label=f"sdist root {label}")
        verify_file(ledger, identity["inputs"]["base_ledger"], label=f"freezer ledger root {label}")
        receipt_values.append(value)
    if not files_equal(wheels[0], wheels[1]) or not files_equal(sdists[0], sdists[1]):
        raise ReleaseError("fresh-root wheel/sdist bytes are not identical")
    if tree_record(frozen[0]) != tree_record(frozen[1]) or not files_equal(ledgers[0], ledgers[1]):
        raise ReleaseError("fresh-root frozen tree/freezer ledger differ")
    if receipt_values[0]["root_identity"] == receipt_values[1]["root_identity"]:
        raise ReleaseError("independent build receipts claim the same root identity")

    output = args.output_dir.absolute()
    if output.exists() or output.is_symlink():
        raise ReleaseError(f"finalization output exists: {output}")
    output.mkdir(parents=True)
    assembly_roots = [output / "assembly-a", output / "assembly-b"]
    for root in assembly_roots:
        root.mkdir()
    require_distinct_nonaliased(*assembly_roots, label="archive assembly")

    source_outputs: list[Path] = []
    ready_outputs: list[Path] = []
    for index, assembly_root in enumerate(assembly_roots):
        label = chr(ord("a") + index)
        source_dir = assembly_root / "source-artifact"
        ready_dir = assembly_root / "ready-artifact"
        source_dir.mkdir()
        ready_dir.mkdir()
        source_output = source_dir / identity["artifacts"]["corresponding_source"]["filename"]
        assemble_corresponding_source.assemble(
            source_namespace(
                args,
                payload=payloads[index],
                receipt=source_receipts[index],
                wheel=wheels[index],
                sdist=sdists[index],
                work=assembly_root / "source-work",
                output=source_output,
            )
        )
        ready_output = ready_dir / identity["artifacts"]["ready_run"]["filename"]
        assemble_ready_run.assemble(
            ready_namespace(
                args,
                frozen=frozen[index],
                ledger=ledgers[index],
                wheel=wheels[index],
                sdist=sdists[index],
                corresponding_source=source_output,
                work=assembly_root / "ready-work",
                output=ready_output,
            )
        )
        source_outputs.append(source_output)
        ready_outputs.append(ready_output)
    for values, artifact_name in (
        (source_outputs, "corresponding_source"),
        (ready_outputs, "ready_run"),
    ):
        if not files_equal(values[0], values[1]):
            raise ReleaseError(f"distinct-root {artifact_name} archive bytes differ")
        verify_artifact(values[0], identity["artifacts"][artifact_name], label=f"final {artifact_name}")

    audit_args = {"identity": identity_path, "release_identity_sha256": identity_hash}
    ready_result = audit_ready(SimpleNamespace(**audit_args, archive=ready_outputs[0]))
    source_result = audit_source(SimpleNamespace(**audit_args, archive=source_outputs[0]))
    if ready_result.get("result") != "pass" or source_result.get("result") != "pass":
        raise ReleaseError("rebuilt archive static audit failed")

    evidence_root = args.evidence.resolve(strict=True)
    assert_relative_evidence(evidence_root)
    expected_paths = {value["path"] for value in identity["verification"]["evidence"]}
    observed_paths = {
        path.relative_to(evidence_root).as_posix()
        for path in evidence_root.rglob("*")
        if path.is_file()
    }
    if observed_paths != expected_paths:
        raise ReleaseError(
            f"evidence inventory differs: missing={sorted(expected_paths - observed_paths)}, extra={sorted(observed_paths - expected_paths)}"
        )
    evidence_values: dict[str, dict[str, Any]] = {}
    for record in identity["verification"]["evidence"]:
        path = evidence_root / record["path"]
        verify_file(
            payloads[0] / record["generator"]["script"]["path"],
            record["generator"]["script"]["file"],
            label=f"checked evidence generator {record['gate']}",
        )
        verify_file(
            args.bootstrap_python.resolve(strict=True),
            record["generator"]["tool"]["file"],
            label=f"evidence Python {record['gate']}",
        )
        verify_evidence_file(
            path,
            record=record,
            identity=identity,
            identity_hash=identity_hash,
        )
        evidence_values[record["gate"]] = read_json(path)
    python_observations = evidence_values["python-artifact-reproducibility"]["observations"]
    if python_observations.get("build_receipts") != [
        python_build_receipt_projection(value) for value in receipt_values
    ]:
        raise ReleaseError("Python reproducibility evidence does not contain exact fresh-root receipts")
    source_suite_observations = evidence_values["source-suite"]["observations"]
    expected_source_executions = [
        source_execution_receipt_projection(read_json(path))
        for path in source_execution_receipts
    ]
    if (
        source_suite_observations.get("canonical_receipt")
        != identity["inputs"]["source_receipt"]
        or source_suite_observations.get("materialization_execution_receipts")
        != expected_source_executions
    ):
        raise ReleaseError("source-suite evidence does not bind both actual materializations")
    archive_observations = evidence_values["archive-reproducibility"]["observations"]
    if archive_observations.get("ready_run") != artifact_record(ready_outputs[0], identity["artifacts"]["ready_run"]["url"]):
        raise ReleaseError("archive reproducibility evidence differs from ready-run bytes")
    if archive_observations.get("corresponding_source") != artifact_record(source_outputs[0], identity["artifacts"]["corresponding_source"]["url"]):
        raise ReleaseError("archive reproducibility evidence differs from source bytes")

    result = {
        "schema": "kazstem-windows-finalization-v2",
        "result": "pass",
        "release_identity_sha256": identity_hash,
        "source": {
            "commit": identity["source_commit"],
            "tree": identity["source_tree"],
            "origin": identity["source_origin"],
            "ref": identity["source_ref"],
            "independent_materializations": 2,
        },
        "independent_python_freezer_builds": 2,
        "independent_archive_assemblies": 2,
        "artifacts": {
            "wheel": identity["artifacts"]["wheel"],
            "sdist": identity["artifacts"]["sdist"],
            "ready_run": identity["artifacts"]["ready_run"],
            "corresponding_source": identity["artifacts"]["corresponding_source"],
        },
        "evidence_gates": sorted(evidence_values),
        "publishing_performed": False,
    }
    (output / "FINALIZATION.json").write_bytes(json_bytes(result))
    return result


def main() -> int:
    require_release_bootstrap("packaging/windows/finalize_release.py")
    parser = argparse.ArgumentParser()
    parser.add_argument("--identity", required=True, type=Path)
    for suffix in ("a", "b"):
        parser.add_argument(f"--source-root-{suffix}", required=True, type=Path)
        parser.add_argument(f"--source-payload-{suffix}", required=True, type=Path)
        parser.add_argument(f"--source-receipt-{suffix}", required=True, type=Path)
        parser.add_argument(f"--source-execution-receipt-{suffix}", required=True, type=Path)
        parser.add_argument(f"--build-root-{suffix}", required=True, type=Path)
        parser.add_argument(f"--roundtrip-root-{suffix}", required=True, type=Path)
        parser.add_argument(f"--frozen-{suffix}", required=True, type=Path)
        parser.add_argument(f"--wheel-{suffix}", required=True, type=Path)
        parser.add_argument(f"--sdist-{suffix}", required=True, type=Path)
        parser.add_argument(f"--base-ledger-{suffix}", required=True, type=Path)
        parser.add_argument(f"--build-receipt-{suffix}", required=True, type=Path)
    parser.add_argument("--components", required=True, type=Path)
    parser.add_argument("--resources", required=True, type=Path)
    parser.add_argument("--runtime", required=True, type=Path)
    parser.add_argument("--platform-lock", required=True, type=Path)
    parser.add_argument("--documents", required=True, type=Path)
    parser.add_argument("--binary-readme-template", required=True, type=Path)
    parser.add_argument("--source-readme-template", required=True, type=Path)
    parser.add_argument("--python-build-identity", required=True, type=Path)
    parser.add_argument("--bootstrap-python", required=True, type=Path)
    parser.add_argument("--wheelhouse", required=True, type=Path)
    parser.add_argument("--optimization-config", required=True, type=Path)
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(finalize(args), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ReleaseError, OSError, ValueError, json.JSONDecodeError) as exc:
        raise SystemExit(f"error: {exc}") from exc
