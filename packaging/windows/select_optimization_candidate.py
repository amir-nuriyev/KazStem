#!/usr/bin/env python3
"""Select the smallest final ZIP after two exact assemblies per candidate."""

from __future__ import annotations

import argparse
import json
from pathlib import Path, PurePosixPath
import tempfile
from typing import Any

from release_common import (
    ReleaseError,
    ZipOutputContract,
    archive_limits,
    artifact_record,
    canonical_hash,
    evidence_envelope,
    file_record,
    identity_sha256,
    inspect_zip,
    json_bytes,
    load_identity,
    read_json,
    release_bootstrap_prefix,
    source_boundary_contract,
    require_release_bootstrap,
    safe_extract_zip,
    tree_record,
    verify_file,
    verify_generator_runtime,
    verify_tree,
    WINDOWS_BEHAVIOR_EQUIVALENCE_CASES,
    _validate_clean_windows_runtime_provenance,
    _validate_windows_dll_denial,
    _validate_windows_timeout_reap,
)


def parse_mapping(values: list[str], label: str) -> dict[str, Path]:
    result: dict[str, Path] = {}
    for value in values:
        name, separator, raw_path = value.partition("=")
        if not separator or not name or name in result:
            raise ReleaseError(f"{label} must use unique NAME=PATH values")
        result[name] = Path(raw_path).resolve(strict=True)
    if len(result) < 2:
        raise ReleaseError("at least two optimization candidates are required")
    return result


def files_equal(first: Path, second: Path) -> bool:
    if first.stat().st_size != second.stat().st_size:
        return False
    with first.open("rb") as left, second.open("rb") as right:
        while True:
            left_block = left.read(1024 * 1024)
            right_block = right.read(1024 * 1024)
            if left_block != right_block:
                return False
            if not left_block:
                return True


def behavior_projection(value: Any, name: str) -> dict[str, Any]:
    if (
        not isinstance(value, dict)
        or value.get("schema") != "kazstem-windows-practical-matrix-v1"
        or value.get("result") != "pass"
        or value.get("candidate", {}).get("name") != name
    ):
        raise ReleaseError(f"candidate {name} does not have strict passing behavior evidence")
    results = value.get("results")
    coverage = value.get("coverage")
    if not isinstance(results, list) or not isinstance(coverage, dict) or value.get("cases") != len(results):
        raise ReleaseError(f"candidate {name} behavior evidence is incomplete")
    records_by_name: dict[str, dict[str, Any]] = {}
    required = {
        "name", "returncode", "stdin_bytes", "stdout_bytes", "stdout_sha256",
        "stderr_bytes", "stderr_sha256",
    }
    for record in results:
        if not isinstance(record, dict) or not required <= set(record):
            raise ReleaseError(f"candidate {name} behavior record lacks exact stream identities")
        record_name = record["name"]
        if not isinstance(record_name, str) or record_name in records_by_name:
            raise ReleaseError(f"candidate {name} has duplicate/invalid behavior names")
        records_by_name[record_name] = record
    missing = [
        case for case in WINDOWS_BEHAVIOR_EQUIVALENCE_CASES
        if case not in records_by_name
    ]
    if missing:
        raise ReleaseError(f"candidate {name} lacks functional cases: {missing}")
    projected = [
        {key: records_by_name[case][key] for key in sorted(required)}
        for case in WINDOWS_BEHAVIOR_EQUIVALENCE_CASES
    ]
    if canonical_hash(projected) != value.get("behavior_fingerprint"):
        raise ReleaseError(f"candidate {name} behavior fingerprint is not reproducible")
    _validate_clean_windows_runtime_provenance(value.get("runtime_provenance"))
    _validate_windows_dll_denial(
        value.get("dll_denial"), value.get("helper_path_denial")
    )
    timeout = value.get("timeout_reap")
    _validate_windows_timeout_reap(timeout)
    if value.get("network_tls_neural_assets_absent") is not True:
        raise ReleaseError(f"candidate {name} contains forbidden network/TLS/neural assets")
    return {
        "results": projected,
        "coverage": coverage,
        "behavior_fingerprint": value.get("behavior_fingerprint"),
        "runtime_provenance": value.get("runtime_provenance"),
        "dll_denial": value.get("dll_denial"),
        "helper_path_denial": value.get("helper_path_denial"),
        "timeout_reap": {
            "result": "pass",
            "bundle_process_tree_observed_before_kill": True,
            "returncode_after_taskkill_tree_nonzero": True,
            "lingering_bundle_processes": [],
        },
        "network_tls_neural_assets_absent": True,
    }


def require_nonaliased(paths: list[Path], *, label: str) -> None:
    for index, first in enumerate(paths):
        for second in paths[index + 1 :]:
            if first == second or first in second.parents or second in first.parents or first.samefile(second):
                raise ReleaseError(f"{label} roots are equal/nested/aliased")


def expected_assembly_argv(
    identity: dict[str, Any], name: str, label: str
) -> list[str]:
    upper = name.upper()
    inner = [
        "<PYTHON>", "packaging/windows/assemble_optimization_candidate.py",
        "--identity", f"<CANDIDATE-IDENTITY-{name}>",
        "--name", name, "--label", label,
        "--config", f"<CANDIDATE-CONFIG-{name}>",
        "--frozen", f"<CANDIDATE-FROZEN-{name}>",
        "--resources", "<RESOURCES>", "--runtime", "<WINDOWS-RUNTIME>",
        "--platform-lock", "<PLATFORM-LOCK>", "--documents", "<DOCUMENTS>",
        "--binary-readme-template", "<BINARY-README-TEMPLATE>",
        "--base-ledger", f"<CANDIDATE-LEDGER-{name}>",
        "--wheel", "<WHEEL>", "--sdist", "<SDIST>",
        "--corresponding-source", "<CORRESPONDING-SOURCE>",
        "--work-root", f"<CANDIDATE-{upper}-ASSEMBLY-{label.upper()}>",
        "--output", f"<CANDIDATE-ZIP-{name}-{label}>",
        "--receipt", f"<CANDIDATE-ASSEMBLY-RECEIPT-{name}-{label}>",
    ]
    return [
        *release_bootstrap_prefix(
            identity, "packaging/windows/assemble_optimization_candidate.py"
        ),
        *inner[2:],
    ]


def verify_assembly_receipt(
    value: Any,
    *,
    final_identity: dict[str, Any],
    candidate_identity_path: Path,
    candidate_identity: dict[str, Any],
    name: str,
    label: str,
    root: Path,
    archive: Path,
    frozen: Path,
    config: Path,
) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {
        "schema", "result", "name", "label", "source", "root_identity", "inputs",
        "output", "execution", "coverage",
    }:
        raise ReleaseError(f"candidate {name}/{label} assembly receipt fields differ")
    if (
        value["schema"] != "kazstem-windows-optimization-archive-assembly-v1"
        or value["result"] != "pass"
        or value["name"] != name
        or value["label"] != label
        or value["source"] != {
            "commit": final_identity["source_commit"],
            "tree": final_identity["source_tree"],
            "origin": final_identity["source_origin"],
            "ref": final_identity["source_ref"],
        }
    ):
        raise ReleaseError(f"candidate {name}/{label} assembly receipt identity differs")
    stat = root.stat()
    if value["root_identity"] != {
        "logical_label": f"{name}-{label}",
        "st_dev": stat.st_dev,
        "st_ino": stat.st_ino,
        "st_ctime_ns": stat.st_ctime_ns,
    }:
        raise ReleaseError(f"candidate {name}/{label} assembly root receipt differs")
    expected_inputs = {
        "identity": file_record(candidate_identity_path),
        "config": file_record(config),
        "frozen_tree": tree_record(frozen),
        "base_ledger": candidate_identity["inputs"]["base_ledger"],
    }
    if value["inputs"] != expected_inputs:
        raise ReleaseError(f"candidate {name}/{label} assembly inputs differ")
    if value["output"] != artifact_record(archive, candidate_identity["artifacts"]["ready_run"]["url"]):
        raise ReleaseError(f"candidate {name}/{label} assembly output differs")
    execution = value["execution"]
    script = execution.get("script", {}) if isinstance(execution, dict) else {}
    if (
        set(execution) != {
            "script", "argv", "cwd", "environment", "tool_versions",
            "source_boundary", "exit_code",
        }
        or script.get("path") != "packaging/windows/assemble_optimization_candidate.py"
        or script.get("file") != file_record(Path.cwd() / script["path"])
        or execution["argv"] != expected_assembly_argv(
            candidate_identity, name, label
        )
        or execution["cwd"] != "<MATERIALIZED-SOURCE>"
        or execution["environment"] != {"LC_ALL": "C", "PYTHONHASHSEED": "0", "TZ": "UTC"}
        or execution["tool_versions"] != read_json(config)["tool_versions"]
        or execution["exit_code"] != 0
    ):
        raise ReleaseError(f"candidate {name}/{label} assembly execution differs")
    expected_boundary = source_boundary_contract(
        candidate_identity,
        "packaging/windows/assemble_optimization_candidate.py",
    )
    expected_boundary.pop("bootstrap")
    if execution["source_boundary"] != expected_boundary:
        raise ReleaseError(f"candidate {name}/{label} source bootstrap differs")
    expected_checks = [
        "candidate-config", "candidate-frozen-tree", "checked-source-bootstrap",
        "deterministic-ready-assembler", "external-fresh-pycache-root",
        "exact-toolchain", "fresh-assembly-root", "output-artifact",
    ]
    if value["coverage"] != {"assertions": 8, "cases": 1, "checks": expected_checks}:
        raise ReleaseError(f"candidate {name}/{label} assembly coverage differs")
    return value


def assembly_receipt_projection(value: dict[str, Any]) -> dict[str, Any]:
    return {
        key: item for key, item in value.items() if key != "root_identity"
    } | {
        "root_identity": {
            "logical_label": value["root_identity"]["logical_label"],
            "distinct_nonnested_nonaliased": True,
        }
    }


def select(args: argparse.Namespace) -> tuple[dict[str, Any], dict[str, Any]]:
    identity_path = args.identity.resolve(strict=True)
    identity = load_identity(identity_path)
    mappings = {
        "candidate": parse_mapping(args.candidate, "--candidate"),
        "candidate_identity": parse_mapping(args.candidate_identity, "--candidate-identity"),
        "assembly_root_a": parse_mapping(args.assembly_root_a, "--assembly-root-a"),
        "assembly_root_b": parse_mapping(args.assembly_root_b, "--assembly-root-b"),
        "archive_a": parse_mapping(args.archive_a, "--archive-a"),
        "archive_b": parse_mapping(args.archive_b, "--archive-b"),
        "receipt_a": parse_mapping(args.receipt_a, "--receipt-a"),
        "receipt_b": parse_mapping(args.receipt_b, "--receipt-b"),
        "behavior": parse_mapping(args.behavior, "--behavior"),
        "config": parse_mapping(args.config, "--config"),
    }
    names = set(mappings["candidate"])
    if any(set(value) != names for value in mappings.values()):
        raise ReleaseError("all optimization NAME=PATH mappings must have identical names")
    expected_candidates = {value["name"]: value for value in identity["optimization"]["candidates"]}
    if names != set(expected_candidates):
        raise ReleaseError("optimization mappings differ from strict release identity")
    require_nonaliased(
        [path for key in ("assembly_root_a", "assembly_root_b") for path in mappings[key].values()],
        label="optimization assembly",
    )

    records: list[dict[str, Any]] = []
    behavior_hashes: set[str] = set()
    config_hashes: set[str] = set()
    behavior_values: dict[str, dict[str, Any]] = {}
    for name in sorted(names):
        frozen = mappings["candidate"][name]
        config_path = mappings["config"][name]
        behavior_path = mappings["behavior"][name]
        if file_record(config_path) != expected_candidates[name]["config"]:
            raise ReleaseError(f"candidate {name} config bytes differ from release identity")
        if file_record(behavior_path) != expected_candidates[name]["behavior"]:
            raise ReleaseError(f"candidate {name} behavior bytes differ from release identity")
        config = read_json(config_path)
        if (
            not isinstance(config, dict)
            or config.get("schema") != "kazstem-windows-optimization-config-v1"
            or config.get("name") != name
            or set(config.get("tool_versions", {})) != {"python", "pyinstaller", "zlib"}
            or config.get("switches", {}).get("python_optimize") != 0
            or config.get("switches", {}).get("upx") is not False
        ):
            raise ReleaseError(f"candidate {name} optimization config is incomplete")
        config_hashes.add(canonical_hash(config))
        behavior_value = read_json(behavior_path)
        behavior_values[name] = behavior_value
        projection = behavior_projection(behavior_value, name)
        behavior_hash = canonical_hash(projection)
        behavior_hashes.add(behavior_hash)
        archives = [mappings["archive_a"][name], mappings["archive_b"][name]]
        roots = [mappings["assembly_root_a"][name], mappings["assembly_root_b"][name]]
        receipts = [mappings["receipt_a"][name], mappings["receipt_b"][name]]
        candidate_identity_path = mappings["candidate_identity"][name]
        candidate_identity = load_identity(candidate_identity_path)
        if (
            candidate_identity["source_commit"] != identity["source_commit"]
            or candidate_identity["source_tree"] != identity["source_tree"]
            or candidate_identity["source_origin"] != identity["source_origin"]
            or candidate_identity["source_ref"] != identity["source_ref"]
            or candidate_identity["inputs"]["optimization_config"] != file_record(config_path)
            or candidate_identity["inputs"]["frozen_tree"] != tree_record(frozen)
            or candidate_identity["optimization"]["selected"] != name
        ):
            raise ReleaseError(f"candidate {name} assembly identity differs from its raw inputs")
        if (
            behavior_value.get("release_identity_sha256")
            != identity_sha256(candidate_identity_path)
            or behavior_value.get("candidate", {}).get("config")
            != file_record(config_path)
            or behavior_value.get("candidate", {}).get("archive")
            != file_record(archives[0])
            or behavior_value.get("candidate", {}).get("role") != "equivalence"
        ):
            raise ReleaseError(f"candidate {name} behavior is not bound to its exact identity/archive/config")
        receipt_values = []
        for label, root, archive, receipt_path in zip(("a", "b"), roots, archives, receipts):
            receipt_values.append(
                verify_assembly_receipt(
                    read_json(receipt_path),
                    final_identity=identity,
                    candidate_identity_path=candidate_identity_path,
                    candidate_identity=candidate_identity,
                    name=name,
                    label=label,
                    root=root,
                    archive=archive,
                    frozen=frozen,
                    config=config_path,
                )
            )
            members = inspect_zip(
                archive,
                limits=archive_limits(candidate_identity, "ready_run"),
                contract=ZipOutputContract(
                    candidate_identity["source_date_epoch"], (".exe", ".dll", ".pyd")
                ),
            )
            if {PurePosixPath(member.name).parts[0] for member in members} != {
                candidate_identity["ready_run"]["top_level"]
            }:
                raise ReleaseError(f"candidate {name}/{label} archive top-level differs")
        if file_record(archives[0]) != file_record(archives[1]) or not files_equal(archives[0], archives[1]):
            raise ReleaseError(f"candidate {name} ZIPs differ across independent assemblies")
        if receipt_values[0]["root_identity"] == receipt_values[1]["root_identity"]:
            raise ReleaseError(f"candidate {name} receipts claim the same assembly root")
        with tempfile.TemporaryDirectory(prefix=f"kazstem-opt-{name}-") as temporary:
            extracted = safe_extract_zip(
                archives[0],
                Path(temporary) / "fresh",
                limits=archive_limits(candidate_identity, "ready_run"),
                contract=ZipOutputContract(
                    candidate_identity["source_date_epoch"], (".exe", ".dll", ".pyd")
                ),
            )
            inclusion = read_json(extracted / "verification/MODULE-NATIVE-INCLUSION-LEDGER.json")
            if (
                inclusion.get("base_ledger", {}).get("frozen_tree") != tree_record(frozen)
                or inclusion.get("base_ledger", {}).get("config") != config
            ):
                raise ReleaseError(f"candidate {name} archive does not bind its raw tree/config")
        tree = tree_record(frozen)
        archive_file = file_record(archives[0])
        records.append(
            {
                "name": name,
                "raw_tree": tree,
                "final_zip": archive_file,
                "candidate_identity": file_record(candidate_identity_path),
                "config": file_record(config_path),
                "behavior": file_record(behavior_path),
                "behavior_sha256": behavior_hash,
                "tool_versions": config["tool_versions"],
                "assembly_receipts": [
                    assembly_receipt_projection(value) for value in receipt_values
                ],
            }
        )
    if len(behavior_hashes) != 1:
        raise ReleaseError("optimization candidates are not behavior-equivalent")
    if len(config_hashes) != len(records):
        raise ReleaseError("optimization candidates do not represent distinct configurations")
    records.sort(
        key=lambda value: (
            value["final_zip"]["bytes"],
            value["final_zip"]["sha256"],
            value["raw_tree"]["regular_file_bytes"],
            value["raw_tree"]["sha256"],
            value["name"],
        )
    )
    selected = records[0]
    if selected["name"] != identity["optimization"]["selected"]:
        raise ReleaseError("strict release identity did not select the smallest final ZIP")
    selected_archive = mappings["archive_a"][selected["name"]]
    if artifact_record(selected_archive, identity["artifacts"]["ready_run"]["url"]) != identity["artifacts"]["ready_run"]:
        raise ReleaseError("selected candidate ZIP is not the exact final ready-run artifact")
    full_path = args.selected_full_regression.resolve(strict=True)
    if file_record(full_path) != identity["optimization"]["selected_full_regression"]:
        raise ReleaseError("selected full-regression bytes differ from release identity")
    full = read_json(full_path)
    if (
        full.get("candidate", {}).get("name") != selected["name"]
        or full.get("candidate", {}).get("role") != "selected-full-regression"
        or full.get("candidate", {}).get("config") != selected["config"]
        or full.get("candidate", {}).get("archive") != selected["final_zip"]
        or full.get("release_identity_sha256")
        != identity_sha256(mappings["candidate_identity"][selected["name"]])
        or canonical_hash(behavior_projection(full, selected["name"]))
        != selected["behavior_sha256"]
    ):
        raise ReleaseError("selected full regression differs from the equivalence matrix")

    logical_argv = ["<PYTHON>", "packaging/windows/select_optimization_candidate.py", "--identity", "<RELEASE-IDENTITY>"]
    for option, key, marker in (
        ("--candidate", "candidate", "TREE"),
        ("--candidate-identity", "candidate_identity", "IDENTITY"),
        ("--assembly-root-a", "assembly_root_a", "ASSEMBLY-A"),
        ("--assembly-root-b", "assembly_root_b", "ASSEMBLY-B"),
        ("--archive-a", "archive_a", "ZIP-A"),
        ("--archive-b", "archive_b", "ZIP-B"),
        ("--receipt-a", "receipt_a", "RECEIPT-A"),
        ("--receipt-b", "receipt_b", "RECEIPT-B"),
        ("--behavior", "behavior", "BEHAVIOR"),
        ("--config", "config", "CONFIG"),
    ):
        for name in sorted(names):
            logical_argv.extend([option, f"{name}=<CANDIDATE-{marker}-{name}>"])
    logical_argv.extend(
        ["--selected-full-regression", "<SELECTED-FULL-REGRESSION>", "--json", "<EVIDENCE-OUTPUT>"]
    )
    evidence_record = verify_generator_runtime(
        identity,
        gate="optimization",
        logical_argv=logical_argv,
    )
    observations = {
        "selection_rule": "smallest final ZIP bytes, then ZIP SHA-256, raw bytes/tree SHA-256, name",
        "behavior_sha256": next(iter(behavior_hashes)),
        "selected": selected["name"],
        "selected_raw_tree": selected["raw_tree"],
        "selected_final_zip": identity["artifacts"]["ready_run"],
        "selected_full_regression": file_record(full_path),
        "candidates": records,
        "two_independent_assemblies_per_candidate": True,
        "python_optimization": "forbidden: checked release gates require __debug__",
        "upx": "forbidden: no pinned audited UPX transform is in the source closure",
    }
    envelope = evidence_envelope(
        identity,
        identity_hash=identity_sha256(identity_path),
        record=evidence_record,
        observations=observations,
    )
    return envelope, observations


def main() -> int:
    require_release_bootstrap("packaging/windows/select_optimization_candidate.py")
    parser = argparse.ArgumentParser()
    parser.add_argument("--identity", required=True, type=Path)
    for option in (
        "candidate", "candidate-identity", "assembly-root-a", "assembly-root-b",
        "archive-a", "archive-b", "receipt-a", "receipt-b", "behavior", "config",
    ):
        parser.add_argument(f"--{option}", action="append", required=True)
    parser.add_argument("--selected-full-regression", required=True, type=Path)
    parser.add_argument("--json", required=True, type=Path)
    args = parser.parse_args()
    result, observations = select(args)
    if args.json.exists() or args.json.is_symlink():
        raise ReleaseError(f"optimization output exists: {args.json}")
    args.json.parent.mkdir(parents=True, exist_ok=True)
    args.json.write_bytes(json_bytes(result))
    print(f"PASS: selected smallest behavior-equivalent final ZIP {observations['selected']}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ReleaseError, OSError, ValueError, json.JSONDecodeError) as exc:
        raise SystemExit(f"error: {exc}") from exc
