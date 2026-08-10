#!/usr/bin/env python3
"""Write a deterministic, source- and toolchain-pinned FST resource manifest."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
from typing import Any


SCHEMA = "qazmorph-resource-manifest-v4"
GUESSER_VERIFICATION_SCHEMA = "qazmorph-guesser-finiteness-v2"
GENERATOR_VERIFICATION_SCHEMA = "qazmorph-productive-generator-finiteness-v2"
REQUIRED_RESOURCES = (
    "kaz.automorf.hfstol",
    "kaz.autogen.hfstol",
    "kaz.guesser.automorf.hfstol",
    "kaz.guesser.autogen.hfstol",
    "kaz.rlx.bin",
)
SOURCE_INPUTS = (
    "apertium-kaz.kaz.lexc",
    "apertium-kaz.kaz.rlx",
    "apertium-kaz.kaz.twol",
)
BUILD_INPUTS = (
    "scripts/bootstrap_h100.sh",
    "scripts/build_resources.sh",
    "scripts/generator_regression_probes.json",
    "scripts/guesser_regression_probes.json",
    "scripts/toolchain_assets.lock.json",
    "scripts/verify_guesser_fst.py",
    "scripts/verify_generator_fst.py",
    "scripts/write_manifest.py",
    "scripts/write_toolchain_manifest.py",
    "src/qazmorph/guesser.py",
    "src/qazmorph/generator.py",
)
BUILD_COMMANDS = (
    "cg-comp",
    "hfst-compose-intersect",
    "hfst-disjunct",
    "hfst-fst2fst",
    "hfst-fst2strings",
    "hfst-fst2txt",
    "hfst-invert",
    "hfst-lexc",
    "hfst-lookup",
    "hfst-minimise",
    "hfst-optimized-lookup",
    "hfst-regexp2fst",
    "hfst-subtract",
    "hfst-twolc",
)


class ManifestError(RuntimeError):
    """Raised when exact build provenance cannot be established."""


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def file_record(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise ManifestError(f"required input or output is missing: {path}")
    return {"bytes": path.stat().st_size, "sha256": sha256(path)}


def read_json_with_identity(path: Path) -> tuple[Any, dict[str, Any]]:
    try:
        with path.open("rb") as stream:
            data = stream.read()
            stat = os.fstat(stream.fileno())
        value = json.loads(data.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ManifestError(f"cannot read JSON artifact {path}: {exc}") from exc
    return value, {
        "bytes": stat.st_size,
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def canonical_hash(value: Any) -> str:
    encoded = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def git_output(source_dir: Path, *arguments: str) -> str:
    try:
        return subprocess.check_output(
            ["git", "-C", str(source_dir), *arguments],
            text=True,
            encoding="utf-8",
            stderr=subprocess.STDOUT,
        ).strip()
    except subprocess.CalledProcessError as exc:
        raise ManifestError(
            f"git {' '.join(arguments)} failed for {source_dir}: {exc.output.strip()}"
        ) from exc


def atomic_write(path: Path, value: dict[str, Any]) -> None:
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(value, stream, ensure_ascii=False, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o644)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def load_toolchain_manifest(toolchain_dir: Path) -> dict[str, Any]:
    path = toolchain_dir / "manifest.json"
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ManifestError(f"cannot read verified toolchain manifest {path}: {exc}") from exc
    if manifest.get("schema") != "qazmorph-toolchain-manifest-v2":
        raise ManifestError(f"unsupported toolchain manifest schema: {path}")
    bundle_id = manifest.get("bundle_id")
    if not isinstance(bundle_id, str) or len(bundle_id) != 64:
        raise ManifestError(f"invalid toolchain bundle id: {path}")
    identity = {key: value for key, value in manifest.items() if key not in {"bundle_id", "version"}}
    if canonical_hash(identity) != bundle_id:
        raise ManifestError(f"toolchain manifest identity checksum is invalid: {path}")
    return manifest


def validate_generator_verification(
    value: Any,
    path: Path,
    *,
    resource_dir: Path,
    project_root: Path,
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ManifestError(
            f"productive-generator verification report is invalid: {path}"
        )
    try:
        graph = value["graph"]
        inverse = value["inverse_relation"]
        optimized = value["optimized_runtime"]
        probes = value["inversion_probes"]
        direction_relation = value["generation_direction_relation"]
        direction_probes = value["directionality_probes"]
        installed = value["installed_artifacts"]
        combined = value["combined_generation_subset"]
        inputs = value["inputs"]
    except (KeyError, TypeError) as exc:
        raise ManifestError(
            f"productive-generator verification report is invalid: {path}"
        ) from exc
    if not all(
        isinstance(section, dict)
        for section in (
            graph,
            inverse,
            optimized,
            probes,
            direction_relation,
            direction_probes,
            installed,
            combined,
            inputs,
        )
    ):
        raise ManifestError(
            f"productive-generator verification report is invalid: {path}"
        )

    def positive(item: object) -> bool:
        return isinstance(item, int) and not isinstance(item, bool) and item > 0

    valid = (
        value.get("schema") == GENERATOR_VERIFICATION_SCHEMA
        and graph.get("reachable_input_epsilon_cycle") is False
        and inverse.get("generator_inverse_equals_productive_analyzer") is True
        and inverse.get("productive_analyzer_minus_generator_inverse_empty") is True
        and inverse.get("generator_inverse_minus_productive_analyzer_empty") is True
        and optimized.get("full_relation_equivalent_to_standard") is True
        and optimized.get("standard_minus_optimized_roundtrip_empty") is True
        and optimized.get("optimized_roundtrip_minus_standard_empty") is True
        and optimized.get("candidate_sets_equal_to_standard") is True
        and optimized.get("standard_optimized_mismatches") == []
        and optimized.get("cycle_markers") == 0
        and optimized.get("cap_markers") == 0
        and positive(optimized.get("queries"))
        and positive(probes.get("required_pairs_checked"))
        and probes["required_pairs_checked"] >= 64
        and probes.get("required_pairs_missing") == []
        and positive(probes.get("forbidden_pairs_checked"))
        and probes.get("forbidden_pairs_observed") == 0
        and probes.get("forbidden_pairs_found") == []
        and probes.get("all_queries_keyed") is True
        and probes.get("cycle_markers") == 0
        and probes.get("cap_markers") == 0
        and direction_relation.get(
            "generation_safe_analyzer_subset_of_full_analyzer"
        )
        is True
        and direction_relation.get("generation_safe_minus_full_empty") is True
        and direction_relation.get("full_minus_generation_safe_nonempty") is True
        and direction_probes.get("required_pairs_checked") == 3
        and direction_probes.get("required_pairs_missing") == []
        and direction_probes.get("forbidden_pairs_checked") == 3
        and direction_probes.get("forbidden_pairs_observed") == 0
        and direction_probes.get("forbidden_pairs_found") == []
        and direction_probes.get("canonical_short_instrumental_only") is True
        and direction_probes.get(
            "analysis_only_adjective_comparative_excluded"
        )
        is True
        and direction_probes.get("analysis_only_verb_future_plan_excluded") is True
        and installed.get("all_installed_relations_equivalent_to_standard") is True
        and all(
            isinstance(installed.get(name), dict)
            and installed[name].get("full_relation_equivalent_to_standard") is True
            and installed[name].get(
                "standard_minus_optimized_roundtrip_empty"
            )
            is True
            and installed[name].get(
                "optimized_roundtrip_minus_standard_empty"
            )
            is True
            for name in (
                "dictionary_generator",
                "dictionary_analyzer_surface_to_lexical",
                "full_productive_analyzer",
            )
        )
        and combined.get(
            "dictionary_and_productive_generator_subset_of_analyzers"
        )
        is True
        and combined.get("generated_minus_accepted_empty") is True
    )
    if not valid:
        raise ManifestError(
            f"productive-generator verification report is invalid: {path}"
        )
    expected_inputs = {
        "generation_safe_productive_analyzer_standard",
        "full_productive_analyzer_standard",
        "full_productive_analyzer_optimized",
        "productive_generator_standard",
        "productive_generator_optimized",
        "dictionary_generator_standard",
        "dictionary_generator_optimized",
        "dictionary_analyzer_lexical_to_surface_standard",
        "dictionary_analyzer_surface_to_lexical_optimized",
        "baseline_probes",
        "direction_probes",
    }
    if not isinstance(inputs, dict) or set(inputs) != expected_inputs:
        raise ManifestError(
            f"productive-generator verification input inventory is invalid: {path}"
        )
    bound_files = {
        "productive_generator_optimized": resource_dir
        / "kaz.guesser.autogen.hfstol",
        "dictionary_generator_optimized": resource_dir / "kaz.autogen.hfstol",
        "dictionary_analyzer_surface_to_lexical_optimized": resource_dir
        / "kaz.automorf.hfstol",
        "full_productive_analyzer_optimized": resource_dir
        / "kaz.guesser.automorf.hfstol",
        "baseline_probes": project_root / "scripts/guesser_regression_probes.json",
        "direction_probes": project_root
        / "scripts/generator_regression_probes.json",
    }
    for name, bound_path in bound_files.items():
        if inputs.get(name) != file_record(bound_path):
            raise ManifestError(
                "productive-generator proof input does not match the staged or "
                f"checked-in artifact: {name}"
            )
    return value


def build_input_snapshot(project_root: Path) -> dict[str, dict[str, Any]]:
    """Return the exact checked-in project inputs consumed by a resource build."""

    return {
        relative: file_record(project_root / relative)
        for relative in BUILD_INPUTS
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--resource-dir", type=Path)
    parser.add_argument("--source-dir", type=Path)
    parser.add_argument("--toolchain-dir", type=Path)
    parser.add_argument("--project-root", required=True, type=Path)
    parser.add_argument("--guesser-verification", type=Path)
    parser.add_argument("--generator-verification", type=Path)
    parser.add_argument("--expected-build-input-snapshot", type=Path)
    parser.add_argument("--expected-source-commit")
    parser.add_argument("--snapshot-build-inputs", action="store_true")
    args = parser.parse_args()

    project_root = args.project_root.resolve()
    if args.snapshot_build_inputs:
        print(
            json.dumps(
                build_input_snapshot(project_root),
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 0
    missing = [
        name
        for name in (
            "resource_dir",
            "source_dir",
            "toolchain_dir",
            "guesser_verification",
            "generator_verification",
            "expected_build_input_snapshot",
        )
        if getattr(args, name) is None
    ]
    if missing:
        parser.error(
            "the following arguments are required outside snapshot mode: "
            + ", ".join("--" + name.replace("_", "-") for name in missing)
        )
    resource_dir = args.resource_dir.resolve()
    source_dir = args.source_dir.resolve()
    toolchain_dir = args.toolchain_dir.resolve()
    try:
        expected_build_inputs = json.loads(
            args.expected_build_input_snapshot.read_text(encoding="utf-8")
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ManifestError(
            "cannot read the initial build-input snapshot: "
            f"{args.expected_build_input_snapshot}: {exc}"
        ) from exc
    if expected_build_inputs != build_input_snapshot(project_root):
        raise ManifestError("project build inputs changed before manifest creation")
    guesser_verification_path = args.guesser_verification.resolve()
    generator_verification_path = args.generator_verification.resolve()
    guesser_verification, guesser_verification_record = read_json_with_identity(
        guesser_verification_path
    )
    guesser_graph = (
        guesser_verification.get("graph")
        if isinstance(guesser_verification, dict)
        else None
    )
    guesser_probes = (
        guesser_verification.get("no_cap_probes")
        if isinstance(guesser_verification, dict)
        else None
    )
    guesser_baseline = (
        guesser_verification.get("baseline_relation")
        if isinstance(guesser_verification, dict)
        else None
    )
    bounded_roots = (
        guesser_probes.get("bounded_root_relation")
        if isinstance(guesser_probes, dict)
        else None
    )
    if (
        not isinstance(guesser_verification, dict)
        or guesser_verification.get("schema") != GUESSER_VERIFICATION_SCHEMA
        or not isinstance(guesser_graph, dict)
        or guesser_graph.get("reachable_input_epsilon_cycle") is not False
        or not isinstance(guesser_probes, dict)
        or guesser_probes.get("cycle_markers") != 0
        or guesser_probes.get("all_lemmas_match_bounded_root_relation") is not True
        or guesser_probes.get("forbidden_readings_observed") != 0
        or not isinstance(guesser_probes.get("forbidden_readings_checked"), int)
        or guesser_probes["forbidden_readings_checked"] < 1
        or not isinstance(guesser_probes.get("probes"), int)
        or guesser_probes["probes"] < 362
        or not isinstance(
            guesser_probes.get("deterministic_adversarial_probes"), int
        )
        or guesser_probes["deterministic_adversarial_probes"] < 256
        or guesser_probes.get("tracked_readings_missing") != []
        or not isinstance(bounded_roots, dict)
        or bounded_roots.get("unbounded_input_epsilon_root_templates") is not False
        or not isinstance(bounded_roots.get("noun_high_vowel_syncope"), dict)
        or bounded_roots["noun_high_vowel_syncope"].get("noun_only") is not True
        or not isinstance(bounded_roots.get("loan_back_harmony"), dict)
        or bounded_roots["loan_back_harmony"].get(
            "generic_back_harmony_g_to_k"
        )
        is not False
        or not isinstance(guesser_baseline, dict)
        or guesser_baseline.get("baseline_subset_of_final") is not True
        or not isinstance(guesser_verification.get("optimized_runtime"), dict)
        or guesser_verification["optimized_runtime"].get(
            "candidate_sets_equal_to_standard"
        )
        is not True
        or guesser_verification["optimized_runtime"].get(
            "full_relation_equivalent_to_standard"
        )
        is not True
        or not isinstance(guesser_probes.get("required_readings_checked"), int)
        or guesser_probes["required_readings_checked"] < 1
    ):
        raise ManifestError(
            f"productive-guesser verification report is invalid: "
            f"{guesser_verification_path}"
        )

    generator_payload, generator_verification_record = read_json_with_identity(
        generator_verification_path
    )
    generator_verification = validate_generator_verification(
        generator_payload,
        generator_verification_path,
        resource_dir=resource_dir,
        project_root=project_root,
    )

    dirty = git_output(source_dir, "status", "--porcelain=v1", "--untracked-files=all")
    if dirty:
        raise ManifestError(f"refusing dirty apertium-kaz source tree:\n{dirty}")
    commit = git_output(source_dir, "rev-parse", "HEAD")
    if args.expected_source_commit and commit != args.expected_source_commit:
        raise ManifestError(
            f"source commit is {commit}, expected {args.expected_source_commit}"
        )
    tree = git_output(source_dir, "rev-parse", "HEAD^{tree}")
    source_date_epoch = int(git_output(source_dir, "show", "-s", "--format=%ct", "HEAD"))
    declared_epoch = os.environ.get("SOURCE_DATE_EPOCH")
    if declared_epoch is None or int(declared_epoch) != source_date_epoch:
        raise ManifestError(
            "SOURCE_DATE_EPOCH must equal the locked source commit timestamp "
            f"({source_date_epoch})"
        )

    toolchain_manifest = load_toolchain_manifest(toolchain_dir)
    toolchain_manifest_path = toolchain_dir / "manifest.json"
    toolchain_commands = toolchain_manifest.get("commands", {})
    for name in BUILD_COMMANDS:
        executable = toolchain_dir / "usr/bin" / name
        record = toolchain_commands.get(name)
        if not executable.is_file() or not isinstance(record, dict):
            raise ManifestError(f"build command is absent from verified toolchain: {name}")
        if record.get("sha256") != sha256(executable):
            raise ManifestError(f"build command differs from toolchain manifest: {name}")

    source_inputs = {
        relative: file_record(source_dir / relative) for relative in SOURCE_INPUTS
    }
    build_inputs = build_input_snapshot(project_root)
    if build_inputs != expected_build_inputs:
        raise ManifestError("project build inputs changed during resource compilation")
    files = {
        name: file_record(resource_dir / name) for name in REQUIRED_RESOURCES
    }
    unexpected = sorted(
        path.name
        for path in resource_dir.iterdir()
        if path.is_file() and path.name not in {*REQUIRED_RESOURCES, "manifest.json"}
    )
    if unexpected:
        raise ManifestError(f"unexpected files in staged resource bundle: {unexpected}")

    identity: dict[str, Any] = {
        "schema": SCHEMA,
        "source": {
            "name": "apertium-kaz",
            "url": "https://github.com/apertium/apertium-kaz",
            "commit": commit,
            "tree": tree,
            "commit_timestamp": datetime.fromtimestamp(
                source_date_epoch, timezone.utc
            ).isoformat(),
            "license": "GPL-3.0",
            "inputs": source_inputs,
        },
        "build": {
            "source_date_epoch": source_date_epoch,
            "locale": "C.UTF-8",
            "timezone": "UTC",
            "python_hash_seed": 0,
            "inputs": build_inputs,
            "verification": {
                "generator_subset_of_analyzer": {
                    "operation": "generation_relation - analysis_relation",
                    "required_result": "empty language",
                    "commands": ["hfst-subtract", "hfst-fst2strings"],
                },
                "productive_guesser_finite_valued": {
                    "operation": (
                        "reject every reachable input-epsilon cycle and run "
                        "the immutable no-cap bounded-root and forbidden-reading "
                        "probe fixture; prove the baseline relation is retained"
                    ),
                    "required_result": (
                        "no reachable input-epsilon cycle, no cycle marker, "
                        "every unknown lemma matches the explicit bounded root "
                        "relation, no forbidden generic loan reading, baseline "
                        "inclusion, and optimized serialization relation-equivalence"
                    ),
                    "commands": [
                        "hfst-fst2fst",
                        "hfst-fst2strings",
                        "hfst-fst2txt",
                        "hfst-lookup",
                        "hfst-optimized-lookup",
                        "hfst-subtract",
                    ],
                    "verifier": "scripts/verify_guesser_fst.py",
                    "probes": "scripts/guesser_regression_probes.json",
                    "report": guesser_verification_record,
                    "result": guesser_verification,
                },
                "productive_generator_finite_valued": {
                    "operation": (
                        "invert the Dir/LR-free finite productive analyzer; "
                        "prove it is a strict subset of the full analyzer; reject every "
                        "generator-orientation input-epsilon cycle; prove exact "
                        "inverse equality, every installed optimized relation, "
                        "immutable direction probes, and combined generated-pair "
                        "analyzer acceptance"
                    ),
                    "required_result": (
                        "finite-valued exact inverse of the generation-safe subset; "
                        "standard and installed optimized relations equal; every "
                        "required pair present; no forbidden loan or Dir/LR pair; "
                        "dictionary plus productive generation is a subset of "
                        "installed accepted analysis"
                    ),
                    "commands": [
                        "hfst-disjunct",
                        "hfst-fst2fst",
                        "hfst-fst2strings",
                        "hfst-fst2txt",
                        "hfst-invert",
                        "hfst-lookup",
                        "hfst-optimized-lookup",
                        "hfst-subtract",
                    ],
                    "verifier": "scripts/verify_generator_fst.py",
                    "probes": "scripts/guesser_regression_probes.json",
                    "direction_probes": (
                        "scripts/generator_regression_probes.json"
                    ),
                    "report": generator_verification_record,
                    "result": generator_verification,
                },
            },
            "toolchain": {
                "bundle_id": toolchain_manifest["bundle_id"],
                "version": toolchain_manifest["version"],
                "manifest": file_record(toolchain_manifest_path),
            },
        },
        "files": files,
    }
    bundle_id = canonical_hash(identity)
    manifest = {
        **identity,
        "bundle_id": bundle_id,
        "version": f"apertium-kaz-{commit[:12]}+qazmorph-{bundle_id[:16]}",
    }
    if build_input_snapshot(project_root) != expected_build_inputs:
        raise ManifestError("project build inputs changed before manifest publication")
    if (
        file_record(guesser_verification_path) != guesser_verification_record
        or file_record(generator_verification_path)
        != generator_verification_record
    ):
        raise ManifestError("a formal verification report changed during manifest creation")
    atomic_write(resource_dir / "manifest.json", manifest)
    print(bundle_id)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ManifestError, ValueError) as error:
        raise SystemExit(f"error: {error}") from error
