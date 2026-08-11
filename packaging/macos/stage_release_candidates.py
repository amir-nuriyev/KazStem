#!/usr/bin/env python3
"""Resolve the finite ready/source compression-name fixed point safely."""

from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
from typing import Any

import assemble_corresponding_source as source_assembler
import assemble_ready_run as ready_assembler
import compare_compression
from release_common import (
    ReleaseError,
    assert_relative_json,
    ensure_distinct_nonaliased_paths,
    ensure_output_outside,
    file_record,
    identity_sha256,
    json_bytes,
    load_identity,
    verify_artifact,
    verify_file,
)


SCHEMA = "kazstem-macos-release-staging-v1"
SUFFIX = {"gzip": ".tar.gz", "xz": ".tar.xz", "zstd": ".tar.zst"}


def _download_url(identity: dict[str, Any], filename: str) -> str:
    return (
        identity["release_url"].rsplit("/tag/", 1)[0]
        + f"/download/v{identity['release']}/{filename}"
    )


def _artifact(identity: dict[str, Any], path: Path) -> dict[str, Any]:
    return {
        "filename": path.name,
        **file_record(path),
        "url": _download_url(identity, path.name),
    }


def _identity_path(root: Path, name: str, identity: dict[str, Any]) -> Path:
    path = root / name
    if path.exists() or path.is_symlink():
        raise ReleaseError(f"staging identity already exists: {name}")
    path.write_bytes(json_bytes(identity))
    loaded = load_identity(path)
    if loaded != identity:
        raise ReleaseError(f"staging identity did not round-trip: {name}")
    return path


def _set_artifact_filename(
    identity: dict[str, Any], asset_name: str, format_name: str
) -> None:
    prefix = f"kazstem-{identity['release']}-{identity['platform']['label']}-" + (
        "ready-run-unsigned" if asset_name == "ready_run" else "corresponding-source"
    )
    filename = prefix + SUFFIX[format_name]
    identity["artifacts"][asset_name]["filename"] = filename
    identity["artifacts"][asset_name]["url"] = _download_url(identity, filename)
    identity["compression"][asset_name]["selected_format"] = format_name


def _set_canonical_tar(
    identity: dict[str, Any], asset_name: str, tar_record: dict[str, Any]
) -> None:
    expected_name = identity["compression"][asset_name]["canonical_tar"]["filename"]
    if tar_record["filename"] != expected_name:
        raise ReleaseError(f"{asset_name} canonical tar name changed during staging")
    identity["compression"][asset_name]["canonical_tar"].update(
        {"bytes": tar_record["bytes"], "sha256": tar_record["sha256"]}
    )


def _source_args(
    args: argparse.Namespace,
    *,
    identity_path: Path,
    work_root: Path,
    output: Path,
    canonical_only: bool,
) -> argparse.Namespace:
    return argparse.Namespace(
        identity=identity_path,
        repository=args.repository,
        payload=args.payload,
        source_readme_template=args.source_readme_template,
        wheel=args.wheel,
        sdist=args.sdist,
        work_root=work_root,
        output=output,
        observation=None,
        canonical_tar_only=canonical_only,
    )


def _ready_args(
    args: argparse.Namespace,
    *,
    identity_path: Path,
    source: Path,
    work_root: Path,
    output: Path,
    canonical_only: bool,
) -> argparse.Namespace:
    return argparse.Namespace(
        identity=identity_path,
        frozen=args.frozen,
        resources=args.resources,
        runtime=args.runtime,
        documents=args.documents,
        binary_readme_template=args.binary_readme_template,
        base_ledger=args.base_ledger,
        wheel=args.wheel,
        sdist=args.sdist,
        corresponding_source=source,
        work_root=work_root,
        output=output,
        observation=None,
        canonical_tar_only=canonical_only,
    )


def _candidate_path(
    comparison_root: Path,
    *,
    asset_name: str,
    canonical_tar: Path,
    format_name: str,
) -> Path:
    return (
        comparison_root
        / asset_name
        / format_name
        / "build-1"
        / (canonical_tar.name[:-4] + SUFFIX[format_name])
    )


def _one_hypothesis(
    args: argparse.Namespace,
    *,
    base: dict[str, Any],
    format_name: str,
    root: Path,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    root.mkdir()
    identity = copy.deepcopy(base)
    _set_artifact_filename(identity, "ready_run", format_name)
    provisional_path = _identity_path(root, "hypothesis-identity.json", identity)

    source_work = root / "source-work"
    source_assembler.assemble(
        _source_args(
            args,
            identity_path=provisional_path,
            work_root=source_work,
            output=root / identity["artifacts"]["corresponding_source"]["filename"],
            canonical_only=True,
        )
    )
    source_tar = (
        source_work
        / identity["compression"]["corresponding_source"]["canonical_tar"]["filename"]
    )
    source_tar_record = {"filename": source_tar.name, **file_record(source_tar)}
    _set_canonical_tar(identity, "corresponding_source", source_tar_record)
    source_comparison_root = root / "source-compression"
    source_comparison = compare_compression._one_asset(
        identity=identity,
        asset_name="corresponding_source",
        canonical_tar=source_tar,
        published=None,
        workspace=source_comparison_root,
        enforce_selection=False,
    )
    source_format = source_comparison["selected"]["format"]
    source_path = _candidate_path(
        source_comparison_root,
        asset_name="corresponding_source",
        canonical_tar=source_tar,
        format_name=source_format,
    )
    _set_artifact_filename(identity, "corresponding_source", source_format)
    if source_path.name != identity["artifacts"]["corresponding_source"]["filename"]:
        raise ReleaseError("measured source candidate filename differs")
    identity["artifacts"]["corresponding_source"] = _artifact(identity, source_path)

    ready_identity_path = _identity_path(root, "ready-identity.json", identity)
    ready_work = root / "ready-work"
    ready_assembler.assemble(
        _ready_args(
            args,
            identity_path=ready_identity_path,
            source=source_path,
            work_root=ready_work,
            output=root / identity["artifacts"]["ready_run"]["filename"],
            canonical_only=True,
        )
    )
    ready_tar = (
        ready_work / identity["compression"]["ready_run"]["canonical_tar"]["filename"]
    )
    ready_tar_record = {"filename": ready_tar.name, **file_record(ready_tar)}
    _set_canonical_tar(identity, "ready_run", ready_tar_record)
    ready_comparison_root = root / "ready-compression"
    ready_comparison = compare_compression._one_asset(
        identity=identity,
        asset_name="ready_run",
        canonical_tar=ready_tar,
        published=None,
        workspace=ready_comparison_root,
        enforce_selection=False,
    )
    measured_ready_format = ready_comparison["selected"]["format"]
    ready_path = _candidate_path(
        ready_comparison_root,
        asset_name="ready_run",
        canonical_tar=ready_tar,
        format_name=measured_ready_format,
    )
    fixed = measured_ready_format == format_name
    result = {
        "hypothesis": format_name,
        "fixed_point": fixed,
        "corresponding_source": source_comparison,
        "ready_run": ready_comparison,
        "source_artifact": _artifact(identity, source_path),
        "ready_artifact": _artifact(identity, ready_path),
        "canonical_tars": {
            "corresponding_source": source_tar_record,
            "ready_run": ready_tar_record,
        },
    }
    paths = {
        "source": source_path,
        "ready_run": ready_path,
        "source_tar": source_tar,
        "ready_tar": ready_tar,
    }
    return result, identity, paths


def stage(args: argparse.Namespace) -> dict[str, Any]:
    if args.workspace.exists() or args.workspace.is_symlink():
        raise ReleaseError("staging workspace must be fresh")
    if args.receipt.exists() or args.receipt.is_symlink():
        raise ReleaseError("staging receipt already exists")
    ensure_distinct_nonaliased_paths(
        args.workspace,
        args.receipt,
        labels=("staging workspace", "staging receipt"),
    )
    ensure_output_outside(args.receipt, args.workspace, label="staging receipt")
    bootstrap_path = args.bootstrap_identity.resolve(strict=True)
    base = load_identity(bootstrap_path)
    if any(
        base["artifacts"][name]["sha256"] != "0" * 64
        or base["compression"][name]["canonical_tar"]["sha256"] != "0" * 64
        for name in ("ready_run", "corresponding_source")
    ):
        raise ReleaseError("staging requires explicit zero-hash native placeholders")
    verify_artifact(
        args.wheel.resolve(strict=True), base["artifacts"]["wheel"], label="wheel"
    )
    verify_artifact(
        args.sdist.resolve(strict=True), base["artifacts"]["sdist"], label="sdist"
    )

    workspace = args.workspace.absolute()
    workspace.mkdir(parents=True)
    hypotheses: list[dict[str, Any]] = []
    states: dict[str, tuple[dict[str, Any], dict[str, Path]]] = {}
    for format_name in ("gzip", "xz", "zstd"):
        result, candidate_identity, paths = _one_hypothesis(
            args,
            base=base,
            format_name=format_name,
            root=workspace / format_name,
        )
        hypotheses.append(result)
        states[format_name] = (candidate_identity, paths)

    fixed = [record for record in hypotheses if record["fixed_point"]]
    if len(fixed) != 1:
        raise ReleaseError(
            f"ready compression/name selection lacks one unique fixed point: "
            f"{[record['hypothesis'] for record in fixed]}"
        )
    chosen = fixed[0]
    chosen_format = chosen["hypothesis"]
    final_identity, paths = states[chosen_format]
    final_ready_format = chosen["ready_run"]["selected"]["format"]
    _set_artifact_filename(final_identity, "ready_run", final_ready_format)
    final_identity["artifacts"]["ready_run"] = _artifact(
        final_identity, paths["ready_run"]
    )
    final_identity_path = _identity_path(
        workspace / chosen_format, "staged-final-identity.json", final_identity
    )

    recheck = workspace / "final-recheck"
    assets = recheck / "assets"
    assets.mkdir(parents=True)
    source_recheck = (
        assets / final_identity["artifacts"]["corresponding_source"]["filename"]
    )
    source_assembler.assemble(
        _source_args(
            args,
            identity_path=final_identity_path,
            work_root=recheck / "source-work",
            output=source_recheck,
            canonical_only=False,
        )
    )
    verify_file(
        source_recheck, file_record(paths["source"]), label="source fixed-point recheck"
    )
    ready_recheck = assets / final_identity["artifacts"]["ready_run"]["filename"]
    ready_assembler.assemble(
        _ready_args(
            args,
            identity_path=final_identity_path,
            source=source_recheck,
            work_root=recheck / "ready-work",
            output=ready_recheck,
            canonical_only=False,
        )
    )
    verify_file(
        ready_recheck,
        file_record(paths["ready_run"]),
        label="ready fixed-point recheck",
    )

    receipt = {
        "schema": SCHEMA,
        "pass": True,
        "release": base["release"],
        "source_commit": base["source_commit"],
        "source_tree": base["source_tree"],
        "source_ref": base["source_ref"],
        "bootstrap_identity_contract_sha256": identity_sha256(bootstrap_path),
        "hypotheses": hypotheses,
        "unique_fixed_point": chosen_format,
        "selected": {
            "corresponding_source": final_identity["artifacts"]["corresponding_source"],
            "ready_run": final_identity["artifacts"]["ready_run"],
            "canonical_tars": chosen["canonical_tars"],
            "staged_identity": {
                "path": f"{chosen_format}/staged-final-identity.json",
                "file": file_record(final_identity_path),
            },
        },
        "independent_recheck": {
            "distinct_nonaliased_roots": True,
            "corresponding_source": {
                "path": f"final-recheck/assets/{source_recheck.name}",
                "file": file_record(source_recheck),
            },
            "ready_run": {
                "path": f"final-recheck/assets/{ready_recheck.name}",
                "file": file_record(ready_recheck),
            },
        },
    }
    assert_relative_json(receipt, label="release staging receipt")
    args.receipt.parent.mkdir(parents=True, exist_ok=True)
    args.receipt.write_bytes(json_bytes(receipt))
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bootstrap-identity", required=True, type=Path)
    parser.add_argument("--repository", required=True, type=Path)
    parser.add_argument("--payload", required=True, type=Path)
    parser.add_argument("--source-readme-template", required=True, type=Path)
    parser.add_argument("--frozen", required=True, type=Path)
    parser.add_argument("--resources", required=True, type=Path)
    parser.add_argument("--runtime", required=True, type=Path)
    parser.add_argument("--documents", required=True, type=Path)
    parser.add_argument("--binary-readme-template", required=True, type=Path)
    parser.add_argument("--base-ledger", required=True, type=Path)
    parser.add_argument("--wheel", required=True, type=Path)
    parser.add_argument("--sdist", required=True, type=Path)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--receipt", required=True, type=Path)
    args = parser.parse_args()
    stage(args)
    print("PASS: unique macOS compression/name fixed point staged and reproduced")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ReleaseError, OSError, ValueError, json.JSONDecodeError) as exc:
        raise SystemExit(f"error: {exc}") from exc
