#!/usr/bin/env python3
"""Assemble the deterministic Windows corresponding-source ZIP."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import shutil

from release_common import (
    ReleaseError,
    archive_limits,
    artifact_record,
    checksum_rows,
    copy_tree_exact,
    ensure_output_outside,
    file_record,
    json_bytes,
    load_identity,
    manifest_records,
    normalize_tree,
    read_json,
    require_release_bootstrap,
    source_ready_location,
    verify_artifact,
    verify_file,
    verify_or_observe_output,
    verify_required_paths,
    verify_source_receipt,
    verify_tree,
    write_deterministic_zip,
)


def render_template(path: Path, replacements: dict[str, str]) -> bytes:
    try:
        text = path.read_text(encoding="utf-8", errors="strict")
    except (OSError, UnicodeError) as exc:
        raise ReleaseError(f"cannot read source README template: {exc}") from exc
    for key, value in replacements.items():
        marker = "{{" + key + "}}"
        if text.count(marker) != 1:
            raise ReleaseError(f"source template marker must occur once: {marker}")
        text = text.replace(marker, value)
    if "{{" in text or "}}" in text:
        raise ReleaseError("unresolved source template marker")
    return text.encode("utf-8")


def assemble(args: argparse.Namespace) -> dict[str, object]:
    ensure_output_outside(args.output, args.work_root, label="source archive output")
    if args.observation:
        ensure_output_outside(args.observation, args.work_root, label="source observation")
    if args.output.exists() or args.output.is_symlink():
        raise ReleaseError(f"source output already exists: {args.output}")
    identity = load_identity(args.identity.resolve(strict=True))
    inputs = identity["inputs"]
    source_contract = identity["corresponding_source"]
    artifacts = identity["artifacts"]
    payload = args.source_payload.resolve(strict=True)
    components = args.components.resolve(strict=True)
    verify_tree(payload, inputs["source_payload_tree"], label="application source payload")
    verify_file(args.source_readme_template.resolve(strict=True), inputs["source_readme_template"], label="source README template")
    verify_artifact(args.wheel.resolve(strict=True), artifacts["wheel"], label="canonical wheel")
    verify_artifact(args.sdist.resolve(strict=True), artifacts["sdist"], label="canonical sdist")
    python_build_identity = args.python_build_identity.resolve(strict=True)
    verify_file(
        python_build_identity,
        inputs["canonical_python_build_identity"],
        label="canonical Python build identity",
    )
    source_receipt = args.source_receipt.resolve(strict=True)
    verify_file(source_receipt, inputs["source_receipt"], label="Git source materialization receipt")
    receipt_value = read_json(source_receipt)
    verify_source_receipt(receipt_value, identity)

    work_root = args.work_root.absolute()
    if work_root.exists() or work_root.is_symlink():
        raise ReleaseError(f"source work root already exists: {work_root}")
    work_root.mkdir(parents=True)
    root = work_root / source_contract["top_level"]
    root.mkdir()
    categories = source_contract["categories"]
    for relative in categories.values():
        (root / relative).mkdir(parents=True, exist_ok=False)
    application_target = root / categories["application"] / "KazStem"
    copy_tree_exact(payload, application_target)
    application_licenses = root / categories["licenses"] / "KazStem"
    application_licenses.mkdir()
    for relative in ("LICENSE", "NOTICE", "THIRD_PARTY.md"):
        source = payload / relative
        if not source.is_file() or source.is_symlink():
            raise ReleaseError(f"application source lacks required license file: {relative}")
        shutil.copyfile(source, application_licenses / relative)

    copied_components: list[dict[str, object]] = []
    for value in source_contract["components"]:
        source = components / value["source"]
        verify_artifact(source, value["artifact"], label=f"source component {value['name']}")
        target = root / value["destination"]
        category_root = root / categories[value["category"]]
        try:
            target.resolve(strict=False).relative_to(category_root.resolve(strict=True))
        except ValueError as exc:
            raise ReleaseError(f"source component escapes category: {value['name']}") from exc
        if target.exists() or target.is_symlink():
            raise ReleaseError(f"source component destination exists: {value['destination']}")
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        copied_components.append(
            {
                "name": value["name"],
                "version": value["version"],
                "license": value["license"],
                "category": value["category"],
                "path": value["destination"],
                "artifact": value["artifact"],
            }
        )

    wheelhouse = root / source_contract["wheelhouse_destination"]
    if not wheelhouse.is_dir():
        raise ReleaseError(
            "corresponding-source components do not materialize the bound freezer wheelhouse"
        )
    verify_tree(
        wheelhouse,
        inputs["build_wheelhouse_tree"],
        label="copied offline freezer wheelhouse",
    )

    # Canonical Python artifacts are independently copied even when the closure
    # inventory also names them; destinations make any accidental collision fail.
    canonical_root = root / categories["build"] / "canonical-python-artifacts"
    canonical_root.mkdir(parents=True)
    for path, record in ((args.wheel.resolve(strict=True), artifacts["wheel"]), (args.sdist.resolve(strict=True), artifacts["sdist"])):
        target = canonical_root / path.name
        if target.exists():
            raise ReleaseError(f"canonical Python artifact duplicated: {path.name}")
        shutil.copyfile(path, target)
        verify_file(target, {"bytes": record["bytes"], "sha256": record["sha256"]}, label=f"copied {path.name}")
    build_identity_target = root / categories["build"] / "canonical-python-build-identity.json"
    shutil.copyfile(python_build_identity, build_identity_target)

    (root / source_contract["source_commit_file"]).parent.mkdir(parents=True, exist_ok=True)
    (root / source_contract["source_commit_file"]).write_text(identity["source_commit"] + "\n", encoding="ascii", newline="\n")
    (root / source_contract["source_date_epoch_file"]).write_text(str(identity["source_date_epoch"]) + "\n", encoding="ascii", newline="\n")
    (root / "README.md").write_bytes(
        render_template(
            args.source_readme_template.resolve(strict=True),
            {
                "VERSION": identity["release"],
                "TARGET": identity["platform"]["label"],
                "READY_FILENAME": artifacts["ready_run"]["filename"],
                "READY_URL": artifacts["ready_run"]["url"],
                "RELEASE_URL": identity["release_url"],
            },
        )
    )
    (root / "SOURCE-CLOSURE.json").write_bytes(
        json_bytes(
            {
                "schema": "kazstem-windows-source-closure-v1",
                "release": identity["release"],
                "source_commit": identity["source_commit"],
                "source_ref": identity["source_ref"],
                "paired_ready_run": source_ready_location(identity),
                "canonical_python_artifacts": {
                    "wheel": artifacts["wheel"],
                    "sdist": artifacts["sdist"],
                },
                "canonical_python_build_identity": {
                    "path": f"{categories['build']}/canonical-python-build-identity.json",
                    "file": inputs["canonical_python_build_identity"],
                },
                "components": copied_components,
                "offline_freezer_wheelhouse": {
                    "path": source_contract["wheelhouse_destination"],
                    "tree": inputs["build_wheelhouse_tree"],
                },
                "native_runtime_bundle": inputs["runtime_tree"],
                "source_materialization": {
                    "source": receipt_value["source"],
                    "payload_tree": receipt_value["payload_tree"],
                    "receipt": inputs["source_receipt"],
                },
            }
        )
    )

    verification = root / categories["evidence"]
    shutil.copyfile(source_receipt, verification / "GIT-SOURCE-MATERIALIZATION.json")
    (verification / "SOURCE-ASSEMBLY.json").write_bytes(
        json_bytes(
            {
                "schema": "kazstem-windows-source-assembly-v1",
                "result": "pass",
                "release": identity["release"],
                "source_commit": identity["source_commit"],
                "components": len(copied_components),
                "native_runtime_bundle_id": inputs["runtime_tree"]["bundle_id"],
            }
        )
    )
    manifest_path = root / "SOURCE-MANIFEST.json"
    files, directories = manifest_records(root, excluded={"SOURCE-MANIFEST.json", "SOURCE-FILES.sha256"})
    manifest_path.write_bytes(
        json_bytes(
            {
                "schema": "kazstem-windows-corresponding-source-manifest-v1",
                "release": identity["release"],
                "source_commit": identity["source_commit"],
                "files": files,
                "directories": directories,
            }
        )
    )
    checksum_path = root / "SOURCE-FILES.sha256"
    checksum_path.write_text(
        "\n".join(checksum_rows(root, excluded={"SOURCE-FILES.sha256"})) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    verify_required_paths(root, source_contract["required_paths"])
    normalize_tree(root, epoch=identity["source_date_epoch"], executable_paths=set())
    output = args.output.absolute()
    if output.name != artifacts["corresponding_source"]["filename"]:
        raise ReleaseError("source output filename differs from identity")
    write_deterministic_zip(root, output, epoch=identity["source_date_epoch"], limits=archive_limits(identity, "corresponding_source"))
    verify_or_observe_output(
        output,
        artifacts["corresponding_source"],
        observation=args.observation.absolute() if args.observation else None,
        label="corresponding source",
    )
    return {
        "result": "pass",
        "archive": artifact_record(output, artifacts["corresponding_source"]["url"]),
        "components": len(copied_components),
        "top_level": root.name,
    }


def main() -> int:
    require_release_bootstrap("packaging/windows/assemble_corresponding_source.py")
    parser = argparse.ArgumentParser()
    parser.add_argument("--identity", required=True, type=Path)
    parser.add_argument("--source-payload", required=True, type=Path)
    parser.add_argument("--components", required=True, type=Path)
    parser.add_argument("--source-readme-template", required=True, type=Path)
    parser.add_argument("--source-receipt", required=True, type=Path)
    parser.add_argument("--wheel", required=True, type=Path)
    parser.add_argument("--sdist", required=True, type=Path)
    parser.add_argument("--python-build-identity", required=True, type=Path)
    parser.add_argument("--work-root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--observation", type=Path)
    args = parser.parse_args()
    print(json.dumps(assemble(args), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ReleaseError, OSError, ValueError, json.JSONDecodeError) as exc:
        raise SystemExit(f"error: {exc}") from exc
