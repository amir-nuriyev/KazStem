#!/usr/bin/env python3
"""Verify immutable browser assets, then stage a GitHub Pages directory."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_package_manifest(package_root: Path) -> None:
    manifest_path = package_root / "PACKAGE-MANIFEST.json"
    if manifest_path.is_symlink():
        raise SystemExit(f"package manifest does not permit symlinks: {manifest_path}")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    expected_keys = {
        "base_project_commit",
        "base_project_version",
        "branch",
        "file_count",
        "files",
        "freeze_time_publication_state",
        "schema",
        "self_excluded",
        "total_bytes",
    }
    if set(manifest) != expected_keys:
        raise SystemExit("unexpected package-manifest fields")
    if (
        manifest["schema"] != "kazstem.browser-isolated-package.v1"
        or manifest["self_excluded"] != "PACKAGE-MANIFEST.json"
        or manifest["freeze_time_publication_state"]
        != {"deployed": False, "pushed": False}
    ):
        raise SystemExit("invalid package-manifest identity or freeze state")

    observed: dict[str, dict[str, object]] = {}
    for path in sorted(package_root.rglob("*")):
        if path.is_symlink():
            raise SystemExit(f"package manifest does not permit symlinks: {path}")
        if "__pycache__" in path.parts or path == manifest_path:
            continue
        if not path.is_file():
            continue
        relative = path.relative_to(package_root).as_posix()
        content = path.read_bytes()
        observed[relative] = {
            "bytes": len(content),
            "sha256": hashlib.sha256(content).hexdigest(),
        }
    if observed != manifest["files"]:
        missing = sorted(set(manifest["files"]) - set(observed))
        extra = sorted(set(observed) - set(manifest["files"]))
        changed = sorted(
            path
            for path in set(observed) & set(manifest["files"])
            if observed[path] != manifest["files"][path]
        )
        raise SystemExit(
            "browser package differs from PACKAGE-MANIFEST.json "
            f"(missing={missing}, extra={extra}, changed={changed})"
        )
    if (
        manifest["file_count"] != len(observed)
        or manifest["total_bytes"]
        != sum(record["bytes"] for record in observed.values())
    ):
        raise SystemExit("package-manifest count or byte total mismatch")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    package_root = root / "browser-poc"
    verify_package_manifest(package_root)
    web = package_root / "web"
    manifest_path = web / "resources" / "resource-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    resource = web / "resources" / manifest["resource"]["path"]
    if resource.stat().st_size != manifest["resource"]["bytes"]:
        raise SystemExit("resource byte size does not match manifest")
    if sha256(resource) != manifest["resource"]["sha256"]:
        raise SystemExit("resource SHA-256 does not match manifest")
    proof_record = manifest["proofs"]["candidate_probe_ledger"]
    proof = web / "resources" / proof_record["path"]
    if proof.stat().st_size != proof_record["bytes"] or sha256(proof) != proof_record["sha256"]:
        raise SystemExit("probe-ledger size/SHA-256 does not match manifest")
    required = [
        web / "index.html",
        web / "app.js",
        web / "worker.js",
        web / "csr.js",
        web / "analysis.js",
        web / "casefold.js",
        web / "formats.js",
        web / "styles.css",
        web / "sw.js",
        web / "manifest.webmanifest",
        web / "icons" / "icon.svg",
        web / "legal" / "LICENSE",
        web / "legal" / "THIRD_PARTY.md",
        web / "legal" / "SOURCE.md",
        web / "legal" / "SOURCE-ARCHIVE.json",
        web / "legal" / "kazstem-browser-corresponding-source-0.2.1.tar.gz",
        web / "resources" / "probe-ledger-summary.json",
    ]
    missing = [str(path) for path in required if not path.is_file()]
    if missing:
        raise SystemExit("missing Pages source/proof closure: " + ", ".join(missing))
    proof_summary = json.loads(proof.read_text(encoding="utf-8"))
    if proof_summary.get("result") != "pass" or proof_summary.get("probe_count") != 31_568:
        raise SystemExit("probe-ledger summary is not a complete passing gate")
    for record in proof_summary["compressed_exact_ledgers"].values():
        artifact = web / "proofs" / record["path"]
        if artifact.stat().st_size != record["bytes"] or sha256(artifact) != record["sha256"]:
            raise SystemExit(f"compressed exact-ledger mismatch: {artifact}")
    source_archive = web / "legal" / "kazstem-browser-corresponding-source-0.2.1.tar.gz"
    source_record = json.loads((web / "legal" / "SOURCE-ARCHIVE.json").read_text(encoding="utf-8"))
    if (
        source_record != {
            "bytes": source_archive.stat().st_size,
            "path": source_archive.name,
            "schema": "kazstem.browser-source-archive.v1",
            "sha256": sha256(source_archive),
        }
    ):
        raise SystemExit("corresponding-source archive size/SHA-256 mismatch")
    if args.output.exists():
        raise SystemExit(f"refusing to overwrite staging directory: {args.output}")
    shutil.copytree(web, args.output)
    (args.output / ".nojekyll").touch()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
