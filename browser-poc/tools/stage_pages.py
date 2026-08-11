#!/usr/bin/env python3
"""Verify immutable browser assets, then stage a GitHub Pages directory."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import tarfile


PACKAGE_BUILD_STATE = {
    "distribution_scope": "public",
    "pages_status": "published",
    "repository_visibility": "public",
}
SOURCE_ARCHIVE_NAME = "kazstem-browser-corresponding-source-0.2.1.tar.gz"
SOURCE_BROWSER_PREFIX = "./browser-poc/"


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
        "package_build_state",
        "schema",
        "self_excluded",
        "total_bytes",
    }
    if set(manifest) != expected_keys:
        raise SystemExit("unexpected package-manifest fields")
    if (
        manifest["schema"] != "kazstem.browser-isolated-package.v2"
        or manifest["self_excluded"] != "PACKAGE-MANIFEST.json"
        or manifest["package_build_state"] != PACKAGE_BUILD_STATE
    ):
        raise SystemExit("invalid package-manifest identity or build state")

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


def is_preferred_browser_source(relative: str) -> bool:
    """Return whether a package file is preferred source shipped in the archive."""

    if relative == "PACKAGE-MANIFEST.json" or "__pycache__" in Path(relative).parts:
        return False
    if relative.startswith("reports/"):
        return False
    if relative.startswith("web/proofs/") or relative.startswith("web/resources/"):
        return False
    if relative in {
        "web/legal/SOURCE-ARCHIVE.json",
        f"web/legal/{SOURCE_ARCHIVE_NAME}",
    }:
        return False
    return True


def verify_source_archive(package_root: Path, source_archive: Path) -> None:
    """Require the bundle's browser subtree to equal the current preferred source."""

    expected = {
        f"{SOURCE_BROWSER_PREFIX}{path.relative_to(package_root).as_posix()}": path
        for path in sorted(package_root.rglob("*"))
        if path.is_file()
        and not path.is_symlink()
        and is_preferred_browser_source(path.relative_to(package_root).as_posix())
    }
    try:
        archive = tarfile.open(source_archive, mode="r:gz")
    except (OSError, tarfile.TarError) as error:
        raise SystemExit(f"invalid corresponding-source archive: {error}") from error
    with archive:
        members: dict[str, tarfile.TarInfo] = {}
        for member in archive.getmembers():
            name = member.name if member.name.startswith("./") else f"./{member.name}"
            if name in members:
                raise SystemExit(f"duplicate corresponding-source member: {name}")
            members[name] = member
            if name.startswith(SOURCE_BROWSER_PREFIX) and not (
                member.isfile() or member.isdir()
            ):
                raise SystemExit(
                    f"browser corresponding source does not permit links/devices: {name}"
                )

        actual = {
            name: member
            for name, member in members.items()
            if name.startswith(SOURCE_BROWSER_PREFIX) and member.isfile()
        }
        if set(actual) != set(expected):
            missing = sorted(set(expected) - set(actual))
            extra = sorted(set(actual) - set(expected))
            raise SystemExit(
                "corresponding-source browser closure mismatch "
                f"(missing={missing}, extra={extra})"
            )
        for name, path in expected.items():
            member_file = archive.extractfile(actual[name])
            if member_file is None:
                raise SystemExit(f"could not read corresponding-source member: {name}")
            archived = member_file.read()
            current = path.read_bytes()
            if archived != current:
                raise SystemExit(f"stale corresponding-source browser member: {name}")

        bundle_manifest_member = members.get("./SOURCE-BUNDLE-MANIFEST.json")
        if bundle_manifest_member is None or not bundle_manifest_member.isfile():
            raise SystemExit("missing corresponding-source bundle manifest")
        bundle_manifest_file = archive.extractfile(bundle_manifest_member)
        if bundle_manifest_file is None:
            raise SystemExit("could not read corresponding-source bundle manifest")
        try:
            bundle_manifest = json.loads(bundle_manifest_file.read().decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise SystemExit("invalid corresponding-source bundle manifest") from error
        if (
            bundle_manifest.get("schema")
            != "kazstem-browser-corresponding-source-v1"
            or bundle_manifest.get("kazstem")
            != {
                "commit": "97cf865a0cef20ee78be1610bbe76ec6c7e52006",
                "version": "0.2.1",
            }
            or bundle_manifest.get("apertium_kaz")
            != {"commit": "95c6dd0d8536ee69a7058634b03a3e82100b6b6e"}
        ):
            raise SystemExit("unexpected corresponding-source bundle identity")


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
        web / "legal" / SOURCE_ARCHIVE_NAME,
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
    source_archive = web / "legal" / SOURCE_ARCHIVE_NAME
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
    verify_source_archive(package_root, source_archive)
    if args.output.exists():
        raise SystemExit(f"refusing to overwrite staging directory: {args.output}")
    shutil.copytree(web, args.output)
    (args.output / ".nojekyll").touch()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
