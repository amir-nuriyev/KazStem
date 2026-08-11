#!/usr/bin/env python3
"""Regression checks for the Pages package-integrity gate."""

from __future__ import annotations

import hashlib
import io
import importlib.util
import json
from pathlib import Path
import sys
import tarfile
import tempfile


STAGE_PAGES = Path(__file__).resolve().parents[1] / "tools" / "stage_pages.py"
SPEC = importlib.util.spec_from_file_location("kazstem_stage_pages", STAGE_PAGES)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load stage_pages.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def file_record(path: Path) -> dict[str, object]:
    content = path.read_bytes()
    return {"bytes": len(content), "sha256": hashlib.sha256(content).hexdigest()}


def write_manifest(root: Path, files: dict[str, dict[str, object]]) -> Path:
    manifest = {
        "base_project_commit": "97cf865a0cef20ee78be1610bbe76ec6c7e52006",
        "base_project_version": "0.2.1",
        "branch": "codex/browser-pages-poc",
        "file_count": len(files),
        "files": files,
        "package_build_state": {
            "distribution_scope": "public",
            "pages_status": "published",
            "repository_visibility": "public",
        },
        "schema": "kazstem.browser-isolated-package.v2",
        "self_excluded": "PACKAGE-MANIFEST.json",
        "total_bytes": sum(record["bytes"] for record in files.values()),
    }
    output = root / "PACKAGE-MANIFEST.json"
    output.write_text(json.dumps(manifest, sort_keys=True) + "\n", encoding="utf-8")
    return output


def expect_failure(root: Path, fragment: str) -> None:
    try:
        MODULE.verify_package_manifest(root)
    except SystemExit as error:
        if fragment not in str(error):
            raise AssertionError(f"expected {fragment!r} in {str(error)!r}") from error
    else:
        raise AssertionError("tampered package unexpectedly passed verification")


def expect_source_failure(root: Path, archive: Path, fragment: str) -> None:
    try:
        MODULE.verify_source_archive(root, archive)
    except SystemExit as error:
        if fragment not in str(error):
            raise AssertionError(f"expected {fragment!r} in {str(error)!r}") from error
    else:
        raise AssertionError("tampered source archive unexpectedly passed verification")


def write_source_fixture(archive_path: Path, readme: bytes, *, extra: bool = False) -> None:
    bundle_manifest = json.dumps({
        "schema": "kazstem-browser-corresponding-source-v1",
        "kazstem": {
            "commit": "97cf865a0cef20ee78be1610bbe76ec6c7e52006",
            "version": "0.2.1",
        },
        "apertium_kaz": {
            "commit": "95c6dd0d8536ee69a7058634b03a3e82100b6b6e",
        },
    }).encode("utf-8")
    with tarfile.open(archive_path, mode="w:gz") as archive:
        for name, content in [
            ("./SOURCE-BUNDLE-MANIFEST.json", bundle_manifest),
            ("./browser-poc/README.md", readme),
        ] + ([("./browser-poc/extra.js", b"extra\n")] if extra else []):
            member = tarfile.TarInfo(name)
            member.size = len(content)
            archive.addfile(member, io.BytesIO(content))


def main() -> int:
    assertions = 0
    with tempfile.TemporaryDirectory(prefix="kazstem-stage-integrity-") as directory:
        root = Path(directory)
        payload = root / "payload.txt"
        payload.write_text("frozen\n", encoding="utf-8")
        expected = {"payload.txt": file_record(payload)}
        manifest = write_manifest(root, expected)

        MODULE.verify_package_manifest(root)
        assertions += 1

        payload.write_text("changed\n", encoding="utf-8")
        expect_failure(root, "changed=['payload.txt']")
        assertions += 1
        payload.write_text("frozen\n", encoding="utf-8")

        extra = root / "extra.txt"
        extra.write_text("unexpected\n", encoding="utf-8")
        expect_failure(root, "extra=['extra.txt']")
        assertions += 1
        extra.unlink()

        payload.unlink()
        expect_failure(root, "missing=['payload.txt']")
        assertions += 1
        payload.write_text("frozen\n", encoding="utf-8")

        link = root / "payload-link.txt"
        link.symlink_to(payload.name)
        expect_failure(root, "does not permit symlinks")
        assertions += 1
        link.unlink()

        manifest_content = manifest.read_text(encoding="utf-8")
        manifest.unlink()
        manifest_target = root / "manifest-target.json"
        manifest_target.write_text(manifest_content, encoding="utf-8")
        manifest.symlink_to(manifest_target.name)
        expect_failure(root, "does not permit symlinks")
        assertions += 1

        manifest.unlink()
        manifest_target.unlink()
        manifest = write_manifest(root, expected)
        record = json.loads(manifest.read_text(encoding="utf-8"))
        record["package_build_state"]["pages_status"] = "not-published"
        manifest.write_text(json.dumps(record, sort_keys=True) + "\n", encoding="utf-8")
        expect_failure(root, "invalid package-manifest identity or build state")
        assertions += 1

        record["package_build_state"]["pages_status"] = "published"
        record["schema"] = "kazstem.browser-isolated-package.v1"
        manifest.write_text(json.dumps(record, sort_keys=True) + "\n", encoding="utf-8")
        expect_failure(root, "invalid package-manifest identity or build state")
        assertions += 1

    with tempfile.TemporaryDirectory(prefix="kazstem-source-integrity-") as directory:
        fixture = Path(directory)
        root = fixture / "browser-poc"
        root.mkdir()
        readme = root / "README.md"
        readme.write_text("current\n", encoding="utf-8")
        archive = fixture / "source.tar.gz"
        write_source_fixture(archive, b"current\n")

        MODULE.verify_source_archive(root, archive)
        assertions += 1

        readme.write_text("stale\n", encoding="utf-8")
        expect_source_failure(root, archive, "stale corresponding-source browser member")
        assertions += 1
        readme.write_text("current\n", encoding="utf-8")

        missing = root / "missing.js"
        missing.write_text("missing\n", encoding="utf-8")
        expect_source_failure(root, archive, "missing=['./browser-poc/missing.js']")
        assertions += 1
        missing.unlink()

        write_source_fixture(archive, b"current\n", extra=True)
        expect_source_failure(root, archive, "extra=['./browser-poc/extra.js']")
        assertions += 1

    print(json.dumps({
        "schema": "kazstem.browser-stage-package-integrity.v2",
        "assertions": assertions,
        "result": "pass",
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
