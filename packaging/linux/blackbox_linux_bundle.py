#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import time
from xml.etree import ElementTree

from release_common import ReleaseError, ensure_output_outside, load_identity, read_json


if not __debug__:
    raise RuntimeError("the Linux black-box release gate must not run with -O")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


class Gate:
    def __init__(
        self, root: Path, expected_version: str, expected_resource_version: str
    ) -> None:
        self.root = root.resolve(strict=True)
        self.executable = self.root / "kazstem"
        self.expected_version = expected_version
        self.expected_resource_version = expected_resource_version
        self.results: list[dict[str, object]] = []

    def run(
        self,
        name: str,
        args: list[str],
        *,
        input_bytes: bytes = b"",
        expected: int = 0,
        cwd: Path | None = None,
        env: dict[str, str] | None = None,
        timeout: float = 40.0,
    ) -> subprocess.CompletedProcess[bytes]:
        started = time.monotonic()
        completed = subprocess.run(
            args,
            input=input_bytes,
            cwd=cwd,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
        )
        elapsed = time.monotonic() - started
        if completed.returncode != expected:
            raise AssertionError(
                f"{name}: return code {completed.returncode}, expected {expected}; "
                f"stderr={completed.stderr.decode('utf-8', 'replace')!r}"
            )
        self.results.append({
            "name": name,
            "returncode": completed.returncode,
            "seconds": round(elapsed, 6),
            "stdin_bytes": len(input_bytes),
            "stdout_bytes": len(completed.stdout),
            "stdout_sha256": sha256_bytes(completed.stdout),
            "stderr_bytes": len(completed.stderr),
            "stderr_sha256": sha256_bytes(completed.stderr),
        })
        return completed

    @staticmethod
    def jsonl(value: bytes) -> list[dict[str, object]]:
        return [json.loads(line) for line in value.decode("utf-8").splitlines()]

    @staticmethod
    def reconstructed(records: list[dict[str, object]]) -> str:
        return "".join(
            str(record["text"])
            for record in records
            if record.get("consumes_input") is True
        )

    def execute(self) -> dict[str, object]:
        assert self.executable.is_file() and os.access(self.executable, os.X_OK)

        version = self.run("version", [str(self.executable), "--version"])
        assert version.stdout == f"kazstem {self.expected_version}\n".encode("ascii")
        for alias in ("qazmorph", "mystem-kz"):
            path = self.root / alias
            assert path.is_symlink() and os.readlink(path) == "kazstem"
            result = self.run(f"version-alias-{alias}", [str(path), "--version"])
            assert result.stdout == version.stdout

        base_text = "балалар мектепке барды.\n"
        base = self.run(
            "base-jsonl",
            [str(self.executable), "-c", "--format", "jsonl"],
            input_bytes=base_text.encode("utf-8"),
        )
        base_records = self.jsonl(base.stdout)
        assert self.reconstructed(base_records) == base_text
        assert any(
            analysis.get("lemma") == "бала"
            and analysis.get("source") == "lexicon"
            for record in base_records
            for analysis in record.get("analysis", [])
        )
        assert {
            record.get("resource_version") for record in base_records
            if record.get("record_type") == "token"
        } == {self.expected_resource_version}

        oov_text = "суперқазақшалар\n"
        oov = self.run(
            "productive-oov",
            [str(self.executable), "--format", "jsonl"],
            input_bytes=oov_text.encode("utf-8"),
        )
        oov_records = self.jsonl(oov.stdout)
        assert any(
            analysis.get("guessed") is True and analysis.get("source") == "guesser"
            for record in oov_records
            for analysis in record.get("analysis", [])
        )

        cg = self.run(
            "constraint-grammar",
            [str(self.executable), "-d", "-c", "--format", "jsonl"],
            input_bytes=base_text.encode("utf-8"),
        )
        cg_records = self.jsonl(cg.stdout)
        assert self.reconstructed(cg_records) == base_text
        assert {
            record.get("mode") for record in cg_records
            if record.get("record_type") == "token"
        } == {"contextual"}

        json_text = "Бала & <мектеп>.\n"
        legacy_json = self.run(
            "mystem-json",
            [str(self.executable), "-c", "--format", "json"],
            input_bytes=json_text.encode("utf-8"),
        )
        json_records = json.loads(legacy_json.stdout)
        assert "".join(record["text"] for record in json_records) == json_text
        assert legacy_json.stdout.startswith(b'[{"analysis":')
        assert legacy_json.stdout.index(b'"analysis"') < legacy_json.stdout.index(
            b'"text"'
        )

        xml = self.run(
            "xml",
            [str(self.executable), "-c", "--format", "xml"],
            input_bytes=json_text.encode("utf-8"),
        )
        xml_root = ElementTree.fromstring(xml.stdout)
        assert xml_root.tag == "html"
        assert "".join(xml_root.itertext()) == json_text
        first_word = xml_root.find("./body/se/w")
        assert first_word is not None and first_word.text is None
        assert list(first_word) and list(first_word)[-1].tail == "Бала"

        protected = "Қазақ e\u0301 ^$[]{}\\/\r\n\x00соң\n"
        protected_result = self.run(
            "unicode-reserved-nul-jsonl",
            [str(self.executable), "-c", "--format", "jsonl"],
            input_bytes=protected.encode("utf-8"),
        )
        protected_records = self.jsonl(protected_result.stdout)
        assert self.reconstructed(protected_records) == protected

        xml_error = self.run(
            "xml-forbidden-nul",
            [str(self.executable), "-c", "--format", "xml"],
            input_bytes=b"a\x00b",
            expected=2,
        )
        assert b"U+0000" in xml_error.stderr
        assert b"Traceback" not in xml_error.stderr

        runtime_roots = sorted(
            path
            for path in (self.root / ".qazmorph/platform-runtimes").iterdir()
            if path.is_dir()
        )
        assert len(runtime_roots) == 1
        runtime = runtime_roots[0]
        lookup = runtime / "usr/bin/hfst-optimized-lookup"
        generator = self.root / ".qazmorph/resources/kaz.autogen.hfstol"
        generated = self.run(
            "generation",
            [str(lookup), "-q", "-u", "-n", "128", str(generator)],
            input_bytes="кітап<n><pl><dat>\n".encode("utf-8"),
        )
        assert "кітаптарға" in generated.stdout.decode("utf-8")

        with tempfile.TemporaryDirectory(prefix="kazstem hostile Қаз []^$\n") as temp:
            hostile = Path(temp)
            hostile_bin = hostile / "fake bin"
            hostile_bin.mkdir()
            marker = hostile / "PATH-WAS-USED"
            for command in ("hfst-proc", "hfst-optimized-lookup", "cg-proc"):
                fake = hostile_bin / command
                fake.write_text(
                    f"#!/bin/sh\nprintf used > {str(marker)!r}\nexit 97\n",
                    encoding="utf-8",
                )
                fake.chmod(0o755)
            fake_resources = hostile / ".qazmorph/resources"
            fake_resources.mkdir(parents=True)
            (fake_resources / "kaz.automorf.hfstol").write_bytes(b"hostile")
            input_path = hostile / "кіріс ^$[]{} space\n.txt"
            output_path = hostile / "шығыс Қазақ space\n.json"
            file_text = "Қазақстан ^$[]{} мектеп\n"
            input_path.write_text(file_text, encoding="utf-8", newline="")
            environment = {
                key: value for key, value in os.environ.items()
                if not key.startswith("QAZMORPH_")
                and not key.startswith("DYLD_")
                and not key.startswith("LD_")
                and key not in {"CG3_DEFAULT", "CG3_OVERRIDE"}
            }
            environment["PATH"] = str(hostile_bin)
            environment["HOME"] = str(hostile / "fake home")
            self.run(
                "hostile-cwd-file-paths",
                [
                    str(self.executable), "-c", "--format", "json",
                    str(input_path), str(output_path),
                ],
                cwd=hostile,
                env=environment,
            )
            output_records = json.loads(output_path.read_bytes())
            assert "".join(record["text"] for record in output_records) == file_text
            with input_path.open(encoding="utf-8", newline="") as source:
                assert source.read() == file_text
            assert not marker.exists()
            self.run(
                "hostile-cwd-constraint-grammar",
                [str(self.executable), "-d", "--format", "jsonl"],
                input_bytes="балалар\n".encode("utf-8"),
                cwd=hostile,
                env=environment,
            )
            assert not marker.exists()

        forbidden_weight_suffixes = {".pt", ".pth", ".ckpt", ".safetensors", ".onnx"}
        forbidden_weights: list[str] = []
        for path in self.root.rglob("*"):
            if path.is_file() and (
                path.suffix.lower() in forbidden_weight_suffixes
                or path.name == "pytorch_model.bin"
            ):
                forbidden_weights.append(path.relative_to(self.root).as_posix())
        assert not forbidden_weights, forbidden_weights

        symlinks: list[dict[str, str]] = []
        special_entries: list[str] = []
        for path in self.root.rglob("*"):
            mode = path.lstat().st_mode
            if path.is_symlink():
                resolved = path.resolve(strict=True)
                resolved.relative_to(self.root)
                symlinks.append({
                    "path": path.relative_to(self.root).as_posix(),
                    "target": os.readlink(path),
                })
            elif not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
                special_entries.append(path.relative_to(self.root).as_posix())
        assert not special_entries, special_entries

        return {
            "schema": "kazstem-linux-blackbox-v1",
            "root": self.root.name,
            "tests": len(self.results),
            "results": self.results,
            "source_checksums": "verified by the paired-source gate",
            "symlinks": symlinks,
            "unsupported_special_entries": special_entries,
            "neural_weight_files": forbidden_weights,
        }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path)
    parser.add_argument("--identity", required=True, type=Path)
    parser.add_argument("--json", type=Path)
    args = parser.parse_args()
    identity = load_identity(args.identity.resolve(strict=True))
    root = args.root.resolve(strict=True)
    if root.name != identity["ready_run"]["top_level"]:
        raise ReleaseError("black-box root name differs from the release identity")
    if args.json:
        ensure_output_outside(args.json, root, label="black-box evidence output")
    if args.json and (args.json.exists() or args.json.is_symlink()):
        raise ReleaseError(f"black-box evidence output already exists: {args.json}")
    resource_manifest = read_json(
        root / identity["ready_run"]["resource_destination"] / "manifest.json"
    )
    if (
        not isinstance(resource_manifest, dict)
        or resource_manifest.get("bundle_id")
        != identity["inputs"]["resource_tree"]["bundle_id"]
        or not isinstance(resource_manifest.get("version"), str)
        or not resource_manifest["version"]
    ):
        raise ReleaseError("embedded resource manifest differs from release identity")
    summary = Gate(
        root,
        identity["release"],
        resource_manifest["version"],
    ).execute()
    summary["pass"] = True
    summary["release"] = identity["release"]
    summary["source_commit"] = identity["source_commit"]
    summary["source_tree"] = identity["source_tree"]
    value = json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if args.json:
        args.json.write_text(value, encoding="utf-8")
    else:
        print(value, end="")
    print(f"PASS: {summary['tests']} black-box commands", file=os.sys.stderr)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ReleaseError, OSError, ValueError, json.JSONDecodeError) as exc:
        raise SystemExit(f"error: {exc}") from exc
