#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import random
import re
import statistics
import stat
import subprocess
import sys
import tempfile
import time
from typing import Any
from xml.etree import ElementTree

from release_common import ReleaseError, ensure_output_outside, load_identity, verify_artifact


if not __debug__:
    raise RuntimeError("the Linux practical release gate must not run with -O")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, int((len(ordered) - 1) * fraction)))
    return ordered[index]


def jsonl_reconstruct(value: bytes) -> str:
    return "".join(
        str(row["text"])
        for row in (json.loads(line) for line in value.decode("utf-8").splitlines())
        if row.get("consumes_input") is True
    )


def jsonl_file_reconstruct(path: Path) -> str:
    pieces: list[str] = []
    with path.open(encoding="utf-8") as stream:
        for line in stream:
            row = json.loads(line)
            if row.get("consumes_input") is True:
                pieces.append(str(row["text"]))
    return "".join(pieces)


def fingerprint(root: Path) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for path in [root, *sorted(root.rglob("*"), key=lambda item: item.as_posix())]:
        relative = "." if path == root else path.relative_to(root).as_posix()
        metadata = path.lstat()
        record: dict[str, Any] = {
            "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
            "mtime_ns": metadata.st_mtime_ns,
        }
        if path.is_symlink():
            record.update({"kind": "symlink", "target": os.readlink(path)})
        elif path.is_dir():
            record["kind"] = "directory"
        elif path.is_file():
            record.update(
                {
                    "kind": "file",
                    "bytes": metadata.st_size,
                    "sha256": sha256_file(path),
                }
            )
        else:
            raise AssertionError(f"unsupported bundle entry: {path}")
        result[relative] = record
    return result


class Matrix:
    def __init__(
        self,
        root: Path,
        wheel: Path,
        *,
        expected_version: str,
        source_commit: str,
    ) -> None:
        self.root = root.resolve(strict=True)
        self.executable = self.root / "kazstem"
        self.wheel = wheel.resolve(strict=True)
        self.expected_version = expected_version
        self.source_commit = source_commit
        self.cases: list[dict[str, Any]] = []
        self.profiles: dict[str, Any] = {}
        # Keep the tooling virtualenv itself on an ASCII-safe path; hostile
        # Unicode/newline path handling is exercised independently below.
        self.temporary = tempfile.TemporaryDirectory(prefix="kazstem-matrix-")
        self.temp = Path(self.temporary.name)
        self.environment = {
            key: value
            for key, value in os.environ.items()
            if not key.startswith("QAZMORPH_")
            and not key.startswith("DYLD_")
            and not key.startswith("LD_")
            and not key.upper().endswith("_PROXY")
            and key not in {"CG3_DEFAULT", "CG3_OVERRIDE"}
        }
        self.environment.update(
            {
                "HOME": str(self.temp / "offline-home"),
                "http_proxy": "http://127.0.0.1:9",
                "https_proxy": "http://127.0.0.1:9",
                "HTTP_PROXY": "http://127.0.0.1:9",
                "HTTPS_PROXY": "http://127.0.0.1:9",
                "NO_PROXY": "",
                "LC_ALL": "C",
                "LANG": "C",
            }
        )
        (self.temp / "offline-home").mkdir()
        self.before = fingerprint(self.root)

    def close(self) -> None:
        self.temporary.cleanup()

    def run(
        self,
        name: str,
        arguments: list[str],
        *,
        input_bytes: bytes = b"",
        expected: int = 0,
        cwd: Path | None = None,
        environment: dict[str, str] | None = None,
        timeout: float = 90.0,
    ) -> subprocess.CompletedProcess[bytes]:
        started = time.perf_counter()
        completed = subprocess.run(
            arguments,
            input=input_bytes,
            cwd=cwd or self.temp,
            env=environment or self.environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
        )
        elapsed = time.perf_counter() - started
        if completed.returncode != expected:
            raise AssertionError(
                f"{name}: rc={completed.returncode}, expected={expected}, "
                f"stderr={completed.stderr.decode('utf-8', 'replace')!r}"
            )
        self.cases.append(
            {
                "name": name,
                "returncode": completed.returncode,
                "seconds": round(elapsed, 6),
                "stdin_bytes": len(input_bytes),
                "stdout_bytes": len(completed.stdout),
                "stdout_sha256": sha256_bytes(completed.stdout),
                "stderr_bytes": len(completed.stderr),
                "stderr_sha256": sha256_bytes(completed.stderr),
            }
        )
        return completed

    def binary(
        self,
        name: str,
        flags: list[str],
        *,
        text: str = "",
        expected: int = 0,
        timeout: float = 90.0,
    ) -> subprocess.CompletedProcess[bytes]:
        return self.run(
            name,
            [str(self.executable), *flags],
            input_bytes=text.encode("utf-8"),
            expected=expected,
            timeout=timeout,
        )

    def execute(self) -> dict[str, Any]:
        assert self.executable.is_file() and os.access(self.executable, os.X_OK)
        assert self.root.parent != self.root

        version = self.binary("version", ["--version"])
        assert version.stdout == f"kazstem {self.expected_version}\n".encode("ascii")
        help_result = self.binary("help", ["--help"])
        assert b"--format" in help_result.stdout and b"--fixlist" in help_result.stdout
        for alias in ("qazmorph", "mystem-kz"):
            path = self.root / alias
            assert path.is_symlink() and os.readlink(path) == "kazstem"
            alias_result = self.run(f"alias-{alias}", [str(path), "--version"])
            assert alias_result.stdout == version.stdout

        text = "Қазақстан & балалар мектепке барды.\n"
        text_result = self.binary("format-text", ["-c", "-i", "--format", "text"], text=text)
        assert "Қазақстан" in text_result.stdout.decode() and "=PROPN" in text_result.stdout.decode()

        json_result = self.binary("format-json", ["-c", "-i", "--format", "json"], text=text)
        assert json_result.stdout.startswith(b'[{"analysis":')
        json_rows = json.loads(json_result.stdout)
        assert "".join(row["text"] for row in json_rows) == text
        first = next(row for row in json_rows if "analysis" in row)
        assert list(first) == ["analysis", "text"]
        assert all(list(row)[:1] == ["lex"] for row in first["analysis"])

        jsonl_result = self.binary("format-jsonl", ["-c", "--format", "jsonl"], text=text)
        assert jsonl_reconstruct(jsonl_result.stdout) == text

        xml_result = self.binary("format-xml", ["-c", "-i", "--format", "xml"], text=text)
        xml_root = ElementTree.fromstring(xml_result.stdout)
        assert "".join(xml_root.itertext()) == text
        words = xml_root.findall("./body/se/w")
        assert words and words[0].text is None and list(words[0])[-1].tail == "Қазақстан"

        conllu_result = self.binary("format-conllu", ["--format", "conllu"], text=text)
        conllu_lines = [line for line in conllu_result.stdout.decode().splitlines() if line and not line.startswith("#")]
        assert conllu_lines and all(len(line.split("\t")) == 10 for line in conllu_lines)

        clustered = self.binary("clustered-cin", ["-cin", "--format", "text"], text="Сәлем !\n")
        assert b"\n" in clustered.stdout
        newline_json = self.binary("newline-json", ["-cn", "--format", "json"], text="Сәлем !")
        assert all(isinstance(json.loads(line), dict) for line in newline_json.stdout.decode().splitlines())
        merged = self.binary("merge-i-g", ["-i", "-g", "--format", "json"], text="foo")
        assert json.loads(merged.stdout)[0]["analysis"]
        lemmas = self.binary("lemmas-only", ["-l", "--format", "text"], text="балалар")
        assert b"{" not in lemmas.stdout and "бала" in lemmas.stdout.decode()
        sentence = self.binary("sentence-markers", ["-c", "-s", "--format", "text"], text="Сәлем. Бала.")
        assert br"{\s}" in sentence.stdout
        weighted = self.binary("weight-no-invented-scores", ["-c", "-i", "--weight", "--format", "json"], text="балалар")
        assert "wt" not in json.loads(weighted.stdout)[0]["analysis"][0]
        filtered = self.binary("filter-gram", ["-i", "--filter-gram", "NOUN", "--format", "json"], text="балалар")
        assert all("NOUN" in row.get("gr", "") for row in json.loads(filtered.stdout)[0]["analysis"])
        eng = self.binary("eng-gr-noop", ["-c", "-i", "--eng-gr", "--format", "jsonl"], text="балалар")
        plain_eng = self.binary("eng-gr-control", ["-c", "-i", "--format", "jsonl"], text="балалар")
        assert eng.stdout == plain_eng.stdout
        ktb = self.binary("ud-profile-ktb", ["-c", "--ud-profile", "ktb", "--format", "jsonl"], text="Қазақстан")
        assert all(row.get("ud_profile") == "ktb" for row in map(json.loads, ktb.stdout.decode().splitlines()))

        fixlist = self.temp / "fix list Қазақ ^$[].jsonl"
        fixlist.write_text('{"form":"Тест","lemma":"арнайы","tags":["n"]}\n', encoding="utf-8")
        fixed = self.binary("fixlist", ["--fixlist", str(fixlist), "--format", "json"], text="Тест")
        assert json.loads(fixed.stdout)[0]["analysis"][0]["lex"] == "арнайы"
        fixlist_tsv = self.temp / "fix list Қазақ.tsv"
        fixlist_tsv.write_text("Тест\tарнайы2\tn,sg,nom\n", encoding="utf-8")
        fixed_tsv = self.binary("fixlist-tsv", ["--fixlist", str(fixlist_tsv), "--format", "json"], text="Тест")
        assert json.loads(fixed_tsv.stdout)[0]["analysis"][0]["lex"] == "арнайы2"

        oov = self.binary("productive-oov", ["--format", "jsonl"], text="суперқазақшалар")
        assert any(
            analysis.get("source") == "guesser" and analysis.get("guessed") is True
            for row in map(json.loads, oov.stdout.decode().splitlines())
            for analysis in row.get("analysis", [])
        )
        generated_all = self.binary("generate-all", ["--generate-all", "--format", "jsonl"], text="суперқазақшалар")
        assert any(json.loads(line).get("analysis") for line in generated_all.stdout.decode().splitlines())
        no_guesser = self.binary("no-guesser", ["--no-guesser", "--format", "jsonl"], text="qazmorphzzzz")
        assert not any(
            analysis.get("source") == "guesser"
            for row in map(json.loads, no_guesser.stdout.decode().splitlines())
            for analysis in row.get("analysis", [])
        )
        dictionary_only = self.binary("dictionary-only", ["-c", "-w", "--format", "jsonl"], text="qazmorphzzzz !")
        assert "qazmorphzzzz" not in jsonl_reconstruct(dictionary_only.stdout)

        cg = self.binary("constraint-grammar", ["-d", "-c", "--format", "jsonl"], text="балалар мектепке барды.\n")
        assert {row.get("mode") for row in map(json.loads, cg.stdout.decode().splitlines()) if row.get("record_type") == "token"} == {"contextual"}

        runtime_candidates = list((self.root / ".qazmorph/platform-runtimes").iterdir())
        assert len(runtime_candidates) == 1
        runtime = runtime_candidates[0]
        generator = self.root / ".qazmorph/resources/kaz.autogen.hfstol"
        generation = self.run(
            "generation",
            [str(runtime / "usr/bin/hfst-optimized-lookup"), "-q", "-u", "-n", "128", str(generator)],
            input_bytes="кітап<n><pl><dat>\n".encode(),
        )
        generated_forms = [line.split("\t")[1] for line in generation.stdout.decode().splitlines() if "\t" in line]
        assert "кітаптарға" in generated_forms
        roundtrip = self.binary("generation-roundtrip", ["-c", "--format", "json"], text="кітаптарға")
        assert any(a["lex"] == "кітап" for a in json.loads(roundtrip.stdout)[0]["analysis"])

        line_text = "бір\rекі\nүш\r\nи\u0306 ^$[]{}\\/\x00соң"
        line_result = self.binary("line-endings-decomposed-reserved-nul", ["-c", "--format", "jsonl"], text=line_text)
        assert jsonl_reconstruct(line_result.stdout) == line_text
        xml_error = self.binary("xml-nul-controlled-error", ["-c", "--format", "xml"], text="a\x00b", expected=2)
        assert b"U+0000" in xml_error.stderr and b"Traceback" not in xml_error.stderr
        invalid_utf8 = self.run("invalid-utf8-controlled", [str(self.executable), "-e", "utf-8"], input_bytes=b"\xff", expected=2)
        assert b"Traceback" not in invalid_utf8.stderr
        for encoding in ("base64_codec", "not-a-real-codec"):
            failure = self.binary(f"invalid-encoding-{encoding}", ["-e", encoding], expected=2)
            assert b"unsupported text encoding" in failure.stderr and b"Traceback" not in failure.stderr
        cp1251_text = "тест\n"
        cp1251 = self.run(
            "cp1251",
            [str(self.executable), "-c", "-e", "cp1251", "--format", "text"],
            input_bytes=cp1251_text.encode("cp1251"),
        )
        cp1251.stdout.decode("cp1251")
        for encoding in ("utf-16", "utf-32", "koi8-r", "latin-1"):
            encoding_text = "тест\n" if encoding != "latin-1" else "test 123!\n"
            encoded = self.run(
                f"encoding-{encoding}",
                [str(self.executable), "-c", "-e", encoding, "--format", "text"],
                input_bytes=encoding_text.encode(encoding),
            )
            encoded.stdout.decode(encoding)
        for name, flags in (
            ("sentence-json-rejected", ["-c", "-s", "--format", "json"]),
            ("merge-without-i-rejected", ["-g"]),
            ("guess-limit-rejected", ["--guess-limit", "0"]),
            ("neural-missing-model-controlled", ["--neural"]),
        ):
            failure = self.binary(name, flags, expected=2)
            assert b"Traceback" not in failure.stderr

        hostile = self.temp / "hostile cwd Қазақ []^$\n"
        hostile.mkdir()
        hostile_bin = hostile / "fake bin"
        hostile_bin.mkdir()
        marker = hostile / "PATH-USED"
        for command in ("hfst-proc", "hfst-optimized-lookup", "cg-proc"):
            fake = hostile_bin / command
            fake.write_text(f"#!/bin/sh\nprintf used > {str(marker)!r}\nexit 97\n", encoding="utf-8")
            fake.chmod(0o755)
        positional_input = hostile / "кіріс ^$[]{} space\n.txt"
        positional_output = hostile / "шығыс Қазақ space\n.json"
        positional_text = "Қазақстан ^$[]{} мектеп\r\n"
        positional_input.write_text(positional_text, encoding="utf-8", newline="")
        hostile_env = dict(self.environment)
        hostile_env["PATH"] = str(hostile_bin)
        self.run(
            "positional-hostile-offline",
            [str(self.executable), "-c", "--format", "json", str(positional_input), str(positional_output)],
            cwd=hostile,
            environment=hostile_env,
        )
        assert "".join(row["text"] for row in json.loads(positional_output.read_bytes())) == positional_text
        assert not marker.exists()

        rng = random.Random(20260810)
        letters = "абвгғдеёжзийкқлмнңоөпрстуұүфхһцчшщъыіьэюяӘҒҚҢӨҰҮҺІABCxyz0123456789"
        punctuation = "[]{}^$/\\<>@#*+_-.,!?;:'\"()%&=|~`"
        pieces: list[str] = []
        while sum(map(len, pieces)) < 30000:
            choice = rng.randrange(6)
            if choice < 3:
                pieces.append("".join(rng.choice(letters) for _ in range(rng.randint(1, 16))))
            elif choice == 3:
                pieces.append(rng.choice((" ", "  ", "\t", "\n", "\r\n")))
            elif choice == 4:
                pieces.append(rng.choice(("и\u0306", "е\u0308", "ә\u0301", "C++")))
            else:
                pieces.append("".join(rng.choice(punctuation) for _ in range(rng.randint(1, 8))))
        randomized = "".join(pieces)
        random_result = self.binary("randomized-reconstruction-30k", ["-c", "--format", "jsonl"], text=randomized, timeout=180)
        assert jsonl_reconstruct(random_result.stdout) == randomized

        startup_times: list[float] = []
        for index in range(15):
            result = self.binary(f"startup-version-{index:02d}", ["--version"])
            startup_times.append(float(self.cases[-1]["seconds"]))
            assert result.stdout == version.stdout
        for index in range(10):
            repeated = self.binary(f"repeated-analysis-{index:02d}", ["-c", "--format", "jsonl"], text="балалар мектепке барды.\n")
            assert jsonl_reconstruct(repeated.stdout) == "балалар мектепке барды.\n"
        self.profiles["startup_version_seconds"] = {
            "runs": len(startup_times),
            "median": round(statistics.median(startup_times), 6),
            "p95_sample": round(percentile(startup_times, 0.95), 6),
            "minimum": round(min(startup_times), 6),
            "maximum": round(max(startup_times), 6),
        }

        workload_phrase = "Қазақстандағы балалар мектепке барып, кітаптарды оқыды.\n"
        repeats = 220000 // len(workload_phrase) + 1
        workload = (workload_phrase * repeats)[: max(220000, len(workload_phrase) * repeats)]
        workload_input = self.temp / "realistic-220k-input.txt"
        workload_input.write_text(workload, encoding="utf-8", newline="")
        workload_runs: list[dict[str, Any]] = []
        for index in range(2):
            output = self.temp / f"realistic-220k-output-{index}.jsonl"
            timed = self.run(
                f"realistic-220k-run-{index}",
                ["/usr/bin/time", "-v", str(self.executable), "-c", "--format", "jsonl", str(workload_input), str(output)],
                timeout=300,
            )
            assert jsonl_file_reconstruct(output) == workload
            stderr = timed.stderr.decode("utf-8", "replace")
            rss_match = re.search(r"Maximum resident set size \(kbytes\):\s*(\d+)", stderr)
            seconds = float(self.cases[-1]["seconds"])
            workload_runs.append(
                {
                    "run": index,
                    "input_characters": len(workload),
                    "input_utf8_bytes": len(workload.encode()),
                    "output_bytes": output.stat().st_size,
                    "output_sha256": sha256_file(output),
                    "seconds": round(seconds, 6),
                    "input_characters_per_second": round(len(workload) / seconds, 3),
                    "maximum_resident_set_size_bytes": int(rss_match.group(1)) * 1024 if rss_match else None,
                }
            )
        assert workload_runs[0]["output_sha256"] == workload_runs[1]["output_sha256"]
        self.profiles["realistic_workload"] = workload_runs

        wheel_site = self.temp / "wheel-site"
        bootstrap_python = Path(sys.executable).resolve(strict=True)
        pip_site = Path(__import__("pip").__file__).resolve().parents[1]
        install_environment = dict(self.environment)
        install_environment["PYTHONPATH"] = str(pip_site)
        self.run(
            "wheel-install",
            [str(bootstrap_python), "-m", "pip", "install", "--no-index", "--no-deps", "--target", str(wheel_site), str(self.wheel)],
            environment=install_environment,
            timeout=120,
        )
        # A single canonical wheel must already carry the exact unified native
        # runtime lock embedded in every frozen bundle. Release-only overlays
        # would make the wheel/sdist provenance claim false, so compare bytes
        # and fail rather than mutating the isolated installation.
        wheel_lock = wheel_site / "qazmorph/platform_runtime_assets.lock.json"
        frozen_lock = self.root / "_internal/qazmorph/platform_runtime_assets.lock.json"
        assert wheel_lock.read_bytes() == frozen_lock.read_bytes()
        python = bootstrap_python
        wheel_env = dict(self.environment)
        wheel_env["QAZMORPH_RESOURCE_DIR"] = str(self.root / ".qazmorph/resources")
        wheel_env["PYTHONNOUSERSITE"] = "1"
        wheel_env["PYTHONPATH"] = str(wheel_site)
        comparison_text = "Қазақстан & балалар мектепке барды.\r\n"
        binary_comparison = self.binary("comparison-frozen", ["-c", "--format", "jsonl"], text=comparison_text)
        wheel_comparison = self.run(
            "comparison-wheel-cli",
            [str(wheel_site / "bin/kazstem"), "-c", "--format", "jsonl"],
            input_bytes=comparison_text.encode(),
            environment=wheel_env,
        )
        module_comparison = self.run(
            "comparison-python-module",
            [str(python), "-m", "qazmorph", "-c", "--format", "jsonl"],
            input_bytes=comparison_text.encode(),
            environment=wheel_env,
        )
        api_code = (
            "from qazmorph import Analyzer\n"
            "from qazmorph.formats import format_jsonl\n"
            f"text={comparison_text!r}\n"
            f"with Analyzer(resource_dir={str(self.root / '.qazmorph/resources')!r}) as a:\n"
            " print(format_jsonl(a.analyze(text), copy_input=True), end='')\n"
        )
        api_comparison = self.run(
            "comparison-wheel-api",
            [str(python), "-c", api_code],
            environment=wheel_env,
        )
        assert binary_comparison.stdout == wheel_comparison.stdout == module_comparison.stdout == api_comparison.stdout

        build_identity = json.loads(
            (self.root / "verification/BUILD-IDENTITY.json").read_text()
        )
        assert build_identity["source_commit"] == self.source_commit
        ledger = json.loads((self.root / "verification/MODULE-NATIVE-INCLUSION-LEDGER.json").read_text())
        assert not any(
            token in path.name.lower()
            for path in self.root.rglob("*")
            for token in ("libssl", "libcrypto", "_ssl.", "_hashlib.")
        )
        assert ledger["banned_runtime_matches"] == []
        assert {"ssl", "_ssl", "socket", "urllib.request", "email", "asyncio", "multiprocessing", "sqlite3", "tkinter", "xml", "_hashlib"} <= set(
            ledger["analysis"]["declared_exclusions"]
        )
        assert ledger["hashlib_sha256_provider"].startswith("CPython built-in _sha2")

        processes = subprocess.run(
            ["ps", "-axo", "pid=,command="],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
        ).stdout.splitlines()
        lingering = [
            line
            for line in processes
            if str(self.root) in line and any(name in line for name in ("hfst-proc", "hfst-optimized-lookup", "cg-proc"))
        ]
        assert not lingering, lingering

        after = fingerprint(self.root)
        assert self.before == after
        resource_root = self.root / ".qazmorph/resources"
        runtime_root = runtime
        for sealed in (resource_root, runtime_root):
            assert not any(
                not path.is_symlink() and path.lstat().st_mode & 0o222
                for path in [sealed, *sealed.rglob("*")]
            )

        return {
            "schema": "kazstem-linux-practical-matrix-v1",
            "root": self.root.name,
            "source_commit": self.source_commit,
            "host": {
                "platform": platform.platform(),
                "machine": platform.machine(),
                "python": platform.python_version(),
            },
            "cases": len(self.cases),
            "results": self.cases,
            "profiles": self.profiles,
            "coverage": {
                "formats": ["text", "json", "jsonl", "xml", "conllu"],
                "flags": ["-c", "-n", "-i", "-g", "-w", "-l", "-s", "-d", "--weight", "--filter-gram", "--fixlist", "--generate-all", "--no-guesser", "--ud-profile", "--eng-gr"],
                "io": ["stdin", "positional input/output", "hostile Unicode/newline paths"],
                "unicode": ["LF", "CR", "CRLF", "decomposed Unicode", "reserved syntax", "NUL"],
                "engines": ["dictionary", "productive OOV", "Constraint Grammar", "generation", "generation round-trip"],
                "parity": ["frozen CLI", "two aliases", "wheel CLI", "python -m qazmorph", "wheel API"],
            },
            "bundle_fingerprint_unchanged": True,
            "read_only_resource_runtime_unchanged": True,
            "lingering_native_processes": [],
            "network_tls_modules_absent": True,
            "neural_weights": [],
            "optimization_review": {
                "additional_pruning_accepted": [],
                "decision": "No additional removal is behavior-preserving after the full matrix.",
                "retained": {
                    "zlib_extension": "PyInstaller bootstrap hard requirement; CPython zlib is built in and resolves Ubuntu host zlib1g.",
                    "multibyte_codecs": "Required by the advertised arbitrary text-encoding option.",
                    "hash_extensions": "hashlib guaranteed constructors initialize them; _sha2 supplies SHA-256 while _hashlib/OpenSSL stay absent.",
                    "icu": "Exact Ubuntu 24.04 host libicu74 boundary; arbitrary Unicode is retained without bundling a second copy.",
                    "sqlite_native_library": "Exact Ubuntu 24.04 host dependency of cg-proc/libcg3, not Python sqlite3.",
                },
            },
            "result": "pass",
        }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path)
    parser.add_argument("--identity", required=True, type=Path)
    parser.add_argument("--wheel", required=True, type=Path)
    parser.add_argument("--json", required=True, type=Path)
    args = parser.parse_args()
    identity = load_identity(args.identity.resolve(strict=True))
    root = args.root.resolve(strict=True)
    if root.name != identity["ready_run"]["top_level"]:
        raise ReleaseError("practical-matrix root name differs from release identity")
    ensure_output_outside(args.json, root, label="practical evidence output")
    if args.json.exists() or args.json.is_symlink():
        raise ReleaseError(f"practical evidence output already exists: {args.json}")
    verify_artifact(
        args.wheel.resolve(strict=True),
        identity["artifacts"]["wheel"],
        label="practical-matrix wheel",
    )
    matrix = Matrix(
        root,
        args.wheel,
        expected_version=identity["release"],
        source_commit=identity["source_commit"],
    )
    try:
        result = matrix.execute()
    finally:
        matrix.close()
    result["release"] = identity["release"]
    args.json.write_text(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
    print(f"PASS: {result['cases']} practical/performance cases")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ReleaseError, OSError, ValueError, json.JSONDecodeError) as exc:
        raise SystemExit(f"error: {exc}") from exc
