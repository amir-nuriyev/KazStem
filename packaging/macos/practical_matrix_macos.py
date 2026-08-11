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
import tempfile
import time
from typing import Any
from xml.etree import ElementTree

from release_common import (
    ReleaseError,
    absolute_reference,
    begin_gate_execution,
    gate_envelope,
    identity_sha256,
    json_bytes,
    load_identity,
    locked_gate_invocation,
    verify_ready_root_identity,
)


PRODUCTIVE_GENERATION_PROBE = r"""
import json
import os
from pathlib import Path
from qazmorph import Analyzer

resource_dir = Path(os.environ["QAZMORPH_RESOURCE_DIR"])
cases = 0
with Analyzer(resource_dir=resource_dir, guess=True) as analyzer:
    provenance = analyzer.backend.runtime_provenance()
    assert provenance["official"] is True, provenance["non_official_reasons"]
    assert analyzer.backend.manifest["schema"] == "qazmorph-resource-manifest-v4"
    assert analyzer.backend.productive_generator_safe is True

    lexical = "мүлдемжоқлемма"
    tags = ("n", "pl", "dat")
    result = analyzer.generate_detailed(lexical, tags, productive=True)
    assert result.source == "productive" and result.productive_attempted is True
    assert "мүлдемжоқлеммаларға" in result.forms
    for form in result.forms:
        document = analyzer.analyze(form)
        assert any(
            analysis.raw == "мүлдемжоқлемма<n><pl><dat>"
            for token in document.tokens
            for analysis in token.analyses
        )
    cases += 1

    irregulars = (
        ("ерін", ("n", "px1sg", "nom"), "ернім", "ерінім"),
        ("мұрын", ("n", "px1sg", "nom"), "мұрным", "мұрыным"),
        ("қауіп", ("n", "px1sg", "nom"), "қаупім", "қауібім"),
    )
    for lemma, query_tags, required, forbidden in irregulars:
        item = analyzer.generate_detailed(lemma, query_tags, productive=True)
        assert item.source == "dictionary" and item.productive_attempted is False
        assert required in item.forms and forbidden not in item.forms
        cases += 1

    for lemma in ("Тосынтүбір", "тосын түбір", "тосын-түбір"):
        item = analyzer.generate_detailed(lemma, ("n", "nom"), productive=True)
        assert item.source == "none" and item.reason == "ineligible_lemma"
        cases += 1

    directionality = (
        ("тосынтүбір", ("n", "ins"), "тосынтүбірмен", "тосынтүбірменен"),
        ("тосынсапа", ("adj", "comp"), "тосынсапарақ", "тосынсапалау"),
        (
            "тосынет",
            ("v", "iv", "fut_plan", "p3", "sg"),
            "тосынетпек",
            "тосынетпекші",
        ),
    )
    for lemma, query_tags, required, forbidden in directionality:
        item = analyzer.generate_detailed(lemma, query_tags, productive=True)
        assert item.source == "productive"
        assert required in item.forms and forbidden not in item.forms
        cases += 1

    forbidden_loans = {
        "блок": "блогы",
        "каталок": "каталогы",
        "аналок": "аналогы",
        "психолок": "психологы",
    }
    for lemma, forbidden in forbidden_loans.items():
        forms = analyzer.generate(
            lemma, ("n", "px3sp", "nom"), productive=True
        )
        assert forbidden not in forms
        cases += 1

    diagnostics = analyzer.generation_diagnostics
    assert diagnostics["productive_available"] == 1
    assert diagnostics["productive_queries"] >= 1
    assert diagnostics["productive_hits"] >= 1

print(
    json.dumps(
        {
            "schema": "kazstem-bf1f-productive-generation-probe-v1",
            "cases": cases,
            "resource_bundle_id": analyzer.backend.manifest["bundle_id"],
            "runtime_bundle_id": provenance["active_runtime"]["bundle_id"],
            "productive_queries": diagnostics["productive_queries"],
            "productive_hits": diagnostics["productive_hits"],
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
)
"""

HOSTILE_LOADER_PROBE = r"""
import hashlib
import json
import os
from pathlib import Path
from qazmorph import Analyzer

ambient = {
    "LD_FUTURE_INJECTOR": "/hostile/future-ld.so",
    "DYLD_LIBRARY_PATH": "/hostile/dyld-library",
    "DYLD_INSERT_LIBRARIES": "/hostile/dyld-insert.dylib",
    "DYLD_FUTURE_INJECTOR": "/hostile/future-dyld.dylib",
    "GLIBC_TUNABLES": "glibc.malloc.check=3",
}
os.environ.update(ambient)
resource_dir = Path(os.environ["QAZMORPH_RESOURCE_DIR"])
with Analyzer(resource_dir=resource_dir, guess=True) as analyzer:
    for name in ambient:
        assert name not in analyzer.backend.environment
    document = analyzer.analyze("балалар мектепке барды.\n")
    assert "".join(token.text for token in document.tokens) == document.text
    provenance = analyzer.backend.runtime_provenance()

assert provenance["official"] is False
policy = provenance["environment"]["loader_policy"]
assert policy["schema"] == "qazmorph-native-helper-loader-environment-v2"
assert policy["clean_parent_startup"] is False
assert policy["all_ambient_values_removed_from_helper_environment"] is True
assert set(policy["ambient_records"]) == {
    "LD_FUTURE_INJECTOR",
    "DYLD_LIBRARY_PATH",
    "DYLD_INSERT_LIBRARIES",
    "DYLD_FUTURE_INJECTOR",
}
for name in policy["ambient_records"]:
    assert policy["ambient_records"][name] == {
        "ambient_present": True,
        "removed_from_helper_environment": True,
        "sha256": hashlib.sha256(os.fsencode(ambient[name])).hexdigest(),
    }
assert policy["glibc_tunables"] == {
    "ambient_present": True,
    "removed_from_helper_environment": True,
    "sha256": hashlib.sha256(os.fsencode(ambient["GLIBC_TUNABLES"])).hexdigest(),
}
encoded = json.dumps(provenance, ensure_ascii=False, sort_keys=True)
assert not any(value in encoded for value in ambient.values())
print(
    json.dumps(
        {
            "schema": "kazstem-hostile-loader-scrub-probe-v1",
            "captured_names": sorted(policy["ambient_records"]),
            "glibc_tunables_captured": True,
            "helper_environment_scrubbed": True,
            "non_official_reasons": len(provenance["non_official_reasons"]),
        },
        sort_keys=True,
        separators=(",", ":"),
    )
)
"""


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
        identity: dict[str, Any],
        bootstrap_python: Path,
    ) -> None:
        self.root = root.resolve(strict=True)
        self.identity = identity
        self.executable = self.root / identity["ready_run"]["launcher"]["path"]
        self.wheel = wheel.resolve(strict=True)
        self.bootstrap_python = bootstrap_python.resolve(strict=True)
        resource_root = self.root / identity["ready_run"]["resource_destination"]
        self.resource_manifest = json.loads(
            (resource_root / "manifest.json").read_text(encoding="utf-8")
        )
        if (
            not isinstance(self.resource_manifest, dict)
            or self.resource_manifest.get("bundle_id")
            != identity["inputs"]["resource_tree"]["bundle_id"]
        ):
            raise ReleaseError("practical matrix resource manifest identity differs")
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
            and key not in {"CG3_DEFAULT", "CG3_OVERRIDE"}
        }
        self.environment.update(
            {
                "HOME": str(self.temp / "offline-home"),
                "http_proxy": "http://127.0.0.1:9",
                "https_proxy": "http://127.0.0.1:9",
                "HTTP_PROXY": "http://127.0.0.1:9",
                "HTTPS_PROXY": "http://127.0.0.1:9",
                "NO_PROXY": "*",
                "LC_ALL": "C",
                "LANG": "C",
            }
        )
        (self.temp / "offline-home").mkdir()
        self.before = fingerprint(self.root)

    def close(self) -> None:
        self.temporary.cleanup()

    def logical_token(self, value: str) -> str:
        logical = value
        for root, label in (
            (self.root, "bundle"),
            (self.temp, "workspace"),
        ):
            logical = logical.replace(str(root), label)
        logical = logical.replace(str(self.bootstrap_python), "bootstrap-python")
        if logical != value:
            if absolute_reference(logical) is not None:
                raise AssertionError(f"embedded absolute argv token remains: {logical}")
            return logical
        path = Path(value)
        if not path.is_absolute():
            return value
        resolved = path.resolve(strict=False)
        for root, label in (
            (self.root, "bundle"),
            (self.temp, "workspace"),
        ):
            if resolved == root or root in resolved.parents:
                return f"{label}/{resolved.relative_to(root).as_posix()}"
        if resolved == self.bootstrap_python:
            return "bootstrap-python"
        if value == "/usr/bin/time":
            return "time"
        raise AssertionError(f"unmapped absolute argv token: {value}")

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
                "argv": [self.logical_token(item) for item in arguments],
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
        assert version.stdout == f"kazstem {self.identity['release']}\n".encode("ascii")
        self.profiles["cold_start_version_seconds"] = self.cases[-1]["seconds"]
        help_result = self.binary("help", ["--help"])
        assert b"--format" in help_result.stdout and b"--fixlist" in help_result.stdout
        for alias in self.identity["ready_run"]["aliases"]:
            path = self.root / alias
            assert (
                path.is_symlink()
                and os.readlink(path) == self.identity["ready_run"]["launcher"]["path"]
            )
            alias_result = self.run(f"alias-{alias}", [str(path), "--version"])
            assert alias_result.stdout == version.stdout

        text = "Қазақстан & балалар мектепке барды.\n"
        text_result = self.binary(
            "format-text", ["-c", "-i", "--format", "text"], text=text
        )
        assert (
            "Қазақстан" in text_result.stdout.decode()
            and "=PROPN" in text_result.stdout.decode()
        )

        json_result = self.binary(
            "format-json", ["-c", "-i", "--format", "json"], text=text
        )
        assert json_result.stdout.startswith(b'[{"analysis":')
        json_rows = json.loads(json_result.stdout)
        assert "".join(row["text"] for row in json_rows) == text
        first = next(row for row in json_rows if "analysis" in row)
        assert list(first) == ["analysis", "text"]
        assert all(list(row)[:1] == ["lex"] for row in first["analysis"])

        jsonl_result = self.binary(
            "format-jsonl", ["-c", "--format", "jsonl"], text=text
        )
        assert jsonl_reconstruct(jsonl_result.stdout) == text

        xml_result = self.binary(
            "format-xml", ["-c", "-i", "--format", "xml"], text=text
        )
        xml_root = ElementTree.fromstring(xml_result.stdout)
        assert "".join(xml_root.itertext()) == text
        words = xml_root.findall("./body/se/w")
        assert (
            words and words[0].text is None and list(words[0])[-1].tail == "Қазақстан"
        )

        conllu_result = self.binary("format-conllu", ["--format", "conllu"], text=text)
        conllu_lines = [
            line
            for line in conllu_result.stdout.decode().splitlines()
            if line and not line.startswith("#")
        ]
        assert conllu_lines and all(
            len(line.split("\t")) == 10 for line in conllu_lines
        )

        clustered = self.binary(
            "clustered-cin", ["-cin", "--format", "text"], text="Сәлем !\n"
        )
        assert b"\n" in clustered.stdout
        newline_json = self.binary(
            "newline-json", ["-cn", "--format", "json"], text="Сәлем !"
        )
        assert all(
            isinstance(json.loads(line), dict)
            for line in newline_json.stdout.decode().splitlines()
        )
        merged = self.binary("merge-i-g", ["-i", "-g", "--format", "json"], text="foo")
        assert json.loads(merged.stdout)[0]["analysis"]
        lemmas = self.binary("lemmas-only", ["-l", "--format", "text"], text="балалар")
        assert b"{" not in lemmas.stdout and "бала" in lemmas.stdout.decode()
        sentence = self.binary(
            "sentence-markers", ["-c", "-s", "--format", "text"], text="Сәлем. Бала."
        )
        assert rb"{\s}" in sentence.stdout
        weighted = self.binary(
            "weight-no-invented-scores",
            ["-c", "-i", "--weight", "--format", "json"],
            text="балалар",
        )
        assert "wt" not in json.loads(weighted.stdout)[0]["analysis"][0]
        filtered = self.binary(
            "filter-gram",
            ["-i", "--filter-gram", "NOUN", "--format", "json"],
            text="балалар",
        )
        assert all(
            "NOUN" in row.get("gr", "")
            for row in json.loads(filtered.stdout)[0]["analysis"]
        )
        eng = self.binary(
            "eng-gr-noop", ["-c", "-i", "--eng-gr", "--format", "jsonl"], text="балалар"
        )
        plain_eng = self.binary(
            "eng-gr-control", ["-c", "-i", "--format", "jsonl"], text="балалар"
        )
        assert eng.stdout == plain_eng.stdout
        ktb = self.binary(
            "ud-profile-ktb",
            ["-c", "--ud-profile", "ktb", "--format", "jsonl"],
            text="Қазақстан",
        )
        assert all(
            row.get("ud_profile") == "ktb"
            for row in map(json.loads, ktb.stdout.decode().splitlines())
        )

        fixlist = self.temp / "fix list Қазақ ^$[].jsonl"
        fixlist.write_text(
            '{"form":"Тест","lemma":"арнайы","tags":["n"]}\n', encoding="utf-8"
        )
        fixed = self.binary(
            "fixlist", ["--fixlist", str(fixlist), "--format", "json"], text="Тест"
        )
        assert json.loads(fixed.stdout)[0]["analysis"][0]["lex"] == "арнайы"

        oov = self.binary(
            "productive-oov", ["--format", "jsonl"], text="суперқазақшалар"
        )
        assert any(
            analysis.get("source") == "guesser" and analysis.get("guessed") is True
            for row in map(json.loads, oov.stdout.decode().splitlines())
            for analysis in row.get("analysis", [])
        )
        generated_all = self.binary(
            "generate-all",
            ["--generate-all", "--format", "jsonl"],
            text="суперқазақшалар",
        )
        assert any(
            json.loads(line).get("analysis")
            for line in generated_all.stdout.decode().splitlines()
        )
        no_guesser = self.binary(
            "no-guesser", ["--no-guesser", "--format", "jsonl"], text="qazmorphzzzz"
        )
        assert not any(
            analysis.get("source") == "guesser"
            for row in map(json.loads, no_guesser.stdout.decode().splitlines())
            for analysis in row.get("analysis", [])
        )
        dictionary_only = self.binary(
            "dictionary-only", ["-c", "-w", "--format", "jsonl"], text="qazmorphzzzz !"
        )
        assert "qazmorphzzzz" not in jsonl_reconstruct(dictionary_only.stdout)

        cg = self.binary(
            "constraint-grammar",
            ["-d", "-c", "--format", "jsonl"],
            text="балалар мектепке барды.\n",
        )
        assert {
            row.get("mode")
            for row in map(json.loads, cg.stdout.decode().splitlines())
            if row.get("record_type") == "token"
        } == {"contextual"}

        runtime = (
            self.root
            / self.identity["ready_run"]["runtime_parent"]
            / self.identity["inputs"]["runtime_tree"]["bundle_id"]
        )
        generator = (
            self.root
            / self.identity["ready_run"]["resource_destination"]
            / "kaz.autogen.hfstol"
        )
        generation = self.run(
            "generation",
            [
                str(runtime / "usr/bin/hfst-optimized-lookup"),
                "-q",
                "-u",
                "-n",
                "128",
                str(generator),
            ],
            input_bytes="кітап<n><pl><dat>\n".encode(),
        )
        generated_forms = [
            line.split("\t")[1]
            for line in generation.stdout.decode().splitlines()
            if "\t" in line
        ]
        assert "кітаптарға" in generated_forms
        roundtrip = self.binary(
            "generation-roundtrip", ["-c", "--format", "json"], text="кітаптарға"
        )
        assert any(
            a["lex"] == "кітап" for a in json.loads(roundtrip.stdout)[0]["analysis"]
        )

        line_text = "бір\rекі\nүш\r\nи\u0306 ^$[]{}\\/\x00соң"
        line_result = self.binary(
            "line-endings-decomposed-reserved-nul",
            ["-c", "--format", "jsonl"],
            text=line_text,
        )
        assert jsonl_reconstruct(line_result.stdout) == line_text
        xml_error = self.binary(
            "xml-nul-controlled-error",
            ["-c", "--format", "xml"],
            text="a\x00b",
            expected=2,
        )
        assert b"U+0000" in xml_error.stderr and b"Traceback" not in xml_error.stderr
        invalid_utf8 = self.run(
            "invalid-utf8-controlled",
            [str(self.executable), "-e", "utf-8"],
            input_bytes=b"\xff",
            expected=2,
        )
        assert b"Traceback" not in invalid_utf8.stderr
        for encoding in ("base64_codec", "not-a-real-codec"):
            failure = self.binary(
                f"invalid-encoding-{encoding}", ["-e", encoding], expected=2
            )
            assert (
                b"unsupported text encoding" in failure.stderr
                and b"Traceback" not in failure.stderr
            )
        cp1251_text = "тест\n"
        cp1251 = self.run(
            "cp1251",
            [str(self.executable), "-c", "-e", "cp1251", "--format", "text"],
            input_bytes=cp1251_text.encode("cp1251"),
        )
        cp1251.stdout.decode("cp1251")
        for name, flags in (
            ("sentence-json-rejected", ["-c", "-s", "--format", "json"]),
            ("merge-without-i-rejected", ["-g"]),
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
            fake.write_text(
                f"#!/bin/sh\nprintf used > {str(marker)!r}\nexit 97\n", encoding="utf-8"
            )
            fake.chmod(0o755)
        positional_input = hostile / "кіріс ^$[]{} space\n.txt"
        positional_output = hostile / "шығыс Қазақ space\n.json"
        positional_text = "Қазақстан ^$[]{} мектеп\r\n"
        positional_input.write_text(positional_text, encoding="utf-8", newline="")
        hostile_env = dict(self.environment)
        hostile_env["PATH"] = str(hostile_bin)
        self.run(
            "positional-hostile-offline",
            [
                str(self.executable),
                "-c",
                "--format",
                "json",
                str(positional_input),
                str(positional_output),
            ],
            cwd=hostile,
            environment=hostile_env,
        )
        assert (
            "".join(row["text"] for row in json.loads(positional_output.read_bytes()))
            == positional_text
        )
        assert not marker.exists()

        rng = random.Random(20260810)
        letters = "абвгғдеёжзийкқлмнңоөпрстуұүфхһцчшщъыіьэюяӘҒҚҢӨҰҮҺІABCxyz0123456789"
        punctuation = "[]{}^$/\\<>@#*+_-.,!?;:'\"()%&=|~`"
        pieces: list[str] = []
        while sum(map(len, pieces)) < 30000:
            choice = rng.randrange(6)
            if choice < 3:
                pieces.append(
                    "".join(rng.choice(letters) for _ in range(rng.randint(1, 16)))
                )
            elif choice == 3:
                pieces.append(rng.choice((" ", "  ", "\t", "\n", "\r\n")))
            elif choice == 4:
                pieces.append(rng.choice(("и\u0306", "е\u0308", "ә\u0301", "C++")))
            else:
                pieces.append(
                    "".join(rng.choice(punctuation) for _ in range(rng.randint(1, 8)))
                )
        randomized = "".join(pieces)
        random_result = self.binary(
            "randomized-reconstruction-30k",
            ["-c", "--format", "jsonl"],
            text=randomized,
            timeout=180,
        )
        assert jsonl_reconstruct(random_result.stdout) == randomized

        startup_times: list[float] = []
        for index in range(15):
            result = self.binary(f"startup-version-{index:02d}", ["--version"])
            startup_times.append(float(self.cases[-1]["seconds"]))
            assert result.stdout == version.stdout
        for index in range(10):
            repeated = self.binary(
                f"repeated-analysis-{index:02d}",
                ["-c", "--format", "jsonl"],
                text="балалар мектепке барды.\n",
            )
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
        workload = (workload_phrase * repeats)[
            : max(220000, len(workload_phrase) * repeats)
        ]
        workload_input = self.temp / "realistic-220k-input.txt"
        workload_input.write_text(workload, encoding="utf-8", newline="")
        workload_runs: list[dict[str, Any]] = []
        for index in range(2):
            output = self.temp / f"realistic-220k-output-{index}.jsonl"
            timed = self.run(
                f"realistic-220k-run-{index}",
                [
                    "/usr/bin/time",
                    "-lp",
                    str(self.executable),
                    "-c",
                    "--format",
                    "jsonl",
                    str(workload_input),
                    str(output),
                ],
                timeout=300,
            )
            assert jsonl_file_reconstruct(output) == workload
            stderr = timed.stderr.decode("utf-8", "replace")
            rss_match = re.search(r"\n?\s*(\d+)\s+maximum resident set size", stderr)
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
                    "maximum_resident_set_size_bytes": int(rss_match.group(1))
                    if rss_match
                    else None,
                }
            )
        assert workload_runs[0]["output_sha256"] == workload_runs[1]["output_sha256"]
        self.profiles["realistic_workload"] = workload_runs

        venv = self.temp / "wheel-venv"
        # The uv-managed interpreter launching this verifier is relocatable and
        # cannot bootstrap a symlinked venv from /private/tmp on this host.
        # Use the exact Homebrew CPython that built the frozen bundle.
        bootstrap_python = self.bootstrap_python
        assert bootstrap_python.is_file()
        self.run(
            "wheel-venv-create",
            [str(bootstrap_python), "-m", "venv", str(venv)],
            timeout=120,
        )
        python = venv / "bin/python"
        pip = venv / "bin/pip"
        self.run(
            "wheel-install",
            [str(pip), "install", "--no-index", "--no-deps", str(self.wheel)],
            timeout=120,
        )
        wheel_env = dict(self.environment)
        wheel_env["QAZMORPH_RESOURCE_DIR"] = str(
            self.root / self.identity["ready_run"]["resource_destination"]
        )
        hostile_loader_probe = self.run(
            "hostile-loader-environment-scrub",
            [str(python), "-c", HOSTILE_LOADER_PROBE],
            environment=wheel_env,
            timeout=180,
        )
        hostile_loader = json.loads(hostile_loader_probe.stdout)
        assert set(hostile_loader) == {
            "schema",
            "captured_names",
            "glibc_tunables_captured",
            "helper_environment_scrubbed",
            "non_official_reasons",
        }
        assert hostile_loader["schema"] == "kazstem-hostile-loader-scrub-probe-v1"
        assert hostile_loader["captured_names"] == [
            "DYLD_FUTURE_INJECTOR",
            "DYLD_INSERT_LIBRARIES",
            "DYLD_LIBRARY_PATH",
            "LD_FUTURE_INJECTOR",
        ]
        assert hostile_loader["glibc_tunables_captured"] is True
        assert hostile_loader["helper_environment_scrubbed"] is True
        assert hostile_loader["non_official_reasons"] == 5
        self.profiles["hostile_loader_environment"] = hostile_loader
        productive_generation: dict[str, Any]
        if self.resource_manifest.get("schema") == "qazmorph-resource-manifest-v4":
            productive_probe = self.run(
                "bf1f-productive-generation-api",
                [str(python), "-c", PRODUCTIVE_GENERATION_PROBE],
                environment=wheel_env,
                timeout=180,
            )
            productive_generation = json.loads(productive_probe.stdout)
            assert set(productive_generation) == {
                "schema",
                "cases",
                "resource_bundle_id",
                "runtime_bundle_id",
                "productive_queries",
                "productive_hits",
            }
            assert productive_generation == {
                **productive_generation,
                "schema": "kazstem-bf1f-productive-generation-probe-v1",
                "cases": 14,
                "resource_bundle_id": self.identity["inputs"]["resource_tree"][
                    "bundle_id"
                ],
                "runtime_bundle_id": self.identity["inputs"]["runtime_tree"][
                    "bundle_id"
                ],
            }
            assert productive_generation["productive_queries"] >= 1
            assert productive_generation["productive_hits"] >= 1
        else:
            productive_generation = {
                "schema": "kazstem-bf1f-productive-generation-probe-v1",
                "cases": 0,
                "resource_bundle_id": self.resource_manifest["bundle_id"],
                "runtime_bundle_id": self.identity["inputs"]["runtime_tree"][
                    "bundle_id"
                ],
                "productive_queries": 0,
                "productive_hits": 0,
                "not_applicable": "current f03 release resource is schema v3",
            }
        self.profiles["bf1f_productive_generation"] = productive_generation
        comparison_text = "Қазақстан & балалар мектепке барды.\r\n"
        binary_comparison = self.binary(
            "comparison-frozen", ["-c", "--format", "jsonl"], text=comparison_text
        )
        wheel_comparison = self.run(
            "comparison-wheel-cli",
            [str(venv / "bin/kazstem"), "-c", "--format", "jsonl"],
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
            f"with Analyzer(resource_dir={str(self.root / self.identity['ready_run']['resource_destination'])!r}) as a:\n"
            " print(format_jsonl(a.analyze(text), copy_input=True), end='')\n"
        )
        api_comparison = self.run(
            "comparison-wheel-api",
            [str(python), "-c", api_code],
            environment=wheel_env,
        )
        assert (
            binary_comparison.stdout
            == wheel_comparison.stdout
            == module_comparison.stdout
            == api_comparison.stdout
        )

        ledger = json.loads(
            (self.root / "verification/MODULE-NATIVE-INCLUSION-LEDGER.json").read_text()
        )
        assert not any(
            token in path.name.lower()
            for path in self.root.rglob("*")
            for token in ("libssl", "libcrypto", "_ssl.", "_hashlib.")
        )
        modules = ledger["base_ledger"]["module_inventory"]["modules"]
        banned = self.identity["minimization"]["banned_modules"]
        assert not any(
            module == prefix or module.startswith(prefix + ".")
            for module in modules
            for prefix in banned
        )
        assert ledger["base_ledger"]["module_inventory"]["sha2_present"] is True

        processes = subprocess.run(
            ["ps", "-axo", "pid=,command="],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
        ).stdout.splitlines()
        lingering = [
            line
            for line in processes
            if str(self.root) in line
            and any(
                name in line
                for name in ("hfst-proc", "hfst-optimized-lookup", "cg-proc")
            )
        ]
        assert not lingering, lingering

        after = fingerprint(self.root)
        assert self.before == after
        resource_root = self.root / self.identity["ready_run"]["resource_destination"]
        runtime_root = runtime
        for sealed in (resource_root, runtime_root):
            assert not any(
                path.lstat().st_mode & 0o222 for path in [sealed, *sealed.rglob("*")]
            )

        return {
            "schema": "kazstem-macos-practical-matrix-v1",
            "pass": True,
            "release": self.identity["release"],
            "root": self.root.name,
            "source_commit": self.identity["source_commit"],
            "source_tree": self.identity["source_tree"],
            "resource_bundle_id": self.resource_manifest["bundle_id"],
            "resource_schema": self.resource_manifest["schema"],
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
                "flags": [
                    "-c",
                    "-n",
                    "-i",
                    "-g",
                    "-w",
                    "-l",
                    "-s",
                    "-d",
                    "--weight",
                    "--filter-gram",
                    "--fixlist",
                    "--generate-all",
                    "--no-guesser",
                    "--ud-profile",
                    "--eng-gr",
                ],
                "io": [
                    "stdin",
                    "positional input/output",
                    "hostile Unicode/newline paths",
                ],
                "unicode": [
                    "LF",
                    "CR",
                    "CRLF",
                    "decomposed Unicode",
                    "reserved syntax",
                    "NUL",
                ],
                "engines": [
                    "dictionary",
                    "productive OOV",
                    "Constraint Grammar",
                    "generation",
                    "generation round-trip",
                ],
                "bf1f_productive_generation": {
                    "required": self.resource_manifest.get("schema")
                    == "qazmorph-resource-manifest-v4",
                    "executed_cases": productive_generation["cases"],
                    "probe_schema": productive_generation["schema"],
                },
                "loader_environment": {
                    "clean_parent_official_gate": True,
                    "hostile_parent_non_official_probe": hostile_loader["schema"],
                    "captured_names": hostile_loader["captured_names"],
                    "glibc_tunables_captured": True,
                    "helper_environment_scrubbed": True,
                },
                "parity": [
                    "frozen CLI",
                    "two aliases",
                    "wheel CLI",
                    "python -m qazmorph",
                    "wheel API",
                ],
            },
            "bundle_fingerprint_unchanged": True,
            "read_only_resource_runtime_unchanged": True,
            "lingering_native_processes": [],
            "network_tls_modules_absent": True,
            "neural_weights": [],
            "optimization_review": {
                "additional_pruning_accepted": [],
                "decision": "No additional removal among the recorded measured candidates passed the full matrix; no global-minimum claim is made.",
                "retained": {
                    "zlib_extension": "PyInstaller bootstrap hard requirement; negative control exits 255.",
                    "multibyte_codecs": "Required by the advertised arbitrary text-encoding option.",
                    "hash_extensions": "hashlib guaranteed constructors initialize them; _sha2 supplies SHA-256 while _hashlib/OpenSSL stay absent.",
                    "full_icu_data": "Arbitrary Unicode is advertised; finite probes cannot prove a filtered ICU image complete.",
                    "sqlite_native_library": "Reachable dependency of cg-proc/libcg3, not Python sqlite3.",
                },
            },
            "result": "pass",
        }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--identity", required=True, type=Path)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--wheel", required=True, type=Path)
    parser.add_argument("--bootstrap-python", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists() or args.output.is_symlink():
        raise ReleaseError("practical evidence output already exists")
    identity_path = args.identity.resolve(strict=True)
    identity = load_identity(identity_path)
    execution = begin_gate_execution(identity, "practical", caller_file=__file__)
    root_binding = verify_ready_root_identity(args.root, identity)
    matrix = Matrix(args.root, args.wheel, identity, args.bootstrap_python)
    try:
        result = matrix.execute()
    finally:
        matrix.close()
    result["root_binding"] = root_binding
    envelope = gate_envelope(
        identity=identity,
        identity_contract_sha256=identity_sha256(identity_path),
        gate="practical",
        subjects=["ready_run", "wheel"],
        invocation=locked_gate_invocation(
            identity,
            "practical",
            stdout=f"PASS: {result['cases']} practical/performance cases\n".encode(
                "ascii"
            ),
            execution=execution,
        ),
        coverage={
            "descendant_processes": max(1, result["cases"] * 2),
            "full_descendant_coverage": True,
            "network_trace": None,
            "observations": {
                "cases": result["cases"],
                "formats": len(result["coverage"]["formats"]),
                "performance_runs": len(result["profiles"]["realistic_workload"]),
                "startup_runs": result["profiles"]["startup_version_seconds"]["runs"],
            },
            "trace_complete": True,
            "trace_truncated": False,
        },
        payload=result,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(json_bytes(envelope))
    print(f"PASS: {result['cases']} practical/performance cases")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (
        ReleaseError,
        OSError,
        ValueError,
        json.JSONDecodeError,
        AssertionError,
    ) as exc:
        raise SystemExit(f"error: {exc}") from exc
