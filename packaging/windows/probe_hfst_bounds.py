#!/usr/bin/env python3
"""Prove the locked Windows HFST helpers accept bounded-result options."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys
import tempfile


PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from qazmorph.backend import BackendError  # noqa: E402
from qazmorph.guesser import _PersistentLookupWorker  # noqa: E402


TIMEOUT_SECONDS = 10
OUTPUT_CAP = 1024 * 1024
HELPERS = (
    ("hfst-optimized-lookup", "--analyses", "hfst/bin/hfst-optimized-lookup.exe"),
    ("hfst-lookup", "--max-number", "hfst/bin/hfst-lookup.exe"),
)


class ProbeError(RuntimeError):
    pass


def run(command: list[str], *, input_bytes: bytes | None = None) -> bytes:
    try:
        completed = subprocess.run(
            command,
            input=input_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise ProbeError(f"helper probe timed out after {TIMEOUT_SECONDS}s") from exc
    if len(completed.stdout) > OUTPUT_CAP:
        raise ProbeError("helper probe output exceeded its 1-MiB audit cap")
    if completed.returncode:
        raise ProbeError(
            f"helper probe exited {completed.returncode}: "
            f"{completed.stdout.decode('utf-8', 'replace')[-4096:]}"
        )
    return completed.stdout


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--optimized-resource", type=Path)
    parser.add_argument("--surface", default="балалар")
    args = parser.parse_args()
    root = args.root.resolve(strict=True)
    records: list[dict[str, object]] = []
    for name, long_option, relative in HELPERS:
        executable = root / relative
        if not executable.is_file():
            raise ProbeError(f"missing helper: {relative}")
        help_text = run([str(executable), "--help"]).decode("utf-8", "strict")
        if (
            "-n" not in help_text
            or long_option not in help_text
            or "--pipe-mode" not in help_text
        ):
            raise ProbeError(
                f"{name} does not document -n/{long_option}/--pipe-mode"
            )
        version = run(
            [str(executable), "-n", "1", "--pipe-mode=both", "--version"]
        ).decode("utf-8", "strict").strip()
        if not version:
            raise ProbeError(f"{name} emitted no version output")
        records.append(
            {
                "helper": name,
                "path": relative,
                "short_option": "-n",
                "long_option": long_option,
                "pipe_mode": "both",
                "bound": 1,
                "timeout_seconds": TIMEOUT_SECONDS,
                "version_output": version,
            }
        )

    generated = args.optimized_resource is None
    with tempfile.TemporaryDirectory(prefix="kazstem-hfst-bound-probe-") as temporary:
        if generated:
            temporary_root = Path(temporary)
            expression = temporary_root / "two-analysis-probe.regex"
            ordinary = temporary_root / "two-analysis-probe.hfst"
            resource = temporary_root / "two-analysis-probe.hfstol"
            regexp = root / "hfst/bin/hfst-regexp2fst.exe"
            converter = root / "hfst/bin/hfst-fst2fst.exe"
            if not regexp.is_file() or not converter.is_file():
                raise ProbeError("locked HFST archive lacks semantic-probe compilers")
            expression.write_bytes(b"a:b | a:c\n")
            run([
                str(regexp),
                "-f",
                "openfst-tropical",
                "-o",
                str(ordinary),
                str(expression),
            ])
            run([str(converter), "-O", str(ordinary), "-o", str(resource)])
            if not ordinary.is_file() or not resource.is_file():
                raise ProbeError("semantic-probe compilers produced no transducer")
            surface = "a"
        else:
            resource = args.optimized_resource.resolve(strict=True)
            surface = args.surface
        executable = root / HELPERS[0][2]
        common = [str(executable), "-q", "--pipe-mode=both"]
        control_output = run(
            [*common, str(resource)],
            input_bytes=(surface + "\n").encode("utf-8"),
        )
        bounded_output = run(
            [str(executable), "-n", "1", "-q", "--pipe-mode=both", str(resource)],
            input_bytes=(surface + "\n").encode("utf-8"),
        )
        protocol = _PersistentLookupWorker(("native-probe",), {})
        try:
            control_rows = protocol._parse_windows_oneshot_response(
                control_output, max_lines=4096, max_bytes=OUTPUT_CAP
            )
            bounded_rows = protocol._parse_windows_oneshot_response(
                bounded_output, max_lines=1, max_bytes=OUTPUT_CAP
            )
        except BackendError as exc:
            raise ProbeError(f"semantic helper response violates protocol: {exc}") from exc
        if (
            len(control_rows) < 2
            or len(bounded_rows) != 1
            or bounded_rows != control_rows[:1]
            or any(row.split("\t", 1)[0] != surface for row in control_rows)
        ):
            raise ProbeError("semantic -n 1 probe did not preserve exactly one result")
        semantic = {
            "status": "pass",
            "helper": HELPERS[0][0],
            "resource": resource.name,
            "resource_kind": "generated two-analysis FST" if generated else "supplied resource",
            "surface": surface,
            "control_nonempty_rows": len(control_rows),
            "bounded_nonempty_rows": len(bounded_rows),
            "bounded_prefix_matches_control": True,
            "bound": 1,
        }
    result = {
        "schema": "kazstem-windows-hfst-result-bound-probe-v1",
        "result": "pass",
        "helpers": records,
        "semantic_query": semantic,
    }
    args.output.write_text(
        json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ProbeError, BackendError, OSError, UnicodeError, ValueError) as error:
        raise SystemExit(f"error: {error}") from error
