#!/usr/bin/env python3
"""Measure deterministic MyStem-shaped JSON output from an extracted bundle."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time
from typing import Any

from release_common import (
    ReleaseError,
    ensure_output_outside,
    json_bytes,
    load_identity,
    sha256_file,
)


def _reconstruct(path: Path) -> str:
    try:
        rows = json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ReleaseError(f"benchmark output is not UTF-8 JSON: {exc}") from exc
    if not isinstance(rows, list) or any(
        not isinstance(row, dict) or not isinstance(row.get("text"), str)
        for row in rows
    ):
        raise ReleaseError("benchmark output is not a MyStem-shaped JSON array")
    return "".join(row["text"] for row in rows)


def benchmark(args: argparse.Namespace) -> dict[str, Any]:
    ensure_output_outside(args.output, args.root, label="benchmark evidence output")
    if args.output.exists() or args.output.is_symlink():
        raise ReleaseError(f"benchmark output already exists: {args.output}")
    identity = load_identity(args.identity.resolve(strict=True))
    root = args.root.resolve(strict=True)
    if root.name != identity["ready_run"]["top_level"]:
        raise ReleaseError("benchmark root name differs from the release identity")
    executable = root / identity["ready_run"]["launcher"]["path"]
    if not executable.is_file() or not os.access(executable, os.X_OK):
        raise ReleaseError(
            f"ready-run executable is missing or not executable: {executable}"
        )
    if args.characters < 1000 or args.characters > 64 * 1024**2:
        raise ReleaseError("--characters must be between 1,000 and 67,108,864")
    if args.runs < 2 or args.runs > 20:
        raise ReleaseError("--runs must be between 2 and 20")
    if args.timeout <= 0 or args.timeout > 3600:
        raise ReleaseError(
            "--timeout must be greater than zero and at most 3,600 seconds"
        )
    timer = Path("/usr/bin/time")
    if not timer.is_file():
        raise ReleaseError("the Linux compatibility benchmark requires /usr/bin/time")
    phrase = "Қазақстандағы балалар мектепке барып, кітаптарды оқыды.\n"
    workload = (phrase * (args.characters // len(phrase) + 1))[: args.characters]
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(("QAZMORPH_", "LD_", "DYLD_"))
        and not key.upper().endswith("_PROXY")
    }
    environment.update(
        {
            "LC_ALL": "C",
            "LANG": "C",
            "TZ": "UTC",
            "NO_PROXY": "",
            "http_proxy": "http://127.0.0.1:9",
            "https_proxy": "http://127.0.0.1:9",
            "HTTP_PROXY": "http://127.0.0.1:9",
            "HTTPS_PROXY": "http://127.0.0.1:9",
        }
    )
    results: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="kazstem-compat-perf-") as temporary:
        temp = Path(temporary)
        home = temp / "offline-home"
        home.mkdir()
        environment["HOME"] = str(home)
        source = temp / "input.txt"
        source.write_text(workload, encoding="utf-8", newline="")
        for index in range(args.runs):
            destination = temp / f"output-{index}.json"
            started = time.perf_counter()
            try:
                completed = subprocess.run(
                    [
                        str(timer),
                        "-v",
                        str(executable),
                        "-c",
                        "-i",
                        "--format",
                        "json",
                        str(source),
                        str(destination),
                    ],
                    env=environment,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=args.timeout,
                    check=False,
                )
            except subprocess.TimeoutExpired as exc:
                raise ReleaseError(
                    f"benchmark run {index} exceeded {args.timeout} seconds"
                ) from exc
            elapsed = time.perf_counter() - started
            if completed.returncode:
                raise ReleaseError(
                    f"benchmark run {index} failed ({completed.returncode}): "
                    f"{completed.stderr.decode('utf-8', 'replace')}"
                )
            if _reconstruct(destination) != workload:
                raise ReleaseError(
                    f"benchmark run {index} did not reconstruct its exact input"
                )
            stderr = completed.stderr.decode("utf-8", "replace")
            rss = re.search(r"Maximum resident set size \(kbytes\):\s*(\d+)", stderr)
            results.append(
                {
                    "run": index,
                    "cache_state": "first process"
                    if index == 0
                    else "new process; host page cache may be warm",
                    "input_characters": len(workload),
                    "input_utf8_bytes": len(workload.encode("utf-8")),
                    "output_bytes": destination.stat().st_size,
                    "output_sha256": sha256_file(destination),
                    "seconds": round(elapsed, 6),
                    "input_characters_per_second": round(len(workload) / elapsed, 3),
                    "maximum_resident_set_size_bytes": int(rss.group(1)) * 1024
                    if rss
                    else None,
                }
            )
    output_hashes = {row["output_sha256"] for row in results}
    if len(output_hashes) != 1:
        raise ReleaseError("fresh benchmark processes produced different output bytes")
    report = {
        "schema": "kazstem-linux-mystem-json-performance-v2",
        "pass": True,
        "release": identity["release"],
        "source_commit": identity["source_commit"],
        "root": root.name,
        "format": "MyStem-shaped JSON (-c -i --format json)",
        "runs": results,
        "output_identity": True,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(json_bytes(report))
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path)
    parser.add_argument("--identity", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--characters", type=int, default=220_000)
    parser.add_argument("--runs", type=int, default=2)
    parser.add_argument("--timeout", type=float, default=300.0)
    args = parser.parse_args()
    result = benchmark(args)
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ReleaseError, OSError, ValueError, json.JSONDecodeError) as exc:
        raise SystemExit(f"error: {exc}") from exc
