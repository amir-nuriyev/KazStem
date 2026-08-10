#!/usr/bin/env python3
"""Create a reproducible raw-text sample on the configured H100 host only."""

from __future__ import annotations

import argparse
import hashlib
from importlib import metadata
import json
import os
from pathlib import Path
import platform
import socket
import tempfile
from typing import Any, Sequence


DATASET = "kz-transformers/multidomain-kazakh-dataset"
REVISION = "7a1fcdf9830b1c34b44b3038aafb672447f41890"
SPLIT = "train"


class SampleError(RuntimeError):
    pass


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _atomic_write(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Stream a pinned Kazakh raw-text prefix; run only on the H100 host."
    )
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--rows", type=int, default=5_000)
    parser.add_argument("--expected-host", default="arboghast")
    parser.add_argument("--expected-sha256")
    parser.add_argument("--expected-first-id")
    parser.add_argument("--expected-last-id")
    return parser


def run(args: argparse.Namespace) -> dict[str, Any]:
    if socket.gethostname() != args.expected_host:
        raise SampleError(
            f"refusing dataset access on {socket.gethostname()}; expected {args.expected_host}"
        )
    if args.rows < 1:
        raise SampleError("--rows must be positive")
    try:
        from datasets import load_dataset
    except ImportError as exc:
        raise SampleError("the Hugging Face datasets package is required on H100") from exc

    dataset = load_dataset(DATASET, split=SPLIT, streaming=True, revision=REVISION)
    selected: list[str] = []
    first_id: str | None = None
    last_id: str | None = None
    for row in dataset:
        text = row.get("text")
        if row.get("predicted_language") != "kaz" or not isinstance(text, str) or not text.strip():
            continue
        row_id = str(row.get("id"))
        if first_id is None:
            first_id = row_id
        last_id = row_id
        selected.append(text)
        if len(selected) == args.rows:
            break
    if len(selected) != args.rows:
        raise SampleError(f"stream ended after {len(selected)} selected rows")

    payload = "\n".join(selected).encode("utf-8")
    digest = hashlib.sha256(payload).hexdigest()
    if args.expected_sha256 and digest != args.expected_sha256:
        raise SampleError(f"sample SHA-256 is {digest}, expected {args.expected_sha256}")
    if args.expected_first_id and first_id != args.expected_first_id:
        raise SampleError(f"first id is {first_id}, expected {args.expected_first_id}")
    if args.expected_last_id and last_id != args.expected_last_id:
        raise SampleError(f"last id is {last_id}, expected {args.expected_last_id}")

    output = args.output.expanduser().resolve()
    _atomic_write(output, payload)
    script = Path(__file__).resolve()
    manifest = {
        "schema_version": "qazmorph.raw-sample.v1",
        "dataset": DATASET,
        "dataset_revision": REVISION,
        "split": SPLIT,
        "selection": f"first {args.rows} nonempty rows with predicted_language=kaz",
        "rows": args.rows,
        "first_id": first_id,
        "last_id": last_id,
        "characters": len(payload.decode("utf-8")),
        "utf8_bytes": len(payload),
        "sha256": digest,
        "extractor": {
            "path": str(script),
            "bytes": script.stat().st_size,
            "sha256": _sha256(script),
            "python": platform.python_version(),
            "datasets": metadata.version("datasets"),
            "huggingface_hub": metadata.version("huggingface-hub"),
        },
    }
    _atomic_write(
        output.with_name(output.name + ".json"),
        (json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode(
            "utf-8"
        ),
    )
    return manifest


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        manifest = run(args)
    except (SampleError, OSError, UnicodeError, ValueError) as exc:
        parser.exit(2, f"prepare_multidomain_sample.py: error: {exc}\n")
    print(json.dumps(manifest, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
