#!/usr/bin/env python3
"""Export an unweighted HFST AT&T graph to KazStem's browser CSR format.

Run this only after ``hfst-fst2txt`` has exported the verified analyzer.  The
format intentionally contains no compiler/runtime code: it is a little-endian
header followed by four typed arrays and a final-state bitmap.
"""

from __future__ import annotations

import argparse
from decimal import Decimal, InvalidOperation
import hashlib
import json
import os
from pathlib import Path
import struct
import tempfile
from typing import BinaryIO


MAGIC = b"KZCSR001"
EPSILON = "@0@"
ATT_ESCAPES = {"@_SPACE_@": " "}
SUPPORTED_ATT_META_SYMBOLS = frozenset({EPSILON, *ATT_ESCAPES})
MAX_U32 = 2**32 - 1


class ExportError(ValueError):
    pass


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def decode_symbol(symbol: str) -> str:
    if symbol.startswith("@") and symbol.endswith("@") and symbol not in SUPPORTED_ATT_META_SYMBOLS:
        raise ExportError(f"unsupported HFST meta/flag symbol: {symbol}")
    return ATT_ESCAPES.get(symbol, symbol)


def align(stream: BinaryIO, alignment: int = 4) -> None:
    padding = (-stream.tell()) % alignment
    if padding:
        stream.write(b"\0" * padding)


def write_u16(stream: BinaryIO, values: list[int]) -> None:
    stream.write(struct.pack(f"<{len(values)}H", *values))


def write_u32(stream: BinaryIO, values: list[int]) -> None:
    stream.write(struct.pack(f"<{len(values)}I", *values))


def exact_zero(value: str, *, line_number: int) -> None:
    try:
        weight = Decimal(value)
    except InvalidOperation as exc:
        raise ExportError(f"invalid weight at AT&T row {line_number}: {value!r}") from exc
    if not weight.is_finite() or weight != 0:
        raise ExportError(f"browser-v1 rejects nonzero/nonfinite weight at row {line_number}: {value!r}")


def require_distinct_paths(*paths: Path) -> None:
    resolved = [path.expanduser().resolve(strict=False) for path in paths]
    if len(set(resolved)) != len(resolved):
        raise ExportError("ATT, resource, manifest, and probe-ledger paths must be distinct")
    existing = [path for path in paths if path.exists()]
    for index, left in enumerate(existing):
        for right in existing[index + 1 :]:
            if left.samefile(right):
                raise ExportError("input/output paths alias the same existing file")


def atomic_write(path: Path, writer) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            writer(stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def export(att_path: Path, output_path: Path, manifest_path: Path, args: argparse.Namespace) -> None:
    require_distinct_paths(att_path, output_path, manifest_path, args.probe_ledger)
    arcs: list[tuple[int, int, str, str]] = []
    final_states: set[int] = set()
    states: set[int] = set()

    with att_path.open(encoding="utf-8", newline="") as source:
        for line_number, raw_line in enumerate(source, 1):
            fields = raw_line.rstrip("\r\n").split("\t")
            if len(fields) == 5:
                source_state, target_state = int(fields[0]), int(fields[1])
                if not 0 <= source_state < MAX_U32 or not 0 <= target_state < MAX_U32:
                    raise ExportError(f"state ID outside browser-v1 uint32 range at row {line_number}")
                exact_zero(fields[4], line_number=line_number)
                arcs.append((source_state, target_state, fields[2], fields[3]))
                states.update((source_state, target_state))
            elif len(fields) == 2:
                state = int(fields[0])
                if not 0 <= state < MAX_U32:
                    raise ExportError(f"final state outside browser-v1 uint32 range at row {line_number}")
                exact_zero(fields[1], line_number=line_number)
                states.add(state)
                final_states.add(state)
            elif fields != [""]:
                raise ExportError(f"unexpected AT&T row {line_number}: {fields!r}")

    if not states or 0 not in states:
        raise ExportError("graph has no start state 0")
    state_count = max(states) + 1
    if states != set(range(state_count)):
        raise ExportError("browser-v1 requires densely numbered states")
    raw_meta_symbols = sorted(
        {
            symbol
            for _source, _target, input_symbol, output_symbol in arcs
            for symbol in (input_symbol, output_symbol)
            if symbol.startswith("@") and symbol.endswith("@")
        }
    )
    unsupported_meta_symbols = set(raw_meta_symbols) - SUPPORTED_ATT_META_SYMBOLS
    if unsupported_meta_symbols:
        raise ExportError(
            "browser-v1 has no semantics for HFST meta/flag symbols: "
            + ", ".join(sorted(unsupported_meta_symbols))
        )
    for side, index in (("input", 2), ("output", 3)):
        decoded_to_raw: dict[str, set[str]] = {}
        for arc in arcs:
            raw = arc[index]
            decoded_to_raw.setdefault(decode_symbol(raw), set()).add(raw)
        collisions = {decoded: raw for decoded, raw in decoded_to_raw.items() if len(raw) > 1}
        if collisions:
            raise ExportError(f"{side} ATT decode aliases distinct symbols: {collisions!r}")

    # Acyclicity of input-epsilon arcs makes exhaustive lookup finite for every
    # finite input.  Keep this formal graph gate alongside candidate probes.
    epsilon_adjacency: list[list[int]] = [[] for _ in range(state_count)]
    for source_state, target_state, input_symbol, _output_symbol in arcs:
        if input_symbol == EPSILON:
            epsilon_adjacency[source_state].append(target_state)
    colors = bytearray(state_count)

    def visit(state: int) -> None:
        if colors[state] == 1:
            raise ExportError(f"reachable input-epsilon cycle includes state {state}")
        if colors[state] == 2:
            return
        colors[state] = 1
        for target in epsilon_adjacency[state]:
            visit(target)
        colors[state] = 2

    visit(0)

    # Preserve the exporter order within a state. Candidate equality is set
    # based, while this stable order keeps repeat builds byte-identical.
    arcs.sort(key=lambda arc: arc[0])
    input_symbols = [EPSILON] + sorted(
        {decode_symbol(arc[2]) for arc in arcs if arc[2] != EPSILON}
    )
    output_symbols = [""] + sorted(
        {decode_symbol(arc[3]) for arc in arcs if arc[3] != EPSILON}
    )
    if len(input_symbols) > 65535 or len(output_symbols) > 65535:
        raise ExportError("browser-v1 uint16 symbol table is too small")
    input_ids = {symbol: index for index, symbol in enumerate(input_symbols)}
    output_ids = {symbol: index for index, symbol in enumerate(output_symbols)}

    row_offsets = [0] * (state_count + 1)
    targets: list[int] = []
    arc_inputs: list[int] = []
    arc_outputs: list[int] = []
    cursor = 0
    for state in range(state_count):
        row_offsets[state] = cursor
        while cursor < len(arcs) and arcs[cursor][0] == state:
            _source, target, input_symbol, output_symbol = arcs[cursor]
            targets.append(target)
            arc_inputs.append(
                0 if input_symbol == EPSILON else input_ids[decode_symbol(input_symbol)]
            )
            arc_outputs.append(
                0 if output_symbol == EPSILON else output_ids[decode_symbol(output_symbol)]
            )
            cursor += 1
    row_offsets[state_count] = cursor
    if cursor != len(arcs):
        raise ExportError("arcs were not completely indexed")

    metadata = {
        "schema": "kazstem.browser-csr.v1",
        "endianness": "little",
        "project": {
            "name": "KazStem",
            "version": args.project_version,
            "commit": args.project_commit,
        },
        "source": {
            "apertium_kaz_commit": args.apertium_commit,
            "att_sha256": sha256(att_path),
        },
        "att_symbol_audit": {
            "meta_symbols": raw_meta_symbols,
            "supported_meta_symbols": sorted(SUPPORTED_ATT_META_SYMBOLS),
            "identity_symbols": [],
            "unknown_symbols": [],
            "flag_diacritics": [],
        },
        "graph": {
            "start_state": 0,
            "state_count": state_count,
            "arc_count": len(arcs),
            "final_count": len(final_states),
            "input_epsilon_cycle_reachable": False,
        },
        "input_symbols": input_symbols,
        "output_symbols": output_symbols,
        "arrays": [
            {"name": "row_offsets", "type": "u32", "length": len(row_offsets)},
            {"name": "targets", "type": "u32", "length": len(targets)},
            {"name": "inputs", "type": "u16", "length": len(arc_inputs)},
            {"name": "outputs", "type": "u16", "length": len(arc_outputs)},
            {"name": "finals", "type": "u8", "length": state_count},
        ],
    }
    metadata_bytes = json.dumps(
        metadata, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")

    def write_resource(output: BinaryIO) -> None:
        output.write(MAGIC)
        output.write(struct.pack("<I", len(metadata_bytes)))
        output.write(metadata_bytes)
        align(output)
        write_u32(output, row_offsets)
        write_u32(output, targets)
        write_u16(output, arc_inputs)
        write_u16(output, arc_outputs)
        output.write(bytes(1 if state in final_states else 0 for state in range(state_count)))

    atomic_write(output_path, write_resource)

    resource_hash = sha256(output_path)
    expected_bytes = (
        ((12 + len(metadata_bytes) + 3) // 4) * 4
        + 4 * len(row_offsets)
        + 4 * len(targets)
        + 2 * len(arc_inputs)
        + 2 * len(arc_outputs)
        + state_count
    )
    if output_path.stat().st_size != expected_bytes or sha256(output_path) != resource_hash:
        raise ExportError("post-write resource byte/hash verification failed")
    if not args.probe_ledger.is_file():
        raise ExportError(f"candidate probe ledger is unavailable: {args.probe_ledger}")
    probe_ledger_record = {
        "path": args.probe_ledger.name,
        "bytes": args.probe_ledger.stat().st_size,
        "sha256": sha256(args.probe_ledger),
    }
    manifest = {
        "schema": "kazstem.browser-resource-manifest.v1",
        "project_version": args.project_version,
        "project_commit": args.project_commit,
        "apertium_kaz_commit": args.apertium_commit,
        "resource": {
            "path": output_path.name,
            "bytes": output_path.stat().st_size,
            "sha256": resource_hash,
            "graph": metadata["graph"],
        },
        "proofs": {
            "input_epsilon_cycle_reachable": False,
            "candidate_probe_ledger": probe_ledger_record,
        },
        "unsupported_modes": [
            "constraint-grammar",
            "neural-ranking",
            "productive-oov",
            "generation",
        ],
    }
    manifest_bytes = (
        json.dumps(manifest, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    ).encode("utf-8")
    atomic_write(manifest_path, lambda stream: stream.write(manifest_bytes))
    if manifest_path.stat().st_size != len(manifest_bytes) or sha256(manifest_path) != hashlib.sha256(manifest_bytes).hexdigest():
        raise ExportError("post-write manifest byte/hash verification failed")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("att", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--project-version", required=True)
    parser.add_argument("--project-commit", required=True)
    parser.add_argument("--apertium-commit", required=True)
    parser.add_argument("--probe-ledger", type=Path, default=Path("probes/browser-probes.native.json"))
    args = parser.parse_args()
    export(args.att, args.output, args.manifest, args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
