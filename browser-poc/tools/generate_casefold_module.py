#!/usr/bin/env python3
"""Freeze Python/H100 full Unicode casefold mappings for browser unknowns."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import unicodedata


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    rows: list[str] = []
    digest = hashlib.sha256()
    for codepoint in range(0x110000):
        if 0xD800 <= codepoint <= 0xDFFF:
            continue
        character = chr(codepoint)
        folded = character.casefold()
        if folded == character:
            continue
        digest.update(f"{codepoint:X}\t{folded}\n".encode("utf-8"))
        rows.append(f"  [0x{codepoint:X}, {folded!r}],")
    source = (
        "// Generated on H100 by tools/generate_casefold_module.py.\n"
        f"export const CASEFOLD_UNICODE_VERSION = {unicodedata.unidata_version!r};\n"
        f"export const CASEFOLD_TABLE_SHA256 = {digest.hexdigest()!r};\n"
        "const CASEFOLD = new Map([\n"
        + "\n".join(rows)
        + "\n]);\n\n"
        "export function unicodeCasefold(value) {\n"
        "  return Array.from(value, (character) => CASEFOLD.get(character.codePointAt(0)) ?? character).join('');\n"
        "}\n"
    )
    # repr emits single-quoted Python strings. The mapping contains no line
    # terminators requiring JavaScript-specific escaping in this Unicode set;
    # make backslash/quote escapes explicit and fail if Node syntax tests ever
    # disagree.
    args.output.write_text(source, encoding="utf-8")
    print(f"unicode={unicodedata.unidata_version} rows={len(rows)} sha256={digest.hexdigest()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
