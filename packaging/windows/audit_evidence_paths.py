#!/usr/bin/env python3
"""Reject machine-local absolute roots from textual release evidence."""

from __future__ import annotations

import argparse
import json
from pathlib import Path, PurePosixPath, PureWindowsPath
import sys
from typing import Any


WINDOWS_PACKAGING_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(WINDOWS_PACKAGING_ROOT))

from evidence_path_contract import absolute_path_kind  # noqa: E402


TEXT_SUFFIXES = {".json", ".jsonl", ".log", ".md", ".sha256", ".txt"}


class EvidenceError(RuntimeError):
    pass


def normalized(value: str) -> str:
    return value.replace("\\", "/").casefold()


def forbidden_tokens(value: str) -> set[str]:
    tokens: set[str] = set()
    if PureWindowsPath(value).is_absolute() or PurePosixPath(value).is_absolute():
        tokens.add(normalized(value).rstrip("/"))
    lexical = Path(value)
    resolved = lexical.resolve(strict=False)
    tokens.add(normalized(str(resolved)).rstrip("/"))
    try:
        relative_target = resolved.relative_to(lexical.parent.resolve(strict=False))
    except ValueError:
        pass
    else:
        tokens.add(
            normalized(str(lexical.parent / relative_target)).rstrip("/")
        )
    return tokens


def json_strings(value: Any):
    if isinstance(value, str):
        yield value
    elif isinstance(value, list):
        for item in value:
            yield from json_strings(item)
    elif isinstance(value, dict):
        for key, item in value.items():
            yield str(key)
            yield from json_strings(item)


def scan_evidence(
    root: Path,
    *,
    forbidden_values: list[str],
    output: Path | None = None,
) -> dict[str, Any]:
    """Run the reviewed decoded JSON/text scanner without writing output."""

    root = root.resolve(strict=True)
    output_resolved = output.resolve(strict=False) if output is not None else None
    forbidden = sorted(
        {
            token
            for value in forbidden_values
            for token in forbidden_tokens(value)
        },
        key=len,
        reverse=True,
    )
    if any(not token or token == "/" for token in forbidden):
        raise EvidenceError("refusing an empty or filesystem-root forbidden token")

    checked: list[str] = []
    failures: list[dict[str, str]] = []
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
        if not path.is_file() or (
            output_resolved is not None and path.resolve() == output_resolved
        ):
            continue
        if path.suffix.casefold() not in TEXT_SUFFIXES:
            continue
        relative = path.relative_to(root).as_posix()
        try:
            text = path.read_text(encoding="utf-8-sig", errors="strict")
        except (OSError, UnicodeError) as exc:
            raise EvidenceError(f"cannot decode textual evidence {relative}: {exc}") from exc
        values: list[str]
        if path.suffix.casefold() in {".json", ".jsonl"}:
            try:
                if path.suffix.casefold() == ".jsonl":
                    decoded = [json.loads(line) for line in text.splitlines() if line]
                else:
                    decoded = json.loads(text)
            except json.JSONDecodeError as exc:
                raise EvidenceError(f"invalid JSON evidence {relative}: {exc}") from exc
            values = list(json_strings(decoded))
        else:
            values = [text]
        for value in values:
            observed = normalized(value)
            for token in forbidden:
                if token in observed:
                    failures.append({"file": relative, "forbidden_root": token})
            residual_kind = absolute_path_kind(value)
            if residual_kind is not None:
                failures.append(
                    {
                        "file": relative,
                        "forbidden_root": f"<{residual_kind}-path>",
                    }
                )
        checked.append(relative)
    if not checked:
        raise EvidenceError("no textual evidence files were checked")
    if failures:
        raise EvidenceError(
            "absolute machine paths leaked into evidence: "
            + json.dumps(failures, ensure_ascii=False, sort_keys=True)
        )
    return {
        "schema": "kazstem-logical-evidence-path-audit-v1",
        "result": "pass",
        "root": root.name,
        "text_files_checked": checked,
        "forbidden_root_count": len(forbidden),
        "absolute_root_leaks": [],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--forbid", required=True, action="append")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    result = scan_evidence(
        args.root,
        forbidden_values=args.forbid,
        output=args.output,
    )
    args.output.resolve().write_text(
        json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(
        "logical evidence paths verified across "
        f"{len(result['text_files_checked'])} text files"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (EvidenceError, OSError, ValueError) as error:
        raise SystemExit(f"error: {error}") from error
