#!/usr/bin/env python3
"""Shared fail-closed checks for machine-absolute paths in Windows evidence."""

from __future__ import annotations

import re


DRIVE_ABSOLUTE = re.compile(r"(?i)(?<![a-z0-9])[a-z]:/+")
FILE_URI_ABSOLUTE = re.compile(
    r"(?i)(?<![a-z0-9+.-])file:(?:/+|[a-z]:/+)"
)
CURRENT_DRIVE_ROOTED = re.compile(
    r"(?ix)(?:^|[\s\"'(<[{=,:])/(?!/)(?:[^/\s\"'<>|]+/)+[^/\s\"'<>|]+"
)
UNC_OR_DEVICE = re.compile(
    r"(?ix)//[^/\s\"'<>|]+/[^/\s\"'<>|]+"
)
ALLOWED_WEB_SCHEME = re.compile(r"(?i)(?<![a-z0-9+.-])https?:$")
NT_DEVICE = re.compile(
    r"(?i)(?<![a-z0-9+:])/(?:\?\?|\?|\.|device|globalroot)(?:/|$)"
)


def normalized_path_text(value: str) -> str:
    return value.replace("\\", "/")


def absolute_path_kind(value: str) -> str | None:
    normalized = normalized_path_text(value)
    if FILE_URI_ABSOLUTE.search(normalized):
        return "file-uri"
    if DRIVE_ABSOLUTE.search(normalized):
        return "drive-absolute"
    if CURRENT_DRIVE_ROOTED.search(normalized):
        return "current-drive-rooted"
    if NT_DEVICE.search(normalized):
        return "nt-device"
    for match in UNC_OR_DEVICE.finditer(normalized):
        if not ALLOWED_WEB_SCHEME.search(normalized[: match.start()]):
            return "unc-or-device"
    return None
