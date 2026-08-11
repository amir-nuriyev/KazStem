#!/usr/bin/env python3
"""Start KazStem from the exact canonical wheel embedded in the frozen tree."""

from __future__ import annotations

import importlib
from pathlib import Path
import sys


def _embedded_wheel() -> Path:
    root_value = getattr(sys, "_MEIPASS", None)
    if not isinstance(root_value, str) or not root_value:
        raise RuntimeError("KazStem frozen bootstrap has no PyInstaller content root")
    root = Path(root_value)
    wheels = sorted(root.glob("kazstem-*-py3-none-any.whl"))
    if len(wheels) != 1 or wheels[0].is_symlink() or not wheels[0].is_file():
        raise RuntimeError("KazStem frozen bootstrap lacks one canonical embedded wheel")
    return wheels[0]


def main() -> int:
    wheel = _embedded_wheel()
    sys.path.insert(0, str(wheel))
    cli = importlib.import_module("qazmorph.cli")
    if not str(Path(cli.__file__ or "")).startswith(str(wheel)):
        raise RuntimeError("KazStem was not imported from the embedded canonical wheel")
    return int(cli.main() or 0)


if __name__ == "__main__":
    raise SystemExit(main())
