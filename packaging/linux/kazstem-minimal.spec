# -*- mode: python ; coding: utf-8 -*-
"""Minimal auditable PyInstaller recipe for Ubuntu 24.04 x86_64."""

import os
from pathlib import Path


entrypoint = Path(os.environ["KAZSTEM_FROZEN_BOOTSTRAP"]).resolve(strict=True)
wheel = Path(os.environ["KAZSTEM_CANONICAL_WHEEL"]).resolve(strict=True)
if not wheel.name.startswith("kazstem-") or not wheel.name.endswith("-py3-none-any.whl"):
    raise SystemExit("KAZSTEM_CANONICAL_WHEEL has a noncanonical filename")
optimize = int(os.environ.get("KAZSTEM_PYTHON_OPTIMIZE", "0"))

# Keep the exact canonical wheel as the sole qazmorph import source.  This
# makes wheel consumption independently byte-auditable after freezing; the
# bootstrap inserts the wheel into sys.path before importing qazmorph.cli.
datas = [(str(wheel), ".")]

a = Analysis(
    [str(entrypoint)],
    # Analyze the exact wheel to retain its transitive stdlib dependency
    # closure.  The qazmorph modules themselves are removed from the PYZ below
    # so runtime imports still come exclusively from the embedded wheel bytes.
    pathex=[str(wheel)],
    binaries=[],
    datas=datas,
    hiddenimports=["qazmorph.cli"],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        "ssl", "_ssl", "socket", "_socket", "http", "urllib.request",
        "urllib.error", "urllib.response", "urllib.robotparser", "email",
        "ftplib", "netrc", "mimetypes", "xml", "asyncio",
        "multiprocessing", "concurrent", "concurrent.futures", "sqlite3",
        "_sqlite3", "tkinter", "_tkinter", "turtle", "turtledemo", "pydoc",
        "idlelib", "bz2", "_bz2", "lzma", "_lzma", "compression", "_zstd",
        "gzip", "tarfile", "zipfile", "zlib", "encodings.base64_codec",
        "encodings.bz2_codec", "encodings.hex_codec", "encodings.quopri_codec",
        "encodings.rot_13", "encodings.uu_codec", "encodings.zlib_codec",
        "_hashlib", "statistics", "_statistics", "decimal", "_decimal",
        "_pydecimal", "fractions", "numbers", "random", "_random", "pickle",
        "_pickle", "_compat_pickle", "csv", "_csv", "ctypes", "_ctypes",
        "logging", "tempfile", "importlib.metadata", "importlib.resources",
        "importlib.readers", "py_compile", "tracemalloc", "sysconfig",
        "_sysconfigdata__x86_64-linux-gnu", "_osx_support", "_aix_support",
        "plistlib", "base64", "binascii", "quopri", "calendar", "datetime",
        "_datetime", "array", "grp", "resource", "heapq", "_heapq",
        "pprint", "contextvars", "getopt", "readline", "rlcompleter",
        "termios", "curses", "unittest", "test", "doctest", "pdb", "profile",
        "pstats", "cProfile", "distutils", "setuptools", "pip", "ensurepip",
        "venv",
    ],
    noarchive=False,
    optimize=optimize,
)

# KazStem does not use inspect source retrieval.  Removing this runtime hook
# also avoids pulling the generic archive/source-inspection stack back in.
a.scripts = [entry for entry in a.scripts if entry[0] != "pyi_rth_inspect"]
a.pure = [
    entry
    for entry in a.pure
    if entry[0] != "qazmorph" and not entry[0].startswith("qazmorph.")
]

pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="kazstem",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
    disable_windowed_traceback=False,
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="kazstem",
)
