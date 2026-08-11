# -*- mode: python ; coding: utf-8 -*-
"""Minimal, auditable PyInstaller recipe for Windows x86-64."""

import os
from pathlib import Path

from PyInstaller.utils.hooks import collect_data_files


entrypoint = Path(os.environ["KAZSTEM_ENTRYPOINT"]).resolve(strict=True)
noarchive_value = os.environ.get("KAZSTEM_NOARCHIVE", "0")
if noarchive_value not in {"0", "1"}:
    raise ValueError("KAZSTEM_NOARCHIVE must be exactly 0 or 1")
noarchive = noarchive_value == "1"
if os.environ.get("KAZSTEM_PYTHON_OPTIMIZE", "0") != "0":
    raise ValueError(
        "Windows release builds forbid -O while helper cleanup contains active asserts"
    )
datas = collect_data_files("qazmorph")

a = Analysis(
    [str(entrypoint)],
    pathex=[],
    binaries=[],
    datas=datas,
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        "ssl", "_ssl", "socket", "_socket", "http", "urllib.request",
        "urllib.error", "urllib.response", "urllib.robotparser", "email",
        "ftplib", "netrc", "ipaddress", "mimetypes", "xml", "asyncio",
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
        "_osx_support", "_aix_support", "plistlib", "base64", "binascii",
        "quopri", "calendar", "datetime", "_datetime", "array", "resource",
        "grp", "pwd", "termios", "readline", "rlcompleter", "curses",
        "heapq", "_heapq", "pprint", "contextvars", "getopt", "unittest",
        "test", "doctest", "pdb", "profile", "pstats", "cProfile",
        "distutils", "setuptools", "pip", "ensurepip", "venv",
    ],
    noarchive=noarchive,
    optimize=0,
)

# KazStem never retrieves Python source at runtime.  Removing this generic
# PyInstaller hook also prevents archive/source-inspection modules from being
# reintroduced after the explicit exclusions above.
a.scripts = [entry for entry in a.scripts if entry[0] != "pyi_rth_inspect"]

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
