# -*- mode: python ; coding: utf-8 -*-
"""Minimal, auditable PyInstaller recipe for the macOS arm64 CLI asset."""

import os
from pathlib import Path

from PyInstaller.utils.hooks import collect_data_files


entrypoint = Path(os.environ["KAZSTEM_ENTRYPOINT"]).resolve(strict=True)
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
        "ssl", "_ssl", "socket", "_socket", "http", "urllib", "email",
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
        "_sysconfigdata__darwin_darwin", "_osx_support", "_aix_support",
        "plistlib", "base64", "binascii", "quopri", "calendar", "datetime",
        "_datetime", "array", "grp", "resource", "heapq", "_heapq",
        "pprint", "contextvars", "getopt", "_scproxy", "unittest", "test",
        "doctest", "pdb", "profile", "pstats", "cProfile", "distutils",
        "setuptools", "pip", "ensurepip", "venv",
    ],
    noarchive=False,
    optimize=0,
)

# PyInstaller's stock hook only teaches inspect.getsourcefile() about frozen
# source paths. KazStem uses inspect indirectly for dataclass signatures and
# unwrapping; neither needs that hook. Omitting it also removes the otherwise
# unused zipfile/shutil archive stack. argparse itself still retains shutil for
# terminal-width formatting.
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
    argv_emulation=False,
    target_arch="arm64",
    codesign_identity=None,
    entitlements_file=None,
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
