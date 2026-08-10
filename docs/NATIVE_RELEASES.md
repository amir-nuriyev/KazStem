# Native release bundles

KazStem source resources and the native programs that execute them have
separate identities. This matters for f03e: its immutable manifest records the
Ubuntu 24.04 r4 toolchain that built and verified the FST/CG bytes. Shipping
those same resource bytes with a native macOS runtime does not rewrite that
history.

## Bundle layout

```text
kazstem-<version>-<platform>/
  kazstem
  .qazmorph/
    resources/
      manifest.json
      kaz.*
    platform-runtimes/
      <runtime-bundle-id>/
        manifest.json
        usr/bin/...
        usr/lib/...
```

At startup KazStem loads the public
`qazmorph/platform_runtime_assets.lock.json`. A detached runtime is eligible
only when all of these match:

1. normalized operating system and architecture;
2. exact resource bundle ID;
3. content-addressed runtime directory beneath the resource bundle's own
   `.qazmorph` root;
4. runtime-manifest byte length, SHA-256, and bundle ID;
5. complete regular-file and symlink inventory, command hashes, and read-only
   seal.

An unlocked platform/resource pair retains the historical resource-bound
toolchain behavior. Once an entry matches, a missing or changed detached
runtime fails closed. KazStem does not search a home-directory cache, ambient
`PATH`, or a release-only hidden path for an official detached runtime.

## macOS arm64 v0.2.2 runtime

The source inputs, URLs, byte lengths, SHA-256 values, command versions, and
license inventory are fixed by
`scripts/platform_runtime_sources.lock.json`. The runtime manifest is produced
deterministically with:

```bash
python3 scripts/write_platform_runtime_manifest.py \
  --runtime-dir PATH/TO/runtime \
  --archive-dir PATH/TO/pinned-archives \
  --source-dir PATH/TO/corresponding-source \
  --lock scripts/platform_runtime_sources.lock.json
```

The helper binaries are thin Apple arm64 Mach-O files. Their non-system dylibs
are copied into `usr/lib` and resolved with bundle-relative rpaths. Apple
`libSystem` and `libc++` remain host System Libraries, so the bundle is not a
byte-closed operating-system image. `DYLD_LIBRARY_PATH` or
`DYLD_INSERT_LIBRARIES` makes runtime provenance non-official.
Although the top-level HFST/CG executables declare macOS 11.0, the recursive
non-system closure includes dylibs declaring macOS 14.0. The runtime lock
therefore records 14.0 as its truthful minimum; the final frozen launcher may
impose a newer minimum and must be labeled from its own Mach-O audit.

The v0.2.2 CLI archive is unsigned in the distribution sense: upstream helper
binaries and the PyInstaller executable may have ad-hoc signatures, but there
is no Apple Developer ID, Team ID, notarization ticket, or stapling claim.
Release notes and the filename identify the exact tested macOS/arm64 target.

The reference frozen launcher is built from the release wheel with CPython
3.14.3, PyInstaller 6.22.0, and `pyinstaller-hooks-contrib` 2026.6. PyInstaller
must collect the packaged runtime lock; resources and native helpers remain
outside `_internal` in the layout above:

```bash
python3 -m venv build-venv
build-venv/bin/python -m pip install \
  pyinstaller==6.22.0 pyinstaller-hooks-contrib==2026.6 \
  dist/kazstem-0.2.2-py3-none-any.whl
SOURCE_DATE_EPOCH=1786361661 build-venv/bin/pyinstaller \
  --clean --noconfirm --onedir --noupx --target-arch arm64 \
  --name kazstem --collect-data qazmorph build-venv/bin/kazstem
```

The exact build-tool wheels and their hashes belong in the binary asset's
verification report; they are not runtime inputs. After PyInstaller completes,
copy only the verified f03e directory and content-addressed platform runtime
under `.qazmorph`, add notices/corresponding source, remove extended attributes,
normalize archive ownership and timestamps, and test a fresh extraction outside
the checkout.

## Other platforms

Platform runtimes are never inferred from a similarly named archive. Each
Windows, Linux, macOS Intel, or additional architecture asset needs its own
native build, checked-in lock entry, recursive dependency audit, license/source
closure, and fresh-extract black-box test. Absence of such an entry means that
KazStem falls back to the resource's original toolchain contract; it is not a
claim that a binary for that platform exists.
