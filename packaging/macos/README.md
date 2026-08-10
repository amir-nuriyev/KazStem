# macOS arm64 ready-run recipe

This recipe builds the unsigned/not-notarized KazStem 0.2.2 CLI asset tested on
macOS 15 arm64. It never changes or relabels the f03e resource bytes.

Build the checked-in source twice at `SOURCE_DATE_EPOCH=1786361661`, require
byte-identical wheels and normalized sdists, then install the exact wheel into
an isolated CPython 3.14.3 environment containing the SHA-locked PyInstaller
6.22.0 and hooks-contrib 2026.6 wheels. Set `KAZSTEM_ENTRYPOINT` to that
environment's `kazstem` entry point and run:

```sh
LC_ALL=C LANG=C PYTHONHASHSEED=0 SOURCE_DATE_EPOCH=1786361661 \
  pyinstaller --clean --noconfirm \
  --distpath pyinstaller-dist --workpath pyinstaller-work \
  packaging/macos/kazstem-minimal.spec
```

The spec removes networking/TLS, HTTP/email/URL, asyncio/multiprocessing,
SQLite, UI, test/build, unused compression, ctypes, XML-parser, and generic
archive stacks. `_hashlib` and `_ssl` are absent; `_sha2` remains and must be
proven to implement `hashlib.sha256`. PyInstaller forcibly retains the `zlib`
extension for its own compressed bootstrap archive: deleting it must fail the
negative control with `Module object for pyimod01_archive is NULL`.

Copy only the sealed f03e resource directory and the runtime declared by the
checked-in platform lock. For the reviewed Project.JJ runtime, remove the
unused generic `hfst-lookup`; analysis uses `hfst-proc`, OOV and generation use
`hfst-optimized-lookup`, and contextual mode uses `cg-proc`. Recursively retain
only the dylibs reached by those three executables.

For each copied Mach-O, compare the untouched upstream byte size with a copy
processed by `/usr/bin/strip -S -x` and then
`codesign --force --sign - --timestamp=none`. Retain a transformed copy only
when it is strictly smaller and every behavior, dependency, minimum-OS, and
strict-signature gate passes. In the reviewed native runtime this transforms
only `libfst.27.dylib`; the other files retain their exact Project.JJ archive
bytes and upstream ad-hoc/linker signatures. The transformed library has a new
local ad-hoc signature and is fully rebound by the regenerated runtime
manifest. Do not post-process the PyInstaller launcher: it contains an appended
CArchive and its symbol audit has no removable local symbols. PyInstaller's
copied Python Mach-O files are independently stripped and ad-hoc signed; re-sign
the complete copied `Python.framework` after its binary is stripped. Set every
native-runtime executable/symlink to its final read-only executable mode and
every library to its final read-only data mode *before* regenerating the
detached runtime manifest from the exact source lock. Keep only the runtime
root temporarily owner-writable for the manifest's atomic replacement; then
seal that directory too and require `--verify` to reproduce the manifest from
the fully sealed tree. Rename it to its content-addressed bundle ID, update the
public runtime lock, rebuild the wheel, and repeat the frozen build.

Seal the resource/runtime directories read-only. Add only notices, licenses,
the module/native inclusion ledger, and an exact name/size/SHA-256/URL binding
to the same-release corresponding-source asset. The lean binary must not embed
source or build-tool archives. Normalize archive ownership, modes, timestamps,
and gzip headers; build twice; fresh-extract elsewhere; then run the complete
black-box, provenance, module, Mach-O, path, source-binding, and no-neural gates.

The 33 MiB ICU data library is deliberately retained. ICU resource selection
is dynamic and the CLI accepts arbitrary Unicode input, so finite Kazakh/KTB
fixtures cannot prove that a filtered data image preserves all advertised
behavior. A filtered ICU candidate is acceptable only with a reproducible ICU
build recipe and byte-semantic equality across the complete release gate.
