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

## macOS arm64 v0.2.3 runtime

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

The v0.2.3 CLI archive is unsigned in the distribution sense: upstream helper
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
  dist/kazstem-0.2.3-py3-none-any.whl
SOURCE_DATE_EPOCH=1786361661 build-venv/bin/pyinstaller \
  --clean --noconfirm \
  --distpath pyinstaller-dist --workpath pyinstaller-work \
  packaging/macos/kazstem-minimal.spec
```

Set `KAZSTEM_ENTRYPOINT` to the absolute `build-venv/bin/kazstem` path for that
command. The checked-in spec records the complete exclusion set and removes
PyInstaller's source-introspection runtime hook, which the CLI does not use.
The exact build-tool wheels and their hashes belong in the paired corresponding-
source asset; they are not runtime inputs. The remaining assembly, safe strip,
ad-hoc signing, source binding, and verification procedure is recorded in
`packaging/macos/README.md`.

## Ubuntu 24.04 x86-64 runtime

The checked-in Linux entry binds runtime
`39a01ea673d024b0d6080739b5bb23c76daf0f7ed7bdb95dd1157d9dce4b627e`
to f03e. Its 9,958-byte manifest has SHA-256
`67da829d117d39d7de34afbc67dd649be24156fa9fab613aa318b438b9637f4b`.
`scripts/platform_runtime_sources.linux-x86_64.lock.json` fixes the exact six
Ubuntu binary packages and four complete Debian source sets. The public build
and ELF-closure recipes are under `packaging/linux/`; no release-only package
lock overlay is part of the contract.

This target is Ubuntu 24.04 x86-64 with glibc 2.39, not generic Linux. The
recursive audit records every host library, package version, required GLIBC/
GLIBCXX/CXXABI symbol version, missing or escaped dependency, and the explicit
absence of `_ssl`, `_hashlib`, `libssl`, and `libcrypto`.

## Windows Server 2022 x86-64 tested runtime

The Windows pipeline runs only on a real GitHub-hosted `windows-2022` runner.
That is the only verified Windows OS target at this stage; the release does
not infer a Windows 10 compatibility floor from a Server 2022 build.
It consumes the exact Project.JJ HFST and CG-3 ZIPs fixed by
`scripts/platform_runtime_sources.windows-x86_64.lock.json`, verifies their
entire path/type/CRC inventory, and targets only the three required commands
plus their recursively reached non-system DLLs. Every ordinary and delay-load
import must resolve to an adjacent manifest-bound DLL or the checked Windows
system allowlist; every retained file must be AMD64 PE. OpenSSL must not be in
that closure.

The reviewed `windows-2022` inventory run `31418211507` binds runtime bundle
`17a69ae11ff3fd92a555e8c95571223cbe8b217ec409a0b9b368f0aed90ee465`
to f03e. Its 20,697-byte manifest has SHA-256
`554a776a942e2db65ca34bb6e05e0c258976848203cbece38ababc0067d1ee46`.
The closure is three executables plus 16 DLLs (51,315,200 payload bytes), all
AMD64 PE32+; only `advapi32.dll`, `kernel32.dll`, `msvcrt.dll`, and
`user32.dll` cross the bundle boundary. This inventory is a native-runtime
input, not a ready-run release asset.

Windows cannot portably preserve a denying directory ACL through an ordinary
ZIP. Runtime provenance therefore does not reinterpret Windows `READONLY`
attributes as POSIX permissions: `sealed_read_only` remains false, the cache is
disabled, and every resource/runtime file is freshly re-hashed under the
`windows-complete-inventory-force-rehash-v1` contract. Official status still
requires the exact complete inventory, manifest, command hashes, PE closure,
and no executable override.

CPython's Windows selector cannot wait on anonymous subprocess pipes. The
productive HFST guesser consequently uses a bounded one-shot child on Windows,
with the same caller-specific input bound, strict UTF-8 and mode-specific HFST
grammar, output line/byte bounds, absolute deadline, completion status,
protocol-correlation, and cleanup gates. The one-shot command requests one
extra result as a completeness sentinel and its bounded readers always reap the
child. POSIX builds retain the faster persistent worker.

Windows ZIP extraction does not supply a portable POSIX executable bit, and
`os.access(path, os.X_OK)` is therefore evidence only. Helper availability is
proved by a regular `.exe` entry, exact manifest/hash identity, and successful
native version execution before the helper is accepted.

The ready-run ZIP is unsigned: no Authenticode publisher signature, timestamp,
or SmartScreen reputation is claimed. The release notes must say this plainly;
users may see an operating-system warning. Signing a later asset changes its
bytes and requires a new checksum and verification ledger.

## Additional platforms

Platform runtimes are never inferred from a similarly named archive. Each
additional architecture or OS needs its own native build, checked-in lock
entry, recursive dependency audit, license/source closure, two distinct-root
reproducibility builds, and fresh-extract black-box test. Absence of such an
entry means that KazStem falls back to the resource's original toolchain
contract; it is not a claim that a binary for that platform exists.
