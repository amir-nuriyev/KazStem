# Windows x86-64 ready-run recipe

KazStem's Windows 0.2.3 asset is built and tested only on a real GitHub-hosted
`windows-2022` runner. Cross-compiled or Wine-only results are not release
evidence.
The bootstrap therefore records Windows Server 2022 build 10.0.20348 as the
tested floor and does not claim Windows 10 validation.

The exact Project.JJ binary inputs and complete corresponding-source set are
bound by `scripts/platform_runtime_sources.windows-x86_64.lock.json`.
`build_runtime.py` validates every ZIP path, type, CRC, size, and digest;
requires duplicate DLLs to be byte-identical; copies only three commands plus
their recursively reached DLLs; executes the command version probes; binds the
ordinary and delay-load PE graph into the runtime manifest; and emits a
proposed unified package lock. The proposal is a bootstrap artifact, not a
release. Run `31418211507` produced the independently audited runtime now bound
by the checked package lock: bundle
`17a69ae11ff3fd92a555e8c95571223cbe8b217ec409a0b9b368f0aed90ee465`,
with a 20,697-byte manifest whose SHA-256 is
`554a776a942e2db65ca34bb6e05e0c258976848203cbece38ababc0067d1ee46`.
Any native input, recipe, or manifest-contract change requires a new proposal,
review, and checked lock identity before a ready-run archive is built.

The audited native closure is deliberately flat under `usr/bin`, so Windows
can resolve every non-system DLL beside the exact helper executable. The
pipeline targets the three required commands and their smallest recursively
reachable AMD64 DLL set. The bound runtime contains three executables and 16
DLLs (51,315,200 payload bytes); all are AMD64 PE32+, and its only unbundled
imports are `advapi32.dll`, `kernel32.dll`, `msvcrt.dll`, and `user32.dll`.
There are no symlinks, installers, registry changes, services,
administrator requirements, neural weights, network clients, or OpenSSL.

Run the private inventory workflow first:

```text
.github/workflows/windows-runtime-inventory.yml
```

The workflow has `contents: read`, persists no checkout credentials, and can
only upload a seven-day Actions artifact. It checks out the exact pull-request
head, requires every platform source/runtime lock to be LF-only and byte-equal
to `git show HEAD:path`, and records the candidate SHA, hosted-image identity,
Windows host details, and CPython identity without machine-local paths. It then
downloads locked inputs, runs source-side path/PE/seal tests, builds in two
distinct non-aliased roots, requires exact runtime and proposed-lock equality,
rejects absolute runner paths in all textual evidence, and uploads the
candidate runtime plus proposed lock for review. It never creates a tag or
GitHub release.

With the Windows entry checked in, rebuild the one canonical 0.2.3 wheel and
sdist, then rebuild Mac, Linux, and Windows from that same source identity.
The Windows frozen launcher uses CPython 3.14.3, PyInstaller 6.22.0, and the
checked `kazstem-minimal.spec`. The final release workflow must perform two
from-scratch builds in distinct roots and require byte-identical normalized
ZIP hashes.

A fresh extraction outside the checkout must prove:

1. `platform.machine()` and `AMD64` normalize to `x86_64`;
2. all three native helpers are regular `.exe` files, match the manifest hash,
   and actually execute their version probes without modifying `PATH`,
   installing software, or requiring elevation; `os.access(path, os.X_OK)` is
   recorded truthfully but is not treated as a Windows execution permission;
3. the manifest-bound DLL closure resolves beside the helpers, with no missing,
   ambiguous, PATH-sourced, non-AMD64, or unallowlisted import;
4. the complete-inventory/forced-rehash Windows integrity contract reports
   verified provenance while truthfully retaining `sealed_read_only=false`;
5. MyStem text/JSON/XML envelopes, lossless JSONL, OOV, CG, generation, Unicode,
   CRLF, literal NUL, CP1251, malformed encodings, hostile file paths, and
   cleanup/no-lingering-process cases pass;
6. repeated large practical workloads are deterministic and record timing and
   peak working set without overstating cross-language performance;
7. no `_ssl`, `_hashlib`, `libssl`, `libcrypto`, OpenSSL source, neural weight,
   updater, or network client is present;
8. every executable/DLL is checked for Authenticode status and the published
   notes say the archive is unsigned and may trigger SmartScreen.

Corresponding source is a separate checksum-bound asset. The minimized binary
ZIP must not embed the Project.JJ ZIPs, compiler sources, CPython source,
PyInstaller sources, or other build archives.
