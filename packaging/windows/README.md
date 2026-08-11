# Windows x86-64 ready-run recipe

KazStem's Windows 0.2.3 asset is built and tested only on a real GitHub-hosted
`windows-2022` runner. Cross-compiled or Wine-only results are not release
evidence.
The bootstrap therefore records Windows Server 2022 build 10.0.20348 as the
tested floor and does not claim Windows 10 validation.

The checked-in Windows binding remains f03e-only. bf1f productive generation
is pending a real `windows-2022` build, complete PE audit, one-shot protocol
suite, and practical behavior matrix; it is not inferred from Linux evidence.

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

## Final ready-run tooling

The scripts in this directory implement the final candidate gate, but they do
not publish anything. `.github/workflows/windows-final-release-candidate.yml`
is intentionally read-only and currently runs only the source-side contract
suite. It has no permission to create a tag, release, package, or public asset.

The final run starts only from the immutable `refs/tags/v0.2.3` ref and its
exact commit, tree, and public origin. `materialize_git_source.py` must create
two absent, mutually non-aliased roots. It emits one deterministic canonical
Git-archive receipt plus a different live execution receipt for each root.
The latter binds the checked command and tools and verifies the actual root
object; published evidence retains logical labels and the non-alias result,
not host-specific inode numbers.

No Python release tool is launched directly from the checkout. The runner's
Git-only seed step first creates a fresh, fully inventoried materialization;
all subsequent tools, including `materialize_git_source.py`, enter through
`release_bootstrap.py`. The exact interpreter prefix is `-I -B -X
pycache_prefix=<fresh-external-root>`. The bootstrap requires that cache root
to be absent and outside the protected source, rejects every adjacent
`__pycache__` directory and `*.pyc`, `*.pyo`, or `*.pyd` file before importing
any project module, verifies the complete source-tree identity and live v2
materialization receipts, and checks both source and cache again after the
tool exits. `-B` is not treated as sufficient: Python can still read an
existing unchecked-hash bytecode file. The bootstrap, common verifier,
process supervisor, path auditor, and source-suite runner are one hash-bound
support bundle in every generator contract.

`build_python_freezer.py` is the Windows orchestration layer. Its freezer
wheelhouse is tree-hashed, copied into corresponding source, and installed
with `--no-index`, an exact `--find-links`, `--require-hashes`, binary-only,
and no-dependency resolution. The CPython executable is bound by its complete
file hash and AMD64 PE32+ identity. The selected optimization JSON is bound by
its exact bytes. Windows does not regenerate the canonical wheel or sdist. It
loads the exact checked `packaging/build_canonical_python_artifacts.py`
validator, verifies the v2 identity and Linux execution receipt, and copies
that exact pair into each independent freezer root.

Wheel ZIP bytes depend on the compressor implementation. The canonical wheel
and sdist therefore come from one fixed, hash-bound build environment. A
Windows receipts explicitly state `windows_rebuild_performed=false`; they must
never describe different cross-zlib compressed bytes as reproducible. The
validated Linux receipt proves the independent, adversarially retimed sdist
roundtrip and exact wheel/sdist equality. Windows evidence separately proves
two independent PyInstaller builds consumed those exact artifact bytes.

Optimization is measured on the downloadable result. Each distinct PyInstaller
configuration is assembled twice by `assemble_optimization_candidate.py` in
independent roots. `select_optimization_candidate.py` requires byte-identical,
canonical ZIPs for each candidate, behavior-equivalent practical matrices,
and a separate full rerun of the selected candidate. It selects by final ZIP
bytes (then deterministic hash/tree/name tie-breaks), reports raw frozen-tree
bytes separately, and requires the selected ZIP to equal the final ready-run
artifact identity. Python `-O` and UPX are forbidden.

The final evidence set is generated only by the exact bootstrap and script
hashes, logical argument vectors (including the isolated external-cache
prefix), controlled environments, Python executable bytes, fresh source
materialization identity, source commit/tree/origin/tag, and per-gate coverage
frozen in the release identity.
It contains these gates:

1. two independent Python/freezer builds and the third-root sdist roundtrip;
2. two deterministic final ready-run and corresponding-source ZIP assemblies;
3. physical and logical archive closure, normalized metadata, checksums, and
   magic-driven inspection of every nested source archive;
4. all five output formats, OOV guessing, Constraint Grammar, generation,
   Unicode/CRLF/NUL/CP1251/malformed input, hostile paths, read-only/offline
   use, aliases, module CLI, and Python API parity;
5. missing and PATH-substituted DLL/helper denial, forced provenance rehash,
   successful-run cleanup, and forced-timeout process-tree cleanup;
6. suspended child creation, Job assignment before resume, bounded capture,
   and `ActiveProcesses == 0` on success, timeout, overflow, reader failure,
   and assignment failure; a surviving descendant is reaped and fails the run;
7. offline installation of the exact canonical wheel into a fresh non-aliased
   target, identical current/isolated-child imports, and recomputable hashes of
   every discovered, run, skipped, expected-failure, and unexpected test ID;
8. rejection of ambient `GIT_*`, `LD_*`, `DYLD_*`, and `GLIBC_TUNABLES`, an
   identity-bound Git executable under a minimal environment, and runtime hash
   verification of every transitive release helper; Git additionally uses
   `GIT_NO_REPLACE_OBJECTS=1`, disables fsmonitor and the untracked cache with
   checked `-c` arguments, and cannot inherit work-tree/object-directory
   redirections;
9. repeated deterministic large outputs, startup timing, process-tree peak
   working set, and explicit performance thresholds;
10. every PE's native Authenticode status plus the unsigned/SmartScreen notice;
11. exact source closure, licenses and URLs, with OpenSSL, network/TLS modules,
   neural assets, source archives, and installers absent from the ready-run.

`finalize_release.py` is fail-closed: it verifies all live roots and receipts,
reassembles both public ZIPs, compares their bytes, validates every strict
evidence envelope, and writes `FINALIZATION.json` with
`publishing_performed: false`. Uploading assets is a separate, reviewable step
outside this tooling.
