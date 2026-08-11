# macOS 15 arm64 public-release tooling

This directory builds and audits KazStem's lean, ready-to-run macOS archive and
its separately published corresponding-source archive. The target is thin
arm64 on macOS 15 or newer. The ready-run is ad-hoc signed for local integrity,
but has no Developer ID identity, TeamIdentifier, notarization, or stapled
ticket. Nothing here pushes, tags, publishes, notarizes, or changes the f03e
linguistic-resource bytes.

The checked-in Darwin release binding remains f03e-only. The bf1f productive
resource candidate must not replace it until a real macOS native build passes
the complete dependency, protocol, provenance, and practical acceptance
matrix; Linux validation is not portable evidence for that swap.

Every final action consumes one generated
`kazstem-macos-release-identity-v2` document. That document locks the exact
version, tag URL, Git commit/tree/origin, epoch, canonical wheel and sdist,
resource and Darwin runtime manifests, complete build/source closure, CPython
and PyInstaller stack, archive policies, compression tools, and every evidence
generator. A hand-written release claim is not a substitute for this file.

## What the pipeline proves

The checked tooling requires all of the following before finalization:

- two distinct, non-aliased fresh roots rebuild the canonical Python pair,
  create independent freezer environments, run PyInstaller, and assemble both
  native archives; copied launchers or copied reproduction receipts fail;
- a canonical wheel/sdist builder uses an exact offline, hash-locked wheelhouse,
  canonicalizes ZIP/tar/gzip metadata, rebuilds an adversarially retimed
  extracted sdist, and records the Python/zlib/tool identity used for byte
  comparison;
- the ready-run contains the f03e resources and only the selected Darwin
  runtime. It contains no neural weights, source archives, OpenSSL, `_ssl`,
  `_hashlib`, network/TLS/HTTP/email/URL stacks, installer, or updater; `_sha2`
  must positively provide SHA-256 and removing PyInstaller's required `zlib`
  must fail its negative control;
- every Mach-O is thin arm64 with a macOS 15 deployment floor. All non-system
  dependencies resolve inside the bundle; only `/usr/lib` and Apple frameworks
  are external boundaries. Bundle-relative rpaths must precede inherited
  absolute rpaths;
- stripped candidates are retained only when smaller and behavior,
  dependencies, deployment floor, and signature checks remain identical.
  Inner transforms are followed by bottom-up ad-hoc re-signing and strict
  verification of the complete `Python.framework` and every embedded
  framework/bundle;
- ready-run and corresponding-source compression are both measured from their
  own canonical normalized **uncompressed tar**. gzip, xz, and zstd are built
  twice, decompressed back to the exact tar/tree, and the smallest pre-declared
  eligible candidate is selected. The report states a measured component
  floor, never an unverifiable global minimum;
- hostile outer and nested archives are rejected with raw/decompressed/header,
  member, file, and aggregate caps. Traversal, absolute/Windows/device/ADS and
  non-NFC names, case collisions, duplicate names, hardlinks, devices, FIFOs,
  encryption, PAX xattrs/ACLs, AppleDouble, `__MACOSX`, unsafe symlink chains,
  and undeclared magic-recognized archives all fail;
- black-box and practical gates cover aliases/version, analysis/OOV,
  dictionary/productive generation and round trips, CG, all five formats,
  MyStem flags/envelopes/deduplication, stdin/files, CR/LF/CRLF, Unicode and
  decomposed text, emoji, malformed UTF-8, NUL/XML failures, hostile paths and
  cwd, read-only/offline use, wheel/module/API/frozen byte parity, randomized
  lossless reconstruction, large output, repetition, cleanup, startup,
  throughput, and peak RSS;
- the macOS sandbox/process gate denies network operations for every checked
  descendant and includes a denied socket negative control plus normalized,
  non-truncated trace events. Module absence alone is never called network
  isolation.

## Release ordering

The source archive stores a stable projection containing the ready-run
version, filename, and URL, but never its hash and never the source archive's
own compression-dependent name or hash. The ready-run then stores the exact
source filename, URL, byte count, and SHA-256. This is intentionally one-way.

Because the ready filename is selected by measured compression while the
ready payload binds the source archive, staging must evaluate the finite
gzip/xz/zstd filename choices and require a unique measured fixed point. Once
the canonical uncompressed tar records and winning formats are known,
`prepare_release_identity.py` generates the final identity from checked inputs.
Final assembly must reproduce those exact records from fresh roots; observation
or quarantined candidates are never final artifacts.

Run release gates only from the generated logical release workspace. Each
identity-bound gate is invoked with the exact checked Python using `-S`, exact
relative argv, fixed locale/hash seed/epoch/timezone, and a real timeout. Before
working it verifies the live interpreter, executing script bytes, clean source
commit/tree/origin, and environment. Evidence contains only logical or
bundle-relative paths; HTTPS URLs and the documented Apple system boundaries
are the only absolute references allowed.

The principal tools are:

- `prepare_release_identity.py`: derive and strictly round-trip the final
  identity from exact files and generated observations;
- `prepare_bf1f_validation.py`: verify the checked bf1f producer manifest and
  f03-only Darwin lock, then emit an external candidate lock plus the exact
  native acceptance matrix. Its receipt always records that bf1f is disabled;
- `build_frozen_runtime.py`: create and minimize one fresh PyInstaller tree,
  re-sign frameworks/bundles, and emit its full module/native ledger;
- `assemble_corresponding_source.py` and `assemble_ready_run.py`: create the
  canonical tar and identity-selected container without overwriting outputs;
- `compare_compression.py`: measure gzip/xz/zstd twice for both canonical tars;
- `audit_corresponding_source_archive.py` and
  `audit_ready_run_archive.py`: hostile fresh-extraction and closure audits;
- `verify_python_reproducibility.py`: coordinate independent canonical Python,
  freezer, source, and ready-run builds with per-root receipts;
- `audit_macho_closure.py`, `audit_module_native_inclusion.py`,
  `blackbox_macos_bundle.py`, `practical_matrix_macos.py`, and
  `verify_offline_processes.py`: native, minimization, behavior, performance,
  and offline evidence;
- `finalize_release.py`: recompute every identity, artifact, receipt, evidence,
  archive, and co-publication binding and write the final ledger plus
  `SHA256SUMS` only after every gate passes.

The corresponding-source payload must include the exact Git archive; all
Project.JJ/HFST/CG/foma/OpenFst/readline/ICU/ncurses/SQLite/zlib inputs;
CPython, PyInstaller, hooks, and build-stack wheels plus preferred source,
recipes, patches, licenses, and notices. OpenSSL source is deliberately absent
because the binary and native-dependency audits must prove that no OpenSSL
code is distributed.

The 33 MiB ICU data library remains unless a separately reproducible ICU build
and the complete release behavior matrix prove a smaller candidate equivalent.
Finite Kazakh fixtures do not justify claiming arbitrary Unicode coverage for a
filtered ICU image.

## bf1f Darwin candidate

`bf1f-validation-matrix.json` fixes the only proposed lock change and the
native behavior, closure, provenance, offline, performance, reproduction, and
source gates required before review. The preparation tool refuses to write
inside the repository, requires the tracked Darwin entry to remain exactly
f03-only, and emits a candidate whose sole semantic lock change replaces that
one resource ID while retaining runtime `5341c48b…` byte-for-byte. The output
is deliberately not a release input and cannot certify native validation.

Only evidence from a real macOS 15 arm64 build may unblock the tracked swap.
The candidate must rebuild the wheel and frozen runtime in independent roots,
run every matrix case without skips, and reproduce all archive and evidence
identities. Ubuntu bf1f results do not satisfy any Darwin gate.
