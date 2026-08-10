# Changelog

## 0.2.3 — 2026-08-10

Unified native-runtime and Windows portability release.

- Checks the audited macOS arm64 and Ubuntu 24.04 x86-64 runtime identities
  into one package-data lock; release-only lock overlays are forbidden.
- Adds the complete checked-in Ubuntu minimal-runtime recipe, exact binary and
  corresponding-source lock, PyInstaller spec, and recursive ELF audit.
- Adds a real Windows x86-64 runtime pipeline for `windows-2022`, using exact
  Project.JJ inputs and targeting the smallest proven PE closure with no
  OpenSSL; the audited closure is bound at three executables plus 16 DLLs.
- Statically validates every regular and delay-load PE import, rejects missing,
  unreachable, non-AMD64, ambiguous, or unsafe runtime entries, and binds the
  closure into the content-addressed runtime manifest.
- Uses complete inventory plus forced fresh hashes on Windows, where ZIPs do
  not portably preserve POSIX directory modes; `sealed_read_only` remains
  truthful instead of being inferred from synthetic mode bits.
- Falls back to bounded one-shot HFST guessing on Windows because CPython's
  Windows selector cannot wait on anonymous subprocess pipes; POSIX retains
  the faster persistent worker.
- Requires two from-scratch, distinct-root native builds per platform to
  produce byte-identical archives and bundle-relative verification evidence.
- Documents unsigned/AuthentiCode and SmartScreen status explicitly and keeps
  corresponding source separate from the minimized ready-run archive.

- Adds a checked-in platform/runtime lock that binds the macOS arm64 helper
  manifest to the exact f03e resource bundle.
- Selects detached runtimes only from the resource bundle's own
  content-addressed root and fails closed on platform, resource, manifest,
  bundle, inventory, or read-only-seal mismatch.
- Reports the original Ubuntu toolchain that built f03e separately from the
  active platform runtime without changing any f03e resource byte.
- Adds deterministic platform-runtime manifest/source locks, license inventory,
  and macOS dynamic-loader injection diagnostics.
- Keeps XML escaping byte-compatible while avoiding the unused networking and
  TLS dependency tree pulled in by Python's general-purpose SAX utilities.
- Matches the empirically audited MyStem 3.1 JSON member and XML element/
  attribute order for the documented compatibility envelopes.
- Stable-deduplicates rows that become identical only after the deliberately
  lossy MyStem text/JSON/XML projection; the Python API and JSONL continue to
  retain every distinct raw finite-state reading.
- Prunes the unused generic `hfst-lookup` executable from the ready-run Mac
  runtime while retaining `hfst-proc`, optimized generation, and CG support.
- Leaves the analyzer lattice, generator, OOV, and CG morphology unchanged;
  only the documented MyStem-compatible presentation is tightened as above.
- Supersedes the private, unpublished 0.2.2 native-runtime candidates; no
  public 0.2.2 release or artifact is part of the release history.

## 0.2.1 — 2026-08-10

Packaging-only patch release.

- Removes an invalid PyPI Trove classifier rejected during the first trusted
  publishing attempt.
- Adds release-asset checksum and embedded name/version validation to the PyPI
  trusted-publishing workflow.
- Leaves the analyzer, generator, resource contract, and reported evaluation
  results unchanged from 0.2.0.

## 0.2.0 — 2026-08-10

First public KazStem release.

- Adds the `kazstem` command while preserving `qazmorph` and `mystem-kz`.
- Preserves complete finite-state candidates, raw tags, morphemes, offsets, and
  provenance through the Python API and lossless JSONL v2 format.
- Separates atomic consuming tokens from overlapping dictionary phrase spans.
- Adds formally finite and bounded productive OOV analysis for eligible Kazakh
  noun, adjective, and verb stems.
- Adds candidate-constrained Constraint Grammar and optional neural ranking.
- Adds MyStem-shaped text, JSON, and XML plus CoNLL-U output.
- Adds exact resource/toolchain manifests, read-only sealing, runtime rehashing,
  and fail-closed lookup framing.
- Publishes reproducible evaluation and performance methodology and results.

Known limitations are documented in `README.md` and
`docs/MYSTEM_COMPATIBILITY.md`; this release does not claim byte-for-byte
MyStem emulation or universal linguistic correctness.
