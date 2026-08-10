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
- Trusts the historical finiteness-v1 proof only for the exact content-addressed
  f03e resource bundle. Unknown but well-formed v1 bundles remain available for
  nonproductive, nonofficial dictionary rollback; malformed proofs are rejected.
- Enforces strict UTF-8 and the exact standard/optimized HFST response grammars,
  preserves complete-versus-incomplete lookup outcomes in the cache, drains
  delayed blank separators, and applies one deadline across lock waits, writes,
  reads, the bounded retry, and response validation.
- Validates dictionary-generation lemmas, structured tag containers, encoded
  4,096-byte request bounds, positive integer limits, and finite timeouts before
  launching a helper.
- Loads the sealed bf1 resource-manifest v4 bundle, including its stronger
  finiteness-v2 guesser proof and finite productive-generator exact inverse,
  while retaining f03e as the pinned analysis-only rollback.
- Adds noun-only high-vowel syncope, the literal `*кубок` back-harmony
  family, forbidden generic-loan probes, and root-diverse bounded ranking.
- Adds explicit dictionary-first `productive=True` generation with strict wire
  grammar, one total deadline, hard response bounds, and public-lattice
  roundtrip validation.
- Preserves bf1f's exact resource-producer inputs separately from successor
  runtime consumer source and verifies that corresponding-source snapshot
  fail-closed.
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
- Leaves dictionary and CG morphology unchanged; MyStem-compatible presentation
  changes remain limited to the documented envelopes above, while the bounded
  productive additions are explicitly listed separately.
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
