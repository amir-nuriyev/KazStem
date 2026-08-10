# Changelog

## 0.2.2 — 2026-08-10

Native-runtime provenance release.

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
- Prunes the unused generic `hfst-lookup` executable from the ready-run Mac
  runtime while retaining `hfst-proc`, optimized generation, and CG support.
- Leaves analyzer, generator, OOV, CG, and output-format semantics unchanged.

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
