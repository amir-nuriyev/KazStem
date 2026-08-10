# Changelog

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
