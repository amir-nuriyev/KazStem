# `kazstem-macos-release-identity-v2`

`release_common.load_identity()` is the normative validator. It rejects
duplicate JSON keys, missing or extra fields, unbounded values, unsafe paths,
case collisions, non-HTTPS publication URLs, unsupported tools, incomplete
source/build closure, stale gate inventories, and identities that do not name
macOS 15 thin arm64.

## Identity sections

- `release`, `source_commit`, `source_tree`, `source_origin`,
  `source_date_epoch`, and `release_url` bind the exact public tag and Git tree.
- `platform` is exactly Darwin/arm64, records the filename-safe target label and
  macOS 15.0 floor, and states that the asset is unsigned by a developer and
  not notarized.
- `artifacts` binds wheel, sdist, ready-run, and corresponding source by exact
  filename, byte count, SHA-256, and same-release GitHub download URL.
- `inputs` binds the frozen/resource/runtime/source-payload trees; manifests and
  runtime IDs; canonical Git archive; templates; unified/runtime-source locks;
  documents; complete canonical/freezer source closure; offline freezer
  wheelhouse and requirements; freezer spec; and the exact Mac freezer CPython.
- `ready_run` defines the stable root, launcher and aliases, platform lock,
  bundle destinations, permitted removals, required paths, and banned names.
- `corresponding_source` defines distinct application/resource/runtime/freezer/
  build/license/evidence roots, Git identity markers, required paths, and a
  complete exact nested-archive inventory.
- `archive_limits` supplies independently bounded ready, source, and nested
  policies below immutable implementation ceilings.
- `compression` binds each canonical uncompressed tar and its checked producer,
  the exact gzip/xz/zstd tools and argv, compatibility decisions made before
  size comparison, the measured selected format, and the
  `smallest-eligible-byte-identical` rule. Artifact suffixes are derived from
  that selection, not hard-coded to xz.
- `mach_o` binds thin arm64, macOS system boundaries, runtime manifest, exact
  rpath policy, and ad-hoc/no-team/no-notarization signature policy.
- `minimization` binds required and banned modules/native fragments, negative
  controls, measured compression candidates, strip acceptance, and the honest
  `measured-candidates-component-floor` claim scope.
- `verification` binds the immutable Linux canonical-Python authority (checked
  shared builder/supervisor/Linux validator, exact Linux identity and v2
  evidence hashes, tag object, interpreter source and source companions), the
  two Mac freezer/native roots, freezer commands, environment/tool executables,
  sandbox policy, and exact evidence gate set. Every generator includes the
  checked script record, full logical argv/cwd, commit/tree, environment, tool,
  subjects, and timeout.

Tree identities are canonical SHA-256 hashes over sorted relative paths, entry
kinds, modes, regular-file bytes/hashes, and symlink targets. `tree_record()` and
`file_record()` generate them; release configuration must not copy them from a
previous version.

## Non-circular publication binding

The source archive's `SOURCE-IDENTITY.json` is a stable v2 projection. It
contains the exact ready-run filename and URL plus canonical Python/source
identity, but it contains neither native archive hash and does not contain the
source archive's own compression-dependent name. The ready-run's
`CORRESPONDING-SOURCE.json` binds the final source filename, URL, bytes, and
SHA-256. Therefore:

1. canonical Python artifacts and all source/binary inputs are sealed;
2. the checked staging tool evaluates ready filename choices, builds the source
   canonical tar, measures source compression, then builds the ready canonical
   tar with the exact selected source record;
3. gzip/xz/zstd measurements must yield a unique eligible fixed point for the
   ready filename; ambiguity or instability fails;
4. the final identity is generated with both raw tar records and both selected
   compressed artifact records;
5. Linux proves the canonical Python pair in at least three fresh roots; two
   genuinely independent Mac roots consume that pair and reproduce the freezer
   tree, canonical tars, and compressed native assets byte-for-byte.

Canonical Python ZIP byte identity is scoped to the exact identity-bound
Python and zlib implementation. A platform receipt with different zlib may be
used only for normalized content/metadata parity, never as evidence of ZIP byte
identity. macOS does not claim compressed wheel byte reproduction under a
different interpreter/zlib identity; it verifies and consumes the exact
Linux-authoritative bytes.

## Archive and evidence rules

Assemblers reject existing outputs/workspaces, nested or aliased output and
observation paths, hardlinks, input collisions, unresolved templates, and
unexpected overlays. They normalize uid/gid, modes, order, timestamps, and
container headers. PAX xattrs/ACLs, AppleDouble, and `__MACOSX` never enter the
archive. A fresh extraction may observe only OS-managed
`com.apple.provenance`. macOS may also attach that one protected attribute to
working inputs; it is ignored for content identity because it cannot be removed
reliably, while every other xattr is rejected. Fresh-extract provenance is
recorded as an observation, and no xattr is ever treated as archive content.

Evidence files use `kazstem-release-gate-envelope-v1`. The stable
`identity_contract_sha256` excludes only the final evidence files' own byte/hash
records while retaining their paths, types, subjects, and complete generator
contracts. The finalizer loads every exact schema, scans decoded JSON keys and
values plus text for absolute build paths, recomputes all artifact/evidence/
receipt hashes, matches every reproduction root to one unique receipt, rejects
extra root files or inode aliases, and records the full finalized identity and
every evidence identity in its ledger.

Final artifact directories contain only the canonical wheel, canonical sdist,
selected ready-run archive, selected corresponding-source archive, and the
generated `SHA256SUMS`. The tooling never turns a mismatched observation into a
passing or publishable artifact.
