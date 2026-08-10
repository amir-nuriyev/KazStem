# Parameterized Linux release identity

Every final Linux release tool consumes the same UTF-8 JSON object with schema
`kazstem-linux-release-identity-v1`. `release_common.load_identity()` rejects
duplicate JSON keys, missing or extra fields, non-canonical paths, Windows ADS
names, case-insensitive path collisions, non-HTTPS URLs, URL queries or
fragments, non-canonical artifact names, and unsafe or unbounded archive caps.
There are no release-version, commit, build-root, temporary-path, artifact-size,
or artifact-hash constants in the tools.

The identity has these exact top-level sections:

- `release`, `source_commit`, `source_date_epoch`, and `release_url` identify
  the tag. `release_url` is the exact public GitHub URL ending in
  `/releases/tag/v<release>`.
- `platform` records `linux`, `x86_64`, a filename-safe label, the truthful
  advertised Ubuntu target, and `generic_linux: false`.
- `artifacts` binds the wheel, sdist, ready-run archive, and corresponding
  source with exact filename, bytes, SHA-256, and release-download URL. Every
  URL is derived from the tag as `/download/v<release>/<filename>`.
- `inputs` binds the complete frozen, resource, runtime, and source-payload
  trees; the two bundle manifests and IDs; the base freezer ledger; both
  README templates; and every public document copied into the binary.
- `ready_run` declares the top-level archive name, launcher, checked-in unified
  platform lock, bundle destinations, aliases, the exact frozen files that may
  be removed, required output paths, and case-folded banned filename fragments.
- `corresponding_source` declares its top level, relative evidence root, exact
  commit/epoch marker files, distinct required category roots for application,
  linguistic resources, native runtime, freezer, build inputs, licenses, and
  evidence, plus every nested tar, zip/wheel, Debian archive, or standalone
  gzip stream with its exact identity and format.
- `archive_limits` independently caps member count, single-file bytes, total
  declared bytes, and UTF-8 path length for the binary, source, and nested
  archives. The implementation also imposes hard ceilings that an identity
  cannot raise.
- `verification` requires at least two distinct build roots and checksum-binds
  each typed evidence gate. The exact gate set is ready/source archive audit,
  black box, practical matrix, compatibility performance, ELF closure, runtime
  provenance, source suite, network trace, three-way Python reproducibility,
  compression comparison, and optimization ledger; omitting or duplicating a
  gate invalidates the identity.

Tree records are canonical hashes over sorted paths, entry kinds, POSIX modes,
regular-file bytes and hashes, and symlink targets. Use
`release_common.tree_record(path)` and `release_common.file_record(path)` to
calculate candidate input records. A final identity must be reviewed and
committed; an unchecked, release-only runtime-lock overlay is invalid.

## Hash bootstrapping without self-reference

The corresponding-source archive embeds a stable `SOURCE-IDENTITY.json`
projection. It includes artifact filenames and exact URLs but deliberately
does not embed either native archive's own byte count or hash. The ready-run
embeds the already-sealed source record but not its own record. This ordering
removes an impossible self-hash cycle:

1. Assemble source once with `--observation candidate-source.json`. A mismatch
   remains an explicit failure; the observation is only the measured record.
2. Put that exact record into `artifacts.corresponding_source`, then reproduce
   the source archive from a new root.
3. Assemble the ready-run once with `--observation candidate-ready.json`, bind
   its measured record, and reproduce both archives from two clean roots.
4. Run both fresh-extraction auditors. Their
   `identity_contract_sha256` excludes only the evidence files' own byte/hash
   records, while retaining their paths, gate names, and kinds, so adding the exact
   audit hashes to `verification.evidence` does not change the reports.
5. Rerun the auditors against the final identity and require byte-identical
   reports before finalization.

Generate the mandatory canonical Python reproducibility gate with
`verify_python_reproducibility.py`: pass three independently built directories
containing the exact wheel and sdist plus the wheel rebuilt from the canonical
sdist. The report contains only logical build labels and exact artifact records.

Observation output never turns a mismatch into success. A mismatched output is
renamed with an `.unsealed-<hash-prefix>` suffix, so no final-named candidate is
left behind. It must not be copied to a public artifact directory.

## Deterministic assembly and auditing

The source companion is built first:

```sh
python3 packaging/linux/assemble_corresponding_source.py \
  --identity RELEASE-IDENTITY.json \
  --payload SOURCE-PAYLOAD \
  --source-readme-template packaging/linux/CORRESPONDING-SOURCE-README.template.md \
  --wheel DIST/kazstem-VERSION-py3-none-any.whl \
  --sdist DIST/kazstem-VERSION.tar.gz \
  --work-root BUILD-A/source-work \
  --output BUILD-A/kazstem-VERSION-PLATFORM-corresponding-source.tar.xz
```

Then assemble the ready-run with the exact source archive:

```sh
python3 packaging/linux/assemble_ready_run.py \
  --identity RELEASE-IDENTITY.json \
  --frozen FROZEN-TREE --resources RESOURCE-TREE --runtime RUNTIME-TREE \
  --documents SOURCE-CHECKOUT \
  --binary-readme-template packaging/linux/BINARY-README.template.md \
  --base-ledger FREEZER-LEDGER.json \
  --wheel DIST/kazstem-VERSION-py3-none-any.whl \
  --sdist DIST/kazstem-VERSION.tar.gz \
  --corresponding-source BUILD-A/kazstem-VERSION-PLATFORM-corresponding-source.tar.xz \
  --work-root BUILD-A/ready-work \
  --output BUILD-A/kazstem-VERSION-PLATFORM-ready-run.tar.xz
```

Both assemblers reject pre-existing work roots and outputs, verify every input
tree/file byte and hash, write sorted internal manifests and checksums, seal
modes/timestamps, and create deterministic xz archives with normalized names,
owners, modes, order, and `SOURCE_DATE_EPOCH`.

Audit only into nonexistent fresh roots:

```sh
python3 packaging/linux/audit_ready_run_archive.py READY.tar.xz \
  --identity RELEASE-IDENTITY.json --fresh-root EXTRACT/ready \
  --output EVIDENCE/ready-audit.json
python3 packaging/linux/audit_corresponding_source_archive.py SOURCE.tar.xz \
  --identity RELEASE-IDENTITY.json --fresh-root EXTRACT/source \
  --output EVIDENCE/source-audit.json
```

The auditors reject traversal, duplicate and Unicode/case-colliding names,
ADS/device names, escaping links, hardlinks and other special entries, cap
violations, incomplete internal checksum/manifests, undeclared nested archives,
unsafe nested tar/zip/Debian contents, artifact identity mismatches, source
omissions, and absolute build paths in evidence.

Run `benchmark_compat_linux.py` plus the checked black-box, practical, ELF,
runtime-provenance, and source-suite gates. Normalize the raw backend runtime
report with `normalize_runtime_provenance.py`; it verifies the selected runtime,
resource binding, manifest, and executables, converts only paths below the
extracted ready-run to the `bundle/` namespace, and rejects every outside path.
The ELF closure gate likewise emits logical `ubuntu-host/<soname>` locations
instead of build-machine paths. After binding the exact evidence
hashes, finalize a clean directory containing only the four artifacts:

```sh
python3 packaging/linux/finalize_release.py \
  --identity RELEASE-IDENTITY.json \
  --artifacts FINAL-ARTIFACTS --evidence FINAL-EVIDENCE \
  --repro-root BUILD-A --repro-root BUILD-B \
  --output FINAL-EVIDENCE/final-linux-release.json
```

The finalizer re-verifies all bytes, hashes, embedded source URL, safe archive
envelopes, exact evidence, and distinct-root identity. It adds only the global
`SHA256SUMS`; the final artifact directory must then contain the wheel, sdist,
ready-run, corresponding-source archive, and that checksum file.
