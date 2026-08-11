# Parameterized Linux release identity

Every final Linux release tool consumes the same UTF-8 JSON object with schema
`kazstem-linux-release-identity-v2`. `release_common.load_identity()` rejects
duplicate JSON keys, missing or extra fields, non-canonical paths, Windows ADS
names, case-insensitive path collisions, non-HTTPS URLs, URL queries or
fragments, non-canonical artifact names, and unsafe or unbounded archive caps.
There are no release-version, commit, build-root, temporary-path, artifact-size,
or artifact-hash constants in the tools.

The identity has these exact top-level sections:

- `release`, `source_commit`, `source_tag_object`, `source_tree`, `source_origin`, `source_ref`,
  `source_date_epoch`, and `release_url` identify the source. The commit must be
  the exact object at the immutable `refs/tags/v<release>` ref, its tree must
  match, and the HTTPS origin must correspond to the public release URL.
- `platform` records `linux`, `x86_64`, a filename-safe label, the truthful
  advertised Ubuntu target, and `generic_linux: false`.
- `artifacts` binds the wheel, sdist, ready-run archive, and corresponding
  source with exact filename, bytes, SHA-256, and release-download URL. Every
  URL is derived from the tag as `/download/v<release>/<filename>`.
- `inputs` binds the complete frozen, resource, runtime, and supplemental
  source-payload trees; the two bundle manifests and IDs; the base freezer
  ledger; both README templates; every public document copied into the binary;
  and the exact bytes, command, prefix, and Git version for `git archive`.
- `ready_run` declares the top-level archive name, launcher, checked-in unified
  platform lock, bundle destinations, aliases, the exact frozen files that may
  be removed, required output paths, the one exact embedded canonical wheel,
  and case-folded banned filename fragments. Every other nested archive remains
  forbidden in the binary asset.
- `corresponding_source` declares its top level, relative evidence root, exact
  commit/epoch marker files, distinct required category roots for application,
  linguistic resources, native runtime, freezer, build inputs, licenses, and
  evidence, plus every nested tar, zip/wheel, Debian archive, or standalone
  gzip stream with its exact identity and format.
- `archive_limits` independently caps member count, single-file bytes, total
  declared bytes, and UTF-8 path length for the binary, source, and nested
  archives. The implementation also imposes hard ceilings that an identity
  cannot raise.
- `verification` pins the shared canonical-Python v2 identity, its offline
  wheelhouse/requirements and explicitly scoped CPython/provider byte-input
  and source records (not an ambient system-DSO closure), plus a
  distinct hash-locked freezer wheelhouse, source archives, extracted licenses,
  clean-root frozen-launcher commands that consume the just-built wheel, root-local
  native assembler scripts,
  tool binaries/versions, environment, compression candidates, bounded `strace -f`
  network policy, and every gate's exact argv, source cwd/tree, script and
  generator hashes, timeout, payload schema, artifact subjects, and evidence
  bytes. On Linux each envelope additionally records the systemd user-slice
  `TasksMax`/`pids.max` value, successful `cgroup.kill`, and observed
  `cgroup.events` `populated=0` cleanup. The exact gate set is ready/source archive audit,
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
   its measured record, and reproduce both archives from three fresh roots.
4. Run both fresh-extraction auditors. Their
   `identity_contract_sha256` excludes only the evidence files' own byte/hash
   records, while retaining paths, gates, subjects, kinds, and execution contracts, so adding the exact
   audit hashes to `verification.evidence` does not change the reports.
5. Rerun the auditors against the final identity and require byte-identical
   reports before finalization.

Generate the reproducibility gate with `verify_python_reproducibility.py`. It
creates its own three non-local/non-hardlinked clones, checks out the exact
release tag, invokes the shared canonical builder in each root, provisions its
hash-locked wheelhouse twice without an index, adversarially retimes and
rebuilds from the canonical sdist, and requires exact wheel/sdist bytes. Each
fresh freezer consumes that wheel. Each clone's checked source/ready assembler
and `release_common.py` then produce both native archives plus real A/B raw-tar
producer receipts. Stale, copied, hardlinked, nested, or aliased outputs fail.

```sh
python3 packaging/linux/verify_python_reproducibility.py \
  --identity RELEASE-IDENTITY.json --repository SOURCE-CHECKOUT \
  --canonical-artifacts FINAL-PYTHON \
  --python-build-identity PYTHON-BUILD-IDENTITY.json \
  --python-wheelhouse OFFLINE-WHEELHOUSE \
  --python-freezer-wheelhouse OFFLINE-FREEZER-WHEELHOUSE \
  --python-interpreter-source Python-X.Y.Z.tgz \
  --payload SUPPLEMENTAL-SOURCE \
  --resources RESOURCE-TREE --runtime RUNTIME-TREE --documents SOURCE-CHECKOUT \
  --binary-readme-template packaging/linux/BINARY-README.template.md \
  --source-readme-template packaging/linux/CORRESPONDING-SOURCE-README.template.md \
  --base-ledger FREEZER-LEDGER.json --workspace FRESH-WORKSPACE \
  --output EVIDENCE/python-reproducibility-payload.json
```

Observation output never turns a mismatch into success. A mismatched output is
renamed with an `.unsealed-<hash-prefix>` suffix, so no final-named candidate is
left behind. It must not be copied to a public artifact directory.

## Deterministic assembly and auditing

The source companion is built first:

```sh
python3 packaging/linux/assemble_corresponding_source.py \
  --identity RELEASE-IDENTITY.json \
  --repository SOURCE-CHECKOUT \
  --payload SOURCE-PAYLOAD \
  --source-readme-template packaging/linux/CORRESPONDING-SOURCE-README.template.md \
  --wheel DIST/kazstem-VERSION-py3-none-any.whl \
  --sdist DIST/kazstem-VERSION.tar.gz \
  --work-root BUILD-A/source-work \
  --output BUILD-A/kazstem-VERSION-PLATFORM-corresponding-source.tar.xz \
  --raw-tar-output BUILD-A/canonical/kazstem-VERSION-PLATFORM-corresponding-source.tar \
  --producer-receipt BUILD-A/producer-receipts/corresponding-source-tar-producer.json
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
  --output BUILD-A/kazstem-VERSION-PLATFORM-ready-run.tar.xz \
  --raw-tar-output BUILD-A/canonical/kazstem-VERSION-PLATFORM-ready-run.tar \
  --producer-receipt BUILD-A/producer-receipts/ready-run-tar-producer.json
```

Both assemblers reject pre-existing work roots and outputs, verify every input
tree/file byte and hash, write sorted internal manifests and checksums, seal
modes/timestamps, and create the selected gzip or xz container from a
normalized canonical tar. The raw tar is independently produced twice; exact A/B
hashes, normalized tree, tagged script/common bytes, argv, environment,
Python tool, selected compression, and final container are receipt-bound.

Audit only into nonexistent fresh roots:

```sh
python3 packaging/linux/audit_ready_run_archive.py READY.tar.xz \
  --identity RELEASE-IDENTITY.json --fresh-root EXTRACT/ready \
  --output EVIDENCE/ready-audit.json
python3 packaging/linux/audit_corresponding_source_archive.py SOURCE.tar.xz \
  --identity RELEASE-IDENTITY.json --fresh-root EXTRACT/source \
  --output EVIDENCE/source-audit.json
```

The auditors reject traversal, duplicate, ancestor, and Unicode/case-colliding names,
ADS/device names, escaping links, hardlinks and other special entries, cap
violations across raw/decompressed tar streams, physical headers, PAX/GNU
extensions, bodies, padding, raw ZIP/metadata/end records, incomplete internal
checksum/manifests, magic-detected undeclared or unsupported nested archives,
unsafe nested tar/zip/Debian contents, artifact identity mismatches, source
omissions, and absolute build paths in evidence.

Run `benchmark_compat_linux.py` plus the checked black-box, practical, ELF,
runtime-provenance, and source-suite gates. Every command is launched by
`generate_gate_evidence.py` from the exact identity-pinned source tree;
arbitrary commands or cwd overrides are not accepted. Source-suite, full
Python reproducibility, and network-workload gates run under a bound inherited
seccomp/no-new-privileges network-denial policy. A secondary `strace -f`
observation is concurrently capped and retains nontruncated stream hashes plus
a normalized syscall-name/count ledger; it is not labeled a complete process
inventory. `run_source_suite.py` bootstraps the exact identity-bound pip wheel,
installs the exact KazStem wheel into a fresh offline target, proves parent/child imports originate there, and
requires the exact identity-bound sorted test-ID hash/count.
`run_network_workload.py` extracts the ready-run and executes its launcher on
the fixed identity-bound workload. Normalize the raw backend runtime
report with `normalize_runtime_provenance.py`; it verifies the selected runtime,
resource binding, manifest, and executables, converts only paths below the
extracted ready-run to the `bundle/` namespace, and rejects every outside path.
It also requires loader-policy v2: prefix-wide exact-uppercase `LD_*`/`DYLD_*`
and `GLIBC_TUNABLES` capture, clean parent startup, helper scrubbing, and only a
manifest-derived Linux `LD_LIBRARY_PATH`.
The ELF closure gate likewise emits logical `ubuntu-host/<soname>` locations
instead of build-machine paths. After binding the exact evidence
hashes, finalize a clean directory containing only the four artifacts:

```sh
python3 packaging/linux/generate_gate_evidence.py \
  --identity RELEASE-IDENTITY.json --gate source-suite \
  --source-checkout SOURCE-CHECKOUT --artifacts-dir FINAL-ARTIFACTS \
  --gate-input python_freezer_wheelhouse=OFFLINE-FREEZER-WHEELHOUSE \
  --output EVIDENCE/source-suite.json
```

```sh
python3 packaging/linux/finalize_release.py \
  --identity RELEASE-IDENTITY.json \
  --artifacts FINAL-ARTIFACTS --evidence FINAL-EVIDENCE \
  --repro-root BUILD-A --repro-root BUILD-B --repro-root BUILD-C \
  --output FINAL-REPORTS/final-linux-release.json
```

Use `generate_compression_comparison.py --producer-dir BUILD-A` to consume the
real checked A/B raw-tar receipts and execute every identity-pinned candidate
twice. It records filenames, commands/environments, exact tool versions/hashes,
A/B output bytes/hashes, deterministic tradeoffs, and selects the exact minimum
size with a stable name tie-break. `generate_optimization_ledger.py` binds that
decision to the exact black-box and practical envelopes; the finalizer repeats
all selection and cross-evidence checks.

The finalizer re-verifies all bytes, hashes, embedded source URL, safe archive
envelopes, exact evidence, and receipt-bound distinct roots. It adds
`RELEASE-IDENTITY.json`, `EVIDENCE-SHA256SUMS`, and `SHA256SUMS`, records the
full finalized identity and every evidence file, and rehashes them immediately
before success. The final platform report also receives a detached
`<report>.sha256` sidecar.
