# Canonical Python artifacts

All release platforms and PyPI consume the one wheel/sdist pair produced by
`packaging/build_canonical_python_artifacts.py`. The strict input schema is
`kazstem-canonical-python-build-identity-v2`; the checked receipt schema is
`kazstem-canonical-python-build-receipt-v2`.

The identity binds the immutable `refs/tags/v<release>` commit and tree, HTTPS
origin, fixed epoch, exact Git/Python executables and versions, execution
platform, zlib compile/runtime versions, every source input, and the shared
canonicalizer bytes. The separately checked remote-authority gate anchors the
local tag object and peeled commit at the public origin. The identity also
binds:

- a hash-locked offline wheelhouse and requirements file containing `build`,
  `setuptools`, `wheel`, `packaging`, `pyproject-hooks`, `twine`, and all
  transitive build dependencies;
- the exact `pip install --no-index --require-hashes --no-deps` provisioning
  command and installed distribution/version inventory;
- exact build and sdist-roundtrip commands and controlled environments;
- the CPython upstream source archive, license, and build recipe, plus the
  machine-readable `kazstem-python-builder-byte-inputs-v1` record covering the
  interpreter bytes, standard-library tree with declared exclusions, zlib
  extension or built-in module, loaded libz, provider/package revision, and
  every declared binary/source package companion;
- expected metadata version, license expression, complete classifier set,
  Wheel-Version 1.0, `Root-Is-Purelib: true`, and the single
  `py3-none-any` tag;
- exact final wheel/sdist bytes and hard physical/archive limits.

The canonical release run uses one reviewed Linux execution identity and at
least three fresh roots. For the Ubuntu provider, `upstream_version` records
the CPython X.Y.Z while `version` records the exact Ubuntu package revision;
the four CPython binary packages, `zlib1g`, and the matching Python/zlib source
sets are mandatory. macOS and Windows consume those exact Python artifacts. A
runner may claim a cross-platform byte rebuild only if its exact tool,
declared interpreter byte inputs, zlib, command, and output identities match;
normalized layout alone is not a cross-zlib byte-equivalence claim.

This record is deliberately **not** a complete host-runtime or transitive-DSO
attestation. It does not claim an ambient system-DSO closure, a compiler
toolchain derivation, or that the interpreter was rebuilt from the listed
source. Those exclusions are exact fields in `evidence_scope`. Reproducibility
of the pure wheel/sdist is established by exact inputs plus three independent
byte-identical builds. OpenSSL/libcrypto is not a KazStem artifact-build input
and is neither added to the final ready-run asset nor requested as a separate
corresponding-source component.
The `not_claimed` inventory explicitly includes `ambient-system-dso-closure`,
`compiler-toolchain-derivation`, and
`interpreter-binary-rebuild-from-declared-source`.

Wheel input is physically closed (no prepended, trailing, or unreferenced ZIP
bytes), every RECORD hash/size is checked, and the output uses sorted fixed
timestamps and a platform-neutral all-files-0644 mode policy. Sdist input is
gzip/physical-tar capped before `tarfile`, with header/checksum/body/padding and
PAX/GNU-extension policy enforced. The output is filename-free mtime-zero gzip
over USTAR, also with all files at 0644. Wheel METADATA and sdist PKG-INFO must
be byte-identical, and both primary and roundtrip pairs pass the exact bound
`twine check --strict` command.

The primary and roundtrip workspaces, output, receipt, source, identity,
wheelhouse, and interpreter source must be fresh/distinct/nonnested where
applicable. The canonical sdist is extracted into the independent roundtrip
root, every entry is adversarially retimed, the locked environment is
provisioned again, and both rebuilt artifacts must be byte-identical. Command
capture is hard-capped, timeout kills the process group, and lingering
descendants are a failure. Linux additionally uses a dedicated systemd user
slice with exact `TasksMax`/`pids.max`, writes `cgroup.kill`, and waits for
`cgroup.events` to report `populated 0`. A subreaper, `(pid,starttime)`
inventory, and pidfds provide an independent cleanup layer. Published receipts contain only logical
roots and a checked distinct/nonaliased result—never transient device/inode
values.

```sh
python3 packaging/build_canonical_python_artifacts.py \
  --identity PYTHON-BUILD-IDENTITY.json \
  --source-checkout MATERIALIZED-TAGGED-SOURCE \
  --wheelhouse OFFLINE-HASHED-WHEELHOUSE \
  --requirements packaging/python-build-requirements.lock \
  --interpreter-source Python-X.Y.Z.tgz \
  --workspace FRESH-PRIMARY \
  --roundtrip-workspace FRESH-ROUNDTRIP \
  --output-dir DIST \
  --receipt CANONICAL-PYTHON-BUILD-RECEIPT.json
```

`validate_receipt(receipt, identity=..., output_dir=...)` rechecks the strict
receipt, exact commands/environments/tools, offline package inventories,
metadata audits, retimed roundtrip, and final output bytes. Use `--observation`
only to bootstrap exact artifact hashes. A mismatch remains failure and every
canonical-named mismatch is quarantined; an observation is not release proof.
