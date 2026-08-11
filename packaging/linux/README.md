# Ubuntu 24.04 x86-64 ready-run recipe

This recipe reproduces KazStem's minimized Ubuntu 24.04 x86-64 detached
runtime and frozen CLI.  It is deliberately not advertised as generic Linux:
the audited host boundary is glibc 2.39 and the recorded Ubuntu Noble system
libraries.

The final release identity, checked-in unified platform lock, and runtime/source
locks bind the exact resource bundle, runtime bundle, and manifest bytes. This
recipe deliberately contains no release-specific bundle ID or manifest hash;
an audited resource refresh therefore changes identity data, not tool code.

`scripts/platform_runtime_sources.linux-x86_64.lock.json` binds the six exact
Ubuntu binary packages and all four complete Debian source sets.  Verify those
directories before extraction, then build the runtime from the original r4
toolchain bundle:

```sh
python3 packaging/linux/build_minimal_runtime.py \
  --full-toolchain PATH/TO/R4/PREFIX \
  --archives PATH/TO/SIX/DEBS \
  --sources PATH/TO/DEBIAN/SOURCES \
  --source-lock scripts/platform_runtime_sources.linux-x86_64.lock.json \
  --output-parent BUILD/platform-runtimes \
  --base-lock src/qazmorph/platform_runtime_assets.lock.json \
  --lock-output BUILD/platform_runtime_assets.lock.json
```

The output must reproduce the identity-bound bundle and manifest. The
runtime contains only `hfst-proc`, `hfst-optimized-lookup`, `cg-proc`, and the
four recursively reached non-host libraries.  Do not remove another ELF or
move a host library into the archive without regenerating the manifest and
rerunning the full behavior and closure gates.

Build the frozen launcher from the canonical release wheel with the checked
orchestrator, exact declared Ubuntu CPython byte inputs, and the identity-bound
offline PyInstaller 6.22.0 / hooks-contrib 2026.6 wheelhouse:

```sh
python3 -S packaging/linux/build_frozen_from_wheel.py \
  --identity RELEASE-IDENTITY.json \
  --source-checkout MATERIALIZED-TAGGED-SOURCE \
  --wheel kazstem-0.2.3-py3-none-any.whl \
  --wheelhouse OFFLINE-FREEZER-WHEELHOUSE \
  --requirements packaging/linux/python-freezer-requirements.lock \
  --workspace FRESH-FREEZER-WORKSPACE \
  --frozen FRESH-FROZEN-OUTPUT \
  --receipt FROZEN-WHEEL-CONSUMPTION.json
```

The spec analyzes the canonical wheel for its transitive standard-library
closure, removes every `qazmorph` module from PyInstaller's PYZ, and embeds the
exact wheel as the sole runtime import source. The v2 receipt and three-root
verifier independently bind the wheel, RECORD/package inventory, internal
provision/build commands, full frozen inventory, and embedded wheel bytes. The
spec consumes the package's checked-in unified Mac/Linux/Windows runtime lock;
release-only lock overlays are forbidden. The ready-run assembler may
remove only PyInstaller's copied `libexpat.so.1` and `libz.so.1`, which the
audited Ubuntu target resolves at its host boundary.  It must retain a ledger
of those removals and fail if any other ELF is changed.

Copy the exact identity-bound resource and content-addressed Linux runtime
trees beside the frozen launcher, seal the POSIX bundle read-only, and produce
the archive with
normalized ownership, modes, ordering, and timestamps.  A release candidate
must pass, from a fresh extraction:

1. the 13-command core black-box gate and expanded practical matrix;
2. all MyStem text/JSON/XML/JSONL formats, OOV, CG, and generation cases;
3. Unicode, CRLF, literal NUL, malformed-input, and reconstruction cases;
4. large-file deterministic-output and peak-memory checks;
5. `packaging/linux/audit_elf_closure.py`, with no missing/escaped dependency,
   `_ssl`, `_hashlib`, `libssl`, or `libcrypto`;
6. fresh runtime provenance with `official=true` and no non-official reasons;
7. an independently verified corresponding-source companion containing the
   exact wheel/sdist, resource source, Ubuntu source sets, freezer sources,
   recipes, licenses, and verification ledgers.

The checked black-box and expanded gates are
`packaging/linux/blackbox_linux_bundle.py` and
`packaging/linux/practical_matrix_linux.py`. Pass both the final strict release
identity with `--identity`; version, commit, wheel, and root-name overrides are
not accepted, so evidence from an older candidate is not reusable. The source
companion README must be rendered from
`packaging/linux/CORRESPONDING-SOURCE-README.template.md` and all placeholders
must be replaced before its archive is hashed.

No source archive, OpenSSL source, neural weights, installer, updater, or
network client belongs in the ready-run binary archive.  Corresponding source
is a separate checksum-bound release asset.

## Final release orchestration

The parameterized final tooling is documented in
`packaging/linux/RELEASE-IDENTITY.md`. All assemblers, archive auditors, the
compatibility benchmark, and the finalizer consume one strict
`kazstem-linux-release-identity-v2` file. The identity checksum-binds every
input and output, supplies exact release-download URLs, caps all outer and
nested archives, and contains no build-root paths.

The final sequence is source assembly, source observation binding, binary
assembly, binary observation binding, three self-created clean-root builds with
per-root receipts, fresh binary/source audits, practical gates, evidence
binding, audit replay, and
finalization. Gate argv, source cwd/tree, scripts, tools, timeouts, payload
schemas, and artifact subjects are exact identity fields. Observation
mismatches remain failures and are never publishable release candidates.

The shared canonical-Python v2 builder provisions a hash-locked offline
wheelhouse in each fresh root, binds CPython source/recipe/license and zlib,
runs strict metadata checks, and rebuilds wheel+sdist after adversarially
retiming an independent sdist extraction. The freezer must consume that exact
wheel. Native assemblers execute from each tagged clone and emit checked A/B
raw-tar producer receipts before compression. Source-suite, full
reproducibility, and the fixed ready-run network workload run under the bound
`strace -f` observation and inherited no-new-privileges/seccomp network-denial
policy. The trace is not described as an exhaustive process inventory; the
seccomp filter is the denial boundary. Every supervised H100 command also
runs in a fresh systemd user slice whose exact `TasksMax` equals `pids.max`;
cleanup writes `cgroup.kill` and waits for `cgroup.events` to report
`populated 0`, with process groups and the subreaper retained independently.
The final report has its own detached
SHA-256 sidecar in addition to artifact, identity, and evidence ledgers.
