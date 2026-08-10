# Ubuntu 24.04 x86-64 ready-run recipe

This recipe reproduces KazStem's minimized Ubuntu 24.04 x86-64 detached
runtime and frozen CLI.  It is deliberately not advertised as generic Linux:
the audited host boundary is glibc 2.39 and the recorded Ubuntu Noble system
libraries.

The checked-in runtime binding is:

- resource bundles `f03e703d3e2a67044a7d91fd7d575b92cb4e61aa782fb67cff91b0a5ff0ebd5a`
  and `bf1f31ff6e5860585b9e4134f12dcfb9d6df8030ee87b368e5a5f29eb45c1188`;
- runtime bundle `39a01ea673d024b0d6080739b5bb23c76daf0f7ed7bdb95dd1157d9dce4b627e`;
- 9,958-byte runtime manifest with SHA-256
  `67da829d117d39d7de34afbc67dd649be24156fa9fab613aa318b438b9637f4b`.

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

The output must reproduce the bundle and manifest identities above.  The
runtime contains only `hfst-proc`, `hfst-optimized-lookup`, `cg-proc`, and the
four recursively reached non-host libraries.  Do not remove another ELF or
move a host library into the archive without regenerating the manifest and
rerunning the full behavior and closure gates.

Build the frozen launcher from the canonical release wheel with CPython 3.12.3,
PyInstaller 6.22.0, and hooks-contrib 2026.6.  Set `KAZSTEM_ENTRYPOINT` to the
isolated environment's `kazstem` entry point and run:

```sh
LC_ALL=C.UTF-8 LANG=C.UTF-8 PYTHONHASHSEED=0 SOURCE_DATE_EPOCH=1786361661 \
  pyinstaller --clean --noconfirm \
  --distpath pyinstaller-dist --workpath pyinstaller-work \
  packaging/linux/kazstem-minimal.spec
```

The spec consumes the package's checked-in unified Mac/Linux/Windows runtime
lock; release-only lock overlays are forbidden.  The ready-run assembler may
remove only PyInstaller's copied `libexpat.so.1` and `libz.so.1`, which the
audited Ubuntu target resolves at its host boundary.  It must retain a ledger
of those removals and fail if any other ELF is changed.

Copy the exact selected f03e or bf1f resources and content-addressed Linux
runtime beside the frozen launcher, seal the POSIX bundle read-only, and
produce the archive with normalized ownership, modes, ordering, and
timestamps. A release candidate must pass, from a fresh extraction:

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
`kazstem-linux-release-identity-v1` file. The identity checksum-binds every
input and output, supplies exact release-download URLs, caps all outer and
nested archives, and contains no build-root paths.

The final sequence is source assembly, source observation binding, binary
assembly, binary observation binding, two clean-root reproductions, fresh
binary/source audits, practical gates, evidence binding, audit replay, and
finalization. Observation mismatches remain failures and are never publishable
release candidates.
