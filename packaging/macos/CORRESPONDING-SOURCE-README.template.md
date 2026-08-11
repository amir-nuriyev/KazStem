# KazStem @VERSION@ macOS corresponding source

This archive is the checksum-bound source companion for
`@BINARY_ARCHIVE@` at `@BINARY_URL@`. It is not needed at runtime and must be
published beside that binary under `@RELEASE_URL@`, as recorded in the binary's
`CORRESPONDING-SOURCE.json`.

The KazStem application source is commit `@SOURCE_COMMIT@` with
`SOURCE_DATE_EPOCH=@SOURCE_DATE_EPOCH@`. The canonical
Python wheel is `@WHEEL_FILENAME@` (SHA-256 `@WHEEL_SHA256@`) and the canonical
sdist is `@SDIST_FILENAME@` (SHA-256 `@SDIST_SHA256@`). The linguistic bundle
is resource `@RESOURCE_BUNDLE_ID@`. The detached Project.JJ macOS runtime is bundle
`@RUNTIME_BUNDLE_ID@` and was built from the exact inputs in
`scripts/platform_runtime_sources.lock.json`.

This companion includes the canonical wheel and sdist, exact resource source,
all binary-package source sets, CPython and freezer corresponding source,
build wheels and source distributions, licenses/notices, checked recipes, and
verification ledgers. Verify `SHA256SUMS` and every nested inventory before
use.

Verify/reproduce the detached runtime with
`scripts/write_platform_runtime_manifest.py`, audit it with
`packaging/macos/audit_macho_closure.py`, and run
`packaging/macos/blackbox_macos_bundle.py` plus
`packaging/macos/practical_matrix_macos.py`. Build the ready-run archive twice
from distinct clean roots with normalized bundle-relative evidence. Both
native archives must be byte-identical before publication.

The binary target is macOS 15 arm64, not generic macOS. No OpenSSL,
neural weights, installer, updater, or network client belongs in the ready-run
binary. This separate archive supplies corresponding source for every binary
component that is distributed in that ready-run asset.
