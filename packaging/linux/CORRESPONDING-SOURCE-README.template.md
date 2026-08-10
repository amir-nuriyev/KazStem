# KazStem @VERSION@ Linux corresponding source

This archive is the checksum-bound source companion for
`@BINARY_ARCHIVE@` at `@BINARY_URL@`. It is not needed at runtime and must be
published beside that binary under `@RELEASE_URL@`, as recorded in the binary's
`CORRESPONDING-SOURCE.json`.

The KazStem application source is commit `@SOURCE_COMMIT@` with
`SOURCE_DATE_EPOCH=@SOURCE_DATE_EPOCH@`. The canonical
Python wheel is `@WHEEL_FILENAME@` (SHA-256 `@WHEEL_SHA256@`) and the canonical
sdist is `@SDIST_FILENAME@` (SHA-256 `@SDIST_SHA256@`). The linguistic bundle
is resource `@RESOURCE_BUNDLE_ID@`. The detached Ubuntu runtime is bundle
`@RUNTIME_BUNDLE_ID@` and was built from the exact inputs in
`scripts/platform_runtime_sources.linux-x86_64.lock.json`.

This companion includes the canonical wheel and sdist, exact resource source,
all binary-package source sets, CPython and freezer corresponding source,
build wheels and source distributions, licenses/notices, checked recipes, and
verification ledgers. Verify `SHA256SUMS` and every nested inventory before
use.

Reproduce the detached runtime with
`packaging/linux/build_minimal_runtime.py`, audit it with
`packaging/linux/audit_elf_closure.py`, and run
`packaging/linux/blackbox_linux_bundle.py` plus
`packaging/linux/practical_matrix_linux.py`. Build the ready-run archive twice
from distinct clean roots with normalized bundle-relative evidence. Both
native archives must be byte-identical before publication.

The binary target is Ubuntu 24.04 x86-64, not generic Linux. No OpenSSL,
neural weights, installer, updater, or network client belongs in the ready-run
binary. This separate archive supplies corresponding source for every binary
component that is distributed in that ready-run asset.
