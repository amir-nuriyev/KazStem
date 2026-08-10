# bf1f resource-producer source snapshot

This directory preserves the exact project-owned source inputs recorded in
resource bundle `bf1f31ff6e5860585b9e4134f12dcfb9d6df8030ee87b368e5a5f29eb45c1188`.
It is producer source, not the Python runtime consumer implementation.

The current `src/qazmorph/` files retain later protocol, deadline, portability,
and public-input hardening. Their bytes therefore must not be substituted for
the manifest-bound producer files in this directory, and the sealed bf1f
manifest must not be rewritten merely to match a successor consumer.

Corresponding-source packaging for bf1f must include this directory unchanged,
the clean Apertium Kazakh tree identified in `SNAPSHOT.json`, and the locked
HFST/CG3 binary and corresponding-source closure identified there. Packaging
must verify every byte count and SHA-256 before claiming the snapshot is
complete. A missing, extra, or changed producer input is a hard failure.

The snapshot is independently sufficient, with the named external inputs and
locked r5 toolchain, to rebuild the exact bf1f resource bundle byte-for-byte.
