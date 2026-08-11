# bf1f resource-producer source snapshot

This directory preserves the exact project-owned source inputs and sealed
manifest recorded in resource bundle
`bf1f31ff6e5860585b9e4134f12dcfb9d6df8030ee87b368e5a5f29eb45c1188`.
It is a producer-input snapshot, not the Python runtime consumer
implementation and not, by itself, the complete release corresponding-source
asset.

The current `src/qazmorph/` files retain later protocol, deadline, portability,
and public-input hardening. Their bytes therefore must not be substituted for
the manifest-bound producer files in this directory, and the sealed bf1f
manifest must not be rewritten merely to match a successor consumer.

Corresponding-source packaging for bf1f must include this directory unchanged,
the clean Apertium Kazakh tree identified in `SNAPSHOT.json`, the exact r5
toolchain inventory, all six locked Ubuntu binary archives, and all twelve
locked corresponding-source archives. Packaging must run
`packaging/verify_resource_producer_snapshot.py` with every physical closure
path. The canonical release builder must consume the returned
`release_closure_identity`; a producer-input-only receipt is insufficient for
publication. A missing, extra, symlinked, or changed entry is a hard failure.

Those verified inputs together are independently sufficient to rebuild the
exact bf1f resource bundle byte-for-byte. The checked-in manifest copy is also
rehashed and its canonical content identity recomputed before any external
source or toolchain binding is accepted.
