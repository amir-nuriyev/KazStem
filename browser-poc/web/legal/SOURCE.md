# Corresponding source and reproducible browser resource

This proof of concept is GPL-3.0-or-later. The JavaScript served to the browser
is its preferred form for modification. `analyzer.kzc` is a deterministic,
unweighted typed-array encoding of a transducer compiled from GPL-3.0
`apertium-kaz` data; it contains no neural weights.

Exact identities:

- KazStem 0.2.1 source: commit
  `97cf865a0cef20ee78be1610bbe76ec6c7e52006` (tag `v0.2.1`) at
  <https://github.com/amir-nuriyev/KazStem>.
- `apertium-kaz` source: commit
  `95c6dd0d8536ee69a7058634b03a3e82100b6b6e` at
  <https://github.com/apertium/apertium-kaz>.
- HFST source used by the Ubuntu 24.04 `3.16.0-5build4` build tool: upstream
  `v3.16.0` commit `3a99b739c77a22a369a51cae18c8e5eb8df0cbe4` at
  <https://github.com/hfst/hfst>. HFST is a build tool here; no HFST runtime is
  linked into or shipped with the CSR traverser.
- The exact Ubuntu archive hashes and package metadata are in
  `scripts/toolchain_assets.lock.json` in the KazStem source.

The same Pages location includes
`kazstem-browser-corresponding-source-0.2.1.tar.gz`. The adjacent generated
`SOURCE-ARCHIVE.json` records and verifies its exact byte size and SHA-256
without introducing a circular hash into the source archive itself.
It contains exact archives of both Git commits, the complete preferred browser
POC source/exporter/tests/workflow draft, licenses, and these build instructions.
It contains no neural weights.

Rebuild on the supported H100 host from the repository root:

```sh
bash scripts/bootstrap_h100.sh
toolchain=$(readlink -f .qazmorph/toolchain)
resource=$(readlink -f .qazmorph/resources)
export PATH="$toolchain/usr/bin:$PATH"
export LD_LIBRARY_PATH="$toolchain/usr/lib/x86_64-linux-gnu"
hfst-fst2txt "$resource/kaz.automorf.hfstol" -o kaz.automorf.att
python3 browser-poc/tools/export_att_csr.py \
  kaz.automorf.att browser-poc/web/resources/analyzer.kzc \
  browser-poc/web/resources/resource-manifest.json \
  --project-version 0.2.1 \
  --project-commit 97cf865a0cef20ee78be1610bbe76ec6c7e52006 \
  --apertium-commit 95c6dd0d8536ee69a7058634b03a3e82100b6b6e \
  --probe-ledger browser-poc/web/resources/probe-ledger-summary.json
```

The exporter rejects weights, unsupported HFST identity/unknown/flag symbols,
input-epsilon cycles, non-dense/out-of-range states, symbol aliases, path
aliases, malformed fields, and post-write hash/size drift. The native/browser
ordered-candidate proof artifacts are under `browser-poc/reports` and their
hashes are recorded in the browser proof summary.

Retain that release-matched archive at the same download location for as long
as the browser object code is offered. A durable source link is useful but is
not used as a substitute for this archive.
