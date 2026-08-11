# KazStem {{VERSION}} for {{TARGET}}

This archive is the no-install Windows Server 2022 x86-64 build of KazStem.
Run `kazstem.exe`; `qazmorph.exe` and `mystem-kz.exe` are byte-identical
compatibility aliases. No administrator privileges, installer, registry
changes, neural weights, network client, OpenSSL, or external morphology tools
are required.

Features in this build include ambiguity-preserving Kazakh analysis,
productive out-of-vocabulary guessing, Constraint Grammar disambiguation,
HFST generation and analysis/generation round-trips, lossless text/JSON/JSONL/
XML/CoNLL-U output, UTF-8 and CP1251 input, stdin and file processing, and the
documented `kazstem`, `qazmorph`, and `mystem-kz` command-line interfaces.

The archive is intentionally **unsigned**. Windows SmartScreen may therefore
show an unrecognized-app warning. Verify the SHA-256 published on the GitHub
release before running it.

The analyzer resource bundle is `{{RESOURCE_BUNDLE_ID}}`; the audited Windows
native runtime is `{{RUNTIME_BUNDLE_ID}}`.

Complete corresponding source, including the exact native build inputs, is:

- `{{SOURCE_FILENAME}}`
- SHA-256: `{{SOURCE_SHA256}}`
- {{SOURCE_URL}}

The release notes and bundled `verification/` records state the exact tested
OS build, tool versions, hashes, Authenticode status, performance measurements,
and known compatibility limits. Windows 10 is not claimed by this artifact.
