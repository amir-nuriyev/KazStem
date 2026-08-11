# KazStem @VERSION@ ready-run for @TARGET@

Run directly after extraction:

```sh
./kazstem --version
printf 'Қазақстандағы балалар мектепке барды.\n' | ./kazstem -c -i --format json
```

`qazmorph` and `mystem-kz` are aliases for the same executable. The bundle is
offline and includes the exact `@RESOURCE_BUNDLE_ID@` Kazakh morphology and
the detached `@RUNTIME_BUNDLE_ID@` native runtime selected by the checked-in
unified platform lock. It contains no neural weights, OpenSSL, updater,
network client, installer, or source/build archive.

Target: @TARGET@. This asset is not advertised as generic Linux or portable
to older glibc distributions.

The separately published `@SOURCE_FILENAME@` (SHA-256 `@SOURCE_SHA256@`) is
the required checksum-bound source companion. Its exact release download URL
is @SOURCE_URL@. `CORRESPONDING-SOURCE.json` records the same binding in
machine-readable form.
