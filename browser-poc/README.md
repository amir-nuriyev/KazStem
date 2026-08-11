# KazStem Browser / GitHub Pages proof of concept

Status: **publicly deployed proof of concept; not production-parity yet**. The
browser source was developed on `codex/browser-pages-poc`, based on KazStem
`v0.2.1` commit `97cf865a0cef20ee78be1610bbe76ec6c7e52006`, and is
now distributed from the public repository and GitHub Pages. Package-manifest
v2 records that public build context without a mutable pushed/deployed claim.

## Feasibility decision

Use the custom unweighted CSR/typed-array export for the first browser lattice
runtime. Keep a narrowly compiled native HFST optimized-lookup WASM build as a
fallback experiment for `hfst-proc`-level document tokenization parity. Do not
put CG3 or neural code in the MVP.

Why:

- The verified dictionary `.hfstol` is 1,634,211 bytes. Its exact custom CSR is
  950,181 bytes (SHA-256
  `d0df783b4a51eef7db513662ca2fb4ae2d78f7c78ca7b4b797e84e72ccc3c4c0`),
  gzip-9 353,784 bytes, without a C++ allocator, virtual filesystem, Emscripten
  glue, or HFST runtime dependency.
- The relation has 42,965 dense states, 91,470 arcs, 230 final states, 176
  input symbols, 289 output symbols, 16,764 input-epsilon arcs, no nonzero
  weights, and no reachable input-epsilon cycle.
- The complete AT&T symbol audit found only `@0@` and `@_SPACE_@`; there are no
  identity/unknown symbols or flag diacritics. The exporter still fails closed
  on any future unsupported `@…@` symbol.
- H100 currently has no `emcc`, `em++`, `wasm-opt`, Rust, or Clang toolchain, so
  a native-WASM size is not measured. Installing a hash-pinned Emscripten SDK
  is a separate experiment, not a reason to delay the smaller proven route.
- CG3's 27,022-byte compiled grammar is not the runtime. A browser port would
  also need the CG3 C++ engine and ICU behavior; a custom CG interpreter would
  be another correctness project. Contextual mode stays visibly unsupported.

## H100 evidence

All builds and performance/correctness experiments ran on the private H100
stage `/home/amodo/kazstem-browser-pages.3ONjr7/repo`. The local copy contains
source and H100-produced artifacts only.

| Gate | Result |
|---|---:|
| HFST → AT&T export | 0.13 s, 19,252 KiB max RSS |
| AT&T bytes / gzip-9 / zstd-19 | 2,464,207 / 479,601 / 374,125 |
| AT&T → CSR export | 0.21 s, 56,368 KiB max RSS |
| CSR bytes / gzip-9 / zstd-19 | 950,181 / 353,784 / 308,853 |
| Small immutable ordered probe gate | 24/24 exact |
| Full direct-relation gate | 31,568/31,568 exact ordered raw candidate arrays |
| Full gate inventory | every 4,642 distinct KTB form + all 29,242 distinct whitespace types in the frozen raw-5k sample, normalized/deduplicated |
| Full constructor/init (including graph validation) | 6.85 ms |
| Full 31,568-surface comparison | 263.15 ms |
| Repeated direct lookup throughput | 1,350,883 Unicode code points/s |
| Malformed resource and cap tests | 8/8 pass |

The KTB checkout is pinned at
`c850e5334a50befaf35a0907df766c4de89f68a1`. The deployed
[`probe-ledger-summary.json`](web/resources/probe-ledger-summary.json) binds the
source inventories, exact native and browser ledgers, resource SHA, runtime
measurements, malformed/cap result, and compressed exact ledgers. Full-proof
RSS (151,740 KiB) includes parsing/writing roughly 15 MB of comparison JSON and
is not representative of ordinary worker lookup; the 24-probe run peaked at
58,256 KiB process RSS.

## Browser architecture begun here

- `web/worker.js` fetches the manifest and resource from the same origin,
  enforces a hard byte limit and exact length, computes SHA-256 **before**
  constructing the transducer, cross-checks inner/outer project identities,
  and reports the verified hash to the UI.
- `web/csr.js` validates exact metadata and array schemas, symbols, dimensions,
  monotone CSR offsets, targets, symbol IDs, finals, and the epsilon-cycle
  proof bit. Lookup has 256-code-point input, 512-candidate, 250,000-step, and
  4,096-output-code-point bounds. Output backpointers avoid quadratic string
  concatenation. Results use HFST's ordered `vector<string>` semantics.
- The main thread streams UTF-8 file chunks through `TextDecoderStream` with
  one-chunk-at-a-time worker acknowledgement; drag/drop and a file picker share
  the path. This is explicitly buffered after transfer: the POC file limit is
  4 MiB, the worker rejects more than 4 Mi UTF-16 units or 32 Mi output units,
  and returns only counts plus the selected serialized output (not a second
  structured-clone copy of the full document). Cancel terminates/recreates the
  worker so it can interrupt synchronous traversal.
- Text, MyStem-shaped JSON/XML/text, JSONL v2, and CoNLL-U serializers run in
  the worker. XML performs controlled XML 1.0 character rejection. JSONL marks
  consuming atomic token records separately from non-consuming
  `analysis_span` records and carries the full resource/proof identity.
- The responsive UI is keyboard/focus accessible, has live status/progress,
  local download, deterministic version/hash display, a privacy/source panel,
  no analytics/CDN/API, and a same-origin CSP.
- The service worker precaches every analysis/runtime/legal asset. Runtime
  analysis needs no network after that cache completes. SharedArrayBuffer and
  WASM threads are intentionally not required.
- `workflows/pages.yml` preserves the reviewed workflow source; the active copy
  is under `.github/workflows/pages.yml`. All four official Pages actions are
  pinned to full commits. The public workflow only verifies and publishes
  reviewed H100-generated bytes.

## Bundle and performance targets

- Required first offline cache: **≤ 2 MiB uncompressed app + analyzer**, with
  the 950,181-byte resource leaving ample room. Exact proof ledgers and the
  corresponding-source archive are downloadable audit artifacts, not runtime
  dependencies.
- Worker init: **< 50 ms desktop, < 200 ms current mobile** after fetch/hash.
- Warm lookup: **≥ 100,000 input code points/s** on a current midrange mobile;
  H100 Node is 1.35M/s and is not used as a mobile claim.
- Normal worker memory: **< 64 MiB** for resource/runtime and bounded queues,
  excluding caller-selected input/output blobs. Large-file output must become
  stream-to-disk where the File System Access API is available.
- No request to a non-same-origin URL; no neural weights in the bundle.

## Exact blockers before an MVP may be called faithful

1. **Full-document partition and phrase spans.** Direct FST candidate order is
   proven, but browser tokenization is not yet equal to `hfst-proc` for every
   reserved character, CR/LF/NUL, hyphen chain, maximal lexical cohort, and MWE
   whose authoritative end can fall inside an edge token. The POC preserves a
   contiguous exact consuming partition and labels its bounded (8-token / 96
   UTF-16-unit) span scan incomplete. This must become a native-vs-browser
   document ledger before release.
2. **Structured-analysis parity.** The main UD projection is ported, but the
   complete Python NFC boundary map, projection-alias append order, protected
   literal-character rules, and every serializer option still need fixture
   equality. The current UI says this is a POC and does not claim those gates.
3. **True streaming computation.** File decode/transfer has backpressure, but
   the worker currently joins chunks before document analysis so cross-chunk
   offsets/spans stay simple. Production needs bounded carry, incremental
   token/span analysis, and streaming output/download without weakening exact
   reconstruction.
4. **CG3/contextual, productive OOV, generation, and neural mode** are disabled
   and listed in the manifest/UI. Unknowns are explicit; no mode silently
   substitutes a heuristic implementation. Neural weights are excluded.
5. **Mobile/browser benchmarks.** H100 establishes algorithmic headroom, not a
   device claim. Chrome, Firefox, Safari, and Android runs must measure cold
   hash/init, throughput, memory, offline upgrade, large-file cancellation, and
   malformed UTF-8/XML controls.
6. **Redistribution review.** The public Pages artifact includes GPL/third-party
   notices and a release-matched corresponding-source archive beside the CSR.
   `web/legal/SOURCE.md` pins sources and rebuild steps. Any replacement object
   code must reseal that source closure and pass legal review before deployment.

## GitHub Pages constraints

Pages provides HTTPS/service-worker support, but not a repository-controlled
arbitrary response-header mechanism. Therefore this design does not depend on
COOP/COEP, SharedArrayBuffer, or WASM threads. GitHub documents a 1 GB published
site limit, recommended 1 GB source repository limit, 10-minute deployment
timeout, and soft 100 GB/month bandwidth limit. A roughly 1 MiB analyzer is
well inside the platform limits and avoids wasting the bandwidth budget.

Run a local static preview only after the H100-produced artifacts are present:

```sh
python3 -m http.server --directory browser-poc/web 8080
```

This preview command is not a build or benchmark.
