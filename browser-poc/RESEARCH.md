# Primary-source research notes

- GitHub Pages limits: <https://docs.github.com/en/pages/getting-started-with-github-pages/github-pages-limits>
  documents the 1 GB published-site limit, recommended 1 GB source repository,
  10-minute deployment timeout, and soft 100 GB/month bandwidth limit.
- GitHub Pages HTTPS: <https://docs.github.com/en/pages/getting-started-with-github-pages/securing-your-github-pages-site-with-https>
  confirms `github.io` sites support HTTPS, which is required for service
  workers and Web Crypto in normal browser deployments.
- Cross-origin isolation requirements:
  <https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Cross-Origin-Embedder-Policy>
  and
  <https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Cross-Origin-Opener-Policy>
  document that shared memory/SharedArrayBuffer requires COEP plus COOP. Pages
  does not expose a repository-level arbitrary-header configuration feature,
  so the design deliberately uses one ordinary dedicated worker without shared
  memory or WASM threads.
- WebAssembly core goals: <https://webassembly.github.io/spec/core/intro/introduction.html>
  describes its safe, portable, compact execution format. That supports a
  native HFST experiment in principle but does not establish that the full
  HFST/CG3 dependency surface will be smaller than the measured custom graph.
- Emscripten: <https://emscripten.org/> and
  <https://github.com/emscripten-core/emscripten> document C/C++ → WebAssembly
  compilation and its browser/Node output. No native-WASM size is reported
  because the H100 host did not have the toolchain installed; a future test
  must pin the SDK commit before building.
- HFST v3.16.0 source: <https://github.com/hfst/hfst/tree/v3.16.0> identifies
  the GPL v3 library/tool suite and configurable backends/dependency surface.
  H100 source inspection at pinned commit
  `3a99b739c77a22a369a51cae18c8e5eb8df0cbe4` confirmed optimized lookup stores
  results as `std::set<pair<float, vector<string>>>`; this is why the browser
  comparator sorts output-symbol vectors rather than traversal order or joined
  strings.
- HFST symbol semantics:
  <https://hfst.github.io/python/3.12.1/Symbols.html> documents epsilon,
  identity, and unknown symbols. The exported Kazakh analyzer audit contains
  only AT&T `@0@` and escaped space, but the exporter rejects all unimplemented
  meta/flag symbols rather than treating them as literal text.
- CG3 source: <https://github.com/GrammarSoft/cg3> is the authoritative runtime
  codebase for the compiled grammar. The small `.rlx.bin` size alone is not a
  browser runtime size measurement.

These sources establish platform/runtime constraints. Bundle size, graph
properties, exact candidate ordering, throughput, and memory numbers in this
POC come from the versioned H100 artifacts and ledgers, not from web claims.
