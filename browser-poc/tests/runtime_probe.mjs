import fs from "node:fs";
import { createHash } from "node:crypto";
import { performance } from "node:perf_hooks";
import { CsrTransducer } from "../web/csr.js";

const [resourcePath, manifestPath, ledgerPath, outputPath] = process.argv.slice(2);
if (!resourcePath || !manifestPath || !ledgerPath || !outputPath) {
  throw new Error("usage: node runtime_probe.mjs RESOURCE MANIFEST LEDGER OUTPUT");
}

const before = process.memoryUsage();
const initStart = performance.now();
const source = fs.readFileSync(resourcePath);
const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
const resourceHash = createHash("sha256").update(source).digest("hex");
if (source.byteLength !== manifest.resource.bytes || resourceHash !== manifest.resource.sha256) {
  throw new Error("resource manifest size/SHA-256 verification failed before constructor");
}
const owned = source.buffer.slice(source.byteOffset, source.byteOffset + source.byteLength);
const transducer = CsrTransducer.fromArrayBuffer(owned);
const initMs = performance.now() - initStart;
const afterInit = process.memoryUsage();
const ledger = JSON.parse(fs.readFileSync(ledgerPath, "utf8"));

const comparisons = [];
let orderedEqual = true;
const probeStart = performance.now();
for (const row of ledger.rows) {
  const browser = transducer.lookup(row.normalized);
  const equal = JSON.stringify(browser) === JSON.stringify(row.candidates);
  orderedEqual &&= equal;
  comparisons.push({
    surface: row.surface,
    native: row.candidates,
    browser,
    ordered_equal: equal,
  });
}
const probeMs = performance.now() - probeStart;

const benchmarkSurfaces = ledger.rows.map((row) => row.normalized);
const requestedIterations = Number.parseInt(process.env.KAZSTEM_BENCH_ITERATIONS ?? "500", 10);
const iterations = Number.isSafeInteger(requestedIterations) && requestedIterations > 0 ? requestedIterations : 500;
let codePoints = 0;
const throughputStart = performance.now();
for (let iteration = 0; iteration < iterations; iteration += 1) {
  for (const surface of benchmarkSurfaces) {
    codePoints += Array.from(surface).length;
    transducer.lookup(surface);
  }
}
const throughputMs = performance.now() - throughputStart;
const afterBenchmark = process.memoryUsage();
const report = {
  schema: "kazstem.browser-runtime-probe.v1",
  resource_sha256_verified_before_constructor: true,
  resource_sha256: resourceHash,
  ordered_candidate_arrays_equal: orderedEqual,
  probe_count: ledger.rows.length,
  init_ms: initMs,
  probe_ms: probeMs,
  benchmark: {
    iterations,
    code_points: codePoints,
    elapsed_ms: throughputMs,
    code_points_per_second: codePoints / (throughputMs / 1000),
  },
  memory_bytes: {
    before,
    after_init: afterInit,
    after_benchmark: afterBenchmark,
  },
  comparisons,
};
fs.writeFileSync(outputPath, `${JSON.stringify(report, null, 2)}\n`);
if (!orderedEqual) process.exitCode = 1;
