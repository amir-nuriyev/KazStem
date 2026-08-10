import { CsrTransducer, sha256Hex } from "./csr.js";
import { numberAnalysis, parseAnalysis, unknownAnalysis } from "./analysis.js";
import { serialize } from "./formats.js";

const MAX_RESOURCE_BYTES = 16 * 1024 * 1024;
const MAX_INPUT_UTF16 = 4 * 1024 * 1024;
const MAX_OUTPUT_UTF16 = 32 * 1024 * 1024;
const EXPECTED_UNSUPPORTED_MODES = ["constraint-grammar", "neural-ranking", "productive-oov", "generation"];
const ORTHOGRAPHIC_HYPHENS = new Set(["-", "‐", "‑"]);
const DASH_PUNCTUATION = new Set(["‒", "–", "—", "−"]);
const LETTER_MARK_NUMBER = /[\p{L}\p{M}\p{N}]/u;
const LETTER_MARK = /[\p{L}\p{M}]/u;
const WHITESPACE = /\s/u;

let transducer;
let identity;
const jobs = new Map();

function exactKeys(object, expected, label) {
  if (!object || typeof object !== "object" || Array.isArray(object)) throw new Error(`Invalid ${label}`);
  const observed = Object.keys(object).sort();
  const wanted = [...expected].sort();
  if (JSON.stringify(observed) !== JSON.stringify(wanted)) throw new Error(`Unexpected ${label} fields`);
}

async function fetchVerifiedResource() {
  const manifestUrl = new URL("./resources/resource-manifest.json", self.location.href);
  if (manifestUrl.origin !== self.location.origin) throw new Error("Resource manifest must be same-origin");
  const manifestResponse = await fetch(manifestUrl, { cache: "no-cache", credentials: "same-origin" });
  if (!manifestResponse.ok || new URL(manifestResponse.url).origin !== self.location.origin) {
    throw new Error(`Resource manifest fetch failed: ${manifestResponse.status}`);
  }
  const manifestText = await manifestResponse.text();
  if (manifestText.length > 64 * 1024) throw new Error("Resource manifest exceeds its size bound");
  const manifest = JSON.parse(manifestText);
  exactKeys(
    manifest,
    ["apertium_kaz_commit", "project_commit", "project_version", "proofs", "resource", "schema", "unsupported_modes"],
    "resource manifest",
  );
  exactKeys(manifest.resource, ["bytes", "graph", "path", "sha256"], "resource record");
  exactKeys(manifest.proofs, ["candidate_probe_ledger", "input_epsilon_cycle_reachable"], "proof record");
  exactKeys(manifest.proofs.candidate_probe_ledger, ["bytes", "path", "sha256"], "probe-ledger record");
  if (
    manifest.schema !== "kazstem.browser-resource-manifest.v1" ||
    manifest.resource.path !== "analyzer.kzc" ||
    !Number.isSafeInteger(manifest.resource.bytes) ||
    manifest.resource.bytes < 1 || manifest.resource.bytes > MAX_RESOURCE_BYTES ||
    !/^[0-9a-f]{64}$/.test(manifest.resource.sha256) ||
    manifest.proofs.candidate_probe_ledger.path !== "probe-ledger-summary.json" ||
    !Number.isSafeInteger(manifest.proofs.candidate_probe_ledger.bytes) ||
    manifest.proofs.candidate_probe_ledger.bytes < 1 || manifest.proofs.candidate_probe_ledger.bytes > 64 * 1024 ||
    !/^[0-9a-f]{64}$/.test(manifest.proofs.candidate_probe_ledger.sha256) ||
    manifest.proofs.input_epsilon_cycle_reachable !== false
  ) {
    throw new Error("Invalid or unsafe browser resource manifest");
  }
  const resourceUrl = new URL(`./resources/${manifest.resource.path}`, self.location.href);
  if (resourceUrl.origin !== self.location.origin) throw new Error("Analyzer resource must be same-origin");
  const resourceResponse = await fetch(resourceUrl, { cache: "force-cache", credentials: "same-origin" });
  if (!resourceResponse.ok || new URL(resourceResponse.url).origin !== self.location.origin) {
    throw new Error(`Analyzer resource fetch failed: ${resourceResponse.status}`);
  }
  const declaredLength = Number(resourceResponse.headers.get("content-length"));
  if (Number.isFinite(declaredLength) && declaredLength > manifest.resource.bytes) {
    throw new Error("Analyzer response exceeds the manifested byte size");
  }
  const buffer = await resourceResponse.arrayBuffer();
  if (buffer.byteLength !== manifest.resource.bytes) throw new Error("Analyzer byte size mismatch");
  const observedHash = await sha256Hex(buffer);
  if (observedHash !== manifest.resource.sha256) throw new Error("Analyzer SHA-256 mismatch");
  const runtime = CsrTransducer.fromArrayBuffer(buffer);
  if (
    runtime.metadata.project.commit !== manifest.project_commit ||
    runtime.metadata.project.version !== manifest.project_version ||
    runtime.metadata.source.apertium_kaz_commit !== manifest.apertium_kaz_commit
  ) {
    throw new Error("Analyzer metadata identity does not match its outer manifest");
  }
  if (JSON.stringify(runtime.metadata.graph) !== JSON.stringify(manifest.resource.graph)) {
    throw new Error("Analyzer inner/outer graph manifests differ");
  }
  if (JSON.stringify(manifest.unsupported_modes) !== JSON.stringify(EXPECTED_UNSUPPORTED_MODES)) {
    throw new Error("Analyzer unsupported-mode declaration is missing or reordered");
  }
  const proofUrl = new URL(`./resources/${manifest.proofs.candidate_probe_ledger.path}`, self.location.href);
  if (proofUrl.origin !== self.location.origin) throw new Error("Probe ledger must be same-origin");
  const proofResponse = await fetch(proofUrl, { cache: "force-cache", credentials: "same-origin" });
  if (!proofResponse.ok || new URL(proofResponse.url).origin !== self.location.origin) {
    throw new Error(`Probe-ledger fetch failed: ${proofResponse.status}`);
  }
  const proofBuffer = await proofResponse.arrayBuffer();
  if (proofBuffer.byteLength !== manifest.proofs.candidate_probe_ledger.bytes) throw new Error("Probe-ledger byte size mismatch");
  const proofHash = await sha256Hex(proofBuffer);
  if (proofHash !== manifest.proofs.candidate_probe_ledger.sha256) throw new Error("Probe-ledger SHA-256 mismatch");
  const proof = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(proofBuffer));
  if (
    proof.schema !== "kazstem.browser-probe-ledger-summary.v1" || proof.result !== "pass" ||
    proof.resource_sha256 !== observedHash || proof.resource_sha256_verified_before_constructor !== true ||
    proof.probe_count !== 31568
  ) {
    throw new Error("Probe-ledger result or resource binding is invalid");
  }
  return { runtime, manifest, observedHash, proofHash };
}

function isComponent(character) {
  return LETTER_MARK_NUMBER.test(character);
}

function isHyphenInternal(points, index) {
  return (
    ORTHOGRAPHIC_HYPHENS.has(points[index]) && index > 0 && index + 1 < points.length &&
    LETTER_MARK.test(points[index - 1]) && LETTER_MARK.test(points[index + 1])
  );
}

function classify(surface, analyses) {
  if (/^\s+$/u.test(surface)) return "space";
  if (analyses.length && analyses.every((analysis) => analysis.upos === "PUNCT")) return "punct";
  if (analyses.length && analyses.every((analysis) => analysis.upos === "NUM")) return "number";
  if (/^\p{N}+$/u.test(surface)) return "number";
  if (/\p{L}/u.test(surface)) return "word";
  if (/^\p{P}+$/u.test(surface)) return "punct";
  return "symbol";
}

function dictionaryAnalyses(surface, profile) {
  const raw = transducer.lookup(surface.normalize("NFC"));
  return raw.map((candidate) => parseAnalysis(candidate, profile)).filter(Boolean);
}

function makeToken(surface, sliceStart, codePointStart, profile) {
  const normalized = surface.normalize("NFC");
  let analyses = dictionaryAnalyses(normalized, profile);
  let kind = classify(surface, analyses);
  if (!analyses.length && ["word", "number"].includes(kind)) {
    analyses = [kind === "number" ? numberAnalysis(normalized) : unknownAnalysis(normalized)];
  }
  kind = classify(surface, analyses);
  const token = {
    text: surface,
    start: codePointStart,
    end: codePointStart + Array.from(surface).length,
    kind,
    normalized: normalized === surface ? null : normalized,
    analyses,
    selected: analyses.length === 1 ? 0 : null,
    sentence_end: [...surface].some((character) => ".!?".includes(character)),
  };
  Object.defineProperties(token, {
    slice_start: { value: sliceStart, enumerable: false },
    slice_end: { value: sliceStart + surface.length, enumerable: false },
  });
  return token;
}

function tokenize(text, profile) {
  const tokens = [];
  let utf16 = 0;
  let codePoints = 0;
  while (utf16 < text.length) {
    const rest = text.slice(utf16);
    const points = Array.from(rest);
    if (WHITESPACE.test(points[0])) {
      let pointCount = 1;
      while (pointCount < points.length && WHITESPACE.test(points[pointCount])) pointCount += 1;
      const surface = points.slice(0, pointCount).join("");
      tokens.push(makeToken(surface, utf16, codePoints, profile));
      utf16 += surface.length;
      codePoints += Array.from(surface).length;
      continue;
    }

    // Preserve an exact whole dictionary cohort (notably 51%-дан) before
    // applying orthographic fallback boundaries.
    let runCount = points.findIndex((point) => WHITESPACE.test(point));
    if (runCount < 0) runCount = points.length;
    const run = points.slice(0, runCount).join("");
    if (dictionaryAnalyses(run.normalize("NFC"), profile).length) {
      tokens.push(makeToken(run, utf16, codePoints, profile));
      utf16 += run.length;
      codePoints += Array.from(run).length;
      continue;
    }

    let pointCount = 1;
    if (isComponent(points[0])) {
      while (
        pointCount < points.length &&
        (isComponent(points[pointCount]) || isHyphenInternal(points, pointCount))
      ) pointCount += 1;
    } else if (DASH_PUNCTUATION.has(points[0]) || ORTHOGRAPHIC_HYPHENS.has(points[0])) {
      pointCount = 1;
    }
    const surface = points.slice(0, pointCount).join("");
    tokens.push(makeToken(surface, utf16, codePoints, profile));
    utf16 += surface.length;
    codePoints += Array.from(surface).length;
  }
  if (tokens.map((token) => token.text).join("") !== text) throw new Error("Tokenizer reconstruction invariant failed");
  return tokens;
}

function findBoundedSpans(text, tokens, profile) {
  const spans = [];
  for (let startToken = 0; startToken < tokens.length; startToken += 1) {
    if (tokens[startToken].kind === "space") continue;
    for (let endToken = startToken + 2; endToken <= Math.min(tokens.length, startToken + 8); endToken += 1) {
      const sliceStart = tokens[startToken].slice_start;
      const sliceEnd = tokens[endToken - 1].slice_end;
      const start = tokens[startToken].start;
      const end = tokens[endToken - 1].end;
      const surface = text.slice(sliceStart, sliceEnd);
      if (surface.length > 96) break;
      if (!/\s/u.test(surface)) continue;
      const analyses = dictionaryAnalyses(surface.normalize("NFC"), profile);
      if (!analyses.length) continue;
      spans.push({
        text: surface, start, end, token_start: startToken, token_end: endToken,
        normalized: surface.normalize("NFC") === surface ? null : surface.normalize("NFC"),
        analyses, selected: analyses.length === 1 ? 0 : null, sentence_end: false,
      });
    }
  }
  return spans;
}

function analyze(text, options) {
  const profile = options.udProfile ?? "universal";
  const tokens = tokenize(text, profile);
  const spans = findBoundedSpans(text, tokens, profile);
  return {
    schema_version: "qazmorph.document.v2",
    text,
    normalized_text: text.normalize("NFC") === text ? null : text.normalize("NFC"),
    tokens,
    analysis_spans: spans,
    mode: "lattice",
    resource_version: `${identity.project_version}+browser.${identity.resource.sha256}.proof.${identity.proofs.candidate_probe_ledger.sha256}`,
    resource_sha256: identity.resource.sha256,
    probe_ledger: identity.proofs.candidate_probe_ledger,
    ud_profile: profile,
    browser_limits: {
      full_document_partition_parity: false,
      phrase_span_scan_complete: false,
      phrase_span_max_tokens: 8,
      phrase_span_max_utf16: 96,
      unsupported_modes: identity.unsupported_modes,
    },
  };
}

async function initialize() {
  const loaded = await fetchVerifiedResource();
  transducer = loaded.runtime;
  identity = loaded.manifest;
  self.postMessage({
    type: "ready",
    identity: {
      projectVersion: identity.project_version,
      projectCommit: identity.project_commit,
      apertiumCommit: identity.apertium_kaz_commit,
      resourceBytes: identity.resource.bytes,
      resourceSha256: loaded.observedHash,
      probeLedger: identity.proofs.candidate_probe_ledger,
      probeLedgerSha256: loaded.proofHash,
      unsupportedModes: identity.unsupported_modes,
    },
  });
}

self.onmessage = (event) => {
  const message = event.data;
  try {
    if (message.type === "start") {
      if (!transducer) throw new Error("Analyzer resource is not ready");
      jobs.set(message.jobId, { parts: [], length: 0, options: message.options ?? {} });
      self.postMessage({ type: "ack", jobId: message.jobId, sequence: -1 });
    } else if (message.type === "chunk") {
      const job = jobs.get(message.jobId);
      if (!job) throw new Error("Unknown analysis job");
      if (typeof message.text !== "string" || job.length + message.text.length > MAX_INPUT_UTF16) {
        throw new Error("Input exceeds the buffered 4 Mi UTF-16-unit POC bound");
      }
      job.parts.push(message.text);
      job.length += message.text.length;
      self.postMessage({ type: "ack", jobId: message.jobId, sequence: message.sequence, consumed: job.length });
    } else if (message.type === "finish") {
      const job = jobs.get(message.jobId);
      if (!job) throw new Error("Unknown analysis job");
      jobs.delete(message.jobId);
      const document = analyze(job.parts.join(""), job.options);
      const output = serialize(document, job.options.format ?? "jsonl");
      if (output.length > MAX_OUTPUT_UTF16) throw new Error("Output exceeds the buffered 32 Mi UTF-16-unit POC bound");
      self.postMessage({
        type: "result",
        jobId: message.jobId,
        output,
        summary: { tokens: document.tokens.length, spans: document.analysis_spans.length },
      });
    } else if (message.type === "cancel") {
      jobs.delete(message.jobId);
      self.postMessage({ type: "cancelled", jobId: message.jobId });
    }
  } catch (error) {
    if (message?.jobId) jobs.delete(message.jobId);
    self.postMessage({ type: "error", jobId: message?.jobId, message: error instanceof Error ? error.message : String(error) });
  }
};

initialize().catch((error) => {
  self.postMessage({ type: "fatal", message: error instanceof Error ? error.message : String(error) });
});
