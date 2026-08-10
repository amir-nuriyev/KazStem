import assert from "node:assert/strict";
import fs from "node:fs";
import { CsrTransducer } from "../web/csr.js";

const resourcePath = process.argv[2];
if (!resourcePath) throw new Error("usage: node malformed_resource.mjs RESOURCE");
const source = fs.readFileSync(resourcePath);
const original = source.buffer.slice(source.byteOffset, source.byteOffset + source.byteLength);
const decoder = new TextDecoder();
const encoder = new TextEncoder();
const align4 = (value) => (value + 3) & ~3;

function metadataOf(buffer) {
  const length = new DataView(buffer).getUint32(8, true);
  return JSON.parse(decoder.decode(new Uint8Array(buffer, 12, length)));
}

function rebuild(buffer, mutate) {
  const view = new DataView(buffer);
  const oldLength = view.getUint32(8, true);
  const metadata = metadataOf(buffer);
  mutate(metadata);
  const encoded = encoder.encode(JSON.stringify(metadata));
  const oldPayload = new Uint8Array(buffer, align4(12 + oldLength));
  const output = new ArrayBuffer(align4(12 + encoded.length) + oldPayload.length);
  const bytes = new Uint8Array(output);
  bytes.set(new Uint8Array(buffer, 0, 8), 0);
  new DataView(output).setUint32(8, encoded.length, true);
  bytes.set(encoded, 12);
  bytes.set(oldPayload, align4(12 + encoded.length));
  return output;
}

function clone(buffer) {
  return buffer.slice(0);
}

assert.doesNotThrow(() => CsrTransducer.fromArrayBuffer(clone(original)));

const badMagic = clone(original);
new Uint8Array(badMagic)[0] ^= 0xff;
assert.throws(() => CsrTransducer.fromArrayBuffer(badMagic), /Unsupported or truncated/);

assert.throws(
  () => CsrTransducer.fromArrayBuffer(rebuild(original, (metadata) => { metadata.unexpected = true; })),
  /Unexpected resource metadata fields/,
);
assert.throws(
  () => CsrTransducer.fromArrayBuffer(rebuild(original, (metadata) => { metadata.arrays[1].name = "row_offsets"; })),
  /duplicate|reordered/i,
);
assert.throws(
  () => CsrTransducer.fromArrayBuffer(rebuild(original, (metadata) => { metadata.att_symbol_audit.meta_symbols.push("@_IDENTITY_SYMBOL_@"); })),
  /unsupported HFST/i,
);

const badTarget = clone(original);
const metadata = metadataOf(badTarget);
let cursor = align4(12 + new DataView(badTarget).getUint32(8, true));
cursor += metadata.arrays[0].length * 4;
new DataView(badTarget).setUint32(cursor, metadata.graph.state_count, true);
assert.throws(() => CsrTransducer.fromArrayBuffer(badTarget), /out of bounds/);

const transducer = CsrTransducer.fromArrayBuffer(clone(original));
assert.throws(() => transducer.lookup("кітап", { maxSteps: 1 }), /step bound/);
assert.throws(() => transducer.lookup("кітап", { maxCandidates: 1 }), /candidate bound/);
assert.throws(() => transducer.lookup("а".repeat(257)), /input exceeds/);

process.stdout.write(JSON.stringify({
  schema: "kazstem.browser-malformed-resource-tests.v1",
  assertions: 8,
  result: "pass",
}) + "\n");
