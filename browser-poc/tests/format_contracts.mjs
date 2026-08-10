import assert from "node:assert/strict";
import fs from "node:fs";
import { parseAnalysis, unknownAnalysis } from "../web/analysis.js";
import { unicodeCasefold } from "../web/casefold.js";
import { serialize } from "../web/formats.js";

const fixturePath = process.argv[2];
if (!fixturePath) throw new Error("usage: node format_contracts.mjs NATIVE_FIXTURE");
const fixture = JSON.parse(fs.readFileSync(fixturePath, "utf8"));
for (const row of fixture.casefold_examples) assert.equal(unicodeCasefold(row.input), row.expected);
const known = parseAnalysis(fixture.raw_analysis);
assert.deepEqual(known, fixture.analysis);

const tokens = fixture.document.tokens.map((token) => ({
  text: token.text,
  start: token.start,
  end: token.end,
  kind: token.kind,
  normalized: token.normalized,
  analyses: token.analysis_kind === "known" ? [known] : token.analysis_kind === "unknown" ? [unknownAnalysis(token.text)] : [],
  selected: token.selected,
  sentence_end: token.sentence_end,
}));
const spanFixture = fixture.document.span;
const document = {
  text: fixture.document.text,
  normalized_text: fixture.document.normalized_text,
  tokens,
  analysis_spans: [{
    ...spanFixture,
    analyses: [known],
  }],
  mode: "lattice",
  resource_version: "fixture",
  ud_profile: "universal",
};

assert.equal(tokens.map((token) => token.text).join(""), document.text);
assert.equal(tokens[0].end, 1, "astral emoji must consume one code-point offset");
assert.equal(tokens[2].end - tokens[2].start, 6, "decomposed token offsets must remain original code points");
for (const format of ["text", "json", "jsonl", "xml", "conllu"]) {
  assert.equal(serialize(document, format), fixture.expected[format], `${format} must equal native v0.2.1 output`);
}

const invalid = {
  ...document,
  text: "\0",
  normalized_text: null,
  tokens: [{ text: "\0", start: 0, end: 1, kind: "symbol", normalized: null, analyses: [], selected: null, sentence_end: false }],
  analysis_spans: [],
};
assert.throws(() => serialize(invalid, "xml"), /XML 1\.0-forbidden U\+0000/);
assert.equal(fixture.xml_nul_error, "XML output token text contains XML 1.0-forbidden code point U+0000 at character 0");

process.stdout.write(JSON.stringify({
  schema: "kazstem.browser-format-contracts.v1",
  native_fixture_schema: fixture.schema,
  assertions: 15,
  result: "pass",
}) + "\n");
