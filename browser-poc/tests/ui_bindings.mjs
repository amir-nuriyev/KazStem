import assert from "node:assert/strict";
import fs from "node:fs";

const [appPath, htmlPath] = process.argv.slice(2);
if (!appPath || !htmlPath) {
  throw new Error("usage: node ui_bindings.mjs APP_JS INDEX_HTML");
}

const app = fs.readFileSync(appPath, "utf8");
const html = fs.readFileSync(htmlPath, "utf8");
const expected = {
  runtimeStatus: "runtime-status",
  inputSize: "input-size",
  dropZone: "drop-zone",
  fileInput: "file-input",
  fileName: "file-name",
  sourceText: "source-text",
  format: "format",
  analyze: "analyze",
  cancel: "cancel",
  progress: "progress",
  download: "download",
  result: "result",
  projectId: "project-id",
  resourceId: "resource-id",
  sourceId: "source-id",
  probeId: "probe-id",
  offlineId: "offline-id",
};

const objectBody = app.match(/const elements = \{([\s\S]*?)\n\};/)?.[1];
assert.ok(objectBody, "app.js must declare an explicit elements object");
const observed = Object.fromEntries(
  [...objectBody.matchAll(/^\s*([A-Za-z_$][\w$]*): document\.getElementById\("([^"]+)"\),?$/gm)]
    .map((match) => [match[1], match[2]]),
);
assert.deepEqual(observed, expected, "camelCase properties must map explicitly to hyphenated DOM ids");
assert.doesNotMatch(app, /Object\.fromEntries\([\s\S]*?getElementById/, "generic id-key mapping recreates the original bug");
assert.match(
  app,
  /Object\.values\(elements\)\.some\(\(element\) => element === null\)/,
  "missing DOM nodes must fail before listeners or worker startup",
);
const clearResultBody = app.match(/function clearResult\(\) \{([\s\S]*?)\n\}/)?.[1];
assert.ok(clearResultBody, "app.js must centralize stale-result invalidation");
assert.match(clearResultBody, /lastResult = "";/);
assert.match(clearResultBody, /elements\.result\.value = "";/);
assert.match(clearResultBody, /elements\.download\.disabled = true;/);
assert.match(app.match(/async function analyze\(\) \{([\s\S]*?)\n\}/)?.[1] ?? "", /clearResult\(\);/);
assert.match(app.match(/function fail\(message\) \{([\s\S]*?)\n\}/)?.[1] ?? "", /clearResult\(\);/);

const htmlIds = [...html.matchAll(/\sid="([^"]+)"/g)].map((match) => match[1]);
for (const [property, id] of Object.entries(expected)) {
  assert.equal(htmlIds.filter((candidate) => candidate === id).length, 1, `${property}/${id} must bind exactly one node`);
  assert.match(app, new RegExp(`elements\\.${property}\\b`), `${property} must be referenced through the camelCase binding`);
}

// This is the precise regression: the former implementation keyed the object
// by raw ids ("runtime-status") while all call sites used camelCase
// (elements.runtimeStatus). Keep the counterexample executable in the test so
// a future "simplification" cannot silently restore it.
const fakeNodes = Object.fromEntries(htmlIds.map((id) => [id, { id }]));
const legacy = Object.fromEntries(Object.values(expected).map((id) => [id, fakeNodes[id]]));
assert.equal(legacy.runtimeStatus, undefined);
assert.equal(legacy.fileInput, undefined);
const fixed = Object.fromEntries(Object.entries(expected).map(([property, id]) => [property, fakeNodes[id]]));
assert.equal(fixed.runtimeStatus.id, "runtime-status");
assert.equal(fixed.fileInput.id, "file-input");

process.stdout.write(JSON.stringify({
  schema: "kazstem.browser-ui-bindings.v1",
  bindings: Object.keys(expected).length,
  assertions: 49,
  result: "pass",
}) + "\n");
