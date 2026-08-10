const MAX_FILE_BYTES = 4 * 1024 * 1024;
const elements = {
  runtimeStatus: document.getElementById("runtime-status"),
  inputSize: document.getElementById("input-size"),
  dropZone: document.getElementById("drop-zone"),
  fileInput: document.getElementById("file-input"),
  fileName: document.getElementById("file-name"),
  sourceText: document.getElementById("source-text"),
  format: document.getElementById("format"),
  analyze: document.getElementById("analyze"),
  cancel: document.getElementById("cancel"),
  progress: document.getElementById("progress"),
  download: document.getElementById("download"),
  result: document.getElementById("result"),
  projectId: document.getElementById("project-id"),
  resourceId: document.getElementById("resource-id"),
  sourceId: document.getElementById("source-id"),
  probeId: document.getElementById("probe-id"),
  offlineId: document.getElementById("offline-id"),
};
if (Object.values(elements).some((element) => element === null)) {
  throw new Error("KazStem Browser page is missing a required UI element");
}
const extensions = { text: "txt", json: "json", jsonl: "jsonl", xml: "xml", conllu: "conllu" };
let selectedFile = null;
let worker = null;
let ready = false;
let currentJob = null;
let lastResult = "";
let identity = null;
const acknowledgements = new Map();

function startWorker() {
  ready = false;
  elements.analyze.disabled = true;
  elements.runtimeStatus.textContent = "Loading verified analyzer…";
  worker = new Worker(new URL("./worker.js", import.meta.url), { type: "module", name: "kazstem-analyzer" });
  worker.addEventListener("message", handleWorkerMessage);
}

function setBusy(value) {
  elements.analyze.disabled = value || !ready;
  elements.cancel.hidden = !value;
  elements.fileInput.disabled = value;
  elements.sourceText.disabled = value;
  elements.format.disabled = value;
}

function updateSize() {
  elements.inputSize.textContent = `${elements.sourceText.value.length.toLocaleString()} characters`;
}

function clearResult() {
  lastResult = "";
  elements.result.value = "";
  elements.download.disabled = true;
}

function fail(message) {
  clearResult();
  elements.progress.textContent = message;
  elements.progress.classList.add("error");
  setBusy(false);
}

function waitForAck(jobId, sequence) {
  return new Promise((resolve, reject) => acknowledgements.set(`${jobId}:${sequence}`, { resolve, reject }));
}

async function sendChunk(jobId, sequence, text) {
  const pending = waitForAck(jobId, sequence);
  worker.postMessage({ type: "chunk", jobId, sequence, text });
  await pending;
}

async function streamInput(jobId) {
  if (!selectedFile) {
    await sendChunk(jobId, 0, elements.sourceText.value);
    return;
  }
  if (selectedFile.size > MAX_FILE_BYTES) throw new Error("File exceeds the buffered 4 MiB proof-of-concept limit");
  const reader = selectedFile.stream().pipeThrough(new TextDecoderStream("utf-8", { fatal: true })).getReader();
  let sequence = 0;
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      if (currentJob !== jobId) { await reader.cancel(); return; }
      await sendChunk(jobId, sequence, value);
      sequence += 1;
      elements.progress.textContent = `Read ${sequence.toLocaleString()} chunks locally…`;
    }
  } finally {
    reader.releaseLock();
  }
}

async function analyze() {
  const jobId = crypto.randomUUID();
  currentJob = jobId;
  clearResult();
  elements.progress.classList.remove("error");
  elements.progress.textContent = "Starting local worker…";
  setBusy(true);
  try {
    const started = waitForAck(jobId, -1);
    worker.postMessage({ type: "start", jobId, options: { format: elements.format.value, udProfile: "universal" } });
    await started;
    await streamInput(jobId);
    if (currentJob === jobId) {
      elements.progress.textContent = "Traversing the verified local dictionary…";
      worker.postMessage({ type: "finish", jobId });
    }
  } catch (error) {
    worker.postMessage({ type: "cancel", jobId });
    fail(error instanceof Error ? error.message : String(error));
  }
}

function chooseFile(file) {
  if (!file) return;
  if (file.size > MAX_FILE_BYTES) { fail("File exceeds the buffered 4 MiB proof-of-concept limit"); return; }
  selectedFile = file;
  elements.fileName.textContent = `${file.name} · ${file.size.toLocaleString()} bytes · streamed as UTF-8`;
  elements.sourceText.value = "";
  elements.sourceText.placeholder = "The selected file will be streamed directly to the worker.";
  updateSize();
}

function handleWorkerMessage(event) {
  const message = event.data;
  if (message.type === "ready") {
    ready = true;
    identity = message.identity;
    elements.runtimeStatus.textContent = "Verified analyzer ready";
    elements.projectId.textContent = `${identity.projectVersion} · ${identity.projectCommit}`;
    elements.resourceId.textContent = `${identity.resourceSha256} · ${identity.resourceBytes.toLocaleString()} bytes`;
    elements.sourceId.textContent = identity.apertiumCommit;
    elements.probeId.textContent = `${identity.probeLedger.path} · ${identity.probeLedgerSha256}`;
    elements.analyze.disabled = false;
  } else if (message.type === "ack") {
    const pending = acknowledgements.get(`${message.jobId}:${message.sequence}`);
    if (pending) { acknowledgements.delete(`${message.jobId}:${message.sequence}`); pending.resolve(); }
  } else if (message.type === "result" && message.jobId === currentJob) {
    currentJob = null;
    lastResult = message.output;
    elements.result.value = lastResult;
    elements.download.disabled = false;
    elements.progress.textContent = `Complete · ${message.summary.tokens.toLocaleString()} consuming tokens · ${message.summary.spans.toLocaleString()} non-consuming bounded spans`;
    setBusy(false);
  } else if (message.type === "cancelled" && message.jobId === currentJob) {
    currentJob = null;
    elements.progress.textContent = "Cancelled";
    setBusy(false);
  } else if (["error", "fatal"].includes(message.type)) {
    if (message.jobId === currentJob || message.type === "fatal") currentJob = null;
    fail(message.message);
  }
}

function cancelAndRestart() {
  if (!currentJob || !worker) return;
  worker.terminate();
  for (const pending of acknowledgements.values()) pending.reject(new Error("Cancelled"));
  acknowledgements.clear();
  currentJob = null;
  elements.progress.textContent = "Cancelled; restarting the verified local worker…";
  setBusy(false);
  startWorker();
}

elements.sourceText.addEventListener("input", () => { selectedFile = null; elements.fileName.textContent = "Using pasted text"; updateSize(); });
elements.fileInput.addEventListener("change", () => chooseFile(elements.fileInput.files[0]));
elements.dropZone.addEventListener("dragover", (event) => { event.preventDefault(); elements.dropZone.classList.add("dragging"); });
elements.dropZone.addEventListener("dragleave", () => elements.dropZone.classList.remove("dragging"));
elements.dropZone.addEventListener("drop", (event) => { event.preventDefault(); elements.dropZone.classList.remove("dragging"); chooseFile(event.dataTransfer.files[0]); });
elements.analyze.addEventListener("click", analyze);
elements.cancel.addEventListener("click", cancelAndRestart);
elements.download.addEventListener("click", () => {
  const format = elements.format.value;
  const blob = new Blob([lastResult], { type: format === "json" || format === "jsonl" ? "application/json;charset=utf-8" : "text/plain;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `kazstem-${identity.projectVersion}-${identity.resourceSha256.slice(0, 12)}.${extensions[format]}`;
  link.click();
  // Safari may begin resolving the synthetic download after the click task.
  setTimeout(() => URL.revokeObjectURL(url), 1000);
});

if ("serviceWorker" in navigator) {
  navigator.serviceWorker.register("./sw.js", { scope: "./" }).then(() => navigator.serviceWorker.ready).then((registration) => {
    if (!registration.active) throw new Error("service worker did not activate");
    elements.offlineId.textContent = "Offline cache active; no runtime network API";
  }).catch((error) => { elements.offlineId.textContent = `Offline cache unavailable: ${error.message}`; });
} else {
  elements.offlineId.textContent = "Service workers unsupported in this browser";
}
updateSize();
startWorker();
