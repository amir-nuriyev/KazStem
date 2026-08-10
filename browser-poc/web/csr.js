const MAGIC = "KZCSR001";
const decoder = new TextDecoder("utf-8", { fatal: true });

function align4(value) {
  return (value + 3) & ~3;
}

function readMagic(bytes) {
  return String.fromCharCode(...bytes.subarray(0, 8));
}

function requireExactKeys(object, expected, label) {
  if (!object || typeof object !== "object" || Array.isArray(object)) {
    throw new Error(`Invalid ${label}`);
  }
  const observed = Object.keys(object).sort();
  const wanted = [...expected].sort();
  if (observed.length !== wanted.length || observed.some((key, index) => key !== wanted[index])) {
    throw new Error(`Unexpected ${label} fields: ${observed.join(",")}`);
  }
}

export class CsrTransducer {
  static fromArrayBuffer(buffer) {
    const bytes = new Uint8Array(buffer);
    if (bytes.byteLength < 16 || readMagic(bytes) !== MAGIC) {
      throw new Error("Unsupported or truncated KazStem browser resource");
    }
    const view = new DataView(buffer);
    const metadataLength = view.getUint32(8, true);
    const metadataEnd = 12 + metadataLength;
    if (metadataEnd > bytes.byteLength) {
      throw new Error("Truncated KazStem browser resource metadata");
    }
    const metadata = JSON.parse(decoder.decode(bytes.subarray(12, metadataEnd)));
    if (metadata.schema !== "kazstem.browser-csr.v1") {
      throw new Error(`Unsupported resource schema: ${metadata.schema}`);
    }
    requireExactKeys(
      metadata,
      ["arrays", "att_symbol_audit", "endianness", "graph", "input_symbols", "output_symbols", "project", "schema", "source"],
      "resource metadata",
    );
    requireExactKeys(
      metadata.graph,
      ["arc_count", "final_count", "input_epsilon_cycle_reachable", "start_state", "state_count"],
      "resource graph metadata",
    );
    requireExactKeys(metadata.project, ["commit", "name", "version"], "project metadata");
    requireExactKeys(metadata.source, ["apertium_kaz_commit", "att_sha256"], "source metadata");
    if (metadata.endianness !== "little") throw new Error("Unsupported resource endianness");
    requireExactKeys(
      metadata.att_symbol_audit,
      ["flag_diacritics", "identity_symbols", "meta_symbols", "supported_meta_symbols", "unknown_symbols"],
      "ATT symbol audit",
    );
    if (
      JSON.stringify(metadata.att_symbol_audit.meta_symbols) !== JSON.stringify(["@0@", "@_SPACE_@"]) ||
      metadata.att_symbol_audit.identity_symbols.length ||
      metadata.att_symbol_audit.unknown_symbols.length ||
      metadata.att_symbol_audit.flag_diacritics.length
    ) {
      throw new Error("Resource contains unsupported HFST identity, unknown, flag, or control symbols");
    }

    let cursor = align4(metadataEnd);
    const arrays = {};
    const constructors = { u32: Uint32Array, u16: Uint16Array, u8: Uint8Array };
    const widths = { u32: 4, u16: 2, u8: 1 };
    const expectedArrays = ["row_offsets", "targets", "inputs", "outputs", "finals"];
    const expectedTypes = ["u32", "u32", "u16", "u16", "u8"];
    if (
      metadata.arrays.length !== expectedArrays.length ||
      metadata.arrays.some(
        (entry, index) => entry?.name !== expectedArrays[index] || entry?.type !== expectedTypes[index],
      )
    ) {
      throw new Error("Unexpected, missing, duplicate, or reordered resource arrays");
    }
    for (const entry of metadata.arrays) {
      requireExactKeys(entry, ["length", "name", "type"], `array ${entry?.name ?? "?"}`);
      const Constructor = constructors[entry.type];
      const width = widths[entry.type];
      if (!Constructor || !Number.isSafeInteger(entry.length) || entry.length < 0) {
        throw new Error("Invalid resource array manifest");
      }
      const end = cursor + entry.length * width;
      if (end > bytes.byteLength) {
        throw new Error(`Truncated resource array: ${entry.name}`);
      }
      arrays[entry.name] = new Constructor(buffer, cursor, entry.length);
      cursor = end;
    }
    if (cursor !== bytes.byteLength) {
      throw new Error("Resource has trailing or misaligned data");
    }
    return new CsrTransducer(metadata, arrays);
  }

  constructor(metadata, arrays) {
    this.metadata = metadata;
    this.rowOffsets = arrays.row_offsets;
    this.targets = arrays.targets;
    this.inputs = arrays.inputs;
    this.outputs = arrays.outputs;
    this.finals = arrays.finals;
    this.inputSymbols = metadata.input_symbols;
    this.outputSymbols = metadata.output_symbols;
    if (
      !Array.isArray(this.inputSymbols) ||
      !Array.isArray(this.outputSymbols) ||
      this.inputSymbols[0] !== "@0@" ||
      this.outputSymbols[0] !== "" ||
      new Set(this.inputSymbols).size !== this.inputSymbols.length ||
      new Set(this.outputSymbols).size !== this.outputSymbols.length ||
      this.inputSymbols.slice(1).some((symbol) => typeof symbol !== "string" || Array.from(symbol).length !== 1) ||
      this.outputSymbols.some((symbol) => typeof symbol !== "string")
    ) {
      throw new Error("Invalid or duplicate resource symbol table");
    }
    this.outputCodePointLengths = this.outputSymbols.map((symbol) => Array.from(symbol).length);
    this.inputIds = new Map(this.inputSymbols.map((symbol, index) => [symbol, index]));
    const { state_count: stateCount, arc_count: arcCount } = metadata.graph;
    if (
      this.rowOffsets.length !== stateCount + 1 ||
      this.targets.length !== arcCount ||
      this.inputs.length !== arcCount ||
      this.outputs.length !== arcCount ||
      this.finals.length !== stateCount ||
      this.rowOffsets[stateCount] !== arcCount
    ) {
      throw new Error("Resource graph dimensions do not match its manifest");
    }
    if (
      !Number.isSafeInteger(stateCount) || stateCount < 1 ||
      !Number.isSafeInteger(arcCount) || arcCount < 0 ||
      !Number.isSafeInteger(metadata.graph.start_state) ||
      metadata.graph.start_state < 0 || metadata.graph.start_state >= stateCount ||
      this.rowOffsets[0] !== 0
    ) {
      throw new Error("Invalid resource graph bounds");
    }
    let observedFinals = 0;
    for (let state = 0; state < stateCount; state += 1) {
      if (this.rowOffsets[state] > this.rowOffsets[state + 1] || this.rowOffsets[state + 1] > arcCount) {
        throw new Error("Resource CSR row offsets are not monotone and bounded");
      }
      if (this.finals[state] > 1) throw new Error("Invalid final-state bitmap value");
      observedFinals += this.finals[state];
    }
    if (observedFinals !== metadata.graph.final_count) throw new Error("Final-state count mismatch");
    for (let arc = 0; arc < arcCount; arc += 1) {
      if (
        this.targets[arc] >= stateCount ||
        this.inputs[arc] >= this.inputSymbols.length ||
        this.outputs[arc] >= this.outputSymbols.length
      ) {
        throw new Error("Resource arc target or symbol ID is out of bounds");
      }
    }
    if (metadata.graph.input_epsilon_cycle_reachable !== false) {
      throw new Error("Resource did not pass the input-epsilon acyclicity gate");
    }
  }

  lookup(surface, options = {}) {
    const maxCandidates = options.maxCandidates ?? 512;
    const maxSteps = options.maxSteps ?? 250_000;
    const maxOutputCodePoints = options.maxOutputCodePoints ?? 4096;
    const input = Array.from(surface.normalize("NFC"));
    if (input.length > (options.maxInputCodePoints ?? 256)) {
      throw new Error("Lookup input exceeds the browser resource bound");
    }
    const inputIds = input.map((symbol) => this.inputIds.get(symbol) ?? -1);
    if (inputIds.includes(-1)) {
      return [];
    }

    const resultPaths = [];
    const resultSet = new Set();
    const stack = [{ state: this.metadata.graph.start_state, position: 0, output: null, outputCodePoints: 0 }];
    let steps = 0;
    while (stack.length) {
      if (++steps > maxSteps) {
        throw new Error("Lookup exceeded the deterministic step bound");
      }
      const frame = stack.pop();

      if (frame.position === inputIds.length && this.finals[frame.state]) {
        const tokens = [];
        for (let node = frame.output; node; node = node.parent) tokens.push(node.id);
        tokens.reverse();
        const key = tokens.join(",");
        if (!resultSet.has(key)) {
          resultSet.add(key);
          resultPaths.push(tokens);
          if (resultPaths.length > maxCandidates) {
            throw new Error("Lookup exceeded the deterministic candidate bound");
          }
        }
      }

      const begin = this.rowOffsets[frame.state];
      const end = this.rowOffsets[frame.state + 1];
      // Reverse push order so the original deterministic arc order is visited
      // first. Candidate-set equality is the normative gate.
      for (let arc = end - 1; arc >= begin; arc -= 1) {
        const inputId = this.inputs[arc];
        const epsilon = inputId === 0;
        if (!epsilon && (frame.position >= inputIds.length || inputIds[frame.position] !== inputId)) {
          continue;
        }
        const outputId = this.outputs[arc];
        const outputCodePoints = frame.outputCodePoints + this.outputCodePointLengths[outputId];
        if (outputCodePoints > maxOutputCodePoints) {
          throw new Error("Lookup exceeded the deterministic output bound");
        }
        stack.push({
          state: this.targets[arc],
          position: frame.position + (epsilon ? 0 : 1),
          output: outputId === 0 ? frame.output : { parent: frame.output, id: outputId },
          outputCodePoints,
        });
      }
    }
    // HFST stores one-level lookup results in std::set<pair<weight,
    // vector<string>>>. This unweighted graph therefore orders candidates by
    // output-symbol vectors, not discovery order or concatenated raw strings.
    resultPaths.sort((left, right) => {
      const length = Math.min(left.length, right.length);
      for (let index = 0; index < length; index += 1) {
        if (left[index] !== right[index]) return left[index] - right[index];
      }
      return left.length - right.length;
    });
    return resultPaths.map((path) => path.map((id) => this.outputSymbols[id]).join(""));
  }
}

export async function sha256Hex(buffer) {
  if (!globalThis.crypto?.subtle) {
    throw new Error("Web Crypto is required to verify the resource identity");
  }
  const digest = await globalThis.crypto.subtle.digest("SHA-256", buffer);
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}
