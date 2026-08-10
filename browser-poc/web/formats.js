function grammar(analysis) {
  const features = Object.entries(analysis.features).map(([key, value]) => `${key}=${value}`);
  return [analysis.upos, ...features].join(",");
}

function mystemAnalysis(analysis) {
  const row = { lex: analysis.lemma, gr: grammar(analysis) };
  if (analysis.guessed) row.qual = "bastard";
  if (analysis.score !== null) row.wt = analysis.score;
  return row;
}

function analysisJson(analysis) {
  return { ...analysis, lex: analysis.lemma, gr: grammar(analysis), qual: analysis.guessed ? "guessed" : null };
}

function xml10(value, field) {
  let index = 0;
  for (const character of value) {
    const codepoint = character.codePointAt(0);
    const valid =
      [0x09, 0x0a, 0x0d].includes(codepoint) ||
      (codepoint >= 0x20 && codepoint <= 0xd7ff) ||
      (codepoint >= 0xe000 && codepoint <= 0xfffd) ||
      (codepoint >= 0x10000 && codepoint <= 0x10ffff);
    if (!valid) throw new Error(`XML output ${field} contains XML 1.0-forbidden U+${codepoint.toString(16).toUpperCase().padStart(4, "0")} at character ${index}`);
    index += 1;
  }
  return value;
}

function xmlText(value, field) {
  return xml10(value, field).replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;");
}

function xmlAttribute(value, field) {
  return `"${xmlText(String(value), field).replaceAll('"', "&quot;")}"`;
}

export function formatText(document) {
  return document.tokens.map((token) => {
    if (!["word", "number"].includes(token.kind)) return token.text;
    if (!token.analyses.length) return token.text;
    const body = token.analyses.map((analysis) => `${analysis.lemma}${analysis.guessed ? "?" : ""}=${grammar(analysis)}`).join("|");
    return `${token.text}{${body}}`;
  }).join("");
}

export function formatJson(document) {
  const rows = document.tokens.map((token) => {
    const row = { text: token.text };
    if (["word", "number"].includes(token.kind) && token.analyses.length) row.analysis = token.analyses.map(mystemAnalysis);
    return row;
  });
  return `${JSON.stringify(rows)}\n`;
}

export function formatJsonl(document) {
  const rows = document.tokens.map((token, tokenIndex) => JSON.stringify({
    schema_version: "qazmorph.jsonl-record.v2",
    record_type: "token",
    consumes_input: true,
    token_index: tokenIndex,
    text: token.text,
    start: token.start,
    end: token.end,
    kind: token.kind,
    normalized: token.normalized,
    mode: document.mode,
    resource_version: document.resource_version,
    ud_profile: document.ud_profile,
    analysis: token.analyses.map(analysisJson),
    selected: token.selected,
    sentence_end: token.sentence_end,
  }));
  for (let spanIndex = 0; spanIndex < document.analysis_spans.length; spanIndex += 1) {
    const span = document.analysis_spans[spanIndex];
    rows.push(JSON.stringify({
      schema_version: "qazmorph.jsonl-record.v2",
      record_type: "analysis_span",
      consumes_input: false,
      span_index: spanIndex,
      text: span.text,
      start: span.start,
      end: span.end,
      token_start: span.token_start,
      token_end: span.token_end,
      normalized: span.normalized,
      mode: document.mode,
      resource_version: document.resource_version,
      ud_profile: document.ud_profile,
      analysis: span.analyses.map(analysisJson),
      selected: span.selected,
      sentence_end: span.sentence_end,
    }));
  }
  return rows.length ? `${rows.join("\n")}\n` : "";
}

export function formatXml(document) {
  const chunks = ['<?xml version="1.0" encoding="UTF-8"?>', "<html><body><se>"];
  for (const token of document.tokens) {
    if (!["word", "number"].includes(token.kind)) {
      chunks.push(xmlText(token.text, "token text"));
      continue;
    }
    chunks.push("<w>", xmlText(token.text, "token text"));
    for (const analysis of token.analyses) {
      const attrs = [
        `lex=${xmlAttribute(analysis.lemma, "analysis lex")}`,
        `gr=${xmlAttribute(grammar(analysis), "analysis gr")}`,
      ];
      if (analysis.guessed) attrs.splice(1, 0, `qual=${xmlAttribute("bastard", "analysis qual")}`);
      chunks.push(`<ana ${attrs.join(" ")} />`);
    }
    chunks.push("</w>");
  }
  chunks.push("</se></body></html>\n");
  return chunks.join("");
}

export function formatConllu(document) {
  const lines = [];
  let index = 1;
  for (const token of document.tokens) {
    if (token.kind === "space") continue;
    const analysis = token.selected !== null ? token.analyses[token.selected] : (token.analyses.length === 1 ? token.analyses[0] : null);
    const lemma = analysis?.lemma ?? "_";
    const upos = analysis?.upos ?? (token.kind === "punct" ? "PUNCT" : "X");
    const features = analysis && Object.keys(analysis.features).length
      ? Object.entries(analysis.features).map(([key, value]) => `${key}=${value}`).join("|")
      : "_";
    const misc = [`StartChar=${token.start}`, `EndChar=${token.end}`];
    if (token.analyses.length > 1) misc.push(`Candidates=${token.analyses.length}`, "Unresolved=Yes");
    if (analysis?.guessed) misc.push("Guess=Yes");
    lines.push([index, token.text, lemma, upos, "_", features, "_", "_", "_", misc.join("|")].join("\t"));
    index += 1;
    if (token.sentence_end) { lines.push(""); index = 1; }
  }
  if (lines.at(-1) !== "") lines.push("");
  return `${lines.join("\n")}\n`;
}

export function serialize(document, format) {
  if (format === "text") return formatText(document);
  if (format === "json") return formatJson(document);
  if (format === "jsonl") return formatJsonl(document);
  if (format === "xml") return formatXml(document);
  if (format === "conllu") return formatConllu(document);
  throw new Error(`Unsupported output format: ${format}`);
}
