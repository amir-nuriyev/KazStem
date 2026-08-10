import { unicodeCasefold } from "./casefold.js";

const POS = {
  n: "NOUN", np: "PROPN", adj: "ADJ", adv: "ADV", v: "VERB", vaux: "AUX", cop: "AUX",
  prn: "PRON", det: "DET", num: "NUM", post: "ADP", postadv: "ADV", cnjcoo: "CCONJ",
  cnjsub: "SCONJ", cnjadv: "SCONJ", ij: "INTJ", ideo: "X", paren: "X", qst: "PART",
  mod: "PART", mod_ass: "PART", mod_emo: "PART", emph: "PART", sent: "PUNCT", cm: "PUNCT",
  apos: "PUNCT", lquot: "PUNCT", rquot: "PUNCT", lpar: "PUNCT", rpar: "PUNCT",
  guio: "PUNCT", punct: "PUNCT", ltr: "SYM", sym: "SYM", abbr: "NOUN",
};
const PRIMARY_CASE = { nom: "Nom", gen: "Gen", dat: "Dat", acc: "Acc", loc: "Loc", abl: "Abl", ins: "Ins" };
const SECONDARY_CASE = { abe: "Abe", equ: "Equ", sim: "Equ", reas: "Cau" };
const VERB_FORM = {
  ger: "Ger", ger2: "Ger", ger_abs: "Ger", ger_fut: "Ger", ger_impf: "Ger", ger_obs: "Ger",
  ger_past: "Ger", ger_perf: "Ger", ger_ppot: "Ger", gpr_fut: "Part", gpr_impf: "Part",
  gpr_past: "Part", gpr_pot: "Part", gpr_pot2: "Part", gpr_ppot: "Part", gna_after: "Conv",
  gna_cond: "Conv", gna_impf: "Conv", gna_perf: "Conv", gna_until: "Conv", prc_cond: "Inf",
  prc_fplan: "Inf", prc_impf: "Inf", prc_irre: "Inf", prc_perf: "Inf", prc_plan: "Inf", prc_vol: "Inf",
};
const FINITE = new Set(["imp", "opt", "pres", "aor", "past", "ifi", "ifi_evid", "fut", "fut_plan", "pih"]);

function first(tags, mapping) {
  for (const tag of tags) if (mapping[tag] !== undefined) return mapping[tag];
  return undefined;
}

function last(tags, mapping) {
  for (let index = tags.length - 1; index >= 0; index -= 1) {
    if (mapping[tags[index]] !== undefined) return mapping[tags[index]];
  }
  return undefined;
}

export function projectUd(tags, profile = "universal") {
  if (!new Set(["universal", "ktb"]).has(profile)) throw new Error(`Unknown UD profile: ${profile}`);
  const upos = first(tags, POS) ?? "X";
  const features = {};
  const caseValue = last(tags, PRIMARY_CASE) ?? last(tags, SECONDARY_CASE) ?? (tags.includes("attr") ? "Nom" : undefined);
  if (caseValue) features.Case = caseValue;
  const verbForm = first(tags, VERB_FORM);
  if (verbForm) features.VerbForm = verbForm;
  else if (["VERB", "AUX"].includes(upos) && tags.some((tag) => FINITE.has(tag))) features.VerbForm = "Fin";

  const mood = first(tags, {
    imp: "Imp", opt: "Opt", prc_cond: "Cnd", gna_cond: "Cnd", prc_vol: "Des", prc_fplan: "Des",
    prc_plan: "Prp", fut_plan: "Des", gpr_pot: "Pot", gpr_pot2: "Pot", gpr_ppot: "Pot", ger_ppot: "Pot",
  });
  if (mood) features.Mood = mood;
  else if (["VERB", "AUX"].includes(upos) && features.VerbForm === "Fin") features.Mood = "Ind";
  const tense = first(tags, {
    past: "Past", ifi: "Past", ifi_evid: "Past", pih: "Past", pres: "Pres", aor: "Pres", fut: "Fut",
    fut_plan: "Fut", prc_fplan: "Fut", gpr_fut: "Fut", gpr_past: "Past", gpr_ppot: "Past",
    ger_fut: "Fut", ger_obs: "Fut", ger_past: "Past", ger_ppot: "Past",
  });
  if (tense) features.Tense = tense;
  const aspect = first(tags, {
    aor: "Hab", pih: "Imp", prc_impf: "Imp", gna_impf: "Imp", gpr_impf: "Imp", ger_impf: "Imp",
    prc_perf: "Perf", gna_perf: "Perf", ger_perf: "Perf",
  });
  if (aspect) features.Aspect = aspect;
  if (tags.includes("neg")) {
    if (["PRON", "DET"].includes(upos)) features.PronType = "Neg";
    else if (["VERB", "AUX"].includes(upos)) features.Polarity = "Neg";
  }
  if (tags.includes("comp")) features.Degree = "Cmp";
  const voices = new Set();
  for (const [tag, value] of Object.entries({ pass: "Pass", caus: "Cau", coop: "Rcp", recip: "Rcp" })) {
    if (tags.includes(tag) && (tag !== "recip" || upos === "VERB")) voices.add(value);
  }
  if (tags.includes("ref") && upos === "VERB") voices.add("Rfl");
  if (voices.size) features.Voice = [...voices].sort().join(",");
  if (tags.includes("evid") || tags.includes("ifi_evid")) features.Evident = profile === "ktb" ? "Fh" : "Nfh";
  if (tags.includes("frm")) features.Polite = "Form";
  const person = tags.find((tag) => ["p1", "p2", "p3"].includes(tag));
  if (person) features.Person = person.slice(1);
  if (tags.includes("pl") && ["VERB", "AUX", "PRON", "NOUN", "PROPN", "ADJ"].includes(upos)) features.Number = "Plur";
  else if (tags.includes("sg") && ["VERB", "AUX", "PRON"].includes(upos)) features.Number = "Sing";
  const possessor = tags.find((tag) => tag.startsWith("px") && tag.length >= 4);
  if (possessor) {
    const tail = possessor.slice(2);
    if (["1", "2", "3"].includes(tail[0])) features["Person[psor]"] = tail[0];
    if (tail.endsWith("pl")) features["Number[psor]"] = "Plur";
    else if (tail.endsWith("sg")) features["Number[psor]"] = "Sing";
    else if (tail.endsWith("sp")) features["Number[psor]"] = "Plur,Sing";
  }
  if (tags.includes("dem")) features.PronType = "Dem";
  else {
    const pronType = first(tags, { pers: "Prs", recip: "Rcp", itg: "Int", qnt: "Tot", ind: "Ind", ref: "Prs" });
    if (pronType && ["PRON", "DET", "ADV"].includes(upos)) features.PronType = pronType;
  }
  if (tags.includes("ref") && ["PRON", "DET"].includes(upos)) features.Reflex = "Yes";
  if (tags.includes("ord")) features.NumType = "Ord";
  else if (tags.includes("coll")) features.NumType = profile === "ktb" ? "Coll" : "Sets";
  else if (tags.includes("dist")) features.NumType = "Dist";
  else if (upos === "NUM") features.NumType = "Card";
  const nameType = first(tags, { top: "Geo", ant: "Giv", cog: "Sur", pat: "Pat", org: "Com", al: "Oth" });
  if (nameType) features.NameType = nameType;
  if (upos === "PROPN" && tags.includes("m")) features.Gender = "Masc";
  else if (upos === "PROPN" && tags.includes("f")) features.Gender = "Fem";
  if (tags.includes("abbr")) features.Abbr = "Yes";
  if (tags.includes("qst")) features.PartType = "Int";
  else if (tags.includes("emph")) features.PartType = "Emp";
  else if (tags.some((tag) => ["mod", "mod_ass", "mod_emo"].includes(tag))) features.PartType = "Mod";
  if (tags.includes("unk")) features.Foreign = "Yes";
  if (tags.includes("err_orth")) features.Typo = "Yes";
  if (profile === "ktb") {
    delete features.Abbr; delete features.NameType; delete features.PartType;
    if (features.Case === "Equ") delete features.Case;
  }
  return { upos, features: Object.fromEntries(Object.entries(features).sort()) };
}

function splitUnescaped(value, delimiter) {
  const parts = [];
  let current = "";
  let escaped = false;
  for (const character of value) {
    if (escaped) { current += `\\${character}`; escaped = false; }
    else if (character === "\\") escaped = true;
    else if (character === delimiter) { parts.push(current); current = ""; }
    else current += character;
  }
  if (escaped) current += "\\";
  parts.push(current);
  return parts;
}

function unescapeMorphology(value) {
  let output = "";
  let escaped = false;
  for (const character of value) {
    if (escaped) { output += character; escaped = false; }
    else if (character === "\\") escaped = true;
    else output += character;
  }
  if (escaped) output += "\\";
  return output;
}

function firstUnescaped(value, target) {
  let escaped = false;
  for (let index = 0; index < value.length; index += 1) {
    if (escaped) escaped = false;
    else if (value[index] === "\\") escaped = true;
    else if (value[index] === target) return index;
  }
  return -1;
}

export function parseAnalysis(raw, profile = "universal") {
  if (!raw || raw.startsWith("*") || raw.endsWith("+?")) return null;
  const morphemes = [];
  const tags = [];
  for (const part of splitUnescaped(raw, "+")) {
    const tagStart = firstUnescaped(part, "<");
    const lemma = unescapeMorphology(tagStart < 0 ? part : part.slice(0, tagStart));
    const segmentTags = [...part.matchAll(/<([^<>]+)>/g)].map((match) => match[1]);
    tags.push(...segmentTags);
    const projection = projectUd(segmentTags, profile);
    morphemes.push({ lemma, tags: segmentTags, upos: projection.upos, features: projection.features });
  }
  const primary = morphemes.find((morpheme) => morpheme.lemma || morpheme.tags.length);
  const lemma = morphemes.find((morpheme) => morpheme.lemma)?.lemma ?? raw;
  const projection = primary ?? projectUd(tags, profile);
  return {
    schema_version: "qazmorph.analysis.v1",
    lemma,
    upos: projection.upos,
    features: projection.features,
    tags,
    morphemes,
    raw,
    source: "lexicon",
    score: null,
    guessed: false,
    orthographic_variant: tags.includes("err_orth"),
  };
}

export function unknownAnalysis(surface) {
  const lemma = unicodeCasefold(surface.normalize("NFC"));
  const tags = ["unknown"];
  return {
    schema_version: "qazmorph.analysis.v1",
    lemma, upos: "X", features: {}, tags,
    morphemes: [{ lemma, tags, upos: "X", features: {} }],
    raw: `${lemma}<unknown>`, source: "unknown", score: null, guessed: true, orthographic_variant: false,
  };
}

export function numberAnalysis(surface) {
  const lemma = surface.normalize("NFC");
  const tags = ["num"];
  const features = { NumType: "Card" };
  return {
    schema_version: "qazmorph.analysis.v1",
    lemma, upos: "NUM", features, tags,
    morphemes: [{ lemma, tags, upos: "NUM", features }],
    raw: `${lemma}<num>`, source: "rule", score: null, guessed: true, orthographic_variant: false,
  };
}
