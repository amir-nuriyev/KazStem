# Analysis contract

The stable analysis schema below is richer than the compatibility serializers.
See [MyStem command-line compatibility](MYSTEM_COMPATIBILITY.md) for the exact
option/output matrix and intentional differences.

## Modes

- `lattice`: return every distinct reading licensed by the dictionary FST.
- `contextual`: apply Constraint Grammar and retain any ambiguity it cannot
  resolve. No arbitrary first-reading fallback is labeled certain.
- `neural`: rank the unchanged legal lattice with contextual predictions.
  JSONL retains all candidates and records the selected index.

Constraint Grammar and neural ranking are alternative contextual modes. The
CLI and Python API reject a request to enable both before running backend work.

## Lossless token contract

`Document.text` is the exact caller input. NFC text is stored separately only
when it differs. `Document.tokens` is one contiguous, non-overlapping consuming
partition with half-open offsets into the original input. Concatenating token
surfaces reconstructs the input exactly. A `space` token contains only Unicode
whitespace; every other token contains no whitespace. Backend control
characters—including literal caller NUL—are escaped before HFST. An alignment
failure raises an error rather than fabricating offsets.

Text, JSON, and JSONL retain those caller code points losslessly. XML 1.0 has a
smaller legal character repertoire: it cannot represent NUL, most C0 controls,
Unicode surrogate code points, U+FFFE, or U+FFFF. The XML formatter validates
every token surface and analysis attribute that it is about to emit and raises
the dedicated `XMLFormatError` before returning a document if any value is not
representable. The CLI reports that condition as a normal status-2 error without
a traceback. Serializer options may still omit a value; validation applies to
the selected XML view rather than weakening the underlying token contract.

U+002D hyphen-minus, U+2010 hyphen, and U+2011 non-breaking hyphen are internal
to one orthographic token when flanked by Unicode letters/marks. Figure, en,
em, and mathematical minus dashes are punctuation even without surrounding
spaces; leading/trailing hyphens are punctuation. An exact dictionary cohort
such as `51%-дан` remains one token.

Whitespace-bearing dictionary cohorts are not tokens. They are immutable
`qazmorph.analysis-span.v1` objects in `Document.analysis_spans`, with exact
original character offsets, the exact range of intersected atomic token
indices, every original raw candidate in order, and a separate selected index.
Character offsets are authoritative and can start/end inside an edge token—for
example the dictionary span `мына мекен` ends inside orthographic
`мекен-жайға`. A span never consumes or duplicates text, and its morphemes are
never heuristically distributed among visible words.

The tokenizer recognizes Apertium-reserved characters literally, including
`[]{}^$/\\<>@#*+`. Synthetic period boundaries sometimes emitted after `?` or
`!` are dropped only when they have no source span.

`Document.as_dict()`, `Token.as_dict()`, and `AnalysisSpan.as_dict()` use
`qazmorph.document.v2`, `qazmorph.token.v1`, and
`qazmorph.analysis-span.v1`. Token/span API objects name the candidate array
`analyses` and expose the selected analysis object (or null). CLI JSONL uses
`qazmorph.jsonl-record.v2`: the array is `analysis`, `selected` is an index,
and every record declares `record_type: token|analysis_span` plus
`consumes_input` and `ud_profile`. `Document.ud_profile` carries the same
projection provenance. Only consuming token rows participate in reconstruction.
Full JSONL reconstruction requires `-c` without `-w`; filters or `-w` can omit
records. `Document.text` remains exact regardless of serializer options.

## Analysis identity

The public representation is lossless first and UD-compatible second:

```json
{
  "schema_version": "qazmorph.analysis.v1",
  "lemma": "кітап",
  "upos": "NOUN",
  "features": {
    "Case": "Abl",
    "Number": "Plur",
    "Number[psor]": "Plur",
    "Person[psor]": "1"
  },
  "tags": ["n", "pl", "px1pl", "abl"],
  "morphemes": [{
    "lemma": "кітап",
    "tags": ["n", "pl", "px1pl", "abl"],
    "upos": "NOUN",
    "features": {
      "Case": "Abl",
      "Number": "Plur",
      "Number[psor]": "Plur",
      "Person[psor]": "1"
    }
  }],
  "raw": "кітап<n><pl><px1pl><abl>",
  "source": "lexicon",
  "score": null,
  "guessed": false,
  "orthographic_variant": false
}
```

`signature` is a convenient lemma/UPOS/UD-feature projection. Internal
deduplication uses `identity`, which additionally includes raw morphology. Thus
`<n><attr>` and `<n><nom>` survive even if both project to `Case=Nom`.

Joined `+` segments remain independent morpheme objects. Finite features from a
zero-surface copula are not copied onto a visible noun. A contextual syntactic
UPOS, such as `AUX` for a lexical `<v>` reading, is stored separately from the
lexical UPOS/raw tags.

## UD projection

The default profile uses legal universal values. Notable rules:

- the last primary case wins over secondary cases and `attr`;
- bare `attr` projects to `Case=Nom`;
- `aor` becomes `Aspect=Hab|Mood=Ind|Tense=Pres|VerbForm=Fin`;
- `prc_*` forms project to `VerbForm=Inf`, `gna_*` to `Conv`, `gpr_*`
  to `Part`, and `ger_*` to `Ger`;
- `px3sp` becomes `Number[psor]=Plur,Sing|Person[psor]=3`;
- `coll` becomes the universal `NumType=Sets`;
- indirect evidential morphology becomes `Evident=Nfh`;
- multiple voices are retained as one sorted comma-valued feature.

The explicit `ktb` projection profile changes `Sets → Coll` and `Nfh → Fh` and
suppresses `NameType`, `Abbr`, `PartType`, and `Case=Equ`, which KTB r2.18 does
not annotate. Select it with `Analyzer(ud_profile="ktb")` or CLI
`--ud-profile ktb`; the universal profile remains the default. Raw tags are
never discarded, so projection changes do not lose morphology. Corpus scores
must always name the profile used.

Some raw readings license more than one defensible UD view. For consuming
atomic tokens, QazMorph appends those views after the complete original FST
candidate sequence; it never replaces or reorders that sequence:

- a non-guessed compiled `<num>` reading on a surface consisting entirely of
  Unicode decimal digits gets an additional `NumType=Ord` view;
- the same reading also gets `NumType=Card,Ord` under the opt-in `ktb` profile,
  matching that treebank's conversion convention;
- explicit `<adj><subst>`, `<n><attr>`, and `<adj><advl>` usage tags license
  additional `NOUN`, `ADJ`, and `ADV` views, respectively.

These candidates retain the licensed lemma, raw string, ordered tags, and all
raw-derived features verbatim; only UPOS changes for a usage alias, and both the
top-level analysis and its primary morpheme change together. In particular,
nominal Case/Number/possessor features survive `n+attr → ADJ`, comparative
Degree survives `adj+advl → ADV`, and Degree can survive a comparative
`adj+subst → NOUN`. Removing those overt features would make the alternative
projection morphologically lossy. A raw `<prn>` or `<det>` does not by itself
license swapping PRON and DET, so no such alias is generated. Capitalization,
lexical lookup tables, and other surface heuristics are not used.

Projection aliases are not injected into `AnalysisSpan`. A phrase span remains
the exact original backend raw sequence and provenance layer; only its
documented phrase-fixlist entries may follow that sequence. This keeps the FST
phrase lattice directly auditable while the consuming atomic token carries the
extra lossy UD views used for evaluation and selection.

An alias has `source=rule` but `guessed=false`: it decorates an already present,
non-guessed `source=lexicon` candidate and cannot create dictionary coverage for
an OOV. Consequently MyStem `-w`/`dictionary_only` retains both the licensed
reading and its aliases, while guessed numeric fallback readings remain
excluded. If one CG raw choice maps to multiple UD views sharing that raw,
selection abstains. Neural mode may select among them when its UD features
differ; an otherwise exact tie keeps the original FST candidate because the
original sequence is the stable prefix.

## Scores and selection

- Unweighted FST and CG readings: `score = null`.
- OOV candidates: a normalized within-token heuristic distribution.
- Neural candidates: a normalized within-token reranking distribution.

None of these is advertised as a calibrated language-wide probability. A token
has `selected = null` whenever the active mode abstains.

Resource/runtime provenance distinguishes functional execution from an
official verified run. Resource v3 binds an optimized guesser and a read-only,
completely inventoried extracted HFST/CG bundle. The legacy finiteness-v1
result authorizes productive guessing only when the verified content-addressed
bundle is exactly f03e; unknown valid v1 bundles are nonproductive/nonofficial
and malformed proof sections fail closed. Explicit executable overrides,
ambient library search paths, and legacy v2 rollback set
`official=false`. The extracted subset is verified, but host-provided ELF
dependencies are not byte-locked; provenance therefore states
`byte_closed=false` rather than implying a hermetic operating-system image.

Constraint Grammar operates separately on the atomic and phrase streams. An
exact atomic CG cohort retains the established pruning behavior; if CG does not
return that exact interval, QazMorph falls back to its lattice candidates and
abstains rather than fabricating an OOV. Phrase spans always retain the full
pre-CG raw lattice; `AnalysisSpan.selected` records a unique CG choice when one
exists. Neural ranking initially applies to exact atomic tokens and abstains on
multi-token spans rather than inventing a cross-token scoring rule.

## Fixlists

JSONL:

```json
{"form":"формасы","lemma":"форма","tags":["n","px3sp","nom"]}
```

TSV:

```text
формасы<TAB>форма<TAB>n,px3sp,nom
```

For consuming atomic tokens, entries override the compiled dictionary.
Multiple entries preserve ambiguity. For a whitespace-bearing phrase span,
fixlist readings are appended after the complete backend lattice: span
provenance is append-only and an override cannot erase licensed FST candidates.
Keys and lemmas are NFC-normalized; tags are validated and lexical delimiters
are escaped or rejected.
