# MyStem command-line compatibility

This is a clean-room compatibility layer based on Yandex's public
[MyStem command-line documentation](https://yandex.ru/dev/mystem/doc/ru/)
and its published
[examples](https://yandex.ru/dev/mystem/doc/ru/usage-examples). The MyStem
binary is not used or inspected. Compatibility here means that familiar
invocation and output shapes are available for Kazakh; it does **not** mean
byte-for-byte Russian MyStem emulation.

## Option matrix

| MyStem interface | KazStem status | Exact KazStem contract |
|---|---|---|
| `mystem [options] [input] [output]` | Compatible | `kazstem` accepts the same zero, one, or two positional-file convention. Omission and `-` select standard input/output. |
| clustered short flags, for example `-cin` | Compatible | Zero-argument short flags may be combined using normal Unix syntax. `-?` is a help alias and `-v` is a version alias. |
| `-n` | Compatible in `text` and JSON | Emits each word, and with `-c` each copied segment, on its own line. Copied text gaps escape space as `_`, underscore as `\_`, backslash as `\\`, and CR/LF as `\r`/`\n`. MyStem JSON switches from an array to one object per line. JSONL is already record-delimited; XML and CoNLL-U use their own structure. |
| `-c` | Compatible | Retains atomic gaps and punctuation in text, JSON, JSONL, and XML. No lexical record contains whitespace. CoNLL-U necessarily omits whitespace rows but retains offsets. |
| `-w` | Compatible | Removes generated/OOV readings and lexical tokens left without a dictionary reading. With `-c`, nonlexical separators are still retained. |
| `-l` | Compatible in `text` | Omits surface forms and braces in text. Structured formats retain `text` because it identifies each record. |
| `-i` | Shape-compatible, Kazakh tagset | Adds `gr` in MyStem JSON/XML and grammar text after `=`. Values are English UPOS plus legal UD features, not Russian MyStem grammemes. JSONL and CoNLL-U always retain structured morphology. |
| `-g` | Compatible grouping | Requires `-i`, as in the public MyStem contract. Readings with one lemma become one record whose distinct grammars are joined in parentheses. |
| `-s` | Compatible in `text` and XML | Requires `-c`. Text emits MyStem's `{\s}` marker. XML starts a new `<se>` only at a detected sentence boundary with following lexical content. The public docs do not define a portable JSON marker record, so `-s --format json` is rejected; JSONL already has `sentence_end`. |
| `-e ENCODING` | Compatible plus extension | The documented `cp866`, `cp1251`, `koi8-r`, and `utf-8` work for characters representable by those encodings. Kazakh-specific letters generally require UTF-8. Other Python **text encodings** are accepted after an encode/decode validation; binary transforms such as `base64_codec` are rejected. The XML declaration records the selected encoding. |
| `-d` | Interface-compatible, different model | Runs Kazakh Constraint Grammar. It prunes only justified readings and retains unresolved ambiguity instead of silently choosing candidate zero. |
| `--eng-gr` | Accepted no-op | QazMorph's public tags are already English UPOS/UD. There is no Russian-label default to translate. |
| `--filter-gram TAG[,TAG]` | Supported with explicit semantics | Every requested value must occur in a reading's raw tags, UPOS, or exact `Feature=Value`. Repeating the option adds conjunctive requirements. |
| `--fixlist PATH` | Same purpose, different file grammar | Overrides atomic-token dictionary readings, but accepts validated JSONL or three-column TSV. On a whitespace phrase span the fixlist is append-only so it cannot erase the raw FST lattice. MyStem's Russian bracketed paradigm syntax is not parsed. |
| `--format text` | MyStem-shaped | Emits `surface{lemma...}` text and preserves physical input line endings even without `-c`. Kazakh grammar labels and score availability differ as described here. |
| `--format json` | MyStem-shaped | Emits one compact JSON array per invocation, or one object per line with `-n`. Records contain `text`; lexical records add `analysis` items using only public MyStem field names `lex`, optional `gr`, `qual="bastard"`, and optional `wt`. |
| `--format xml` | MyStem-shaped | Emits the documented `<?xml?><html><body><se><w>surface<ana .../></w></se></body></html>` hierarchy and `lex`, optional `qual`, `gr`, and `wt` attributes. Every emitted text and attribute value is checked against the XML 1.0 character repertoire; unrepresentable values (including NUL, forbidden C0 controls, surrogates, U+FFFE, and U+FFFF) produce a controlled status-2 error. Text/JSON/JSONL remain the lossless transport for those code points. |
| `--generate-all` | Safety-bounded | Expands the productive OOV lattice up to 256 hypotheses. MyStem's potentially unbounded behavior is intentionally not claimed. |
| `--weight` | Field-compatible, different score contract | Places text weight after the lemma and before `=grammar`; JSON/XML use `wt`. A field is emitted only when a scoring layer supplied a value. Unweighted FST/CG readings remain null rather than receiving invented probabilities. |

## KazStem extensions

`--format jsonl` uses `qazmorph.jsonl-record.v2`. Atomic `token` records and
overlapping `analysis_span` records retain offsets, raw FST tags, joined
morphemes, provenance, nullable scores, every visible legal candidate, and the
selected candidate index. Every row declares `consumes_input`; only token rows
consume text. Full-input reconstruction requires `-c` and no `-w`; without
`-c`, nonlexical token rows are omitted, and `-w` can omit OOV tokens or spans.
The Python API uses `qazmorph.document.v2`, `qazmorph.token.v1`, and
`qazmorph.analysis-span.v1`, with `analyses` plus a selected analysis object.
`--format conllu` emits the atomic UD projection and omits overlapping spans.
`--neural`, `--neural-model-dir`, `--cpu`, `--no-guesser`, `--guess-limit`, and
`--resource-dir` have no MyStem counterpart.
`--ud-profile universal|ktb` is another extension: it changes only the lossy UD
projection and is recorded in JSONL/API output; MyStem-shaped schemas have no
field for this provenance.

## Deliberately unsupported or non-identical behavior

- Russian MyStem grammeme names and Russian-language analyses are not emitted;
  this system analyzes Kazakh and exposes UPOS/UD plus lossless Apertium tags.
- MyStem's bracketed fixlist paradigm syntax is not accepted.
- `-d` does not reproduce MyStem's proprietary Russian disambiguator.
- MyStem's context-independent lemma-frequency model is not reproduced.
- Exact JSON chunking per physical input line and byte-for-byte whitespace or
  attribute order are not compatibility guarantees. The JSON value and XML
  document emitted by QazMorph are independently parseable.
- No undocumented binary behavior is claimed. When the public documentation
  does not specify a representation, QazMorph either exposes a documented
  extension or rejects the combination instead of guessing.
