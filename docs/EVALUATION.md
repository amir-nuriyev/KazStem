# Evaluation protocol

## Claims

Keep three questions separate:

1. Did tokenization preserve and align the input?
2. Did the candidate lattice contain the gold reading?
3. Did a contextual layer select the gold reading?

Candidate recall is an upper bound only for lexical selected top-1 fields when
the selected raw analysis is present in the separately executed lattice pass
and the same lemma/UPOS/features are compared. The current neural layer can
project a licensed lexical `VERB` to contextual `AUX`; the schema and evaluator
also keep any separately supplied contextual features distinct, although the
current Stanza ranker does not populate them. Context-projected UD fields need
not occur together on a raw FST candidate and are therefore not bounded by
candidate recall. Evaluator v4 reports
`contextual_top1.lexical_selected_top1` and
`contextual_top1.context_projected_ud_top1` separately, with explicit
upper-bound applicability and selected-raw containment. Reporting only accuracy
on aligned tokens also hides tokenizer failures, so the evaluator keeps
unaligned gold tokens in end-to-end denominators.

## Public annotated corpus

UD Kazakh-KTB 2.18 contains about 10.5k tokens across 1,078 sentences. Lemmas
were manually annotated; POS/features were manually annotated in the original
scheme and converted to UD. The treebank is too small for a canonical
train/dev/test division. Its maintainers recommend merging files and reporting
ten-fold jackknife/cross-validation.

KTB is useful but is not independent gold for the current system. Its
morphological processing explicitly follows Apertium Turkic-lexicon principles,
while QazMorph's FST and CG resources come from `apertium-kaz`. Consequently,
an evaluation over all KTB files is a full-corpus compatibility diagnostic, not
a canonical held-out score. A future ten-fold result must freeze the folds and
ensure that no fold was used to tune a fixlist, projection, grammar, or ranker
before it can be described as cross-validation.

The optional neural layer needs a stricter label. Stanza's Kazakh resource
index names its tokenizer, MWT, lemma, and POS packages `ktb`, and maps
`kk_ktb` to UD Kazakh-KTB. For partial UD treebanks, Stanza's training-data
preparation swaps the two source files when `train` has at most 1,000 words and
`test` has more than 5,000; KTB meets that condition. Thus the large official
KTB `test` file contributed training data to the packaged Stanza model. Neural
evaluation over full KTB has training overlap and may be reported only as a
contaminated diagnostic.

The official `train` file has just 31 sentences and 529 syntactic words. It can
be used as a tiny **Stanza-unseen audit** because Stanza's swap reserves it as
test data, but it is still part of KTB, shares its annotation conventions, and
is not independent gold. Do not call this slice a representative held-out
benchmark.

Authoritative provenance:

- [UD KTB README and split recommendation](https://github.com/UniversalDependencies/UD_Kazakh-KTB/blob/r2.18/README.md)
- [UD KTB 2.18 size statistics](https://github.com/UniversalDependencies/UD_Kazakh-KTB/blob/r2.18/stats.xml)
- [Stanza 1.14 Kazakh resource packages](https://github.com/stanfordnlp/stanza-resources/blob/main/resources_1.14.0.json)
- [Stanza short-name-to-treebank mapping](https://github.com/stanfordnlp/stanza/blob/main/stanza/models/common/short_name_to_treebank.py)
- [Stanza partial-treebank file swap](https://github.com/stanfordnlp/stanza/blob/v1.10.1/stanza/utils/datasets/prepare_tokenizer_treebank.py#L1282-L1320)

The evaluator reports:

- sentences, surface tokens, syntactic words, MWTs, and empty nodes;
- exact 1:1, split, merge, and unresolved alignments;
- dictionary coverage and guessed/unknown rates;
- candidate lemma, UPOS, lemma+UPOS, and full-feature recall;
- contextual selection/abstention coverage;
- lexical selected top-1 lemma/UPOS/full accuracy and, in neural mode, separate
  context-projected UD top-1 metrics;
- aligned-only and end-to-end values;
- resource/source hashes and runtime metadata.

Runtime reports distinguish resource-bound, manifest-verified executables from
explicit `QAZMORPH_*` overrides. Overrides remain useful for development, but
set `valid_for_official_result_claims=false`; benchmark reports apply the same
rule to official performance claims. The verified scope is the complete sealed
resource bundle and extracted toolchain subset, not a byte-closed host image;
reports therefore set `byte_closed=false`. Ambient `LD_LIBRARY_PATH`,
`LD_PRELOAD`, or `LD_AUDIT` also makes a run non-official; raw
`LD_PRELOAD`/`LD_AUDIT` values are hashed rather than copied into the report.
Legacy resource v2 remains usable for
rollback but non-official, while official runs require the sealed v3
resource/toolchain layout.

Neural validity is independent of the FST backend flag. An official neural run
must recompute the checked-in model and live-environment manifests, bind the
same model bundle in both, retain unchanged artifacts through the run, and
confirm that requested CPU/GPU placement matches the actual pipeline and model
parameters. Custom models remain usable, but unverifiable configurations are
reported as non-official.

Run from the repository root on the frozen evaluation host:

```bash
export PYTHONPATH="$PWD/src"
export QAZMORPH_RESOURCE_DIR="$PWD/.qazmorph/resources"

python3 scripts/evaluate_ud.py \
  --resource-dir "$QAZMORPH_RESOURCE_DIR" \
  .qazmorph/evaluation/UD_Kazakh-KTB-r2.18/kk_ktb-ud-train.conllu \
  .qazmorph/evaluation/UD_Kazakh-KTB-r2.18/kk_ktb-ud-test.conllu
```

That command evaluates the FST/CG system on the complete corpus and must retain
the diagnostic label above. For the tiny Stanza-unseen audit, evaluate only the
official `train` file with `--mode neural`. Neural mode reports unresolved
span/tokenization matches explicitly. Do not tune the lexicon, projection, or
ranker on the slice being reported.

The evaluator default is the semantically richer `universal` UD projection.
An additional `--ud-profile ktb` run may be reported as a treebank-compatibility
view, never as a change to the underlying morphology. Reports must bind the
profile and show exact feature bundles separately from subset-compatible
relations so richer legal analyzer features are not mislabeled as missing
morphology.

## Independent-gold gap

No licensed, downloadable, independent Kazakh gold corpus with the exact
lemma/POS/morpheme-chain target has been integrated into this repository.
Therefore none of the KTB diagnostics establishes generalization to arbitrary
Kazakh or supports a 100% correctness claim.

The strongest next target identified in the literature is the manually
annotated `kD1` corpus described by Tolegen, Toleu, and Mussabayev in
[Voted-Perceptron Approach for Kazakh Morphological Disambiguation](https://aclanthology.org/2020.sltu-1.36/).
The paper describes the corpus, but the data and a redistribution license are
not available from the cited publication. Obtain the authors' corpus and
written license, freeze an untouched test split, document any tag conversion,
and only then publish independent-gold results.

## Regression gold

The stdlib conformance suite freezes parser, tag-mapping, serialization,
generation, reserved-character, OOV, Unicode-offset, and selected Kazakh
linguistic invariants. Passing it establishes implementation conformance, not
generalization to all Kazakh.

## Performance

Report cold and warm behavior separately:

- single-document and repeated API latency (p50/p95/p99);
- tokens and Unicode characters per second;
- peak RSS and resource size;
- FST lattice, CG, and neural modes independently;
- short, long, OOV-heavy, and reserved-character inputs;
- exact CPU/GPU/OS/resource versions.

Cold means a fresh process; it does not claim that the OS page cache was
dropped. The benchmark performs no download and accepts only local input text.

## Large raw corpora

The Multidomain Kazakh Dataset has no gold morphology. Use it only for lexical
coverage, domain/OOV slices, frequency priors, and throughput. Stream or place
it under a host-local, non-repository path. Deduplicate it against every evaluation sentence
before training or lexicon mining.

The checked-in sampler freezes a reproducible prefix by dataset revision, row
selection, endpoint IDs, and SHA-256. Keep its payload outside the source
repository:

```bash
python3 scripts/prepare_multidomain_sample.py \
  --output .qazmorph/evaluation/multidomain_5000_prefix_8efcab.txt \
  --rows 5000 \
  --expected-sha256 8efcab8460023829a2d8907d15df31fdbcb96226d4b540f5bf53133a1f02df5e \
  --expected-first-id f2b81db7-6196-4bc2-b189-f574dc65a7f4 \
  --expected-last-id e1e5f349-081e-4a08-9311-67505e5cb754

python3 scripts/evaluate_raw.py --pretty \
  --resource-dir "$QAZMORPH_RESOURCE_DIR" \
  --output .qazmorph/evaluation/multidomain-raw.json \
  .qazmorph/evaluation/multidomain_5000_prefix_8efcab.txt
```

`evaluate_raw.py` verifies source/input/resource hashes, exact reconstruction,
dictionary/guesser/unknown coverage, OOV lookup caps/timeouts/failures/cyclic
truncations, shorter-root productive analyses, and throughput. These are
operational measurements only; the raw corpus supplies
no lemma, POS, feature, or top-1 correctness labels.
