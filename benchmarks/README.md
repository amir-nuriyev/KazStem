# Reproducible evaluation and benchmarks

Run corpus evaluation and performance experiments on an isolated machine with
the pinned resource/toolchain bundle. The tools never download data; every
input path must already exist on that machine.

```sh
cd KazStem
export QAZMORPH_RESOURCE_DIR="$PWD/.qazmorph/resources"
export PYTHONPATH="$PWD/src"

# Full-corpus FST/CG diagnostic; this is not a canonical held-out split.
python3 scripts/evaluate_ud.py --pretty --output /tmp/ud-cg.json \
  .qazmorph/evaluation/UD_Kazakh-KTB-r2.18

# Candidate recall only.
python3 scripts/evaluate_ud.py --mode lattice --output /tmp/ud-lattice.json \
  .qazmorph/evaluation/UD_Kazakh-KTB-r2.18

# Tiny Stanza-unseen audit only; this 31-sentence KTB slice is not independent.
.qazmorph/neural-venv/bin/python scripts/evaluate_ud.py \
  --mode neural --neural-device cpu --output /tmp/ud-neural.json \
  .qazmorph/evaluation/UD_Kazakh-KTB-r2.18/kk_ktb-ud-train.conllu

# Fresh-process and warmed-instance performance for lattice and CG modes.
python3 scripts/benchmark.py --mode both --runs 20 --pretty \
  --output /tmp/performance.json \
  .qazmorph/evaluation/UD_Kazakh-KTB-r2.18

# Neural performance; `all` benchmarks lattice, CG, and neural modes.
.qazmorph/neural-venv/bin/python scripts/benchmark.py \
  --mode neural --neural-device gpu --runs 20 \
  --output /tmp/performance-neural.json \
  .qazmorph/evaluation/UD_Kazakh-KTB-r2.18

# Raw operational coverage/losslessness/throughput; never morphology accuracy.
python3 scripts/evaluate_raw.py --pretty \
  --output /tmp/multidomain-raw.json \
  .qazmorph/evaluation/multidomain_5000_prefix_8efcab.txt
```

The packaged Stanza Kazakh tokenizer/POS/lemma models are trained on KTB. A
neural evaluation over all KTB files therefore has training overlap and may be
retained only as a contaminated diagnostic. The official 31-sentence `train`
file is Stanza-unseen because Stanza's partial-treebank preparation trained on
the large official `test` file, but it is too small and too closely related to
be independent gold. Full-corpus FST/CG evaluation is also diagnostic because
KTB morphology follows Apertium principles and QazMorph uses `apertium-kaz`.
See [the evaluation protocol](../docs/EVALUATION.md) for the provenance and
independent-gold limitation.

The evaluator reports both end-to-end and aligned-only metrics. End-to-end
denominators retain tokenization/alignment failures. Candidate recall asks
whether any licensed lattice reading matches the gold field; full-analysis
recall requires one candidate to match lemma, UPOS, and the exact UD feature
bundle. Explicit unknown placeholders never earn morphology credit. Neural
reports include counts of tokens unresolved by gold/qazmorph tokenization or by
Stanza/FST span mismatch. Evaluator v4 separates candidate-constrained lexical
selected top-1 from neural context-projected UD top-1; the latter is not bounded
by lattice recall because its contextual UPOS—and any separately supplied
contextual features—need not coexist on a raw FST candidate. The current Stanza
ranker supplies contextual `AUX` projection but does not populate contextual
features.

The benchmark defines cold as a fresh Python worker process without clearing OS
page caches. Warm measurements reuse one `Analyzer` after a fixed warm-up. JSON
contains raw latency samples, percentile summaries, token/character/byte
throughput, process and child RSS, input hashes, resource manifests, evaluator
and project-source hashes, and hashes for Stanza's `resources.json` plus every
neural model artifact. `--runs` controls warmed measurement repetitions;
`--cold-runs` and `--warmup-runs` are separate.

Benchmark v3 independently re-hashes the sealed resource manifest and every
compiled artifact in each worker and again in the parent. Neural performance is
eligible for an official label only when the checked-in model/environment
verifier succeeds, the environment names the selected model bundle, artifacts
remain unchanged, and requested CPU/GPU placement matches the live pipeline and
all parameter-bearing processors. Custom neural configurations still run, but
are explicitly non-official.
