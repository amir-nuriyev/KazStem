# KazStem 0.2.0: verified reference-host results

This page records the publication-final KazStem 0.2.0 verification performed
on 2026-08-10. Every resource build, model setup, test, corpus read,
evaluation, and benchmark ran on the same isolated AMD EPYC/H100 reference
host. Corpus, model, and detailed machine-readable report payloads are not
part of the source repository.

## Bottom line

KazStem 0.2.0 is a deterministic finite-state analyzer and generator with
Constraint Grammar (CG) disambiguation and an optional candidate-constrained
neural ranker. The default `universal` projection preserves legal UD detail;
the opt-in `ktb` projection reproduces Kazakh-KTB conventions without changing
the underlying raw morphology.

The strongest result is the ambiguity-preserving lattice: on related KTB gold,
exact full-analysis candidate recall is 89.719% aligned / 87.965% end-to-end in
the universal profile, and 96.409% / 94.524% in the KTB compatibility profile.
The profile difference is annotation compatibility, not an improvement to the
FST. CG is precise but abstains often. On the tiny 31-sentence Stanza-unseen
audit, the neural ranker is useful for coverage: it selects 99.213% of aligned
tokens versus CG's 62.992%, raising universal aligned exact full analysis from
53.346% to 76.378%. Its selected-only exactness is lower, and the sample is not
independent gold.

These are bounded implementation and compatibility results. They do **not**
establish 100% linguistic correctness for arbitrary Kazakh.

## Release gates and immutable identities

The final strict suite ran 323 tests: 322 passed, one was intentionally skipped,
and there were zero failures or errors. The skip is the unsupported emission of
CoNLL-U multiword-token rows for joined morphemes whose reliable surface spans
are absent upstream; JSONL retains those morphemes.
The suite also freezes exact newline preservation for positional CLI input and
fail-fast rejection of the invalid combined neural-plus-CG API configuration.

| Component | Final identity |
|---|---|
| QazMorph | `0.2.0` |
| Morphology source | `apertium-kaz` commit `95c6dd0d8536ee69a7058634b03a3e82100b6b6e` (GPL-3.0) |
| Resource bundle | `f03e703d3e2a67044a7d91fd7d575b92cb4e61aa782fb67cff91b0a5ff0ebd5a` |
| Resource manifest | 7,043 bytes; SHA-256 `095fb8e70981281a21826e9a42292bad86ab25b9452a6db767827562d9defba9` |
| Toolchain bundle | `66c1914a645ffedc1d663decb2676d525d3b0751f7371418f6efff44c94fe3fc` |
| Toolchain manifest | 48,440 bytes; SHA-256 `21df490d51029961968b639d32621ae2bd877e4b968ab1c6945a1bd70731908b` |
| Raw-evaluator software snapshot | `ac219a985defe0ca3eee600b0c0827968d7bc7c560b823306082e6fea1554e51` |
| UD-evaluator software snapshot | `983af758541ee92791bd2c9cabacbde295e527cdf29da02c6a18b0d932be4aa6` |
| Benchmark software snapshot | `2af7059c9fe9f199fa8acd2c93b2bd74248946faaeae50091e228abf6c335e65` |
| Neural model bundle | `2cea9eb5b641cbe745e51603a03afdf832062fd926b695cd155ba4c698f36fe7` |
| Neural model manifest | 1,757 bytes; SHA-256 `0f9a757663d16081ea3d6c1e4dadf8fede126b91a6a89de824cc10a992d96e99` |
| Neural environment bundle | `d5dbc7b1f2c3ddc5e19874c1b78ee36e62f7293bf3c696b2ec4a2824d76b96ef` |
| Neural environment manifest | 10,439 bytes; SHA-256 `dab18c5cf039c293b8669f7fc49171bc1d115c13c839d846f593549be2f80c3c` |
| Neural runtime | Stanza 1.14.0; Torch 2.11.0+cu130; CUDA runtime 13.0 |
| Accelerator | NVIDIA H100 PCIe, compute capability 9.0 |

The model bundle contains nine pinned files totaling 263,159,964 bytes. The
environment manifest records 142 visible Python distributions and verifies
that tokenization, MWT, POS, and lemma model parameters all ran on `cuda:0`.

Every official report forced a content rehash of the sealed five-file resource
inventory and 180-file extracted toolchain inventory after the relevant work.
All bound executables re-verified, inputs remained unchanged, and every report
has an official-valid status. The verified scope is nevertheless
`byte_closed=false`: dynamically linked host ELF dependencies outside the
extracted toolchain manifest are not byte-locked.

The resource build has three formal gates:

- `generation_relation - analysis_relation` is empty, so every compiled
  generator pair is accepted by the analyzer.
- The productive guesser graph has 3,774 reachable states, 87,075 arcs, 16,472
  input-epsilon arcs, and no reachable input-epsilon cycle. It is finite-valued
  for every finite input.
- Standard and optimized guesser serializations are relation-equivalent in
  both subtraction directions. Seventy-five no-cap probes produced 2,080
  distinct readings with zero cycle markers and all lemmas inside the declared
  bounded root relation.

Two clean resource builds produced the same content-addressed bundle. The
optimized productive guesser uses nonempty identity roots plus the bounded
stem-final mappings `б→п`, `г→к`, and `ғ→қ`.

## Metric conventions

UD evaluation includes punctuation. `Aligned` scores only exact one-to-one
surface alignments. `End-to-end` keeps all gold tokens in the denominator, so
surface-equivalent grouped tokens and unaligned tokens are misses rather than
being silently dropped.

Candidate-lattice recall is an oracle-existence measure: a field is recalled
when at least one returned candidate matches. Contextual top-1 counts
abstentions as misses. `Exact full` requires one candidate to match lemma,
UPOS, and the exact sorted UD feature bundle.

Feature relations are reported separately:

- `Exact`: candidate features equal gold features.
- `G ⊆ C`: one candidate contains every gold feature and may retain additional
  legal detail.
- `C ⊆ G`: one candidate contains no feature outside gold and may be
  underspecified.

These subset rates are independent candidate-existence relations; they are not
substitutes for exact accuracy.

## Raw multidomain coverage and robustness

The frozen input is the first 5,000 nonempty Kazakh rows selected by the
checked-in streaming sampler from
`kz-transformers/multidomain-kazakh-dataset` revision
`7a1fcdf9830b1c34b44b3038aafb672447f41890`. It contains 650,498 Unicode
characters / 1,184,475 UTF-8 bytes and has SHA-256
`8efcab8460023829a2d8907d15df31fdbcb96226d4b540f5bf53133a1f02df5e`.
Its manifest is 797 bytes with SHA-256
`0e19332d87a4fc0fcdc8171f8e6ece386ab0c7b00dfbc8001c9f2c3efc64fddd`.
The dataset has no morphology labels, so this section measures coverage,
losslessness, bounded-lookup integrity, and throughput—not accuracy.

| Measure | Productive guesser off | Productive guesser on |
|---|---:|---:|
| Word + number tokens | 82,056 | 82,056 |
| Compiled-dictionary tokens | 74,688 (91.021%) | 74,688 (91.021%) |
| Deterministic-rule-only tokens | 11 (0.013%) | 11 (0.013%) |
| Base-analyzer licensed `<unk>` only | 544 (0.663%) | 544 (0.663%) |
| Productive-guesser-only tokens | 0 | 4,461 (5.437%) |
| Explicit unknown-only tokens | 6,813 (8.303%) | 2,352 (2.866%) |
| Zero-analysis tokens | 0 | 0 |
| Genuine candidate records | 399,942 | 435,623 |
| Mean genuine candidates / lexical token | 4.874 | 5.309 |
| Maximum genuine candidates | 27 | 27 |
| Lossless reconstructed chunks | 7 / 7 | 7 / 7 |
| Evaluation wall time | 23.446 s | 26.437 s |
| Lexical tokens / second | 3,499.7 | 3,103.8 |
| Python peak RSS | 218.14 MiB | 241.94 MiB |
| Productive OOV lattice status | Not applicable | Complete under configured bounds |

The productive guesser recovers 4,461 / 6,813 (65.4778%) baseline unknown
tokens. It emits 35,681 candidate readings; 2,609 recovered tokens have a
shorter lemma candidate and 133 have a configured stem-final alternation.
The run made 3,245 productive lookups and 1,220 deterministic prefilter skips.
There were zero response-cap aborts, timeouts, failures, cycle markers, unsafe
resource skips, and protocol restarts. The 8,192-entry LRU held all 4,465
distinct keys in the workload.

`Complete` is operational and configuration-bounded. It means no configured
lookup was capped, timed out, failed, cycled, or used an unsafe resource; it
does not mean every linguistically possible OOV analysis exists.

## Atomic KTB alignment

UD Kazakh-KTB r2.18 is pinned at commit
`c850e5334a50befaf35a0907df766c4de89f68a1`. The combined public files contain
1,078 sentences and 10,536 syntactic words. Their identities are:

- `kk_ktb-ud-train.conllu`: 40,712 bytes; SHA-256
  `6297597914a3f319db573573f927a6577c702f5fa00dcd653162aab46026aeaa`.
- `kk_ktb-ud-test.conllu`: 809,028 bytes; SHA-256
  `1100846ee50c2f970562a21dca8415a381c470ea06bdb8496ae213d59c3a3c4e`.

The analyzer emitted 10,456 atomic tokens. Exactly 10,330 / 10,536 gold tokens
(98.045%) align one-to-one. The remaining 206 gold / 126 analyzer tokens form
100 surface-equivalent groups: 41 exact UD multiword-token spans, 10 analyzer
punctuation splits, and 49 other split/merge groups. Zero tokens are unaligned,
100% of the gold surface is accounted for, and zero analyzer tokens or groups
contain lexical whitespace. Non-consuming dictionary phrase spans therefore
remain available without corrupting the consuming token partition.

Among 8,269 aligned non-punctuation lexical tokens, 8,229 (99.516%) have a
compiled-lexicon candidate and 8,252 (99.794%) have a genuine analysis. Forty
occurrences are operational OOV, and 20 receive a productive guesser
hypothesis. The KTB workload has zero cap, timeout, failure, cycle, unsafe, or
protocol-restart events.

## KTB candidate-lattice diagnostic

| Profile | Scope | Lemma | UPOS | Exact features | G ⊆ C features | C ⊆ G features | Exact full |
|---|---|---:|---:|---:|---:|---:|---:|
| Universal | Aligned (10,330) | 98.974% | 97.609% | 91.636% | 98.374% | 92.498% | 89.719% |
| Universal | End-to-end (10,536) | 97.039% | 95.700% | 89.844% | 96.450% | 90.689% | 87.965% |
| KTB compatibility | Aligned (10,330) | 98.974% | 97.609% | 97.502% | 98.993% | 97.928% | 96.409% |
| KTB compatibility | End-to-end (10,536) | 97.039% | 95.700% | 95.596% | 97.058% | 96.014% | 94.524% |

The universal profile is the default and keeps semantically richer legal UD
features. The KTB profile uses that treebank's `Fh`/`Coll` conventions and
suppresses distinctions absent from its inventory, including `Abbr`,
`NameType`, `PartType`, and equative `Case`. It also exposes KTB's combined
numeric convention where licensed. Raw FST readings remain unchanged. The
universal/KTB lattices contain 42,355 / 42,773 genuine projected candidates,
respectively.

These are **not independent or held-out scores**. KTB morphology follows
Apertium principles and QazMorph uses pinned Apertium resources. They measure
compatibility and expose errors; they do not establish generalization.

## Constraint Grammar diagnostic

CG selects only when one genuine reading remains; unresolved ambiguity is an
abstention.

| Profile | Scope | Selection coverage | Lemma top-1 | UPOS top-1 | Exact features | Exact full |
|---|---|---:|---:|---:|---:|---:|
| Universal | Aligned (10,330) | 65.528% | 64.337% | 61.810% | 58.296% | 56.273% |
| Universal | End-to-end (10,536) | 64.246% | 63.079% | 60.602% | 57.156% | 55.173% |
| KTB compatibility | Aligned (10,330) | 65.528% | 64.337% | 61.810% | 62.430% | 60.368% |
| KTB compatibility | End-to-end (10,536) | 64.246% | 63.079% | 60.602% | 61.209% | 59.188% |

CG selected 6,769 / 10,330 aligned tokens. Among those selections, exact full
analysis is 85.877% in the universal profile and 92.126% in the KTB profile.
All 6,830 genuine contextual raw selections, including selections outside the
one-to-one scoring subset, occur on the same character span in the separately
executed lattice; containment mismatches are zero.

## Is the neural layer useful?

Yes, as an optional coverage-oriented candidate ranker; no, not yet as evidence
of independent general-domain quality. The packaged Stanza Kazakh models are
KTB-trained, so a neural score on the full KTB corpus would have training
overlap. The audit below uses KTB's tiny official `train` file—31 sentences /
529 gold words—which is Stanza-unseen but still same-treebank and
non-independent. Of those words, 508 align one-to-one.

All values below use the QazMorph-licensed lexical selection, not an
unconstrained Stanza prediction. Abstentions are misses in aligned and
end-to-end columns.

| Mode | Profile | Selected / aligned | Selected-only exact full | Aligned lemma | Aligned UPOS | Aligned exact features | Aligned exact full | End-to-end exact full |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| CG | Universal | 320 / 508 (62.992%) | 84.688% | 61.417% | 58.268% | 55.512% | 53.346% | 51.229% |
| Neural GPU | Universal | 504 / 508 (99.213%) | 76.984% | 94.488% | 89.567% | 80.906% | 76.378% | 73.346% |
| CG | KTB compatibility | 320 / 508 (62.992%) | 91.250% | 61.417% | 58.268% | 59.646% | 57.480% | 55.198% |
| Neural GPU | KTB compatibility | 504 / 508 (99.213%) | 83.135% | 94.488% | 89.567% | 87.008% | 82.480% | 79.206% |

The neural layer selects 338 / 339 ambiguous aligned tokens; one lacks an
exact neural span. It trades selected-only precision for much higher coverage:
in the universal view, selected-only exact full analysis falls from 84.688% to
76.984%, while aligned exact full analysis rises from 53.346% to 76.378%.
Every one of its 513 genuine raw selections is present in the independent FST
lattice pass, with zero mismatches. The result supports retaining neural mode
as optional, but the sample is far too small and related to support a broad
accuracy claim.

## Framing-final performance

The benchmark host exposes 64 logical CPUs on an AMD EPYC 9354P and one NVIDIA
H100 PCIe. OS page caches were left in their natural state. `Cold analysis`
measures one `Analyzer.analyze` call in a fresh process but excludes imports,
construction, provenance hashing, close, serialization, and IPC.
`Fresh-process` includes the complete worker lifecycle. `Warm` reuses one
analyzer after declared warm-up calls.

| Workload / mode | Cold / warm samples | Cold analysis p50 / p95 (ms) | Fresh-process p50 / p95 (ms) | Warm p50 / p95 (ms) | Warm output tok/s | Max Python worker peak RSS (MiB) |
|---|---:|---:|---:|---:|---:|---:|
| Built-in lattice | 3 / 20 | 27.198 / 27.939 | 285.774 / 286.100 | 22.760 / 25.639 | 1,542.8 | 33.36 |
| Built-in CG | 3 / 20 | 32.944 / 34.734 | 289.385 / 290.843 | 25.868 / 27.850 | 1,391.9 | 33.34 |
| Full KTB lattice | 2 / 5 | 2,250.372 / 2,271.956 | 2,544.665 / 2,567.078 | 2,421.765 / 2,467.964 | 4,391.2 | 158.97 |
| Full KTB CG | 2 / 5 | 2,213.999 / 2,215.376 | 2,490.686 / 2,491.514 | 2,260.974 / 2,294.345 | 4,641.6 | 111.45 |
| Built-in neural GPU | 3 / 20 | 336.625 / 338.827 | 7,384.749 / 7,423.947 | 50.731 / 55.864 | 634.7 | 1,603.04 |
| KTB train31 neural GPU | 2 / 5 | 700.099 / 700.149 | 7,740.728 / 7,773.975 | 322.633 / 399.161 | 1,521.3 | 1,609.47 |
| Raw 5,000 lattice + guesser | 1 / 3 | 24,409.755 / 24,409.755 | 25,041.667 / 25,041.667 | 24,321.586 / 25,429.948 | 4,203.1 | 1,291.27 |

The raw cold p50 and p95 are the same single observation, not a percentile
distribution. Its warm-up populated 4,465 cache entries; the three measured
passes added 20,439 cache hits and zero misses, productive lookups, or prefilter
work. All 23 benchmark worker protocol-restart counters and all lattice
incompleteness counters are zero.

The RSS column is the maximum reported Python-worker peak after analyzer close
across cold and warm runs. It does not add the separately reported
`RUSAGE_CHILDREN` peak, which is the largest waited child—not an aggregate or a
simultaneous Python-plus-child measurement. Neural constructor medians are
about 3.0 seconds; FST/CG constructor medians are about 50 ms. Full-process
neural latency additionally includes imports, model/environment verification,
provenance hashing, teardown, and IPC.

KTB rows are performance workloads and related compatibility diagnostics, not
independent accuracy gold.

## Primary artifact ledger

Report identifiers are filenames in the private evaluation archive; times are
the reference host's UTC file modification times.
SHA-256 values were independently recomputed after each report's internal
post-run verification passed.

| Artifact | Report identifier | Bytes | Recorded mtime (UTC) | SHA-256 |
|---|---|---:|---|---|
| Raw, no guesser | `multidomain_5000_noguess_f03e_cache8192_final_v3.json` | 21,378 | 2026-08-10 07:52:30 | `373c98e50edcd4550b00c92a2b4da4bfb190a6c399ca3f0f3cc5a191ce593362` |
| Raw, guesser | `multidomain_5000_guess_f03e_cache8192_final_v3.json` | 21,569 | 2026-08-10 07:54:11 | `3a199322df8dfdc051549f692495a7688bb2f7339aefee523c47bf169f49926d` |
| Full KTB lattice, universal | `ktb_r2.18_lattice_universal_f03e_framing_final_v4.json` | 70,193 | 2026-08-10 07:55:13 | `375e7ab0176fff4b767ecbf5da21393864fe95825ef20fd13f7bdfa8753038f2` |
| Full KTB lattice, KTB | `ktb_r2.18_lattice_ktb_f03e_framing_final_v4.json` | 70,192 | 2026-08-10 07:55:50 | `06d578d405b6dda2ae06e208733813da76e9146990d157b2ef28bcec7e20c4dc` |
| Full KTB CG, universal | `ktb_r2.18_cg_universal_f03e_framing_final_v4.json` | 123,213 | 2026-08-10 07:56:53 | `b17e1c9d37b771afddc2e781541c3337047c19a324e731f607c5a3a949f6a9ae` |
| Full KTB CG, KTB | `ktb_r2.18_cg_ktb_f03e_framing_final_v4.json` | 123,218 | 2026-08-10 07:58:01 | `221d77b66189742ceed42d5303f25088c2ce2da81c6803bb0a57e6efb9f2ffd8` |
| Train31 CG, universal | `ktb_train31_cg_universal_framing_final_v4.json` | 99,121 | 2026-08-10 07:52:02 | `3d30799b33837898cf6808dd08e3aedda600fb8507c912d58ee8936ab06dac7a` |
| Train31 CG, KTB | `ktb_train31_cg_ktb_framing_final_v4.json` | 99,105 | 2026-08-10 07:52:14 | `9f81f3c105dfa297ede612ed4602eafe4a4eb1fed948442c2f3a2c02063c097f` |
| Train31 neural GPU, universal | `ktb_train31_neural_gpu_universal_framing_final_v4.json` | 117,500 | 2026-08-10 07:52:11 | `2e0c8a58a36ba3efb425a6ced6dec52b3fd5391363661534d927b212d18f6992` |
| Train31 neural GPU, KTB | `ktb_train31_neural_gpu_ktb_framing_final_v4.json` | 117,495 | 2026-08-10 07:52:23 | `3e9832eaeb2d6f34a211054415f167642644d32fe43e4eeb26cad9ccc780b446` |
| Benchmark, built-in lattice + CG | `benchmark_builtin_both_framing_final_v3.json` | 101,252 | 2026-08-10 08:04:53 | `9f2ff4af34b35f498ba0be3b2e3b295f3767d6ff80ef955a18f1a5d33b4cbc9a` |
| Benchmark, full KTB lattice + CG | `benchmark_ktb_r2.18_both_framing_final_v3.json` | 95,009 | 2026-08-10 08:05:44 | `dacb65f2ea7a0f397b5483c666ec17d4a05576831f75431a6763b3a5a3238639` |
| Benchmark, built-in neural GPU | `benchmark_builtin_neural_gpu_framing_final_v3.json` | 68,932 | 2026-08-10 08:06:30 | `5c052f5c2cbbb1dd65da10a73d0a3a8dc6d4bd9125a6acc937c43fd3cd9d5593` |
| Benchmark, train31 neural GPU | `benchmark_ktb_train31_neural_gpu_framing_final_v3.json` | 65,730 | 2026-08-10 08:07:11 | `b62c9ecf0a480485c495a0b53ad93c6478bb7151853df1b9da9139962bb4a9b5` |
| Benchmark, raw lattice + guesser | `benchmark_multidomain_5000_lattice_guess_framing_final_v3.json` | 46,635 | 2026-08-10 08:09:32 | `c75e18e0fd27d1c159db5097b02fc4bdba418c20f7462fe960efb8d58b33646e` |

## Development-only supplemental audits

Two earlier reports are retained solely as development diagnostics. They use
resource bundle
`f091920f60361d77546f882309d5c262a9e65e612df5318e40f9478d253f1ff9`.
Its four morphology payloads are byte-identical to the final `f03e` payloads,
but these reports predate the final backend, formatter, forced toolchain rehash,
8,192-entry cache, and lookup-framing fix. They are **not official release
evidence** and are not used in any central accuracy or performance table.

- `ktb_r2.18_atomic_span_gate_f091_v1.json`:
  4,343 bytes; 2026-08-10 05:03:43 UTC; SHA-256
  `c1f62707b4d3e6dce05127f548fd794dc9a422e3e98d679a0c25b2b67e772c4a`.
  It recorded 341 / 341 parent phrase spans and 1,653 / 1,653 original raw
  candidates preserved with zero failures.
- `benchmark_atomic_fastpath_f091_v1.json`:
  3,139 bytes; 2026-08-10 05:08:01 UTC; SHA-256
  `0858f8821b87387990662f5690f46e13c74d603d4ee2e527e1d804238696b3ee`.
  Its development microbenchmark measured roughly 1.98× speedup for the
  ordinary exact-partition single-pass path versus a forced two-pass
  counterfactual.

The authoritative atomic-token evidence is the final `f03e` KTB alignment
above; the authoritative performance evidence is the framing-final benchmark
ledger.

## Remaining evidence gap and limitations

There is no integrated, licensed, downloadable, independent Kazakh gold corpus
for exact lemma/POS/ordered-morpheme evaluation. The manually annotated `kD1`
corpus described by Tolegen, Toleu, and Mussabayev in
[Voted-Perceptron Approach for Kazakh Morphological Disambiguation](https://aclanthology.org/2020.sltu-1.36/)
is the strongest identified target, but its data and a redistribution license
are not published with the paper. Until independent data is licensed,
deduplicated, frozen, and annotated against an explicit contract, no result on
this page supports a universal 100% correctness claim.

Current limitations include:

- Primary orthography is Kazakh Cyrillic. Arabic-script Kazakh is not yet
  claimed; it needs the upstream transliteration composition.
- The productive OOV relation covers identity roots and three final-voicing
  mappings. Its frozen probes still miss vowel-deletion analyses for
  `ауыз→аузы`, `орын→орны`, and `халық→халқы`, plus the loan alternation
  `суперкубок→суперкубогы`.
- Productive lookup remains safety-bounded to 512 raw readings (2,048 under
  `--generate-all`) and a two-second complete-query deadline. Any unresolved
  cap, timeout, cycle, protocol failure, or worker failure is surfaced in
  diagnostics and invalidates a complete-lattice claim.
- CoNLL-U emits atomic non-whitespace FORM rows. It does not encode overlapping
  whitespace phrase spans or invent multiword-token rows for joined morphemes
  without reliable surface spans. JSONL v2 retains the full token and phrase
  lattice.
- XML is constrained by the XML 1.0 character repertoire. NUL, forbidden C0
  controls, surrogates, U+FFFE, and U+FFFF produce a controlled formatter error;
  text, JSON, and JSONL remain the lossless transports for those code points.
- CG intentionally abstains. Neural mode remains optional until it earns its
  place on genuinely independent held-out data.
- `--generate-all` is response-size bounded even though the productive FST is
  formally finite-valued per finite input.

See the [evaluation protocol](../docs/EVALUATION.md),
[behavior contract](../docs/CONTRACT.md), and
[benchmark instructions](README.md) for exact commands and definitions.
