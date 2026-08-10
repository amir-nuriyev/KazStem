# Contributing to KazStem

Bug reports and focused pull requests are welcome. Please include the smallest
Kazakh input that reproduces the behavior, the exact KazStem version, output
mode, resource-manifest identity, and whether productive or neural analysis was
enabled.

Changes to morphology, projection, ranking, or tokenization require regression
tests and must preserve the lossless reconstruction and bounded-lookup
contracts. Do not tune against sealed evaluation data. Resource and benchmark
work should follow `docs/EVALUATION.md`; source-only changes should run the full
unit suite before submission.

By submitting a contribution, you agree that it is licensed under the
repository's GPL-3.0-or-later license.
