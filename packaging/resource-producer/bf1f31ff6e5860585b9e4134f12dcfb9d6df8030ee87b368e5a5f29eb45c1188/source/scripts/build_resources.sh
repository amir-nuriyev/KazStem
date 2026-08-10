#!/usr/bin/env bash
set -euo pipefail

umask 022
export LC_ALL=C.UTF-8
export LANG=C.UTF-8
export TZ=UTC
export PYTHONHASHSEED=0

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
runtime_dir=${QAZMORPH_RUNTIME_DIR:-"$project_root/.qazmorph"}
source_dir=${QAZMORPH_APERTIUM_KAZ_SOURCE:-"$runtime_dir/sources/apertium-kaz"}
expected_commit=${QAZMORPH_APERTIUM_KAZ_COMMIT:-95c6dd0d8536ee69a7058634b03a3e82100b6b6e}
expected_host=${QAZMORPH_H100_HOSTNAME:-arboghast}
activate_resources=${QAZMORPH_ACTIVATE_RESOURCES:-1}
resource_dir="$runtime_dir/resources"
log_dir="$runtime_dir/logs"

if [[ $(hostname) != "$expected_host" ]]; then
  echo "Refusing to compile resources on $(hostname); expected $expected_host." >&2
  exit 2
fi
if [[ "$activate_resources" != 0 && "$activate_resources" != 1 ]]; then
  echo "QAZMORPH_ACTIVATE_RESOURCES must be 0 or 1." >&2
  exit 2
fi
for command in cmp flock git python3 readlink; do
  command -v "$command" >/dev/null || {
    echo "Required resource-build command is unavailable: $command" >&2
    exit 2
  }
done

mkdir -p "$runtime_dir" "$log_dir"
exec 8>"$runtime_dir/resources.lock"
flock -x 8

# Resolve the mutable convenience symlink exactly once after taking the build
# lock.  Every compiler invocation and the final manifest now use this one
# immutable directory, even if a concurrent bootstrap atomically advances the
# stable link for a future build.
toolchains_root=$(readlink -f -- "$runtime_dir/toolchains")
toolchain_dir=$(readlink -f -- "$runtime_dir/toolchain")
case "$toolchain_dir/" in
  "$toolchains_root"/*/) ;;
  *)
    echo "Resolved toolchain is outside the immutable toolchains directory: $toolchain_dir" >&2
    exit 2
    ;;
esac
if [[ ! -f "$toolchain_dir/manifest.json" ]]; then
  echo "Verified toolchain manifest is missing; run scripts/bootstrap_h100.sh first." >&2
  exit 2
fi
toolchain_name=$(basename "$toolchain_dir")
python3 "$project_root/scripts/write_toolchain_manifest.py" \
  --toolchain-dir "$toolchain_dir" \
  --deb-dir "$runtime_dir/debs/$toolchain_name" \
  --lock "$project_root/scripts/toolchain_assets.lock.json" \
  --verify >/dev/null
if [[ ! -d "$source_dir/.git" ]]; then
  echo "Missing apertium-kaz git source at $source_dir" >&2
  exit 2
fi
actual_commit=$(git -C "$source_dir" rev-parse HEAD)
if [[ "$actual_commit" != "$expected_commit" ]]; then
  echo "apertium-kaz is at $actual_commit, expected $expected_commit" >&2
  exit 2
fi
if [[ -n $(git -C "$source_dir" status --porcelain=v1 --untracked-files=all) ]]; then
  echo "Refusing to compile a dirty apertium-kaz source tree: $source_dir" >&2
  exit 2
fi
export SOURCE_DATE_EPOCH
SOURCE_DATE_EPOCH=$(git -C "$source_dir" show -s --format=%ct HEAD)

build_dir=$(mktemp -d "$runtime_dir/build-stage.XXXXXX")
resource_stage=$(mktemp -d "$runtime_dir/resources-stage.XXXXXX")
link_stage=""
legacy_moved=""
cleanup() {
  [[ -z "${link_stage:-}" || ! -L "$link_stage" ]] || rm -f -- "$link_stage"
  [[ -z "${build_dir:-}" || ! -d "$build_dir" ]] || rm -rf -- "$build_dir"
  [[ -z "${resource_stage:-}" || ! -d "$resource_stage" ]] || rm -rf -- "$resource_stage"
  if [[ -n "${legacy_moved:-}" && ! -e "$resource_dir" && ! -L "$resource_dir" ]]; then
    mv "$legacy_moved" "$resource_dir"
  fi
}
trap cleanup EXIT

export PATH="$toolchain_dir/usr/bin:$PATH"
library_dir="$toolchain_dir/usr/lib/x86_64-linux-gnu"
export LD_LIBRARY_PATH="$library_dir${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
unset CG3_DEFAULT CG3_OVERRIDE

for command in hfst-lexc hfst-twolc hfst-compose-intersect hfst-disjunct hfst-minimise hfst-invert hfst-fst2fst hfst-fst2strings hfst-fst2txt hfst-lookup hfst-regexp2fst hfst-subtract cg-comp; do
  command -v "$command" >/dev/null || {
    echo "Missing $command; run scripts/bootstrap_h100.sh first." >&2
    exit 2
  }
done
[[ -f "$source_dir/apertium-kaz.kaz.lexc" ]] || {
  echo "Missing apertium-kaz source at $source_dir" >&2
  exit 2
}

cd "$build_dir"
build_input_snapshot="$build_dir/build-inputs.start.json"
python3 "$project_root/scripts/write_manifest.py" \
  --project-root "$project_root" \
  --snapshot-build-inputs >"$build_input_snapshot"

# Match apertium-kaz's direction-specific upstream build. Analysis retains both
# explicitly directional variants but excludes orthographic-error paths; the
# generator excludes entries marked analysis-only (Dir/LR in upstream naming).
grep -v -e 'Err/Orth' "$source_dir/apertium-kaz.kaz.lexc" >kaz.analysis.lexc
grep -v -e 'Dir/LR' -e 'Err/Orth' "$source_dir/apertium-kaz.kaz.lexc" >kaz.generation.lexc
hfst-lexc --Werror kaz.analysis.lexc -o kaz.analysis.lexc.hfst >"$log_dir/hfst-analysis-lexc.log" 2>&1
hfst-lexc --Werror kaz.generation.lexc -o kaz.generation.lexc.hfst >"$log_dir/hfst-generation-lexc.log" 2>&1
hfst-twolc "$source_dir/apertium-kaz.kaz.twol" -o kaz.twol.hfst >"$log_dir/hfst-twolc.log" 2>&1
hfst-compose-intersect -1 kaz.analysis.lexc.hfst -2 kaz.twol.hfst \
  | hfst-minimise -o kaz.analysis.hfst
hfst-compose-intersect -1 kaz.generation.lexc.hfst -2 kaz.twol.hfst \
  | hfst-minimise -o kaz.generation.hfst

# Formal bidirectional invariant: every lexical-to-surface pair licensed by the
# generator must also be accepted by the analyzer. A single path in G - A is a
# concrete counterexample and makes the build fail before optimized artifacts
# can be installed.
hfst-subtract -1 kaz.generation.hfst -2 kaz.analysis.hfst \
  -o kaz.generation-not-analysis.hfst \
  >"$log_dir/generation-subset.log" 2>&1
counterexample=$(hfst-fst2strings -n 1 kaz.generation-not-analysis.hfst \
  2>>"$log_dir/generation-subset.log")
if [[ -n "$counterexample" ]]; then
  printf 'Generator relation is not a subset of analyzer relation; counterexample: %s\n' \
    "$counterexample" >&2
  exit 2
fi
printf 'PASS: generation relation minus analysis relation is empty.\n' \
  >>"$log_dir/generation-subset.log"

hfst-invert kaz.analysis.hfst | hfst-fst2fst -O -o kaz.automorf.hfstol
hfst-fst2fst -O kaz.generation.hfst -o kaz.autogen.hfstol

# The public source contains a deliberately disabled Cyrillic open-stem path.
# Enable it in two direction-specific fallback sources. Analysis retains
# Dir/LR paths; productive generation removes those explicitly analysis-only
# variants before the finite root filter is applied.
awk '
  { print }
  $0 == "LEXICON Guesser" {
    letters = "а | ә | б | в | г | ғ | д | е | ё | ж | з | и | і | й | к | қ | л | м | н | ң | о | ө | п | р | с | т | у | ұ | ү | ф | х | һ | ц | ч | ш | щ | ь | ы | ъ | э | ю | я"
    print "<[" letters "]+> N1 ;"
    print "<[" letters "]+> A1 ;"
    print "<[" letters "]+> V-TV ;"
    print "<[" letters "]+> V-IV ;"
  }
' "$source_dir/apertium-kaz.kaz.lexc" >kaz.guesser.injected.lexc
grep -v -e 'Err/Orth' kaz.guesser.injected.lexc \
  >kaz.guesser.analysis.lexc
grep -v -e 'Dir/LR' -e 'Err/Orth' kaz.guesser.injected.lexc \
  >kaz.guesser.generation.lexc
hfst-lexc --Werror kaz.guesser.analysis.lexc -o kaz.guesser.analysis.lexc.hfst \
  >"$log_dir/hfst-guesser-lexc.log" 2>&1
hfst-lexc --Werror kaz.guesser.generation.lexc \
  -o kaz.guesser.generation.lexc.hfst \
  >"$log_dir/hfst-guesser-generation-lexc.log" 2>&1
hfst-compose-intersect -1 kaz.guesser.analysis.lexc.hfst -2 kaz.twol.hfst \
  | hfst-minimise -o kaz.guesser.analysis.hfst
hfst-compose-intersect -1 kaz.guesser.generation.lexc.hfst -2 kaz.twol.hfst \
  | hfst-minimise -o kaz.guesser.generation.hfst
hfst-invert kaz.guesser.analysis.hfst \
  -o kaz.guesser.unfiltered.automorf.hfst
hfst-invert kaz.guesser.generation.hfst \
  -o kaz.guesser.generation.unfiltered.automorf.hfst

# The upstream two-level grammar licenses stem-internal zero correspondences
# such as ы:0.  Applying it to an arbitrary ``[Cyrillic]+`` stem and then
# inverting therefore creates input-epsilon root loops: hfst-lookup reports a
# real ``[...cyclic...]`` truncation instead of a complete candidate set.
#
# First retain the existing bounded relation unchanged. Then add two isolated
# noun-only subrelations: one output-only high vowel may occur exactly once
# immediately before the final root consonant, and a back-harmony surface may
# map to a lemma ending in the literal compound head ``кубок``. The latter is
# deliberately suffix-gated instead of generalizing г→к: a generic rule would
# rank false lemmas such as каталок, аналок, блок, and психолок above their
# identity guesses. Every loop below consumes a surface character; the one
# root epsilon in the syncope branch is structurally one-shot.
guesser_identity_pairs='а:а | ә:ә | б:б | в:в | г:г | ғ:ғ | д:д | е:е | ё:ё | ж:ж | з:з | и:и | і:і | й:й | к:к | қ:қ | л:л | м:м | н:н | ң:ң | о:о | ө:ө | п:п | р:р | с:с | т:т | у:у | ұ:ұ | ү:ү | ф:ф | х:х | һ:һ | ц:ц | ч:ч | ш:ш | щ:щ | ь:ь | ы:ы | ъ:ъ | э:э | ю:ю | я:я'
guesser_final_alternations='б:п | г:к | ғ:қ'
guesser_consonant_identity_pairs='б:б | в:в | г:г | ғ:ғ | д:д | ж:ж | з:з | й:й | к:к | қ:қ | л:л | м:м | н:н | ң:ң | п:п | р:р | с:с | т:т | ф:ф | х:х | һ:һ | ц:ц | ч:ч | ш:ш | щ:щ | ь:ь | ъ:ъ'
guesser_tail='[ ?:? | ?:0 | 0:? ]*'

printf '@bin"kaz.guesser.unfiltered.automorf.hfst" & [ [ [ [ %s ]+ | [ %s ]+ [ %s ] ] ] [ 0:"<n>" | 0:"<adj>" | 0:"<v>" ] [ ?:? | ?:0 | 0:? ]* ]\n' \
  "$guesser_identity_pairs" \
  "$guesser_identity_pairs" \
  "$guesser_final_alternations" \
  | hfst-regexp2fst -f openfst-tropical \
  | hfst-minimise -o kaz.guesser.baseline.automorf.hfst

printf '@bin"kaz.guesser.unfiltered.automorf.hfst" & [ [ %s ]+ [ 0:ы | 0:і ] [ %s ] 0:"<n>" %s ]\n' \
  "$guesser_identity_pairs" \
  "$guesser_consonant_identity_pairs" \
  "$guesser_tail" \
  | hfst-regexp2fst -f openfst-tropical \
  | hfst-minimise -o kaz.guesser.noun-syncope.automorf.hfst

# The upstream arbitrary-root continuation treats final к as front-harmonic.
# Normalize one or more consuming back suffix vowels to that canonical front
# surface before composition, then admit only a lexical root ending кубок.
# Intersecting after composition prevents any normalization inside the root.
printf '[ [ %s ]* [ ы:і | а:е ] [ [ %s ] | [ ы:і | а:е ] ]* ]\n' \
  "$guesser_identity_pairs" \
  "$guesser_identity_pairs" \
  | hfst-regexp2fst -f openfst-tropical \
  | hfst-minimise -o kaz.guesser.back-to-front-suffix.hfst
printf '@bin"kaz.guesser.back-to-front-suffix.hfst" .o. @bin"kaz.guesser.baseline.automorf.hfst"\n' \
  | hfst-regexp2fst -f openfst-tropical \
  | hfst-minimise -o kaz.guesser.back-harmony-composed.automorf.hfst
printf '@bin"kaz.guesser.back-harmony-composed.automorf.hfst" & [ [ [ %s ]* к:к у:у б:б о:о г:к ] 0:"<n>" %s ]\n' \
  "$guesser_identity_pairs" \
  "$guesser_tail" \
  | hfst-regexp2fst -f openfst-tropical \
  | hfst-minimise -o kaz.guesser.kubok-family.automorf.hfst

printf '[ @bin"kaz.guesser.baseline.automorf.hfst" | @bin"kaz.guesser.noun-syncope.automorf.hfst" | @bin"kaz.guesser.kubok-family.automorf.hfst" ]\n' \
  | hfst-regexp2fst -f openfst-tropical \
  | hfst-minimise -o kaz.guesser.filtered.automorf.hfst

# Reapply the same finite root construction to the Dir/LR-free relation. The
# upstream lexical arcs for tracked syncope roots (for example ауыз:ау%{y%}з)
# are themselves marked Dir/LR, so intersecting the safe analyzer directly
# would silently lose those canonical generated forms. Instead, insert one
# high vowel into a syncopated surface, require at least one consuming suffix
# character, feed that canonicalized surface through the already-safe baseline,
# and retain only paths already licensed by the full noun-syncope relation and
# whose recovered vowel is immediately before the final lexical root consonant.
# Keep that recovered Dir/LR-root class separate from the native syncope arcs
# which remain in the safe upstream source. Both branches preserve safe suffix
# direction and are structural subsets of the full analysis relation.
printf '@bin"kaz.guesser.generation.unfiltered.automorf.hfst" & [ [ [ [ %s ]+ | [ %s ]+ [ %s ] ] ] [ 0:"<n>" | 0:"<adj>" | 0:"<v>" ] [ ?:? | ?:0 | 0:? ]* ]\n' \
  "$guesser_identity_pairs" \
  "$guesser_identity_pairs" \
  "$guesser_final_alternations" \
  | hfst-regexp2fst -f openfst-tropical \
  | hfst-minimise -o kaz.guesser.generation.baseline.automorf.hfst

printf '@bin"kaz.guesser.generation.unfiltered.automorf.hfst" & [ [ %s ]+ [ 0:ы | 0:і ] [ %s ] 0:"<n>" %s ]\n' \
  "$guesser_identity_pairs" \
  "$guesser_consonant_identity_pairs" \
  "$guesser_tail" \
  | hfst-regexp2fst -f openfst-tropical \
  | hfst-minimise -o kaz.guesser.generation.noun-syncope-retained.automorf.hfst

printf '[ [ %s ]+ [ 0:ы | 0:і ] [ %s ] [ %s ]+ ]\n' \
  "$guesser_identity_pairs" \
  "$guesser_consonant_identity_pairs" \
  "$guesser_identity_pairs" \
  | hfst-regexp2fst -f openfst-tropical \
  | hfst-minimise -o kaz.guesser.generation.noun-syncope-normalizer.hfst
printf '@bin"kaz.guesser.generation.noun-syncope-normalizer.hfst" .o. @bin"kaz.guesser.generation.baseline.automorf.hfst"\n' \
  | hfst-regexp2fst -f openfst-tropical \
  | hfst-minimise -o kaz.guesser.generation.noun-syncope-composed.automorf.hfst
printf '[ @bin"kaz.guesser.noun-syncope.automorf.hfst" & @bin"kaz.guesser.generation.noun-syncope-composed.automorf.hfst" ] & [ [ %s ]+ [ 0:ы | 0:і ] [ %s ] 0:"<n>" %s ]\n' \
  "$guesser_identity_pairs" \
  "$guesser_consonant_identity_pairs" \
  "$guesser_tail" \
  | hfst-regexp2fst -f openfst-tropical \
  | hfst-minimise -o kaz.guesser.generation.noun-syncope-recovered.automorf.hfst

printf '[ @bin"kaz.guesser.generation.noun-syncope-retained.automorf.hfst" | @bin"kaz.guesser.generation.noun-syncope-recovered.automorf.hfst" ]\n' \
  | hfst-regexp2fst -f openfst-tropical \
  | hfst-minimise -o kaz.guesser.generation.noun-syncope.automorf.hfst

printf '@bin"kaz.guesser.back-to-front-suffix.hfst" .o. @bin"kaz.guesser.generation.baseline.automorf.hfst"\n' \
  | hfst-regexp2fst -f openfst-tropical \
  | hfst-minimise -o kaz.guesser.generation.back-harmony-composed.automorf.hfst
printf '@bin"kaz.guesser.generation.back-harmony-composed.automorf.hfst" & [ [ [ %s ]* к:к у:у б:б о:о г:к ] 0:"<n>" %s ]\n' \
  "$guesser_identity_pairs" \
  "$guesser_tail" \
  | hfst-regexp2fst -f openfst-tropical \
  | hfst-minimise -o kaz.guesser.generation.kubok-family.automorf.hfst

printf '[ @bin"kaz.guesser.generation.baseline.automorf.hfst" | @bin"kaz.guesser.generation.noun-syncope.automorf.hfst" | @bin"kaz.guesser.generation.kubok-family.automorf.hfst" ]\n' \
  | hfst-regexp2fst -f openfst-tropical \
  | hfst-minimise -o kaz.guesser.generation.filtered.automorf.hfst

# Optimized lookup was unsafe for the former cyclic relation. The finite
# filtered graph converts safely and is materially faster. The verifier below
# converts it back and proves both relation differences empty before install.
hfst-fst2fst -O kaz.guesser.filtered.automorf.hfst \
  -o kaz.guesser.automorf.hfstol

# Derive productive generation only from the generation-direction-safe finite
# analyzer relation. The independent verifier proves exact inversion, safe
# subset inclusion, installed-artifact equivalence, and direction-specific
# required/forbidden probes.
hfst-invert kaz.guesser.generation.filtered.automorf.hfst \
  | hfst-minimise -o kaz.guesser.autogen.hfst
hfst-fst2fst -O kaz.guesser.autogen.hfst \
  -o kaz.guesser.autogen.hfstol

# This is a formal graph gate, not a sample-only smoke test: no input-epsilon
# cycle may be reachable from the initial state.  The checked-in probes then
# exercise every open-class continuation and a stratified set of formerly
# capped corpus types with hfst-lookup's result cap disabled.
python3 "$project_root/scripts/verify_guesser_fst.py" \
  --baseline-fst kaz.guesser.baseline.automorf.hfst \
  --fst kaz.guesser.filtered.automorf.hfst \
  --optimized-fst kaz.guesser.automorf.hfstol \
  --fst2fst hfst-fst2fst \
  --fst2strings hfst-fst2strings \
  --fst2txt hfst-fst2txt \
  --lookup hfst-lookup \
  --optimized-lookup hfst-optimized-lookup \
  --subtract hfst-subtract \
  --probes "$project_root/scripts/guesser_regression_probes.json" \
  --output "$log_dir/guesser-finiteness.json"

python3 "$project_root/scripts/verify_generator_fst.py" \
  --analyzer-fst kaz.guesser.generation.filtered.automorf.hfst \
  --full-analyzer-fst kaz.guesser.filtered.automorf.hfst \
  --full-analyzer-optimized-fst kaz.guesser.automorf.hfstol \
  --fst kaz.guesser.autogen.hfst \
  --optimized-fst kaz.guesser.autogen.hfstol \
  --dictionary-generator-fst kaz.generation.hfst \
  --dictionary-generator-optimized-fst kaz.autogen.hfstol \
  --dictionary-analyzer-fst kaz.analysis.hfst \
  --dictionary-analyzer-optimized-fst kaz.automorf.hfstol \
  --fst2fst hfst-fst2fst \
  --fst2strings hfst-fst2strings \
  --fst2txt hfst-fst2txt \
  --lookup hfst-lookup \
  --optimized-lookup hfst-optimized-lookup \
  --subtract hfst-subtract \
  --invert hfst-invert \
  --disjunct hfst-disjunct \
  --probes "$project_root/scripts/guesser_regression_probes.json" \
  --direction-probes "$project_root/scripts/generator_regression_probes.json" \
  --output "$log_dir/generator-finiteness.json"

cg-comp "$source_dir/apertium-kaz.kaz.rlx" kaz.rlx.bin >"$log_dir/cg-comp.log" 2>&1

install -m 0644 kaz.automorf.hfstol "$resource_stage/kaz.automorf.hfstol"
install -m 0644 kaz.autogen.hfstol "$resource_stage/kaz.autogen.hfstol"
install -m 0644 kaz.guesser.automorf.hfstol "$resource_stage/kaz.guesser.automorf.hfstol"
install -m 0644 kaz.guesser.autogen.hfstol "$resource_stage/kaz.guesser.autogen.hfstol"
install -m 0644 kaz.rlx.bin "$resource_stage/kaz.rlx.bin"
python3 "$project_root/scripts/write_manifest.py" \
  --project-root "$project_root" \
  --snapshot-build-inputs >build-inputs.end.json
if ! cmp -s "$build_input_snapshot" build-inputs.end.json; then
  echo "Project build inputs changed during resource compilation." >&2
  exit 2
fi
bundle_id=$(python3 "$project_root/scripts/write_manifest.py" \
  --resource-dir "$resource_stage" \
  --source-dir "$source_dir" \
  --toolchain-dir "$toolchain_dir" \
  --project-root "$project_root" \
  --guesser-verification "$log_dir/guesser-finiteness.json" \
  --generator-verification "$log_dir/generator-finiteness.json" \
  --expected-build-input-snapshot "$build_input_snapshot" \
  --expected-source-commit "$expected_commit")
if [[ ! "$bundle_id" =~ ^[0-9a-f]{64}$ ]]; then
  echo "Resource manifest returned an invalid bundle id: $bundle_id" >&2
  exit 2
fi

# Content-addressed directories are immutable snapshots. The stable `resources`
# symlink is replaced with one rename, so readers see either the old complete
# bundle or the new complete bundle, never a half-populated directory.
bundle_dir="$runtime_dir/resources.$bundle_id"
if [[ -e "$bundle_dir" ]]; then
  if [[ ! -d "$bundle_dir" ]] || ! diff -qr "$resource_stage" "$bundle_dir" >/dev/null; then
    echo "Existing content-addressed bundle differs: $bundle_dir" >&2
    exit 2
  fi
  rm -rf -- "$resource_stage"
  resource_stage=""
else
  mv "$resource_stage" "$bundle_dir"
  resource_stage=""
fi

# Reapply the seal even when a byte-identical content-addressed bundle already
# exists.  This makes bootstrap/build idempotently repair permission drift
# instead of silently reactivating a writable snapshot.
chmod -R a-w "$bundle_dir"
if [[ -n $(find "$bundle_dir" \( -type f -o -type d \) -perm /222 -print -quit) ]]; then
  echo "Content-addressed resource bundle is not sealed read-only: $bundle_dir" >&2
  exit 2
fi

if [[ "$activate_resources" == 0 ]]; then
  echo "Built and verified resources in $bundle_dir"
  echo "Activation deferred; $resource_dir remains unchanged"
  exit 0
fi

link_stage="$runtime_dir/.resources-link.$$"
rm -f -- "$link_stage"
ln -s "$(basename "$bundle_dir")" "$link_stage"
if [[ -d "$resource_dir" && ! -L "$resource_dir" ]]; then
  legacy="$runtime_dir/resources.legacy-pre-content-addressed"
  if [[ -e "$legacy" || -L "$legacy" ]]; then
    echo "Cannot preserve existing resources directory; legacy target exists: $legacy" >&2
    exit 2
  fi
  mv "$resource_dir" "$legacy"
  legacy_moved="$legacy"
fi
mv -Tf "$link_stage" "$resource_dir"
link_stage=""
legacy_moved=""

echo "Built resources in $bundle_dir"
echo "Activated $resource_dir -> $(readlink "$resource_dir")"
