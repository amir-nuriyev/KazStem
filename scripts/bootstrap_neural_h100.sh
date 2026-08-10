#!/usr/bin/env bash
set -euo pipefail

umask 022
export LC_ALL=C.UTF-8
export LANG=C.UTF-8
export TZ=UTC
export PYTHONHASHSEED=0
unset PYTHONHOME PYTHONPATH

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
runtime_dir=${QAZMORPH_RUNTIME_DIR:-"$project_root/.qazmorph"}
expected_host=${QAZMORPH_H100_HOSTNAME:-arboghast}
lock_file="$project_root/scripts/neural_assets.lock.json"
manifest_helper="$project_root/scripts/write_neural_manifest.py"
model_dir="$runtime_dir/neural/stanza"
venv_dir="$runtime_dir/neural-venv"
cache_dir=/dev/shm/qazmorph-neural-uv-cache

if [[ $(hostname) != "$expected_host" ]]; then
  echo "Refusing neural setup on $(hostname); expected $expected_host." >&2
  exit 2
fi
for command in cp diff flock realpath sha256sum /usr/bin/python3; do
  command -v "$command" >/dev/null || {
    echo "Required neural-bootstrap command is unavailable: $command" >&2
    exit 2
  }
done
[[ -f "$runtime_dir/resources/manifest.json" ]] || {
  echo "Run scripts/bootstrap_h100.sh before installing neural mode." >&2
  exit 2
}
[[ -f "$lock_file" && -f "$manifest_helper" ]] || {
  echo "Neural lock or manifest helper is missing from the project." >&2
  exit 2
}

mkdir -p "$runtime_dir/neural" "$runtime_dir/neural-venvs" "$runtime_dir/logs" "$cache_dir"
exec 7>"$runtime_dir/neural.lock"
flock -x 7

# A complete active pair can be reused only if package versions, project source,
# CUDA runtime, and every model byte still agree with their manifests.
if [[ -x "$venv_dir/bin/python" && -e "$model_dir" ]] \
  && /usr/bin/python3 "$manifest_helper" --lock "$lock_file" \
       --model-dir "$model_dir" --verify-model-manifest >/dev/null 2>&1 \
  && "$venv_dir/bin/python" "$manifest_helper" --lock "$lock_file" \
       --model-dir "$model_dir" --project-root "$project_root" \
       --verify-environment-manifest >/dev/null 2>&1; then
  echo "Neural runtime already matches its exact manifests."
  echo "$venv_dir/bin/qazmorph --neural --resource-dir $runtime_dir/resources"
  exit 0
fi

uv_bin=$(command -v uv || true)
if [[ -z "$uv_bin" && -x "$HOME/.local/bin/uv" ]]; then
  uv_bin="$HOME/.local/bin/uv"
fi
[[ -n "$uv_bin" ]] || {
  echo "uv is required for no-root neural setup on this host." >&2
  exit 2
}
readarray -t installer_lock < <(/usr/bin/python3 - "$lock_file" <<'PY'
import json
import sys

lock = json.load(open(sys.argv[1], encoding="utf-8"))
print(lock["installer"]["uv_version"])
print(lock["installer"]["uv_sha256"])
PY
)
actual_uv_version=$("$uv_bin" --version)
actual_uv_sha=$(sha256sum "$uv_bin" | awk '{print $1}')
if [[ "$actual_uv_version" != "${installer_lock[0]}" || "$actual_uv_sha" != "${installer_lock[1]}" ]]; then
  echo "uv differs from the neural lock: version=$actual_uv_version sha256=$actual_uv_sha" >&2
  exit 2
fi

readarray -t requirements < <(
  /usr/bin/python3 "$manifest_helper" --lock "$lock_file" --print-requirements
)
if (( ${#requirements[@]} == 0 )); then
  echo "Neural package lock yielded no requirements." >&2
  exit 2
fi

venv_stage=$(mktemp -d "$runtime_dir/neural-venvs/stanza-1.14.0.XXXXXX")
rmdir "$venv_stage"
model_stage=""
model_link_stage=""
venv_link_stage=""
legacy_model_moved=""
legacy_venv_moved=""
installation_complete=0
cleanup() {
  [[ -z "$model_link_stage" || ! -L "$model_link_stage" ]] || rm -f -- "$model_link_stage"
  [[ -z "$venv_link_stage" || ! -L "$venv_link_stage" ]] || rm -f -- "$venv_link_stage"
  [[ -z "$model_stage" || ! -d "$model_stage" ]] || rm -rf -- "$model_stage"
  if (( installation_complete == 0 )) && [[ -d "$venv_stage" ]]; then
    rm -rf -- "$venv_stage"
  fi
  if [[ -n "$legacy_model_moved" && ! -e "$model_dir" && ! -L "$model_dir" ]]; then
    mv "$legacy_model_moved" "$model_dir"
  fi
  if [[ -n "$legacy_venv_moved" && ! -e "$venv_dir" && ! -L "$venv_dir" ]]; then
    mv "$legacy_venv_moved" "$venv_dir"
  fi
}
trap cleanup EXIT

export UV_CACHE_DIR="$cache_dir"
export UV_LINK_MODE=copy
export PIP_CACHE_DIR="$cache_dir"
"$uv_bin" venv --python /usr/bin/python3 --system-site-packages "$venv_stage"
"$uv_bin" pip install --python "$venv_stage/bin/python" --no-deps \
  "${requirements[@]}"
"$uv_bin" pip install --python "$venv_stage/bin/python" --no-deps \
  --no-build-isolation "$project_root"

# Reuse already downloaded bytes only after exact lock verification. Otherwise
# download into an isolated staging directory; the active model path is untouched.
model_bundle_dir=""
if [[ -e "$model_dir" ]] && /usr/bin/python3 "$manifest_helper" \
  --lock "$lock_file" --model-dir "$model_dir" --verify-model-manifest >/dev/null 2>&1; then
  model_bundle_dir=$(realpath "$model_dir")
else
  model_stage=$(mktemp -d "$runtime_dir/neural/models-stage.XXXXXX")
  if [[ -e "$model_dir" ]] && /usr/bin/python3 "$manifest_helper" \
    --lock "$lock_file" --model-dir "$model_dir" --verify-model-files >/dev/null 2>&1; then
    cp -a --reflink=auto "$model_dir/." "$model_stage/"
    rm -f -- "$model_stage/manifest.json"
  else
    QAZMORPH_STANZA_MODEL_STAGE="$model_stage" \
    QAZMORPH_STANZA_LANGUAGE=kk \
    QAZMORPH_STANZA_PROCESSORS=tokenize,pos,lemma \
      "$venv_stage/bin/python" - <<'PY'
import os
import stanza

stanza.download(
    os.environ["QAZMORPH_STANZA_LANGUAGE"],
    model_dir=os.environ["QAZMORPH_STANZA_MODEL_STAGE"],
    processors=os.environ["QAZMORPH_STANZA_PROCESSORS"],
    verbose=False,
)
PY
  fi

  /usr/bin/python3 "$manifest_helper" --lock "$lock_file" \
    --model-dir "$model_stage" --verify-model-files
  model_bundle_id=$(/usr/bin/python3 "$manifest_helper" --lock "$lock_file" \
    --model-dir "$model_stage" --write-model-manifest)
  if [[ ! "$model_bundle_id" =~ ^[0-9a-f]{64}$ ]]; then
    echo "Neural model manifest returned an invalid bundle id: $model_bundle_id" >&2
    exit 2
  fi
  model_bundle_dir="$runtime_dir/neural/models.$model_bundle_id"
  if [[ -e "$model_bundle_dir" ]]; then
    if [[ ! -d "$model_bundle_dir" ]] || ! diff -qr "$model_stage" "$model_bundle_dir" >/dev/null; then
      echo "Existing content-addressed neural model differs: $model_bundle_dir" >&2
      exit 2
    fi
    rm -rf -- "$model_stage"
    model_stage=""
  else
    mv "$model_stage" "$model_bundle_dir"
    model_stage=""
    chmod -R a-w "$model_bundle_dir"
  fi
fi

/usr/bin/python3 "$manifest_helper" --lock "$lock_file" \
  --model-dir "$model_bundle_dir" --verify-model-manifest >/dev/null

model_link_stage="$runtime_dir/neural/.stanza-link.$$"
rm -f -- "$model_link_stage"
ln -s "$(basename "$model_bundle_dir")" "$model_link_stage"
if [[ -d "$model_dir" && ! -L "$model_dir" ]]; then
  legacy_model="$runtime_dir/neural/models.legacy-pre-content-addressed"
  if [[ -e "$legacy_model" || -L "$legacy_model" ]]; then
    echo "Cannot preserve existing neural model directory; legacy target exists: $legacy_model" >&2
    exit 2
  fi
  mv "$model_dir" "$legacy_model"
  legacy_model_moved="$legacy_model"
fi
mv -Tf "$model_link_stage" "$model_dir"
model_link_stage=""
legacy_model_moved=""

"$venv_stage/bin/python" "$manifest_helper" --lock "$lock_file" \
  --model-dir "$model_dir" --project-root "$project_root" \
  --write-environment-manifest >/dev/null
"$venv_stage/bin/python" "$manifest_helper" --lock "$lock_file" \
  --model-dir "$model_dir" --project-root "$project_root" \
  --verify-environment-manifest >/dev/null

venv_link_stage="$runtime_dir/.neural-venv-link.$$"
rm -f -- "$venv_link_stage"
ln -s "neural-venvs/$(basename "$venv_stage")" "$venv_link_stage"
if [[ -d "$venv_dir" && ! -L "$venv_dir" ]]; then
  legacy_venv="$runtime_dir/neural-venvs/legacy-pre-verified-manifest"
  if [[ -e "$legacy_venv" || -L "$legacy_venv" ]]; then
    echo "Cannot preserve existing neural environment; legacy target exists: $legacy_venv" >&2
    exit 2
  fi
  mv "$venv_dir" "$legacy_venv"
  legacy_venv_moved="$legacy_venv"
fi
mv -Tf "$venv_link_stage" "$venv_dir"
venv_link_stage=""
legacy_venv_moved=""
installation_complete=1

echo "Neural mode installed with exact package and model manifests. Run:"
echo "$venv_dir/bin/qazmorph --neural --resource-dir $runtime_dir/resources"
