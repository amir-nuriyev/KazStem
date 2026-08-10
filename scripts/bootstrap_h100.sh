#!/usr/bin/env bash
set -euo pipefail

umask 022
export LC_ALL=C.UTF-8
export LANG=C.UTF-8
export TZ=UTC
export PYTHONHASHSEED=0

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
runtime_dir=${QAZMORPH_RUNTIME_DIR:-"$project_root/.qazmorph"}
expected_host=${QAZMORPH_H100_HOSTNAME:-arboghast}

if [[ $(hostname) != "$expected_host" ]]; then
  echo "Refusing to bootstrap on $(hostname); expected $expected_host (set QAZMORPH_H100_HOSTNAME to override)." >&2
  exit 2
fi

for command in apt-get dpkg-deb flock git python3 sha256sum; do
  command -v "$command" >/dev/null || {
    echo "Required bootstrap command is unavailable: $command" >&2
    exit 2
  }
done

mkdir -p "$runtime_dir/debs" "$runtime_dir/toolchains" "$runtime_dir/sources" "$runtime_dir/logs"
exec 9>"$runtime_dir/bootstrap.lock"
flock -x 9

available_kib=$(df -Pk "$runtime_dir" | awk 'NR == 2 { print $4 }')
if (( available_kib < 524288 )); then
  echo "At least 512 MiB of free remote storage is required; found ${available_kib} KiB." >&2
  exit 2
fi

# This revision is backed by a checked-in byte-level archive lock. Keep the
# preceding verified extraction alongside it for auditability and rollback.
toolchain_version=ubuntu-noble-hfst3.16.0-cg3-1.4.6-r4-read-only
toolchain_target="$runtime_dir/toolchains/$toolchain_version"
debs_target="$runtime_dir/debs/$toolchain_version"
archive_lock="$project_root/scripts/toolchain_assets.lock.json"
[[ -f "$archive_lock" ]] || {
  echo "Checked-in toolchain archive lock is missing: $archive_lock" >&2
  exit 2
}
readarray -t packages < <(
  python3 "$project_root/scripts/write_toolchain_manifest.py" \
    --lock "$archive_lock" \
    --print-package-specs
)
if (( ${#packages[@]} == 0 )); then
  echo "Toolchain archive lock yielded no package specifications." >&2
  exit 2
fi

toolchain_stage=""
source_stage=""
toolchain_link=""
legacy_toolchain_moved=""
cleanup() {
  [[ -z "$toolchain_link" || ! -L "$toolchain_link" ]] || rm -f -- "$toolchain_link"
  if [[ -n "$toolchain_stage" && -d "$toolchain_stage" ]]; then
    chmod -R u+w "$toolchain_stage" 2>/dev/null || true
    rm -rf -- "$toolchain_stage"
  fi
  [[ -z "$source_stage" || ! -d "$source_stage" ]] || rm -rf -- "$source_stage"
  if [[ -n "$legacy_toolchain_moved" && ! -e "$runtime_dir/toolchain" && ! -L "$runtime_dir/toolchain" ]]; then
    mv "$legacy_toolchain_moved" "$runtime_dir/toolchain"
  fi
}
trap cleanup EXIT

if [[ -e "$toolchain_target" || -e "$debs_target" ]]; then
  if [[ ! -d "$toolchain_target" || ! -d "$debs_target" ]]; then
    echo "Refusing an incomplete pinned toolchain installation: $toolchain_target" >&2
    exit 2
  fi
  python3 "$project_root/scripts/write_toolchain_manifest.py" \
    --toolchain-dir "$toolchain_target" \
    --deb-dir "$debs_target" \
    --lock "$archive_lock" \
    --verify >/dev/null
else
  toolchain_stage=$(mktemp -d "$runtime_dir/toolchains/${toolchain_version}.stage.XXXXXX")
  mkdir -p "$toolchain_stage/debs" "$toolchain_stage/prefix"
  (
    cd "$toolchain_stage/debs"
    for package in "${packages[@]}"; do
      apt-get download "$package"
    done
    # Reject a changed mirror payload, unexpected archive, wrong package
    # metadata, or architecture mismatch before extracting a single byte.
    python3 "$project_root/scripts/write_toolchain_manifest.py" \
      --deb-dir "$toolchain_stage/debs" \
      --lock "$archive_lock" \
      --verify-archives-only
    for archive in ./*.deb; do
      dpkg-deb -x "$archive" "$toolchain_stage/prefix"
    done
  ) >"$runtime_dir/logs/toolchain.log" 2>&1

  # Record the immutable file modes themselves in the manifest. Keep only the
  # staging root writable long enough for the atomic manifest write, then seal
  # the complete prefix and its byte-locked Debian archives before activation.
  find "$toolchain_stage/prefix" -mindepth 1 \( -type f -o -type d \) \
    -exec chmod a-w {} +
  python3 "$project_root/scripts/write_toolchain_manifest.py" \
    --toolchain-dir "$toolchain_stage/prefix" \
    --deb-dir "$toolchain_stage/debs" \
    --lock "$archive_lock" >/dev/null
  chmod a-w "$toolchain_stage/prefix/manifest.json"
  find "$toolchain_stage/debs" -mindepth 1 \( -type f -o -type d \) \
    -exec chmod a-w {} +

  # Both targets are new and on the runtime filesystem. Never overwrite a
  # pre-existing path: an interrupted or foreign install needs inspection.
  mv "$toolchain_stage/prefix" "$toolchain_target"
  mv "$toolchain_stage/debs" "$debs_target"
  chmod a-w "$toolchain_target" "$debs_target"
  rmdir "$toolchain_stage"
  toolchain_stage=""
fi

python3 "$project_root/scripts/write_toolchain_manifest.py" \
  --toolchain-dir "$toolchain_target" \
  --deb-dir "$debs_target" \
  --lock "$archive_lock" \
  --verify >/dev/null
if [[ -n $(find "$toolchain_target" "$debs_target" \
  \( -type f -o -type d \) -perm /222 -print -quit) ]]; then
  echo "Pinned toolchain/deb bundle is unexpectedly writable: $toolchain_target" >&2
  exit 2
fi

toolchain_link="$runtime_dir/.toolchain-link.$$"
rm -f -- "$toolchain_link"
ln -s "toolchains/$toolchain_version" "$toolchain_link"
if [[ -d "$runtime_dir/toolchain" && ! -L "$runtime_dir/toolchain" ]]; then
  legacy_toolchain="$runtime_dir/toolchains/legacy-pre-verified-manifest"
  if [[ -e "$legacy_toolchain" || -L "$legacy_toolchain" ]]; then
    echo "Cannot preserve existing toolchain; legacy target exists: $legacy_toolchain" >&2
    exit 2
  fi
  mv "$runtime_dir/toolchain" "$legacy_toolchain"
  legacy_toolchain_moved="$legacy_toolchain"
fi
mv -Tf "$toolchain_link" "$runtime_dir/toolchain"
toolchain_link=""
legacy_toolchain_moved=""

source_dir="$runtime_dir/sources/apertium-kaz"
source_commit=95c6dd0d8536ee69a7058634b03a3e82100b6b6e
source_url=https://github.com/apertium/apertium-kaz.git
if [[ ! -e "$source_dir" ]]; then
  source_stage=$(mktemp -d "$runtime_dir/sources/apertium-kaz.stage.XXXXXX")
  rmdir "$source_stage"
  git clone --filter=blob:none "$source_url" "$source_stage"
  mv "$source_stage" "$source_dir"
  source_stage=""
elif [[ ! -d "$source_dir/.git" ]]; then
  echo "Refusing to replace a non-git source path: $source_dir" >&2
  exit 2
fi

if [[ -n $(git -C "$source_dir" status --porcelain=v1 --untracked-files=all) ]]; then
  echo "Refusing to build from a dirty apertium-kaz checkout: $source_dir" >&2
  exit 2
fi
git -C "$source_dir" fetch --depth 1 origin "$source_commit"
git -C "$source_dir" checkout --detach "$source_commit"
if [[ $(git -C "$source_dir" rev-parse HEAD) != "$source_commit" ]]; then
  echo "apertium-kaz did not resolve to the locked commit $source_commit" >&2
  exit 2
fi
if [[ -n $(git -C "$source_dir" status --porcelain=v1 --untracked-files=all) ]]; then
  echo "apertium-kaz became dirty after checkout: $source_dir" >&2
  exit 2
fi

QAZMORPH_RUNTIME_DIR="$runtime_dir" \
QAZMORPH_APERTIUM_KAZ_SOURCE="$source_dir" \
QAZMORPH_APERTIUM_KAZ_COMMIT="$source_commit" \
  bash "$project_root/scripts/build_resources.sh"

echo "qazmorph runtime installed at $runtime_dir"
echo "export QAZMORPH_RESOURCE_DIR=$runtime_dir/resources"
