#!/usr/bin/env bash
# Synchronize runtime-port vendored data from the canonical repository UCD data.
#
# This is intentionally local and bounded: it does not download Unicode data,
# does not run Lean, and does not build proof/conformance roots. Update the
# canonical `Unicode/Ucd/` files and root `data/` symlink surface first, then
# run this script with `--apply`.

set -euo pipefail

cd "$(dirname "$0")/.."

mode="check"
haskell_dir="${UNICODE_HASKELL_DIR:-ports/haskell}"
python_data_dir="${UNICODE_PYTHON_DATA_DIR:-src/unicode_python/data}"
jvm_dir="${UNICODE_JVM_DIR:-ports/jvm}"
go_dir="${UNICODE_GO_DIR:-ports/go}"
typescript_dir="${UNICODE_TYPESCRIPT_DIR:-ports/typescript}"
dotnet_dir="${UNICODE_DOTNET_DIR:-ports/dotnet}"
swift_dir="${UNICODE_SWIFT_DIR:-ports/swift}"
zig_dir="${UNICODE_ZIG_DIR:-ports/zig}"

root_manifest_files=(
  CaseFolding.txt
  CompositionExclusions.txt
  confusables.txt
  DerivedCoreProperties.txt
  emoji-variation-sequences.txt
  IdentifierStatus.txt
  KnownAttackTargets.txt
  PropertyValueAliases.txt
  ScriptExtensions.txt
  Scripts.txt
  StandardizedVariants.txt
  UnicodeData.txt
  UCD-VERSION
)

python_files=(
  CaseFolding.txt
  CompositionExclusions.txt
  DerivedCoreProperties.txt
  IdentifierStatus.txt
  KnownAttackTargets.txt
  PropertyValueAliases.txt
  ScriptExtensions.txt
  Scripts.txt
  StandardizedVariants.txt
  UnicodeData.txt
  confusables.txt
  emoji-variation-sequences.txt
)

haskell_files=(
  UnicodeData.txt
  CompositionExclusions.txt
  DerivedNormalizationProps.txt
  confusables.txt
  KnownAttackTargets.txt
)

homoglyph_files=(
  confusables.txt
  KnownAttackTargets.txt
)

usage() {
  cat <<'USAGE'
Usage: scripts/sync-runtime-data.sh [--check|--apply]

Default mode is --check.

Modes:
  --check   Verify runtime vendored data/manifests are already synchronized.
  --apply   Copy canonical data into runtime ports, refresh SHA256SUMS files,
            regenerate generated runtime tables, then run the data guard.

Environment:
  UNICODE_HASKELL_DIR=PATH
  UNICODE_PYTHON_DATA_DIR=PATH
  UNICODE_JVM_DIR=PATH
  UNICODE_GO_DIR=PATH
  UNICODE_TYPESCRIPT_DIR=PATH
  UNICODE_DOTNET_DIR=PATH
  UNICODE_SWIFT_DIR=PATH
  UNICODE_ZIG_DIR=PATH

Notes:
  - This script does not download Unicode data.
  - This script does not build Lean or full conformance roots.
  - Canonical UCD/security bytes must already be present under Unicode/Ucd
    and the root data/ symlink surface.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --check)
      mode="check"
      ;;
    --apply)
      mode="apply"
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
  shift
done

require_file() {
  local path="$1"
  if [[ ! -e "$path" ]]; then
    echo "FATAL: missing required data file: $path" >&2
    exit 1
  fi
}

copy_file() {
  local src="$1"
  local dst="$2"
  require_file "$src"
  mkdir -p "$(dirname "$dst")"
  cp "$src" "$dst"
}

check_same_file() {
  local src="$1"
  local dst="$2"
  require_file "$src"
  require_file "$dst"
  if ! cmp -s "$src" "$dst"; then
    echo "drift: $dst differs from $src" >&2
    echo "run: scripts/sync-runtime-data.sh --apply" >&2
    exit 1
  fi
}

check_same_version_keys() {
  local src="$1"
  local dst="$2"
  require_file "$src"
  require_file "$dst"
  local src_keys
  local dst_keys
  src_keys="$(grep -E '^(UCD|UCA|PINNED)=' "$src")"
  dst_keys="$(grep -E '^(UCD|UCA|PINNED)=' "$dst")"
  if [[ "$src_keys" != "$dst_keys" ]]; then
    echo "drift: version keys in $dst differ from $src" >&2
    echo "run: scripts/sync-runtime-data.sh --apply" >&2
    exit 1
  fi
}

sync_haskell_version() {
  local tmp
  tmp="$(mktemp)"
  grep -E '^(UCD|UCA|PINNED)=' data/UCD-VERSION > "$tmp"
  awk '
    BEGIN { skipping = 1 }
    skipping && /^(UCD|UCA|PINNED)=/ { next }
    { skipping = 0; print }
  ' "$haskell_dir/data/UCD-VERSION" >> "$tmp"
  mv "$tmp" "$haskell_dir/data/UCD-VERSION"
}

write_manifest() {
  local dir="$1"
  shift
  (
    cd "$dir"
    sha256sum "$@" > SHA256SUMS
  )
}

check_manifest() {
  local dir="$1"
  (
    cd "$dir"
    sha256sum -c --strict --quiet SHA256SUMS
  )
}

sync_python() {
  local file
  for file in "${python_files[@]}"; do
    copy_file "data/$file" "$python_data_dir/$file"
  done
}

check_python() {
  local file
  for file in "${python_files[@]}"; do
    check_same_file "data/$file" "$python_data_dir/$file"
  done
}

sync_haskell() {
  sync_haskell_version
  copy_file data/UnicodeData.txt "$haskell_dir/data/UnicodeData.txt"
  copy_file data/CompositionExclusions.txt "$haskell_dir/data/CompositionExclusions.txt"
  copy_file Unicode/Ucd/DerivedNormalizationProps.txt "$haskell_dir/data/DerivedNormalizationProps.txt"
  copy_file data/confusables.txt "$haskell_dir/data/confusables.txt"
  copy_file data/KnownAttackTargets.txt "$haskell_dir/data/KnownAttackTargets.txt"
  write_manifest "$haskell_dir/data" "${haskell_files[@]}"
  (
    cd "$haskell_dir"
    scripts/generate-unicode-data.sh
    scripts/generate-composition-exclusions.sh
    scripts/generate-derived-normalization-props.sh
  )
}

check_haskell() {
  check_same_version_keys data/UCD-VERSION "$haskell_dir/data/UCD-VERSION"
  check_same_file data/UnicodeData.txt "$haskell_dir/data/UnicodeData.txt"
  check_same_file data/CompositionExclusions.txt "$haskell_dir/data/CompositionExclusions.txt"
  check_same_file Unicode/Ucd/DerivedNormalizationProps.txt "$haskell_dir/data/DerivedNormalizationProps.txt"
  check_same_file data/confusables.txt "$haskell_dir/data/confusables.txt"
  check_same_file data/KnownAttackTargets.txt "$haskell_dir/data/KnownAttackTargets.txt"
  check_manifest "$haskell_dir/data"
}

sync_go() {
  local file
  for file in "${homoglyph_files[@]}"; do
    copy_file "data/$file" "$go_dir/security/data/$file"
  done
  write_manifest "$go_dir/security/data" "${homoglyph_files[@]}"
}

check_go() {
  local file
  for file in "${homoglyph_files[@]}"; do
    check_same_file "data/$file" "$go_dir/security/data/$file"
  done
  check_manifest "$go_dir/security/data"
}

sync_jvm() {
  local file
  for file in "${homoglyph_files[@]}"; do
    copy_file "data/$file" "$jvm_dir/src/main/resources/com/unicodesecurity/data/$file"
  done
  write_manifest "$jvm_dir/src/main/resources/com/unicodesecurity/data" "${homoglyph_files[@]}"
}

check_jvm() {
  local file
  for file in "${homoglyph_files[@]}"; do
    check_same_file "data/$file" "$jvm_dir/src/main/resources/com/unicodesecurity/data/$file"
  done
  check_manifest "$jvm_dir/src/main/resources/com/unicodesecurity/data"
}

sync_typescript() {
  local file
  for file in "${homoglyph_files[@]}"; do
    copy_file "data/$file" "$typescript_dir/src/data/$file"
  done
  write_manifest "$typescript_dir/src/data" "${homoglyph_files[@]}"
}

check_typescript() {
  local file
  for file in "${homoglyph_files[@]}"; do
    check_same_file "data/$file" "$typescript_dir/src/data/$file"
  done
  check_manifest "$typescript_dir/src/data"
}

sync_dotnet() {
  local file
  for file in "${homoglyph_files[@]}"; do
    copy_file "data/$file" "$dotnet_dir/Data/$file"
  done
  write_manifest "$dotnet_dir/Data" "${homoglyph_files[@]}"
}

check_dotnet() {
  local file
  for file in "${homoglyph_files[@]}"; do
    check_same_file "data/$file" "$dotnet_dir/Data/$file"
  done
  check_manifest "$dotnet_dir/Data"
}

sync_swift() {
  local file
  for file in "${homoglyph_files[@]}"; do
    copy_file "data/$file" "$swift_dir/Sources/UnicodeSecurity/Resources/Data/$file"
  done
  write_manifest "$swift_dir/Sources/UnicodeSecurity/Resources/Data" "${homoglyph_files[@]}"
}

check_swift() {
  local file
  for file in "${homoglyph_files[@]}"; do
    check_same_file "data/$file" "$swift_dir/Sources/UnicodeSecurity/Resources/Data/$file"
  done
  check_manifest "$swift_dir/Sources/UnicodeSecurity/Resources/Data"
}

sync_zig() {
  local file
  for file in "${homoglyph_files[@]}"; do
    copy_file "data/$file" "$zig_dir/src/data/$file"
  done
  write_manifest "$zig_dir/src/data" "${homoglyph_files[@]}"
  (
    cd "$zig_dir"
    python3 tools/generate_confusables_data.py
  )
}

check_zig() {
  local file
  for file in "${homoglyph_files[@]}"; do
    check_same_file "data/$file" "$zig_dir/src/data/$file"
  done
  check_manifest "$zig_dir/src/data"
  (
    cd "$zig_dir"
    python3 tools/generate_confusables_data.py --check
  )
}

if [[ "$mode" == "apply" ]]; then
  write_manifest data "${root_manifest_files[@]}"
  sync_python
  sync_haskell
  sync_go
  sync_jvm
  sync_typescript
  sync_dotnet
  sync_swift
  sync_zig
  scripts/check-runtime-data.sh
  echo "clean: runtime data synchronized from canonical UCD inputs"
else
  check_manifest data
  check_python
  check_haskell
  check_go
  check_jvm
  check_typescript
  check_dotnet
  check_swift
  check_zig
  scripts/check-runtime-data.sh
  echo "clean: runtime data sync check passed"
fi
