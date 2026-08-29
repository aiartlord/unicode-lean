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
rust_dir="${UNICODE_RUST_DIR:-ports/rust}"
cpp_dir="${UNICODE_CPP_DIR:-ports/cpp}"
python_data_dir="${UNICODE_PYTHON_DATA_DIR:-ports/python/src/unicode_python/data}"
jvm_dir="${UNICODE_JVM_DIR:-ports/jvm}"
go_dir="${UNICODE_GO_DIR:-ports/go}"
typescript_dir="${UNICODE_TYPESCRIPT_DIR:-ports/typescript}"
dotnet_dir="${UNICODE_DOTNET_DIR:-ports/dotnet}"
swift_dir="${UNICODE_SWIFT_DIR:-ports/swift}"
zig_dir="${UNICODE_ZIG_DIR:-ports/zig}"
ruby_dir="${UNICODE_RUBY_DIR:-ports/ruby}"
lua_dir="${UNICODE_LUA_DIR:-ports/lua}"
php_dir="${UNICODE_PHP_DIR:-ports/php}"
elixir_dir="${UNICODE_ELIXIR_DIR:-ports/elixir}"
erlang_dir="${UNICODE_ERLANG_DIR:-ports/erlang}"
cobol_dir="${UNICODE_COBOL_DIR:-ports/cobol}"

root_manifest_files=(
  CaseFolding.txt
  CompositionExclusions.txt
  confusables.txt
  DerivedBidiClass.txt
  DerivedCoreProperties.txt
  DerivedJoiningType.txt
  EastAsianWidth.txt
  emoji-variation-sequences.txt
  emoji-data.txt
  emoji-zwj-sequences.txt
  IdentifierStatus.txt
  KnownAttackTargets.txt
  PropertyValueAliases.txt
  ScriptExtensions.txt
  Scripts.txt
  SpecialCasing.txt
  StandardizedVariants.txt
  UnicodeData.txt
  bip39/chinese_simplified.txt
  bip39/chinese_traditional.txt
  bip39/czech.txt
  bip39/english.txt
  bip39/french.txt
  bip39/italian.txt
  bip39/japanese.txt
  bip39/korean.txt
  bip39/portuguese.txt
  bip39/spanish.txt
  UCD-VERSION
)

python_files=(
  CaseFolding.txt
  CompositionExclusions.txt
  DerivedBidiClass.txt
  DerivedCoreProperties.txt
  EastAsianWidth.txt
  IdentifierStatus.txt
  KnownAttackTargets.txt
  PropertyValueAliases.txt
  ScriptExtensions.txt
  Scripts.txt
  SpecialCasing.txt
  StandardizedVariants.txt
  UnicodeData.txt
  confusables.txt
  emoji-variation-sequences.txt
  emoji-data.txt
  emoji-zwj-sequences.txt
  bip39/chinese_simplified.txt
  bip39/chinese_traditional.txt
  bip39/czech.txt
  bip39/english.txt
  bip39/french.txt
  bip39/italian.txt
  bip39/japanese.txt
  bip39/korean.txt
  bip39/portuguese.txt
  bip39/spanish.txt
)

# The Rust crate compile-time include_str!s the full canonical set.
rust_files=(
  CaseFolding.txt
  CompositionExclusions.txt
  DerivedBidiClass.txt
  DerivedCoreProperties.txt
  DerivedJoiningType.txt
  EastAsianWidth.txt
  IdentifierStatus.txt
  KnownAttackTargets.txt
  PropertyValueAliases.txt
  ScriptExtensions.txt
  Scripts.txt
  SpecialCasing.txt
  StandardizedVariants.txt
  UnicodeData.txt
  confusables.txt
  emoji-variation-sequences.txt
  emoji-data.txt
  emoji-zwj-sequences.txt
  bip39/chinese_simplified.txt
  bip39/chinese_traditional.txt
  bip39/czech.txt
  bip39/english.txt
  bip39/french.txt
  bip39/italian.txt
  bip39/japanese.txt
  bip39/korean.txt
  bip39/portuguese.txt
  bip39/spanish.txt
)

# The C++ header package loads exactly these ten via ucd::Tables::load_from_dir
# and Database::load_from_dir (the CMake install foreach mirrors this set).
cpp_files=(
  CaseFolding.txt
  CompositionExclusions.txt
  DerivedBidiClass.txt
  DerivedCoreProperties.txt
  IdentifierStatus.txt
  KnownAttackTargets.txt
  PropertyValueAliases.txt
  ScriptExtensions.txt
  Scripts.txt
  SpecialCasing.txt
  UnicodeData.txt
  confusables.txt
  emoji-data.txt
  emoji-zwj-sequences.txt
  bip39/chinese_simplified.txt
  bip39/chinese_traditional.txt
  bip39/czech.txt
  bip39/english.txt
  bip39/french.txt
  bip39/italian.txt
  bip39/japanese.txt
  bip39/korean.txt
  bip39/portuguese.txt
  bip39/spanish.txt
)

haskell_files=(
  EastAsianWidth.txt
  CaseFolding.txt
  UnicodeData.txt
  DerivedBidiClass.txt
  CompositionExclusions.txt
  DerivedNormalizationProps.txt
  DerivedCoreProperties.txt
  IdentifierStatus.txt
  SpecialCasing.txt
  confusables.txt
  KnownAttackTargets.txt
  StandardizedVariants.txt
  emoji-variation-sequences.txt
  emoji-data.txt
  emoji-zwj-sequences.txt
  bip39/chinese_simplified.txt
  bip39/chinese_traditional.txt
  bip39/czech.txt
  bip39/english.txt
  bip39/french.txt
  bip39/italian.txt
  bip39/japanese.txt
  bip39/korean.txt
  bip39/portuguese.txt
  bip39/spanish.txt
)

# Casing/bip39 tables the Haskell port loads at runtime, all sourced from
# the canonical data/ tree (copied by a loop rather than named individually).
haskell_data_dir_files=(
  DerivedCoreProperties.txt
  SpecialCasing.txt
  bip39/chinese_simplified.txt
  bip39/chinese_traditional.txt
  bip39/czech.txt
  bip39/english.txt
  bip39/french.txt
  bip39/italian.txt
  bip39/japanese.txt
  bip39/korean.txt
  bip39/portuguese.txt
  bip39/spanish.txt
)

homoglyph_files=(
  CaseFolding.txt
  confusables.txt
  KnownAttackTargets.txt
  StandardizedVariants.txt
  emoji-variation-sequences.txt
  emoji-data.txt
  emoji-zwj-sequences.txt
)

go_files=(
  "${homoglyph_files[@]}"
  EastAsianWidth.txt
  IdentifierStatus.txt
  UnicodeData.txt
  DerivedBidiClass.txt
  CompositionExclusions.txt
  DerivedCoreProperties.txt
  SpecialCasing.txt
  bip39/chinese_simplified.txt
  bip39/chinese_traditional.txt
  bip39/czech.txt
  bip39/english.txt
  bip39/french.txt
  bip39/italian.txt
  bip39/japanese.txt
  bip39/korean.txt
  bip39/portuguese.txt
  bip39/spanish.txt
)

zig_files=(
  "${homoglyph_files[@]}"
  IdentifierStatus.txt
  UnicodeData.txt
  DerivedBidiClass.txt
  CompositionExclusions.txt
  DerivedCoreProperties.txt
  SpecialCasing.txt
  bip39/chinese_simplified.txt
  bip39/chinese_traditional.txt
  bip39/czech.txt
  bip39/english.txt
  bip39/french.txt
  bip39/italian.txt
  bip39/japanese.txt
  bip39/korean.txt
  bip39/portuguese.txt
  bip39/spanish.txt
)

# The remaining runtime ports read Bidi_Class from DerivedBidiClass.txt
# (the same pinned table Lean reads: explicit ranges, then @missing
# defaults, then the L fallback), so each bundles the homoglyph set plus
# DerivedBidiClass.txt.
typescript_files=(
  EastAsianWidth.txt
  "${homoglyph_files[@]}"
  IdentifierStatus.txt
  DerivedBidiClass.txt
  UnicodeData.txt
  CompositionExclusions.txt
  DerivedCoreProperties.txt
  SpecialCasing.txt
  bip39/chinese_simplified.txt
  bip39/chinese_traditional.txt
  bip39/czech.txt
  bip39/english.txt
  bip39/french.txt
  bip39/italian.txt
  bip39/japanese.txt
  bip39/korean.txt
  bip39/portuguese.txt
  bip39/spanish.txt
)

jvm_files=(
  EastAsianWidth.txt
  "${homoglyph_files[@]}"
  IdentifierStatus.txt
  DerivedBidiClass.txt
  UnicodeData.txt
  CompositionExclusions.txt
  DerivedCoreProperties.txt
  SpecialCasing.txt
  bip39/chinese_simplified.txt
  bip39/chinese_traditional.txt
  bip39/czech.txt
  bip39/english.txt
  bip39/french.txt
  bip39/italian.txt
  bip39/japanese.txt
  bip39/korean.txt
  bip39/portuguese.txt
  bip39/spanish.txt
)

dotnet_files=(
  "${homoglyph_files[@]}"
  IdentifierStatus.txt
  DerivedBidiClass.txt
  UnicodeData.txt
  CompositionExclusions.txt
  DerivedCoreProperties.txt
  SpecialCasing.txt
  bip39/chinese_simplified.txt
  bip39/chinese_traditional.txt
  bip39/czech.txt
  bip39/english.txt
  bip39/french.txt
  bip39/italian.txt
  bip39/japanese.txt
  bip39/korean.txt
  bip39/portuguese.txt
  bip39/spanish.txt
)

swift_files=(
  "${homoglyph_files[@]}"
  IdentifierStatus.txt
  DerivedBidiClass.txt
  UnicodeData.txt
  CompositionExclusions.txt
  DerivedCoreProperties.txt
  SpecialCasing.txt
  bip39/chinese_simplified.txt
  bip39/chinese_traditional.txt
  bip39/czech.txt
  bip39/english.txt
  bip39/french.txt
  bip39/italian.txt
  bip39/japanese.txt
  bip39/korean.txt
  bip39/portuguese.txt
  bip39/spanish.txt
)

ruby_files=(
  CaseFolding.txt
  CompositionExclusions.txt
  DerivedBidiClass.txt
  DerivedCoreProperties.txt
  EastAsianWidth.txt
  IdentifierStatus.txt
  KnownAttackTargets.txt
  PropertyValueAliases.txt
  ScriptExtensions.txt
  Scripts.txt
  SpecialCasing.txt
  StandardizedVariants.txt
  UnicodeData.txt
  confusables.txt
  emoji-variation-sequences.txt
  emoji-data.txt
  emoji-zwj-sequences.txt
  bip39/chinese_simplified.txt
  bip39/chinese_traditional.txt
  bip39/czech.txt
  bip39/english.txt
  bip39/french.txt
  bip39/italian.txt
  bip39/japanese.txt
  bip39/korean.txt
  bip39/portuguese.txt
  bip39/spanish.txt
)

lua_files=(
  EastAsianWidth.txt
  "${ruby_files[@]}"
)

php_files=(
  EastAsianWidth.txt
  "${ruby_files[@]}"
)

elixir_files=(
  EastAsianWidth.txt
  "${ruby_files[@]}"
)

erlang_files=(
  EastAsianWidth.txt
  "${ruby_files[@]}"
)

cobol_files=(
  "${root_manifest_files[@]}"
  GraphemeBreakProperty.txt
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
  UNICODE_RUBY_DIR=PATH
  UNICODE_LUA_DIR=PATH
  UNICODE_PHP_DIR=PATH
  UNICODE_ELIXIR_DIR=PATH
  UNICODE_ERLANG_DIR=PATH
  UNICODE_COBOL_DIR=PATH

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

sync_rust() {
  local file
  for file in "${rust_files[@]}"; do
    copy_file "data/$file" "$rust_dir/data/$file"
  done
  write_manifest "$rust_dir/data" "${rust_files[@]}"
}

check_rust() {
  local file
  for file in "${rust_files[@]}"; do
    check_same_file "data/$file" "$rust_dir/data/$file"
  done
  check_manifest "$rust_dir/data"
}

sync_cpp() {
  local file
  for file in "${cpp_files[@]}"; do
    copy_file "data/$file" "$cpp_dir/data/$file"
  done
  write_manifest "$cpp_dir/data" "${cpp_files[@]}"
}

check_cpp() {
  local file
  for file in "${cpp_files[@]}"; do
    check_same_file "data/$file" "$cpp_dir/data/$file"
  done
  check_manifest "$cpp_dir/data"
}

sync_haskell() {
  sync_haskell_version
  copy_file data/UnicodeData.txt "$haskell_dir/data/UnicodeData.txt"
  copy_file data/DerivedBidiClass.txt "$haskell_dir/data/DerivedBidiClass.txt"
  copy_file data/CaseFolding.txt "$haskell_dir/data/CaseFolding.txt"
  copy_file data/CompositionExclusions.txt "$haskell_dir/data/CompositionExclusions.txt"
  copy_file Unicode/Ucd/DerivedNormalizationProps.txt "$haskell_dir/data/DerivedNormalizationProps.txt"
  copy_file data/confusables.txt "$haskell_dir/data/confusables.txt"
  copy_file data/KnownAttackTargets.txt "$haskell_dir/data/KnownAttackTargets.txt"
  copy_file data/StandardizedVariants.txt "$haskell_dir/data/StandardizedVariants.txt"
  copy_file data/emoji-variation-sequences.txt "$haskell_dir/data/emoji-variation-sequences.txt"
  copy_file data/emoji-data.txt "$haskell_dir/data/emoji-data.txt"
  copy_file data/emoji-zwj-sequences.txt "$haskell_dir/data/emoji-zwj-sequences.txt"
  local file
  for file in "${haskell_data_dir_files[@]}"; do
    copy_file "data/$file" "$haskell_dir/data/$file"
  done
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
  check_same_file data/DerivedBidiClass.txt "$haskell_dir/data/DerivedBidiClass.txt"
  check_same_file data/CaseFolding.txt "$haskell_dir/data/CaseFolding.txt"
  check_same_file data/CompositionExclusions.txt "$haskell_dir/data/CompositionExclusions.txt"
  check_same_file Unicode/Ucd/DerivedNormalizationProps.txt "$haskell_dir/data/DerivedNormalizationProps.txt"
  check_same_file data/confusables.txt "$haskell_dir/data/confusables.txt"
  check_same_file data/KnownAttackTargets.txt "$haskell_dir/data/KnownAttackTargets.txt"
  check_same_file data/StandardizedVariants.txt "$haskell_dir/data/StandardizedVariants.txt"
  check_same_file data/emoji-variation-sequences.txt "$haskell_dir/data/emoji-variation-sequences.txt"
  check_same_file data/emoji-data.txt "$haskell_dir/data/emoji-data.txt"
  check_same_file data/emoji-zwj-sequences.txt "$haskell_dir/data/emoji-zwj-sequences.txt"
  local file
  for file in "${haskell_data_dir_files[@]}"; do
    check_same_file "data/$file" "$haskell_dir/data/$file"
  done
  check_manifest "$haskell_dir/data"
}

sync_go() {
  local file
  for file in "${go_files[@]}"; do
    copy_file "data/$file" "$go_dir/security/data/$file"
  done
  write_manifest "$go_dir/security/data" "${go_files[@]}"
}

check_go() {
  local file
  for file in "${go_files[@]}"; do
    check_same_file "data/$file" "$go_dir/security/data/$file"
  done
  check_manifest "$go_dir/security/data"
}

sync_jvm() {
  local file
  for file in "${jvm_files[@]}"; do
    copy_file "data/$file" "$jvm_dir/src/main/resources/com/unicodesecurity/data/$file"
  done
  write_manifest "$jvm_dir/src/main/resources/com/unicodesecurity/data" "${jvm_files[@]}"
}

check_jvm() {
  local file
  for file in "${jvm_files[@]}"; do
    check_same_file "data/$file" "$jvm_dir/src/main/resources/com/unicodesecurity/data/$file"
  done
  check_manifest "$jvm_dir/src/main/resources/com/unicodesecurity/data"
}

sync_typescript() {
  local file
  for file in "${typescript_files[@]}"; do
    copy_file "data/$file" "$typescript_dir/src/data/$file"
  done
  write_manifest "$typescript_dir/src/data" "${typescript_files[@]}"
}

check_typescript() {
  local file
  for file in "${typescript_files[@]}"; do
    check_same_file "data/$file" "$typescript_dir/src/data/$file"
  done
  check_manifest "$typescript_dir/src/data"
}

sync_dotnet() {
  local file
  for file in "${dotnet_files[@]}"; do
    copy_file "data/$file" "$dotnet_dir/Data/$file"
  done
  write_manifest "$dotnet_dir/Data" "${dotnet_files[@]}"
}

check_dotnet() {
  local file
  for file in "${dotnet_files[@]}"; do
    check_same_file "data/$file" "$dotnet_dir/Data/$file"
  done
  check_manifest "$dotnet_dir/Data"
}

sync_swift() {
  local file
  for file in "${swift_files[@]}"; do
    copy_file "data/$file" "$swift_dir/Sources/UnicodeSecurity/Resources/Data/$file"
  done
  write_manifest "$swift_dir/Sources/UnicodeSecurity/Resources/Data" "${swift_files[@]}"
}

check_swift() {
  local file
  for file in "${swift_files[@]}"; do
    check_same_file "data/$file" "$swift_dir/Sources/UnicodeSecurity/Resources/Data/$file"
  done
  check_manifest "$swift_dir/Sources/UnicodeSecurity/Resources/Data"
}

sync_zig() {
  local file
  for file in "${zig_files[@]}"; do
    copy_file "data/$file" "$zig_dir/src/data/$file"
  done
  write_manifest "$zig_dir/src/data" "${zig_files[@]}"
  (
    cd "$zig_dir"
    python3 tools/generate_confusables_data.py
  )
}

check_zig() {
  local file
  for file in "${zig_files[@]}"; do
    check_same_file "data/$file" "$zig_dir/src/data/$file"
  done
  check_manifest "$zig_dir/src/data"
  (
    cd "$zig_dir"
    python3 tools/generate_confusables_data.py --check
  )
}

sync_data_dir() {
  local dir="$1"
  shift
  local file
  for file in "$@"; do
    copy_file "data/$file" "$dir/$file"
  done
  write_manifest "$dir" "$@"
}

check_data_dir() {
  local dir="$1"
  shift
  local file
  for file in "$@"; do
    check_same_file "data/$file" "$dir/$file"
  done
  check_manifest "$dir"
}

if [[ "$mode" == "apply" ]]; then
  write_manifest data "${root_manifest_files[@]}"
  sync_python
  sync_rust
  sync_cpp
  sync_haskell
  sync_go
  sync_jvm
  sync_typescript
  sync_dotnet
  sync_swift
  sync_zig
  sync_data_dir "$ruby_dir/data" "${ruby_files[@]}"
  sync_data_dir "$lua_dir/data" "${lua_files[@]}"
  sync_data_dir "$php_dir/data" "${php_files[@]}"
  sync_data_dir "$elixir_dir/priv/data" "${elixir_files[@]}"
  sync_data_dir "$erlang_dir/priv/data" "${erlang_files[@]}"
  sync_data_dir "$cobol_dir/data" "${cobol_files[@]}"
  scripts/check-runtime-data.sh
  echo "clean: runtime data synchronized from canonical UCD inputs"
else
  check_manifest data
  check_python
  check_rust
  check_cpp
  check_haskell
  check_go
  check_jvm
  check_typescript
  check_dotnet
  check_swift
  check_zig
  check_data_dir "$ruby_dir/data" "${ruby_files[@]}"
  check_data_dir "$lua_dir/data" "${lua_files[@]}"
  check_data_dir "$php_dir/data" "${php_files[@]}"
  check_data_dir "$elixir_dir/priv/data" "${elixir_files[@]}"
  check_data_dir "$erlang_dir/priv/data" "${erlang_files[@]}"
  check_data_dir "$cobol_dir/data" "${cobol_files[@]}"
  scripts/check-runtime-data.sh
  echo "clean: runtime data sync check passed"
fi
