#!/usr/bin/env bash
# Guard that runtime ports are self-contained deployment surfaces.

set -euo pipefail

cd "$(dirname "$0")/.."

fail() {
  echo "FATAL: $*" >&2
  exit 1
}

require_file() {
  local path="$1"
  [[ -f "$path" ]] || fail "missing file: $path"
}

reject_runtime_pattern() {
  local label="$1"
  local pattern="$2"
  shift 2
  local hits
  hits="$(grep -RInE -- "$pattern" "$@" || true)"
  if [[ -n "$hits" ]]; then
    echo "FATAL: $label violates self-contained runtime contract" >&2
    echo "$hits" >&2
    exit 1
  fi
}

echo "== rust crate =="
require_file Cargo.toml
require_file Cargo.lock
require_file data/confusables.txt
require_file data/KnownAttackTargets.txt
require_file data/StandardizedVariants.txt
require_file data/emoji-variation-sequences.txt

echo "== python package =="
require_file pyproject.toml
require_file src/unicode_python/data/confusables.txt
require_file src/unicode_python/data/KnownAttackTargets.txt
require_file src/unicode_python/data/StandardizedVariants.txt
require_file src/unicode_python/data/emoji-variation-sequences.txt
reject_runtime_pattern \
  "python package" \
  '(fixtures/security|/fixtures|ports/|Unicode/|"\.\./|'\''\.\./)' \
  src/unicode_python/*.py \
  src/unicode_python/security

echo "== cpp header package =="
require_file CMakeLists.txt
require_file include/unicode_cpp/security/covert/variation_selector_pairs.hpp
grep -Fq 'file(REAL_PATH' CMakeLists.txt \
  || fail "C++ package does not resolve runtime data symlinks before install"
# shellcheck disable=SC2016
grep -Fq 'DESTINATION ${CMAKE_INSTALL_DATADIR}/unicode_cpp/data' CMakeLists.txt \
  || fail "C++ package does not install its runtime data files"
reject_runtime_pattern \
  "cpp installed headers" \
  '("\.\./|data/StandardizedVariants|data/emoji-variation-sequences|fixtures/security)' \
  include/unicode_cpp

echo "== haskell package =="
require_file ports/haskell/unicode-haskell.cabal
require_file ports/haskell/data/confusables.txt
require_file ports/haskell/data/KnownAttackTargets.txt
require_file ports/haskell/data/StandardizedVariants.txt
require_file ports/haskell/data/emoji-variation-sequences.txt
require_file ports/haskell/data/SHA256SUMS
require_file ports/haskell/testdata/fixtures/security/policy_contract.json
require_file ports/haskell/testdata/fixtures/security/detectors/homoglyph_confusable.json
require_file ports/haskell/testdata/fixtures/security/detectors/mixed_script_admissibility.json
grep -Fqx '  data/confusables.txt' ports/haskell/unicode-haskell.cabal \
  || fail "Haskell cabal data-files missing data/confusables.txt"
grep -Fqx '  data/KnownAttackTargets.txt' ports/haskell/unicode-haskell.cabal \
  || fail "Haskell cabal data-files missing data/KnownAttackTargets.txt"
grep -Fqx '  data/StandardizedVariants.txt' ports/haskell/unicode-haskell.cabal \
  || fail "Haskell cabal data-files missing data/StandardizedVariants.txt"
grep -Fqx '  data/emoji-variation-sequences.txt' ports/haskell/unicode-haskell.cabal \
  || fail "Haskell cabal data-files missing data/emoji-variation-sequences.txt"
grep -Fqx '  data/SHA256SUMS' ports/haskell/unicode-haskell.cabal \
  || fail "Haskell cabal extra-source-files missing data/SHA256SUMS"
grep -Fqx '  testdata/fixtures/security/*.json' ports/haskell/unicode-haskell.cabal \
  || fail "Haskell cabal extra-source-files missing testdata/fixtures/security/*.json"
grep -Fqx '  testdata/fixtures/security/detectors/*.json' ports/haskell/unicode-haskell.cabal \
  || fail "Haskell cabal extra-source-files missing testdata/fixtures/security/detectors/*.json"
reject_runtime_pattern \
  "haskell library" \
  '(\.\./\.\./|fixtures/security|ports/)' \
  ports/haskell/src

echo "== jvm package =="
require_file ports/jvm/README.md
require_file ports/jvm/scripts/test.sh
require_file ports/jvm/src/main/java/com/unicodesecurity/Security.java
require_file ports/jvm/src/main/resources/com/unicodesecurity/data/confusables.txt
require_file ports/jvm/src/main/resources/com/unicodesecurity/data/KnownAttackTargets.txt
require_file ports/jvm/src/main/resources/com/unicodesecurity/data/StandardizedVariants.txt
require_file ports/jvm/src/main/resources/com/unicodesecurity/data/emoji-variation-sequences.txt
require_file ports/jvm/src/main/resources/com/unicodesecurity/data/SHA256SUMS
require_file ports/jvm/testdata/fixtures/security/policy_contract.json
require_file ports/jvm/testdata/fixtures/security/detectors/homoglyph_confusable.json
require_file ports/jvm/testdata/fixtures/security/detectors/mixed_script_admissibility.json
reject_runtime_pattern \
  "jvm runtime package" \
  '(\.\./\.\./|fixtures/security|ports/|Unicode/|FileReader|Files\.read|Paths\.get)' \
  ports/jvm/src/main/java

echo "== go module =="
require_file ports/go/go.mod
require_file ports/go/security/data/confusables.txt
require_file ports/go/security/data/KnownAttackTargets.txt
require_file ports/go/security/data/StandardizedVariants.txt
require_file ports/go/security/data/emoji-variation-sequences.txt
require_file ports/go/security/data/SHA256SUMS
require_file ports/go/security/testdata/fixtures/security/policy_contract.json
require_file ports/go/security/testdata/fixtures/security/detectors/homoglyph_confusable.json
require_file ports/go/security/testdata/fixtures/security/detectors/mixed_script_admissibility.json
grep -Fq '//go:embed data/confusables.txt' ports/go/security/homoglyph.go \
  || fail "Go homoglyph data is not embedded"
grep -Fq '//go:embed data/KnownAttackTargets.txt' ports/go/security/homoglyph.go \
  || fail "Go target data is not embedded"
grep -Fq '//go:embed data/StandardizedVariants.txt' ports/go/security/homoglyph.go \
  || fail "Go standardized variation data is not embedded"
grep -Fq '//go:embed data/emoji-variation-sequences.txt' ports/go/security/homoglyph.go \
  || fail "Go emoji variation data is not embedded"
reject_runtime_pattern \
  "go runtime package" \
  '(\.\./|fixtures/security|os\.ReadFile|ioutil\.ReadFile)' \
  ports/go/security/homoglyph.go \
  ports/go/security/json.go \
  ports/go/security/multiencoding_policy.go \
  ports/go/security/policy.go \
  ports/go/security/utf8_policy.go

echo "== typescript package =="
require_file ports/typescript/package.json
require_file ports/typescript/src/security-core.js
require_file ports/typescript/src/security.js
require_file ports/typescript/src/edge.js
require_file ports/typescript/src/security.d.ts
require_file ports/typescript/src/edge.d.ts
require_file ports/typescript/src/data/confusables.txt
require_file ports/typescript/src/data/KnownAttackTargets.txt
require_file ports/typescript/src/data/StandardizedVariants.txt
require_file ports/typescript/src/data/emoji-variation-sequences.txt
require_file ports/typescript/src/data/SHA256SUMS
require_file ports/typescript/testdata/fixtures/security/policy_contract.json
require_file ports/typescript/testdata/fixtures/security/detectors/homoglyph_confusable.json
require_file ports/typescript/testdata/fixtures/security/detectors/mixed_script_admissibility.json
reject_runtime_pattern \
  "typescript runtime package" \
  '(\.\./\.\./|fixtures/security|ports/|Unicode/)' \
  ports/typescript/src/*.js
reject_runtime_pattern \
  "typescript edge package" \
  'node:' \
  ports/typescript/src/security-core.js \
  ports/typescript/src/edge.js \
  ports/typescript/src/wasm.js

echo "== dotnet package =="
require_file ports/dotnet/README.md
require_file ports/dotnet/src/UnicodeSecurity/UnicodeSecurity.csproj
require_file ports/dotnet/src/UnicodeSecurity/Security.cs
require_file ports/dotnet/Data/confusables.txt
require_file ports/dotnet/Data/KnownAttackTargets.txt
require_file ports/dotnet/Data/StandardizedVariants.txt
require_file ports/dotnet/Data/emoji-variation-sequences.txt
require_file ports/dotnet/Data/SHA256SUMS
require_file ports/dotnet/testdata/fixtures/security/policy_contract.json
require_file ports/dotnet/testdata/fixtures/security/detectors/homoglyph_confusable.json
require_file ports/dotnet/testdata/fixtures/security/detectors/mixed_script_admissibility.json
grep -Fq '<None Include="../../Data/*.txt"' ports/dotnet/src/UnicodeSecurity/UnicodeSecurity.csproj \
  || fail ".NET project does not include vendored package data"
reject_runtime_pattern \
  "dotnet runtime package" \
  '(\.\./\.\./|fixtures/security|ports/|Unicode/)' \
  ports/dotnet/src/UnicodeSecurity/Security.cs

echo "== swift package =="
require_file ports/swift/README.md
require_file ports/swift/Package.swift
require_file ports/swift/scripts/test.sh
require_file ports/swift/Sources/UnicodeSecurity/UnicodeSecurity.swift
require_file ports/swift/Sources/UnicodeSecurity/Resources/Data/confusables.txt
require_file ports/swift/Sources/UnicodeSecurity/Resources/Data/KnownAttackTargets.txt
require_file ports/swift/Sources/UnicodeSecurity/Resources/Data/StandardizedVariants.txt
require_file ports/swift/Sources/UnicodeSecurity/Resources/Data/emoji-variation-sequences.txt
require_file ports/swift/Sources/UnicodeSecurity/Resources/Data/SHA256SUMS
require_file ports/swift/ContractTests/Resources/fixtures/security/policy_contract.json
require_file ports/swift/ContractTests/Resources/fixtures/security/detectors/homoglyph_confusable.json
require_file ports/swift/ContractTests/Resources/fixtures/security/detectors/mixed_script_admissibility.json
reject_runtime_pattern \
  "swift runtime package" \
  '(\.\./\.\./|fixtures/security|ports/|Unicode/|FileManager\.default\.currentDirectoryPath)' \
  ports/swift/Sources/UnicodeSecurity/UnicodeSecurity.swift

echo "== zig package =="
require_file ports/zig/build.zig
require_file ports/zig/src/confusables_data.zig
require_file ports/zig/src/data/confusables.txt
require_file ports/zig/src/data/KnownAttackTargets.txt
require_file ports/zig/src/data/StandardizedVariants.txt
require_file ports/zig/src/data/emoji-variation-sequences.txt
require_file ports/zig/src/data/SHA256SUMS
require_file ports/zig/testdata/fixtures/security/policy_contract.json
require_file ports/zig/testdata/fixtures/security/detectors/homoglyph_confusable.json
require_file ports/zig/testdata/fixtures/security/detectors/mixed_script_admissibility.json
grep -Fq '@embedFile("data/KnownAttackTargets.txt")' ports/zig/src/security.zig \
  || fail "Zig known-target data is not embedded"
grep -Fq '@embedFile("data/StandardizedVariants.txt")' ports/zig/src/security.zig \
  || fail "Zig standardized variation data is not embedded"
grep -Fq '@embedFile("data/emoji-variation-sequences.txt")' ports/zig/src/security.zig \
  || fail "Zig emoji variation data is not embedded"
reject_runtime_pattern \
  "zig runtime source" \
  '(\.\./|fixtures/security|std\.fs|readFile)' \
  ports/zig/src/*.zig
reject_runtime_pattern \
  "zig build/test package" \
  '\.\./\.\./fixtures/security' \
  ports/zig/build.zig

echo "clean: runtime ports are self-contained"
