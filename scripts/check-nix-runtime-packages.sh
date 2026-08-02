#!/usr/bin/env bash
# Build and smoke-test tracked Nix runtime package outputs without building Lean.

set -euo pipefail

cd "$(dirname "$0")/.."

usage() {
  cat <<'USAGE'
Usage: scripts/check-nix-runtime-packages.sh

Builds and smoke-tests the tracked runtime flake package outputs:
  - .#unicode-security
  - .#unicode-python
  - .#unicode-cpp
  - .#unicode-haskell
  - .#unicode-jvm
  - .#unicode-go
  - .#unicode-typescript
  - .#unicode-dotnet
  - .#unicode-swift
  - .#unicode-zig

This is a tracked-source check. Commit the runtime port files before using it
as release evidence; untracked files are not included in Nix flake source
copies.

Environment:
  NIX_BUILD_FLAGS="..."  Extra flags passed to each nix build invocation.
  PYTHON=python          Python used for import smoke tests.
  CXX=c++                C++ compiler used for installed-header smoke tests.
  JAVAC=javac            Java compiler used for installed-module smoke tests.
  JAVA=java              Java runtime used for installed-module smoke tests.
  GO=go                  Go tool used for installed-module smoke tests.
  NODE=node              Node.js used for installed-module smoke tests.
  DOTNET=dotnet          .NET SDK used for installed-module smoke tests.
  SWIFT=swift            Swift tool used for installed-package smoke tests.
USAGE
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

fail() {
  echo "FATAL: $*" >&2
  exit 1
}

require_tracked() {
  local path="$1"
  git ls-files --error-unmatch "$path" >/dev/null 2>&1 \
    || fail "Nix runtime package smoke requires tracked source path: $path"
}

cleanup_paths=()
cleanup() {
  local path
  for path in "${cleanup_paths[@]}"; do
    rm -rf "$path"
  done
}
trap cleanup EXIT

make_temp_dir() {
  local dir
  dir="$(mktemp -d)"
  cleanup_paths+=("$dir")
  printf '%s\n' "$dir"
}

nix_build_args=(--no-link --print-out-paths)
if [[ -n "${NIX_BUILD_FLAGS:-}" ]]; then
  # shellcheck disable=SC2206
  extra_nix_build_args=(${NIX_BUILD_FLAGS})
  nix_build_args+=("${extra_nix_build_args[@]}")
fi

nix_out() {
  local attr="$1"
  local paths=()
  mapfile -t paths < <(nix build ".#$attr" "${nix_build_args[@]}")
  [[ "${#paths[@]}" -eq 1 ]] || fail "nix build .#$attr returned ${#paths[@]} paths"
  printf '%s\n' "${paths[0]}"
}

require_file() {
  local path="$1"
  [[ -f "$path" ]] || fail "missing file: $path"
}

require_real_file() {
  local path="$1"
  [[ -f "$path" && ! -L "$path" ]] || fail "missing real file: $path"
}

require_dir() {
  local path="$1"
  [[ -d "$path" ]] || fail "missing directory: $path"
}

require_tracked ports/rust/Cargo.toml
require_tracked ports/rust/Cargo.lock
require_tracked ports/python/pyproject.toml
require_tracked ports/cpp/CMakeLists.txt
require_tracked ports/cpp/include/unicode_cpp/utf8.hpp
require_tracked ports/cpp/include/unicode_cpp/security/policy.hpp
require_tracked ports/cpp/include/unicode_cpp/security/covert/variation_selector_pairs.hpp
require_tracked ports/haskell/unicode-haskell.cabal
require_tracked ports/haskell/testdata/fixtures/security/policy_contract.json
require_tracked ports/haskell/testdata/fixtures/security/detectors/homoglyph_confusable.json
require_tracked ports/haskell/testdata/fixtures/security/detectors/mixed_script_admissibility.json
require_tracked ports/jvm/scripts/test.sh
require_tracked ports/jvm/src/main/java/com/unicodesecurity/Security.java
require_tracked ports/jvm/src/main/resources/com/unicodesecurity/data/SHA256SUMS
require_tracked ports/jvm/src/main/resources/com/unicodesecurity/data/confusables.txt
require_tracked ports/jvm/src/main/resources/com/unicodesecurity/data/KnownAttackTargets.txt
require_tracked ports/jvm/src/test/java/com/unicodesecurity/SecurityContractTest.java
require_tracked ports/jvm/testdata/fixtures/security/policy_contract.json
require_tracked ports/go/go.mod
require_tracked ports/go/security/policy.go
require_tracked ports/go/security/data/SHA256SUMS
require_tracked ports/go/security/data/confusables.txt
require_tracked ports/go/security/data/KnownAttackTargets.txt
require_tracked ports/go/security/testdata/fixtures/security/policy_contract.json
require_tracked ports/typescript/package.json
require_tracked ports/typescript/src/security-core.js
require_tracked ports/typescript/src/security.js
require_tracked ports/typescript/src/edge.js
require_tracked ports/typescript/src/data/SHA256SUMS
require_tracked ports/typescript/src/data/confusables.txt
require_tracked ports/typescript/src/data/KnownAttackTargets.txt
require_tracked ports/typescript/test/security.test.js
require_tracked ports/typescript/testdata/fixtures/security/policy_contract.json
require_tracked ports/dotnet/src/UnicodeSecurity/UnicodeSecurity.csproj
require_tracked ports/dotnet/src/UnicodeSecurity/Security.cs
require_tracked ports/dotnet/Data/SHA256SUMS
require_tracked ports/dotnet/Data/confusables.txt
require_tracked ports/dotnet/Data/KnownAttackTargets.txt
require_tracked ports/dotnet/test/UnicodeSecurity.Tests/UnicodeSecurity.Tests.csproj
require_tracked ports/dotnet/test/UnicodeSecurity.Tests/Program.cs
require_tracked ports/dotnet/testdata/fixtures/security/policy_contract.json
require_tracked ports/swift/Package.swift
require_tracked ports/swift/scripts/test.sh
require_tracked ports/swift/Sources/UnicodeSecurity/UnicodeSecurity.swift
require_tracked ports/swift/Sources/UnicodeSecurity/Resources/Data/SHA256SUMS
require_tracked ports/swift/Sources/UnicodeSecurity/Resources/Data/confusables.txt
require_tracked ports/swift/Sources/UnicodeSecurity/Resources/Data/KnownAttackTargets.txt
require_tracked ports/swift/ContractTests/SecurityContractTests.swift
require_tracked ports/swift/ContractTests/Resources/fixtures/security/policy_contract.json
require_tracked ports/zig/build.zig
require_tracked scripts/cold-start-runtime.sh

echo "== nix package: unicode-security =="
security_out="$(nix_out unicode-security)"
security_bin="$security_out/bin/unicode-security"
require_file "$security_bin"
"$security_bin" --version >/dev/null
security_smoke="$(printf 'Hello' | "$security_bin" scan --profile gateway-header --mode enforce --json)"
expected_security_smoke='{"action":"allow","profile":"gateway-header","mode":"enforce","input":[72,101,108,108,111],"findings":[],"normalized":null}'
[[ "$security_smoke" == "$expected_security_smoke" ]] \
  || fail "unicode-security Nix package smoke scan mismatch"

echo "== nix package: unicode-python =="
python_out="$(nix_out unicode-python)"
mapfile -t python_site_dirs < <(find "$python_out" -type d -name site-packages | sort)
[[ "${#python_site_dirs[@]}" -gt 0 ]] \
  || fail "unicode-python Nix package has no site-packages directory"
python_bin="${PYTHON:-python}"
command -v "$python_bin" >/dev/null 2>&1 || fail "Python not found: $python_bin"
PYTHONPATH="${python_site_dirs[0]}" "$python_bin" - <<'PY'
import unicode_python

assert unicode_python.is_valid_utf8(b"Hello")
assert unicode_python.decode_to_codepoints(b"Hi") == [72, 105]
PY

echo "== nix package: unicode-cpp =="
cpp_out="$(nix_out unicode-cpp)"
require_file "$cpp_out/include/unicode_cpp/utf8.hpp"
require_file "$cpp_out/include/unicode_cpp/security/policy.hpp"
require_real_file "$cpp_out/share/unicode_cpp/data/confusables.txt"
require_real_file "$cpp_out/share/unicode_cpp/data/CaseFolding.txt"
require_real_file "$cpp_out/share/unicode_cpp/data/CompositionExclusions.txt"
require_real_file "$cpp_out/share/unicode_cpp/data/DerivedCoreProperties.txt"
require_real_file "$cpp_out/share/unicode_cpp/data/KnownAttackTargets.txt"
require_real_file "$cpp_out/share/unicode_cpp/data/IdentifierStatus.txt"
require_real_file "$cpp_out/share/unicode_cpp/data/PropertyValueAliases.txt"
require_real_file "$cpp_out/share/unicode_cpp/data/ScriptExtensions.txt"
require_real_file "$cpp_out/share/unicode_cpp/data/Scripts.txt"
require_real_file "$cpp_out/share/unicode_cpp/data/UnicodeData.txt"
cpp_tmp="$(make_temp_dir)"
cat > "$cpp_tmp/nix_cpp_smoke.cpp" <<'CPP'
#include <cstdint>
#include <span>
#include <vector>

#include "unicode_cpp/security/policy.hpp"
#include "unicode_cpp/utf8.hpp"

int main() {
  using unicode_cpp::security::policy::Action;
  using unicode_cpp::security::policy::Mode;
  using unicode_cpp::security::policy::Profile;

  const std::vector<std::uint8_t> bytes = {'H', 'e', 'l', 'l', 'o'};
  const std::span<const std::uint8_t> input{bytes.data(), bytes.size()};
  if (!unicode_cpp::is_valid_utf8(input)) return 1;
  const auto verdict =
      unicode_cpp::security::policy::scan_utf8(Profile::GatewayHeader,
                                               Mode::Enforce, input);
  return verdict.action == Action::Allow ? 0 : 2;
}
CPP
cxx="${CXX:-c++}"
command -v "$cxx" >/dev/null 2>&1 || fail "C++ compiler not found: $cxx"
"$cxx" -std=c++20 -I "$cpp_out/include" "$cpp_tmp/nix_cpp_smoke.cpp" \
  -o "$cpp_tmp/nix_cpp_smoke"
"$cpp_tmp/nix_cpp_smoke"

echo "== nix package: unicode-haskell =="
haskell_out="$(nix_out unicode-haskell)"
require_dir "$haskell_out"
if [[ ! -d "$haskell_out/lib" && ! -d "$haskell_out/share" ]]; then
  fail "unicode-haskell Nix package has no lib/share output"
fi

echo "== nix package: unicode-jvm =="
jvm_out="$(nix_out unicode-jvm)"
jvm_root="$jvm_out/share/unicode-jvm"
require_file "$jvm_root/src/main/java/com/unicodesecurity/Security.java"
require_file "$jvm_root/src/main/resources/com/unicodesecurity/data/SHA256SUMS"
require_file "$jvm_root/src/main/resources/com/unicodesecurity/data/CaseFolding.txt"
require_file "$jvm_root/src/main/resources/com/unicodesecurity/data/confusables.txt"
require_file "$jvm_root/src/main/resources/com/unicodesecurity/data/KnownAttackTargets.txt"
require_file "$jvm_root/src/main/resources/com/unicodesecurity/data/StandardizedVariants.txt"
require_file "$jvm_root/src/main/resources/com/unicodesecurity/data/emoji-variation-sequences.txt"
require_file "$jvm_root/src/test/java/com/unicodesecurity/SecurityContractTest.java"
require_file "$jvm_root/testdata/fixtures/security/policy_contract.json"
javac_bin="${JAVAC:-javac}"
java_bin="${JAVA:-java}"
command -v "$javac_bin" >/dev/null 2>&1 || fail "javac not found: $javac_bin"
command -v "$java_bin" >/dev/null 2>&1 || fail "java not found: $java_bin"
jvm_tmp="$(make_temp_dir)"
cp -R "$jvm_root" "$jvm_tmp/jvm"
chmod -R u+w "$jvm_tmp/jvm"
(
  cd "$jvm_tmp/jvm"
  PATH="$(dirname "$(command -v "$javac_bin")"):$PATH" \
    JVM_BUILD_DIR="$jvm_tmp/jvm-build" \
    scripts/test.sh
) || fail "unicode-jvm Nix package test smoke failed"

echo "== nix package: unicode-go =="
go_out="$(nix_out unicode-go)"
go_root="$go_out/share/unicode-go"
require_file "$go_root/go.mod"
require_file "$go_root/security/policy.go"
require_file "$go_root/security/data/SHA256SUMS"
require_file "$go_root/security/data/CaseFolding.txt"
require_file "$go_root/security/data/confusables.txt"
require_file "$go_root/security/data/KnownAttackTargets.txt"
require_file "$go_root/security/data/StandardizedVariants.txt"
require_file "$go_root/security/data/emoji-variation-sequences.txt"
require_file "$go_root/security/data/UnicodeData.txt"
require_file "$go_root/security/testdata/fixtures/security/policy_contract.json"
go_bin="${GO:-go}"
command -v "$go_bin" >/dev/null 2>&1 || fail "Go not found: $go_bin"
go_tmp="$(make_temp_dir)"
(
  cd "$go_root"
  export HOME="$go_tmp/home"
  export GOCACHE="$go_tmp/go-build"
  export GOMODCACHE="$go_tmp/go-mod"
  mkdir -p "$HOME" "$GOCACHE" "$GOMODCACHE"
  "$go_bin" test ./...
) || fail "unicode-go Nix package test smoke failed"

echo "== nix package: unicode-typescript =="
typescript_out="$(nix_out unicode-typescript)"
typescript_root="$typescript_out/share/unicode-typescript"
require_file "$typescript_root/package.json"
require_file "$typescript_root/src/security-core.js"
require_file "$typescript_root/src/security.js"
require_file "$typescript_root/src/edge.js"
require_file "$typescript_root/src/security.d.ts"
require_file "$typescript_root/src/edge.d.ts"
require_file "$typescript_root/src/data/SHA256SUMS"
require_file "$typescript_root/src/data/CaseFolding.txt"
require_file "$typescript_root/src/data/confusables.txt"
require_file "$typescript_root/src/data/KnownAttackTargets.txt"
require_file "$typescript_root/src/data/StandardizedVariants.txt"
require_file "$typescript_root/src/data/emoji-variation-sequences.txt"
require_file "$typescript_root/test/security.test.js"
require_file "$typescript_root/testdata/fixtures/security/policy_contract.json"
node_bin="${NODE:-node}"
command -v "$node_bin" >/dev/null 2>&1 || fail "Node.js not found: $node_bin"
(
  cd "$typescript_root"
  "$node_bin" --test test/*.test.js
) || fail "unicode-typescript Nix package test smoke failed"

echo "== nix package: unicode-dotnet =="
dotnet_out="$(nix_out unicode-dotnet)"
dotnet_root="$dotnet_out/share/unicode-dotnet"
require_file "$dotnet_root/src/UnicodeSecurity/UnicodeSecurity.csproj"
require_file "$dotnet_root/src/UnicodeSecurity/Security.cs"
require_file "$dotnet_root/Data/SHA256SUMS"
require_file "$dotnet_root/Data/CaseFolding.txt"
require_file "$dotnet_root/Data/confusables.txt"
require_file "$dotnet_root/Data/KnownAttackTargets.txt"
require_file "$dotnet_root/Data/StandardizedVariants.txt"
require_file "$dotnet_root/Data/emoji-variation-sequences.txt"
require_file "$dotnet_root/test/UnicodeSecurity.Tests/UnicodeSecurity.Tests.csproj"
require_file "$dotnet_root/test/UnicodeSecurity.Tests/Program.cs"
require_file "$dotnet_root/testdata/fixtures/security/policy_contract.json"
mapfile -t dotnet_generated_dirs < <(
  find "$dotnet_root" -type d \( -name bin -o -name obj \) | sort
)
[[ "${#dotnet_generated_dirs[@]}" -eq 0 ]] \
  || fail "unicode-dotnet Nix package contains generated build directories: ${dotnet_generated_dirs[*]}"
dotnet_bin="${DOTNET:-dotnet}"
command -v "$dotnet_bin" >/dev/null 2>&1 || fail ".NET SDK not found: $dotnet_bin"
dotnet_tmp="$(make_temp_dir)"
cp -R "$dotnet_root" "$dotnet_tmp/dotnet"
chmod -R u+w "$dotnet_tmp/dotnet"
(
  cd "$dotnet_tmp/dotnet"
  export DOTNET_CLI_HOME="$dotnet_tmp/dotnet-home"
  export DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1
  export DOTNET_NOLOGO=1
  mkdir -p "$DOTNET_CLI_HOME"
  "$dotnet_bin" run --project test/UnicodeSecurity.Tests/UnicodeSecurity.Tests.csproj
) || fail "unicode-dotnet Nix package test smoke failed"

echo "== nix package: unicode-swift =="
swift_out="$(nix_out unicode-swift)"
swift_root="$swift_out/share/unicode-swift"
require_file "$swift_root/Package.swift"
require_file "$swift_root/scripts/test.sh"
require_file "$swift_root/Sources/UnicodeSecurity/UnicodeSecurity.swift"
require_file "$swift_root/Sources/UnicodeSecurity/Resources/Data/SHA256SUMS"
require_file "$swift_root/Sources/UnicodeSecurity/Resources/Data/CaseFolding.txt"
require_file "$swift_root/Sources/UnicodeSecurity/Resources/Data/confusables.txt"
require_file "$swift_root/Sources/UnicodeSecurity/Resources/Data/KnownAttackTargets.txt"
require_file "$swift_root/Sources/UnicodeSecurity/Resources/Data/StandardizedVariants.txt"
require_file "$swift_root/Sources/UnicodeSecurity/Resources/Data/emoji-variation-sequences.txt"
require_file "$swift_root/ContractTests/SecurityContractTests.swift"
require_file "$swift_root/ContractTests/Resources/fixtures/security/policy_contract.json"
mapfile -t swift_generated_dirs < <(
  find "$swift_root" -type d -name .build | sort
)
[[ "${#swift_generated_dirs[@]}" -eq 0 ]] \
  || fail "unicode-swift Nix package contains generated build directories: ${swift_generated_dirs[*]}"
# Building `.#unicode-swift` above (nix_out) runs the package's contract tests in
# its checkPhase under the pinned swift 5.10.1, sandboxed and reproducible — that
# is the hermetic validation. Re-running scripts/test.sh here would invoke swiftpm
# in the ambient shell, whose unwired swift cannot parse target info; so this
# stage asserts the built package's output surface (the require_file checks above)
# and relies on the derivation's own checkPhase for the swiftpm build and tests.

echo "== nix package: unicode-zig =="
zig_out="$(nix_out unicode-zig)"
mapfile -t zig_artifacts < <(
  find "$zig_out" -type f \
    \( -name 'libunicode_security*' -o -name 'unicode_security*' \) \
    | sort
)
[[ "${#zig_artifacts[@]}" -gt 0 ]] \
  || fail "unicode-zig Nix package has no unicode_security artifact"
require_file "$zig_out/share/unicode-zig/src/security.zig"
require_file "$zig_out/share/unicode-zig/src/case_folding_data.zig"
require_file "$zig_out/share/unicode-zig/src/confusables_data.zig"
require_file "$zig_out/share/unicode-zig/src/normalization_data.zig"
require_file "$zig_out/share/unicode-zig/src/data/CaseFolding.txt"
require_file "$zig_out/share/unicode-zig/src/data/confusables.txt"
require_file "$zig_out/share/unicode-zig/src/data/KnownAttackTargets.txt"
require_file "$zig_out/share/unicode-zig/src/data/StandardizedVariants.txt"
require_file "$zig_out/share/unicode-zig/src/data/emoji-variation-sequences.txt"
require_file "$zig_out/share/unicode-zig/src/data/UnicodeData.txt"
require_file "$zig_out/share/unicode-zig/testdata/fixtures/security/policy_contract.json"
require_file "$zig_out/share/unicode-zig/testdata/fixtures/security/detectors/homoglyph_confusable.json"
require_file "$zig_out/share/unicode-zig/testdata/fixtures/security/detectors/mixed_script_admissibility.json"

echo "clean: Nix runtime package smoke checks pass"
