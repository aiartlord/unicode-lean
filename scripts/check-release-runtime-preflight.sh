#!/usr/bin/env bash
# Runtime release preflight. This gate is intentionally bounded and never
# invokes Lean assurance or full-conformance builds.

set -euo pipefail

cd "$(dirname "$0")/.."

allow_dirty=0
allow_untracked=0
run_package=1
run_nix_packages=1
dist_dir="${UNICODE_RUNTIME_DIST:-/tmp/unicode-runtime-release-preflight}"

usage() {
  cat <<'USAGE'
Usage: scripts/check-release-runtime-preflight.sh [options]

Default behavior:
  - require a clean git tree
  - require runtime release paths to be tracked by git
  - run source/runtime guards
  - build and verify the runtime package tree
  - smoke packaged gateway/Go/TypeScript/Swift deployment consumers
  - build and smoke tracked Nix runtime package outputs

Options:
  --allow-dirty        Allow modified tracked files.
  --allow-untracked    Allow untracked release paths; skips tracked-source Nix smoke.
  --skip-package       Skip scripts/package-runtime.sh.
  --skip-nix-packages  Skip scripts/check-nix-runtime-packages.sh.
  --dist-dir DIR       Runtime package output directory.
  -h, --help           Show this help.

Environment:
  JOBS=N               Build jobs for package/runtime checks. Defaults to 1 here.
  UNICODE_RUNTIME_DIST Runtime package output directory if --dist-dir is omitted.
USAGE
}

fail() {
  echo "FATAL: $*" >&2
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --allow-dirty)
      allow_dirty=1
      ;;
    --allow-untracked)
      allow_untracked=1
      run_nix_packages=0
      ;;
    --skip-package)
      run_package=0
      ;;
    --skip-nix-packages)
      run_nix_packages=0
      ;;
    --dist-dir)
      [[ $# -ge 2 ]] || fail "--dist-dir requires a value"
      dist_dir="$2"
      shift
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

require_tracked() {
  local path="$1"
  git ls-files --error-unmatch "$path" >/dev/null 2>&1 \
    || fail "release runtime preflight requires tracked source path: $path"
}

required_paths=(
  Cargo.toml
  Cargo.lock
  pyproject.toml
  CMakeLists.txt
  include/unicode_cpp/utf8.hpp
  include/unicode_cpp/security/policy.hpp
  include/unicode_cpp/security/covert/variation_selector_pairs.hpp
  ports/haskell/unicode-haskell.cabal
  ports/haskell/testdata/fixtures/security/policy_contract.json
  ports/haskell/testdata/fixtures/security/detectors/homoglyph_confusable.json
  ports/haskell/testdata/fixtures/security/detectors/mixed_script_admissibility.json
  ports/jvm/scripts/test.sh
  ports/jvm/src/main/java/com/unicodesecurity/Security.java
  ports/jvm/src/main/resources/com/unicodesecurity/data/SHA256SUMS
  ports/jvm/src/main/resources/com/unicodesecurity/data/confusables.txt
  ports/jvm/src/main/resources/com/unicodesecurity/data/KnownAttackTargets.txt
  ports/jvm/src/test/java/com/unicodesecurity/SecurityContractTest.java
  ports/jvm/testdata/fixtures/security/policy_contract.json
  ports/go/go.mod
  ports/go/security/policy.go
  ports/go/security/testdata/fixtures/security/policy_contract.json
  ports/typescript/package.json
  ports/typescript/src/security-core.js
  ports/typescript/src/security.js
  ports/typescript/src/edge.js
  ports/typescript/test/security.test.js
  ports/typescript/testdata/fixtures/security/policy_contract.json
  ports/dotnet/src/UnicodeSecurity/UnicodeSecurity.csproj
  ports/dotnet/src/UnicodeSecurity/Security.cs
  ports/dotnet/Data/SHA256SUMS
  ports/dotnet/Data/confusables.txt
  ports/dotnet/Data/KnownAttackTargets.txt
  ports/dotnet/test/UnicodeSecurity.Tests/UnicodeSecurity.Tests.csproj
  ports/dotnet/test/UnicodeSecurity.Tests/Program.cs
  ports/dotnet/testdata/fixtures/security/policy_contract.json
  ports/swift/Package.swift
  ports/swift/scripts/test.sh
  ports/swift/Sources/UnicodeSecurity/UnicodeSecurity.swift
  ports/swift/Sources/UnicodeSecurity/Resources/Data/SHA256SUMS
  ports/swift/Sources/UnicodeSecurity/Resources/Data/confusables.txt
  ports/swift/Sources/UnicodeSecurity/Resources/Data/KnownAttackTargets.txt
  ports/swift/ContractTests/SecurityContractTests.swift
  ports/swift/ContractTests/Resources/fixtures/security/policy_contract.json
  ports/zig/build.zig
  scripts/cold-start-runtime.sh
  scripts/package-runtime.sh
  scripts/check-runtime-package.sh
  scripts/check-nix-runtime-packages.sh
  scripts/check-port-self-contained.sh
  scripts/check-deployment-smokes.sh
  scripts/check-rust-warning-policy.sh
  scripts/check-runtime-data.sh
)

echo "== git release state =="
if [[ "$allow_dirty" -eq 0 && -n "$(git status --porcelain --untracked-files=no)" ]]; then
  git status --short --untracked-files=no >&2
  fail "tracked files are modified; rerun with --allow-dirty only for local rehearsal"
fi

if [[ "$allow_untracked" -eq 0 ]]; then
  for path in "${required_paths[@]}"; do
    require_tracked "$path"
  done
else
  echo "notice: --allow-untracked set; tracked-source Nix package smoke is disabled"
fi

echo "== source/runtime guards =="
scripts/check-policy-contract.sh
scripts/check-runtime-data.sh
scripts/check-port-self-contained.sh
scripts/check-rust-warning-policy.sh
scripts/audit-launch-cleanup.sh --out /tmp/unicode-launch-cleanup-preflight.txt

if [[ "$run_package" -eq 1 ]]; then
  echo "== runtime package =="
  env JOBS="${JOBS:-1}" UNICODE_RUNTIME_DIST="$dist_dir" scripts/package-runtime.sh

  echo "== deployment smokes =="
  scripts/check-deployment-smokes.sh --dist-dir "$dist_dir"
fi

if [[ "$run_nix_packages" -eq 1 ]]; then
  echo "== tracked Nix runtime packages =="
  scripts/check-nix-runtime-packages.sh
fi

echo "clean: runtime release preflight passed"
