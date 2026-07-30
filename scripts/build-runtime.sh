#!/usr/bin/env bash
# Build the bounded runtime/API tier only. This intentionally does not build
# Lean; proof-heavy roots live behind build-assurance/build-full-conformance.

set -euo pipefail

cd "$(dirname "$0")/.."

jobs="${JOBS:-2}"
export CARGO_BUILD_JOBS="$jobs"

if [[ "${RUST_WARNINGS:-0}" != "1" ]]; then
  if [[ -n "${RUSTFLAGS:-}" ]]; then
    export RUSTFLAGS="$RUSTFLAGS -Awarnings"
  else
    export RUSTFLAGS="-Awarnings"
  fi
fi

scripts/check-runtime-import-boundary.sh
scripts/check-policy-contract.sh
scripts/check-runtime-data.sh
scripts/check-port-self-contained.sh

cargo build --locked --manifest-path ports/rust/Cargo.toml --bin unicode-security

echo "clean: runtime build completed without Lean"
