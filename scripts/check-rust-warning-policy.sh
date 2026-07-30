#!/usr/bin/env bash
# Guard the Rust public-doc lint policy used by runtime release scripts.

set -euo pipefail

cd "$(dirname "$0")/.."

fail() {
  echo "FATAL: $*" >&2
  exit 1
}

grep -Fqx 'missing_docs = "warn"' ports/rust/Cargo.toml \
  || fail "ports/rust/Cargo.toml must keep Rust missing_docs at warn while public docs are burned down"

grep -Fqx '#![warn(missing_docs)]' ports/rust/src/lib.rs \
  || fail "ports/rust/src/lib.rs must keep Rust missing_docs visible for public API burn-down"

grep -Fq 'RUST_WARNINGS' scripts/test-runtime-ports.sh \
  || fail "runtime port gate must expose RUST_WARNINGS=1 for Rust warning inspection"

grep -Fq -- '-Awarnings' scripts/test-runtime-ports.sh \
  || fail "runtime port gate must suppress warning noise by default"

grep -Fq 'RUST_WARNINGS' scripts/install-unicode-security.sh \
  || fail "CLI installer must expose RUST_WARNINGS=1 for Rust warning inspection"

grep -Fq -- '-Awarnings' scripts/install-unicode-security.sh \
  || fail "CLI installer must suppress warning noise by default"

grep -Fq 'RUST_WARNINGS' scripts/build-runtime.sh \
  || fail "runtime build script must expose RUST_WARNINGS=1 for Rust warning inspection"

grep -Fq -- '-Awarnings' scripts/build-runtime.sh \
  || fail "runtime build script must suppress warning noise by default"

echo "clean: Rust warning policy is explicit"
