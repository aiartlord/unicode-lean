#!/usr/bin/env bash
# Install the unicode-security CLI into a local prefix and smoke-test it.
# This is a runtime-only path; it does not build Lean.

set -euo pipefail

cd "$(dirname "$0")/.."

prefix="${1:-${UNICODE_SECURITY_PREFIX:-dist/runtime/rust}}"
jobs="${JOBS:-2}"

case "$prefix" in
  /*) prefix_abs="$prefix" ;;
  *) prefix_abs="$PWD/$prefix" ;;
esac

mkdir -p "$prefix_abs"

export CARGO_BUILD_JOBS="$jobs"
if [[ "${RUST_WARNINGS:-0}" != "1" ]]; then
  if [[ -n "${RUSTFLAGS:-}" ]]; then
    export RUSTFLAGS="$RUSTFLAGS -Awarnings"
  else
    export RUSTFLAGS="-Awarnings"
  fi
fi
cargo install --path ports/rust --bin unicode-security --root "$prefix_abs" --force --locked

bin="$prefix_abs/bin/unicode-security"
if [[ ! -x "$bin" ]]; then
  echo "FATAL: installed unicode-security binary missing at $bin" >&2
  exit 1
fi

"$bin" --version >/dev/null

smoke="$(
  printf 'Hello' | "$bin" scan --profile gateway-header --mode enforce --json
)"
expected='{"action":"allow","profile":"gateway-header","mode":"enforce","input":[72,101,108,108,111],"findings":[],"normalized":null}'
if [[ "$smoke" != "$expected" ]]; then
  echo "FATAL: unicode-security smoke scan mismatch" >&2
  echo "actual:   $smoke" >&2
  echo "expected: $expected" >&2
  exit 1
fi

version="$(awk -F '"' '/^version = / { print $2; exit }' ports/rust/Cargo.toml)"
cat > "$prefix_abs/UNICODE_SECURITY_INSTALL.txt" <<INSTALL
unicode-security CLI install

version: $version
binary: bin/unicode-security
smoke: scan gateway-header/enforce ASCII JSON allow
lean: not built
INSTALL

echo "clean: unicode-security installed and smoke-tested at $prefix_abs"
