#!/usr/bin/env bash
# Build and run the dependency-free Swift contract test executable.

set -euo pipefail

cd "$(dirname "$0")/.."

swift_bin="${SWIFT:-swift}"

if command -v nix-store >/dev/null 2>&1; then
  closure_roots=()
  for tool in "$swift_bin" swift-run swift-test swift-package; do
    if command -v "$tool" >/dev/null 2>&1; then
      tool_path="$(readlink -f "$(command -v "$tool")")"
      while IFS= read -r root; do
        closure_roots+=("$root")
      done < <(nix-store -qR "$tool_path" 2>/dev/null || true)
    fi
  done
  if [[ "${#closure_roots[@]}" -gt 0 ]]; then
    swift_lib_dirs="$(
      find "${closure_roots[@]}" -type f \
        \( -name 'libdispatch.so' -o -name 'libFoundation.so' \) \
        -printf '%h\n' 2>/dev/null | sort -u | paste -sd:
    )"
    if [[ -n "$swift_lib_dirs" ]]; then
      export LD_LIBRARY_PATH="$swift_lib_dirs${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
    fi
  fi
fi

swift_args=()
if [[ -n "${SWIFT_SCRATCH_PATH:-}" ]]; then
  swift_args+=(--scratch-path "$SWIFT_SCRATCH_PATH")
fi

"$swift_bin" run "${swift_args[@]}" UnicodeSecurityContractTests
