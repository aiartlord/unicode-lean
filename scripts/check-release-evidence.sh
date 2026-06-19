#!/usr/bin/env bash
# Smoke-test release evidence generation without publishing anything.

set -euo pipefail

cd "$(dirname "$0")/.."

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

bash scripts/release-evidence.sh ci-smoke "$tmpdir"

(
  cd "$tmpdir"
  sha256sum -c --strict --quiet SHA256SUMS
)

if command -v jq >/dev/null 2>&1; then
  jq empty "$tmpdir/unicode-lean-ci-smoke.sbom.cdx.json"
fi

echo "clean: release evidence generator emitted valid artifacts"
