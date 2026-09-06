#!/usr/bin/env bash
# The pinned conformance inputs, as a tracked sha256sum manifest.
#
# `fixtures/conformance/CONFORMANCE-INPUTS.sha256` names every published
# Unicode test file the conformance report counts and the SHA-256 of the bytes
# under `Unicode/Ucd/`. It is tracked so a release is pinned to its inputs from
# a clean checkout, not from a build directory. Two things have to hold: the
# files on disk match the manifest, and the manifest is the one
# `scripts/conformance-run.py --emit-inputs-manifest` would write from those
# files, so it cannot drift from the report that cites it.

set -euo pipefail

cd "$(dirname "$0")/.."

manifest="fixtures/conformance/CONFORMANCE-INPUTS.sha256"

if [ ! -f "$manifest" ]; then
  echo "FATAL: $manifest missing; write it with: python3 scripts/conformance-run.py --emit-inputs-manifest"
  exit 1
fi

sha256sum -c --strict --quiet "$manifest"

fresh="$(mktemp)"
trap 'rm -f "$fresh"' EXIT
python3 scripts/conformance-run.py --emit-inputs-manifest "$fresh" > /dev/null

if ! cmp -s "$fresh" "$manifest"; then
  echo "FATAL: $manifest is not what the report would emit from the pinned inputs:"
  diff "$manifest" "$fresh" || true
  echo "regenerate with: python3 scripts/conformance-run.py --emit-inputs-manifest"
  exit 1
fi

count="$(wc -l < "$manifest" | tr -d ' ')"
echo "clean: $count pinned conformance inputs match $manifest"
