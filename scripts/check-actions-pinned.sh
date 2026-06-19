#!/usr/bin/env bash
# Fail if any external GitHub Actions workflow dependency is referenced by a
# mutable tag or branch instead of a full 40-character commit SHA.

set -euo pipefail

cd "$(dirname "$0")/.."

if [ ! -d .github/workflows ]; then
  echo "clean: no GitHub Actions workflows present"
  exit 0
fi

uses_lines="$(grep -RInE '^[[:space:]-]*uses:[[:space:]]+[^[:space:]#]+' \
    --include='*.yml' --include='*.yaml' .github/workflows \
    || true)"

if [ -z "$uses_lines" ]; then
  echo "clean: no GitHub Actions dependencies present"
  exit 0
fi

unpinned_hits="$(printf '%s\n' "$uses_lines" \
  | grep -vE 'uses:[[:space:]]+\./' \
  | grep -vE '@[0-9a-fA-F]{40}([[:space:]]*(#.*)?)?$' \
  || true)"

if [ -n "$unpinned_hits" ]; then
  echo "FATAL: external GitHub Actions dependencies must be pinned to full commit SHAs:"
  echo "$unpinned_hits"
  exit 1
fi

echo "clean: external GitHub Actions dependencies are commit-SHA pinned"
