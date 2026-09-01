#!/usr/bin/env bash
# Verify the Security Conformance Layer fixtures match the SHA-256
# hashes pinned in `Unicode/Ucd/Security/SHA256SUMS`.  Tampering with a
# fixture would let a kernel checks over those bytes claim a
# verdict that disagrees with the published threat model, so the
# guard enforces byte-exact equality with the publication that was
# committed at release time.

set -euo pipefail

cd "$(dirname "$0")/../Unicode/Ucd/Security"

if [ ! -f SHA256SUMS ]; then
  echo "FATAL: SHA256SUMS missing under Unicode/Ucd/Security/"
  exit 1
fi

# `sha256sum -c` succeeds iff every listed file matches its hash.
sha256sum -c --strict --quiet SHA256SUMS

# `sha256sum -c` says nothing about a file the manifest omits, so a fixture
# added without a hash would sit in this directory unpinned and the check above
# would still pass. Every `.txt` here must be listed.
unpinned=""
for fixture in *.txt; do
  if ! grep -qF "  $fixture" SHA256SUMS; then
    unpinned="$unpinned $fixture"
  fi
done
if [ -n "$unpinned" ]; then
  echo "FATAL: Security fixture(s) present but absent from SHA256SUMS:$unpinned"
  exit 1
fi

count="$(wc -l < SHA256SUMS | tr -d ' ')"
echo "clean: $count Security UCD-pinned file(s) match SHA-256 manifest"
