#!/usr/bin/env bash
# Verify the bundled UCD source files match the SHA-256 hashes pinned
# in `Unicode/Ucd/SHA256SUMS`. Tampering with a UCD `.txt` file would
# allow a kernel checks over those bytes to lie, so the guard
# enforces byte-exact equality with the publication that was committed
# at release time.

set -euo pipefail

cd "$(dirname "$0")/../Unicode/Ucd"

if [ ! -f SHA256SUMS ]; then
  echo "FATAL: SHA256SUMS missing under Unicode/Ucd/"
  exit 1
fi

# `sha256sum -c` succeeds iff every listed file matches its hash.
sha256sum -c --strict --quiet SHA256SUMS

# `sha256sum -c` says nothing about a file the manifest omits, so a corpus added
# without a hash would sit here unpinned and the check above would still pass.
# Every `.txt` at this level must be listed.
unpinned=""
for corpus in *.txt; do
  if ! grep -qF "  $corpus" SHA256SUMS; then
    unpinned="$unpinned $corpus"
  fi
done
if [ -n "$unpinned" ]; then
  echo "FATAL: UCD source file(s) present but absent from SHA256SUMS:$unpinned"
  exit 1
fi

echo "clean: UCD source files match SHA-256 manifest"
