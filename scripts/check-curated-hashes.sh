#!/usr/bin/env bash
# Verify the bundled curated data files match the SHA-256 hashes
# pinned in `Unicode/Ucd/Curated/SHA256SUMS`.  The three curated
# tables (KnownAttackTargets, WatermarkSchemes, GlitchTokens) are
# embedded into the `Unicode.Generated.<Name>` modules via
# `include_str` at build time, so a byte change to a `.txt`
# silently changes what the module compiles.  The guard enforces
# byte-exact equality with the publication that was committed at
# release time.

set -euo pipefail

cd "$(dirname "$0")/../Unicode/Ucd/Curated"

if [ ! -f SHA256SUMS ]; then
  echo "FATAL: SHA256SUMS missing under Unicode/Ucd/Curated/"
  exit 1
fi

sha256sum -c --strict --quiet SHA256SUMS

# `sha256sum -c` says nothing about a file the manifest omits, so a data file
# added without a hash would sit here unpinned and the check above would still
# pass. Every `.txt` here must be listed.
unpinned=""
for curated in *.txt; do
  if ! grep -qF "  $curated" SHA256SUMS; then
    unpinned="$unpinned $curated"
  fi
done
if [ -n "$unpinned" ]; then
  echo "FATAL: curated data file(s) present but absent from SHA256SUMS:$unpinned"
  exit 1
fi

count="$(wc -l < SHA256SUMS | tr -d ' ')"
echo "clean: $count curated data file(s) match SHA-256 manifest"
