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

count="$(wc -l < SHA256SUMS | tr -d ' ')"
echo "clean: $count curated data file(s) match SHA-256 manifest"
