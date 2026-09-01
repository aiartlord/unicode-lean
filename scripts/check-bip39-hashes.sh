#!/usr/bin/env bash
# Verify the bundled BIP-39 wordlist files match the SHA-256 hashes
# pinned in `Unicode/Ucd/BIP39/SHA256SUMS`.  The ten wordlists are
# embedded into the `Unicode.Generated.BIP39.<Lang>` modules via
# `include_str` at build time and a kernel-checked
# `wordlist_count : wordlist.size = 2048` theorem reads back from
# the embedded bytes, so a byte change to a `.txt` would silently
# change the theorem's witness.  The guard enforces byte-exact
# equality with the publication that was committed at release time.

set -euo pipefail

cd "$(dirname "$0")/../Unicode/Ucd/BIP39"

if [ ! -f SHA256SUMS ]; then
  echo "FATAL: SHA256SUMS missing under Unicode/Ucd/BIP39/"
  exit 1
fi

# `sha256sum -c` succeeds iff every listed file matches its hash.
sha256sum -c --strict --quiet SHA256SUMS

# `sha256sum -c` says nothing about a file the manifest omits, so a wordlist
# added without a hash would sit here unpinned and the check above would still
# pass. Every `.txt` here must be listed.
unpinned=""
for wordlist in *.txt; do
  if ! grep -qF "  $wordlist" SHA256SUMS; then
    unpinned="$unpinned $wordlist"
  fi
done
if [ -n "$unpinned" ]; then
  echo "FATAL: BIP-39 wordlist(s) present but absent from SHA256SUMS:$unpinned"
  exit 1
fi

count="$(wc -l < SHA256SUMS | tr -d ' ')"
echo "clean: $count BIP-39 wordlist(s) match SHA-256 manifest"
