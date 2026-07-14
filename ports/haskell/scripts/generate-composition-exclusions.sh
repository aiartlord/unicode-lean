#!/usr/bin/env bash
# Generate `src/Unicode/Generated/CompositionExclusions.hs` from
# `data/CompositionExclusions.txt`.
#
# Haskell counterpart to the Lean
# `Unicode/Generated/CompositionExclusions.lean`, which embeds the
# same UCD bytes via `include_str` and parses on first access. The
# Haskell side pre-extracts the literal codepoint list at generation
# time and commits the result to the repo.
#
# Re-run whenever `data/CompositionExclusions.txt` is bumped. The Lean
# spec and Haskell port MUST agree byte-for-byte on the source file —
# see `data/SHA256SUMS`.

set -euo pipefail

cd "$(dirname "$0")/.."

SRC=data/CompositionExclusions.txt
OUT=src/Unicode/Generated/CompositionExclusions.hs

if [ ! -f "$SRC" ]; then
  echo "FATAL: $SRC missing — vendor the UCD file before generating" >&2
  exit 1
fi

mkdir -p "$(dirname "$OUT")"

cat > "$OUT" <<'HEADER'
{-|
Module      : Unicode.Generated.CompositionExclusions
Description : Codepoints excluded from canonical composition.

GENERATED FILE — DO NOT EDIT. Re-run
@scripts/generate-composition-exclusions.sh@ to regenerate.

Haskell port of @Unicode.Generated.CompositionExclusions@. Same UCD
source bytes (see @data/UCD-VERSION@), same
row filter (one codepoint per non-blank non-comment line).

Semantics: the codepoints below decompose canonically but do NOT
recompose during NFC/NFKC synthesis. See UAX #15 §1.2 and
@https:\/\/www.unicode.org\/reports\/tr15\/#Primary_Exclusion_List_Table@.
-}
module Unicode.Generated.CompositionExclusions
  ( codepoints
  ) where

-- | Sorted codepoints excluded from canonical composition.
codepoints :: [Int]
codepoints =
HEADER

awk -v first=1 '
  # Strip the inline "# comment" tail and surrounding whitespace.
  {
      line = $0
      sub(/#.*$/, "", line)
      gsub(/^[ \t]+|[ \t]+$/, "", line)
  }
  line == "" { next }
  {
      prefix = (first ? "  [ " : "  , ")
      first = 0
      printf "%s0x%s\n", prefix, line
  }
  END {
      if (first) {
          # Pathological empty input — emit an empty literal so the
          # module still compiles.
          printf "  [\n"
      }
      print "  ]"
  }
' "$SRC" >> "$OUT"

echo "wrote $OUT ($(wc -l < "$OUT") lines)"
