#!/usr/bin/env bash
# Generate `src/Unicode/Generated/UnicodeData.hs` from
# `data/UnicodeData.txt`.
#
# This is the Haskell counterpart to the Lean
# `Unicode/Generated/UnicodeData.lean`, which embeds the same UCD
# bytes via `include_str` and parses on first access. The Haskell
# side pre-extracts the NFC-relevant subset (rows where
# `canonicalCombiningClass != 0` OR `Decomposition_Mapping` is a
# canonical — non-`<tag>`-prefixed — sequence) into a literal table
# at generation time. The output is committed to the repo: there is
# no compile-time parse.
#
# Re-run whenever `data/UnicodeData.txt` is bumped. The pinned UCD
# release is the one named in `data/UCD-VERSION`; the Lean spec and
# Haskell port MUST agree byte-for-byte on the source file.

set -euo pipefail

cd "$(dirname "$0")/.."

SRC=data/UnicodeData.txt
OUT=src/Unicode/Generated/UnicodeData.hs

if [ ! -f "$SRC" ]; then
  echo "FATAL: $SRC missing — vendor the UCD file before generating" >&2
  exit 1
fi

mkdir -p "$(dirname "$OUT")"

cat > "$OUT" <<'HEADER'
{-|
Module      : Unicode.Generated.UnicodeData
Description : NFC-relevant subset of UCD UnicodeData.txt.

GENERATED FILE — DO NOT EDIT. Re-run
@scripts/generate-unicode-data.sh@ to regenerate.

Haskell port of @Unicode.Generated.UnicodeData@. Same UCD source bytes
(see @data/UCD-VERSION@), same row filter
(rows where @canonicalCombiningClass != 0@ OR
@Decomposition_Mapping@ is a canonical — non-@\<tag\>@-prefixed —
sequence). Compatibility decompositions and Hangul syllables
(handled algorithmically in 'Unicode.Normalization.Hangul') are
absent from the table by construction.
-}
module Unicode.Generated.UnicodeData
  ( UnicodeDataRow (UnicodeDataRow, codepoint, canonicalCombiningClass, canonicalDecomposition)
  , rows
  ) where

import Data.Word (Word8)

-- | One entry of the NFC-relevant subset of UnicodeData.txt. Fields
-- correspond to UCD columns 0, 3, and 5 per UAX #44.
data UnicodeDataRow = UnicodeDataRow
  { codepoint               :: !Int
  , canonicalCombiningClass :: !Word8
  , canonicalDecomposition  :: ![Int]
  }
  deriving stock (Eq, Show)

-- | NFC-relevant rows from UnicodeData.txt. Sorted by codepoint
-- (the source file's natural order).
rows :: [UnicodeDataRow]
rows =
HEADER

awk -F';' -v first=1 '
  function decompList(dm) {
      gsub(/^[ \t]+|[ \t]+$/, "", dm)
      if (dm == "") return "[]"
      n = split(dm, parts, /[ \t]+/)
      out = "["
      for (i = 1; i <= n; i++) {
          if (i > 1) out = out ", "
          out = out "0x" parts[i]
      }
      return out "]"
  }

  {
      cp = $1
      ccc = $4
      dm = $6
  }

  # Skip blank lines (split with no fields produces $1="")
  cp == "" { next }

  # Strip compat-decompositions: anything beginning with "<tag>".
  dm ~ /^</ { dm = "" }

  # NFC-inert filter: ccc == 0 AND no canonical decomposition.
  ccc == "0" && dm == "" { next }

  {
      prefix = (first ? "  [ " : "  , ")
      first = 0
      printf "%sUnicodeDataRow { codepoint = 0x%s, canonicalCombiningClass = %d, canonicalDecomposition = %s }\n",
             prefix, cp, ccc, decompList(dm)
  }

  END {
      if (first) {
          # No rows matched — emit an empty literal so the module compiles.
          printf "  [\n"
      }
      print "  ]"
  }
' "$SRC" >> "$OUT"

echo "wrote $OUT ($(wc -l < "$OUT") lines)"
