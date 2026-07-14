#!/usr/bin/env bash
# Generate `src/Unicode/Generated/DerivedNormalizationProps.hs` from
# `data/DerivedNormalizationProps.txt`.
#
# Haskell counterpart to the Lean
# `Unicode/Generated/DerivedNormalizationProps.lean`. This first
# slice extracts only the `Full_Composition_Exclusion` ranges — the
# table the NFC compose pass consults to skip recomposition. The
# `NFC_QC` / `NFKC_QC` / `NFD_QC` / `NFKD_QC` QuickCheck tables ship
# in a later slice; they are optimisations and the NFC algorithm is
# correct without them.
#
# Re-run whenever `data/DerivedNormalizationProps.txt` is bumped.
# The Lean spec and Haskell port MUST agree byte-for-byte on the
# source file — see `data/SHA256SUMS`.

set -euo pipefail

cd "$(dirname "$0")/.."

SRC=data/DerivedNormalizationProps.txt
OUT=src/Unicode/Generated/DerivedNormalizationProps.hs

if [ ! -f "$SRC" ]; then
  echo "FATAL: $SRC missing — vendor the UCD file before generating" >&2
  exit 1
fi

mkdir -p "$(dirname "$OUT")"

cat > "$OUT" <<'HEADER'
{-|
Module      : Unicode.Generated.DerivedNormalizationProps
Description : NFC-relevant subset of DerivedNormalizationProps.txt.

GENERATED FILE — DO NOT EDIT. Re-run
@scripts/generate-derived-normalization-props.sh@ to regenerate.

Haskell port of @Unicode.Generated.DerivedNormalizationProps@.
Same UCD source bytes (see @data/UCD-VERSION@).

This first slice exposes only the @Full_Composition_Exclusion@ ranges
— the broader test that the NFC compose pass uses to skip recomposing
canonical decompositions that may not recombine
(@CompositionExclusions.txt@ ∪ singleton decompositions ∪ non-starter
decompositions). The QuickCheck tables (@NFC_QC@ / @NFKC_QC@ /
@NFD_QC@ / @NFKD_QC@) ship in a later slice; they are optimisations
and NFC remains correct without them.
-}
module Unicode.Generated.DerivedNormalizationProps
  ( fullCompositionExclusion
  ) where

-- | Codepoint ranges (@lo, hi@; inclusive) carrying
-- @Full_Composition_Exclusion@. Sorted by @lo@.
fullCompositionExclusion :: [(Int, Int)]
fullCompositionExclusion =
HEADER

awk -v first=1 '
  # Skip blank or comment-only lines.
  /^[[:space:]]*(#|$)/ { next }

  # Match Full_Composition_Exclusion rows. The line shape is:
  #   "<range>  ; <prop> # <comment>"
  # We split on ";" — but want the prop column to be the literal
  # token "Full_Composition_Exclusion" (after stripping whitespace
  # and the trailing comment).
  {
      raw = $0
      # Drop trailing "# comment" tail.
      sub(/#.*$/, "", raw)
      # Split on ";".
      n = split(raw, fields, ";")
      if (n < 2) next

      rng  = fields[1]
      prop = fields[2]
      gsub(/^[ \t]+|[ \t]+$/, "", rng)
      gsub(/^[ \t]+|[ \t]+$/, "", prop)

      if (prop != "Full_Composition_Exclusion") next

      # Parse range: "XXXX" or "XXXX..YYYY". awk treats ".." as a
      # regex in split(), so reach for index/substr instead.
      dotIdx = index(rng, "..")
      if (dotIdx > 0) {
          lo = substr(rng, 1, dotIdx - 1)
          hi = substr(rng, dotIdx + 2)
      } else {
          lo = rng
          hi = rng
      }

      prefix = (first ? "  [ " : "  , ")
      first = 0
      printf "%s(0x%s, 0x%s)\n", prefix, lo, hi
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
