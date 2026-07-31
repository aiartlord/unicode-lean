#!/usr/bin/env bash
# Generate `src/Unicode/Generated/DerivedBidiClass.hs` from
# `data/DerivedBidiClass.txt`.
#
# Haskell counterpart to the Lean
# `Unicode/Generated/DerivedBidiClass.lean`, which embeds the same UCD
# bytes and exposes the parsed Bidi_Class ranges. The Haskell side
# pre-extracts the ranges into literal tables at generation time and
# commits the result to the repo: there is no compile-time parse.
#
# Only the strong Bidi_Class distinction the display layer needs is
# retained: R, AL, and L map to themselves; every other Bidi_Class
# collapses to `BidiOther`. Retaining the explicit `BidiOther` ranges
# is load-bearing — an explicit non-strong row inside a default-R or
# default-AL block must win over that block's default.
#
# Two tables are emitted:
#   * explicitRanges — DATA lines `LO..HI ; SHORT` / `CP ; SHORT`,
#     in file (ascending codepoint) order, which is sorted by lower
#     bound for canonical UCD DerivedBidiClass.txt.
#   * defaultRanges  — `# @missing: LO..HI; Long_Name` comment lines,
#     in file order; the last matching default wins at lookup time.
#
# Re-run whenever `data/DerivedBidiClass.txt` is bumped. The pinned UCD
# release is the one named in `data/UCD-VERSION`; the Lean spec and
# Haskell port MUST agree byte-for-byte on the source file — see
# `data/SHA256SUMS`.

set -euo pipefail

cd "$(dirname "$0")/.."

SRC=data/DerivedBidiClass.txt
OUT=src/Unicode/Generated/DerivedBidiClass.hs

if [ ! -f "$SRC" ]; then
  echo "FATAL: $SRC missing — vendor the UCD file before generating" >&2
  exit 1
fi

mkdir -p "$(dirname "$OUT")"

cat > "$OUT" <<'HEADER'
{-|
Module      : Unicode.Generated.DerivedBidiClass
Description : Strong Bidi_Class ranges from UCD DerivedBidiClass.txt.

GENERATED FILE — DO NOT EDIT. Re-run
@scripts/generate-derived-bidi-class.sh@ to regenerate.

Haskell port of @Unicode.Generated.DerivedBidiClass@. Same UCD source
bytes (see @data/UCD-VERSION@). Only the strong Bidi_Class distinction
the display layer needs is retained — @R@, @AL@, and @L@ map to
themselves; every other Bidi_Class collapses to 'BidiOther'.

'lookup' semantics (implemented in 'Unicode.Security.Policy'): an
explicit range wins; otherwise the last matching @\@missing@ default
range wins; otherwise the codepoint is @L@. Retaining the explicit
'BidiOther' ranges is load-bearing — an explicit non-strong row inside
a default-@R@ or default-@AL@ block must override that block's default.
-}
module Unicode.Generated.DerivedBidiClass
  ( BidiStrong (BidiAL, BidiL, BidiOther, BidiR)
  , explicitRanges
  , defaultRanges
  ) where

-- | The strong Bidi_Class distinction the display layer needs. Every
-- Bidi_Class other than @R@, @AL@, and @L@ collapses to 'BidiOther'.
data BidiStrong
  = BidiR
  | BidiAL
  | BidiL
  | BidiOther
  deriving stock (Eq, Show)

-- | Explicit Bidi_Class ranges @(lo, hi, class)@, sorted by lower
-- bound (file order for canonical UCD DerivedBidiClass.txt).
explicitRanges :: [(Int, Int, BidiStrong)]
explicitRanges =
HEADER

awk -v first=1 '
  function ctor(s) {
      if (s == "R")  return "BidiR"
      if (s == "AL") return "BidiAL"
      if (s == "L")  return "BidiL"
      return "BidiOther"
  }
  # DATA lines begin with a hex digit.
  /^[0-9A-Fa-f]/ {
      nfields = split($0, parts, ";")
      if (nfields < 2) next
      range = parts[1]
      gsub(/[ \t]+/, "", range)
      cls = parts[2]
      sub(/#.*$/, "", cls)
      gsub(/[ \t]+/, "", cls)
      if (index(range, "..") > 0) {
          split(range, rb, /\.\./)
          lo = rb[1]
          hi = rb[2]
      } else {
          lo = range
          hi = range
      }
      prefix = (first ? "  [ " : "  , ")
      first = 0
      printf "%s(0x%s, 0x%s, %s)\n", prefix, lo, hi, ctor(cls)
  }
  END {
      if (first) {
          printf "  [\n"
      }
      print "  ]"
  }
' "$SRC" >> "$OUT"

cat >> "$OUT" <<'MID'

-- | Default @\@missing@ Bidi_Class ranges @(lo, hi, class)@, in file
-- order. The last range that matches a codepoint wins.
defaultRanges :: [(Int, Int, BidiStrong)]
defaultRanges =
MID

awk -v first=1 '
  function lctor(s) {
      if (s == "Right_To_Left") return "BidiR"
      if (s == "Arabic_Letter") return "BidiAL"
      if (s == "Left_To_Right") return "BidiL"
      return "BidiOther"
  }
  /^# @missing:/ {
      body = $0
      sub(/^# @missing:[ \t]*/, "", body)
      nfields = split(body, parts, ";")
      if (nfields < 2) next
      range = parts[1]
      gsub(/[ \t]+/, "", range)
      cls = parts[2]
      gsub(/[ \t]+/, "", cls)
      if (index(range, "..") > 0) {
          split(range, rb, /\.\./)
          lo = rb[1]
          hi = rb[2]
      } else {
          lo = range
          hi = range
      }
      prefix = (first ? "  [ " : "  , ")
      first = 0
      printf "%s(0x%s, 0x%s, %s)\n", prefix, lo, hi, lctor(cls)
  }
  END {
      if (first) {
          printf "  [\n"
      }
      print "  ]"
  }
' "$SRC" >> "$OUT"

echo "wrote $OUT ($(wc -l < "$OUT") lines)"
