#!/usr/bin/env bash
# Generate `src/Unicode/Generated/EastAsianWidth.hs` from
# `data/EastAsianWidth.txt`.
#
# Haskell counterpart to the Lean `Unicode/Generated/EastAsianWidth.lean`,
# which embeds the same UCD bytes and exposes the parsed East_Asian_Width
# ranges. The Haskell side pre-extracts the ranges into a literal table at
# generation time and commits the result: there is no compile-time parse.
#
# One table is emitted. The file's `# @missing: 0000..10FFFF; N` line declares
# Neutral over the whole space, so an unlisted codepoint is `EawN` and no
# separate default table is needed — unlike DerivedBidiClass, which has real
# per-block defaults.
#
# Re-run whenever `data/EastAsianWidth.txt` is bumped. The pinned UCD release
# is the one named in `data/UCD-VERSION`; the Lean spec and Haskell port MUST
# agree byte-for-byte on the source file — see `data/SHA256SUMS`.

set -euo pipefail

cd "$(dirname "$0")/.."

SRC=data/EastAsianWidth.txt
OUT=src/Unicode/Generated/EastAsianWidth.hs

if [ ! -f "$SRC" ]; then
  echo "FATAL: $SRC missing — vendor the UCD file before generating" >&2
  exit 1
fi

mkdir -p "$(dirname "$OUT")"

cat > "$OUT" <<'HEADER'
{-|
Module      : Unicode.Generated.EastAsianWidth
Description : East_Asian_Width ranges from UCD EastAsianWidth.txt.

GENERATED FILE — DO NOT EDIT. Re-run
@scripts/generate-east-asian-width.sh@ to regenerate.

Haskell port of @Unicode.Generated.EastAsianWidth@. Same UCD source bytes
(see @data/UCD-VERSION@). The file's @\@missing@ line declares @N@ over the
whole codepoint space, so a codepoint absent from 'explicitRanges' is
'EawN' and there is no default table.
-}
module Unicode.Generated.EastAsianWidth
  ( EastAsianWidth (EawA, EawF, EawH, EawN, EawNa, EawW)
  , explicitRanges
  ) where

-- | UAX #11 @East_Asian_Width@ class.
data EastAsianWidth
  = EawA
  | EawF
  | EawH
  | EawN
  | EawNa
  | EawW
  deriving stock (Eq, Show)

-- | Explicit @East_Asian_Width@ ranges @(lo, hi, class)@, sorted by lower
-- bound (file order for canonical UCD EastAsianWidth.txt).
explicitRanges :: [(Int, Int, EastAsianWidth)]
explicitRanges =
HEADER

awk -v first=1 '
  function ctor(s) {
      if (s == "A")  return "EawA"
      if (s == "F")  return "EawF"
      if (s == "H")  return "EawH"
      if (s == "Na") return "EawNa"
      if (s == "W")  return "EawW"
      return "EawN"
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

echo "wrote $OUT"
