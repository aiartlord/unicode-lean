#!/usr/bin/env bash
# Verify the bundled UCD source files are byte-identical to the Unicode
# Consortium's published 17.0.0 files, by fetching each one from
# unicode.org and comparing SHA-256.
#
# `check-ucd-hashes.sh` is the sibling guard and answers a different
# question. It compares the working tree against `Unicode/Ucd/SHA256SUMS`,
# so it detects tampering after release but cannot detect a file that was
# committed wrong in the first place: a bad file and a matching bad digest
# pass it. This script is what grounds the chain out at the Consortium,
# which is the claim `docs/explanation/tcb.md` makes for the pinned tables.
#
# Requires network access. Intended for CI and for release evidence, not
# for the inner build loop -- it downloads roughly 40 MB, and Unihan.zip
# is most of that.

set -euo pipefail

cd "$(dirname "$0")/.."

base="${UNICODE_UPSTREAM_BASE:-https://www.unicode.org/Public/17.0.0}"
ucd_dir="Unicode/Ucd"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# Upstream layout for 17.0.0. Unlike earlier versions, which published
# uca/, security/, idna/ and emoji/ as sibling trees under /Public with
# their own version numbers, 17.0.0 consolidates all of them under the
# single /Public/17.0.0/ directory. Each entry is `<file> <subdirectory>`.
plain_files="
BidiBrackets.txt ucd
BidiCharacterTest.txt ucd
BidiMirroring.txt ucd
BidiTest.txt ucd
CaseFolding.txt ucd
CompositionExclusions.txt ucd
DerivedCoreProperties.txt ucd
DerivedNormalizationProps.txt ucd
EastAsianWidth.txt ucd
LineBreak.txt ucd
NormalizationTest.txt ucd
PropertyAliases.txt ucd
PropertyValueAliases.txt ucd
PropList.txt ucd
ScriptExtensions.txt ucd
Scripts.txt ucd
SpecialCasing.txt ucd
StandardizedVariants.txt ucd
UnicodeData.txt ucd
VerticalOrientation.txt ucd
DerivedBidiClass.txt ucd/extracted
DerivedJoiningType.txt ucd/extracted
GraphemeBreakProperty.txt ucd/auxiliary
GraphemeBreakTest.txt ucd/auxiliary
LineBreakTest.txt ucd/auxiliary
SentenceBreakProperty.txt ucd/auxiliary
SentenceBreakTest.txt ucd/auxiliary
WordBreakProperty.txt ucd/auxiliary
WordBreakTest.txt ucd/auxiliary
emoji-data.txt ucd/emoji
emoji-variation-sequences.txt ucd/emoji
emoji-sequences.txt emoji
emoji-test.txt emoji
emoji-zwj-sequences.txt emoji
IdnaMappingTable.txt idna
IdnaTestV2.txt idna
confusables.txt security
IdentifierStatus.txt security
IdentifierType.txt security
allkeys.txt uca
"

# Files the Consortium ships only inside an archive. Each entry is
# `<archive-path> <file> [<file> ...]`.
archives="
uca/CollationTest.zip CollationTest_NON_IGNORABLE.txt CollationTest_NON_IGNORABLE_SHORT.txt CollationTest_SHIFTED.txt CollationTest_SHIFTED_SHORT.txt
ucd/Unihan.zip Unihan_Variants.txt Unihan_NumericValues.txt
"

# MANIFEST.txt is this repository's own inventory of the pinned files --
# name, byte size and digest -- not a Unicode publication. It is excluded
# here by name rather than skipped silently, so the count below still adds
# up against SHA256SUMS.
local_only="MANIFEST.txt"

checked=0
mismatched=0
missing=0

report() {
  local name="$1" expected="$2" actual="$3"
  if [ "$expected" = "$actual" ]; then
    checked=$((checked + 1))
  else
    mismatched=$((mismatched + 1))
    echo "MISMATCH: $name"
    echo "    local:    $expected"
    echo "    upstream: $actual"
  fi
}

digest_of() { sha256sum "$1" | cut -d' ' -f1; }

printf '%s\n' "$plain_files" > "$work/plain.list"

# Read from a file, not a pipe: a piped `while` runs in a subshell and the
# tallies below would be discarded when it exits.
while read -r name subdir; do
  [ -z "$name" ] && continue
  if [ ! -f "$ucd_dir/$name" ]; then
    echo "MISSING LOCALLY: $ucd_dir/$name"
    missing=$((missing + 1))
    continue
  fi
  if ! curl -sSf --max-time 120 -o "$work/$name" "$base/$subdir/$name"; then
    echo "FETCH FAILED: $base/$subdir/$name"
    missing=$((missing + 1))
    continue
  fi
  report "$name" "$(digest_of "$ucd_dir/$name")" "$(digest_of "$work/$name")"
done < "$work/plain.list"

printf '%s\n' "$archives" > "$work/archives.list"

while read -r archive rest; do
  [ -z "$archive" ] && continue
  zipfile="$work/$(basename "$archive")"
  if ! curl -sSf --max-time 600 -o "$zipfile" "$base/$archive"; then
    echo "FETCH FAILED: $base/$archive"
    for _ in $rest; do missing=$((missing + 1)); done
    continue
  fi
  extract="$work/$(basename "$archive" .zip)-extract"
  mkdir -p "$extract"
  unzip -qo "$zipfile" -d "$extract"
  for name in $rest; do
    if [ ! -f "$ucd_dir/$name" ]; then
      echo "MISSING LOCALLY: $ucd_dir/$name"
      missing=$((missing + 1))
      continue
    fi
    found="$(find "$extract" -name "$name" -type f | head -1)"
    if [ -z "$found" ]; then
      echo "NOT IN ARCHIVE: $name (expected inside $archive)"
      missing=$((missing + 1))
      continue
    fi
    report "$name" "$(digest_of "$ucd_dir/$name")" "$(digest_of "$found")"
  done
done < "$work/archives.list"

echo
echo "checked $checked file(s) against $base"
echo "excluded (not a Unicode publication): $local_only"

if [ "$mismatched" -ne 0 ] || [ "$missing" -ne 0 ]; then
  echo "FAIL: $mismatched mismatched, $missing unavailable"
  exit 1
fi

echo "clean: bundled UCD files are byte-identical to the published 17.0.0 tables"
