/-
  Unicode.Conformance.Security.HomoglyphConfusableTest

  Conformance proof for the I1 family.  Folds the universal
  `Unicode.Security.Fixture` parser over the hand-curated
  `HomoglyphConfusableTest.txt` fixture and `decide`-closes
  the predicate that every row's expected verdict matches what
  `Unicode.Security.Identity.HomoglyphConfusable.detect` produces.
-/

import Unicode.Security.Fixture
import Unicode.Security.Identity.HomoglyphConfusable

namespace Unicode.Conformance.Security.HomoglyphConfusableTest

open Unicode.Security.Calculus
open Unicode.Security.Fixture
open Unicode.Security.Identity.HomoglyphConfusable

-- ═══════════════════════════════════════════════════════════════════════════════
-- §1 Raw fixture + parsed rows
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Hand-curated fixture — 16 rows across 4 sections
    covering: legitimate-Latin clear cases, the Oct 2025 NuGet
    Nethereum typosquat shape, IDN homograph attacks against
    `apple` / `paypal`, Math-Alpha posing variants (Bold /
    Italic / Script / Fraktur), and Fullwidth disguise. -/
def rawFixture : String :=
  include_str "../../Ucd/Security/HomoglyphConfusableTest.txt"

/-- All parsed rows from the bundled fixture. -/
def rows : List Row := parseFixture rawFixture

-- ═══════════════════════════════════════════════════════════════════════════════
-- §2 Per-family classification-name mapping
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Project an `Classification` to `(ClassificationKind, sub-threat-tag)`. -/
def projectClassify
    (c : Classification) : ClassificationKind × Option String :=
  if c.isClear then (.clear, none) else (.hazard, c.tag)

/-- Project an `Classification` to the positions array. -/
def projectPositions (c : Classification) : List Nat :=
  c.positions

-- ═══════════════════════════════════════════════════════════════════════════════
-- §3 Per-row verifier
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Render a `RestrictionLevel` as the bare constructor name used
    in fixture column-4 attribution. -/
@[inline]
def restrictionString : Unicode.Restriction.RestrictionLevel → String
  | .ASCIIOnly             => "ASCIIOnly"
  | .SingleScript          => "SingleScript"
  | .HighlyRestrictive     => "HighlyRestrictive"
  | .ModeratelyRestrictive => "ModeratelyRestrictive"
  | .MinimallyRestrictive  => "MinimallyRestrictive"
  | .Unrestricted          => "Unrestricted"

/-- Validate the I1 verdict's metadata fields against the row's
    column-4 attribution.  Key recognised: `restriction` against
    the UTS #39 §5 restriction level of the row's input. -/
def metadataMatches (v : Verdict)
    (attr : KeyValueAttribution) : Bool :=
  attr.checkStringKey "restriction" (restrictionString v.restrictionLevel)

/-- Run `detect` on the row's input and check the verdict against
    the fixture's expected classification, sub-threat name,
    hazard positions, AND the column-4 attribution metadata. -/
def verifyRow (r : Row) : Bool :=
  let v := detect r.input
  let (kind, subTag) := projectClassify v.classify
  let pos := projectPositions v.classify
  metadataMatches v r.attribution &&
  decide (kind = r.expectedKind) &&
  decide (subTag = r.expectedSubThreat) &&
  decide (pos = r.expectedPositions)

-- ═══════════════════════════════════════════════════════════════════════════════
-- §4 Headline conformance theorem + row-count gate
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Every fixture row's detector verdict matches its expected verdict. -/
theorem all_rows_pass : rows.all verifyRow = true := by decide

/-- Row-count gate. -/
theorem row_count : rows.length = 41 := by decide

/-- Section coverage gates. -/
theorem covers_clear :
    (rows.filter (·.sectionName = "Clear")).length ≥ 5 := by decide

theorem covers_target_match :
    (rows.filter (·.sectionName = "TargetMatch")).length ≥ 8 := by
  decide

theorem covers_math_alpha :
    (rows.filter (·.sectionName = "MathAlpha")).length ≥ 8 := by decide

theorem covers_width_class :
    (rows.filter (·.sectionName = "WidthClass")).length ≥ 5 := by
  decide

theorem covers_decomposition_swap :
    (rows.filter (·.sectionName = "DecompositionSwap")).length ≥ 4 := by
  decide

theorem covers_cross_script_mix :
    (rows.filter (·.sectionName = "CrossScriptMix")).length ≥ 7 := by
  decide

theorem covers_restriction_low :
    (rows.filter (·.sectionName = "RestrictionLow")).length ≥ 3 := by
  decide

/-- Regression: the Nethereum Oct-2025 typosquat fires `TargetMatch`. -/
theorem nethereum_typosquat_caught :
    (detect #[0x4E, 0x65, 0x74, 0x68, 0x65, 0x72, 0x0435, 0x75, 0x6D]).classify.tag
      = some "TargetMatch" := by decide

/-- Regression: the legitimate "Nethereum" stays clear. -/
theorem nethereum_legit_clear :
    (detect #[0x4E, 0x65, 0x74, 0x68, 0x65, 0x72, 0x65, 0x75, 0x6D]).classify.isClear
      = true := by decide

end Unicode.Conformance.Security.HomoglyphConfusableTest
