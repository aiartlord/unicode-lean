/-
  Unicode.Conformance.Security.HomoglyphConfusableTest

  Conformance proof for the I1 family.  Folds the universal
  `Unicode.Security.Fixture` parser over the hand-curated
  `HomoglyphConfusableTest.txt` fixture and `native_decide`-closes
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

/-- Hand-curated v1 fixture for I1 — 16 rows across 4 sections
    covering: legitimate-Latin clear cases, the Oct 2025 NuGet
    Nethereum typosquat shape, IDN homograph attacks against
    `apple` / `paypal`, Math-Alpha posing variants (Bold /
    Italic / Script / Fraktur), and Fullwidth disguise. -/
def rawFixture : String :=
  include_str "../../Ucd/Security/HomoglyphConfusableTest.txt"

/-- All parsed rows from the bundled fixture. -/
def rows : Array Row := parseFixture rawFixture

-- ═══════════════════════════════════════════════════════════════════════════════
-- §2 Per-family classification-name mapping
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Project an `I1Classification` to `(ClassificationKind, sub-threat-tag)`. -/
def projectClassify
    (c : I1Classification) : ClassificationKind × Option String :=
  if c.isClear then (.clear, none) else (.hazard, c.tag)

/-- Project an `I1Classification` to the positions array. -/
def projectPositions (c : I1Classification) : Array Nat :=
  c.positions

-- ═══════════════════════════════════════════════════════════════════════════════
-- §3 Per-row verifier
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Run `detect` on the row's input and check the verdict against
    the fixture's expected classification, sub-threat name, and
    hazard positions. -/
def verifyRow (r : Row) : Bool :=
  let v := detect r.input
  let (kind, subTag) := projectClassify v.classify
  let pos := projectPositions v.classify
  decide (kind = r.expectedKind) &&
  decide (subTag = r.expectedSubThreat) &&
  decide (pos = r.expectedPositions)

-- ═══════════════════════════════════════════════════════════════════════════════
-- §4 Headline conformance theorem + row-count gate
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Every fixture row's detector verdict matches its expected verdict. -/
theorem all_rows_pass : rows.all verifyRow = true := by native_decide

/-- Row-count gate. -/
theorem row_count : rows.size = 16 := by native_decide

/-- Section coverage gates. -/
theorem covers_clear :
    (rows.filter (·.sectionName = "Clear")).size ≥ 5 := by native_decide

theorem covers_target_match :
    (rows.filter (·.sectionName = "TargetMatch")).size ≥ 3 := by
  native_decide

theorem covers_math_alpha :
    (rows.filter (·.sectionName = "MathAlpha")).size ≥ 5 := by native_decide

theorem covers_width_class :
    (rows.filter (·.sectionName = "WidthClass")).size ≥ 3 := by
  native_decide

/-- Regression: the Nethereum Oct-2025 typosquat fires `TargetMatch`. -/
theorem nethereum_typosquat_caught :
    (detect #[0x4E, 0x65, 0x74, 0x68, 0x65, 0x72, 0x0435, 0x75, 0x6D]).classify.tag
      = some "TargetMatch" := by native_decide

/-- Regression: the legitimate "Nethereum" stays clear. -/
theorem nethereum_legit_clear :
    (detect #[0x4E, 0x65, 0x74, 0x68, 0x65, 0x72, 0x65, 0x75, 0x6D]).classify.isClear
      = true := by native_decide

end Unicode.Conformance.Security.HomoglyphConfusableTest
